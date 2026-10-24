//! Один владелец viewport, терминального вывода и очереди клавиатуры.
use crate::{terminal::Footer, ui};
use anyhow::{Result, bail};
use crossterm::{
    cursor::{Hide, MoveTo, Show},
    event::{
        self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
        Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseEventKind,
    },
    execute, queue,
    style::{Color, Print, ResetColor, SetBackgroundColor, SetForegroundColor},
    terminal::{
        self, BeginSynchronizedUpdate, Clear, ClearType, EndSynchronizedUpdate,
        EnterAlternateScreen, LeaveAlternateScreen,
    },
};
use std::{
    collections::VecDeque,
    io::{self, Write},
    sync::{Arc, Condvar, Mutex, OnceLock, mpsc},
    thread,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Paint {
    #[default]
    Normal,
    Border,
    Muted,
    Selected,
    Error,
    Success,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Editor,
    Picker,
    Approval,
    Busy,
    Transition,
}
#[derive(Clone, Debug)]
pub struct Panel {
    pub rows: Vec<String>,
    pub styles: Vec<Paint>,
    pub cursor: Option<(usize, usize)>,
    pub mode: Mode,
}
struct State {
    footer: Footer,
    history: VecDeque<String>,
    bytes: usize,
    panel: Option<Panel>,
    mode: Mode,
    phase: Option<(String, Instant)>,
    scroll: usize,
    anchor: Option<usize>,
    cancel: CancellationToken,
    suspended: usize,
    stop: bool,
    generation: u64,
    input_epoch: u64,
    picker_cancelled: bool,
    editor_events: VecDeque<Event>,
}
struct Inbound {
    event: Event,
    mode: Mode,
    epoch: u64,
}
pub struct Screen {
    state: Mutex<State>,
    wake: Condvar,
    io: Mutex<()>,
    rx: Mutex<mpsc::Receiver<io::Result<Inbound>>>,
    tx: mpsc::Sender<io::Result<Inbound>>,
}
pub struct SessionGuard {
    screen: Arc<Screen>,
    workers: Vec<thread::JoinHandle<()>>,
}
pub struct Suspended {
    screen: Option<Arc<Screen>>,
}
static ACTIVE: OnceLock<Mutex<Option<Arc<Screen>>>> = OnceLock::new();
fn active() -> &'static Mutex<Option<Arc<Screen>>> {
    ACTIVE.get_or_init(|| Mutex::new(None))
}
pub fn current() -> Option<Arc<Screen>> {
    active().lock().unwrap_or_else(|e| e.into_inner()).clone()
}
pub fn notice(text: impl AsRef<str>) {
    if let Some(screen) = current() {
        screen.line(text.as_ref());
    } else {
        eprintln!("{}", ui::safe(text.as_ref()));
    }
}
fn footer_rows(height: usize) -> usize {
    if height >= 6 {
        2
    } else if height >= 2 {
        1
    } else {
        0
    }
}
pub fn panel_height(height: u16) -> u16 {
    height
        .saturating_sub(footer_rows(height as usize) as u16)
        .max(1)
}

impl Screen {
    fn new(footer: Footer) -> Arc<Self> {
        let (tx, rx) = mpsc::channel();
        Arc::new(Self {
            state: Mutex::new(State {
                footer,
                history: VecDeque::from([String::new()]),
                bytes: 0,
                panel: None,
                mode: Mode::Busy,
                phase: None,
                scroll: 0,
                anchor: None,
                cancel: CancellationToken::new(),
                suspended: 0,
                stop: false,
                generation: 1,
                input_epoch: 0,
                picker_cancelled: false,
                editor_events: VecDeque::new(),
            }),
            wake: Condvar::new(),
            io: Mutex::new(()),
            rx: Mutex::new(rx),
            tx,
        })
    }
    fn change(&self, f: impl FnOnce(&mut State)) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut s);
        s.generation = s.generation.wrapping_add(1);
        self.wake.notify_all();
    }
    pub fn set_panel(&self, panel: Panel) {
        self.change(|s| {
            if s.mode != panel.mode {
                s.picker_cancelled = false;
            }
            if s.mode != panel.mode && panel.mode != Mode::Editor {
                s.input_epoch = s.input_epoch.wrapping_add(1);
            }
            s.mode = panel.mode;
            s.phase = None;
            s.panel = Some(panel);
        });
    }
    pub fn clear_panel(&self) {
        self.change(|s| {
            s.panel = None;
            s.picker_cancelled = false;
            s.mode = if s.mode == Mode::Approval {
                Mode::Busy
            } else {
                Mode::Transition
            };
        });
    }
    pub fn event(&self) -> io::Result<Event> {
        loop {
            {
                let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
                if s.mode == Mode::Editor
                    && let Some(event) = s.editor_events.pop_front()
                {
                    return Ok(event);
                }
            }
            let input = self
                .rx
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .recv()
                .map_err(|_| io::Error::new(io::ErrorKind::UnexpectedEof, "closed"))??;
            let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if input.mode == Mode::Editor && s.mode != Mode::Editor {
                if s.editor_events.len() < 65_536 {
                    s.editor_events.push_back(input.event);
                }
                continue;
            }
            if input.mode == s.mode && (input.mode == Mode::Editor || input.epoch == s.input_epoch)
            {
                return Ok(input.event);
            }
        }
    }
    pub fn set_footer(&self, footer: Footer) {
        self.change(|s| s.footer = footer);
    }
    pub fn append(&self, text: &str) {
        let text = ui::safe(text);
        self.change(|s| {
            for part in text.split_inclusive('\n') {
                if s.history.is_empty() {
                    s.history.push_back(String::new());
                }
                let content = part.strip_suffix('\n').unwrap_or(part);
                s.history.back_mut().unwrap().push_str(content);
                s.bytes = s.bytes.saturating_add(content.len());
                if s.history.back().is_some_and(|line| line.len() > 131_072) {
                    let last = s.history.back_mut().unwrap();
                    let mut at = last.len() - 65_536;
                    while !last.is_char_boundary(at) {
                        at += 1;
                    }
                    last.drain(..at);
                    last.insert_str(0, "[…сокращено на экране…] ");
                    s.bytes = s.bytes.saturating_sub(at);
                }
                if part.ends_with('\n') {
                    s.history.push_back(String::new());
                }
            }
            while (s.bytes > 2 * 1024 * 1024 || s.history.len() > 10_000) && s.history.len() > 1 {
                if let Some(old) = s.history.pop_front() {
                    s.bytes = s.bytes.saturating_sub(old.len());
                }
            }
        });
    }
    pub fn line(&self, text: &str) {
        self.append(&format!("{text}\n"));
    }
    pub fn busy(&self, label: &str) {
        self.change(|s| {
            s.mode = Mode::Busy;
            s.panel = None;
            s.phase = Some((flat(label), Instant::now()));
        });
    }
    pub fn pause(&self) {
        self.change(|s| s.phase = None);
    }
    pub fn bind_cancel(&self, token: CancellationToken) {
        self.change(|s| s.cancel = token);
    }
    pub fn clear_history(&self) {
        self.change(|s| {
            s.history = VecDeque::from([String::new()]);
            s.bytes = 0;
            s.scroll = 0;
            s.anchor = None;
        });
    }
    pub fn usage(&self, input: u64, output: u64) {
        self.change(|s| {
            s.footer.input_tokens = s.footer.input_tokens.saturating_add(input);
            s.footer.output_tokens = s.footer.output_tokens.saturating_add(output);
        });
    }
    pub fn follow_tail(&self) {
        self.change(|s| {
            s.scroll = 0;
            s.anchor = None;
        });
    }
    pub fn context(&self, chars: usize) {
        self.change(|s| s.footer.context_chars = chars);
    }
    pub fn approve(&self, preview: &str) -> Result<crate::ui::Approval> {
        self.line(&format!("\nПодтверждение действия:\n{}", ui::safe(preview)));
        self.change(|s| {
            s.scroll = 0;
            s.anchor = None;
        });
        let mut allow = false;
        let result = (|| -> Result<crate::ui::Approval> {
            loop {
                self.set_panel(Panel {
                    rows: vec![
                        "╭ Подтверждение действия ─────────────────────".into(),
                        format!(
                            "│ {} Отклонить    {} Разрешить один раз",
                            if allow { " " } else { "›" },
                            if allow { "›" } else { " " }
                        ),
                        "╰ y — разрешить · n/Esc — нет · Enter — выбранное".into(),
                    ],
                    styles: vec![Paint::Border, Paint::Selected, Paint::Muted],
                    cursor: None,
                    mode: Mode::Approval,
                });
                match self.event()? {
                    Event::Key(k) if k.kind != KeyEventKind::Release => match (k.code, k.modifiers)
                    {
                        (KeyCode::Char('c'), m) if m.contains(KeyModifiers::CONTROL) => {
                            return Ok(ui::Approval::Cancel);
                        }
                        (KeyCode::Char('y' | 'Y' | 'д' | 'Д'), _) => {
                            return Ok(ui::Approval::Yes);
                        }
                        (KeyCode::Char('n' | 'N' | 'н' | 'Н') | KeyCode::Esc, _) => {
                            return Ok(ui::Approval::No);
                        }
                        (
                            KeyCode::Left
                            | KeyCode::Right
                            | KeyCode::Up
                            | KeyCode::Down
                            | KeyCode::Tab,
                            _,
                        ) => allow = !allow,
                        (KeyCode::Enter, _) => {
                            return Ok(if allow {
                                ui::Approval::Yes
                            } else {
                                ui::Approval::No
                            });
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
        })();
        self.clear_panel();
        result
    }
    #[cfg(test)]
    pub(crate) fn test_screen() -> Arc<Self> {
        Self::new(Footer {
            model: "test-model".into(),
            provider: "custom".into(),
            effort: "auto".into(),
            permissions: "ask".into(),
            plan: false,
            context_chars: 0,
            input_tokens: 0,
            output_tokens: 0,
            workspace: "project".into(),
        })
    }
    #[cfg(test)]
    pub(crate) fn history_text(&self) -> String {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .history
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    }
}
fn flat(text: &str) -> String {
    ui::safe(text).replace('\n', "\\n").replace('\t', "    ")
}
fn clip(text: &str, width: usize) -> String {
    let mut out = String::new();
    let mut cells = 0;
    for g in text.graphemes(true) {
        let w = UnicodeWidthStr::width(g);
        if cells + w > width {
            break;
        }
        out.push_str(g);
        cells += w;
    }
    out
}
fn wrap(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![String::new()];
    }
    let text = flat(text);
    let mut result = vec![];
    let mut row = String::new();
    let mut cells = 0;
    for g in text.graphemes(true) {
        let w = UnicodeWidthStr::width(g);
        if cells + w > width && !row.is_empty() {
            result.push(std::mem::take(&mut row));
            cells = 0;
        }
        if w <= width {
            row.push_str(g);
            cells += w;
        }
    }
    result.push(row);
    result
}
fn num(n: u64) -> String {
    crate::presentation::number(n)
}
fn status(footer: &Footer, width: usize, scroll: usize) -> Vec<(String, Paint)> {
    let permission = &footer.permissions;
    let mode = if footer.plan {
        "ПЛАН"
    } else {
        "РАБОТА"
    };
    let tail = format!(
        " · {} · {} · {}",
        footer.provider, footer.effort, permission
    );
    let model = clip(
        &flat(&footer.model),
        width.saturating_sub(UnicodeWidthStr::width(tail.as_str()) + mode.len() + 3),
    );
    let first = if width >= 54 {
        format!("{model}{tail} · {mode}")
    } else {
        format!(
            "{} · {} · {} · {}",
            clip(&flat(&footer.model), width.saturating_sub(24)),
            footer.effort,
            permission,
            mode
        )
    };
    let percent = footer.context_chars.saturating_mul(100) / 180_000;
    let filled = (percent.min(100) / 10).min(10);
    let meter = format!("{}{}", "█".repeat(filled), "░".repeat(10 - filled));
    let second = if width >= 78 {
        format!(
            "Контекст [{meter}] {percent}% лок. · ↑{} ↓{} ток. · {}",
            num(footer.input_tokens),
            num(footer.output_tokens),
            if scroll == 0 {
                "PgUp/PgDn история".into()
            } else {
                format!("↑{scroll} · Ctrl+End вниз")
            }
        )
    } else {
        format!(
            "Контекст {percent}% лок. · ↑{} ↓{}",
            num(footer.input_tokens),
            num(footer.output_tokens)
        )
    };
    vec![
        (clip(&flat(&first), width), Paint::Normal),
        (clip(&second, width), Paint::Muted),
    ]
}
#[derive(Debug)]
struct Frame {
    rows: Vec<(String, Paint)>,
    cursor: Option<(usize, usize)>,
}
fn compose(s: &State, width: u16, height: u16) -> Frame {
    let width = usize::from(width.saturating_sub(1));
    let height = usize::from(height.max(1));
    let footer_count = footer_rows(height);
    let mut panel = s.panel.clone().unwrap_or_else(|| {
        let label = s
            .phase
            .as_ref()
            .map(|(label, since)| {
                let spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
                format!(
                    "{} {label} · {:.1}s",
                    spinner[(since.elapsed().as_millis() / 90 % 10) as usize],
                    since.elapsed().as_secs_f64()
                )
            })
            .unwrap_or_else(|| {
                if s.mode == Mode::Busy {
                    "Получаю ответ… · Esc — отменить".into()
                } else {
                    "Готовлю поле ввода…".into()
                }
            });
        let title = clip(" rcode ", width.saturating_sub(2));
        let hint = clip(
            " Esc/Ctrl+C — прервать · PgUp/PgDn — история ",
            width.saturating_sub(2),
        );
        let content = clip(&flat(&label), width.saturating_sub(4));
        Panel {
            rows: vec![
                format!(
                    "╭{title}{}╮",
                    "─".repeat(width.saturating_sub(2 + UnicodeWidthStr::width(title.as_str())))
                ),
                format!(
                    "│ {content}{} │",
                    " ".repeat(width.saturating_sub(4 + UnicodeWidthStr::width(content.as_str())))
                ),
                format!(
                    "╰{hint}{}╯",
                    "─".repeat(width.saturating_sub(2 + UnicodeWidthStr::width(hint.as_str())))
                ),
            ],
            styles: vec![Paint::Border, Paint::Normal, Paint::Muted],
            cursor: None,
            mode: Mode::Busy,
        }
    });
    let available = height.saturating_sub(footer_count);
    let panel_count = panel.rows.len().min(available);
    let panel_offset = panel.rows.len().saturating_sub(panel_count);
    let body_count = available.saturating_sub(panel_count);
    let mut rows = vec![(String::new(), Paint::Normal); height];
    let mut history = Vec::new();
    for line in &s.history {
        history.extend(wrap(line, width));
    }
    // A trailing open line is a cursor position, not another transcript row.
    if history.last().is_some_and(String::is_empty) && history.len() > 1 {
        history.pop();
    }
    let maximum = history.len().saturating_sub(body_count);
    let start = s
        .anchor
        .map(|a| a.min(maximum))
        .unwrap_or_else(|| maximum.saturating_sub(s.scroll.min(maximum)));
    let scroll = maximum.saturating_sub(start);
    for (i, line) in history.into_iter().skip(start).take(body_count).enumerate() {
        let paint =
            if line.starts_with("❯") || line.starts_with("✦") || line.trim_start().starts_with('●')
            {
                Paint::Border
            } else if line.starts_with("✗") || line.starts_with("Ошибка") {
                Paint::Error
            } else if line.starts_with('✓') || line.starts_with('+') {
                Paint::Success
            } else {
                Paint::Normal
            };
        rows[i] = (line, paint);
    }
    for (i, line) in panel
        .rows
        .drain(..)
        .skip(panel_offset)
        .take(panel_count)
        .enumerate()
    {
        rows[body_count + i] = (
            clip(&flat(&line), width),
            panel
                .styles
                .get(panel_offset + i)
                .copied()
                .unwrap_or_default(),
        );
    }
    let status = status(&s.footer, width, scroll);
    if footer_count == 2 {
        rows[height - 2] = status[0].clone();
        rows[height - 1] = status[1].clone();
    } else if footer_count == 1 {
        rows[height - 1] = status[0].clone();
    }
    let cursor = panel.cursor.and_then(|(row, col)| {
        if row < panel_offset || row >= panel_offset + panel_count || width == 0 {
            None
        } else {
            Some((
                body_count + row - panel_offset,
                col.min(width.saturating_sub(1)),
            ))
        }
    });
    Frame { rows, cursor }
}
fn render(frame: &Frame) -> io::Result<()> {
    let mut out = io::stdout();
    queue!(out, BeginSynchronizedUpdate, Hide)?;
    for (row, (text, paint)) in frame.rows.iter().enumerate() {
        queue!(
            out,
            MoveTo(0, row as u16),
            ResetColor,
            Clear(ClearType::CurrentLine)
        )?;
        match paint {
            Paint::Border => queue!(out, SetForegroundColor(Color::Cyan))?,
            Paint::Muted => queue!(out, SetForegroundColor(Color::Grey))?,
            Paint::Selected => queue!(
                out,
                SetBackgroundColor(Color::DarkCyan),
                SetForegroundColor(Color::White)
            )?,
            Paint::Error => queue!(out, SetForegroundColor(Color::Red))?,
            Paint::Success => queue!(out, SetForegroundColor(Color::Green))?,
            Paint::Normal => {}
        }
        queue!(out, Print(text), ResetColor)?;
    }
    if let Some((row, col)) = frame.cursor {
        queue!(out, MoveTo(col as u16, row as u16), Show)?;
    }
    queue!(out, EndSynchronizedUpdate)?;
    out.flush()
}
fn maximum_scroll(s: &State, width: u16, height: u16) -> usize {
    let width = width.saturating_sub(1) as usize;
    let height = height.max(1) as usize;
    let available = height.saturating_sub(footer_rows(height));
    let panel = s.panel.as_ref().map_or(3, |p| p.rows.len()).min(available);
    let body = available.saturating_sub(panel);
    let mut lines = s
        .history
        .iter()
        .map(|line| wrap(line, width).len())
        .sum::<usize>();
    if s.history.back().is_some_and(String::is_empty) && lines > 1 {
        lines -= 1;
    }
    lines.saturating_sub(body)
}
fn route(screen: &Screen, event: Event) {
    let mut deliver = true;
    let target;
    let epoch;
    {
        let mut s = screen.state.lock().unwrap_or_else(|e| e.into_inner());
        let defer_to_editor = s.mode == Mode::Picker && s.picker_cancelled;
        if s.mode == Mode::Picker
            && matches!(&event,Event::Key(k)if k.kind!=KeyEventKind::Release&&(k.code==KeyCode::Esc||(k.code==KeyCode::Char('c')&&k.modifiers.contains(KeyModifiers::CONTROL))))
        {
            s.picker_cancelled = true;
        }

        let (width, height) = terminal::size()
            .ok()
            .filter(|(w, h)| *w > 0 && *h > 0)
            .unwrap_or((80, 24));
        let is_scroll = matches!(
            &event,
            Event::Mouse(_)
                | Event::Resize(_, _)
                | Event::Key(KeyEvent {
                    code: KeyCode::PageUp | KeyCode::PageDown | KeyCode::Home | KeyCode::End,
                    ..
                })
        );
        if is_scroll {
            let max = maximum_scroll(&s, width, height);
            s.scroll = s
                .anchor
                .map(|a| max.saturating_sub(a))
                .unwrap_or(s.scroll.min(max));
        }
        let step = usize::from(height / 2).max(1);
        match &event {
            Event::Key(k) if k.kind != KeyEventKind::Release => {
                if s.mode == Mode::Busy
                    && (k.code == KeyCode::Esc
                        || (k.code == KeyCode::Char('c')
                            && k.modifiers.contains(KeyModifiers::CONTROL)))
                {
                    s.cancel.cancel();
                    s.phase = Some(("Прерываю…".into(), Instant::now()));
                    deliver = false;
                } else if s.mode != Mode::Picker && k.code == KeyCode::PageUp {
                    s.scroll = s.scroll.saturating_add(step).min(100_000);
                    deliver = false;
                } else if s.mode != Mode::Picker && k.code == KeyCode::PageDown {
                    s.scroll = s.scroll.saturating_sub(step);
                    deliver = false;
                } else if k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::End {
                    s.scroll = 0;
                    deliver = false;
                } else if k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Home {
                    s.scroll = 100_000;
                    deliver = false;
                } else if s.mode == Mode::Busy {
                    deliver = false;
                }
            }
            Event::Mouse(m) => {
                match m.kind {
                    MouseEventKind::ScrollUp => s.scroll = s.scroll.saturating_add(3).min(100_000),
                    MouseEventKind::ScrollDown => s.scroll = s.scroll.saturating_sub(3),
                    _ => {}
                }
                deliver = false;
            }
            _ => {}
        }
        if is_scroll {
            let max = maximum_scroll(&s, width, height);
            s.scroll = s.scroll.min(max);
            s.anchor = if s.scroll == 0 {
                None
            } else {
                Some(max - s.scroll)
            };
        }
        target = if defer_to_editor || s.mode == Mode::Transition || s.mode == Mode::Busy {
            Mode::Editor
        } else {
            s.mode
        };
        epoch = s.input_epoch;
        s.generation = s.generation.wrapping_add(1);
        screen.wake.notify_all();
    }
    if deliver {
        let _ = screen.tx.send(Ok(Inbound {
            event,
            mode: target,
            epoch,
        }));
    }
}
pub fn start(footer: Footer) -> Result<SessionGuard> {
    if current().is_some() {
        bail!("Терминальный экран уже открыт");
    }
    let screen = Screen::new(footer);
    terminal::enable_raw_mode()?;
    if let Err(e) = execute!(
        io::stdout(),
        EnterAlternateScreen,
        EnableBracketedPaste,
        EnableMouseCapture,
        Hide,
        Clear(ClearType::All)
    ) {
        let _ = terminal::disable_raw_mode();
        let _ = execute!(
            io::stdout(),
            DisableMouseCapture,
            DisableBracketedPaste,
            Show,
            LeaveAlternateScreen
        );
        return Err(e.into());
    }
    *active().lock().unwrap_or_else(|e| e.into_inner()) = Some(screen.clone());
    let mut guard = SessionGuard {
        screen: screen.clone(),
        workers: vec![],
    };
    let draw = screen.clone();
    guard.workers.push(
        thread::Builder::new()
            .name("rcode-screen".into())
            .spawn(move || {
                let mut generation = 0;
                let mut size = (0, 0);
                let mut tick = Instant::now();
                loop {
                    {
                        let s = draw.state.lock().unwrap_or_else(|e| e.into_inner());
                        if s.stop {
                            break;
                        }
                        let _ = draw
                            .wake
                            .wait_timeout(s, Duration::from_millis(35))
                            .unwrap_or_else(|e| e.into_inner());
                    }
                    let _io = draw.io.lock().unwrap_or_else(|e| e.into_inner());
                    let s = draw.state.lock().unwrap_or_else(|e| e.into_inner());
                    if s.stop {
                        break;
                    }
                    if s.suspended > 0 {
                        continue;
                    }
                    let new_size = terminal::size().unwrap_or((80, 24));
                    let animated = s.phase.is_some() && tick.elapsed() > Duration::from_millis(90);
                    if s.generation != generation || new_size != size || animated {
                        let frame = compose(&s, new_size.0, new_size.1);
                        generation = s.generation;
                        size = new_size;
                        drop(s);
                        if render(&frame).is_err() {
                            break;
                        }
                        tick = Instant::now();
                    }
                }
            })?,
    );
    let input = screen.clone();
    guard.workers.push(
        thread::Builder::new()
            .name("rcode-input".into())
            .spawn(move || {
                loop {
                    {
                        let _io = input.io.lock().unwrap_or_else(|e| e.into_inner());
                        let s = input.state.lock().unwrap_or_else(|e| e.into_inner());
                        if s.stop {
                            break;
                        }
                        let suspended = s.suspended > 0;
                        drop(s);
                        if !suspended {
                            match event::poll(Duration::from_millis(15)) {
                                Ok(true) => match event::read() {
                                    Ok(e) => route(&input, e),
                                    Err(e) => {
                                        let _ = input.tx.send(Err(e));
                                        break;
                                    }
                                },
                                Ok(false) => {}
                                Err(e) => {
                                    let _ = input.tx.send(Err(e));
                                    break;
                                }
                            }
                        }
                    }
                    thread::sleep(Duration::from_millis(1));
                }
            })?,
    );
    Ok(guard)
}
impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.screen.change(|s| {
            s.stop = true;
            s.cancel.cancel();
        });
        for t in self.workers.drain(..) {
            let _ = t.join();
        }
        let _io = self.screen.io.lock().unwrap_or_else(|e| e.into_inner());
        *active().lock().unwrap_or_else(|e| e.into_inner()) = None;
        let _ = execute!(
            io::stdout(),
            EndSynchronizedUpdate,
            DisableMouseCapture,
            DisableBracketedPaste,
            ResetColor,
            Show,
            LeaveAlternateScreen
        );
        let _ = terminal::disable_raw_mode();
        let _ = io::stdout().flush();
    }
}
pub fn suspend() -> Result<Suspended> {
    let Some(screen) = current() else {
        return Ok(Suspended { screen: None });
    };
    {
        let _io = screen.io.lock().unwrap_or_else(|e| e.into_inner());
        let mut s = screen.state.lock().unwrap_or_else(|e| e.into_inner());
        s.suspended += 1;
        if s.suspended == 1 {
            let result = (|| -> io::Result<()> {
                execute!(
                    io::stdout(),
                    DisableMouseCapture,
                    DisableBracketedPaste,
                    ResetColor,
                    Show,
                    LeaveAlternateScreen
                )?;
                terminal::disable_raw_mode()
            })();
            if let Err(error) = result {
                s.suspended = 0;
                let _ = terminal::enable_raw_mode();
                let _ = execute!(
                    io::stdout(),
                    EnterAlternateScreen,
                    EnableBracketedPaste,
                    EnableMouseCapture,
                    Hide
                );
                s.generation = s.generation.wrapping_add(1);
                screen.wake.notify_all();
                return Err(error.into());
            }
        }
    }
    Ok(Suspended {
        screen: Some(screen),
    })
}
impl Drop for Suspended {
    fn drop(&mut self) {
        if let Some(screen) = &self.screen {
            let _io = screen.io.lock().unwrap_or_else(|e| e.into_inner());
            let mut s = screen.state.lock().unwrap_or_else(|e| e.into_inner());
            s.suspended = s.suspended.saturating_sub(1);
            if s.suspended == 0 && !s.stop {
                let _ = terminal::enable_raw_mode();
                let _ = execute!(
                    io::stdout(),
                    EnterAlternateScreen,
                    EnableBracketedPaste,
                    EnableMouseCapture,
                    Hide,
                    Clear(ClearType::All)
                );
                s.generation = s.generation.wrapping_add(1);
                screen.wake.notify_all();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn editor() -> Panel {
        Panel {
            rows: vec!["╭ rcode".into(), "│ ".into(), "╰────".into()],
            styles: vec![Paint::Border, Paint::Normal, Paint::Border],
            cursor: Some((1, 2)),
            mode: Mode::Editor,
        }
    }
    #[test]
    fn footer_is_on_last_rows_and_editor_cursor_above_it() {
        for (w, h) in [(80, 24), (140, 28), (36, 10)] {
            let screen = Screen::test_screen();
            screen.set_panel(editor());
            screen.line("Welcome");
            let s = screen.state.lock().unwrap();
            let frame = compose(&s, w, h);
            assert_eq!(frame.rows.len(), h as usize);
            assert!(frame.rows[h as usize - 1].0.contains("Контекст"));
            assert!(frame.rows[h as usize - 2].0.contains("ask"));
            assert_eq!(frame.cursor.unwrap().0, h as usize - 4);
            assert_eq!(frame.rows[0].0, "Welcome");
        }
    }
    #[test]
    fn stream_and_busy_never_overwrite_footer() {
        let screen = Screen::test_screen();
        screen.busy("Ожидаю API");
        for i in 0..100 {
            screen.line(&format!("line {i}"));
        }
        screen.append("partial");
        let s = screen.state.lock().unwrap();
        let frame = compose(&s, 80, 24);
        assert!(frame.rows[23].0.contains("Контекст"));
        assert!(frame.rows[..19].iter().any(|r| r.0 == "partial"));
        assert!(frame.rows[20].0.contains("Ожидаю API"));
        assert!(frame.cursor.is_none());
    }
    #[test]
    fn history_scroll_and_unicode_resize_preserve_anchors() {
        let screen = Screen::test_screen();
        screen.set_panel(editor());
        for i in 0..100 {
            screen.line(&format!("Строка {i} 世界"));
        }
        screen.change(|s| s.scroll = 50);
        for (w, h) in [(80, 24), (36, 10), (4, 3), (1, 1), (140, 28)] {
            let s = screen.state.lock().unwrap();
            let f = compose(&s, w, h);
            assert_eq!(f.rows.len(), h as usize);
            for row in &f.rows {
                assert!(UnicodeWidthStr::width(row.0.as_str()) <= w.saturating_sub(1) as usize);
            }
            if h >= 6 {
                assert!(f.rows[h as usize - 1].0.contains("Контекст"));
            }
        }
        assert!(screen.history_text().contains("Строка 0"));
    }
    #[test]
    fn busy_keyboard_cancels_but_menu_control_c_is_delivered() {
        let screen = Screen::test_screen();
        let token = CancellationToken::new();
        screen.bind_cancel(token.clone());
        screen.busy("run");
        route(
            &screen,
            Event::Key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
        );
        assert!(token.is_cancelled());
        let token = CancellationToken::new();
        screen.bind_cancel(token.clone());
        screen.set_panel(Panel {
            mode: Mode::Picker,
            ..editor()
        });
        route(
            &screen,
            Event::Key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
        );
        assert!(!token.is_cancelled());
        assert!(matches!(screen.event().unwrap(), Event::Key(_)));
    }
    #[test]
    fn control_sequences_are_data_not_terminal_commands() {
        let screen = Screen::test_screen();
        screen.line("x\x1b[2J\x1b]0;bad\x07\u{202e}");
        let f = compose(&screen.state.lock().unwrap(), 80, 24);
        assert!(
            f.rows.iter().all(|r| !r.0.contains('\x1b')
                && !r.0.contains('\x07')
                && !r.0.contains('\u{202e}'))
        );
    }
    #[test]
    fn scrolling_down_after_home_moves_immediately() {
        let screen = Screen::test_screen();
        screen.set_panel(editor());
        for i in 0..100 {
            screen.line(&format!("line {i}"));
        }
        route(
            &screen,
            Event::Key(KeyEvent::new(KeyCode::Home, KeyModifiers::CONTROL)),
        );
        let before = compose(&screen.state.lock().unwrap(), 80, 24).rows[0]
            .0
            .clone();
        assert_eq!(before, "line 0");
        route(
            &screen,
            Event::Key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE)),
        );
        let after = compose(&screen.state.lock().unwrap(), 80, 24).rows[0]
            .0
            .clone();
        assert_ne!(after, before);
    }
    #[test]
    fn reading_history_stays_in_place_during_streaming() {
        let screen = Screen::test_screen();
        screen.set_panel(editor());
        for i in 0..100 {
            screen.line(&format!("line {i}"));
        }
        route(
            &screen,
            Event::Key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE)),
        );
        let before = compose(&screen.state.lock().unwrap(), 80, 24).rows[0]
            .0
            .clone();
        screen.line("incoming answer");
        let after = compose(&screen.state.lock().unwrap(), 80, 24).rows[0]
            .0
            .clone();
        assert_eq!(after, before);
    }
    #[test]
    fn transition_keystrokes_survive_without_approving_later_dialogs() {
        let screen = Screen::test_screen();
        screen.set_panel(Panel {
            mode: Mode::Picker,
            ..editor()
        });
        screen.clear_panel();
        route(
            &screen,
            Event::Key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE)),
        );
        screen.set_panel(Panel {
            mode: Mode::Approval,
            ..editor()
        });
        route(
            &screen,
            Event::Key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE)),
        );
        assert_eq!(
            screen.event().unwrap(),
            Event::Key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE))
        );
        screen.clear_panel();
        screen.set_panel(editor());
        assert_eq!(
            screen.event().unwrap(),
            Event::Key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE))
        );
    }
    #[test]
    fn keys_after_picker_cancel_are_kept_even_before_cancel_is_consumed() {
        let screen = Screen::test_screen();
        screen.set_panel(Panel {
            mode: Mode::Picker,
            ..editor()
        });
        route(
            &screen,
            Event::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
        );
        route(
            &screen,
            Event::Key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE)),
        );
        assert_eq!(
            screen.event().unwrap(),
            Event::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
        );
        screen.clear_panel();
        screen.set_panel(editor());
        route(
            &screen,
            Event::Key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE)),
        );
        assert_eq!(
            screen.event().unwrap(),
            Event::Key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE))
        );
    }
}
