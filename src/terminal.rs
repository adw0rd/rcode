//! Ввод и меню в общем viewport с резервным режимом scrollback.

use anyhow::{Result, bail};
use crossterm::{
    cursor::{Hide, MoveDown, MoveToColumn, MoveUp, Show},
    event::{
        self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind,
        KeyModifiers,
    },
    execute, queue,
    style::{Color, Print, ResetColor, SetBackgroundColor, SetForegroundColor},
    terminal::{self, Clear, ClearType, disable_raw_mode, enable_raw_mode},
};
use std::borrow::Cow;
use std::io::{self, IsTerminal, Write};
use std::sync::{Arc, mpsc};
use std::time::Duration;
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

pub(crate) const MAX_INPUT: usize = 65_536;
const CONTEXT_BUDGET: usize = 180_000;
pub(crate) const MAX_HISTORY: usize = 1_000;

#[derive(Clone, Debug)]
pub struct Footer {
    pub model: String,
    pub provider: String,
    pub effort: String,
    pub permissions: String,
    pub plan: bool,
    pub context_chars: usize,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub workspace: String,
}

pub struct CommandSpec {
    pub name: &'static str,
    pub description: &'static str,
}

pub const COMMANDS: &[CommandSpec] = &[
    CommandSpec {
        name: "/model",
        description: "Выбрать модель",
    },
    CommandSpec {
        name: "/provider",
        description: "Выбрать провайдера",
    },
    CommandSpec {
        name: "/effort",
        description: "Настроить глубину рассуждений",
    },
    CommandSpec {
        name: "/permissions",
        description: "Настроить разрешения инструментов",
    },
    CommandSpec {
        name: "/resume",
        description: "Продолжить сохранённую сессию",
    },
    CommandSpec {
        name: "/agents",
        description: "Субагенты: задачи, результаты и токены",
    },
    CommandSpec {
        name: "/context",
        description: "Использование контекста",
    },
    CommandSpec {
        name: "/cost",
        description: "Расход токенов и стоимость",
    },
    CommandSpec {
        name: "/balance",
        description: "Баланс провайдера и лимиты ключа",
    },
    CommandSpec {
        name: "/status",
        description: "Модель, настройки и сессия",
    },
    CommandSpec {
        name: "/plan",
        description: "Переключить режим планирования",
    },
    CommandSpec {
        name: "/diff",
        description: "Показать изменения файлов",
    },
    CommandSpec {
        name: "/undo",
        description: "Отменить файловые изменения",
    },
    CommandSpec {
        name: "/compact",
        description: "Сжать историю диалога",
    },
    CommandSpec {
        name: "/export",
        description: "Сохранить диалог в Markdown",
    },
    CommandSpec {
        name: "/attach",
        description: "Приложить изображение PNG/JPEG/TIFF",
    },
    CommandSpec {
        name: "/clear",
        description: "Начать новый диалог",
    },
    CommandSpec {
        name: "/connect",
        description: "Подключить провайдера",
    },
    CommandSpec {
        name: "/help",
        description: "Команды и сочетания клавиш",
    },
    CommandSpec {
        name: "/exit",
        description: "Завершить работу",
    },
];

#[derive(Debug, PartialEq, Eq)]
pub enum Input {
    Submit(String),
    Interrupt,
    Eof,
}

#[derive(Default)]
pub struct Editor {
    history: Vec<String>,
}

impl Editor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn read_plain(&self, prompt: &str) -> Result<Input> {
        // Readline owns Unix signal handlers while alive. Drop it before any
        // API wait so Ctrl+C reaches Tokio; the shared input history lives here.
        let mut editor = crate::ui::editor()?;
        for entry in &self.history {
            let _ = editor.add_history_entry(entry.as_str());
        }
        match editor.readline(prompt) {
            Ok(text) => Ok(Input::Submit(text)),
            Err(rustyline::error::ReadlineError::Interrupted) => Ok(Input::Interrupt),
            Err(rustyline::error::ReadlineError::Eof) => Ok(Input::Eof),
            Err(error) => Err(error.into()),
        }
    }

    pub fn read(&mut self, footer: &Footer) -> Result<Input> {
        if !supported() {
            bail!("Терминальный редактор требует интерактивный терминал");
        }
        if let Some(screen) = crate::screen::current() {
            screen.set_footer(footer.clone());
        }
        let _guard = TerminalGuard::enter()?;
        let mut frame = InlineFrame::new(crate::screen::Mode::Editor);
        let mut state = ReadState::default();
        loop {
            let (width, height) = terminal::size()?;
            let view = if frame.fullscreen() {
                viewport_editor_view(&state, footer, width, height)
            } else {
                editor_view(&state, footer, width, height)
            };
            frame.draw(&view, width)?;
            match frame.event()? {
                Event::Key(key) => {
                    if let Some(input) = state.key(key, &self.history) {
                        return Ok(input);
                    }
                }
                Event::Paste(text) => {
                    state.buffer.insert(&text);
                    state.edited();
                }
                Event::Resize(_, _) => frame.resized()?,
                _ => {}
            }
        }
    }

    pub fn add_history(&mut self, text: &str) {
        if text.trim().is_empty() || self.history.last().is_some_and(|last| last == text) {
            return;
        }
        if self.history.len() == MAX_HISTORY {
            self.history.remove(0);
        }
        let mut buffer = Buffer::default();
        buffer.insert(text);
        self.history.push(buffer.text);
    }
}

#[derive(Clone)]
pub struct Choice {
    pub label: String,
    pub detail: String,
    pub enabled: bool,
}

pub fn supported() -> bool {
    io::stdin().is_terminal()
        && io::stdout().is_terminal()
        && io::stderr().is_terminal()
        && std::env::var("TERM").ok().is_none_or(|term| term != "dumb")
}

pub fn select(title: &str, choices: &[Choice], current: usize) -> Result<Option<usize>> {
    select_with_updates(title, choices, current, None)
}

pub(crate) fn select_with_updates(
    title: &str,
    choices: &[Choice],
    current: usize,
    updates: Option<&mpsc::Receiver<(usize, String)>>,
) -> Result<Option<usize>> {
    if !supported() {
        bail!("Меню выбора требует интерактивный терминал");
    }
    if choices.is_empty() {
        return Ok(None);
    }
    let _guard = TerminalGuard::enter()?;
    let mut frame = InlineFrame::new(crate::screen::Mode::Picker);
    let mut picker = Picker::new(choices, current);
    let mut dirty = true;
    loop {
        if let Some(updates) = updates {
            for (index, detail) in updates.try_iter() {
                picker.update_detail(index, detail);
                dirty = true;
            }
        }
        let (width, height) = terminal::size()?;
        if dirty {
            let view = if frame.fullscreen() {
                viewport_picker_view(title, &picker, width, height)
            } else {
                picker_view(title, &picker, width, height)
            };
            frame.draw(&view, width)?;
            dirty = false;
        }
        let input = if updates.is_some() {
            frame.event_timeout(Duration::from_millis(100))?
        } else {
            Some(frame.event()?)
        };
        let Some(input) = input else { continue };
        dirty = true;
        let page = picker_page(frame.panel_height(height));
        match input {
            Event::Key(key) if key.kind != KeyEventKind::Release => {
                let control = key.modifiers.contains(KeyModifiers::CONTROL);
                match key.code {
                    KeyCode::Esc => return Ok(None),
                    KeyCode::Char('c' | 'd') if control => return Ok(None),
                    KeyCode::Enter => {
                        if let Some(index) = picker.choice() {
                            return Ok(Some(index));
                        }
                    }
                    KeyCode::Up | KeyCode::BackTab => picker.navigate(-1),
                    KeyCode::Down | KeyCode::Tab => picker.navigate(1),
                    KeyCode::PageUp => picker.navigate(-(page as isize)),
                    KeyCode::PageDown => picker.navigate(page as isize),
                    KeyCode::Backspace => {
                        picker.query.backspace();
                        picker.filter();
                    }
                    KeyCode::Char('u') if control => {
                        picker.query = Buffer::default();
                        picker.filter();
                    }
                    KeyCode::Char(ch) if !control && !key.modifiers.contains(KeyModifiers::ALT) => {
                        picker.query.insert(&ch.to_string());
                        picker.filter();
                    }
                    _ => {}
                }
            }
            Event::Paste(text) => {
                picker.query.insert(&text.replace(['\n', '\r'], " "));
                picker.filter();
            }
            Event::Resize(_, _) => frame.resized()?,
            _ => {}
        }
    }
}

#[derive(Default)]
struct Buffer {
    text: String,
    cursor: usize,
}

impl Buffer {
    fn insert(&mut self, text: &str) {
        let available = MAX_INPUT.saturating_sub(self.text.len());
        let mut bytes = 0;
        for grapheme in text.graphemes(true) {
            if bytes + grapheme.len() > available {
                break;
            }
            bytes += grapheme.len();
        }
        self.text.insert_str(self.cursor, &text[..bytes]);
        self.cursor += bytes;
        self.normalize_cursor();
    }

    // Вставка и удаление разделителя могут объединить соседние графемы.
    fn normalize_cursor(&mut self) {
        self.cursor = self
            .text
            .grapheme_indices(true)
            .map(|(index, _)| index)
            .chain(std::iter::once(self.text.len()))
            .find(|&index| index >= self.cursor)
            .unwrap_or(self.text.len());
    }

    fn left(&mut self) {
        self.cursor = self.text[..self.cursor]
            .grapheme_indices(true)
            .next_back()
            .map_or(0, |(index, _)| index);
    }

    fn right(&mut self) {
        if let Some(grapheme) = self.text[self.cursor..].graphemes(true).next() {
            self.cursor += grapheme.len();
        }
    }

    fn backspace(&mut self) {
        let end = self.cursor;
        self.left();
        self.text.drain(self.cursor..end);
        self.normalize_cursor();
    }

    fn delete(&mut self) {
        let start = self.cursor;
        self.right();
        self.text.drain(start..self.cursor);
        self.cursor = start;
        self.normalize_cursor();
    }

    fn delete_word(&mut self) {
        let end = self.cursor;
        while self.cursor > 0
            && self.text[..self.cursor]
                .graphemes(true)
                .next_back()
                .is_some_and(|g| g.chars().all(char::is_whitespace))
        {
            self.left();
        }
        while self.cursor > 0
            && self.text[..self.cursor]
                .graphemes(true)
                .next_back()
                .is_some_and(|g| !g.chars().all(char::is_whitespace))
        {
            self.left();
        }
        self.text.drain(self.cursor..end);
        self.normalize_cursor();
    }

    fn home(&mut self) {
        self.cursor = self.text[..self.cursor]
            .rfind('\n')
            .map_or(0, |index| index + 1);
    }

    fn end(&mut self) {
        self.cursor += self.text[self.cursor..]
            .find('\n')
            .unwrap_or(self.text.len() - self.cursor);
    }

    fn kill_end(&mut self) {
        let start = self.cursor;
        self.end();
        let end = if self.cursor == start && self.text.as_bytes().get(start) == Some(&b'\n') {
            start + 1
        } else {
            self.cursor
        };
        self.text.drain(start..end);
        self.cursor = start;
        self.normalize_cursor();
    }

    fn vertical(&mut self, down: bool) {
        let start = self.text[..self.cursor]
            .rfind('\n')
            .map_or(0, |index| index + 1);
        let column = self.text[start..self.cursor].graphemes(true).count();
        let range = if down {
            let Some(end) = self.text[self.cursor..].find('\n') else {
                return;
            };
            let next_start = self.cursor + end + 1;
            let next_end = next_start
                + self.text[next_start..]
                    .find('\n')
                    .unwrap_or(self.text.len() - next_start);
            next_start..next_end
        } else {
            if start == 0 {
                return;
            }
            let previous_end = start - 1;
            let previous_start = self.text[..previous_end]
                .rfind('\n')
                .map_or(0, |index| index + 1);
            previous_start..previous_end
        };
        self.cursor = range.start
            + self.text[range.clone()]
                .grapheme_indices(true)
                .nth(column)
                .map_or(range.len(), |(index, _)| index);
    }
}

#[derive(Default)]
struct ReadState {
    buffer: Buffer,
    history_index: Option<usize>,
    draft: String,
    command_index: usize,
    menu_dismissed: bool,
}

impl ReadState {
    fn key(&mut self, key: KeyEvent, history: &[String]) -> Option<Input> {
        if key.kind == KeyEventKind::Release {
            return None;
        }
        let control = key.modifiers.contains(KeyModifiers::CONTROL);
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        if control {
            match key.code {
                KeyCode::Char('c') => {
                    if self.buffer.text.is_empty() {
                        return Some(Input::Interrupt);
                    }
                    *self = Self::default();
                }
                KeyCode::Char('d') => {
                    if self.buffer.text.is_empty() {
                        return Some(Input::Eof);
                    }
                    self.buffer.delete();
                    self.edited();
                }
                KeyCode::Char('p') => self.history(history, true),
                KeyCode::Char('n') => self.history(history, false),
                KeyCode::Char('a') => self.buffer.home(),
                KeyCode::Char('e') => self.buffer.end(),
                KeyCode::Char('b') => self.buffer.left(),
                KeyCode::Char('f') => self.buffer.right(),
                KeyCode::Char('w') => {
                    self.buffer.delete_word();
                    self.edited();
                }
                KeyCode::Char('u') => {
                    self.buffer.text.drain(..self.buffer.cursor);
                    self.buffer.cursor = 0;
                    self.edited();
                }
                KeyCode::Char('k') => {
                    self.buffer.kill_end();
                    self.edited();
                }
                KeyCode::Char('j') => {
                    self.buffer.insert("\n");
                    self.edited();
                }
                _ => {}
            }
            return None;
        }
        match key.code {
            KeyCode::Enter if alt || key.modifiers.contains(KeyModifiers::SHIFT) => {
                self.buffer.insert("\n");
                self.edited();
            }
            KeyCode::Enter => {
                if !self.commands().is_empty() {
                    self.complete();
                }
                return Some(Input::Submit(self.buffer.text.clone()));
            }
            KeyCode::Tab => self.complete(),
            KeyCode::Esc => self.menu_dismissed = true,
            KeyCode::Up | KeyCode::Down => {
                let down = key.code == KeyCode::Down;
                let commands = self.commands();
                if !commands.is_empty() {
                    self.command_index = if down {
                        (self.command_index + 1) % commands.len()
                    } else {
                        (self.command_index + commands.len() - 1) % commands.len()
                    };
                } else if self.buffer.text.contains('\n') {
                    self.buffer.vertical(down);
                } else {
                    self.history(history, !down);
                }
            }
            KeyCode::Left => self.buffer.left(),
            KeyCode::Right => self.buffer.right(),
            KeyCode::Home => self.buffer.home(),
            KeyCode::End => self.buffer.end(),
            KeyCode::Backspace => {
                self.buffer.backspace();
                self.edited();
            }
            KeyCode::Delete => {
                self.buffer.delete();
                self.edited();
            }
            KeyCode::Char(ch) if !alt => {
                self.buffer.insert(&ch.to_string());
                self.edited();
            }
            _ => {}
        }
        None
    }

    fn edited(&mut self) {
        self.command_index = 0;
        self.menu_dismissed = false;
    }
    fn commands(&self) -> Vec<usize> {
        let text = self.buffer.text.as_str();
        if self.menu_dismissed || !text.starts_with('/') || text.chars().any(char::is_whitespace) {
            return vec![];
        }
        COMMANDS
            .iter()
            .enumerate()
            .filter_map(|(index, command)| command.name.starts_with(text).then_some(index))
            .collect()
    }

    fn complete(&mut self) {
        if let Some(index) = self.commands().get(self.command_index).copied() {
            self.buffer = Buffer::default();
            self.buffer.insert(COMMANDS[index].name);
            self.menu_dismissed = true;
        }
    }

    fn history(&mut self, history: &[String], older: bool) {
        if history.is_empty() {
            return;
        }
        let next = match (self.history_index, older) {
            (None, true) => {
                self.draft = self.buffer.text.clone();
                Some(history.len() - 1)
            }
            (Some(index), true) => Some(index.saturating_sub(1)),
            (Some(index), false) if index + 1 < history.len() => Some(index + 1),
            _ => None,
        };
        let text = match next {
            Some(index) => &history[index],
            None if self.history_index.is_some() => &self.draft,
            None => return,
        };
        self.buffer = Buffer::default();
        self.buffer.insert(text);
        self.history_index = next;
        self.command_index = 0;
        self.menu_dismissed = true;
    }
}

struct Picker<'a> {
    choices: Cow<'a, [Choice]>,
    query: Buffer,
    filtered: Vec<usize>,
    selected: Option<usize>,
}

impl<'a> Picker<'a> {
    fn new(choices: &'a [Choice], current: usize) -> Self {
        let mut picker = Self {
            choices: Cow::Borrowed(choices),
            query: Buffer::default(),
            filtered: (0..choices.len()).collect(),
            selected: choices
                .get(current)
                .filter(|choice| choice.enabled)
                .map(|_| current),
        };
        if picker.selected.is_none() {
            picker.selected = picker
                .filtered
                .iter()
                .position(|&index| choices[index].enabled);
        }
        picker
    }

    fn update_detail(&mut self, index: usize, detail: String) {
        if index < self.choices.len() {
            self.choices.to_mut()[index].detail = detail;
            // Metadata must not change search results or move the user's cursor.
            // Filtering resumes when the user edits the query.
        }
    }

    fn filter(&mut self) {
        let previous = self.choice();
        let query = flat(&self.query.text).to_lowercase();
        self.filtered = self
            .choices
            .iter()
            .enumerate()
            .filter_map(|(index, choice)| {
                format!("{} {}", flat(&choice.label), flat(&choice.detail))
                    .to_lowercase()
                    .contains(&query)
                    .then_some(index)
            })
            .collect();
        self.selected = previous
            .and_then(|previous| {
                self.filtered
                    .iter()
                    .position(|&index| index == previous && self.choices[index].enabled)
            })
            .or_else(|| {
                self.filtered
                    .iter()
                    .position(|&index| self.choices[index].enabled)
            });
    }

    fn navigate(&mut self, delta: isize) {
        let enabled: Vec<usize> = self
            .filtered
            .iter()
            .enumerate()
            .filter_map(|(position, &index)| self.choices[index].enabled.then_some(position))
            .collect();
        if enabled.is_empty() {
            self.selected = None;
            return;
        }
        let current = self
            .selected
            .and_then(|position| enabled.iter().position(|&index| index == position))
            .unwrap_or(0);
        let next = (current as isize + delta).rem_euclid(enabled.len() as isize) as usize;
        self.selected = Some(enabled[next]);
    }

    fn choice(&self) -> Option<usize> {
        self.selected
            .and_then(|position| self.filtered.get(position))
            .copied()
            .filter(|&index| self.choices[index].enabled)
    }
}

struct View {
    rows: Vec<String>,
    styles: Vec<RowStyle>,
    cursor_row: usize,
    cursor_col: usize,
}

#[derive(Clone, Copy)]
enum RowStyle {
    Normal,
    Border,
    Error,
    ShellInput(usize),
    Subtle,
    Selected,
    Disabled,
}

impl View {
    fn new() -> Self {
        Self {
            rows: vec![],
            styles: vec![],
            cursor_row: 0,
            cursor_col: 0,
        }
    }

    fn push(&mut self, text: impl Into<String>, style: RowStyle, width: usize) {
        self.rows.push(clip(&text.into(), width));
        self.styles.push(style);
    }
}

fn editor_view(state: &ReadState, footer: &Footer, width: u16, height: u16) -> View {
    editor_layout(state, footer, width, height, true)
}

fn viewport_editor_view(state: &ReadState, footer: &Footer, width: u16, height: u16) -> View {
    editor_layout(
        state,
        footer,
        width,
        crate::screen::panel_height(height),
        false,
    )
}

fn editor_layout(
    state: &ReadState,
    footer: &Footer,
    width: u16,
    height: u16,
    inline_footer: bool,
) -> View {
    // Последняя ячейка остаётся свободной: терминал не создаёт неявную строку.
    let width = usize::from(width.saturating_sub(1));
    let height = usize::from(height.max(1));
    let framed = width >= 6 && height >= if inline_footer { 4 } else { 3 };
    let footer_rows = if !inline_footer {
        0
    } else if framed {
        if height == 4 {
            1
        } else if height == 5 {
            2
        } else {
            3
        }
    } else {
        (height - 1).min(2)
    };
    let shell_mode = state.buffer.text.trim_start().starts_with('!');
    let commands = state.commands();
    let menu_rows = if framed && !commands.is_empty() {
        let overhead = if inline_footer { 7 } else { 4 };
        commands.len().min(8).min(height.saturating_sub(overhead))
    } else {
        0
    };
    let border_rows = if framed { 2 } else { 0 };
    let input_rows = height
        .saturating_sub(footer_rows + border_rows + menu_rows + usize::from(menu_rows > 0))
        .clamp(1, 5);
    let (prefix, suffix) = if framed {
        ("│ ", " │")
    } else if width >= 3 {
        ("› ", "")
    } else {
        ("", "")
    };
    let inner_width =
        width.saturating_sub(UnicodeWidthStr::width(prefix) + UnicodeWidthStr::width(suffix));
    let input = wrapped_input(&state.buffer, inner_width);
    let shell_marker = shell_mode
        .then(|| {
            input.rows.iter().enumerate().find_map(|(index, row)| {
                let trimmed = row.trim_start();
                trimmed
                    .starts_with('!')
                    .then_some((index, prefix.len() + row.len() - trimmed.len()))
            })
        })
        .flatten();
    let end = (input.cursor_row + 1).max(input_rows).min(input.rows.len());
    let start = end.saturating_sub(input_rows);
    let mut view = View::new();
    if framed {
        let label = if shell_mode && start > 0 {
            " rcode · shell · ↑ ещё строки "
        } else if shell_mode {
            " rcode · shell "
        } else if start > 0 {
            " rcode · ↑ ещё строки "
        } else {
            " rcode "
        };
        view.push(
            border(label, width, true),
            if shell_mode {
                RowStyle::Error
            } else {
                RowStyle::Border
            },
            width,
        );
    }
    let input_start = view.rows.len();
    for (index, row) in input.rows.iter().enumerate().take(end).skip(start) {
        let padding = if framed {
            " ".repeat(inner_width.saturating_sub(UnicodeWidthStr::width(row.as_str())))
        } else {
            String::new()
        };
        view.push(
            format!("{prefix}{row}{padding}{suffix}"),
            match shell_marker {
                Some((marker_row, offset)) if marker_row == index => RowStyle::ShellInput(offset),
                _ => RowStyle::Normal,
            },
            width,
        );
    }
    view.cursor_row = input_start + input.cursor_row.saturating_sub(start);
    view.cursor_col =
        (UnicodeWidthStr::width(prefix) + input.cursor_col).min(width.saturating_sub(1));
    if framed {
        view.push(
            border(
                if shell_mode {
                    " Enter — выполнить локально "
                } else {
                    ""
                },
                width,
                false,
            ),
            if shell_mode {
                RowStyle::Error
            } else {
                RowStyle::Border
            },
            width,
        );
    }
    if menu_rows > 0 {
        view.push(
            "Команды · ↑↓ выбор · Tab дополнить · Enter выполнить",
            RowStyle::Subtle,
            width,
        );
        let selected = state.command_index.min(commands.len() - 1);
        let offset = selected.saturating_sub(menu_rows - 1);
        for (position, &index) in commands.iter().enumerate().skip(offset).take(menu_rows) {
            let command = &COMMANDS[index];
            let selected = position == selected;
            view.push(
                format!(
                    "{} {:<14} {}",
                    if selected { "›" } else { " " },
                    command.name,
                    command.description
                ),
                if selected {
                    RowStyle::Selected
                } else {
                    RowStyle::Normal
                },
                width,
            );
        }
    }
    if footer_rows > 0 {
        let mode = if footer.plan {
            "ПЛАН"
        } else {
            "РАБОТА"
        };
        let status = if width < 50 {
            format!(
                "{mode} · {} · {} · {}",
                flat(&footer.provider),
                flat(&footer.effort),
                flat(&footer.model)
            )
        } else {
            let remaining = format!(
                " · {} · {} · {} · {mode}",
                ellipsis(&flat(&footer.provider), width / 4),
                ellipsis(&flat(&footer.effort), width / 5),
                ellipsis(&flat(&footer.permissions), width / 4)
            );
            let model_width = width.saturating_sub(UnicodeWidthStr::width(remaining.as_str()));
            format!("{}{remaining}", ellipsis(&flat(&footer.model), model_width))
        };
        view.push(status, RowStyle::Subtle, width);
    }
    if footer_rows > 1 {
        let percent = footer
            .context_chars
            .saturating_mul(100)
            .checked_div(CONTEXT_BUDGET)
            .unwrap_or(0);
        let filled = percent.min(100) / 10;
        let meter = format!("{}{}", "█".repeat(filled), "░".repeat(10 - filled));
        let context = if width >= 90 {
            format!(
                "Контекст [{meter}] {percent}% · локальный {}/180 000 симв. · токены ↑{} ↓{}",
                grouped(footer.context_chars as u64),
                grouped(footer.input_tokens),
                grouped(footer.output_tokens)
            )
        } else if width >= 59 {
            format!(
                "Контекст [{meter}] {percent}% локальный · ↑{} ↓{} ток.",
                grouped(footer.input_tokens),
                grouped(footer.output_tokens)
            )
        } else {
            format!(
                "Контекст {percent}% (локальный) · ↑{} ↓{} ток.",
                grouped(footer.input_tokens),
                grouped(footer.output_tokens)
            )
        };
        view.push(context, RowStyle::Subtle, width);
    }
    if footer_rows > 2 {
        view.push(
            format!(
                "{} · / команды · Shift/Alt+Enter · Ctrl+J новая строка · Ctrl+P/N история",
                ellipsis(&flat(&footer.workspace), width / 3)
            ),
            RowStyle::Subtle,
            width,
        );
    }
    view
}

fn picker_page(height: u16) -> usize {
    usize::from(height.saturating_sub(4)).clamp(1, 8)
}

fn viewport_picker_view(title: &str, picker: &Picker<'_>, width: u16, height: u16) -> View {
    picker_view(title, picker, width, crate::screen::panel_height(height))
}

fn picker_view(title: &str, picker: &Picker<'_>, width: u16, height: u16) -> View {
    let width = usize::from(width.saturating_sub(1));
    let height = usize::from(height.max(1));
    let mut view = View::new();
    if height >= 3 {
        view.push(
            border(&format!(" {} ", flat(title)), width, true),
            RowStyle::Border,
            width,
        );
    }
    let query = flat(&picker.query.text);
    let prefix = if width >= 10 { "Поиск: " } else { "/ " };
    let query_width = width.saturating_sub(UnicodeWidthStr::width(prefix) + 1);
    let visible_query = tail(&query, query_width);
    view.cursor_row = view.rows.len();
    view.cursor_col = (UnicodeWidthStr::width(prefix)
        + UnicodeWidthStr::width(visible_query.as_str()))
    .min(width.saturating_sub(1));
    view.push(format!("{prefix}{visible_query}"), RowStyle::Normal, width);
    let remaining = height.saturating_sub(view.rows.len());
    let bottom_rows = usize::from(height >= 4) + usize::from(height >= 5);
    let item_count = remaining.saturating_sub(bottom_rows).min(8);
    if item_count > 0 {
        if picker.filtered.is_empty() {
            view.push("  Ничего не найдено", RowStyle::Subtle, width);
        } else {
            let selected = picker.selected.unwrap_or(0);
            let offset = selected.saturating_sub(item_count - 1);
            for (position, &index) in picker
                .filtered
                .iter()
                .enumerate()
                .skip(offset)
                .take(item_count)
            {
                let choice = &picker.choices[index];
                let active = picker.selected == Some(position);
                let style = if !choice.enabled {
                    RowStyle::Disabled
                } else if active {
                    RowStyle::Selected
                } else {
                    RowStyle::Normal
                };
                let unavailable = if choice.enabled {
                    ""
                } else {
                    " · недоступно"
                };
                let detail = if choice.detail.is_empty() {
                    String::new()
                } else {
                    format!(" · {}", flat(&choice.detail))
                };
                view.push(
                    format!(
                        "{} {}{detail}{unavailable}",
                        if active { "›" } else { " " },
                        flat(&choice.label)
                    ),
                    style,
                    width,
                );
            }
        }
    }
    if height >= 4 {
        view.push(border("", width, false), RowStyle::Border, width);
    }
    if height >= 5 {
        let position = picker.selected.map_or(0, |index| index + 1);
        view.push(
            format!(
                "↑↓ выбор · PgUp/PgDn · Enter принять · Esc назад · {position}/{}",
                picker.filtered.len()
            ),
            RowStyle::Subtle,
            width,
        );
    }
    view
}

struct WrappedInput {
    rows: Vec<String>,
    cursor_row: usize,
    cursor_col: usize,
}

fn wrapped_input(buffer: &Buffer, width: usize) -> WrappedInput {
    let mut result = WrappedInput {
        rows: vec![String::new()],
        cursor_row: 0,
        cursor_col: 0,
    };
    if width == 0 {
        return result;
    }
    let mut column = 0;
    for (index, grapheme) in buffer.text.grapheme_indices(true) {
        let newline = grapheme.contains('\n');
        let mut display = if newline {
            String::new()
        } else {
            crate::ui::safe(grapheme).replace('\t', "    ")
        };
        let mut cells = UnicodeWidthStr::width(display.as_str());
        if cells > width {
            display = clip(&display, width);
            if display.is_empty() {
                display.push('�');
            }
            cells = UnicodeWidthStr::width(display.as_str());
        }
        if !newline && column + cells > width {
            result.rows.push(String::new());
            column = 0;
        }
        if index == buffer.cursor {
            result.cursor_row = result.rows.len() - 1;
            result.cursor_col = column;
        }
        if newline {
            result.rows.push(String::new());
            column = 0;
        } else {
            result
                .rows
                .last_mut()
                .expect("всегда есть строка")
                .push_str(&display);
            column += cells;
        }
    }
    if buffer.cursor == buffer.text.len() {
        result.cursor_row = result.rows.len() - 1;
        result.cursor_col = column;
    }
    result
}

fn flat(text: &str) -> String {
    crate::ui::safe(text).replace(['\n', '\r', '\t'], " ")
}

fn clip(text: &str, width: usize) -> String {
    let mut result = String::new();
    let mut cells = 0;
    for grapheme in text.graphemes(true) {
        let next = UnicodeWidthStr::width(grapheme);
        if cells + next > width {
            break;
        }
        result.push_str(grapheme);
        cells += next;
    }
    result
}

fn ellipsis(text: &str, width: usize) -> String {
    if UnicodeWidthStr::width(text) <= width {
        return text.to_owned();
    }
    if width == 0 {
        return String::new();
    }
    format!("{}…", clip(text, width - 1))
}

fn tail(text: &str, width: usize) -> String {
    let mut start = text.len();
    let mut cells = 0;
    for (index, grapheme) in text.grapheme_indices(true).rev() {
        let next = UnicodeWidthStr::width(grapheme);
        if cells + next > width {
            break;
        }
        start = index;
        cells += next;
    }
    text[start..].to_owned()
}

fn border(label: &str, width: usize, top: bool) -> String {
    if width < 2 {
        return "─".repeat(width);
    }
    let label = clip(label, width - 2);
    let padding = width - 2 - UnicodeWidthStr::width(label.as_str());
    let (left, right) = if top { ('╭', '╮') } else { ('╰', '╯') };
    format!("{left}{label}{}{right}", "─".repeat(padding))
}

fn grouped(value: u64) -> String {
    let text = value.to_string();
    let mut result = String::new();
    for (index, digit) in text.chars().enumerate() {
        if index > 0 && (text.len() - index).is_multiple_of(3) {
            result.push(' ');
        }
        result.push(digit);
    }
    result
}

/// Передаёт панель общему viewport; вне него использует обычный scrollback.
struct InlineFrame {
    screen: Option<Arc<crate::screen::Screen>>,
    mode: crate::screen::Mode,
    output: io::Stdout,
    rows: usize,
    cursor_row: usize,
    width: Option<u16>,
}

impl InlineFrame {
    fn new(mode: crate::screen::Mode) -> Self {
        Self {
            screen: crate::screen::current(),
            mode,
            output: io::stdout(),
            rows: 0,
            cursor_row: 0,
            width: None,
        }
    }

    fn fullscreen(&self) -> bool {
        self.screen.is_some()
    }

    fn panel_height(&self, height: u16) -> u16 {
        if self.fullscreen() {
            crate::screen::panel_height(height)
        } else {
            height
        }
    }

    fn event(&self) -> io::Result<Event> {
        match &self.screen {
            Some(screen) => screen.event(),
            None => event::read(),
        }
    }

    fn event_timeout(&self, timeout: Duration) -> io::Result<Option<Event>> {
        match &self.screen {
            Some(screen) => screen.event_timeout(timeout),
            None if event::poll(timeout)? => event::read().map(Some),
            None => Ok(None),
        }
    }

    fn draw(&mut self, view: &View, width: u16) -> io::Result<()> {
        if let Some(screen) = &self.screen {
            use crate::screen::{Paint, Panel};
            screen.set_panel(Panel {
                rows: view.rows.clone(),
                styles: view
                    .styles
                    .iter()
                    .map(|style| match style {
                        RowStyle::Normal => Paint::Normal,
                        RowStyle::Border => Paint::Border,
                        RowStyle::Error => Paint::Error,
                        RowStyle::ShellInput(marker) => Paint::ShellInput(*marker),
                        RowStyle::Subtle | RowStyle::Disabled => Paint::Muted,
                        RowStyle::Selected => Paint::Selected,
                    })
                    .collect(),
                cursor: Some((view.cursor_row, view.cursor_col)),
                mode: self.mode,
            });
            return Ok(());
        }
        if self.width.is_some_and(|old| old != width) {
            self.resized()?;
        }
        self.clear()?;
        self.width = Some(width);
        queue!(self.output, Hide, MoveToColumn(0))?;
        self.rows = view.rows.len();
        // Пока кадр пишется, позиция сохраняется после каждой явной строки.
        for (index, (row, style)) in view.rows.iter().zip(&view.styles).enumerate() {
            queue!(self.output, Clear(ClearType::CurrentLine), ResetColor)?;
            match style {
                RowStyle::Border => queue!(self.output, SetForegroundColor(Color::DarkCyan))?,
                RowStyle::Error => queue!(self.output, SetForegroundColor(Color::Red))?,
                RowStyle::Subtle | RowStyle::Disabled => {
                    queue!(self.output, SetForegroundColor(Color::DarkGrey))?
                }
                RowStyle::Selected => queue!(
                    self.output,
                    SetBackgroundColor(Color::DarkCyan),
                    SetForegroundColor(Color::White)
                )?,
                RowStyle::Normal | RowStyle::ShellInput(_) => {}
            }
            if let RowStyle::ShellInput(marker) = style {
                let mut column = 0;
                crate::screen::print_shell_input(
                    &mut self.output,
                    row,
                    *marker,
                    None,
                    &mut column,
                )?;
            } else {
                queue!(self.output, Print(row))?;
            }
            queue!(self.output, ResetColor)?;
            if index + 1 < view.rows.len() {
                queue!(self.output, Print("\r\n"))?;
                self.cursor_row = index + 1;
            }
        }
        let up = view
            .rows
            .len()
            .saturating_sub(1)
            .saturating_sub(view.cursor_row);
        if up > 0 {
            queue!(self.output, MoveUp(up as u16))?;
        }
        self.cursor_row = view.cursor_row;
        queue!(self.output, MoveToColumn(view.cursor_col as u16), Show)?;
        self.output.flush()
    }

    fn clear(&mut self) -> io::Result<()> {
        if let Some(screen) = &self.screen {
            screen.clear_panel();
            return Ok(());
        }
        if self.rows == 0 {
            return Ok(());
        }
        queue!(self.output, Hide, MoveToColumn(0))?;
        if self.cursor_row > 0 {
            queue!(self.output, MoveUp(self.cursor_row as u16))?;
        }
        for index in 0..self.rows {
            queue!(self.output, Clear(ClearType::CurrentLine))?;
            if index + 1 < self.rows {
                queue!(self.output, MoveDown(1))?;
            }
        }
        if self.rows > 1 {
            queue!(self.output, MoveUp((self.rows - 1) as u16))?;
        }
        self.rows = 0;
        self.cursor_row = 0;
        queue!(self.output, MoveToColumn(0))?;
        Ok(())
    }

    fn resized(&mut self) -> io::Result<()> {
        if self.fullscreen() {
            self.width = None;
            return Ok(());
        }
        if self.rows > 0 {
            // После reflow относительная высота старого кадра неизвестна.
            // Не поднимаемся к истории: продолжаем ниже прежней позиции.
            let down = self.rows.saturating_sub(self.cursor_row + 1);
            if down > 0 {
                queue!(self.output, MoveDown(down as u16))?;
            }
            queue!(self.output, MoveToColumn(0), Print("\r\n"))?;
            self.rows = 0;
            self.cursor_row = 0;
        }
        self.width = None;
        Ok(())
    }
}

impl Drop for InlineFrame {
    fn drop(&mut self) {
        let _ = self.clear();
        if !self.fullscreen() {
            let _ = execute!(self.output, ResetColor, Show);
        }
    }
}

struct TerminalGuard {
    fullscreen: bool,
    raw: bool,
    paste: bool,
}

impl TerminalGuard {
    fn enter() -> io::Result<Self> {
        let mut guard = Self {
            fullscreen: crate::screen::current().is_some(),
            raw: false,
            paste: false,
        };
        if guard.fullscreen {
            return Ok(guard);
        }
        enable_raw_mode()?;
        guard.raw = true;
        guard.paste = true;
        execute!(io::stdout(), EnableBracketedPaste, Show)?;
        Ok(guard)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if self.fullscreen {
            return;
        }
        if self.paste {
            let _ = execute!(io::stdout(), DisableBracketedPaste);
        }
        let _ = execute!(io::stdout(), ResetColor, Show);
        if self.raw {
            let _ = disable_raw_mode();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unicode_width::UnicodeWidthStr;

    fn footer() -> Footer {
        Footer {
            model: "модель-🦀-очень-длинное-название".into(),
            provider: "Провайдер".into(),
            effort: "high".into(),
            permissions: "спрашивать".into(),
            plan: true,
            context_chars: 90_000,
            input_tokens: 1234,
            output_tokens: 567,
            workspace: "/путь/с/宽/символами\u{1b}[2J".into(),
        }
    }

    fn choices() -> Vec<Choice> {
        vec![
            Choice {
                label: "Первая".into(),
                detail: "YandexGPT".into(),
                enabled: true,
            },
            Choice {
                label: "Вторая".into(),
                detail: "GigaChat".into(),
                enabled: false,
            },
            Choice {
                label: "Третья".into(),
                detail: "OpenRouter".into(),
                enabled: true,
            },
        ]
    }

    #[test]
    fn edits_graphemes_without_splitting_unicode() {
        let mut buffer = Buffer::default();
        buffer.insert("аe\u{301}👩‍💻宽");
        buffer.left();
        buffer.backspace();
        assert_eq!(buffer.text, "аe\u{301}宽");
        buffer.backspace();
        assert_eq!(buffer.text, "а宽");
        buffer.delete();
        assert_eq!(buffer.text, "а");
    }

    #[test]
    fn paste_preserves_lines_and_limits_input_at_grapheme_boundaries() {
        let mut buffer = Buffer::default();
        buffer.insert("первая\nвторая\n");
        assert_eq!(buffer.text, "первая\nвторая\n");
        buffer.insert(&"宽".repeat(30_000));
        assert!(buffer.text.len() <= 65_536);
        assert!(buffer.text.ends_with('宽'));
        assert_eq!(buffer.cursor, buffer.text.len());
    }

    #[test]
    fn word_and_line_edits_keep_other_lines() {
        let mut buffer = Buffer::default();
        buffer.insert("первая\nдва три");
        buffer.delete_word();
        assert_eq!(buffer.text, "первая\nдва ");
        buffer.home();
        buffer.kill_end();
        assert_eq!(buffer.text, "первая\n");
        buffer.end();
        assert_eq!(buffer.cursor, buffer.text.len());
    }

    #[test]
    fn agents_command_completes_and_stops_menu_before_an_id() {
        let mut state = ReadState::default();
        state.buffer.insert("/age");
        state.complete();
        assert_eq!(state.buffer.text, "/agents");
        state.buffer.insert(" agent-id");
        state.edited();
        assert!(state.commands().is_empty());
    }

    #[test]
    fn slash_completion_selects_the_highlighted_command() {
        let mut state = ReadState::default();
        state.buffer.insert("/p");
        let matches = state.commands();
        assert_eq!(
            matches
                .iter()
                .map(|&i| COMMANDS[i].name)
                .collect::<Vec<_>>(),
            ["/provider", "/permissions", "/plan"]
        );
        state.command_index = 1;
        state.complete();
        assert_eq!(state.buffer.text, "/permissions");
        assert!(state.menu_dismissed);
    }

    #[test]
    fn history_restores_the_unsubmitted_draft() {
        let mut editor = Editor::new();
        editor.add_history("первый");
        editor.add_history("первый");
        editor.add_history("второй");
        editor.add_history("   ");
        assert_eq!(editor.history, ["первый", "второй"]);
        let mut state = ReadState::default();
        state.buffer.insert("черновик");
        state.history(&editor.history, true);
        assert_eq!(state.buffer.text, "второй");
        state.history(&editor.history, true);
        assert_eq!(state.buffer.text, "первый");
        state.history(&editor.history, false);
        state.history(&editor.history, false);
        assert_eq!(state.buffer.text, "черновик");
    }

    #[test]
    fn picker_searches_details_and_skips_disabled_choices() {
        let choices = choices();
        let mut picker = Picker::new(&choices, 0);
        picker.navigate(1);
        assert_eq!(picker.choice(), Some(2));
        picker.navigate(1);
        assert_eq!(picker.choice(), Some(0));
        picker.query.insert("GIGACHAT");
        picker.filter();
        assert_eq!(picker.filtered, [1]);
        assert_eq!(picker.choice(), None);
        picker.query = Buffer::default();
        picker.query.insert("router");
        picker.filter();
        assert_eq!(picker.choice(), Some(2));
    }

    #[test]
    fn balance_updates_keep_search_results_and_selection_stable() {
        let choices = ["openrouter", "gigachat"].map(|label| Choice {
            label: label.into(),
            detail: "ключ подключён (баланс: …)".into(),
            enabled: true,
        });
        let mut picker = Picker::new(&choices, 1);
        picker.query.insert("баланс");
        picker.filter();
        picker.update_detail(1, "ключ подключён (Остаток 1.2m ток.)".into());
        assert_eq!(picker.query.text, "баланс");
        assert_eq!(picker.filtered, [0, 1]);
        assert_eq!(picker.choice(), Some(1));
        assert!(
            picker_view("Провайдер", &picker, 140, 10)
                .rows
                .iter()
                .any(|row| {
                    row.starts_with("› gigachat") && row.contains("Остаток 1.2m ток.")
                })
        );
    }

    #[test]
    fn all_views_fit_tiny_and_resized_terminals() {
        let mut state = ReadState::default();
        state
            .buffer
            .insert("宽e\u{301}🦀\nвторая\nтретья\nчетвёртая\nпятая\nшестая\u{1b}[2J");
        let choices = choices();
        let picker = Picker::new(&choices, 0);
        for width in [0, 1, 2, 3, 5, 10, 20, 40, 80, 120] {
            for height in [0, 1, 2, 3, 4, 7, 12, 24] {
                for view in [
                    editor_view(&state, &footer(), width, height),
                    picker_view("Модель\n\u{1b}[2J", &picker, width, height),
                ] {
                    assert!(!view.rows.is_empty());
                    assert!(view.rows.len() <= usize::from(height.max(1)));
                    assert!(view.cursor_row < view.rows.len());
                    assert!(view.cursor_col <= usize::from(width.saturating_sub(1)));
                    for row in view.rows {
                        assert!(
                            UnicodeWidthStr::width(row.as_str())
                                <= usize::from(width.saturating_sub(1)),
                            "{width}x{height}: {row:?}"
                        );
                        assert!(!row.contains(['\u{1b}', '\n', '\r', '\t']));
                    }
                }
            }
        }
    }

    #[test]
    fn footer_marks_local_context_and_token_counts() {
        let view = editor_view(&ReadState::default(), &footer(), 180, 24);
        let text = view.rows.join("\n");
        assert!(text.contains("локальный"));
        assert!(text.contains("180 000"));
        assert!(text.contains("1 234"));
        assert!(text.contains("567"));
        assert!(text.contains("ПЛАН"));
    }

    #[test]
    fn interrupt_clears_a_draft_before_exiting_and_control_d_is_eof_only_when_empty() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let mut state = ReadState::default();
        state.buffer.insert("черновик");
        let ctrl_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(state.key(ctrl_c, &[]), None);
        assert!(state.buffer.text.is_empty());
        assert_eq!(state.key(ctrl_c, &[]), Some(Input::Interrupt));
        assert_eq!(
            state.key(
                KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL),
                &[]
            ),
            Some(Input::Eof)
        );
    }

    #[test]
    fn tab_completes_without_submission_and_alt_enter_inserts_a_line() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let mut state = ReadState::default();
        state.buffer.insert("/mo");
        assert_eq!(
            state.key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE), &[]),
            None
        );
        assert_eq!(state.buffer.text, "/model");
        assert_eq!(
            state.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), &[]),
            Some(Input::Submit("/model".into()))
        );
        let mut state = ReadState::default();
        state.buffer.insert("первая");
        state.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::ALT), &[]);
        state.buffer.insert("вторая");
        assert_eq!(state.buffer.text, "первая\nвторая");
    }

    #[test]
    fn joining_lines_keeps_the_cursor_on_a_grapheme_boundary() {
        let mut buffer = Buffer::default();
        buffer.insert("a\n\u{301}b");
        buffer.home();
        buffer.backspace();
        assert_eq!(buffer.text, "a\u{301}b");
        assert_eq!(buffer.cursor, "a\u{301}".len());
        buffer.backspace();
        assert_eq!(buffer.text, "b");
    }

    #[test]
    fn long_model_names_leave_room_for_provider_effort_and_mode() {
        let mut footer = footer();
        footer.model = "очень-длинная-модель/".repeat(30);
        let text = editor_view(&ReadState::default(), &footer, 100, 24)
            .rows
            .join("\n");
        assert!(text.contains("Провайдер"));
        assert!(text.contains("high"));
        assert!(text.contains("ПЛАН"));
    }

    #[test]
    fn context_meter_is_visible_in_an_eighty_column_terminal() {
        let text = editor_view(&ReadState::default(), &footer(), 80, 24)
            .rows
            .join("\n");
        assert!(text.contains("[█████░░░░░]"));
        assert!(text.contains("локальный"));
        assert!(text.contains("1 234"));
        assert!(text.contains("567"));
    }

    #[test]
    fn viewport_editor_leaves_status_to_the_persistent_footer() {
        let mut state = ReadState::default();
        state.buffer.insert("Запрос с 宽 и 🦀");
        let view = viewport_editor_view(&state, &footer(), 100, 24);
        let text = view.rows.join("\n");
        assert!(text.contains("Запрос с 宽 и 🦀"));
        assert!(!text.contains("Провайдер"));
        assert!(!text.contains("Контекст"));
        assert!(!text.contains("Alt+Enter"));
    }

    #[test]
    fn shell_input_has_a_distinct_cue_and_ordinary_history_restores_the_prompt() {
        let mut state = ReadState::default();
        state.buffer.insert("  !printf 'привет'\n!echo ещё");
        let view = viewport_editor_view(&state, &footer(), 100, 24);
        assert!(view.rows[0].starts_with("╭ rcode · shell"));
        assert!(
            view.rows
                .iter()
                .any(|row| row.contains("Enter — выполнить локально"))
        );
        assert!(state.commands().is_empty());
        assert!(!view.rows.iter().any(|row| row.contains("Tab дополнить")));

        state.buffer = Buffer::default();
        state.buffer.insert("!");
        state.key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE), &[]);
        let view = viewport_editor_view(&state, &footer(), 100, 24);
        assert!(!view.rows.join("\n").contains("shell"));

        state.buffer.insert("!pwd");
        state.history(&["обычный запрос".into()], true);
        let view = viewport_editor_view(&state, &footer(), 100, 24);
        assert!(view.rows[0].starts_with("╭ rcode "));
        assert!(!view.rows.join("\n").contains("shell"));
        assert!(!view.rows.join("\n").contains("выполнить локально"));
    }

    #[test]
    fn bare_shell_marker_shows_the_local_execution_hint() {
        let mut state = ReadState::default();
        state.buffer.insert("!");
        for view in [
            editor_view(&state, &footer(), 100, 24),
            viewport_editor_view(&state, &footer(), 100, 24),
        ] {
            assert!(view.rows[0].contains("shell"));
            assert!(view.rows.join("\n").contains("Enter — выполнить локально"));
        }
    }

    #[test]
    fn shell_marker_style_follows_wrapping_and_leaves_other_bangs_unstyled() {
        let mut state = ReadState::default();
        state.buffer.insert("           !a\n!b");
        let view = viewport_editor_view(&state, &footer(), 12, 24);
        let markers: Vec<_> = view
            .rows
            .iter()
            .zip(&view.styles)
            .filter_map(|(row, style)| match style {
                RowStyle::ShellInput(offset) => Some((row, *offset)),
                _ => None,
            })
            .collect();
        assert_eq!(markers.len(), 1);
        let (row, offset) = markers[0];
        assert!(row[offset..].starts_with("!a"));
        assert_eq!(UnicodeWidthStr::width(&row[..offset]), 6);
        assert!(matches!(view.styles[0], RowStyle::Error));
        assert!(matches!(view.styles.last(), Some(RowStyle::Error)));

        for (width, height) in [(1, 1), (3, 4), (12, 6), (80, 24)] {
            let view = viewport_editor_view(&state, &footer(), width, height);
            assert_eq!(view.rows.len(), view.styles.len());
            assert!(view.cursor_row < view.rows.len());
            assert!(view.cursor_col < usize::from(width));
            assert!(!view.rows.join("\n").contains('\u{1b}'));
        }
    }

    #[test]
    fn viewport_panels_fit_above_the_footer_with_unicode_and_tiny_sizes() {
        let mut state = ReadState::default();
        state
            .buffer
            .insert("宽e\u{301}🦀\nвторая\nтретья\nчетвёртая\nпятая\nшестая\u{1b}[2J");
        let choices = choices();
        let picker = Picker::new(&choices, 2);
        for width in [0, 1, 2, 3, 5, 10, 20, 40, 80, 120] {
            for height in [0, 1, 2, 3, 4, 5, 6, 7, 12, 24] {
                let available = usize::from(crate::screen::panel_height(height));
                for view in [
                    viewport_editor_view(&state, &footer(), width, height),
                    viewport_picker_view("Модель\n\u{1b}[2J", &picker, width, height),
                ] {
                    assert!(!view.rows.is_empty());
                    assert!(view.rows.len() <= available, "{width}x{height}");
                    assert_eq!(view.rows.len(), view.styles.len());
                    assert!(view.cursor_row < view.rows.len());
                    assert!(view.cursor_col <= usize::from(width.saturating_sub(1)));
                    for row in view.rows {
                        assert!(
                            UnicodeWidthStr::width(row.as_str())
                                <= usize::from(width.saturating_sub(1)),
                            "{width}x{height}: {row:?}"
                        );
                        assert!(!row.contains(['\u{1b}', '\n', '\r', '\t']));
                    }
                }
            }
        }
    }

    #[test]
    fn viewport_menus_keep_the_selected_item_visible_above_the_footer() {
        let mut state = ReadState::default();
        state.buffer.insert("/");
        state.command_index = COMMANDS.len() - 1;
        let choices: Vec<_> = (0..30)
            .map(|index| Choice {
                label: format!("Модель {index}"),
                detail: "Описание".into(),
                enabled: true,
            })
            .collect();
        let picker = Picker::new(&choices, 29);
        for height in [7, 8, 9, 12, 24] {
            let commands = viewport_editor_view(&state, &footer(), 80, height);
            assert!(commands.rows.iter().any(|row| row.contains("/exit")));
            assert!(commands.rows.len() <= usize::from(crate::screen::panel_height(height)));
            let selection = viewport_picker_view("Модели", &picker, 80, height);
            assert!(selection.rows.iter().any(|row| row.contains("Модель 29")));
            assert!(selection.rows.len() <= usize::from(crate::screen::panel_height(height)));
        }
    }

    #[test]
    fn slash_menu_and_picker_keep_selection_visible_in_short_windows() {
        let mut state = ReadState::default();
        state.buffer.insert("/");
        state.command_index = COMMANDS.len() - 1;
        let choices: Vec<_> = (0..30)
            .map(|index| Choice {
                label: format!("Модель {index}"),
                detail: "Описание".into(),
                enabled: true,
            })
            .collect();
        let picker = Picker::new(&choices, 29);
        for height in [8, 9, 12, 24] {
            let commands = editor_view(&state, &footer(), 80, height);
            assert!(commands.rows.len() <= usize::from(height));
            assert!(commands.rows.iter().any(|row| row.contains("/exit")));
            let selection = picker_view("Модели", &picker, 80, height);
            assert!(selection.rows.len() <= usize::from(height));
            assert!(selection.rows.iter().any(|row| row.contains("Модель 29")));
        }
    }
}
