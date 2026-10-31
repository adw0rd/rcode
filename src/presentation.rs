use crate::ui;
use serde_json::Value;
use std::{
    io::{self, Write},
    sync::{Arc, Condvar, Mutex},
    thread,
    time::{Duration, Instant},
};
use unicode_width::UnicodeWidthChar;

pub fn clip(text: &str, width: usize) -> String {
    let text = ui::safe(text);
    let mut size = 0;
    let mut result = String::new();
    for c in text.chars() {
        let cells = c.width().unwrap_or(0);
        if size + cells > width {
            break;
        }
        result.push(c);
        size += cells;
    }
    result
}
fn tool_heading(name: &str) -> String {
    let name = ui::safe(name).replace('\n', "\\n").replace('\t', "\\t");
    format!("  ● {}", clip(&name, 80))
}
fn output_excerpt(text: &str, max: usize) -> Vec<String> {
    let mut lines: Vec<String> = text.lines().take(max).map(|s| clip(s, 200)).collect();
    let rest = text.lines().count().saturating_sub(max);
    if rest > 0 {
        lines.push(format!("… ещё {rest} строк"));
    }
    lines
}
pub fn tone(text: &str, code: &str, rich: bool) -> String {
    if rich && crate::screen::current().is_none() && std::env::var_os("NO_COLOR").is_none() {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}
pub fn number(value: u64) -> String {
    if value >= 1_000_000 {
        format!("{:.1}m", value as f64 / 1_000_000.)
    } else if value >= 1000 {
        format!("{:.1}k", value as f64 / 1000.)
    } else {
        value.to_string()
    }
}
pub fn inline(text: &str, width: usize) -> String {
    clip(&text.replace('\n', "\\n").replace('\t', "\\t"), width)
}
pub fn agent_heading(data: &Value) -> String {
    let status = match data["status"].as_str().unwrap_or_default() {
        "running" => "работает",
        "completed" => "готово",
        "failed" => "ошибка",
        "cancelled" => "отменён",
        "interrupted" => "прерван",
        _ => "неизвестно",
    };
    let role = match data["role"].as_str().unwrap_or_default() {
        "worker" => "worker",
        "explorer" => "explorer",
        "reviewer" => "reviewer",
        _ => "агент",
    };
    let id: String = data["id"]
        .as_str()
        .unwrap_or_default()
        .chars()
        .take(8)
        .collect();
    format!(
        "{} [{}] · {} · {} · ↑{} ↓{}",
        inline(data["name"].as_str().unwrap_or("Субагент"), 60),
        inline(&id, 8),
        role,
        status,
        number(data["usage"]["input_tokens"].as_u64().unwrap_or_default()),
        number(data["usage"]["output_tokens"].as_u64().unwrap_or_default()),
    )
}
struct Phase {
    label: Option<String>,
    since: Instant,
    rendered: bool,
    stop: bool,
}
struct Progress {
    shared: Arc<(Mutex<Phase>, Condvar)>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Progress {
    fn new(rich: bool) -> Self {
        let shared = Arc::new((
            Mutex::new(Phase {
                label: None,
                since: Instant::now(),
                rendered: false,
                stop: false,
            }),
            Condvar::new(),
        ));
        let worker = if rich && crate::screen::current().is_none() {
            let state = shared.clone();
            Some(thread::spawn(move || {
                let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
                let mut tick = 0;
                let (mut phase, cond) =
                    (state.0.lock().unwrap_or_else(|e| e.into_inner()), &state.1);
                loop {
                    if phase.stop {
                        break;
                    }
                    if let Some(label) = &phase.label
                        && crate::screen::current().is_none()
                    {
                        let width = crossterm::terminal::size()
                            .map_or(80, |s| s.0 as usize)
                            .saturating_sub(1);
                        let text = clip(
                            &format!(
                                "{} {} · {:.1}s · Ctrl+C прервать",
                                frames[tick % frames.len()],
                                label,
                                phase.since.elapsed().as_secs_f64()
                            ),
                            width,
                        );
                        let _ = write!(io::stderr(), "\r\x1b[2K{}", tone(&text, "38;5;110", true));
                        let _ = io::stderr().flush();
                        phase.rendered = true;
                        tick += 1;
                    }
                    phase = cond
                        .wait_timeout(phase, Duration::from_millis(90))
                        .unwrap_or_else(|e| e.into_inner())
                        .0;
                }
            }))
        } else {
            None
        };
        Self { shared, worker }
    }
    fn set(&self, label: &str) {
        if self.worker.is_some() {
            let mut s = self.shared.0.lock().unwrap_or_else(|e| e.into_inner());
            s.label = Some(ui::safe(label).replace('\n', "\\n").replace('\t', "\\t"));
            s.since = Instant::now();
            self.shared.1.notify_one();
        }
    }
    fn pause(&self) {
        let mut s = self.shared.0.lock().unwrap_or_else(|e| e.into_inner());
        s.label = None;
        if s.rendered {
            if crate::screen::current().is_none() {
                let _ = write!(io::stderr(), "\r\x1b[2K");
                let _ = io::stderr().flush();
            }
            s.rendered = false;
        }
    }
}
impl Drop for Progress {
    fn drop(&mut self) {
        self.pause();
        {
            let mut s = self.shared.0.lock().unwrap_or_else(|e| e.into_inner());
            s.stop = true;
            self.shared.1.notify_one();
        }
        if let Some(t) = self.worker.take() {
            let _ = t.join();
        }
    }
}
#[derive(Default)]
struct DisplayState {
    text_open: bool,
    started: Option<Instant>,
    tools: usize,
}
pub struct Human {
    rich: bool,
    progress: Progress,
    state: Mutex<DisplayState>,
}
impl Human {
    pub fn new(rich: bool) -> Self {
        Self {
            rich,
            progress: Progress::new(rich),
            state: Mutex::new(DisplayState::default()),
        }
    }
    pub fn is_rich(&self) -> bool {
        self.rich
    }
    pub fn pause(&self) {
        if let Some(screen) = crate::screen::current() {
            screen.pause();
        }
        self.progress.pause();
    }
    pub fn busy(&self, label: &str) {
        self.busy_to(label, crate::screen::current().as_deref());
    }
    fn busy_to(&self, label: &str, screen: Option<&crate::screen::Screen>) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.text_open {
            if let Some(screen) = screen {
                if !self.rich {
                    screen.append("\n");
                }
            } else {
                println!();
            }
            state.text_open = false;
        }
        if let Some(screen) = screen {
            screen.busy(&ui::safe(label));
        } else {
            self.progress.set(label);
        }
    }
    pub fn emit(&self, kind: &str, data: &Value) {
        self.emit_to(kind, data, crate::screen::current().as_deref());
    }
    fn emit_to(&self, kind: &str, data: &Value, screen: Option<&crate::screen::Screen>) {
        self.progress.pause();
        if let Some(screen) = screen {
            screen.pause();
        }
        let rich = self.rich && screen.is_none();
        macro_rules! line {
            ($($arg:tt)*) => {
                if let Some(screen) = screen {
                    screen.line(&format!($($arg)*));
                } else {
                    eprintln!($($arg)*);
                }
            };
        }
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if kind != "text"
            && !matches!(kind, "usage" | "agent_update")
            && data["agent_id"].is_null()
            && let Some(screen) = screen
        {
            screen.finish_markdown();
        }
        if kind != "text" && s.text_open {
            if let Some(screen) = screen {
                if !self.rich {
                    screen.append("\n");
                }
            } else {
                println!();
            }
            s.text_open = false;
        }
        match kind {
            "image" => {
                line!(
                    "  Изображение: {} · {:.1} КиБ",
                    ui::safe(data["name"].as_str().unwrap_or_default()),
                    data["bytes"].as_u64().unwrap_or_default() as f64 / 1024.0
                );
            }
            "shell_start" => {
                line!(
                    "\n{} {}",
                    tone("!", "31", rich),
                    ui::safe(data["command"].as_str().unwrap_or_default())
                );
            }
            "shell_result" => {
                let content = data["content"].as_str().unwrap_or_default();
                if let Ok(result) = serde_json::from_str::<Value>(content) {
                    for key in ["stdout", "stderr"] {
                        let text = result[key]
                            .as_str()
                            .unwrap_or_default()
                            .trim_end_matches('\n');
                        if !text.is_empty() {
                            line!("{}", ui::safe(text));
                        }
                    }
                    let summary = match result["reason"]
                        .as_str()
                        .or_else(|| result["error"].as_str())
                    {
                        Some("cancelled") => "↳ прервано".to_owned(),
                        Some("timeout") => "↳ превышено время выполнения".to_owned(),
                        Some("output_limit") => "↳ достигнут лимит вывода".to_owned(),
                        Some("interrupted") => {
                            "↳ выполнение прервано; результат неизвестен".to_owned()
                        }
                        Some(error) => format!("↳ {}", ui::safe(error)),
                        None => result["exit_code"]
                            .as_i64()
                            .map(|code| format!("↳ exit {code}"))
                            .unwrap_or_else(|| "↳ процесс завершён сигналом".into()),
                    };
                    let elapsed = data["elapsed_secs"]
                        .as_f64()
                        .map(|seconds| format!(" · {seconds:.1}s"))
                        .unwrap_or_default();
                    let error = data["is_error"] == true || result["exit_code"].as_i64() != Some(0);
                    line!(
                        "{}{}",
                        tone(&summary, if error { "31" } else { "2" }, rich),
                        elapsed
                    );
                } else {
                    line!("{}", tone(&ui::safe(content), "31", rich));
                }
            }
            "start" => {
                s.started = Some(Instant::now());
                s.tools = 0;
                if self.rich {
                    line!("\n{}", tone("✦ rcode", "1;38;5;110", rich));
                }
            }
            "text" => {
                let text = ui::safe(data["text"].as_str().unwrap_or_default());
                if let Some(screen) = screen {
                    if self.rich {
                        screen.append_markdown(&text);
                    } else {
                        screen.append(&text);
                    }
                } else {
                    print!("{text}");
                    let _ = io::stdout().flush();
                }
                if !text.is_empty() {
                    s.text_open = !text.ends_with('\n');
                }
            }
            "tool_start" => {
                s.tools += 1;
                let name = data["name"].as_str().unwrap_or("tool");
                let args: Value = serde_json::from_str(data["arguments"].as_str().unwrap_or("{}"))
                    .unwrap_or_default();
                let detail = args
                    .get("path")
                    .or_else(|| args.get("pattern"))
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                line!(
                    "{} {}",
                    tone(&tool_heading(name), "38;5;110", rich),
                    clip(detail, 100)
                );
            }
            "tool_result" => {
                let error = data["is_error"] == true;
                let content = data["content"].as_str().unwrap_or_default();
                let name = data["name"].as_str().unwrap_or_default();
                if error {
                    line!("{}", tone("    ↳ ошибка", "31", rich));
                    for line in output_excerpt(content, 5) {
                        line!("      {line}");
                    }
                } else if name == "run_command" {
                    if let Ok(v) = serde_json::from_str::<Value>(content) {
                        line!("    ↳ exit {}", v["exit_code"]);
                        for key in ["stdout", "stderr"] {
                            for line in output_excerpt(v[key].as_str().unwrap_or_default(), 6) {
                                line!("      {line}");
                            }
                        }
                    }
                } else if let Some(paths) =
                    data["changed_paths"].as_array().filter(|p| !p.is_empty())
                {
                    for p in paths {
                        line!(
                            "{} {}",
                            tone("    ✓", "32", rich),
                            ui::safe(p.as_str().unwrap_or_default())
                        );
                    }
                } else {
                    let parsed = serde_json::from_str::<Value>(content).ok();
                    let detail = parsed
                        .as_ref()
                        .and_then(|v| v.get("matches").or_else(|| v.get("files")))
                        .and_then(Value::as_array)
                        .map(|a| format!("{} результатов", a.len()))
                        .unwrap_or_else(|| "готово".into());
                    line!("    ↳ {detail}");
                }
            }
            "preview" => {
                for line in data["diff"].as_str().unwrap_or_default().lines() {
                    let color = if line.starts_with('+') {
                        "32"
                    } else if line.starts_with('-') {
                        "31"
                    } else {
                        "2"
                    };
                    line!("{}", tone(&ui::safe(line), color, rich));
                }
            }
            "error" => line!(
                "{} {}",
                tone("✗", "31", rich),
                ui::safe(data["message"].as_str().unwrap_or_default())
            ),
            "warning" => line!(
                "{} {}",
                tone("!", "33", rich),
                ui::safe(data["message"].as_str().unwrap_or_default())
            ),
            "context_compacted" => {
                if data["unit"] == "estimated_tokens" {
                    line!(
                        "↻ Автокомпакт: ~{} → ~{} оценочных токенов",
                        number(data["before"].as_u64().unwrap_or_default()),
                        number(data["after"].as_u64().unwrap_or_default())
                    );
                } else {
                    line!(
                        "↻ Автокомпакт: {} → {} символов",
                        number(data["before_chars"].as_u64().unwrap_or_default()),
                        number(data["after_chars"].as_u64().unwrap_or_default())
                    );
                }
                line!(
                    "{}",
                    ui::safe(
                        data["message"]
                            .as_str()
                            .unwrap_or("Контекст автоматически сжат")
                    )
                );
            }
            "usage" => {
                if let Some(screen) = screen {
                    screen.usage(
                        data["input_tokens"].as_u64().unwrap_or_default(),
                        data["output_tokens"].as_u64().unwrap_or_default(),
                    );
                }
            }
            "agent_update" => {
                let color = match data["status"].as_str().unwrap_or_default() {
                    "completed" => "32",
                    "failed" | "cancelled" | "interrupted" => "33",
                    _ => "38;5;110",
                };
                line!("  {}", tone(&agent_heading(data), color, rich));
                if data["status"] != "running" {
                    for content in output_excerpt(data["result"].as_str().unwrap_or_default(), 2) {
                        line!("    ↳ {content}");
                    }
                }
            }
            "done" => {
                let time = s
                    .started
                    .map(|t| t.elapsed().as_secs_f64())
                    .unwrap_or_default();
                line!(
                    "\n{}",
                    tone(
                        &format!(
                            "── {:.1}s · {} действий · ↑{} ↓{} токенов",
                            time,
                            s.tools,
                            number(
                                data["turn_input_tokens"]
                                    .as_u64()
                                    .or_else(|| data["input_tokens"].as_u64())
                                    .unwrap_or_default()
                            ),
                            number(
                                data["turn_output_tokens"]
                                    .as_u64()
                                    .or_else(|| data["output_tokens"].as_u64())
                                    .unwrap_or_default()
                            )
                        ),
                        "2",
                        rich
                    )
                );
            }
            _ => {}
        }
    }
}
pub fn welcome(root: &std::path::Path, provider: &str, model: &str, rich: bool) {
    welcome_to(
        root,
        provider,
        model,
        rich,
        crate::screen::current().as_deref(),
    );
}
fn welcome_to(
    root: &std::path::Path,
    provider: &str,
    model: &str,
    rich: bool,
    screen: Option<&crate::screen::Screen>,
) {
    if let Some(screen) = screen {
        screen.line(&format!(
            "rcode {} · {} / {}",
            env!("CARGO_PKG_VERSION"),
            ui::safe(provider),
            ui::safe(model),
        ));
        screen.line(&ui::safe(&root.display().to_string()));
        screen.line("/ меню · /model модель · /effort глубина · /help справка");
        return;
    }
    if !rich {
        eprintln!(
            "rcode {} · {provider} / {}\n{}\n/help — команды",
            env!("CARGO_PKG_VERSION"),
            ui::safe(model),
            root.display()
        );
        return;
    }
    let width = crossterm::terminal::size()
        .map_or(80, |s| s.0 as usize)
        .saturating_sub(2)
        .clamp(8, 76);
    let title = clip(
        &format!(" rcode {} ", env!("CARGO_PKG_VERSION")),
        width.saturating_sub(2),
    );
    let pad = width.saturating_sub(2 + unicode_width::UnicodeWidthStr::width(title.as_str()));
    eprintln!(
        "\n{}",
        tone(&format!("╭{title}{}╮", "─".repeat(pad)), "38;5;110", true)
    );
    for content in [format!("{provider} / {model}"), root.display().to_string()] {
        let content = clip(
            &content.replace('\n', "\\n").replace('\t', "\\t"),
            width.saturating_sub(4),
        );
        let pad = width.saturating_sub(4 + unicode_width::UnicodeWidthStr::width(content.as_str()));
        eprintln!("│ {content}{} │", " ".repeat(pad));
    }
    eprintln!(
        "{}",
        tone(
            &format!("╰{}╯", "─".repeat(width.saturating_sub(2))),
            "38;5;110",
            true
        )
    );
    eprintln!(
        "  {}",
        tone(
            "/ меню · /model модель · /effort глубина · /help справка",
            "2",
            true
        )
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn automatic_compaction_notice_reports_actual_char_counts_without_fake_usage() {
        let screen = crate::screen::Screen::test_screen();
        let human = Human::new(true);
        human.emit_to("context_compacted", &json!({"automatic":true,"before_chars":171000,"after_chars":109000,"saved_chars":62000,"message":"Текущий запрос сохранён"}), Some(&screen));
        let history = screen.history_text();
        assert!(history.contains("Автокомпакт: 171.0k → 109.0k символов"));
        assert!(history.contains("Текущий запрос сохранён"));
        assert_eq!(human.state.lock().unwrap().tools, 0);
        assert!(!history.contains("токенов"));
    }
    #[test]
    fn background_agent_events_do_not_split_the_parent_markdown_stream() {
        let screen = crate::screen::Screen::test_screen();
        let human = Human::new(true);
        human.emit_to("text", &json!({"text":"```python\nprint("}), Some(&screen));
        human.emit_to(
            "tool_start",
            &json!({"agent_id":"worker", "name":"read_file"}),
            Some(&screen),
        );
        human.busy_to("Субагент читает файл", Some(&screen));
        human.emit_to(
            "tool_result",
            &json!({"agent_id":"worker", "name":"read_file", "content":"{}"}),
            Some(&screen),
        );
        human.emit_to(
            "usage",
            &json!({"input_tokens":1,"output_tokens":1}),
            Some(&screen),
        );
        human.emit_to("text", &json!({"text":"'ok')\n```"}), Some(&screen));
        human.emit_to("done", &json!({}), Some(&screen));
        let history = screen.history_text();
        assert!(
            history.contains("```python\nprint('ok')\n```"),
            "{history:?}"
        );
        assert!(history.contains("● read_file"));
    }
    #[test]
    fn agent_updates_stay_in_history_without_injecting_terminal_controls() {
        let screen = crate::screen::Screen::test_screen();
        let human = Human::new(true);
        human.emit_to("text", &json!({"text":"Основной ответ"}), Some(&screen));
        let result = (0..20)
            .map(|i| format!("result {i}\x1b[2J\u{202e}"))
            .collect::<Vec<_>>()
            .join("\n");
        human.emit_to(
            "agent_update",
            &json!({
                "id":"12345678-agent", "name":"Обзор\n\x1b[2J\u{202e}",
                "role":"reviewer", "status":"completed", "result":result,
                "usage":{"input_tokens":321,"output_tokens":45}
            }),
            Some(&screen),
        );
        let history = screen.history_text();
        assert!(history.starts_with("Основной ответ\n"), "{history:?}");
        assert!(history.contains("12345678"), "{history:?}");
        assert!(history.contains("Обзор\\n"), "{history:?}");
        assert!(history.contains("↑321 ↓45"), "{history:?}");
        assert!(history.contains("result 0"), "{history:?}");
        assert!(!history.contains("result 19"), "{history:?}");
        assert!(!history.contains('\x1b') && !history.contains('\u{202e}'));
        assert_eq!(human.state.lock().unwrap().tools, 0);
        assert!(!human.state.lock().unwrap().text_open);
    }

    #[test]
    fn viewport_keeps_streamed_text_together_and_separates_tool_output() {
        let screen = crate::screen::Screen::test_screen();
        let human = Human::new(true);
        human.emit_to("text", &json!({"text":"Первая "}), Some(&screen));
        human.emit_to(
            "text",
            &json!({"text":"строка\x1b[2J\u{202e}"}),
            Some(&screen),
        );
        human.emit_to(
            "tool_start",
            &json!({"name":"read_file", "arguments":r#"{"path":"src/lib.rs"}"#}),
            Some(&screen),
        );
        human.emit_to(
            "tool_result",
            &json!({"name":"read_file", "is_error":true,"content":"Ошибка\x1b[2J\u{202e}"}),
            Some(&screen),
        );
        let history = screen.history_text();
        assert!(
            history.starts_with("Первая строка[2J\\u{202e}\n  ● read_file src/lib.rs\n"),
            "{history:?}"
        );
        assert!(
            history.contains("    ↳ ошибка\n      Ошибка[2J\\u{202e}\n"),
            "{history:?}"
        );
        assert!(!history.contains('\x1b') && !history.contains('\u{202e}'));
        assert_eq!(human.state.lock().unwrap().tools, 1);
        assert!(!human.state.lock().unwrap().text_open);
    }
    #[test]
    fn viewport_welcome_uses_plain_history_lines() {
        let screen = crate::screen::Screen::test_screen();
        welcome_to(
            std::path::Path::new("/tmp/проект\x1b"),
            "OpenRouter",
            "model\x1b\u{202e}",
            true,
            Some(&screen),
        );
        let history = screen.history_text();
        assert!(
            history.starts_with(&format!(
                "rcode {} · OpenRouter / model\\u{{202e}}\n",
                env!("CARGO_PKG_VERSION")
            )),
            "{history:?}"
        );
        assert!(history.contains("/tmp/проект\n"), "{history:?}");
        assert!(!history.contains('\x1b') && !history.contains('╭'));
    }
    #[test]
    fn viewport_summary_preserves_action_and_real_token_counts() {
        let screen = crate::screen::Screen::test_screen();
        let human = Human::new(true);
        human.emit_to("start", &json!({}), Some(&screen));
        human.emit_to("tool_start", &json!({"name":"read_file"}), Some(&screen));
        human.emit_to(
            "usage",
            &json!({"input_tokens":321,"output_tokens":45}),
            Some(&screen),
        );
        human.emit_to(
            "done",
            &json!({"turn_input_tokens":321,"turn_output_tokens":45}),
            Some(&screen),
        );
        let history = screen.history_text();
        assert!(
            history.contains("1 действий · ↑321 ↓45 токенов"),
            "{history:?}"
        );
        assert!(human.state.lock().unwrap().started.is_some());
    }
    #[test]
    fn command_output_is_bounded_and_terminal_safe() {
        let output = (0..30)
            .map(|i| format!("line {i}\x1b\u{202e}"))
            .collect::<Vec<_>>()
            .join("\n");
        let lines = output_excerpt(&output, 4);
        assert_eq!(lines.len(), 5);
        assert!(lines.last().unwrap().contains("26"));
        assert!(
            lines
                .iter()
                .all(|s| !s.contains('\x1b') && !s.contains('\u{202e}'))
        );
    }
    #[test]
    fn untrusted_tool_names_cannot_emit_terminal_sequences() {
        let heading = tool_heading("read_file\x1b[2J\x1b]0;HIJACK\x07\u{202e}");
        assert!(
            !heading.contains('\x1b') && !heading.contains('\x07') && !heading.contains('\u{202e}')
        );
    }
    #[test]
    fn labels_fit_narrow_terminals_without_breaking_utf8() {
        for width in 0..20 {
            let text = clip("Привет 世界 👩‍💻", width);
            assert!(unicode_width::UnicodeWidthStr::width(text.as_str()) <= width);
        }
    }
}
