//! Интерактивное уточнение требований у оператора (`ask_user`).
//!
//! Инструмент доступен только основному агенту в интерактивной терминальной
//! сессии (включая `/plan`), не расширяет разрешения и не предназначен для
//! ввода секретов или обхода подтверждений `Screen::approve`.

use crate::{protocol::ToolDefinition, ui};
use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io;

pub const TOOL_NAME: &str = "ask_user";
pub const MAX_QUESTIONS: usize = 3;
pub const MIN_OPTIONS: usize = 2;
pub const MAX_OPTIONS: usize = 4;
pub const MAX_QUESTION_CHARS: usize = 240;
pub const MAX_OPTION_CHARS: usize = 120;
pub const MAX_ANSWER_CHARS: usize = 400;
pub const CUSTOM_OPTION_LABEL: &str = "Свой вариант…";

pub const PROMPT_GUIDANCE: &str = "\nUse ask_user (1–3 brief questions, 2–4 options, recommended first) only for ambiguous, costly decisions that inspecting files cannot resolve; never use it for permission approvals or routine details, and do not re-ask in the same turn.";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuestionSpec {
    pub question: String,
    pub options: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AskRequest {
    pub questions: Vec<QuestionSpec>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AskOutcome {
    Selected(usize),
    Custom(String),
    Dismissed,
    Interrupted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnswerSource {
    Option,
    Custom,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnsweredQuestion {
    pub question_index: usize,
    pub question: String,
    pub source: AnswerSource,
    pub option_index: Option<usize>,
    pub answer: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AskStatus {
    Answered,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AskReceipt {
    pub status: AskStatus,
    pub total_questions: usize,
    pub answered_count: usize,
    pub answers: Vec<AnsweredQuestion>,
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub cached_in_turn: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub note: Option<String>,
}

impl AskReceipt {
    pub fn build(total_questions: usize, answers: Vec<AnsweredQuestion>, cancelled: bool) -> Self {
        let status = if !cancelled && answers.len() == total_questions {
            AskStatus::Answered
        } else {
            AskStatus::Cancelled
        };
        let note = match status {
            AskStatus::Answered => None,
            AskStatus::Cancelled if answers.is_empty() => Some(
                "Оператор закрыл панель опроса без выбора (это не согласие с первым вариантом). Не повторяйте тот же опрос в этом ходе: продолжите с безопасным обратимым допущением или кратко уточните в итоговом ответе."
                    .into(),
            ),
            AskStatus::Cancelled => Some(
                "Оператор прервал опрос после части вопросов (оставшиеся вопросы без ответа — не согласие с их первым вариантом). Учтите данные ответы и не открывайте повторно отменённые вопросы в этом ходе."
                    .into(),
            ),
        };
        Self {
            status,
            total_questions,
            answered_count: answers.len(),
            answers,
            cached_in_turn: false,
            note,
        }
    }

    pub fn redact_checked<F>(&self, mut redact: F) -> Result<Self>
    where
        F: FnMut(&str) -> Result<String>,
    {
        let mut answers = Vec::with_capacity(self.answers.len());
        for item in &self.answers {
            answers.push(AnsweredQuestion {
                question_index: item.question_index,
                question: redact(&item.question)?,
                source: item.source,
                option_index: item.option_index,
                answer: redact(&item.answer)?,
            });
        }
        let note = match &self.note {
            Some(text) => Some(redact(text)?),
            None => None,
        };
        Ok(Self {
            status: self.status,
            total_questions: self.total_questions,
            answered_count: self.answered_count,
            answers,
            cached_in_turn: self.cached_in_turn,
            note,
        })
    }
}

pub fn definition() -> ToolDefinition {
    ToolDefinition {
        name: TOOL_NAME.into(),
        description: "Задать 1–3 кратких вопроса (по 2–4 варианта, рекомендуемый первым с «(Рекомендуется)»; «Свой вариант…» добавляется сам) только при неоднозначной развилке, не решаемой чтением кода. Не заменяет подтверждение прав; не запрашивайте пароли и ключи.".into(),
        parameters: json!({
            "type": "object",
            "properties": {
                "questions": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": MAX_QUESTIONS,
                    "items": {
                        "type": "object",
                        "properties": {
                            "question": {
                                "type": "string",
                                "minLength": 1,
                                "maxLength": MAX_QUESTION_CHARS
                            },
                            "options": {
                                "type": "array",
                                "minItems": MIN_OPTIONS,
                                "maxItems": MAX_OPTIONS,
                                "items": {
                                    "type": "string",
                                    "minLength": 1,
                                    "maxLength": MAX_OPTION_CHARS
                                }
                            }
                        },
                        "required": ["question", "options"],
                        "additionalProperties": false
                    }
                }
            },
            "required": ["questions"],
            "additionalProperties": false
        }),
    }
}

/// Нормализует многострочный или табулированный текст в одну аккуратную строку
/// без управляющих символов (сохраняя корректные Unicode-графемы и ZWJ-эмодзи;
/// экранирование терминала выполняет `ui::safe` только при выводе на экран).
pub fn normalize_inline_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut prev_space = false;
    for ch in text.chars() {
        if matches!(ch, '\r' | '\n' | '\t') || ch.is_whitespace() {
            if !out.is_empty() && !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else if !ch.is_control() {
            out.push(ch);
            prev_space = false;
        }
    }
    if out.ends_with(' ') {
        out.pop();
    }
    out
}

/// Нормализует вставку в поле собственного ответа: переводы строк и табы
/// заменяются одиночными пробелами, управляющие символы отбрасываются.
pub fn sanitize_paste(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut prev_newline = false;
    for ch in text.chars() {
        if matches!(ch, '\r' | '\n' | '\t') {
            if !prev_newline {
                out.push(' ');
                prev_newline = true;
            }
        } else if !ch.is_control() {
            out.push(ch);
            prev_newline = false;
        }
    }
    out
}

fn is_reserved_custom_option(normalized_lower: &str) -> bool {
    let trimmed = normalized_lower
        .trim_matches(|c: char| c.is_ascii_punctuation() || c == '…' || c.is_whitespace());
    matches!(
        trimmed,
        "другое"
            | "другой вариант"
            | "свой вариант"
            | "свой ответ"
            | "other"
            | "custom"
            | "custom answer"
    )
}

pub fn parse_request(args: &Value) -> Result<AskRequest> {
    let Some(obj) = args.as_object() else {
        bail!("Аргументы ask_user должны быть JSON-объектом");
    };
    for key in obj.keys() {
        ensure!(
            key == "questions",
            "Неизвестное поле ask_user: «{}»",
            ui::safe(key)
        );
    }
    let Some(raw_questions) = obj.get("questions").and_then(Value::as_array) else {
        bail!("Поле questions должно быть массивом от 1 до {MAX_QUESTIONS} вопросов");
    };
    ensure!(
        (1..=MAX_QUESTIONS).contains(&raw_questions.len()),
        "Укажите от 1 до {MAX_QUESTIONS} вопросов (передано: {})",
        raw_questions.len()
    );
    let mut questions = Vec::with_capacity(raw_questions.len());
    let mut seen_questions = HashSet::new();
    for (q_idx, item) in raw_questions.iter().enumerate() {
        let Some(q_obj) = item.as_object() else {
            bail!("Вопрос #{} должен быть JSON-объектом", q_idx + 1);
        };
        for key in q_obj.keys() {
            ensure!(
                matches!(key.as_str(), "question" | "options"),
                "Неизвестное поле в вопросе #{}: «{}»",
                q_idx + 1,
                ui::safe(key)
            );
        }
        let Some(raw_q) = q_obj.get("question").and_then(Value::as_str) else {
            bail!("Вопрос #{}: поле question должно быть строкой", q_idx + 1);
        };
        let question = normalize_inline_text(raw_q);
        ensure!(
            !question.is_empty(),
            "Вопрос #{}: текст вопроса не может быть пустым",
            q_idx + 1
        );
        let q_chars = question.chars().count();
        ensure!(
            q_chars <= MAX_QUESTION_CHARS,
            "Вопрос #{} слишком длинный ({} симв., максимум {})",
            q_idx + 1,
            q_chars,
            MAX_QUESTION_CHARS
        );
        ensure!(
            seen_questions.insert(question.to_lowercase()),
            "Дублирующийся вопрос #{}",
            q_idx + 1
        );

        let Some(raw_opts) = q_obj.get("options").and_then(Value::as_array) else {
            bail!(
                "Вопрос #{}: поле options должно быть массивом от {MIN_OPTIONS} до {MAX_OPTIONS} строк",
                q_idx + 1
            );
        };
        ensure!(
            (MIN_OPTIONS..=MAX_OPTIONS).contains(&raw_opts.len()),
            "Вопрос #{}: нужно от {MIN_OPTIONS} до {MAX_OPTIONS} вариантов (передано: {})",
            q_idx + 1,
            raw_opts.len()
        );
        let mut options = Vec::with_capacity(raw_opts.len());
        let mut seen_opts = HashSet::new();
        for (o_idx, raw_opt) in raw_opts.iter().enumerate() {
            let Some(opt_str) = raw_opt.as_str() else {
                bail!(
                    "Вопрос #{}, вариант #{}: ожидалась строка",
                    q_idx + 1,
                    o_idx + 1
                );
            };
            let option = normalize_inline_text(opt_str);
            ensure!(
                !option.is_empty(),
                "Вопрос #{}, вариант #{}: пустая строка недопустима",
                q_idx + 1,
                o_idx + 1
            );
            let o_chars = option.chars().count();
            ensure!(
                o_chars <= MAX_OPTION_CHARS,
                "Вопрос #{}, вариант #{} слишком длинный ({} симв., максимум {})",
                q_idx + 1,
                o_idx + 1,
                o_chars,
                MAX_OPTION_CHARS
            );
            let lower = option.to_lowercase();
            ensure!(
                !is_reserved_custom_option(&lower),
                "Вопрос #{}: не добавляйте пункт «{}» — интерфейс добавляет «{}» автоматически",
                q_idx + 1,
                option,
                CUSTOM_OPTION_LABEL
            );
            ensure!(
                seen_opts.insert(lower),
                "Вопрос #{}: дублирующийся вариант «{}»",
                q_idx + 1,
                option
            );
            options.push(option);
        }
        questions.push(QuestionSpec { question, options });
    }
    Ok(AskRequest { questions })
}

pub fn question_fingerprint(item: &QuestionSpec) -> String {
    let mut hasher = Sha256::new();
    hasher.update(item.question.to_lowercase().as_bytes());
    hasher.update(b"\0");
    for opt in &item.options {
        hasher.update(opt.to_lowercase().as_bytes());
        hasher.update(b"\x1f");
    }
    format!("{:x}", hasher.finalize())
}

pub fn request_fingerprint(request: &AskRequest) -> String {
    let mut hasher = Sha256::new();
    for item in &request.questions {
        hasher.update(question_fingerprint(item).as_bytes());
        hasher.update(b"\x1e");
    }
    format!("{:x}", hasher.finalize())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PlainSubMode {
    SelectingChoice,
    EnteringCustom,
}

struct PlainStateMachine {
    options_len: usize,
    mode: PlainSubMode,
}

impl PlainStateMachine {
    fn new(
        spec: &QuestionSpec,
        index: usize,
        total: usize,
        write_notice: &mut dyn FnMut(&str),
    ) -> Self {
        let custom_num = spec.options.len() + 1;
        let heading = if total > 1 {
            format!(
                "\nУточнение ({}/{}) — {}:",
                index + 1,
                total,
                ui::safe(&spec.question)
            )
        } else {
            format!("\nУточнение — {}:", ui::safe(&spec.question))
        };
        write_notice(&heading);
        for (i, opt) in spec.options.iter().enumerate() {
            write_notice(&format!("  {}. {}", i + 1, ui::safe(opt)));
        }
        write_notice(&format!("  {custom_num}. {CUSTOM_OPTION_LABEL}"));
        write_notice("  (Не вводите пароли и API-ключи: ответ передаётся модели)");
        Self {
            options_len: spec.options.len(),
            mode: PlainSubMode::SelectingChoice,
        }
    }

    fn current_prompt(&self) -> String {
        let custom_num = self.options_len + 1;
        match self.mode {
            PlainSubMode::SelectingChoice => format!("Номер 1–{custom_num} (0 — отмена): "),
            PlainSubMode::EnteringCustom => "Ваш вариант (0 — назад к списку): ".to_owned(),
        }
    }

    fn consume_line(
        &mut self,
        raw: &str,
        overflowed: bool,
        write_notice: &mut dyn FnMut(&str),
    ) -> Option<AskOutcome> {
        let custom_num = self.options_len + 1;
        match self.mode {
            PlainSubMode::SelectingChoice => {
                if overflowed {
                    write_notice(&format!(
                        "Некорректный выбор. Введите номер 1–{custom_num} или 0 для отмены."
                    ));
                    return None;
                }
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    write_notice(&format!(
                        "Пустой ввод не выбирает вариант по умолчанию. Введите число 1–{custom_num} или 0 для отмены."
                    ));
                    return None;
                }
                if trimmed == "0" {
                    return Some(AskOutcome::Dismissed);
                }
                let Ok(number) = trimmed.parse::<usize>() else {
                    write_notice(&format!(
                        "Некорректный выбор. Введите номер 1–{custom_num} или 0 для отмены."
                    ));
                    return None;
                };
                if (1..=self.options_len).contains(&number) {
                    return Some(AskOutcome::Selected(number - 1));
                }
                if number == custom_num {
                    self.mode = PlainSubMode::EnteringCustom;
                    return None;
                }
                write_notice(&format!(
                    "Номер вне диапазона. Введите 1–{custom_num} или 0 для отмены."
                ));
                None
            }
            PlainSubMode::EnteringCustom => {
                if !overflowed && raw.trim() == "0" {
                    self.mode = PlainSubMode::SelectingChoice;
                    return None;
                }
                if overflowed {
                    write_notice(&format!(
                        "Ответ слишком длинный (лимит {MAX_ANSWER_CHARS} симв.): сократите текст."
                    ));
                    return None;
                }
                let cleaned = normalize_inline_text(raw);
                if cleaned.is_empty() {
                    write_notice("Ответ не может быть пустым (введите текст или 0 для возврата).");
                    return None;
                }
                let chars = cleaned.chars().count();
                if chars > MAX_ANSWER_CHARS {
                    write_notice(&format!(
                        "Ответ слишком длинный ({chars} симв., лимит {MAX_ANSWER_CHARS}): сократите текст."
                    ));
                    return None;
                }
                Some(AskOutcome::Custom(cleaned))
            }
        }
    }
}

/// Диалог выбора для одного вопроса в `--plain` с переданным источником строк
/// (`Ok(None)` означает EOF, `Err(Interrupted)` — `Ctrl+C`).
pub fn ask_one_plain_with<R, W>(
    spec: &QuestionSpec,
    index: usize,
    total: usize,
    mut read_line: R,
    mut write_notice: W,
) -> io::Result<AskOutcome>
where
    R: FnMut(&str) -> io::Result<Option<String>>,
    W: FnMut(&str),
{
    let mut state = PlainStateMachine::new(spec, index, total, &mut write_notice);
    loop {
        let prompt = state.current_prompt();
        let raw = match read_line(&prompt) {
            Ok(Some(line)) => line,
            Ok(None) => return Ok(AskOutcome::Dismissed),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {
                return Ok(AskOutcome::Interrupted);
            }
            Err(err) => return Err(err),
        };
        if let Some(outcome) = state.consume_line(&raw, false, &mut write_notice) {
            return Ok(outcome);
        }
    }
}

/// Неблокирующий пошаговый опрос одного вопроса в `--plain`, позволяющий
/// `ToolExecutor` параллельно обслуживать `settle_managed` и мгновенно выходить
/// по `CancellationToken` без оставленного фонового читателя `stdin`.
pub struct PlainQuestionPrompt {
    state: PlainStateMachine,
    line_buf: Vec<u8>,
    line_overflow: bool,
}

impl PlainQuestionPrompt {
    const MAX_LINE_BYTES: usize = 8192;

    pub fn new(spec: &QuestionSpec, index: usize, total: usize) -> io::Result<Self> {
        if crate::screen::current().is_some() {
            return Err(io::Error::other(
                "PlainQuestionPrompt нельзя запускать при активном полноэкранном Screen",
            ));
        }
        let mut emit = |line: &str| eprintln!("{}", ui::safe(line));
        let state = PlainStateMachine::new(spec, index, total, &mut emit);
        Self::print_prompt(&state.current_prompt())?;
        Ok(Self {
            state,
            line_buf: Vec::new(),
            line_overflow: false,
        })
    }

    fn print_prompt(prompt: &str) -> io::Result<()> {
        use io::Write as _;
        let mut stderr = io::stderr();
        write!(stderr, "{}", ui::safe(prompt))?;
        stderr.flush()
    }

    pub fn step(&mut self) -> io::Result<Option<AskOutcome>> {
        #[cfg(unix)]
        {
            while poll_stdin_ready()? {
                let mut byte = 0u8;
                match read_stdin_byte(&mut byte) {
                    Ok(0) => {
                        if self.line_buf.is_empty() && !self.line_overflow {
                            return Ok(Some(AskOutcome::Dismissed));
                        }
                        let line = String::from_utf8_lossy(&self.line_buf).into_owned();
                        let overflowed = self.line_overflow;
                        self.line_buf.clear();
                        self.line_overflow = false;
                        let mut emit = |msg: &str| eprintln!("{}", ui::safe(msg));
                        if let Some(outcome) = self.state.consume_line(&line, overflowed, &mut emit)
                        {
                            return Ok(Some(outcome));
                        }
                        return Ok(Some(AskOutcome::Dismissed));
                    }
                    Ok(_) => match byte {
                        b'\x03' => return Ok(Some(AskOutcome::Interrupted)),
                        b'\x04' if self.line_buf.is_empty() && !self.line_overflow => {
                            return Ok(Some(AskOutcome::Dismissed));
                        }
                        b'\n' => {
                            let line = String::from_utf8_lossy(&self.line_buf).into_owned();
                            let overflowed = self.line_overflow;
                            self.line_buf.clear();
                            self.line_overflow = false;
                            let mut emit = |msg: &str| eprintln!("{}", ui::safe(msg));
                            if let Some(outcome) =
                                self.state.consume_line(&line, overflowed, &mut emit)
                            {
                                return Ok(Some(outcome));
                            }
                            Self::print_prompt(&self.state.current_prompt())?;
                        }
                        other => {
                            if self.line_buf.len() < Self::MAX_LINE_BYTES {
                                self.line_buf.push(other);
                            } else {
                                self.line_overflow = true;
                            }
                        }
                    },
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => return Ok(None),
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                    Err(err) => return Err(err),
                }
            }
            Ok(None)
        }
        #[cfg(not(unix))]
        {
            use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
            use std::time::Duration;
            while event::poll(Duration::ZERO)? {
                match event::read()? {
                    Event::Paste(pasted) => {
                        for b in pasted.as_bytes() {
                            if self.line_buf.len() < Self::MAX_LINE_BYTES {
                                self.line_buf.push(*b);
                            } else {
                                self.line_overflow = true;
                            }
                        }
                    }
                    Event::Key(k) if k.kind != KeyEventKind::Release => match (k.code, k.modifiers)
                    {
                        (KeyCode::Char('c'), m) if m.contains(KeyModifiers::CONTROL) => {
                            return Ok(Some(AskOutcome::Interrupted));
                        }
                        (KeyCode::Char('d'), m)
                            if m.contains(KeyModifiers::CONTROL)
                                && self.line_buf.is_empty()
                                && !self.line_overflow =>
                        {
                            return Ok(Some(AskOutcome::Dismissed));
                        }
                        (KeyCode::Esc, _) => return Ok(Some(AskOutcome::Dismissed)),
                        (KeyCode::Backspace, _) => {
                            let mut text = String::from_utf8_lossy(&self.line_buf).into_owned();
                            text.pop();
                            self.line_buf = text.into_bytes();
                        }
                        (KeyCode::Enter, _) => {
                            eprintln!();
                            let line = String::from_utf8_lossy(&self.line_buf).into_owned();
                            let overflowed = self.line_overflow;
                            self.line_buf.clear();
                            self.line_overflow = false;
                            let mut emit = |msg: &str| eprintln!("{}", ui::safe(msg));
                            if let Some(outcome) =
                                self.state.consume_line(&line, overflowed, &mut emit)
                            {
                                return Ok(Some(outcome));
                            }
                            Self::print_prompt(&self.state.current_prompt())?;
                        }
                        (KeyCode::Char(ch), m)
                            if !m.intersects(KeyModifiers::CONTROL | KeyModifiers::SUPER) =>
                        {
                            let mut utf8 = [0u8; 4];
                            for b in ch.encode_utf8(&mut utf8).as_bytes() {
                                if self.line_buf.len() < Self::MAX_LINE_BYTES {
                                    self.line_buf.push(*b);
                                } else {
                                    self.line_overflow = true;
                                }
                            }
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
            Ok(None)
        }
    }
}

#[cfg(unix)]
fn read_stdin_byte(byte: &mut u8) -> io::Result<usize> {
    // Читаем напрямую из дескриптора ядра без userspace-буфера `std::io::stdin()`,
    // иначе `BufReader` заберёт `\n` из FD за одно системное чтение и следующий
    // `poll(STDIN_FILENO)` не увидит оставшийся в userspace символ перевода строки.
    let rc = unsafe { libc::read(libc::STDIN_FILENO, std::ptr::from_mut(byte).cast(), 1) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc as usize)
    }
}

#[cfg(unix)]
fn poll_stdin_ready() -> io::Result<bool> {
    let mut pfd = libc::pollfd {
        fd: libc::STDIN_FILENO,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(err);
    }
    Ok(rc > 0 && (pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[test]
    fn schema_and_parser_enforce_bounds_duplicates_and_unknown_fields() {
        let def = definition();
        assert_eq!(def.name, TOOL_NAME);
        assert!(def.description.contains("не запрашивайте пароли"));

        // Valid 2-question payload with whitespace normalization.
        let parsed = parse_request(&json!({
            "questions": [
                {
                    "question": "  Какой формат\nконфига выбрать?  ",
                    "options": ["TOML (Рекомендуется)", "YAML"]
                },
                {
                    "question": "Где хранить миграции?",
                    "options": ["migrations/ (Рекомендуется)", "db/migrations/", "sql/"]
                }
            ]
        }))
        .unwrap();
        assert_eq!(parsed.questions.len(), 2);
        assert_eq!(
            parsed.questions[0].question,
            "Какой формат конфига выбрать?"
        );

        // Unknown top-level or nested field is rejected.
        assert!(
            parse_request(&json!({
                "questions": [{"question": "Q?", "options": ["A", "B"]}],
                "extra": true
            }))
            .is_err()
        );
        assert!(
            parse_request(&json!({
                "questions": [{"question": "Q?", "options": ["A", "B"], "multi": true}]
            }))
            .is_err()
        );

        // Bounds: 0 questions, 4 questions, 1 option, 5 options.
        assert!(parse_request(&json!({"questions": []})).is_err());
        assert!(
            parse_request(&json!({
                "questions": [
                    {"question": "Q1?", "options": ["A", "B"]},
                    {"question": "Q2?", "options": ["A", "B"]},
                    {"question": "Q3?", "options": ["A", "B"]},
                    {"question": "Q4?", "options": ["A", "B"]}
                ]
            }))
            .is_err()
        );
        assert!(
            parse_request(&json!({"questions": [{"question": "Q?", "options": ["OnlyOne"]}]}))
                .is_err()
        );
        assert!(
            parse_request(&json!({
                "questions": [{"question": "Q?", "options": ["1", "2", "3", "4", "5"]}]
            }))
            .is_err()
        );

        // Normalized duplicate options & reserved "Другое"/"Other".
        assert!(
            parse_request(&json!({
                "questions": [{"question": "Q?", "options": ["Вариант  А", "вариант\nа"]}]
            }))
            .is_err()
        );
        assert!(
            parse_request(&json!({
                "questions": [{"question": "Q?", "options": ["SQLite (Рекомендуется)", "Другое"]}]
            }))
            .is_err()
        );
        assert!(
            parse_request(&json!({
                "questions": [{"question": "Q?", "options": ["SQLite", "Other..."]}]
            }))
            .is_err()
        );

        // Length limits in Unicode scalars (not bytes).
        let max_q = "я".repeat(MAX_QUESTION_CHARS);
        let over_q = "я".repeat(MAX_QUESTION_CHARS + 1);
        assert!(
            parse_request(&json!({"questions": [{"question": max_q, "options": ["Да", "Нет"]}]}))
                .is_ok()
        );
        assert!(
            parse_request(&json!({"questions": [{"question": over_q, "options": ["Да", "Нет"]}]}))
                .is_err()
        );
    }

    #[test]
    fn plain_mode_rejects_empty_default_handles_eof_interrupt_and_overlong_custom_input() {
        let spec = QuestionSpec {
            question: "Какую БД использовать?".into(),
            options: vec!["SQLite (Рекомендуется)".into(), "PostgreSQL".into()],
        };

        // Empty input must NOT select option 1; subsequent "2" selects PostgreSQL.
        let mut inputs = VecDeque::from([Ok(Some(String::new())), Ok(Some("2".into()))]);
        let mut notices = Vec::new();
        let out = ask_one_plain_with(
            &spec,
            0,
            1,
            |_| inputs.pop_front().unwrap(),
            |msg| notices.push(msg.to_owned()),
        )
        .unwrap();
        assert_eq!(out, AskOutcome::Selected(1));
        assert!(notices.iter().any(|m| m.contains("Пустой ввод")));

        // Custom answer: overlong rejected without truncation, "0" backs out, then valid custom.
        let overlong = "а".repeat(MAX_ANSWER_CHARS + 5);
        let mut inputs = VecDeque::from([
            Ok(Some("3".into())),
            Ok(Some(overlong)),
            Ok(Some("0".into())),
            Ok(Some("3".into())),
            Ok(Some("  DuckDB\nв памяти  ".into())),
        ]);
        let out = ask_one_plain_with(&spec, 0, 1, |_| inputs.pop_front().unwrap(), |_| {}).unwrap();
        assert_eq!(out, AskOutcome::Custom("DuckDB в памяти".into()));

        // EOF -> Dismissed, Interrupted -> Interrupted.
        let eof = ask_one_plain_with(&spec, 0, 1, |_| Ok(None), |_| {}).unwrap();
        assert_eq!(eof, AskOutcome::Dismissed);
        let intr = ask_one_plain_with(
            &spec,
            0,
            1,
            |_| Err(io::Error::new(io::ErrorKind::Interrupted, "ctrl-c")),
            |_| {},
        )
        .unwrap();
        assert_eq!(intr, AskOutcome::Interrupted);
    }

    #[test]
    fn cancelled_receipt_never_masquerades_as_answered_and_checked_redaction_fails_closed() {
        let partial = AskReceipt::build(
            2,
            vec![AnsweredQuestion {
                question_index: 0,
                question: "Стек?".into(),
                source: AnswerSource::Option,
                option_index: Some(0),
                answer: "Rust".into(),
            }],
            true,
        );
        assert_eq!(partial.status, AskStatus::Cancelled);
        assert_eq!(partial.answered_count, 1);
        assert!(partial.note.as_deref().unwrap().contains("прервал опрос"));

        let redacted = partial
            .redact_checked(|text| Ok(text.replace("Rust", "[REDACTED]")))
            .unwrap();
        assert_eq!(redacted.answers[0].answer, "[REDACTED]");

        assert!(
            partial
                .redact_checked(|_| bail!("redaction unavailable"))
                .is_err()
        );
    }
}
