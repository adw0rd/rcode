//! Context budgets. Cloud providers keep the historical local budget in
//! characters; local servers are budgeted in conservatively estimated tokens
//! against the context the profile (or the running server) actually provides.
use crate::{
    config::{ProviderKind, ProviderSettings},
    protocol::{Message, ToolDefinition},
    state::{AUTO_COMPACT_THRESHOLD, CONTEXT_LIMIT},
};
use serde::Serialize;
use serde_json::{Map, Value, json};

/// Estimated tokens charged for one image in a local request.
pub const IMAGE_TOKENS: usize = 1536;
const MESSAGE_TOKENS: usize = 8;
/// Upper bound of the usage-based correction of estimates.
pub const MAX_CALIBRATION: f64 = 2.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextUnit {
    Chars,
    EstimatedTokens,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ContextSource {
    Cloud,
    /// `context_tokens` of the profile: an estimate the server did not confirm.
    Profile,
    /// The context reported by the running server is smaller and wins.
    Runtime,
}

impl ContextSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cloud => "cloud",
            Self::Profile => "profile",
            Self::Runtime => "runtime",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ContextBudget {
    pub unit: ContextUnit,
    /// Whole input allowance of one request, including `overhead`.
    pub limit: usize,
    /// System prompt and tool definitions; history must fit next to them.
    pub overhead: usize,
    pub source: ContextSource,
    /// Effective server context and answer reserve for local profiles.
    pub context_tokens: Option<u32>,
    pub max_output_tokens: Option<u32>,
    calibration: f64,
}

pub fn message_chars(message: &Message) -> usize {
    message.content.as_ref().map_or(0, |s| s.chars().count())
        + message.images.len() * crate::images::IMAGE_CONTEXT_CHARS
        + message
            .tool_calls
            .iter()
            .map(|call| call.function.arguments.len())
            .sum::<usize>()
}

/// Deliberately pessimistic. Dense code and JSON tool schemas reach 0.35-0.45
/// tokens per ASCII character, so ASCII counts as 2.5 bytes per token; other
/// UTF-8 text (Cyrillic, CJK) as 3 bytes per token.
pub fn estimate_text_tokens(text: &str) -> usize {
    let ascii = text.bytes().filter(u8::is_ascii).count();
    ascii.div_ceil(5) * 2 + (text.len() - ascii).div_ceil(3)
}

pub fn estimate_message_tokens(message: &Message) -> usize {
    let calls: usize = message
        .tool_calls
        .iter()
        .map(|call| {
            estimate_text_tokens(&call.function.name)
                + estimate_text_tokens(&call.function.arguments)
                + estimate_text_tokens(&call.id)
        })
        .sum();
    MESSAGE_TOKENS
        + message.content.as_deref().map_or(0, estimate_text_tokens)
        + message.images.len() * IMAGE_TOKENS
        + calls
}

pub fn estimate_tools(tools: &[ToolDefinition]) -> usize {
    serde_json::to_string(tools).map_or(0, |json| estimate_text_tokens(&json))
}

/// System prompt and tool definitions sent with every request.
pub fn estimate_overhead(system: &str, tools: &[ToolDefinition]) -> usize {
    MESSAGE_TOKENS + estimate_text_tokens(system) + estimate_tools(tools)
}

/// Uncalibrated estimate of a request exactly as sent (system message included);
/// compared with the prompt tokens a server reports to calibrate later estimates.
pub fn estimate_request(messages: &[Message], tools: &[ToolDefinition]) -> usize {
    messages.iter().map(estimate_message_tokens).sum::<usize>() + estimate_tools(tools)
}

/// Raises later estimates when the server counted more prompt tokens.
pub fn calibrated(current: f64, estimated: usize, observed_prompt_tokens: u64) -> f64 {
    if estimated == 0 || observed_prompt_tokens as f64 <= estimated as f64 {
        return current;
    }
    current.max((observed_prompt_tokens as f64 / estimated as f64).min(MAX_CALIBRATION))
}

impl ContextBudget {
    pub fn cloud() -> Self {
        Self {
            unit: ContextUnit::Chars,
            limit: CONTEXT_LIMIT,
            overhead: 0,
            source: ContextSource::Cloud,
            context_tokens: None,
            max_output_tokens: None,
            calibration: 1.0,
        }
    }

    /// `runtime_context`: context reported by the running server, if any.
    pub fn for_provider(
        settings: &ProviderSettings,
        runtime_context: Option<u32>,
        calibration: f64,
        overhead: usize,
    ) -> Self {
        let Some(local) = settings
            .local
            .as_ref()
            .filter(|_| settings.kind == ProviderKind::Local)
        else {
            return Self::cloud();
        };
        let (context, source) = match runtime_context {
            Some(runtime) if runtime < local.context_tokens => (runtime, ContextSource::Runtime),
            _ => (local.context_tokens, ContextSource::Profile),
        };
        let output = effective_output(settings.max_output_tokens, context);
        let reserve = (context / 10).max(1024);
        Self {
            unit: ContextUnit::EstimatedTokens,
            limit: context.saturating_sub(output).saturating_sub(reserve) as usize,
            overhead,
            source,
            context_tokens: Some(context),
            max_output_tokens: Some(output),
            calibration: calibration.clamp(1.0, MAX_CALIBRATION),
        }
    }

    pub fn is_tokens(&self) -> bool {
        self.unit == ContextUnit::EstimatedTokens
    }

    pub fn measure(&self, message: &Message) -> usize {
        match self.unit {
            ContextUnit::Chars => message_chars(message),
            ContextUnit::EstimatedTokens => {
                (estimate_message_tokens(message) as f64 * self.calibration).ceil() as usize
            }
        }
    }

    pub fn used(&self, messages: &[Message]) -> usize {
        messages.iter().map(|message| self.measure(message)).sum()
    }

    /// What the footer shows: history plus the fixed request overhead.
    pub fn request_used(&self, messages: &[Message]) -> usize {
        self.used(messages).saturating_add(self.scaled_overhead())
    }

    fn scaled_overhead(&self) -> usize {
        (self.overhead as f64 * self.calibration).ceil() as usize
    }

    /// Space for the conversation history next to the system prompt and tools.
    pub fn history_limit(&self) -> usize {
        self.limit.saturating_sub(self.scaled_overhead())
    }

    pub fn threshold(&self) -> usize {
        match self.unit {
            ContextUnit::Chars => AUTO_COMPACT_THRESHOLD,
            ContextUnit::EstimatedTokens => self.history_limit() * 5 / 6,
        }
    }

    pub fn target(&self) -> usize {
        match self.unit {
            ContextUnit::Chars => 110_000,
            ContextUnit::EstimatedTokens => self.history_limit() * 11 / 18,
        }
    }

    pub fn manual_target(&self) -> usize {
        match self.unit {
            ContextUnit::Chars => 20_000,
            ContextUnit::EstimatedTokens => self.history_limit() / 9,
        }
    }

    /// Minimum headroom kept above protected messages during compaction.
    pub fn reserve(&self) -> usize {
        match self.unit {
            ContextUnit::Chars => 4000,
            ContextUnit::EstimatedTokens => (self.history_limit() / 45).max(256),
        }
    }

    pub fn unit_label(&self) -> &'static str {
        match self.unit {
            ContextUnit::Chars => "символов",
            ContextUnit::EstimatedTokens => "оценочных токенов",
        }
    }

    pub fn limit_sentence(&self) -> String {
        match self.unit {
            ContextUnit::Chars => format!("Локальный лимит — {CONTEXT_LIMIT} символов."),
            ContextUnit::EstimatedTokens => format!(
                "Лимит запроса local — {} оценочных токенов: контекст {} ({}), минус ответ {} и резерв; системный промпт и инструменты занимают ~{}.",
                self.limit,
                self.context_tokens.unwrap_or_default(),
                if self.source == ContextSource::Runtime {
                    "сообщён сервером"
                } else {
                    "из профиля, сервером не подтверждён"
                },
                self.max_output_tokens.unwrap_or_default(),
                self.scaled_overhead()
            ),
        }
    }

    pub fn percent(&self, used: usize) -> usize {
        used.saturating_mul(100)
            .checked_div(self.limit)
            .unwrap_or(100)
    }

    /// Tool output admitted to a local history per model step: a quarter of the
    /// history, so the newest receipts stay verbatim next to the task and memory
    /// through the following compaction. Cloud keeps its unbounded receipts.
    pub fn receipt_limit(&self) -> Option<usize> {
        self.is_tokens().then(|| self.history_limit() / 4)
    }
}

/// denied/interrupted/unknown receipts: never shortened or summarised as success.
pub fn is_restricted_receipt(content: &str) -> bool {
    serde_json::from_str::<Value>(content).is_ok_and(|value| {
        value["error"] == "denied"
            || value["error"] == "interrupted"
            || value["outcome"] == "unknown"
    })
}

const TRUNCATED: &str = "rcode_truncated";

/// Status, outcome and identity fields: never dropped from a shortened receipt
/// and never changed in type. Oversized strings among them are shortened only
/// down to `ESSENTIAL_CHARS`, so they stay present and bounded.
const ESSENTIAL: &[&str] = &[
    "error",
    "message",
    "status",
    "outcome",
    "exit_code",
    "signal",
    "reason",
    "path",
    "sha256",
    "start_line",
    "total_lines",
    "next_line",
    "ends_with_newline",
    "truncated",
    "next_offset",
];
const ESSENTIAL_CHARS: usize = 400;
/// Head of a non-JSON result kept by the last-resort receipt.
const EXCERPT_CHARS: usize = 300;

fn truncation_hint(tool: &str) -> &'static str {
    match tool {
        "read_file" => {
            "Host shortened this read to fit the local model context; see rcode_truncated.fields.content. With complete_lines, every shown line is whole: continue with read_file start_line=next_line and a smaller max_lines. With partial_line, that single line is longer than the context allows and its omitted part cannot be obtained by paging (next_line, if any, is the following line): use search for the exact text you need. Do not re-read the same range."
        }
        "run_command" => {
            "Host shortened this output to fit the local model context; the command ran once and was not repeated. Do not re-run it to see the omitted lines: for a file use read_file with start_line/max_lines or search; otherwise use a narrower side-effect-free command (grep -n, sed -n 'A,Bp')."
        }
        _ => {
            "Host shortened this result to fit the local model context. Narrow the request (path, pattern, offset, max_results) instead of repeating it."
        }
    }
}

/// Appended to the hint when the host hid entries of a paginated result: the
/// tool's `next_offset` pointed past the hidden entries, so it is withdrawn.
const PAGINATION_HINT: &str = "The host hid entries of this page, so the original pagination no longer applies: next_offset was withdrawn (original_next_offset is only a record, not a continuation; null meant the listing ended after the hidden entries). The hidden entries follow the shown ones: to access them, repeat the request from your original offset with a narrower range (smaller max_results or a narrower path).";

fn pagination_hint(tool: &str) -> String {
    format!("{} {PAGINATION_HINT}", truncation_hint(tool))
}

/// Head and tail of `text` within `budget` characters; metadata of the omitted middle.
fn cut_middle(text: &str, budget: usize) -> (String, Value) {
    let chars: Vec<char> = text.chars().collect();
    let head = budget * 2 / 3;
    let tail = budget - head;
    let start: String = chars[..head].iter().collect();
    let omitted: String = chars[head..chars.len() - tail].iter().collect();
    let end: String = chars[chars.len() - tail..].iter().collect();
    let first = start.matches('\n').count() + 1;
    let last = first + omitted.matches('\n').count();
    let lines = json!([first, last]);
    (
        format!(
            "{start}\n[rcode: {} characters omitted here, lines {first}-{last}]\n{end}",
            omitted.chars().count()
        ),
        json!({"omitted_chars": omitted.chars().count(), "omitted_lines": lines}),
    )
}

/// An essential string longer than `ESSENTIAL_CHARS`: shortened in the middle
/// to at least that many characters, never removed.
fn bound_essential(text: &str, budget: usize) -> (String, Value) {
    let length = text.chars().count();
    cut_middle(text, budget.max(ESSENTIAL_CHARS).min(length))
}

fn shrink_object(
    tool: &str,
    mut object: Map<String, Value>,
    share: f64,
    original: usize,
    is_error: bool,
) -> String {
    let mut omitted = Map::new();
    // Set when entries of an array were hidden; next_offset is withdrawn after
    // the loop (its key is still in `keys`).
    let mut paging_hidden = false;
    let keys: Vec<String> = object.keys().cloned().collect();
    for key in keys {
        let size = object[&key].to_string().chars().count();
        if size <= 256 {
            continue;
        }
        let budget = ((size as f64) * share) as usize;
        if ESSENTIAL.contains(&key.as_str()) {
            // Status fields keep their type; only long strings are shortened.
            if let Value::String(text) = &object[&key]
                && text.chars().count() > ESSENTIAL_CHARS
            {
                let (text, info) = bound_essential(text, budget);
                object.insert(key.clone(), text.into());
                omitted.insert(key, info);
            }
            continue;
        }
        match object[&key].clone() {
            Value::String(text)
                if tool == "read_file"
                    && key == "content"
                    && text
                        .split_inclusive('\n')
                        .next()
                        .is_some_and(|line| line.chars().count() <= budget) =>
            {
                // Whole numbered lines only, so paging from next_line stays
                // exact. Characters, not UTF-8 bytes, are compared with budget.
                let mut kept = String::new();
                let mut kept_chars = 0;
                let mut lines = 0;
                for line in text.split_inclusive('\n') {
                    let chars = line.chars().count();
                    if kept_chars + chars > budget {
                        break;
                    }
                    kept.push_str(line);
                    kept_chars += chars;
                    lines += 1;
                }
                let start = object["start_line"].as_u64().unwrap_or(1);
                object.insert(key.clone(), kept.into());
                object.insert("next_line".into(), json!(start + lines));
                omitted.insert(
                    key,
                    json!({"complete_lines": true, "shown_lines": [start, start + lines - 1], "next_line": start + lines}),
                );
            }
            Value::String(text) if tool == "read_file" && key == "content" => {
                // The first line alone is longer than the budget (for example a
                // minified file): show its head and tail and say so. Paging
                // cannot return the omitted middle of a line.
                let start = object["start_line"].as_u64().unwrap_or(1);
                let mut lines = text.split_inclusive('\n');
                let line = lines.next().unwrap_or_default();
                let more = lines.next().is_some();
                let body = line.strip_suffix('\n').unwrap_or(line);
                let chars: Vec<char> = body.chars().collect();
                let keep = budget.min(chars.len());
                let head = keep * 2 / 3;
                let tail = keep - head;
                let omitted_chars = chars.len() - keep;
                let shown: String = chars[..head].iter().collect();
                let end: String = chars[chars.len() - tail..].iter().collect();
                object.insert(
                    key.clone(),
                    format!(
                        "{shown}\n[rcode: {omitted_chars} characters omitted inside line {start}; this line is longer than the local context]\n{end}\n"
                    )
                    .into(),
                );
                let mut info = json!({"partial_line": start, "line_chars": chars.len(), "omitted_chars": omitted_chars, "complete_lines": false});
                if more {
                    // The following lines were not shown; resume from them.
                    object.insert("next_line".into(), json!(start + 1));
                    info["next_line"] = json!(start + 1);
                }
                omitted.insert(key, info);
            }
            Value::String(text) => {
                let (text, info) = cut_middle(&text, budget.min(text.chars().count()));
                object.insert(key.clone(), text.into());
                omitted.insert(key, info);
            }
            Value::Array(items) => {
                let mut kept = Vec::new();
                let mut used = 2;
                for item in &items {
                    used += item.to_string().chars().count() + 1;
                    if used > budget {
                        break;
                    }
                    kept.push(item.clone());
                }
                let hidden = items.len() - kept.len();
                let mut info = json!({"omitted_items": hidden});
                if hidden > 0
                    && let Some(next) = object.get("next_offset")
                {
                    // Not a continuation: it pointed past the hidden entries.
                    info["original_next_offset"] = next.clone();
                    info["narrow_request"] = true.into();
                    paging_hidden = true;
                }
                omitted.insert(key.clone(), info);
                object.insert(key, Value::Array(kept));
                if object.get("truncated").is_some_and(Value::is_boolean) {
                    object.insert("truncated".into(), true.into());
                }
            }
            _ => {
                let text = object[&key].to_string();
                let (text, info) = cut_middle(&text, budget.min(text.chars().count()));
                object.insert(key.clone(), text.into());
                omitted.insert(key, info);
            }
        }
    }
    let hint = if paging_hidden {
        object.remove("next_offset");
        pagination_hint(tool)
    } else {
        truncation_hint(tool).to_owned()
    };
    object.entry("is_error").or_insert_with(|| is_error.into());
    object.insert(
        TRUNCATED.into(),
        json!({"original_chars": original, "fields": omitted, "hint": hint}),
    );
    Value::Object(object).to_string()
}

/// Last resort when no proportional shortening fits: the status and identity
/// fields of the original (or the head of a non-JSON result) and an explicit
/// error flag. Its size is bounded by constants, so the outcome is never
/// replaced by a bare "truncated" that reads as success.
fn essential_receipt(
    tool: &str,
    object: Option<&Map<String, Value>>,
    content: &str,
    original: usize,
    is_error: bool,
) -> String {
    let mut receipt = Map::new();
    let mut dropped = Vec::new();
    match object {
        Some(object) => {
            for (key, value) in object {
                if !ESSENTIAL.contains(&key.as_str()) {
                    dropped.push(key.clone());
                    continue;
                }
                let value = match value {
                    Value::String(text) if text.chars().count() > ESSENTIAL_CHARS => {
                        bound_essential(text, ESSENTIAL_CHARS).0.into()
                    }
                    other => other.clone(),
                };
                receipt.insert(key.clone(), value);
            }
        }
        None => {
            let excerpt: String = content.chars().take(EXCERPT_CHARS).collect();
            receipt.insert("excerpt".into(), excerpt.into());
        }
    }
    // A dropped non-empty array hides the entries next_offset would skip:
    // withdraw it as a continuation, as shrink_object does.
    let paging_hidden = object.is_some_and(|object| {
        dropped.iter().any(|key| {
            object[key]
                .as_array()
                .is_some_and(|items| !items.is_empty())
        })
    });
    let original_next = paging_hidden
        .then(|| receipt.remove("next_offset"))
        .flatten();
    if original_next.is_some() && receipt.get("truncated").is_some_and(Value::is_boolean) {
        receipt.insert("truncated".into(), true.into());
    }
    receipt.entry("is_error").or_insert_with(|| is_error.into());
    let mut truncated = json!({"original_chars": original, "hint": truncation_hint(tool)});
    if let Some(next) = original_next {
        truncated["original_next_offset"] = next;
        truncated["narrow_request"] = true.into();
        truncated["hint"] = pagination_hint(tool).into();
    }
    if !dropped.is_empty() {
        truncated["omitted_fields"] = json!(dropped);
    }
    receipt.insert(TRUNCATED.into(), truncated);
    Value::Object(receipt).to_string()
}

/// Bounds one tool result to `limit` units of `budget` before it enters the
/// history, keeping the structure, status fields and what was omitted. The
/// full result was already shown to the user in the tool event.
pub fn bound_receipt(
    budget: &ContextBudget,
    tool: &str,
    content: &str,
    limit: usize,
    is_error: bool,
) -> String {
    let cost = |text: &str| budget.measure(&Message::text("tool", text));
    let total = cost(content);
    if total <= limit || is_restricted_receipt(content) {
        return content.to_owned();
    }
    let original = content.chars().count();
    let object = match serde_json::from_str::<Value>(content) {
        Ok(Value::Object(object)) => Some(object),
        _ => None,
    };
    let mut share = limit as f64 / total as f64;
    for _ in 0..16 {
        let candidate = match &object {
            Some(object) => shrink_object(tool, object.clone(), share, original, is_error),
            None => {
                let (text, info) = cut_middle(content, (original as f64 * share) as usize);
                format!(
                    "{text}\n[{TRUNCATED}: {}; {}]",
                    json!({"original_chars": original, "is_error": is_error, "omitted": info}),
                    truncation_hint(tool)
                )
            }
        };
        if cost(&candidate) <= limit {
            return candidate;
        }
        share *= 0.8;
    }
    essential_receipt(tool, object.as_ref(), content, original, is_error)
}

/// The answer reserve never exceeds a quarter of the effective context.
pub fn effective_output(max_output_tokens: u32, context_tokens: u32) -> u32 {
    max_output_tokens.min(context_tokens / 4).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::{LocalRuntime, profile_settings};

    fn local() -> ProviderSettings {
        profile_settings("p", "http://127.0.0.1:8080/v1", LocalRuntime::Mlx, "m")
    }

    #[test]
    fn estimate_is_conservative_for_ascii_and_cyrillic() {
        let ascii = "fn main() { println!(\"hello\"); }".repeat(20);
        let cyrillic = "Привет, мир! Это проверка оценки токенов. ".repeat(20);
        // Typical BPE tokenizers: ~4 ASCII chars and ~2-3 Cyrillic chars per token.
        assert!(estimate_text_tokens(&ascii) >= ascii.len() / 4);
        assert!(estimate_text_tokens(&cyrillic) >= cyrillic.chars().count() / 2);
        let message = Message::user("abc");
        assert_eq!(estimate_message_tokens(&message), 8 + 2);
        // Tool schemas are dense JSON: at least one token per 2.5 characters.
        let tools = serde_json::to_string(&crate::tools::Tools::definitions()).unwrap();
        assert!(estimate_text_tokens(&tools) * 5 >= tools.chars().count() * 2);
        let code = "let x: Vec<u8> = vec![1, 2, 3]; // ok\n".repeat(50);
        assert!(estimate_text_tokens(&code) * 5 >= code.len() * 2);
        // Cyrillic: two bytes per character, so three bytes per token is ~0.67 per char.
        assert_eq!(estimate_text_tokens("абв"), 2);
    }

    #[test]
    fn local_budget_32768_4096_is_25396() {
        let budget = ContextBudget::for_provider(&local(), None, 1.0, 0);
        assert!(budget.is_tokens());
        assert_eq!(budget.limit, 25_396);
        assert_eq!(budget.source, ContextSource::Profile);
        assert_eq!(budget.max_output_tokens, Some(4096));
    }

    #[test]
    fn budget_counts_system_and_tools() {
        let tools = crate::tools::Tools::definitions();
        let overhead = estimate_overhead(&"s".repeat(3000), &tools);
        assert!(overhead > 1000 + 8);
        let budget = ContextBudget::for_provider(&local(), None, 1.0, overhead);
        assert_eq!(budget.history_limit(), 25_396 - overhead);
        assert_eq!(budget.request_used(&[]), overhead);
        assert!(budget.threshold() < budget.history_limit());
    }

    #[test]
    fn runtime_ctx_smaller_than_profile_wins() {
        let budget = ContextBudget::for_provider(&local(), Some(8192), 1.0, 0);
        assert_eq!(budget.source, ContextSource::Runtime);
        assert_eq!(budget.context_tokens, Some(8192));
        assert_eq!(budget.max_output_tokens, Some(2048));
        assert_eq!(budget.limit, 8192 - 2048 - 1024);
        let larger = ContextBudget::for_provider(&local(), Some(131_072), 1.0, 0);
        assert_eq!(larger.source, ContextSource::Profile);
        assert_eq!(larger.limit, 25_396);
    }

    #[test]
    fn calibration_raises_estimate_from_usage_capped() {
        assert_eq!(calibrated(1.0, 1000, 900), 1.0);
        assert_eq!(calibrated(1.0, 1000, 1500), 1.5);
        assert_eq!(calibrated(1.5, 1000, 1200), 1.5);
        assert_eq!(calibrated(1.0, 1000, 9000), MAX_CALIBRATION);
        let message = Message::user("x".repeat(300));
        let plain = ContextBudget::for_provider(&local(), None, 1.0, 0).measure(&message);
        let scaled = ContextBudget::for_provider(&local(), None, 1.5, 0).measure(&message);
        assert_eq!(plain, 128);
        assert_eq!(scaled, 192);
    }

    #[test]
    fn local_receipts_are_bounded_with_exact_paging_and_status() {
        let budget = ContextBudget::for_provider(&local(), None, 1.0, 9000);
        let limit = budget.receipt_limit().unwrap();
        assert_eq!(limit, (25_396 - 9000) / 4);
        assert_eq!(ContextBudget::cloud().receipt_limit(), None);
        let cost = |text: &str| budget.measure(&Message::text("tool", text));
        let lines: String = (1..=500)
            .map(|line| format!("{line}\tdocumentation line {line} with some words\n"))
            .collect();
        let read = json!({"path":"README.md","sha256":"abc","start_line":1,"total_lines":900,"next_line":501,"content":lines}).to_string();
        let bounded = bound_receipt(&budget, "read_file", &read, limit, false);
        assert!(cost(&bounded) <= limit);
        let value: Value = serde_json::from_str(&bounded).unwrap();
        let shown = value["content"].as_str().unwrap();
        let next = value["next_line"].as_u64().unwrap();
        // Only whole lines; paging resumes exactly at the first omitted line.
        assert!(shown.ends_with('\n') && next > 1 && next < 501);
        assert_eq!(shown.lines().count() as u64, next - 1);
        assert!(
            shown
                .lines()
                .last()
                .unwrap()
                .starts_with(&format!("{}\t", next - 1))
        );
        assert_eq!(value["sha256"], "abc");
        assert_eq!(value["total_lines"], 900);
        assert!(
            value["rcode_truncated"]["hint"]
                .as_str()
                .unwrap()
                .contains("start_line")
        );

        let stdout: String = (1..=2000).map(|line| format!("out {line}\n")).collect();
        let shell = json!({"exit_code":2,"signal":null,"stdout":stdout,"stderr":"FAILURE_AT_END","reason":null}).to_string();
        let bounded = bound_receipt(&budget, "run_command", &shell, limit, true);
        assert!(cost(&bounded) <= limit);
        let value: Value = serde_json::from_str(&bounded).unwrap();
        assert_eq!(value["exit_code"], 2, "status fields are never altered");
        assert_eq!(value["stderr"], "FAILURE_AT_END");
        let stdout = value["stdout"].as_str().unwrap();
        assert!(stdout.starts_with("out 1\n") && stdout.ends_with("out 2000\n"));
        let omitted = &value["rcode_truncated"]["fields"]["stdout"]["omitted_lines"];
        assert!(omitted[0].as_u64().unwrap() > 1 && omitted[1].as_u64().unwrap() < 2000);
        assert!(stdout.contains(&format!("lines {}-{}", omitted[0], omitted[1])));

        let plain = "x".repeat(200_000);
        assert!(cost(&bound_receipt(&budget, "wait_agent", &plain, limit, false)) <= limit);
        // Small results stay byte-for-byte unchanged.
        assert_eq!(
            bound_receipt(&budget, "read_file", "short", limit, false),
            "short"
        );
    }

    #[test]
    fn tiny_budgets_keep_status_identity_and_an_explicit_error_flag() {
        let budget = ContextBudget::for_provider(&local(), None, 1.0, 9000);
        let cost = |text: &str| budget.measure(&Message::text("tool", text));
        // A failed command whose output alone exceeds the limit many times.
        let shell = json!({"exit_code":1,"signal":null,"stdout":"o".repeat(60_000),"stderr":"e".repeat(20_000),"reason":"output_limit","shell_changes_managed":false}).to_string();
        for limit in [50, 300, 2000] {
            let bounded = bound_receipt(&budget, "run_command", &shell, limit, true);
            let value: Value = serde_json::from_str(&bounded).unwrap();
            assert_eq!(value["exit_code"], 1, "{limit}: {bounded}");
            assert!(value.get("signal").is_some_and(Value::is_null), "{bounded}");
            assert_eq!(value["reason"], "output_limit");
            assert_eq!(value["is_error"], true);
            assert!(value["rcode_truncated"]["original_chars"].as_u64().unwrap() > 80_000);
            if limit == 50 {
                // The last-resort receipt lists what it dropped.
                assert!(
                    value["rcode_truncated"]["omitted_fields"]
                        .to_string()
                        .contains("stdout")
                );
                assert!(value.get("stdout").is_none());
            }
            // Bounded by constants even when the limit cannot be met.
            assert!(bounded.chars().count() < 2_000 || cost(&bounded) <= limit);
        }
        // Oversized essential strings stay present, typed and bounded.
        let failure = json!({"error":"x".repeat(10_000),"path":"src/main.rs","sha256":"f".repeat(64),"status":404,"truncated":true,"details":"d".repeat(30_000)}).to_string();
        for limit in [20, 600, 3000] {
            let bounded = bound_receipt(&budget, "read_file", &failure, limit, true);
            let value: Value = serde_json::from_str(&bounded).unwrap();
            let error = value["error"].as_str().unwrap();
            assert!(
                error.starts_with("xxx") && error.chars().count() < 10_000,
                "{error}"
            );
            assert_eq!(value["path"], "src/main.rs");
            assert_eq!(value["sha256"], "f".repeat(64));
            assert_eq!(value["status"], 404);
            assert_eq!(value["truncated"], true);
            assert_eq!(value["is_error"], true);
        }
        // A successful receipt says so explicitly too.
        let success =
            json!({"path":"a.txt","sha256":"abc","entries":["e".repeat(50_000)]}).to_string();
        let value: Value =
            serde_json::from_str(&bound_receipt(&budget, "list_files", &success, 20, false))
                .unwrap();
        assert_eq!(value["is_error"], false);
        assert_eq!(value["path"], "a.txt");
        assert_eq!(value["sha256"], "abc");
        // A non-JSON error keeps its head and the error flag, not a bare marker.
        let plain = format!("Файл не найден: missing.txt\n{}", "z".repeat(200_000));
        for limit in [20, 5000] {
            let bounded = bound_receipt(&budget, "read_file", &plain, limit, true);
            assert!(bounded.contains("Файл не найден: missing.txt"), "{bounded}");
            assert!(bounded.contains(r#""is_error":true"#), "{bounded}");
            assert!(bounded.chars().count() < 30_000);
        }
    }

    #[test]
    fn read_file_pages_whole_utf8_lines_and_marks_partial_long_lines() {
        // The first line fits by characters but not by UTF-8 bytes.
        let lines: String = (41..=50)
            .map(|line| format!("{line}\t{}\n", "я".repeat(1000)))
            .collect();
        let object = json!({"path":"ru.txt","sha256":"abc","start_line":41,"total_lines":90,"next_line":51,"ends_with_newline":true,"content":lines});
        let Value::Object(object) = object else {
            unreachable!()
        };
        let size = object["content"].to_string().chars().count();
        let first = 1004;
        assert!(size * 15 / 100 > first && size * 15 / 100 < 2 * 1000);
        let value: Value =
            serde_json::from_str(&shrink_object("read_file", object, 0.15, size, false)).unwrap();
        let shown = value["content"].as_str().unwrap();
        assert_eq!(shown, format!("41\t{}\n", "я".repeat(1000)));
        assert_eq!(value["next_line"], 42);
        let fields = &value["rcode_truncated"]["fields"]["content"];
        assert_eq!(fields["complete_lines"], true);
        assert_eq!(fields["shown_lines"], json!([41, 41]));

        let budget = ContextBudget::for_provider(&local(), None, 1.0, 9000);
        let limit = budget.receipt_limit().unwrap();
        let cost = |text: &str| budget.measure(&Message::text("tool", text));
        let lines: String = (1..=500)
            .map(|line| format!("{line}\tстрока документации номер {line} с русским текстом\n"))
            .collect();
        let read = json!({"path":"ru.md","sha256":"abc","start_line":1,"total_lines":800,"next_line":501,"ends_with_newline":true,"content":lines}).to_string();
        let bounded = bound_receipt(&budget, "read_file", &read, limit, false);
        assert!(cost(&bounded) <= limit);
        let value: Value = serde_json::from_str(&bounded).unwrap();
        let shown = value["content"].as_str().unwrap();
        let next = value["next_line"].as_u64().unwrap();
        assert!(shown.ends_with('\n') && next > 1 && next < 501);
        assert_eq!(shown.lines().count() as u64, next - 1);
        assert!(
            shown
                .lines()
                .last()
                .unwrap()
                .starts_with(&format!("{}\t", next - 1))
        );
        assert_eq!(
            value["rcode_truncated"]["fields"]["content"]["complete_lines"],
            true
        );

        // A minified single line: honest partial-line metadata, no paging promise.
        let minified = format!("1\t{}END\n", "{\"k\":\"значение\"},".repeat(1500));
        let read = json!({"path":"app.min.js","sha256":"def","start_line":1,"total_lines":1,"next_line":null,"ends_with_newline":true,"content":minified}).to_string();
        let bounded = bound_receipt(&budget, "read_file", &read, limit, false);
        assert!(cost(&bounded) <= limit);
        let value: Value = serde_json::from_str(&bounded).unwrap();
        assert_eq!(value["path"], "app.min.js");
        assert_eq!(value["sha256"], "def");
        assert_eq!(value["total_lines"], 1);
        assert!(value["next_line"].is_null(), "{bounded}");
        let shown = value["content"].as_str().unwrap();
        assert!(
            shown.starts_with("1\t{") && shown.ends_with("END\n"),
            "{shown}"
        );
        assert!(shown.contains("omitted inside line 1"));
        let fields = &value["rcode_truncated"]["fields"]["content"];
        assert_eq!(fields["partial_line"], 1);
        assert_eq!(fields["complete_lines"], false);
        assert!(fields["omitted_chars"].as_u64().unwrap() > 0);
        let hint = value["rcode_truncated"]["hint"].as_str().unwrap();
        assert!(!hint.contains("shown lines are complete") && hint.contains("partial_line"));
        // A long line followed by more lines: paging resumes at the next line,
        // never at a position past the omitted middle.
        let mixed = format!("7\t{}\n8\tshort\n9\tshort\n", "ж".repeat(30_000));
        let read = json!({"path":"m.txt","sha256":"abc","start_line":7,"total_lines":20,"next_line":10,"content":mixed}).to_string();
        let value: Value =
            serde_json::from_str(&bound_receipt(&budget, "read_file", &read, limit, false))
                .unwrap();
        assert_eq!(value["next_line"], 8);
        assert_eq!(
            value["rcode_truncated"]["fields"]["content"]["partial_line"],
            7
        );
        assert!(!value["content"].as_str().unwrap().contains("8\tshort"));
    }

    #[test]
    fn restricted_receipts_are_never_shortened_into_a_false_outcome() {
        let budget = ContextBudget::for_provider(&local(), None, 1.0, 9000);
        for receipt in [
            json!({"error":"denied","message":"User permission required; action was not executed","details":"d".repeat(60_000)}),
            json!({"error":"interrupted","outcome":"unknown","hint":"never replay automatically","details":"u".repeat(60_000)}),
        ] {
            let receipt = receipt.to_string();
            assert_eq!(
                bound_receipt(&budget, "run_command", &receipt, 100, true),
                receipt
            );
        }
    }

    /// A list_files page clipped by the host withdraws next_offset (shrunk
    /// and last-resort receipts alike); the raw receipt stays complete.
    fn check_clipped_list_files_page(next_offset: Value, listing_truncated: bool) {
        let budget = ContextBudget::for_provider(&local(), None, 1.0, 9000);
        let cost = |text: &str| budget.measure(&Message::text("tool", text));
        let files: Vec<String> = (0..100)
            .map(|index| format!("src/module_{index:03}/component_{index:03}.rs"))
            .collect();
        let raw = json!({"files":files,"truncated":listing_truncated,"next_offset":next_offset,"scan_limited":false}).to_string();
        let copy = raw.clone();
        // Unclipped: byte-for-byte, next_offset still a real continuation.
        assert_eq!(
            bound_receipt(&budget, "list_files", &raw, 1_000_000, false),
            raw
        );

        let limit = cost(&raw) / 3;
        let bounded = bound_receipt(&budget, "list_files", &raw, limit, false);
        assert!(cost(&bounded) <= limit, "{bounded}");
        let value: Value = serde_json::from_str(&bounded).unwrap();
        let shown = value["files"].as_array().unwrap();
        assert!(!shown.is_empty() && shown.len() < 100, "{bounded}");
        // The shown entries are the head; the hidden ones follow them.
        assert_eq!(value["files"], json!(files[..shown.len()]));
        assert!(value.get("next_offset").is_none(), "{bounded}");
        assert_eq!(value["truncated"], true);
        assert_eq!(value["scan_limited"], false);
        assert_eq!(value["is_error"], false);
        let info = &value["rcode_truncated"]["fields"]["files"];
        assert_eq!(info["omitted_items"], 100 - shown.len());
        assert_eq!(info["original_next_offset"], next_offset);
        assert!(info.get("original_next_offset").is_some());
        assert_eq!(info["narrow_request"], true);
        let hint = value["rcode_truncated"]["hint"].as_str().unwrap();
        assert!(
            hint.contains("original pagination no longer applies"),
            "{hint}"
        );
        assert!(hint.contains("from your original offset with a narrower range"));

        // Last resort: the array itself is gone, next_offset is still withdrawn.
        let bounded = bound_receipt(&budget, "list_files", &raw, 20, false);
        let value: Value = serde_json::from_str(&bounded).unwrap();
        assert!(value.get("files").is_none() && value.get("next_offset").is_none());
        assert_eq!(value["truncated"], true);
        assert_eq!(value["is_error"], false);
        let truncated = &value["rcode_truncated"];
        assert_eq!(truncated["original_next_offset"], next_offset);
        assert!(truncated.get("original_next_offset").is_some());
        assert_eq!(truncated["narrow_request"], true);
        assert!(truncated["omitted_fields"].to_string().contains("files"));
        assert!(
            truncated["hint"]
                .as_str()
                .unwrap()
                .contains("original pagination no longer applies")
        );

        // The complete receipt (shown to the user) is untouched.
        assert_eq!(raw, copy);
        let original: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(original["files"].as_array().unwrap().len(), 100);
        assert_eq!(original["next_offset"], next_offset);
        assert_eq!(original["truncated"], listing_truncated);
    }

    #[test]
    fn clipped_list_files_page_withdraws_next_offset_100() {
        check_clipped_list_files_page(json!(100), true);
    }

    #[test]
    fn clipped_list_files_last_page_withdraws_null_next_offset() {
        check_clipped_list_files_page(Value::Null, false);
    }

    #[test]
    fn cloud_budget_still_180000_chars() {
        for kind in [
            ProviderKind::Yandex,
            ProviderKind::GigaChat,
            ProviderKind::OpenRouter,
            ProviderKind::Custom,
        ] {
            let budget =
                ContextBudget::for_provider(&ProviderSettings::new(kind), Some(4096), 2.0, 9999);
            assert_eq!(budget.unit, ContextUnit::Chars);
            assert_eq!(budget.limit, 180_000);
            assert_eq!(budget.threshold(), 150_000);
            assert_eq!(budget.target(), 110_000);
            assert_eq!(budget.history_limit(), 180_000);
            assert_eq!(budget.measure(&Message::user("абв")), 3);
        }
    }
}
