//! Context budgets. Cloud providers keep the historical local budget in
//! characters; local servers are budgeted in conservatively estimated tokens
//! against the context the profile (or the running server) actually provides.
use crate::{
    config::{ProviderKind, ProviderSettings},
    protocol::{Message, ToolDefinition},
    state::{AUTO_COMPACT_THRESHOLD, CONTEXT_LIMIT},
};
use serde::Serialize;

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
