use crate::config::Effort;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ToolCall>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_meta: Option<ProviderMeta>,
}

impl Message {
    pub fn text(role: &str, content: impl Into<String>) -> Self {
        Self {
            role: role.into(),
            content: Some(content.into()),
            ..Self::default()
        }
    }

    pub fn user(content: impl Into<String>) -> Self {
        Self::text("user", content)
    }

    pub fn assistant(completion: &Completion) -> Self {
        Self {
            role: "assistant".into(),
            content: Some(completion.content.clone()),
            tool_calls: completion.tool_calls.clone(),
            provider_meta: completion.provider_meta.clone(),
            ..Self::default()
        }
    }

    pub fn tool(call: &ToolCall, content: impl Into<String>) -> Self {
        Self {
            role: "tool".into(),
            content: Some(content.into()),
            tool_call_id: Some(call.id.clone()),
            name: Some(call.function.name.clone()),
            ..Self::default()
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderMeta {
    pub kind: String,
    pub data: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    #[serde(rename = "type", default = "function_type")]
    pub kind: String,
    pub function: FunctionCall,
}

fn function_type() -> String {
    "function".into()
}

impl ToolCall {
    pub fn new(name: &str, arguments: Value) -> Self {
        Self {
            id: format!("call_{}", uuid::Uuid::new_v4().simple()),
            kind: function_type(),
            function: FunctionCall {
                name: name.into(),
                arguments: arguments.to_string(),
            },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FunctionCall {
    pub name: String,
    pub arguments: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters: Value,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cached_input_tokens: u64,
    #[serde(default)]
    pub cost_usd: Option<f64>,
}

#[derive(Clone, Debug, Default)]
pub struct Completion {
    pub content: String,
    pub tool_calls: Vec<ToolCall>,
    pub usage: Usage,
    pub finish_reason: String,
    pub model: Option<String>,
    pub provider_meta: Option<ProviderMeta>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ModelInfo {
    pub id: String,
    pub name: String,
    pub supports_tools: Option<bool>,
    #[serde(default)]
    pub context_length: Option<u64>,
    #[serde(default)]
    pub supports_reasoning: Option<bool>,
    #[serde(default)]
    pub supported_efforts: Option<Vec<Effort>>,
}

#[cfg(test)]
mod model_tests {
    use super::ModelInfo;

    #[test]
    fn legacy_model_metadata_deserializes_without_new_fields() {
        let model: ModelInfo =
            serde_json::from_str(r#"{"id":"legacy","name":"Legacy model","supports_tools":true}"#)
                .unwrap();
        assert_eq!(model.id, "legacy");
        assert_eq!(model.supports_tools, Some(true));
        assert_eq!(model.context_length, None);
        assert_eq!(model.supports_reasoning, None);
        assert_eq!(model.supported_efforts, None);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureKind {
    Auth,
    Context,
    RateLimit,
    Transport,
    Protocol,
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct ProviderFailure {
    pub kind: FailureKind,
    pub status: Option<u16>,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolOutcome {
    pub is_error: bool,
    pub content: String,
    pub changed_paths: Vec<String>,
}

impl ToolOutcome {
    pub fn success(content: impl Into<String>) -> Self {
        Self {
            is_error: false,
            content: content.into(),
            changed_paths: vec![],
        }
    }
    pub fn error(content: impl Into<String>) -> Self {
        Self {
            is_error: true,
            content: content.into(),
            changed_paths: vec![],
        }
    }
}
