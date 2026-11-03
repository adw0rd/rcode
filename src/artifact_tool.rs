//! Read-only access through opaque IDs and a host-supplied actor scope.
use crate::{
    artifacts::ArtifactStore,
    context::ContextBudget,
    protocol::{Message, ToolDefinition, ToolOutcome},
};
use anyhow::{Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
const NAME: &str = "read_tool_output";

pub(crate) fn definition() -> ToolDefinition {
    ToolDefinition{name:NAME.into(),description:"Read a saved result by artifact_id from this session. Main may read collected worker artifacts; workers only their own. Use start_line/max_lines or a literal query; offset/max_bytes reads UTF-8 byte pages, including very long lines. Never rerun a command to retrieve omitted output.".into(),parameters:json!({"type":"object","properties":{
        "artifact_id":{"type":"string","maxLength":36},"start_line":{"type":"integer","minimum":1},"max_lines":{"type":"integer","minimum":1,"maximum":500},"query":{"type":"string","maxLength":1024},"offset":{"type":"integer","minimum":0},"max_bytes":{"type":"integer","minimum":4,"maximum":65536}},"required":["artifact_id"],"additionalProperties":false})}
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    artifact_id: String,
    start_line: Option<usize>,
    max_lines: Option<usize>,
    query: Option<String>,
    offset: Option<usize>,
    max_bytes: Option<usize>,
}

pub(crate) fn execute(
    store: &ArtifactStore,
    value: &Value,
    actor: Option<&str>,
    fit: Option<&(ContextBudget, usize)>,
) -> ToolOutcome {
    let result = (|| -> Result<String> {
        let args: Args = serde_json::from_value(value.clone())?;
        ensure!(
            args.query.as_ref().is_none_or(|q| q.len() <= 1024),
            "Поисковый запрос превышает 1024 байта"
        );
        let fits = |text: &str| {
            fit.is_none_or(|(budget, limit)| budget.measure(&Message::text("tool", text)) <= *limit)
        };
        if let Some(offset) = args.offset {
            ensure!(
                args.query.is_none() && args.start_line.is_none() && args.max_lines.is_none(),
                "Смещение нельзя смешивать с поиском или строками"
            );
            let mut bytes = args.max_bytes.unwrap_or(16 * 1024);
            ensure!((4..=65536).contains(&bytes), "Некорректный размер страницы");
            loop {
                let page = store.read_bytes(actor, &args.artifact_id, offset, bytes)?;
                let mut value = serde_json::to_value(page)?;
                value["artifact_id"] = json!(args.artifact_id);
                let text = value.to_string();
                if fits(&text) {
                    return Ok(text);
                }
                ensure!(
                    bytes > 4,
                    "Метаданные артефакта не помещаются в контекст; увеличьте лимит контекста"
                );
                bytes = (bytes / 2).max(4);
            }
        }
        ensure!(
            args.max_bytes.is_none(),
            "max_bytes используется вместе с offset"
        );
        let mut lines = args.max_lines.unwrap_or(80);
        ensure!((1..=500).contains(&lines), "Допускается 1–500 строк");
        loop {
            let page = store.read(
                actor,
                &args.artifact_id,
                args.start_line.unwrap_or(1),
                lines,
                args.query.as_deref(),
            )?;
            let mut value = serde_json::to_value(page)?;
            value["artifact_id"] = json!(args.artifact_id);
            let text = value.to_string();
            if fits(&text) {
                return Ok(text);
            }
            ensure!(
                lines > 1,
                "Строка не помещается в контекст; используйте offset и меньший max_bytes"
            );
            lines = (lines / 2).max(1);
        }
    })();
    match result {Ok(text)=>ToolOutcome::success(text),Err(e)=>ToolOutcome::error(json!({"error":"artifact_read_failed","message":format!("{e:#}"),"hint":"Для длинных строк используйте offset=0 и max_bytes=4096; продолжайте с next_offset."}).to_string())}
}
