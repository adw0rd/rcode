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

#[cfg(test)]
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn execute(
    store: &ArtifactStore,
    value: &Value,
    actor: Option<&str>,
    fit: Option<&(ContextBudget, usize)>,
) -> ToolOutcome {
    let events = crate::app::Events::new(false);
    execute_with_events(store, value, actor, fit, &events, false)
}

pub(crate) fn execute_with_events(
    store: &ArtifactStore,
    value: &Value,
    actor: Option<&str>,
    fit: Option<&(ContextBudget, usize)>,
    events: &crate::app::Events,
    checked: bool,
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
        let mut cached_clean: Option<(crate::app::SecretGen, String)> = None;
        let last_used_gen = std::cell::Cell::new([0u8; 32]);
        let mut normalize_full =
            |meta: &crate::artifacts::ArtifactMeta, raw: String| -> Result<String> {
                let current_gen = events.secret_generation();
                let (secret_gen, clean) = if let Some((cached_gen, ref clean)) = cached_clean
                    && cached_gen == current_gen
                {
                    (cached_gen, clean.clone())
                } else {
                    let (gen_id, clean) =
                        events.redact_full_artifact_for_page(&meta.origin.tool, &raw, checked)?;
                    cached_clean = Some((gen_id, clean.clone()));
                    (gen_id, clean)
                };
                ensure!(
                    !meta.truncated || store.can_read_truncated_artifact(&meta.id, secret_gen),
                    "Усечённый по квоте артефакт недоступен для чтения после обновления ключей"
                );
                last_used_gen.set(secret_gen);
                Ok(clean)
            };
        if let Some(offset) = args.offset {
            ensure!(
                args.query.is_none() && args.start_line.is_none() && args.max_lines.is_none(),
                "Смещение нельзя смешивать с поиском или строками"
            );
            let mut bytes = args.max_bytes.unwrap_or(16 * 1024);
            ensure!((4..=65536).contains(&bytes), "Некорректный размер страницы");
            loop {
                let page = store.read_bytes_with(
                    actor,
                    &args.artifact_id,
                    offset,
                    bytes,
                    &mut normalize_full,
                )?;
                let used_gen = last_used_gen.get();
                let page_content = page.content.clone();
                let mut value = serde_json::to_value(page)?;
                value["artifact_id"] = json!(args.artifact_id);
                value["max_bytes"] = json!(bytes);
                let text = value.to_string();
                if fits(&text) {
                    events.note_artifact_id(&args.artifact_id);
                    events.note_verified_artifact_page_at(
                        used_gen,
                        &args.artifact_id,
                        &page_content,
                        crate::app::VerifiedPageRecipe::Bytes {
                            actor: actor.map(str::to_owned),
                            offset,
                            max_bytes: bytes,
                        },
                    );
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
            let page = store.read_with(
                actor,
                &args.artifact_id,
                args.start_line.unwrap_or(1),
                lines,
                args.query.as_deref(),
                &mut normalize_full,
            )?;
            let used_gen = last_used_gen.get();
            let page_content = page.content.clone();
            let mut value = serde_json::to_value(page)?;
            value["artifact_id"] = json!(args.artifact_id);
            value["max_lines"] = json!(lines);
            if let Some(ref q) = args.query {
                value["query"] = json!(events.redact(q));
            }
            let text = value.to_string();
            if fits(&text) {
                events.note_artifact_id(&args.artifact_id);
                events.note_verified_artifact_page_at(
                    used_gen,
                    &args.artifact_id,
                    &page_content,
                    crate::app::VerifiedPageRecipe::Lines {
                        actor: actor.map(str::to_owned),
                        start_line: args.start_line.unwrap_or(1),
                        max_lines: lines,
                        query: args.query.clone(),
                    },
                );
                return Ok(text);
            }
            ensure!(
                lines > 1,
                "Строка не помещается в контекст; используйте offset и меньший max_bytes"
            );
            lines = (lines / 2).max(1);
        }
    })();
    match result {Ok(text)=>ToolOutcome::success(text),Err(e)=>ToolOutcome::error(json!({"error":"artifact_read_failed","message":events.redact(&format!("{e:#}")),"hint":"Для длинных строк используйте offset=0 и max_bytes=4096; продолжайте с next_offset."}).to_string())}
}
