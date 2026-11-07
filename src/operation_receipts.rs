//! Публикация результата после сохранения артефакта, задачи и commit журнала.
//! Разрешения проверяет caller до begin; восстановление никогда не исполняет tools.
use crate::{
    artifacts::{ArtifactMeta, ArtifactOrigin, ArtifactStore},
    config::ConfigStore,
    context::{ContextBudget, preview_receipt},
    operation_journal::{OperationJournal, Outcome, PendingIntent},
    protocol::{Message, ProviderMeta, ToolCall, ToolOutcome},
    state::Session,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const UNKNOWN: &str = "Исход операции неизвестен: подтверждение завершения не сохранено. Проверьте файлы и процессы перед повтором; автоматически действие не повторялось.";
const WORKER_SUMMARY_MAX: usize = 8 * 1024;
const WORKER_PREVIEW_MAX: usize = 512;
const WORKER_OUTPUT_MAX: usize = 64 * 1024;

pub(crate) struct PendingOperation {
    id: String,
    origin: ArtifactOrigin,
    revision: u64,
}

impl PendingOperation {
    pub(crate) fn operation_id(&self) -> &str {
        &self.id
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HandoffReference {
    pub operation_id: String,
    pub terminal: ArtifactMeta,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HandoffData {
    pub version: u32,
    #[serde(default = "handoff_status")]
    pub status: String,
    pub command_id: String,
    pub lifetime_id: String,
    pub worker: String,
    pub parent_scope_id: String,
    pub expected_epoch: u64,
    pub ownership_epoch: u64,
    pub stdout_offset: usize,
    pub stderr_offset: usize,
    pub owner: Option<String>,
    pub operation_id: String,
}
fn handoff_status() -> String {
    "transferred".into()
}
#[derive(Clone)]
pub(crate) struct CommittedHandoff {
    reference: HandoffReference,
    data: HandoffData,
}
impl CommittedHandoff {
    pub(crate) fn reference(&self) -> &HandoffReference {
        &self.reference
    }
    pub(crate) fn data(&self) -> &HandoffData {
        &self.data
    }
}

pub(crate) fn committed_handoff(
    journal: &OperationJournal,
    artifacts: &ArtifactStore,
    session_id: &str,
    reference: &HandoffReference,
    command_id: &str,
    lifetime_id: &str,
    origin: &ArtifactOrigin,
) -> Result<CommittedHandoff> {
    journal.check_session(session_id)?;
    let record = journal
        .records(artifacts)?
        .into_iter()
        .find(|r| r.operation_id == reference.operation_id)
        .ok_or_else(|| anyhow::anyhow!("Handoff operation not found"))?;
    ensure!(
        record.origin.tool == "handoff_command"
            && record.outcome == Outcome::Succeeded
            && record.origin.actor == origin.actor
            && record.origin.turn == origin.turn
            && record.origin.actor.is_some()
            && record.terminal.as_ref() == Some(&reference.terminal),
        "Uncommitted or foreign handoff reference"
    );
    let payload = journal
        .terminal_payload(&record.operation_id, artifacts)?
        .ok_or_else(|| anyhow::anyhow!("Handoff not committed"))?;
    let saved: SavedResult = serde_json::from_value(payload)?;
    ensure!(
        saved.version == 1
            && !saved.is_error
            && saved.output_format.is_none()
            && saved.output.origin == record.origin
            && saved.output.session_id == session_id,
        "Invalid handoff receipt"
    );
    let data: HandoffData = serde_json::from_str(&artifacts.verify_required(&saved.output)?)?;
    let intent: SavedRequest =
        serde_json::from_value(journal.intent_payload(&record.operation_id, artifacts)?)?;
    ensure!(
        intent.version == 1 && intent.arguments.origin == record.origin,
        "Invalid handoff intent"
    );
    let args: Value = serde_json::from_str(&artifacts.verify_required(&intent.arguments)?)?;
    ensure!(
        data.version == 1
            && data.status == "transferred"
            && data.command_id == command_id
            && data.lifetime_id == lifetime_id
            && data.operation_id == reference.operation_id
            && data.expected_epoch == 0
            && data.ownership_epoch == 1
            && data.owner.is_none()
            && Some(data.worker.as_str()) == origin.actor.as_deref()
            && args["command_id"] == command_id
            && args["lifetime_id"] == lifetime_id
            && args["worker"] == data.worker
            && args["parent_scope_id"] == data.parent_scope_id
            && args["expected_epoch"] == 0
            && !data.parent_scope_id.is_empty(),
        "Handoff identity mismatch"
    );
    Ok(CommittedHandoff {
        reference: reference.clone(),
        data,
    })
}

/// Host capability долгого действия. Это не разрешение, не PID и не признак
/// живого процесса. Не сериализуется, не клонируется и не усыновляется при resume.
pub struct BackgroundOperation {
    pending: PendingIntent,
    arguments: ArtifactMeta,
}

impl BackgroundOperation {
    pub fn operation_id(&self) -> &str {
        self.pending.operation_id()
    }
}

/// Подтверждённый результат без provider tool message. Полный текст читается
/// через output; terminal связывает результат с предыдущей завершённой операцией.
pub struct BackgroundReceipt {
    pub operation_id: String,
    pub output: ArtifactMeta,
    pub terminal: ArtifactMeta,
    pub task_revision: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedResult {
    version: u32,
    is_error: bool,
    output: ArtifactMeta,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous: Option<crate::task_state::TaskOperation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    output_format: Option<OutputFormat>,
}

/// Add bounded host observations to a failed worker wait without changing its
/// failure status or any other fields from the AgentRecord.
pub(crate) fn enrich_worker_wait(
    mut outcome: ToolOutcome,
    journal: Option<&OperationJournal>,
    artifacts: Option<&ArtifactStore>,
    session_id: &str,
    turn: u64,
    secrets: &[String],
) -> ToolOutcome {
    let Ok(record) = serde_json::from_str::<crate::agents::AgentRecord>(&outcome.content) else {
        return outcome;
    };
    if record.role != crate::agents::AgentRole::Worker
        || !matches!(
            record.status,
            crate::agents::AgentStatus::Failed
                | crate::agents::AgentStatus::Cancelled
                | crate::agents::AgentStatus::Interrupted
        )
    {
        return outcome;
    }
    let summary = match (journal, artifacts) {
        (Some(journal), Some(artifacts)) => {
            match journal.worker_observation_sources(artifacts, session_id, &record.id, turn) {
                Ok(sources) => worker_summary(sources, artifacts, session_id, secrets),
                Err(_) => Ok(unavailable_worker_summary("journal_unavailable")),
            }
        }
        _ => Ok(unavailable_worker_summary("journal_unavailable")),
    };
    let summary = summary.unwrap_or_else(|_| unavailable_worker_summary("summary_unavailable"));
    let Ok(mut value) = serde_json::from_str::<Value>(&outcome.content) else {
        return outcome;
    };
    let Some(object) = value.as_object_mut() else {
        return outcome;
    };
    object.insert("worker_receipts".into(), summary);
    if let Ok(content) = serde_json::to_string(&value) {
        outcome.content = content;
    }
    outcome
}

pub(crate) fn enrich_worker_wait_unavailable(
    mut outcome: ToolOutcome,
    reason: &'static str,
) -> ToolOutcome {
    let Ok(record) = serde_json::from_str::<crate::agents::AgentRecord>(&outcome.content) else {
        return outcome;
    };
    if record.role != crate::agents::AgentRole::Worker
        || !matches!(
            record.status,
            crate::agents::AgentStatus::Failed
                | crate::agents::AgentStatus::Cancelled
                | crate::agents::AgentStatus::Interrupted
        )
    {
        return outcome;
    }
    let Ok(mut value) = serde_json::from_str::<Value>(&outcome.content) else {
        return outcome;
    };
    if let Some(object) = value.as_object_mut() {
        object.insert("worker_receipts".into(), unavailable_worker_summary(reason));
        if let Ok(content) = serde_json::to_string(&value) {
            outcome.content = content;
        }
    }
    outcome
}

fn unavailable_worker_summary(reason: &str) -> Value {
    json!({
        "version": 1,
        "available": false,
        "goal_verified": false,
        "scope": "worker_turn",
        "selection": "last_8_committed_by_admission",
        "observations": [],
        "omitted_operations": 0,
        "pending_operations": 0,
        "unavailable_operations": 0,
        "truncated": false,
        "unavailable_reason": reason,
        "semantics": "Saved observations at their revisions; worker failure unchanged; absence does not prove no action; no current process state is asserted."
    })
}

fn worker_summary(
    sources: crate::operation_journal::WorkerObservationSources,
    artifacts: &ArtifactStore,
    session_id: &str,
    secrets: &[String],
) -> Result<Value> {
    let mut unavailable = sources.unavailable;
    let mut observations = Vec::new();
    for source in sources.sources {
        let mut observation = json!({
            "operation_id": source.operation_id,
            "tool": source.origin.tool,
            "revision": source.revision,
            "operation_outcome": source.outcome,
            "terminal": source.terminal.id,
        });
        if secrets.iter().any(|secret| {
            !secret.is_empty()
                && [
                    source.operation_id.as_str(),
                    source.terminal.id.as_str(),
                    source.origin.call_id.as_str(),
                    source.origin.tool.as_str(),
                    source.origin.actor.as_deref().unwrap_or_default(),
                ]
                .iter()
                .any(|id| id.contains(secret))
        }) {
            unavailable += 1;
            continue;
        }
        let saved: SavedResult = match serde_json::from_value::<SavedResult>(source.payload) {
            Ok(saved) if saved.version == 1 => saved,
            _ => {
                unavailable += 1;
                continue;
            }
        };
        let valid_tool = matches!(
            source.origin.tool.as_str(),
            "start_command"
                | "poll_command"
                | "send_command_input"
                | "stop_command"
                | "handoff_command"
                | "command_lifetime"
                | "command_input_lifetime"
                | "run_command"
                | "write_file"
                | "edit_file"
                | "delete_file"
                | "mkdir"
                | "read_file"
                | "search"
                | "web_fetch"
                | "update_plan"
                | "load_skill"
        );
        if !valid_tool
            || saved.output.session_id != session_id
            || saved.output.origin != source.origin
        {
            unavailable += 1;
            continue;
        }
        let output_id = saved.output.id.clone();
        if secrets
            .iter()
            .any(|secret| !secret.is_empty() && output_id.contains(secret))
        {
            unavailable += 1;
            continue;
        }
        observation["output"] = json!(output_id);
        if saved.output_format.is_some() {
            observation["payload_unavailable"] = json!("manifest_not_expanded");
            observation["stdout_truncated"] = json!(false);
            observations.push(observation);
            continue;
        }
        if saved.output.truncated || saved.output.bytes > WORKER_OUTPUT_MAX {
            observation["payload_unavailable"] = json!("output_over_limit_or_truncated");
            observation["stdout_truncated"] = json!(false);
            observations.push(observation);
            continue;
        }
        let text = match artifacts.verify_output(&saved.output) {
            Ok(text) => text,
            Err(_) => {
                unavailable += 1;
                continue;
            }
        };
        let native_job = matches!(
            source.origin.tool.as_str(),
            "start_command"
                | "poll_command"
                | "send_command_input"
                | "stop_command"
                | "handoff_command"
                | "command_lifetime"
                | "command_input_lifetime"
        );
        let mut parsed = native_job
            .then(|| serde_json::from_str::<Value>(&text).ok())
            .flatten();
        if let Some(value) = parsed.as_mut() {
            if worker_fields_have_secret_ids(value, secrets) {
                unavailable += 1;
                continue;
            }
            redact_json_strings(value, secrets)?;
        }
        let clean = if parsed.is_none() || source.origin.tool == "run_command" {
            crate::redaction::redact_text(&text, secrets)?
        } else {
            String::new()
        };
        let fields = parsed
            .as_ref()
            .map(|value| worker_fields(&source.origin.tool, value))
            .unwrap_or_else(|| json!({}));
        observation["fields"] = fields;
        let stdout = if matches!(
            source.origin.tool.as_str(),
            "start_command" | "poll_command" | "stop_command"
        ) {
            parsed
                .as_ref()
                .and_then(|value| value.get("stdout"))
                .and_then(Value::as_str)
                .unwrap_or("")
        } else if source.origin.tool == "run_command" {
            clean.as_str()
        } else {
            ""
        };
        let preview = utf8_prefix(stdout, WORKER_PREVIEW_MAX);
        observation["stdout_preview"] = json!(preview);
        let native_truncated = native_job
            && parsed
                .as_ref()
                .and_then(|value| value.get("output_truncated"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
        if native_job
            && parsed
                .as_ref()
                .and_then(|value| value.get("payload_unavailable"))
                .and_then(Value::as_bool)
                == Some(true)
        {
            observation["payload_unavailable"] = json!("native_receipt_unavailable");
        }
        observation["stdout_truncated"] = json!(preview.len() < stdout.len() || native_truncated);
        observations.push(observation);
    }
    let had_truncation = observations.iter().any(|observation| {
        observation["stdout_truncated"] == true
            || observation["fields"]["inputs_truncated"] == true
            || observation["fields"]["output_truncated"] == true
    });
    let mut summary = json!({
        "version": 1,
        "available": true,
        "goal_verified": false,
        "scope": "worker_turn",
        "selection": "last_8_committed_by_admission",
        "observations": observations,
        "omitted_operations": sources.omitted,
        "pending_operations": sources.pending,
        "unavailable_operations": unavailable,
        "truncated": sources.omitted > 0 || had_truncation,
        "semantics": "Saved observations at their revisions; worker failure unchanged; absence does not prove no action; no current process state is asserted."
    });
    redact_json_strings(&mut summary, secrets)?;
    loop {
        let bytes = serde_json::to_vec(&summary)?;
        if bytes.len() <= WORKER_SUMMARY_MAX {
            break;
        }
        let observations = summary["observations"]
            .as_array_mut()
            .expect("summary observations");
        let mut preview_shrunk = false;
        for observation in observations.iter_mut().rev() {
            if let Some(preview) = observation["stdout_preview"]
                .as_str()
                .filter(|s| !s.is_empty())
            {
                let cut = preview.len().saturating_sub(64);
                observation["stdout_preview"] = json!(utf8_prefix(preview, cut));
                observation["stdout_truncated"] = json!(true);
                preview_shrunk = true;
                break;
            }
        }
        if preview_shrunk {
            summary["truncated"] = json!(true);
            continue;
        }
        if observations.pop().is_some() {
            summary["omitted_operations"] =
                json!(summary["omitted_operations"].as_u64().unwrap_or(0) + 1);
            summary["truncated"] = json!(true);
            continue;
        }
        summary["unavailable_reason"] = json!("summary_over_limit");
        summary["available"] = json!(false);
        break;
    }
    Ok(summary)
}

fn utf8_prefix(value: &str, bytes: usize) -> &str {
    let mut end = bytes.min(value.len());
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn worker_fields(tool: &str, value: &Value) -> Value {
    let mut fields = serde_json::Map::new();
    let uuid = |v: &Value| {
        v.as_str()
            .is_some_and(|s| uuid::Uuid::parse_str(s).is_ok_and(|id| id.to_string() == s))
    };
    if matches!(
        tool,
        "start_command"
            | "poll_command"
            | "stop_command"
            | "handoff_command"
            | "send_command_input"
            | "command_lifetime"
            | "command_input_lifetime"
    ) {
        for key in ["command_id", "input_id"] {
            if value.get(key).is_some_and(uuid) {
                fields.insert(key.into(), value[key].clone());
            }
        }
        if let Some(status) = value.get("status").and_then(Value::as_str).filter(|s| {
            matches!(
                *s,
                "running" | "exited" | "stopped" | "timed_out" | "cancelled" | "failed" | "unknown"
            )
        }) {
            fields.insert("status".into(), json!(status));
        }
        for key in ["cleanup_complete", "delivery_cancelled"] {
            if let Some(flag) = value.get(key).and_then(Value::as_bool) {
                fields.insert(key.into(), json!(flag));
            }
        }
        for key in [
            "output_truncated",
            "payload_unavailable",
            "redaction_incomplete",
        ] {
            if let Some(flag) = value.get(key).and_then(Value::as_bool) {
                fields.insert(key.into(), json!(flag));
            }
        }
        for key in ["exit_code", "signal"] {
            if let Some(n) = value
                .get(key)
                .filter(|v| v.is_null() || v.as_i64().is_some())
            {
                fields.insert(key.into(), n.clone());
            }
        }
        if let Some(delivery) = value.get("delivery").and_then(Value::as_str).filter(|s| {
            matches!(
                *s,
                "accepted" | "delivered" | "rejected" | "cancelled" | "io_error"
            )
        }) {
            fields.insert("delivery".into(), json!(delivery));
        }
        for key in ["written", "total"] {
            if let Some(n) = value.get(key).and_then(Value::as_u64) {
                fields.insert(key.into(), json!(n));
            }
        }
        let input_values: Vec<&Value> = if tool == "command_input_lifetime" {
            vec![value]
        } else {
            value
                .get("inputs")
                .and_then(Value::as_array)
                .map(|inputs| inputs.iter().collect())
                .unwrap_or_default()
        };
        if !input_values.is_empty()
            || value.get("inputs").is_some()
            || tool == "command_input_lifetime"
        {
            let inputs_truncated = input_values.len() > 4;
            let mut accepted = Vec::new();
            for input in input_values.into_iter().take(4) {
                let mut item = serde_json::Map::new();
                if input.get("input_id").is_some_and(uuid) {
                    item.insert("input_id".into(), input["input_id"].clone());
                }
                if let Some(delivery) = input.get("delivery").and_then(Value::as_str).filter(|s| {
                    matches!(
                        *s,
                        "accepted" | "delivered" | "rejected" | "cancelled" | "io_error"
                    )
                }) {
                    item.insert("delivery".into(), json!(delivery));
                }
                for key in ["written", "total"] {
                    if let Some(n) = input.get(key).and_then(Value::as_u64) {
                        item.insert(key.into(), json!(n));
                    }
                }
                accepted.push(Value::Object(item));
            }
            fields.insert("inputs".into(), json!(accepted));
            fields.insert("inputs_truncated".into(), json!(inputs_truncated));
        }
    }
    Value::Object(fields)
}

fn worker_fields_have_secret_ids(value: &Value, secrets: &[String]) -> bool {
    let has_secret = |field: &Value| {
        field.as_str().is_some_and(|id| {
            secrets
                .iter()
                .any(|secret| !secret.is_empty() && id.contains(secret))
        })
    };
    has_secret(&value["command_id"])
        || has_secret(&value["input_id"])
        || value["inputs"]
            .as_array()
            .is_some_and(|inputs| inputs.iter().any(|input| has_secret(&input["input_id"])))
}

fn redact_json_strings(value: &mut Value, secrets: &[String]) -> Result<()> {
    match value {
        Value::String(text) => *text = crate::redaction::redact_text(text, secrets)?,
        Value::Array(items) => {
            for item in items {
                redact_json_strings(item, secrets)?;
            }
        }
        Value::Object(fields) => {
            for item in fields.values_mut() {
                redact_json_strings(item, secrets)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OutputFormat {
    CommandManifestV1,
    CommandManifestV2,
}

fn verify_saved_output(artifacts: &ArtifactStore, saved: &SavedResult) -> Result<String> {
    let text = if saved.output_format.is_some() {
        artifacts.verify_required(&saved.output)?
    } else {
        artifacts.verify_output(&saved.output)?
    };
    match saved.output_format {
        Some(OutputFormat::CommandManifestV1) => {
            crate::job_manifest::verify(artifacts, &text, &saved.output.session_id)?
        }
        Some(OutputFormat::CommandManifestV2) => {
            crate::job_epochs::verify(artifacts, &text, &saved.output.session_id)?
        }
        None => {}
    }
    Ok(text)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedRequest {
    version: u32,
    arguments: ArtifactMeta,
}

/// Resolve only committed command lifetimes; UUIDs never recreate native ownership.
pub(crate) fn command_output(
    journal: &OperationJournal,
    artifacts: &ArtifactStore,
    session_id: &str,
    actor: Option<&str>,
    request: &crate::job_tools::PollArgs,
    secrets: &[String],
) -> Result<Option<Value>> {
    journal.check_session(session_id)?;
    // The journal has a hard 2048-operation limit, including after recovery.
    // Filter by immutable actor/tool before loading command payloads.
    for record in journal.records(artifacts)? {
        if record.origin.tool != "command_lifetime" || record.terminal.is_none() {
            continue;
        }
        let intent = journal.intent_payload(&record.operation_id, artifacts)?;
        let saved: SavedRequest = serde_json::from_value(intent)?;
        ensure!(saved.version == 1, "Неизвестная версия запроса процесса");
        ensure!(
            saved.arguments.origin == record.origin,
            "Чужие аргументы процесса"
        );
        let args: Value = serde_json::from_str(&artifacts.verify_required(&saved.arguments)?)?;
        if args["command_id"] != request.command_id {
            continue;
        }
        ensure!(
            args["origin"]["actor"] == serde_json::to_value(&record.origin.actor)?
                && args["origin"]["turn"] == record.origin.turn,
            "Чужой origin процесса"
        );
        let payload = journal
            .terminal_payload(&record.operation_id, artifacts)?
            .ok_or_else(|| anyhow::anyhow!("Результат процесса не подтверждён"))?;
        let saved: SavedResult = serde_json::from_value(payload)?;
        ensure!(
            saved.version == 1
                && matches!(
                    saved.output_format,
                    Some(OutputFormat::CommandManifestV1 | OutputFormat::CommandManifestV2)
                )
                && saved.output.origin == record.origin
                && saved.output.session_id == session_id,
            "Чужой или неизвестный формат результата процесса"
        );
        let original_worker = record.origin.actor.as_deref() == actor;
        if !(original_worker
            || actor.is_none()
                && matches!(saved.output_format, Some(OutputFormat::CommandManifestV2)))
        {
            return Ok(None);
        }
        let text = if matches!(saved.output_format, Some(OutputFormat::CommandManifestV2)) {
            artifacts.verify_required(&saved.output)?
        } else {
            verify_saved_output(artifacts, &saved)?
        };
        if matches!(saved.output_format, Some(OutputFormat::CommandManifestV2)) {
            let reference = crate::job_epochs::reference(&text)?;
            let proof = committed_handoff(
                journal,
                artifacts,
                session_id,
                &reference,
                &request.command_id,
                &record.operation_id,
                &record.origin,
            )?;
            return crate::job_epochs::page(
                artifacts,
                &text,
                session_id,
                &record.origin,
                request,
                &proof,
                original_worker,
                secrets,
            )
            .map(Some);
        }
        return crate::job_manifest::page(
            artifacts,
            &text,
            session_id,
            &record.origin,
            request,
            secrets,
        )
        .map(Some);
    }
    Ok(None)
}

fn unknown(id: &str) -> String {
    json!({"error":"interrupted","outcome":"unknown","operation_id":id,"hint":UNKNOWN}).to_string()
}

fn catalog_origin() -> ArtifactOrigin {
    ArtifactOrigin {
        actor: None,
        turn: 0,
        tool: "operation_catalog".into(),
        call_id: "history".into(),
    }
}

fn restore_catalog(
    artifacts: &ArtifactStore,
    session: &mut Session,
    heads: &[crate::task_state::TaskOperation],
) -> Result<()> {
    use sha2::{Digest, Sha256};
    let existing = session
        .task_state
        .operation_catalog()
        .map(|r| ArtifactMeta {
            version: 1,
            id: r.artifact_id.clone(),
            session_id: r.session_id.clone(),
            origin: catalog_origin(),
            bytes: r.bytes,
            sha256: r.sha256.clone(),
            truncated: false,
        });
    let old_text = existing
        .as_ref()
        .map(|meta| artifacts.verify_required(meta))
        .transpose()?;
    if heads.is_empty() {
        return session.task_state.restore_operation_catalog(None);
    }
    let text = json!({"version":1,"session_id":session.id,"additional_heads":heads}).to_string();
    if old_text.as_deref() == Some(&text) {
        return Ok(());
    }
    // Check TaskState capacity before publishing a new required artifact.
    let mut capacity = session.task_state.clone();
    capacity.restore_operation_catalog(Some(crate::task_state::TaskReference {
        artifact_id: "00000000-0000-4000-8000-000000000000".into(),
        session_id: session.id.clone(),
        sha256: format!("{:x}", Sha256::digest(text.as_bytes())),
        bytes: text.len(),
    }))?;
    // IDs/hashes only: no user text, arguments or output are duplicated here.
    let meta = artifacts.capture_required(catalog_origin(), &text, &[])?;
    session.task_state.restore_operation_catalog(Some(
        crate::task_state::TaskReference::from_artifact(&meta)?,
    ))
}

fn tagged(call: &ToolCall, id: &str, content: String) -> Message {
    let mut message = Message::tool(call, content);
    message.host_operation = Some(id.into());
    message
}

fn message_id(message: &Message) -> Option<&str> {
    message.host_operation.as_deref()
}

/// Повторяющиеся provider call ID допустимы в разных шагах. Корреляция только
/// по UUID хоста; текст результата никогда не задаёт эту связь.
pub(crate) fn put_message(
    session: &mut Session,
    call: &ToolCall,
    outcome: &ToolOutcome,
    content: String,
) -> Result<()> {
    if let Some(id) = &outcome.recorded_operation {
        let mut messages = session
            .messages
            .iter_mut()
            .filter(|m| message_id(m) == Some(id.as_str()));
        let message = messages
            .next()
            .ok_or_else(|| anyhow::anyhow!("Потеряна связь результата с операцией"))?;
        ensure!(
            message.role == "tool"
                && message.tool_call_id.as_deref() == Some(&call.id)
                && message.name.as_deref() == Some(&call.function.name),
            "Результат не соответствует вызову"
        );
        ensure!(
            messages.next().is_none(),
            "Повторная ссылка на операцию в истории"
        );
        message.content = Some(content);
    } else {
        session.messages.push(Message::tool(call, content));
    }
    Ok(())
}

pub(crate) fn preview(text: &str, meta: &ArtifactMeta, is_error: bool) -> String {
    let mut value = match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(object)) => Value::Object(object),
        _ => json!({"text":text}),
    };
    // The artifact checksum verifies the saved receipt, not a file read by the
    // tool. Keep it in ArtifactMeta; showing two hashes here caused models to
    // pass the receipt digest as write_file.expected_sha256.
    value.as_object_mut().unwrap().remove("artifact_sha256");
    value["artifact_id"] = json!(meta.id);
    value["artifact_bytes"] = json!(meta.bytes);
    value["artifact_truncated"] = json!(meta.truncated);
    preview_receipt(
        &ContextBudget::cloud(),
        &meta.origin.tool,
        &value.to_string(),
        16 * 1024,
        is_error,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn begin(
    journal: &mut OperationJournal,
    artifacts: &ArtifactStore,
    session: &mut Session,
    store: &ConfigStore,
    call: &ToolCall,
    actor: Option<&str>,
    args: &Value,
    secrets: &[String],
) -> Result<PendingOperation> {
    journal.check_active()?;
    let mut reservation = session.clone();
    reservation.task_state = session.task_state.operation_capacity_state(&session.id)?;
    let revision = reservation.task_state.revision();
    if actor.is_none() {
        reservation.messages.push(tagged(
            call,
            "00000000-0000-4000-8000-000000000000",
            "\u{0001}".repeat(16 * 1024),
        ));
    }
    ensure!(
        serde_json::to_vec_pretty(&reservation)?.len() <= 8 * 1024 * 1024 - 4096,
        "В сессии недостаточно места для результата; сократите историю перед действием"
    );
    let id = uuid::Uuid::new_v4().to_string();
    let origin = ArtifactOrigin {
        actor: actor.map(str::to_owned),
        turn: session.turn_index,
        tool: call.function.name.clone(),
        call_id: call.id.clone(),
    };
    // write_file/edit_file allow arguments larger than the small journal
    // envelope. Preserve them completely in a separate required artifact.
    let arguments =
        artifacts.capture_required(origin.clone(), &serde_json::to_string(args)?, secrets)?;
    artifacts.verify_required(&arguments)?;
    let request = serde_json::to_value(SavedRequest {
        version: 1,
        arguments,
    })?;
    journal.begin(&id, origin.clone(), &request, artifacts, secrets)?;
    ensure!(
        journal.intent_payload(&id, artifacts)? == request,
        "Удаление секрета изменило ссылку на аргументы"
    );
    if actor.is_none() {
        let mut candidate = session.clone();
        candidate.messages.push(tagged(call, &id, unknown(&id)));
        candidate.save(store)?;
        *session = candidate;
    }
    Ok(PendingOperation {
        id,
        origin,
        revision,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn finish(
    pending: PendingOperation,
    journal: &mut OperationJournal,
    artifacts: &ArtifactStore,
    session: &mut Session,
    store: &ConfigStore,
    call: &ToolCall,
    mut outcome: ToolOutcome,
    secrets: &[String],
) -> Result<ToolOutcome> {
    ensure!(
        pending.origin.turn == session.turn_index
            && pending.origin.tool == call.function.name
            && pending.origin.call_id == call.id,
        "Операция не соответствует текущему вызову"
    );
    let output = artifacts.capture(pending.origin.clone(), &outcome.content, secrets)?;
    let text = artifacts.verify_output(&output)?;
    let payload = SavedResult {
        version: 1,
        is_error: outcome.is_error,
        output: output.clone(),
        previous: session.task_state.last_operation().cloned(),
        output_format: None,
    };
    let payload = serde_json::to_value(payload)?;
    let prepared = journal.prepare_finish(
        &pending.id,
        if outcome.is_error {
            Outcome::Failed
        } else {
            Outcome::Succeeded
        },
        &payload,
        pending.revision,
        artifacts,
        secrets,
    )?;
    let envelope: Value = serde_json::from_str(&artifacts.verify_required(prepared.artifact())?)?;
    ensure!(
        envelope["payload"] == payload,
        "Удаление секрета изменило ссылку на результат"
    );
    let mut candidate = session.clone();
    candidate.task_state.host_operation_saved(&prepared)?;
    let receipt = preview(&text, &output, outcome.is_error);
    outcome.content = text;
    outcome.recorded_output = Some(output);
    outcome.recorded_operation = Some(pending.id);
    if pending.origin.actor.is_none() {
        put_message(&mut candidate, call, &outcome, receipt)?;
    }
    candidate.save(store)?;
    *session = candidate;
    journal.commit_finish(&prepared, artifacts)?;
    Ok(outcome)
}

/// Caller сначала получает разрешение. Native spawn допускается только после
/// успеха этого метода; ошибка никогда не означает разрешение повторить действие.
/// Сохраняет задачу/ход, аргументы и намерение, не добавляя provider-сообщений.
#[allow(clippy::too_many_arguments)]
pub fn begin_background(
    journal: &mut OperationJournal,
    artifacts: &ArtifactStore,
    session: &mut Session,
    store: &ConfigStore,
    call: &ToolCall,
    actor: Option<&str>,
    args: &Value,
    secrets: &[String],
) -> Result<BackgroundOperation> {
    journal.check_session(&session.id)?;
    let mut reservation = session.clone();
    reservation.task_state = session.task_state.operation_capacity_state(&session.id)?;
    ensure!(
        serde_json::to_vec_pretty(&reservation)?.len() <= 8 * 1024 * 1024 - 4096,
        "В сессии недостаточно места для результата; сократите историю перед действием"
    );
    session.save(store)?;
    let id = uuid::Uuid::new_v4().to_string();
    let origin = ArtifactOrigin {
        actor: actor.map(str::to_owned),
        turn: session.turn_index,
        tool: call.function.name.clone(),
        call_id: call.id.clone(),
    };
    let arguments =
        artifacts.capture_required(origin.clone(), &serde_json::to_string(args)?, secrets)?;
    artifacts.verify_required(&arguments)?;
    let request = serde_json::to_value(SavedRequest {
        version: 1,
        arguments: arguments.clone(),
    })?;
    journal.begin(&id, origin, &request, artifacts, secrets)?;
    ensure!(
        journal.intent_payload(&id, artifacts)? == request,
        "Удаление секрета изменило ссылку на аргументы"
    );
    Ok(BackgroundOperation {
        pending: journal.pending_intent(&id)?,
        arguments,
    })
}

/// Завершает действие в текущем либо более позднем ходе. Caller подтверждает
/// реальный исход процесса до вызова. Публикация только после save + commit;
/// ошибка persistence закрывает журнал до recovery, без повторного spawn.
#[allow(clippy::too_many_arguments)]
pub fn finish_background(
    operation: &BackgroundOperation,
    journal: &mut OperationJournal,
    artifacts: &ArtifactStore,
    session: &mut Session,
    store: &ConfigStore,
    outcome: ToolOutcome,
    secrets: &[String],
) -> Result<BackgroundReceipt> {
    finish_background_inner(
        operation, journal, artifacts, session, store, outcome, secrets, None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn finish_command_manifest(
    operation: &BackgroundOperation,
    journal: &mut OperationJournal,
    artifacts: &ArtifactStore,
    session: &mut Session,
    store: &ConfigStore,
    outcome: ToolOutcome,
    secrets: &[String],
) -> Result<BackgroundReceipt> {
    let version = serde_json::from_str::<Value>(&outcome.content)?["version"].as_u64();
    let format = match version {
        Some(1) => OutputFormat::CommandManifestV1,
        Some(2) => OutputFormat::CommandManifestV2,
        _ => anyhow::bail!("Unknown command manifest version"),
    };
    finish_background_inner(
        operation,
        journal,
        artifacts,
        session,
        store,
        outcome,
        secrets,
        Some(format),
    )
}

#[allow(clippy::too_many_arguments)]
fn finish_background_inner(
    operation: &BackgroundOperation,
    journal: &mut OperationJournal,
    artifacts: &ArtifactStore,
    session: &mut Session,
    store: &ConfigStore,
    outcome: ToolOutcome,
    secrets: &[String],
    output_format: Option<OutputFormat>,
) -> Result<BackgroundReceipt> {
    // Validate capabilities before writing artifacts, even if a caller retained
    // an opaque handle after reopening the same session or passed a wrong one.
    journal.check_pending(&operation.pending, &session.id, artifacts)?;
    ensure!(
        session.turn_index >= operation.pending.origin().turn,
        "Нельзя завершить действие в ходе старше его запуска"
    );
    let result = (|| {
        artifacts.verify_required(&operation.arguments)?;
        if let Some(previous) = session.task_state.last_operation() {
            let (terminal, revision) =
                journal.committed_reference(&previous.operation_id, artifacts)?;
            ensure!(
                crate::task_state::TaskReference::from_artifact(&terminal)? == previous.terminal
                    && revision == previous.revision,
                "Предыдущий результат задачи не соответствует журналу"
            );
        }
        let revision = session.task_state.next_operation_revision(&session.id)?;
        let output = if output_format.is_some() {
            let meta = artifacts.capture_required(
                operation.pending.origin().clone(),
                &outcome.content,
                secrets,
            )?;
            ensure!(
                artifacts.verify_required(&meta)? == outcome.content,
                "Удаление секрета изменило manifest процесса"
            );
            meta
        } else {
            artifacts.capture(
                operation.pending.origin().clone(),
                &outcome.content,
                secrets,
            )?
        };
        let saved = SavedResult {
            version: 1,
            is_error: outcome.is_error,
            output: output.clone(),
            previous: session.task_state.last_operation().cloned(),
            output_format,
        };
        verify_saved_output(artifacts, &saved)?;
        if matches!(saved.output_format, Some(OutputFormat::CommandManifestV2)) {
            let reference = crate::job_epochs::reference(&outcome.content)?;
            let args: Value =
                serde_json::from_str(&artifacts.verify_required(&operation.arguments)?)?;
            let id = args["command_id"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing command identity"))?;
            let proof = committed_handoff(
                journal,
                artifacts,
                &session.id,
                &reference,
                id,
                operation.operation_id(),
                operation.pending.origin(),
            )?;
            crate::job_epochs::bind(
                artifacts,
                &outcome.content,
                &session.id,
                operation.pending.origin(),
                id,
                &proof,
            )?;
        }
        let payload = serde_json::to_value(saved)?;
        let prepared = journal.prepare_finish(
            operation.operation_id(),
            if outcome.is_error {
                Outcome::Failed
            } else {
                Outcome::Succeeded
            },
            &payload,
            revision,
            artifacts,
            secrets,
        )?;
        let envelope: Value =
            serde_json::from_str(&artifacts.verify_required(prepared.artifact())?)?;
        ensure!(
            envelope["payload"] == payload,
            "Удаление секрета изменило ссылку на результат"
        );
        let mut candidate = session.clone();
        candidate.task_state.host_operation_saved(&prepared)?;
        candidate.save(store)?;
        let terminal = journal.commit_finish(&prepared, artifacts)?;
        *session = candidate;
        Ok(BackgroundReceipt {
            operation_id: operation.operation_id().into(),
            output,
            terminal,
            task_revision: revision,
        })
    })();
    if result.is_err() {
        // The runtime retains the handle and must clean up/recover. Do not form
        // a later chain from a session whose terminal commit is ambiguous.
        journal.fail_closed();
    }
    result
}

/// Commit журнала важнее текста истории. Проверяем все сохранённые результаты,
/// даже если соответствующие сообщения уже свернулись при compaction.
pub(crate) fn reconcile(
    journal: &OperationJournal,
    artifacts: &ArtifactStore,
    session: &mut Session,
) -> Result<()> {
    reconcile_background(journal, artifacts, session, &[])
}

/// Владелец передаёт только удерживаемые фоновые действия текущего открытия.
/// Capability означает ответственность host за получение результата, а не
/// liveness процесса. После restart список пуст; строки/PID не заменяют токен.
pub fn reconcile_background(
    journal: &OperationJournal,
    artifacts: &ArtifactStore,
    session: &mut Session,
    owned: &[&BackgroundOperation],
) -> Result<()> {
    journal.check_session(&session.id)?;
    let mut current = std::collections::HashSet::new();
    for operation in owned {
        journal.check_pending(&operation.pending, &session.id, artifacts)?;
        ensure!(
            session.turn_index >= operation.pending.origin().turn,
            "Фоновое действие относится к более позднему ходу"
        );
        ensure!(
            current.insert(operation.operation_id()),
            "Повторная capability фонового действия"
        );
    }
    let records = journal.records(artifacts)?;
    let mut candidate = session.clone();
    let mut known = std::collections::HashSet::new();
    let mut unresolved = Vec::new();
    let mut referenced = std::collections::HashSet::new();
    for record in &records {
        known.insert(record.operation_id.as_str());
        let request: SavedRequest =
            serde_json::from_value(journal.intent_payload(&record.operation_id, artifacts)?)?;
        ensure!(
            request.version == 1
                && request.arguments.session_id == session.id
                && request.arguments.origin == record.origin,
            "Аргументы не соответствуют операции"
        );
        artifacts.verify_required(&request.arguments)?;
        let content = if let Some(payload) =
            journal.terminal_payload(&record.operation_id, artifacts)?
        {
            let saved: SavedResult = serde_json::from_value(payload)?;
            if let Some(previous) = &saved.previous {
                referenced.insert(previous.operation_id.clone());
                let earlier = records
                    .iter()
                    .find(|r| r.operation_id == previous.operation_id)
                    .ok_or_else(|| anyhow::anyhow!("Потеряна предыдущая операция"))?;
                let terminal = earlier
                    .terminal
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Предыдущая операция не подтверждена"))?;
                ensure!(
                    crate::task_state::TaskReference::from_artifact(terminal)? == previous.terminal
                        && earlier.task_revision == Some(previous.revision)
                        && record
                            .task_revision
                            .is_some_and(|revision| previous.revision < revision),
                    "Цепочка результатов не соответствует журналу"
                );
            }
            ensure!(
                saved.version == 1
                    && saved.output.session_id == session.id
                    && saved.output.origin == record.origin
                    && record.outcome
                        == if saved.is_error {
                            Outcome::Failed
                        } else {
                            Outcome::Succeeded
                        },
                "Результат не соответствует операции"
            );
            ensure!(
                record
                    .task_revision
                    .is_some_and(|r| r <= session.task_state.revision()),
                "Состояние задачи старше подтверждённой операции"
            );
            let text = verify_saved_output(artifacts, &saved)?;
            if matches!(saved.output_format, Some(OutputFormat::CommandManifestV2)) {
                let reference = crate::job_epochs::reference(&text)?;
                let args: Value =
                    serde_json::from_str(&artifacts.verify_required(&request.arguments)?)?;
                let id = args["command_id"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("Missing command identity"))?;
                let proof = committed_handoff(
                    journal,
                    artifacts,
                    &session.id,
                    &reference,
                    id,
                    &record.operation_id,
                    &record.origin,
                )?;
                crate::job_epochs::bind(artifacts, &text, &session.id, &record.origin, id, &proof)?;
            }
            preview(&text, &saved.output, saved.is_error)
        } else {
            candidate
                .task_state
                .invalidate_operation(&record.operation_id);
            if !current.contains(record.operation_id.as_str()) {
                unresolved.push(record);
            }
            unknown(&record.operation_id)
        };
        let mut matching = candidate
            .messages
            .iter_mut()
            .filter(|m| message_id(m) == Some(record.operation_id.as_str()));
        if let Some(message) = matching.next() {
            ensure!(
                record.origin.actor.is_none()
                    && message.role == "tool"
                    && message.tool_call_id.as_deref() == Some(&record.origin.call_id)
                    && message.name.as_deref() == Some(&record.origin.tool),
                "История не соответствует журналу операции"
            );
            ensure!(
                matching.next().is_none(),
                "Повторная ссылка на операцию в истории"
            );
            message.content = Some(content);
        }
    }
    for message in &candidate.messages {
        if message.host_operation.is_some() {
            ensure!(
                message_id(message).is_some_and(|id| known.contains(id)),
                "В истории неизвестная операция"
            );
        }
    }
    if let Some(last) = session.task_state.last_operation() {
        let record = records
            .iter()
            .find(|r| r.operation_id == last.operation_id)
            .ok_or_else(|| anyhow::anyhow!("В задаче неизвестная операция"))?;
        if let Some(terminal) = &record.terminal {
            ensure!(
                crate::task_state::TaskReference::from_artifact(terminal)? == last.terminal
                    && record.task_revision == Some(last.revision),
                "Ссылка задачи не соответствует журналу"
            );
        }
    }
    let latest = records
        .iter()
        .filter(|r| r.terminal.is_some())
        .max_by_key(|r| r.task_revision);
    candidate.task_state.restore_operation(
        latest
            .map(|record| {
                Ok::<_, anyhow::Error>(crate::task_state::TaskOperation {
                    operation_id: record.operation_id.clone(),
                    terminal: crate::task_state::TaskReference::from_artifact(
                        record.terminal.as_ref().expect("filtered"),
                    )?,
                    revision: record
                        .task_revision
                        .ok_or_else(|| anyhow::anyhow!("Отсутствует ревизия результата"))?,
                })
            })
            .transpose()?,
    )?;
    let extra_heads = records
        .iter()
        .filter(|record| {
            record.terminal.is_some()
                && !referenced.contains(&record.operation_id)
                && latest.is_none_or(|last| last.operation_id != record.operation_id)
        })
        .map(|record| {
            Ok::<_, anyhow::Error>(crate::task_state::TaskOperation {
                operation_id: record.operation_id.clone(),
                terminal: crate::task_state::TaskReference::from_artifact(
                    record.terminal.as_ref().expect("filtered"),
                )?,
                revision: record
                    .task_revision
                    .ok_or_else(|| anyhow::anyhow!("Отсутствует ревизия результата"))?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    restore_catalog(artifacts, &mut candidate, &extra_heads)?;
    // One bounded host warning also covers worker operations and compacted
    // root receipts. Replace it on every reconciliation instead of appending.
    candidate.messages.retain(|m| {
        m.role != "user"
            || !m
                .provider_meta
                .as_ref()
                .is_some_and(|p| p.kind == "rcode_runtime" && p.data["operation_recovery"] == true)
    });
    if !unresolved.is_empty() {
        let references: Vec<_> = unresolved.iter().rev().take(16).map(|r| json!({"operation_id":r.operation_id,"intent_artifact":r.intent.id,"actor":r.origin.actor,"tool":r.origin.tool})).collect();
        let mut warning = Message::user(json!({"runtime_warning":UNKNOWN,"unknown_operations":unresolved.len(),"recent":references}).to_string());
        warning.provider_meta = Some(ProviderMeta {
            kind: "rcode_runtime".into(),
            data: json!({"operation_recovery":true}),
        });
        candidate.messages.push(warning);
    }
    *session = candidate;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::config::{ProviderKind, ProviderSettings};
    use crate::protocol::Completion;
    use sha2::{Digest, Sha256};

    fn setup() -> (
        tempfile::TempDir,
        ConfigStore,
        Session,
        ArtifactStore,
        OperationJournal,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("project");
        std::fs::create_dir(&root).unwrap();
        let store = ConfigStore::at(temp.path().join("state")).unwrap();
        let mut session = Session::new(&root, ProviderSettings::new(ProviderKind::Custom)).unwrap();
        session
            .task_state
            .host_followup("Исправить задачу")
            .unwrap();
        session.turn_index = 1;
        session.save(&store).unwrap();
        let artifacts = ArtifactStore::open(&session.dir(&store), &session.id).unwrap();
        let journal =
            OperationJournal::open(&session.dir(&store), &session.id, &artifacts).unwrap();
        (temp, store, session, artifacts, journal)
    }

    fn call(session: &mut Session, store: &ConfigStore) -> ToolCall {
        let mut call = ToolCall::new("write_file", json!({"path":"proof","content":"saved"}));
        call.id = "provider-reuses-this-id".into();
        session.messages.push(Message::assistant(&Completion {
            tool_calls: vec![call.clone()],
            ..Default::default()
        }));
        session.save(store).unwrap();
        call
    }

    fn worker_record(
        actor: &str,
        role: crate::agents::AgentRole,
        status: crate::agents::AgentStatus,
    ) -> String {
        serde_json::to_string(&crate::agents::AgentRecord {
            id: actor.into(),
            name: "worker".into(),
            task: "short task".into(),
            role,
            status,
            result: "worker failed after local actions".into(),
            usage: Default::default(),
            transferred_commands: vec![],
        })
        .unwrap()
    }

    fn commit_actor_tool(
        journal: &mut OperationJournal,
        artifacts: &ArtifactStore,
        session: &mut Session,
        store: &ConfigStore,
        actor: &str,
        tool: &str,
        output: &str,
    ) -> String {
        let mut call = ToolCall::new(tool, json!({}));
        call.id = uuid::Uuid::new_v4().to_string();
        let pending = begin(
            journal,
            artifacts,
            session,
            store,
            &call,
            Some(actor),
            &json!({}),
            &[],
        )
        .unwrap();
        finish(
            pending,
            journal,
            artifacts,
            session,
            store,
            &call,
            ToolOutcome::success(output),
            &[],
        )
        .unwrap()
        .recorded_operation
        .unwrap()
    }

    fn failed_worker_outcome(actor: &str) -> ToolOutcome {
        ToolOutcome {
            is_error: true,
            content: worker_record(
                actor,
                crate::agents::AgentRole::Worker,
                crate::agents::AgentStatus::Failed,
            ),
            changed_paths: vec![],
            recorded_operation: None,
            recorded_output: None,
        }
    }

    #[test]
    fn worker_summary_filters_exact_actor_turn_and_counts_pending() {
        let (_temp, store, mut session, artifacts, mut journal) = setup();
        let actor = uuid::Uuid::new_v4().to_string();
        let other = uuid::Uuid::new_v4().to_string();
        let matching = commit_actor_tool(
            &mut journal,
            &artifacts,
            &mut session,
            &store,
            &actor,
            "poll_command",
            &json!({"command_id":uuid::Uuid::new_v4().to_string(),"stdout":"SAFE"}).to_string(),
        );
        let foreign = commit_actor_tool(
            &mut journal,
            &artifacts,
            &mut session,
            &store,
            &other,
            "poll_command",
            "foreign",
        );
        session.turn_index = 2;
        let wrong_turn = commit_actor_tool(
            &mut journal,
            &artifacts,
            &mut session,
            &store,
            &actor,
            "poll_command",
            "wrong turn",
        );
        session.turn_index = 1;
        let foreign_payload = journal
            .terminal_payload(&foreign, &artifacts)
            .unwrap()
            .unwrap();
        let foreign_meta: ArtifactMeta =
            serde_json::from_value(foreign_payload["output"].clone()).unwrap();
        let wrong_turn_payload = journal
            .terminal_payload(&wrong_turn, &artifacts)
            .unwrap()
            .unwrap();
        let wrong_turn_meta: ArtifactMeta =
            serde_json::from_value(wrong_turn_payload["output"].clone()).unwrap();
        let mut pending_call = ToolCall::new("stop_command", json!({}));
        pending_call.id = uuid::Uuid::new_v4().to_string();
        let pending = begin(
            &mut journal,
            &artifacts,
            &mut session,
            &store,
            &pending_call,
            Some(&actor),
            &json!({}),
            &[],
        )
        .unwrap();
        let prepared_output = artifacts
            .capture(pending.origin.clone(), "prepared but not committed", &[])
            .unwrap();
        let prepared_payload = serde_json::to_value(SavedResult {
            version: 1,
            is_error: false,
            output: prepared_output,
            previous: None,
            output_format: None,
        })
        .unwrap();
        let _prepared = journal
            .prepare_finish(
                &pending.id,
                Outcome::Succeeded,
                &prepared_payload,
                pending.revision,
                &artifacts,
                &[],
            )
            .unwrap();
        // Corrupt an artifact for another actor. Exact filtering must avoid it.
        std::fs::write(
            session.dir(&store).join("artifacts").join(&foreign_meta.id),
            b"corrupt",
        )
        .unwrap();
        std::fs::write(
            session
                .dir(&store)
                .join("artifacts")
                .join(&wrong_turn_meta.id),
            b"corrupt wrong turn",
        )
        .unwrap();

        let outcome = enrich_worker_wait(
            failed_worker_outcome(&actor),
            Some(&journal),
            Some(&artifacts),
            &session.id,
            1,
            &[],
        );
        let result: Value = serde_json::from_str(&outcome.content).unwrap();
        let receipts = &result["worker_receipts"];
        assert_eq!(receipts["pending_operations"], 1);
        assert_eq!(receipts["unavailable_operations"], 0);
        assert_eq!(receipts["observations"].as_array().unwrap().len(), 1);
        assert_eq!(receipts["observations"][0]["operation_id"], matching);
        assert!(outcome.is_error);
    }

    #[test]
    fn worker_summary_keeps_eight_admissions_and_sorts_by_commit_revision() {
        let (_temp, store, mut session, artifacts, mut journal) = setup();
        let actor = uuid::Uuid::new_v4().to_string();
        let mut pending = Vec::new();
        for n in 0..9 {
            let mut call = ToolCall::new("poll_command", json!({}));
            call.id = uuid::Uuid::new_v4().to_string();
            let operation = begin(
                &mut journal,
                &artifacts,
                &mut session,
                &store,
                &call,
                Some(&actor),
                &json!({}),
                &[],
            )
            .unwrap();
            pending.push((operation, call, n));
        }
        let oldest_id = pending[0].0.operation_id().to_owned();
        for (operation, _call, n) in pending.into_iter().rev() {
            let output_text = json!({"stdout":format!("receipt-{n}")}).to_string();
            let output = artifacts
                .capture(operation.origin.clone(), &output_text, &[])
                .unwrap();
            let payload = serde_json::to_value(SavedResult {
                version: 1,
                is_error: false,
                output,
                previous: None,
                output_format: None,
            })
            .unwrap();
            journal
                .finish(
                    &operation.id,
                    Outcome::Succeeded,
                    &payload,
                    n + 1,
                    &artifacts,
                    &[],
                )
                .unwrap();
        }
        let sources = journal
            .worker_observation_sources(&artifacts, &session.id, &actor, 1)
            .unwrap();
        assert_eq!(sources.omitted, 1);
        assert_eq!(sources.pending, 0);
        assert_eq!(sources.sources.len(), 8);
        assert!(
            sources
                .sources
                .windows(2)
                .all(|pair| pair[0].revision >= pair[1].revision)
        );
        assert!(
            !sources
                .sources
                .iter()
                .any(|source| source.operation_id == oldest_id)
        );
    }

    #[test]
    fn worker_summary_redacts_full_unicode_output_before_preview_and_preserves_failure() {
        let (_temp, store, mut session, artifacts, mut journal) = setup();
        let actor = uuid::Uuid::new_v4().to_string();
        let secret = "секретный-хвост-0123456789";
        let stdout = format!("{}{}🙂", "a".repeat(500), secret);
        commit_actor_tool(
            &mut journal,
            &artifacts,
            &mut session,
            &store,
            &actor,
            "poll_command",
            &json!({"stdout":stdout}).to_string(),
        );
        let outcome = enrich_worker_wait(
            failed_worker_outcome(&actor),
            Some(&journal),
            Some(&artifacts),
            &session.id,
            1,
            &[secret.into()],
        );
        let result: Value = serde_json::from_str(&outcome.content).unwrap();
        let receipts = &result["worker_receipts"];
        assert_eq!(receipts["available"], true);
        assert!(
            receipts["observations"][0]["stdout_preview"]
                .as_str()
                .unwrap()
                .len()
                <= WORKER_PREVIEW_MAX
        );
        assert!(!receipts.to_string().contains(secret));
        assert!(serde_json::to_vec(receipts).unwrap().len() <= WORKER_SUMMARY_MAX);
        assert!(outcome.is_error);
    }

    #[test]
    fn worker_summary_skips_oversized_outputs_before_reading_body() {
        let (_temp, store, mut session, artifacts, mut journal) = setup();
        let actor = uuid::Uuid::new_v4().to_string();
        commit_actor_tool(
            &mut journal,
            &artifacts,
            &mut session,
            &store,
            &actor,
            "run_command",
            &"x".repeat(WORKER_OUTPUT_MAX + 1),
        );
        crate::artifacts::reset_read_bytes();
        let outcome = enrich_worker_wait(
            failed_worker_outcome(&actor),
            Some(&journal),
            Some(&artifacts),
            &session.id,
            1,
            &[],
        );
        let result: Value = serde_json::from_str(&outcome.content).unwrap();
        let observation = &result["worker_receipts"]["observations"][0];
        assert_eq!(
            observation["payload_unavailable"],
            "output_over_limit_or_truncated"
        );
        assert!(crate::artifacts::read_bytes_count() < WORKER_OUTPUT_MAX);
        assert!(
            serde_json::to_vec(&result["worker_receipts"])
                .unwrap()
                .len()
                <= WORKER_SUMMARY_MAX
        );
    }

    #[test]
    fn worker_summary_never_reads_a_manifest_or_its_pages() {
        let (_temp, store, mut session, artifacts, mut journal) = setup();
        let actor = uuid::Uuid::new_v4().to_string();
        let mut call = ToolCall::new("command_lifetime", json!({}));
        call.id = uuid::Uuid::new_v4().to_string();
        let operation = begin(
            &mut journal,
            &artifacts,
            &mut session,
            &store,
            &call,
            Some(&actor),
            &json!({}),
            &[],
        )
        .unwrap();
        let manifest = format!(
            "{{\"version\":1,\"page_id\":\"{}\",\"padding\":\"{}\"}}",
            uuid::Uuid::new_v4(),
            "x".repeat(128 * 1024)
        );
        let output = artifacts
            .capture_required(operation.origin.clone(), &manifest, &[])
            .unwrap();
        let payload = serde_json::to_value(SavedResult {
            version: 1,
            is_error: false,
            output: output.clone(),
            previous: None,
            output_format: Some(OutputFormat::CommandManifestV1),
        })
        .unwrap();
        journal
            .finish(
                &operation.id,
                Outcome::Succeeded,
                &payload,
                1,
                &artifacts,
                &[],
            )
            .unwrap();
        let output_path = session.dir(&store).join("artifacts").join(&output.id);
        let mut corrupted = std::fs::read(&output_path).unwrap();
        *corrupted.last_mut().unwrap() ^= 0x01;
        std::fs::write(&output_path, corrupted).unwrap();
        crate::artifacts::reset_read_bytes();
        let outcome = enrich_worker_wait(
            failed_worker_outcome(&actor),
            Some(&journal),
            Some(&artifacts),
            &session.id,
            1,
            &[],
        );
        let result: Value = serde_json::from_str(&outcome.content).unwrap();
        let observation = &result["worker_receipts"]["observations"][0];
        assert_eq!(observation["payload_unavailable"], "manifest_not_expanded");
        assert_eq!(observation["output"], output.id);
        assert_eq!(result["worker_receipts"]["unavailable_operations"], 0);
        assert!(crate::artifacts::read_bytes_count() < 64 * 1024);
    }

    #[test]
    fn worker_summary_is_bounded_after_json_escaping_and_preserves_native_input_truth() {
        let (_temp, store, mut session, artifacts, mut journal) = setup();
        let actor = uuid::Uuid::new_v4().to_string();
        let command_id = uuid::Uuid::new_v4().to_string();
        let inputs = (0..5).map(|_| json!({
            "input_id":uuid::Uuid::new_v4().to_string(), "delivery":"accepted", "written":0, "total":900
        })).collect::<Vec<_>>();
        commit_actor_tool(
            &mut journal,
            &artifacts,
            &mut session,
            &store,
            &actor,
            "poll_command",
            &json!({
                "command_id":command_id,"status":"running","inputs":inputs,
                "output_truncated":true,"payload_unavailable":true,"stdout":""
            })
            .to_string(),
        );
        let outcome = enrich_worker_wait(
            failed_worker_outcome(&actor),
            Some(&journal),
            Some(&artifacts),
            &session.id,
            1,
            &[],
        );
        let result: Value = serde_json::from_str(&outcome.content).unwrap();
        let receipts = &result["worker_receipts"];
        let observation = &receipts["observations"][0];
        assert_eq!(observation["fields"]["command_id"], command_id);
        assert_eq!(observation["fields"]["inputs"].as_array().unwrap().len(), 4);
        assert_eq!(observation["fields"]["inputs_truncated"], true);
        assert_eq!(observation["fields"]["inputs"][0]["delivery"], "accepted");
        assert_eq!(observation["fields"]["inputs"][0]["written"], 0);
        assert_eq!(observation["fields"]["output_truncated"], true);
        assert_eq!(
            observation["payload_unavailable"],
            "native_receipt_unavailable"
        );
        assert_eq!(observation["stdout_truncated"], true);
        assert_eq!(receipts["truncated"], true);

        for _ in 0..8 {
            commit_actor_tool(
                &mut journal,
                &artifacts,
                &mut session,
                &store,
                &actor,
                "poll_command",
                &json!({"stdout":"\u{0000}".repeat(512)}).to_string(),
            );
        }
        let bounded = enrich_worker_wait(
            failed_worker_outcome(&actor),
            Some(&journal),
            Some(&artifacts),
            &session.id,
            1,
            &[],
        );
        let bounded_json: Value = serde_json::from_str(&bounded.content).unwrap();
        let bounded_summary = &bounded_json["worker_receipts"];
        assert!(serde_json::to_vec(bounded_summary).unwrap().len() <= WORKER_SUMMARY_MAX);
        assert_eq!(bounded_summary["truncated"], true);
        assert_eq!(bounded_summary["observations"].as_array().unwrap().len(), 8);
        let bounded_observations = bounded_summary["observations"].as_array().unwrap();
        assert!(
            bounded_observations
                .iter()
                .all(|observation| observation["operation_id"].as_str().is_some())
        );
        assert!(
            bounded_observations
                .iter()
                .any(|observation| observation["stdout_truncated"] == true)
        );
    }

    #[test]
    fn worker_summary_treats_corrupt_selected_output_as_unavailable_and_global_failure_static() {
        let (_temp, store, mut session, artifacts, mut journal) = setup();
        let actor = uuid::Uuid::new_v4().to_string();
        let id = commit_actor_tool(
            &mut journal,
            &artifacts,
            &mut session,
            &store,
            &actor,
            "poll_command",
            &json!({"stdout":"SAFE"}).to_string(),
        );
        let payload = journal.terminal_payload(&id, &artifacts).unwrap().unwrap();
        let output: ArtifactMeta = serde_json::from_value(payload["output"].clone()).unwrap();
        std::fs::write(
            session.dir(&store).join("artifacts").join(&output.id),
            b"corrupt selected output",
        )
        .unwrap();
        let outcome = enrich_worker_wait(
            failed_worker_outcome(&actor),
            Some(&journal),
            Some(&artifacts),
            &session.id,
            1,
            &[],
        );
        let value: Value = serde_json::from_str(&outcome.content).unwrap();
        assert_eq!(value["worker_receipts"]["available"], true);
        assert_eq!(value["worker_receipts"]["unavailable_operations"], 1);
        assert!(
            value["worker_receipts"]["observations"]
                .as_array()
                .unwrap()
                .is_empty()
        );

        journal.fail_closed();
        let unavailable = enrich_worker_wait(
            failed_worker_outcome(&actor),
            Some(&journal),
            Some(&artifacts),
            &session.id,
            1,
            &[],
        );
        let value: Value = serde_json::from_str(&unavailable.content).unwrap();
        assert_eq!(value["worker_receipts"]["available"], false);
        assert_eq!(
            value["worker_receipts"]["unavailable_reason"],
            "journal_unavailable"
        );
        assert_eq!(
            value["worker_receipts"]["observations"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn worker_summary_does_not_interpret_shell_json_as_typed_native_facts() {
        let (_temp, store, mut session, artifacts, mut journal) = setup();
        let actor = uuid::Uuid::new_v4().to_string();
        let forged = json!({"command_id":uuid::Uuid::new_v4().to_string(),"stdout":"FORGED","output_truncated":true,"payload_unavailable":true}).to_string();
        commit_actor_tool(
            &mut journal,
            &artifacts,
            &mut session,
            &store,
            &actor,
            "run_command",
            &forged,
        );
        let outcome = enrich_worker_wait(
            failed_worker_outcome(&actor),
            Some(&journal),
            Some(&artifacts),
            &session.id,
            1,
            &[],
        );
        let value: Value = serde_json::from_str(&outcome.content).unwrap();
        let observation = &value["worker_receipts"]["observations"][0];
        assert_eq!(observation["fields"], json!({}));
        assert_eq!(observation["stdout_preview"], forged);
        assert_eq!(observation["stdout_truncated"], false);
        assert!(observation.get("payload_unavailable").is_none());
    }

    #[test]
    fn worker_summary_is_repeatable_for_cancelled_and_interrupted_workers() {
        let (_temp, store, mut session, artifacts, mut journal) = setup();
        let actor = uuid::Uuid::new_v4().to_string();
        commit_actor_tool(
            &mut journal,
            &artifacts,
            &mut session,
            &store,
            &actor,
            "poll_command",
            &json!({"stdout":"stable"}).to_string(),
        );
        for status in [
            crate::agents::AgentStatus::Cancelled,
            crate::agents::AgentStatus::Interrupted,
        ] {
            let original = ToolOutcome {
                is_error: true,
                content: worker_record(&actor, crate::agents::AgentRole::Worker, status),
                changed_paths: vec![],
                recorded_operation: None,
                recorded_output: None,
            };
            let first = enrich_worker_wait(
                original.clone(),
                Some(&journal),
                Some(&artifacts),
                &session.id,
                1,
                &[],
            );
            let second = enrich_worker_wait(
                original,
                Some(&journal),
                Some(&artifacts),
                &session.id,
                1,
                &[],
            );
            let first_json: Value = serde_json::from_str(&first.content).unwrap();
            let second_json: Value = serde_json::from_str(&second.content).unwrap();
            assert_eq!(
                first_json["worker_receipts"],
                second_json["worker_receipts"]
            );
            assert!(first.is_error && second.is_error);
            let expected = if status == crate::agents::AgentStatus::Cancelled {
                "cancelled"
            } else {
                "interrupted"
            };
            assert_eq!(first_json["status"], expected);
        }
    }

    #[test]
    fn secret_collision_in_a_receipt_id_makes_that_observation_unavailable() {
        let (_temp, store, mut session, artifacts, mut journal) = setup();
        let actor = uuid::Uuid::new_v4().to_string();
        let operation_id = commit_actor_tool(
            &mut journal,
            &artifacts,
            &mut session,
            &store,
            &actor,
            "poll_command",
            &json!({"stdout":"safe"}).to_string(),
        );
        let secret = operation_id[..8].to_owned();
        let outcome = enrich_worker_wait(
            failed_worker_outcome(&actor),
            Some(&journal),
            Some(&artifacts),
            &session.id,
            1,
            std::slice::from_ref(&secret),
        );
        let value: Value = serde_json::from_str(&outcome.content).unwrap();
        assert_eq!(value["worker_receipts"]["unavailable_operations"], 1);
        assert!(
            value["worker_receipts"]["observations"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(!value["worker_receipts"].to_string().contains(&secret));
    }

    #[test]
    fn worker_wait_only_enriches_failed_workers_and_never_changes_outcome_flags() {
        let actor = uuid::Uuid::new_v4().to_string();
        for (role, status) in [
            (
                crate::agents::AgentRole::Worker,
                crate::agents::AgentStatus::Completed,
            ),
            (
                crate::agents::AgentRole::Explorer,
                crate::agents::AgentStatus::Failed,
            ),
        ] {
            let original = ToolOutcome {
                is_error: false,
                content: worker_record(&actor, role, status),
                changed_paths: vec!["kept".into()],
                recorded_operation: Some("op".into()),
                recorded_output: None,
            };
            let before = original.content.clone();
            let enriched = enrich_worker_wait(original, None, None, "session", 1, &[]);
            assert_eq!(enriched.content, before);
            assert!(!enriched.is_error);
            assert_eq!(enriched.changed_paths, vec!["kept"]);
            assert_eq!(enriched.recorded_operation.as_deref(), Some("op"));
        }
    }

    #[test]
    fn model_preview_keeps_file_or_skill_hash_without_exposing_the_receipt_digest() {
        let (_temp, _store, _session, artifacts, _journal) = setup();
        for tool in ["read_file", "load_skill"] {
            let text=json!({"path":"fixture.txt","sha256":"f".repeat(64),"content":"original","artifact_sha256":"legacy receipt digest"}).to_string();
            let meta = artifacts
                .capture(
                    ArtifactOrigin {
                        actor: None,
                        turn: 1,
                        tool: tool.into(),
                        call_id: "read".into(),
                    },
                    &text,
                    &[],
                )
                .unwrap();
            let value: Value = serde_json::from_str(&preview(&text, &meta, false)).unwrap();
            assert_eq!(value["sha256"], "f".repeat(64));
            assert!(value.get("artifact_sha256").is_none());
            assert_eq!(value["artifact_id"], meta.id);
            assert_eq!(value["artifact_bytes"], meta.bytes);
            assert_eq!(value["artifact_truncated"], false);
            assert_eq!(
                meta.sha256,
                format!("{:x}", Sha256::digest(text.as_bytes()))
            );
            assert_eq!(artifacts.verify_required(&meta).unwrap(), text);
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[tokio::test]
    async fn durable_lookup_requires_committed_lifetime_and_exact_worker_owner() {
        use crate::jobs::{JobKind, JobOrigin, JobSpec, JobStatus, JobsSupervisor};
        use std::time::Duration;
        use tokio_util::sync::CancellationToken;
        let (_temp, store, mut session, artifacts, mut journal) = setup();
        let jobs = JobsSupervisor::new_for_session(&session.id, vec![]).unwrap();
        jobs.attach_cleanup_guard(journal.cleanup_guard()).unwrap();
        let reservation = jobs.reserve_start().unwrap();
        let id = reservation.id().to_owned();
        let origin = JobOrigin {
            actor: Some("worker".into()),
            turn: 1,
        };
        let args = json!({"command_id":id,"origin":origin});
        let pending = begin_background(
            &mut journal,
            &artifacts,
            &mut session,
            &store,
            &ToolCall::new("command_lifetime", args.clone()),
            Some("worker"),
            &args,
            &[],
        )
        .unwrap();
        let request = crate::job_tools::PollArgs {
            command_id: id.clone(),
            stdout_offset: 0,
            stderr_offset: 0,
            max_bytes: 64,
        };
        assert!(
            command_output(
                &journal,
                &artifacts,
                &session.id,
                Some("worker"),
                &request,
                &[]
            )
            .unwrap()
            .is_none()
        );
        jobs.start_reserved(
            reservation,
            JobSpec {
                kind: JobKind::Managed,
                argv: vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    "printf failed-output; exit 7".into(),
                ],
                cwd: session.root.clone(),
                env: vec![],
                origin,
                lifetime: Duration::from_secs(60),
                idle_timeout: Duration::from_secs(60),
                stdin: false,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let view = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let view = jobs.poll(Some("worker"), &id, 0, 0, 64).await.unwrap();
                if view.status != JobStatus::Running {
                    break view;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        jobs.publish_snapshot(&view, |view| {
            let manifest = crate::job_manifest::capture(&jobs, &artifacts, view)?;
            let mut outcome = ToolOutcome::success(manifest);
            outcome.is_error = true;
            finish_command_manifest(
                &pending,
                &mut journal,
                &artifacts,
                &mut session,
                &store,
                outcome,
                &[],
            )
        })
        .await
        .unwrap();
        jobs.acknowledge_payload(Some("worker"), &id).unwrap();
        let result = command_output(
            &journal,
            &artifacts,
            &session.id,
            Some("worker"),
            &request,
            &[],
        )
        .unwrap()
        .unwrap();
        assert_eq!(result["stdout"], "failed-output");
        assert_eq!(result["exit_code"], 7);
        for actor in [None, Some("other")] {
            assert!(
                command_output(&journal, &artifacts, &session.id, actor, &request, &[])
                    .unwrap()
                    .is_none()
            );
        }
        assert!(
            command_output(
                &journal,
                &artifacts,
                "other-session",
                Some("worker"),
                &request,
                &[]
            )
            .is_err()
        );
        jobs.shutdown().await.unwrap();
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[tokio::test]
    async fn handed_off_lifetime_keeps_epoch_artifact_owners_and_committed_read_grants() {
        use crate::jobs::{JobKind, JobOrigin, JobSpec, JobStatus, JobsSupervisor};
        use std::time::Duration;
        use tokio_util::sync::CancellationToken;
        for corrupt in [false, true] {
            let (_temp, store, mut session, artifacts, mut journal) = setup();
            let jobs = JobsSupervisor::new_for_session(&session.id, vec![]).unwrap();
            jobs.attach_cleanup_guard(journal.cleanup_guard()).unwrap();
            let reservation = jobs.reserve_start().unwrap();
            let id = reservation.id().to_owned();
            let origin = JobOrigin {
                actor: Some("epoch-worker".into()),
                turn: 1,
            };
            let args = json!({"command_id":id,"origin":origin});
            let lifetime = begin_background(
                &mut journal,
                &artifacts,
                &mut session,
                &store,
                &ToolCall::new("command_lifetime", args.clone()),
                Some("epoch-worker"),
                &args,
                &[],
            )
            .unwrap();
            let worker = CancellationToken::new();
            let parent = CancellationToken::new();
            jobs.start_reserved(reservation, JobSpec { kind: JobKind::Managed,
            argv: vec!["/bin/sh".into(), "-c".into(), "printf before; printf olderr >&2; while [ ! -f release ]; do sleep 0.01; done; printf after; printf newerr >&2; sleep 30".into()],
            cwd: session.root.clone(), env: vec![], origin, lifetime: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(60), stdin: false }, worker.clone()).await.unwrap();
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let view = jobs
                        .poll(Some("epoch-worker"), &id, 0, 0, 64)
                        .await
                        .unwrap();
                    if view.stdout == "before" && view.stderr == "olderr" {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            let call = ToolCall::new("handoff_command", json!({"command_id":id}));
            let args = json!({"command_id":id,"lifetime_id":lifetime.operation_id(),"worker":"epoch-worker","parent_scope_id":"parent-native","expected_epoch":0});
            let pending = begin(
                &mut journal,
                &artifacts,
                &mut session,
                &store,
                &call,
                Some("epoch-worker"),
                &args,
                &[],
            )
            .unwrap();
            let operation_id = pending.operation_id().to_owned();
            jobs.handoff_to_parent(
                "epoch-worker",
                &id,
                &operation_id,
                0,
                "parent-native",
                parent.clone(),
            )
            .unwrap();
            let data = HandoffData {
                version: 1,
                status: "transferred".into(),
                command_id: id.clone(),
                lifetime_id: lifetime.operation_id().into(),
                worker: "epoch-worker".into(),
                parent_scope_id: "parent-native".into(),
                expected_epoch: 0,
                ownership_epoch: 1,
                stdout_offset: 6,
                stderr_offset: 6,
                owner: None,
                operation_id: operation_id.clone(),
            };
            finish(
                pending,
                &mut journal,
                &artifacts,
                &mut session,
                &store,
                &call,
                ToolOutcome::success(serde_json::to_string(&data).unwrap()),
                &[],
            )
            .unwrap();
            let reference = HandoffReference {
                operation_id: operation_id.clone(),
                terminal: journal
                    .committed_reference(&operation_id, &artifacts)
                    .unwrap()
                    .0,
            };
            let proof = committed_handoff(
                &journal,
                &artifacts,
                &session.id,
                &reference,
                &id,
                lifetime.operation_id(),
                lifetime.pending.origin(),
            )
            .unwrap();
            worker.cancel();
            assert_eq!(
                jobs.poll(None, &id, 0, 0, 64).await.unwrap().status,
                JobStatus::Running
            );
            assert!(
                jobs.poll(Some("epoch-worker"), &id, 0, 0, 64)
                    .await
                    .is_err()
            );
            std::fs::write(session.root.join("release"), "go").unwrap();
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let view = jobs.poll(None, &id, 0, 0, 64).await.unwrap();
                    if view.stdout == "beforeafter" && view.stderr == "olderrnewerr" {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            let stopped = jobs.stop(None, &id).await.unwrap();
            let result = jobs
                .publish_snapshot(&stopped, |view| {
                    let mut text = crate::job_epochs::capture(&jobs, &artifacts, view, &proof)?;
                    if corrupt {
                        let mut value: Value = serde_json::from_str(&text)?;
                        for field in ["stdout", "stderr"] {
                            for page in value[field].as_array_mut().unwrap() {
                                let meta: ArtifactMeta =
                                    serde_json::from_value(page["artifact"].clone())?;
                                let bytes = artifacts.verify_required(&meta)?;
                                let mut origin = meta.origin;
                                origin.actor = Some("epoch-worker".into());
                                page["artifact"] = serde_json::to_value(
                                    artifacts.capture_required(origin, &bytes, &[])?,
                                )?;
                                page["epoch"] = json!(0);
                            }
                        }
                        value["terminal"]["epoch_boundaries"][1]["stdout_offset"] =
                            value["terminal"]["next_stdout_offset"].clone();
                        value["terminal"]["epoch_boundaries"][1]["stderr_offset"] =
                            value["terminal"]["next_stderr_offset"].clone();
                        text = value.to_string();
                        crate::job_epochs::verify(&artifacts, &text, &session.id)?; // self-consistent, but contradicts committed cuts
                    }
                    let mut outcome = ToolOutcome::success(text);
                    outcome.is_error = true;
                    finish_command_manifest(
                        &lifetime,
                        &mut journal,
                        &artifacts,
                        &mut session,
                        &store,
                        outcome,
                        &[],
                    )
                })
                .await;
            if corrupt {
                assert!(
                    result.is_err(),
                    "Manifest cuts must bind to committed handoff before lifetime commit"
                );
                jobs.shutdown().await.unwrap();
                continue;
            }
            let receipt = result.unwrap();
            let text = artifacts.verify_required(&receipt.output).unwrap();
            let manifest: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(manifest["version"], 2);
            for field in ["stdout", "stderr"] {
                let pages = manifest[field].as_array().unwrap();
                assert_eq!(pages.len(), 2);
                let old: ArtifactMeta =
                    serde_json::from_value(pages[0]["artifact"].clone()).unwrap();
                let new: ArtifactMeta =
                    serde_json::from_value(pages[1]["artifact"].clone()).unwrap();
                assert_eq!(old.origin.actor.as_deref(), Some("epoch-worker"));
                assert_eq!(new.origin.actor, None);
                assert!(
                    artifacts
                        .read(Some("epoch-worker"), &old.id, 1, 10, None)
                        .is_ok()
                );
                assert!(
                    artifacts
                        .read(Some("epoch-worker"), &new.id, 1, 10, None)
                        .is_err()
                );
            }
            assert!(
                artifacts
                    .read(Some("epoch-worker"), &receipt.output.id, 1, 10, None)
                    .is_err()
            );
            assert!(
                artifacts
                    .read_bytes(Some("epoch-worker"), &receipt.output.id, 0, 64)
                    .is_err()
            );
            let request = crate::job_tools::PollArgs {
                command_id: id.clone(),
                stdout_offset: 0,
                stderr_offset: 0,
                max_bytes: 64,
            };
            let old = command_output(
                &journal,
                &artifacts,
                &session.id,
                Some("epoch-worker"),
                &request,
                &[],
            )
            .unwrap()
            .unwrap();
            assert_eq!(old["stdout"], "before");
            assert_eq!(old["stderr"], "olderr");
            let full = command_output(&journal, &artifacts, &session.id, None, &request, &[])
                .unwrap()
                .unwrap();
            assert_eq!(full["stdout"], "beforeafter");
            assert_eq!(full["stderr"], "olderrnewerr");
            assert!(
                command_output(
                    &journal,
                    &artifacts,
                    &session.id,
                    Some("other"),
                    &request,
                    &[]
                )
                .unwrap()
                .is_none()
            );
            reconcile_background(&journal, &artifacts, &mut session, &[]).unwrap();
            let mut large = manifest.clone();
            large["stdout"] = json!([large["stdout"][0].clone()]);
            for index in 0..32 {
                let origin = ArtifactOrigin {
                    actor: None,
                    turn: 1,
                    tool: "command_output".into(),
                    call_id: id.clone(),
                };
                let text = match index {
                    0 => format!("{}KEY-", "Z".repeat(65532)),
                    1 => format!("привет{}", "Z".repeat(65524)),
                    _ => "Z".repeat(65536),
                };
                let artifact = artifacts.capture_required(origin, &text, &[]).unwrap();
                large["stdout"].as_array_mut().unwrap().push(json!({"offset":6+index*65536,"end":6+(index+1)*65536,"epoch":1,"artifact":artifact}));
            }
            large["terminal"]["next_stdout_offset"] = json!(6 + 32 * 65536);
            let text = large.to_string();
            crate::job_epochs::verify(&artifacts, &text, &session.id).unwrap();
            crate::artifacts::reset_read_bytes();
            let request = crate::job_tools::PollArgs {
                command_id: id.clone(),
                stdout_offset: 6 + 16 * 65536,
                stderr_offset: 0,
                max_bytes: 4,
            };
            assert_eq!(
                crate::job_epochs::page(
                    &artifacts,
                    &text,
                    &session.id,
                    lifetime.pending.origin(),
                    &request,
                    &proof,
                    false,
                    &[]
                )
                .unwrap()["stdout"],
                "ZZZZ"
            );
            assert!(
                crate::artifacts::read_bytes_count() <= 512 * 1024,
                "A four-byte poll must not reload full multi-MiB output: {}",
                crate::artifacts::read_bytes_count()
            );
            let keys = vec!["KEY-привет".to_owned()];
            let mut offset = 6 + 65532;
            for _ in 0..4 {
                let request = crate::job_tools::PollArgs {
                    command_id: id.clone(),
                    stdout_offset: offset,
                    stderr_offset: 0,
                    max_bytes: 4,
                };
                let result = crate::job_epochs::page(
                    &artifacts,
                    &text,
                    &session.id,
                    lifetime.pending.origin(),
                    &request,
                    &proof,
                    false,
                    &keys,
                )
                .unwrap();
                assert_eq!(result["stdout"], "****");
                assert_eq!(result["next_stdout_offset"], offset + 4);
                offset = result["next_stdout_offset"].as_u64().unwrap() as usize;
            }
            let request = crate::job_tools::PollArgs {
                command_id: id.clone(),
                stdout_offset: 6 + 65536,
                stderr_offset: 0,
                max_bytes: 5,
            };
            let result = crate::job_epochs::page(
                &artifacts,
                &text,
                &session.id,
                lifetime.pending.origin(),
                &request,
                &proof,
                false,
                &keys,
            )
            .unwrap();
            assert_eq!(result["stdout"], "****");
            assert_eq!(result["next_stdout_offset"], 6 + 65540); // requested end lies inside a Cyrillic scalar
            let mut tampered = manifest;
            tampered["terminal"]["epoch_boundaries"][1]["stdout_offset"] = json!(0);
            assert!(
                crate::job_epochs::verify(&artifacts, &tampered.to_string(), &session.id).is_err()
            );
            jobs.shutdown().await.unwrap();
        }
    }

    fn background(
        journal: &mut OperationJournal,
        artifacts: &ArtifactStore,
        session: &mut Session,
        store: &ConfigStore,
    ) -> BackgroundOperation {
        begin_background(
            journal,
            artifacts,
            session,
            store,
            &ToolCall::new("command_lifetime", json!({"command":"host fixture"})),
            None,
            &json!({"command":"host fixture"}),
            &[],
        )
        .unwrap()
    }

    #[test]
    fn background_finishes_across_turns_in_completion_order_with_other_tools() {
        let (_temp, store, mut session, artifacts, mut journal) = setup();
        let first = background(&mut journal, &artifacts, &mut session, &store);
        let second = background(&mut journal, &artifacts, &mut session, &store);
        assert!(session.messages.is_empty());
        assert_eq!(session.task_state.revision(), 0);
        assert_eq!(journal.records(&artifacts).unwrap().len(), 2);
        let call = call(&mut session, &store);
        let ordinary = begin(
            &mut journal,
            &artifacts,
            &mut session,
            &store,
            &call,
            None,
            &json!({}),
            &[],
        )
        .unwrap();
        finish(
            ordinary,
            &mut journal,
            &artifacts,
            &mut session,
            &store,
            &call,
            ToolOutcome::success("ordinary"),
            &[],
        )
        .unwrap();
        let ordinary = session.task_state.last_operation().unwrap().clone();
        let messages = serde_json::to_value(&session.messages).unwrap();
        session.turn_index += 1;
        session
            .task_state
            .host_followup("Дождаться двух процессов")
            .unwrap();
        session.save(&store).unwrap();
        let before = session.task_state.revision();
        let second_receipt = finish_background(
            &second,
            &mut journal,
            &artifacts,
            &mut session,
            &store,
            ToolOutcome::success("SECOND"),
            &[],
        )
        .unwrap();
        let first_receipt = finish_background(
            &first,
            &mut journal,
            &artifacts,
            &mut session,
            &store,
            ToolOutcome::success("FIRST"),
            &[],
        )
        .unwrap();
        assert_eq!(second_receipt.task_revision, before + 1);
        assert_eq!(first_receipt.task_revision, before + 2);
        assert_eq!(serde_json::to_value(&session.messages).unwrap(), messages);
        let second_payload = journal
            .terminal_payload(second.operation_id(), &artifacts)
            .unwrap()
            .unwrap();
        assert_eq!(
            second_payload["previous"]["operation_id"],
            ordinary.operation_id
        );
        let first_payload = journal
            .terminal_payload(first.operation_id(), &artifacts)
            .unwrap()
            .unwrap();
        assert_eq!(
            first_payload["previous"]["operation_id"],
            second.operation_id()
        );
        assert!(
            finish_background(
                &first,
                &mut journal,
                &artifacts,
                &mut session,
                &store,
                ToolOutcome::success("DUPLICATE"),
                &[]
            )
            .is_err()
        );
        drop(journal);
        session = Session::load(&store, &session.id, &session.root).unwrap();
        let journal =
            OperationJournal::open(&session.dir(&store), &session.id, &artifacts).unwrap();
        reconcile(&journal, &artifacts, &mut session).unwrap();
        assert_eq!(
            session.task_state.last_operation().unwrap().operation_id,
            first.operation_id()
        );
        assert!(session.task_state.operation_catalog().is_none());
        assert_eq!(serde_json::to_value(&session.messages).unwrap(), messages);
        assert_eq!(
            artifacts.verify_output(&first_receipt.output).unwrap(),
            "FIRST"
        );
        assert_eq!(
            first_receipt.terminal,
            *journal.records(&artifacts).unwrap()[0]
                .terminal
                .as_ref()
                .unwrap()
        );
    }

    #[test]
    fn background_capability_cannot_adopt_reopened_or_foreign_pending() {
        let (_temp, store, mut session, artifacts, mut journal) = setup();
        let pending = background(&mut journal, &artifacts, &mut session, &store);
        let (_other, other_store, mut other, other_artifacts, mut other_journal) = setup();
        let before = serde_json::to_value(&other).unwrap();
        assert!(
            finish_background(
                &pending,
                &mut other_journal,
                &other_artifacts,
                &mut other,
                &other_store,
                ToolOutcome::success("FOREIGN"),
                &[]
            )
            .is_err()
        );
        assert_eq!(serde_json::to_value(&other).unwrap(), before);
        assert!(other_journal.records(&other_artifacts).unwrap().is_empty());
        drop(journal);
        let mut journal =
            OperationJournal::open(&session.dir(&store), &session.id, &artifacts).unwrap();
        let count = std::fs::read_dir(session.dir(&store).join("artifacts"))
            .unwrap()
            .count();
        assert!(
            finish_background(
                &pending,
                &mut journal,
                &artifacts,
                &mut session,
                &store,
                ToolOutcome::success("ADOPTED"),
                &[]
            )
            .is_err()
        );
        assert_eq!(
            std::fs::read_dir(session.dir(&store).join("artifacts"))
                .unwrap()
                .count(),
            count
        );
        reconcile(&journal, &artifacts, &mut session).unwrap();
        assert!(
            session
                .messages
                .last()
                .unwrap()
                .content
                .as_ref()
                .unwrap()
                .contains("unknown_operations")
        );
        assert!(session.task_state.last_operation().is_none());
    }

    #[test]
    fn background_reconciliation_distinguishes_owned_work_from_abandoned_intents() {
        let (_temp, store, mut session, artifacts, mut journal) = setup();
        let owned = background(&mut journal, &artifacts, &mut session, &store);
        let abandoned = background(&mut journal, &artifacts, &mut session, &store);
        reconcile_background(&journal, &artifacts, &mut session, &[&owned, &abandoned]).unwrap();
        assert!(session.messages.is_empty());
        reconcile_background(&journal, &artifacts, &mut session, &[&owned]).unwrap();
        let warning: Value =
            serde_json::from_str(session.messages.last().unwrap().content.as_ref().unwrap())
                .unwrap();
        assert_eq!(warning["unknown_operations"], 1);
        assert_eq!(
            warning["recent"][0]["operation_id"],
            abandoned.operation_id()
        );
        let before = serde_json::to_value(&session).unwrap();
        assert!(
            reconcile_background(&journal, &artifacts, &mut session, &[&owned, &owned]).is_err()
        );
        assert_eq!(serde_json::to_value(&session).unwrap(), before);
        drop(journal);
        let journal =
            OperationJournal::open(&session.dir(&store), &session.id, &artifacts).unwrap();
        assert!(reconcile_background(&journal, &artifacts, &mut session, &[&owned]).is_err());
        assert_eq!(serde_json::to_value(&session).unwrap(), before);
        reconcile_background(&journal, &artifacts, &mut session, &[]).unwrap();
        let warning: Value =
            serde_json::from_str(session.messages.last().unwrap().content.as_ref().unwrap())
                .unwrap();
        assert_eq!(warning["unknown_operations"], 2);
    }

    #[test]
    fn background_save_failure_preserves_memory_and_blocks_later_commits() {
        let (_temp, store, mut session, artifacts, mut journal) = setup();
        let first = background(&mut journal, &artifacts, &mut session, &store);
        let second = background(&mut journal, &artifacts, &mut session, &store);
        let before = serde_json::to_value(&session).unwrap();
        let path = session.dir(&store).join("session.json");
        std::fs::write(&path, "foreign edit").unwrap();
        assert!(
            finish_background(
                &first,
                &mut journal,
                &artifacts,
                &mut session,
                &store,
                ToolOutcome::success("NOT COMMITTED"),
                &[]
            )
            .is_err()
        );
        assert_eq!(serde_json::to_value(&session).unwrap(), before);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "foreign edit");
        assert!(
            finish_background(
                &second,
                &mut journal,
                &artifacts,
                &mut session,
                &store,
                ToolOutcome::success("LATER"),
                &[]
            )
            .is_err()
        );
        assert!(journal.check_active().is_err());
        drop(journal);
        let journal =
            OperationJournal::open(&session.dir(&store), &session.id, &artifacts).unwrap();
        assert!(
            journal
                .records(&artifacts)
                .unwrap()
                .iter()
                .all(|r| r.outcome == Outcome::Unknown)
        );
    }

    #[test]
    fn background_commit_failure_publishes_nothing_and_recovery_uses_disk_commit() {
        for point in ["before_rename", "after_rename", "directory_sync"] {
            let (_temp, store, mut session, artifacts, mut journal) = setup();
            let pending = background(&mut journal, &artifacts, &mut session, &store);
            let before = serde_json::to_value(&session).unwrap();
            journal.fault = Some(point);
            assert!(
                finish_background(
                    &pending,
                    &mut journal,
                    &artifacts,
                    &mut session,
                    &store,
                    ToolOutcome::success("TERMINAL"),
                    &[]
                )
                .is_err(),
                "{point}"
            );
            assert_eq!(serde_json::to_value(&session).unwrap(), before, "{point}");
            assert!(journal.check_active().is_err());
            drop(journal);
            session = Session::load(&store, &session.id, &session.root).unwrap();
            let journal =
                OperationJournal::open(&session.dir(&store), &session.id, &artifacts).unwrap();
            reconcile(&journal, &artifacts, &mut session).unwrap();
            assert_eq!(session.task_state.revision(), 1);
            assert_eq!(
                session.task_state.last_operation().is_some(),
                point != "before_rename"
            );
            assert_eq!(
                journal.records(&artifacts).unwrap()[0].outcome,
                if point == "before_rename" {
                    Outcome::Unknown
                } else {
                    Outcome::Succeeded
                }
            );
        }
    }

    #[test]
    fn background_rejects_old_turn_missing_arguments_and_uncommitted_previous() {
        for fault in ["turn", "arguments", "previous"] {
            let (_temp, store, mut session, artifacts, mut journal) = setup();
            let pending = background(&mut journal, &artifacts, &mut session, &store);
            match fault {
                "turn" => session.turn_index = 0,
                "arguments" => std::fs::remove_file(
                    session
                        .dir(&store)
                        .join("artifacts")
                        .join(&pending.arguments.id),
                )
                .unwrap(),
                "previous" => {
                    let other = background(&mut journal, &artifacts, &mut session, &store);
                    let prepared = journal
                        .prepare_finish(
                            other.operation_id(),
                            Outcome::Succeeded,
                            &Value::Null,
                            1,
                            &artifacts,
                            &[],
                        )
                        .unwrap();
                    session.task_state.host_operation_saved(&prepared).unwrap();
                    session.save(&store).unwrap();
                }
                _ => unreachable!(),
            }
            let count = std::fs::read_dir(session.dir(&store).join("artifacts"))
                .unwrap()
                .count();
            let before = serde_json::to_value(&session).unwrap();
            assert!(
                finish_background(
                    &pending,
                    &mut journal,
                    &artifacts,
                    &mut session,
                    &store,
                    ToolOutcome::success("MUST NOT WRITE"),
                    &[]
                )
                .is_err(),
                "{fault}"
            );
            assert_eq!(
                std::fs::read_dir(session.dir(&store).join("artifacts"))
                    .unwrap()
                    .count(),
                count
            );
            assert_eq!(serde_json::to_value(&session).unwrap(), before);
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[tokio::test]
    async fn background_live_process_finishes_after_another_tool_and_turn() {
        use crate::jobs::{JobKind, JobOrigin, JobSpec, JobStatus, JobsSupervisor};
        use std::time::Duration;
        use tokio_util::sync::CancellationToken;
        let (_temp, store, mut session, artifacts, mut journal) = setup();
        let pending = background(&mut journal, &artifacts, &mut session, &store);
        let supervisor = JobsSupervisor::new_for_session(&session.id, vec![]).unwrap();
        supervisor
            .attach_cleanup_guard(journal.cleanup_guard())
            .unwrap();
        let spec = JobSpec {
            kind: JobKind::Managed,
            argv: vec![
                "/bin/sh".into(),
                "-c".into(),
                "printf READY; while [ ! -f release ]; do sleep 0.01; done; printf DONE".into(),
            ],
            cwd: session.root.clone(),
            env: vec![],
            origin: JobOrigin {
                actor: None,
                turn: session.turn_index,
            },
            lifetime: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(60),
            stdin: false,
        };
        // The native effect is admitted only after its durable intent exists.
        assert_eq!(
            journal.records(&artifacts).unwrap()[0].outcome,
            Outcome::Unknown
        );
        let started = supervisor
            .start(spec, CancellationToken::new())
            .await
            .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let view = supervisor.poll(None, &started.id, 0, 0, 1024).await?;
                if view.stdout == "READY" {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let call = call(&mut session, &store);
            let write = begin(
                &mut journal,
                &artifacts,
                &mut session,
                &store,
                &call,
                None,
                &json!({"path":"proof","content":"saved while process is running"}),
                &[],
            )?;
            std::fs::write(session.root.join("proof"), "saved while process is running")?;
            finish(
                write,
                &mut journal,
                &artifacts,
                &mut session,
                &store,
                &call,
                ToolOutcome::success("written"),
                &[],
            )?;
            let previous = session.task_state.last_operation().unwrap().clone();
            session.turn_index += 1;
            session.save(&store)?;
            std::fs::write(session.root.join("release"), "")?;
            let done = loop {
                let view = supervisor.poll(None, &started.id, 0, 0, 1024).await?;
                if view.status != JobStatus::Running {
                    break view;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            };
            ensure!(
                done.status == JobStatus::Exited
                    && done.exit_code == Some(0)
                    && done.cleanup_complete,
                "native process did not finish with confirmed cleanup"
            );
            let receipt = supervisor
                .publish_snapshot(&done, |snapshot| {
                    finish_background(
                        &pending,
                        &mut journal,
                        &artifacts,
                        &mut session,
                        &store,
                        ToolOutcome::success(serde_json::to_string(snapshot)?),
                        &[],
                    )
                })
                .await?;
            let saved: Value = serde_json::from_str(&artifacts.verify_output(&receipt.output)?)?;
            ensure!(
                saved["stdout"] == "READYDONE" && saved["id"] == started.id,
                "output does not belong to the native process"
            );
            let terminal = journal
                .terminal_payload(pending.operation_id(), &artifacts)?
                .unwrap();
            ensure!(
                terminal["previous"]["operation_id"] == previous.operation_id,
                "background receipt lost the intervening tool"
            );
            Ok::<_, anyhow::Error>(receipt)
        })
        .await;
        supervisor.shutdown().await.unwrap();
        let receipt = result.unwrap().unwrap();
        drop(journal);
        session = Session::load(&store, &session.id, &session.root).unwrap();
        let journal =
            OperationJournal::open(&session.dir(&store), &session.id, &artifacts).unwrap();
        reconcile(&journal, &artifacts, &mut session).unwrap();
        assert_eq!(
            session.task_state.last_operation().unwrap().operation_id,
            receipt.operation_id
        );
        assert_eq!(
            std::fs::read_to_string(session.root.join("proof")).unwrap(),
            "saved while process is running"
        );
    }

    #[test]
    fn committed_receipts_with_repeated_provider_ids_recover_by_host_identity() {
        let (_temp, store, mut session, artifacts, mut journal) = setup();
        let mut ids = Vec::new();
        for text in ["first", "second"] {
            let call = call(&mut session, &store);
            let pending = begin(
                &mut journal,
                &artifacts,
                &mut session,
                &store,
                &call,
                None,
                &json!({}),
                &[],
            )
            .unwrap();
            assert_eq!(
                journal.records(&artifacts).unwrap().last().unwrap().outcome,
                Outcome::Unknown
            );
            let result = finish(
                pending,
                &mut journal,
                &artifacts,
                &mut session,
                &store,
                &call,
                ToolOutcome::success(text),
                &[],
            )
            .unwrap();
            ids.push(result.recorded_operation.unwrap());
        }
        assert_ne!(ids[0], ids[1]);
        assert_eq!(session.task_state.revision(), 2);
        let revision = session.task_state.revision();
        for message in &mut session.messages {
            if message.host_operation.is_some() {
                message.content = Some("spoofed success".into());
            }
        }
        session.save(&store).unwrap();
        drop(journal);
        let journal =
            OperationJournal::open(&session.dir(&store), &session.id, &artifacts).unwrap();
        reconcile(&journal, &artifacts, &mut session).unwrap();
        let results: Vec<_> = session
            .messages
            .iter()
            .filter(|m| m.role == "tool")
            .collect();
        assert_eq!(results.len(), 2);
        assert!(results[0].content.as_ref().unwrap().contains("first"));
        assert!(results[1].content.as_ref().unwrap().contains("second"));
        assert_eq!(session.task_state.revision(), revision);
        session.repair_pending().unwrap();
    }

    #[test]
    fn saved_success_before_commit_becomes_unknown_without_replay_or_revision_rollback() {
        let (_temp, store, mut session, artifacts, mut journal) = setup();
        let call = call(&mut session, &store);
        let pending = begin(
            &mut journal,
            &artifacts,
            &mut session,
            &store,
            &call,
            None,
            &json!({}),
            &[],
        )
        .unwrap();
        let marker = session.root.join("proof");
        std::fs::write(&marker, "one effect").unwrap();
        let prepared = journal
            .prepare_finish(
                &pending.id,
                Outcome::Succeeded,
                &Value::Null,
                pending.revision,
                &artifacts,
                &[],
            )
            .unwrap();
        session.task_state.host_operation_saved(&prepared).unwrap();
        session.messages.last_mut().unwrap().content = Some("SUCCESS BEFORE COMMIT".into());
        session.save(&store).unwrap();
        let revision = session.task_state.revision();
        drop(journal);
        let journal =
            OperationJournal::open(&session.dir(&store), &session.id, &artifacts).unwrap();
        session = Session::load(&store, &session.id, &session.root).unwrap();
        reconcile(&journal, &artifacts, &mut session).unwrap();
        assert_eq!(session.task_state.revision(), revision);
        assert!(session.task_state.last_operation().is_none());
        assert!(
            !serde_json::to_string(&session.messages)
                .unwrap()
                .contains("SUCCESS BEFORE COMMIT")
        );
        assert!(
            session
                .messages
                .iter()
                .any(|m| m.content.as_deref().is_some_and(|c| c.contains("unknown")))
        );
        let first = serde_json::to_value(&session).unwrap();
        reconcile(&journal, &artifacts, &mut session).unwrap();
        assert_eq!(serde_json::to_value(&session).unwrap(), first);
        assert_eq!(std::fs::read_to_string(marker).unwrap(), "one effect");
    }

    #[test]
    fn committed_worker_results_remain_discoverable_after_restart_without_delivery() {
        let (_temp, store, mut session, artifacts, mut journal) = setup();
        let call = ToolCall::new("run_command", json!({"command":"true"}));
        let mut receipts = Vec::new();
        for text in ["FIRST_RESULT", "SECOND_RESULT"] {
            let pending = begin(
                &mut journal,
                &artifacts,
                &mut session,
                &store,
                &call,
                Some("worker"),
                &json!({}),
                &[],
            )
            .unwrap();
            finish(
                pending,
                &mut journal,
                &artifacts,
                &mut session,
                &store,
                &call,
                ToolOutcome::success(text),
                &[],
            )
            .unwrap();
            receipts.push(session.task_state.last_operation().unwrap().clone());
        }
        assert!(session.messages.is_empty());
        drop(journal);
        session = Session::load(&store, &session.id, &session.root).unwrap();
        let journal =
            OperationJournal::open(&session.dir(&store), &session.id, &artifacts).unwrap();
        reconcile(&journal, &artifacts, &mut session).unwrap();
        assert!(
            session
                .task_state
                .projection()
                .unwrap()
                .contains(&receipts[1].terminal.artifact_id)
        );
        let payload = journal
            .terminal_payload(&receipts[1].operation_id, &artifacts)
            .unwrap()
            .unwrap();
        assert_eq!(
            payload["previous"]["terminal"]["artifact_id"],
            receipts[0].terminal.artifact_id
        );
        assert_eq!(payload["previous"]["revision"], receipts[0].revision);
        let page = crate::artifact_tool::execute(
            &artifacts,
            &json!({"artifact_id": receipts[1].terminal.artifact_id}),
            None,
            None,
        );
        assert!(!page.is_error);
        assert!(page.content.contains(&receipts[0].terminal.artifact_id));
    }

    #[test]
    fn provisional_operation_does_not_hide_the_previous_committed_worker_result() {
        let (_temp, store, mut session, artifacts, mut journal) = setup();
        let call = ToolCall::new("run_command", json!({"command":"true"}));
        let first = begin(
            &mut journal,
            &artifacts,
            &mut session,
            &store,
            &call,
            Some("worker"),
            &json!({}),
            &[],
        )
        .unwrap();
        finish(
            first,
            &mut journal,
            &artifacts,
            &mut session,
            &store,
            &call,
            ToolOutcome::success("confirmed"),
            &[],
        )
        .unwrap();
        let confirmed = session.task_state.last_operation().unwrap().clone();
        let second = begin(
            &mut journal,
            &artifacts,
            &mut session,
            &store,
            &call,
            Some("worker"),
            &json!({}),
            &[],
        )
        .unwrap();
        let prepared = journal
            .prepare_finish(
                &second.id,
                Outcome::Succeeded,
                &Value::Null,
                second.revision,
                &artifacts,
                &[],
            )
            .unwrap();
        session.task_state.host_operation_saved(&prepared).unwrap();
        session.save(&store).unwrap();
        drop(journal);
        let journal =
            OperationJournal::open(&session.dir(&store), &session.id, &artifacts).unwrap();
        reconcile(&journal, &artifacts, &mut session).unwrap();
        assert_eq!(session.task_state.last_operation(), Some(&confirmed));
        assert_eq!(session.task_state.revision(), 2);
        assert!(
            session
                .task_state
                .projection()
                .unwrap()
                .contains(&confirmed.terminal.artifact_id)
        );
        assert!(
            session
                .messages
                .last()
                .unwrap()
                .content
                .as_ref()
                .unwrap()
                .contains(&second.id)
        );
    }

    #[test]
    fn legacy_worker_receipts_get_a_stable_readable_catalog_without_rewriting_terminals() {
        let (_temp, store, mut session, artifacts, mut journal) = setup();
        let call = ToolCall::new("run_command", json!({"command":"true"}));
        let mut terminals = Vec::new();
        for text in ["legacy-first", "legacy-second"] {
            let pending = begin(
                &mut journal,
                &artifacts,
                &mut session,
                &store,
                &call,
                Some("worker"),
                &json!({}),
                &[],
            )
            .unwrap();
            let output = artifacts
                .capture(pending.origin.clone(), text, &[])
                .unwrap();
            let prepared = journal
                .prepare_finish(
                    &pending.id,
                    Outcome::Succeeded,
                    &json!({"version":1,"is_error":false,"output":output}),
                    pending.revision,
                    &artifacts,
                    &[],
                )
                .unwrap();
            session.task_state.host_operation_saved(&prepared).unwrap();
            session.save(&store).unwrap();
            terminals.push(journal.commit_finish(&prepared, &artifacts).unwrap());
        }
        let originals: Vec<_> = terminals
            .iter()
            .map(|m| artifacts.verify_required(m).unwrap())
            .collect();
        drop(journal);
        let journal =
            OperationJournal::open(&session.dir(&store), &session.id, &artifacts).unwrap();
        reconcile(&journal, &artifacts, &mut session).unwrap();
        let state = serde_json::to_value(&session.task_state).unwrap();
        let catalog_id = state["operation_catalog"]["artifact_id"]
            .as_str()
            .expect("legacy catalog");
        assert!(
            session
                .task_state
                .projection()
                .unwrap()
                .contains(catalog_id)
        );
        let page = crate::artifact_tool::execute(
            &artifacts,
            &json!({"artifact_id":catalog_id}),
            None,
            None,
        );
        assert!(!page.is_error);
        assert!(page.content.contains(&terminals[0].id));
        let mut assembled = String::new();
        let mut offset = 0;
        loop {
            let result = crate::artifact_tool::execute(
                &artifacts,
                &json!({"artifact_id":catalog_id,"offset":offset,"max_bytes":64}),
                None,
                None,
            );
            assert!(!result.is_error);
            let page: Value = serde_json::from_str(&result.content).unwrap();
            assembled.push_str(page["content"].as_str().unwrap());
            match page["next_offset"].as_u64() {
                Some(next) => {
                    assert!(next > offset);
                    offset = next;
                }
                None => break,
            }
        }
        let catalog: Value = serde_json::from_str(&assembled).unwrap();
        assert_eq!(
            catalog["additional_heads"][0]["terminal"]["artifact_id"],
            terminals[0].id
        );
        let count = std::fs::read_dir(session.dir(&store).join("artifacts"))
            .unwrap()
            .count();
        session.save(&store).unwrap();
        session = Session::load(&store, &session.id, &session.root).unwrap();
        reconcile(&journal, &artifacts, &mut session).unwrap();
        assert_eq!(
            std::fs::read_dir(session.dir(&store).join("artifacts"))
                .unwrap()
                .count(),
            count
        );
        assert_eq!(
            terminals
                .iter()
                .map(|m| artifacts.verify_required(m).unwrap())
                .collect::<Vec<_>>(),
            originals
        );
        let mut foreign = serde_json::to_value(&session.task_state).unwrap();
        foreign["operation_catalog"]["session_id"] = json!(uuid::Uuid::new_v4().to_string());
        assert!(serde_json::from_value::<crate::task_state::TaskState>(foreign).is_err());
        let before = serde_json::to_value(&session).unwrap();
        std::fs::remove_file(session.dir(&store).join("artifacts").join(catalog_id)).unwrap();
        assert!(reconcile(&journal, &artifacts, &mut session).is_err());
        assert_eq!(serde_json::to_value(&session).unwrap(), before);
    }

    #[test]
    fn large_write_arguments_remain_complete_without_expanding_terminal_envelopes() {
        let (_temp, store, mut session, artifacts, mut journal) = setup();
        let call = call(&mut session, &store);
        let args = json!({"path":"large.txt", "content":"x".repeat(400 * 1024)});
        let pending = begin(
            &mut journal,
            &artifacts,
            &mut session,
            &store,
            &call,
            None,
            &args,
            &[],
        )
        .unwrap();
        assert_eq!(
            journal.records(&artifacts).unwrap()[0].operation_id,
            pending.id
        );
        let request: SavedRequest =
            serde_json::from_value(journal.intent_payload(&pending.id, &artifacts).unwrap())
                .unwrap();
        let stored: Value =
            serde_json::from_str(&artifacts.verify_required(&request.arguments).unwrap()).unwrap();
        assert_eq!(stored, args);
        reconcile(&journal, &artifacts, &mut session).unwrap();
        std::fs::remove_file(
            session
                .dir(&store)
                .join("artifacts")
                .join(request.arguments.id),
        )
        .unwrap();
        let before = serde_json::to_value(&session).unwrap();
        assert!(reconcile(&journal, &artifacts, &mut session).is_err());
        assert_eq!(serde_json::to_value(&session).unwrap(), before);
    }

    #[test]
    fn worker_publication_updates_task_without_unmatched_root_tool_message() {
        let (_temp, store, mut session, artifacts, mut journal) = setup();
        let call = ToolCall::new("run_command", json!({"command":"true"}));
        let pending = begin(
            &mut journal,
            &artifacts,
            &mut session,
            &store,
            &call,
            Some("worker"),
            &json!({}),
            &[],
        )
        .unwrap();
        let result = finish(
            pending,
            &mut journal,
            &artifacts,
            &mut session,
            &store,
            &call,
            ToolOutcome::success("exit 0"),
            &[],
        )
        .unwrap();
        assert!(result.recorded_operation.is_some());
        assert_eq!(session.task_state.revision(), 1);
        assert!(session.messages.is_empty());
        reconcile(&journal, &artifacts, &mut session).unwrap();
        assert!(session.messages.is_empty());
        begin(
            &mut journal,
            &artifacts,
            &mut session,
            &store,
            &call,
            Some("worker"),
            &json!({}),
            &[],
        )
        .unwrap();
        reconcile(&journal, &artifacts, &mut session).unwrap();
        assert_eq!(session.messages.len(), 1);
        assert_eq!(session.messages[0].role, "user");
        assert!(
            session.messages[0]
                .content
                .as_ref()
                .unwrap()
                .contains("worker")
        );
    }

    #[test]
    fn failed_session_save_never_commits_or_overwrites_foreign_history() {
        let (_temp, store, mut session, artifacts, mut journal) = setup();
        let call = call(&mut session, &store);
        let pending = begin(
            &mut journal,
            &artifacts,
            &mut session,
            &store,
            &call,
            None,
            &json!({}),
            &[],
        )
        .unwrap();
        let path = session.dir(&store).join("session.json");
        let foreign = b"external edit to preserve";
        std::fs::write(&path, foreign).unwrap();
        assert!(
            finish(
                pending,
                &mut journal,
                &artifacts,
                &mut session,
                &store,
                &call,
                ToolOutcome::success("done"),
                &[]
            )
            .is_err()
        );
        assert_eq!(std::fs::read(path).unwrap(), foreign);
        assert_eq!(
            journal.records(&artifacts).unwrap()[0].outcome,
            Outcome::Unknown
        );
        assert!(session.task_state.last_operation().is_none());
    }

    #[test]
    fn full_session_is_rejected_before_intent_and_revision_overflow_is_atomic() {
        let (_temp, store, mut session, artifacts, mut journal) = setup();
        let call = call(&mut session, &store);
        session
            .messages
            .insert(0, Message::user("x".repeat(8 * 1024 * 1024 - 32 * 1024)));
        session.save(&store).unwrap();
        let before = serde_json::to_value(&session).unwrap();
        assert!(
            begin(
                &mut journal,
                &artifacts,
                &mut session,
                &store,
                &call,
                None,
                &json!({}),
                &[]
            )
            .is_err()
        );
        assert_eq!(serde_json::to_value(&session).unwrap(), before);
        assert!(journal.records(&artifacts).unwrap().is_empty());
        let mut state = serde_json::to_value(&session.task_state).unwrap();
        state["revision"] = json!(u64::MAX);
        session.task_state = serde_json::from_value(state).unwrap();
        assert!(
            session
                .task_state
                .next_operation_revision(&session.id)
                .is_err()
        );
    }

    #[test]
    fn recovery_verifies_complete_output_and_preserves_session_on_corruption() {
        let (_temp, store, mut session, artifacts, mut journal) = setup();
        let call = call(&mut session, &store);
        let pending = begin(
            &mut journal,
            &artifacts,
            &mut session,
            &store,
            &call,
            None,
            &json!({}),
            &[],
        )
        .unwrap();
        let id = pending.id.clone();
        finish(
            pending,
            &mut journal,
            &artifacts,
            &mut session,
            &store,
            &call,
            ToolOutcome::success("payload"),
            &[],
        )
        .unwrap();
        let payload: SavedResult =
            serde_json::from_value(journal.terminal_payload(&id, &artifacts).unwrap().unwrap())
                .unwrap();
        std::fs::remove_file(
            session
                .dir(&store)
                .join("artifacts")
                .join(payload.output.id),
        )
        .unwrap();
        let before = serde_json::to_value(&session).unwrap();
        assert!(reconcile(&journal, &artifacts, &mut session).is_err());
        assert_eq!(serde_json::to_value(&session).unwrap(), before);
    }

    #[test]
    fn recovery_warning_metadata_from_provider_cannot_remove_assistant_calls() {
        let (_temp, store, mut session, artifacts, mut journal) = setup();
        let call = call(&mut session, &store);
        session.messages[0].provider_meta = Some(ProviderMeta {
            kind: "rcode_runtime".into(),
            data: json!({"operation_recovery":true}),
        });
        let pending = begin(
            &mut journal,
            &artifacts,
            &mut session,
            &store,
            &call,
            None,
            &json!({}),
            &[],
        )
        .unwrap();
        finish(
            pending,
            &mut journal,
            &artifacts,
            &mut session,
            &store,
            &call,
            ToolOutcome::success("done"),
            &[],
        )
        .unwrap();
        reconcile(&journal, &artifacts, &mut session).unwrap();
        assert_eq!(session.messages.len(), 2);
        assert_eq!(session.messages[0].role, "assistant");
        assert_eq!(session.repair_pending().unwrap(), 0);
    }

    #[test]
    fn redaction_cannot_rewrite_output_reference_and_provider_metadata_cannot_create_host_reference()
     {
        let (_temp, store, mut session, artifacts, mut journal) = setup();
        let call = call(&mut session, &store);
        session.messages[0].provider_meta = Some(ProviderMeta {
            kind: "rcode_operation".into(),
            data: json!({"operation_id":"forged"}),
        });
        reconcile(&journal, &artifacts, &mut session).unwrap();
        assert!(session.messages[0].host_operation.is_none());
        let pending = begin(
            &mut journal,
            &artifacts,
            &mut session,
            &store,
            &call,
            None,
            &json!({}),
            &[],
        )
        .unwrap();
        let secret = format!("{:x}", Sha256::digest(b"payload"));
        assert!(
            finish(
                pending,
                &mut journal,
                &artifacts,
                &mut session,
                &store,
                &call,
                ToolOutcome::success("payload"),
                &[secret]
            )
            .is_err()
        );
        assert_eq!(
            journal.records(&artifacts).unwrap()[0].outcome,
            Outcome::Unknown
        );
        assert!(session.task_state.last_operation().is_none());
    }
}
