//! Публикация результата после сохранения артефакта, задачи и commit журнала.
//! Разрешения проверяет caller до begin; восстановление никогда не исполняет tools.
use crate::{
    artifacts::{ArtifactMeta, ArtifactOrigin, ArtifactStore},
    config::ConfigStore,
    context::{ContextBudget, preview_receipt},
    operation_journal::{OperationJournal, Outcome},
    protocol::{Message, ProviderMeta, ToolCall, ToolOutcome},
    state::Session,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const UNKNOWN: &str = "Исход операции неизвестен: подтверждение завершения не сохранено. Проверьте файлы и процессы перед повтором; автоматически действие не повторялось.";

pub(crate) struct PendingOperation {
    id: String,
    origin: ArtifactOrigin,
    revision: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedResult {
    version: u32,
    is_error: bool,
    output: ArtifactMeta,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous: Option<crate::task_state::TaskOperation>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedRequest {
    version: u32,
    arguments: ArtifactMeta,
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
    value["artifact_id"] = json!(meta.id);
    value["artifact_bytes"] = json!(meta.bytes);
    value["artifact_sha256"] = json!(meta.sha256);
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

/// Commit журнала важнее текста истории. Проверяем все сохранённые результаты,
/// даже если соответствующие сообщения уже свернулись при compaction.
pub(crate) fn reconcile(
    journal: &OperationJournal,
    artifacts: &ArtifactStore,
    session: &mut Session,
) -> Result<()> {
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
            preview(
                &artifacts.verify_output(&saved.output)?,
                &saved.output,
                saved.is_error,
            )
        } else {
            candidate
                .task_state
                .invalidate_operation(&record.operation_id);
            unresolved.push(record);
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
