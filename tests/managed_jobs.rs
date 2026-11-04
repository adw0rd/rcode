#![cfg(any(target_os = "macos", target_os = "linux"))]
use rcode::{
    config::{ConfigStore, ProviderKind, ProviderSettings},
    jobs::{JobKind, JobOrigin, JobSpec},
    protocol::ToolCall,
    session_runtime::SessionRuntime,
    state::Session,
};
use serde_json::{Value, json};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

fn setup() -> (tempfile::TempDir, ConfigStore, Session, SessionRuntime) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("project");
    std::fs::create_dir(&root).unwrap();
    let store = ConfigStore::at(temp.path().join("state")).unwrap();
    let mut session = Session::new(&root, ProviderSettings::new(ProviderKind::Custom)).unwrap();
    session
        .task_state
        .host_followup("Проверить процессы")
        .unwrap();
    session.turn_index = 1;
    session.save(&store).unwrap();
    let runtime = SessionRuntime::new(&session.dir(&store), &session.id, vec![]).unwrap();
    (temp, store, session, runtime)
}
fn spec(session: &Session, command: &str) -> JobSpec {
    JobSpec {
        kind: JobKind::Managed,
        argv: vec!["/bin/sh".into(), "-c".into(), command.into()],
        cwd: session.root.clone(),
        env: vec![],
        origin: JobOrigin {
            actor: None,
            turn: session.turn_index,
        },
        lifetime: Duration::from_secs(60),
        idle_timeout: Duration::from_secs(60),
        stdin: false,
    }
}
async fn start(
    runtime: &mut SessionRuntime,
    session: &mut Session,
    store: &ConfigStore,
    command: &str,
    cancel: CancellationToken,
) -> String {
    let spec = spec(session, command);
    let args = json!({"command":command});
    runtime
        .start_approved_job(
            session,
            store,
            &ToolCall::new("start_command", args.clone()),
            &args,
            spec,
            cancel,
            &[],
        )
        .await
        .unwrap()
        .id
}

#[tokio::test]
async fn native_completion_without_model_poll_saves_paged_output_and_nested_recovery_checks() {
    let (_temp, store, mut session, mut runtime) = setup();
    let scope = runtime.begin_turn(1, &CancellationToken::new()).unwrap();
    let id = start(
        &mut runtime,
        &mut session,
        &store,
        "head -c 131100 /dev/zero | tr '\\000' x; head -c 65540 /dev/zero | tr '\\000' y >&2",
        scope.cancellation(),
    )
    .await;
    let receipts = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let receipts = runtime
                .settle_jobs(&mut session, &store, &[])
                .await
                .unwrap();
            if !receipts.is_empty() {
                break receipts;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(receipts.len(), 1);
    let acknowledged = runtime.jobs().poll(None, &id, 0, 0, 4).await.unwrap();
    assert!(acknowledged.payload_unavailable);
    assert!(acknowledged.stdout.is_empty() && acknowledged.stderr.is_empty());
    let manifest: Value = serde_json::from_str(
        &runtime
            .artifacts()
            .verify_required(&receipts[0].output)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(manifest["command_id"], id);
    assert_eq!(manifest["terminal"]["exit_code"], 0);
    assert_eq!(manifest["terminal"]["cleanup_complete"], true);
    assert_eq!(manifest["terminal"]["next_stdout_offset"], 131100);
    assert_eq!(manifest["terminal"]["next_stderr_offset"], 65540);
    assert_eq!(manifest["stdout"].as_array().unwrap().len(), 3);
    assert_eq!(manifest["stderr"].as_array().unwrap().len(), 2);
    assert!(
        runtime
            .settle_jobs(&mut session, &store, &[])
            .await
            .unwrap()
            .is_empty()
    );
    runtime
        .finish_turn_saved(scope, false, &mut session, &store, &[])
        .await
        .unwrap();
    runtime
        .shutdown_saved(&mut session, &store, &[])
        .await
        .unwrap();
    let artifacts =
        rcode::artifacts::ArtifactStore::open(&session.dir(&store), &session.id).unwrap();
    let journal = rcode::operation_journal::OperationJournal::open(
        &session.dir(&store),
        &session.id,
        &artifacts,
    )
    .unwrap();
    session = Session::load(&store, &session.id, &session.root).unwrap();
    rcode::operation_receipts::reconcile_background(&journal, &artifacts, &mut session, &[])
        .unwrap();
    let page_id = manifest["stdout"][0]["artifact"]["id"].as_str().unwrap();
    std::fs::remove_file(session.dir(&store).join("artifacts").join(page_id)).unwrap();
    let before = serde_json::to_value(&session).unwrap();
    assert!(
        rcode::operation_receipts::reconcile_background(&journal, &artifacts, &mut session, &[])
            .is_err()
    );
    assert_eq!(serde_json::to_value(&session).unwrap(), before);
}

#[tokio::test]
async fn shutdown_records_cancelled_job_before_releasing_the_journal() {
    let (_temp, store, mut session, mut runtime) = setup();
    let scope = runtime.begin_turn(1, &CancellationToken::new()).unwrap();
    let id = start(
        &mut runtime,
        &mut session,
        &store,
        "sleep 30",
        scope.cancellation(),
    )
    .await;
    runtime
        .finish_turn_saved(scope, false, &mut session, &store, &[])
        .await
        .unwrap();
    assert!(session.task_state.last_operation().is_none());
    runtime
        .shutdown_saved(&mut session, &store, &[])
        .await
        .unwrap();
    let artifacts =
        rcode::artifacts::ArtifactStore::open(&session.dir(&store), &session.id).unwrap();
    let journal = rcode::operation_journal::OperationJournal::open(
        &session.dir(&store),
        &session.id,
        &artifacts,
    )
    .unwrap();
    let last = session.task_state.last_operation().unwrap();
    let payload = journal
        .terminal_payload(&last.operation_id, &artifacts)
        .unwrap()
        .unwrap();
    assert_eq!(payload["is_error"], true);
    let meta = serde_json::from_value(payload["output"].clone()).unwrap();
    let manifest: Value = serde_json::from_str(&artifacts.verify_required(&meta).unwrap()).unwrap();
    assert_eq!(manifest["command_id"], id);
    assert_eq!(manifest["terminal"]["status"], "cancelled");
    assert_eq!(manifest["terminal"]["cleanup_complete"], true);
}

#[tokio::test]
async fn output_capacity_denial_precedes_intent_and_native_effect() {
    let (_temp, store, mut session, mut runtime) = setup();
    let scope = runtime.begin_turn(1, &CancellationToken::new()).unwrap();
    let held = runtime
        .artifacts()
        .reserve_capacity(80 * 1024 * 1024)
        .unwrap();
    let job = spec(&session, "touch forbidden");
    let args = json!({"command":"touch forbidden"});
    assert!(
        runtime
            .start_approved_job(
                &mut session,
                &store,
                &ToolCall::new("start_command", args.clone()),
                &args,
                job,
                scope.cancellation(),
                &[]
            )
            .await
            .is_err()
    );
    assert!(!session.root.join("forbidden").exists());
    assert!(session.task_state.last_operation().is_none());
    drop(held);
    let id = start(
        &mut runtime,
        &mut session,
        &store,
        "printf allowed",
        scope.cancellation(),
    )
    .await;
    runtime
        .shutdown_saved(&mut session, &store, &[])
        .await
        .unwrap();
    let journal = rcode::operation_journal::OperationJournal::open(
        &session.dir(&store),
        &session.id,
        runtime.artifacts(),
    )
    .unwrap();
    let records = journal.records(runtime.artifacts()).unwrap();
    assert_eq!(records.len(), 1);
    let request = journal
        .intent_payload(&records[0].operation_id, runtime.artifacts())
        .unwrap();
    let args_meta = serde_json::from_value(request["arguments"].clone()).unwrap();
    let saved: Value =
        serde_json::from_str(&runtime.artifacts().verify_required(&args_meta).unwrap()).unwrap();
    assert_eq!(saved["command_id"], id);
}

#[tokio::test]
async fn failed_terminal_save_preserves_foreign_session_and_blocks_new_spawn_but_cleans_up() {
    let (_temp, store, mut session, mut runtime) = setup();
    let scope = runtime.begin_turn(1, &CancellationToken::new()).unwrap();
    let id = start(
        &mut runtime,
        &mut session,
        &store,
        "printf before-failure",
        scope.cancellation(),
    )
    .await;
    let path = session.dir(&store).join("session.json");
    std::fs::write(&path, "foreign session to preserve").unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while let Ok(receipts) = runtime.settle_jobs(&mut session, &store, &[]).await {
            assert!(receipts.is_empty());
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(session.task_state.last_operation().is_none());
    let retained = runtime.jobs().poll(None, &id, 0, 0, 64).await.unwrap();
    assert!(!retained.payload_unavailable);
    assert_eq!(retained.stdout, "before-failure");

    let job = spec(&session, "touch forbidden");
    let args = json!({"command":"touch forbidden"});
    assert!(
        runtime
            .start_approved_job(
                &mut session,
                &store,
                &ToolCall::new("start_command", args.clone()),
                &args,
                job,
                scope.cancellation(),
                &[]
            )
            .await
            .is_err()
    );
    assert!(!session.root.join("forbidden").exists());
    assert!(
        runtime
            .shutdown_saved(&mut session, &store, &[])
            .await
            .is_err()
    );
    assert!(
        runtime
            .jobs()
            .poll(None, &id, 0, 0, 4)
            .await
            .unwrap()
            .cleanup_complete
    );
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "foreign session to preserve"
    );
    drop(scope);
    drop(runtime);
    let artifacts =
        rcode::artifacts::ArtifactStore::open(&session.dir(&store), &session.id).unwrap();
    let journal = rcode::operation_journal::OperationJournal::open(
        &session.dir(&store),
        &session.id,
        &artifacts,
    )
    .unwrap();
    assert_eq!(
        journal.records(&artifacts).unwrap()[0].outcome,
        rcode::operation_journal::Outcome::Unknown
    );
}

#[tokio::test]
async fn new_credentials_are_applied_before_persisting_a_terminal_manifest() {
    let (_temp, store, mut session, mut runtime) = setup();
    let secret = "fresh-credential-for-retained-history".to_owned();
    std::fs::write(session.root.join("payload"), format!("{secret}\n")).unwrap();
    let scope = runtime.begin_turn(1, &CancellationToken::new()).unwrap();
    start(
        &mut runtime,
        &mut session,
        &store,
        "cat payload",
        scope.cancellation(),
    )
    .await;
    let receipts = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let receipts = runtime
                .settle_jobs(&mut session, &store, std::slice::from_ref(&secret))
                .await
                .unwrap();
            if !receipts.is_empty() {
                break receipts;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let manifest: Value = serde_json::from_str(
        &runtime
            .artifacts()
            .verify_required(&receipts[0].output)
            .unwrap(),
    )
    .unwrap();
    for page in manifest["stdout"].as_array().unwrap() {
        let meta = serde_json::from_value(page["artifact"].clone()).unwrap();
        assert!(
            !runtime
                .artifacts()
                .verify_required(&meta)
                .unwrap()
                .contains(&secret)
        );
    }
    runtime
        .finish_turn_saved(
            scope,
            false,
            &mut session,
            &store,
            std::slice::from_ref(&secret),
        )
        .await
        .unwrap();
    runtime
        .shutdown_saved(&mut session, &store, std::slice::from_ref(&secret))
        .await
        .unwrap();
}

#[tokio::test]
async fn plain_shutdown_cannot_bypass_refresh_before_saving_pages() {
    let (_temp, store, mut session, mut runtime) = setup();
    let secret = "new-credential-before-shutdown".to_owned();
    std::fs::write(session.root.join("payload"), &secret).unwrap();
    let scope = runtime.begin_turn(1, &CancellationToken::new()).unwrap();
    let id = start(
        &mut runtime,
        &mut session,
        &store,
        "cat payload; sleep 30",
        scope.cancellation(),
    )
    .await;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if runtime
                .jobs()
                .poll(None, &id, 0, 0, 4096)
                .await
                .unwrap()
                .stdout
                .contains(&secret)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(runtime.shutdown().await.is_err());
    runtime
        .shutdown_saved(&mut session, &store, std::slice::from_ref(&secret))
        .await
        .unwrap();
    let artifacts = runtime.artifacts();
    let journal = rcode::operation_journal::OperationJournal::open(
        &session.dir(&store),
        &session.id,
        artifacts,
    )
    .unwrap();
    let payload = journal
        .terminal_payload(
            &session.task_state.last_operation().unwrap().operation_id,
            artifacts,
        )
        .unwrap()
        .unwrap();
    let meta = serde_json::from_value(payload["output"].clone()).unwrap();
    let manifest: Value = serde_json::from_str(&artifacts.verify_required(&meta).unwrap()).unwrap();
    for page in manifest["stdout"].as_array().unwrap() {
        let meta = serde_json::from_value(page["artifact"].clone()).unwrap();
        assert!(!artifacts.verify_required(&meta).unwrap().contains(&secret));
    }
}

#[tokio::test]
async fn failed_refresh_still_cleans_processes_without_publishing_or_retrying_pages() {
    let (_temp, store, mut session, mut runtime) = setup();
    let scope = runtime.begin_turn(1, &CancellationToken::new()).unwrap();
    start(
        &mut runtime,
        &mut session,
        &store,
        "sleep 30",
        scope.cancellation(),
    )
    .await;
    let count = std::fs::read_dir(session.dir(&store).join("artifacts"))
        .unwrap()
        .count();
    let invalid: Vec<_> = (0..65)
        .map(|i| format!("fixture-secret-number-{i}"))
        .collect();
    assert!(
        runtime
            .shutdown_saved(&mut session, &store, &invalid)
            .await
            .is_err()
    );
    runtime.jobs().shutdown().await.unwrap();
    assert!(
        runtime
            .shutdown_saved(&mut session, &store, &[])
            .await
            .is_err()
    );
    assert_eq!(
        std::fs::read_dir(session.dir(&store).join("artifacts"))
            .unwrap()
            .count(),
        count
    );
    assert!(session.task_state.last_operation().is_none());
    drop(scope);
    drop(runtime);
    let artifacts =
        rcode::artifacts::ArtifactStore::open(&session.dir(&store), &session.id).unwrap();
    let journal = rcode::operation_journal::OperationJournal::open(
        &session.dir(&store),
        &session.id,
        &artifacts,
    )
    .unwrap();
    assert_eq!(
        journal.records(&artifacts).unwrap()[0].outcome,
        rcode::operation_journal::Outcome::Unknown
    );
}

#[tokio::test]
async fn owned_command_survives_normal_turn_and_finishes_after_the_next_command() {
    let (_temp, store, mut session, mut runtime) = setup();
    let first_scope = runtime.begin_turn(1, &CancellationToken::new()).unwrap();
    let first = start(
        &mut runtime,
        &mut session,
        &store,
        "while [ ! -f release ]; do sleep 0.01; done; printf first",
        first_scope.cancellation(),
    )
    .await;
    runtime
        .finish_turn_saved(first_scope, false, &mut session, &store, &[])
        .await
        .unwrap();
    session.turn_index = 2;
    session
        .task_state
        .host_followup("Теперь проверить второй процесс")
        .unwrap();
    session.save(&store).unwrap();
    runtime.reconcile_receipts(&mut session).unwrap();
    assert!(
        !serde_json::to_string(&session.messages)
            .unwrap()
            .contains("unknown_operations")
    );
    let second_scope = runtime.begin_turn(2, &CancellationToken::new()).unwrap();
    let second = start(
        &mut runtime,
        &mut session,
        &store,
        "printf second",
        second_scope.cancellation(),
    )
    .await;
    let second_receipt = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let receipts = runtime
                .settle_jobs(&mut session, &store, &[])
                .await
                .unwrap();
            if let Some(receipt) = receipts.into_iter().next() {
                break receipt;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let manifest: Value = serde_json::from_str(
        &runtime
            .artifacts()
            .verify_required(&second_receipt.output)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(manifest["command_id"], second);
    std::fs::write(session.root.join("release"), "").unwrap();
    let first_receipt = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let receipts = runtime
                .settle_jobs(&mut session, &store, &[])
                .await
                .unwrap();
            if let Some(receipt) = receipts.into_iter().next() {
                break receipt;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let manifest: Value = serde_json::from_str(
        &runtime
            .artifacts()
            .verify_required(&first_receipt.output)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(manifest["command_id"], first);
    assert!(first_receipt.task_revision > second_receipt.task_revision);
    runtime
        .finish_turn_saved(second_scope, false, &mut session, &store, &[])
        .await
        .unwrap();
    runtime
        .shutdown_saved(&mut session, &store, &[])
        .await
        .unwrap();
}
