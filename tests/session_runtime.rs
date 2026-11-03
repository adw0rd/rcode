#![cfg(any(target_os = "macos", target_os = "linux"))]
use rcode::jobs::{JobKind, JobOrigin, JobSpec, JobStatus};
use rcode::session_runtime::SessionRuntime;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

fn runtime(dir: &std::path::Path) -> SessionRuntime {
    SessionRuntime::new(dir, &uuid::Uuid::new_v4().to_string(), vec![]).unwrap()
}
fn spec(root: &std::path::Path, turn: u64, actor: Option<&str>) -> JobSpec {
    JobSpec {
        kind: JobKind::Managed,
        argv: vec!["/bin/sh".into(), "-c".into(), "sleep 30".into()],
        cwd: root.into(),
        env: vec![],
        origin: JobOrigin {
            actor: actor.map(str::to_owned),
            turn,
        },
        lifetime: Duration::from_secs(60),
        idle_timeout: Duration::from_secs(60),
        stdin: false,
    }
}

#[tokio::test]
async fn replacement_prepares_without_stealing_the_active_session_lease() {
    let d = tempfile::tempdir().unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let mut old = SessionRuntime::new(d.path(), &id, vec![]).unwrap();
    let turn = old.begin_turn(1, &CancellationToken::new()).unwrap();
    let mut replacement = SessionRuntime::new(d.path(), &id, vec![]).unwrap();
    assert!(
        replacement
            .begin_turn(1, &CancellationToken::new())
            .is_err()
    );
    old.finish_turn(turn, false).await.unwrap();
    // An idle interactive runtime still owns its persisted session.
    assert!(
        replacement
            .begin_turn(1, &CancellationToken::new())
            .is_err()
    );
    old.shutdown().await.unwrap();
    let turn = replacement
        .begin_turn(1, &CancellationToken::new())
        .unwrap();
    replacement.finish_turn(turn, false).await.unwrap();
    replacement.shutdown().await.unwrap();
}

#[tokio::test]
async fn failed_journal_activation_does_not_consume_a_turn() {
    let d = tempfile::tempdir().unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let a = rcode::artifacts::ArtifactStore::open(d.path(), &id).unwrap();
    drop(rcode::operation_journal::OperationJournal::open(d.path(), &id, &a).unwrap());
    let path = d.path().join("operations/index.json");
    let original = std::fs::read(&path).unwrap();
    let mut bad: serde_json::Value = serde_json::from_slice(&original).unwrap();
    bad["version"] = 2.into();
    std::fs::write(&path, serde_json::to_vec(&bad).unwrap()).unwrap();
    let mut execution = SessionRuntime::new(d.path(), &id, vec![]).unwrap();
    assert!(execution.begin_turn(1, &CancellationToken::new()).is_err());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&std::fs::read(&path).unwrap()).unwrap()["version"],
        2
    );
    std::fs::write(&path, original).unwrap();
    let turn = execution.begin_turn(1, &CancellationToken::new()).unwrap();
    execution.finish_turn(turn, false).await.unwrap();
    execution.shutdown().await.unwrap();
}

#[tokio::test]
async fn abandoned_runtime_keeps_the_session_lease_through_native_cleanup() {
    let d = tempfile::tempdir().unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let mut old = SessionRuntime::new(d.path(), &id, vec![]).unwrap();
    let turn = old.begin_turn(1, &CancellationToken::new()).unwrap();
    old.jobs()
        .start(spec(d.path(), 1, None), turn.cancellation())
        .await
        .unwrap();
    old.finish_turn(turn, false).await.unwrap();
    let mut replacement = SessionRuntime::new(d.path(), &id, vec![]).unwrap();
    drop(old);
    // current_thread: cleanup futures have not yet been polled after emergency Drop.
    assert!(
        replacement
            .begin_turn(1, &CancellationToken::new())
            .is_err()
    );
    let next = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Ok(scope) = replacement.begin_turn(1, &CancellationToken::new()) {
                break scope;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    replacement.finish_turn(next, false).await.unwrap();
    replacement.shutdown().await.unwrap();
}

#[tokio::test]
async fn direct_start_before_runtime_activation_is_denied_before_spawn() {
    let d = tempfile::tempdir().unwrap();
    let mut execution = runtime(d.path());
    let mut command = spec(d.path(), 1, None);
    command.argv[2] = "touch forbidden-sentinel".into();
    assert!(
        execution
            .jobs()
            .start(command, CancellationToken::new())
            .await
            .is_err()
    );
    assert!(!d.path().join("forbidden-sentinel").exists());
    let turn = execution.begin_turn(1, &CancellationToken::new()).unwrap();
    execution.finish_turn(turn, false).await.unwrap();
    execution.shutdown().await.unwrap();
}

#[tokio::test]
async fn cancelled_shutdown_retains_lease_until_verified_retry_even_with_live_scope() {
    let d = tempfile::tempdir().unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let mut old = SessionRuntime::new(d.path(), &id, vec![]).unwrap();
    let scope = old.begin_turn(1, &CancellationToken::new()).unwrap();
    old.jobs()
        .start(spec(d.path(), 1, None), scope.cancellation())
        .await
        .unwrap();
    {
        let shutdown = old.shutdown();
        tokio::pin!(shutdown);
        assert!(futures_util::poll!(shutdown.as_mut()).is_pending());
    }
    let mut replacement = SessionRuntime::new(d.path(), &id, vec![]).unwrap();
    assert!(
        replacement
            .begin_turn(1, &CancellationToken::new())
            .is_err()
    );
    assert!(old.begin_turn(2, &CancellationToken::new()).is_err());
    old.shutdown().await.unwrap();
    // The old TurnControl still holds Core, but confirmed shutdown released its lease.
    let next = replacement
        .begin_turn(1, &CancellationToken::new())
        .unwrap();
    drop(scope);
    replacement.finish_turn(next, false).await.unwrap();
    replacement.shutdown().await.unwrap();
}

#[tokio::test]
async fn parent_path_alias_cannot_create_another_session_owner() {
    let d = tempfile::tempdir().unwrap();
    let real = d.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let alias = d.path().join("alias");
    std::os::unix::fs::symlink(&real, &alias).unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let mut owner = SessionRuntime::new(&real, &id, vec![]).unwrap();
    owner.activate().unwrap();
    let mut other = SessionRuntime::new(&alias, &id, vec![]).unwrap();
    assert!(other.activate().is_err());
    owner.shutdown().await.unwrap();
    other.activate().unwrap();
    other.shutdown().await.unwrap();
}

#[tokio::test]
async fn normal_turn_survives_agent_root_cancellation_but_session_shutdown_closes_job() {
    let d = tempfile::tempdir().unwrap();
    let mut runtime = runtime(d.path());
    let interrupt = CancellationToken::new();
    let scope = runtime.begin_turn(1, &interrupt).unwrap();
    let job = runtime
        .jobs()
        .start(spec(d.path(), 1, None), scope.cancellation())
        .await
        .unwrap();
    runtime.finish_turn(scope, false).await.unwrap();
    // Existing turn cleanup cancels its model/agent root after disconnecting it.
    interrupt.cancel();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        runtime
            .jobs()
            .poll(None, &job.id, 0, 0, 4)
            .await
            .unwrap()
            .status,
        JobStatus::Running
    );
    let next = runtime.begin_turn(2, &CancellationToken::new()).unwrap();
    runtime.finish_turn(next, false).await.unwrap();
    runtime.shutdown().await.unwrap();
    let end = runtime.jobs().poll(None, &job.id, 0, 0, 4).await.unwrap();
    assert!(end.cleanup_complete);
    assert_ne!(end.status, JobStatus::Running);
}

#[tokio::test]
async fn actual_interrupt_cleans_only_the_current_turn() {
    let d = tempfile::tempdir().unwrap();
    let mut runtime = runtime(d.path());
    let first = runtime.begin_turn(1, &CancellationToken::new()).unwrap();
    let old = runtime
        .jobs()
        .start(spec(d.path(), 1, None), first.cancellation())
        .await
        .unwrap();
    runtime.finish_turn(first, false).await.unwrap();
    let interrupt = CancellationToken::new();
    let current = runtime.begin_turn(2, &interrupt).unwrap();
    let job = runtime
        .jobs()
        .start(spec(d.path(), 2, None), current.cancellation())
        .await
        .unwrap();
    interrupt.cancel();
    runtime.finish_turn(current, false).await.unwrap();
    let end = runtime.jobs().poll(None, &job.id, 0, 0, 4).await.unwrap();
    assert!(end.cleanup_complete);
    assert_eq!(end.status, JobStatus::Cancelled);
    assert_eq!(
        runtime
            .jobs()
            .poll(None, &old.id, 0, 0, 4)
            .await
            .unwrap()
            .status,
        JobStatus::Running
    );
    runtime.shutdown().await.unwrap();
}

#[tokio::test]
async fn worker_completion_cleans_owned_jobs_but_preserves_explicit_handoff() {
    let d = tempfile::tempdir().unwrap();
    let mut runtime = runtime(d.path());
    let scope = runtime.begin_turn(1, &CancellationToken::new()).unwrap();
    let worker = CancellationToken::new();
    let owned = runtime
        .jobs()
        .start(spec(d.path(), 1, Some("worker")), worker.clone())
        .await
        .unwrap();
    let handed = runtime
        .jobs()
        .start(spec(d.path(), 1, Some("worker")), worker.clone())
        .await
        .unwrap();
    runtime
        .jobs()
        .handoff_to_parent(
            "worker",
            &handed.id,
            "handoff",
            0,
            "parent",
            scope.cancellation(),
        )
        .unwrap();
    runtime.finish_turn(scope, false).await.unwrap();
    worker.cancel();
    assert!(
        runtime
            .jobs()
            .poll(Some("worker"), &owned.id, 0, 0, 4)
            .await
            .unwrap()
            .cleanup_complete
    );
    assert_eq!(
        runtime
            .jobs()
            .poll(None, &handed.id, 0, 0, 4)
            .await
            .unwrap()
            .status,
        JobStatus::Running
    );
    assert!(
        runtime
            .jobs()
            .poll(Some("worker"), &handed.id, 0, 0, 4)
            .await
            .is_err()
    );
    runtime.shutdown().await.unwrap();
}

#[tokio::test]
async fn abandoned_scope_cancels_and_turn_identity_cannot_be_reused() {
    let d = tempfile::tempdir().unwrap();
    let mut runtime = runtime(d.path());
    let scope = runtime.begin_turn(4, &CancellationToken::new()).unwrap();
    assert!(runtime.begin_turn(5, &CancellationToken::new()).is_err());
    let job = runtime
        .jobs()
        .start(spec(d.path(), 4, None), scope.cancellation())
        .await
        .unwrap();
    drop(scope);
    assert!(runtime.begin_turn(4, &CancellationToken::new()).is_err());
    runtime.shutdown().await.unwrap();
    assert!(
        runtime
            .jobs()
            .poll(None, &job.id, 0, 0, 4)
            .await
            .unwrap()
            .cleanup_complete
    );
    assert!(runtime.begin_turn(5, &CancellationToken::new()).is_err());
}

#[tokio::test]
async fn closed_turn_rejects_a_late_spawn_before_execution() {
    let d = tempfile::tempdir().unwrap();
    let mut runtime = runtime(d.path());
    let scope = runtime.begin_turn(1, &CancellationToken::new()).unwrap();
    runtime.finish_turn(scope, false).await.unwrap();
    let mut late = spec(d.path(), 1, None);
    late.argv[2] = "printf ran > should-not-exist".into();
    let attempt = runtime.jobs().start(late, CancellationToken::new()).await;
    runtime.shutdown().await.unwrap();
    assert!(
        attempt.is_err(),
        "closed origin turn admitted a new process"
    );
    assert!(!d.path().join("should-not-exist").exists());
}

#[tokio::test]
async fn interrupt_during_worker_cleanup_still_cancels_main_job() {
    let d = tempfile::tempdir().unwrap();
    let mut runtime = runtime(d.path());
    let interrupt = CancellationToken::new();
    let scope = runtime.begin_turn(1, &interrupt).unwrap();
    let main = runtime
        .jobs()
        .start(spec(d.path(), 1, None), scope.cancellation())
        .await
        .unwrap();
    let mut worker_spec = spec(d.path(), 1, Some("worker"));
    worker_spec.argv[2] =
        "trap 'sleep 0.25; exit 0' TERM; printf ready > ready; while :; do sleep 0.02; done".into();
    runtime
        .jobs()
        .start(worker_spec, CancellationToken::new())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while !d.path().join("ready").exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let later = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(60)).await;
        interrupt.cancel();
    });
    runtime.finish_turn(scope, false).await.unwrap();
    later.await.unwrap();
    let end = runtime.jobs().poll(None, &main.id, 0, 0, 4).await.unwrap();
    runtime.shutdown().await.unwrap();
    assert!(
        end.cleanup_complete,
        "accepted interruption lost during worker cleanup"
    );
    assert_eq!(end.status, JobStatus::Cancelled);
}

#[tokio::test]
async fn abandoned_turn_also_cancels_worker_with_independent_token() {
    let d = tempfile::tempdir().unwrap();
    let mut runtime = runtime(d.path());
    let scope = runtime.begin_turn(1, &CancellationToken::new()).unwrap();
    let worker = runtime
        .jobs()
        .start(spec(d.path(), 1, Some("worker")), CancellationToken::new())
        .await
        .unwrap();
    drop(scope);
    let cleaned = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let job = runtime
                .jobs()
                .poll(Some("worker"), &worker.id, 0, 0, 4)
                .await
                .unwrap();
            if job.cleanup_complete {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok();
    runtime.shutdown().await.unwrap();
    assert!(
        cleaned,
        "abandoned turn leaked a worker job until session shutdown"
    );
}
