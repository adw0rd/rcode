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
