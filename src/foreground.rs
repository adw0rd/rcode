//! Synchronous shell adapter. Production callers supply the session supervisor;
//! permissions stay in app, durable intent precedes spawn, publication follows commit.
use crate::{
    agents::AgentRequest,
    app::Events,
    artifacts::ArtifactStore,
    config::ConfigStore,
    jobs::{JobKind, JobOrigin, JobSnapshot, JobSpec, JobStatus, JobsSupervisor},
    operation_journal::OperationJournal,
    protocol::{ToolCall, ToolOutcome},
    state::Session,
    tools::Tools,
};
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::{path::Path, time::Duration};
use tokio_util::sync::CancellationToken;

const PAGE: usize = 64 * 1024;
// Includes worst-case JSON escaping of both bounded output and arguments,
// output metadata, terminal envelope, and journal frames. This is quota,
// not a guarantee against filesystem failure.
const RECEIPT_RESERVE: usize = 4 * 1024 * 1024;

pub(crate) fn prepare(root: &Path, args: &Value, origin: JobOrigin) -> Result<JobSpec> {
    crate::tools::validate_args("run_command", args)?;
    let (command, seconds) = crate::tools::command_args(args)?;
    let env = std::env::vars_os()
        .filter(|(key, _)| crate::jobs::allowed_env(&key.to_string_lossy()))
        .map(|(key, value)| {
            Ok((
                key.into_string()
                    .map_err(|_| anyhow::anyhow!("Shell environment name is not UTF-8"))?,
                value
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("Shell environment value is not UTF-8"))?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(JobSpec {
        kind: JobKind::Foreground,
        argv: vec!["/bin/sh".into(), "-c".into(), command.into()],
        cwd: root.into(),
        env,
        origin,
        lifetime: Duration::from_secs(seconds as u64),
        idle_timeout: Duration::from_secs(seconds as u64),
        stdin: false,
        sandbox: crate::sandbox::PreparedSandbox::off(),
    })
}

struct CancelOnDrop(CancellationToken);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

pub(crate) async fn wait(
    jobs: &JobsSupervisor,
    owner: Option<&str>,
    id: &str,
    worker: Option<&AgentRequest>,
    scope: &CancellationToken,
) -> Result<JobSnapshot> {
    tokio::time::timeout(Duration::from_secs(310), async {
        loop {
            if worker.is_some_and(|a| a.reply.is_closed() || a.cancel.is_cancelled()) {
                scope.cancel();
            }
            let view = jobs.poll(owner, id, 0, 0, 4).await?;
            if view.status != JobStatus::Running {
                return jobs.poll(owner, id, 0, 0, PAGE).await;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("Foreground deadline exceeded; cleanup remains unconfirmed")?
}

fn outcome(
    view: &JobSnapshot,
    delivery_cancelled: bool,
    sandbox: &crate::sandbox::SandboxReceiptMeta,
) -> ToolOutcome {
    let reason = if delivery_cancelled {
        Some("worker_unavailable")
    } else if !view.cleanup_complete {
        Some("cleanup_unknown")
    } else if view.output_truncated {
        Some("output_limit")
    } else {
        match view.status {
            JobStatus::TimedOut => Some("timeout"),
            JobStatus::Stopped | JobStatus::Cancelled => Some("cancelled"),
            JobStatus::Failed | JobStatus::Unknown => Some("execution_failed"),
            JobStatus::Exited => None,
            JobStatus::Running => Some("execution_incomplete"),
        }
    };
    let content = json!({"command_id":view.id,"exit_code":view.exit_code,"signal":view.signal,
        "stdout":if delivery_cancelled { "" } else { &view.stdout },
        "stderr":if delivery_cancelled { "" } else { &view.stderr },"reason":reason,
        "status":view.status,"delivery_cancelled":delivery_cancelled,
        "shell_changes_managed":false,"note":crate::tools::SHELL_NOTE,
        "termination":"process_group","cleanup_complete":view.cleanup_complete,
        "cleanup_warning":view.cleanup_warning,"output_truncated":view.output_truncated,
        "redaction_incomplete":view.redaction_incomplete || delivery_cancelled,"utf8_lossy":view.utf8_lossy,
        "sandbox":sandbox})
    .to_string();
    ToolOutcome {
        is_error: reason.is_some() || view.exit_code != Some(0) || view.signal.is_some(),
        content,
        changed_paths: vec![],
        recorded_operation: None,
        recorded_output: None,
    }
}

// Credential publication is held by the caller. Reply closure linearizes
// before this receipt (failed, no output) or after its durable commit. Preserve
// the real exit and cleanup even if closure races with successful process EOF.
fn complete(
    view: &JobSnapshot,
    worker: Option<&AgentRequest>,
    sandbox: &crate::sandbox::SandboxReceiptMeta,
    save: impl FnOnce(ToolOutcome) -> Result<ToolOutcome>,
) -> Result<ToolOutcome> {
    if let Some(worker) = worker {
        worker.admission.with_state(|open| {
            save(outcome(
                view,
                !open || worker.reply.is_closed() || worker.cancel.is_cancelled(),
                sandbox,
            ))
        })
    } else {
        save(outcome(view, false, sandbox))
    }
}

pub(crate) struct Durable<'a> {
    pub tools: &'a mut Tools,
    pub events: &'a Events,
    pub jobs: &'a JobsSupervisor,
    pub journal: &'a mut OperationJournal,
    pub artifacts: &'a ArtifactStore,
    pub session: &'a mut Session,
    pub store: &'a ConfigStore,
}
impl Durable<'_> {
    pub(crate) async fn run(
        &mut self,
        call: &ToolCall,
        args: &Value,
        worker: Option<&AgentRequest>,
        cancel: &CancellationToken,
        turn_cancel: &CancellationToken,
        authority: crate::sandbox::ExecutionAuthority,
    ) -> Result<ToolOutcome> {
        let owner = worker.map(|a| a.agent_id.as_str());
        let mut spec = match prepare(
            self.tools.root(),
            args,
            JobOrigin {
                actor: owner.map(str::to_owned),
                turn: self.session.turn_index,
            },
        ) {
            Ok(spec) => spec,
            Err(error) => return Ok(ToolOutcome::error(format!("{error:#}"))),
        };
        let secrets = self.events.secret_snapshot();
        self.jobs.refresh_credentials(&secrets).await?;
        // This is a preflight refusal only. start_reserved rechecks admission
        // atomically before spawn; reservation does not promise a resource slot.
        if let Err(error) = self.jobs.check_start_capacity() {
            return Ok(ToolOutcome::error(format!("{error:#}")));
        }
        if turn_cancel.is_cancelled() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "Задача отменена; shell не запускался",
            )
            .into());
        }
        if cancel.is_cancelled() {
            return Ok(ToolOutcome::error(
                "Задача отменена; действие не исполнялось",
            ));
        }
        let sandbox = match crate::sandbox::PreparedSandbox::prepare(
            authority.policy(),
            self.tools.root(),
            &self.tools.extra_directories(),
            Some(self.store.root()),
            &secrets,
        ) {
            Ok(sandbox) => sandbox,
            Err(error) => return Ok(ToolOutcome::error(format!("{error:#}"))),
        };
        sandbox.apply_to_env(&mut spec.env);
        let sandbox_meta = sandbox.receipt_meta();
        spec.sandbox = sandbox;
        if turn_cancel.is_cancelled() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "Задача отменена; shell не запускался",
            )
            .into());
        }
        if cancel.is_cancelled() {
            return Ok(ToolOutcome::error(
                "Задача отменена; действие не исполнялось",
            ));
        }
        let reservation = self.jobs.reserve_start()?;
        let id = reservation.id().to_owned();
        let budget = self.artifacts.reserve_capacity(RECEIPT_RESERVE)?;
        let artifacts = self.artifacts.reserved(&budget)?;
        self.tools.mark_shell_used()?;
        let intent = json!({"command_id":id,"arguments":args,"kind":spec.kind,
            "origin":spec.origin,"argv":spec.argv,"cwd":spec.cwd,"stdin":false,
            "lifetime_ms":spec.lifetime.as_millis(),"idle_ms":spec.idle_timeout.as_millis(),
            "sandbox":sandbox_meta});
        let pending = crate::operation_receipts::begin(
            self.journal,
            &artifacts,
            self.session,
            self.store,
            call,
            owner,
            &intent,
            &secrets,
        )?;
        let scope = cancel.child_token();
        let _guard = CancelOnDrop(scope.clone());
        // Native admission has no suspension points between spawn and ownership.
        // On Err the enriched intent remains unknown; never retry or fall back.
        let mut entered_start = false;
        let start = || {
            entered_start = true;
            if turn_cancel.is_cancelled() {
                return Err(
                    crate::jobs::PreSpawnCancelled("Задача отменена; shell не запускался").into(),
                );
            }
            if cancel.is_cancelled()
                || worker.is_some_and(|a| a.reply.is_closed() || a.cancel.is_cancelled())
            {
                return Err(crate::jobs::PreSpawnCancelled(
                    "Worker или вызов отменён до запуска shell",
                )
                .into());
            }
            self.jobs
                .start_reserved_now(reservation, spec, scope.clone())
        };
        let started = if let Some(worker) = worker {
            worker.admission.with_open(start)
        } else {
            start()
        };
        if let Err(error) = started {
            return Err(classify_pre_spawn_start_error(
                error,
                !entered_start,
                turn_cancel.is_cancelled(),
            ));
        }
        wait(self.jobs, owner, &id, worker, &scope).await?;
        self.events.refresh_keys(self.store)?;
        let secrets = self.events.secret_snapshot();
        self.jobs.refresh_credentials(&secrets).await?;
        let view = self.jobs.poll(owner, &id, 0, 0, PAGE).await?;
        let result = self
            .jobs
            .publish_snapshot(&view, |current| {
                complete(current, worker, &sandbox_meta, |outcome| {
                    crate::operation_receipts::finish(
                        pending,
                        self.journal,
                        &artifacts,
                        self.session,
                        self.store,
                        call,
                        outcome,
                        &secrets,
                    )
                })
            })
            .await?;
        // A failed write leaves payload owned by runtime. Unknown cleanup never
        // releases its native resource obligation or retained evidence.
        if view.cleanup_complete {
            self.jobs.acknowledge_payload(owner, &id)?;
        }
        Ok(result)
    }
}

fn classify_pre_spawn_start_error(
    error: anyhow::Error,
    rejected_before_start_closure: bool,
    turn_cancelled: bool,
) -> anyhow::Error {
    let refused_before_spawn = rejected_before_start_closure
        || error
            .downcast_ref::<crate::jobs::PreSpawnCancelled>()
            .is_some();
    let cause = if refused_before_spawn && turn_cancelled {
        anyhow::Error::from(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "Задача отменена; shell не запускался",
        ))
    } else {
        error
    };
    cause.context("Запуск shell не подтверждён; намерение сохранено без автоматического повтора")
}

/// Public Tools convenience path outside an application SessionRuntime. The app
/// never uses it for model commands or !: both must share its session supervisor.
pub(crate) async fn standalone(
    tools: &mut Tools,
    args: &Value,
    cancel: &CancellationToken,
) -> Result<ToolOutcome> {
    let spec = prepare(
        tools.root(),
        args,
        JobOrigin {
            actor: None,
            turn: 0,
        },
    )?;
    tools.mark_shell_used()?;
    let jobs = JobsSupervisor::new(&uuid::Uuid::new_v4().to_string(), vec![])?;
    let scope = cancel.child_token();
    let _guard = CancelOnDrop(scope.clone());
    let result: Result<ToolOutcome> = async {
        let started = jobs.start(spec, scope.clone()).await?;
        let view = wait(&jobs, None, &started.id, None, &scope).await?;
        let off_meta = crate::sandbox::SandboxReceiptMeta::off();
        jobs.publish_snapshot(&view, |view| Ok(outcome(view, false, &off_meta)))
            .await
    }
    .await;
    let cleanup = jobs.shutdown().await;
    match (result, cleanup) {
        (Ok(outcome), Ok(())) => Ok(outcome),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use crate::{
        config::{ProviderKind, ProviderSettings},
        session_runtime::SessionRuntime,
    };

    async fn fault_case(cancelled: bool, reply_closed: bool, closed_before: bool) -> Result<()> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().join("project");
        std::fs::create_dir(&root)?;
        let store = ConfigStore::at(temp.path().join("state"))?;
        let mut session = Session::new(&root, ProviderSettings::new(ProviderKind::Custom))?;
        session
            .task_state
            .host_followup("Validate explicit shell execution")?;
        session.turn_index = 1;
        session.save(&store)?;
        let session_file = session.dir(&store).join("session.json");
        let mut tools = Tools::new(&root, &session.dir(&store).join("checkpoints"))?;
        tools.begin_turn()?;
        let events = Events::new(true);
        events.remember("abcdef".into());
        let mut runtime =
            SessionRuntime::new(&session.dir(&store), &session.id, events.secret_snapshot())?;
        let cancel = CancellationToken::new();
        let scope = runtime.begin_turn(1, &cancel)?;
        // The shell contains only a prefix of the known secret. That prefix
        // must never escape on cancellation, including a late durable receipt.
        let command = if cancelled {
            "printf abc; printf x >> once; printf ready > ready; (sleep 1; printf bad > escaped) & wait"
        } else {
            "printf diagnostic; printf x >> once; printf ready > ready; while [ ! -f release ]; do sleep 0.01; done"
        };
        let call = ToolCall::new("run_command", json!({"command":command}));
        let (sender, mut receiver) = tokio::sync::oneshot::channel();
        if closed_before {
            receiver.close();
        }
        let worker = crate::agents::AgentRequest {
            agent_id: "worker-safe".into(),
            name: "worker-safe".into(),
            role: crate::agents::AgentRole::Worker,
            call: call.clone(),
            cancel: cancel.clone(),
            reply: sender,
            admission: Default::default(),
            transfers: Default::default(),
        };
        let actor = reply_closed.then_some(&worker);
        let owner = actor.map(|a| a.agent_id.as_str());
        let trigger_root = root.clone();
        let trigger_cancel = cancel.clone();
        let trigger_file = session_file.clone();
        let trigger = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(5), async {
                while !trigger_root.join("ready").exists() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            if reply_closed {
                drop(receiver);
            } else if cancelled {
                trigger_cancel.cancel();
            } else {
                std::fs::write(trigger_file, "foreign session").unwrap();
                std::fs::write(trigger_root.join("release"), "go").unwrap();
            }
        });
        {
            let (artifacts, journal, jobs, _) = runtime.receipt_resources()?;
            let journal = journal.unwrap();
            let result = Durable {
                tools: &mut tools,
                events: &events,
                jobs,
                journal,
                artifacts,
                session: &mut session,
                store: &store,
            }
            .run(
                &call,
                &json!({"command":command}),
                actor,
                &cancel,
                &cancel,
                crate::sandbox::ExecutionAuthority::ModelTool(
                    crate::sandbox::EffectiveSandboxPolicy::off(),
                ),
            )
            .await;
            if closed_before {
                trigger.abort();
                let _ = trigger.await;
            } else {
                if result.is_err() && !root.join("ready").exists() {
                    trigger.abort();
                    let _ = trigger.await;
                    return result
                        .map(|_| ())
                        .context("foreground fixture failed before process marker");
                }
                trigger.await?;
            }
            let records = journal.records(artifacts)?;
            assert_eq!(records.len(), 1);
            let intent = journal.intent_payload(&records[0].operation_id, artifacts)?;
            let meta = serde_json::from_value(intent["arguments"].clone())?;
            let saved: Value = serde_json::from_str(&artifacts.verify_required(&meta)?)?;
            let id = saved["command_id"].as_str().unwrap();
            if closed_before {
                assert!(result.is_err());
                assert!(
                    jobs.poll(owner, id, 0, 0, PAGE).await.is_err(),
                    "closed worker spawned a native process"
                );
                assert!(
                    journal
                        .terminal_payload(&records[0].operation_id, artifacts)?
                        .is_none()
                );
                assert!(!root.join("once").exists());
            } else {
                let view = jobs.poll(owner, id, 0, 0, PAGE).await?;
                assert!(view.cleanup_complete);
                if cancelled {
                    let outcome = result?;
                    let value: Value = serde_json::from_str(&outcome.content)?;
                    assert!(outcome.is_error);
                    assert_eq!(
                        value["reason"],
                        if reply_closed {
                            "worker_unavailable"
                        } else {
                            "cancelled"
                        }
                    );
                    assert!(!value["stdout"].as_str().unwrap().contains("abc"));
                    assert!(
                        view.payload_unavailable,
                        "committed cleanup may acknowledge payload"
                    );
                } else {
                    assert!(
                        result.is_err(),
                        "foreign session write must block publication"
                    );
                    assert!(
                        !view.payload_unavailable,
                        "uncommitted output was acknowledged"
                    );
                    assert_eq!(view.stdout, "diagnostic");
                    assert!(
                        journal
                            .terminal_payload(&records[0].operation_id, artifacts)?
                            .is_none()
                    );
                    assert_eq!(std::fs::read_to_string(&session_file)?, "foreign session");
                }
            }
        }
        runtime
            .finish_turn_saved(
                scope,
                false,
                &mut session,
                &store,
                &events.secret_snapshot(),
            )
            .await?;
        let closed = runtime
            .shutdown_saved(&mut session, &store, &events.secret_snapshot())
            .await;
        closed?;
        if !cancelled {
            assert_eq!(std::fs::read_to_string(&session_file)?, "foreign session");
        }
        if closed_before {
            assert!(!root.join("once").exists());
        } else {
            assert_eq!(std::fs::read_to_string(root.join("once"))?, "x");
        }
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(!root.join("escaped").exists());
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_preflight_is_an_interrupt() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("project");
        std::fs::create_dir(&root).unwrap();
        let store = ConfigStore::at(temp.path().join("state")).unwrap();
        let mut session = Session::new(&root, ProviderSettings::new(ProviderKind::Custom)).unwrap();
        let mut tools = Tools::new(&root, &session.dir(&store).join("checkpoints")).unwrap();
        tools.begin_turn().unwrap();
        let events = Events::new(true);
        let mut runtime = SessionRuntime::new(&session.dir(&store), &session.id, vec![]).unwrap();
        let (artifacts, journal, jobs, _) = runtime.receipt_resources().unwrap();
        let cancel = CancellationToken::new();
        cancel.cancel();
        let error = Durable {
            tools: &mut tools,
            events: &events,
            jobs,
            journal: journal.unwrap(),
            artifacts,
            session: &mut session,
            store: &store,
        }
        .run(
            &ToolCall::new(
                "run_command",
                json!({"command":"printf unexpected > started"}),
            ),
            &json!({"command":"printf unexpected > started"}),
            None,
            &cancel,
            &cancel,
            crate::sandbox::ExecutionAuthority::ModelTool(
                crate::sandbox::EffectiveSandboxPolicy::off(),
            ),
        )
        .await
        .unwrap_err();
        assert_eq!(crate::app::exit_code(&error), 130, "{error:#}");
        assert!(!root.join("started").exists());
    }

    #[tokio::test]
    async fn worker_only_cancellation_vs_turn_cancellation_through_durable_run() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("project");
        std::fs::create_dir(&root).unwrap();
        let store = ConfigStore::at(temp.path().join("state")).unwrap();
        let mut session = Session::new(&root, ProviderSettings::new(ProviderKind::Custom)).unwrap();
        session
            .task_state
            .host_followup("Validate worker vs turn cancellation")
            .unwrap();
        session.turn_index = 1;
        session.save(&store).unwrap();
        let mut tools = Tools::new(&root, &session.dir(&store).join("checkpoints")).unwrap();
        tools.begin_turn().unwrap();
        let events = Events::new(true);
        let mut runtime = SessionRuntime::new(&session.dir(&store), &session.id, vec![]).unwrap();
        let turn_cancel = CancellationToken::new();
        let scope = runtime.begin_turn(1, &turn_cancel).unwrap();

        // 1. Worker-only cancel BEFORE begin (`!turn_cancel.is_cancelled()`, `worker_cancel.is_cancelled()`)
        //    returns a regular ToolOutcome error without aborting the turn or creating an Unknown intent.
        {
            let (artifacts, journal, jobs, _) = runtime.receipt_resources().unwrap();
            let journal = journal.unwrap();
            let worker_cancel = CancellationToken::new();
            worker_cancel.cancel();
            let (reply, _scoped, admission) = crate::agents::scoped_reply_for_test();
            let worker = crate::agents::AgentRequest {
                agent_id: "worker-timeout".into(),
                name: "worker-timeout".into(),
                role: crate::agents::AgentRole::Worker,
                call: ToolCall::new("run_command", json!({"command":"printf bad > started"})),
                cancel: worker_cancel.clone(),
                reply,
                admission,
                transfers: Default::default(),
            };
            let outcome = Durable {
                tools: &mut tools,
                events: &events,
                jobs,
                journal,
                artifacts,
                session: &mut session,
                store: &store,
            }
            .run(
                &worker.call,
                &json!({"command":"printf bad > started"}),
                Some(&worker),
                &worker_cancel,
                &turn_cancel,
                crate::sandbox::ExecutionAuthority::ModelTool(
                    crate::sandbox::EffectiveSandboxPolicy::off(),
                ),
            )
            .await
            .expect("worker-only preflight cancel must not abort parent turn");
            assert!(outcome.is_error);
            assert!(journal.records(artifacts).unwrap().is_empty());
        }

        // 2. Closed worker reply AFTER begin while parent `turn_cancel` is active (NOT cancelled)
        //    must return exit_code 2 (never misclassified as 130 turn interrupt).
        {
            let (artifacts, journal, jobs, _) = runtime.receipt_resources().unwrap();
            let journal = journal.unwrap();
            let worker_cancel = CancellationToken::new();
            let (reply, scoped, admission) = crate::agents::scoped_reply_for_test();
            drop(scoped);
            let worker = crate::agents::AgentRequest {
                agent_id: "worker-closed".into(),
                name: "worker-closed".into(),
                role: crate::agents::AgentRole::Worker,
                call: ToolCall::new("run_command", json!({"command":"printf bad > started"})),
                cancel: worker_cancel.clone(),
                reply,
                admission,
                transfers: Default::default(),
            };
            let err = Durable {
                tools: &mut tools,
                events: &events,
                jobs,
                journal,
                artifacts,
                session: &mut session,
                store: &store,
            }
            .run(
                &worker.call,
                &json!({"command":"printf bad > started"}),
                Some(&worker),
                &worker_cancel,
                &turn_cancel,
                crate::sandbox::ExecutionAuthority::ModelTool(
                    crate::sandbox::EffectiveSandboxPolicy::off(),
                ),
            )
            .await
            .unwrap_err();
            assert_eq!(crate::app::exit_code(&err), 2, "{err:#}");
            assert!(!root.join("started").exists());
        }

        runtime
            .finish_turn_saved(scope, true, &mut session, &store, &[])
            .await
            .unwrap();
        runtime
            .shutdown_saved(&mut session, &store, &[])
            .await
            .unwrap();
    }

    #[test]
    fn cancelled_turn_pre_spawn_errors_map_to_interrupt_130_without_masking_spawn_failures() {
        // 1. Reply gate closed before `start` closure ran + turn cancelled -> 130.
        let closed_err = anyhow::anyhow!("Worker reply closed before native action");
        let interrupted = classify_pre_spawn_start_error(closed_err, true, true);
        assert_eq!(crate::app::exit_code(&interrupted), 130, "{interrupted:#}");
        assert!(format!("{interrupted:#}").contains("Запуск shell не подтверждён"));

        // 2. Supervisor `PreSpawnCancelled("scope cancelled")` inside `start_reserved_now`
        //    after `start` closure began + turn cancelled -> 130!
        let supervisor_pre_spawn =
            anyhow::Error::from(crate::jobs::PreSpawnCancelled("scope cancelled"));
        let interrupted_sup = classify_pre_spawn_start_error(supervisor_pre_spawn, false, true);
        assert_eq!(
            crate::app::exit_code(&interrupted_sup),
            130,
            "{interrupted_sup:#}"
        );

        // 3. When the turn is NOT cancelled (isolated worker timeout), exit_code remains 2.
        let worker_only = classify_pre_spawn_start_error(
            anyhow::Error::from(crate::jobs::PreSpawnCancelled("scope cancelled")),
            false,
            false,
        );
        assert_eq!(crate::app::exit_code(&worker_only), 2, "{worker_only:#}");

        // 4. Genuine supervisor/spawn failure (not `PreSpawnCancelled` and after entering `start`)
        //    is NEVER masked even if `turn_cancelled` is true.
        let real_spawn_err = classify_pre_spawn_start_error(
            anyhow::anyhow!("four resource slots occupied"),
            false,
            true,
        );
        assert_eq!(
            crate::app::exit_code(&real_spawn_err),
            2,
            "{real_spawn_err:#}"
        );
    }

    #[tokio::test]
    async fn cancellation_keeps_private_prefix_hidden_and_reaps_descendants() {
        tokio::time::timeout(Duration::from_secs(15), fault_case(true, false, false))
            .await
            .unwrap()
            .unwrap();
    }
    #[tokio::test]
    async fn reply_closed_after_native_success_is_failed_without_exposing_eof_tail() {
        let temp = tempfile::tempdir().unwrap();
        let jobs = JobsSupervisor::new("terminal-close", vec!["abcdef".into()]).unwrap();
        let cancel = CancellationToken::new();
        let args = json!({"command":"printf abc"});
        let spec = prepare(
            temp.path(),
            &args,
            JobOrigin {
                actor: Some("worker-safe".into()),
                turn: 1,
            },
        )
        .unwrap();
        let started = jobs.start(spec, cancel.clone()).await.unwrap();
        let view = wait(&jobs, Some("worker-safe"), &started.id, None, &cancel)
            .await
            .unwrap();
        assert_eq!(view.stdout, "abc", "successful native EOF was not reached");
        assert_eq!(view.exit_code, Some(0));
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let worker = crate::agents::AgentRequest {
            agent_id: "worker-safe".into(),
            name: "worker-safe".into(),
            role: crate::agents::AgentRole::Worker,
            call: ToolCall::new("run_command", args),
            cancel: CancellationToken::new(),
            reply: sender,
            admission: Default::default(),
            transfers: Default::default(),
        };
        drop(receiver); // after confirmed EOF, before durable publication
        let off_meta = crate::sandbox::SandboxReceiptMeta::off();
        let receipt = jobs
            .publish_snapshot(&view, |current| {
                complete(current, Some(&worker), &off_meta, Ok)
            })
            .await
            .unwrap();
        assert!(receipt.is_error);
        let value: Value = serde_json::from_str(&receipt.content).unwrap();
        assert_eq!(value["reason"], "worker_unavailable");
        assert_eq!(value["status"], "exited");
        assert_eq!(value["exit_code"], 0);
        assert_eq!(value["signal"], Value::Null);
        assert_eq!(value["cleanup_complete"], true);
        assert_eq!(value["delivery_cancelled"], true);
        assert_eq!(value["redaction_incomplete"], true);
        assert_eq!(value["stdout"], "");
        assert!(!worker.cancel.is_cancelled());
        jobs.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn already_closed_worker_reply_never_spawns_foreground() {
        tokio::time::timeout(Duration::from_secs(15), fault_case(true, true, true))
            .await
            .unwrap()
            .unwrap();
    }
    #[tokio::test]
    async fn closed_worker_reply_cancels_foreground_and_reaps_descendants() {
        tokio::time::timeout(Duration::from_secs(15), fault_case(true, true, false))
            .await
            .unwrap()
            .unwrap();
    }
    #[tokio::test]
    async fn failed_commit_retains_native_output_and_never_overwrites_foreign_session() {
        tokio::time::timeout(Duration::from_secs(15), fault_case(false, false, false))
            .await
            .unwrap()
            .unwrap();
    }
}
