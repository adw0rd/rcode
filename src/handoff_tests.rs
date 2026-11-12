use super::*;
use crate::{
    config::{ProviderKind, ProviderSettings},
    jobs::{JobKind, JobOrigin, JobSpec, JobStatus},
    session_runtime::SessionRuntime,
};
use clap::Parser;
use std::time::Duration;

struct Reset;
impl Drop for Reset {
    fn drop(&mut self) {
        HANDOFF_TEST_FAULT.with(|f| f.set(0));
    }
}

async fn fault_case(mode: u8) -> Result<()> {
    let _reset = Reset;
    let temp = tempfile::tempdir()?;
    let project = temp.path().join("project");
    std::fs::create_dir(&project)?;
    let store = ConfigStore::at(temp.path().join("state"))?;
    let mut session = Session::new(&project, ProviderSettings::new(ProviderKind::Custom))?;
    session.task_state.host_followup("test handoff")?;
    session.turn_index = 1;
    session.save(&store)?;
    let mut runtime = SessionRuntime::new(&session.dir(&store), &session.id, vec![])?;
    let cancel = CancellationToken::new();
    let scope = runtime.begin_turn(1, &cancel)?;
    let worker = CancellationToken::new();
    let start = ToolCall::new("start_command", json!({"command":"sleep 30"}));
    let spec = JobSpec {
        kind: JobKind::Managed,
        argv: vec!["/bin/sh".into(), "-c".into(), "sleep 30".into()],
        env: vec![],
        cwd: project.clone(),
        origin: JobOrigin {
            actor: Some("fault-worker".into()),
            turn: 1,
        },
        lifetime: Duration::from_secs(60),
        idle_timeout: Duration::from_secs(60),
        stdin: false,
    };
    let id = runtime
        .start_approved_job(
            &mut session,
            &store,
            &start,
            &json!({"command":"sleep 30"}),
            spec,
            worker.clone(),
            &[],
        )
        .await?
        .id;
    let mut tools = Tools::new(&project, &temp.path().join("checkpoints"))?;
    tools.begin_turn()?;
    let mut cli = Cli::parse_from(["rcode"]);
    cli.json = true;
    cli.allow_shell = mode != 0;
    cli.approval_mode = Some(ApprovalMode::AutoEdit);
    let events = Events::new(true);
    let skills = SkillCatalog::empty();
    let (reply, receiver) = tokio::sync::oneshot::channel();
    let mut receiver = Some(receiver);
    if mode == 3 {
        receiver.take();
    }
    let call = ToolCall::new("handoff_command", json!({"command_id":id}));
    let actor = AgentRequest {
        agent_id: "fault-worker".into(),
        name: "fault-worker".into(),
        role: AgentRole::Worker,
        call: call.clone(),
        cancel: worker.clone(),
        reply,
        admission: Default::default(),
        transfers: Default::default(),
    };
    let parent_token = scope.cancellation();
    let parent_id = scope.identity();
    {
        let (artifacts, journal, jobs, managed) = runtime.receipt_resources()?;
        let mut executor = ToolExecutor {
            tools: &mut tools,
            events: &events,
            cli: &cli,
            cancel: &cancel,
            plan: false,
            denied: false,
            last_error: false,
            balance: None,
            store: Some(&store),
            skills: &skills,
            skill_page: SkillPage::default(),
            artifacts: Some(artifacts),
            turn_index: 1,
            journal,
            jobs: Some(jobs),
            managed: Some(managed),
            job_cancel: parent_token,
            parent_scope_id: parent_id,
            observations: None,
            asked_questions: std::collections::HashMap::new(),
        };
        HANDOFF_TEST_FAULT.with(|f| f.set(mode));
        let result = executor
            .execute(&call, Some(&actor), Some(&mut session))
            .await;
        if mode == 2 {
            assert!(
                result.is_err(),
                "post-native CAS conflict must not publish success"
            );
            let view = jobs.poll(None, &id, 0, 0, 4).await?;
            assert!(view.owner.is_none());
            assert_eq!(view.ownership_epoch, 1);
            worker.cancel();
            assert_eq!(
                jobs.poll(None, &id, 0, 0, 4).await?.status,
                JobStatus::Running
            );
            let sentinel = ToolCall::new("run_command", json!({"command":"touch forbidden"}));
            assert!(
                executor
                    .execute(&sentinel, None, Some(&mut session))
                    .await
                    .is_err()
            );
            assert!(!project.join("forbidden").exists());
            assert_eq!(
                std::fs::read_to_string(session.dir(&store).join("session.json"))?,
                "foreign session"
            );
        } else {
            assert!(
                result?.is_error,
                "handoff must be refused before native point"
            );
            assert_eq!(
                jobs.poll(Some("fault-worker"), &id, 0, 0, 4)
                    .await?
                    .owner
                    .as_deref(),
                Some("fault-worker")
            );
        }
    }
    let result = runtime
        .finish_turn_saved(scope, true, &mut session, &store, &[])
        .await;
    if mode == 2 {
        assert!(result.is_err());
    } else {
        result?;
    }
    let owner = if mode == 2 {
        None
    } else {
        Some("fault-worker")
    };
    assert!(
        runtime
            .jobs()
            .poll(owner, &id, 0, 0, 4)
            .await?
            .cleanup_complete
    );
    let result = runtime.shutdown_saved(&mut session, &store, &[]).await;
    if mode == 2 {
        assert!(result.is_err());
        assert_eq!(
            std::fs::read_to_string(session.dir(&store).join("session.json"))?,
            "foreign session"
        );
    } else {
        result?;
    }
    Ok(())
}

#[tokio::test]
async fn cancellation_after_handoff_intent_keeps_worker_ownership() {
    tokio::time::timeout(Duration::from_secs(20), fault_case(1))
        .await
        .unwrap()
        .unwrap();
}
#[tokio::test]
async fn failed_commit_after_native_handoff_keeps_parent_cleanup_and_blocks_actions() {
    tokio::time::timeout(Duration::from_secs(20), fault_case(2))
        .await
        .unwrap()
        .unwrap();
}
#[tokio::test]
async fn handoff_needs_separate_permission_and_open_worker_reply() {
    for mode in [0, 3] {
        tokio::time::timeout(Duration::from_secs(20), fault_case(mode))
            .await
            .unwrap()
            .unwrap();
    }
}
