//! Runtime план сохраняется до следующей генерации; fixtures без платных API.
mod support;
use rcode::{
    config::{ConfigStore, ProviderKind, ProviderSettings},
    protocol::Message,
    state::Session,
    task_state::PlanUpdate,
};
use serde_json::{Value, json};
use std::{path::Path, time::Duration};
use support::{Server, text_reply, tool_reply};

fn saved(home: &Path) -> Value {
    let path = std::fs::read_dir(home.join("sessions"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
        .join("session.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[tokio::test]
async fn plan_is_durable_before_next_request_and_cannot_rewrite_user_goal() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("project");
    std::fs::create_dir(&root).unwrap();
    let home = tmp.path().join("state");
    let observed = home.clone();
    let server = Server::start(move |request, index| {
        let request = request.json();
        if index == 0 {
            assert!(
                request["tools"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|t| t["function"]["name"] == "update_plan")
            );
            tool_reply(
                "plan-1",
                "update_plan",
                &json!({"steps":[{"id":"check","step":"Check project","status":"in_progress"}]}),
            )
        } else if index == 1 {
            let state = saved(&observed);
            assert_eq!(state["task_state"]["goal"], "ORIGINAL_GOAL");
            assert_eq!(state["task_state"]["steps"][0]["id"], "check");
            assert!(
                request["messages"][0]["content"]
                    .as_str()
                    .unwrap()
                    .contains("Check project")
            );
            tool_reply(
                "plan-2",
                "update_plan",
                &json!({"steps":[],"goal":"HIJACKED"}),
            )
        } else {
            let state = saved(&observed);
            assert_eq!(state["task_state"]["goal"], "ORIGINAL_GOAL");
            assert_eq!(state["task_state"]["steps"][0]["id"], "check");
            let receipt = request["messages"]
                .as_array()
                .unwrap()
                .iter()
                .rev()
                .find(|m| m["role"] == "tool")
                .unwrap();
            assert!(receipt["content"].as_str().unwrap().contains("error"));
            text_reply("The original plan is preserved; invalid update refused.")
        }
    });
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_rcode"));
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("RCODE_HOME", &home)
        .env("RCODE_CUSTOM_API_KEY", "task-state-fixture-key")
        .args([
            "-C",
            root.to_str().unwrap(),
            "--provider",
            "custom",
            "--base-url",
            &server.base(),
            "--model",
            "fixture",
            "--json",
            "--plan",
            "--max-steps",
            "4",
            "exec",
            "ORIGINAL_GOAL",
        ])
        .kill_on_drop(true);
    #[cfg(windows)]
    if let Some(v) = std::env::var_os("SYSTEMROOT") {
        command.env("SYSTEMROOT", v);
    }
    let output = tokio::time::timeout(Duration::from_secs(15), command.output())
        .await
        .expect("runtime завершает fixture")
        .unwrap();
    assert_eq!(
        server.generations().len(),
        3,
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let events: Vec<Value> = output
        .stdout
        .split(|b| *b == b'\n')
        .filter(|s| !s.is_empty())
        .map(|s| serde_json::from_slice(s).unwrap())
        .collect();
    assert!(events.iter().any(|e| e["type"] == "plan_updated"));
    assert_eq!(saved(&home)["task_state"]["goal"], "ORIGINAL_GOAL");
}

#[test]
fn three_compactions_and_resume_keep_host_goal_and_advisory_plan() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("project");
    std::fs::create_dir(&root).unwrap();
    let store = ConfigStore::at(tmp.path().join("state")).unwrap();
    let mut session = Session::new(&root, ProviderSettings::new(ProviderKind::Custom)).unwrap();
    session.task_state.host_followup("ORIGINAL_GOAL").unwrap();
    session
        .task_state
        .update_plan(
            serde_json::from_value::<PlanUpdate>(
                json!({"steps":[{"id":"test","step":"Run real validation","status":"completed"}]}),
            )
            .unwrap(),
        )
        .unwrap();
    for n in 0..3 {
        for i in 0..16 {
            session.messages.push(Message::user(format!("old {n}-{i}")));
            session
                .messages
                .push(Message::text("assistant", "old data ".repeat(2000)));
        }
        session.messages.push(Message::user(format!("CURRENT_{n}")));
        session.compact().unwrap();
        session.save(&store).unwrap();
        session = Session::load(&store, &session.id, &root).unwrap();
        assert_eq!(session.task_state.goal(), "ORIGINAL_GOAL");
        assert_eq!(session.task_state.steps()[0].id, "test");
        assert!(
            session
                .task_state
                .projection()
                .unwrap()
                .contains("not verified")
        );
    }
}
#[tokio::test]
async fn oversized_advisory_plan_is_rejected_without_poisoning_a_small_local_profile() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("project");
    std::fs::create_dir(&root).unwrap();
    let home = tmp.path().join("state");
    let observed = home.clone();
    let server = Server::start(move |request, index| {
        if !request.is_generation() {
            return support::Response::json(404, json!({}));
        }
        if index == 0 {
            let steps:Vec<_>=(0..20).map(|i|json!({"id":format!("step-{i}"),"step":format!("Check {i}: {}","bounded details ".repeat(40)),"status":"pending"})).collect();
            tool_reply("large-plan", "update_plan", &json!({"steps":steps}))
        } else {
            assert!(
                saved(&observed)["task_state"]["steps"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
            text_reply(
                "Plan exceeds this model context; keep the original task and shorten the plan.",
            )
        }
    });
    let store = ConfigStore::at(home.clone()).unwrap();
    let mut settings = store.load().unwrap();
    let mut profile = rcode::local::profile_settings(
        "small",
        &server.base(),
        rcode::local::LocalRuntime::OpenAi,
        "fixture",
    );
    profile.local.as_mut().unwrap().context_tokens = 8192;
    profile.max_output_tokens = 512;
    settings.local.active = Some("small".into());
    settings.local.profiles.insert("small".into(), profile);
    store.save(&settings).unwrap();
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_rcode"));
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("RCODE_HOME", &home)
        .args([
            "-C",
            root.to_str().unwrap(),
            "--profile",
            "small",
            "--plan",
            "--json",
            "--max-steps",
            "3",
            "exec",
            "ORIGINAL_GOAL",
        ])
        .kill_on_drop(true);
    #[cfg(windows)]
    if let Some(v) = std::env::var_os("SYSTEMROOT") {
        cmd.env("SYSTEMROOT", v);
    }
    let output = tokio::time::timeout(Duration::from_secs(20), cmd.output())
        .await
        .expect("local plan fixture deadline")
        .unwrap();
    assert_eq!(
        server.generations().len(),
        2,
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let state = saved(&home);
    assert_eq!(state["task_state"]["goal"], "ORIGINAL_GOAL");
    assert!(state["task_state"]["steps"].as_array().unwrap().is_empty());
    let results: Vec<Value> = output
        .stdout
        .split(|b| *b == b'\n')
        .filter(|b| !b.is_empty())
        .map(|b| serde_json::from_slice(b).unwrap())
        .collect();
    assert!(results.iter().any(|e| e["type"] == "tool_result"
        && e["name"] == "update_plan"
        && e["is_error"] == true));
    assert!(!results.iter().any(|e| e["type"] == "plan_updated"));
}
