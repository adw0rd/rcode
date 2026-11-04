//! Real-CLI coverage for handing a running command from a worker to its parent.
#![cfg(any(target_os = "linux", target_os = "macos"))]
mod support;

use serde_json::{Value, json};
use std::{
    path::Path,
    process::Output,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use support::{Request, Server, text_reply, tool_reply};
use tokio::process::Command;

const KEY: &str = "handoff-synthetic-key";

fn latest(request: &Request) -> Option<(String, Value)> {
    request.json()["messages"]
        .as_array()?
        .iter()
        .rev()
        .find(|message| message["role"] == "tool")
        .map(|message| {
            let content = message["content"].as_str().unwrap_or_default();
            let value =
                serde_json::from_str(content).unwrap_or_else(|_| Value::String(content.to_owned()));
            (
                message["name"].as_str().unwrap_or_default().to_owned(),
                value,
            )
        })
}

fn user_task(request: &Request) -> String {
    request.json()["messages"]
        .as_array()
        .and_then(|messages| messages.iter().find(|message| message["role"] == "user"))
        .and_then(|message| message["content"].as_str())
        .expect("fixture request has a user task")
        .to_owned()
}

fn offered_tools(request: &Request) -> Vec<String> {
    request.json()["tools"]
        .as_array()
        .expect("fixture request has tool definitions")
        .iter()
        .filter_map(|tool| tool["function"]["name"].as_str().map(str::to_owned))
        .collect()
}

async fn run(project: &Path, state: &Path, server: &Server) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rcode"));
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("RCODE_HOME", state)
        .env("RCODE_CUSTOM_API_KEY", KEY)
        .args([
            "-C",
            project.to_str().unwrap(),
            "--provider",
            "custom",
            "--model",
            "fixture",
            "--base-url",
            &server.base(),
            "--json",
            "--max-steps",
            "12",
            "--allow-shell",
            "--approval-mode",
            "auto-edit",
            "exec",
            "PARENT_HANDOFF: delegate the command to a worker, collect it, then release and stop it.",
        ])
        .kill_on_drop(true);
    tokio::time::timeout(Duration::from_secs(30), command.output())
        .await
        .expect("CLI must finish within 30 seconds")
        .unwrap()
}

async fn handoff_case(fail_worker: bool) {
    let project = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let marker = project.path().join("release");
    std::fs::write(project.path().join("user-marker"), "UNCHANGED").unwrap();
    let handoff_receipt = Arc::new(Mutex::new(None::<Value>));
    let captured_receipt = handoff_receipt.clone();
    let generations = Arc::new(AtomicUsize::new(0));
    let counted_generations = generations.clone();

    let server = Server::start(move |request, _global_step| {
        let step = request.json()["messages"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|m| m["role"] == "tool")
            .count();
        if request.is_generation() {
            assert!(counted_generations.fetch_add(1, Ordering::SeqCst) < 20);
        }
        let task = user_task(request);
        if task.starts_with("WORKER_HANDOFF") {
            assert!(step < 8, "worker fixture is bounded");
            let offered = offered_tools(request);
            match step {
                0 => {
                    assert!(offered.contains(&"start_command".to_owned()));
                    tool_reply(
                        "worker-start-command",
                        "start_command",
                        &json!({
                            "command": "printf worker; while [ ! -f release ]; do sleep 0.01; done; printf parent; sleep 30",
                            "stdin": false
                        }),
                    )
                }
                1 => {
                    let (name, receipt) = latest(request).expect("worker start receipt");
                    assert_eq!(name, "start_command");
                    let command_id = receipt["command_id"]
                        .as_str()
                        .expect("start receipt has real command ID")
                        .to_owned();
                    assert!(offered.contains(&"handoff_command".to_owned()));
                    *captured_receipt.lock().unwrap() = Some(receipt);
                    tool_reply(
                        "worker-handoff-command",
                        "handoff_command",
                        &json!({"command_id": command_id}),
                    )
                }
                2 => {
                    let (_, receipt) = latest(request).expect("handoff receipt");
                    assert_eq!(receipt["ownership_epoch"], 1);
                    assert!(receipt["owner"].is_null());
                    assert!(receipt["command_id"].as_str().is_some());
                    *captured_receipt.lock().unwrap() = None;
                    if fail_worker {
                        tool_reply(
                            "worker-failure-after-handoff",
                            "read_file",
                            &json!({"path":"deliberately-missing"}),
                        )
                    } else {
                        text_reply("WORKER_FINISHED_WITHOUT_COMMAND_ID")
                    }
                }
                _ => text_reply("WORKER_FAILED_AFTER_HANDOFF_WITHOUT_ID"),
            }
        } else {
            assert!(task.starts_with("PARENT_HANDOFF"));
            assert!(step < 12, "parent fixture is bounded");
            let offered = offered_tools(request);
            assert!(!offered.contains(&"handoff_command".to_owned()));
            match step {
                0 => tool_reply(
                    "spawn-worker",
                    "spawn_agent",
                    &json!({
                        "task": "WORKER_HANDOFF: start and hand off the running command",
                        "name": "handoff-worker",
                        "role": "worker"
                    }),
                ),
                1 => text_reply("PARENT_PREMATURE_FINAL"),
                _ => {
                    let (tool_name, result) = latest(request).expect("parent tool receipt");
                    match tool_name.as_str() {
                        "wait_agent" => {
                            let transfers = result["transferred_commands"].as_array().expect(
                                "host transfer records survive independently of worker prose",
                            );
                            assert_eq!(transfers.len(), 1);
                            assert_eq!(transfers[0]["ownership_epoch"], 1);
                            *captured_receipt.lock().unwrap() =
                                Some(json!({"command_id":transfers[0]["command_id"]}));
                            tool_reply(
                                "parent-release",
                                "run_command",
                                &json!({"command":"touch release"}),
                            )
                        }
                        "run_command" => {
                            let receipt = captured_receipt
                                .lock()
                                .unwrap()
                                .clone()
                                .expect("worker captured its actual start receipt");
                            let command_id = receipt["command_id"].as_str().unwrap();
                            tool_reply(
                                "parent-poll",
                                "poll_command",
                                &json!({"command_id": command_id}),
                            )
                        }
                        "poll_command" => {
                            let stdout = result["stdout"].as_str().unwrap_or_default();
                            if stdout.contains("parent") {
                                let command_id = captured_receipt.lock().unwrap().as_ref().unwrap()
                                    ["command_id"]
                                    .as_str()
                                    .unwrap()
                                    .to_owned();
                                tool_reply(
                                    "parent-stop",
                                    "stop_command",
                                    &json!({"command_id": command_id}),
                                )
                            } else {
                                let polls = request.json()["messages"]
                                    .as_array()
                                    .unwrap()
                                    .iter()
                                    .filter(|message| {
                                        message["role"] == "tool"
                                            && message["name"] == "poll_command"
                                    })
                                    .count();
                                assert!(polls <= 4, "parent polling is bounded to four calls");
                                assert!(polls < 4, "command must produce parent output promptly");
                                std::thread::sleep(Duration::from_millis(50));
                                let command_id = captured_receipt.lock().unwrap().as_ref().unwrap()
                                    ["command_id"]
                                    .as_str()
                                    .unwrap()
                                    .to_owned();
                                tool_reply(
                                    "parent-poll-again",
                                    "poll_command",
                                    &json!({"command_id": command_id}),
                                )
                            }
                        }
                        "stop_command" => text_reply("PARENT_STOPPED_HANDED_OFF_COMMAND"),
                        other => panic!("unexpected parent tool receipt: {other}"),
                    }
                }
            }
        }
    });

    let output = run(project.path(), state.path(), &server).await;
    assert!(
        output.status.success(),
        "CLI failed with {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(KEY));
    assert!(marker.is_file(), "parent release command ran");
    assert_eq!(
        std::fs::read_to_string(project.path().join("user-marker")).unwrap(),
        "UNCHANGED"
    );
    let events = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert!(events.iter().any(|event| {
        event["type"] == "text"
            && event["text"]
                .as_str()
                .unwrap_or_default()
                .contains("PARENT_STOPPED_HANDED_OFF_COMMAND")
    }));
    assert!(
        !events.iter().any(|event| event["type"] == "tool_result"
            && event["is_error"] == true
            && !(fail_worker
                && matches!(event["name"].as_str(), Some("read_file" | "wait_agent")))),
        "all real tool invocations should succeed: {events:?}"
    );
    let receipt = handoff_receipt
        .lock()
        .unwrap()
        .clone()
        .expect("worker start receipt");
    assert!(receipt["command_id"].as_str().is_some());
    if fail_worker {
        assert!(events.iter().any(|e| e["type"] == "agent_update"
            && e["status"] == "failed"
            && e["transferred_commands"][0]["command_id"].is_string()));
    }
}

#[tokio::test]
async fn worker_hands_running_command_to_parent_until_parent_stops_it() {
    handoff_case(false).await;
}
#[tokio::test]
async fn parent_receives_committed_command_even_if_worker_fails_after_transfer() {
    handoff_case(true).await;
}
