//! Real-CLI regression coverage for worker native-command receipts.
#![cfg(any(target_os = "linux", target_os = "macos"))]
mod support;

use serde_json::{Value, json};
use std::{path::Path, process::Output, time::Duration};
use support::{Request, Server, text_reply, tool_reply};
use tokio::process::Command;

const KEY: &str = "worker-receipts-synthetic-key";
const PARENT: &str = "PARENT_WORKER_RECEIPTS";
const WORKER: &str = "WORKER_RECEIPTS_TASK";

fn task(request: &Request) -> String {
    request.json()["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|message| message["role"] == "user")
        .unwrap()["content"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn latest_tool(request: &Request) -> Option<(String, Value)> {
    request.json()["messages"]
        .as_array()?
        .iter()
        .rev()
        .find(|message| message["role"] == "tool")
        .map(|message| {
            let raw = message["content"].as_str().unwrap_or_default();
            let value = serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.to_owned()));
            (
                message["name"].as_str().unwrap_or_default().to_owned(),
                value,
            )
        })
}

fn latest_call(request: &Request) -> Option<(String, Value)> {
    request.json()["messages"]
        .as_array()?
        .iter()
        .rev()
        .find_map(|message| {
            (message["role"] == "assistant")
                .then(|| message["tool_calls"].as_array())
                .flatten()
                .and_then(|calls| calls.last())
        })
        .map(|call| {
            let function = &call["function"];
            let arguments = function["arguments"].as_str().unwrap_or_default();
            (
                function["name"].as_str().unwrap_or_default().to_owned(),
                serde_json::from_str(arguments).unwrap_or(Value::Null),
            )
        })
}

fn tool_count(request: &Request) -> usize {
    request.json()["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|message| message["role"] == "tool")
        .count()
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
            "4",
            "--agent-timeout-secs",
            "30",
            "--approval-mode",
            "auto-edit",
            "--allow-shell",
            "exec",
            "PARENT_WORKER_RECEIPTS: delegate to a worker, wait, then summarize.",
        ])
        .kill_on_drop(true);
    tokio::time::timeout(Duration::from_secs(40), command.output())
        .await
        .expect("CLI and worker broker must finish within 40 seconds")
        .unwrap()
}

fn is_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok()
}

#[tokio::test]
async fn failed_worker_wait_includes_host_command_receipts() {
    let project = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("user-marker"), "PRESERVE-USER-WORK\n").unwrap();

    let ready = project.path().join("child-ready");
    let server = Server::start(move |request, _| {
        if task(request).starts_with(WORKER) {
            match tool_count(request) {
                0 => tool_reply(
                    "worker-start",
                    "start_command",
                    &json!({
                        "command":"read line; printf 'WORKER_STDOUT:%s\\n' \"$line\"; printf ready > child-ready; sleep 30",
                        "stdin":true,
                        "lifetime_minutes":1,
                        "idle_minutes":1
                    }),
                ),
                1 => {
                    let (_, start) = latest_tool(request).expect("start receipt");
                    tool_reply(
                        "worker-input",
                        "send_command_input",
                        &json!({
                            "command_id":start["command_id"],
                            "text":"worker-input-marker",
                            "append_newline":true,
                            "close":true
                        }),
                    )
                }
                2 => {
                    let deadline = std::time::Instant::now() + Duration::from_secs(5);
                    while !ready.is_file() && std::time::Instant::now() < deadline {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    assert!(
                        ready.is_file(),
                        "child did not consume stdin and publish stdout"
                    );
                    let command_id = request.json()["messages"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter(|message| message["role"] == "tool")
                        .filter_map(|message| {
                            serde_json::from_str::<Value>(message["content"].as_str()?).ok()
                        })
                        .find_map(|receipt| receipt["command_id"].as_str().map(str::to_owned))
                        .expect("worker command ID");
                    tool_reply(
                        "worker-poll",
                        "poll_command",
                        &json!({"command_id":command_id,"max_bytes":4096}),
                    )
                }
                3 => {
                    let (_, poll) = latest_tool(request).expect("poll receipt");
                    tool_reply(
                        "worker-stop",
                        "stop_command",
                        &json!({"command_id":poll["command_id"]}),
                    )
                }
                step => panic!("unexpected worker API step {step}"),
            }
        } else {
            assert!(
                task(request).starts_with(PARENT),
                "unexpected model context: {}",
                task(request)
            );
            match tool_count(request) {
                0 => tool_reply(
                    "parent-spawn",
                    "spawn_agent",
                    &json!({
                        "task":"WORKER_RECEIPTS_TASK: run a command, collect host receipts, then stop it",
                        "name":"receipt-worker",
                        "role":"worker"
                    }),
                ),
                1 => {
                    let (_, spawned) = latest_tool(request).expect("spawn receipt");
                    tool_reply(
                        "parent-wait",
                        "wait_agent",
                        &json!({"agent_id":spawned["agent_id"]}),
                    )
                }
                2 => {
                    let (name, wait) = latest_tool(request).expect("parent wait receipt");
                    assert_eq!(name, "wait_agent");
                    assert_eq!(wait["status"], "failed");
                    assert_eq!(wait["worker_receipts"]["available"], true);
                    assert!(
                        wait["worker_receipts"]["observations"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|observation| {
                                observation["tool"] == "stop_command"
                                    && observation["fields"]["cleanup_complete"] == true
                            })
                    );
                    text_reply(
                        "Worker failed at its step limit; host results were collected, goal remains unverified.",
                    )
                }
                step => panic!("unexpected parent API step {step}"),
            }
        }
    });

    let output = run(project.path(), state.path(), &server).await;
    assert_eq!(
        output.status.code(),
        Some(1),
        "failed worker wait should make the turn incomplete\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(KEY));
    assert_eq!(
        std::fs::read_to_string(project.path().join("user-marker")).unwrap(),
        "PRESERVE-USER-WORK\n"
    );

    let events = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<Value>(line).expect("JSONL event"))
        .collect::<Vec<_>>();
    let wait = events
        .iter()
        .find(|event| event["type"] == "tool_result" && event["name"] == "wait_agent")
        .expect("parent received wait_agent result");
    assert_eq!(
        wait["is_error"], true,
        "worker should exhaust its 4-step limit"
    );
    let wait_result: Value = serde_json::from_str(wait["content"].as_str().unwrap()).unwrap();
    assert_eq!(wait_result["status"], "failed");
    assert!(
        wait_result["result"]
            .as_str()
            .unwrap()
            .contains("лимит шагов")
    );
    let receipts = &wait_result["worker_receipts"];
    assert!(
        receipts.is_object(),
        "failed wait_agent result lacks worker_receipts: {wait_result}"
    );
    assert_eq!(receipts["version"], 1);
    assert_eq!(receipts["available"], true);
    assert_eq!(receipts["goal_verified"], false);
    assert!(serde_json::to_vec(receipts).unwrap().len() <= 8192);
    let observations = receipts["observations"]
        .as_array()
        .expect("receipt observations");
    assert!(
        !observations.is_empty(),
        "host observations must survive worker failure"
    );
    assert!(
        observations.iter().any(|observation| {
            observation["tool"] == "start_command"
                && observation["fields"]["command_id"]
                    .as_str()
                    .is_some_and(is_uuid)
        }),
        "start receipt with real command ID is missing: {receipts}"
    );
    assert!(
        observations.iter().any(|observation| {
            observation["tool"] == "send_command_input"
                && observation["fields"]["input_id"]
                    .as_str()
                    .is_some_and(is_uuid)
        }),
        "input receipt with real input ID is missing: {receipts}"
    );
    assert!(
        observations.iter().any(|observation| {
            observation["tool"] == "poll_command"
                && observation["stdout_preview"]
                    .as_str()
                    .is_some_and(|stdout| stdout.contains("WORKER_STDOUT:worker-input-marker\n"))
        }),
        "host receipt should preserve real child stdout: {receipts}"
    );
    assert!(
        observations.iter().any(|observation| {
            observation["tool"] == "stop_command"
                && observation["fields"]["status"] == "stopped"
                && observation["fields"]["cleanup_complete"] == true
        }),
        "stopped cleanup receipt is missing: {receipts}"
    );
    assert!(
        observations
            .iter()
            .all(|observation| observation["tool"] != "read_tool_output"),
        "summary should not require artifact readback: {receipts}"
    );

    let generations = server.generations();
    let workers = generations
        .iter()
        .filter(|request| task(request).starts_with(WORKER))
        .collect::<Vec<_>>();
    assert_eq!(
        workers.len(),
        4,
        "worker must not be replayed or get a fifth model step"
    );
    assert_eq!(
        generations.len(),
        8,
        "four parent and four worker model steps are expected"
    );
    assert!(
        generations.iter().all(|request| {
            task(request).starts_with(PARENT) || task(request).starts_with(WORKER)
        }),
        "unexpected provider request context"
    );

    let start = workers[1];
    let input = workers[2];
    let poll = workers[3];
    let (start_tool, start_args) = latest_call(start).expect("worker start tool call");
    assert_eq!(start_tool, "start_command");
    assert_eq!(start_args["stdin"], true);
    assert_eq!(start_args["lifetime_minutes"], 1);
    assert_eq!(start_args["idle_minutes"], 1);
    let start_receipt = latest_tool(start).unwrap().1;
    let (input_tool, input_args) = latest_call(input).expect("worker input tool call");
    assert_eq!(input_tool, "send_command_input");
    assert_eq!(input_args["text"], "worker-input-marker");
    assert_eq!(input_args["append_newline"], true);
    assert_eq!(input_args["close"], true);
    let input_receipt = latest_tool(input).unwrap().1;
    assert_eq!(input_args["command_id"], start_receipt["command_id"]);
    let poll_receipt = latest_tool(poll).unwrap().1;
    let (poll_tool, poll_args) = latest_call(poll).expect("worker poll tool call");
    assert_eq!(poll_tool, "poll_command");
    assert_eq!(poll_args["max_bytes"], 4096);
    let command_id = start_receipt["command_id"].as_str().unwrap();
    assert!(is_uuid(command_id));
    assert_eq!(input_receipt["command_id"], command_id);
    assert_eq!(poll_receipt["command_id"], command_id);
    assert!(is_uuid(input_receipt["input_id"].as_str().unwrap()));
    assert_eq!(input_receipt["delivery"], "accepted");
    let poll_observation = observations
        .iter()
        .find(|o| o["tool"] == "poll_command")
        .unwrap();
    assert_eq!(poll_observation["fields"]["command_id"], command_id);
    assert_eq!(
        poll_observation["stdout_preview"],
        "WORKER_STDOUT:worker-input-marker\n"
    );
    assert!(
        poll_observation["fields"]["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|input| {
                input["input_id"] == input_receipt["input_id"]
                    && input["delivery"] == "delivered"
                    && input["written"] == b"worker-input-marker\n".len()
                    && input["total"] == b"worker-input-marker\n".len()
            })
    );
    for request in generations
        .iter()
        .filter(|request| task(request).starts_with(PARENT))
    {
        let body = request.json();
        for message in body["messages"].as_array().unwrap() {
            if message["role"] == "tool" {
                assert!(matches!(
                    message["name"].as_str(),
                    Some("spawn_agent" | "wait_agent")
                ));
            }
            if let Some(calls) = message["tool_calls"].as_array() {
                assert!(calls.iter().all(|call| matches!(
                    call["function"]["name"].as_str(),
                    Some("spawn_agent" | "wait_agent")
                )));
            }
        }
    }

    let stop_start = events
        .iter()
        .find(|event| event["type"] == "tool_start" && event["name"] == "stop_command")
        .expect("worker actually requested stop_command");
    let stop_args: Value = serde_json::from_str(stop_start["arguments"].as_str().unwrap()).unwrap();
    assert_eq!(stop_args["command_id"], command_id);

    let parent = generations
        .iter()
        .filter(|request| task(request).starts_with(PARENT))
        .collect::<Vec<_>>();
    let (spawn_tool, _) = latest_call(parent[1]).expect("parent spawn call");
    assert_eq!(spawn_tool, "spawn_agent");
    let (wait_tool, wait_args) = latest_call(parent[2]).expect("parent wait call");
    assert_eq!(wait_tool, "wait_agent");
    assert_eq!(wait_args["agent_id"], wait_result["id"]);

    let session_file = std::fs::read_dir(state.path().join("sessions"))
        .unwrap()
        .map(|entry| entry.unwrap().path().join("session.json"))
        .find(|path| path.is_file())
        .expect("session metadata persisted");
    let session_json: Value =
        serde_json::from_slice(&std::fs::read(&session_file).unwrap()).unwrap();
    let session_dir = session_file.parent().unwrap();
    let session_id = session_json["id"].as_str().unwrap();
    let store = rcode::config::ConfigStore::at(state.path()).unwrap();
    let loaded = rcode::state::Session::load(&store, session_id, project.path()).unwrap();
    assert_eq!(loaded.id, session_id);
    let artifacts = rcode::artifacts::ArtifactStore::open(session_dir, session_id).unwrap();
    let journal =
        rcode::operation_journal::OperationJournal::open(session_dir, session_id, &artifacts)
            .unwrap();
    let committed = journal.records(&artifacts).unwrap();
    for observation in observations {
        let record = committed
            .iter()
            .find(|r| r.operation_id == observation["operation_id"])
            .unwrap();
        assert_eq!(record.origin.actor.as_deref(), wait_result["id"].as_str());
        assert_eq!(record.origin.turn, loaded.turn_index);
        assert_eq!(
            record.terminal.as_ref().unwrap().id,
            observation["terminal"]
        );
        assert_eq!(
            record.task_revision.unwrap(),
            observation["revision"].as_u64().unwrap()
        );
        let payload = journal
            .terminal_payload(&record.operation_id, &artifacts)
            .unwrap()
            .unwrap();
        let output_meta: rcode::artifacts::ArtifactMeta =
            serde_json::from_value(payload["output"].clone()).unwrap();
        assert_eq!(output_meta.id, observation["output"]);
        artifacts.verify_output(&output_meta).unwrap();
    }
    let records: Value =
        serde_json::from_slice(&std::fs::read(session_dir.join("operations/index.json")).unwrap())
            .unwrap();
    let native = records["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|record| record["origin"]["tool"] == "command_lifetime")
        .collect::<Vec<_>>();
    assert_eq!(
        native.len(),
        1,
        "worker command journal should remain intact"
    );
    let payload = journal
        .terminal_payload(native[0]["operation_id"].as_str().unwrap(), &artifacts)
        .unwrap()
        .expect("committed worker terminal receipt");
    let meta: rcode::artifacts::ArtifactMeta =
        serde_json::from_value(payload["output"].clone()).unwrap();
    let manifest: Value = serde_json::from_str(&artifacts.verify_required(&meta).unwrap()).unwrap();
    assert_eq!(manifest["command_id"], command_id);
    assert_eq!(manifest["terminal"]["cleanup_complete"], true);
}
