//! Integration coverage for persisted command polling across a real CLI restart.
#![cfg(any(target_os = "linux", target_os = "macos"))]
mod support;

use serde_json::{Value, json};
use std::{
    fs,
    path::Path,
    process::Output,
    sync::{Arc, Mutex},
    time::Duration,
};
use support::{Request, Server, text_reply, tool_reply};
use tokio::process::Command;

const KEY: &str = "persisted-poll-synthetic-key";

fn latest(request: &Request) -> Option<Value> {
    request.json()["messages"]
        .as_array()?
        .iter()
        .rev()
        .find(|message| message["role"] == "tool")
        .map(|message| {
            let content = message["content"].as_str().unwrap_or_default();
            serde_json::from_str(content).unwrap_or_else(|_| Value::String(content.to_owned()))
        })
}

async fn run(project: &Path, state: &Path, server: &Server, flags: &[&str]) -> Output {
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
            "8",
            "--approval-mode",
            "auto-edit",
        ])
        .args(flags)
        .args(["exec", "Poll the persisted command and report its output."])
        .kill_on_drop(true);
    tokio::time::timeout(Duration::from_secs(30), command.output())
        .await
        .expect("CLI must finish within 30 seconds")
        .unwrap()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "CLI failed with {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[tokio::test]
async fn persisted_command_can_be_polled_after_cli_restart() {
    let project = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let executions = project.path().join("executions");
    let captured_id = Arc::new(Mutex::new(None::<String>));
    let first_capture = captured_id.clone();

    let first_server = Server::start(move |request, step| {
        assert!(request.is_generation());
        assert!(step <= 1, "first CLI script is bounded");
        match step {
            0 => tool_reply(
                "start-command",
                "start_command",
                &json!({
                    "command": "printf x >> executions; printf FIRSTSECOND"
                }),
            ),
            1 => {
                let receipt = latest(request).expect("latest tool content contains start receipt");
                let id = receipt["command_id"]
                    .as_str()
                    .expect("start receipt contains the real command ID")
                    .to_owned();
                *first_capture.lock().unwrap() = Some(id);
                std::thread::sleep(Duration::from_millis(750));
                text_reply("Command started; polling will continue after restart.")
            }
            _ => unreachable!(),
        }
    });

    let first_output = run(
        project.path(),
        state.path(),
        &first_server,
        &["--allow-shell"],
    )
    .await;
    assert_success(&first_output);
    let command_id = captured_id
        .lock()
        .unwrap()
        .clone()
        .expect("first CLI captured the command ID");

    let second_id = command_id.clone();
    let second_server = Server::start(move |request, step| {
        assert!(request.is_generation());
        assert!(step <= 3, "second CLI script is bounded");
        match step {
            0 => tool_reply(
                "poll-first",
                "poll_command",
                &json!({"command_id": second_id, "max_bytes": 5}),
            ),
            1 => {
                let result = latest(request).expect("first poll result");
                assert_eq!(result["persisted"], true);
                assert_eq!(result["stdout"], "FIRST");
                assert_eq!(result["next_stdout_offset"], 5);
                assert_eq!(result["payload_unavailable"], false);
                assert_eq!(result["status"], "exited");
                tool_reply(
                    "poll-second",
                    "poll_command",
                    &json!({"command_id": second_id, "stdout_offset": 5, "max_bytes": 4}),
                )
            }
            2 => {
                let result = latest(request).expect("second poll result");
                assert_eq!(result["persisted"], true);
                assert_eq!(result["stdout"], "SECO");
                assert_eq!(result["next_stdout_offset"], 9);
                tool_reply(
                    "poll-third",
                    "poll_command",
                    &json!({"command_id": second_id, "stdout_offset": 9, "max_bytes": 4}),
                )
            }
            3 => {
                let result = latest(request).expect("third poll result");
                assert_eq!(result["persisted"], true);
                assert_eq!(result["stdout"], "ND");
                assert_eq!(result["next_stdout_offset"], 11);
                text_reply("Persisted command output was recovered.")
            }
            _ => unreachable!(),
        }
    });

    let second_output = run(
        project.path(),
        state.path(),
        &second_server,
        &["--resume", "latest"],
    )
    .await;
    assert_success(&second_output);
    // Persist an admitted intent with no native start. Recovery must never replay it.
    let session_id = String::from_utf8_lossy(&second_output.stdout)
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .find(|event| event["type"] == "start")
        .unwrap()["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let pending_id = "11111111-1111-4111-8111-111111111111";
    {
        let store = rcode::config::ConfigStore::at(state.path().to_path_buf()).unwrap();
        let mut session = rcode::state::Session::load(&store, &session_id, project.path()).unwrap();
        let artifacts =
            rcode::artifacts::ArtifactStore::open(&session.dir(&store), &session.id).unwrap();
        let mut journal = rcode::operation_journal::OperationJournal::open(
            &session.dir(&store),
            &session.id,
            &artifacts,
        )
        .unwrap();
        let args = json!({"command_id":pending_id,"origin":{"actor":null,"turn":session.turn_index},
            "arguments":{"command":"printf REPLAYED >> executions"}});
        rcode::operation_receipts::begin_background(
            &mut journal,
            &artifacts,
            &mut session,
            &store,
            &rcode::protocol::ToolCall::new("command_lifetime", args.clone()),
            None,
            &args,
            &[],
        )
        .unwrap();
    }
    let old_id = command_id;
    let rejected = Arc::new(Mutex::new(Vec::new()));
    let captured = rejected.clone();
    let third_server = Server::start(move |request, step| {
        assert!(step <= 5);
        if step > 0 && step <= 4 {
            let result = latest(request).unwrap();
            assert_eq!(result["error"], "command_failed");
            assert!(
                result["message"]
                    .as_str()
                    .unwrap()
                    .contains("job not found")
            );
            captured.lock().unwrap().push(result);
        }
        match step {
            0 => tool_reply(
                "no-adopt-input",
                "send_command_input",
                &json!({"command_id":old_id,"text":"printf REPLAYED >> executions\n"}),
            ),
            1 => tool_reply(
                "no-adopt-stop",
                "stop_command",
                &json!({"command_id":old_id}),
            ),
            2 => tool_reply(
                "no-replay-pending",
                "poll_command",
                &json!({"command_id":pending_id}),
            ),
            3 => tool_reply(
                "no-adopt-missing",
                "poll_command",
                &json!({"command_id":"22222222-2222-4222-8222-222222222222"}),
            ),
            _ => text_reply("Process ownership was not restored; no action was retried."),
        }
    });
    let denied_output = run(
        project.path(),
        state.path(),
        &third_server,
        &["--resume", "latest", "--allow-shell"],
    )
    .await;
    assert_eq!(
        denied_output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&denied_output.stdout)
    );
    assert_eq!(rejected.lock().unwrap().len(), 4);
    assert_eq!(
        fs::read_to_string(executions).unwrap(),
        "x",
        "resuming and polling must not execute the command again"
    );
}
