//! Wire tests for automatic cleanup of native command lifetimes.
#![cfg(any(target_os = "linux", target_os = "macos"))]
mod support;

use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Output,
    sync::{Arc, Mutex},
    time::Duration,
};
use support::{Request, Server, text_reply, tool_reply};
use tokio::process::Command;

const KEY: &str = "jobs-cleanup-synthetic-key";

fn latest(request: &Request) -> Option<Value> {
    request.json()["messages"]
        .as_array()?
        .iter()
        .rev()
        .find(|m| m["role"] == "tool")
        .map(|m| {
            serde_json::from_str(m["content"].as_str().unwrap())
                .unwrap_or_else(|_| m["content"].clone())
        })
}

fn files(root: &Path) -> Vec<(PathBuf, String)> {
    let mut found = Vec::new();
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            found.extend(files(&path));
        } else {
            found.push((path.clone(), fs::read_to_string(path).unwrap_or_default()));
        }
    }
    found
}

fn native_records(root: &Path) -> Vec<Value> {
    files(root)
        .into_iter()
        .filter(|(path, _)| path.ends_with("operations/index.json"))
        .flat_map(|(_, body)| {
            serde_json::from_str::<Value>(&body).unwrap()["records"]
                .as_array()
                .unwrap()
                .clone()
        })
        .filter(|record| record["origin"]["tool"] == "command_lifetime")
        .collect()
}

async fn run(project: &Path, state: &Path, server: &Server) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rcode"));
    cmd.env_clear()
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
            "--allow-shell",
            "exec",
            "Exercise the command and summarize.",
        ])
        .kill_on_drop(true);
    tokio::time::timeout(Duration::from_secs(30), cmd.output())
        .await
        .expect("CLI must finish within 30 seconds")
        .unwrap()
}

fn assert_json_output(output: &Output) -> Vec<Value> {
    assert!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).expect("--json emits JSON lines"))
        .collect()
}

fn session_artifacts(
    state: &Path,
) -> (
    rcode::artifacts::ArtifactStore,
    rcode::operation_journal::OperationJournal,
) {
    let session_path = files(state)
        .into_iter()
        .find(|(path, _)| path.file_name().is_some_and(|name| name == "session.json"))
        .expect("session metadata is persisted")
        .0;
    let session: Value = serde_json::from_slice(&fs::read(&session_path).unwrap()).unwrap();
    let session_dir = session_path.parent().unwrap();
    let session_id = session["id"].as_str().unwrap();
    let artifacts = rcode::artifacts::ArtifactStore::open(session_dir, session_id).unwrap();
    let journal =
        rcode::operation_journal::OperationJournal::open(session_dir, session_id, &artifacts)
            .unwrap();
    (artifacts, journal)
}

#[cfg(unix)]
fn pid_is_live(pid: i32) -> bool {
    unsafe extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }
    // Signal zero checks process existence without sending a signal.
    unsafe { kill(pid, 0) == 0 }
}

#[tokio::test]
async fn final_reply_follows_cleanup_of_unstopped_command() {
    let project = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let pid_file = project.path().join("child.pid");
    let pid_marker = pid_file.clone();
    let seen = Arc::new(Mutex::new(Vec::<Value>::new()));
    let capture = seen.clone();
    let server = Server::start(move |request, step| {
        assert!(request.is_generation());
        if let Some(reply) = latest(request) {
            capture.lock().unwrap().push(reply);
        }
        match step {
            0 => tool_reply(
                "start",
                "start_command",
                &json!({
                    "command": "echo $$ > child.pid; sleep 30",
                    "stdin": false
                }),
            ),
            _ => {
                for _ in 0..100 {
                    if pid_marker.exists() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                text_reply("Command started.")
            }
        }
    });

    let output = run(project.path(), state.path(), &server).await;
    let events = assert_json_output(&output);
    let replies = seen.lock().unwrap();
    let start = replies.first().expect("start command result was observed");
    let id = start["command_id"].as_str().expect("real command ID");
    assert_eq!(start["status"], "running");

    let pid: i32 = fs::read_to_string(&pid_file)
        .expect("child wrote its PID marker")
        .trim()
        .parse()
        .unwrap();
    assert!(
        !pid_is_live(pid),
        "CLI must reap/stop the child before exit"
    );

    let records = native_records(state.path());
    assert_eq!(records.len(), 1);
    let (artifacts, journal) = session_artifacts(state.path());
    let payload = journal
        .terminal_payload(records[0]["operation_id"].as_str().unwrap(), &artifacts)
        .unwrap()
        .expect("command lifetime has a committed terminal payload");
    let meta: rcode::artifacts::ArtifactMeta =
        serde_json::from_value(payload["output"].clone()).unwrap();
    let manifest: Value = serde_json::from_str(&artifacts.verify_required(&meta).unwrap()).unwrap();
    assert_eq!(manifest["command_id"], id);
    assert_eq!(manifest["terminal"]["cleanup_complete"], true);

    let final_index = events
        .iter()
        .rposition(|event| {
            event["type"] == "done"
                || event["type"] == "final_done"
                || event["event"] == "done"
                || event["event"] == "final_done"
        })
        .expect("JSON stream contains the final-done event");
    assert_eq!(final_index, events.len() - 1, "final-done is emitted last");
}

#[tokio::test]
async fn naturally_finished_command_is_persisted_before_final_reply_without_polling() {
    let project = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let state_for_handler = state.path().to_path_buf();
    let inspected = Arc::new(Mutex::new(false));
    let observed = inspected.clone();
    let server = Server::start(move |request, step| {
        assert!(request.is_generation());
        match step {
            0 => tool_reply(
                "start",
                "start_command",
                &json!({"command":"/bin/sh -c 'sleep 0.1; printf done'", "stdin":false}),
            ),
            1 => {
                // The start-result reply is present in this generation. Allow the
                // background lifecycle ticker to observe natural process exit.
                std::thread::sleep(Duration::from_millis(750));
                let records = native_records(&state_for_handler);
                assert_eq!(
                    records.len(),
                    1,
                    "lifetime record must be indexed before reply"
                );
                let record = &records[0];
                assert!(
                    record["terminal"].is_object()
                        || record["terminal"].is_string()
                        || matches!(
                            record["status"].as_str(),
                            Some("committed" | "completed" | "terminal")
                        ),
                    "lifetime must be terminal in operations index before final reply: {record}"
                );
                *observed.lock().unwrap() = true;
                text_reply("The command completed naturally.")
            }
            _ => panic!("fixture must not require polling"),
        }
    });

    let output = run(project.path(), state.path(), &server).await;
    assert_json_output(&output);
    assert!(
        *inspected.lock().unwrap(),
        "server inspected index before final reply"
    );
    assert_eq!(native_records(state.path()).len(), 1);
}
