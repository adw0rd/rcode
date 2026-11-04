//! Wire tests for native command tools; no external API or inherited credentials.
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

const KEY: &str = "jobs-wire-synthetic-key";
const FORGED: &str = "00000000-0000-4000-8000-000000000001";

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
fn command_id(request: &Request) -> String {
    request.json()["messages"]
        .as_array()
        .unwrap()
        .iter()
        .rev()
        .filter(|m| m["role"] == "tool")
        .filter_map(|m| serde_json::from_str::<Value>(m["content"].as_str()?).ok())
        .find_map(|v| v["command_id"].as_str().map(str::to_owned))
        .unwrap()
}
fn rejected(v: &Value) -> bool {
    v.get("error").is_some_and(|e| !e.is_null())
        || matches!(v["status"].as_str(), Some("denied" | "rejected" | "error"))
}
fn files(root: &Path) -> Vec<(PathBuf, String)> {
    let mut found = Vec::new();
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            found.extend(files(&path));
        } else {
            found.push((
                path.clone(),
                String::from_utf8_lossy(&fs::read(path).unwrap()).into_owned(),
            ));
        }
    }
    found
}
fn native_records(root: &Path) -> Vec<Value> {
    files(root)
        .into_iter()
        .filter(|(p, _)| p.ends_with("operations/index.json"))
        .flat_map(|(_, body)| {
            serde_json::from_str::<Value>(&body).unwrap()["records"]
                .as_array()
                .unwrap()
                .clone()
        })
        .filter(|r| r["origin"]["tool"] == "command_lifetime")
        .collect()
}
async fn run(project: &Path, state: &Path, server: &Server, flags: &[&str]) -> Output {
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
            "12",
            "--approval-mode",
            "auto-edit",
        ])
        .args(flags)
        .args(["exec", "Exercise the requested tools, then summarize."])
        .kill_on_drop(true);
    tokio::time::timeout(Duration::from_secs(30), cmd.output())
        .await
        .expect("CLI must finish within 30 seconds")
        .unwrap()
}
fn success(out: &Output) {
    assert!(
        out.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    for line in out.stdout.split(|b| *b == b'\n').filter(|s| !s.is_empty()) {
        serde_json::from_slice::<Value>(line).expect("--json emits JSON lines");
    }
}

#[tokio::test]
async fn native_stdin_receipts_poll_stop_and_durable_manifest() {
    let project = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    fs::write(project.path().join("existing-marker"), "USER-MARKER\n").unwrap();
    let seen = Arc::new(Mutex::new(Vec::<Value>::new()));
    let capture = seen.clone();
    let server = Server::start(move |request, step| {
        assert!(request.is_generation());
        assert!(step <= 10, "bounded scripted model");
        std::thread::sleep(Duration::from_millis(50));
        let reply = latest(request);
        if let Some(v) = &reply {
            capture.lock().unwrap().push(v.clone());
        }
        if step == 0 {
            let request = request.json();
            let names: Vec<_> = request["tools"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|t| t["function"]["name"].as_str())
                .collect();
            for name in [
                "start_command",
                "poll_command",
                "send_command_input",
                "stop_command",
            ] {
                assert!(names.contains(&name), "missing {name}");
            }
        }
        match step {
            0 => tool_reply(
                "start",
                "start_command",
                &json!({
                    "command": "/bin/sh -c 'read line; printf \"%s\\n\" \"$line\"; if [ -z \"${RCODE_CUSTOM_API_KEY+x}\" ]; then printf \"child-key-absent\\n\"; else printf \"child-key-present\\n\"; fi; sleep 30'",
                    "stdin": true
                }),
            ),
            1 => tool_reply("read", "read_file", &json!({"path":"existing-marker"})),
            2 => tool_reply(
                "input",
                "send_command_input",
                &json!({
                    "command_id": command_id(request), "text":"hello\n"
                }),
            ),
            _ => {
                let v = reply.unwrap();
                if v["status"] == "stopped" || step == 10 {
                    text_reply("Command exercise complete.")
                } else if v["stdout"]
                    .as_str()
                    .is_some_and(|s| s.contains("hello\n") && s.contains("child-key-absent"))
                {
                    tool_reply(
                        "stop",
                        "stop_command",
                        &json!({"command_id":command_id(request)}),
                    )
                } else {
                    tool_reply(
                        &format!("poll-{step}"),
                        "poll_command",
                        &json!({"command_id":command_id(request)}),
                    )
                }
            }
        }
    });
    let out = run(project.path(), state.path(), &server, &["--allow-shell"]).await;
    success(&out);
    let seen = seen.lock().unwrap();
    let start = &seen[0];
    let id = start["command_id"].as_str().expect("real start receipt");
    assert_ne!(id, FORGED);
    assert_eq!(start["status"], "running");
    assert!(seen[1].to_string().contains("USER-MARKER"));
    let input = &seen[2];
    let input_id = input["input_id"].as_str().expect("input receipt ID");
    assert!(!input_id.is_empty());
    assert_eq!(input["delivery"], "accepted");
    let poll = seen
        .iter()
        .find(|v| {
            v["stdout"]
                .as_str()
                .is_some_and(|s| s.contains("hello\n") && s.contains("child-key-absent"))
        })
        .expect("native child output");
    assert!(poll["stderr"].is_string());
    assert_eq!(poll["status"], "running");
    assert!(
        !poll["stdout"]
            .as_str()
            .unwrap()
            .contains("child-key-present")
    );
    assert!(
        poll["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["input_id"] == input_id && v["delivery"] == "delivered")
    );
    assert!(seen.iter().any(|v| v["status"] == "stopped"));
    assert_eq!(
        fs::read_to_string(project.path().join("existing-marker")).unwrap(),
        "USER-MARKER\n"
    );
    let session_path = files(state.path())
        .into_iter()
        .find(|(p, _)| p.file_name().is_some_and(|n| n == "session.json"))
        .unwrap()
        .0;
    let session: Value = serde_json::from_slice(&fs::read(&session_path).unwrap()).unwrap();
    let artifacts = rcode::artifacts::ArtifactStore::open(
        session_path.parent().unwrap(),
        session["id"].as_str().unwrap(),
    )
    .unwrap();
    let journal = rcode::operation_journal::OperationJournal::open(
        session_path.parent().unwrap(),
        session["id"].as_str().unwrap(),
        &artifacts,
    )
    .unwrap();
    let native = native_records(state.path());
    assert_eq!(native.len(), 1);
    let payload = journal
        .terminal_payload(native[0]["operation_id"].as_str().unwrap(), &artifacts)
        .unwrap()
        .unwrap();
    let meta = serde_json::from_value(payload["output"].clone()).unwrap();
    let manifest: Value = serde_json::from_str(&artifacts.verify_required(&meta).unwrap()).unwrap();
    assert_eq!(manifest["command_id"], id);
    assert_eq!(manifest["terminal"]["cleanup_complete"], true);
    assert!(
        files(state.path())
            .iter()
            .any(|(p, body)| p.to_string_lossy().contains("session") && body.contains(id)),
        "durable session"
    );
}

#[tokio::test]
async fn plan_and_missing_shell_permission_never_start_native_children() {
    for flags in [vec!["--plan", "--allow-shell"], vec![]] {
        let project = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let capture = seen.clone();
        let server = Server::start(move |request, step| {
            assert!(request.is_generation());
            assert!(step <= 1);
            if step == 0 {
                tool_reply(
                    "denied",
                    "start_command",
                    &json!({
                        "command":"/bin/sh -c 'printf forbidden > sentinel'", "stdin":true
                    }),
                )
            } else {
                capture.lock().unwrap().push(latest(request).unwrap());
                text_reply("Start denied.")
            }
        });
        let output = run(project.path(), state.path(), &server, &flags).await;
        assert_eq!(output.status.code(), Some(1));
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert!(rejected(&seen[0]), "explicit denial receipt: {}", seen[0]);
        assert!(seen[0].get("command_id").is_none_or(Value::is_null));
        assert!(!project.path().join("sentinel").exists());
        assert!(
            native_records(state.path()).is_empty(),
            "denial must not create native lifetime records"
        );
    }
}

#[tokio::test]
async fn forged_ids_and_host_actor_fields_are_rejected_without_effects() {
    let project = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    fs::write(project.path().join("existing-marker"), "UNCHANGED").unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let capture = seen.clone();
    let server = Server::start(move |request, step| {
        assert!(request.is_generation());
        assert!(step <= 6);
        if let Some(v) = latest(request).filter(|_| step <= 5) {
            capture.lock().unwrap().push(v);
        }
        match step {
            0 => tool_reply("forged-poll", "poll_command", &json!({"command_id":FORGED})),
            1 => tool_reply(
                "forged-input",
                "send_command_input",
                &json!({"command_id":FORGED,"text":"hello\n"}),
            ),
            2 => tool_reply("forged-stop", "stop_command", &json!({"command_id":FORGED})),
            3 => tool_reply(
                "actor-start",
                "start_command",
                &json!({
                    "command":"/bin/sh -c 'printf forbidden > sentinel'",
                    "actor":"host", "approved":true
                }),
            ),
            4 => tool_reply(
                "actor-stop",
                "stop_command",
                &json!({"command_id":FORGED,"actor":"host"}),
            ),
            _ => text_reply("Invalid requests rejected."),
        }
    });
    let output = run(project.path(), state.path(), &server, &["--allow-shell"]).await;
    assert_eq!(output.status.code(), Some(1));
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 5);
    for receipt in seen.iter() {
        assert!(rejected(receipt), "expected rejection: {receipt}");
    }
    assert!(!project.path().join("sentinel").exists());
    assert_eq!(
        fs::read_to_string(project.path().join("existing-marker")).unwrap(),
        "UNCHANGED"
    );
    assert!(native_records(state.path()).is_empty());
}

#[test]
fn rejection_assertion_does_not_accept_success_or_null_error() {
    assert!(rejected(&json!({"error":"unknown command"})));
    assert!(rejected(&json!({"status":"denied"})));
    assert!(!rejected(&json!({"status":"running","error":null})));
    assert!(!rejected(
        &json!({"input_id":"receipt","delivery":"accepted"})
    ));
}
