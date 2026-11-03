//! Завершение хода: только текст, остановленные workers и точный usage.
//! Локальные HTTP fixtures, без живых API.
mod support;

use serde_json::{Value, json};
#[cfg(unix)]
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::{path::Path, process::Output, time::Duration};
use support::{Response, Server};
use tokio::process::Command;

const KEY: &str = "turn-finish-synthetic-key";

fn tool(name: &str, arguments: Value) -> Response {
    Response::json(
        200,
        json!({"choices":[{"message":{
        "role":"assistant","content":null,"tool_calls":[{
            "id":"finish-call","type":"function",
            "function":{"name":name,"arguments":arguments.to_string()}
        }]
    },"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":20,"completion_tokens":2,"prompt_tokens_details":{"cached_tokens":10}}}),
    )
}

fn summary(text: &str) -> Response {
    Response::json(
        200,
        json!({"choices":[{"message":{"role":"assistant","content":text},"finish_reason":"stop"}],
        "usage":{"prompt_tokens":100,"completion_tokens":5,"prompt_tokens_details":{"cached_tokens":80}}}),
    )
}

fn is_summary(request: &Value) -> bool {
    request["messages"]
        .as_array()
        .unwrap()
        .iter()
        .any(|message| {
            message["role"] == "assistant"
                && message["content"]
                    .as_str()
                    .is_some_and(|text| text.contains("ЛИМИТ ХОДА"))
        })
}

fn command(project: &Path, state: &Path, server: &Server) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rcode"));
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
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
            "1",
            "--approval-mode",
            "auto-edit",
            "exec",
            "PARENT_TASK",
        ])
        .kill_on_drop(true);
    #[cfg(windows)]
    if let Some(value) = std::env::var_os("SYSTEMROOT") {
        command.env("SYSTEMROOT", value);
    }
    command
}

async fn run(project: &Path, state: &Path, server: &Server) -> Output {
    tokio::time::timeout(
        Duration::from_secs(12),
        command(project, state, server).output(),
    )
    .await
    .expect("CLI завершает ход без зависания")
    .unwrap()
}

fn events(output: &Output) -> Vec<Value> {
    output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect()
}

fn saved(state: &Path) -> Value {
    let dir = std::fs::read_dir(state.join("sessions"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    serde_json::from_slice(&std::fs::read(dir.join("session.json")).unwrap()).unwrap()
}

#[tokio::test]
async fn final_summary_accounts_for_cached_tokens_and_sends_no_tools() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    std::fs::create_dir(&project).unwrap();
    let server = Server::start(|request, _| {
        if is_summary(&request.json()) {
            summary("Сделано: просмотрены файлы. Осталось: продолжить.")
        } else {
            tool("list_files", json!({}))
        }
    });
    let output = run(&project, &state, &server).await;
    assert_eq!(output.status.code(), Some(1));
    assert!(
        events(&output)
            .iter()
            .any(|event| event["type"] == "done" && event["summary"] == true)
    );
    let requests = server.generations();
    assert_eq!(requests.len(), 2);
    let request = requests[1].json();
    assert!(request.get("tools").is_none());
    let session = saved(&state);
    assert_eq!(session["usage"]["cached_input_tokens"], 90);
    assert_eq!(session["last_usage"]["cached_input_tokens"], 80);
}

#[tokio::test]
async fn final_tool_call_is_not_saved_executed_or_reported_as_a_summary() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    std::fs::create_dir(&project).unwrap();
    let server = Server::start(|request, _| {
        if is_summary(&request.json()) {
            tool("write_file", json!({"path":"late.txt","content":KEY}))
        } else {
            tool("list_files", json!({}))
        }
    });
    let output = run(&project, &state, &server).await;
    assert_eq!(output.status.code(), Some(1));
    let events = events(&output);
    assert!(events.iter().any(|event| event["type"] == "error"));
    assert!(!events.iter().any(|event| event["type"] == "done"));
    assert!(!project.join("late.txt").exists());
    let session = saved(&state);
    assert!(
        !session.to_string().contains(KEY),
        "Ключ нельзя сохранять даже в отклонённом ответе"
    );
    assert_eq!(
        session["messages"].as_array().unwrap().last().unwrap()["role"],
        "tool"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(KEY));
    assert_eq!(session["usage"]["cached_input_tokens"], 20);
}

#[tokio::test]
async fn empty_final_summary_reports_the_stop_reason_without_a_false_done() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    std::fs::create_dir(&project).unwrap();
    let server = Server::start(|request, _| {
        if is_summary(&request.json()) {
            summary(" \n\t")
        } else {
            tool("list_files", json!({}))
        }
    });
    let output = run(&project, &state, &server).await;
    let events = events(&output);
    assert_eq!(output.status.code(), Some(1));
    assert!(!events.iter().any(|event| event["type"] == "done"));
    assert!(events.iter().any(|event| {
        event["type"] == "error"
            && event["message"]
                .as_str()
                .unwrap()
                .contains("лимит шагов (1)")
    }));
    assert_eq!(saved(&state)["usage"]["cached_input_tokens"], 90);
}

#[tokio::test]
async fn failed_final_request_preserves_the_stop_reason_and_history() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    std::fs::create_dir(&project).unwrap();
    let server = Server::start(|request, _| {
        if is_summary(&request.json()) {
            Response::json(400, json!({"error":{"message":KEY}}))
        } else {
            tool("list_files", json!({}))
        }
    });
    let output = run(&project, &state, &server).await;
    assert_eq!(output.status.code(), Some(1));
    let events = events(&output);
    assert!(!events.iter().any(|event| event["type"] == "done"));
    assert!(events.iter().any(|event| {
        event["type"] == "error"
            && event["message"]
                .as_str()
                .unwrap()
                .contains("лимит шагов (1)")
    }));
    assert_eq!(
        saved(&state)["messages"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()["role"],
        "tool"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(KEY));
}

#[tokio::test]
async fn valid_streamed_summary_redacts_secrets_in_output_and_history() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    std::fs::create_dir(&project).unwrap();
    let server = Server::start(|request, _| {
        if is_summary(&request.json()) {
            Response::sse(&[
                json!({"choices":[{"delta":{"content":"Итог: turn-finish-"}}]}),
                json!({"choices":[{"delta":{"content":"synthetic-key."}}]}),
                json!({"choices":[{"delta":{},"finish_reason":"stop"}]}),
            ])
        } else {
            tool("list_files", json!({}))
        }
    });
    let output = run(&project, &state, &server).await;
    assert_eq!(output.status.code(), Some(1));
    let events = events(&output);
    assert!(
        events
            .iter()
            .any(|event| event["type"] == "done" && event["summary"] == true)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(KEY));
    let session = saved(&state);
    assert!(!session.to_string().contains(KEY));
    assert_eq!(
        session["messages"].as_array().unwrap().last().unwrap()["content"],
        "Итог: [REDACTED]."
    );
}

#[tokio::test]
async fn workers_are_stopped_and_collected_before_the_summary_snapshot() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    std::fs::create_dir(&project).unwrap();
    let server = Server::start(|request, _| {
        let request = request.json();
        if is_summary(&request) {
            // Даём старому broker время исполнить поздний write_file.
            std::thread::sleep(Duration::from_millis(200));
            summary("Субагент остановлен; задача не завершена.")
        } else if request["messages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|message| message["content"] == "WORKER_TASK")
        {
            tool(
                "write_file",
                json!({"path":"late.txt","content":"late worker change"}),
            )
        } else {
            tool("spawn_agent", json!({"task":"WORKER_TASK","role":"worker"}))
        }
    });
    let output = run(&project, &state, &server).await;
    assert_eq!(output.status.code(), Some(1));
    let requests = server.generations();
    let request = requests
        .iter()
        .map(|request| request.json())
        .find(is_summary)
        .unwrap();
    assert!(
        request["messages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|message| {
                message["role"] == "tool"
                    && message["name"] == "wait_agent"
                    && message["content"]
                        .as_str()
                        .is_some_and(|text| text.contains("cancelled"))
            }),
        "Резюме должно видеть окончательное состояние субагента"
    );
    assert!(!project.join("late.txt").exists());
    let events = events(&output);
    let done = events
        .iter()
        .position(|event| event["type"] == "done")
        .unwrap();
    assert!(!events[done + 1..].iter().any(|event| matches!(
        event["type"].as_str(),
        Some("agent_update" | "usage" | "tool_result")
    )));
    let session = saved(&state);
    assert_eq!(session["agents"][0]["status"], "cancelled");
    for field in ["input_tokens", "output_tokens"] {
        assert_eq!(events[done][field], session["usage"][field]);
    }
}

#[cfg(unix)]
#[tokio::test]
async fn sigint_during_final_summary_keeps_exit_130() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    std::fs::create_dir(&project).unwrap();
    let entered = Arc::new(AtomicBool::new(false));
    let signal_ready = entered.clone();
    let server = Server::start(move |request, _| {
        if is_summary(&request.json()) {
            signal_ready.store(true, Ordering::SeqCst);
            summary("Слишком поздний итог").delayed(Duration::from_secs(2))
        } else {
            tool("list_files", json!({}))
        }
    });
    let child = command(&project, &state, &server)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !entered.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Финальный запрос должен начаться");
    assert_eq!(
        unsafe { libc::kill(child.id().unwrap() as i32, libc::SIGINT) },
        0
    );
    let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(130),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        events(&output)
            .iter()
            .any(|event| event["type"] == "error" && event["exit_code"] == 130)
    );
}
