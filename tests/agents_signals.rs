#![cfg(unix)]

use serde_json::{Value, json};
use std::{path::Path, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    process::Command,
    task::JoinHandle,
};

fn reply(request: &Value) -> Value {
    let messages = request["messages"].as_array().unwrap();
    let task = messages
        .iter()
        .find(|message| message["role"] == "user")
        .unwrap()["content"]
        .as_str()
        .unwrap();
    let has_result = messages.iter().any(|message| message["role"] == "tool");
    let message = if has_result {
        json!({"role":"assistant","content":"Finished"})
    } else {
        let (name, arguments) = if task == "SIGNAL_CHILD" {
            (
                "run_command",
                json!({"command":"sleep 1; printf unexpected > late-mutation.txt"}),
            )
        } else {
            (
                "spawn_agent",
                json!({"task":"SIGNAL_CHILD","role":"worker"}),
            )
        };
        json!({"role":"assistant","content":null,"tool_calls":[{
            "id":"signal-fixture-call","type":"function",
            "function":{"name":name,"arguments":arguments.to_string()}
        }]})
    };
    json!({"choices":[{"message":message,"finish_reason":if has_result {"stop"} else {"tool_calls"}}],
        "usage":{"prompt_tokens":5,"completion_tokens":2}})
}

async fn exchange(mut socket: TcpStream) {
    let mut bytes = Vec::new();
    let split = loop {
        let mut chunk = [0; 4096];
        let count = socket.read(&mut chunk).await.unwrap();
        if count == 0 {
            return;
        }
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break index + 4;
        }
        assert!(bytes.len() < 64 * 1024);
    };
    let headers = String::from_utf8_lossy(&bytes[..split]);
    let length = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find_map(|(name, value)| {
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap();
    assert!(length < 2 * 1024 * 1024);
    while bytes.len() < split + length {
        let mut chunk = [0; 4096];
        let count = socket.read(&mut chunk).await.unwrap();
        if count == 0 {
            return;
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    let request = serde_json::from_slice(&bytes[split..split + length]).unwrap();
    let body = reply(&request).to_string();
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = socket.write_all(header.as_bytes()).await;
    let _ = socket.write_all(body.as_bytes()).await;
}

struct Server {
    url: String,
    task: JoinHandle<()>,
}

impl Server {
    async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/v1", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (socket, _) = accepted.unwrap();
                        connections.spawn(async move {
                            tokio::time::timeout(Duration::from_secs(3), exchange(socket)).await.unwrap();
                        });
                    }
                    Some(result) = connections.join_next(), if !connections.is_empty() => {
                        result.unwrap();
                    }
                }
            }
        });
        Self { url, task }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn interrupt_on_child_tool(
    project: &Path,
    state: &Path,
    endpoint: &str,
) -> (i32, Vec<Value>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rcode"))
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("RCODE_HOME", state)
        .env("RCODE_CUSTOM_API_KEY", "signals-fixture-synthetic-key")
        .args([
            "-C",
            project.to_str().unwrap(),
            "--provider",
            "custom",
            "--model",
            "signals-fixture",
            "--base-url",
            endpoint,
            "--json",
            "--allow-shell",
            "exec",
            "SIGNAL_PARENT",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut stderr = child.stderr.take().unwrap();
    let stderr_task = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).await.unwrap();
        bytes
    });
    let mut sent = false;
    let mut events = Vec::new();
    while let Some(line) = lines.next_line().await.unwrap() {
        let event: Value = serde_json::from_str(&line).expect("Чистый JSONL stdout");
        if !sent && event["type"] == "tool_start" && event["name"] == "run_command" {
            assert!(event["agent_id"].is_string(), "Нужен инструмент ребёнка");
            // Send immediately: yielding or sleeping here would hide the listener gap.
            let pid = child.id().unwrap();
            // SAFETY: pid belongs to our live fixture child, and SIGINT is valid.
            assert_eq!(unsafe { libc::kill(pid as libc::pid_t, libc::SIGINT) }, 0);
            sent = true;
        }
        events.push(event);
    }
    let status = child.wait().await.unwrap();
    let stderr = stderr_task.await.unwrap();
    assert!(sent, "Не получили child tool_start: {events:?}");
    assert!(
        stderr.is_empty(),
        "stderr={}",
        String::from_utf8_lossy(&stderr)
    );
    (status.code().unwrap_or(-1), events)
}

#[tokio::test]
async fn immediate_sigint_cancels_workers_and_persists_usage_without_late_mutations() {
    tokio::time::timeout(Duration::from_secs(18), async {
        let temporary = tempfile::tempdir().unwrap();
        let server = Server::new().await;
        let mut failures = Vec::new();
        let mut projects = Vec::new();
        for attempt in 0..5 {
            let project = temporary.path().join(format!("project-{attempt}"));
            let state = temporary.path().join(format!("state-{attempt}"));
            std::fs::create_dir(&project).unwrap();
            let (code, events) = tokio::time::timeout(
                Duration::from_secs(3),
                interrupt_on_child_tool(&project, &state, &server.url),
            )
            .await
            .expect("SIGINT не должен оставлять CLI/pipe/broker в ожидании");
            let id = events
                .iter()
                .find(|event| event["type"] == "start")
                .unwrap()["session_id"]
                .as_str()
                .unwrap();
            let saved: Value = serde_json::from_slice(
                &std::fs::read(state.join("sessions").join(id).join("session.json")).unwrap(),
            )
            .unwrap();
            let agents = saved["agents"].as_array().unwrap();
            assert_eq!(agents.len(), 1);
            assert!(agents[0]["usage"]["input_tokens"].as_u64().unwrap() >= 5);
            assert!(agents[0]["usage"]["output_tokens"].as_u64().unwrap() >= 2);
            for field in ["input_tokens", "output_tokens"] {
                let emitted: u64 = events
                    .iter()
                    .filter(|event| event["type"] == "usage")
                    .map(|event| event[field].as_u64().unwrap())
                    .sum();
                assert_eq!(
                    saved["usage"][field], emitted,
                    "Usage не потерян при cleanup"
                );
            }
            if code != 130 || agents[0]["status"] != "cancelled" {
                failures.push(format!(
                    "попытка {attempt}: exit={code}, agent={}",
                    agents[0]["status"]
                ));
            }
            let mut pending = std::collections::HashSet::new();
            for message in saved["messages"].as_array().unwrap() {
                for call in message["tool_calls"].as_array().into_iter().flatten() {
                    assert!(pending.insert(call["id"].as_str().unwrap()));
                }
                if message["role"] == "tool" {
                    assert!(pending.remove(message["tool_call_id"].as_str().unwrap()));
                }
            }
            assert!(
                pending.is_empty(),
                "Cleanup должен закрыть прерванные вызовы"
            );
            projects.push(project);
        }
        tokio::time::sleep(Duration::from_millis(1100)).await;
        for project in projects {
            if project.join("late-mutation.txt").exists() {
                failures.push(format!(
                    "поздняя запись после SIGINT: {}",
                    project.display()
                ));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    })
    .await
    .expect("Пять проверок SIGINT должны закончиться за 18 секунд");
}
