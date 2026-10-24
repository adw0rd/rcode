use rcode::tools::Tools;
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    process::Command,
};
use tokio_util::sync::CancellationToken;

fn final_reply(text: &str) -> Value {
    json!({"choices":[{"message":{"role":"assistant","content":text},"finish_reason":"stop"}],"usage":{"prompt_tokens":40,"completion_tokens":5}})
}
fn calls(calls: Vec<Value>) -> Value {
    json!({"choices":[{"message":{"role":"assistant","content":null,"tool_calls":calls},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":40,"completion_tokens":5}})
}
fn call(id: &str, name: &str, args: Value) -> Value {
    json!({"id":id,"type":"function","function":{"name":name,"arguments":args.to_string()}})
}
fn reply(request: &Value) -> Value {
    let messages = request["messages"].as_array().unwrap();
    let task = messages
        .iter()
        .find(|message| message["role"] == "user")
        .unwrap()["content"]
        .as_str()
        .unwrap();
    let tools = messages
        .iter()
        .filter(|message| message["role"] == "tool")
        .collect::<Vec<_>>();
    if task.starts_with("WORKER_EDIT") {
        if tools.is_empty() {
            calls(vec![call(
                "worker-read",
                "read_file",
                json!({"path":"target.txt"}),
            )])
        } else if tools.len() == 1 {
            calls(vec![call(
                "worker-edit",
                "edit_file",
                json!({"path":"target.txt","old_text":"user work","new_text":"agent change"}),
            )])
        } else {
            final_reply("WORKER_FINISHED")
        }
    } else if task.starts_with("EXPLORE_READ") {
        if tools.is_empty() {
            calls(vec![call(
                "explorer-read",
                "read_file",
                json!({"path":"README.md"}),
            )])
        } else {
            final_reply("EXPLORER_FINISHED")
        }
    } else if tools.is_empty() {
        calls(vec![
            call(
                "spawn-worker",
                "spawn_agent",
                json!({"task":"WORKER_EDIT: read and edit target.txt", "name":"editor", "role":"worker"}),
            ),
            call(
                "spawn-explorer",
                "spawn_agent",
                json!({"task":"EXPLORE_READ: inspect README.md", "name":"reader", "role":"explorer"}),
            ),
        ])
    } else if tools.iter().any(|message| message["name"] == "wait_agent") {
        final_reply("PARENT_COLLECTED_RESULTS")
    } else {
        // The host must collect outstanding results and request another main step.
        final_reply("PARENT_PREMATURE_FINAL")
    }
}

struct Server {
    url: String,
    requests: Arc<Mutex<Vec<Value>>>,
    cancel: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
}
impl Server {
    async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/v1", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let cancel = CancellationToken::new();
        let stopped = cancel.clone();
        let handle = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = stopped.cancelled() => break,
                    Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                    accepted = listener.accept() => {
                        let (mut stream, _) = accepted.unwrap();
                        let captured = captured.clone();
                        tasks.spawn(async move {
                            let exchange = async {
                                let mut bytes = Vec::new();
                                let split = loop {
                                    let mut chunk = [0;4096];
                                    let count = stream.read(&mut chunk).await.unwrap();
                                    if count == 0 { return; }
                                    bytes.extend_from_slice(&chunk[..count]);
                                    if let Some(index) = bytes.windows(4).position(|part|part == b"\r\n\r\n") { break index+4; }
                                    assert!(bytes.len() < 64*1024);
                                };
                                let headers = String::from_utf8_lossy(&bytes[..split]);
                                let length = headers.lines().filter_map(|line|line.split_once(':'))
                                    .find_map(|(name,value)|name.eq_ignore_ascii_case("content-length").then(||value.trim().parse::<usize>().unwrap())).unwrap();
                                assert!(length < 2*1024*1024);
                                while bytes.len() < split+length {
                                    let mut chunk = [0;4096];
                                    let count = stream.read(&mut chunk).await.unwrap();
                                    if count == 0 { return; }
                                    bytes.extend_from_slice(&chunk[..count]);
                                }
                                let request: Value = serde_json::from_slice(&bytes[split..split+length]).unwrap();
                                let response = reply(&request).to_string();
                                captured.lock().unwrap().push(request);
                                let headers = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",response.len());
                                let _ = stream.write_all(headers.as_bytes()).await;
                                let _ = stream.write_all(response.as_bytes()).await;
                            };
                            let _ = tokio::time::timeout(Duration::from_secs(5),exchange).await;
                        });
                    }
                }
            }
            tasks.shutdown().await;
        });
        Self {
            url,
            requests,
            cancel,
            handle,
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.handle.abort();
    }
}

async fn run(project: &Path, state: &Path, endpoint: &str, allow_edits: bool) -> Vec<Value> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rcode"));
    command
        .env_clear()
        .env("RCODE_HOME", state)
        .env("RCODE_CUSTOM_API_KEY", "agents-cli-fixture-key")
        .args([
            "-C",
            project.to_str().unwrap(),
            "--provider",
            "custom",
            "--model",
            "fixture-model",
            "--base-url",
            endpoint,
            "--json",
            "--max-steps",
            "8",
        ])
        .kill_on_drop(true);
    #[cfg(windows)]
    if let Some(value) = std::env::var_os("SYSTEMROOT") {
        command.env("SYSTEMROOT", value);
    }
    if allow_edits {
        command.args(["--approval-mode", "auto-edit"]);
    }
    command.args(["exec", "PARENT_TASK: delegate editing and reading"]);
    let output = tokio::time::timeout(Duration::from_secs(25), command.output())
        .await
        .expect("CLI/broker deadlock")
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(if allow_edits { 0 } else { 1 }),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("agents-cli-fixture-key"));
    output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect()
}

#[tokio::test]
async fn subagent_edits_share_parent_undo_usage_and_early_final_is_collected() {
    let temporary = tempfile::tempdir().unwrap();
    let project = temporary.path().join("project");
    let state = temporary.path().join("state");
    std::fs::create_dir(&project).unwrap();
    std::fs::write(project.join("target.txt"), "user work\n").unwrap();
    std::fs::write(project.join("README.md"), "project notes\n").unwrap();
    let server = Server::new().await;
    let events = run(&project, &state, &server.url, true).await;
    assert_eq!(
        std::fs::read_to_string(project.join("target.txt")).unwrap(),
        "agent change\n"
    );
    let text = events
        .iter()
        .filter(|event| event["type"] == "text")
        .filter_map(|event| event["text"].as_str())
        .collect::<String>();
    assert!(text.contains("PARENT_COLLECTED_RESULTS"));
    let id = events
        .iter()
        .find(|event| event["type"] == "start")
        .unwrap()["session_id"]
        .as_str()
        .unwrap();
    let session_path = state.join("sessions").join(id);
    let session: Value =
        serde_json::from_slice(&std::fs::read(session_path.join("session.json")).unwrap()).unwrap();
    let agents = session["agents"].as_array().unwrap();
    assert_eq!(agents.len(), 2);
    assert!(agents.iter().all(|agent| agent["status"] == "completed"));
    let request_count = server.requests.lock().unwrap().len() as u64;
    let done = events.iter().find(|event| event["type"] == "done").unwrap();
    assert_eq!(done["input_tokens"], request_count * 40);
    assert_eq!(done["output_tokens"], request_count * 5);
    let mut tools = Tools::new(&project, &session_path.join("checkpoints")).unwrap();
    tools.undo().unwrap();
    assert_eq!(
        std::fs::read_to_string(project.join("target.txt")).unwrap(),
        "user work\n"
    );
}

#[tokio::test]
async fn editing_worker_does_not_bypass_parent_ask_permissions() {
    let temporary = tempfile::tempdir().unwrap();
    let project = temporary.path().join("project");
    let state = temporary.path().join("state");
    std::fs::create_dir(&project).unwrap();
    std::fs::write(project.join("target.txt"), "user work\n").unwrap();
    std::fs::write(project.join("README.md"), "project notes\n").unwrap();
    let server = Server::new().await;
    let events = run(&project, &state, &server.url, false).await;
    assert_eq!(
        std::fs::read_to_string(project.join("target.txt")).unwrap(),
        "user work\n"
    );
    assert!(events.iter().any(|event| {
        event["type"] == "tool_result"
            && event["is_error"] == true
            && event["content"]
                .as_str()
                .unwrap_or_default()
                .contains("denied")
    }));
}
