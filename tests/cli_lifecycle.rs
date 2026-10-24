use serde_json::{Value, json};
use std::{
    fs,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const API_KEY: &str = "lifecycle-selected-api-secret";
const SERVER_TIMEOUT: Duration = Duration::from_secs(8);
const PROCESS_TIMEOUT: Duration = Duration::from_secs(12);

struct Reply {
    status: u16,
    content_type: &'static str,
    body: String,
    advertised_length: Option<usize>,
}

impl Reply {
    fn json(value: Value) -> Self {
        Self::raw(200, "application/json", value.to_string())
    }

    fn raw(status: u16, content_type: &'static str, body: impl Into<String>) -> Self {
        Self {
            status,
            content_type,
            body: body.into(),
            advertised_length: None,
        }
    }
}

struct Server {
    url: String,
    stopped: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<Result<Vec<Value>, String>>>,
}

impl Server {
    fn start(replies: Vec<Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/v1", listener.local_addr().unwrap());
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = stopped.clone();
        let handle = thread::spawn(move || {
            let deadline = Instant::now() + SERVER_TIMEOUT;
            let mut requests = Vec::new();
            for reply in replies {
                let mut socket = loop {
                    if stop.load(Ordering::Relaxed) || Instant::now() >= deadline {
                        return Err(format!(
                            "mock expected another request after {} requests",
                            requests.len()
                        ));
                    }
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => return Err(format!("mock accept failed: {error}")),
                    }
                };
                // Accepted sockets can inherit O_NONBLOCK on macOS.
                socket
                    .set_nonblocking(false)
                    .map_err(|error| error.to_string())?;
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .map_err(|error| error.to_string())?;
                socket
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .map_err(|error| error.to_string())?;
                requests
                    .push(read_request(&mut socket, deadline).map_err(|error| error.to_string())?);
                let length = reply.advertised_length.unwrap_or(reply.body.len());
                write!(socket,
                    "HTTP/1.1 {} Test Response\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    reply.status, reply.content_type, length, reply.body
                ).map_err(|error| error.to_string())?;
            }
            Ok(requests)
        });
        Self {
            url,
            stopped,
            handle: Some(handle),
        }
    }

    fn finish(mut self) -> Vec<Value> {
        self.handle
            .take()
            .unwrap()
            .join()
            .expect("mock server panicked")
            .expect("mock server failed")
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn read_before_deadline(
    socket: &mut TcpStream,
    buffer: &mut [u8],
    deadline: Instant,
) -> io::Result<usize> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "mock request deadline exceeded"))?;
    socket.set_read_timeout(Some(remaining.min(Duration::from_secs(2))))?;
    socket.read(buffer)
}

fn read_request(socket: &mut TcpStream, deadline: Instant) -> io::Result<Value> {
    let mut bytes = Vec::new();
    let header_end = loop {
        let mut buffer = [0_u8; 4096];
        let count = read_before_deadline(socket, &mut buffer, deadline)?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "request header ended early",
            ));
        }
        bytes.extend_from_slice(&buffer[..count]);
        if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break index + 4;
        }
        if bytes.len() > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request header too large",
            ));
        }
    };
    let header = String::from_utf8_lossy(&bytes[..header_end]);
    let length = header
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find_map(|(name, value)| {
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>())
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing content length"))?
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if length > 2 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "request body too large",
        ));
    }
    while bytes.len() < header_end + length {
        let mut buffer = [0_u8; 4096];
        let count = read_before_deadline(socket, &mut buffer, deadline)?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "request body ended early",
            ));
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    serde_json::from_slice(&bytes[header_end..header_end + length])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

struct Fixture {
    _temporary: tempfile::TempDir,
    project: PathBuf,
    home: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let project = temporary.path().join("project");
        let home = temporary.path().join("rcode-home");
        fs::create_dir(&project).unwrap();
        Self {
            _temporary: temporary,
            project,
            home,
        }
    }

    fn run(&self, endpoint: &str, extra: &[&str]) -> Output {
        self.run_with_env(endpoint, extra, &[])
    }

    fn run_with_env(&self, endpoint: &str, extra: &[&str], environment: &[(&str, &str)]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rcode"));
        command
            .env_clear()
            .env("RCODE_HOME", &self.home)
            .env("RCODE_CUSTOM_API_KEY", API_KEY)
            .args([
                "-C",
                self.project.to_str().unwrap(),
                "--provider",
                "custom",
                "--model",
                "fixture-model",
                "--base-url",
                endpoint,
            ])
            .args(extra)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (name, value) in environment {
            command.env(name, value);
        }
        #[cfg(unix)]
        command.env("PATH", "/usr/bin:/bin");
        #[cfg(windows)]
        for name in ["SYSTEMROOT", "COMSPEC", "PATH", "PATHEXT"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        let mut child = command.spawn().unwrap();
        let deadline = Instant::now() + PROCESS_TIMEOUT;
        loop {
            if child.try_wait().unwrap().is_some() {
                return child.wait_with_output().unwrap();
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "CLI exceeded test timeout; stderr: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn session_path(&self, id: &str) -> PathBuf {
        self.home.join("sessions").join(id).join("session.json")
    }
}

fn final_reply(text: &str) -> Reply {
    Reply::json(
        json!({"choices":[{"message":{"role":"assistant","content":text},"finish_reason":"stop"}]}),
    )
}

fn call(id: &str, name: &str, arguments: Value) -> Value {
    json!({"id":id,"type":"function","function":{"name":name,"arguments":arguments.to_string()}})
}

fn tool_reply(calls: Vec<Value>) -> Reply {
    Reply::json(
        json!({"choices":[{"message":{"role":"assistant","content":null,"tool_calls":calls},"finish_reason":"tool_calls"}]}),
    )
}

fn events(output: &Output, code: i32) -> Vec<Value> {
    assert_eq!(
        output.status.code(),
        Some(code),
        "stderr: {}\nstdout: {}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    let events: Vec<Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(line).expect("stdout must contain only JSONL"))
        .collect();
    assert!(!events.is_empty());
    assert!(events.iter().all(|event| event["version"] == 1));
    assert!(!stdout.contains(API_KEY));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(API_KEY));
    events
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

#[test]
fn failed_command_gets_one_recovery_step_before_the_agent_stops() {
    let fixture = Fixture::new();
    let server = Server::start(vec![
        tool_reply(vec![call(
            "missing-command",
            "run_command",
            json!({"command":"rcode_fixture_missing_executable_78234"}),
        )]),
        final_reply("Команда не найдена. Проверьте окружение самостоятельно."),
        tool_reply(vec![call(
            "recovery-command",
            "run_command",
            json!({"command":"printf recovered"}),
        )]),
        final_reply("Готово"),
    ]);
    let output = fixture.run(
        &server.url,
        &[
            "--allow-shell",
            "exec",
            "--json",
            "Выполни задачу, исправляя ошибки окружения самостоятельно",
        ],
    );
    let captured = events(&output, 0);
    let requests = server.finish();
    assert_eq!(
        requests.len(),
        4,
        "Ранний ответ после сбоя не должен завершать агентный цикл"
    );
    assert!(captured.iter().any(|event| {
        event["type"] == "tool_result"
            && event["content"]
                .as_str()
                .unwrap_or_default()
                .contains("recovered")
    }));
}

#[test]
fn unresolved_tool_failure_is_incomplete_after_bounded_recovery() {
    let fixture = Fixture::new();
    let server = Server::start(vec![
        tool_reply(vec![call(
            "missing-command",
            "run_command",
            json!({"command":"rcode_fixture_missing_executable_78234"}),
        )]),
        final_reply("Не смог выполнить команду"),
        final_reply("По-прежнему не смог выполнить задачу"),
    ]);
    let output = fixture.run(
        &server.url,
        &["--allow-shell", "exec", "--json", "Выполни задачу"],
    );
    let captured = events(&output, 1);
    assert_eq!(server.finish().len(), 3);
    assert_eq!(
        captured
            .iter()
            .find(|event| event["type"] == "done")
            .unwrap()["exit_code"],
        1
    );
}

#[test]
fn corrected_agent_argument_error_is_not_a_permanent_permission_denial() {
    let fixture = Fixture::new();
    fs::write(fixture.project.join("notes.txt"), "actual project notes").unwrap();
    let server = Server::start(vec![
        tool_reply(vec![call(
            "bad-id",
            "wait_agent",
            json!({"agent_id":"nonexistent"}),
        )]),
        tool_reply(vec![call(
            "actual-read",
            "read_file",
            json!({"path":"notes.txt"}),
        )]),
        final_reply("Заметки прочитаны"),
    ]);
    let output = fixture.run(&server.url, &["exec", "--json", "Прочитай заметки проекта"]);
    let captured = events(&output, 0);
    assert_eq!(server.finish().len(), 3);
    assert!(captured.iter().any(|event| event["type"] == "tool_result"
        && event["name"] == "wait_agent"
        && event["is_error"] == true));
    assert!(captured.iter().any(|event| event["type"] == "tool_result"
        && event["name"] == "read_file"
        && event["is_error"] == false));
}

#[test]
fn textual_tool_markers_are_not_executed_or_reported_as_completed() {
    let fixture = Fixture::new();
    let server = Server::start(vec![final_reply(
        "[TOOL_CALL_START]run_command\n{\"command\":\"printf unsafe > must-not-exist.txt\"}",
    )]);
    let output = fixture.run(
        &server.url,
        &["--allow-shell", "exec", "--json", "Создай файл"],
    );
    let captured = events(&output, 4);
    assert_eq!(server.finish().len(), 1);
    assert!(!fixture.project.join("must-not-exist.txt").exists());
    assert!(
        !captured
            .iter()
            .any(|event| event["type"] == "tool_start" || event["type"] == "done")
    );
}

#[test]
fn max_steps_exhaustion_preserves_completed_tool_result_and_exits_one() {
    let fixture = Fixture::new();
    fs::write(fixture.project.join("input.txt"), "readable input").unwrap();
    let server = Server::start(vec![tool_reply(vec![call(
        "read-once",
        "read_file",
        json!({"path":"input.txt"}),
    )])]);
    let output = fixture.run(
        &server.url,
        &[
            "--max-steps",
            "1",
            "exec",
            "--json",
            "Прочитай файл и продолжи",
        ],
    );
    let events = events(&output, 1);
    assert_eq!(events.last().unwrap()["type"], "error");
    assert_eq!(events.last().unwrap()["exit_code"], 1);
    assert!(!events.iter().any(|event| event["type"] == "done"));
    let result = events
        .iter()
        .find(|event| event["type"] == "tool_result")
        .unwrap();
    assert_eq!(result["is_error"], false);
    let id = events
        .iter()
        .find(|event| event["type"] == "start")
        .unwrap()["session_id"]
        .as_str()
        .unwrap();
    let session = read_json(&fixture.session_path(id));
    assert_eq!(
        session["messages"].as_array().unwrap().last().unwrap()["tool_call_id"],
        "read-once"
    );
    assert_eq!(server.finish().len(), 1);
}

#[test]
fn plan_mode_denies_write_and_shell_even_when_other_flags_allow_them() {
    let fixture = Fixture::new();
    let server = Server::start(vec![
        tool_reply(vec![
            call(
                "plan-write",
                "write_file",
                json!({"path":"written.txt","content":"forbidden"}),
            ),
            call(
                "plan-shell",
                "run_command",
                json!({"command":"printf forbidden > shell.txt","timeout_secs":3}),
            ),
        ]),
        final_reply("Для применения плана требуется отдельный запуск."),
    ]);
    let output = fixture.run(
        &server.url,
        &[
            "--plan",
            "--allow-shell",
            "--approval-mode",
            "auto-edit",
            "exec",
            "--json",
            "Только составь план",
        ],
    );
    let events = events(&output, 1);
    assert!(!fixture.project.join("written.txt").exists());
    assert!(!fixture.project.join("shell.txt").exists());
    let results: Vec<_> = events
        .iter()
        .filter(|event| event["type"] == "tool_result")
        .collect();
    assert_eq!(results.len(), 2);
    assert!(
        results.iter().all(|event| event["is_error"] == true
            && event["content"].as_str().unwrap().contains("denied"))
    );
    let requests = server.finish();
    let names: Vec<_> = requests[0]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["function"]["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"read_file"));
    assert!(
        !names
            .iter()
            .any(|name| matches!(*name, "write_file" | "edit_file" | "run_command"))
    );
    assert_eq!(
        requests[1]["messages"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|message| message["role"] == "tool")
            .count(),
        2
    );
}

#[cfg(unix)]
#[test]
fn allowed_shell_runs_without_api_credentials_in_child_environment() {
    let fixture = Fixture::new();
    let server = Server::start(vec![
        tool_reply(vec![call(
            "shell-env",
            "run_command",
            json!({"command":"printf executed > shell-ran.txt; /usr/bin/env","timeout_secs":3}),
        )]),
        final_reply("Команда выполнена."),
    ]);
    let credentials = [
        ("OPENAI_API_KEY", "lifecycle-openai-secret"),
        ("OPENROUTER_API_KEY", "lifecycle-router-secret"),
        ("RCODE_OPENROUTER_API_KEY", "lifecycle-rcode-router-secret"),
        ("YANDEX_API_KEY", "lifecycle-yandex-secret"),
        ("RCODE_YANDEX_API_KEY", "lifecycle-rcode-yandex-secret"),
        ("YANDEX_IAM_TOKEN", "lifecycle-iam-secret"),
        ("GIGACHAT_AUTH_KEY", "lifecycle-giga-secret"),
        ("RCODE_GIGACHAT_AUTH_KEY", "lifecycle-rcode-giga-secret"),
        ("GIGACHAT_CREDENTIALS", "lifecycle-giga-credentials-secret"),
    ];
    let output = fixture.run_with_env(
        &server.url,
        &[
            "--allow-shell",
            "exec",
            "--json",
            "Проверь окружение команды",
        ],
        &credentials,
    );
    let events = events(&output, 0);
    assert_eq!(
        fs::read_to_string(fixture.project.join("shell-ran.txt")).unwrap(),
        "executed"
    );
    let result = events
        .iter()
        .find(|event| event["type"] == "tool_result")
        .unwrap();
    assert_eq!(result["is_error"], false);
    let content: Value = serde_json::from_str(result["content"].as_str().unwrap()).unwrap();
    assert_eq!(content["exit_code"], 0);
    let environment = content["stdout"].as_str().unwrap();
    assert!(environment.lines().any(|line| line.starts_with("PATH=")));
    assert!(environment.lines().any(|line| line.starts_with("PWD=")));
    for (name, secret) in credentials
        .into_iter()
        .chain([("RCODE_CUSTOM_API_KEY", API_KEY)])
    {
        assert!(
            !environment
                .lines()
                .any(|line| line.starts_with(&format!("{name}="))),
            "shell inherited {name}"
        );
        assert!(!environment.contains(secret));
    }
    assert_eq!(server.finish().len(), 2);
}

#[cfg(unix)]
#[test]
fn resume_closes_interrupted_tool_call_without_replaying_its_side_effect() {
    let fixture = Fixture::new();
    let first_server = Server::start(vec![tool_reply(vec![call(
        "interrupted-shell",
        "run_command",
        json!({"command":"printf 'executed\\n' >> invocation-count.txt","timeout_secs":3}),
    )])]);
    let first = fixture.run(
        &first_server.url,
        &[
            "--max-steps",
            "1",
            "--allow-shell",
            "exec",
            "--json",
            "Выполни действие один раз",
        ],
    );
    let first_events = events(&first, 1);
    assert_eq!(first_server.finish().len(), 1);
    let id = first_events
        .iter()
        .find(|event| event["type"] == "start")
        .unwrap()["session_id"]
        .as_str()
        .unwrap();
    let path = fixture.session_path(id);
    let mut session = read_json(&path);
    // Имитируем crash после side effect, но до сохранения результата инструмента.
    session["messages"]
        .as_array_mut()
        .unwrap()
        .retain(|message| message["role"] != "tool");
    fs::write(&path, serde_json::to_vec_pretty(&session).unwrap()).unwrap();
    assert_eq!(
        fs::read_to_string(fixture.project.join("invocation-count.txt")).unwrap(),
        "executed\n"
    );

    let resumed_server = Server::start(vec![final_reply(
        "Состояние прерванного действия проверено; повтор не нужен.",
    )]);
    let resumed = fixture.run(
        &resumed_server.url,
        &[
            "--resume",
            id,
            "--allow-shell",
            "exec",
            "--json",
            "Продолжи без повторного исполнения",
        ],
    );
    let resumed_events = events(&resumed, 0);
    assert!(
        !resumed_events
            .iter()
            .any(|event| event["type"] == "tool_start")
    );
    assert_eq!(
        fs::read_to_string(fixture.project.join("invocation-count.txt")).unwrap(),
        "executed\n"
    );
    let requests = resumed_server.finish();
    assert_eq!(requests.len(), 1);
    let messages = requests[0]["messages"].as_array().unwrap();
    let repaired: Vec<_> = messages
        .iter()
        .filter(|message| message["tool_call_id"] == "interrupted-shell")
        .collect();
    assert_eq!(repaired.len(), 1);
    let content: Value = serde_json::from_str(repaired[0]["content"].as_str().unwrap()).unwrap();
    assert_eq!(content["error"], "interrupted");
    assert_eq!(content["outcome"], "unknown");
    let saved = read_json(&path);
    assert_eq!(
        saved["messages"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|message| message["tool_call_id"] == "interrupted-shell")
            .count(),
        1
    );
}

#[test]
fn auth_401_exits_three_without_echoing_upstream_credentials() {
    let fixture = Fixture::new();
    let server = Server::start(vec![Reply::raw(
        401,
        "application/json",
        json!({"error":{"message":API_KEY}}).to_string(),
    )]);
    let output = fixture.run(&server.url, &["exec", "--json", "Проверь доступ"]);
    let events = events(&output, 3);
    assert_eq!(events.last().unwrap()["type"], "error");
    assert_eq!(events.last().unwrap()["exit_code"], 3);
    assert!(!events.iter().any(|event| event["type"] == "done"));
    assert_eq!(server.finish().len(), 1);
}

#[test]
fn malformed_json_and_missing_completion_shape_exit_four() {
    for body in ["{broken", r#"{"choices":[]}"#] {
        let fixture = Fixture::new();
        let server = Server::start(vec![Reply::raw(200, "application/json", body)]);
        let output = fixture.run(&server.url, &["exec", "--json", "Получи ответ"]);
        let events = events(&output, 4);
        assert_eq!(events.last().unwrap()["type"], "error");
        assert_eq!(events.last().unwrap()["exit_code"], 4);
        assert!(
            !events
                .iter()
                .any(|event| event["type"] == "done" || event["type"] == "tool_start")
        );
        assert_eq!(server.finish().len(), 1);
    }
}

#[test]
fn truncated_sse_does_not_execute_a_received_tool_call_and_exits_four() {
    let fixture = Fixture::new();
    let partial = json!({"choices":[{"delta":{"tool_calls":[{"index":0,"id":"partial-write","type":"function","function":{"name":"write_file","arguments":json!({"path":"partial.txt","content":"must not execute"}).to_string()}}]},"finish_reason":null}]});
    let server = Server::start(vec![Reply::raw(
        200,
        "text/event-stream",
        format!("data: {partial}\n\n"),
    )]);
    let output = fixture.run(
        &server.url,
        &[
            "--approval-mode",
            "auto-edit",
            "exec",
            "--json",
            "Создай файл",
        ],
    );
    let events = events(&output, 4);
    assert!(!fixture.project.join("partial.txt").exists());
    assert!(
        !events
            .iter()
            .any(|event| event["type"] == "tool_start" || event["type"] == "done")
    );
    assert_eq!(events.last().unwrap()["exit_code"], 4);
    assert_eq!(server.finish().len(), 1);
}

#[test]
fn truncated_http_body_exits_four() {
    let fixture = Fixture::new();
    let mut response = Reply::raw(200, "application/json", "{\"choices\":[");
    response.advertised_length = Some(response.body.len() + 50);
    let server = Server::start(vec![response]);
    let output = fixture.run(&server.url, &["exec", "--json", "Получи полный ответ"]);
    let events = events(&output, 4);
    assert_eq!(events.last().unwrap()["type"], "error");
    assert_eq!(events.last().unwrap()["exit_code"], 4);
    assert!(!events.iter().any(|event| event["type"] == "done"));
    assert_eq!(server.finish().len(), 1);
}

#[test]
fn context_overflow_does_not_append_request_and_explicit_compact_recovers() {
    use rcode::{
        config::{ConfigStore, ProviderKind, ProviderSettings},
        protocol::Message,
        state::Session,
    };
    let fixture = Fixture::new();
    let store = ConfigStore::at(&fixture.home).unwrap();
    let mut session = Session::new(
        &fixture.project,
        ProviderSettings::new(ProviderKind::Custom),
    )
    .unwrap();
    session.messages.push(Message::user("earlier request"));
    session
        .messages
        .push(Message::text("assistant", "x".repeat(180_001)));
    session.save(&store).unwrap();
    let output = fixture.run(
        "http://127.0.0.1:1/v1",
        &["--resume", &session.id, "exec", "--json", "new request"],
    );
    events(&output, 1);
    let saved = read_json(&fixture.session_path(&session.id));
    assert_eq!(saved["messages"].as_array().unwrap().len(), 2);
    let server = Server::start(vec![final_reply("RECOVERED")]);
    let output = fixture.run(
        &server.url,
        &[
            "--resume",
            &session.id,
            "--compact",
            "exec",
            "--json",
            "new request",
        ],
    );
    let output_events = events(&output, 0);
    assert!(output_events.iter().any(|e| e["type"] == "done"));
    assert_eq!(server.finish().len(), 1);
}
