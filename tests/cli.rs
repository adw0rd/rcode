use serde_json::{Value, json};
use std::{
    io::{self, Read, Seek, Write},
    net::{TcpListener, TcpStream},
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

const NETWORK_TIMEOUT: Duration = Duration::from_secs(30);
const PROCESS_TIMEOUT: Duration = Duration::from_secs(40);

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

fn server(replies: Vec<Value>) -> (String, thread::JoinHandle<Vec<Value>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = format!("http://{}/v1", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + NETWORK_TIMEOUT;
        let mut requests = Vec::new();
        for reply in replies {
            let mut socket = loop {
                assert!(
                    Instant::now() < deadline,
                    "mock request deadline exceeded after {} requests",
                    requests.len()
                );
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("mock accept failed: {error}"),
                }
            };
            // Accepted sockets can inherit O_NONBLOCK on macOS.
            socket.set_nonblocking(false).unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut bytes = Vec::new();
            let split = loop {
                let mut b = [0u8; 1024];
                let n = read_before_deadline(&mut socket, &mut b, deadline).unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&b[..n]);
                if let Some(i) = bytes.windows(4).position(|s| s == b"\r\n\r\n") {
                    break i + 4;
                }
                assert!(bytes.len() <= 64 * 1024, "mock request header too large");
            };
            let header = String::from_utf8_lossy(&bytes[..split]);
            let length = header
                .lines()
                .find_map(|l| {
                    l.to_lowercase()
                        .strip_prefix("content-length:")
                        .map(|s| s.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            assert!(length <= 2 * 1024 * 1024, "mock request body too large");
            while bytes.len() < split + length {
                let mut b = [0u8; 4096];
                let n = read_before_deadline(&mut socket, &mut b, deadline).unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&b[..n]);
            }
            requests.push(serde_json::from_slice(&bytes[split..split + length]).unwrap());
            let body = reply.to_string();
            write!(socket,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
        }
        requests
    });
    (address, handle)
}

fn output_with_deadline(command: &mut Command) -> Output {
    #[cfg(windows)]
    if let Some(system_root) = std::env::var_os("SYSTEMROOT") {
        command.env("SYSTEMROOT", system_root);
    }
    // Regular files avoid pipe backpressure and inherited pipes keeping output open.
    let stdout = tempfile::tempfile().unwrap();
    let stderr = tempfile::tempfile().unwrap();
    let mut child = command
        .stdin(Stdio::null())
        .stdout(stdout.try_clone().unwrap())
        .stderr(stderr.try_clone().unwrap())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    let (status, timed_out) = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break (status, false);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            break (child.wait().unwrap(), true);
        }
        thread::sleep(Duration::from_millis(10));
    };
    let read_capture = |mut file: std::fs::File| {
        file.rewind().unwrap();
        let mut bytes = Vec::new();
        file.take(2 * 1024 * 1024).read_to_end(&mut bytes).unwrap();
        bytes
    };
    let output = Output {
        status,
        stdout: read_capture(stdout),
        stderr: read_capture(stderr),
    };
    assert!(
        !timed_out,
        "CLI exceeded test timeout; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn final_reply(text: &str) -> Value {
    json!({"choices":[{"message":{"role":"assistant","content":text},"finish_reason":"stop"}],"usage":{"prompt_tokens":20,"completion_tokens":5}})
}
fn tool_reply(name: &str, args: Value) -> Value {
    json!({"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_test","type":"function","function":{"name":name,"arguments":args.to_string()}}]},"finish_reason":"tool_calls"}]})
}
fn run(
    root: &std::path::Path,
    home: &std::path::Path,
    endpoint: &str,
    extra: &[&str],
) -> std::process::Output {
    output_with_deadline(
        Command::new(env!("CARGO_BIN_EXE_rcode"))
            .args([
                "-C",
                root.to_str().unwrap(),
                "--provider",
                "custom",
                "--base-url",
                endpoint,
                "--model",
                "test",
            ])
            .args(extra)
            .env("RCODE_HOME", home)
            .env("RCODE_CUSTOM_API_KEY", "test-only-key"),
    )
}

#[test]
fn repeated_external_path_errors_stop_before_the_model_spends_the_whole_step_budget() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("project");
    std::fs::create_dir(&root).unwrap();
    let (url, handle) = server((0..3).map(|i| tool_reply("write_file", json!({
        "path":tmp.path().join(format!("outside-{i}.txt")), "content":"not authorized"
    }))).collect());
    let output = run(
        &root,
        &tmp.path().join("state"),
        &url,
        &[
            "--json",
            "--max-steps",
            "24",
            "--approval-mode",
            "auto-edit",
            "exec",
            "Create an external project",
        ],
    );
    let requests = handle.join().unwrap();
    assert_eq!(requests.len(), 3);
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(1), "{text}");
    assert!(text.contains("Повторяется ошибка внешнего пути"), "{text}");
    for i in 0..3 {
        assert!(!tmp.path().join(format!("outside-{i}.txt")).exists());
    }
}

#[cfg(unix)]
#[test]
fn external_path_recovery_uses_shell_only_when_it_is_authorized() {
    for allowed in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        std::fs::create_dir(&root).unwrap();
        let external = tmp.path().join("outside.txt");
        let (url, handle) = server(vec![
            tool_reply("write_file", json!({"path":external,"content":"created"})),
            tool_reply(
                "run_command",
                json!({"command":format!("printf '%s' 'created' > '{}'", external.display())}),
            ),
            final_reply("Finished"),
        ]);
        let mut options = vec!["--json", "--approval-mode", "auto-edit"];
        if allowed {
            options.push("--allow-shell");
        }
        options.extend(["exec", "Create the external file"]);
        let output = run(&root, &tmp.path().join("state"), &url, &options);
        let requests = handle.join().unwrap();
        assert!(requests[1]["messages"].as_array().unwrap().iter().any(|m| {
            m["role"] == "tool"
                && m["content"]
                    .as_str()
                    .is_some_and(|c| c.contains("outside_workspace") && c.contains("run_command"))
        }));
        assert_eq!(external.exists(), allowed);
        assert_eq!(
            output.status.code(),
            Some(if allowed { 0 } else { 1 }),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        if allowed {
            assert_eq!(std::fs::read_to_string(external).unwrap(), "created");
        }
    }
}
#[test]
fn runtime_model_identity_follows_explicit_provider_switch_on_resume() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("project with spaces");
    std::fs::create_dir(&root).unwrap();
    let instructions = "This repository is implemented in Rust. Preserve the user's changes.";
    std::fs::write(root.join("AGENTS.md"), instructions).unwrap();
    let (url, handle) = server(vec![
        final_reply("First answer"),
        final_reply("Second answer"),
    ]);
    for (index, (provider, model, effort)) in [
        ("yandex", "yandexgpt/latest", "low"),
        ("openrouter", "fixture/second-model", "high"),
    ]
    .into_iter()
    .enumerate()
    {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rcode"));
        command
            .env_clear()
            .env("RCODE_HOME", tmp.path().join("state"))
            .env("RCODE_YANDEX_API_KEY", "fixture-yandex-identity-secret")
            .env("RCODE_OPENROUTER_API_KEY", "fixture-router-identity-secret")
            .args([
                "-C",
                root.to_str().unwrap(),
                "--provider",
                provider,
                "--model",
                model,
                "--effort",
                effort,
                "--folder-id",
                "folder",
                "--base-url",
                &url,
                "--json",
            ]);
        if index > 0 {
            command.args([
                "--resume",
                "latest",
                "--approval-mode",
                "auto-edit",
                "--allow-shell",
            ]);
        }
        let output = output_with_deadline(command.args(["exec", "Какая модель мне отвечает?"]));
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let requests = handle.join().unwrap();
    for (index, (provider, model, effort)) in [
        ("yandex", "yandexgpt/latest", "low"),
        ("openrouter", "fixture/second-model", "high"),
    ]
    .into_iter()
    .enumerate()
    {
        let system = requests[index]["messages"][0]["content"].as_str().unwrap();
        let context: Value = serde_json::from_str(
            system
                .rsplit_once("<rcode_runtime_context>\n")
                .expect("The actual API request must include the current model identity")
                .1
                .split_once("\n</rcode_runtime_context>")
                .unwrap()
                .0,
        )
        .unwrap();
        assert_eq!(context["harness"], "rcode");
        assert_eq!(context["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(context["provider"], provider);
        assert_eq!(context["model"], model);
        assert_eq!(context["effort"], effort);
        assert_eq!(context["mode"], "agent");
        assert_eq!(
            context["permissions"]["file_changes"],
            if index == 0 { "ask" } else { "allowed" }
        );
        assert_eq!(
            context["permissions"]["shell_commands"],
            if index == 0 { "ask" } else { "allowed" }
        );
        assert_eq!(context["permissions"]["approval_ui"], false);
        assert_eq!(
            context["working_directory"],
            root.canonicalize().unwrap().to_str().unwrap()
        );
        assert!(system.contains(instructions));
        assert!(!system.contains("fixture-yandex-identity-secret"));
        assert!(!system.contains("fixture-router-identity-secret"));
    }
    assert_eq!(requests[0]["model"], "gpt://folder/yandexgpt/latest");
    assert_eq!(requests[1]["model"], "fixture/second-model");
    assert!(
        requests[1]["messages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|message| message["role"] == "assistant" && message["content"] == "First answer")
    );
}

#[test]
fn exec_applies_patch_and_emits_versioned_jsonl() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("project");
    std::fs::create_dir(&root).unwrap();
    let (url, handle) = server(vec![
        tool_reply(
            "write_file",
            json!({"path":"answer.txt","content":"Привет\n"}),
        ),
        final_reply("Готово"),
    ]);
    let out = run(
        &root,
        &tmp.path().join("home"),
        &url,
        &[
            "exec",
            "--json",
            "--approval-mode",
            "auto-edit",
            "Создай файл",
        ],
    );
    assert!(
        out.status.success(),
        "stderr: {}\nstdout: {}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    assert_eq!(
        std::fs::read_to_string(root.join("answer.txt")).unwrap(),
        "Привет\n"
    );
    let events: Vec<Value> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert!(events.iter().all(|e| e["version"] == 1));
    assert_eq!(events.last().unwrap()["type"], "done");
    let requests = handle.join().unwrap();
    assert!(
        requests[1]["messages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["role"] == "tool")
    );
    assert!(
        !serde_json::to_string(&events)
            .unwrap()
            .contains("test-only-key")
    );
}
#[test]
fn noninteractive_shell_is_denied_and_exit_is_unsuccessful() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("project");
    std::fs::create_dir(&root).unwrap();
    let (url, handle) = server(vec![
        tool_reply("run_command", json!({"command":"echo unsafe > sentinel"})),
        final_reply("Команда отклонена"),
    ]);
    let out = run(
        &root,
        &tmp.path().join("home"),
        &url,
        &["exec", "--json", "Проверь проект"],
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "stderr: {}\nstdout: {}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(!root.join("sentinel").exists());
    let requests = handle.join().unwrap();
    assert!(requests[1]["messages"].to_string().contains("denied"));
}
#[test]
fn missing_credentials_is_config_error_without_network() {
    let tmp = tempfile::tempdir().unwrap();
    let out = output_with_deadline(
        Command::new(env!("CARGO_BIN_EXE_rcode"))
            .args(["--provider", "gigachat", "exec", "--json", "hello"])
            .env_clear()
            .env("RCODE_HOME", tmp.path()),
    );
    assert_eq!(out.status.code(), Some(2));
    let error: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(error["type"], "error");
}
