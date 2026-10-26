use rcode::{
    config::{ConfigStore, ProviderKind, ProviderSettings},
    protocol::Message,
    state::Session,
};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::TcpListener,
    process::Command,
    thread,
    time::{Duration, Instant},
};

fn server(replies: Vec<Value>) -> (String, thread::JoinHandle<Vec<Value>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/v1", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut requests = Vec::new();
        for reply in replies {
            let mut socket = loop {
                assert!(Instant::now() < deadline, "fixture request timed out");
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("fixture accept failed: {error}"),
                }
            };
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut bytes = Vec::new();
            let split = loop {
                let mut part = [0; 4096];
                let read = socket.read(&mut part).unwrap();
                assert!(read > 0);
                bytes.extend_from_slice(&part[..read]);
                if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                    break index + 4;
                }
                assert!(bytes.len() < 64 * 1024);
            };
            let length: usize = String::from_utf8_lossy(&bytes[..split])
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|n| n.trim().parse().unwrap())
                })
                .unwrap();
            assert!(length < 2 * 1024 * 1024);
            while bytes.len() < split + length {
                let mut part = [0; 4096];
                let read = socket.read(&mut part).unwrap();
                assert!(read > 0);
                bytes.extend_from_slice(&part[..read]);
            }
            requests.push(serde_json::from_slice(&bytes[split..split + length]).unwrap());
            let body = reply.to_string();
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        }
        requests
    });
    (url, handle)
}

fn final_reply(text: &str) -> Value {
    json!({"choices":[{"message":{"role":"assistant","content":text},"finish_reason":"stop"}]})
}

fn tool_reply(id: usize, name: &str, arguments: Value, content: &str) -> Value {
    json!({"choices":[{"message":{"role":"assistant","content":content,"tool_calls":[{"id":format!("call_{id}"),"type":"function","function":{"name":name,"arguments":arguments.to_string()}}]},"finish_reason":"tool_calls"}]})
}

#[test]
fn resumed_full_session_compacts_before_sending_the_new_prompt() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("project");
    std::fs::create_dir(&root).unwrap();
    let home = temporary.path().join("state");
    let store = ConfigStore::at(home.clone()).unwrap();
    let mut session = Session::new(&root, ProviderSettings::new(ProviderKind::Custom)).unwrap();
    for index in 0..12 {
        session.messages.push(Message::user(format!(
            "Задача {index}: сохраняй пользовательские файлы"
        )));
        session
            .messages
            .push(Message::text("assistant", "старый ответ ".repeat(2000)));
    }
    session.save(&store).unwrap();
    assert!(session.context_chars() > 180_000);
    let prompt = format!(
        "Текущий запрос: {} КОНЕЦ_ЗАПРОСА",
        "точные требования ".repeat(600)
    );
    let (url, fixture) = server(vec![final_reply("Продолжаю")]);
    let output = Command::new(env!("CARGO_BIN_EXE_rcode"))
        .args([
            "-C",
            root.to_str().unwrap(),
            "--json",
            "--provider",
            "custom",
            "--model",
            "test",
            "--base-url",
            &url,
            "--resume",
            &session.id,
            "exec",
            &prompt,
        ])
        .env("RCODE_HOME", &home)
        .env("RCODE_CUSTOM_API_KEY", "fixture-key")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let requests = fixture.join().unwrap();
    assert_eq!(requests.len(), 1);
    let messages = requests[0]["messages"].as_array().unwrap();
    assert!(
        messages
            .iter()
            .any(|message| message["role"] == "user" && message["content"] == prompt)
    );
    let events: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(
        events
            .iter()
            .any(|event| event["type"] == "context_compacted" && event["automatic"] == true)
    );
    let loaded = Session::load(&store, &session.id, &root).unwrap();
    assert!(loaded.context_chars() < 150_000);
    assert!(
        loaded
            .messages
            .iter()
            .any(|message| message.content.as_deref() == Some(&prompt))
    );
}

#[test]
fn long_tool_turn_compacts_without_replaying_actions_or_forgetting_denials() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("project");
    std::fs::create_dir(&root).unwrap();
    let home = temporary.path().join("state");
    let store = ConfigStore::at(home.clone()).unwrap();
    let mut session = Session::new(&root, ProviderSettings::new(ProviderKind::Custom)).unwrap();
    session.save(&store).unwrap();
    let mut replies = vec![tool_reply(
        0,
        "run_command",
        json!({"command":"touch must-not-exist"}),
        "",
    )];
    for index in 1..9 {
        replies.push(tool_reply(
            index,
            "list_files",
            json!({}),
            &format!("Результаты анализа {index}: {}", "x".repeat(50_000)),
        ));
    }
    replies.push(final_reply("Остановлено после отказа в разрешении"));
    let (url, fixture) = server(replies);
    let prompt = "Исследуй проект; учитывай отказ в shell, продолжай разрешённое чтение";
    let output = Command::new(env!("CARGO_BIN_EXE_rcode"))
        .args([
            "-C",
            root.to_str().unwrap(),
            "--json",
            "--provider",
            "custom",
            "--model",
            "test",
            "--base-url",
            &url,
            "--resume",
            &session.id,
            "exec",
            prompt,
        ])
        .env("RCODE_HOME", &home)
        .env("RCODE_CUSTOM_API_KEY", "fixture-key")
        .output()
        .unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "{text}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let requests = fixture.join().unwrap();
    assert_eq!(requests.len(), 10);
    let events: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(
        events
            .iter()
            .filter(|event| event["type"] == "context_compacted")
            .count()
            >= 2,
        "{text}"
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event["type"] == "tool_start")
            .count(),
        9
    );
    assert!(!root.join("must-not-exist").exists());
    let final_messages = requests.last().unwrap()["messages"].as_array().unwrap();
    assert!(
        final_messages
            .iter()
            .any(|message| message["role"] == "user" && message["content"] == prompt)
    );
    assert!(final_messages.iter().any(|message| {
        message["content"]
            .as_str()
            .is_some_and(|content| content.contains("denied") && content.contains("not executed"))
    }));
    let mut loaded = Session::load(&store, &session.id, &root).unwrap();
    assert_eq!(loaded.repair_pending().unwrap(), 0);
    assert!(loaded.context_chars() < 150_000);
}

// Windows rejects a 160 KiB command line before rcode starts. The shared turn
// guard is also tested directly in app::tests on every platform.
#[cfg(unix)]
#[test]
fn oversized_new_request_is_rejected_without_network_or_losing_the_session() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("project");
    std::fs::create_dir(&root).unwrap();
    let home = temporary.path().join("state");
    let store = ConfigStore::at(home.clone()).unwrap();
    let mut session = Session::new(&root, ProviderSettings::new(ProviderKind::Custom)).unwrap();
    session
        .messages
        .push(Message::user("Сохрани старую задачу"));
    session.save(&store).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/v1", listener.local_addr().unwrap());
    let output = Command::new(env!("CARGO_BIN_EXE_rcode"))
        .args([
            "-C",
            root.to_str().unwrap(),
            "--json",
            "--provider",
            "custom",
            "--model",
            "test",
            "--base-url",
            &url,
            "--resume",
            &session.id,
            "exec",
        ])
        .args(std::iter::repeat_n("x".repeat(4000), 40))
        .env("RCODE_HOME", &home)
        .env("RCODE_CUSTOM_API_KEY", "fixture-key")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let events: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["type"], "error");
    assert!(
        events[0]["message"]
            .as_str()
            .unwrap()
            .contains("сократите запрос")
    );
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    let loaded = Session::load(&store, &session.id, &root).unwrap();
    assert_eq!(loaded.messages.len(), 1);
    assert_eq!(loaded.messages[0].content, session.messages[0].content);
    assert_eq!(loaded.turn_index, 0);
}

#[test]
fn image_limit_preflight_runs_after_old_attachments_are_compacted() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("project");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("screen.png"), b"\x89PNG\r\n\x1a\nfixture").unwrap();
    let home = temporary.path().join("state");
    let store = ConfigStore::at(home.clone()).unwrap();
    let mut session = Session::new(&root, ProviderSettings::new(ProviderKind::Custom)).unwrap();
    let mut old = rcode::images::user_message("screen.png", &root).unwrap();
    old.images = vec![old.images[0].clone(); rcode::images::MAX_IMAGES];
    old.content = Some("старые требования ".repeat(4000));
    session.messages.push(old);
    session
        .messages
        .push(Message::text("assistant", "старый ответ ".repeat(2000)));
    assert!(session.context_chars() > rcode::state::AUTO_COMPACT_THRESHOLD);
    session.save(&store).unwrap();
    let (url, fixture) = server(vec![final_reply("Новое изображение принято")]);
    let output = Command::new(env!("CARGO_BIN_EXE_rcode"))
        .args([
            "-C",
            root.to_str().unwrap(),
            "--json",
            "--provider",
            "custom",
            "--model",
            "test",
            "--base-url",
            &url,
            "--resume",
            &session.id,
            "exec",
            "/attach screen.png Новый запрос",
        ])
        .env("RCODE_HOME", &home)
        .env("RCODE_CUSTOM_API_KEY", "fixture-key")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let requests = fixture.join().unwrap();
    assert_eq!(requests.len(), 1);
    let image_count = requests[0]["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|message| message["content"].as_array())
        .flatten()
        .filter(|part| part["type"] == "image_url")
        .count();
    assert_eq!(image_count, 1);
    let restored = Session::load(&store, &session.id, &root).unwrap();
    assert_eq!(restored.messages.iter().flat_map(|m| &m.images).count(), 1);
    assert!(restored.messages.iter().any(|message| {
        message.content.as_deref() == Some("Новый запрос") && message.images.len() == 1
    }));
}
