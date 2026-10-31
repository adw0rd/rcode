//! Чёрные контракты `rcode local …` по internal-плану: профили, ключи, loopback.
//! Только loopback fixtures на порту 0, без живых моделей и платных API.

use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, VecDeque},
    io::{self, Read, Seek, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const PROCESS_TIMEOUT: Duration = Duration::from_secs(20);
const FIXTURE_LIFETIME: Duration = Duration::from_secs(90);
const MARKER: &str = "test-synthetic-marker";
const CLOUD_ENV: [(&str, &str); 8] = [
    ("RCODE_CUSTOM_API_KEY", "test-synthetic-marker-custom"),
    ("OPENAI_API_KEY", "test-synthetic-marker-openai"),
    ("RCODE_OPENROUTER_API_KEY", "test-synthetic-marker-router"),
    ("OPENROUTER_API_KEY", "test-synthetic-marker-router2"),
    ("RCODE_YANDEX_API_KEY", "test-synthetic-marker-yandex"),
    ("YANDEX_API_KEY", "test-synthetic-marker-yandex2"),
    ("RCODE_GIGACHAT_AUTH_KEY", "test-synthetic-marker-giga"),
    ("RCODE_GIGACHAT_CREDENTIALS", "test-synthetic-marker-giga2"),
];

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: String,
}

impl Seen {
    fn is_chat(&self) -> bool {
        self.method == "POST" && self.path.ends_with("/chat/completions")
    }
    fn authorization(&self) -> Option<&str> {
        self.headers.get("authorization").map(String::as_str)
    }
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
    fn raw(&self) -> String {
        format!(
            "{} {}\n{:?}\n{}",
            self.method, self.path, self.headers, self.body
        )
    }
}

enum Mode {
    Serve {
        model: String,
        replies: VecDeque<(u16, Value)>,
    },
    Redirect(String),
}

/// Долгоживущий loopback-сервер: `/models`, очередь ответов chat, 404 на прочие GET.
struct Fixture {
    url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
    stop: Arc<AtomicBool>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl Fixture {
    fn serve(model: &str, replies: Vec<Value>) -> Self {
        Self::with_status(
            model,
            replies.into_iter().map(|reply| (200, reply)).collect(),
        )
    }
    fn with_status(model: &str, replies: Vec<(u16, Value)>) -> Self {
        Self::start(Mode::Serve {
            model: model.into(),
            replies: replies.into(),
        })
    }
    fn redirect_to(target: &str) -> Self {
        Self::start(Mode::Redirect(target.into()))
    }
    fn start(mut mode: Mode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/v1", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (log, halt) = (Arc::clone(&seen), Arc::clone(&stop));
        thread::spawn(move || {
            let deadline = Instant::now() + FIXTURE_LIFETIME;
            while !halt.load(Ordering::SeqCst) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((socket, _)) => {
                        if let Some(request) = handle(socket, &mut mode) {
                            log.lock().unwrap().push(request);
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self { url, seen, stop }
    }
    fn requests(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
    fn chats(&self) -> Vec<Seen> {
        self.requests().into_iter().filter(Seen::is_chat).collect()
    }
}

fn handle(mut socket: TcpStream, mode: &mut Mode) -> Option<Seen> {
    // Accepted sockets can inherit O_NONBLOCK on macOS.
    socket.set_nonblocking(false).ok()?;
    socket.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .ok()?;
    let mut bytes = Vec::new();
    let split = loop {
        let mut chunk = [0u8; 4096];
        let read = socket.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(index) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            break index + 4;
        }
        if bytes.len() > 64 * 1024 {
            return None;
        }
    };
    let head = String::from_utf8_lossy(&bytes[..split]).into_owned();
    let mut lines = head.lines();
    let mut start = lines.next().unwrap_or_default().split_whitespace();
    let method = start.next().unwrap_or_default().to_string();
    let path = start.next().unwrap_or_default().to_string();
    let headers: BTreeMap<String, String> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    let length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0)
        .min(4 * 1024 * 1024);
    while bytes.len() < split + length {
        let mut chunk = [0u8; 8192];
        let read = socket.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    let end = bytes.len().min(split + length);
    let body = String::from_utf8_lossy(&bytes[split..end]).into_owned();
    let (status, extra, reply) = match mode {
        Mode::Redirect(target) => (
            302,
            format!("Location: {target}{path}\r\n"),
            json!({"redirect": true}),
        ),
        Mode::Serve { model, .. } if method == "GET" && path.ends_with("/models") => (
            200,
            String::new(),
            json!({"object":"list","data":[{"id":model,"object":"model","owned_by":"fixture"}]}),
        ),
        Mode::Serve { replies, .. } if method == "POST" && path.ends_with("/chat/completions") => {
            let (status, reply) = replies
                .pop_front()
                .unwrap_or_else(|| (500, json!({"error":{"message":"fixture exhausted"}})));
            (status, String::new(), reply)
        }
        Mode::Serve { .. } => (404, String::new(), json!({"error":"not found"})),
    };
    let text = reply.to_string();
    let _ = write!(
        socket,
        "HTTP/1.1 {status} Fixture\r\n{extra}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        text.len()
    );
    Some(Seen {
        method,
        path,
        headers,
        body,
    })
}

fn final_reply(text: &str) -> Value {
    json!({"choices":[{"index":0,"message":{"role":"assistant","content":text},"finish_reason":"stop"}],"usage":{"prompt_tokens":20,"completion_tokens":5}})
}

fn tool_reply(id: &str, name: &str, args: Value) -> Value {
    json!({"choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[{"id":id,"type":"function","function":{"name":name,"arguments":args.to_string()}}]},"finish_reason":"tool_calls"}]})
}

/// Изолированное окружение: свой HOME/XDG/RCODE_HOME и синтетические cloud-ключи.
struct Sandbox {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    state: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        for dir in [
            "home",
            "xdg/config",
            "xdg/data",
            "xdg/state",
            "xdg/cache",
            "state",
        ] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        let state = root.join("state");
        Self {
            _tmp: tmp,
            root,
            state,
        }
    }
    fn project(&self, name: &str) -> PathBuf {
        let path = self.root.join(name);
        std::fs::create_dir_all(&path).unwrap();
        path
    }
    fn rcode(&self, args: &[&str], stdin: Option<&str>) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rcode"));
        command.env_clear();
        for name in ["PATH", "TMPDIR", "SYSTEMROOT"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command
            .env("HOME", self.root.join("home"))
            .env("USERPROFILE", self.root.join("home"))
            .env("XDG_CONFIG_HOME", self.root.join("xdg/config"))
            .env("XDG_DATA_HOME", self.root.join("xdg/data"))
            .env("XDG_STATE_HOME", self.root.join("xdg/state"))
            .env("XDG_CACHE_HOME", self.root.join("xdg/cache"))
            .env("RCODE_HOME", &self.state)
            .envs(CLOUD_ENV)
            .args(args);
        run_with_deadline(command, stdin)
    }
    fn ok(&self, args: &[&str], stdin: Option<&str>) -> Output {
        let output = self.rcode(args, stdin);
        assert!(
            output.status.success(),
            "rcode {args:?} failed\n{}",
            text(&output)
        );
        output
    }
    fn file(&self, name: &str) -> String {
        std::fs::read_to_string(self.state.join(name)).unwrap_or_default()
    }
    fn profiles(&self) -> Vec<Value> {
        let output = self.ok(&["local", "list", "--json"], None);
        profiles_from(&String::from_utf8_lossy(&output.stdout))
    }
    fn profile(&self, name: &str) -> Option<Value> {
        self.profiles()
            .into_iter()
            .find(|profile| profile["profile"] == name)
    }
    fn exec(&self, project: &Path, profile: Option<&str>, prompt: &str) -> Output {
        let mut args = vec!["exec", "--provider", "local"];
        if let Some(profile) = profile {
            args.extend(["--profile", profile]);
        }
        args.extend([
            "--approval-mode",
            "full-access",
            "--allow-shell",
            "--json",
            "-C",
            project.to_str().unwrap(),
            prompt,
        ]);
        self.rcode(&args, None)
    }
}

fn run_with_deadline(mut command: Command, stdin: Option<&str>) -> Output {
    // Regular files avoid pipe backpressure and inherited pipes keeping output open.
    let stdout = tempfile::tempfile().unwrap();
    let stderr = tempfile::tempfile().unwrap();
    let mut child = command
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(stdout.try_clone().unwrap())
        .stderr(stderr.try_clone().unwrap())
        .spawn()
        .unwrap();
    if let (Some(text), Some(mut pipe)) = (stdin, child.stdin.take()) {
        // EPIPE допустим: команда может не читать stdin.
        let _ = pipe.write_all(text.as_bytes());
    }
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
    let capture = |mut file: std::fs::File| {
        file.rewind().unwrap();
        let mut bytes = Vec::new();
        file.take(4 * 1024 * 1024).read_to_end(&mut bytes).unwrap();
        bytes
    };
    let output = Output {
        status,
        stdout: capture(stdout),
        stderr: capture(stderr),
    };
    assert!(
        !timed_out,
        "rcode exceeded test deadline; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// Формат `local list --json` берём толерантно: массив, объект-обёртка или JSONL.
fn profiles_from(stdout: &str) -> Vec<Value> {
    fn collect(value: Value, found: &mut Vec<Value>) {
        match value {
            Value::Array(items) => {
                for item in items {
                    collect(item, found);
                }
            }
            Value::Object(map) if map.get("profile").is_some_and(Value::is_string) => {
                found.push(Value::Object(map));
            }
            Value::Object(map) => {
                for (_, item) in map {
                    collect(item, found);
                }
            }
            _ => {}
        }
    }
    let mut found = Vec::new();
    if let Ok(value) = serde_json::from_str::<Value>(stdout) {
        collect(value, &mut found);
    } else {
        for line in stdout.lines() {
            if let Ok(value) = serde_json::from_str::<Value>(line) {
                collect(value, &mut found);
            }
        }
    }
    found
}

fn events(output: &Output) -> Vec<Value> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

fn text(output: &Output) -> String {
    format!(
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn add(sandbox: &Sandbox, name: &str, url: &str, model: &str, extra: &[&str], key: Option<&str>) {
    let mut args = vec![
        "local",
        "add",
        name,
        "--base-url",
        url,
        "--runtime",
        "openai",
        "--model",
        model,
    ];
    args.extend_from_slice(extra);
    let output = sandbox.ok(&args, key);
    if let Some(key) = key {
        assert!(!text(&output).contains(key), "key echoed by local add");
    }
}

fn walk(path: &Path) -> Vec<PathBuf> {
    if path.is_dir() {
        std::fs::read_dir(path)
            .unwrap()
            .flatten()
            .flat_map(|entry| walk(&entry.path()))
            .collect()
    } else if path.exists() {
        vec![path.to_path_buf()]
    } else {
        Vec::new()
    }
}

#[test]
fn two_profiles_keep_active_choice_across_restarts_and_old_cloud_config_survives() {
    let sandbox = Sandbox::new();
    let cloud = Fixture::serve("legacy-model", vec![final_reply("FROM_CUSTOM")]);
    let alpha = Fixture::serve("model-a", vec![final_reply("FROM_ALPHA")]);
    let beta = Fixture::serve("model-b2", vec![final_reply("FROM_BETA")]);
    // Конфиг v0.6.2: без поля `local`, active = custom.
    let legacy = json!({
        "version": 1,
        "active": "custom",
        "providers": {
            "custom": {"kind": "custom", "model": "legacy-model", "base_url": cloud.url},
            "openrouter": {"kind": "openrouter", "model": "fixture/router-model", "base_url": "https://openrouter.ai/api/v1"}
        }
    });
    std::fs::write(sandbox.state.join("config.json"), legacy.to_string()).unwrap();

    add(
        &sandbox,
        "alpha",
        &alpha.url,
        "model-a",
        &["--activate"],
        None,
    );
    add(&sandbox, "beta", &beta.url, "model-b", &[], None);
    let listed = sandbox.profiles();
    assert_eq!(listed.len(), 2, "{listed:?}");
    let alpha_row = sandbox.profile("alpha").unwrap();
    assert_eq!(alpha_row["active"], true);
    assert_eq!(alpha_row["model"], "model-a");
    assert_eq!(alpha_row["key"], "none");
    assert_eq!(sandbox.profile("beta").unwrap()["active"], false);

    sandbox.ok(&["local", "use", "beta", "--model", "model-b2"], None);
    // Каждый вызов — новый процесс: выбор переживает перезапуск.
    let beta_row = sandbox.profile("beta").unwrap();
    assert_eq!(beta_row["active"], true);
    assert_eq!(beta_row["model"], "model-b2");
    assert_eq!(sandbox.profile("alpha").unwrap()["active"], false);

    let project = sandbox.project("project");
    let output = sandbox.exec(&project, None, "Кто отвечает?");
    assert!(output.status.success(), "{}", text(&output));
    assert!(text(&output).contains("FROM_BETA"));
    assert_eq!(beta.chats().len(), 1);
    assert_eq!(beta.chats()[0].json()["model"], "model-b2");
    assert!(
        alpha.chats().is_empty(),
        "inactive profile must not be called"
    );

    let output = sandbox.exec(&project, Some("alpha"), "Кто отвечает?");
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(alpha.chats().len(), 1);
    assert_eq!(alpha.chats()[0].json()["model"], "model-a");

    let config: Value = serde_json::from_str(&sandbox.file("config.json")).unwrap();
    assert_eq!(config["version"], 1);
    assert_eq!(config["providers"]["custom"]["model"], "legacy-model");
    assert_eq!(
        config["providers"]["custom"]["base_url"],
        cloud.url.as_str()
    );
    assert_eq!(
        config["providers"]["openrouter"]["model"],
        "fixture/router-model"
    );
    assert!(
        config["providers"].get("local").is_none(),
        "D2: no providers.local"
    );

    // Custom по-прежнему читает свой env-ключ; local его никогда не видел.
    let output = sandbox.rcode(
        &[
            "exec",
            "--provider",
            "custom",
            "--json",
            "-C",
            project.to_str().unwrap(),
            "Привет",
        ],
        None,
    );
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(
        cloud.chats()[0].authorization(),
        Some("Bearer test-synthetic-marker-custom")
    );
    for request in alpha.requests().iter().chain(&beta.requests()) {
        assert!(request.authorization().is_none(), "{}", request.raw());
        assert!(!request.raw().contains(MARKER), "{}", request.raw());
    }

    sandbox.ok(&["local", "remove", "alpha"], None);
    let listed = sandbox.profiles();
    assert_eq!(listed.len(), 1, "{listed:?}");
    assert_eq!(listed[0]["profile"], "beta");
}

#[test]
fn noauth_profile_runs_read_edit_shell_cycle_without_any_cloud_key() {
    let sandbox = Sandbox::new();
    let project = sandbox.project("project");
    std::fs::write(project.join("greet.sh"), "printf 'hello WORLD\\n'\n").unwrap();
    let server = Fixture::serve(
        "coder",
        vec![
            tool_reply("call_read", "read_file", json!({"path":"greet.sh"})),
            tool_reply(
                "call_edit",
                "edit_file",
                json!({"path":"greet.sh","old_text":"WORLD","new_text":"LOCAL"}),
            ),
            tool_reply(
                "call_run",
                "run_command",
                json!({"command":"sh greet.sh > out.txt"}),
            ),
            final_reply("TOOL_CYCLE_DONE"),
        ],
    );
    add(
        &sandbox,
        "coder",
        &server.url,
        "coder",
        &["--activate"],
        None,
    );
    let output = sandbox.exec(&project, Some("coder"), "Исправь приветствие и запусти");
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));

    assert_eq!(
        std::fs::read_to_string(project.join("greet.sh")).unwrap(),
        "printf 'hello LOCAL\\n'\n"
    );
    assert_eq!(
        std::fs::read_to_string(project.join("out.txt")).unwrap(),
        "hello LOCAL\n"
    );
    let events = events(&output);
    for name in ["read_file", "edit_file", "run_command"] {
        let receipt = events
            .iter()
            .find(|event| event["type"] == "tool_result" && event["name"] == name)
            .unwrap_or_else(|| panic!("no {name} receipt: {}", text(&output)));
        assert_eq!(receipt["is_error"], false, "{receipt}");
    }
    assert!(text(&output).contains("TOOL_CYCLE_DONE"));

    let chats = server.chats();
    assert_eq!(chats.len(), 4);
    let last = chats[3].json();
    assert!(
        last["messages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|message| message["role"] == "tool" && message["tool_call_id"] == "call_run"),
        "shell receipt must reach the model: {last}"
    );
    for request in server.requests() {
        assert!(request.authorization().is_none(), "{}", request.raw());
        assert!(!request.raw().contains(MARKER), "{}", request.raw());
    }
    for chat in &chats {
        let body = chat.json();
        assert!(body.get("reasoning_effort").is_none(), "{body}");
        assert!(body.get("reasoning").is_none(), "{body}");
    }
    assert!(!text(&output).contains(MARKER));
}

#[test]
fn profile_key_goes_only_to_its_endpoint_and_changed_endpoint_blocks_resume() {
    let sandbox = Sandbox::new();
    let key_a = "sk-local-alpha-test-synthetic-marker-0001";
    let bearer = format!("Bearer {key_a}");
    let alpha = Fixture::serve("model-a", vec![final_reply("FROM_ALPHA")]);
    let beta = Fixture::serve("model-b", vec![final_reply("FROM_BETA")]);
    let moved = Fixture::serve("model-a", vec![final_reply("FROM_MOVED")]);
    add(
        &sandbox,
        "alpha",
        &alpha.url,
        "model-a",
        &["--api-key-stdin", "--activate"],
        Some(key_a),
    );
    add(&sandbox, "beta", &beta.url, "model-b", &[], None);
    assert_eq!(sandbox.profile("alpha").unwrap()["key"], "stored");
    assert_eq!(sandbox.profile("beta").unwrap()["key"], "none");

    let other = sandbox.project("other");
    let output = sandbox.exec(&other, Some("beta"), "Ход другого профиля");
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(beta.chats().len(), 1);
    for request in beta.requests() {
        assert!(request.authorization().is_none(), "{}", request.raw());
        assert!(
            !request.raw().contains(key_a),
            "key of alpha leaked to beta"
        );
    }

    // Сессия alpha создаётся последней: `--resume latest` выберет её при любой семантике.
    let resumed = sandbox.project("resumed");
    let output = sandbox.exec(&resumed, Some("alpha"), "Первый ход");
    assert!(output.status.success(), "{}", text(&output));
    assert!(!text(&output).contains(key_a));
    assert_eq!(alpha.chats()[0].authorization(), Some(bearer.as_str()));

    // Тот же профиль и ключ, но другой endpoint: снимок сессии больше не совпадает (D5).
    sandbox.ok(&["local", "remove", "alpha"], None);
    add(
        &sandbox,
        "alpha",
        &moved.url,
        "model-a",
        &["--api-key-stdin", "--activate"],
        Some(key_a),
    );
    let alpha_before = alpha.requests().len();
    let output = sandbox.rcode(
        &[
            "exec",
            "--resume",
            "latest",
            "--json",
            "-C",
            resumed.to_str().unwrap(),
            "Продолжи",
        ],
        None,
    );
    assert!(!output.status.success(), "{}", text(&output));
    assert!(!text(&output).contains(key_a));
    for request in alpha.requests()[alpha_before..]
        .iter()
        .chain(&moved.requests())
    {
        assert!(
            !request.raw().contains(key_a),
            "key sent after endpoint change: {}",
            request.raw()
        );
    }
}

#[test]
fn local_key_stays_out_of_output_config_history_and_shell_env() {
    let sandbox = Sandbox::new();
    let key = "sk-local-secret-test-synthetic-marker-0002";
    let rotated = "sk-local-rotated-test-synthetic-marker-0003";
    let bearer = format!("Bearer {key}");
    let project = sandbox.project("project");
    let server = Fixture::with_status(
        "keyed",
        vec![
            (
                200,
                tool_reply(
                    "call_env",
                    "run_command",
                    json!({"command":"env > env.txt"}),
                ),
            ),
            (200, final_reply("ENV_DONE")),
            (
                400,
                json!({"error":{"message":format!("bad key {rotated}")}}),
            ),
            (200, final_reply("NO_KEY_DONE")),
        ],
    );
    add(
        &sandbox,
        "keyed",
        &server.url,
        "keyed",
        &["--api-key-stdin", "--activate"],
        Some(key),
    );
    let output = sandbox.exec(&project, Some("keyed"), "Покажи окружение");
    assert!(output.status.success(), "{}", text(&output));
    assert!(!text(&output).contains(key));
    let env = std::fs::read_to_string(project.join("env.txt")).unwrap();
    assert!(!env.contains(key), "local key leaked into shell env");
    assert!(!env.contains(MARKER), "cloud keys must not reach shell env");
    let chats = server.chats();
    assert_eq!(chats.len(), 2);
    assert!(
        chats
            .iter()
            .all(|chat| chat.authorization() == Some(bearer.as_str()))
    );

    let output = sandbox.ok(&["local", "key", "keyed", "--stdin"], Some(rotated));
    assert!(!text(&output).contains(rotated));
    let output = sandbox.exec(&project, Some("keyed"), "Ошибка с ключом в теле");
    assert!(!output.status.success());
    assert!(
        !text(&output).contains(rotated),
        "error body must be redacted"
    );

    let listing = sandbox.ok(&["local", "list", "--json"], None);
    assert!(!text(&listing).contains(key) && !text(&listing).contains(rotated));
    for file in walk(&sandbox.state) {
        if file
            .file_name()
            .is_some_and(|name| name == "credentials.json")
        {
            continue;
        }
        let content = String::from_utf8_lossy(&std::fs::read(&file).unwrap()).into_owned();
        assert!(
            !content.contains(key) && !content.contains(rotated),
            "key stored in {}",
            file.display()
        );
    }
    let credentials = sandbox.file("credentials.json");
    assert!(credentials.contains(rotated) && !credentials.contains(key));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(sandbox.state.join("credentials.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "credentials.json must be private");
    }

    let output = sandbox.ok(&["local", "key", "keyed", "--delete"], None);
    assert!(!text(&output).contains(rotated));
    assert!(!sandbox.file("credentials.json").contains(rotated));
    assert_eq!(sandbox.profile("keyed").unwrap()["key"], "none");
    let calls = server.requests().len();
    // key_required может дать Missing до сети (D3/D7): успех не требуется.
    let output = sandbox.exec(&project, Some("keyed"), "Без ключа");
    assert!(!text(&output).contains(key) && !text(&output).contains(rotated));
    for request in &server.requests()[calls..] {
        assert!(request.authorization().is_none(), "{}", request.raw());
    }
}

#[test]
fn local_profiles_reject_remote_hosts_url_credentials_and_redirects() {
    let sandbox = Sandbox::new();
    let guard = Fixture::serve("guarded", Vec::new());
    let authority = guard
        .url
        .trim_start_matches("http://")
        .trim_end_matches("/v1");
    let with_userinfo = format!("http://fixture-user:url-password-marker@{authority}/v1");
    for (name, url) in [
        ("lan", "http://192.168.1.10:8080/v1".to_string()),
        ("remote", "https://example.com/v1".to_string()),
        ("userinfo", with_userinfo),
    ] {
        let output = sandbox.rcode(
            &[
                "local",
                "add",
                name,
                "--base-url",
                &url,
                "--runtime",
                "openai",
                "--model",
                "m",
            ],
            None,
        );
        assert!(
            !output.status.success(),
            "{name} accepted: {}",
            text(&output)
        );
    }
    assert!(guard.requests().is_empty(), "rejected URL was contacted");
    let localhost = guard.url.replace("127.0.0.1", "localhost");
    add(&sandbox, "loopback", &localhost, "guarded", &[], None);
    let names: Vec<_> = sandbox
        .profiles()
        .into_iter()
        .map(|profile| profile["profile"].clone())
        .collect();
    assert_eq!(names, vec![json!("loopback")]);

    let key = "sk-local-redirect-test-synthetic-marker-0004";
    let target = Fixture::serve("redirected", vec![final_reply("FOLLOWED")]);
    let redirect = Fixture::redirect_to(target.url.trim_end_matches("/v1"));
    // add может сам отвергнуть redirect при probe /models: это тоже допустимый отказ.
    let output = sandbox.rcode(
        &[
            "local",
            "add",
            "redirect",
            "--base-url",
            &redirect.url,
            "--runtime",
            "openai",
            "--model",
            "redirected",
            "--api-key-stdin",
        ],
        Some(key),
    );
    assert!(!text(&output).contains(key));
    let project = sandbox.project("project");
    let output = sandbox.exec(&project, Some("redirect"), "Ответь");
    assert!(!output.status.success(), "{}", text(&output));
    assert!(!text(&output).contains("FOLLOWED"));
    assert!(!text(&output).contains(key));
    assert!(target.requests().is_empty(), "redirect was followed");
}
