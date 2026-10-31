//! Headless end-to-end checks of local profiles through the real binary on
//! loopback fixtures (no live model, no paid API). Every process runs with a
//! cleared environment and its own RCODE_HOME; keys here are synthetic.
#![cfg(unix)]
mod support;

use serde_json::{Value, json};
use std::{
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};
use support::{Request, Response, Server, text_reply, tool_reply};

const DEADLINE: Duration = Duration::from_secs(40);
const CLOUD_MARKER: &str = "synthetic-cloud-env-marker";

struct Home {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    state: PathBuf,
}

impl Home {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        for dir in ["home", "xdg", "state"] {
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
        path.canonicalize().unwrap()
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rcode"));
        command.env_clear();
        for name in ["PATH", "TMPDIR"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command
            .env("HOME", self.root.join("home"))
            .env("XDG_CONFIG_HOME", self.root.join("xdg"))
            .env("RCODE_HOME", &self.state)
            // Synthetic cloud keys: a local profile must never send them.
            .env("OPENAI_API_KEY", format!("{CLOUD_MARKER}-openai"))
            .env("RCODE_CUSTOM_API_KEY", format!("{CLOUD_MARKER}-custom"))
            .env("OPENROUTER_API_KEY", format!("{CLOUD_MARKER}-router"))
            .args(args);
        command
    }

    fn run(&self, args: &[&str], stdin: Option<&str>) -> Output {
        let (child, stdout, stderr) = spawn(self.command(args), stdin);
        wait(child, stdout, stderr, DEADLINE)
    }

    fn ok(&self, args: &[&str], stdin: Option<&str>) -> Output {
        let output = self.run(args, stdin);
        assert!(output.status.success(), "rcode {args:?}\n{}", text(&output));
        output
    }

    fn add(&self, name: &str, base: &str, runtime: &str, model: &str, extra: &[&str]) {
        let mut args = vec![
            "local",
            "add",
            name,
            "--base-url",
            base,
            "--runtime",
            runtime,
            "--model",
            model,
        ];
        args.extend(extra);
        self.ok(&args, None);
    }

    fn exec(&self, project: &Path, extra: &[&str], prompt: &str) -> Output {
        let mut args = vec!["exec", "--json", "-C", project.to_str().unwrap()];
        args.extend(extra);
        args.push(prompt);
        self.run(&args, None)
    }

    fn files_text(&self) -> String {
        let mut text = String::new();
        let mut stack = vec![self.state.clone()];
        while let Some(path) = stack.pop() {
            if path.is_dir() {
                stack.extend(std::fs::read_dir(&path).unwrap().map(|e| e.unwrap().path()));
            } else if let Ok(content) = std::fs::read(&path) {
                text.push_str(&String::from_utf8_lossy(&content));
            }
        }
        text
    }
}

fn spawn(mut command: Command, stdin: Option<&str>) -> (Child, std::fs::File, std::fs::File) {
    let stdout = tempfile::tempfile().unwrap();
    let stderr = tempfile::tempfile().unwrap();
    command
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(stdout.try_clone().unwrap())
        .stderr(stderr.try_clone().unwrap());
    let mut child = command.spawn().unwrap();
    if let Some(input) = stdin {
        let mut pipe = child.stdin.take().unwrap();
        pipe.write_all(input.as_bytes()).unwrap();
    }
    (child, stdout, stderr)
}

fn wait(
    mut child: Child,
    mut stdout: std::fs::File,
    mut stderr: std::fs::File,
    deadline: Duration,
) -> Output {
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() > deadline {
            let _ = child.kill();
            panic!("rcode did not finish within {deadline:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let read = |file: &mut std::fs::File| {
        let mut bytes = Vec::new();
        file.rewind().unwrap();
        file.read_to_end(&mut bytes).unwrap();
        bytes
    };
    Output {
        status,
        stdout: read(&mut stdout),
        stderr: read(&mut stderr),
    }
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn events(output: &Output) -> Vec<Value> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

fn of_type<'a>(events: &'a [Value], kind: &str) -> Vec<&'a Value> {
    events
        .iter()
        .filter(|event| event["type"] == kind)
        .collect()
}

fn no_cloud_key(server: &Server) {
    for request in server.requests() {
        assert!(request.authorization().is_none(), "{:?}", request.headers);
        assert!(!String::from_utf8_lossy(&request.body).contains(CLOUD_MARKER));
    }
}

/// Chat models plus `/props` with a configurable context for llama.cpp.
fn local_server(model: &'static str, answer: &'static str) -> Server {
    Server::start(move |request, _| match request.path.as_str() {
        "/v1/models" => Response::json(
            200,
            json!({"data":[{"id":model},{"id":"nomic-embed-text"}]}),
        ),
        path if path.ends_with("/chat/completions") => text_reply(answer),
        _ => Response::json(404, json!({"error":"not found"})),
    })
}

fn system_text(request: &Request) -> String {
    request.json()["messages"][0]["content"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

#[test]
fn resume_local_session_uses_snapshot_endpoint_not_active_cloud() {
    let home = Home::new();
    let local = local_server("local-model", "FROM_LOCAL");
    let cloud = local_server("cloud-model", "FROM_CLOUD");
    std::fs::write(
        home.state.join("config.json"),
        json!({"version":1,"active":"custom","providers":{"custom":{"kind":"custom","model":"cloud-model","base_url":cloud.base()}}}).to_string(),
    )
    .unwrap();
    home.add("box", &local.base(), "openai", "local-model", &[]);
    let project = home.project("project");
    let first = home.exec(&project, &["--profile", "box"], "первый ход");
    assert!(first.status.success(), "{}", text(&first));
    // Active provider stays custom; resume without --provider keeps the local snapshot.
    let config: Value =
        serde_json::from_str(&std::fs::read_to_string(home.state.join("config.json")).unwrap())
            .unwrap();
    assert_eq!(config["active"], "custom");
    let resumed = home.exec(&project, &["--resume", "latest"], "продолжи");
    assert!(resumed.status.success(), "{}", text(&resumed));
    assert!(text(&resumed).contains("FROM_LOCAL"));
    assert_eq!(local.generations().len(), 2);
    assert!(
        cloud.requests().is_empty(),
        "cloud fixture must not be called"
    );
    no_cloud_key(&local);
}

#[test]
fn resume_with_deleted_profile_noauth_continues_keyed_fails_clearly() {
    let home = Home::new();
    let open = local_server("m", "OPEN_OK");
    let keyed = local_server("m", "KEYED_OK");
    let key = "sk-local-keyed-synthetic-0002";
    home.add("open", &open.base(), "openai", "m", &[]);
    home.ok(
        &[
            "local",
            "add",
            "keyed",
            "--base-url",
            &keyed.base(),
            "--runtime",
            "openai",
            "--model",
            "m",
            "--api-key-stdin",
        ],
        Some(key),
    );
    let a = home.project("a");
    let b = home.project("b");
    assert!(
        home.exec(&a, &["--profile", "open"], "ход")
            .status
            .success()
    );
    assert!(
        home.exec(&b, &["--profile", "keyed"], "ход")
            .status
            .success()
    );
    assert_eq!(
        keyed.generations()[0].authorization(),
        Some(format!("Bearer {key}").as_str())
    );
    home.ok(&["local", "remove", "open"], None);
    home.ok(&["local", "remove", "keyed"], None);
    assert!(
        !home.files_text().contains(key),
        "key must be deleted with its profile"
    );

    let resumed = home.exec(&a, &["--resume", "latest"], "дальше");
    assert!(resumed.status.success(), "{}", text(&resumed));
    assert_eq!(open.generations().len(), 2);
    no_cloud_key(&open);

    let before = keyed.requests().len();
    let refused = home.exec(&b, &["--resume", "latest"], "дальше");
    assert!(!refused.status.success());
    assert!(text(&refused).contains("удалён"), "{}", text(&refused));
    assert_eq!(
        keyed.requests().len(),
        before,
        "no request after the keyed profile is gone"
    );
}

#[test]
fn explicit_profile_or_provider_on_resume_overrides_snapshot() {
    let home = Home::new();
    let first = local_server("m1", "FROM_FIRST");
    let second = local_server("m2", "FROM_SECOND");
    let cloud = local_server("cloud-model", "FROM_CLOUD");
    std::fs::write(
        home.state.join("config.json"),
        json!({"version":1,"active":"custom","providers":{"custom":{"kind":"custom","model":"cloud-model","base_url":cloud.base()}}}).to_string(),
    )
    .unwrap();
    home.add("first", &first.base(), "openai", "m1", &[]);
    home.add("second", &second.base(), "openai", "m2", &[]);
    let project = home.project("project");
    assert!(
        home.exec(&project, &["--profile", "first"], "ход")
            .status
            .success()
    );
    let switched = home.exec(
        &project,
        &["--resume", "latest", "--profile", "second"],
        "ход",
    );
    assert!(switched.status.success(), "{}", text(&switched));
    assert!(text(&switched).contains("FROM_SECOND"));
    assert_eq!(second.generations()[0].json()["model"], "m2");
    let to_cloud = home.exec(
        &project,
        &["--resume", "latest", "--provider", "custom"],
        "ход",
    );
    assert!(to_cloud.status.success(), "{}", text(&to_cloud));
    assert_eq!(
        cloud.generations()[0].authorization(),
        Some(format!("Bearer {CLOUD_MARKER}-custom").as_str())
    );
    assert_eq!(first.generations().len(), 1);
    no_cloud_key(&first);
    no_cloud_key(&second);
}

#[test]
fn profile_flag_conflicts_with_cloud_provider_and_unknown_profile_fails_before_network() {
    let home = Home::new();
    let server = local_server("m", "never");
    home.add("box", &server.base(), "openai", "m", &[]);
    let project = home.project("project");
    let conflict = home.exec(
        &project,
        &["--provider", "custom", "--profile", "box"],
        "ход",
    );
    assert!(!conflict.status.success());
    assert!(text(&conflict).contains("--profile"), "{}", text(&conflict));
    let unknown = home.exec(&project, &["--profile", "missing"], "ход");
    assert!(!unknown.status.success());
    assert!(
        text(&unknown).contains("rcode local list"),
        "{}",
        text(&unknown)
    );
    let invalid = home.exec(&project, &["--profile", "Bad Name"], "ход");
    assert!(!invalid.status.success());
    assert!(server.generations().is_empty());
}

#[test]
fn doctor_local_reports_profile_without_network_and_check_reads_runtime_context() {
    let home = Home::new();
    let server = Server::start(|request, _| match request.path.as_str() {
        "/v1/models" => Response::json(200, json!({"data":[{"id":"m","owned_by":"llamacpp"}]})),
        "/props" => Response::json(
            200,
            json!({"default_generation_settings":{"n_ctx":8192},"total_slots":1}),
        ),
        _ => Response::json(404, json!({})),
    });
    home.add("llama", &server.base(), "llamacpp", "m", &[]);
    let output = home.ok(&["doctor", "--json", "--profile", "llama"], None);
    let report = &of_type(&events(&output), "doctor")[0].clone();
    assert_eq!(report["local"], true);
    assert_eq!(report["provider"], "local");
    assert_eq!(report["profile"], "llama");
    assert_eq!(report["credential"], "not_required");
    assert_eq!(report["context_tokens"], 32768);
    assert_eq!(report["context_source"], "profile");
    assert_eq!(report["network_checked"], false);
    assert!(
        server.requests().is_empty(),
        "doctor without --check stays offline"
    );

    let output = home.ok(&["doctor", "--check", "--json", "--profile", "llama"], None);
    let report = &of_type(&events(&output), "doctor")[0].clone();
    assert_eq!(report["network_checked"], true);
    assert_eq!(report["models"], 1);
    assert_eq!(report["context_tokens"], 8192);
    assert_eq!(report["context_source"], "runtime");
    no_cloud_key(&server);
    // Read-only metadata only: no generation, no write to the server.
    assert!(
        server
            .requests()
            .iter()
            .all(|request| request.method == "GET")
    );

    // A profile that requires a key and has none is reported, not guessed.
    home.ok(
        &[
            "local",
            "add",
            "locked",
            "--base-url",
            &server.base(),
            "--runtime",
            "openai",
            "--model",
            "m",
            "--api-key-stdin",
        ],
        Some("sk-local-locked-synthetic-0003"),
    );
    home.ok(&["local", "key", "locked", "--delete"], None);
    let output = home.run(&["doctor", "--json", "--profile", "locked"], None);
    assert_eq!(output.status.code(), Some(2), "{}", text(&output));
    assert_eq!(
        of_type(&events(&output), "doctor")[0]["credential"],
        "missing"
    );
}

#[test]
fn models_provider_local_lists_chat_models_only() {
    let home = Home::new();
    let server = local_server("chat-model", "unused");
    home.add(
        "box",
        &server.base(),
        "openai",
        "chat-model",
        &["--activate"],
    );
    let output = home.ok(&["models", "--provider", "local", "--json"], None);
    let ids: Vec<String> = of_type(&events(&output), "model")
        .iter()
        .map(|model| model["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(ids, ["chat-model"], "embedding models are hidden");
    no_cloud_key(&server);
}

#[test]
fn help_mentions_local_commands() {
    let home = Home::new();
    let top = text(&home.ok(&["--help"], None));
    assert!(
        top.contains("локальн") && top.contains("--profile"),
        "{top}"
    );
    let local = text(&home.ok(&["local", "--help"], None));
    for command in ["discover", "list", "add", "use", "key", "remove"] {
        assert!(local.contains(command), "{command}: {local}");
    }
    let add = text(&home.ok(&["local", "add", "--help"], None));
    assert!(
        add.contains("--api-key-stdin") && add.contains("--context-tokens"),
        "{add}"
    );
    assert!(!add.contains("--api-key "), "a key is never an argument");
}

#[test]
fn small_server_context_warns_once_and_caps_output() {
    let home = Home::new();
    let server = Server::start(|request, _| match request.path.as_str() {
        "/props" => Response::json(200, json!({"default_generation_settings":{"n_ctx":12288}})),
        path if path.ends_with("/chat/completions") => text_reply("SMALL_OK"),
        _ => Response::json(404, json!({})),
    });
    home.add("llama", &server.base(), "llamacpp", "m", &["--activate"]);
    let project = home.project("project");
    let output = home.exec(&project, &["--provider", "local"], "привет");
    assert!(output.status.success(), "{}", text(&output));
    let all = events(&output);
    let warnings = of_type(&all, "warning");
    assert_eq!(warnings.len(), 1, "{all:?}");
    assert!(warnings[0]["message"].as_str().unwrap().contains("12288"));
    // A quarter of the server context bounds the answer reserve.
    assert_eq!(server.generations()[0].json()["max_tokens"], 3072);
    assert!(
        server.generations()[0]
            .json()
            .get("reasoning_effort")
            .is_none()
    );
}

fn big_prompt(tag: &str, chars: usize) -> String {
    let mut prompt = format!("{tag} ");
    while prompt.len() < chars {
        prompt.push_str("lorem ipsum dolor sit amet ");
    }
    prompt
}

#[test]
fn local_history_compacts_in_estimated_tokens_before_network() {
    let home = Home::new();
    let server = local_server("m", "OK");
    // 16384 context: limit 16384 - 4096 - 1638 = 10650 estimated tokens per request.
    home.add(
        "small",
        &server.base(),
        "openai",
        "m",
        &["--activate", "--context-tokens", "16384"],
    );
    let project = home.project("project");
    let mut compacted = Vec::new();
    for turn in 0..4 {
        let resume: &[&str] = if turn == 0 {
            &[]
        } else {
            &["--resume", "latest"]
        };
        let output = home.exec(&project, resume, &big_prompt(&format!("TURN{turn}"), 7000));
        assert!(output.status.success(), "turn {turn}: {}", text(&output));
        compacted.extend(
            of_type(&events(&output), "context_compacted")
                .into_iter()
                .cloned(),
        );
    }
    assert!(
        !compacted.is_empty(),
        "history must be compacted before the server overflows"
    );
    assert_eq!(compacted[0]["unit"], "estimated_tokens");
    assert!(compacted[0].get("before_chars").is_none());
    for request in server.generations() {
        let body = String::from_utf8_lossy(&request.body).into_owned();
        // ASCII bytes / 2.5 is the estimate rcode uses; JSON framing adds a little.
        assert!(
            body.len() * 2 / 5 <= 10650 + 1500,
            "request too large: {}",
            body.len()
        );
    }
    let last = server.generations().pop().unwrap();
    assert!(!String::from_utf8_lossy(&last.body).contains(&big_prompt("TURN0", 7000)));
}

#[test]
fn oversized_local_request_is_blocked_in_tokens_without_generation() {
    let home = Home::new();
    let server = local_server("m", "never");
    home.add(
        "small",
        &server.base(),
        "openai",
        "m",
        &["--activate", "--context-tokens", "16384"],
    );
    let project = home.project("project");
    let output = home.exec(&project, &[], &big_prompt("HUGE", 60_000));
    assert_eq!(output.status.code(), Some(1), "{}", text(&output));
    let all = events(&output);
    let errors = of_type(&all, "error");
    let message = errors[0]["message"].as_str().unwrap();
    assert!(message.contains("оценочных токенов"), "{message}");
    assert!(server.generations().is_empty());
}

#[test]
fn subagent_on_same_local_server_runs_single_flight_without_deadlock() {
    let home = Home::new();
    let server = Server::start(|request, _| {
        if !request.is_generation() {
            return Response::json(404, json!({}));
        }
        let messages = request.json()["messages"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if system_text(request).contains("subagent") {
            return text_reply("SUB_DONE").delayed(Duration::from_millis(60));
        }
        let spawned = messages.iter().any(|message| message["role"] == "tool");
        if spawned {
            text_reply("MAIN_DONE").delayed(Duration::from_millis(60))
        } else {
            tool_reply(
                "call-spawn",
                "spawn_agent",
                &json!({"task":"осмотри проект","role":"explorer"}),
            )
            .delayed(Duration::from_millis(30))
        }
    });
    home.add("box", &server.base(), "openai", "m", &["--activate"]);
    let project = home.project("project");
    let output = home.exec(&project, &[], "делегируй осмотр");
    assert!(output.status.success(), "{}", text(&output));
    let all = events(&output);
    let waited = of_type(&all, "tool_result").into_iter().any(|result| {
        result["name"] == "wait_agent"
            && result["content"]
                .as_str()
                .unwrap_or_default()
                .contains("SUB_DONE")
    });
    assert!(waited, "{all:?}");
    assert!(server.generations().len() >= 3);
    assert_eq!(
        server.max_concurrent_generations(),
        1,
        "one generation per local server"
    );
    no_cloud_key(&server);
}

#[test]
fn reasoning_is_neither_shown_nor_saved() {
    let home = Home::new();
    let server = Server::start(|request, _| {
        if !request.is_generation() {
            return Response::json(404, json!({}));
        }
        Response::sse(&[
            json!({"choices":[{"index":0,"delta":{"role":"assistant","reasoning_content":"SECRET_THOUGHT_A"}}]}),
            json!({"choices":[{"index":0,"delta":{"content":"<think>SECRET_THOUGHT_B</think>\n\nVISIBLE `<think>` ANSWER"}}]}),
            json!({"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}),
        ])
    });
    home.add("box", &server.base(), "openai", "m", &["--activate"]);
    let project = home.project("project");
    let output = home.exec(&project, &[], "вопрос");
    assert!(output.status.success(), "{}", text(&output));
    let shown = text(&output);
    assert!(shown.contains("VISIBLE `<think>` ANSWER"), "{shown}");
    assert!(!shown.contains("SECRET_THOUGHT"), "{shown}");
    let saved = home.files_text();
    assert!(saved.contains("VISIBLE"));
    assert!(
        !saved.contains("SECRET_THOUGHT"),
        "reasoning must not be persisted"
    );
    // The next request does not send reasoning back either.
    let next = home.exec(&project, &["--resume", "latest"], "ещё");
    assert!(next.status.success());
    let body = String::from_utf8_lossy(&server.generations()[1].body).into_owned();
    assert!(!body.contains("SECRET_THOUGHT"));
}

#[test]
fn sigint_during_local_generation_exits_130_and_resume_continues() {
    let home = Home::new();
    let server = Server::start(|request, index| {
        if !request.is_generation() {
            return Response::json(404, json!({}));
        }
        if index == 0 {
            // Slow stream: the CLI is interrupted while it reads it.
            let mut events = vec![
                json!({"choices":[{"index":0,"delta":{"role":"assistant","content":"PARTIAL"}}]}),
            ];
            events
                .extend((0..50).map(|_| json!({"choices":[{"index":0,"delta":{"content":"."}}]})));
            Response::sse(&events).delayed(Duration::from_millis(100))
        } else {
            text_reply("AFTER_CANCEL")
        }
    });
    home.add("box", &server.base(), "openai", "m", &["--activate"]);
    let project = home.project("project");
    let (child, stdout, stderr) = spawn(
        home.command(&[
            "exec",
            "--json",
            "-C",
            project.to_str().unwrap(),
            "долгий ответ",
        ]),
        None,
    );
    let start = Instant::now();
    while server.generations().is_empty() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "no generation started"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(300));
    // SAFETY: the pid belongs to the child spawned above and SIGINT is valid.
    assert_eq!(
        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGINT) },
        0
    );
    let output = wait(child, stdout, stderr, Duration::from_secs(10));
    assert_eq!(output.status.code(), Some(130), "{}", text(&output));
    let resumed = home.exec(&project, &["--resume", "latest"], "продолжи");
    assert!(resumed.status.success(), "{}", text(&resumed));
    assert!(text(&resumed).contains("AFTER_CANCEL"));
    assert_eq!(server.generations().len(), 2);
}

/// Connections accepted on [::1]:port; `None` when IPv6 loopback is unavailable.
fn ipv6_listener(port: u16) -> Option<std::sync::Arc<std::sync::atomic::AtomicUsize>> {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let listener = std::net::TcpListener::bind(("::1", port)).ok()?;
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            if stream.is_ok() {
                count.fetch_add(1, Ordering::SeqCst);
            }
        }
    });
    Some(accepted)
}

#[test]
fn profile_key_never_follows_a_base_url_override_or_another_loopback_alias() {
    use std::sync::atomic::Ordering;
    let home = Home::new();
    let real = local_server("m", "REAL_OK");
    let other = local_server("m", "OTHER");
    let key = "sk-local-bound-synthetic-0004";
    home.ok(
        &[
            "local",
            "add",
            "keyed",
            "--base-url",
            &real.base(),
            "--runtime",
            "openai",
            "--model",
            "m",
            "--api-key-stdin",
        ],
        Some(key),
    );
    let project = home.project("project");
    let moved = home.exec(
        &project,
        &["--profile", "keyed", "--base-url", &other.base()],
        "ход",
    );
    assert!(!moved.status.success(), "{}", text(&moved));
    assert!(!text(&moved).contains(key));
    assert!(other.requests().is_empty() && real.requests().is_empty());

    if let Some(accepted) = ipv6_listener(real.port) {
        let alias = format!("http://[::1]:{}/v1", real.port);
        let output = home.exec(
            &project,
            &["--profile", "keyed", "--base-url", &alias],
            "ход",
        );
        assert!(!output.status.success(), "{}", text(&output));
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            0,
            "[::1] is another endpoint"
        );
    }

    // `localhost` is the same literal 127.0.0.1 endpoint and keeps the key.
    let same = format!("http://localhost:{}/v1", real.port);
    let output = home.exec(
        &project,
        &["--profile", "keyed", "--base-url", &same],
        "ход",
    );
    assert!(output.status.success(), "{}", text(&output));
    assert!(text(&output).contains("REAL_OK"));
    assert_eq!(
        real.generations()[0].authorization(),
        Some(format!("Bearer {key}").as_str())
    );
    assert!(!text(&output).contains(key));
}

#[test]
fn mlx_template_reasoning_with_orphan_close_is_hidden() {
    let home = Home::new();
    let server = Server::start(|request, _| {
        if !request.is_generation() {
            return Response::json(404, json!({}));
        }
        Response::sse(&[
            json!({"choices":[{"index":0,"delta":{"role":"assistant","content":"HIDDEN_PLAN: прочитать"}}]}),
            json!({"choices":[{"index":0,"delta":{"content":" файл</thi"}}]}),
            json!({"choices":[{"index":0,"delta":{"content":"nk>\n\nОТВЕТ МОДЕЛИ"}}]}),
            json!({"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}),
        ])
    });
    home.add("mlx", &server.base(), "mlx", "m", &["--activate"]);
    let project = home.project("project");
    let output = home.exec(&project, &[], "вопрос");
    assert!(output.status.success(), "{}", text(&output));
    assert!(text(&output).contains("ОТВЕТ МОДЕЛИ"));
    assert!(!text(&output).contains("HIDDEN_PLAN"));
    assert!(!home.files_text().contains("HIDDEN_PLAN"));
}

#[test]
fn add_without_model_takes_the_first_chat_model_or_asks_for_one() {
    let home = Home::new();
    let server = Server::start(|request, _| match request.path.as_str() {
        "/v1/models" => Response::json(
            200,
            json!({"data":[{"id":"text-embedding-nomic"},{"id":"chat-first"},{"id":"chat-second"}]}),
        ),
        _ => Response::json(404, json!({})),
    });
    let output = home.ok(
        &[
            "local",
            "add",
            "auto",
            "--base-url",
            &server.base(),
            "--runtime",
            "openai",
        ],
        None,
    );
    assert!(text(&output).contains("chat-first"), "{}", text(&output));
    let listed = home.ok(&["local", "list", "--json"], None);
    let rows = of_type(&events(&listed), "local_profile")
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(rows[0]["model"], "chat-first");
    assert!(
        server.generations().is_empty(),
        "adding a profile never generates"
    );
    no_cloud_key(&server);

    // A stopped server: the profile needs an explicit --model and nothing is saved.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "http://127.0.0.1:{}/v1",
        closed.local_addr().unwrap().port()
    );
    drop(closed);
    let output = home.run(
        &[
            "local",
            "add",
            "later",
            "--base-url",
            &url,
            "--runtime",
            "openai",
        ],
        None,
    );
    assert!(!output.status.success());
    assert!(text(&output).contains("--model"), "{}", text(&output));
    home.ok(
        &[
            "local",
            "add",
            "later",
            "--base-url",
            &url,
            "--runtime",
            "openai",
            "--model",
            "m",
        ],
        None,
    );
}

#[test]
fn key_requirement_follows_stored_keys_and_replaced_addresses() {
    let home = Home::new();
    let server = local_server("m", "KEYED_OK");
    let other = local_server("m", "OTHER_OK");
    let key = "sk-local-replace-synthetic-0006";
    let project = home.project("project");
    let key_of = |name: &str| {
        let listed = home.ok(&["local", "list", "--json"], None);
        of_type(&events(&listed), "local_profile")
            .into_iter()
            .find(|row| row["profile"] == name)
            .map(|row| row["key"].as_str().unwrap().to_owned())
            .unwrap()
    };

    // A key stored later marks the profile as requiring one: after --delete
    // requests stop before the network instead of going out unauthenticated.
    home.add("p", &server.base(), "openai", "m", &[]);
    home.ok(&["local", "key", "p", "--stdin"], Some(key));
    home.ok(&["local", "key", "p", "--delete"], None);
    let blocked = home.exec(&project, &["--profile", "p"], "ход");
    assert!(!blocked.status.success());
    assert!(
        text(&blocked).contains("rcode local key p --stdin"),
        "{}",
        text(&blocked)
    );
    assert!(server.requests().is_empty());

    // Re-adding on the same address keeps the key; a new address drops it.
    home.ok(
        &[
            "local",
            "add",
            "q",
            "--base-url",
            &server.base(),
            "--runtime",
            "openai",
            "--model",
            "m",
            "--api-key-stdin",
        ],
        Some(key),
    );
    home.ok(
        &[
            "local",
            "add",
            "q",
            "--base-url",
            &server.base(),
            "--runtime",
            "openai",
            "--model",
            "m2",
            "--force",
        ],
        None,
    );
    assert_eq!(key_of("q"), "stored");
    let output = home.exec(&project, &["--profile", "q"], "ход");
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(
        server.generations()[0].authorization(),
        Some(format!("Bearer {key}").as_str())
    );
    home.ok(
        &[
            "local",
            "add",
            "q",
            "--base-url",
            &other.base(),
            "--runtime",
            "openai",
            "--model",
            "m",
            "--force",
        ],
        None,
    );
    assert_eq!(key_of("q"), "none");
    let output = home.exec(&project, &["--profile", "q"], "ход");
    assert!(output.status.success(), "{}", text(&output));
    no_cloud_key(&other);
    assert!(
        !home.files_text().contains(key),
        "the key of the old address is deleted"
    );
}

#[test]
fn new_profile_never_inherits_an_orphan_key_of_its_name() {
    let home = Home::new();
    let server = local_server("m", "FRESH_OK");
    let orphan = "sk-local-orphan-synthetic-0007";
    let project = home.project("project");
    // A key left under the name, e.g. by a session whose profile was removed.
    rcode::config::ConfigStore::at(&home.state)
        .unwrap()
        .save_local_credential("p", orphan)
        .unwrap();
    home.add("p", &server.base(), "openai", "m", &[]);
    let listed = home.ok(&["local", "list", "--json"], None);
    let rows = of_type(&events(&listed), "local_profile")
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["key"], "none", "{rows:?}");
    let output = home.exec(&project, &["--profile", "p"], "ход");
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(server.generations().len(), 1);
    no_cloud_key(&server);
    assert!(
        !home.files_text().contains(orphan),
        "the orphan key is deleted when the name is created again"
    );
}
