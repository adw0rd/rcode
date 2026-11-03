//! Сквозные сценарии `web_search` (Yandex/Brave/Tavily): настоящий
//! `rcode exec --json` против loopback-fixture поискового API и модельного
//! сервера. Без внешней сети. Ключ передаётся как credential, не через argv.
mod support;

use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    process::Output,
};
use support::{Response, Server, text_reply, tool_reply};

const API_KEY: &str = "websearch-fixture-key-0001";
const SEARCH_KEY: &str = "search-fixture-key-0000000001";

struct Sandbox {
    _tmp: tempfile::TempDir,
    project: std::path::PathBuf,
    state: std::path::PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        std::fs::create_dir_all(root.join("home")).unwrap();
        std::fs::create_dir_all(root.join("state")).unwrap();
        std::fs::create_dir_all(root.join("project")).unwrap();
        Self {
            state: root.join("state"),
            project: root.join("project"),
            _tmp: tmp,
        }
    }

    fn home(&self) -> std::path::PathBuf {
        self._tmp.path().join("home")
    }

    fn rcode(&self, args: &[&str]) -> Output {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_rcode"));
        command.env_clear();
        for name in ["PATH", "TMPDIR", "SYSTEMROOT"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command
            .env("HOME", self.home())
            .env("USERPROFILE", self.home())
            .env("RCODE_HOME", &self.state)
            .env("RCODE_CUSTOM_API_KEY", API_KEY)
            .args(args);
        run(command)
    }

    fn exec(&self, server: &Server, prompt: &str) -> Output {
        let base = server.base();
        self.rcode(&[
            "-C",
            self.project.to_str().unwrap(),
            "--provider",
            "custom",
            "--base-url",
            &base,
            "--model",
            "fixture-model",
            "--json",
            "exec",
            prompt,
        ])
    }
}

fn run(mut command: std::process::Command) -> Output {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let mut child = command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return Output {
                status,
                stdout: take(&mut child).into_bytes(),
                stderr: Vec::new(),
            };
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("rcode превысил 60 с");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

fn take(child: &mut std::process::Child) -> String {
    if let Some(mut stdout) = child.stdout.take() {
        let mut text = String::new();
        let _ = stdout.read_to_string(&mut text);
        return text;
    }
    String::new()
}

fn stdout_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn events(output: &Output) -> Vec<Value> {
    stdout_text(output)
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

fn tool_results(output: &Output) -> Vec<Value> {
    events(output)
        .into_iter()
        .filter(|event| event["type"] == "tool_result" && event["name"] == "web_search")
        .map(|event| {
            serde_json::from_str::<Value>(event["content"].as_str().unwrap_or("{}")).unwrap()
        })
        .collect()
}

#[test]
fn unconfigured_search_returns_instructions_without_prompt() {
    let sandbox = Sandbox::new();
    let server = Server::start(|request, index| {
        if !request.is_generation() {
            return no_generation();
        }
        if index == 0 {
            return tool_reply("w1", "web_search", &json!({"query": "rcode rust"}));
        }
        text_reply("Готово")
    });
    let output = sandbox.exec(&server, "Найди в интернете rcode rust");
    let receipts = tool_results(&output);
    assert_eq!(receipts.len(), 1, "{}", stdout_text(&output));
    assert_eq!(receipts[0]["error"], "not_configured");
    assert!(
        receipts[0]["message"]
            .as_str()
            .unwrap()
            .contains("rcode websearch provider"),
        "{}",
        stdout_text(&output)
    );
    let guidance = receipts[0]["message"].as_str().unwrap();
    for provider in ["Yandex Search API", "Brave Search API", "Tavily"] {
        assert!(
            guidance.contains(provider),
            "Нет понятного выбора {provider}: {guidance}"
        );
    }
    assert!(guidance.contains("/websearch") && guidance.contains("rcode websearch key"));
    assert!(
        !guidance.contains("echo КЛЮЧ"),
        "Ключ не должен вводиться в аргументах команды или истории shell"
    );
}

#[test]
fn configured_brave_searches_and_returns_results() {
    let sandbox = Sandbox::new();
    let search_body = r#"{"web": {"results": [
        {"title": "Rcode", "url": "https://github.com/adw0rd/rcode", "description": "Терминальный агент"}
    ]}}"#;
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        search_body.len()
    );
    let mut response = head.into_bytes();
    response.extend_from_slice(search_body.as_bytes());
    let (port, listener) = serve(response);
    let base = format!("http://127.0.0.1:{port}");
    configure_sandbox(&sandbox, "brave", Some(&base));
    let server = Server::start(move |request, index| {
        if !request.is_generation() {
            return no_generation();
        }
        if index == 0 {
            return tool_reply(
                "w1",
                "web_search",
                &json!({"query": "rcode rust", "max_results": 3}),
            );
        }
        text_reply("Ответ готов")
    });
    let output = sandbox.exec(&server, "Найди rcode rust");
    assert!(
        output.status.success(),
        "{} {}",
        stdout_text(&output),
        String::from_utf8_lossy(&output.stderr)
    );
    let receipts = tool_results(&output);
    assert_eq!(receipts.len(), 1, "{}", stdout_text(&output));
    assert_eq!(receipts[0]["provider"], "brave");
    assert_eq!(receipts[0]["count"], 1);
    assert_eq!(receipts[0]["results"][0]["title"], "Rcode");
    let _listener_guard = listener;
}

#[test]
fn reflected_search_keys_never_enter_results_model_history_or_events() {
    for (key, reflected) in [
        (SEARCH_KEY, SEARCH_KEY),
        ("synthetic-/+key", "synthetic-%2F%2Bkey"),
    ] {
        let sandbox = Sandbox::new();
        let search_api = Server::start(move |_, _| {
            Response::json(
                200,
                json!({"results":[{
                    "title":format!("API reflected {reflected}"),
                    "url":format!("https://fixture.invalid/?debug={reflected}"),
                    "content":format!("prefix {reflected} suffix")
                }]}),
            )
        });
        configure_sandbox(&sandbox, "tavily", Some(&search_api.url));
        std::fs::write(
            sandbox.state.join("credentials.json"),
            json!({"version":1,"providers":{"custom":API_KEY,"websearch:tavily":key}}).to_string(),
        )
        .unwrap();
        let model = Server::start(|request, index| {
            if !request.is_generation() {
                return no_generation();
            }
            if index == 0 {
                return tool_reply("w1", "web_search", &json!({"query":"fixture"}));
            }
            text_reply("Ответ с отредактированным результатом")
        });
        let output = sandbox.exec(&model, "Найди fixture");
        assert!(output.status.success());
        assert!(
            !stdout_text(&output).contains(reflected),
            "Ключ попал в JSONL результата"
        );
        assert!(
            model
                .generations()
                .iter()
                .all(|request| !request.json().to_string().contains(reflected)),
            "Ключ передан модели"
        );
        let session = std::fs::read_dir(sandbox.state.join("sessions"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path()
            .join("session.json");
        assert!(
            !std::fs::read_to_string(session)
                .unwrap()
                .contains(reflected),
            "Ключ сохранён в историю"
        );
        assert!(
            tool_results(&output)[0]["results"][0]["snippet"]
                .as_str()
                .unwrap()
                .contains("[REDACTED]")
        );
    }
}

fn configure_sandbox(sandbox: &Sandbox, provider: &str, base: Option<&str>) {
    let mut config = json!({
        "version": 1,
        "active": "custom",
        "providers": {"custom": {"kind": "custom", "model": "fixture-model", "base_url": "https://fixture.invalid/v1"}},
        "websearch": {"provider": provider}
    });
    if let Some(base) = base {
        config["websearch"]["base_url"] = json!(base);
    }
    let path = sandbox.state.join("config.json");
    std::fs::write(&path, serde_json::to_string(&config).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let credential_id = format!("websearch:{provider}");
    let credentials =
        json!({"version": 1, "providers": {"custom": API_KEY, (credential_id): SEARCH_KEY}});
    let path = sandbox.state.join("credentials.json");
    std::fs::write(&path, serde_json::to_string(&credentials).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn serve(response: Vec<u8>) -> (u16, std::sync::Arc<std::net::TcpListener>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let listener = std::sync::Arc::new(listener);
    let shared = listener.clone();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = shared.accept() {
            let mut buffer = [0u8; 8192];
            let _ = stream.read(&mut buffer);
            let _ = stream.write_all(&response);
        }
    });
    (port, listener)
}

fn no_generation() -> Response {
    Response::sse(&[json!({"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})])
}

#[test]
fn yandex_search_receives_api_key_and_folder_id() {
    let sandbox = Sandbox::new();
    let search_body = r#"{"docs": [{"url": "https://ya.example", "title": "Y", "snippet": "S"}]}"#;
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        search_body.len()
    );
    let mut response = head.into_bytes();
    response.extend_from_slice(search_body.as_bytes());
    let (port, listener) = serve(response);
    let base = format!("http://127.0.0.1:{port}");
    configure_sandbox(&sandbox, "yandex", Some(&base));
    let mut config: Value =
        serde_json::from_str(&std::fs::read_to_string(sandbox.state.join("config.json")).unwrap())
            .unwrap();
    config["websearch"]["folder_id"] = json!("folder-123");
    std::fs::write(
        sandbox.state.join("config.json"),
        serde_json::to_string(&config).unwrap(),
    )
    .unwrap();
    let server = Server::start(move |request, index| {
        if !request.is_generation() {
            return no_generation();
        }
        if index == 0 {
            return tool_reply("w1", "web_search", &json!({"query": "тест"}));
        }
        text_reply("Ответ готов")
    });
    let output = sandbox.exec(&server, "Найди тест");
    assert!(
        output.status.success(),
        "{} {}",
        stdout_text(&output),
        String::from_utf8_lossy(&output.stderr)
    );
    let receipts = tool_results(&output);
    assert_eq!(receipts[0]["provider"], "yandex");
    assert_eq!(receipts[0]["results"][0]["url"], "https://ya.example");
    let _listener_guard = listener;
}

#[test]
fn websearch_key_accepts_the_documented_stdin_flag() {
    let sandbox = Sandbox::new();
    assert!(
        sandbox
            .rcode(&["websearch", "provider", "tavily"])
            .status
            .success()
    );
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_rcode"))
        .args(["websearch", "key", "--stdin"])
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .envs(std::env::var_os("SYSTEMROOT").map(|value| ("SYSTEMROOT", value)))
        .env("RCODE_HOME", &sandbox.state)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(SEARCH_KEY.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let credentials: Value =
        serde_json::from_slice(&std::fs::read(sandbox.state.join("credentials.json")).unwrap())
            .unwrap();
    assert_eq!(credentials["providers"]["websearch:tavily"], SEARCH_KEY);
    assert!(!stdout_text(&output).contains(SEARCH_KEY));
}

#[test]
fn websearch_cli_manages_provider_and_key() {
    let sandbox = Sandbox::new();
    let status = sandbox.rcode(&["websearch", "status", "--json"]);
    assert!(status.status.success(), "{}", stdout_text(&status));
    assert!(events(&status).iter().any(|e| e["provider"] == Value::Null));

    let missing_provider = sandbox.rcode(&["websearch", "provider", "unknown"]);
    assert_eq!(missing_provider.status.code(), Some(2));

    let key_without_provider = sandbox.rcode(&["websearch", "key", "--api-key-stdin"]);
    assert_eq!(key_without_provider.status.code(), Some(2));

    let set = sandbox.rcode(&["websearch", "provider", "brave", "--json"]);
    assert!(set.status.success(), "{}", stdout_text(&set));
    let set = sandbox.rcode(&["websearch", "key", "--api-key-stdin"]);
    // Ключ не подан в stdin: команда должна упасть, а не сохранить пустоту.
    assert!(set.status.code() != Some(0), "{}", stdout_text(&set));

    let mut key_input = std::process::Command::new(env!("CARGO_BIN_EXE_rcode"));
    key_input
        .args(["websearch", "key", "--api-key-stdin"])
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", sandbox.home())
        .env("RCODE_HOME", &sandbox.state)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = key_input.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(SEARCH_KEY.as_bytes())
        .unwrap();
    drop(child.stdin.take());
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let credentials: Value = serde_json::from_str(
        &std::fs::read_to_string(sandbox.state.join("credentials.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(credentials["providers"]["websearch:brave"], SEARCH_KEY);

    let status = sandbox.rcode(&["websearch", "status", "--json"]);
    assert!(
        events(&status)
            .iter()
            .any(|e| e["provider"] == "brave" && e["key"] == true)
    );

    let clear = sandbox.rcode(&["websearch", "clear", "--json"]);
    assert!(clear.status.success());
    let credentials: Value = serde_json::from_str(
        &std::fs::read_to_string(sandbox.state.join("credentials.json")).unwrap(),
    )
    .unwrap();
    assert!(credentials["providers"].get("websearch").is_none());
    assert!(credentials["providers"].get("websearch:brave").is_none());
}

#[test]
fn changing_search_provider_requires_its_own_key_and_resets_api_options() {
    let sandbox = Sandbox::new();
    configure_sandbox(&sandbox, "brave", Some("http://127.0.0.1:9"));
    let mut config: Value =
        serde_json::from_slice(&std::fs::read(sandbox.state.join("config.json")).unwrap()).unwrap();
    config["websearch"]["folder_id"] = json!("old-folder");
    std::fs::write(sandbox.state.join("config.json"), config.to_string()).unwrap();
    // Reselecting the same API must preserve a valid key and its configuration.
    assert!(
        sandbox
            .rcode(&["websearch", "provider", "brave"])
            .status
            .success()
    );
    assert!(
        events(&sandbox.rcode(&["websearch", "status", "--json"]))
            .iter()
            .any(|event| event["provider"] == "brave" && event["key"] == true)
    );
    assert!(
        sandbox
            .rcode(&["websearch", "provider", "tavily"])
            .status
            .success()
    );
    let status = sandbox.rcode(&["websearch", "status", "--json"]);
    assert!(
        events(&status).iter().all(|event| event["key"] == false),
        "{}",
        stdout_text(&status)
    );
    let changed: Value =
        serde_json::from_slice(&std::fs::read(sandbox.state.join("config.json")).unwrap()).unwrap();
    assert!(changed["websearch"]["base_url"].is_null());
    assert!(changed["websearch"]["folder_id"].is_null());
}

#[test]
fn legacy_or_other_api_search_keys_never_reach_the_selected_provider() {
    for slot in ["websearch", "websearch:brave"] {
        let sandbox = Sandbox::new();
        let search_api = Server::start(|_, _| {
            Response::json(
                200,
                json!({"results":[{
                    "title":"Fixture", "url":"https://fixture.invalid", "content":"fixture"
                }]}),
            )
        });
        configure_sandbox(&sandbox, "tavily", Some(&search_api.url));
        std::fs::write(
            sandbox.state.join("credentials.json"),
            json!({
                "version":1, "providers":{"custom":API_KEY, (slot):SEARCH_KEY}
            })
            .to_string(),
        )
        .unwrap();
        let model = Server::start(|request, index| {
            if !request.is_generation() {
                return no_generation();
            }
            if index == 0 {
                return tool_reply("w1", "web_search", &json!({"query":"fixture"}));
            }
            text_reply("Настройте ключ выбранного API")
        });
        let output = sandbox.exec(&model, "Найди fixture");
        let receipts = tool_results(&output);
        assert_eq!(
            receipts[0]["error"],
            "not_configured",
            "{slot}: {}",
            stdout_text(&output)
        );
        assert!(
            search_api.requests().is_empty(),
            "Непривязанный ключ отправлен в API"
        );
    }
}

#[test]
fn clearing_search_removes_scoped_and_legacy_keys_but_preserves_model_keys() {
    let sandbox = Sandbox::new();
    configure_sandbox(&sandbox, "tavily", None);
    std::fs::write(sandbox.state.join("credentials.json"), json!({
        "version":1, "providers":{"custom":API_KEY,"websearch":SEARCH_KEY,
            "websearch:yandex":SEARCH_KEY,"websearch:brave":SEARCH_KEY,"websearch:tavily":SEARCH_KEY}
    }).to_string()).unwrap();
    assert!(sandbox.rcode(&["websearch", "clear"]).status.success());
    let credentials: Value =
        serde_json::from_slice(&std::fs::read(sandbox.state.join("credentials.json")).unwrap())
            .unwrap();
    assert_eq!(credentials["providers"], json!({"custom":API_KEY}));
}

/// Живой вызов Tavily: запускается только с TAVILY_API_KEY в окружении и
/// только явно (`cargo test --test web_search -- --ignored`). Это не fixture:
/// расходуются квоты реального API, содержимое результатов не фиксируется.
#[test]
#[ignore = "живой вызов Tavily по TAVILY_API_KEY; запуск: cargo test --test web_search -- --ignored live_tavily"]
fn live_tavily_search() {
    let Ok(key) = std::env::var("TAVILY_API_KEY") else {
        eprintln!("SKIP live Tavily: TAVILY_API_KEY не задана");
        assert!(
            std::env::var_os("RCODE_REQUIRE_LIVE_TEST").is_none_or(|value| value != "1"),
            "RCODE_REQUIRE_LIVE_TEST=1 требует TAVILY_API_KEY"
        );
        return;
    };
    assert!(key.len() >= 8, "TAVILY_API_KEY подозрительно короткая");
    let sandbox = Sandbox::new();
    configure_sandbox(&sandbox, "tavily", None);
    let credentials =
        json!({"version": 1, "providers": {"custom": API_KEY, "websearch:tavily": key}});
    let path = sandbox.state.join("credentials.json");
    std::fs::write(&path, serde_json::to_string(&credentials).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let server = Server::start(move |request, index| {
        if !request.is_generation() {
            return no_generation();
        }
        if index == 0 {
            return tool_reply(
                "w1",
                "web_search",
                &json!({"query": "Tavily search API for AI agents", "max_results": 5}),
            );
        }
        text_reply("Ответ готов")
    });
    let output = sandbox.exec(&server, "Найди Tavily search API");
    let stdout = stdout_text(&output);
    assert!(
        output.status.success(),
        "{} {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    let receipts = tool_results(&output);
    assert_eq!(receipts.len(), 1, "{stdout}");
    assert!(
        receipts[0].get("error").is_none(),
        "живой Tavily вернул ошибку: {}",
        receipts[0]
    );
    assert_eq!(receipts[0]["provider"], "tavily");
    let count = receipts[0]["count"].as_u64().unwrap();
    assert!((1..=5).contains(&count), "count={count}");
    let results = receipts[0]["results"].as_array().unwrap();
    for result in results {
        assert!(
            result["url"].as_str().unwrap().starts_with("http"),
            "нет URL: {result}"
        );
        assert!(!result["title"].as_str().unwrap().is_empty());
    }
    // Ключ не попадает в события и логи.
    assert!(!stdout.contains(&key), "ключ утёк в JSONL");
    println!(
        "live Tavily: {count} результатов, первый URL {}",
        results[0]["url"]
    );
}
