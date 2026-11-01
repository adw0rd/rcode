//! Сквозные сценарии вспомогательной модели чтения изображений: настоящий
//! `rcode exec --json` против loopback-fixture. Читатель и основной провайдер
//! — один kind (custom), fixture различает запросы по наличию изображений и
//! по полю model. Без внешней сети.
mod support;

use serde_json::{Value, json};
use support::{Response, Server, text_reply};

fn models_catalog() -> Response {
    Response::json(
        200,
        json!({"data": [
            {"id": "fixture-model", "name": "Fixture text model",
             "architecture": {"input_modalities": ["text"]}},
            {"id": "vision-reader-model", "name": "Fixture vision model",
             "architecture": {"input_modalities": ["text", "image"]}}
        ]}),
    )
}

const API_KEY: &str = "vision-fixture-key-0001";

// 1×1 PNG (67 байт), корректно разбирается images.rs.
const PNG_1X1: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
    0x89, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
    0x42, 0x60, 0x82,
];

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

    fn exec(&self, server: &Server, prompt: &str) -> Output {
        let base = server.base();
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_rcode"));
        command.env_clear();
        for name in ["PATH", "TMPDIR", "SYSTEMROOT"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command
            .env("HOME", self._tmp.path().join("home"))
            .env("USERPROFILE", self._tmp.path().join("home"))
            .env("RCODE_HOME", &self.state)
            .env("RCODE_CUSTOM_API_KEY", API_KEY)
            .current_dir(&self.project)
            .args([
                "--provider",
                "openrouter",
                "--base-url",
                &base,
                "--model",
                "fixture-model",
                "--json",
                "exec",
                prompt,
            ])
            .stdin(std::process::Stdio::null())
            .output()
            .map(|output| Output {
                status: output.status,
                stdout: output.stdout,
                stderr: output.stderr,
            })
            .unwrap()
    }
}

struct Output {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn stdout_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[allow(dead_code)]
fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn events(output: &Output) -> Vec<Value> {
    stdout_text(output)
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

fn configure(sandbox: &Sandbox, base: &str, vision: Option<(&str, &str)>) {
    let mut config = json!({
        "version": 1,
        "active": "custom",
        "providers": {
            "custom": {"kind": "custom", "model": "fixture-model", "base_url": base},
            "openrouter": {"kind": "openrouter", "model": "fixture-model", "base_url": base}
        }
    });
    if let Some((provider, model)) = vision {
        config["vision"] = json!({"provider": provider, "model": model});
    }
    let path = sandbox.state.join("config.json");
    std::fs::write(&path, serde_json::to_string(&config).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let credentials =
        json!({"version": 1, "providers": {"custom": API_KEY, "openrouter": API_KEY}});
    let path = sandbox.state.join("credentials.json");
    std::fs::write(&path, serde_json::to_string(&credentials).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn png_in(sandbox: &Sandbox) -> String {
    let path = sandbox.project.join("screen.png");
    std::fs::write(&path, PNG_1X1).unwrap();
    path.display().to_string()
}

fn no_reply() -> Response {
    Response::sse(&[json!({"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})])
}

/// Один fixture-сервер обслуживает и читателя, и основную модель: запрос
/// читателя несёт изображения и model=vision-reader-model, ответ — расшифровка;
/// основной запрос текстовый, images пустые, модель — fixture-model.
#[test]
fn reader_describes_images_for_a_text_only_model() {
    let main = Server::start(|request, _index| {
        if !request.is_generation() {
            if request.path.ends_with("/models") {
                return models_catalog();
            }
            return no_reply();
        }
        let body = request.json();
        let user = body["messages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|message| message["role"] == "user")
            .cloned()
            .unwrap_or(Value::Null);
        let has_images = user["content"]
            .as_array()
            .is_some_and(|parts| parts.iter().any(|part| part["type"] == "image_url"));
        if has_images {
            assert_eq!(body["model"], "vision-reader-model", "запрос читателя");
            let parts = user["content"].as_array().unwrap();
            let text = parts[0]["text"].as_str().unwrap();
            assert!(text.starts_with("Перепиши дословно весь текст"), "{text}");
            assert!(text.contains("Что на скрине"), "вопрос доходит: {text}");
            let images: Vec<_> = parts
                .iter()
                .filter(|part| part["type"] == "image_url")
                .collect();
            assert_eq!(images.len(), 1);
            assert!(
                images[0]["image_url"]["url"]
                    .as_str()
                    .unwrap()
                    .starts_with("data:image/png;base64,")
            );
            text_reply("СКРИН: Подтверждение действия — Отклонить или Разрешить")
        } else {
            assert_eq!(body["model"], "fixture-model");
            text_reply("Ответ готов")
        }
    });
    let sandbox = Sandbox::new();
    configure(
        &sandbox,
        &main.base(),
        Some(("openrouter", "vision-reader-model")),
    );
    let png = png_in(&sandbox);
    let output = sandbox.exec(&main, &format!("Что на скрине? {png}"));
    let text = stdout_text(&output);
    assert!(output.status.success(), "{text}");
    let vision = events(&output)
        .into_iter()
        .find(|event| event["type"] == "vision")
        .expect("нет события vision");
    assert_eq!(vision["provider"], "openrouter");
    assert_eq!(vision["model"], "vision-reader-model");
    assert_eq!(vision["images"], 1);
    assert!(
        events(&output).iter().any(|event| {
            event["type"] == "text" && event["text"].as_str().unwrap().contains("Ответ готов")
        }),
        "{text}"
    );
}

#[test]
fn unconfigured_vision_reports_the_vision_command() {
    let main = Server::start(|request, _index| {
        if !request.is_generation() {
            if request.path.ends_with("/models") {
                return models_catalog();
            }
            return no_reply();
        }
        let body = request.json();
        if body["messages"].as_array().unwrap().iter().any(|message| {
            message["role"] == "user"
                && message["images"]
                    .as_array()
                    .is_some_and(|images| !images.is_empty())
        }) {
            panic!("текст-only модель не должна получать изображения: {body}");
        }
        text_reply("Ответ готов")
    });
    let sandbox = Sandbox::new();
    configure(&sandbox, &main.base(), None);
    let png = png_in(&sandbox);
    let output = sandbox.exec(&main, &format!("Что на скрине? {png}"));
    let text = stdout_text(&output);
    assert!(
        !output.status.success(),
        "без настроенного читателя ход не должен тихо продолжаться: {text}"
    );
    assert!(
        text.contains("/vision"),
        "ошибка должна подсказывать /vision: {text}"
    );
}
