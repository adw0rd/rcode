//! Опциональные живые E2E: используют сохранённый ключ и платный API только при --ignored.
use rcode::config::{ConfigStore, ProviderKind};
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Seek},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

struct Fixture {
    kind: ProviderKind,
    directory: tempfile::TempDir,
    state: tempfile::TempDir,
    project: PathBuf,
    secret: String,
}
impl Fixture {
    fn new() -> Self {
        Self::for_provider(ProviderKind::Yandex)
    }
    fn for_provider(kind: ProviderKind) -> Self {
        let source = ConfigStore::new().expect("Настройте rcode connect перед живым тестом");
        let credential = source
            .credential(kind)
            .unwrap()
            .expect("Нужен сохранённый API-ключ; тест не спрашивает ключ в терминале");
        let mut settings = source.load().unwrap();
        let mut provider = settings.provider(kind);
        let override_name = if kind == ProviderKind::Yandex {
            "RCODE_LIVE_YANDEX_MODEL"
        } else {
            "RCODE_LIVE_GIGACHAT_MODEL"
        };
        if let Ok(model) = std::env::var(override_name) {
            provider.model = model;
        }
        assert!(
            (kind == ProviderKind::Yandex
                && matches!(
                    provider.base_url.as_deref(),
                    None | Some("https://ai.api.cloud.yandex.net/v1")
                ))
                || (kind == ProviderKind::GigaChat
                    && matches!(
                        provider.base_url.as_deref(),
                        None | Some("https://api.giga.chat/v1")
                    )),
            "Live-тест ожидает официальный endpoint провайдера"
        );
        provider.max_output_tokens = 4096;
        provider.idle_timeout_secs = if kind == ProviderKind::GigaChat {
            90
        } else {
            30
        };
        provider.validate().unwrap();
        settings.active = kind;
        settings.providers.clear();
        settings.providers.insert(kind.to_string(), provider);
        #[cfg(unix)]
        let directory = tempfile::Builder::new()
            .prefix("rcode-live-")
            .tempdir_in("/tmp")
            .unwrap();
        #[cfg(not(unix))]
        let directory = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let store = ConfigStore::at(state.path()).unwrap();
        store.save(&settings).unwrap();
        store.save_credential(kind, &credential.value).unwrap();
        let project = directory.path().join("workspace");
        fs::create_dir(&project).unwrap();
        fs::write(project.join("AGENTS.md"),"Текущий проект реализован на Rust. Сохраняйте существующие файлы пользователя. Общайтесь по-русски.\n").unwrap();
        Self {
            kind,
            directory,
            state,
            project,
            secret: credential.value,
        }
    }

    fn run(&self, prompt: &str) -> Vec<Value> {
        self.run_with_directories(prompt, &[])
    }

    fn run_with_directories(&self, prompt: &str, directories: &[&Path]) -> Vec<Value> {
        let binary = std::env::var_os("RCODE_LIVE_BINARY")
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_rcode").into());
        let mut command = Command::new(binary);
        command
            .env_clear()
            .env("RCODE_HOME", self.state.path())
            .args([
                "-C",
                self.project.to_str().unwrap(),
                "--provider",
                self.kind.as_str(),
                "--json",
                "--max-steps",
                "24",
                "--approval-mode",
                "auto-edit",
                "--allow-shell",
                "exec",
                prompt,
            ]);
        for name in [
            "PATH",
            "HOME",
            "LANG",
            "TMPDIR",
            "SYSTEMROOT",
            "HTTPS_PROXY",
            "HTTP_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
        ] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        for directory in directories {
            command.arg("--add-dir").arg(directory);
        }
        let output = output_with_deadline(&mut command, Duration::from_secs(180));
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stdout.contains(&self.secret) && !stderr.contains(&self.secret),
            "Ключ попал в вывод"
        );
        let events: Vec<Value> = stdout
            .lines()
            .map(|line| serde_json::from_str(line).expect("Ожидался чистый JSONL"))
            .collect();
        if let Some(directory) = std::env::var_os("RCODE_LIVE_ARTIFACT_DIR") {
            let path = PathBuf::from(directory).join(format!(
                "{}-{}.json",
                self.kind,
                if prompt.contains("Godot") {
                    "godot"
                } else if prompt.contains("tkinter") {
                    "python"
                } else {
                    "workers"
                }
            ));
            rcode::config::write_private_json(&path, &events).unwrap();
        }
        let answers = events
            .iter()
            .filter(|event| event["type"] == "text")
            .filter_map(|event| event["text"].as_str())
            .collect::<String>();
        let errors = events
            .iter()
            .filter(|event| event["type"] == "error")
            .filter_map(|event| event["message"].as_str())
            .collect::<Vec<_>>();
        assert!(
            output.status.success(),
            "rcode завершился с {:?}; ошибки={errors:?}; ответ={answers}; stderr={stderr}",
            output.status.code()
        );
        assert!(
            events.iter().any(|event| event["type"] == "tool_start"),
            "Ответ без единого действия: {answers}"
        );
        assert!(
            events
                .iter()
                .any(|event| event["type"] == "done" && event["exit_code"] == 0)
        );
        events
    }
}

#[test]
#[ignore = "Живой GigaChat API и установленный Python; запускать явно с --ignored"]
fn gigachat_rewrites_existing_python_file_with_host_read_snapshot() {
    let fixture = Fixture::for_provider(ProviderKind::GigaChat);
    let target = fixture.directory.path().join("rewrite");
    fs::create_dir(&target).unwrap();
    let file = target.join("main.py");
    fs::write(&file, "def greeting():\n    return 'before'\n\nif __name__ == '__main__':\n    print(greeting())\n").unwrap();
    let prompt = format!(
        "В файле {} измени greeting() так, чтобы она возвращала строку after. Сначала прочитай файл через read_file, затем перезапиши полный файл через write_file, сохранив остальную логику. expected_sha256 не передавай: host использует snapshot успешного чтения и отклонит запись, если файл изменился. Проверь файл запуском python3 без графических окон. Работай самостоятельно без субагентов, других файлов и изменений вне этой папки.",
        file.display()
    );
    let events = fixture.run_with_directories(&prompt, &[&target]);
    let call_ids: Vec<_> = events
        .iter()
        .filter(|e| e["type"] == "tool_start" && e["name"] == "write_file")
        .filter(|e| {
            serde_json::from_str::<Value>(e["arguments"].as_str().unwrap_or("")).is_ok_and(|a| {
                a["path"].as_str().is_some_and(|p| {
                    Path::new(p).file_name() == Some(std::ffi::OsStr::new("main.py"))
                }) && a.get("expected_sha256").is_none_or(Value::is_null)
            })
        })
        .map(|e| e["id"].clone())
        .collect();
    assert!(
        events.iter().any(|e| e["type"] == "tool_result"
            && e["name"] == "write_file"
            && e["is_error"] == false
            && call_ids.contains(&e["id"])),
        "Модель должна перезаписать существующий файл через host read snapshot"
    );
    assert!(
        !events
            .iter()
            .any(|e| e["type"] == "tool_result" && e["is_error"] == true),
        "В коротком read→write сценарии не должно быть ошибок инструментов"
    );
    let output = output_with_deadline(
        Command::new("python3").arg("-I").arg(&file),
        Duration::from_secs(15),
    );
    assert!(
        output.status.success(),
        "Python oracle завершился с ошибкой"
    );
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "after");
    println!(
        "PASS: GigaChat rewrote an existing external Python file after read_file without expected_sha256; independent Python execution returned after; GUI not launched"
    );
}

#[test]
#[ignore = "Живой GigaChat API и установленный Python; запускать явно с --ignored"]
fn gigachat_writes_python_game_in_explicit_external_directory() {
    let fixture = Fixture::for_provider(ProviderKind::GigaChat);
    let target = fixture.directory.path().join("saper");
    fs::create_dir(&target).unwrap();
    let prompt = format!(
        "Напиши простую игру «Сапёр» на Python с tkinter в существующей папке {}. Один файл main.py, поле 9×9 с 10 минами, открытие клеток и флаги. Проверь синтаксис без запуска графического окна.",
        target.display()
    );
    let events = fixture.run_with_directories(&prompt, &[&target]);
    let file = target.join("main.py");
    assert!(file.is_file(), "Игра не создана во внешнем каталоге");
    let source = fs::read_to_string(&file).unwrap();
    assert!(source.contains("tkinter"), "Нет запрошенного tkinter");
    assert!(
        events.iter().any(|e| e["type"] == "tool_result"
            && e["name"] == "write_file"
            && e["is_error"] == false
            && e["changed_paths"]
                .as_array()
                .is_some_and(
                    |paths| paths.iter().any(|p| p.as_str().is_some_and(|p| Path::new(p)
                        .file_name()
                        == Some(std::ffi::OsStr::new("main.py"))))
                )),
        "Файл должен быть записан обычным write_file"
    );
    assert!(
        !events.iter().any(|e| e["type"] == "tool_result"
            && e["content"]
                .as_str()
                .is_some_and(|s| s.contains("outside_workspace"))),
        "Лишний цикл ошибки внешнего пути"
    );
    let output = output_with_deadline(
        Command::new("python3")
            .args(["-I", "-m", "py_compile"])
            .arg(&file),
        Duration::from_secs(15),
    );
    assert!(
        output.status.success(),
        "Независимый Python oracle: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    println!(
        "PASS: GigaChat wrote external tkinter game using file tools; independent Python syntax validation passed; GUI not launched"
    );
}

fn output_with_deadline(command: &mut Command, duration: Duration) -> Output {
    let stdout = tempfile::tempfile().unwrap();
    let stderr = tempfile::tempfile().unwrap();
    let mut child = command
        .stdin(Stdio::null())
        .stdout(stdout.try_clone().unwrap())
        .stderr(stderr.try_clone().unwrap())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + duration;
    let (status, timed_out) = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break (status, false);
        }
        if Instant::now() >= deadline {
            #[cfg(unix)]
            unsafe {
                libc::kill(child.id() as i32, libc::SIGINT);
            }
            let grace = Instant::now() + Duration::from_secs(2);
            while child.try_wait().unwrap().is_none() && Instant::now() < grace {
                thread::sleep(Duration::from_millis(20));
            }
            if child.try_wait().unwrap().is_none() {
                let _ = child.kill();
            }
            break (child.wait().unwrap(), true);
        }
        thread::sleep(Duration::from_millis(20));
    };
    let read = |mut file: fs::File| {
        file.rewind().unwrap();
        let mut bytes = Vec::new();
        file.take(1024 * 1024).read_to_end(&mut bytes).unwrap();
        bytes
    };
    let output = Output {
        status,
        stdout: read(stdout),
        stderr: read(stderr),
    };
    assert!(
        !timed_out,
        "Процесс не завершился за {} секунд",
        duration.as_secs()
    );
    output
}

fn godot_binary() -> PathBuf {
    if let Some(path) = std::env::var_os("RCODE_GODOT_BIN") {
        return path.into();
    }
    for directory in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
        for name in ["godot", "godot4", "godot.exe", "godot4.exe"] {
            let path = directory.join(name);
            if path.is_file() {
                return path;
            }
        }
    }
    panic!("Для Godot E2E установите Godot 4 или укажите RCODE_GODOT_BIN");
}

fn godot_oracle(engine: &Path, project: &Path, script: &Path) -> Result<(), String> {
    if !project.join("project.godot").is_file() {
        return Err("project.godot не создан".into());
    }
    fs::write(
        script,
        r#"extends SceneTree
func _initialize():
    call_deferred("check_scene")
func check_scene():
    var scene_path = ProjectSettings.get_setting("application/run/main_scene", "")
    if str(scene_path).is_empty():
        push_error("Main scene is missing")
        quit(21)
        return
    var packed = load(scene_path)
    if not packed is PackedScene:
        push_error("Main scene is not a PackedScene")
        quit(22)
        return
    var scene = packed.instantiate()
    root.add_child(scene)
    for step in range(4):
        await process_frame
    print("RCODE_GODOT_ORACLE_READY")
    quit(0)
"#,
    )
    .map_err(|error| error.to_string())?;
    let output = output_with_deadline(
        Command::new(engine).args([
            "--headless",
            "--path",
            project.to_str().unwrap(),
            "--script",
            script.to_str().unwrap(),
        ]),
        Duration::from_secs(25),
    );
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !output.status.success()
        || !text.contains("RCODE_GODOT_ORACLE_READY")
        || text.contains("SCRIPT ERROR:")
        || text.contains("ERROR:")
        || text.contains("Failed to load")
    {
        return Err(format!("Godot не загрузил сцену: {text}"));
    }
    Ok(())
}

fn verify_oracle_controls(engine: &Path, base: &Path) {
    let project = base.join("oracle-control");
    fs::create_dir(&project).unwrap();
    fs::write(
        project.join("project.godot"),
        "config_version=5\n[application]\nrun/main_scene=\"res://main.tscn\"\n",
    )
    .unwrap();
    fs::write(project.join("main.tscn"),"[gd_scene load_steps=2 format=3]\n[ext_resource type=\"Script\" path=\"res://main.gd\" id=\"1\"]\n[node name=\"Main\" type=\"Node2D\"]\nscript = ExtResource(\"1\")\n").unwrap();
    fs::write(project.join("main.gd"), "extends Node2D\n").unwrap();
    let script = base.join("oracle-control.gd");
    godot_oracle(engine, &project, &script).expect("Положительный контроль Godot oracle");
    fs::write(project.join("main.gd"), "extends Node2D\nfunc broken(:\n").unwrap();
    assert!(
        godot_oracle(engine, &project, &script).is_err(),
        "Oracle должен отказывать при ошибке GDScript, даже если engine вернул 0"
    );
}

#[test]
#[ignore = "Живой платный Yandex API и установленный Godot 4; запускать явно с --ignored"]
fn yandex_creates_and_loads_godot_game_outside_workspace() {
    creates_and_loads_godot_game_outside_workspace(ProviderKind::Yandex);
}

#[test]
#[ignore = "Живой GigaChat API и установленный Godot 4; запускать явно с --ignored"]
fn gigachat_creates_and_loads_godot_game_outside_workspace() {
    creates_and_loads_godot_game_outside_workspace(ProviderKind::GigaChat);
}

fn creates_and_loads_godot_game_outside_workspace(kind: ProviderKind) {
    let engine = godot_binary();
    let fixture = Fixture::for_provider(kind);
    verify_oracle_controls(&engine, fixture.directory.path());
    let prompt = format!(
        "создай в {} папку test_godot и в ней самую минимальную игру для теста на Godot 4",
        fixture.directory.path().display()
    );
    let events = fixture.run(&prompt);
    let game = fixture.directory.path().join("test_godot");
    assert!(!game.starts_with(&fixture.project));
    if let Err(error) = godot_oracle(
        &engine,
        &game,
        &fixture.directory.path().join("oracle-generated.gd"),
    ) {
        let answer = events
            .iter()
            .filter(|event| event["type"] == "text")
            .filter_map(|event| event["text"].as_str())
            .collect::<String>();
        let tools=events.iter().filter(|event|event["type"] == "tool_result").map(|event|json!({"name":event["name"],"is_error":event["is_error"],"content":event["content"]})).collect::<Vec<_>>();
        panic!("{error}; answer={answer}; tools={tools:?}");
    }
    assert!(
        events
            .iter()
            .any(|event| event["type"] == "tool_start" && event["name"] == "run_command"),
        "Выход за root должен использовать разрешённый shell"
    );
    println!(
        "PASS: natural {kind} request created a real Godot game outside cwd; independent scene-load oracle passed"
    );
}

#[test]
#[ignore = "Живой платный Yandex API; запускать явно с --ignored"]
fn yandex_delegates_real_file_work_to_two_workers() {
    let fixture = Fixture::new();
    let events=fixture.run("Делегируй двум отдельным субагентам worker две независимые задачи в текущей папке. Первый должен сам создать apple.txt с содержимым APPLE_OK, второй сам создать pear.txt с содержимым PEAR_OK. Используй spawn_agent с role worker, дождись обоих через wait_agent и проверь файлы. Не создавай эти файлы вместо субагентов.");
    for (file, expected) in [("apple.txt", "APPLE_OK"), ("pear.txt", "PEAR_OK")] {
        assert_eq!(
            fs::read_to_string(fixture.project.join(file))
                .expect("Субагент не создал файл")
                .trim(),
            expected
        );
    }
    let worker_ids = events
        .iter()
        .filter(|event| {
            event["type"] == "tool_result"
                && event["name"] == "write_file"
                && event["is_error"] == false
        })
        .filter_map(|event| event["agent_id"].as_str())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(
        worker_ids.len(),
        2,
        "Должны работать два реальных worker, а не только основной агент"
    );
    let saved = ConfigStore::at(fixture.state.path()).unwrap();
    let id = events
        .iter()
        .find(|event| event["type"] == "start")
        .unwrap()["session_id"]
        .as_str()
        .unwrap();
    let session: Value = serde_json::from_slice(
        &fs::read(saved.sessions_dir().join(id).join("session.json")).unwrap(),
    )
    .unwrap();
    let agents = session["agents"].as_array().unwrap();
    assert_eq!(agents.len(), 2);
    assert!(agents.iter().all(|agent| agent["status"] == "completed"
        && agent["role"] == "worker"
        && agent["usage"]["input_tokens"].as_u64().unwrap() > 0));
    println!(
        "PASS: two actual Yandex worker contexts created independent files; results and usage persisted"
    );
}
