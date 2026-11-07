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
        self.run_expected(prompt, directories, 24, 0)
    }

    fn run_expected(
        &self,
        prompt: &str,
        directories: &[&Path],
        max_steps: u32,
        expected_exit: i32,
    ) -> Vec<Value> {
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
                &max_steps.to_string(),
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
            output.status.code() == Some(expected_exit),
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
                .any(|event| event["type"] == "done" && event["exit_code"] == expected_exit)
        );
        events
    }
}

#[test]
#[ignore = "Живой GigaChat API; запускать явно с --ignored"]
fn gigachat_failed_worker_wait_contains_committed_results_without_readback() {
    let fixture = Fixture::for_provider(ProviderKind::GigaChat);
    let events = fixture.run_expected(
        "Создай ровно одного worker и передай ему этот сценарий полностью, сохранив JSON-аргументы дословно. Основной агент вызывает только spawn_agent и wait_agent, затем сообщает факты из worker_receipts без новых инструментов. У worker ровно четыре шага, по одному инструменту на каждом. Шаг 1: start_command с точными аргументами {\"command\":\"cat; sleep 600\",\"stdin\":true,\"lifetime_minutes\":15,\"idle_minutes\":15}. Точка с запятой и sleep входят внутрь строки command: не сокращай её до cat. Шаг 2: send_command_input для полученного command_id, text=giga-worker-summary, append_newline=true, close=true. Шаг 3: poll_command того же ID, stdout должен быть giga-worker-summary и один LF, inputs delivery=delivered. Шаг 4: stop_command того же ID, cleanup_complete=true. После четвёртого инструмента хост остановит worker по лимиту шагов: ожидается Failed. Сообщи этот сбой честно, успешные инструменты не доказывают выполнение цели. Не повторяй действия, не читай артефакты. Не используй run_command, файлы, сеть, handoff или других workers.",
        &[],
        4,
        1,
    );
    let starts = events
        .iter()
        .filter(|e| e["type"] == "tool_start")
        .collect::<Vec<_>>();
    let parent = starts
        .iter()
        .filter(|e| e["agent_id"].is_null())
        .collect::<Vec<_>>();
    assert_eq!(
        parent.len(),
        2,
        "Parent должен только запустить и собрать worker"
    );
    assert_eq!(parent[0]["name"], "spawn_agent");
    assert_eq!(parent[1]["name"], "wait_agent");
    let worker = starts
        .iter()
        .filter(|e| !e["agent_id"].is_null())
        .collect::<Vec<_>>();
    assert_eq!(worker.len(), 4);
    for (event, name) in worker.iter().zip([
        "start_command",
        "send_command_input",
        "poll_command",
        "stop_command",
    ]) {
        assert_eq!(event["name"], name);
    }
    let start_args: Value = serde_json::from_str(worker[0]["arguments"].as_str().unwrap()).unwrap();
    assert_eq!(start_args["command"], "cat; sleep 600");
    assert_eq!(start_args["stdin"], true);
    assert_eq!(start_args["lifetime_minutes"], 15);
    assert_eq!(start_args["idle_minutes"], 15);
    let wait = events
        .iter()
        .find(|e| e["type"] == "tool_result" && e["name"] == "wait_agent")
        .unwrap();
    assert_eq!(wait["is_error"], true);
    let receipt: Value = serde_json::from_str(wait["content"].as_str().unwrap()).unwrap();
    assert_eq!(receipt["status"], "failed");
    assert!(receipt["result"].as_str().unwrap().contains("лимит шагов"));
    let summary = &receipt["worker_receipts"];
    assert_eq!(summary["available"], true);
    assert_eq!(summary["goal_verified"], false);
    assert!(serde_json::to_vec(summary).unwrap().len() <= 8192);
    let observations = summary["observations"].as_array().unwrap();
    let stop = observations
        .iter()
        .find(|o| o["tool"] == "stop_command")
        .unwrap();
    assert_eq!(stop["fields"]["status"], "stopped");
    assert_eq!(stop["fields"]["cleanup_complete"], true);
    let poll = observations
        .iter()
        .find(|o| o["tool"] == "poll_command")
        .unwrap();
    assert_eq!(poll["stdout_preview"], "giga-worker-summary\n");
    assert_eq!(poll["stdout_truncated"], false);
    assert_eq!(poll["fields"]["command_id"], stop["fields"]["command_id"]);
    assert!(
        poll["fields"]["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|input| {
                input["delivery"] == "delivered" && input["written"] == 20 && input["total"] == 20
            })
    );
}

#[test]
#[ignore = "Живой GigaChat API и установленный Python; запускать явно с --ignored"]
fn gigachat_managed_command_delivers_stdin_and_stops_without_shell_fallback() {
    let fixture = Fixture::for_provider(ProviderKind::GigaChat);
    let events = fixture.run("Проверь управление одним процессом через инструменты. Вызови ровно один start_command: command = read line; printf '%s\\n' \"$line\"; sleep 30, stdin = true, lifetime_minutes = 1, idle_minutes = 1. Полученный command_id используй во всех следующих вызовах. Затем ровно один send_command_input: text = giga-stdin-canary с переводом строки в конце, close = true. Через poll_command получи stdout со строкой giga-stdin-canary и подтверждение delivery=delivered для input_id. Затем stop_command останови процесс и заверши ответ. Разрешены только start_command, send_command_input, poll_command, stop_command. Не используй run_command, субагентов, файлы, сеть и другие команды.");
    let receipts: Vec<_> = events
        .iter()
        .filter(|e| e["type"] == "tool_result")
        .map(|e| {
            assert_eq!(e["is_error"], false, "Управление процессом вернуло ошибку");
            (
                e["name"].as_str().unwrap(),
                serde_json::from_str::<Value>(e["content"].as_str().unwrap()).unwrap(),
            )
        })
        .collect();
    assert!(
        events
            .iter()
            .filter(|e| e["type"] == "tool_start")
            .all(|e| matches!(
                e["name"].as_str(),
                Some("start_command" | "send_command_input" | "poll_command" | "stop_command")
            )),
        "Недопустимый fallback в сценарии managed tools"
    );
    let starts: Vec<_> = receipts
        .iter()
        .filter(|(name, _)| *name == "start_command")
        .collect();
    let inputs: Vec<_> = receipts
        .iter()
        .filter(|(name, _)| *name == "send_command_input")
        .collect();
    assert_eq!(starts.len(), 1);
    assert_eq!(inputs.len(), 1);
    let command_id = starts[0].1["command_id"]
        .as_str()
        .expect("Реальный command_id");
    assert_eq!(starts[0].1["status"], "running");
    assert_eq!(inputs[0].1["delivery"], "accepted");
    let input_id = inputs[0].1["input_id"].as_str().expect("Реальный input_id");
    assert!(receipts.iter().all(|(_, r)| r["command_id"] == command_id));
    assert!(
        receipts.iter().any(|(name, r)| *name == "poll_command"
            && r["stdout"]
                .as_str()
                .is_some_and(|s| s.contains("giga-stdin-canary\n"))
            && r["inputs"].as_array().is_some_and(|items| items
                .iter()
                .any(|v| v["input_id"] == input_id && v["delivery"] == "delivered"))),
        "Нет фактической доставки stdin и вывода процесса"
    );
    assert!(
        receipts
            .iter()
            .any(|(name, r)| *name == "stop_command" && r["status"] == "stopped"),
        "Нет подтвержденной остановки"
    );
    println!(
        "PASS: native GigaChat started one managed process, sent one input, observed its delivery and output, then stopped it without run_command fallback"
    );
}

#[test]
#[ignore = "Живой GigaChat API и установленный Python; запускать явно с --ignored"]
fn gigachat_superpowers_tdd_observes_red_before_fix_and_independent_green() {
    let fixture = Fixture::for_provider(ProviderKind::GigaChat);
    let skill = fixture
        .project
        .join(".rcode/skills/test-driven-development");
    fs::create_dir_all(&skill).unwrap();
    for name in ["SKILL.md", "testing-anti-patterns.md"] {
        fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/superpowers-upstream/skills/test-driven-development")
                .join(name),
            skill.join(name),
        )
        .unwrap();
    }
    let original = "def total(values):\n    return sum(set(values))\n";
    let production = fixture.project.join("prices.py");
    let tests = fixture.project.join("test_prices.py");
    fs::write(&production, original).unwrap();
    fs::write(&tests, "import unittest\nfrom prices import total\n\nclass PricesTest(unittest.TestCase):\n    def test_empty(self):\n        self.assertEqual(total([]), 0)\n    def test_sum(self):\n        self.assertEqual(total([2, 3]), 5)\n").unwrap();
    let events = fixture.run("Используй установленный скилл test-driven-development через load_skill. Исправь баг в prices.py: total([2,2,3]) должна давать 7, сейчас даёт 5; total суммирует все значения, включая повторы. Дизайн и план такого исправления согласованы. Сначала прочитай файлы, добавь регрессионный unittest в test_prices.py и реально запусти его, наблюдая ожидаемое падение неправильной суммы. Только после этого минимально исправь prices.py и реально проверь все тесты. Чтение и правки только через файловые инструменты; shell только для точной команды python3 -B -m unittest -v без дополнительных команд. Без субагентов, коммитов, сети, установки зависимостей и правок AGENTS.md. Итог кратко по-русски.");
    let result = |e: &Value| {
        serde_json::from_str::<Value>(e["content"].as_str().unwrap_or("")).unwrap_or(Value::Null)
    };
    let output = |r: &Value| {
        format!(
            "{}\n{}",
            r["stdout"].as_str().unwrap_or(""),
            r["stderr"].as_str().unwrap_or("")
        )
    };
    let sum_failure = |s: &str| {
        s.contains("FAIL: test_")
            && s.contains("AssertionError:")
            && (s.contains("5 != 7") || s.contains("7 != 5"))
            && s.contains("FAILED (failures=")
            && !s.contains("ERROR:")
            && !s.contains("ImportError")
    };
    let mut test_commands = Vec::new();
    for e in events.iter().filter(|e| e["type"] == "tool_start") {
        assert!(
            matches!(
                e["name"].as_str(),
                Some(
                    "list_files"
                        | "read_file"
                        | "search"
                        | "load_skill"
                        | "write_file"
                        | "edit_file"
                        | "run_command"
                )
            ),
            "Неожиданный инструмент в TDD сценарии"
        );
        if e["name"] == "run_command" {
            let args: Value = serde_json::from_str(e["arguments"].as_str().unwrap_or("")).unwrap();
            assert_eq!(
                args["command"].as_str().map(str::trim),
                Some("python3 -B -m unittest -v"),
                "Shell используется только для запуска unittest"
            );
            test_commands.push(e["id"].clone());
        }
    }
    assert!(
        events.iter().any(|e| e["type"] == "tool_result"
            && e["name"] == "load_skill"
            && e["is_error"] == false
            && result(e)["content"]
                .as_str()
                .is_some_and(|s| s.contains("NO PRODUCTION CODE WITHOUT A FAILING TEST FIRST"))),
        "Оригинальный Superpowers TDD должен быть реально загружен"
    );
    let red = events
        .iter()
        .position(|e| {
            let r = result(e);
            e["type"] == "tool_result"
                && e["name"] == "run_command"
                && test_commands.contains(&e["id"])
                && r["exit_code"].as_i64().is_some_and(|n| n != 0)
                && sum_failure(&output(&r))
        })
        .expect("Нет реально наблюдавшегося RED регрессии");
    let fix = events
        .iter()
        .position(|e| {
            e["type"] == "tool_result"
                && e["is_error"] == false
                && e["changed_paths"].as_array().is_some_and(|paths| {
                    paths.iter().any(|p| {
                        p.as_str().is_some_and(|p| {
                            Path::new(p) == Path::new("prices.py") || Path::new(p) == production
                        })
                    })
                })
        })
        .expect("Нет подтвержденной правки production файла");
    assert!(red < fix, "Production изменен до наблюдаемого RED");
    assert!(
        events.iter().enumerate().any(|(i, e)| i > fix
            && e["type"] == "tool_result"
            && e["name"] == "run_command"
            && test_commands.contains(&e["id"])
            && result(e)["exit_code"] == 0
            && output(&result(e)).lines().any(|s| s == "OK")),
        "Нет реального GREEN после исправления"
    );
    let run_tests = || {
        output_with_deadline(
            Command::new("python3")
                .args(["-I", "-B", "-m", "unittest", "discover", "-s", ".", "-v"])
                .env("PYTHONDONTWRITEBYTECODE", "1")
                .current_dir(&fixture.project),
            Duration::from_secs(15),
        )
    };
    assert!(
        run_tests().status.success(),
        "Независимый unittest GREEN не прошел"
    );
    let independent = output_with_deadline(
        Command::new("python3").args(["-I", "-B", "-c", "import sys;sys.path.insert(0,'.');from prices import total;assert total([2,2,3])==7;assert total([])==0;assert total([-2,-2,3])==-1;assert total([1,2])==3"])
            .current_dir(&fixture.project), Duration::from_secs(15));
    assert!(
        independent.status.success(),
        "Независимая проверка контракта не прошла"
    );
    let fixed = fs::read(&production).unwrap();
    assert_ne!(fixed, original.as_bytes());
    fs::write(&production, original).unwrap();
    let mutant = run_tests();
    fs::write(&production, fixed).unwrap();
    let mutant_output = format!(
        "{}\n{}",
        String::from_utf8_lossy(&mutant.stdout),
        String::from_utf8_lossy(&mutant.stderr)
    );
    assert!(
        !mutant.status.success() && sum_failure(&mutant_output),
        "Новая регрессия не обнаружила неправильную сумму исходного бага"
    );
    println!(
        "PASS: native GigaChat loaded original Superpowers TDD, observed RED before production edit, then GREEN; independent checks passed and regression rejected original bug"
    );
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
