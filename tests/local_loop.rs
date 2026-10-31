//! A small local context (32K MLX profile) must not trap the agent in a
//! read → auto-compact → re-read loop. Loopback fixtures only: no live model.
#![cfg(unix)]
mod support;

use rcode::{
    config::ConfigStore,
    context::{ContextBudget, estimate_overhead, estimate_text_tokens},
    local::{LocalRuntime, profile_settings},
    protocol::{Completion, Message, ToolCall},
    state::Session,
};
use serde_json::{Value, json};
use std::{
    io::{Read, Seek},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};
use support::{Request, Response, Server, text_reply, tool_reply};

const FACT: &str = "TASK_FACT: release codename is blue-otter";
const TAIL: &str = "README_TAIL_MARKER";
const MEMORY_PREFIX: &str = "Сокращённая история rcode";

struct Home {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    state: PathBuf,
    project: PathBuf,
}

impl Home {
    fn new(server: &Server) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        for dir in ["home", "xdg", "state", "project"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        let home = Self {
            state: root.join("state"),
            project: root.join("project").canonicalize().unwrap(),
            root,
            _tmp: tmp,
        };
        let added = home.run(&[
            "local",
            "add",
            "mlx",
            "--base-url",
            &server.base(),
            "--runtime",
            "mlx",
            "--model",
            "qwen-27b",
        ]);
        assert!(added.status.success(), "{}", text(&added));
        home
    }

    fn run(&self, args: &[&str]) -> Output {
        let stdout = tempfile::tempfile().unwrap();
        let stderr = tempfile::tempfile().unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_rcode"));
        command.env_clear();
        for name in ["PATH", "TMPDIR"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        let mut child = command
            .env("HOME", self.root.join("home"))
            .env("XDG_CONFIG_HOME", self.root.join("xdg"))
            .env("RCODE_HOME", &self.state)
            .args(args)
            .stdin(Stdio::null())
            .stdout(stdout.try_clone().unwrap())
            .stderr(stderr.try_clone().unwrap())
            .spawn()
            .unwrap();
        let start = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if start.elapsed() > Duration::from_secs(90) {
                let _ = child.kill();
                panic!("rcode did not finish");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let read = |mut file: std::fs::File| {
            let mut bytes = Vec::new();
            file.rewind().unwrap();
            file.read_to_end(&mut bytes).unwrap();
            bytes
        };
        Output {
            status,
            stdout: read(stdout),
            stderr: read(stderr),
        }
    }

    /// Headless task on the local profile; file edits and shell are allowed so
    /// the host never asks, as in an auto-edit session with shell enabled.
    fn exec(&self, extra: &[&str], prompt: &str) -> Output {
        let mut args = vec![
            "exec",
            "--json",
            "-C",
            self.project.to_str().unwrap(),
            "--profile",
            "mlx",
            "--approval-mode",
            "auto-edit",
            "--allow-shell",
        ];
        args.extend(extra);
        args.push(prompt);
        self.run(&args)
    }

    fn load(&self, events: &[Value]) -> Session {
        let id = events
            .iter()
            .find(|event| event["type"] == "start")
            .and_then(|event| event["session_id"].as_str())
            .unwrap()
            .to_owned();
        Session::load(
            &ConfigStore::at(self.state.clone()).unwrap(),
            &id,
            &self.project,
        )
        .unwrap()
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

/// ~45 KB: well above the history of a 32K context, below run_command's 64 KiB.
fn write_readme(project: &Path) {
    let mut readme = String::from("# gstack\n\n");
    for line in 0..560 {
        if line == 14 {
            readme.push_str(FACT);
            readme.push('\n');
        }
        readme.push_str(&format!(
            "line {line:04}: gstack toolkit documentation paragraph with filler words.\n"
        ));
    }
    readme.push_str(TAIL);
    readme.push('\n');
    std::fs::write(project.join("README.md"), readme).unwrap();
}

fn messages(request: &Request) -> Vec<Value> {
    request.json()["messages"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

fn content(message: &Value) -> &str {
    message["content"].as_str().unwrap_or_default()
}

/// Name of the call the given tool result answers.
fn answered_tool(messages: &[Value], result: &Value) -> Option<String> {
    let id = result["tool_call_id"].as_str()?;
    messages
        .iter()
        .flat_map(|message| {
            message["tool_calls"]
                .as_array()
                .cloned()
                .unwrap_or_default()
        })
        .find(|call| call["id"] == id)
        .and_then(|call| call["function"]["name"].as_str().map(str::to_owned))
}

fn mlx_budget(overhead: usize) -> ContextBudget {
    let settings = profile_settings(
        "mlx",
        "http://127.0.0.1:1/v1",
        LocalRuntime::Mlx,
        "qwen-27b",
    );
    ContextBudget::for_provider(&settings, None, 1.0, overhead)
}

/// The host's own estimate of the fixed part of every request.
fn request_overhead(request: &Request) -> usize {
    let mut tools = rcode::tools::Tools::definitions();
    tools.extend(rcode::agents::AgentPool::definitions());
    estimate_overhead(content(&messages(request)[0]), &tools)
}

/// Upper estimate of a whole request in the host's token units.
fn request_tokens(request: &Request) -> usize {
    request_overhead(request)
        + messages(request)
            .iter()
            .skip(1)
            .map(|message| {
                8 + estimate_text_tokens(content(message))
                    + estimate_text_tokens(&message["tool_calls"].to_string())
            })
            .sum::<usize>()
}

fn models() -> Response {
    Response::json(200, json!({"data":[{"id":"qwen-27b"}]}))
}

#[test]
fn local_32k_model_receives_the_fresh_readme_receipt_after_compaction_and_finishes() {
    let server = Server::start(|request, index| {
        if !request.is_generation() {
            return models();
        }
        let messages = messages(request);
        if index == 0 {
            // Previous turn: a long answer that leaves less than an eighth of
            // the history for the next large tool receipt.
            let budget = mlx_budget(request_overhead(request));
            let tokens = budget.threshold() - budget.history_limit() / 8 - 400;
            return text_reply(&"earlier analysis ".repeat(tokens * 5 / 2 / 17));
        }
        let last = messages.last().unwrap();
        if last["role"] == "tool" && content(last).contains(FACT) {
            return tool_reply(
                &format!("call_{index}"),
                "write_file",
                &json!({"path":"notes.txt","content":"blue-otter\n"}),
            );
        }
        if last["role"] == "tool" && answered_tool(&messages, last).as_deref() == Some("write_file")
        {
            return text_reply("notes.txt записан: blue-otter");
        }
        tool_reply(
            &format!("call_{index}"),
            "run_command",
            &json!({"command":"cat README.md"}),
        )
    });
    let home = Home::new(&server);
    write_readme(&home.project);
    let first = home.exec(&[], "Расскажи о проекте подробно");
    assert!(first.status.success(), "{}", text(&first));
    let output = home.exec(
        &["--resume", "latest", "--max-steps", "8"],
        "Прочитай README и запиши кодовое имя релиза в notes.txt",
    );
    let log = text(&output);
    assert!(output.status.success(), "{log}");
    assert_eq!(
        std::fs::read_to_string(home.project.join("notes.txt")).unwrap(),
        "blue-otter\n"
    );
    let generations = server.generations();
    assert_eq!(generations.len(), 4, "{log}");
    // The README receipt ran into the compaction threshold, yet the very next
    // request still carries it, bounded, with its head, tail and paging hint.
    let next = &generations[2];
    let next_messages = messages(next);
    assert!(
        next_messages
            .iter()
            .any(|message| content(message).starts_with(MEMORY_PREFIX)),
        "the request after the README receipt must follow an automatic compaction"
    );
    let receipt = content(next_messages.last().unwrap());
    assert!(receipt.contains(FACT) && receipt.contains(TAIL));
    assert!(receipt.contains("start_line"), "addressed reading hint");
    assert!(receipt.len() < 45_000, "receipt must be bounded");
    let limit = mlx_budget(0).limit;
    for request in &generations {
        assert!(
            request_tokens(request) <= limit,
            "request exceeds 32K budget"
        );
    }
    let events = events(&output);
    // Shortening is not silent: the user is told which result the model got bounded.
    assert!(
        of_type(&events, "warning")
            .iter()
            .any(|warning| warning["message"].as_str().unwrap().contains("run_command"))
    );
    let receipt_event = events
        .iter()
        .position(|event| event["type"] == "tool_result" && event["name"] == "run_command")
        .unwrap();
    assert!(
        events[receipt_event..]
            .iter()
            .any(|event| event["type"] == "context_compacted")
    );
    assert_eq!(home.load(&events).repair_pending().unwrap(), 0);
}

#[test]
fn stubborn_identical_shell_reads_get_feedback_then_a_bounded_stop() {
    let server = Server::start(|request, index| {
        if !request.is_generation() {
            return models();
        }
        tool_reply(
            &format!("call_{index}"),
            "run_command",
            &json!({"command":"cat README.md"}),
        )
    });
    let home = Home::new(&server);
    write_readme(&home.project);
    let output = home.exec(&[], "Изучи README gstack");
    let log = text(&output);
    assert_eq!(output.status.code(), Some(1), "{log}");
    let generations = server.generations();
    assert!(
        generations.len() <= 6,
        "{} requests\n{log}",
        generations.len()
    );
    assert!(generations.iter().any(|request| {
        messages(request).iter().any(|message| {
            message["role"] == "user" && content(message).starts_with("[rcode runtime feedback")
        })
    }));
    let events = events(&output);
    // Every requested command really ran: detection never replaces execution.
    let results = of_type(&events, "tool_result");
    assert_eq!(results.len(), generations.len(), "{log}");
    assert!(
        results.iter().all(|result| result["name"] == "run_command"
            && result["is_error"] == false
            && result["content"].as_str().unwrap().contains(TAIL)),
        "{log}"
    );
    let errors = of_type(&events, "error");
    assert_eq!(errors.len(), 1, "{log}");
    let message = errors[0]["message"].as_str().unwrap();
    assert!(
        message.contains("run_command") && !message.contains("лимит шагов"),
        "{message}"
    );
    assert!(of_type(&events, "context_compacted").len() <= 2, "{log}");
    let mut session = home.load(&events);
    assert_eq!(session.repair_pending().unwrap(), 0);
    assert_eq!(session.messages.last().unwrap().role, "tool");
}

/// Identical receipts of commands with side effects or shell syntax are not a
/// read loop: four appends and four polls with the same output all run and the
/// model's final answer is a success.
#[test]
fn identical_appends_and_polls_are_never_stopped_as_repeated_reads() {
    let server = Server::start(|request, index| {
        if !request.is_generation() {
            return models();
        }
        let id = format!("call_{index}");
        match index {
            0..=3 => tool_reply(
                &id,
                "run_command",
                &json!({"command":"printf x >> events.txt"}),
            ),
            4..=7 => tool_reply(
                &id,
                "run_command",
                &json!({"command":"test -f done.flag || echo waiting"}),
            ),
            _ => text_reply("Готово: четыре записи добавлены"),
        }
    });
    let home = Home::new(&server);
    let output = home.exec(&[], "Добавь x в events.txt четыре раза и опроси done.flag");
    let log = text(&output);
    assert!(output.status.success(), "{log}");
    let events = events(&output);
    assert!(of_type(&events, "error").is_empty(), "{log}");
    assert_eq!(server.generations().len(), 9, "{log}");
    assert_eq!(
        std::fs::read_to_string(home.project.join("events.txt")).unwrap(),
        "xxxx"
    );
    let results = of_type(&events, "tool_result");
    assert_eq!(results.len(), 8, "{log}");
    assert!(
        results[4..]
            .iter()
            .all(|result| result["content"].as_str().unwrap().contains("waiting")),
        "{log}"
    );
    assert!(
        server.generations().iter().all(|request| {
            messages(request)
                .iter()
                .all(|message| !content(message).starts_with("[rcode runtime feedback"))
        }),
        "{log}"
    );
    let answer: String = of_type(&events, "text")
        .iter()
        .filter_map(|event| event["text"].as_str())
        .collect();
    assert!(answer.contains("Готово"), "{log}");
    let done = of_type(&events, "done");
    assert_eq!(done.len(), 1, "{log}");
    assert_eq!(done[0]["exit_code"], 0, "{log}");
}

#[test]
fn alternating_identical_reads_are_also_bounded() {
    let server = Server::start(|request, index| {
        if !request.is_generation() {
            return models();
        }
        let (name, arguments) = if index % 2 == 0 {
            ("read_file", json!({"path":"README.md"}))
        } else {
            ("run_command", json!({"command":"cat README.md"}))
        };
        tool_reply(&format!("call_{index}"), name, &arguments)
    });
    let home = Home::new(&server);
    write_readme(&home.project);
    let output = home.exec(&[], "Изучи README gstack");
    let log = text(&output);
    assert_eq!(output.status.code(), Some(1), "{log}");
    assert!(server.generations().len() <= 8, "{log}");
    assert_eq!(of_type(&events(&output), "error").len(), 1, "{log}");
}

#[test]
fn rereads_after_a_write_and_changing_polls_are_not_treated_as_a_loop() {
    let server = Server::start(|request, index| {
        if !request.is_generation() {
            return models();
        }
        let id = format!("call_{index}");
        let read = json!({"path":"a.txt"});
        let poll = json!({"command":"printf x >> poll.log; wc -c < poll.log"});
        match index {
            0..=2 => tool_reply(&id, "read_file", &read),
            3 => tool_reply(
                &id,
                "edit_file",
                &json!({"path":"a.txt","old_text":"alpha","new_text":"beta"}),
            ),
            // The shell restores the old bytes: a later read returns a result
            // identical to the reads before the successful edit.
            4 => tool_reply(
                &id,
                "run_command",
                &json!({"command":"printf 'alpha\\n' > a.txt"}),
            ),
            5 | 6 => tool_reply(&id, "read_file", &read),
            7..=10 => tool_reply(&id, "run_command", &poll),
            _ => text_reply("Готово"),
        }
    });
    let home = Home::new(&server);
    std::fs::write(home.project.join("a.txt"), "alpha\n").unwrap();
    let output = home.exec(&[], "Проверь a.txt и дождись четырёх опросов");
    let log = text(&output);
    assert!(output.status.success(), "{log}");
    assert!(of_type(&events(&output), "error").is_empty(), "{log}");
    assert_eq!(server.generations().len(), 12, "{log}");
    assert_eq!(
        std::fs::read_to_string(home.project.join("poll.log")).unwrap(),
        "xxxx"
    );
    assert_eq!(
        std::fs::read_to_string(home.project.join("a.txt")).unwrap(),
        "alpha\n"
    );
}

#[test]
fn task_denials_and_unfinished_batches_survive_local_compaction_and_resume() {
    let base = tempfile::tempdir().unwrap();
    let project = base.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let store = ConfigStore::at(base.path().join("state")).unwrap();
    let settings = profile_settings(
        "mlx",
        "http://127.0.0.1:1/v1",
        LocalRuntime::Mlx,
        "qwen-27b",
    );
    let budget = mlx_budget(9000);
    let mut session = Session::new(&project, settings).unwrap();
    let batch = |session: &mut Session, calls: Vec<ToolCall>, results: &[&str]| {
        session.messages.push(Message::assistant(&Completion {
            tool_calls: calls.clone(),
            ..Completion::default()
        }));
        for (call, result) in calls.iter().zip(results) {
            session.messages.push(Message::tool(call, *result));
        }
    };
    session.messages.push(Message::user("Old task"));
    let old_denied = r#"{"error":"denied","message":"OLD_DENIAL action was not executed"}"#;
    batch(
        &mut session,
        vec![ToolCall::new(
            "run_command",
            json!({"command":"rm -rf old"}),
        )],
        &[old_denied],
    );
    session
        .messages
        .push(Message::text("assistant", "old analysis ".repeat(4000)));
    let task = "Current task: KEEP_TASK update notes.txt";
    session.messages.push(Message::user(task));
    let denied =
        r#"{"error":"denied","message":"User permission required; action was not executed"}"#;
    batch(
        &mut session,
        vec![ToolCall::new(
            "run_command",
            json!({"command":"rm -rf build"}),
        )],
        &[denied],
    );
    let readme = format!("{{\"content\":\"{}\"}}", "readme text ".repeat(1500));
    batch(
        &mut session,
        vec![ToolCall::new("read_file", json!({"path":"README.md"}))],
        &[&readme],
    );
    let unfinished = vec![
        ToolCall::new("write_file", json!({"path":"notes.txt","content":"n"})),
        ToolCall::new("run_command", json!({"command":"cargo test"})),
    ];
    batch(&mut session, unfinished.clone(), &["written"]);
    assert!(session.auto_compact_within(0, &budget).unwrap() > 0);
    let check = |session: &Session, resumed: bool| {
        let raw = |text: &str| {
            session
                .messages
                .iter()
                .any(|message| message.content.as_deref() == Some(text))
        };
        assert!(
            raw(task) && raw(denied),
            "task and current denial stay verbatim"
        );
        let summary = session.messages[0].content.as_deref().unwrap();
        assert!(summary.starts_with(MEMORY_PREFIX));
        assert!(summary.contains("OLD_DENIAL") && summary.contains("не означают успех"));
        let results: Vec<_> = session
            .messages
            .iter()
            .filter(|message| message.tool_call_id.as_deref() == Some(unfinished[1].id.as_str()))
            .collect();
        if resumed {
            // Closed as unknown on resume, never as success and never replayed.
            assert_eq!(results.len(), 1);
            let content = results[0].content.as_deref().unwrap();
            assert!(content.contains("interrupted") && content.contains("unknown"));
        } else {
            assert!(
                results.is_empty(),
                "no fabricated result for a pending call"
            );
        }
        assert!(
            session
                .messages
                .iter()
                .flat_map(|message| &message.tool_calls)
                .any(|call| call.id == unfinished[1].id)
        );
    };
    check(&session, false);
    session.save(&store).unwrap();
    let mut resumed = Session::load(&store, &session.id, &project).unwrap();
    check(&resumed, true);
    resumed
        .messages
        .push(Message::text("assistant", "more analysis ".repeat(4000)));
    resumed.compact_within(&budget).unwrap();
    check(&resumed, true);
    assert_eq!(resumed.repair_pending().unwrap(), 0);
}
