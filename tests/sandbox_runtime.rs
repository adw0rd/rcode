//! End-to-end runtime wire tests for host-enforced OS sandbox across main turns,
//! worker subagents, `start_command` -> `handoff_command` -> `stop_command`
//! `ShellTmp` lifecycle, parallel `ShellTmp` isolation, preflight failure
//! journal hygiene, and `--final-review-repair`.
#![cfg(any(target_os = "linux", target_os = "macos"))]
mod support;

use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Output,
    sync::{Arc, Mutex},
    time::Duration,
};
use support::{Request, Server, text_reply, tool_reply};
use tokio::process::Command;

const KEY: &str = "sandbox-runtime-synthetic-key";

fn latest_tool(request: &Request) -> Option<(String, Value)> {
    request.json()["messages"]
        .as_array()?
        .iter()
        .rev()
        .find(|m| m["role"] == "tool")
        .map(|m| {
            let content = m["content"].as_str().unwrap_or_default();
            let parsed =
                serde_json::from_str(content).unwrap_or_else(|_| Value::String(content.to_owned()));
            (m["name"].as_str().unwrap_or_default().to_owned(), parsed)
        })
}

fn system_prompt_text(request: &Request) -> String {
    request.json()["messages"]
        .as_array()
        .and_then(|msgs| msgs.iter().find(|m| m["role"] == "system"))
        .and_then(|m| m["content"].as_str())
        .unwrap_or_default()
        .to_owned()
}

fn first_user_text(request: &Request) -> String {
    request.json()["messages"]
        .as_array()
        .and_then(|msgs| msgs.iter().find(|m| m["role"] == "user"))
        .and_then(|m| m["content"].as_str())
        .unwrap_or_default()
        .to_owned()
}

fn last_user_text(request: &Request) -> String {
    request.json()["messages"]
        .as_array()
        .and_then(|msgs| msgs.iter().rfind(|m| m["role"] == "user"))
        .and_then(|m| m["content"].as_str())
        .unwrap_or_default()
        .to_owned()
}

fn collect_files(root: &Path) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(root) else {
        return out;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            out.extend(collect_files(&p));
        } else if let Ok(bytes) = fs::read(&p) {
            out.push((p, String::from_utf8_lossy(&bytes).into_owned()));
        }
    }
    out
}

fn journal_records(state: &Path) -> Vec<Value> {
    collect_files(state)
        .into_iter()
        .filter(|(p, _)| p.ends_with("operations/index.json"))
        .flat_map(|(_, body)| {
            serde_json::from_str::<Value>(&body).unwrap()["records"]
                .as_array()
                .unwrap()
                .clone()
        })
        .collect()
}

async fn run_rcode(
    project: &Path,
    state: &Path,
    home: &Path,
    server: &Server,
    extra_args: &[&str],
    prompt: &str,
) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rcode"));
    cmd.env_clear()
        .env(
            "PATH",
            std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into()),
        )
        .env("HOME", home)
        .env("RCODE_HOME", state)
        .env("OPENAI_API_KEY", KEY);
    for key in ["TMPDIR", "TEMP", "TMP"] {
        if let Some(v) = std::env::var_os(key) {
            cmd.env(key, v);
        }
    }
    cmd.args([
        "-C",
        project.to_str().unwrap(),
        "--provider",
        "custom",
        "--model",
        "fixture",
        "--base-url",
        &server.base(),
        "--json",
        "--max-steps",
        "14",
    ])
    .args(extra_args)
    .args(["exec", prompt])
    .kill_on_drop(true);
    tokio::time::timeout(Duration::from_secs(30), cmd.output())
        .await
        .expect("CLI timed out")
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_access_and_allow_shell_never_disable_read_only_sandbox_across_main_worker_and_repair()
{
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().canonicalize().unwrap();
    let project = base.join("project");
    let state = base.join("state");
    let home = base.join("home");
    for d in [&project, &state, &home.join(".ssh")] {
        fs::create_dir_all(d).unwrap();
    }
    fs::write(project.join("README.md"), "IMMUTABLE\n").unwrap();
    fs::write(home.join(".ssh/id_ed25519"), "HOME_SSH_SECRET").unwrap();

    let observed_main_tmp: Arc<Mutex<Option<PathBuf>>> = Arc::new(Mutex::new(None));
    let observed_main_tmp_srv = observed_main_tmp.clone();
    let worker_saw_denial = Arc::new(Mutex::new(false));
    let worker_saw_denial_srv = worker_saw_denial.clone();
    let repair_saw_denial = Arc::new(Mutex::new(false));
    let repair_saw_denial_srv = repair_saw_denial.clone();
    let cred_file = state.join("credentials.json");

    let server = Server::start(move |request, _global_step| {
        let has_tools = request
            .json()
            .get("tools")
            .and_then(Value::as_array)
            .is_some_and(|t| !t.is_empty());
        if !has_tools {
            // Read-only final review call (`review_model = same`).
            return text_reply("Check README.md in repair pass without mutating workspace.");
        }

        let sys = system_prompt_text(request);
        assert!(
            sys.contains("\"shell_sandbox\":{\"mode\":\"read-only\",\"network\":false}")
                || sys.contains("\"mode\":\"read-only\""),
            "system prompt missing active shell_sandbox: {sys}"
        );
        assert!(
            !sys.contains("is not an OS sandbox")
                && !sys.contains("Shell has the user's privileges"),
            "system prompt contradicts active OS sandbox: {sys}"
        );
        if let Some(run_desc) = request.json()["tools"]
            .as_array()
            .and_then(|tools| {
                tools
                    .iter()
                    .find(|t| t["function"]["name"] == "run_command")
            })
            .and_then(|t| t["function"]["description"].as_str())
        {
            assert!(
                run_desc.contains("внутри активной read-only OS-песочницы")
                    && !run_desc.contains("Это не OS sandbox")
                    && !run_desc.contains("с правами пользователя")
                    && !run_desc.contains("mkdir и quoted heredoc создают файлы"),
                "run_command description contradicts active read-only OS sandbox: {run_desc}"
            );
        }

        let task = first_user_text(request);
        let tool_count = request.json()["messages"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|m| m["role"] == "tool")
            .count();

        if task.starts_with("WORKER_RO_CHECK") {
            match tool_count {
                0 => tool_reply(
                    "w-cmd",
                    "run_command",
                    &json!({
                        "command": format!(
                            "if printf pwn > worker_pwn.txt 2>/dev/null || cat '{}' 2>/dev/null; then printf ESCAPED; else printf BLOCKED; fi",
                            cred_file.display()
                        )
                    }),
                ),
                1 => {
                    let (_, receipt) = latest_tool(request).unwrap();
                    assert_eq!(receipt["stdout"], "BLOCKED", "receipt={receipt}");
                    assert_eq!(receipt["sandbox"]["requested_mode"], "read-only");
                    *worker_saw_denial_srv.lock().unwrap() = true;
                    text_reply("Worker verified read-only sandbox.")
                }
                _ => panic!("unexpected worker step"),
            }
        } else if last_user_text(request).contains("<untrusted_final_review>") {
            // Repair pass! Must ALSO run under read-only sandbox.
            let repair_tools = request.json()["messages"]
                .as_array()
                .unwrap()
                .iter()
                .rev()
                .take_while(|m| m["role"] != "user")
                .filter(|m| m["role"] == "tool")
                .count();
            match repair_tools {
                0 => tool_reply(
                    "repair-cmd",
                    "run_command",
                    &json!({
                        "command": "if printf repair_pwn > repair_pwn.txt 2>/dev/null; then printf ESCAPED; else printf REPAIR_BLOCKED; fi"
                    }),
                ),
                1 => {
                    let (_, receipt) = latest_tool(request).unwrap();
                    assert_eq!(receipt["stdout"], "REPAIR_BLOCKED", "receipt={receipt}");
                    assert_eq!(receipt["sandbox"]["requested_mode"], "read-only");
                    *repair_saw_denial_srv.lock().unwrap() = true;
                    text_reply("Final repaired answer confirmed under read-only sandbox.")
                }
                _ => panic!("unexpected repair step"),
            }
        } else {
            match tool_count {
                0 => tool_reply(
                    "m-cmd",
                    "run_command",
                    &json!({
                        "command": "if printf pwn > README.md 2>/dev/null; then exit 9; fi; printf tmp_ok > \"$TMPDIR/probe.txt\" && printf '%s' \"$TMPDIR\""
                    }),
                ),
                1 => {
                    let (_, receipt) = latest_tool(request).unwrap();
                    assert_eq!(receipt["exit_code"], 0, "receipt={receipt}");
                    assert_eq!(receipt["sandbox"]["requested_mode"], "read-only");
                    let tmp_path = PathBuf::from(receipt["stdout"].as_str().unwrap().trim());
                    assert!(
                        !tmp_path.exists(),
                        "ShellTmp should already be cleaned up before tool result returns: {}",
                        tmp_path.display()
                    );
                    *observed_main_tmp_srv.lock().unwrap() = Some(tmp_path);
                    tool_reply(
                        "m-spawn",
                        "spawn_agent",
                        &json!({
                            "name": "ro-worker",
                            "role": "worker",
                            "task": "WORKER_RO_CHECK"
                        }),
                    )
                }
                2 => {
                    let (_, spawn_res) = latest_tool(request).unwrap();
                    let id = spawn_res["agent_id"].as_str().unwrap().to_owned();
                    tool_reply("m-wait", "wait_agent", &json!({"agent_id": id}))
                }
                3 => text_reply("Draft complete."),
                _ => panic!("unexpected main step {tool_count}"),
            }
        }
    });

    // Save a dummy credential in RCODE_HOME/credentials.json so worker attempts to read a real file.
    fs::write(
        state.join("credentials.json"),
        "{\"version\":1,\"providers\":{\"openrouter\":\"CANARY-SECRET-VALUE\"}}\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(
            state.join("credentials.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }

    let out = run_rcode(
        &project,
        &state,
        &home,
        &server,
        &[
            "--approval-mode",
            "full-access",
            "--allow-shell",
            "--sandbox",
            "read-only",
            "--final-review-repair",
        ],
        "Verify read-only sandbox across main, worker, and repair.",
    )
    .await;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "status={} stderr={stderr}\nstdout={stdout}",
        out.status
    );

    let start_ev: Value = stdout
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find(|v| v["type"] == "start" || v["event"] == "start")
        .expect("start event emitted");
    assert_eq!(start_ev["sandbox"]["mode"], "read-only");
    assert_eq!(start_ev["sandbox"]["network"], false);

    assert!(observed_main_tmp.lock().unwrap().is_some());
    assert!(*worker_saw_denial.lock().unwrap());
    assert!(*repair_saw_denial.lock().unwrap());
    assert_eq!(
        fs::read_to_string(project.join("README.md")).unwrap(),
        "IMMUTABLE\n"
    );
    assert!(!project.join("worker_pwn.txt").exists());
    assert!(!project.join("repair_pwn.txt").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_command_handoff_preserves_sandbox_and_keeps_shell_tmp_until_stop_command() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().canonicalize().unwrap();
    let project = base.join("project");
    let state = base.join("state");
    let home = base.join("home");
    let outside = base.join("outside");
    for d in [&project, &state, &home, &outside] {
        fs::create_dir_all(d).unwrap();
    }
    let outside_secret = outside.join("secret.txt");
    fs::write(&outside_secret, "OUTSIDE_HANDOFF_SECRET").unwrap();

    let captured_tmp: Arc<Mutex<Option<PathBuf>>> = Arc::new(Mutex::new(None));
    let captured_tmp_srv = captured_tmp.clone();
    let project_srv = project.clone();

    let server = Server::start(move |request, _step| {
        let task = first_user_text(request);
        let tool_count = request.json()["messages"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|m| m["role"] == "tool")
            .count();

        if task.starts_with("WORKER_BG") {
            match tool_count {
                0 => tool_reply(
                    "w-start",
                    "start_command",
                    &json!({
                        "command": format!(
                            "printf alive > \"$TMPDIR/live.txt\" && printf '%s' \"$TMPDIR\" > job_tmp.path && if cat '{}' 2>/dev/null; then printf LEAKED > leaked; fi; sleep 60",
                            outside_secret.display()
                        ),
                        "stdin": false
                    }),
                ),
                1 => {
                    let (name, receipt) = latest_tool(request).unwrap();
                    assert_eq!(name, "start_command");
                    assert_eq!(receipt["sandbox"]["requested_mode"], "workspace-write");
                    let cid = receipt["command_id"].as_str().unwrap().to_owned();
                    tool_reply("w-handoff", "handoff_command", &json!({"command_id": cid}))
                }
                2 => text_reply("Worker handed off background job."),
                _ => panic!("unexpected worker step"),
            }
        } else {
            match tool_count {
                0 => tool_reply(
                    "p-spawn",
                    "spawn_agent",
                    &json!({
                        "name": "bg-worker",
                        "role": "worker",
                        "task": "WORKER_BG"
                    }),
                ),
                1 => {
                    let (_, spawn_res) = latest_tool(request).unwrap();
                    let id = spawn_res["agent_id"].as_str().unwrap().to_owned();
                    tool_reply("p-wait", "wait_agent", &json!({"agent_id": id}))
                }
                2 => {
                    let (_, wait_res) = latest_tool(request).unwrap();
                    let cid = wait_res["transferred_commands"][0]["command_id"]
                        .as_str()
                        .unwrap()
                        .to_owned();
                    // Wait briefly for the background shell to write `job_tmp.path`.
                    let deadline = std::time::Instant::now() + Duration::from_secs(5);
                    while !project_srv.join("job_tmp.path").exists()
                        && std::time::Instant::now() < deadline
                    {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    let job_tmp = PathBuf::from(
                        fs::read_to_string(project_srv.join("job_tmp.path"))
                            .unwrap()
                            .trim(),
                    );
                    // CRITICAL: Worker has ALREADY exited after `handoff_command`, yet the job's
                    // private `ShellTmp` MUST still exist while the process is running!
                    assert!(
                        job_tmp.join("live.txt").is_file(),
                        "ShellTmp was deleted prematurely on worker exit: {}",
                        job_tmp.display()
                    );
                    assert!(!project_srv.join("leaked").exists());
                    *captured_tmp_srv.lock().unwrap() = Some(job_tmp);
                    tool_reply("p-stop", "stop_command", &json!({"command_id": cid}))
                }
                3 => {
                    let (name, stop_res) = latest_tool(request).unwrap();
                    assert_eq!(name, "stop_command");
                    assert_eq!(stop_res["cleanup_complete"], true);
                    let job_tmp = captured_tmp_srv.lock().unwrap().clone().unwrap();
                    assert!(
                        !job_tmp.exists(),
                        "ShellTmp must be deleted once stop_command confirms cleanup: {}",
                        job_tmp.display()
                    );
                    text_reply("Stopped handed-off job cleanly.")
                }
                _ => panic!("unexpected parent step"),
            }
        }
    });

    let out = run_rcode(
        &project,
        &state,
        &home,
        &server,
        &[
            "--approval-mode",
            "full-access",
            "--sandbox",
            "workspace-write",
        ],
        "Start background job in worker, hand off, verify ShellTmp, and stop.",
    )
    .await;
    assert!(
        out.status.success(),
        "stderr={}\nstdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    let final_tmp = captured_tmp.lock().unwrap().clone().unwrap();
    assert!(!final_tmp.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn parallel_managed_jobs_have_isolated_per_job_shell_tmp_directories() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().canonicalize().unwrap();
    let project = base.join("project");
    let state = base.join("state");
    let home = base.join("home");
    for d in [&project, &state, &home] {
        fs::create_dir_all(d).unwrap();
    }
    let project_srv = project.clone();
    let ids: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let ids_srv = ids.clone();

    let server = Server::start(move |request, _step| {
        let tool_count = request.json()["messages"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|m| m["role"] == "tool")
            .count();
        match tool_count {
            0 => tool_reply(
                "s1",
                "start_command",
                &json!({"command": "printf a > \"$TMPDIR/a.txt\" && printf '%s' \"$TMPDIR\" > tmp_a && sleep 60", "stdin": false}),
            ),
            1 => {
                let (_, r1) = latest_tool(request).unwrap();
                ids_srv
                    .lock()
                    .unwrap()
                    .push(r1["command_id"].as_str().unwrap().to_owned());
                tool_reply(
                    "s2",
                    "start_command",
                    &json!({"command": "printf b > \"$TMPDIR/b.txt\" && printf '%s' \"$TMPDIR\" > tmp_b && sleep 60", "stdin": false}),
                )
            }
            2 => {
                let (_, r2) = latest_tool(request).unwrap();
                ids_srv
                    .lock()
                    .unwrap()
                    .push(r2["command_id"].as_str().unwrap().to_owned());
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                while (!project_srv.join("tmp_a").exists() || !project_srv.join("tmp_b").exists())
                    && std::time::Instant::now() < deadline
                {
                    std::thread::sleep(Duration::from_millis(20));
                }
                let tmp_a = PathBuf::from(fs::read_to_string(project_srv.join("tmp_a")).unwrap());
                let tmp_b = PathBuf::from(fs::read_to_string(project_srv.join("tmp_b")).unwrap());
                assert_ne!(tmp_a, tmp_b, "each job must get its own isolated ShellTmp");
                assert!(tmp_a.join("a.txt").is_file());
                assert!(!tmp_a.join("b.txt").exists());
                assert!(tmp_b.join("b.txt").is_file());
                let id1 = ids_srv.lock().unwrap()[0].clone();
                tool_reply("stop1", "stop_command", &json!({"command_id": id1}))
            }
            3 => {
                let tmp_a = PathBuf::from(fs::read_to_string(project_srv.join("tmp_a")).unwrap());
                let tmp_b = PathBuf::from(fs::read_to_string(project_srv.join("tmp_b")).unwrap());
                assert!(!tmp_a.exists(), "stopped job_a ShellTmp must be deleted");
                assert!(
                    tmp_b.join("b.txt").is_file(),
                    "job_b ShellTmp must remain untouched while job_b is still running"
                );
                let id2 = ids_srv.lock().unwrap()[1].clone();
                tool_reply("stop2", "stop_command", &json!({"command_id": id2}))
            }
            4 => {
                let tmp_b = PathBuf::from(fs::read_to_string(project_srv.join("tmp_b")).unwrap());
                assert!(!tmp_b.exists(), "stopped job_b ShellTmp must be deleted");
                text_reply("Both isolated jobs cleaned up.")
            }
            _ => panic!("unexpected step"),
        }
    });

    let out = run_rcode(
        &project,
        &state,
        &home,
        &server,
        &[
            "--approval-mode",
            "full-access",
            "--sandbox",
            "workspace-write",
        ],
        "Run two parallel jobs and verify isolated ShellTmp.",
    )
    .await;
    assert!(
        out.status.success(),
        "stderr={}\nstdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sandbox_preflight_refusal_records_zero_unknown_journal_entries() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().canonicalize().unwrap();
    let project = base.join("project");
    let state = base.join("state");
    // Place `home` INSIDE `outer_grant` so `--add-dir outer_grant` passes `Tools::new`,
    // while `PreparedSandbox::prepare` rejects `outer_grant` as an ancestor of `$HOME`!
    let outer_grant = base.join("outer-grant");
    let home = outer_grant.join("nested-home");
    for d in [&project, &state, &home] {
        fs::create_dir_all(d).unwrap();
    }

    let server = Server::start(move |request, _step| {
        let tool_count = request.json()["messages"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|m| m["role"] == "tool")
            .count();
        match tool_count {
            0 => tool_reply("fg-fail", "run_command", &json!({"command": "printf bad"})),
            1 => {
                let (name, res) = latest_tool(request).unwrap();
                assert_eq!(name, "run_command");
                let text = res.to_string();
                assert!(
                    text.contains("$HOME"),
                    "expected sensitive-root refusal: {text}"
                );
                tool_reply(
                    "bg-fail",
                    "start_command",
                    &json!({"command": "sleep 5", "stdin": false}),
                )
            }
            2 => {
                let (name, res) = latest_tool(request).unwrap();
                assert_eq!(name, "start_command");
                assert_eq!(res["error"], "sandbox_preflight_failed", "res={res}");
                tool_reply("ro-ok", "list_files", &json!({}))
            }
            3 => text_reply("Preflight refusals observed."),
            _ => panic!("unexpected step"),
        }
    });

    let out = run_rcode(
        &project,
        &state,
        &home,
        &server,
        &[
            "--approval-mode",
            "full-access",
            "--sandbox",
            "workspace-write",
            "--add-dir",
            outer_grant.to_str().unwrap(),
        ],
        "Trigger preflight refusals for run_command and start_command.",
    )
    .await;
    assert!(
        out.status.success(),
        "stderr={}\nstdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    let records = journal_records(&state);
    assert!(
        records.is_empty(),
        "preflight failure must not write Unknown or phantom journal records: {records:?}"
    );
}
