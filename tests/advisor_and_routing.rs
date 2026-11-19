//! CLI and wire contract tests for `/advisor` (`rcode advisor`, `--advisor`) and
//! `spawn_agent(route)` model routing over local HTTP/SSE fixtures.
mod support;

use serde_json::{Value, json};
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};
use support::{Response, Server, text_reply, tool_reply};

const PRIMARY_KEY: &str = "routing-primary-synthetic-secret";
const ROUTER_KEY: &str = "routing-openrouter-synthetic-secret";
const GIGA_KEY: &str = "routing-gigachat-synthetic-secret";

fn write_state(project: &Path, state: &Path, primary_base: &str, router_base: &str) {
    fs::create_dir_all(project).unwrap();
    fs::create_dir_all(state).unwrap();
    let config = json!({
        "version": 1,
        "active": "custom",
        "providers": {
            "custom": {
                "kind": "custom",
                "model": "primary-coder",
                "base_url": primary_base,
                "stream": true
            },
            "openrouter": {
                "kind": "openrouter",
                "model": "z-ai/glm-5",
                "base_url": router_base,
                "stream": true
            },
            "gigachat": {
                "kind": "gigachat",
                "model": "GigaChat-2-Max",
                "stream": true
            }
        },
        "local": {
            "active": "mlx",
            "profiles": {
                "mlx": {
                    "kind": "local",
                    "model": "Qwen3.8-27B",
                    "base_url": primary_base,
                    "stream": true,
                    "local": {
                        "profile": "mlx",
                        "runtime": "mlx",
                        "thinking": false
                    }
                }
            }
        }
    });
    fs::write(
        state.join("config.json"),
        serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    fs::write(
        state.join("credentials.json"),
        serde_json::to_vec(&json!({
            "version": 1,
            "providers": {
                "custom": PRIMARY_KEY,
                "openrouter": ROUTER_KEY,
                "gigachat": GIGA_KEY
            }
        }))
        .unwrap(),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(state.join("config.json"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(
            state.join("credentials.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
}

fn run_rcode(project: &Path, state: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rcode"));
    cmd.arg("-C")
        .arg(project)
        .args(args)
        .env("RCODE_HOME", state)
        .env_remove("RCODE_YANDEX_API_KEY")
        .env_remove("YANDEX_API_KEY")
        .env_remove("RCODE_GIGACHAT_AUTH_KEY")
        .env_remove("GIGACHAT_AUTH_KEY")
        .env_remove("GIGACHAT_CREDENTIALS")
        .env_remove("RCODE_OPENROUTER_API_KEY")
        .env_remove("OPENROUTER_API_KEY")
        .env_remove("RCODE_CUSTOM_API_KEY")
        .env_remove("OPENAI_API_KEY")
        .env_remove("RCODE_MODEL_SHELL")
        .env_remove("RCODE_EVAL_MODE");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

#[test]
fn cli_advisor_subcommands_model_shell_guard_and_eval_isolation() {
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("project");
    let state = tmp.path().join("state");
    write_state(
        &project,
        &state,
        "http://127.0.0.1:9/v1",
        "http://127.0.0.1:9/v1",
    );

    let status0 = run_rcode(&project, &state, &["advisor", "status", "--json"], &[]);
    assert!(status0.status.success(), "{status0:?}");
    let v0: Value = serde_json::from_slice(&status0.stdout).unwrap();
    assert_eq!(v0["data"]["enabled"], false);
    assert_eq!(v0["data"]["source"], "saved_off");

    // Cyrillic alias `гигачат` resolves offline without network!
    let set_giga = run_rcode(
        &project,
        &state,
        &["advisor", "set", "гигачат", "--json"],
        &[],
    );
    assert!(set_giga.status.success(), "{set_giga:?}");
    let vg: Value = serde_json::from_slice(&set_giga.stdout).unwrap();
    assert_eq!(vg["data"]["enabled"], true);
    assert_eq!(vg["data"]["provider"], "gigachat");
    assert_eq!(vg["data"]["model"], "GigaChat-2-Max");

    // Explicit `openrouter:MODEL` selector
    let set_or = run_rcode(
        &project,
        &state,
        &[
            "advisor",
            "set",
            "openrouter:anthropic/claude-opus-4-6",
            "--json",
        ],
        &[],
    );
    assert!(set_or.status.success(), "{set_or:?}");
    let vor: Value = serde_json::from_slice(&set_or.stdout).unwrap();
    assert_eq!(vor["data"]["provider"], "openrouter");
    assert_eq!(vor["data"]["model"], "anthropic/claude-opus-4-6");

    // Model shell cannot mutate `/advisor` settings!
    let blocked = run_rcode(
        &project,
        &state,
        &["advisor", "off"],
        &[("RCODE_MODEL_SHELL", "1")],
    );
    assert!(!blocked.status.success());

    let off = run_rcode(&project, &state, &["advisor", "off", "--json"], &[]);
    assert!(off.status.success());
    let voff: Value = serde_json::from_slice(&off.stdout).unwrap();
    assert_eq!(voff["data"]["enabled"], false);

    // `--advisor` rejected on non-session subcommands and `eval`.
    let bad_doc = run_rcode(&project, &state, &["--advisor", "gigachat", "doctor"], &[]);
    assert!(!bad_doc.status.success());

    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("evals/todo-api/manifest.json");
    let bad_eval = run_rcode(
        &project,
        &state,
        &[
            "--advisor",
            "gigachat",
            "eval",
            "validate",
            "--suite",
            manifest.to_str().unwrap(),
        ],
        &[],
    );
    assert!(!bad_eval.status.success());
}

#[test]
fn exec_with_advisor_flag_runs_toolless_pass_redacts_secrets_and_honors_force_off() {
    let primary = Server::start(|_req, idx| match idx {
        0 => tool_reply(
            "call_adv_1",
            "advisor",
            &json!({"focus": "архитектура кэша"}),
        ),
        _ => text_reply("Готово с учётом совета."),
    });
    let advisor_srv = Server::start(|_req, _idx| {
        text_reply(&format!(
            "Раздели слой хранения и валидацию ({ROUTER_KEY} / {PRIMARY_KEY})."
        ))
    });

    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("project");
    let state = tmp.path().join("state");
    write_state(&project, &state, &primary.base(), &advisor_srv.base());

    let out = run_rcode(
        &project,
        &state,
        &[
            "--json",
            "--advisor",
            "openrouter:anthropic/claude-opus-4-6",
            "exec",
            &format!("Спроектируй кэш (ключ {PRIMARY_KEY})"),
        ],
        &[],
    );
    assert!(
        out.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(!stdout.contains(PRIMARY_KEY), "{stdout}");
    assert!(!stdout.contains(ROUTER_KEY), "{stdout}");
    let tool_event: Value = stdout
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|ev| ev["type"] == "tool_result" && ev["name"] == "advisor")
        .expect("advisor tool_result event");
    let receipt: Value = serde_json::from_str(tool_event["content"].as_str().unwrap()).unwrap();
    assert_eq!(receipt["advisory"], true);
    assert_eq!(receipt["status"], "advice");
    assert_eq!(receipt["provider"], "openrouter");
    assert_eq!(receipt["model"], "anthropic/claude-opus-4-6");
    assert_eq!(receipt["uses_remaining"], 2);
    assert!(
        receipt["guidance"].as_str().unwrap().contains("[REDACTED]"),
        "{receipt}"
    );

    let adv_requests = advisor_srv.generations();
    assert_eq!(adv_requests.len(), 1);
    let adv_json = adv_requests[0].json();
    assert_eq!(adv_json["model"], "anthropic/claude-opus-4-6");
    assert!(
        adv_json.get("tools").is_none(),
        "advisor wire request must never include tools: {adv_json}"
    );
    let raw_adv_body = String::from_utf8_lossy(&adv_requests[0].body);
    assert!(!raw_adv_body.contains(PRIMARY_KEY), "{raw_adv_body}");
    assert!(!raw_adv_body.contains(ROUTER_KEY), "{raw_adv_body}");

    // Save global advisor, then verify `--advisor off` suppresses advisor declaration & execution.
    let set_global = run_rcode(&project, &state, &["advisor", "set", "openrouter"], &[]);
    assert!(set_global.status.success());

    let primary_off = Server::start(|_req, _idx| text_reply("Без советника."));
    let advisor_unused = Server::start(|_req, _idx| text_reply("Не должен вызываться"));
    write_state(
        &project,
        &state,
        &primary_off.base(),
        &advisor_unused.base(),
    );
    let set_global_again = run_rcode(&project, &state, &["advisor", "set", "openrouter"], &[]);
    assert!(
        set_global_again.status.success(),
        "re-enabling global advisor after write_state must succeed: {}",
        String::from_utf8_lossy(&set_global_again.stderr)
    );
    let verify_enabled = run_rcode(&project, &state, &["--json", "advisor", "status"], &[]);
    assert!(verify_enabled.status.success());
    let verify_json: Value = serde_json::from_slice(&verify_enabled.stdout).unwrap();
    assert_eq!(verify_json["data"]["enabled"], true);

    let out_off = run_rcode(
        &project,
        &state,
        &["--json", "--advisor", "off", "exec", "Короткий ответ"],
        &[],
    );
    assert!(out_off.status.success());
    assert_eq!(advisor_unused.generations().len(), 0);
    let off_req = primary_off.generations()[0].json();
    let tool_names: Vec<&str> = off_req["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["function"]["name"].as_str())
        .collect();
    assert!(
        !tool_names.contains(&"advisor"),
        "--advisor off must omit advisor tool when history has no prior calls: {tool_names:?}"
    );

    // End-to-end 9,000-char advisor reply through `turn_inner`: inline receipt is bounded
    // to <= 8,000 chars with `artifact_id` + `rcode_truncated`, while `read_tool_output`
    // recovers the unclipped `FINAL_UNIQUE_LINE_9000` in its `content` field!
    let primary_9k = Server::start(|req, idx| match idx {
        0 => tool_reply("call_adv_9k", "advisor", &json!({"focus": "Полный разбор"})),
        1 => {
            let body = req.json();
            let adv_msg = body["messages"]
                .as_array()
                .unwrap()
                .iter()
                .find(|m| m["role"] == "tool")
                .expect("tool receipt must be present on step 1");
            let raw_adv = adv_msg["content"].as_str().unwrap();
            assert!(
                raw_adv.chars().count() <= 8_000,
                "inline advisor receipt must be <= 8000 chars: {}",
                raw_adv.chars().count()
            );
            let parsed_adv: Value = serde_json::from_str(raw_adv).unwrap();
            let art_id = parsed_adv["artifact_id"]
                .as_str()
                .expect("artifact_id must be present on advisor receipt");
            tool_reply(
                "call_read_9k",
                "read_tool_output",
                &json!({"artifact_id": art_id, "query": "FINAL_UNIQUE_LINE_9000"}),
            )
        }
        _ => {
            let body = req.json();
            let read_msg = body["messages"]
                .as_array()
                .unwrap()
                .iter()
                .rev()
                .find(|m| m["role"] == "tool")
                .expect("read_tool_output receipt must be present on step 2");
            let parsed_read: Value =
                serde_json::from_str(read_msg["content"].as_str().unwrap()).unwrap();
            let page_content = parsed_read["content"].as_str().unwrap_or_default();
            assert!(
                page_content.contains("FINAL_UNIQUE_LINE_9000"),
                "read_tool_output content must contain the last line of the 9,000-char advisor reply: {parsed_read}"
            );
            text_reply("Прочитан полный ответ советника.")
        }
    });
    let advisor_9k = Server::start(|_req, _idx| {
        text_reply(&format!("{}\nFINAL_UNIQUE_LINE_9000", "w".repeat(9_000)))
    });
    write_state(&project, &state, &primary_9k.base(), &advisor_9k.base());
    let out_9k = run_rcode(
        &project,
        &state,
        &[
            "--json",
            "--advisor",
            "openrouter:anthropic/claude-opus-4-6",
            "exec",
            "Проверь длинный ответ советника",
        ],
        &[],
    );
    assert!(
        out_9k.status.success(),
        "9k advisor + read_tool_output run must succeed: {}",
        String::from_utf8_lossy(&out_9k.stderr)
    );
    assert_eq!(primary_9k.generations().len(), 3);
    assert_eq!(advisor_9k.generations().len(), 1);
}

#[test]
fn exec_same_route_subagent_succeeds_while_different_model_or_provider_and_eval_fail_closed() {
    // 1a) Exact same `RouteIdentity` (`openrouter:z-ai/glm-5` -> `openrouter:z-ai/glm-5`) works in `exec` without extra TTY consent,
    // and `wait_agent` returns the completed worker output!
    let router = Server::start(|req, _idx| {
        let body = req.json();
        let msgs = body["messages"].as_array().unwrap();
        let sys = msgs[0]["content"].as_str().unwrap_or_default();
        if sys.contains("subagent") || sys.contains("explorer") || sys.contains("reviewer") {
            return Response::json(
                200,
                json!({
                    "choices": [{"message": {"role": "assistant", "content": "Ревью GLM: замечаний нет (GLM_SUBAGENT_REVIEW_OK)."}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 22, "completion_tokens": 7}
                }),
            );
        }
        let tool_msgs: Vec<&Value> = msgs.iter().filter(|m| m["role"] == "tool").collect();
        if tool_msgs.is_empty() {
            tool_reply(
                "spawn_glm",
                "spawn_agent",
                &json!({"task": "Проверь модуль", "role": "reviewer", "route": "openrouter:z-ai/glm-5"}),
            )
        } else if tool_msgs.len() == 1 {
            let spawn_content = tool_msgs[0]["content"].as_str().unwrap_or_default();
            let spawn_json: Value = serde_json::from_str(spawn_content).unwrap();
            let agent_id = spawn_json["agent_id"]
                .as_str()
                .or_else(|| spawn_json["id"].as_str())
                .expect("spawn_agent receipt must include agent_id");
            tool_reply("wait_glm", "wait_agent", &json!({"agent_id": agent_id}))
        } else {
            let wait_content = tool_msgs[1]["content"].as_str().unwrap_or_default();
            assert!(
                wait_content.contains("\"status\":\"completed\"")
                    && wait_content.contains("GLM_SUBAGENT_REVIEW_OK"),
                "wait_agent must deliver completed subagent result: {wait_content}"
            );
            text_reply("Ревью через GLM выполнено.")
        }
    });

    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("project");
    let state = tmp.path().join("state");
    write_state(&project, &state, &router.base(), &router.base());

    let same_id = run_rcode(
        &project,
        &state,
        &[
            "--json",
            "--provider",
            "openrouter",
            "--model",
            "z-ai/glm-5",
            "exec",
            "Для ревью используй glm",
        ],
        &[],
    );
    assert!(
        same_id.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&same_id.stdout),
        String::from_utf8_lossy(&same_id.stderr)
    );
    assert!(
        router.generations().len() >= 2,
        "expected both primary and same-identity subagent calls"
    );

    // 1b) Switching model on the same gateway (`openrouter:qwen/qwen3-coder` -> `openrouter:z-ai/glm-5`)
    // changes `RouteIdentity` and MUST fail closed in headless non-TTY `exec` with 0 `z-ai/glm-5` requests!
    let diff_model_router = Server::start(|req, idx| {
        let body = req.json();
        assert_ne!(
            body["model"], "z-ai/glm-5",
            "unapproved model switch on same gateway must never reach the wire"
        );
        match idx {
            0 => tool_reply(
                "spawn_other_model",
                "spawn_agent",
                &json!({"task": "Проверь модуль", "role": "reviewer", "route": "openrouter:z-ai/glm-5"}),
            ),
            _ => text_reply("Смена модели без TTY отклонена."),
        }
    });
    let tmp_diff = tempfile::tempdir().unwrap();
    let project_diff = tmp_diff.path().join("project");
    let state_diff = tmp_diff.path().join("state");
    write_state(
        &project_diff,
        &state_diff,
        &diff_model_router.base(),
        &diff_model_router.base(),
    );
    let diff_out = run_rcode(
        &project_diff,
        &state_diff,
        &[
            "--json",
            "--provider",
            "openrouter",
            "--model",
            "qwen/qwen3-coder",
            "--approval-mode",
            "full-access",
            "exec",
            "Для ревью используй glm",
        ],
        &[],
    );
    assert_eq!(diff_out.status.code(), Some(1));
    assert!(
        diff_model_router
            .generations()
            .iter()
            .all(|r| r.json()["model"] != "z-ai/glm-5")
    );

    // 2) Cross-provider (`local:mlx` -> `openrouter:z-ai/glm-5`) in non-TTY `exec` even with `full-access`
    // MUST fail-closed with 0 network requests to OpenRouter!
    let local_primary = Server::start(|_req, idx| match idx {
        0 => tool_reply(
            "spawn_cloud",
            "spawn_agent",
            &json!({"task": "Отправь код в облако", "role": "reviewer", "route": "glm"}),
        ),
        _ => text_reply("Внешний маршрут заблокирован без TTY."),
    });
    let untouched_cloud = Server::start(|_req, _idx| text_reply("Не должен вызываться"));
    let tmp2 = tempfile::tempdir().unwrap();
    let project2 = tmp2.path().join("project");
    let state2 = tmp2.path().join("state");
    write_state(
        &project2,
        &state2,
        &local_primary.base(),
        &untouched_cloud.base(),
    );

    let cross = run_rcode(
        &project2,
        &state2,
        &[
            "--json",
            "--profile",
            "mlx",
            "--approval-mode",
            "full-access",
            "exec",
            "Для ревью используй glm",
        ],
        &[],
    );
    assert_eq!(cross.status.code(), Some(1));
    assert_eq!(
        untouched_cloud.generations().len(),
        0,
        "local -> cloud subagent without interactive TTY approval must make 0 cloud requests"
    );

    // 3) `RCODE_EVAL_MODE=1` strips `available_routes` from prompt and blocks `spawn_agent(route)`!
    let eval_primary = Server::start(|_req, idx| match idx {
        0 => tool_reply(
            "spawn_eval",
            "spawn_agent",
            &json!({"task": "Попытка обхода в eval", "role": "explorer", "route": "openrouter:z-ai/glm-5"}),
        ),
        _ => text_reply("Заблокировано в eval."),
    });
    let eval_unused = Server::start(|_req, _idx| text_reply("Не должен вызываться"));
    let tmp3 = tempfile::tempdir().unwrap();
    let project3 = tmp3.path().join("project");
    let state3 = tmp3.path().join("state");
    write_state(
        &project3,
        &state3,
        &eval_primary.base(),
        &eval_unused.base(),
    );

    let eval_out = run_rcode(
        &project3,
        &state3,
        &["--json", "--profile", "mlx", "exec", "Задача eval"],
        &[("RCODE_EVAL_MODE", "1")],
    );
    assert_eq!(eval_out.status.code(), Some(1));
    assert_eq!(eval_unused.generations().len(), 0);
    let eval_req = eval_primary.generations()[0].json();
    let eval_sys = eval_req["messages"][0]["content"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(!eval_sys.contains("available_routes"), "{eval_sys}");
    let spawn_tool = eval_req["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["function"]["name"] == "spawn_agent")
        .unwrap();
    assert!(
        spawn_tool["function"]["parameters"]["properties"]
            .get("route")
            .is_none(),
        "eval mode must strip `route` from spawn_agent schema: {spawn_tool}"
    );
    let eval_cli_adv = run_rcode(
        &project3,
        &state3,
        &["advisor", "status"],
        &[("RCODE_EVAL_MODE", "1")],
    );
    assert!(!eval_cli_adv.status.success());
}

#[test]
fn gigachat_advisor_oauth_token_is_redacted_across_clients_and_advisor_forbidden_in_repair() {
    let minted_oauth = "giga-advisor-minted-oauth-sentinel-8842";
    let giga_adv = Server::start(move |req, _idx| {
        if req.path == "/oauth" {
            Response::json(
                200,
                json!({"access_token": minted_oauth, "expires_at": 4102444800000_u64}),
            )
        } else {
            text_reply(&format!(
                "Совет GigaChat с отражённым токеном {minted_oauth}"
            ))
        }
    });
    let primary = Server::start(move |_req, idx| match idx {
        0 => tool_reply("adv_giga", "advisor", &json!({"focus": "проверка OAuth"})),
        // Primary model tries to echo the advisor's freshly minted OAuth token too:
        1 => text_reply(&format!("Черновик без утечки {minted_oauth}")),
        // During `--final-review-repair`, primary tries calling `advisor` (must get `forbidden_in_repair`!)
        2 => tool_reply(
            "adv_in_repair",
            "advisor",
            &json!({"focus": "нельзя в repair"}),
        ),
        _ => text_reply("Исправленный итог."),
    });
    let reviewer =
        Server::start(|_req, _idx| text_reply("Замечание ревьюера: уточни формулировку."));

    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("project");
    let state = tmp.path().join("state");
    write_state(&project, &state, &primary.base(), &reviewer.base());

    let cfg_path = state.join("config.json");
    let mut cfg: Value = serde_json::from_slice(&fs::read(&cfg_path).unwrap()).unwrap();
    cfg["providers"]["gigachat"] = json!({
        "kind": "gigachat",
        "model": "GigaChat-2-Max",
        "base_url": giga_adv.base(),
        "auth_url": format!("{}/oauth", giga_adv.url),
        "stream": true
    });
    cfg["final_review"] = json!({
        "selected": {
            "snapshot": {
                "kind": "openrouter",
                "model": "z-ai/glm-5",
                "base_url": reviewer.base(),
                "stream": true
            }
        }
    });
    fs::write(&cfg_path, serde_json::to_vec(&cfg).unwrap()).unwrap();

    let out = run_rcode(
        &project,
        &state,
        &[
            "--json",
            "--advisor",
            "гигачат",
            "--final-review-repair",
            "exec",
            "Проверь контур советника и ревью",
        ],
        &[],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains(minted_oauth),
        "minted GigaChat OAuth token must never appear in stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("forbidden_in_repair"),
        "advisor call during final_review_repair must be blocked with forbidden_in_repair:\n{stdout}"
    );

    // Check saved session.json on disk for zero OAuth token leaks!
    let sessions_dir = state.join("sessions");
    for entry in fs::read_dir(&sessions_dir).unwrap() {
        let sfile = entry.unwrap().path().join("session.json");
        if sfile.is_file() {
            let text = fs::read_to_string(&sfile).unwrap();
            assert!(
                !text.contains(minted_oauth),
                "minted OAuth token leaked to session.json: {text}"
            );
        }
    }
}

#[test]
fn env_secrets_block_poisoned_routes_before_wire_and_redact_reflected_advisor_guidance() {
    let env_secret = "sk-env-openrouter-sentinel-7731";
    let untouched_poisoned_adv =
        Server::start(|_req, _idx| text_reply("Не должен вызываться при секрете в model"));
    let clean_adv = Server::start(move |_req, _idx| {
        text_reply(&format!("Совет с отражённым ключом {env_secret}"))
    });
    let primary = Server::start(|_req, idx| match idx {
        0 => tool_reply(
            "adv_meta",
            "advisor",
            &json!({"focus": "проверка метаданных"}),
        ),
        _ => text_reply("Готово."),
    });

    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("project");
    let state = tmp.path().join("state");
    write_state(&project, &state, &primary.base(), &clean_adv.base());

    // Remove openrouter from credentials.json so it comes EXCLUSIVELY from env (`OPENROUTER_API_KEY`),
    // and poison `providers.openrouter.model` AND `advisor.selected.snapshot.model` with `env_secret`!
    let creds_path = state.join("credentials.json");
    let mut creds: Value = serde_json::from_slice(&fs::read(&creds_path).unwrap()).unwrap();
    creds["providers"]
        .as_object_mut()
        .unwrap()
        .remove("openrouter");
    fs::write(&creds_path, serde_json::to_vec(&creds).unwrap()).unwrap();

    let cfg_path = state.join("config.json");
    let mut cfg: Value = serde_json::from_slice(&fs::read(&cfg_path).unwrap()).unwrap();
    cfg["providers"]["openrouter"]["model"] = json!(format!("vendor/{env_secret}"));
    cfg["advisor"] = json!({
        "selected": {
            "snapshot": {
                "kind": "openrouter",
                "model": format!("vendor/{env_secret}"),
                "base_url": untouched_poisoned_adv.base(),
                "stream": true
            }
        }
    });
    fs::write(&cfg_path, serde_json::to_vec(&cfg).unwrap()).unwrap();

    // 1) Poisoned saved advisor (`model` contains `env_secret`) must be rejected BEFORE any HTTP call!
    let rejected = run_rcode(
        &project,
        &state,
        &["--json", "exec", "Попробуй запуск с отравленным advisor"],
        &[("OPENROUTER_API_KEY", env_secret)],
    );
    assert!(!rejected.status.success());
    assert_eq!(
        untouched_poisoned_adv.generations().len(),
        0,
        "poisoned advisor route must make 0 HTTP requests"
    );
    assert!(
        !String::from_utf8_lossy(&rejected.stdout).contains(env_secret),
        "{}",
        String::from_utf8_lossy(&rejected.stdout)
    );

    // 2) Override `--advisor openrouter:clean-advisor-model` while `providers.openrouter.model` still holds
    // `env_secret`: `available_routes` must omit the poisoned openrouter default route, `clean_adv` must
    // receive `clean-advisor-model` (zero `env_secret` in request body), and its reflected `env_secret`
    // must be redacted in stdout and `session.json`!
    let primary2 = Server::start(|_req, idx| match idx {
        0 => tool_reply("adv_meta2", "advisor", &json!({"focus": "metadata check"})),
        _ => text_reply("Готово."),
    });
    let tmp2 = tempfile::tempdir().unwrap();
    let project2 = tmp2.path().join("project");
    let state2 = tmp2.path().join("state");
    write_state(&project2, &state2, &primary2.base(), &clean_adv.base());
    let creds_path2 = state2.join("credentials.json");
    let mut creds2: Value = serde_json::from_slice(&fs::read(&creds_path2).unwrap()).unwrap();
    creds2["providers"]
        .as_object_mut()
        .unwrap()
        .remove("openrouter");
    fs::write(&creds_path2, serde_json::to_vec(&creds2).unwrap()).unwrap();
    let cfg_path2 = state2.join("config.json");
    let mut cfg2: Value = serde_json::from_slice(&fs::read(&cfg_path2).unwrap()).unwrap();
    cfg2["providers"]["openrouter"]["model"] = json!(format!("vendor/{env_secret}"));
    fs::write(&cfg_path2, serde_json::to_vec(&cfg2).unwrap()).unwrap();

    let out = run_rcode(
        &project2,
        &state2,
        &[
            "--json",
            "--advisor",
            "openrouter:clean-advisor-model",
            "exec",
            "Проверь фильтрацию env-секрета",
        ],
        &[("OPENROUTER_API_KEY", env_secret)],
    );
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains(env_secret),
        "env secret leaked to stdout: {stdout}"
    );
    assert_eq!(clean_adv.generations().len(), 1);
    for req in primary2.generations() {
        let body = String::from_utf8_lossy(&req.body);
        assert!(
            !body.contains(env_secret),
            "env secret leaked into primary model request body:\n{body}",
        );
    }
    for req in clean_adv.generations() {
        let body = String::from_utf8_lossy(&req.body);
        assert!(
            !body.contains(env_secret),
            "env secret leaked into advisor request body:\n{body}",
        );
    }
    for entry in fs::read_dir(state2.join("sessions")).unwrap() {
        let sfile = entry.unwrap().path().join("session.json");
        if sfile.is_file() {
            let text = fs::read_to_string(&sfile).unwrap();
            assert!(
                !text.contains(env_secret),
                "env secret leaked into session.json:\n{text}"
            );
            assert!(text.contains("[REDACTED]"), "{text}");
        }
    }
}

#[test]
fn same_local_server_advisor_works_in_exec_and_truncated_advisor_preserves_usage() {
    let adv_attempt = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let adv_attempt_srv = adv_attempt.clone();
    let local_srv = Server::start(move |req, _| {
        let body: Value = serde_json::from_slice(&req.body).unwrap_or_default();
        if body["model"] == "Advisor-Local-Model" {
            let n = adv_attempt_srv.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n == 0 {
                // 1st advisor call on the SAME local server returns finish_reason: "length" WITH usage!
                return Response::json(
                    200,
                    json!({
                        "choices": [{
                            "index": 0,
                            "message": {"role": "assistant", "content": "Частичный совет"},
                            "finish_reason": "length"
                        }],
                        "usage": {"prompt_tokens": 111, "completion_tokens": 222}
                    }),
                );
            }
            return Response::json(
                200,
                json!({
                    "choices": [{
                        "index": 0,
                        "message": {"role": "assistant", "content": "Краткий завершённый совет"},
                        "finish_reason": "stop"
                    }],
                    "usage": {"prompt_tokens": 50, "completion_tokens": 20}
                }),
            );
        }
        let tool_count = body["messages"].as_array().map_or(0, |msgs| {
            msgs.iter().filter(|m| m["role"] == "tool").count()
        });
        if tool_count == 0 {
            Response::json(
                200,
                json!({
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "",
                            "tool_calls": [{
                                "id": "call_local_adv_1",
                                "type": "function",
                                "function": {"name": "advisor", "arguments": "{}"}
                            }]
                        },
                        "finish_reason": "tool_calls"
                    }],
                    "usage": {"prompt_tokens": 40, "completion_tokens": 10}
                }),
            )
        } else if tool_count == 1 {
            Response::json(
                200,
                json!({
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "",
                            "tool_calls": [{
                                "id": "call_local_adv_2",
                                "type": "function",
                                "function": {"name": "advisor", "arguments": "{\"focus\":\"короче\"}"}
                            }]
                        },
                        "finish_reason": "tool_calls"
                    }],
                    "usage": {"prompt_tokens": 55, "completion_tokens": 12}
                }),
            )
        } else {
            Response::json(
                200,
                json!({
                    "choices": [{
                        "index": 0,
                        "message": {"role": "assistant", "content": "Готово с учётом локального совета."},
                        "finish_reason": "stop"
                    }],
                    "usage": {"prompt_tokens": 60, "completion_tokens": 15}
                }),
            )
        }
    });

    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("project");
    let state = tmp.path().join("state");
    write_state(&project, &state, &local_srv.base(), &local_srv.base());

    // Switch active provider to `local` (`mlx` pointing to `local_srv`) and save advisor as
    // `local:mlx:Advisor-Local-Model` (same local server, different model name).
    let cfg_path = state.join("config.json");
    let mut cfg: Value = serde_json::from_slice(&fs::read(&cfg_path).unwrap()).unwrap();
    cfg["active"] = json!("local");
    cfg["local"]["profiles"]["mlx"]["base_url"] = json!(local_srv.base());
    fs::write(&cfg_path, serde_json::to_vec(&cfg).unwrap()).unwrap();

    let set_local_adv = run_rcode(
        &project,
        &state,
        &["advisor", "set", "local:mlx:Advisor-Local-Model"],
        &[],
    );
    assert!(set_local_adv.status.success(), "{set_local_adv:?}");

    // `rcode exec` WITHOUT `--advisor` must allow consulting the saved advisor on the same local server!
    let exec_out = run_rcode(
        &project,
        &state,
        &["exec", "Проверь локального советника на том же сервере"],
        &[],
    );
    assert_eq!(
        exec_out.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&exec_out.stdout),
        String::from_utf8_lossy(&exec_out.stderr)
    );
    assert_eq!(
        local_srv.generations().len(),
        5,
        "3 main local calls + 2 local advisor calls on the same server"
    );

    // Verify truncated `finish_reason: "length"` preserved reported usage (`111` / `222`) once,
    // and combined with the 2nd successful call (`50` / `20`) in `auxiliary_usage`!
    let mut found_session = false;
    for entry in fs::read_dir(state.join("sessions")).unwrap() {
        let sfile = entry.unwrap().path().join("session.json");
        if sfile.is_file() {
            found_session = true;
            let sess: Value = serde_json::from_slice(&fs::read(&sfile).unwrap()).unwrap();
            assert_eq!(sess["advisor_calls"][0]["status"], "failed");
            assert_eq!(sess["advisor_calls"][0]["usage"]["input_tokens"], 111);
            assert_eq!(sess["advisor_calls"][0]["usage"]["output_tokens"], 222);
            assert_eq!(sess["advisor_calls"][1]["status"], "completed");
            assert_eq!(sess["advisor_calls"][1]["usage"]["input_tokens"], 50);
            assert_eq!(sess["advisor_calls"][1]["usage"]["output_tokens"], 20);
            assert_eq!(sess["auxiliary_usage"][0]["source"], "advisor");
            assert_eq!(sess["auxiliary_usage"][0]["calls"], 2);
            assert_eq!(sess["auxiliary_usage"][0]["usage"]["input_tokens"], 161);
            assert_eq!(sess["auxiliary_usage"][0]["usage"]["output_tokens"], 242);
        }
    }
    assert!(found_session);
}

fn write_private(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[test]
fn openai_env_does_not_publish_default_custom_and_resume_flag_checks_base_url() {
    let srv_a = Server::start(|_, _| text_reply("OK_A"));
    let srv_b = Server::start(|_, _| text_reply("OK_B"));

    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("project");
    let state = tmp.path().join("state");
    fs::create_dir_all(&project).unwrap();
    fs::create_dir_all(&state).unwrap();

    // 1) Default settings (`active = openrouter`, untouched `custom = http://localhost:11434/v1` / `"local"`)
    // with `OPENAI_API_KEY` in env must NOT match substring `"loc"` onto unconfigured `custom`!
    let mut default_cfg = json!({
        "version": 1,
        "active": "openrouter",
        "providers": {
            "openrouter": {"kind": "openrouter", "model": "vendor/main", "base_url": srv_a.base()},
            "custom": {"kind": "custom", "model": "local", "base_url": "http://localhost:11434/v1"}
        }
    });
    write_private(&state.join("config.json"), &default_cfg.to_string());
    write_private(
        &state.join("credentials.json"),
        &json!({"version": 1, "providers": {"openrouter": "or-secret-key-11112222"}}).to_string(),
    );
    let unconfigured_probe = run_rcode(
        &project,
        &state,
        &["advisor", "set", "loc"],
        &[("OPENAI_API_KEY", "sk-env-openai-secret-9999")],
    );
    assert!(
        !unconfigured_probe.status.success(),
        "OPENAI_API_KEY must not turn untouched default custom into a usable route: {unconfigured_probe:?}"
    );

    // 2) Create a `custom` session on `srv_a` with key A in `credentials.json`, then rotate `custom`
    // on disk to `srv_b` + key B; `--resume latest --folder-id temp` must still block sending key B to `srv_a`!
    default_cfg["active"] = json!("custom");
    default_cfg["providers"]["custom"] =
        json!({"kind": "custom", "model": "m-a", "base_url": srv_a.base()});
    write_private(&state.join("config.json"), &default_cfg.to_string());
    write_private(
        &state.join("credentials.json"),
        &json!({"version": 1, "providers": {"custom": "custom-key-for-a-1111"}}).to_string(),
    );
    let first_turn = run_rcode(&project, &state, &["exec", "первый ход"], &[]);
    assert_eq!(first_turn.status.code(), Some(0), "{first_turn:?}");
    assert_eq!(srv_a.generations().len(), 1);

    default_cfg["providers"]["custom"] =
        json!({"kind": "custom", "model": "m-b", "base_url": srv_b.base()});
    write_private(&state.join("config.json"), &default_cfg.to_string());
    write_private(
        &state.join("credentials.json"),
        &json!({"version": 1, "providers": {"custom": "custom-key-for-b-2222"}}).to_string(),
    );

    let blocked_resume = run_rcode(
        &project,
        &state,
        &[
            "--resume",
            "latest",
            "--folder-id",
            "override-folder",
            "exec",
            "второй ход",
        ],
        &[],
    );
    assert!(
        !blocked_resume.status.success(),
        "--folder-id must not bypass base_url verification on --resume"
    );
    assert_eq!(
        srv_a.generations().len(),
        1,
        "rotated key B must never reach saved endpoint srv_a"
    );
    assert!(srv_b.generations().is_empty());
}
