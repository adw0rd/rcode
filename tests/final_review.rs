//! Optional, host-owned final review routing over local provider fixtures.
mod support;

use rcode::config::{ProviderKind, ProviderSettings};
use rcode::local::{LocalRuntime, profile_settings};
use serde_json::{Value, json};
use sha2::Digest;
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};
use support::{Response, Server, text_reply, tool_reply};

const PRIMARY_KEY: &str = "final-review-primary-synthetic-key";
const REVIEW_KEY: &str = "final-review-selected-synthetic-key";
const USER_TASK: &str = "Review this bounded task.";
const PRIMARY_DRAFT: &str = "Primary draft: one bounded recommendation.";
const REVIEW_RESULT: &str = "Review result: one bounded correction.";

fn fixture_state(project: &Path, state: &Path, primary: &Server, reviewer: &Server) {
    fs::create_dir_all(project).unwrap();
    fs::create_dir_all(state).unwrap();
    let config = json!({
        "version": 1,
        "active": "custom",
        "providers": {
            "custom": {
                "kind": "custom",
                "model": "primary-model",
                "base_url": primary.base(),
                "stream": true
            },
            "openrouter": {
                "kind": "openrouter",
                "model": "configured-review-model",
                "base_url": reviewer.base(),
                "stream": true
            }
        },
        "final_review": {
            "selected": {
                "snapshot": {
                    "kind": "openrouter",
                    "model": "selected-review-model",
                    "base_url": reviewer.base(),
                    "stream": true
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
                "openrouter": REVIEW_KEY
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

fn run_prompt(project: &Path, state: &Path, final_review: bool, prompt: &str) -> Output {
    run_prompt_with(project, state, final_review, &[], prompt)
}

fn run_prompt_with(
    project: &Path,
    state: &Path,
    final_review: bool,
    extra: &[&str],
    prompt: &str,
) -> Output {
    run_provider(
        project,
        state,
        final_review,
        extra,
        "custom",
        "primary-model",
        prompt,
    )
}

fn run_provider(
    project: &Path,
    state: &Path,
    final_review: bool,
    extra: &[&str],
    provider: &str,
    model: &str,
    prompt: &str,
) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rcode"));
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("RCODE_HOME", state)
        .arg("-C")
        .arg(project)
        .args(["--provider", provider, "--model", model, "--json"]);
    if final_review {
        command.arg("--final-review");
    }
    command.args(extra);
    command.args(["exec", prompt]).output().unwrap()
}

fn run_plain_final_review(project: &Path, state: &Path, prompt: &str) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rcode"));
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("RCODE_HOME", state)
        .args(["-C"])
        .arg(project)
        .args([
            "--provider",
            "custom",
            "--model",
            "primary-model",
            "--plain",
            "--final-review",
            "exec",
            prompt,
        ])
        .output()
        .unwrap()
}

fn run(project: &Path, state: &Path, final_review: bool) -> Output {
    run_prompt(project, state, final_review, USER_TASK)
}

fn run_settings_command(state: &Path, args: &[&str], model_shell: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rcode"));
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("RCODE_HOME", state)
        .args(args);
    if model_shell {
        command.env("RCODE_MODEL_SHELL", "1");
    }
    command.output().unwrap()
}

fn events(output: &Output) -> Vec<Value> {
    output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect()
}

fn saved(state: &Path) -> Value {
    let dir = fs::read_dir(state.join("sessions"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    serde_json::from_slice(&fs::read(dir.join("session.json")).unwrap()).unwrap()
}

fn local_review_profile(base: &str, model: &str) -> ProviderSettings {
    let mut profile = profile_settings("reviewer", base, LocalRuntime::OpenAi, model);
    profile.local.as_mut().unwrap().key_required = true;
    profile
}

fn set_local_review(state: &Path, profile: &ProviderSettings, snapshot: &ProviderSettings) {
    let path = state.join("config.json");
    let mut config: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    config["local"] = json!({"profiles":{"reviewer":profile}});
    config["final_review"] = json!({"selected":{"snapshot":snapshot}});
    fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let creds_path = state.join("credentials.json");
    let mut credentials: Value = serde_json::from_slice(&fs::read(&creds_path).unwrap()).unwrap();
    credentials["providers"]["local:reviewer"] = json!("selected-local-review-key");
    fs::write(&creds_path, serde_json::to_vec(&credentials).unwrap()).unwrap();
}

#[test]
fn final_review_default_off_makes_no_extra_request() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    let primary = Server::start(|_, _| text_reply(PRIMARY_DRAFT));
    let reviewer = Server::start(|_, _| text_reply(REVIEW_RESULT));
    fixture_state(&project, &state, &primary, &reviewer);

    let output = run(&project, &state, false);
    assert!(
        output.status.success(),
        "default-off task failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(primary.generations().len(), 1);
    assert!(
        reviewer.requests().is_empty(),
        "default-off route made any request"
    );
    let saved = saved(&state);
    assert_eq!(saved["provider"]["kind"], "custom");
    assert_eq!(saved["usage"]["input_tokens"], 120);
    assert_eq!(saved["usage"]["output_tokens"], 5);
    assert!(
        saved["final_reviews"].as_array().is_none_or(Vec::is_empty),
        "disabled review must not create a result record"
    );
    assert!(
        !events(&output)
            .iter()
            .any(|event| event["type"] == "review_result")
    );
    assert!(
        !events(&output)
            .iter()
            .any(|event| event["type"] == "review_usage")
    );
}

#[test]
fn final_review_runs_selected_stage_without_model_spawn() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    let primary = Server::start(|_, _| text_reply(PRIMARY_DRAFT));
    let reviewer = Server::start(|request, _| {
        let body = request.json();
        assert_eq!(body["model"], "selected-review-model");
        assert_eq!(
            body["max_tokens"], 4096,
            "the selected model's configured output limit is preserved"
        );
        assert!(body["tools"].as_array().is_none_or(Vec::is_empty));
        text_reply(REVIEW_RESULT)
    });
    fixture_state(&project, &state, &primary, &reviewer);

    let output = run(&project, &state, true);
    assert!(
        output.status.success(),
        "explicit final review failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        primary.generations().len(),
        1,
        "no parent generation after review"
    );
    assert_eq!(
        reviewer.generations().len(),
        1,
        "one selected review generation"
    );
    let review_request = reviewer.generations().remove(0);
    assert_eq!(
        review_request.authorization(),
        Some("Bearer final-review-selected-synthetic-key")
    );
    let body = review_request.json();
    assert!(body["tools"].as_array().is_none_or(Vec::is_empty));
    let messages = body["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 2, "fixed system plus one bounded packet");
    let packet: Value = serde_json::from_str(messages[1]["content"].as_str().unwrap()).unwrap();
    assert_eq!(packet["task"], USER_TASK);
    assert_eq!(packet["untrusted_draft"], PRIMARY_DRAFT);

    let events = events(&output);
    let started = events
        .iter()
        .position(|event| event["type"] == "review_started")
        .unwrap();
    let complete = events
        .iter()
        .position(|event| event["type"] == "review_result")
        .unwrap();
    assert!(
        started < complete,
        "review_started must precede the result: {events:?}"
    );
    assert_eq!(events[started]["status"], "pending");
    assert_eq!(events[started]["provider"], "openrouter");
    assert_eq!(events[started]["model"], "selected-review-model");
    assert_eq!(
        events[started]["packet_sha256"],
        session_packet_hash(&review_request)
    );
    assert_eq!(
        events[complete]["packet_sha256"],
        events[started]["packet_sha256"]
    );
    assert_eq!(events[complete]["result"], REVIEW_RESULT);
    assert_eq!(events[complete]["turn_index"], 1);
    let session = saved(&state);
    assert_eq!(session["provider"]["kind"], "custom");
    assert_eq!(
        session["usage"]["input_tokens"], 120,
        "review usage is not folded into primary usage"
    );
    assert_eq!(session["usage"]["output_tokens"], 5);
    assert!(session["agents"].as_array().is_none_or(Vec::is_empty));
    assert!(
        session["final_reviews"]
            .as_array()
            .is_some_and(|records| !records.is_empty()),
        "final review record must stay separate from the primary provider session"
    );
    let review = session["final_reviews"].as_array().unwrap().last().unwrap();
    assert_eq!(review["usage"]["input_tokens"], 120);
    assert_eq!(review["usage"]["output_tokens"], 5);
    assert_eq!(review["provider"], "openrouter");
    assert_eq!(review["model"], "selected-review-model");
    assert_eq!(review["turn_index"], 1);
    assert!(review["draft_sha256"].as_str().is_some());
    assert!(review["route_fingerprint"].as_str().is_some());
    assert_eq!(review["local_profile"], Value::Null);
    assert_eq!(events[started]["draft_sha256"], review["draft_sha256"]);
    assert_eq!(
        events[started]["route_fingerprint"],
        review["route_fingerprint"]
    );
    assert_eq!(events[complete]["draft_sha256"], review["draft_sha256"]);
    assert_eq!(
        events[complete]["route_fingerprint"],
        review["route_fingerprint"]
    );
}

#[test]
fn missing_or_null_review_usage_is_not_saved_or_reported_as_zero() {
    for usage_shape in ["missing", "null", "partial"] {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("project");
        let state = temp.path().join("state");
        let primary = Server::start(|_, _| text_reply(PRIMARY_DRAFT));
        let usage_shape = usage_shape.to_owned();
        let reviewer = Server::start(move |_, _| {
            let mut value = json!({
                "choices":[{"message":{"role":"assistant","content":REVIEW_RESULT},"finish_reason":"stop"}]
            });
            match usage_shape.as_str() {
                "null" => value["usage"] = Value::Null,
                "partial" => value["usage"] = json!({"prompt_tokens":17}),
                _ => {}
            }
            Response::json(200, value)
        });
        fixture_state(&project, &state, &primary, &reviewer);

        let output = run(&project, &state, true);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let session = saved(&state);
        let record = session["final_reviews"].as_array().unwrap().last().unwrap();
        assert!(
            record.get("usage").is_none(),
            "missing/null API usage became a fabricated value: {record}"
        );
        let events = events(&output);
        assert!(!events.iter().any(|event| event["type"] == "review_usage"));
        assert!(
            events
                .iter()
                .any(|event| event["type"] == "review_result" && event["usage"].is_null())
        );
    }
}

#[test]
fn explicit_zero_review_usage_is_reported_from_streamed_usage_event() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    let primary = Server::start(|_, _| text_reply(PRIMARY_DRAFT));
    let reviewer = Server::start(|_, _| {
        Response::sse(&[
            json!({"choices":[{"index":0,"delta":{"role":"assistant","content":REVIEW_RESULT}}]}),
            json!({"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":0,"completion_tokens":0}}),
            json!({"choices":[],"usage":null}),
        ])
    });
    fixture_state(&project, &state, &primary, &reviewer);

    let output = run(&project, &state, true);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let record = saved(&state)["final_reviews"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    assert_eq!(record["usage"]["input_tokens"], 0);
    assert_eq!(record["usage"]["output_tokens"], 0);
    assert!(
        events(&output)
            .iter()
            .any(|event| event["type"] == "review_usage")
    );
    assert_eq!(
        events(&output)
            .iter()
            .find(|event| event["type"] == "review_result")
            .unwrap()["usage"]["input_tokens"],
        0
    );
}

#[test]
fn plain_output_labels_missing_review_usage_unknown() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    let primary = Server::start(|_, _| text_reply(PRIMARY_DRAFT));
    let reviewer = Server::start(|_, _| {
        Response::json(
            200,
            json!({
                "choices":[{"message":{"role":"assistant","content":REVIEW_RESULT},"finish_reason":"stop"}]
            }),
        )
    });
    fixture_state(&project, &state, &primary, &reviewer);

    let output = run_plain_final_review(&project, &state, USER_TASK);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let human = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(human.contains("расход токенов неизвестен"), "{human}");
    assert!(
        !human.contains("Отдельное ревью · openrouter / selected-review-model · ↑0 ↓0"),
        "{human}"
    );
}

fn session_packet_hash(request: &support::Request) -> String {
    let body = request.json();
    let packet = body["messages"][1]["content"].as_str().unwrap();
    format!("{:x}", sha2::Sha256::digest(packet.as_bytes()))
}

#[test]
fn plain_output_shows_selected_final_review_separately() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    let primary = Server::start(|_, _| text_reply(PRIMARY_DRAFT));
    let reviewer = Server::start(|_, _| text_reply(REVIEW_RESULT));
    fixture_state(&project, &state, &primary, &reviewer);

    let output = run_plain_final_review(&project, &state, USER_TASK);
    assert!(
        output.status.success(),
        "plain review failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let human = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        human.contains("Ответ финального ревью · openrouter / selected-review-model"),
        "{human}"
    );
    assert!(human.contains(REVIEW_RESULT), "{human}");
    assert!(
        human.contains("Отдельное ревью · openrouter / selected-review-model · ↑120 ↓5 токенов"),
        "{human}"
    );
    assert_eq!(primary.generations().len(), 1);
    assert_eq!(reviewer.generations().len(), 1);
}

#[test]
fn review_model_cli_sets_route_without_network_and_blocks_model_shell_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    let primary = Server::start(|_, _| text_reply(PRIMARY_DRAFT));
    let reviewer = Server::start(|_, _| text_reply(REVIEW_RESULT));
    fixture_state(&project, &state, &primary, &reviewer);

    let configured = run_settings_command(
        &state,
        &[
            "--json",
            "review-model",
            "set",
            "--provider",
            "openrouter",
            "--model",
            "review/name:custom",
        ],
        false,
    );
    assert!(
        configured.status.success(),
        "{}",
        String::from_utf8_lossy(&configured.stderr)
    );
    let config_path = state.join("config.json");
    let config: Value = serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
    assert_eq!(config["active"], "custom");
    assert_eq!(
        config["providers"]["openrouter"]["model"],
        "configured-review-model"
    );
    assert_eq!(
        config["final_review"]["selected"]["snapshot"]["model"],
        "review/name:custom"
    );
    assert!(primary.requests().is_empty());
    assert!(reviewer.requests().is_empty());

    let status = run_settings_command(
        &state,
        &["--final-review", "--json", "review-model", "status"],
        false,
    );
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    let status_value: Value = serde_json::from_slice(
        status
            .stdout
            .split(|byte| *byte == b'\n')
            .find(|line| !line.is_empty())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(status_value["data"]["enabled"], true);
    assert_eq!(status_value["data"]["provider"], "openrouter");

    let denied = run_settings_command(&state, &["--json", "review-model", "same"], true);
    assert_ne!(denied.status.code(), Some(0));
    let after_denial: Value = serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
    assert_eq!(
        after_denial["final_review"]["selected"]["snapshot"]["model"],
        "review/name:custom"
    );
    let reset = run_settings_command(&state, &["--json", "review-model", "same"], false);
    assert!(
        reset.status.success(),
        "{}",
        String::from_utf8_lossy(&reset.stderr)
    );
    let reset_config: Value = serde_json::from_slice(&fs::read(config_path).unwrap()).unwrap();
    assert!(reset_config.get("final_review").is_none());
    assert!(primary.requests().is_empty());
    assert!(reviewer.requests().is_empty());
}

#[test]
fn changed_selected_route_during_primary_request_is_not_used() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    let new_reviewer = Server::start(|_, _| text_reply("Wrong target"));
    let config_path = state.join("config.json");
    let replacement_url = new_reviewer.base();
    let primary = Server::start(move |_, _| {
        let mut config: Value = serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
        config["providers"]["openrouter"]["base_url"] = json!(replacement_url);
        fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
        text_reply(PRIMARY_DRAFT)
    });
    let old_reviewer = Server::start(|_, _| text_reply("Old target"));
    fixture_state(&project, &state, &primary, &old_reviewer);

    let output = run(&project, &state, true);
    assert_ne!(
        output.status.code(),
        Some(0),
        "stale target must make the enabled review fail visibly"
    );
    assert!(old_reviewer.requests().is_empty());
    assert!(
        new_reviewer.requests().is_empty(),
        "new route must not receive review data"
    );
    let events = events(&output);
    assert!(!events.iter().any(|event| event["type"] == "review_result"));
    let failure = events
        .iter()
        .find(|event| event["type"] == "review_failed")
        .unwrap();
    assert_eq!(failure["status"], "stale_route");
    assert_eq!(failure["provider"], "openrouter");
    assert_eq!(failure["model"], "selected-review-model");
    assert_eq!(failure["turn_index"], 1);
    assert!(failure["draft_sha256"].as_str().is_some());
    assert!(failure["route_fingerprint"].as_str().is_some());
}

#[test]
fn selected_local_review_uses_only_its_endpoint_bound_credential() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    let primary = Server::start(|_, _| text_reply(PRIMARY_DRAFT));
    let reviewer = Server::start(|_, _| text_reply(REVIEW_RESULT));
    fixture_state(&project, &state, &primary, &reviewer);
    let profile = local_review_profile(&reviewer.base(), "selected-local-model");
    set_local_review(&state, &profile, &profile);

    let output = run(&project, &state, true);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(primary.generations().len(), 1);
    assert_eq!(
        primary.generations()[0].authorization(),
        Some("Bearer final-review-primary-synthetic-key")
    );
    assert_eq!(reviewer.generations().len(), 1);
    assert_eq!(
        reviewer.generations()[0].authorization(),
        Some("Bearer selected-local-review-key")
    );
}

#[test]
fn selected_local_review_rejects_snapshot_moved_from_profile_endpoint() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    let primary = Server::start(|_, _| text_reply(PRIMARY_DRAFT));
    let configured_endpoint = Server::start(|_, _| text_reply("wrong configured endpoint"));
    let moved_endpoint = Server::start(|_, _| text_reply("wrong moved endpoint"));
    fixture_state(&project, &state, &primary, &configured_endpoint);
    let profile = local_review_profile(&configured_endpoint.base(), "selected-local-model");
    let moved = local_review_profile(&moved_endpoint.base(), "selected-local-model");
    set_local_review(&state, &profile, &moved);

    let output = run(&project, &state, true);
    assert_ne!(output.status.code(), Some(0));
    assert!(
        primary.requests().is_empty(),
        "stale profile must be rejected before the task turn"
    );
    assert!(configured_endpoint.requests().is_empty());
    assert!(
        moved_endpoint.requests().is_empty(),
        "local key and task packet must not go to a moved endpoint"
    );
}

#[test]
fn refusal_is_a_failed_review_without_fallback_or_success_event() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    let primary = Server::start(|_, _| text_reply(PRIMARY_DRAFT));
    let reviewer = Server::start(|_, _| {
        Response::sse(&[
            json!({"choices":[{"index":0,"delta":{"role":"assistant","refusal":"Refused"}}]}),
            json!({"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1}}),
        ])
    });
    fixture_state(&project, &state, &primary, &reviewer);

    let output = run(&project, &state, true);
    assert_ne!(
        output.status.code(),
        Some(0),
        "refusal is not a completed review"
    );
    assert_eq!(reviewer.generations().len(), 1);
    assert_eq!(
        primary.generations().len(),
        1,
        "no fallback or parent generation"
    );
    assert!(
        !events(&output)
            .iter()
            .any(|event| event["type"] == "review_result")
    );
    assert!(
        events(&output)
            .iter()
            .any(|event| event["type"] == "review_failed")
    );
    let review = saved(&state)["final_reviews"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    assert_eq!(review["status"], "refused");
    assert_eq!(review["refusal"], true);
    assert!(review.get("result").is_none(), "refusal text is not stored");
}

#[test]
fn reviewer_tool_call_is_never_dispatched_and_fails_the_stage() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    let primary = Server::start(|_, _| text_reply(PRIMARY_DRAFT));
    let reviewer = Server::start(|_, _| {
        tool_reply(
            "review-call",
            "run_command",
            &json!({"command":"touch forbidden"}),
        )
    });
    fixture_state(&project, &state, &primary, &reviewer);

    let output = run(&project, &state, true);
    assert_ne!(
        output.status.code(),
        Some(0),
        "a tool call is not a valid review result"
    );
    assert_eq!(reviewer.generations().len(), 1);
    assert_eq!(
        primary.generations().len(),
        1,
        "reviewer tool calls never dispatch or trigger fallback"
    );
    assert!(!project.join("forbidden").exists());
    assert!(
        !events(&output)
            .iter()
            .any(|event| event["type"] == "review_result")
    );
}

#[test]
fn oversized_packet_fails_without_sending_a_review_request() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    let primary = Server::start(|_, _| text_reply(PRIMARY_DRAFT));
    let reviewer = Server::start(|_, _| text_reply(REVIEW_RESULT));
    fixture_state(&project, &state, &primary, &reviewer);

    let output = run_prompt(&project, &state, true, &"x".repeat(66 * 1024));
    assert_ne!(
        output.status.code(),
        Some(0),
        "oversized review packet is a blocked stage"
    );
    assert_eq!(primary.generations().len(), 1);
    assert!(
        reviewer.requests().is_empty(),
        "oversized packets are rejected before the API"
    );
    assert!(
        events(&output)
            .iter()
            .any(|event| event["type"] == "review_failed")
    );
}

#[test]
fn empty_and_length_limited_review_responses_fail_without_success() {
    for name in ["empty", "length"] {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("project");
        let state = temp.path().join("state");
        let primary = Server::start(|_, _| text_reply(PRIMARY_DRAFT));
        let reviewer = Server::start(move |_, _| match name {
            "empty" => text_reply(""),
            _ => Response::json(
                200,
                json!({"choices":[{"message":{"role":"assistant","content":"cut off"},"finish_reason":"length"}]}),
            ),
        });
        fixture_state(&project, &state, &primary, &reviewer);

        let output = run(&project, &state, true);
        assert_ne!(
            output.status.code(),
            Some(0),
            "{name} response is not a completed review"
        );
        assert_eq!(reviewer.generations().len(), 1);
        assert_eq!(primary.generations().len(), 1);
        assert!(
            !events(&output)
                .iter()
                .any(|event| event["type"] == "review_result")
        );
        assert!(
            events(&output)
                .iter()
                .any(|event| event["type"] == "review_failed")
        );
    }
}

#[test]
fn primary_and_review_credentials_are_redacted_before_packet_and_session_save() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    let primary = Server::start(|_, _| text_reply(&format!("draft echoes {PRIMARY_KEY}")));
    let reviewer = Server::start(|_, _| text_reply(&format!("review echoes {REVIEW_KEY}")));
    fixture_state(&project, &state, &primary, &reviewer);

    let output = run(&project, &state, true);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let requests = reviewer.generations();
    assert_eq!(requests.len(), 1);
    let body = requests[0].json();
    assert!(!body.to_string().contains(PRIMARY_KEY));
    assert!(!body.to_string().contains(REVIEW_KEY));
    let session = saved(&state);
    assert!(!session.to_string().contains(PRIMARY_KEY));
    assert!(!session.to_string().contains(REVIEW_KEY));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(PRIMARY_KEY));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(REVIEW_KEY));
}

#[test]
fn cancellation_during_reviewer_wait_saves_cancelled_without_late_result() {
    use std::time::{Duration, Instant};

    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    let primary = Server::start(|_, _| text_reply(PRIMARY_DRAFT));
    let reviewer = Server::start(|_, _| {
        std::thread::sleep(Duration::from_millis(700));
        text_reply(REVIEW_RESULT)
    });
    fixture_state(&project, &state, &primary, &reviewer);

    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_rcode"));
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("RCODE_HOME", &state)
        .arg("-C")
        .arg(&project)
        .args([
            "--provider",
            "custom",
            "--model",
            "primary-model",
            "--json",
            "--final-review",
            "exec",
            USER_TASK,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let child = command.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while reviewer.generations().is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    let generations = reviewer.generations();
    if generations.len() != 1 {
        unsafe { libc::kill(child.id() as i32, libc::SIGKILL) };
        let output = child.wait_with_output().unwrap();
        panic!(
            "review request must be active before cancellation; recorded requests={:?}; child status={}; stdout={}; stderr={}",
            reviewer.requests(),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(130));
    let values: Vec<Value> = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    assert!(!values.iter().any(|event| event["type"] == "review_result"));
    assert!(
        values
            .iter()
            .any(|event| event["type"] == "review_failed" && event["status"] == "cancelled")
    );
    let review = saved(&state)["final_reviews"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    assert_eq!(review["status"], "cancelled");
}

#[test]
fn packet_uses_real_file_and_command_receipts_with_typed_status_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    fs::create_dir_all(&project).unwrap();
    fs::write(project.join("source.txt"), "observed fixture line\n").unwrap();
    let primary = Server::start(|_, index| match index {
        0 => tool_reply("read-call", "read_file", &json!({"path":"source.txt"})),
        1 => tool_reply(
            "command-call",
            "run_command",
            &json!({"command":"printf fixture-output"}),
        ),
        _ => text_reply(PRIMARY_DRAFT),
    });
    let reviewer = Server::start(|_, _| text_reply(REVIEW_RESULT));
    fixture_state(&project, &state, &primary, &reviewer);

    let output = run_prompt_with(
        &project,
        &state,
        true,
        &["--approval-mode", "full-access"],
        USER_TASK,
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let requests = primary.generations();
    assert_eq!(requests.len(), 3);
    let reviewer_body = reviewer.generations().remove(0).json();
    let packet: Value =
        serde_json::from_str(reviewer_body["messages"][1]["content"].as_str().unwrap()).unwrap();
    let evidence = packet["observed_evidence"].as_array().unwrap();
    let read = evidence
        .iter()
        .find(|row| row["tool"] == "read_file")
        .unwrap();
    assert_eq!(read["path"], "source.txt");
    assert!(read["details"]["sha256"].as_str().is_some());
    assert_eq!(read["details"]["content"], "1\tobserved fixture line\n");
    let command = evidence
        .iter()
        .find(|row| row["tool"] == "run_command")
        .unwrap();
    assert_eq!(command["details"]["command"], "printf fixture-output");
    assert_eq!(command["details"]["exit_code"], 0);
    assert_eq!(command["details"]["stdout"], "fixture-output");
    assert_eq!(command["details"]["output_truncated"], false);
    assert_eq!(
        command["details"]["stdout_lossy"],
        Value::Null,
        "the managed shell reports only combined decoding loss, so per-stream status stays unknown"
    );
    assert_eq!(command["details"]["utf8_lossy"], false);
    assert_eq!(command["details"]["redaction_incomplete"], false);
    assert!(
        !evidence
            .iter()
            .any(|row| matches!(row["tool"].as_str(), Some("spawn_agent" | "wait_agent")))
    );
}

#[test]
fn evidence_collector_overflow_blocks_stage_without_calling_reviewer() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    fs::create_dir_all(&project).unwrap();
    for index in 0..65 {
        fs::write(
            project.join(format!("source-{index}.txt")),
            format!("observed file {index}\n"),
        )
        .unwrap();
    }
    let primary = Server::start(|_, index| {
        if index != 0 {
            return text_reply(PRIMARY_DRAFT);
        }
        let tool_calls = (0..65)
            .map(|index| json!({
                "id":format!("evidence-{index}"),
                "type":"function",
                "function":{"name":"read_file","arguments":json!({"path":format!("source-{index}.txt")}).to_string()}
            }))
            .collect::<Vec<_>>();
        Response::json(
            200,
            json!({
                "choices":[{"message":{"role":"assistant","tool_calls":tool_calls},"finish_reason":"tool_calls"}]
            }),
        )
    });
    let reviewer = Server::start(|_, _| text_reply(REVIEW_RESULT));
    fixture_state(&project, &state, &primary, &reviewer);

    let output = run(&project, &state, true);
    assert_ne!(output.status.code(), Some(0));
    assert_eq!(
        primary.generations().len(),
        2,
        "primary should return the tool batch and then its final draft"
    );
    assert!(
        reviewer.requests().is_empty(),
        "incomplete evidence must not be reviewed as complete"
    );
    let session = saved(&state);
    let record = session["final_reviews"]
        .as_array()
        .and_then(|rows| rows.last())
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "missing review record; stderr={} stdout={} session={session}",
                String::from_utf8_lossy(&output.stderr),
                String::from_utf8_lossy(&output.stdout)
            )
        });
    assert_eq!(record["status"], "blocked_context");
    assert!(record.get("packet_sha256").is_none());
}

#[test]
fn total_review_deadline_includes_stream_body_after_headers() {
    use std::time::Duration;
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    let primary = Server::start(|_, _| text_reply(PRIMARY_DRAFT));
    let reviewer =
        Server::start(|_, _| text_reply(REVIEW_RESULT).delayed(Duration::from_millis(600)));
    fixture_state(&project, &state, &primary, &reviewer);
    let path = state.join("config.json");
    let mut config: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    config["providers"]["openrouter"]["request_timeout_secs"] = json!(1);
    config["final_review"]["selected"]["snapshot"]["request_timeout_secs"] = json!(1);
    config["providers"]["openrouter"]["idle_timeout_secs"] = json!(5);
    config["final_review"]["selected"]["snapshot"]["idle_timeout_secs"] = json!(5);
    fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();

    let output = run(&project, &state, true);
    assert_ne!(output.status.code(), Some(0));
    let requests = reviewer.generations();
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0].received.elapsed() < Duration::from_secs(2),
        "total deadline must bound slow body chunks after reviewer receives the request"
    );
    assert!(
        !events(&output)
            .iter()
            .any(|event| event["type"] == "review_result")
    );
}

#[test]
fn primary_gigachat_oauth_token_is_redacted_from_review_packet_and_saved_record() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    let primary_token = "primary-oauth-synthetic-sentinel";
    let primary = Server::start(move |request, _| {
        if request.path == "/oauth" {
            Response::json(
                200,
                json!({"access_token":primary_token,"expires_at":4102444800000_u64}),
            )
        } else {
            assert_eq!(
                request.authorization().unwrap(),
                format!("Bearer {primary_token}")
            );
            text_reply(&format!("draft includes {primary_token}"))
        }
    });
    let reviewer = Server::start(move |_, _| text_reply(&format!("review quotes {primary_token}")));
    fixture_state(&project, &state, &primary, &reviewer);
    let path = state.join("config.json");
    let mut config: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    config["active"] = json!("gigachat");
    let mut giga = serde_json::to_value(ProviderSettings::new(ProviderKind::GigaChat)).unwrap();
    giga["base_url"] = json!(primary.base());
    giga["auth_url"] = json!(format!("{}/oauth", primary.url));
    giga["model"] = json!("primary-giga-model");
    config["providers"]["gigachat"] = giga;
    fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let creds_path = state.join("credentials.json");
    let mut credentials: Value = serde_json::from_slice(&fs::read(&creds_path).unwrap()).unwrap();
    credentials["providers"]["gigachat"] = json!("synthetic-giga-basic-credential");
    fs::write(&creds_path, serde_json::to_vec(&credentials).unwrap()).unwrap();

    let output = run_provider(
        &project,
        &state,
        true,
        &[],
        "gigachat",
        "primary-giga-model",
        USER_TASK,
    );
    assert!(
        output.status.success(),
        "stderr={} stdout={}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let packet = reviewer.generations().remove(0).json()["messages"][1]["content"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(!packet.contains(primary_token));
    let session = saved(&state);
    assert!(!session.to_string().contains(primary_token));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(primary_token));
}

#[test]
fn selected_gigachat_oauth_error_body_is_not_saved_or_published() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    let primary = Server::start(|_, _| text_reply(PRIMARY_DRAFT));
    let review_token = "selected-review-oauth-synthetic-sentinel";
    let reviewer = Server::start(move |request, _| {
        if request.path == "/oauth" {
            Response::json(
                200,
                json!({"access_token":review_token,"expires_at":4102444800000_u64}),
            )
        } else {
            Response::json(500, json!({"error":{"message":review_token}}))
        }
    });
    fixture_state(&project, &state, &primary, &reviewer);
    let path = state.join("config.json");
    let mut config: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let mut giga = serde_json::to_value(ProviderSettings::new(ProviderKind::GigaChat)).unwrap();
    giga["base_url"] = json!(reviewer.base());
    giga["auth_url"] = json!(format!("{}/oauth", reviewer.url));
    giga["model"] = json!("selected-giga-review-model");
    config["providers"]["gigachat"] = giga.clone();
    config["final_review"] = json!({"selected":{"snapshot":giga}});
    fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let creds_path = state.join("credentials.json");
    let mut credentials: Value = serde_json::from_slice(&fs::read(&creds_path).unwrap()).unwrap();
    credentials["providers"]["gigachat"] = json!("synthetic-giga-basic-credential");
    fs::write(&creds_path, serde_json::to_vec(&credentials).unwrap()).unwrap();

    let output = run(&project, &state, true);
    assert_ne!(output.status.code(), Some(0));
    assert_eq!(
        reviewer
            .requests()
            .iter()
            .filter(|request| request.path == "/oauth")
            .count(),
        1
    );
    assert!(!saved(&state).to_string().contains(review_token));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(review_token));
    assert!(
        !events(&output)
            .iter()
            .any(|event| event["type"] == "review_result")
    );
}

#[test]
fn credential_rotation_during_primary_request_is_redacted_and_packet_hash_matches_wire() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    let rotated_key = "rotated-review-synthetic-secret";
    let credential_path = state.join("credentials.json");
    let rotated_for_primary = rotated_key.to_owned();
    let primary = Server::start(move |_, _| {
        let mut credentials: Value =
            serde_json::from_slice(&fs::read(&credential_path).unwrap()).unwrap();
        credentials["providers"]["openrouter"] = json!(rotated_for_primary);
        fs::write(&credential_path, serde_json::to_vec(&credentials).unwrap()).unwrap();
        text_reply(&format!("draft echoes {rotated_key}"))
    });
    let reviewer = Server::start(move |request, _| {
        assert_eq!(
            request.authorization().unwrap(),
            format!("Bearer {rotated_key}")
        );
        text_reply(&format!("review echoes {rotated_key}"))
    });
    fixture_state(&project, &state, &primary, &reviewer);

    let output = run(&project, &state, true);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let request = reviewer.generations().remove(0);
    let wire_packet = request.json()["messages"][1]["content"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(!wire_packet.contains(rotated_key));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(rotated_key));
    let session = saved(&state);
    assert!(!session.to_string().contains(rotated_key));
    let record = session["final_reviews"].as_array().unwrap().last().unwrap();
    let expected_hash = format!("{:x}", sha2::Sha256::digest(wire_packet.as_bytes()));
    assert_eq!(record["packet_sha256"], expected_hash);
}

#[test]
fn late_selected_oauth_token_redaction_failure_blocks_review_result() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    let primary = Server::start(|_, _| text_reply(PRIMARY_DRAFT));
    let oversized_token = "t".repeat(8193);
    let token_for_server = oversized_token.clone();
    let token_for_result = oversized_token.clone();
    let reviewer = Server::start(move |request, _| {
        if request.path == "/oauth" {
            Response::json(
                200,
                json!({"access_token":token_for_server,"expires_at":4102444800000_u64}),
            )
        } else {
            assert!(request.authorization().unwrap().starts_with("Bearer "));
            Response::json(
                200,
                json!({
                    "choices":[{"message":{"role":"assistant","content":format!("review echoes {token_for_result}")},"finish_reason":"stop"}],
                    "usage":{"prompt_tokens":120,"completion_tokens":5}
                }),
            )
        }
    });
    fixture_state(&project, &state, &primary, &reviewer);

    let mut giga = serde_json::to_value(ProviderSettings::new(ProviderKind::GigaChat)).unwrap();
    giga["base_url"] = json!(reviewer.base());
    giga["auth_url"] = json!(format!("{}/oauth", reviewer.url));
    giga["model"] = json!("selected-giga-review-model");
    let path = state.join("config.json");
    let mut config: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    config["providers"]["gigachat"] = giga.clone();
    config["final_review"] = json!({"selected":{"snapshot":giga}});
    fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let creds_path = state.join("credentials.json");
    let mut credentials: Value = serde_json::from_slice(&fs::read(&creds_path).unwrap()).unwrap();
    credentials["providers"]["gigachat"] = json!("synthetic-giga-basic-credential");
    fs::write(&creds_path, serde_json::to_vec(&credentials).unwrap()).unwrap();

    let output = run(&project, &state, true);
    assert_ne!(
        output.status.code(),
        Some(0),
        "late-token redaction failure must fail the review"
    );
    assert_eq!(
        reviewer
            .requests()
            .iter()
            .filter(|request| request.path == "/oauth")
            .count(),
        1
    );
    assert_eq!(reviewer.generations().len(), 1);
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&oversized_token));
    let saved_session = saved(&state);
    assert!(!saved_session.to_string().contains(&oversized_token));
    let record = saved_session["final_reviews"]
        .as_array()
        .unwrap()
        .last()
        .unwrap();
    assert_eq!(record["status"], "failed");
    assert!(record.get("result").is_none());
    assert!(!record.to_string().contains(&oversized_token));
    assert!(
        !events(&output)
            .iter()
            .any(|event| event["type"] == "review_result")
    );
}

#[test]
fn final_review_repair_cli_conflict_and_model_shell_guard() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    let primary = Server::start(|_, _| text_reply(PRIMARY_DRAFT));
    let reviewer = Server::start(|_, _| text_reply(REVIEW_RESULT));
    fixture_state(&project, &state, &primary, &reviewer);

    let conflict = run_settings_command(
        &state,
        &[
            "--final-review",
            "--final-review-repair",
            "--json",
            "review-model",
            "status",
        ],
        false,
    );
    assert_ne!(conflict.status.code(), Some(0));

    let status = run_settings_command(
        &state,
        &["--final-review-repair", "--json", "review-model", "status"],
        false,
    );
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    let status_value: Value = serde_json::from_slice(
        status
            .stdout
            .split(|byte| *byte == b'\n')
            .find(|line| !line.is_empty())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(status_value["data"]["enabled"], true);
    assert_eq!(status_value["data"]["mode"], "repair");

    let blocked = Command::new(env!("CARGO_BIN_EXE_rcode"))
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("RCODE_HOME", &state)
        .env("RCODE_MODEL_SHELL", "1")
        .arg("-C")
        .arg(&project)
        .args([
            "--provider",
            "custom",
            "--model",
            "primary-model",
            "--json",
            "--final-review-repair",
            "exec",
            USER_TASK,
        ])
        .output()
        .unwrap();
    assert_ne!(blocked.status.code(), Some(0));
    assert!(primary.requests().is_empty());
    assert!(reviewer.requests().is_empty());
}

#[test]
fn final_review_repair_executes_bounded_verification_and_strips_transient_feedback() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    fs::create_dir_all(project.join("src")).unwrap();
    fs::write(
        project.join("src/lib.rs"),
        "pub fn answer() -> u32 { 42 }\n",
    )
    .unwrap();

    let repaired_text = "Repaired answer: verified src/lib.rs returns 42.";
    let primary = Server::start(move |request, step| {
        let body = request.json();
        match step {
            0 => text_reply(PRIMARY_DRAFT),
            1 => {
                let tools = body["tools"].as_array().unwrap();
                let tool_names: Vec<&str> = tools
                    .iter()
                    .filter_map(|tool| tool["function"]["name"].as_str())
                    .collect();
                assert!(tool_names.contains(&"read_file"), "{tool_names:?}");
                assert!(!tool_names.contains(&"spawn_agent"), "{tool_names:?}");
                assert!(!tool_names.contains(&"wait_agent"), "{tool_names:?}");
                assert!(!tool_names.contains(&"handoff_command"), "{tool_names:?}");
                let messages = body["messages"].as_array().unwrap();
                let last_user = messages.last().unwrap()["content"].as_str().unwrap();
                assert!(
                    last_user.contains("<untrusted_final_review>"),
                    "{last_user}"
                );
                assert!(last_user.contains(REVIEW_RESULT), "{last_user}");
                tool_reply(
                    "call_repair_read",
                    "read_file",
                    &json!({"path": "src/lib.rs"}),
                )
            }
            2 => text_reply(repaired_text),
            other => panic!("unexpected primary step {other}"),
        }
    });
    let reviewer = Server::start(|_, _| text_reply(REVIEW_RESULT));
    fixture_state(&project, &state, &primary, &reviewer);

    let output = run_prompt_with(
        &project,
        &state,
        false,
        &["--final-review-repair"],
        USER_TASK,
    );
    assert!(
        output.status.success(),
        "stderr={} stdout={}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(primary.generations().len(), 3);
    assert_eq!(reviewer.generations().len(), 1);

    let events = events(&output);
    let draft_pos = events
        .iter()
        .position(|e| e["type"] == "text" && e["origin"] == "primary_draft")
        .unwrap();
    let review_pos = events
        .iter()
        .position(|e| e["type"] == "review_result")
        .unwrap();
    let repair_start_pos = events
        .iter()
        .position(|e| e["type"] == "repair_started")
        .unwrap();
    let repaired_text_pos = events
        .iter()
        .position(|e| e["type"] == "text" && e["origin"] == "primary_repaired")
        .unwrap();
    let repair_result_pos = events
        .iter()
        .position(|e| e["type"] == "repair_result")
        .unwrap();
    assert!(draft_pos < review_pos);
    assert!(review_pos < repair_start_pos);
    assert!(repair_start_pos < repaired_text_pos);
    assert!(repaired_text_pos < repair_result_pos);
    assert_eq!(events[repaired_text_pos]["text"], repaired_text);
    assert_eq!(events[repair_result_pos]["status"], "completed");
    assert_eq!(
        events[repair_result_pos]["verification_status"],
        "verified_scoped"
    );
    assert_eq!(events[repair_result_pos]["repair_steps"], 2);

    let session = saved(&state);
    let record = session["final_reviews"].as_array().unwrap().last().unwrap();
    assert_eq!(record["mode"], "repair");
    assert_eq!(record["status"], "completed");
    assert_eq!(record["repair_status"], "completed");
    assert_eq!(record["verification_status"], "verified_scoped");
    assert_eq!(record["repair_steps"], 2);
    let expected_repaired_sha = format!("{:x}", sha2::Sha256::digest(repaired_text.as_bytes()));
    assert_eq!(record["repaired_sha256"], expected_repaired_sha);

    let messages = session["messages"].as_array().unwrap();
    assert!(
        !messages.iter().any(|m| {
            m["content"]
                .as_str()
                .is_some_and(|c| c.contains("<untrusted_final_review>"))
                || m["provider_meta"]["data"]["final_review_repair"] == json!(true)
        }),
        "transient repair feedback must be stripped from saved session: {messages:?}"
    );
    assert_eq!(
        messages.last().unwrap()["content"].as_str(),
        Some(repaired_text)
    );
}

#[test]
fn final_review_repair_rejects_delegation_and_respects_plan_mode() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    let primary = Server::start(move |request, step| {
        let body = request.json();
        match step {
            0 => text_reply(PRIMARY_DRAFT),
            1 => {
                let tools = body["tools"].as_array().unwrap();
                let names: Vec<&str> = tools
                    .iter()
                    .filter_map(|t| t["function"]["name"].as_str())
                    .collect();
                assert!(!names.contains(&"write_file"), "{names:?}");
                assert!(!names.contains(&"run_command"), "{names:?}");
                assert!(!names.contains(&"spawn_agent"), "{names:?}");
                tool_reply(
                    "call_repair_spawn",
                    "spawn_agent",
                    &json!({"role": "explorer", "task": "forbidden delegation"}),
                )
            }
            2 => {
                let messages = body["messages"].as_array().unwrap();
                let tool_msg = messages.iter().rev().find(|m| m["role"] == "tool").unwrap();
                assert!(
                    tool_msg["content"]
                        .as_str()
                        .unwrap()
                        .contains("forbidden_in_repair"),
                    "{tool_msg}"
                );
                text_reply("Plan repair completed without delegation.")
            }
            other => panic!("unexpected primary step {other}"),
        }
    });
    let reviewer = Server::start(|_, _| text_reply(REVIEW_RESULT));
    fixture_state(&project, &state, &primary, &reviewer);

    let output = run_prompt_with(
        &project,
        &state,
        false,
        &["--final-review-repair", "--plan"],
        USER_TASK,
    );
    assert_ne!(
        output.status.code(),
        Some(0),
        "forbidden tool error during repair must yield nonzero exit code"
    );
    let session = saved(&state);
    assert!(session["agents"].as_array().is_none_or(Vec::is_empty));
    let record = session["final_reviews"].as_array().unwrap().last().unwrap();
    assert_eq!(record["repair_status"], "completed");
}

#[test]
fn final_review_repair_marks_unverified_write_after_check_as_unknown() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    fs::create_dir_all(&project).unwrap();
    fs::write(project.join("note.txt"), "before\n").unwrap();

    let primary = Server::start(move |_, step| match step {
        0 => text_reply(PRIMARY_DRAFT),
        1 => tool_reply("call_read_1", "read_file", &json!({"path": "note.txt"})),
        2 => tool_reply(
            "call_write_1",
            "write_file",
            &json!({"path": "note.txt", "content": "after\n"}),
        ),
        3 => text_reply("Updated note.txt without a post-write verification check."),
        other => panic!("unexpected step {other}"),
    });
    let reviewer = Server::start(|_, _| text_reply(REVIEW_RESULT));
    fixture_state(&project, &state, &primary, &reviewer);

    let output = run_prompt_with(
        &project,
        &state,
        false,
        &["--final-review-repair", "--approval-mode", "full-access"],
        USER_TASK,
    );
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let session = saved(&state);
    let record = session["final_reviews"].as_array().unwrap().last().unwrap();
    assert_eq!(record["repair_status"], "completed");
    assert_eq!(record["verification_status"], "unknown");
    assert_eq!(record["repair_steps"], 3);
}

#[test]
fn final_review_repair_budget_exhaustion_and_single_step_tool_free_cap() {
    // Case A: --max-steps 1 leaves 0 requests for repair -> blocked before calling reviewer.
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    let primary = Server::start(|_, _| text_reply(PRIMARY_DRAFT));
    let reviewer = Server::start(|_, _| text_reply(REVIEW_RESULT));
    fixture_state(&project, &state, &primary, &reviewer);

    let out_exhausted = run_prompt_with(
        &project,
        &state,
        false,
        &["--final-review-repair", "--max-steps", "1"],
        USER_TASK,
    );
    assert_ne!(out_exhausted.status.code(), Some(0));
    assert!(reviewer.requests().is_empty());
    let ev_exhausted = events(&out_exhausted);
    let failed = ev_exhausted
        .iter()
        .find(|e| e["type"] == "review_failed")
        .unwrap();
    assert_eq!(failed["status"], "budget_exhausted");
    assert_eq!(failed["repair_status"], "budget_exhausted");

    // Case B: --max-steps 2 leaves 1 request for repair with tools = [].
    let temp2 = tempfile::tempdir().unwrap();
    let project2 = temp2.path().join("project");
    let state2 = temp2.path().join("state");
    let primary2 = Server::start(|request, step| match step {
        0 => text_reply(PRIMARY_DRAFT),
        1 => {
            let body = request.json();
            assert!(body["tools"].as_array().is_none_or(Vec::is_empty));
            text_reply("Repaired in single tool-free step.")
        }
        other => panic!("unexpected step {other}"),
    });
    let reviewer2 = Server::start(|_, _| text_reply(REVIEW_RESULT));
    fixture_state(&project2, &state2, &primary2, &reviewer2);

    let out_single = run_prompt_with(
        &project2,
        &state2,
        false,
        &["--final-review-repair", "--max-steps", "2"],
        USER_TASK,
    );
    assert!(out_single.status.success());
    let record2 = saved(&state2)["final_reviews"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    assert_eq!(record2["repair_status"], "completed");
    assert_eq!(record2["verification_status"], "not_run");
    assert_eq!(record2["repair_steps"], 1);

    // Case C: --max-steps 2 where primary tries to call a tool on the final tool-free repair step.
    let temp3 = tempfile::tempdir().unwrap();
    let project3 = temp3.path().join("project");
    let state3 = temp3.path().join("state");
    let primary3 = Server::start(|_, step| match step {
        0 => text_reply(PRIMARY_DRAFT),
        1 => tool_reply(
            "call_final_step",
            "read_file",
            &json!({"path": "missing.txt"}),
        ),
        other => panic!("unexpected step {other}"),
    });
    let reviewer3 = Server::start(|_, _| text_reply(REVIEW_RESULT));
    fixture_state(&project3, &state3, &primary3, &reviewer3);

    let out_incomplete = run_prompt_with(
        &project3,
        &state3,
        false,
        &["--final-review-repair", "--max-steps", "2"],
        USER_TASK,
    );
    assert_ne!(out_incomplete.status.code(), Some(0));
    assert_eq!(primary3.generations().len(), 2);
    assert_eq!(reviewer3.generations().len(), 1);
    let ev_incomplete = events(&out_incomplete);
    let rep_failed = ev_incomplete
        .iter()
        .find(|e| e["type"] == "repair_failed")
        .unwrap();
    assert_eq!(rep_failed["status"], "incomplete");
    let record3 = saved(&state3)["final_reviews"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    assert_eq!(record3["repair_status"], "incomplete");
}
