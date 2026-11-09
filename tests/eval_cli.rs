//! Eval metadata validation must never execute case code, hooks or provider setup.
use serde_json::{Value, json};
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

fn run(home: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rcode"));
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("RCODE_HOME", home)
        .args(["--json", "eval"])
        .args(args)
        .stdin(std::process::Stdio::null());
    for name in ["SYSTEMROOT", "TMPDIR", "TEMP", "TMP"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command.output().unwrap()
}
fn suite(root: &Path) -> std::path::PathBuf {
    fs::create_dir_all(root.join("cases/py-add/project")).unwrap();
    fs::create_dir_all(root.join("oracles")).unwrap();
    fs::write(
        root.join("cases/py-add/project/solution.py"),
        "def add(a, b): return a - b\n",
    )
    .unwrap();
    fs::write(root.join("cases/py-add/task.md"), "Исправь сложение.\n").unwrap();
    fs::write(root.join("oracles/py-add.json"), json!({"version":1,"prepare":[],"checks":[{
        "id":"addition","argv":["python3","-I","-c","print(2 + 3)"],"expected_exit":0,"expected_json":5
    }]}).to_string()).unwrap();
    let path = root.join("manifest.json");
    fs::write(&path, json!({"version":1,"cases":[{
        "id":"py-add","language":"python","category":"bugfix", "project":"cases/py-add/project",
        "task":"cases/py-add/task.md","oracle":"oracles/py-add.json", "max_steps":12,"max_requests":24,"timeout_secs":300
    }]}).to_string()).unwrap();
    path
}
fn events(out: &Output) -> Vec<Value> {
    out.stdout
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_slice(l).unwrap())
        .collect()
}
#[test]
fn validate_reads_a_suite_without_credentials_or_running_oracle_commands() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    fs::create_dir(&home).unwrap();
    fs::write(
        home.join("config.json"),
        "invalid configuration must not be read by validate",
    )
    .unwrap();
    let path = suite(root.path());
    let marker = root.path().join("oracle-must-not-execute");
    fs::write(root.path().join("oracles/py-add.json"),json!({"version":1,"prepare":[{
        "argv":["sh","-c",format!("touch '{}'",marker.display())],"timeout_secs":1
    }],"checks":[{"id":"sentinel","argv":["sh","-c",format!("touch '{}'",marker.display())],"expected_exit":0,"expected_stdout":""}]}).to_string()).unwrap();
    let out = run(&home, &["validate", "--suite", path.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let result = events(&out)
        .into_iter()
        .find(|v| v["type"] == "eval_validated")
        .unwrap();
    assert_eq!(result["cases"], 1);
    assert_eq!(result["suite_sha256"].as_str().unwrap().len(), 64);
    assert!(!marker.exists());
    assert!(!home.join("sessions").exists());
    assert_eq!(
        fs::read_to_string(home.join("config.json")).unwrap(),
        "invalid configuration must not be read by validate"
    );
}
#[test]
fn validate_rejects_unknown_versions_and_unknown_fields() {
    let root = tempfile::tempdir().unwrap();
    let path = suite(root.path());
    for value in [
        json!({"version":9,"cases":[]}),
        json!({"version":1,"cases":[],"hook":"do not run"}),
    ] {
        fs::write(&path, value.to_string()).unwrap();
        let out = run(
            root.path(),
            &["validate", "--suite", path.to_str().unwrap()],
        );
        assert!(!out.status.success());
        assert!(events(&out).iter().any(|v| v["type"] == "error"));
    }
}
#[test]
fn validate_accepts_unique_skill_ids_and_rejects_duplicates() {
    let root = tempfile::tempdir().unwrap();
    let path = suite(root.path());
    let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["cases"][0]["require_skills"] = json!([
        "superpowers:using-superpowers",
        "superpowers:test-driven-development"
    ]);
    fs::write(&path, value.to_string()).unwrap();
    let home = root.path().join("home");
    fs::create_dir(&home).unwrap();
    let valid = run(&home, &["validate", "--suite", path.to_str().unwrap()]);
    assert!(
        valid.status.success(),
        "{}{}",
        String::from_utf8_lossy(&valid.stdout),
        String::from_utf8_lossy(&valid.stderr)
    );
    value["cases"][0]["require_skills"] = json!(["superpowers:x", "superpowers:x"]);
    fs::write(&path, value.to_string()).unwrap();
    let invalid = run(&home, &["validate", "--suite", path.to_str().unwrap()]);
    assert!(!invalid.status.success());
}

#[cfg(unix)]
#[test]
fn validate_rejects_symlinked_project_files() {
    let root = tempfile::tempdir().unwrap();
    let path = suite(root.path());
    fs::write(root.path().join("hidden"), "not a fixture").unwrap();
    std::os::unix::fs::symlink(
        root.path().join("hidden"),
        root.path().join("cases/py-add/project/escaped"),
    )
    .unwrap();
    let out = run(
        root.path(),
        &["validate", "--suite", path.to_str().unwrap()],
    );
    assert!(!out.status.success());
    assert!(events(&out).iter().any(|v| v["type"] == "error"));
}
#[test]
fn validate_hash_changes_when_hidden_expectations_change() {
    let root = tempfile::tempdir().unwrap();
    let path = suite(root.path());
    let first = run(
        root.path(),
        &["validate", "--suite", path.to_str().unwrap()],
    );
    assert!(first.status.success());
    let mut value: Value =
        serde_json::from_slice(&fs::read(root.path().join("oracles/py-add.json")).unwrap())
            .unwrap();
    value["checks"][0]["expected_json"] = json!(6);
    fs::write(root.path().join("oracles/py-add.json"), value.to_string()).unwrap();
    let second = run(
        root.path(),
        &["validate", "--suite", path.to_str().unwrap()],
    );
    assert!(second.status.success());
    assert_ne!(
        events(&first)[0]["suite_sha256"],
        events(&second)[0]["suite_sha256"]
    );
}

#[test]
fn validate_supports_json_null_as_an_explicit_expected_value() {
    let root = tempfile::tempdir().unwrap();
    let path = suite(root.path());
    let mut v: Value =
        serde_json::from_slice(&fs::read(root.path().join("oracles/py-add.json")).unwrap())
            .unwrap();
    v["checks"][0]["expected_json"] = Value::Null;
    fs::write(root.path().join("oracles/py-add.json"), v.to_string()).unwrap();
    let out = run(
        root.path(),
        &["validate", "--suite", path.to_str().unwrap()],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}
#[test]
fn validate_rejects_duplicate_json_and_oracle_inside_project() {
    let root = tempfile::tempdir().unwrap();
    let path = suite(root.path());
    fs::write(
        root.path().join("oracles/py-add.json"),
        "{\"version\":1,\"version\":1,\"checks\":[]}",
    )
    .unwrap();
    let out = run(
        root.path(),
        &["validate", "--suite", path.to_str().unwrap()],
    );
    assert!(!out.status.success());
    let path = suite(root.path());
    let mut m: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    m["cases"][0]["oracle"] = json!("cases/py-add/project/checks.json");
    fs::copy(
        root.path().join("oracles/py-add.json"),
        root.path().join("cases/py-add/project/checks.json"),
    )
    .unwrap();
    fs::write(&path, m.to_string()).unwrap();
    let out = run(
        root.path(),
        &["validate", "--suite", path.to_str().unwrap()],
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("Oracle"));
}

#[test]
fn run_requires_explicit_consent_before_reading_provider_configuration() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("config.json"), "must not be loaded").unwrap();
    let path = suite(root.path());
    let out = run(
        root.path(),
        &[
            "run",
            "--suite",
            path.to_str().unwrap(),
            "--report",
            "report.json",
            "--agent-binary",
            "missing",
            "--image",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "--docker-socket",
            "/missing/socket",
            "--series",
            "candidate",
        ],
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("--yes"));
    assert!(!root.path().join("report.json").exists());
}
#[test]
fn compare_requires_identical_complete_configuration_and_never_counts_unknown_as_pass() {
    let root = tempfile::tempdir().unwrap();
    let a = root.path().join("a.json");
    let b = root.path().join("b.json");
    let report = json!({"version":1,"comparison_key":comparison_key(),"artifact":artifact_fixture(),"isolation":isolation_fixture(),"cleanup":"confirmed_absent","counts":{"passed":1,"failed":0,"blocked":0,"unknown":0,"not_run":0},"cases":[passed_fixture()]});
    fs::write(&a, report.to_string()).unwrap();
    let mut changed = report.clone();
    changed["comparison_key"]["selected_profile"]["model"] = json!("different");
    changed["comparison_key"]["effective_profile"]["model"] = json!("different");
    fs::write(&b, changed.to_string()).unwrap();
    let out = run(
        root.path(),
        &[
            "compare",
            "--baseline",
            a.to_str().unwrap(),
            "--candidate",
            b.to_str().unwrap(),
        ],
    );
    assert!(!out.status.success());
    changed = report.clone();
    changed["cases"][0]["status"] = json!("unknown");
    changed["counts"] = json!({"passed":0,"failed":0,"blocked":0,"unknown":1,"not_run":0});
    fs::write(&b, changed.to_string()).unwrap();
    let out = run(
        root.path(),
        &[
            "compare",
            "--baseline",
            a.to_str().unwrap(),
            "--candidate",
            b.to_str().unwrap(),
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let values = events(&out);
    let result = values
        .iter()
        .find(|v| v["type"] == "eval_comparison")
        .unwrap();
    assert_eq!(result["candidate"]["unknown"], 1);
    assert_eq!(result["candidate"]["passed"], 0);
}

#[test]
fn compare_rejects_an_incomplete_key_even_when_both_reports_match() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("report.json");
    fs::write(&path,json!({"version":1,"comparison_key":{},"artifact":artifact_fixture(),"isolation":isolation_fixture(),"cleanup":"confirmed_absent","counts":{"passed":0,"failed":0,"blocked":1,"unknown":0,"not_run":0},"cases":[{"id":"a","status":"blocked","cleanup":"confirmed_absent"}]}).to_string()).unwrap();
    let out = run(
        root.path(),
        &[
            "compare",
            "--baseline",
            path.to_str().unwrap(),
            "--candidate",
            path.to_str().unwrap(),
        ],
    );
    assert!(!out.status.success());
}

#[test]
fn compare_requires_protocol_two_and_validates_budget_skill_ids() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("report.json");
    let mut key = comparison_key();
    key["protocol"] = json!(2);
    key["case_budgets"][0]["require_skills"] = json!([
        "superpowers:using-superpowers",
        "superpowers:test-driven-development"
    ]);
    let mut report = json!({"version":1,"comparison_key":key,"artifact":artifact_fixture(),"isolation":isolation_fixture(),"cleanup":"confirmed_absent","counts":{"passed":1,"failed":0,"blocked":0,"unknown":0,"not_run":0},"cases":[passed_fixture()]});
    fs::write(&path, report.to_string()).unwrap();
    let valid = run(
        root.path(),
        &[
            "compare",
            "--baseline",
            path.to_str().unwrap(),
            "--candidate",
            path.to_str().unwrap(),
        ],
    );
    assert!(
        valid.status.success(),
        "{}",
        String::from_utf8_lossy(&valid.stdout)
    );

    let mut invalid_keys = Vec::new();
    let mut invalid = report["comparison_key"].clone();
    invalid["protocol"] = json!(1);
    invalid_keys.push(invalid);
    let mut invalid = report["comparison_key"].clone();
    invalid["case_budgets"][0]
        .as_object_mut()
        .unwrap()
        .remove("require_skills");
    invalid_keys.push(invalid);
    let mut invalid = report["comparison_key"].clone();
    invalid["case_budgets"][0]["unexpected"] = json!(true);
    invalid_keys.push(invalid);
    for skills in [
        json!(["superpowers:x", "superpowers:x"]),
        json!(["superpowers:"]),
        json!([":using-superpowers"]),
        json!(["superpowers::x"]),
        json!(["superpowers:x y"]),
        json!(["superpowers:é"]),
        json!([format!("superpowers:{}", "x".repeat(117))]),
        json!([42]),
        json!("superpowers:x"),
    ] {
        let mut invalid = report["comparison_key"].clone();
        invalid["case_budgets"][0]["require_skills"] = skills;
        invalid_keys.push(invalid);
    }
    for key in invalid_keys {
        report["comparison_key"] = key;
        fs::write(&path, report.to_string()).unwrap();
        let out = run(
            root.path(),
            &[
                "compare",
                "--baseline",
                path.to_str().unwrap(),
                "--candidate",
                path.to_str().unwrap(),
            ],
        );
        assert!(
            !out.status.success(),
            "invalid comparison key was trusted: {}",
            report["comparison_key"]
        );
    }
}

fn comparison_key() -> Value {
    let selected = rcode::local::profile_settings(
        "fixture",
        "http://127.0.0.1:8080/v1",
        rcode::local::LocalRuntime::Mlx,
        "fixture",
    );
    let mut effective = selected.clone();
    effective.stream = false;
    let helpers: serde_json::Map<String, Value> = [
        "host.py",
        "host_provider.py",
        "host_docker.py",
        "host_snapshot.py",
        "runtime.py",
        "runtime_http.py",
    ]
    .into_iter()
    .map(|k| (k.to_owned(), json!("c".repeat(64))))
    .collect();
    json!({"suite_sha256":"a".repeat(64),"selected_profile":selected,"effective_profile":effective,"image":format!("sha256:{}","d".repeat(64)),"helpers":helpers,"case_budgets":[{"id":"a","sha256":"b".repeat(64),"max_steps":12,"max_requests":24,"timeout_secs":300,"require_skills":["superpowers:using-superpowers","superpowers:test-driven-development"]}],"protocol":2,"steps_definition":"forwarded_model_generations_all_contexts","permissions":{"approval_mode":"auto-edit","allow_shell":true},"transport":"explicit_non_streaming_json"})
}

#[test]
fn compare_accepts_official_gigachat_and_rejects_unsafe_profile_metadata() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("report.json");
    let mut key = comparison_key();
    let mut selected = rcode::config::ProviderSettings::new(rcode::config::ProviderKind::GigaChat);
    selected.model = "GigaChat-3-Ultra".into();
    selected.base_url = None;
    selected.auth_url = Some("https://ngw.devices.sberbank.ru:9443/api/v2/oauth".into());
    let mut effective = selected.clone();
    effective.stream = false;
    key["selected_profile"] = json!(selected);
    key["effective_profile"] = json!(effective);
    let secret = "eval-synthetic-secret-7f4c9a";
    assert!(!key.to_string().contains(secret));
    let mut report = json!({"version":1,"comparison_key":key,"artifact":artifact_fixture(),"isolation":isolation_fixture(),"cleanup":"confirmed_absent","counts":{"passed":1,"failed":0,"blocked":0,"unknown":0,"not_run":0},"cases":[passed_fixture()]});
    fs::write(&path, report.to_string()).unwrap();
    let valid = run(
        root.path(),
        &[
            "compare",
            "--baseline",
            path.to_str().unwrap(),
            "--candidate",
            path.to_str().unwrap(),
        ],
    );
    assert!(
        valid.status.success(),
        "{}",
        String::from_utf8_lossy(&valid.stdout)
    );

    let mut invalid_keys = Vec::new();
    for (field, value) in [
        ("base_url", json!("https://example.com/v1")),
        ("auth_url", json!("https://example.com/oauth")),
        ("ca_file", json!("custom-ca.pem")),
        ("credential", json!(secret)),
        ("token", json!(secret)),
    ] {
        let mut invalid = report["comparison_key"].clone();
        invalid["selected_profile"][field] = value.clone();
        invalid["effective_profile"][field] = value;
        invalid_keys.push(invalid);
    }
    let mut invalid = report["comparison_key"].clone();
    invalid["effective_profile"]["stream"] = json!(true);
    invalid_keys.push(invalid);
    for key in invalid_keys {
        report["comparison_key"] = key;
        fs::write(&path, report.to_string()).unwrap();
        let out = run(
            root.path(),
            &[
                "compare",
                "--baseline",
                path.to_str().unwrap(),
                "--candidate",
                path.to_str().unwrap(),
            ],
        );
        assert!(!out.status.success());
        assert!(!String::from_utf8_lossy(&out.stdout).contains(secret));
        assert!(!String::from_utf8_lossy(&out.stderr).contains(secret));
    }
}

const VALIDATION_SECRET: &str = "eval-validation-secret-51c8e2";

fn assert_key_rejected_without_secret(key: Value) {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("report.json");
    let report = json!({"version":1,"comparison_key":key,"artifact":artifact_fixture(),"isolation":isolation_fixture(),"cleanup":"confirmed_absent","counts":{"passed":1,"failed":0,"blocked":0,"unknown":0,"not_run":0},"cases":[passed_fixture()]});
    fs::write(&path, report.to_string()).unwrap();
    let out = run(
        root.path(),
        &[
            "compare",
            "--baseline",
            path.to_str().unwrap(),
            "--candidate",
            path.to_str().unwrap(),
        ],
    );
    assert!(!out.status.success(), "malformed comparison key accepted");
    assert!(!String::from_utf8_lossy(&out.stdout).contains(VALIDATION_SECRET));
    assert!(!String::from_utf8_lossy(&out.stderr).contains(VALIDATION_SECRET));
}

#[test]
fn compare_rejects_unknown_nested_local_fields_without_publishing_values() {
    for field in ["credential", "token"] {
        let mut key = comparison_key();
        key["selected_profile"]["local"][field] = json!(VALIDATION_SECRET);
        key["effective_profile"]["local"][field] = json!(VALIDATION_SECRET);
        assert_key_rejected_without_secret(key);
    }
}

#[test]
fn compare_does_not_publish_malformed_kind() {
    let mut key = comparison_key();
    key["selected_profile"]["kind"] = json!(VALIDATION_SECRET);
    key["effective_profile"]["kind"] = json!(VALIDATION_SECRET);
    assert_key_rejected_without_secret(key);
}

#[test]
fn compare_does_not_publish_malformed_effort() {
    let mut key = comparison_key();
    key["selected_profile"]["effort"] = json!(VALIDATION_SECRET);
    key["effective_profile"]["effort"] = json!(VALIDATION_SECRET);
    assert_key_rejected_without_secret(key);
}

#[test]
fn compare_does_not_publish_malformed_local_runtime() {
    let mut key = comparison_key();
    key["selected_profile"]["local"]["runtime"] = json!(VALIDATION_SECRET);
    key["effective_profile"]["local"]["runtime"] = json!(VALIDATION_SECRET);
    assert_key_rejected_without_secret(key);
}

#[test]
fn validate_rejects_lifecycle_traversal_and_hashes_the_resume_contract() {
    let root = tempfile::tempdir().unwrap();
    let path = suite(root.path());
    let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["cases"][0]["lifecycle"] =
        json!({"interrupt_after_file":"../outside","resume_prompt":"continue"});
    fs::write(&path, value.to_string()).unwrap();
    assert!(
        !run(
            root.path(),
            &["validate", "--suite", path.to_str().unwrap()]
        )
        .status
        .success()
    );
    value["cases"][0]["lifecycle"]["interrupt_after_file"] = json!("ready");
    fs::write(&path, value.to_string()).unwrap();
    let first = run(
        root.path(),
        &["validate", "--suite", path.to_str().unwrap()],
    );
    assert!(first.status.success());
    value["cases"][0]["lifecycle"]["resume_prompt"] = json!("different");
    fs::write(&path, value.to_string()).unwrap();
    let second = run(
        root.path(),
        &["validate", "--suite", path.to_str().unwrap()],
    );
    assert!(second.status.success());
    assert_ne!(
        events(&first)[0]["suite_sha256"],
        events(&second)[0]["suite_sha256"]
    );
}

#[test]
fn compare_preserves_verified_earlier_cases_when_a_later_case_has_unknown_cleanup() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("partial.json");
    let mut key = comparison_key();
    let mut second = key["case_budgets"][0].clone();
    second["id"] = json!("b");
    key["case_budgets"].as_array_mut().unwrap().push(second);
    fs::write(&path,json!({"version":1,"comparison_key":key,"artifact":artifact_fixture(),"isolation":isolation_fixture(),"cleanup":"unknown","counts":{"passed":1,"failed":0,"blocked":0,"unknown":1,"not_run":0},"cases":[passed_fixture(),{"id":"b","case_sha256":"b".repeat(64),"status":"unknown","cleanup":"unknown"}]}).to_string()).unwrap();
    let out = run(
        root.path(),
        &[
            "compare",
            "--baseline",
            path.to_str().unwrap(),
            "--candidate",
            path.to_str().unwrap(),
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let event = events(&out);
    assert_eq!(event[0]["candidate"]["unknown"], 1);
    assert_eq!(event[0]["candidate_cleanup"], "unknown");
}

fn artifact_fixture() -> Value {
    json!({"series":"fixture","binary_sha256":"e".repeat(64),"platform":"linux","source_sha256":null,"source_hash_verified_by_runner":false})
}
fn isolation_fixture() -> Value {
    json!({"type":"probe_result","uid":10001,"gid":10001,"groups":[],"interfaces":["lo"],"capabilities_empty":true,"no_new_privileges":true,"seccomp_active":true,"root_stdout_denied":true,"signal_probe_denied":true,"external_network_denied":true})
}
fn passed_fixture() -> Value {
    json!({"id":"a","case_sha256":"b".repeat(64),"status":"passed","cleanup":"confirmed_absent","generations":1,"request_attempts":1,"seconds":1.0,"operator_cancelled":false,"tool_requirement_observed":true,
        "agent":{"type":"agent_done","exit_code":0,"signal":null,"leader_reaped":true,"pipes_complete":true,"timed_out":false,"cancelled":false,"truncated":false,"forced":false,"log_sha256":"f".repeat(64),"log_bytes":100},
        "checks":[{"id":"check","passed":true,"exit_code":0,"signal":null,"timed_out":false,"truncated":false,"prepare_failed":false,"stdout_sha256":"c".repeat(64)}],
        "requests":[{"generation":1,"status":"received","http_status":200,"usage":null}]})
}
#[test]
fn compare_rejects_pass_without_isolation_binary_identity_or_positive_evidence() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("report.json");
    let report = json!({"version":1,"comparison_key":comparison_key(),"artifact":artifact_fixture(),"isolation":isolation_fixture(),"cleanup":"confirmed_absent","counts":{"passed":1,"failed":0,"blocked":0,"unknown":0,"not_run":0},"cases":[passed_fixture()]});
    let mut variants = Vec::new();
    for value in [Value::Null, json!({}), json!({"uid":0})] {
        let mut r = report.clone();
        r["isolation"] = value;
        variants.push(r);
    }
    for value in [Value::Null, json!({}), json!({"binary_sha256":"bad"})] {
        let mut r = report.clone();
        r["artifact"] = value;
        variants.push(r);
    }
    for (field, value) in [
        ("generations", json!(0)),
        ("checks", json!([])),
        ("requests", json!([])),
        ("agent", Value::Null),
        ("operator_cancelled", json!(true)),
        ("tool_requirement_observed", json!(false)),
        ("seconds", json!(301)),
    ] {
        let mut r = report.clone();
        r["cases"][0][field] = value;
        variants.push(r);
    }
    let mut r = report.clone();
    r["cases"][0]["agent"]["timed_out"] = json!(true);
    variants.push(r);
    let mut r = report.clone();
    r["cases"][0]["checks"][0]["passed"] = json!(false);
    variants.push(r);
    for value in variants {
        fs::write(&path, value.to_string()).unwrap();
        let out = run(
            root.path(),
            &[
                "compare",
                "--baseline",
                path.to_str().unwrap(),
                "--candidate",
                path.to_str().unwrap(),
            ],
        );
        assert!(
            !out.status.success(),
            "incomplete or contradictory PASS was trusted: {}",
            value
        );
    }
}

#[test]
fn compare_accepts_cancelled_resume_request_without_http_but_rejects_its_failure_status() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("report.json");
    let mut row = passed_fixture();
    row["lifecycle"] = json!({"sentinel_observed":true,"cancel_sent":true,"cancel_signal_sent":true,"first_container_absent":true,"first_forced":false,"explicit_resume_argument":true,"agent_reported_same_session":true});
    row["requests"][0] = json!({"generation":1,"status":"cancelled_by_case","usage":null});
    let mut report = json!({"version":1,"comparison_key":comparison_key(),"artifact":artifact_fixture(),"isolation":isolation_fixture(),"cleanup":"confirmed_absent","counts":{"passed":1,"failed":0,"blocked":0,"unknown":0,"not_run":0},"cases":[row]});
    fs::write(&path, report.to_string()).unwrap();
    assert!(
        run(
            root.path(),
            &[
                "compare",
                "--baseline",
                path.to_str().unwrap(),
                "--candidate",
                path.to_str().unwrap()
            ]
        )
        .status
        .success()
    );
    report["cases"][0]["requests"][0]["http_status"] = json!(500);
    fs::write(&path, report.to_string()).unwrap();
    assert!(
        !run(
            root.path(),
            &[
                "compare",
                "--baseline",
                path.to_str().unwrap(),
                "--candidate",
                path.to_str().unwrap()
            ]
        )
        .status
        .success()
    );
}
