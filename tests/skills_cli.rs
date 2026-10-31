use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as Process;
use tempfile::TempDir;

struct Sandbox {
    _temp: TempDir,
    home: PathBuf,
    project: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("rcode-home");
        let project = temp.path().join("project");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&project).unwrap();
        Self {
            _temp: temp,
            home,
            project,
        }
    }

    fn binary(&self) -> &'static str {
        env!("CARGO_BIN_EXE_rcode")
    }

    fn run(&self, args: &[&str]) -> Output {
        let stdout = tempfile::tempfile().unwrap();
        let stderr = tempfile::tempfile().unwrap();
        let status = Process::new(self.binary())
            .args(args)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", &self.home)
            .env("RCODE_HOME", &self.home)
            .stdin(std::process::Stdio::null())
            .stdout(stdout.try_clone().unwrap())
            .stderr(stderr.try_clone().unwrap())
            .current_dir(&self.project)
            .status()
            .unwrap();
        Output {
            code: status.code().unwrap_or(-1),
            stdout: read_temp(stdout),
            stderr: read_temp(stderr),
        }
    }
}

struct Output {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Output {
    fn events(&self) -> Vec<Value> {
        self.stdout
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }

    fn kinds(&self) -> Vec<String> {
        self.events()
            .iter()
            .filter_map(|event| event["type"].as_str().map(str::to_owned))
            .collect()
    }

    fn assert_clean_jsonl(&self) {
        for event in self.events() {
            assert_eq!(event["version"], 1, "{event}");
        }
        for kind in self.kinds() {
            assert!(
                matches!(
                    kind.as_str(),
                    "skill" | "skill_source" | "command" | "warning" | "error"
                ),
                "неожиданный тип события: {kind}"
            );
        }
    }
}

fn read_temp(mut file: fs::File) -> String {
    use std::io::{Read, Seek};
    file.rewind().unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn put(path: &Path, content: impl AsRef<[u8]>) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

fn skill_text(name: &str, description: &str) -> String {
    format!("---\nname: {name}\ndescription: {description}\n---\nТело {name}\n")
}

#[test]
fn empty_catalog_reports_nothing_and_never_writes_the_manifest() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&["skills", "list"]);
    assert_eq!(output.code, 0, "{}", output.stderr);
    assert!(output.stdout.contains("Скиллов нет"), "{}", output.stdout);
    assert!(!sandbox.home.join("skills.json").exists());
}

#[test]
fn user_and_project_skills_are_listed_with_scope_and_status() {
    let sandbox = Sandbox::new();
    put(
        &sandbox.home.join("skills/review/SKILL.md"),
        skill_text("review", "Ревью"),
    );
    put(
        &sandbox.project.join(".rcode/skills/review/SKILL.md"),
        skill_text("review", "Проектный ревью"),
    );
    put(
        &sandbox.home.join("skills/gone/SKILL.md"),
        skill_text("gone", "Временный"),
    );
    let output = sandbox.run(&["skills", "list", "--json"]);
    assert_eq!(output.code, 0, "{}", output.stderr);
    let events = output.events();
    let review: Vec<_> = events.iter().filter(|e| e["id"] == "review").collect();
    assert_eq!(review.len(), 2, "{events:?}");
    assert!(
        review
            .iter()
            .any(|e| e["scope"] == "user" && e["status"] == "active")
    );
    let project = review.iter().find(|e| e["scope"] == "project").unwrap();
    assert_eq!(project["status"], "shadowed");
    assert_eq!(project["shadowed_by"], "user");
    assert!(
        events
            .iter()
            .any(|e| e["id"] == "gone" && e["status"] == "active")
    );
}

#[test]
fn list_json_emits_only_expected_event_kinds() {
    let sandbox = Sandbox::new();
    put(
        &sandbox.home.join("skills/alpha/SKILL.md"),
        skill_text("alpha", "Первый"),
    );
    put(
        &sandbox.project.join(".rcode/commands/git-pr.md"),
        "---\ndescription: PR\n---\nТело\n",
    );
    let output = sandbox.run(&["skills", "list", "--json"]);
    assert_eq!(output.code, 0, "{}", output.stderr);
    output.assert_clean_jsonl();
    let events = output.events();
    assert!(
        events
            .iter()
            .any(|e| e["type"] == "skill" && e["id"] == "alpha")
    );
    assert!(events.iter().all(|e| e["type"] != "skill_source"));

    let commands = sandbox.run(&["commands", "list", "--json"]);
    assert_eq!(commands.code, 0, "{}", commands.stderr);
    commands.assert_clean_jsonl();
    let events = commands.events();
    let command = events.iter().find(|e| e["type"] == "command").unwrap();
    assert_eq!(command["name"], "git-pr");
    assert_eq!(command["scope"], "project");
}

#[test]
fn disable_and_enable_roundtrip_through_the_manifest() {
    let sandbox = Sandbox::new();
    put(
        &sandbox.home.join("skills/alpha/SKILL.md"),
        skill_text("alpha", "Первый"),
    );
    put(
        &sandbox.home.join("skills/beta/SKILL.md"),
        skill_text("beta", "Второй"),
    );
    let disabled = sandbox.run(&["skills", "disable", "alpha", "--json"]);
    assert_eq!(disabled.code, 0, "{}", disabled.stderr);
    assert_eq!(skill_status(&sandbox, "alpha"), "disabled");
    assert_eq!(skill_status(&sandbox, "beta"), "active");
    assert_eq!(disabled.kinds(), ["skills_toggled"]);

    let enabled = sandbox.run(&["skills", "enable", "alpha", "--json"]);
    assert_eq!(enabled.code, 0, "{}", enabled.stderr);
    assert_eq!(skill_status(&sandbox, "alpha"), "active");
}

#[test]
fn unknown_skill_ids_exit_with_code_2() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&["skills", "disable", "нет-такого"]);
    assert_eq!(output.code, 2, "{} {}", output.stdout, output.stderr);
    assert!(
        output.stderr.contains("Неизвестные скиллы"),
        "{}",
        output.stderr
    );
    assert!(!sandbox.home.join("skills.json").exists());
}

#[test]
fn source_label_prefix_is_accepted_for_toggle() {
    let sandbox = Sandbox::new();
    let manifest = serde_json::json!({
        "version": 1,
        "sources": {
            "pack": {
                "kind": "git",
                "url": "https://example.invalid/pack.git",
                "ref": null,
                "commit": "0123456789abcdef0123456789abcdef01234567",
                "skills_root": "skills",
                "tree_sha256": "deadbeef",
                "package_version": null,
                "installed_at": 1,
                "updated_at": 1
            }
        }
    });
    let path = sandbox.home.join("skills.json");
    put(&path, serde_json::to_string(&manifest).unwrap());
    put(
        &sandbox
            .home
            .join("skill-sources/pack/skills/packed/SKILL.md"),
        skill_text("packed", "Из набора"),
    );
    let output = sandbox.run(&["skills", "disable", "packed", "--json"]);
    assert_eq!(output.code, 0, "{}", output.stderr);
    let saved: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        saved["disabled"],
        serde_json::json!(["pack:packed"]),
        "{saved}"
    );
    assert_eq!(
        saved["sources"]["pack"]["url"],
        "https://example.invalid/pack.git"
    );
}

#[test]
fn damaged_manifest_is_an_error_and_is_not_rewritten() {
    let sandbox = Sandbox::new();
    let path = sandbox.home.join("skills.json");
    put(&path, "{ не json");
    let output = sandbox.run(&["skills", "list"]);
    assert_eq!(output.code, 2, "{} {}", output.stdout, output.stderr);
    assert!(output.stderr.contains("Повреждён"), "{}", output.stderr);
    assert_eq!(fs::read_to_string(&path).unwrap(), "{ не json");
}

#[test]
fn unknown_manifest_version_is_an_error() {
    let sandbox = Sandbox::new();
    let path = sandbox.home.join("skills.json");
    put(&path, r#"{"version": 99}"#);
    let output = sandbox.run(&["skills", "list"]);
    assert_eq!(output.code, 2, "{} {}", output.stdout, output.stderr);
    assert!(output.stderr.contains("версию"), "{}", output.stderr);
    assert_eq!(fs::read_to_string(&path).unwrap(), "{\"version\": 99}");
}

#[test]
fn commands_list_reports_shadowed_by_builtin_without_running_anything() {
    let sandbox = Sandbox::new();
    put(
        &sandbox.project.join(".rcode/commands/permissions.md"),
        "подмена\n",
    );
    put(&sandbox.project.join(".rcode/commands/deploy.md"), "тело\n");
    let output = sandbox.run(&["commands", "list"]);
    assert_eq!(output.code, 0, "{}", output.stderr);
    assert!(output.stdout.contains("name=deploy"), "{}", output.stdout);
    assert!(
        output.stdout.contains("shadowed_by=builtin"),
        "{}",
        output.stdout
    );
}

fn skill_status(sandbox: &Sandbox, id: &str) -> String {
    let output = sandbox.run(&["skills", "list", "--json"]);
    assert_eq!(output.code, 0, "{}", output.stderr);
    output
        .events()
        .into_iter()
        .find(|e| e["type"] == "skill" && e["id"] == id)
        .unwrap_or_else(|| panic!("скилл {id} не найден: {}", output.stdout))["status"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn concurrent_toggles_are_serialized_by_the_lock() {
    let sandbox = Sandbox::new();
    put(
        &sandbox.home.join("skills/alpha/SKILL.md"),
        skill_text("alpha", "Первый"),
    );
    let one = std::thread::spawn(|| ());
    let _ = one.join();
    let mut handles = Vec::new();
    for _ in 0..2 {
        let home = sandbox.home.clone();
        let project = sandbox.project.clone();
        let binary = sandbox.binary();
        handles.push(std::thread::spawn(move || {
            Process::new(binary)
                .args(["skills", "disable", "alpha"])
                .env_clear()
                .env("PATH", std::env::var_os("PATH").unwrap_or_default())
                .env("HOME", &home)
                .env("RCODE_HOME", &home)
                .current_dir(&project)
                .status()
                .unwrap()
        }));
    }
    for handle in handles {
        let status = handle.join().unwrap();
        assert!(status.success());
    }
    let saved: Value =
        serde_json::from_str(&fs::read_to_string(sandbox.home.join("skills.json")).unwrap())
            .unwrap();
    assert_eq!(saved["disabled"], serde_json::json!(["alpha"]));
}

#[test]
fn the_registry_agrees_with_the_cli_listing() {
    let sandbox = Sandbox::new();
    put(
        &sandbox.project.join(".rcode/commands/audit.md"),
        "---\ndescription: Аудит\n---\nтело\n",
    );
    let output = sandbox.run(&["commands", "list", "--json"]);
    let events = output.events();
    let listed: Vec<_> = events
        .iter()
        .filter(|e| e["type"] == "command")
        .map(|e| e["name"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(listed, ["audit"]);
}
