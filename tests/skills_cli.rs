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

fn write_initial_repo(repo: &Path) {
    fs::create_dir_all(repo.join("skills/one")).unwrap();
    fs::create_dir_all(repo.join("skills/two")).unwrap();
    put(
        &repo.join("skills/one/SKILL.md"),
        skill_text("one", "First packed"),
    );
    put(
        &repo.join("skills/two/SKILL.md"),
        skill_text("two", "Second packed"),
    );
    run_git(repo, &["init", "-q"]);
    run_git(
        repo,
        &[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.invalid",
            "add",
            ".",
        ],
    );
    run_git(
        repo,
        &[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.invalid",
            "commit",
            "-m",
            "initial",
        ],
    );
}

fn run_git(repo: &Path, args: &[&str]) {
    let output = Process::new("git")
        .args(args)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", repo.join(".gitconfig"))
        .current_dir(repo)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_available() -> bool {
    Process::new("git")
        .arg("--version")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

fn require_git() -> bool {
    if git_available() {
        true
    } else {
        eprintln!("SKIP Git fixture: git is unavailable");
        assert!(
            std::env::var_os("RCODE_REQUIRE_GIT_TEST").is_none_or(|value| value != "1"),
            "RCODE_REQUIRE_GIT_TEST=1 requires git"
        );
        false
    }
}

#[test]
fn install_local_git_repo_installs_and_lists_prefixed_ids() {
    if !require_git() {
        return;
    }
    let sandbox = Sandbox::new();
    let repo = sandbox._temp.path().join("source-repo");
    fs::create_dir_all(&repo).unwrap();
    write_initial_repo(&repo);
    let source = repo.display().to_string();
    let output = sandbox.run(&["skills", "install", &source, "--yes", "--json"]);
    assert_eq!(output.code, 0, "{} {}", output.stdout, output.stderr);
    output.assert_clean_jsonl();
    let events = output.events();
    let installed = events.iter().find(|e| e["type"] == "skill_source").unwrap();
    assert_eq!(installed["status"], "installed");
    assert_eq!(installed["skills"], 2);
    assert!(installed["commit"].as_str().unwrap().len() >= 7);
    assert!(
        installed["ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|id| id == "source-repo:one")
    );
    assert!(
        sandbox
            .home
            .join("skill-sources/source-repo/skills/one/SKILL.md")
            .is_file()
    );
    let listing = sandbox.run(&["skills", "list", "--json"]);
    let events = listing.events();
    assert!(
        events
            .iter()
            .any(|e| e["id"] == "source-repo:one" && e["status"] == "active")
    );
    assert!(
        events
            .iter()
            .any(|e| e["type"] == "skill_source" && e["label"] == "source-repo")
    );
    assert!(!output.events().iter().any(|e| e["type"] == "warning"));
}

#[test]
fn install_requires_yes_for_network_source_without_terminal() {
    if !require_git() {
        return;
    }
    let sandbox = Sandbox::new();
    let repo = sandbox._temp.path().join("network-repo");
    fs::create_dir_all(&repo).unwrap();
    write_initial_repo(&repo);
    let output = sandbox.run(&["skills", "install", &repo.display().to_string(), "--json"]);
    assert_eq!(output.code, 0, "{} {}", output.stdout, output.stderr);
    assert!(
        output
            .events()
            .iter()
            .any(|e| e["type"] == "skill_source" && e["status"] == "installed")
    );
}

#[test]
fn install_rejects_unsafe_sources_before_running_git() {
    let sandbox = Sandbox::new();
    let unsafe_sources: Vec<String> = vec![
        "http://example.invalid/repo.git".to_owned(),
        "https://user:token@example.invalid/repo.git".to_owned(),
        "git://example.invalid/repo.git".to_owned(),
        "ext::sh -c touch".to_owned(),
        sandbox.home.display().to_string(),
        sandbox.project.display().to_string(),
    ];
    for source in unsafe_sources {
        let output = sandbox.run(&["skills", "install", &source, "--yes", "--json"]);
        assert_eq!(
            output.code, 2,
            "{source}: {} {}",
            output.stdout, output.stderr
        );
        assert!(
            !sandbox.home.join("skill-sources").exists()
                || sandbox
                    .home
                    .join("skill-sources")
                    .read_dir()
                    .map(|entries| entries.count() == 0)
                    .unwrap_or(true),
            "{source} left source files"
        );
    }
}

#[test]
fn dry_run_reports_and_leaves_no_trace() {
    if !require_git() {
        return;
    }
    let sandbox = Sandbox::new();
    let repo = sandbox._temp.path().join("dry-repo");
    fs::create_dir_all(&repo).unwrap();
    write_initial_repo(&repo);
    let output = sandbox.run(&[
        "skills",
        "install",
        &repo.display().to_string(),
        "--dry-run",
        "--yes",
        "--json",
    ]);
    assert_eq!(output.code, 0, "{} {}", output.stdout, output.stderr);
    assert!(
        output
            .events()
            .iter()
            .any(|e| e["type"] == "skill_source" && e["status"] == "dry_run" && e["skills"] == 2)
    );
    assert!(!sandbox.home.join("skill-sources/dry-repo").exists());
    let leftovers: Vec<_> = fs::read_dir(sandbox.home.join("skill-sources"))
        .unwrap()
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(".staging-"))
        .collect();
    assert!(leftovers.is_empty());
}

#[test]
fn update_replaces_atomically_and_reports_changes() {
    if !require_git() {
        return;
    }
    let sandbox = Sandbox::new();
    let repo = sandbox._temp.path().join("update-repo");
    fs::create_dir_all(&repo).unwrap();
    write_initial_repo(&repo);
    let source = repo.display().to_string();
    assert_eq!(
        sandbox
            .run(&["skills", "install", &source, "--yes", "--json"])
            .code,
        0
    );
    put(
        &repo.join("skills/one/SKILL.md"),
        skill_text("one", "First packed changed"),
    );
    fs::remove_dir_all(repo.join("skills/two")).unwrap();
    fs::create_dir_all(repo.join("skills/three")).unwrap();
    put(
        &repo.join("skills/three/SKILL.md"),
        skill_text("three", "Third packed"),
    );
    run_git(
        &repo,
        &[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.invalid",
            "add",
            ".",
        ],
    );
    run_git(
        &repo,
        &[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.invalid",
            "commit",
            "-m",
            "update",
        ],
    );
    let output = sandbox.run(&["skills", "update", "update-repo", "--yes", "--json"]);
    assert_eq!(output.code, 0, "{} {}", output.stdout, output.stderr);
    let event = output
        .events()
        .into_iter()
        .find(|e| e["type"] == "skill_source")
        .unwrap();
    assert_eq!(event["status"], "updated");
    assert!(
        event["added"]
            .as_array()
            .unwrap()
            .iter()
            .any(|id| id == "update-repo:three")
    );
    assert!(
        event["removed"]
            .as_array()
            .unwrap()
            .iter()
            .any(|id| id == "update-repo:two")
    );
    assert!(
        sandbox
            .home
            .join("skill-sources/update-repo/skills/three/SKILL.md")
            .is_file()
    );
    assert!(
        !sandbox
            .home
            .join("skill-sources/update-repo/skills/two")
            .exists()
    );
}

#[test]
fn update_refuses_local_changes_without_force() {
    if !require_git() {
        return;
    }
    let sandbox = Sandbox::new();
    let repo = sandbox._temp.path().join("preserve-repo");
    fs::create_dir_all(&repo).unwrap();
    write_initial_repo(&repo);
    assert_eq!(
        sandbox
            .run(&[
                "skills",
                "install",
                &repo.display().to_string(),
                "--yes",
                "--json"
            ])
            .code,
        0
    );
    put(
        &sandbox
            .home
            .join("skill-sources/preserve-repo/skills/one/SKILL.md"),
        skill_text("one", "User local edit"),
    );
    let output = sandbox.run(&["skills", "update", "preserve-repo", "--yes", "--json"]);
    assert_eq!(output.code, 1, "{} {}", output.stdout, output.stderr);
    assert!(
        output
            .events()
            .iter()
            .any(|e| e["type"] == "skill_source" && e["status"] == "local_changes")
    );
    let installed = fs::read_to_string(
        sandbox
            .home
            .join("skill-sources/preserve-repo/skills/one/SKILL.md"),
    )
    .unwrap();
    assert!(installed.contains("User local edit"));
}

#[test]
fn update_force_preserves_local_changes_in_a_backup() {
    if !require_git() {
        return;
    }
    let sandbox = Sandbox::new();
    let repo = sandbox._temp.path().join("force-repo");
    fs::create_dir_all(&repo).unwrap();
    write_initial_repo(&repo);
    assert_eq!(
        sandbox
            .run(&[
                "skills",
                "install",
                &repo.display().to_string(),
                "--yes",
                "--json"
            ])
            .code,
        0
    );
    put(
        &sandbox
            .home
            .join("skill-sources/force-repo/skills/one/SKILL.md"),
        skill_text("one", "User local edit"),
    );
    let output = sandbox.run(&[
        "skills",
        "update",
        "force-repo",
        "--force",
        "--yes",
        "--json",
    ]);
    assert_eq!(output.code, 0, "{} {}", output.stdout, output.stderr);
    let backups: Vec<_> = fs::read_dir(sandbox.home.join("skill-sources"))
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("force-repo.backup-"))
        .collect();
    assert_eq!(backups.len(), 1, "{}", output.stdout);
    assert!(
        fs::read_to_string(
            sandbox
                .home
                .join("skill-sources")
                .join(&backups[0])
                .join("skills/one/SKILL.md")
        )
        .unwrap()
        .contains("User local edit")
    );
    assert!(
        fs::read_to_string(
            sandbox
                .home
                .join("skill-sources/force-repo/skills/one/SKILL.md")
                .display()
                .to_string()
        )
        .unwrap()
        .contains("First packed")
    );
}

#[test]
fn failed_update_keeps_previous_version() {
    if !require_git() {
        return;
    }
    let sandbox = Sandbox::new();
    let repo = sandbox._temp.path().join("fail-repo");
    fs::create_dir_all(&repo).unwrap();
    write_initial_repo(&repo);
    assert_eq!(
        sandbox
            .run(&[
                "skills",
                "install",
                &repo.display().to_string(),
                "--yes",
                "--json"
            ])
            .code,
        0
    );
    fs::remove_dir_all(&repo).unwrap();
    let output = sandbox.run(&["skills", "update", "fail-repo", "--yes", "--json"]);
    assert_eq!(output.code, 4, "{} {}", output.stdout, output.stderr);
    assert!(
        output
            .events()
            .iter()
            .any(|e| e["type"] == "skill_source" && e["status"] == "unknown")
    );
    assert!(
        sandbox
            .home
            .join("skill-sources/fail-repo/skills/one/SKILL.md")
            .is_file()
    );
    let manifest: Value =
        serde_json::from_str(&fs::read_to_string(sandbox.home.join("skills.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["sources"]["fail-repo"]["status"], Value::Null);
    assert!(manifest["sources"]["fail-repo"]["commit"].is_string());
}

#[test]
fn remove_requires_confirmation_and_deletes() {
    if !require_git() {
        return;
    }
    let sandbox = Sandbox::new();
    let repo = sandbox._temp.path().join("remove-repo");
    fs::create_dir_all(&repo).unwrap();
    write_initial_repo(&repo);
    assert_eq!(
        sandbox
            .run(&[
                "skills",
                "install",
                &repo.display().to_string(),
                "--yes",
                "--json"
            ])
            .code,
        0
    );
    let refused = sandbox.run(&["skills", "remove", "remove-repo"]);
    assert_eq!(refused.code, 2, "{} {}", refused.stdout, refused.stderr);
    assert!(sandbox.home.join("skill-sources/remove-repo").exists());
    let removed = sandbox.run(&["skills", "remove", "remove-repo", "--yes", "--json"]);
    assert_eq!(removed.code, 0, "{} {}", removed.stdout, removed.stderr);
    assert!(
        removed
            .events()
            .iter()
            .any(|e| e["type"] == "skill_source" && e["status"] == "removed")
    );
    assert!(!sandbox.home.join("skill-sources/remove-repo").exists());
    let saved: Value =
        serde_json::from_str(&fs::read_to_string(sandbox.home.join("skills.json")).unwrap())
            .unwrap();
    assert!(saved["sources"].get("remove-repo").is_none());
}

#[test]
fn dir_source_installs_by_copy_and_check_detects_changes() {
    let sandbox = Sandbox::new();
    let source = sandbox._temp.path().join("plain-dir");
    fs::create_dir_all(source.join("skills/plain")).unwrap();
    put(
        &source.join("skills/plain/SKILL.md"),
        skill_text("plain", "Plain catalog"),
    );
    assert_eq!(
        sandbox
            .run(&[
                "skills",
                "install",
                &source.display().to_string(),
                "--yes",
                "--json"
            ])
            .code,
        0
    );
    put(
        &source.join("skills/plain/SKILL.md"),
        skill_text("plain", "Plain changed"),
    );
    let output = sandbox.run(&["skills", "check", "plain-dir", "--json"]);
    assert_eq!(output.code, 0, "{} {}", output.stdout, output.stderr);
    assert!(
        output
            .events()
            .iter()
            .any(|e| e["type"] == "skill_source" && e["status"] == "update_available")
    );
}

#[test]
fn pinned_sha_reports_pinned() {
    if !require_git() {
        return;
    }
    let sandbox = Sandbox::new();
    let repo = sandbox._temp.path().join("pinned-repo");
    fs::create_dir_all(&repo).unwrap();
    write_initial_repo(&repo);
    let commit = git_head(&repo);
    let output = sandbox.run(&[
        "skills",
        "install",
        &repo.display().to_string(),
        "--ref",
        &commit,
        "--yes",
        "--json",
    ]);
    assert_eq!(output.code, 0, "{} {}", output.stdout, output.stderr);
    let check = sandbox.run(&["skills", "check", "pinned-repo", "--json"]);
    assert!(
        check
            .events()
            .iter()
            .any(|e| e["type"] == "skill_source" && e["status"] == "pinned")
    );
}

fn git_head(repo: &Path) -> String {
    let output = Process::new("git")
        .args(["rev-parse", "HEAD"])
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .current_dir(repo)
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

#[test]
fn link_registers_a_foreign_skills_directory_read_only() {
    let sandbox = Sandbox::new();
    let foreign = sandbox._temp.path().join("agents-skills");
    fs::create_dir_all(foreign.join("reviewer")).unwrap();
    put(
        &foreign.join("reviewer/SKILL.md"),
        skill_text("reviewer", "Foreign reviewer"),
    );
    put(
        &foreign.join("SKILL.md"),
        skill_text("root-skill", "Root skill"),
    );
    let output = sandbox.run(&[
        "skills",
        "link",
        &foreign.display().to_string(),
        "--name",
        "agents",
        "--json",
    ]);
    assert_eq!(output.code, 0, "{} {}", output.stdout, output.stderr);
    output.assert_clean_jsonl();
    let events = output.events();
    let linked = events.iter().find(|e| e["type"] == "skill_source").unwrap();
    assert_eq!(linked["status"], "linked");
    assert_eq!(linked["skills"], 2);
    let listing = sandbox.run(&["skills", "list", "--json"]);
    let events = listing.events();
    assert!(
        events
            .iter()
            .any(|e| e["id"] == "agents:reviewer" && e["status"] == "active")
    );
    assert!(events.iter().any(|e| {
        e["type"] == "skill_source"
            && e["label"] == "agents"
            && e["root"]
                .as_str()
                .map(|r| r.ends_with("agents-skills"))
                .unwrap_or(false)
    }));
    assert!(
        fs::read_to_string(foreign.join("reviewer/SKILL.md"))
            .unwrap()
            .contains("Foreign reviewer"),
        "linked files must not be modified"
    );
}

#[test]
fn link_rejects_roots_inside_home_and_invalid_labels() {
    let sandbox = Sandbox::new();
    let inside = sandbox.home.join("skills");
    fs::create_dir_all(&inside).unwrap();
    let output = sandbox.run(&[
        "skills",
        "link",
        &inside.display().to_string(),
        "--name",
        "inner",
    ]);
    assert_eq!(output.code, 2, "{} {}", output.stdout, output.stderr);
    let bad = sandbox.run(&[
        "skills",
        "link",
        &sandbox._temp.path().display().to_string(),
        "--name",
        "Bad!",
    ]);
    assert_eq!(bad.code, 2, "{} {}", bad.stdout, bad.stderr);
}

#[test]
fn unlink_removes_the_entry_without_touching_files() {
    let sandbox = Sandbox::new();
    let foreign = sandbox._temp.path().join("agents-skills");
    fs::create_dir_all(foreign.join("one")).unwrap();
    put(&foreign.join("one/SKILL.md"), skill_text("one", "Foreign"));
    assert_eq!(
        sandbox
            .run(&[
                "skills",
                "link",
                &foreign.display().to_string(),
                "--name",
                "agents",
                "--json"
            ])
            .code,
        0
    );
    let output = sandbox.run(&["skills", "unlink", "agents", "--json"]);
    assert_eq!(output.code, 0, "{} {}", output.stdout, output.stderr);
    assert!(
        output
            .events()
            .iter()
            .any(|e| e["type"] == "skill_source" && e["status"] == "unlinked")
    );
    let listing = sandbox.run(&["skills", "list", "--json"]);
    assert!(!listing.events().iter().any(|e| e["id"] == "agents:one"));
    assert!(foreign.join("one/SKILL.md").is_file());
}

#[test]
fn symlink_collections_in_linked_roots_are_visible() {
    let sandbox = Sandbox::new();
    let real = sandbox._temp.path().join("real-skills/real-one");
    fs::create_dir_all(&real).unwrap();
    put(&real.join("SKILL.md"), skill_text("real-one", "Real skill"));
    let collection = sandbox._temp.path().join("collection");
    fs::create_dir_all(&collection).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real, collection.join("alias")).unwrap();
    let output = sandbox.run(&[
        "skills",
        "link",
        &collection.display().to_string(),
        "--name",
        "coll",
        "--json",
    ]);
    #[cfg(unix)]
    {
        assert_eq!(output.code, 0, "{} {}", output.stdout, output.stderr);
        assert_eq!(
            output
                .events()
                .iter()
                .find(|e| e["type"] == "skill_source")
                .unwrap()["skills"],
            1
        );
        let listing = sandbox.run(&["skills", "list", "--json"]);
        assert!(listing.events().iter().any(|e| e["id"] == "coll:real-one"));
    }
    #[cfg(not(unix))]
    assert_eq!(output.code, 2, "{} {}", output.stdout, output.stderr);
}

#[test]
fn install_runs_from_the_model_shell_with_user_approval() {
    if !require_git() {
        return;
    }
    let sandbox = Sandbox::new();
    let repo = sandbox._temp.path().join("shell-repo");
    fs::create_dir_all(&repo).unwrap();
    write_initial_repo(&repo);
    let output = Process::new(sandbox.binary())
        .args([
            "skills",
            "install",
            &repo.display().to_string(),
            "--yes",
            "--json",
        ])
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", &sandbox.home)
        .env("RCODE_HOME", &sandbox.home)
        .env("RCODE_MODEL_SHELL", "1")
        .current_dir(&sandbox.project)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        sandbox
            .home
            .join("skill-sources/shell-repo/skills/one/SKILL.md")
            .is_file()
    );

    let refused = Process::new(sandbox.binary())
        .args(["websearch", "provider", "brave", "--json"])
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", &sandbox.home)
        .env("RCODE_HOME", &sandbox.home)
        .env("RCODE_MODEL_SHELL", "1")
        .current_dir(&sandbox.project)
        .output()
        .unwrap();
    assert_eq!(
        refused.status.code(),
        Some(2),
        "ключи поиска из shell модели недоступны"
    );
}
