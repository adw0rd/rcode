use rcode::memory::{MemoryId, MemoryScope, MemoryStore, now_utc_rfc3339, serialize_memory_note};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as Process;
use tempfile::TempDir;

struct Sandbox {
    _temp: TempDir,
    home: PathBuf,
    project_a: PathBuf,
    project_b: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("rcode-home");
        let project_a = temp.path().join("project-a");
        let project_b = temp.path().join("project-b");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&project_a).unwrap();
        fs::create_dir_all(&project_b).unwrap();
        Self {
            _temp: temp,
            home,
            project_a,
            project_b,
        }
    }

    fn binary(&self) -> &'static str {
        env!("CARGO_BIN_EXE_rcode")
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_in(&self.project_a, args, &[])
    }

    fn run_in(&self, dir: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
        let stdout = tempfile::tempfile().unwrap();
        let stderr = tempfile::tempfile().unwrap();
        let mut cmd = Process::new(self.binary());
        cmd.args(args)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("RCODE_HOME", &self.home)
            .stdin(std::process::Stdio::null())
            .stdout(stdout.try_clone().unwrap())
            .stderr(stderr.try_clone().unwrap())
            .current_dir(dir);
        for name in ["TMPDIR", "TEMP", "TMP", "SYSTEMROOT"] {
            if let Some(val) = std::env::var_os(name) {
                cmd.env(val_key(name), val);
            }
        }
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        let status = cmd.status().unwrap();
        Output {
            code: status.code().unwrap_or(-1),
            stdout: read_temp(stdout),
            stderr: read_temp(stderr),
        }
    }
}

fn val_key(name: &str) -> &str {
    name
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
}

fn read_temp(mut file: fs::File) -> String {
    use std::io::{Read, Seek};
    file.rewind().unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn seed_note(
    home: &Path,
    project: &Path,
    scope: MemoryScope,
    slug: &str,
    desc: &str,
    aliases: &[&str],
    body: &str,
) {
    let store = MemoryStore::new(home);
    let id = MemoryId::new(scope, slug).unwrap();
    let alias_vec: Vec<String> = aliases.iter().map(|s| (*s).to_owned()).collect();
    let doc =
        serialize_memory_note(slug, desc, scope, &alias_vec, &now_utc_rfc3339(), body).unwrap();
    store
        .commit_write(project, &id, "create", None, &doc, &[], None)
        .unwrap();
}

#[test]
fn empty_memory_status_and_list_never_create_manifest_on_disk() {
    let sb = Sandbox::new();
    let out = sb.run(&["memory", "status"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(
        out.stdout.contains("Межсессионная память"),
        "{}",
        out.stdout
    );
    assert!(!sb.home.join("memory.json").exists());

    let json_out = sb.run(&["--json", "memory", "status"]);
    assert_eq!(json_out.code, 0, "{}", json_out.stderr);
    let events = json_out.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["type"], "memory_status");
    assert_eq!(events[0]["status"], "enabled");
    assert_eq!(events[0]["counts"]["total"], 0);
    assert_eq!(events[0]["counts"]["sent_with_description"], 0);
    assert_eq!(events[0]["counts"]["sent_id_only"], 0);
    assert_eq!(events[0]["counts"]["omitted"], 0);

    let list_out = sb.run(&["memory", "list"]);
    assert_eq!(list_out.code, 0, "{}", list_out.stderr);
    assert!(
        list_out.stdout.contains("Заметок памяти не найдено"),
        "{}",
        list_out.stdout
    );
    assert!(!sb.home.join("memory.json").exists());
}

#[test]
fn enable_disable_and_auto_write_persist_manifest_and_rotate_backups() {
    let sb = Sandbox::new();

    let dis_proj = sb.run(&["memory", "disable", "--project"]);
    assert_eq!(dis_proj.code, 0, "{}", dis_proj.stderr);
    assert!(sb.home.join("memory.json").exists());

    let st1 = sb.run(&["--json", "memory", "status"]).events();
    assert_eq!(st1[0]["status"], "disabled_project");
    assert_eq!(st1[0]["project_enabled"], false);

    // Other project remains enabled.
    let st_b = sb
        .run_in(&sb.project_b, &["--json", "memory", "status"], &[])
        .events();
    assert_eq!(st_b[0]["status"], "enabled");

    let en_proj = sb.run(&["memory", "enable", "--project"]);
    assert_eq!(en_proj.code, 0, "{}", en_proj.stderr);
    let st2 = sb.run(&["--json", "memory", "status"]).events();
    assert_eq!(st2[0]["status"], "enabled");

    let dis_global = sb.run(&["memory", "disable"]);
    assert_eq!(dis_global.code, 0, "{}", dis_global.stderr);
    let st3 = sb.run(&["--json", "memory", "status"]).events();
    assert_eq!(st3[0]["status"], "disabled_global");
    assert_eq!(st3[0]["enabled"], false);

    let en_global = sb.run(&["memory", "enable"]);
    assert_eq!(en_global.code, 0, "{}", en_global.stderr);

    let auto_out = sb.run(&[
        "--json",
        "memory",
        "auto-write",
        "--project",
        "on",
        "--global",
        "off",
    ]);
    assert_eq!(auto_out.code, 0, "{}", auto_out.stderr);
    let auto_ev = auto_out.events();
    assert_eq!(auto_ev[0]["auto_write_project"], true);
    assert_eq!(auto_ev[0]["auto_write_global"], false);

    // Backups of memory.json were created and bounded <= 5.
    let backups_dir = sb.home.join("backups");
    let backups: Vec<_> = fs::read_dir(&backups_dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with("memory.json."))
        .collect();
    assert!(
        !backups.is_empty() && backups.len() <= 5,
        "backups={}",
        backups.len()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for entry in &backups {
            let mode = entry.metadata().unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}

#[test]
fn unknown_manifest_version_fails_closed_without_overwriting_file() {
    let sb = Sandbox::new();
    let future_manifest = json!({
        "version": 99,
        "enabled": true,
        "future_field": "preserve-me"
    })
    .to_string();
    let manifest_path = sb.home.join("memory.json");
    fs::write(&manifest_path, &future_manifest).unwrap();

    for cmd in [
        &["memory", "status"][..],
        &["memory", "enable"][..],
        &["memory", "clear", "--yes"][..],
    ] {
        let out = sb.run(cmd);
        assert_ne!(out.code, 0, "cmd {cmd:?} should fail closed on v99");
    }
    assert_eq!(fs::read_to_string(&manifest_path).unwrap(), future_manifest);
}

#[test]
fn note_lifecycle_list_show_log_diff_undo_conflict_and_rm_purge() {
    let sb = Sandbox::new();
    seed_note(
        &sb.home,
        &sb.project_a,
        MemoryScope::Project,
        "arch",
        "Cargo workspace architecture rules",
        &["cargo", "workspace"],
        "- [stated] Run cargo test --locked.\n",
    );
    seed_note(
        &sb.home,
        &sb.project_b,
        MemoryScope::Project,
        "other-proj",
        "Other project conventions",
        &["other"],
        "- [stated] Python 3.12.\n",
    );
    seed_note(
        &sb.home,
        &sb.project_a,
        MemoryScope::Global,
        "style",
        "Global Russian communication rule",
        &["lang"],
        "- [stated] Communicate in Russian.\n",
    );

    // Status counts 2 notes in project_a (1 project + 1 global).
    let st = sb.run(&["--json", "memory", "status"]).events();
    assert_eq!(st[0]["counts"]["total"], 2);
    assert_eq!(st[0]["counts"]["project"], 1);
    assert_eq!(st[0]["counts"]["global"], 1);
    assert_eq!(st[0]["counts"]["sent_with_description"], 2);

    // List current vs query vs all-projects.
    let list_cur = sb.run(&["--json", "memory", "list"]).events();
    assert_eq!(list_cur.len(), 2);

    let list_query = sb
        .run(&["--json", "memory", "list", "--query", "workspace"])
        .events();
    assert_eq!(list_query.len(), 1);
    assert_eq!(list_query[0]["id"], "project/arch");

    let list_all = sb
        .run(&["--json", "memory", "list", "--scope", "all-projects"])
        .events();
    assert_eq!(list_all.len(), 3);

    // Show note.
    let show_out = sb.run(&["memory", "show", "project/arch"]);
    assert_eq!(show_out.code, 0, "{}", show_out.stderr);
    assert!(
        show_out.stdout.contains("cargo test --locked"),
        "{}",
        show_out.stdout
    );

    let show_json = sb
        .run(&["--json", "memory", "show", "project/arch"])
        .events();
    let note_path = PathBuf::from(show_json[0]["path"].as_str().unwrap());
    let first_sha = show_json[0]["sha256"].as_str().unwrap().to_owned();

    // Second revision via MemoryStore commit_write so we have 2 revisions for log/diff/undo.
    let store = MemoryStore::new(&sb.home);
    let id = MemoryId::parse("project/arch").unwrap();
    let updated_doc = serialize_memory_note(
        "arch",
        "Cargo workspace architecture rules",
        MemoryScope::Project,
        &["cargo".into(), "workspace".into()],
        &now_utc_rfc3339(),
        "- [stated] Run cargo clippy --all-targets -- -D warnings.\n",
    )
    .unwrap();
    store
        .commit_write(
            &sb.project_a,
            &id,
            "replace",
            Some(&first_sha),
            &updated_doc,
            &[],
            None,
        )
        .unwrap();

    // Log & diff.
    let log_events = sb
        .run(&["--json", "memory", "log", "project/arch"])
        .events();
    assert_eq!(log_events.len(), 2);
    let latest_rev_id = log_events[0]["revision_id"].as_str().unwrap().to_owned();

    let diff_out = sb.run(&["memory", "diff", "project/arch", &latest_rev_id]);
    assert_eq!(diff_out.code, 0, "{}", diff_out.stderr);
    assert!(
        diff_out.stdout.contains("cargo clippy"),
        "{}",
        diff_out.stdout
    );

    // Manual edit on disk causes CAS undo conflict unless --force is given!
    let manual_doc = updated_doc.replace("clippy", "fmt");
    fs::write(&note_path, &manual_doc).unwrap();

    let undo_conflict = sb.run(&["memory", "undo", "project/arch"]);
    assert_ne!(undo_conflict.code, 0);
    assert_eq!(fs::read_to_string(&note_path).unwrap(), manual_doc);

    let undo_forced = sb.run(&["memory", "undo", "project/arch", "--force"]);
    assert_eq!(undo_forced.code, 0, "{}", undo_forced.stderr);
    let restored_show = sb.run(&["memory", "show", "project/arch"]);
    assert!(
        restored_show.stdout.contains("cargo test --locked"),
        "{}",
        restored_show.stdout
    );

    // Reversible rm followed by undo restores the deleted note!
    let rm_soft = sb.run(&["memory", "rm", "project/arch"]);
    assert_eq!(rm_soft.code, 0, "{}", rm_soft.stderr);
    assert!(!note_path.exists());

    let undo_rm = sb.run(&["memory", "undo", "project/arch"]);
    assert_eq!(undo_rm.code, 0, "{}", undo_rm.stderr);
    assert!(note_path.exists());

    // rm --purge deletes both the note and all its revisions in .revisions/!
    let rm_purge = sb.run(&["memory", "rm", "--purge", "project/arch"]);
    assert_eq!(rm_purge.code, 0, "{}", rm_purge.stderr);
    assert!(!note_path.exists());
    let log_after_purge = sb
        .run(&["--json", "memory", "log", "project/arch"])
        .events();
    assert!(log_after_purge.is_empty());
}

#[cfg(unix)]
#[test]
fn edit_command_creates_and_updates_note_via_mock_editor_and_rejects_secrets() {
    use std::os::unix::fs::PermissionsExt;

    let sb = Sandbox::new();
    let editor_ok = sb.home.join("mock-editor-ok.sh");
    fs::write(
        &editor_ok,
        "#!/bin/sh\ncat > \"$1\" <<'EOF'\n---\nname: workflow\ndescription: \"Git branch rules\"\nscope: project\naliases: \"git, pr\"\nupdated_at: 2026-11-13T00:00:00Z\n---\n- [stated] Always run clippy before PR.\nEOF\n",
    )
    .unwrap();
    fs::set_permissions(&editor_ok, fs::Permissions::from_mode(0o700)).unwrap();

    let edit_create = sb.run_in(
        &sb.project_a,
        &["memory", "edit", "project/workflow"],
        &[("EDITOR", editor_ok.to_str().unwrap())],
    );
    assert_eq!(edit_create.code, 0, "{}", edit_create.stderr);

    let shown = sb.run(&["memory", "show", "project/workflow"]);
    assert_eq!(shown.code, 0, "{}", shown.stderr);
    assert!(shown.stdout.contains("Always run clippy before PR."));

    // Attempt to inject a GitHub token via editor -> rejected fail-closed without mutating disk!
    let editor_secret = sb.home.join("mock-editor-secret.sh");
    let fake_ghp = format!("ghp_{}", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8");
    fs::write(
        &editor_secret,
        format!(
            "#!/bin/sh\ncat > \"$1\" <<'EOF'\n---\nname: workflow\ndescription: \"Git branch rules\"\nscope: project\nupdated_at: 2026-11-13T00:00:00Z\n---\nToken {fake_ghp}\nEOF\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&editor_secret, fs::Permissions::from_mode(0o700)).unwrap();

    let edit_bad = sb.run_in(
        &sb.project_a,
        &["memory", "edit", "project/workflow"],
        &[("EDITOR", editor_secret.to_str().unwrap())],
    );
    assert_ne!(edit_bad.code, 0);
    let shown_after = sb.run(&["memory", "show", "project/workflow"]);
    assert!(shown_after.stdout.contains("Always run clippy before PR."));
    assert!(!shown_after.stdout.contains(&fake_ghp));
}

#[test]
fn clear_requires_yes_without_tty_and_supports_all_projects_and_purge() {
    let sb = Sandbox::new();
    seed_note(
        &sb.home,
        &sb.project_a,
        MemoryScope::Project,
        "a1",
        "Note A",
        &[],
        "- [stated] A\n",
    );
    seed_note(
        &sb.home,
        &sb.project_b,
        MemoryScope::Project,
        "b1",
        "Note B",
        &[],
        "- [stated] B\n",
    );
    seed_note(
        &sb.home,
        &sb.project_a,
        MemoryScope::Global,
        "g1",
        "Note G",
        &[],
        "- [stated] G\n",
    );

    // Without --yes and without TTY, clear refuses and leaves all 3 notes intact.
    let refused = sb.run(&["memory", "clear"]);
    assert_ne!(refused.code, 0);
    assert_eq!(
        sb.run(&["--json", "memory", "list", "--scope", "all-projects"])
            .events()
            .len(),
        3
    );

    // Clear only current project (project_a) with --yes: project_b and global survive!
    let clr_proj = sb.run(&["--json", "memory", "clear", "--scope", "project", "--yes"]);
    assert_eq!(clr_proj.code, 0, "{}", clr_proj.stderr);
    assert_eq!(
        sb.run(&["--json", "memory", "list", "--scope", "all-projects"])
            .events()
            .len(),
        2
    );

    // Clear --all-projects --purge --yes wipes remaining project_b while preserving global/g1!
    let clr_all_proj = sb.run(&[
        "--json",
        "memory",
        "clear",
        "--all-projects",
        "--purge",
        "--yes",
    ]);
    assert_eq!(clr_all_proj.code, 0, "{}", clr_all_proj.stderr);
    let remaining = sb
        .run(&["--json", "memory", "list", "--scope", "all-projects"])
        .events();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0]["id"], "global/g1");

    // Clear --scope global --purge --yes wipes global/g1!
    let clr_global = sb.run(&[
        "--json", "memory", "clear", "--scope", "global", "--purge", "--yes",
    ]);
    assert_eq!(clr_global.code, 0, "{}", clr_global.stderr);
    assert!(
        sb.run(&["--json", "memory", "list", "--scope", "all-projects"])
            .events()
            .is_empty()
    );
}

#[test]
fn model_shell_and_eval_mode_guards_protect_memory_cli() {
    let sb = Sandbox::new();
    seed_note(
        &sb.home,
        &sb.project_a,
        MemoryScope::Project,
        "note1",
        "Safe note",
        &[],
        "- [stated] Safe\n",
    );

    // RCODE_MODEL_SHELL=1 allows read-only subcommands and blocks all mutating subcommands!
    for ro_cmd in [
        &["memory", "status"][..],
        &["memory", "list"][..],
        &["memory", "show", "project/note1"][..],
    ] {
        let out = sb.run_in(&sb.project_a, ro_cmd, &[("RCODE_MODEL_SHELL", "1")]);
        assert_eq!(out.code, 0, "read-only {ro_cmd:?} failed: {}", out.stderr);
    }
    for mut_cmd in [
        &["memory", "disable"][..],
        &["memory", "enable"][..],
        &["memory", "auto-write", "--project", "on"][..],
        &["memory", "rm", "project/note1"][..],
        &["memory", "undo", "project/note1"][..],
        &["memory", "clear", "--yes"][..],
    ] {
        let out = sb.run_in(&sb.project_a, mut_cmd, &[("RCODE_MODEL_SHELL", "1")]);
        assert_ne!(
            out.code, 0,
            "mutating {mut_cmd:?} must be blocked in RCODE_MODEL_SHELL=1"
        );
    }

    // RCODE_EVAL_MODE=1 blocks ALL memory subcommands including status and list!
    for eval_cmd in [&["memory", "status"][..], &["memory", "list"][..]] {
        let out = sb.run_in(&sb.project_a, eval_cmd, &[("RCODE_EVAL_MODE", "1")]);
        assert_ne!(
            out.code, 0,
            "{eval_cmd:?} must be blocked in RCODE_EVAL_MODE=1"
        );
    }
}

#[test]
fn json_edit_fails_closed_before_spawning_editor() {
    let sb = Sandbox::new();
    let marker = sb.home.join("editor-ran-marker");
    let fake_cmd = format!("sh -c 'touch {}'", marker.display());
    let out = sb.run_in(
        &sb.project_a,
        &["--json", "memory", "edit", "global/prefs"],
        &[("EDITOR", &fake_cmd)],
    );
    assert_ne!(out.code, 0, "memory edit must fail in --json mode");
    assert!(!marker.exists(), "editor must not be spawned in --json");
    let events = out.events();
    assert_eq!(events.len(), 1, "stdout={}", out.stdout);
    assert_eq!(events[0]["type"], "error");
}

#[test]
fn purge_cleans_orphan_revisions_of_already_deleted_notes_in_rm_and_clear() {
    let sb = Sandbox::new();
    seed_note(
        &sb.home,
        &sb.project_a,
        MemoryScope::Project,
        "secret-oops",
        "Accidental note",
        &[],
        "- [stated] First version.\n",
    );
    seed_note(
        &sb.home,
        &sb.project_a,
        MemoryScope::Project,
        "second-oops",
        "Second note",
        &[],
        "- [stated] Second version.\n",
    );

    // Operator runs soft `rm` first -> `.md` is gone, `.revisions/` still holds `prev_content`.
    let rm1 = sb.run(&["memory", "rm", "project/secret-oops"]);
    assert_eq!(rm1.code, 0, "{}", rm1.stderr);
    assert_eq!(
        sb.run(&["--json", "memory", "log", "project/secret-oops"])
            .events()
            .len(),
        2
    );

    // Follow-up `rm --purge` on the already-deleted note succeeds and wipes `.revisions/`!
    let purge1 = sb.run(&["--json", "memory", "rm", "--purge", "project/secret-oops"]);
    assert_eq!(purge1.code, 0, "{}", purge1.stderr);
    let ev = purge1.events();
    assert_eq!(ev[0]["type"], "memory_deleted");
    assert!(ev[0]["deleted_sha256"].is_null());
    assert_eq!(ev[0]["purged_revisions"], true);
    assert_eq!(ev[0]["purged_revisions_count"], 2);
    assert!(
        sb.run(&["--json", "memory", "log", "project/secret-oops"])
            .events()
            .is_empty()
    );

    // Same two-step flow via `clear --purge --yes`: soft `rm` first, then `clear --purge --yes`!
    let rm2 = sb.run(&["memory", "rm", "project/second-oops"]);
    assert_eq!(rm2.code, 0, "{}", rm2.stderr);
    assert_eq!(
        sb.run(&["--json", "memory", "log", "project/second-oops"])
            .events()
            .len(),
        2
    );
    let clr_purge = sb.run(&[
        "--json", "memory", "clear", "--scope", "project", "--purge", "--yes",
    ]);
    assert_eq!(clr_purge.code, 0, "{}", clr_purge.stderr);
    assert!(
        sb.run(&["--json", "memory", "log", "project/second-oops"])
            .events()
            .is_empty()
    );
}

#[test]
fn corrupted_revision_file_fails_cleanly_without_panicking_in_log_and_undo() {
    let sb = Sandbox::new();
    seed_note(
        &sb.home,
        &sb.project_a,
        MemoryScope::Global,
        "corrupt-rev",
        "Note with bad revision",
        &[],
        "- [stated] Clean note.\n",
    );
    let rev_dir = sb.home.join("memory").join(".revisions");
    let bad_rev = rev_dir.join("global__corrupt-rev__99999999999999999999.json");
    let bad_json = json!({
        "version": 1,
        "revision_id": "99999999999999999999",
        "op": "replace",
        "scope": "global",
        "name": "corrupt-rev",
        "created_at": "2026-11-13T00:00:00Z",
        "prev_sha256": "кириллица",
        "post_sha256": "abcd",
        "prev_content": "mismatch"
    })
    .to_string();
    fs::write(&bad_rev, bad_json).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&bad_rev, fs::Permissions::from_mode(0o600)).unwrap();
    }

    for cmd in [
        &["memory", "log", "global/corrupt-rev"][..],
        &["memory", "undo", "global/corrupt-rev"][..],
    ] {
        let out = sb.run(cmd);
        assert_ne!(out.code, 0, "{cmd:?} must reject corrupted revision");
        assert!(
            !out.stderr.contains("panicked at"),
            "must not panic: {}",
            out.stderr
        );
    }
}

#[test]
fn status_reports_stored_counts_when_disabled_and_zero_write_schema_in_plan_mode() {
    let sb = Sandbox::new();
    // Plan mode on empty memory: neither read_memory nor write_memory is active -> schema_chars == 0.
    let plan_empty = sb.run(&["--plan", "--json", "memory", "status"]).events();
    assert_eq!(plan_empty[0]["budget"]["schema_chars"], 0);

    seed_note(
        &sb.home,
        &sb.project_a,
        MemoryScope::Project,
        "p1",
        "Project note",
        &[],
        "- [stated] P1\n",
    );
    seed_note(
        &sb.home,
        &sb.project_a,
        MemoryScope::Global,
        "g1",
        "Global note",
        &[],
        "- [stated] G1\n",
    );

    // Plan mode with notes: read_memory is active, write_memory is not.
    let normal_st = sb.run(&["--json", "memory", "status"]).events();
    let plan_st = sb.run(&["--plan", "--json", "memory", "status"]).events();
    let normal_schema = normal_st[0]["budget"]["schema_chars"].as_u64().unwrap();
    let plan_schema = plan_st[0]["budget"]["schema_chars"].as_u64().unwrap();
    assert!(plan_schema > 0 && plan_schema < normal_schema);

    // When disabled globally: active context counts are 0, stored counts remain 2 (1 + 1), schema_chars == 0.
    assert_eq!(sb.run(&["memory", "disable"]).code, 0);
    let dis_st = sb.run(&["--json", "memory", "status"]).events();
    assert_eq!(dis_st[0]["status"], "disabled_global");
    assert_eq!(dis_st[0]["counts"]["total"], 0);
    assert_eq!(dis_st[0]["counts"]["stored_total"], 2);
    assert_eq!(dis_st[0]["counts"]["stored_project"], 1);
    assert_eq!(dis_st[0]["counts"]["stored_global"], 1);
    assert_eq!(dis_st[0]["budget"]["schema_chars"], 0);
}

#[test]
fn rcode_home_inside_project_is_rejected_and_diff_handles_deleted_or_escaped_secret_notes() {
    let sb = Sandbox::new();
    let nested_home = sb.project_a.join(".state-inside-repo");
    let nested_str = nested_home.to_str().unwrap();

    // Even before `.state-inside-repo` exists, `rcode memory` rejects storing/reading inside project_root
    // BEFORE ConfigStore::new() creates directories or migrates state!
    for cmd in [
        &["memory", "status"][..],
        &["memory", "enable"][..],
        &["memory", "list"][..],
    ] {
        let out = sb.run_in(&sb.project_a, cmd, &[("RCODE_HOME", nested_str)]);
        assert_ne!(out.code, 0, "{cmd:?} must reject RCODE_HOME inside project");
        assert!(
            !nested_home.exists(),
            "ConfigStore::new() must not create {nested_home:?} inside project_root"
        );
    }

    // Seed a valid note, delete it softly, and verify `rcode memory diff` works without unwrap panic!
    seed_note(
        &sb.home,
        &sb.project_a,
        MemoryScope::Global,
        "diff-del",
        "Diff deleted test",
        &[],
        "- [stated] Line before delete.\n",
    );
    assert_eq!(sb.run(&["memory", "rm", "global/diff-del"]).code, 0);
    let revs = sb
        .run(&["--json", "memory", "log", "global/diff-del"])
        .events();
    let del_rev = revs[0]["revision_id"].as_str().unwrap();
    let diff_deleted = sb.run(&["memory", "diff", "global/diff-del", del_rev]);
    assert_eq!(diff_deleted.code, 0, "{}", diff_deleted.stderr);
    assert!(
        diff_deleted
            .stdout
            .contains("-- [stated] Line before delete."),
        "stdout={}",
        diff_deleted.stdout
    );

    // Restore via undo, then write a frontmatter `\u0073k-...` secret onto disk:
    // both `memory show` and `memory diff` must fail closed!
    assert_eq!(sb.run(&["memory", "undo", "global/diff-del"]).code, 0);
    let escaped = "---\nname: diff-del\ndescription: \"\\u0073k-1234567890abcdefghijklmnop\"\nscope: global\nupdated_at: 2026-11-13T00:00:00Z\n---\n- [stated] Line before delete.\n";
    let path = sb.home.join("memory/global/diff-del.md");
    fs::write(&path, escaped).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert_ne!(sb.run(&["memory", "show", "global/diff-del"]).code, 0);
    assert_ne!(
        sb.run(&["memory", "diff", "global/diff-del", del_rev]).code,
        0
    );
    assert!(sb.run(&["--json", "memory", "list"]).events().is_empty());
    assert!(
        sb.run(&["--json", "memory", "list", "--scope", "all-projects"])
            .events()
            .is_empty()
    );
}
