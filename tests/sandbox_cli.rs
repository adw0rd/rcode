use serde_json::Value;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

struct SandboxCliFixture {
    _temp: TempDir,
    home: PathBuf,
    rcode_home: PathBuf,
    project_a: PathBuf,
    #[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
    project_b: PathBuf,
}

struct CmdOutput {
    code: i32,
    stdout: String,
    stderr: String,
}

impl SandboxCliFixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("user-home");
        let rcode_home = temp.path().join("rcode-home");
        let project_a = temp.path().join("project-a");
        let project_b = temp.path().join("project-b");
        for dir in [&home, &rcode_home, &project_a, &project_b] {
            fs::create_dir_all(dir).unwrap();
        }
        Self {
            _temp: temp,
            home,
            rcode_home,
            project_a,
            project_b,
        }
    }

    fn run(&self, args: &[&str]) -> CmdOutput {
        self.run_in(&self.project_a, args, &[])
    }

    fn run_in(&self, dir: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> CmdOutput {
        let mut stdout_file = tempfile::tempfile().unwrap();
        let mut stderr_file = tempfile::tempfile().unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rcode"));
        cmd.args(args)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("RCODE_HOME", &self.rcode_home)
            .stdin(std::process::Stdio::null())
            .stdout(stdout_file.try_clone().unwrap())
            .stderr(stderr_file.try_clone().unwrap())
            .current_dir(dir);
        for key in ["TMPDIR", "TEMP", "TMP", "SYSTEMROOT"] {
            if let Some(val) = std::env::var_os(key) {
                cmd.env(key, val);
            }
        }
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        let status = cmd.status().unwrap();
        let mut stdout = String::new();
        let mut stderr = String::new();
        stdout_file.seek(SeekFrom::Start(0)).unwrap();
        stderr_file.seek(SeekFrom::Start(0)).unwrap();
        stdout_file.read_to_string(&mut stdout).unwrap();
        stderr_file.read_to_string(&mut stderr).unwrap();
        CmdOutput {
            code: status.code().unwrap_or(-1),
            stdout,
            stderr,
        }
    }
}

fn parse_last_json_event(stdout: &str, event_name: &str) -> Value {
    stdout
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .rfind(|v| v["type"] == event_name)
        .unwrap_or_else(|| panic!("missing event {event_name:?} in stdout:\n{stdout}"))
}

#[test]
fn sandbox_status_and_per_project_persistence_with_flag_overrides() {
    let fx = SandboxCliFixture::new();

    let status0 = fx.run(&["sandbox", "status", "--json"]);
    assert_eq!(status0.code, 0, "stderr={}", status0.stderr);
    let ev0 = parse_last_json_event(&status0.stdout, "sandbox");
    assert_eq!(ev0["saved"]["mode"], "off");
    assert_eq!(ev0["saved"]["network"], false);
    assert_eq!(ev0["effective"]["mode"], "off");
    assert_eq!(ev0["effective"]["network"], false);

    // Human-readable `off` status must NOT mislead with "сеть заблокирована".
    let status0_text = fx.run(&["sandbox", "status"]);
    assert_eq!(status0_text.code, 0, "stderr={}", status0_text.stderr);
    assert!(
        status0_text.stdout.contains("без ограничений песочницы")
            && status0_text.stdout.contains("песочница выключена"),
        "stdout={}",
        status0_text.stdout
    );
    assert!(
        !status0_text.stdout.contains("сеть заблокирована"),
        "stdout={}",
        status0_text.stdout
    );

    // `--sandbox-network on` with effective mode `off` must fail closed.
    let bad_net = fx.run(&["--sandbox-network", "on", "sandbox", "status"]);
    assert_ne!(bad_net.code, 0);
    assert!(
        bad_net.stderr.contains("--sandbox-network on"),
        "stderr={}",
        bad_net.stderr
    );

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        // Unsupported OS (e.g. Windows) fails closed when selecting workspace-write or read-only.
        let unsupported = fx.run(&["sandbox", "mode", "workspace-write"]);
        assert_ne!(unsupported.code, 0);
        assert!(unsupported.stderr.contains("fail-closed"));
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        assert_eq!(ev0["support"]["available"], true);

        let set_ww = fx.run(&["sandbox", "mode", "workspace-write", "--json"]);
        assert_eq!(set_ww.code, 0, "stderr={}", set_ww.stderr);
        let ev_ww = parse_last_json_event(&set_ww.stdout, "sandbox");
        assert_eq!(ev_ww["saved"]["mode"], "workspace-write");
        assert_eq!(ev_ww["effective"]["mode"], "workspace-write");
        assert_eq!(ev_ww["effective"]["network"], false);

        // Conflicting CLI override (`--sandbox-network on` + `sandbox mode off`) MUST fail
        // BEFORE mutating saved `permissions.json`!
        let conflict_mode = fx.run(&["--sandbox-network", "on", "sandbox", "mode", "off"]);
        assert_ne!(conflict_mode.code, 0);
        let after_conflict = fx.run(&["sandbox", "status", "--json"]);
        assert_eq!(after_conflict.code, 0);
        let ev_after_conflict = parse_last_json_event(&after_conflict.stdout, "sandbox");
        assert_eq!(ev_after_conflict["saved"]["mode"], "workspace-write");

        let set_net = fx.run(&["sandbox", "network", "on", "--json"]);
        assert_eq!(set_net.code, 0, "stderr={}", set_net.stderr);
        let ev_net = parse_last_json_event(&set_net.stdout, "sandbox");
        assert_eq!(ev_net["saved"]["network"], true);
        assert_eq!(ev_net["effective"]["network"], true);

        // Conflicting CLI override (`--sandbox off --sandbox-network on` + `sandbox network off`)
        // MUST fail BEFORE mutating saved `network = true`!
        let conflict_net = fx.run(&[
            "--sandbox",
            "off",
            "--sandbox-network",
            "on",
            "sandbox",
            "network",
            "off",
        ]);
        assert_ne!(conflict_net.code, 0);
        let after_conflict_net = fx.run(&["sandbox", "status", "--json"]);
        assert_eq!(after_conflict_net.code, 0);
        let ev_after_conflict_net = parse_last_json_event(&after_conflict_net.stdout, "sandbox");
        assert_eq!(ev_after_conflict_net["saved"]["network"], true);

        // `project_b` remains isolated (`off`).
        let status_b = fx.run_in(&fx.project_b, &["sandbox", "status", "--json"], &[]);
        assert_eq!(status_b.code, 0);
        let ev_b = parse_last_json_event(&status_b.stdout, "sandbox");
        assert_eq!(ev_b["saved"]["mode"], "off");
        assert_eq!(ev_b["effective"]["mode"], "off");

        // `--sandbox-network off` overrides saved `network = true`, and `--sandbox off` overrides saved mode.
        let override_net = fx.run(&["--sandbox-network", "off", "sandbox", "status", "--json"]);
        assert_eq!(override_net.code, 0);
        let ev_override_net = parse_last_json_event(&override_net.stdout, "sandbox");
        assert_eq!(ev_override_net["saved"]["network"], true);
        assert_eq!(ev_override_net["effective"]["mode"], "workspace-write");
        assert_eq!(ev_override_net["effective"]["network"], false);

        let override_off = fx.run(&["--sandbox", "off", "sandbox", "status", "--json"]);
        assert_eq!(override_off.code, 0);
        let ev_override_off = parse_last_json_event(&override_off.stdout, "sandbox");
        assert_eq!(ev_override_off["saved"]["mode"], "workspace-write");
        assert_eq!(ev_override_off["effective"]["mode"], "off");
        assert_eq!(ev_override_off["effective"]["network"], false);

        // Resetting back to default (`off` + `network off`) removes redundant entry from permissions.json
        // and rotates backups in RCODE_HOME/backups.
        assert_eq!(fx.run(&["sandbox", "network", "off"]).code, 0);
        assert_eq!(fx.run(&["sandbox", "mode", "off"]).code, 0);
        let perms_raw = fs::read_to_string(fx.rcode_home.join("permissions.json")).unwrap();
        let perms_json: Value = serde_json::from_str(&perms_raw).unwrap();
        assert!(
            perms_json.get("sandbox").is_none(),
            "default ProjectSandbox entry should be pruned: {perms_raw}"
        );
        assert!(fx.rcode_home.join("backups").is_dir());
    }
}

#[test]
fn model_shell_and_eval_guards_reject_sandbox_mutations_and_eval_flags() {
    let fx = SandboxCliFixture::new();

    // `RCODE_MODEL_SHELL=1` allows read-only status, but rejects `mode` and `network` mutations.
    let status_in_shell = fx.run_in(
        &fx.project_a,
        &["sandbox", "status", "--json"],
        &[("RCODE_MODEL_SHELL", "1")],
    );
    assert_eq!(status_in_shell.code, 0, "stderr={}", status_in_shell.stderr);

    let mode_in_shell = fx.run_in(
        &fx.project_a,
        &["sandbox", "mode", "off"],
        &[("RCODE_MODEL_SHELL", "1")],
    );
    assert_ne!(mode_in_shell.code, 0);
    assert!(mode_in_shell.stderr.contains("недоступно из shell модели"));

    let net_in_shell = fx.run_in(
        &fx.project_a,
        &["sandbox", "network", "off"],
        &[("RCODE_MODEL_SHELL", "1")],
    );
    assert_ne!(net_in_shell.code, 0);
    assert!(net_in_shell.stderr.contains("недоступно из shell модели"));

    // `RCODE_EVAL_MODE=1` disables `rcode sandbox` completely.
    let eval_env = fx.run_in(
        &fx.project_a,
        &["sandbox", "status"],
        &[("RCODE_EVAL_MODE", "1")],
    );
    assert_ne!(eval_env.code, 0);
    assert!(eval_env.stderr.contains("rcode eval"));

    // `rcode eval run` rejects `--sandbox` and `--sandbox-network` global flags.
    let eval_flag = fx.run(&[
        "--sandbox",
        "off",
        "--profile",
        "local-test",
        "eval",
        "run",
        "--yes",
        "--suite",
        "suite.json",
        "--report",
        "report.json",
        "--agent-binary",
        "rcode",
        "--image",
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "--docker-socket",
        "/var/run/docker.sock",
        "--series",
        "s1",
    ]);
    assert_ne!(eval_flag.code, 0);
    assert!(
        eval_flag.stderr.contains("несовместимые глобальные флаги"),
        "stderr={}",
        eval_flag.stderr
    );
}
