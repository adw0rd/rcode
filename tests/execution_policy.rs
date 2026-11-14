use rcode::sandbox::{SandboxBackend, SandboxConfig};

#[test]
fn validation_is_read_only_and_off_preserves_literal_argv() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let before: Vec<_> = std::fs::read_dir(&root).unwrap().collect();
    let config = SandboxConfig::default();
    config.validate(&root).unwrap();
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), before.len());
    let argv = vec![
        "a".into(),
        "literal space".into(),
        "$never-evaluated".into(),
    ];
    assert_eq!(config.wrap(&root, &argv).unwrap(), argv);
    assert!(
        SandboxConfig {
            version: 99,
            ..config
        }
        .wrap(&root, &argv)
        .is_err()
    );
}

#[cfg(target_os = "macos")]
#[test]
fn live_macos_sandbox_allows_workspace_and_denies_outside_reads_writes_and_network() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        process::{Command, Stdio},
        thread,
        time::Duration,
    };
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().canonicalize().unwrap();
    let root = base.join("work");
    std::fs::create_dir(&root).unwrap();
    let outside = base.join("outside");
    std::fs::write(&outside, "HOST_CREDENTIAL_CANARY").unwrap();
    let config = SandboxConfig {
        backend: SandboxBackend::Macos,
        ..Default::default()
    };
    let run = |argv: Vec<String>| {
        let wrapped = config.wrap(&root, &argv).unwrap();
        Command::new(&wrapped[0])
            .args(&wrapped[1..])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&root)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    let allowed = run(vec![
        "/bin/sh".into(),
        "-c".into(),
        "printf allowed > allowed.txt".into(),
    ]);
    assert!(
        allowed.status.success(),
        "status={} stderr={}",
        allowed.status,
        String::from_utf8_lossy(&allowed.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(root.join("allowed.txt")).unwrap(),
        "allowed"
    );
    let read = run(vec!["/bin/cat".into(), outside.to_str().unwrap().into()]);
    assert!(!read.status.success());
    assert!(!String::from_utf8_lossy(&read.stdout).contains("HOST_CREDENTIAL_CANARY"));
    let write = run(vec![
        "/bin/sh".into(),
        "-c".into(),
        "printf changed > \"$1\"".into(),
        "sentinel".into(),
        outside.to_str().unwrap().into(),
    ]);
    assert!(!write.status.success());
    assert_eq!(
        std::fs::read_to_string(&outside).unwrap(),
        "HOST_CREDENTIAL_CANARY"
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let blocked = run(vec![
        "/usr/bin/curl".into(),
        "--noproxy".into(),
        "*".into(),
        "--connect-timeout".into(),
        "1".into(),
        url.clone(),
    ]);
    assert!(!blocked.status.success());
    assert!(matches!(listener.accept(),Err(e) if e.kind()==std::io::ErrorKind::WouldBlock));
    let accept = thread::spawn(move || {
        let start = std::time::Instant::now();
        loop {
            match listener.accept() {
                Ok((mut socket, _)) => {
                    // macOS inherits O_NONBLOCK from the listener. The HTTP
                    // peer may connect before it sends its first request bytes.
                    socket.set_nonblocking(false).unwrap();
                    socket
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut b = [0; 2048];
                    let _ = socket.read(&mut b).unwrap();
                    socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                        )
                        .unwrap();
                    return true;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if start.elapsed() >= Duration::from_secs(5) {
                        return false;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("{e}"),
            }
        }
    });
    let allow = SandboxConfig {
        network: true,
        ..config
    };
    let argv = allow
        .wrap(
            &root,
            &[
                "/usr/bin/curl".into(),
                "--noproxy".into(),
                "*".into(),
                "--connect-timeout".into(),
                "2".into(),
                url,
            ],
        )
        .unwrap();
    let connected = Command::new(&argv[0])
        .args(&argv[1..])
        .env_clear()
        .current_dir(&root)
        .output()
        .unwrap();
    let accepted = accept.join().unwrap();
    assert!(
        accepted && connected.status.success(),
        "status={} stderr={}",
        connected.status,
        String::from_utf8_lossy(&connected.stderr)
    );
    assert_eq!(connected.stdout, b"OK");
}

#[cfg(not(target_os = "macos"))]
#[test]
fn unavailable_macos_backend_does_not_spawn_a_sentinel() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let config = SandboxConfig {
        backend: SandboxBackend::Macos,
        ..Default::default()
    };
    assert!(config.wrap(&root, &["sentinel".into()]).is_err());
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
}
#[cfg(target_os = "macos")]
#[test]
fn live_macos_sandbox_cannot_read_private_homebrew_configuration() {
    use std::os::unix::fs::PermissionsExt;
    let private = tempfile::Builder::new()
        .prefix(".rcode-canary-")
        .tempdir_in(if std::path::Path::new("/opt/homebrew/etc").is_dir() {
            "/opt/homebrew/etc"
        } else {
            "/usr/local/etc"
        })
        .unwrap();
    let file = private.path().join("credentials");
    std::fs::write(&file, "PRIVATE_HOMEBREW_CANARY").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let root = workspace.path().canonicalize().unwrap();
    let cfg = SandboxConfig {
        backend: SandboxBackend::Macos,
        ..Default::default()
    };
    let argv = cfg
        .wrap(&root, &["/bin/cat".into(), file.to_str().unwrap().into()])
        .unwrap();
    let out = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .env_clear()
        .current_dir(&root)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!String::from_utf8_lossy(&out.stdout).contains("PRIVATE_HOMEBREW_CANARY"));
}
#[cfg(target_os = "macos")]
#[test]
fn live_protected_paths_override_an_explicit_read_and_write_root() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let private = root.join("private-oracle");
    std::fs::create_dir(&private).unwrap();
    std::fs::write(private.join("value"), "ORACLE_CANARY").unwrap();
    let cfg = SandboxConfig {
        backend: SandboxBackend::Macos,
        read_roots: vec![root.clone()],
        protected_paths: vec![private.clone()],
        ..Default::default()
    };
    let argv = cfg
        .wrap(
            &root,
            &[
                "/bin/cat".into(),
                private.join("value").to_str().unwrap().into(),
            ],
        )
        .unwrap();
    let out = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .env_clear()
        .current_dir(&root)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!String::from_utf8_lossy(&out.stdout).contains("ORACLE_CANARY"));
    let argv = cfg
        .wrap(
            &root,
            &[
                "/bin/sh".into(),
                "-c".into(),
                "printf changed > private-oracle/value".into(),
            ],
        )
        .unwrap();
    let out = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .env_clear()
        .current_dir(&root)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(
        std::fs::read_to_string(private.join("value")).unwrap(),
        "ORACLE_CANARY"
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod live_kernel_suite {
    use rcode::jobs::{JobKind, JobOrigin, JobSnapshot, JobSpec, JobStatus, JobsSupervisor};
    use rcode::sandbox::{EffectiveSandboxPolicy, PreparedSandbox, SandboxMode};
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    async fn run_supervised(
        policy: EffectiveSandboxPolicy,
        workspace: &Path,
        extra_roots: &[PathBuf],
        rcode_home: &Path,
        home_dir: &Path,
        script: &str,
    ) -> JobSnapshot {
        let jobs = JobsSupervisor::new(&uuid::Uuid::new_v4().to_string(), vec![]).unwrap();
        let sandbox = PreparedSandbox::prepare_with_home(
            policy,
            workspace,
            extra_roots,
            Some(rcode_home),
            Some(home_dir),
            &[],
        )
        .unwrap();
        let mut env = vec![
            (
                "PATH".to_owned(),
                std::env::var("PATH")
                    .unwrap_or_else(|_| "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin".into()),
            ),
            ("HOME".to_owned(), home_dir.to_str().unwrap().to_owned()),
        ];
        sandbox.apply_to_env(&mut env);
        let spec = JobSpec {
            kind: JobKind::Foreground,
            argv: vec!["/bin/sh".into(), "-c".into(), script.into()],
            cwd: workspace.to_path_buf(),
            env,
            origin: JobOrigin {
                actor: None,
                turn: 1,
            },
            lifetime: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(30),
            stdin: false,
            sandbox,
        };
        let cancel = CancellationToken::new();
        let started = jobs.start(spec, cancel).await.unwrap();
        let final_snap = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let view = jobs.poll(None, &started.id, 0, 0, 65536).await.unwrap();
                if view.status != JobStatus::Running {
                    break jobs.poll(None, &started.id, 0, 0, 65536).await.unwrap();
                }
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
        })
        .await
        .unwrap();
        jobs.shutdown().await.unwrap();
        final_snap
    }

    #[tokio::test]
    async fn live_kernel_workspace_write_and_read_only_enforce_filesystem_boundaries() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let workspace = base.join("workspace");
        let extra = base.join("extra-approved");
        let rcode_home = base.join("rcode-home");
        let fake_home = base.join("fake-home");
        let outside = base.join("outside");
        for dir in [
            &workspace,
            &extra,
            &rcode_home,
            &fake_home.join(".ssh"),
            &outside,
        ] {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::fs::write(workspace.join("tracked.txt"), "TRACKED_V1").unwrap();
        std::fs::write(extra.join("shared.txt"), "EXTRA_V1").unwrap();
        std::fs::write(rcode_home.join("credentials.json"), "RCODE_CRED_CANARY").unwrap();
        std::fs::write(fake_home.join(".ssh/id_ed25519"), "SSH_KEY_CANARY").unwrap();
        std::fs::write(outside.join("secret.txt"), "OUTSIDE_CANARY").unwrap();

        // Symlink inside workspace pointing to outside secret.
        std::os::unix::fs::symlink(outside.join("secret.txt"), workspace.join("escape_link"))
            .unwrap();

        // 1. Positive control (`Off`): reading outside, writing workspace, and reading via symlink succeed.
        let off_view = run_supervised(
            EffectiveSandboxPolicy::off(),
            &workspace,
            std::slice::from_ref(&extra),
            &rcode_home,
            &fake_home,
            "cat escape_link && printf ok > control.txt",
        )
        .await;
        assert_eq!(off_view.exit_code, Some(0), "stderr={}", off_view.stderr);
        assert_eq!(off_view.stdout, "OUTSIDE_CANARY");
        assert_eq!(
            std::fs::read_to_string(workspace.join("control.txt")).unwrap(),
            "ok"
        );

        // 2. `WorkspaceWrite`: workspace + extra + private TMPDIR writable; outside, RCODE_HOME,
        //    $HOME/.ssh, symlink escape, and hardlink creation all denied by kernel.
        let ww = EffectiveSandboxPolicy {
            mode: SandboxMode::WorkspaceWrite,
            network: false,
        };
        let ww_ok = run_supervised(
            ww,
            &workspace,
            std::slice::from_ref(&extra),
            &rcode_home,
            &fake_home,
            "printf ww_ok > ww.txt && printf extra_ok > \"$1/extra_written.txt\" && printf tmp_ok > \"$TMPDIR/job.txt\" && printf '%s' \"$TMPDIR\"",
            // pass extra via positional arg? run_supervised runs `sh -c script`, so embed path safely:
        )
        .await;
        // Wait: `$1` is empty in `sh -c script`; test explicit path below:
        let _ = ww_ok;
        let script_ww_ok = format!(
            "printf ww_ok > ww.txt && printf extra_ok > '{}' && printf tmp_ok > \"$TMPDIR/job.txt\" && printf '%s' \"$TMPDIR\"",
            extra.join("extra_written.txt").display()
        );
        let ww_ok = run_supervised(
            ww,
            &workspace,
            std::slice::from_ref(&extra),
            &rcode_home,
            &fake_home,
            &script_ww_ok,
        )
        .await;
        assert_eq!(ww_ok.exit_code, Some(0), "stderr={}", ww_ok.stderr);
        assert!(ww_ok.cleanup_complete);
        let job_tmp = PathBuf::from(ww_ok.stdout.trim());
        assert!(
            job_tmp
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("rcode-job-"),
            "unexpected TMPDIR: {}",
            job_tmp.display()
        );
        assert!(
            !job_tmp.exists(),
            "ShellTmp must be deleted immediately on confirmed cleanup: {}",
            job_tmp.display()
        );

        // Even if the sandboxed child strips permissions (`chmod 000`) on nested directories and `$TMPDIR` itself,
        // `jobs::finalize` restores modes without following symlinks and completes confirmed cleanup!
        let chmod_zero_view = run_supervised(
            ww,
            &workspace,
            std::slice::from_ref(&extra),
            &rcode_home,
            &fake_home,
            "mkdir -p \"$TMPDIR/locked/sub\" && printf ro > \"$TMPDIR/locked/sub/f.txt\" && chmod 0400 \"$TMPDIR/locked/sub/f.txt\" && chmod 0000 \"$TMPDIR/locked/sub\" \"$TMPDIR/locked\" \"$TMPDIR\" && printf '%s' \"$TMPDIR\"",
        )
        .await;
        assert_eq!(
            chmod_zero_view.status,
            JobStatus::Exited,
            "reason={:?} stderr={}",
            chmod_zero_view.reason,
            chmod_zero_view.stderr
        );
        assert!(chmod_zero_view.cleanup_complete);
        let chmod_zero_tmp = PathBuf::from(chmod_zero_view.stdout.trim());
        assert!(!chmod_zero_tmp.exists());
        assert_eq!(
            std::fs::read_to_string(workspace.join("ww.txt")).unwrap(),
            "ww_ok"
        );
        assert_eq!(
            std::fs::read_to_string(extra.join("extra_written.txt")).unwrap(),
            "extra_ok"
        );

        for forbidden_read in [
            rcode_home.join("credentials.json"),
            fake_home.join(".ssh/id_ed25519"),
            outside.join("secret.txt"),
            workspace.join("escape_link"),
        ] {
            let view = run_supervised(
                ww,
                &workspace,
                std::slice::from_ref(&extra),
                &rcode_home,
                &fake_home,
                &format!("cat '{}'", forbidden_read.display()),
            )
            .await;
            assert_ne!(
                view.exit_code,
                Some(0),
                "expected read denial for {}",
                forbidden_read.display()
            );
            for canary in ["RCODE_CRED_CANARY", "SSH_KEY_CANARY", "OUTSIDE_CANARY"] {
                assert!(!view.stdout.contains(canary));
                assert!(!view.stderr.contains(canary));
            }
        }

        // Write/truncate outside and through symlink + hardlink creation must fail.
        let outside_write = run_supervised(
            ww,
            &workspace,
            std::slice::from_ref(&extra),
            &rcode_home,
            &fake_home,
            &format!(
                "printf pwn > '{}' || : > '{}' || printf pwn > escape_link || ln '{}' hardlinked.txt",
                outside.join("secret.txt").display(),
                outside.join("secret.txt").display(),
                outside.join("secret.txt").display()
            ),
        )
        .await;
        assert_ne!(outside_write.exit_code, Some(0));
        assert_eq!(
            std::fs::read_to_string(outside.join("secret.txt")).unwrap(),
            "OUTSIDE_CANARY"
        );
        assert!(!workspace.join("hardlinked.txt").exists());

        // 3. `ReadOnly`: reading workspace & extra works, writing `$TMPDIR` works,
        //    writing/truncating/removing inside workspace or extra is denied by kernel!
        let ro = EffectiveSandboxPolicy {
            mode: SandboxMode::ReadOnly,
            network: false,
        };
        let ro_pos = run_supervised(
            ro,
            &workspace,
            std::slice::from_ref(&extra),
            &rcode_home,
            &fake_home,
            &format!(
                "cat tracked.txt && printf ':' && cat '{}' && printf ':tmp=' && printf ok > \"$TMPDIR/ro.txt\" && cat \"$TMPDIR/ro.txt\"",
                extra.join("shared.txt").display()
            ),
        )
        .await;
        assert_eq!(ro_pos.exit_code, Some(0), "stderr={}", ro_pos.stderr);
        assert_eq!(ro_pos.stdout, "TRACKED_V1:EXTRA_V1:tmp=ok");

        let ro_neg = run_supervised(
            ro,
            &workspace,
            std::slice::from_ref(&extra),
            &rcode_home,
            &fake_home,
            &format!(
                "printf mutated > tracked.txt || rm -f tracked.txt || printf mutated > '{}'",
                extra.join("shared.txt").display()
            ),
        )
        .await;
        assert_ne!(ro_neg.exit_code, Some(0));
        assert_eq!(
            std::fs::read_to_string(workspace.join("tracked.txt")).unwrap(),
            "TRACKED_V1"
        );
        assert_eq!(
            std::fs::read_to_string(extra.join("shared.txt")).unwrap(),
            "EXTRA_V1"
        );
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn live_macos_workspace_write_protects_dot_git_dot_rcode_signals_and_outside_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let workspace = base.join("workspace");
        let rcode_home = base.join("rcode-home");
        let fake_home = base.join("fake-home");
        let outside = base.join("outside");
        std::fs::create_dir_all(workspace.join(".git/hooks")).unwrap();
        std::fs::create_dir_all(workspace.join(".rcode")).unwrap();
        std::fs::create_dir_all(&rcode_home).unwrap();
        std::fs::create_dir_all(&fake_home).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(workspace.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::write(workspace.join(".rcode/settings.toml"), "SAFE").unwrap();
        let canary = outside.join("canary.txt");
        std::fs::write(&canary, "CANARY").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&canary, std::fs::Permissions::from_mode(0o644)).unwrap();

        let ww = EffectiveSandboxPolicy {
            mode: SandboxMode::WorkspaceWrite,
            network: false,
        };
        // Reading `.git/HEAD` succeeds, writing `.git/hooks/pre-commit` or `.rcode/settings.toml` fails.
        let git_read = run_supervised(
            ww,
            &workspace,
            &[],
            &rcode_home,
            &fake_home,
            "cat .git/HEAD",
        )
        .await;
        assert_eq!(git_read.exit_code, Some(0));
        assert!(git_read.stdout.contains("refs/heads/main"));

        let git_write = run_supervised(
            ww,
            &workspace,
            &[],
            &rcode_home,
            &fake_home,
            "printf evil > .git/hooks/pre-commit || printf evil > .rcode/settings.toml || mv .git .git-moved || mv \"$PWD\" \"$TMPDIR/moved_ws\"",
        )
        .await;
        assert_ne!(git_write.exit_code, Some(0));
        assert!(workspace.exists(), "workspace root must not be movable");
        assert!(!workspace.join(".git/hooks/pre-commit").exists());
        assert_eq!(
            std::fs::read_to_string(workspace.join(".rcode/settings.toml")).unwrap(),
            "SAFE"
        );

        // Moving and deleting regular files/dirs INSIDE workspace continues to work cleanly.
        let inside_ops = run_supervised(
            ww,
            &workspace,
            &[],
            &rcode_home,
            &fake_home,
            "mkdir sub && printf ok > sub/a.txt && mv sub/a.txt sub/b.txt && rm sub/b.txt && rmdir sub && printf inside_ok",
        )
        .await;
        assert_eq!(
            inside_ops.exit_code,
            Some(0),
            "stderr={}",
            inside_ops.stderr
        );
        assert_eq!(inside_ops.stdout, "inside_ok");

        // Symlinked `.git -> real_git_meta` inside workspace protects `real_git_meta` from writes,
        // and dangling `.git -> missing_target` fails closed during sandbox preparation!
        let sym_ws = base.join("sym-workspace");
        std::fs::create_dir_all(sym_ws.join("real_git_meta")).unwrap();
        std::fs::write(sym_ws.join("real_git_meta/config"), "CLEAN_CFG").unwrap();
        std::os::unix::fs::symlink(sym_ws.join("real_git_meta"), sym_ws.join(".git")).unwrap();
        let sym_git_write = run_supervised(
            ww,
            &sym_ws,
            &[],
            &rcode_home,
            &fake_home,
            "printf pwn > real_git_meta/config || rm -rf real_git_meta || rm -f .git",
        )
        .await;
        assert_ne!(sym_git_write.exit_code, Some(0));
        assert_eq!(
            std::fs::read_to_string(sym_ws.join("real_git_meta/config")).unwrap(),
            "CLEAN_CFG"
        );

        // Symlinked `.git -> config/gitfile` where `config/gitfile` has relative `gitdir: metadata`
        // resolves `metadata` relative to `<workspace>` (matching Git's setup.c) and protects it!
        let sym_gitfile_ws = base.join("sym-gitfile-workspace");
        std::fs::create_dir_all(sym_gitfile_ws.join("config")).unwrap();
        std::fs::create_dir_all(sym_gitfile_ws.join("metadata/hooks")).unwrap();
        std::fs::write(sym_gitfile_ws.join("config/gitfile"), "gitdir: metadata\n").unwrap();
        std::fs::write(sym_gitfile_ws.join("metadata/config"), "GITFILE_CLEAN").unwrap();
        std::os::unix::fs::symlink("config/gitfile", sym_gitfile_ws.join(".git")).unwrap();
        let sym_gitfile_write = run_supervised(
            ww,
            &sym_gitfile_ws,
            &[],
            &rcode_home,
            &fake_home,
            "printf pwn > metadata/config || printf pwn > metadata/hooks/pre-commit || printf pwn > config/gitfile",
        )
        .await;
        assert_ne!(sym_gitfile_write.exit_code, Some(0));
        assert_eq!(
            std::fs::read_to_string(sym_gitfile_ws.join("metadata/config")).unwrap(),
            "GITFILE_CLEAN"
        );
        assert!(!sym_gitfile_ws.join("metadata/hooks/pre-commit").exists());

        let dangling_ws = base.join("dangling-workspace");
        std::fs::create_dir_all(&dangling_ws).unwrap();
        std::os::unix::fs::symlink(dangling_ws.join("does-not-exist"), dangling_ws.join(".git"))
            .unwrap();
        assert!(
            PreparedSandbox::prepare_with_home(
                ww,
                &dangling_ws,
                &[],
                Some(&rcode_home),
                Some(&fake_home),
                &[],
            )
            .is_err(),
            "dangling .git symlink must fail closed"
        );

        // Ordinary `.git/` directory containing `.git/commondir` (`../shared-meta`) MUST protect
        // `shared-meta` (config/hooks) inside `workspace-write`, and multi-hop symlinks inside
        // workspace MUST protect intermediate hops from repointing!
        let common_ws = base.join("commondir-dir-workspace");
        std::fs::create_dir_all(common_ws.join(".git")).unwrap();
        std::fs::create_dir_all(common_ws.join("shared-meta/hooks")).unwrap();
        std::fs::write(common_ws.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::write(common_ws.join(".git/commondir"), "../shared-meta\n").unwrap();
        std::fs::write(common_ws.join("shared-meta/config"), "COMMON_CLEAN").unwrap();
        let common_write = run_supervised(
            ww,
            &common_ws,
            &[],
            &rcode_home,
            &fake_home,
            "printf pwn > shared-meta/config || printf pwn > shared-meta/hooks/pre-commit || mv shared-meta shared-meta-moved",
        )
        .await;
        assert_ne!(common_write.exit_code, Some(0));
        assert_eq!(
            std::fs::read_to_string(common_ws.join("shared-meta/config")).unwrap(),
            "COMMON_CLEAN"
        );
        assert!(!common_ws.join("shared-meta/hooks/pre-commit").exists());

        let chain_ws = base.join("chain-sym-workspace");
        std::fs::create_dir_all(chain_ws.join("hop")).unwrap();
        std::fs::create_dir_all(chain_ws.join("real_git")).unwrap();
        std::fs::write(chain_ws.join("real_git/config"), "CHAIN_CLEAN").unwrap();
        std::os::unix::fs::symlink("../real_git", chain_ws.join("hop/git_link")).unwrap();
        std::os::unix::fs::symlink("hop/git_link", chain_ws.join(".git")).unwrap();
        let chain_write = run_supervised(
            ww,
            &chain_ws,
            &[],
            &rcode_home,
            &fake_home,
            "rm -f hop/git_link || mv hop hop_moved || printf pwn > real_git/config",
        )
        .await;
        assert_ne!(chain_write.exit_code, Some(0));
        assert_eq!(
            std::fs::read_to_string(chain_ws.join("real_git/config")).unwrap(),
            "CHAIN_CLEAN"
        );

        // Symlinked `commondir`, empty `commondir`, and malformed regular `.git` file must fail closed!
        let sym_commondir_ws = base.join("sym-commondir-workspace");
        std::fs::create_dir_all(sym_commondir_ws.join(".git")).unwrap();
        std::fs::create_dir_all(sym_commondir_ws.join("target-meta")).unwrap();
        std::fs::write(sym_commondir_ws.join("ptr"), "../target-meta\n").unwrap();
        std::os::unix::fs::symlink("../ptr", sym_commondir_ws.join(".git/commondir")).unwrap();
        assert!(
            PreparedSandbox::prepare_with_home(
                ww,
                &sym_commondir_ws,
                &[],
                Some(&rcode_home),
                Some(&fake_home),
                &[],
            )
            .is_err(),
            "symlinked .git/commondir must fail closed"
        );

        let malformed_gitfile_ws = base.join("malformed-gitfile-workspace");
        std::fs::create_dir_all(&malformed_gitfile_ws).unwrap();
        std::fs::write(malformed_gitfile_ws.join(".git"), "not-a-gitdir-pointer\n").unwrap();
        assert!(
            PreparedSandbox::prepare_with_home(
                ww,
                &malformed_gitfile_ws,
                &[],
                Some(&rcode_home),
                Some(&fake_home),
                &[],
            )
            .is_err(),
            "malformed regular .git file must fail closed"
        );

        // Signals: signaling own child in same sandbox succeeds; signaling host PID is denied.
        let host_pid = std::process::id();
        let sig_own = run_supervised(
            ww,
            &workspace,
            &[],
            &rcode_home,
            &fake_home,
            "sleep 10 & child=$!; kill -TERM \"$child\" && wait \"$child\" 2>/dev/null; printf own_ok",
        )
        .await;
        assert_eq!(sig_own.exit_code, Some(0), "stderr={}", sig_own.stderr);
        assert_eq!(sig_own.stdout, "own_ok");

        let sig_host = run_supervised(
            ww,
            &workspace,
            &[],
            &rcode_home,
            &fake_home,
            &format!("kill -0 {host_pid}"),
        )
        .await;
        assert_ne!(sig_host.exit_code, Some(0));

        // Metadata mutation (`chmod`, `touch`, `xattr`) on outside canary denied.
        let meta_neg = run_supervised(
            ww,
            &workspace,
            &[],
            &rcode_home,
            &fake_home,
            &format!(
                "chmod 0777 '{0}' || touch '{0}' || xattr -w user.test 1 '{0}'",
                canary.display()
            ),
        )
        .await;
        assert_ne!(meta_neg.exit_code, Some(0));
        let mode_after = std::fs::metadata(&canary).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode_after, 0o644);
    }

    #[tokio::test]
    async fn live_kernel_git_worktree_external_gitdir_works_read_only_and_spoofed_dot_git_is_rejected()
     {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let main_repo = base.join("main-repo");
        let worktree = base.join("linked-wt");
        let secret_dir = base.join("secret-outside");
        let spoof_repo = base.join("spoof-repo");
        let rcode_home = base.join("rcode-home");
        let fake_home = base.join("fake-home");
        for d in [
            &main_repo,
            &secret_dir,
            &spoof_repo,
            &rcode_home,
            &fake_home,
        ] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(secret_dir.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::create_dir_all(secret_dir.join("objects")).unwrap();
        std::fs::create_dir_all(secret_dir.join("refs")).unwrap();
        std::fs::write(secret_dir.join("token.txt"), "SPOOFED_GITDIR_SECRET").unwrap();

        // Create a real git repository + linked worktree.
        let git_ok = std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(&main_repo)
            .status()
            .is_ok_and(|s| s.success());
        if git_ok {
            std::fs::write(main_repo.join("README.md"), "hello\n").unwrap();
            assert!(
                std::process::Command::new("git")
                    .args([
                        "-c",
                        "user.name=Test",
                        "-c",
                        "user.email=test@example.com",
                        "add",
                        "README.md",
                    ])
                    .current_dir(&main_repo)
                    .status()
                    .unwrap()
                    .success()
            );
            assert!(
                std::process::Command::new("git")
                    .args([
                        "-c",
                        "user.name=Test",
                        "-c",
                        "user.email=test@example.com",
                        "commit",
                        "-qm",
                        "init",
                    ])
                    .current_dir(&main_repo)
                    .status()
                    .unwrap()
                    .success()
            );
            assert!(
                std::process::Command::new("git")
                    .args([
                        "worktree",
                        "add",
                        "-q",
                        "-b",
                        "wt-branch",
                        worktree.to_str().unwrap()
                    ])
                    .current_dir(&main_repo)
                    .status()
                    .unwrap()
                    .success()
            );

            let ww = EffectiveSandboxPolicy {
                mode: SandboxMode::WorkspaceWrite,
                network: false,
            };
            // `git status --porcelain` inside the linked worktree succeeds (reads external gitdir + commondir)!
            let status_view = run_supervised(
                ww,
                &worktree,
                &[],
                &rcode_home,
                &fake_home,
                "git status --porcelain && printf wt_status_ok",
            )
            .await;
            assert_eq!(
                status_view.exit_code,
                Some(0),
                "stderr={}",
                status_view.stderr
            );
            assert_eq!(status_view.stdout, "wt_status_ok");

            // Writing into the external main_repo `.git/hooks` from inside the worktree MUST fail on BOTH macOS and Linux!
            let write_ext_git = run_supervised(
                ww,
                &worktree,
                &[],
                &rcode_home,
                &fake_home,
                &format!(
                    "printf pwn > '{}'",
                    main_repo.join(".git/hooks/pwn").display()
                ),
            )
            .await;
            assert_ne!(write_ext_git.exit_code, Some(0));
            assert!(!main_repo.join(".git/hooks/pwn").exists());
        }

        // Spoofed `.git` file pointing to `secret_dir` (without mutual `<gitdir>/gitdir` backlink)
        // MUST NOT grant read access to `secret_dir`!
        std::fs::write(
            spoof_repo.join(".git"),
            format!("gitdir: {}\n", secret_dir.display()),
        )
        .unwrap();
        let spoof_read = run_supervised(
            EffectiveSandboxPolicy {
                mode: SandboxMode::WorkspaceWrite,
                network: false,
            },
            &spoof_repo,
            &[],
            &rcode_home,
            &fake_home,
            &format!("cat '{}'", secret_dir.join("token.txt").display()),
        )
        .await;
        assert_ne!(spoof_read.exit_code, Some(0));
        assert!(!spoof_read.stdout.contains("SPOOFED_GITDIR_SECRET"));
    }

    #[tokio::test]
    async fn live_kernel_af_unix_blocked_even_with_network_on_while_socketpair_and_ip_work() {
        use std::io::{Read, Write};
        use std::os::unix::net::{UnixDatagram, UnixListener};

        // Keep Unix socket path short (`SUN_LEN` <= 104 bytes on macOS).
        let sock_dir = tempfile::Builder::new()
            .prefix("rc-u-")
            .tempdir_in("/tmp")
            .unwrap();
        let sock_base = sock_dir.path().canonicalize().unwrap();
        let stream_sock = sock_base.join("s.sock");
        let dgram_sock = sock_base.join("d.sock");
        let unix_listener = UnixListener::bind(&stream_sock).unwrap();
        unix_listener.set_nonblocking(true).unwrap();
        let unix_dgram = UnixDatagram::bind(&dgram_sock).unwrap();
        unix_dgram.set_nonblocking(true).unwrap();

        let tcp_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        tcp_listener.set_nonblocking(true).unwrap();
        let tcp_port = tcp_listener.local_addr().unwrap().port();

        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let workspace = base.join("ws");
        let rcode_home = base.join("rc");
        let fake_home = base.join("hm");
        for d in [&workspace, &rcode_home, &fake_home] {
            std::fs::create_dir_all(d).unwrap();
        }

        // Positive control (`Off`): python3 connects to pathname AF_UNIX stream socket.
        let py_unix_stream = format!(
            "python3 -c 'import socket; s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect({:?}); s.sendall(b\"hi\"); s.close()'",
            stream_sock.to_str().unwrap()
        );
        let off_unix = run_supervised(
            EffectiveSandboxPolicy::off(),
            &workspace,
            &[],
            &rcode_home,
            &fake_home,
            &py_unix_stream,
        )
        .await;
        assert_eq!(off_unix.exit_code, Some(0), "stderr={}", off_unix.stderr);
        assert!(unix_listener.accept().is_ok());

        // Anonymous `socketpair(AF_UNIX, SOCK_STREAM)` works inside sandbox (`network = false`).
        let no_net = EffectiveSandboxPolicy {
            mode: SandboxMode::WorkspaceWrite,
            network: false,
        };
        let pair_ok = run_supervised(
            no_net,
            &workspace,
            &[],
            &rcode_home,
            &fake_home,
            "python3 -c 'import socket; a,b=socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM); a.sendall(b\"ping\"); print(b.recv(4).decode(), end=\"\")'",
        )
        .await;
        assert_eq!(pair_ok.exit_code, Some(0), "stderr={}", pair_ok.stderr);
        assert_eq!(pair_ok.stdout, "ping");

        // TCP blocked when `network = false`.
        let py_tcp = format!(
            "python3 -c 'import socket; s=socket.create_connection((\"127.0.0.1\", {tcp_port}), timeout=1.0); s.sendall(b\"G\"); print(s.recv(2).decode(), end=\"\")'"
        );
        let tcp_blocked =
            run_supervised(no_net, &workspace, &[], &rcode_home, &fake_home, &py_tcp).await;
        assert_ne!(tcp_blocked.exit_code, Some(0));

        // Even when `network = true`: pathname AF_UNIX (stream + dgram + socketpair DGRAM trick) is BLOCKED,
        // while TCP IPv4 succeeds!
        let with_net = EffectiveSandboxPolicy {
            mode: SandboxMode::WorkspaceWrite,
            network: true,
        };
        let unix_blocked_net_on = run_supervised(
            with_net,
            &workspace,
            &[],
            &rcode_home,
            &fake_home,
            &py_unix_stream,
        )
        .await;
        assert_ne!(unix_blocked_net_on.exit_code, Some(0));

        let py_dgram_escape = format!(
            "python3 -c 'import socket, sys\ntry:\n s=socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)\n s.sendto(b\"x\", {:?})\n sys.exit(0)\nexcept Exception:\n pass\na,b=socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)\na.sendto(b\"x\", {:?})\n'",
            dgram_sock.to_str().unwrap(),
            dgram_sock.to_str().unwrap()
        );
        let dgram_blocked = run_supervised(
            with_net,
            &workspace,
            &[],
            &rcode_home,
            &fake_home,
            &py_dgram_escape,
        )
        .await;
        assert_ne!(dgram_blocked.exit_code, Some(0));
        let mut dgram_buf = [0u8; 8];
        assert!(unix_dgram.recv(&mut dgram_buf).is_err());

        let accept_thread = std::thread::spawn(move || {
            let start = std::time::Instant::now();
            loop {
                match tcp_listener.accept() {
                    Ok((mut conn, _)) => {
                        conn.set_nonblocking(false).unwrap();
                        let mut b = [0u8; 1];
                        let _ = conn.read(&mut b);
                        conn.write_all(b"OK").unwrap();
                        return true;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if start.elapsed() > Duration::from_secs(5) {
                            return false;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => panic!("{e}"),
                }
            }
        });
        let tcp_allowed =
            run_supervised(with_net, &workspace, &[], &rcode_home, &fake_home, &py_tcp).await;
        assert!(accept_thread.join().unwrap());
        assert_eq!(
            tcp_allowed.exit_code,
            Some(0),
            "stderr={}",
            tcp_allowed.stderr
        );
        assert_eq!(tcp_allowed.stdout, "OK");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn live_linux_seccomp_io_uring_chown_xattr_abstract_unix_and_close_range_cloexec() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let workspace = base.join("ws");
        let rcode_home = base.join("rc");
        let fake_home = base.join("hm");
        for d in [&workspace, &rcode_home, &fake_home] {
            std::fs::create_dir_all(d).unwrap();
        }
        let target_file = workspace.join("sample.txt");
        std::fs::write(&target_file, "sample").unwrap();

        // 1. Open a file descriptor WITHOUT O_CLOEXEC in the parent and prove `CLOSE_RANGE_CLOEXEC`
        //    closes it across `execve` in the sandboxed child!
        let c_path = std::ffi::CString::new(target_file.to_str().unwrap()).unwrap();
        let leaked_fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY) };
        assert!(leaked_fd >= 3, "expected fd >= 3, got {leaked_fd}");
        let fd_check = run_supervised(
            EffectiveSandboxPolicy {
                mode: SandboxMode::WorkspaceWrite,
                network: false,
            },
            &workspace,
            &[],
            &rcode_home,
            &fake_home,
            &format!("test ! -e /proc/self/fd/{leaked_fd} && printf closed_ok"),
        )
        .await;
        unsafe {
            libc::close(leaked_fd);
        }
        assert_eq!(fd_check.exit_code, Some(0), "stderr={}", fd_check.stderr);
        assert_eq!(fd_check.stdout, "closed_ok");

        // 2. `io_uring_setup` (425) -> ENOSYS (38); `setxattrat` (463) & `removexattrat` (466)
        //    & `chown` -> EPERM (1)!
        let seccomp_py = r#"python3 -c '
import ctypes, errno, os, sys
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long

# io_uring_setup == 425 -> ENOSYS (38)
rc = libc.syscall(ctypes.c_long(425), ctypes.c_ulong(1), ctypes.c_ulong(0))
assert rc == -1 and ctypes.get_errno() == errno.ENOSYS, f"io_uring got rc={rc} errno={ctypes.get_errno()}"

# setxattrat == 463, removexattrat == 466 -> EPERM (1)
for nr in (463, 466):
    ctypes.set_errno(0)
    rc = libc.syscall(ctypes.c_long(nr), ctypes.c_long(-100), ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0))
    assert rc == -1 and ctypes.get_errno() == errno.EPERM, f"nr={nr} got rc={rc} errno={ctypes.get_errno()}"

# chown -> EPERM (1)
try:
    os.chown("sample.txt", os.geteuid(), os.getegid())
    sys.exit(2)
except PermissionError:
    pass

# setxattr -> EPERM (1)
if hasattr(os, "setxattr"):
    try:
        os.setxattr("sample.txt", b"user.rcode", b"1")
        sys.exit(3)
    except PermissionError:
        pass

print("seccomp_ok", end="")
'"#;
        let seccomp_view = run_supervised(
            EffectiveSandboxPolicy {
                mode: SandboxMode::WorkspaceWrite,
                network: true,
            },
            &workspace,
            &[],
            &rcode_home,
            &fake_home,
            seccomp_py,
        )
        .await;
        assert_eq!(
            seccomp_view.exit_code,
            Some(0),
            "stderr={}",
            seccomp_view.stderr
        );
        assert_eq!(seccomp_view.stdout, "seccomp_ok");

        // 3. Abstract AF_UNIX socket in host is unreachable even with `network = true`!
        let abstract_py_check = r#"python3 -c '
import socket, sys
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect("\0rcode-abstract-probe")
    sys.exit(2)
except PermissionError:
    print("abstract_blocked", end="")
'"#;
        let abs_view = run_supervised(
            EffectiveSandboxPolicy {
                mode: SandboxMode::WorkspaceWrite,
                network: true,
            },
            &workspace,
            &[],
            &rcode_home,
            &fake_home,
            abstract_py_check,
        )
        .await;
        assert_eq!(abs_view.exit_code, Some(0), "stderr={}", abs_view.stderr);
        assert_eq!(abs_view.stdout, "abstract_blocked");
    }
}
