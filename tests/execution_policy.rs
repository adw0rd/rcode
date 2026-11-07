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
