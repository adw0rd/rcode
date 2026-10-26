#[cfg(unix)]
#[test]
fn markdown_streams_resumes_and_allows_native_selection() {
    use std::{
        fs::File,
        io::{Read, Seek},
        os::unix::process::CommandExt,
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    let python = Command::new("python3")
        .args(["-c", "import pty, http.server, termios"])
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let available = python.is_ok_and(|mut child| {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => break status.success(),
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break false;
                }
            }
        }
    });
    if !available {
        eprintln!("SKIP PTY fixture: требуется python3 со стандартными модулями Unix PTY");
        assert!(
            std::env::var_os("RCODE_REQUIRE_PTY_TEST").is_none_or(|value| value != "1"),
            "RCODE_REQUIRE_PTY_TEST=1 требует доступный python3"
        );
        return;
    }

    let stdout = tempfile::tempfile().unwrap();
    let stderr = tempfile::tempfile().unwrap();
    let mut child = Command::new("python3")
        .arg(format!(
            "{}/tests/markdown_pty.py",
            env!("CARGO_MANIFEST_DIR")
        ))
        .arg(env!("CARGO_BIN_EXE_rcode"))
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .envs(std::env::var_os("RCODE_PTY_DUMP_GRID").map(|value| ("RCODE_PTY_DUMP_GRID", value)))
        .stdin(Stdio::null())
        .stdout(stdout.try_clone().unwrap())
        .stderr(stderr.try_clone().unwrap())
        .process_group(0)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(56);
    let (status, timed_out) = 'running: loop {
        if let Some(status) = child.try_wait().unwrap() {
            break (status, false);
        }
        if Instant::now() >= deadline {
            // Python handles SIGTERM by closing/reaping its PTY child first.
            unsafe { libc::kill(-(child.id() as i32), libc::SIGTERM) };
            let cleanup_deadline = Instant::now() + Duration::from_secs(1);
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break 'running (status, true);
                }
                if Instant::now() >= cleanup_deadline {
                    unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
                    break 'running (child.wait().unwrap(), true);
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
        thread::sleep(Duration::from_millis(10));
    };
    let read_capture = |mut file: File| {
        file.rewind().unwrap();
        let mut bytes = Vec::new();
        file.take(128 * 1024).read_to_end(&mut bytes).unwrap();
        String::from_utf8_lossy(&bytes).into_owned()
    };
    let stdout = read_capture(stdout);
    let stderr = read_capture(stderr);
    assert!(
        !timed_out && status.success(),
        "PTY fixture {}: {status}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        if timed_out { "timed out" } else { "failed" }
    );
}

#[cfg(windows)]
#[test]
fn interactive_terminal_pty_fixture_is_unix_only() {
    eprintln!("SKIP PTY fixture: стандартный модуль Python pty доступен только на Unix");
}
