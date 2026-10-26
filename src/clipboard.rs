//! Локальный macOS clipboard. OSC52 fallback выводит только владелец Screen.
#[cfg(any(target_os = "macos", all(test, unix)))]
fn write_to_program(program: &std::ffi::OsStr, args: &[&std::ffi::OsStr], text: &str) -> bool {
    use std::{
        io::{Seek, Write},
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    let Ok(mut input) = tempfile::tempfile() else {
        return false;
    };
    if input.write_all(text.as_bytes()).is_err() || input.rewind().is_err() {
        return false;
    }
    let Ok(mut child) = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_CTYPE", "en_US.UTF-8")
        .stdin(Stdio::from(input))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let deadline = Instant::now() + Duration::from_millis(600);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}
pub(crate) fn copy_local(text: &str) -> bool {
    // Over SSH the target is the terminal host's clipboard, not the server's.
    if ["SSH_TTY", "SSH_CONNECTION", "SSH_CLIENT"]
        .iter()
        .any(|key| std::env::var_os(key).is_some())
    {
        return false;
    }
    #[cfg(target_os = "macos")]
    {
        write_to_program(std::ffi::OsStr::new("/usr/bin/pbcopy"), &[], text)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = text;
        false
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        ffi::OsStr,
        time::{Duration, Instant},
    };
    #[test]
    fn clipboard_writer_passes_unicode_as_stdin_and_hides_parent_environment() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("copy");
        let script = r#"
            /usr/bin/env | while IFS='=' read -r name value; do
                case "$name" in
                    PATH|LC_CTYPE|PWD|SHLVL|_|SDKROOT|CPATH|LIBRARY_PATH|MANPATH|__CF_USER_TEXT_ENCODING) ;;
                    *) exit 1 ;;
                esac
            done || exit 1
            /bin/cat > "$1"
        "#;
        assert!(write_to_program(
            OsStr::new("/bin/sh"),
            &[
                OsStr::new("-c"),
                OsStr::new(script),
                OsStr::new("rcode-clipboard-test"),
                output.as_os_str(),
            ],
            "Привет 世界\n'$(echo no)'\n"
        ));
        assert_eq!(
            std::fs::read_to_string(output).unwrap(),
            "Привет 世界\n'$(echo no)'\n"
        );
    }
    #[test]
    fn clipboard_helper_timeout_is_bounded_and_reaped() {
        let start = Instant::now();
        assert!(!write_to_program(
            OsStr::new("/bin/sleep"),
            &[OsStr::new("5")],
            "value"
        ));
        assert!(start.elapsed() < Duration::from_secs(3));
    }
}
