//! Subprocess crash tests for the filesystem WAL. The child is deliberately
//! killed at a synchronous durability hook; reopening remains the only recovery
//! operation and explicit undo is always driven by the test parent.

use super::*;
use serde_json::json;
use std::{
    env, fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::Duration,
};
use tokio_util::sync::CancellationToken;

const CHILD_ROOT: &str = "RCODE_TEST_WAL_ROOT";
const CHILD_CHECKPOINTS: &str = "RCODE_TEST_WAL_CHECKPOINTS";
const CHILD_SCENARIO: &str = "RCODE_TEST_WAL_SCENARIO";
const CHILD_HOOK: &str = "RCODE_TEST_WAL_HOOK";
const CHILD_INDEX: &str = "RCODE_TEST_WAL_INDEX";

#[derive(Clone, Copy)]
enum Scenario {
    Write,
    CreatedFileWrite,
    GroupUndo,
    ManyFilesUndo,
    ResumeManyFilesUndo,
    LifoUndo,
}

impl Scenario {
    fn as_str(self) -> &'static str {
        match self {
            Self::Write => "write",
            Self::CreatedFileWrite => "created-file-write",
            Self::GroupUndo => "group-undo",
            Self::ManyFilesUndo => "many-files-undo",
            Self::ResumeManyFilesUndo => "resume-many-files-undo",
            Self::LifoUndo => "lifo-undo",
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Point {
    DurableIntent,
    StageDirectoryCreated,
    StageGuardDurable,
    StagePayloadDurable,
    StageCreated,
    PreparedPersisted,
    WorkspaceMutation,
    NamespaceSynced,
    ProgressPersisted,
    Finalized,
}

impl Point {
    fn as_str(self) -> &'static str {
        match self {
            Self::DurableIntent => "DurableIntent",
            Self::StageDirectoryCreated => "StageDirectoryCreated",
            Self::StageGuardDurable => "StageGuardDurable",
            Self::StagePayloadDurable => "StagePayloadDurable",
            Self::StageCreated => "StageCreated",
            Self::PreparedPersisted => "PreparedPersisted",
            Self::WorkspaceMutation => "WorkspaceMutation",
            Self::NamespaceSynced => "NamespaceSynced",
            Self::ProgressPersisted => "ProgressPersisted",
            Self::Finalized => "Finalized",
        }
    }

    fn matches(self, event: WalFaultPoint, wanted_index: usize) -> bool {
        match (self, event) {
            (Self::DurableIntent, WalFaultPoint::DurableIntent)
            | (Self::PreparedPersisted, WalFaultPoint::PreparedPersisted)
            | (Self::Finalized, WalFaultPoint::Finalized) => true,
            (Self::StageDirectoryCreated, WalFaultPoint::StageDirectoryCreated { index })
            | (Self::StageGuardDurable, WalFaultPoint::StageGuardDurable { index })
            | (Self::StagePayloadDurable, WalFaultPoint::StagePayloadDurable { index })
            | (Self::StageCreated, WalFaultPoint::StageCreated { index })
            | (Self::WorkspaceMutation, WalFaultPoint::WorkspaceMutation { index })
            | (Self::NamespaceSynced, WalFaultPoint::NamespaceSynced { index })
            | (Self::ProgressPersisted, WalFaultPoint::ProgressPersisted { index }) => {
                index == wanted_index
            }
            _ => false,
        }
    }
}

async fn tool(tools: &mut Tools, name: &str, args: Value) -> Result<()> {
    let outcome = tools
        .execute(name, &args, &CancellationToken::new())
        .await?;
    ensure!(!outcome.is_error, "{name} failed: {}", outcome.content);
    Ok(())
}

async fn write_file(tools: &mut Tools, relative: &str, bytes: &str) -> Result<()> {
    tool(tools, "read_file", json!({"path":relative})).await?;
    tool(
        tools,
        "write_file",
        json!({"path":relative,"content":bytes}),
    )
    .await
}

fn selected_hook() -> Result<(Point, usize)> {
    let name = env::var(CHILD_HOOK)?;
    let point = match name.as_str() {
        "DurableIntent" => Point::DurableIntent,
        "StageDirectoryCreated" => Point::StageDirectoryCreated,
        "StageGuardDurable" => Point::StageGuardDurable,
        "StagePayloadDurable" => Point::StagePayloadDurable,
        "StageCreated" => Point::StageCreated,
        "PreparedPersisted" => Point::PreparedPersisted,
        "WorkspaceMutation" => Point::WorkspaceMutation,
        "NamespaceSynced" => Point::NamespaceSynced,
        "ProgressPersisted" => Point::ProgressPersisted,
        "Finalized" => Point::Finalized,
        _ => bail!("unknown test hook {name}"),
    };
    let index = env::var(CHILD_INDEX)
        .unwrap_or_else(|_| "0".into())
        .parse()?;
    Ok((point, index))
}

/// Invoked only by the parent harness through `current_exe --exact`.
#[test]
#[ignore = "subprocess-only WAL crash child"]
fn wal_crash_child() {
    let root = PathBuf::from(env::var_os(CHILD_ROOT).expect("child root"));
    let checkpoints = PathBuf::from(env::var_os(CHILD_CHECKPOINTS).expect("child checkpoints"));
    let scenario = env::var(CHILD_SCENARIO).expect("child scenario");
    if matches!(
        scenario.as_str(),
        "many-files-undo" | "resume-many-files-undo"
    ) {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
            0
        );
        limit.rlim_cur = 64.min(limit.rlim_max);
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
    }
    if scenario == "resume-many-files-undo" {
        use std::os::unix::fs::MetadataExt;

        let snapshot = || {
            (0..80)
                .map(|index| {
                    let path = root.join(format!("d-{index:03}/f"));
                    let metadata = fs::metadata(&path).unwrap();
                    (
                        fs::read(&path).unwrap(),
                        metadata.dev(),
                        metadata.ino(),
                        metadata.permissions().mode(),
                    )
                })
                .collect::<Vec<_>>()
        };
        // Capture bytes and inode metadata before opening the WAL. This proves
        // low-FD startup is read-only before explicit undo begins.
        let before_open = snapshot();
        let mut tools = Tools::new(&root, &checkpoints).expect("resume Tools open");
        assert_eq!(snapshot(), before_open, "startup replayed low-FD targets");
        tools.undo().expect("explicit low-FD undo");
        for index in 0..80 {
            let path = root.join(format!("d-{index:03}/f"));
            assert_eq!(
                fs::read(&path).unwrap(),
                format!("USER {index}\n").as_bytes(),
                "wrong restored user bytes for index {index}"
            );
            let expected_mode = if index % 2 == 0 { 0o751 } else { 0o640 };
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                expected_mode,
                "wrong restored mode for index {index}"
            );
        }
        println!("WAL_CHILD_COMPLETE");
        std::io::stdout().flush().unwrap();
        return;
    }
    let (point, index) = selected_hook().expect("valid requested hook");
    let mut tools = Tools::new(&root, &checkpoints).expect("initial Tools open");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    match scenario.as_str() {
        "write" | "created-file-write" => {
            let created = scenario == "created-file-write";
            if !created {
                fs::write(root.join("f"), b"USER\n").unwrap();
                fs::set_permissions(root.join("f"), fs::Permissions::from_mode(0o751)).unwrap();
            }
            tools.begin_turn().unwrap();
            if created {
                rt.block_on(tool(
                    &mut tools,
                    "write_file",
                    json!({"path":"f","content":"AGENT1\n"}),
                ))
                .unwrap();
            } else {
                rt.block_on(write_file(&mut tools, "f", "AGENT1\n"))
                    .unwrap();
            }
            tools.set_wal_fault_hook(Box::new(move |event| {
                if point.matches(event, index) {
                    println!("WAL_CHILD_READY");
                    std::io::stdout().flush().unwrap();
                    let mut byte = [0];
                    let _ = std::io::stdin().read(&mut byte);
                }
            }));
            rt.block_on(write_file(&mut tools, "f", "AGENT2\n"))
                .unwrap();
        }
        "group-undo" => {
            fs::write(root.join("a"), b"A USER\n").unwrap();
            fs::write(root.join("b"), b"B USER\n").unwrap();
            fs::set_permissions(root.join("a"), fs::Permissions::from_mode(0o751)).unwrap();
            tools.begin_turn().unwrap();
            rt.block_on(write_file(&mut tools, "a", "A AGENT\n"))
                .unwrap();
            rt.block_on(write_file(&mut tools, "b", "B AGENT\n"))
                .unwrap();
            rt.block_on(tool(
                &mut tools,
                "write_file",
                json!({"path":"created","content":"CREATED\n"}),
            ))
            .unwrap();
            tools.set_wal_fault_hook(Box::new(move |event| {
                if point.matches(event, index) {
                    println!("WAL_CHILD_READY");
                    std::io::stdout().flush().unwrap();
                    let mut byte = [0];
                    let _ = std::io::stdin().read(&mut byte);
                }
            }));
            tools.undo().unwrap();
        }
        "many-files-undo" => {
            tools.begin_turn().unwrap();
            for index in 0..80 {
                let directory = root.join(format!("d-{index:03}"));
                fs::create_dir(&directory).unwrap();
                let path = directory.join("f");
                fs::write(&path, format!("USER {index}\n")).unwrap();
                let mode = if index % 2 == 0 { 0o751 } else { 0o640 };
                fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
                rt.block_on(write_file(
                    &mut tools,
                    &format!("d-{index:03}/f"),
                    &format!("AGENT {index}\n"),
                ))
                .unwrap();
            }
            tools.set_wal_fault_hook(Box::new(move |event| {
                if point.matches(event, index) {
                    println!("WAL_CHILD_READY");
                    std::io::stdout().flush().unwrap();
                    let mut byte = [0];
                    let _ = std::io::stdin().read(&mut byte);
                }
            }));
            tools.undo().unwrap();
        }
        "lifo-undo" => {
            fs::write(root.join("f"), b"USER\n").unwrap();
            tools.begin_turn().unwrap();
            rt.block_on(write_file(&mut tools, "f", "AGENT1\n"))
                .unwrap();
            tools.begin_turn().unwrap();
            rt.block_on(write_file(&mut tools, "f", "AGENT2\n"))
                .unwrap();
            tools.set_wal_fault_hook(Box::new(move |event| {
                if point.matches(event, index) {
                    println!("WAL_CHILD_READY");
                    std::io::stdout().flush().unwrap();
                    let mut byte = [0];
                    let _ = std::io::stdin().read(&mut byte);
                }
            }));
            tools.undo().unwrap();
        }
        _ => panic!("unknown child scenario {scenario}"),
    }
    panic!("requested WAL hook was never reached");
}

struct ChildGuard {
    child: Option<Child>,
    ready: mpsc::Receiver<String>,
    diagnostics: mpsc::Receiver<String>,
    ready_timeout: Duration,
}

impl ChildGuard {
    fn spawn(
        root: &Path,
        checkpoints: &Path,
        scenario: Scenario,
        point: Point,
        index: usize,
    ) -> Self {
        let executable = env::current_exe().unwrap();
        let mut command = Command::new(executable);
        command
            .args([
                "--exact",
                "tools::file_wal_tests::wal_crash_child",
                "--ignored",
                "--nocapture",
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env(CHILD_ROOT, root)
            .env(CHILD_CHECKPOINTS, checkpoints)
            .env(CHILD_SCENARIO, scenario.as_str())
            .env(CHILD_HOOK, point.as_str())
            .env(CHILD_INDEX, index.to_string());
        for name in ["HOME", "TMPDIR"] {
            if let Some(value) = env::var_os(name) {
                command.env(name, value);
            }
        }
        let mut child = command.spawn().expect("spawn crash child");
        let stderr = child.stderr.take().unwrap();
        let (diagnostics_tx, diagnostics) = mpsc::channel();
        thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = stderr.take(64 * 1024).read_to_end(&mut bytes);
            let _ = diagnostics_tx.send(String::from_utf8_lossy(&bytes).into_owned());
        });
        let stdout = child.stdout.take().unwrap();
        let (tx, ready) = mpsc::channel();
        thread::spawn(move || {
            // libtest emits its own preamble before our handshake. Only the
            // exact marker proves the selected durability point was reached.
            let reader = BufReader::new(stdout).take(64 * 1024);
            for line in reader.lines() {
                match line {
                    Ok(line) if matches!(line.trim(), "WAL_CHILD_READY" | "WAL_CHILD_COMPLETE") => {
                        let _ = tx.send(line);
                    }
                    Ok(_) => {}
                    Err(error) => {
                        let _ = tx.send(format!("stdout error: {error}"));
                        return;
                    }
                }
            }
            let _ = tx.send("child stdout ended before WAL hook".into());
        });
        Self {
            child: Some(child),
            ready,
            diagnostics,
            ready_timeout: Duration::from_secs(
                if matches!(
                    scenario,
                    Scenario::ManyFilesUndo | Scenario::ResumeManyFilesUndo
                ) {
                    60
                } else {
                    10
                },
            ),
        }
    }

    fn wait_ready(&self) -> String {
        let result = self.ready.recv_timeout(self.ready_timeout);
        if let Ok(ref marker) = result
            && marker.trim() == "WAL_CHILD_READY"
        {
            return marker.clone();
        }
        let diagnostics = self
            .diagnostics
            .recv_timeout(Duration::from_secs(1))
            .unwrap_or_else(|_| "child stderr not complete".into());
        panic!(
            "child did not reach WAL hook within {:?}: {result:?}; stderr: {diagnostics}",
            self.ready_timeout
        );
    }

    fn wait_completed_and_exit(&mut self) {
        let deadline = std::time::Instant::now() + self.ready_timeout;
        let marker_timeout = deadline.saturating_duration_since(std::time::Instant::now());
        match self.ready.recv_timeout(marker_timeout) {
            Ok(marker) if marker.trim() == "WAL_CHILD_COMPLETE" => {}
            result => {
                let diagnostics = self
                    .diagnostics
                    .recv_timeout(Duration::from_secs(1))
                    .unwrap_or_else(|_| "child stderr not complete".into());
                self.kill_and_wait();
                panic!("resume child did not complete: {result:?}; stderr: {diagnostics}");
            }
        }

        loop {
            let status = self
                .child
                .as_mut()
                .expect("resume child already reaped")
                .try_wait()
                .expect("poll resume child");
            if let Some(status) = status {
                self.child.take();
                if !status.success() {
                    let diagnostics = self
                        .diagnostics
                        .recv_timeout(Duration::from_secs(1))
                        .unwrap_or_else(|_| "child stderr not complete".into());
                    panic!("resume child failed: {status}; stderr: {diagnostics}");
                }
                return;
            }
            if std::time::Instant::now() >= deadline {
                self.kill_and_wait();
                panic!("resume child did not exit after completion marker");
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn kill_and_wait(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => return,
                    Ok(None) if std::time::Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Ok(None) => {
                        panic!("SIGKILLed WAL child was not reaped within five seconds");
                    }
                    Err(error) => panic!("failed to reap SIGKILLed WAL child: {error}"),
                }
            }
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.kill_and_wait();
    }
}

#[cfg(test)]
mod crash_matrix {
    use super::*;

    fn case_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn git(root: &Path, home: &Path, arguments: &[&str]) -> String {
        let output = Command::new("git")
            .args([
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "init.templateDir=",
            ])
            .args(arguments)
            .current_dir(root)
            .env_clear()
            .env(
                "PATH",
                env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into()),
            )
            .env("HOME", home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn crash(root: &Path, checkpoint: &Path, scenario: Scenario, point: Point, index: usize) {
        let mut child = ChildGuard::spawn(root, checkpoint, scenario, point, index);
        assert_eq!(child.wait_ready().trim(), "WAL_CHILD_READY");
        child.kill_and_wait();
    }

    #[test]
    fn write_crashes_leave_explicit_undo_available() {
        for (point, expected) in [
            (Point::DurableIntent, b"AGENT1\n".as_slice()),
            (Point::StageDirectoryCreated, b"AGENT1\n".as_slice()),
            (Point::StageGuardDurable, b"AGENT1\n".as_slice()),
            (Point::StagePayloadDurable, b"AGENT1\n".as_slice()),
            (Point::StageCreated, b"AGENT1\n".as_slice()),
            (Point::PreparedPersisted, b"AGENT1\n".as_slice()),
            (Point::WorkspaceMutation, b"AGENT2\n".as_slice()),
            (Point::NamespaceSynced, b"AGENT2\n".as_slice()),
            (Point::Finalized, b"AGENT2\n".as_slice()),
        ] {
            let base = case_dir();
            let root = base.path().join("project");
            let checkpoint = base.path().join("checkpoint");
            fs::create_dir(&root).unwrap();
            crash(&root, &checkpoint, Scenario::Write, point, 0);

            let mut reopened = Tools::new(&root, &checkpoint).unwrap();
            assert_eq!(
                fs::read(root.join("f")).unwrap(),
                expected,
                "after {point:?}"
            );
            assert_eq!(
                fs::metadata(root.join("f")).unwrap().permissions().mode() & 0o777,
                0o751
            );
            reopened.undo().unwrap();
            assert_eq!(fs::read(root.join("f")).unwrap(), b"USER\n");
            assert_eq!(
                fs::metadata(root.join("f")).unwrap().permissions().mode() & 0o777,
                0o751
            );
        }
    }

    #[tokio::test]
    async fn same_bytes_write_keeps_inode_manifest_and_previous_undo() {
        use std::os::unix::fs::MetadataExt;
        let base = case_dir();
        let root = base.path().join("project");
        let checkpoint = base.path().join("checkpoint");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("f"), b"USER\n").unwrap();
        fs::set_permissions(root.join("f"), fs::Permissions::from_mode(0o751)).unwrap();
        let mut tools = Tools::new(&root, &checkpoint).unwrap();
        tools.begin_turn().unwrap();
        write_file(&mut tools, "f", "AGENT1\n").await.unwrap();
        let before = fs::metadata(root.join("f")).unwrap();
        let manifest = fs::read(checkpoint.join("checkpoints.json")).unwrap();
        write_file(&mut tools, "f", "AGENT1\n").await.unwrap();
        assert_eq!(
            fs::read(checkpoint.join("checkpoints.json")).unwrap(),
            manifest
        );
        drop(tools);
        let mut reopened = Tools::new(&root, &checkpoint).unwrap();
        let after = fs::metadata(root.join("f")).unwrap();
        assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
        assert_eq!(after.permissions().mode() & 0o777, 0o751);
        reopened.undo().unwrap();
        assert_eq!(fs::read(root.join("f")).unwrap(), b"USER\n");
    }

    #[test]
    fn rewritten_created_file_crashes_keep_explicit_undo_available() {
        use std::os::unix::fs::MetadataExt;
        for (point, expected) in [
            (Point::DurableIntent, b"AGENT1\n".as_slice()),
            (Point::StageDirectoryCreated, b"AGENT1\n".as_slice()),
            (Point::StageGuardDurable, b"AGENT1\n".as_slice()),
            (Point::StagePayloadDurable, b"AGENT1\n".as_slice()),
            (Point::StageCreated, b"AGENT1\n".as_slice()),
            (Point::PreparedPersisted, b"AGENT1\n".as_slice()),
            (Point::WorkspaceMutation, b"AGENT2\n".as_slice()),
            (Point::NamespaceSynced, b"AGENT2\n".as_slice()),
            (Point::Finalized, b"AGENT2\n".as_slice()),
        ] {
            let base = case_dir();
            let root = base.path().join("project");
            let checkpoint = base.path().join("checkpoint");
            fs::create_dir(&root).unwrap();
            crash(&root, &checkpoint, Scenario::CreatedFileWrite, point, 0);
            let before = fs::metadata(root.join("f")).unwrap();
            let mut reopened = Tools::new(&root, &checkpoint).unwrap();
            assert_eq!(
                fs::read(root.join("f")).unwrap(),
                expected,
                "after {point:?}"
            );
            let after = fs::metadata(root.join("f")).unwrap();
            assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
            assert_eq!(after.permissions().mode(), before.permissions().mode());
            reopened.undo().unwrap();
            assert!(
                !root.join("f").exists(),
                "created file survived undo after {point:?}"
            );
        }
    }

    #[test]
    fn stage_namespace_does_not_appear_in_git_index_after_crash() {
        for (point, has_payload) in [
            (Point::StageDirectoryCreated, false),
            (Point::StageGuardDurable, false),
            (Point::StagePayloadDurable, true),
            (Point::StageCreated, true),
        ] {
            let base = case_dir();
            let root = base.path().join("project");
            let checkpoint = base.path().join("checkpoint");
            let home = base.path().join("home");
            fs::create_dir(&root).unwrap();
            fs::create_dir(&home).unwrap();
            git(&root, &home, &["init", "-q"]);
            crash(&root, &checkpoint, Scenario::GroupUndo, point, 0);
            let mut stage_files = Vec::new();
            for entry in fs::read_dir(&root).unwrap() {
                let path = entry.unwrap().path();
                if !path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(".rcode-wal-")
                {
                    continue;
                }
                if path.is_dir() {
                    stage_files.extend(
                        fs::read_dir(path)
                            .unwrap()
                            .map(|entry| entry.unwrap().path()),
                    );
                } else {
                    stage_files.push(path);
                }
            }
            let contains_preimage = stage_files.iter().any(|path| {
                path.is_file()
                    && fs::read(path)
                        .unwrap()
                        .windows(4)
                        .any(|bytes| bytes == b"USER")
            });
            assert_eq!(
                contains_preimage, has_payload,
                "unexpected raw payload at {point:?}"
            );
            git(&root, &home, &["add", "-A"]);
            let staged = git(&root, &home, &["ls-files", "-z"]);
            assert!(
                !staged.split('\0').any(|path| path.contains(".rcode-wal-")),
                "normal git add -A included an internal restore buffer after {point:?}"
            );
            let before = [
                fs::read(root.join("a")).unwrap(),
                fs::read(root.join("b")).unwrap(),
                fs::read(root.join("created")).unwrap(),
            ];
            let mut reopened = Tools::new(&root, &checkpoint).unwrap();
            let after = [
                fs::read(root.join("a")).unwrap(),
                fs::read(root.join("b")).unwrap(),
                fs::read(root.join("created")).unwrap(),
            ];
            assert_eq!(
                after, before,
                "startup mutated user targets after {point:?}"
            );
            reopened.undo().unwrap();
            assert_eq!(fs::read(root.join("a")).unwrap(), b"A USER\n");
            assert_eq!(fs::read(root.join("b")).unwrap(), b"B USER\n");
            assert!(!root.join("created").exists());
        }
    }

    #[tokio::test]
    async fn stage_namespace_is_denied_to_file_tools() {
        let base = case_dir();
        let root = base.path().join("project");
        let checkpoint = base.path().join("checkpoint");
        fs::create_dir(&root).unwrap();
        let name = format!(".rcode-wal-{}.stage", uuid::Uuid::new_v4());
        fs::write(root.join(&name), b"PRIVATE_STAGE_MARKER").unwrap();
        let mut tools = Tools::new(&root, &checkpoint).unwrap();
        let read = tools
            .execute(
                "read_file",
                &json!({"path":name}),
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert!(
            read.is_error,
            "reserved transaction namespace must not be readable by a model"
        );
        let list = tools
            .execute("list_files", &json!({}), &CancellationToken::new())
            .await
            .unwrap();
        assert!(
            !list.content.contains(&name),
            "reserved transaction namespace was listed"
        );
        let write = tools.execute("write_file", &json!({"path":name,"content":"changed", "expected_sha256":sha256(b"PRIVATE_STAGE_MARKER")}), &CancellationToken::new()).await.unwrap();
        assert!(write.is_error);
        assert_eq!(fs::read(root.join(&name)).unwrap(), b"PRIVATE_STAGE_MARKER");
    }

    #[test]
    fn low_fd_large_undo_recovers_prepared_and_mid_publication_crashes() {
        for (point, index) in [
            (Point::PreparedPersisted, 0),
            (Point::WorkspaceMutation, 39),
            (Point::WorkspaceMutation, 79),
        ] {
            let base = case_dir();
            let root = base.path().join("project");
            let checkpoint = base.path().join("checkpoint");
            fs::create_dir(&root).unwrap();
            crash(&root, &checkpoint, Scenario::ManyFilesUndo, point, index);
            let mut resume = ChildGuard::spawn(
                &root,
                &checkpoint,
                Scenario::ResumeManyFilesUndo,
                Point::Finalized,
                0,
            );
            resume.wait_completed_and_exit();
        }
    }

    #[test]
    fn group_undo_crashes_preserve_state_on_open_then_explicit_undo_finishes() {
        for (point, index) in [
            (Point::WorkspaceMutation, 0),
            (Point::ProgressPersisted, 0),
            (Point::WorkspaceMutation, 2),
        ] {
            let base = case_dir();
            let root = base.path().join("project");
            let checkpoint = base.path().join("checkpoint");
            fs::create_dir(&root).unwrap();
            crash(&root, &checkpoint, Scenario::GroupUndo, point, index);
            let before_open = [
                fs::read(root.join("a")).unwrap(),
                fs::read(root.join("b")).unwrap(),
                fs::read(root.join("created")).unwrap_or_default(),
            ];

            let mut reopened = Tools::new(&root, &checkpoint).unwrap();
            let after_open = [
                fs::read(root.join("a")).unwrap(),
                fs::read(root.join("b")).unwrap(),
                fs::read(root.join("created")).unwrap_or_default(),
            ];
            assert_eq!(
                after_open, before_open,
                "startup must not mutate workspace after {point:?} #{index}"
            );
            reopened.undo().unwrap();
            assert_eq!(fs::read(root.join("a")).unwrap(), b"A USER\n");
            assert_eq!(fs::read(root.join("b")).unwrap(), b"B USER\n");
            assert!(!root.join("created").exists());
            assert_eq!(
                fs::metadata(root.join("a")).unwrap().permissions().mode() & 0o777,
                0o751
            );
        }
    }

    #[test]
    fn two_turn_undo_remains_lifo_across_crash() {
        let base = case_dir();
        let root = base.path().join("project");
        let checkpoint = base.path().join("checkpoint");
        fs::create_dir(&root).unwrap();
        crash(
            &root,
            &checkpoint,
            Scenario::LifoUndo,
            Point::WorkspaceMutation,
            0,
        );

        let mut reopened = Tools::new(&root, &checkpoint).unwrap();
        assert_eq!(fs::read(root.join("f")).unwrap(), b"AGENT1\n");
        reopened.undo().unwrap();
        assert_eq!(fs::read(root.join("f")).unwrap(), b"AGENT1\n");
        reopened.undo().unwrap();
        assert_eq!(fs::read(root.join("f")).unwrap(), b"USER\n");
    }
}
