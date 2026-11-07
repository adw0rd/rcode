#![cfg(unix)]

use rcode::tools::Tools;
use serde_json::json;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};
use tokio_util::sync::CancellationToken;

struct Fixture {
    _base: tempfile::TempDir,
    root: PathBuf,
    checkpoints: PathBuf,
    tools: Tools,
}

impl Fixture {
    fn new() -> Self {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("project");
        let checkpoints = base.path().join("checkpoints");
        fs::create_dir(&root).unwrap();
        let mut tools = Tools::new(&root, &checkpoints).unwrap();
        tools.begin_turn().unwrap();
        Self {
            _base: base,
            root,
            checkpoints,
            tools,
        }
    }

    async fn call(&mut self, name: &str, args: serde_json::Value) -> anyhow::Result<()> {
        let outcome = self
            .tools
            .execute(name, &args, &CancellationToken::new())
            .await?;
        anyhow::ensure!(!outcome.is_error, "{name} failed: {}", outcome.content);
        Ok(())
    }

    async fn edit(&mut self, relative: &str, after: &str) -> anyhow::Result<()> {
        self.call("read_file", json!({"path":relative})).await?;
        self.call("write_file", json!({"path":relative,"content":after}))
            .await?;
        let path = self.root.join(relative);
        anyhow::ensure!(fs::read_to_string(path)? == after);
        Ok(())
    }
}

struct RestorePermissions {
    path: PathBuf,
    mode: u32,
}

impl RestorePermissions {
    fn block(path: &Path) -> Self {
        let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
        fs::set_permissions(path, fs::Permissions::from_mode(0o500)).unwrap();
        let guard = Self {
            path: path.to_owned(),
            mode,
        };
        assert!(fs::create_dir(path.join("permission-probe")).is_err());
        guard
    }
}

impl Drop for RestorePermissions {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(self.mode));
    }
}

#[tokio::test]
async fn failed_group_undo_does_not_partially_restore_earlier_file() {
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "fixture requires a non-root Unix user"
    );
    let mut f = Fixture::new();
    for dir in ["a", "b"] {
        fs::create_dir(f.root.join(dir)).unwrap();
        fs::write(f.root.join(dir).join("f"), format!("{dir} original\n")).unwrap();
    }
    f.edit("a/f", "a agent\n").await.unwrap();
    f.edit("b/f", "b agent\n").await.unwrap();

    let blocked = RestorePermissions::block(&f.root.join("b"));
    let undo = f.tools.undo();
    assert!(
        undo.is_err(),
        "undo must surface the later directory failure"
    );
    let a_after_failed_undo = fs::read(f.root.join("a/f")).unwrap();
    let b_after_failed_undo = fs::read(f.root.join("b/f")).unwrap();
    assert_eq!(
        (
            a_after_failed_undo.as_slice(),
            b_after_failed_undo.as_slice()
        ),
        (b"a agent\n".as_slice(), b"b agent\n".as_slice()),
        "failed group undo must leave both workspace postimages untouched"
    );
    assert!(
        fs::read_dir(&f.checkpoints).unwrap().count() > 0,
        "failed undo must retain its checkpoint"
    );
    drop(blocked);

    // A failed batch keeps the checkpoint so it can be retried after access returns.
    f.tools.undo().unwrap();
    assert_eq!(fs::read(f.root.join("a/f")).unwrap(), b"a original\n");
    assert_eq!(fs::read(f.root.join("b/f")).unwrap(), b"b original\n");
}

#[tokio::test]
async fn undo_rejects_same_bytes_replacement_inode_after_reopen() {
    let mut f = Fixture::new();
    let path = f.root.join("f");
    fs::write(&path, b"user original\n").unwrap();
    f.edit("f", "agent update\n").await.unwrap();
    let journal = fs::read_dir(&f.checkpoints).unwrap().count();
    assert!(journal > 0, "expected a persisted checkpoint");
    drop(f.tools);

    let held = f.root.join("held-original-agent-file");
    fs::rename(&path, &held).unwrap();
    fs::write(&path, b"agent update\n").unwrap();
    assert_ne!(
        fs::metadata(&held).unwrap().ino(),
        fs::metadata(&path).unwrap().ino()
    );
    assert_eq!(fs::read(&held).unwrap(), b"agent update\n");
    assert_eq!(fs::read(&path).unwrap(), b"agent update\n");

    let mut reopened = Tools::new(&f.root, &f.checkpoints).unwrap();
    assert!(
        reopened.undo().is_err(),
        "replacement inode must conflict with undo"
    );
    assert_eq!(fs::read(&held).unwrap(), b"agent update\n");
    assert_eq!(fs::read(&path).unwrap(), b"agent update\n");
}

#[tokio::test]
async fn replaced_checkpoint_directory_stops_write_before_workspace_mutation() {
    let mut f = Fixture::new();
    let path = f.root.join("f");
    fs::write(&path, b"USER\n").unwrap();
    let moved = f.checkpoints.with_file_name("checkpoints-held");
    fs::rename(&f.checkpoints, &moved).unwrap();
    fs::create_dir(&f.checkpoints).unwrap();

    let result = f.call("read_file", json!({"path":"f"})).await;
    assert!(result.is_ok());
    let result = f
        .call("write_file", json!({"path":"f","content":"AGENT\n"}))
        .await;
    assert!(
        result.is_err(),
        "replacement checkpoint root must be rejected"
    );
    assert_eq!(fs::read(path).unwrap(), b"USER\n");
    assert!(moved.join("checkpoints.json").exists());
}

#[tokio::test]
async fn same_bytes_workspace_root_replacement_after_reopen_is_rejected() {
    let mut f = Fixture::new();
    fs::write(f.root.join("f"), b"USER\n").unwrap();
    f.edit("f", "AGENT\n").await.unwrap();
    drop(f.tools);

    let held = f.root.with_file_name("project-held");
    fs::rename(&f.root, &held).unwrap();
    fs::create_dir(&f.root).unwrap();
    fs::write(f.root.join("f"), b"AGENT\n").unwrap();
    let reopened = Tools::new(&f.root, &f.checkpoints);
    match reopened {
        Err(_) => {}
        Ok(mut tools) => assert!(
            tools.undo().is_err(),
            "same-path root replacement must not authorize undo"
        ),
    }
    assert_eq!(fs::read(held.join("f")).unwrap(), b"AGENT\n");
    assert_eq!(fs::read(f.root.join("f")).unwrap(), b"AGENT\n");
}

#[tokio::test]
async fn self_gitignore_group_undo_is_all_or_nothing() {
    let mut f = Fixture::new();
    fs::write(f.root.join(".gitignore"), b"tracked.txt\n").unwrap();
    fs::write(f.root.join("tracked.txt"), b"USER\n").unwrap();
    f.edit(".gitignore", "").await.unwrap();
    f.edit("tracked.txt", "AGENT\n").await.unwrap();

    // Restoring .gitignore first would make the second entry inaccessible.
    // The batch must restore the ordinary file before its policy file.
    f.tools.undo().unwrap();
    let ignore_after = fs::read(f.root.join(".gitignore")).unwrap();
    let file_after = fs::read(f.root.join("tracked.txt")).unwrap();
    assert_eq!(ignore_after, b"tracked.txt\n");
    assert_eq!(file_after, b"USER\n");
}

#[test]
fn nonempty_legacy_v1_checkpoint_fails_closed_without_rewrite() {
    use sha2::{Digest, Sha256};

    let base = tempfile::tempdir().unwrap();
    let root = base.path().join("project");
    let checkpoints = base.path().join("checkpoints");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&checkpoints).unwrap();
    fs::write(root.join("f"), b"AGENT\n").unwrap();
    let hash = format!("{:x}", Sha256::digest(b"AGENT\n"));
    let bytes = serde_json::to_vec(&json!({
        "version": 1,
        "root": fs::canonicalize(&root).unwrap(),
        "turns": [{
            "entries": [{
                "root": null,
                "path": "f",
                "before": b"USER\n".to_vec(),
                "mode": 420,
                "readonly": false,
                "after_sha256": hash
            }],
            "shell_used": false
        }]
    }))
    .unwrap();
    fs::write(checkpoints.join("checkpoints.json"), &bytes).unwrap();

    assert!(Tools::new(&root, &checkpoints).is_err());
    assert_eq!(
        fs::read(checkpoints.join("checkpoints.json")).unwrap(),
        bytes
    );
    assert_eq!(fs::read(root.join("f")).unwrap(), b"AGENT\n");
}

#[test]
fn unknown_checkpoint_version_fails_closed_without_rewrite() {
    let base = tempfile::tempdir().unwrap();
    let root = base.path().join("project");
    let checkpoints = base.path().join("checkpoints");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&checkpoints).unwrap();
    fs::write(root.join("f"), b"USER\n").unwrap();
    let bytes = br#"{"version":4294967295,"root":"/unknown","turns":[]}"#;
    fs::write(checkpoints.join("checkpoints.json"), bytes).unwrap();

    assert!(Tools::new(&root, &checkpoints).is_err());
    assert_eq!(
        fs::read(checkpoints.join("checkpoints.json")).unwrap(),
        bytes
    );
    assert_eq!(fs::read(root.join("f")).unwrap(), b"USER\n");
}
