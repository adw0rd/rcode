#![cfg(any(target_os = "macos", target_os = "linux"))]

use rcode::{
    protocol::{ToolCall, ToolOutcome},
    tools::Tools,
};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};
use tokio_util::sync::CancellationToken;

struct Fixture {
    _base: tempfile::TempDir,
    root: PathBuf,
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
            tools,
        }
    }

    fn file(&self, relative: &str, bytes: &[u8]) -> PathBuf {
        let path = self.root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        path
    }

    async fn call(&mut self, call: ToolCall) -> anyhow::Result<ToolOutcome> {
        let args: Value = serde_json::from_str(&call.function.arguments).unwrap();
        self.tools
            .execute(&call.function.name, &args, &CancellationToken::new())
            .await
    }

    async fn read(&mut self, path: &str) -> anyhow::Result<ToolOutcome> {
        self.call(ToolCall::new("read_file", json!({"path":path})))
            .await
    }

    async fn write(&mut self, path: &str, content: &str) -> anyhow::Result<ToolOutcome> {
        self.call(ToolCall::new(
            "write_file",
            json!({"path":path,"content":content}),
        ))
        .await
    }
}

fn rejected(result: &anyhow::Result<ToolOutcome>) -> bool {
    match result {
        Ok(outcome) => outcome.is_error,
        Err(_) => true,
    }
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[tokio::test]
async fn same_bytes_and_mode_on_replacement_inode_rejects_write() {
    let mut f = Fixture::new();
    let path = f.file("p/f", b"user bytes\n");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    let original_inode = fs::metadata(&path).unwrap().ino();
    assert!(!f.read("p/f").await.unwrap().is_error);

    let replacement = f.root.join("p/replacement");
    fs::write(&replacement, b"user bytes\n").unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o640)).unwrap();
    let replacement_inode = fs::metadata(&replacement).unwrap().ino();
    fs::rename(&replacement, &path).unwrap();
    assert_ne!(original_inode, replacement_inode);
    assert_eq!(fs::metadata(&path).unwrap().ino(), replacement_inode);
    assert_eq!(fs::read(&path).unwrap(), b"user bytes\n");
    assert_eq!(mode(&path), 0o640);

    let outcome = f.write("p/f", "agent bytes\n").await;
    assert!(
        rejected(&outcome),
        "replacement inode must invalidate the file snapshot"
    );
    assert_eq!(fs::read(&path).unwrap(), b"user bytes\n");
}

#[tokio::test]
async fn same_file_moved_under_replacement_parent_rejects_write() {
    let mut f = Fixture::new();
    let path = f.file("p/f", b"user bytes\n");
    let file_inode = fs::metadata(&path).unwrap().ino();
    let parent_inode = fs::metadata(f.root.join("p")).unwrap().ino();
    assert!(!f.read("p/f").await.unwrap().is_error);

    let moved_parent = f.root.with_file_name("moved-parent");
    fs::rename(f.root.join("p"), &moved_parent).unwrap();
    fs::create_dir(f.root.join("p")).unwrap();
    fs::rename(moved_parent.join("f"), &path).unwrap();
    assert_ne!(parent_inode, fs::metadata(f.root.join("p")).unwrap().ino());
    assert_eq!(file_inode, fs::metadata(&path).unwrap().ino());

    let outcome = f.write("p/f", "agent bytes\n").await;
    assert!(
        rejected(&outcome),
        "changed parent identity must invalidate the read snapshot"
    );
    assert_eq!(fs::read(&path).unwrap(), b"user bytes\n");
}

#[tokio::test]
async fn renamed_workspace_root_cannot_write_through_stale_directory_handle() {
    let mut f = Fixture::new();
    f.file("f", b"user bytes\n");
    let old_root_inode = fs::metadata(&f.root).unwrap().ino();
    assert!(!f.read("f").await.unwrap().is_error);

    let moved_root = f.root.with_file_name("moved-project");
    fs::rename(&f.root, &moved_root).unwrap();
    let old_file = moved_root.join("f");
    fs::create_dir(&f.root).unwrap();
    let new_file = f.root.join("f");
    fs::write(&new_file, b"user bytes\n").unwrap();
    assert_ne!(old_root_inode, fs::metadata(&f.root).unwrap().ino());
    assert_eq!(fs::read(&old_file).unwrap(), b"user bytes\n");
    assert_eq!(fs::read(&new_file).unwrap(), b"user bytes\n");

    let outcome = f.write("f", "agent bytes\n").await;
    let old_unchanged = fs::read(&old_file).unwrap() == b"user bytes\n";
    let new_unchanged = fs::read(&new_file).unwrap() == b"user bytes\n";
    assert!(
        rejected(&outcome) && old_unchanged && new_unchanged,
        "workspace root rebinding must reject without changing either file: {outcome:?}"
    );
}

#[tokio::test]
async fn read_then_write_on_same_file_object_succeeds() {
    let mut f = Fixture::new();
    let path = f.file("f", b"user original\n");
    assert!(!f.read("f").await.unwrap().is_error);
    let outcome = f.write("f", "agent update\n").await.unwrap();
    assert!(
        !outcome.is_error,
        "ordinary host snapshot write should succeed: {}",
        outcome.content
    );
    assert_eq!(fs::read(path).unwrap(), b"agent update\n");
    f.tools.undo().unwrap();
    assert_eq!(fs::read(f.root.join("f")).unwrap(), b"user original\n");
}

#[tokio::test]
async fn replaced_ancestor_is_rejected_even_when_parent_and_file_are_the_same_objects() {
    let mut f = Fixture::new();
    let path = f.file("a/b/f", b"user bytes\n");
    let ancestor_inode = fs::metadata(f.root.join("a")).unwrap().ino();
    let parent_inode = fs::metadata(f.root.join("a/b")).unwrap().ino();
    let file_inode = fs::metadata(&path).unwrap().ino();
    assert!(!f.read("a/b/f").await.unwrap().is_error);

    let moved = f.root.with_file_name("moved-a");
    fs::rename(f.root.join("a"), &moved).unwrap();
    fs::create_dir(f.root.join("a")).unwrap();
    fs::rename(moved.join("b"), f.root.join("a/b")).unwrap();
    assert_ne!(
        ancestor_inode,
        fs::metadata(f.root.join("a")).unwrap().ino()
    );
    assert_eq!(
        parent_inode,
        fs::metadata(f.root.join("a/b")).unwrap().ino()
    );
    assert_eq!(
        file_inode,
        fs::metadata(f.root.join("a/b/f")).unwrap().ino()
    );

    let outcome = f.write("a/b/f", "agent bytes\n").await;
    assert!(
        rejected(&outcome),
        "changed ancestor must invalidate the read binding"
    );
    assert_eq!(fs::read(&path).unwrap(), b"user bytes\n");
}

#[tokio::test]
async fn stale_workspace_root_rejects_edit_without_touching_either_tree() {
    let mut f = Fixture::new();
    f.file("f", b"user bytes\n");
    let moved = f.root.with_file_name("moved-project");
    fs::rename(&f.root, &moved).unwrap();
    fs::create_dir(&f.root).unwrap();
    fs::write(f.root.join("f"), b"user bytes\n").unwrap();

    let outcome = f
        .call(ToolCall::new(
            "edit_file",
            json!({"path":"f","old_text":"user","new_text":"agent"}),
        ))
        .await;
    assert!(rejected(&outcome), "edit through a stale root must fail");
    assert_eq!(fs::read(moved.join("f")).unwrap(), b"user bytes\n");
    assert_eq!(fs::read(f.root.join("f")).unwrap(), b"user bytes\n");
}

#[tokio::test]
async fn stale_workspace_root_rejects_new_file_without_creating_it_anywhere() {
    let mut f = Fixture::new();
    let moved = f.root.with_file_name("moved-project");
    fs::rename(&f.root, &moved).unwrap();
    fs::create_dir(&f.root).unwrap();

    let outcome = f.write("new.txt", "agent bytes\n").await;
    assert!(
        rejected(&outcome),
        "new-file write through a stale root must fail"
    );
    assert!(!moved.join("new.txt").exists());
    assert!(!f.root.join("new.txt").exists());
}

#[tokio::test]
async fn stale_workspace_root_rejects_undo_without_touching_either_tree() {
    let mut f = Fixture::new();
    f.file("f", b"user bytes\n");
    assert!(!f.read("f").await.unwrap().is_error);
    assert!(!f.write("f", "agent bytes\n").await.unwrap().is_error);
    let moved = f.root.with_file_name("moved-project");
    fs::rename(&f.root, &moved).unwrap();
    fs::create_dir(&f.root).unwrap();
    fs::write(f.root.join("f"), b"agent bytes\n").unwrap();

    assert!(
        f.tools.undo().is_err(),
        "undo must reject the stale retained root"
    );
    assert_eq!(fs::read(moved.join("f")).unwrap(), b"agent bytes\n");
    assert_eq!(fs::read(f.root.join("f")).unwrap(), b"agent bytes\n");
}

#[tokio::test]
async fn explicit_hash_does_not_bypass_a_stale_host_identity_observation() {
    use sha2::{Digest, Sha256};
    let mut f = Fixture::new();
    let path = f.file("f", b"same bytes\n");
    let inode = fs::metadata(&path).unwrap().ino();
    assert!(!f.read("f").await.unwrap().is_error);
    let replacement = f.root.join("replacement");
    fs::write(&replacement, b"same bytes\n").unwrap();
    fs::rename(&replacement, &path).unwrap();
    assert_ne!(inode, fs::metadata(&path).unwrap().ino());

    let outcome = f.call(ToolCall::new(
        "write_file",
        json!({"path":"f","content":"agent bytes\n","expected_sha256":format!("{:x}", Sha256::digest(b"same bytes\n"))}),
    )).await;
    assert!(
        rejected(&outcome),
        "matching bytes/hash must not excuse a changed inode"
    );
    assert_eq!(fs::read(&path).unwrap(), b"same bytes\n");
}

#[tokio::test]
async fn explicit_hash_remains_compatible_without_a_read_observation() {
    use sha2::{Digest, Sha256};
    let mut f = Fixture::new();
    let path = f.file("f", b"original\n");
    let wrong = f
        .call(ToolCall::new(
            "write_file",
            json!({"path":"f","content":"wrong\n","expected_sha256":"0".repeat(64)}),
        ))
        .await;
    assert!(rejected(&wrong));
    let correct = f.call(ToolCall::new(
        "write_file",
        json!({"path":"f","content":"agent\n","expected_sha256":format!("{:x}", Sha256::digest(b"original\n"))}),
    )).await;
    assert!(
        !correct.unwrap().is_error,
        "matching explicit file hash keeps compatibility"
    );
    assert_eq!(fs::read(path).unwrap(), b"agent\n");
}

#[tokio::test]
async fn replaced_explicitly_granted_root_rejects_write() {
    let mut f = Fixture::new();
    let external = f._base.path().join("external");
    fs::create_dir(&external).unwrap();
    fs::write(external.join("f"), b"user bytes\n").unwrap();
    f.tools.add_directory(&external).unwrap();
    assert!(
        !f.read(external.join("f").to_str().unwrap())
            .await
            .unwrap()
            .is_error
    );

    let moved = external.with_file_name("moved-external");
    fs::rename(&external, &moved).unwrap();
    fs::create_dir(&external).unwrap();
    fs::write(external.join("f"), b"user bytes\n").unwrap();
    let outcome = f
        .write(external.join("f").to_str().unwrap(), "agent bytes\n")
        .await;
    assert!(
        rejected(&outcome),
        "replacement of an approved root must fail closed"
    );
    assert_eq!(fs::read(moved.join("f")).unwrap(), b"user bytes\n");
    assert_eq!(fs::read(external.join("f")).unwrap(), b"user bytes\n");
}
