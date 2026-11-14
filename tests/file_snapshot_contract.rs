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

#[tokio::test]
async fn create_then_overwrite_succeeds_without_intermediate_read_and_detects_external_tamper() {
    let mut f = Fixture::new();
    assert!(!f.write("created.py", "v1\n").await.unwrap().is_error);
    assert!(
        !f.write("created.py", "v2\n").await.unwrap().is_error,
        "authoring actor should retain verified snapshot after creating file"
    );
    assert_eq!(fs::read(f.root.join("created.py")).unwrap(), b"v2\n");

    // External modification between writes must still be rejected.
    fs::write(f.root.join("created.py"), b"external\n").unwrap();
    let outcome = f.write("created.py", "v3\n").await;
    assert!(rejected(&outcome));
    assert_eq!(fs::read(f.root.join("created.py")).unwrap(), b"external\n");
}

#[tokio::test]
async fn read_then_edit_then_write_updates_snapshot_while_unobserved_edit_does_not() {
    let mut f = Fixture::new();
    f.file("mod.py", b"alpha = 1\nbeta = 2\n");
    assert!(!f.read("mod.py").await.unwrap().is_error);
    let edited = f
        .call(ToolCall::new(
            "edit_file",
            json!({"path":"mod.py","old_text":"alpha = 1","new_text":"alpha = 10"}),
        ))
        .await
        .unwrap();
    assert!(!edited.is_error, "{}", edited.content);
    let overwritten = f
        .write("mod.py", "alpha = 100\nbeta = 200\n")
        .await
        .unwrap();
    assert!(
        !overwritten.is_error,
        "edit_file on a previously observed file should advance the actor observation: {}",
        overwritten.content
    );
    assert_eq!(
        fs::read(f.root.join("mod.py")).unwrap(),
        b"alpha = 100\nbeta = 200\n"
    );

    // Editing a file that was never read must not mint a full-file observation.
    f.file("unread.py", b"one = 1\ntwo = 2\n");
    let blind_edit = f
        .call(ToolCall::new(
            "edit_file",
            json!({"path":"unread.py","old_text":"one = 1","new_text":"one = 10"}),
        ))
        .await
        .unwrap();
    assert!(!blind_edit.is_error, "{}", blind_edit.content);
    let follow_write = f.write("unread.py", "replaced\n").await;
    assert!(
        rejected(&follow_write),
        "edit_file without prior read must not authorize blind write_file"
    );
    assert_eq!(
        fs::read(f.root.join("unread.py")).unwrap(),
        b"one = 10\ntwo = 2\n"
    );
}

#[tokio::test]
async fn stale_observation_survives_edit_file_and_blocks_explicit_hash_bypass() {
    use sha2::{Digest, Sha256};
    let mut f = Fixture::new();
    let path = f.file("stale.py", b"keep = 1\ntarget = 2\n");
    assert!(!f.read("stale.py").await.unwrap().is_error);

    // External replacement changes inode and bytes while preserving `target = 2`.
    let replacement = f.root.join("stale.replacement");
    fs::write(&replacement, b"external = 99\ntarget = 2\n").unwrap();
    fs::rename(&replacement, &path).unwrap();

    let edited = f
        .call(ToolCall::new(
            "edit_file",
            json!({"path":"stale.py","old_text":"target = 2","new_text":"target = 20"}),
        ))
        .await
        .unwrap();
    assert!(!edited.is_error, "{}", edited.content);
    let post_edit_bytes = b"external = 99\ntarget = 20\n";
    assert_eq!(fs::read(&path).unwrap(), post_edit_bytes);

    let without_hash = f.write("stale.py", "overwrite\n").await;
    assert!(rejected(&without_hash));

    let with_explicit_hash = f
        .call(ToolCall::new(
            "write_file",
            json!({
                "path": "stale.py",
                "content": "overwrite\n",
                "expected_sha256": format!("{:x}", Sha256::digest(post_edit_bytes)),
            }),
        ))
        .await;
    assert!(
        rejected(&with_explicit_hash),
        "stale observation must not be refreshed or erased by edit_file"
    );
    assert_eq!(fs::read(&path).unwrap(), post_edit_bytes);

    // Untouched file without any prior WAL checkpoint: same-inode in-place modification
    // after read_file must block explicit expected_sha256 bypass at prepare() directly
    // (covers filesystems like ext4 when freed inodes are reused on atomic staging renames).
    let same_inode_path = f.file("same_inode.py", b"initial = 1\ntarget = 2\n");
    assert!(!f.read("same_inode.py").await.unwrap().is_error);
    let in_place_inode = fs::metadata(&same_inode_path).unwrap().ino();
    let in_place_bytes = b"in_place = 777\ntarget = 2\n";
    fs::write(&same_inode_path, in_place_bytes).unwrap();
    assert_eq!(
        fs::metadata(&same_inode_path).unwrap().ino(),
        in_place_inode
    );
    let bypass_same_inode = f
        .call(ToolCall::new(
            "write_file",
            json!({
                "path": "same_inode.py",
                "content": "overwrite\n",
                "expected_sha256": format!("{:x}", Sha256::digest(in_place_bytes)),
            }),
        ))
        .await;
    assert!(
        rejected(&bypass_same_inode),
        "explicit expected_sha256 must not bypass a stale read observation on an uncheckpointed file"
    );
    assert_eq!(fs::read(&same_inode_path).unwrap(), in_place_bytes);

    // Irreversible `stale` flag on no-op edit_file without any WAL checkpoint:
    // read(A) -> external in-place write(B) -> no-op edit_file(B -> B) -> external restore(A)
    // on the same inode must still reject write_file until a fresh read_file.
    let aba_path = f.file("aba_noop.py", b"state = 'A'\n");
    let aba_inode = fs::metadata(&aba_path).unwrap().ino();
    assert!(!f.read("aba_noop.py").await.unwrap().is_error);
    fs::write(&aba_path, b"state = 'B'\n").unwrap();
    assert_eq!(fs::metadata(&aba_path).unwrap().ino(), aba_inode);
    let noop_on_stale = f
        .call(ToolCall::new(
            "edit_file",
            json!({
                "path": "aba_noop.py",
                "old_text": "state = 'B'",
                "new_text": "state = 'B'",
            }),
        ))
        .await
        .unwrap();
    assert!(!noop_on_stale.is_error, "{}", noop_on_stale.content);
    fs::write(&aba_path, b"state = 'A'\n").unwrap();
    assert_eq!(fs::metadata(&aba_path).unwrap().ino(), aba_inode);
    assert!(
        rejected(&f.write("aba_noop.py", "overwrite\n").await),
        "no-op edit_file on modified file must mark observation irreversibly stale"
    );
    let aba_explicit = f
        .call(ToolCall::new(
            "write_file",
            json!({
                "path": "aba_noop.py",
                "content": "overwrite\n",
                "expected_sha256": format!("{:x}", Sha256::digest(b"state = 'A'\n")),
            }),
        ))
        .await;
    assert!(
        rejected(&aba_explicit),
        "explicit expected_sha256 must not bypass observation marked stale by no-op edit_file"
    );
    assert!(!f.read("aba_noop.py").await.unwrap().is_error);
    assert!(
        !f.write("aba_noop.py", "fresh = 1\n")
            .await
            .unwrap()
            .is_error
    );
}

#[tokio::test]
async fn noop_write_records_verified_observation_but_noop_edit_and_undo_do_not() {
    use sha2::{Digest, Sha256};
    let mut f = Fixture::new();
    f.file("noop.py", b"same = 1\n");
    let same_hash = format!("{:x}", Sha256::digest(b"same = 1\n"));

    // No-op edit without prior read must not mint an observation.
    let noop_edit = f
        .call(ToolCall::new(
            "edit_file",
            json!({"path":"noop.py","old_text":"same = 1","new_text":"same = 1"}),
        ))
        .await
        .unwrap();
    assert!(!noop_edit.is_error);
    assert!(rejected(&f.write("noop.py", "changed\n").await));

    // No-op write_file with explicit sha256 supplies the full content and records observation.
    let noop_write = f
        .call(ToolCall::new(
            "write_file",
            json!({"path":"noop.py","content":"same = 1\n","expected_sha256":same_hash}),
        ))
        .await
        .unwrap();
    assert!(!noop_write.is_error);
    assert!(!f.write("noop.py", "changed = 2\n").await.unwrap().is_error);

    // Undo restores the previous version on a fresh inode and must not refresh read_snapshots.
    f.tools.undo().unwrap();
    assert_eq!(fs::read(f.root.join("noop.py")).unwrap(), b"same = 1\n");
    assert!(
        rejected(&f.write("noop.py", "after undo\n").await),
        "undo must not grant an observation of restored bytes"
    );

    // Hard-linked file (nlink > 1) must not mint a write observation on no-op or allow modification.
    let linked = f.file("linked.py", b"linked = 1\n");
    fs::hard_link(&linked, f.root.join("linked_alias.py")).unwrap();
    let linked_hash = format!("{:x}", Sha256::digest(b"linked = 1\n"));
    let noop_linked = f
        .call(ToolCall::new(
            "write_file",
            json!({"path":"linked.py","content":"linked = 1\n","expected_sha256":linked_hash}),
        ))
        .await
        .unwrap();
    assert!(!noop_linked.is_error);
    assert!(rejected(&f.write("linked.py", "linked = 2\n").await));
}
