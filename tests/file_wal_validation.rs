#![cfg(any(target_os = "linux", target_os = "macos"))]

use rcode::tools::Tools;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
use tokio_util::sync::CancellationToken;

const MANIFEST: &str = "checkpoints.json";

struct Fixture {
    _base: tempfile::TempDir,
    root: PathBuf,
    checkpoints: PathBuf,
    tools: Option<Tools>,
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
            tools: Some(tools),
        }
    }

    async fn call(&mut self, name: &str, args: Value) -> anyhow::Result<()> {
        let result = self
            .tools
            .as_mut()
            .unwrap()
            .execute(name, &args, &CancellationToken::new())
            .await?;
        anyhow::ensure!(!result.is_error, "{name} failed: {}", result.content);
        Ok(())
    }

    async fn write(&mut self, path: &str, contents: &str) -> anyhow::Result<()> {
        self.call("read_file", json!({"path": path})).await?;
        self.call("write_file", json!({"path": path, "content": contents}))
            .await
    }

    async fn write_with_expected_sha256(
        &mut self,
        path: &str,
        contents: &str,
        expected_sha256: &str,
    ) -> anyhow::Result<()> {
        self.call(
            "write_file",
            json!({
                "path": path,
                "content": contents,
                "expected_sha256": expected_sha256
            }),
        )
        .await
    }

    fn manifest_path(&self) -> PathBuf {
        self.checkpoints.join(MANIFEST)
    }
}

fn manifest_value(f: &Fixture) -> Value {
    let manifest: Value = serde_json::from_slice(&fs::read(f.manifest_path()).unwrap()).unwrap();
    assert_eq!(manifest["version"], 3, "fixture must emit a v3 manifest");
    manifest
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn wal_stage_name() -> String {
    format!(".rcode-wal-{}.stage", uuid::Uuid::new_v4())
}

fn replace_manifest(f: &Fixture, value: &Value) -> Vec<u8> {
    let bytes = serde_json::to_vec(value).unwrap();
    fs::write(f.manifest_path(), &bytes).unwrap();
    bytes
}

fn workspace_snapshot(root: &Path) -> BTreeMap<PathBuf, (Vec<u8>, u32)> {
    fn visit(root: &Path, dir: &Path, files: &mut BTreeMap<PathBuf, (Vec<u8>, u32)>) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            if metadata.is_dir() {
                visit(root, &path, files);
            } else if metadata.is_file() {
                files.insert(
                    path.strip_prefix(root).unwrap().to_owned(),
                    (
                        fs::read(&path).unwrap(),
                        metadata.permissions().mode() & 0o777,
                    ),
                );
            }
        }
    }

    let mut files = BTreeMap::new();
    visit(root, root, &mut files);
    files
}

async fn committed_fixture() -> Fixture {
    let mut f = Fixture::new();
    fs::write(f.root.join("tracked.txt"), b"user-before\n").unwrap();
    // The fixture uses a real Tools write so image references and nested
    // manifest shapes come from the implementation under test.
    f.write("tracked.txt", "agent-after\n").await.unwrap();
    f
}

async fn committed_two_turn_fixture() -> Fixture {
    let mut f = committed_fixture().await;
    f.tools.as_mut().unwrap().begin_turn().unwrap();
    fs::write(f.root.join("later.txt"), b"later-before\n").unwrap();
    f.write("later.txt", "later-after\n").await.unwrap();
    f
}

#[tokio::test]
async fn eleven_one_mib_writes_reopen_and_undo_restore_exact_bytes_and_modes() {
    let mut f = Fixture::new();
    let mut originals = Vec::new();
    for index in 0..11 {
        let name = format!("file-{index}.txt");
        let path = f.root.join(&name);
        let original = format!("{index:02}{}", "b".repeat(1024 * 1024 - 2)).into_bytes();
        assert_eq!(original.len(), 1024 * 1024);
        fs::write(&path, &original).unwrap();
        let mode = if index % 2 == 0 { 0o751 } else { 0o640 };
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        let after = format!("{index:02}{}", "x".repeat(1024 * 1024 - 2));
        assert_eq!(after.len(), 1024 * 1024);
        f.write_with_expected_sha256(&name, &after, &sha256(&original))
            .await
            .unwrap();
        originals.push((name, original, mode));
    }

    let manifest = fs::read(f.manifest_path()).unwrap();
    assert!(
        manifest.len() < 4 * 1024 * 1024,
        "manifest is {} bytes",
        manifest.len()
    );
    assert!(
        !manifest
            .windows(32)
            .any(|window| window == b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
    );
    assert!(
        !manifest
            .windows(32)
            .any(|window| window == b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    );
    drop(f.tools.take());

    let mut reopened = Tools::new(&f.root, &f.checkpoints).unwrap();
    reopened.undo().unwrap();
    for (name, bytes, mode) in originals {
        let path = f.root.join(&name);
        let restored = fs::read(&path).unwrap();
        assert_eq!(
            restored.len(),
            bytes.len(),
            "{name}: wrong length after undo"
        );
        assert_eq!(
            sha256(&restored),
            sha256(&bytes),
            "{name}: hash mismatch after undo"
        );
        assert!(
            restored.as_slice() == bytes.as_slice(),
            "{name}: bytes not exact after undo"
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            mode,
            "{name}: mode mismatch after undo"
        );
    }
}

#[test]
fn checkpoint_lease_is_exclusive_for_tools_lifetime() {
    let mut f = Fixture::new();
    assert!(Tools::new(&f.root, &f.checkpoints).is_err());
    drop(f.tools.take());
    assert!(Tools::new(&f.root, &f.checkpoints).is_ok());
}

#[tokio::test]
async fn v3_without_root_identity_fails_closed_without_rewrite() {
    let mut f = committed_fixture().await;
    drop(f.tools.take());
    let mut state = manifest_value(&f);
    state.as_object_mut().unwrap().remove("root_identity");
    let bytes = replace_manifest(&f, &state);
    let workspace = workspace_snapshot(&f.root);

    assert!(Tools::new(&f.root, &f.checkpoints).is_err());
    assert_eq!(fs::read(f.manifest_path()).unwrap(), bytes);
    assert_eq!(workspace_snapshot(&f.root), workspace);
}

#[tokio::test]
async fn unknown_nested_manifest_field_fails_closed_without_rewrite() {
    let mut f = committed_fixture().await;
    drop(f.tools.take());
    let mut state = manifest_value(&f);
    state["turns"][0]["entries"][0]["after_image"]["surprise"] = json!(true);
    let bytes = replace_manifest(&f, &state);
    let workspace = workspace_snapshot(&f.root);

    assert!(Tools::new(&f.root, &f.checkpoints).is_err());
    assert_eq!(fs::read(f.manifest_path()).unwrap(), bytes);
    assert_eq!(workspace_snapshot(&f.root), workspace);
}

#[tokio::test]
async fn corrupt_referenced_blob_fails_closed_without_rewrite_or_workspace_change() {
    let mut f = committed_fixture().await;
    drop(f.tools.take());
    let state = manifest_value(&f);
    let id = state["turns"][0]["entries"][0]["after_image"]["image"]["id"]
        .as_str()
        .unwrap();
    let blob = f.checkpoints.join("blobs").join(id);
    let original = fs::read(&blob).unwrap();
    let mut corrupted = original.clone();
    corrupted[0] ^= 0xff;
    fs::write(&blob, &corrupted).unwrap();
    let manifest = fs::read(f.manifest_path()).unwrap();
    let workspace = workspace_snapshot(&f.root);

    assert!(Tools::new(&f.root, &f.checkpoints).is_err());
    assert_eq!(fs::read(f.manifest_path()).unwrap(), manifest);
    assert_eq!(fs::read(&blob).unwrap(), corrupted);
    assert_eq!(workspace_snapshot(&f.root), workspace);
}

fn assert_rejected_manifest_unchanged(f: &mut Fixture, state: Value) {
    drop(f.tools.take());
    let bytes = replace_manifest(f, &state);
    let workspace = workspace_snapshot(&f.root);
    assert!(Tools::new(&f.root, &f.checkpoints).is_err());
    assert_eq!(fs::read(f.manifest_path()).unwrap(), bytes);
    assert_eq!(workspace_snapshot(&f.root), workspace);
}

fn pending_write_from_entry(entry: &Value) -> Value {
    let mut candidate = entry.clone();
    // A write intent has not published yet, so its candidate has no published
    // identity. The intended after-image is the original USER preimage; the
    // immediate-before image and identity are the current AGENT postimage.
    candidate["after_image"] = entry["before"].clone();
    candidate["after_sha256"] = entry["before"]["image"]["sha256"].clone();
    candidate["after_mode"] = Value::Null;
    candidate["after_identity"] = Value::Null;
    candidate["binding"] = Value::Null;
    json!({
        "turn": 0,
        "candidate": candidate,
        "before_image": entry["after_image"],
        "before_sha256": entry["after_sha256"],
        "before_identity": entry["after_identity"],
        "before_mode": entry["after_mode"],
        "before_readonly": entry["readonly"],
        "before_binding": entry["binding"],
        "stage": null
    })
}

#[tokio::test]
async fn valid_staging_write_intent_aborts_metadata_only_and_preserves_old_undo() {
    let mut f = committed_fixture().await;
    let mut state = manifest_value(&f);
    let entry = state["turns"][0]["entries"][0].clone();
    let mut pending = pending_write_from_entry(&entry);
    pending["stage"] = json!({
        "name": wal_stage_name(),
        "directory": null,
        "guard": null,
        "payload": null
    });
    state["pending_write"] = pending;
    let postimage = workspace_snapshot(&f.root);
    drop(f.tools.take());
    replace_manifest(&f, &state);

    let mut reopened = Tools::new(&f.root, &f.checkpoints)
        .expect("a valid Staging intent should metadata-abort during reopen");
    assert_eq!(workspace_snapshot(&f.root), postimage);
    let recovered = manifest_value(&f);
    assert!(recovered["pending_write"].is_null());
    assert_eq!(recovered["orphan_stages"].as_array().unwrap().len(), 1);
    assert_eq!(
        recovered["orphan_stages"][0]["stage"]["payload"],
        Value::Null
    );

    reopened
        .undo()
        .expect("the prior committed undo must remain available");
    let restored = f.root.join("tracked.txt");
    assert_eq!(fs::read(&restored).unwrap(), b"user-before\n");
    assert_eq!(
        fs::metadata(&restored).unwrap().permissions().mode() & 0o777,
        entry["mode"].as_u64().unwrap() as u32
    );
}

#[tokio::test]
async fn malformed_nested_write_stage_refs_fail_closed_without_rewrite() {
    let mut f = committed_fixture().await;
    let base = manifest_value(&f);
    let entry = base["turns"][0]["entries"][0].clone();

    let mut missing_stage_name = base.clone();
    let mut pending = pending_write_from_entry(&entry);
    pending["stage"] = json!({
        "directory": null,
        "guard": null,
        "payload": null
    });
    missing_stage_name["pending_write"] = pending;
    assert_rejected_manifest_unchanged(&mut f, missing_stage_name);

    let mut f = committed_fixture().await;
    let base = manifest_value(&f);
    let entry = base["turns"][0]["entries"][0].clone();
    let mut payload_without_guard = base.clone();
    let mut pending = pending_write_from_entry(&entry);
    let stage_identity = entry["after_identity"].clone();
    pending["candidate"]["after_mode"] = entry["mode"].clone();
    pending["candidate"]["after_identity"] = stage_identity.clone();
    pending["candidate"]["binding"] = entry["binding"].clone();
    pending["stage"] = json!({
        "name": wal_stage_name(),
        "directory": stage_identity,
        "guard": null,
        "payload": entry["after_identity"]
    });
    payload_without_guard["pending_write"] = pending;
    assert_rejected_manifest_unchanged(&mut f, payload_without_guard);

    let mut f = committed_fixture().await;
    let base = manifest_value(&f);
    let entry = base["turns"][0]["entries"][0].clone();
    let mut unknown_nested_field = base;
    let mut pending = pending_write_from_entry(&entry);
    pending["stage"] = json!({
        "name": wal_stage_name(),
        "directory": null,
        "guard": null,
        "payload": null,
        "unexpected": true
    });
    unknown_nested_field["pending_write"] = pending;
    assert_rejected_manifest_unchanged(&mut f, unknown_nested_field);
}

#[tokio::test]
async fn malformed_nested_undo_intents_fail_closed_without_rewrite() {
    let mut f = committed_two_turn_fixture().await;
    let mut base = manifest_value(&f);

    let mut stale_turn = base.clone();
    stale_turn["pending_undo"] = json!({
        "turn": 0,
        "order": [0],
        "prepared": false,
        "entries": [{"stage": null, "done": null}]
    });
    assert_rejected_manifest_unchanged(&mut f, stale_turn);

    let mut f = committed_fixture().await;
    base = manifest_value(&f);
    let entry = base["turns"][0]["entries"][0].clone();
    let mut deleted_existing = base.clone();
    deleted_existing["pending_undo"] = json!({
        "turn": 0,
        "order": [0],
        "prepared": true,
        "entries": [{
            "stage": {
                "name": wal_stage_name(),
                "directory": entry["after_identity"],
                "guard": entry["after_identity"],
                "payload": entry["after_identity"]
            },
            "done": {"state": "Deleted"}
        }]
    });
    assert_rejected_manifest_unchanged(&mut f, deleted_existing);

    let mut f = committed_fixture().await;
    base = manifest_value(&f);
    let entry = base["turns"][0]["entries"][0].clone();
    let mut missing_guard = base.clone();
    missing_guard["pending_undo"] = json!({
        "turn": 0,
        "order": [0],
        "prepared": true,
        "entries": [{"stage": {
            "name": wal_stage_name(),
            "directory": entry["after_identity"],
            "guard": null,
            "payload": entry["after_identity"]
        }, "done": null}]
    });
    assert_rejected_manifest_unchanged(&mut f, missing_guard);

    let mut f = committed_fixture().await;
    let base = manifest_value(&f);
    let entry = base["turns"][0]["entries"][0].clone();
    let mut unknown_nested_field = base;
    unknown_nested_field["pending_undo"] = json!({
        "turn": 0,
        "order": [0],
        "prepared": true,
        "entries": [{"stage": {
            "name": wal_stage_name(),
            "directory": entry["after_identity"],
            "guard": entry["after_identity"],
            "payload": entry["after_identity"],
            "unexpected": true
        }, "done": null}]
    });
    assert_rejected_manifest_unchanged(&mut f, unknown_nested_field);
}
