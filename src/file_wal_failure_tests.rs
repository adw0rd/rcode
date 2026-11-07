//! Cross-layer WAL durability failure tests.
//!
//! This file is included as a child of `tools::tests` so it can share its
//! fixture and arm per-store test-only failures at precise WAL phase hooks.

use super::tests::{Fixture, hash};
use super::{Tools, WalFaultPoint};
use crate::file_wal::{BlobStore, StoreFaultPoint};
use serde_json::json;
use std::{fs, path::Path};
use tokio_util::sync::CancellationToken;

fn write_args(path: &str, old: &[u8], new: &str) -> serde_json::Value {
    json!({
        "path": path,
        "content": new,
        "expected_sha256": hash(old),
    })
}

fn manifest(state: &Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(state.join("checkpoints.json")).unwrap()).unwrap()
}

fn inode(path: &Path) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::metadata(path).unwrap();
    (metadata.dev(), metadata.ino())
}

#[tokio::test]
async fn prepared_manifest_temp_sync_failure_leaves_targets_untouched_and_poisons_tools() {
    let mut fixture = Fixture::new();
    fixture.file("a.rs", "user");
    fixture.tools.fail_store_after_wal_point(
        WalFaultPoint::BeforePreparedPersist,
        StoreFaultPoint::ManifestTempFileSync,
        libc::EIO,
    );

    let failure = fixture
        .tools
        .execute(
            "write_file",
            &write_args("a.rs", b"user", "agent"),
            &CancellationToken::new(),
        )
        .await;
    assert!(
        failure.is_err(),
        "expected an injected prepared-manifest EIO"
    );
    assert_eq!(
        fs::read_to_string(fixture.root.join("a.rs")).unwrap(),
        "user"
    );
    let saved = manifest(&fixture.state);
    assert!(saved["pending_write"]["stage"]["name"].as_str().is_some());
    assert!(saved["pending_write"]["stage"]["payload"].is_null());
    assert!(saved["pending_write"]["candidate"]["after_identity"].is_null());

    let retry = fixture
        .tools
        .execute(
            "write_file",
            &write_args("a.rs", b"user", "retry"),
            &CancellationToken::new(),
        )
        .await;
    assert!(retry.is_err(), "same Tools instance must remain poisoned");
    assert_eq!(
        fs::read_to_string(fixture.root.join("a.rs")).unwrap(),
        "user"
    );
    assert!(!fixture.root.join("new.rs").exists());
    let new_write = fixture
        .tools
        .execute(
            "write_file",
            &json!({"path":"new.rs","content":"blocked"}),
            &CancellationToken::new(),
        )
        .await;
    assert!(
        new_write.is_err(),
        "a new write must be blocked after persistence failure"
    );
    assert!(!fixture.root.join("new.rs").exists());
}

#[tokio::test]
async fn prepared_manifest_rename_enospc_keeps_workspace_before_image() {
    let mut fixture = Fixture::new();
    fixture.file("a.rs", "user");
    fixture.tools.fail_store_after_wal_point(
        WalFaultPoint::BeforePreparedPersist,
        StoreFaultPoint::ManifestBeforeRename,
        libc::ENOSPC,
    );

    let failure = fixture
        .tools
        .execute(
            "write_file",
            &write_args("a.rs", b"user", "agent"),
            &CancellationToken::new(),
        )
        .await;
    assert!(
        failure.is_err(),
        "expected ENOSPC immediately before manifest rename"
    );
    assert_eq!(
        fs::read_to_string(fixture.root.join("a.rs")).unwrap(),
        "user"
    );
    let saved = manifest(&fixture.state);
    assert!(saved["pending_write"]["stage"]["name"].as_str().is_some());
    assert!(saved["pending_write"]["stage"]["payload"].is_null());
    assert!(saved["pending_write"]["candidate"]["after_identity"].is_null());
    let retry = fixture
        .tools
        .execute(
            "write_file",
            &write_args("a.rs", b"user", "retry"),
            &CancellationToken::new(),
        )
        .await;
    assert!(retry.is_err());
    assert_eq!(
        fs::read_to_string(fixture.root.join("a.rs")).unwrap(),
        "user"
    );
}

#[tokio::test]
async fn final_manifest_dir_sync_eio_poison_blocks_replay_until_reopen() {
    let mut fixture = Fixture::new();
    fixture.file("a.rs", "user");
    fixture.tools.fail_store_after_wal_point(
        WalFaultPoint::BeforeFinalPersist,
        StoreFaultPoint::ManifestAfterRenameBeforeDirSync,
        libc::EIO,
    );

    let failure = fixture
        .tools
        .execute(
            "write_file",
            &write_args("a.rs", b"user", "agent"),
            &CancellationToken::new(),
        )
        .await;
    assert!(
        failure.is_err(),
        "expected final manifest directory-sync EIO"
    );
    assert!(manifest(&fixture.state)["pending_write"].is_null());
    assert_eq!(
        fs::read_to_string(fixture.root.join("a.rs")).unwrap(),
        "agent"
    );
    let published_inode = inode(&fixture.root.join("a.rs"));

    let retry = fixture
        .tools
        .execute(
            "write_file",
            &write_args("a.rs", b"agent", "duplicate"),
            &CancellationToken::new(),
        )
        .await;
    assert!(
        retry.is_err(),
        "poisoned Tools must not publish a second stage"
    );
    assert_eq!(
        fs::read_to_string(fixture.root.join("a.rs")).unwrap(),
        "agent"
    );
    assert_eq!(inode(&fixture.root.join("a.rs")), published_inode);

    let root = fixture.root.clone();
    let state = fixture.state.clone();
    drop(fixture.tools);
    let mut reopened = Tools::new(&root, &state).unwrap();
    assert_eq!(fs::read_to_string(root.join("a.rs")).unwrap(), "agent");
    assert_eq!(inode(&root.join("a.rs")), published_inode);
    reopened.undo().unwrap();
    assert_eq!(fs::read_to_string(root.join("a.rs")).unwrap(), "user");
}

#[test]
fn blob_sync_failure_leaves_a_private_counted_orphan_without_a_reference() {
    let temp = tempfile::tempdir().unwrap();
    let store_path = temp.path().join("wal");
    let store = BlobStore::open(&store_path).unwrap();
    store.acquire_lock().unwrap();
    assert_eq!(store.open_manifest().unwrap(), None);
    store
        .fail_next(StoreFaultPoint::BlobFileSync, libc::EIO)
        .unwrap();
    assert!(store.write_image(b"private preimage").is_err());
    let entries = fs::read_dir(store_path.join("blobs"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        entries.len(),
        1,
        "failed blob sync must leave a private orphan"
    );
    let metadata = entries[0].metadata().unwrap();
    use std::os::unix::fs::PermissionsExt;
    assert!(metadata.is_file());
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
    assert!(store.reserve(crate::file_wal::MAX_STORE_BYTES, 0).is_err());
}

#[tokio::test]
async fn metadata_slots_keep_previous_undo_available_after_failed_prepared_persist() {
    use std::os::unix::fs::OpenOptionsExt;
    let mut fixture = Fixture::new();
    fixture.file("a.rs", "user");
    let first = fixture
        .tools
        .execute(
            "write_file",
            &write_args("a.rs", b"user", "agent"),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(!first.is_error);
    let entries = fs::read_dir(&fixture.state).unwrap().count()
        + fs::read_dir(fixture.state.join("blobs")).unwrap().count();
    let limit = crate::file_wal::MAX_STORE_ENTRIES - 2;
    for index in entries..limit {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(fixture.state.join(format!("quota-held-{index:05}")))
            .unwrap();
    }
    fixture.tools.fail_store_after_wal_point(
        WalFaultPoint::BeforePreparedPersist,
        StoreFaultPoint::ManifestTempFileSync,
        libc::ENOSPC,
    );
    let rejected = fixture
        .tools
        .execute(
            "write_file",
            &write_args("a.rs", b"agent", "second"),
            &CancellationToken::new(),
        )
        .await;
    assert!(rejected.is_err() || rejected.as_ref().is_ok_and(|outcome| outcome.is_error));
    assert_eq!(fs::read(fixture.root.join("a.rs")).unwrap(), b"agent");
    let root = fixture.root.clone();
    let state = fixture.state.clone();
    drop(fixture.tools);
    let mut reopened = Tools::new(&root, &state)
        .expect("new-write admission must retain namespace slots for recovery and undo");
    reopened.undo().unwrap();
    assert_eq!(fs::read(root.join("a.rs")).unwrap(), b"user");
}
