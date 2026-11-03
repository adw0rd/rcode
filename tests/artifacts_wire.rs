use rcode::artifacts::{ArtifactOrigin, ArtifactStore};
fn origin(actor: Option<&str>) -> ArtifactOrigin {
    ArtifactOrigin {
        actor: actor.map(str::to_owned),
        turn: 7,
        tool: "read_file".into(),
        call_id: "call-7".into(),
    }
}
#[test]
fn receipt_is_private_redacted_immutable_and_owner_scoped() {
    let tmp = tempfile::tempdir().unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let store = ArtifactStore::open(tmp.path(), &id).unwrap();
    let secret = "artifact-secret-canary";
    let meta = store
        .capture(
            origin(Some("worker-a")),
            &format!("first\n{secret}\nlast\n"),
            &[secret.into()],
        )
        .unwrap();
    let page = store.read(Some("worker-a"), &meta.id, 1, 2, None).unwrap();
    assert_eq!(page.content, "first\n[REDACTED]\n");
    assert_eq!(page.next_line, Some(3));
    assert!(store.read(Some("worker-b"), &meta.id, 1, 5, None).is_err());
    assert_eq!(
        store.read(None, &meta.id, 3, 5, None).unwrap().content,
        "last\n"
    );
    assert_eq!(
        store
            .read(None, &meta.id, 1, 500, Some("last"))
            .unwrap()
            .content,
        "3: last\n"
    );
    for path in ["../session.json", "/etc/passwd", ".lock"] {
        assert!(store.read(None, path, 1, 1, None).is_err());
    }
    for e in std::fs::read_dir(tmp.path().join("artifacts")).unwrap() {
        let bytes = std::fs::read(e.unwrap().path()).unwrap();
        assert!(!bytes.windows(secret.len()).any(|w| w == secret.as_bytes()));
    }
    assert!(ArtifactStore::open(tmp.path(), &uuid::Uuid::new_v4().to_string()).is_err());
}
#[cfg(unix)]
#[test]
fn symlink_and_corruption_cannot_be_read_or_overwritten() {
    use std::os::unix::fs::symlink;
    let tmp = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let sid = uuid::Uuid::new_v4().to_string();
    symlink(other.path(), tmp.path().join("artifacts")).unwrap();
    assert!(ArtifactStore::open(tmp.path(), &sid).is_err());
    std::fs::remove_file(tmp.path().join("artifacts")).unwrap();
    let store = ArtifactStore::open(tmp.path(), &sid).unwrap();
    let meta = store.capture(origin(None), "original", &[]).unwrap();
    let path = tmp.path().join("artifacts").join(&meta.id);
    let original = std::fs::read(&path).unwrap();
    let mut changed = original.clone();
    *changed.last_mut().unwrap() ^= 1;
    std::fs::write(&path, &changed).unwrap();
    assert!(store.read(None, &meta.id, 1, 1, None).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), changed);
}
#[cfg(unix)]
#[test]
fn restart_recovers_own_partial_and_double_link_publication_without_replay() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let sid = uuid::Uuid::new_v4().to_string();
    let store = ArtifactStore::open(tmp.path(), &sid).unwrap();
    let meta = store.capture(origin(None), "committed", &[]).unwrap();
    let dir = tmp.path().join("artifacts");
    let linked = dir.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
    std::fs::hard_link(dir.join(&meta.id), &linked).unwrap();
    let partial = dir.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
    std::fs::write(&partial, b"ARTIF").unwrap();
    std::fs::set_permissions(&partial, std::fs::Permissions::from_mode(0o600)).unwrap();
    drop(store);
    let restored = ArtifactStore::open(tmp.path(), &sid).unwrap();
    assert!(!partial.exists() && !linked.exists());
    assert_eq!(
        restored.read(None, &meta.id, 1, 1, None).unwrap().content,
        "committed"
    );
    restored.capture(origin(None), "next receipt", &[]).unwrap();
}
#[test]
fn known_secret_in_structural_session_identifier_is_rejected_before_disk() {
    let tmp = tempfile::tempdir().unwrap();
    let secret = "session-key-canary";
    let store = ArtifactStore::open(tmp.path(), secret).unwrap();
    assert!(
        store
            .capture(origin(None), "safe", &[secret.into()])
            .is_err()
    );
    assert_eq!(
        std::fs::read_dir(tmp.path().join("artifacts"))
            .unwrap()
            .count(),
        1
    );
}
#[test]
fn byte_cursor_recovers_a_long_unicode_line_exactly() {
    let tmp = tempfile::tempdir().unwrap();
    let sid = uuid::Uuid::new_v4().to_string();
    let store = ArtifactStore::open(tmp.path(), &sid).unwrap();
    let content = "ёж🦀".repeat(20000);
    let meta = store.capture(origin(None), &content, &[]).unwrap();
    let mut offset = 0;
    let mut restored = String::new();
    loop {
        let page = store.read_bytes(None, &meta.id, offset, 4096).unwrap();
        assert!(page.content.len() <= 4096);
        restored.push_str(&page.content);
        match page.next_offset {
            Some(next) => {
                assert!(next > offset);
                offset = next
            }
            None => break,
        }
    }
    assert_eq!(restored, content);
    assert!(store.read_bytes(None, &meta.id, 1, 4000).is_err());
    assert!(store.read_bytes(Some("other"), &meta.id, 0, 4000).is_err());
}
