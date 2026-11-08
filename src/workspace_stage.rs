//! Private per-operation staging directories for workspace writes.
//!
//! A stage's payload is created only after a durable `.gitignore` guard is in
//! place. The stage directory is kept open only while one entry is processed;
//! durable references contain names and identities, never open descriptors.

#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    ffi::{OsStr, OsString},
    io::{Read, Write},
    path::Path,
};

use anyhow::{Context, Result, anyhow, ensure};
use cap_fs_ext::{DirExt, FollowSymlinks, MetadataExt, OpenOptionsFollowExt, OpenOptionsSyncExt};
use cap_std::fs::{
    Dir, DirBuilder, DirBuilderExt, Metadata, MetadataExt as UnixMetadataExt, OpenOptions,
    OpenOptionsExt, Permissions, PermissionsExt,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::file_wal::Identity;

pub(crate) const PAYLOAD: &str = "payload";
pub(crate) const GUARD: &str = ".gitignore";
pub(crate) const MAX_STAGE_BYTES: usize = 1024 * 1024;
const GUARD_BYTES: &[u8] = b"*\n";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StageRef {
    pub name: String,
    pub directory: Option<Identity>,
    pub guard: Option<Identity>,
    pub payload: Option<Identity>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PayloadProof {
    pub sha256: String,
    pub len: usize,
    pub mode: u32,
}

/// A transient handle for one stage directory. Keep one of these at a time;
/// group state stores only `StageRef` and reopens each entry when needed.
pub(crate) struct StageDirectory {
    reference: StageRef,
    parent_identity: Identity,
    dir: Dir,
}

impl StageDirectory {
    pub(crate) fn plan_name() -> String {
        format!(".rcode-wal-{}.stage", uuid::Uuid::new_v4())
    }

    pub(crate) fn valid_name(name: &str) -> bool {
        let Some(uuid) = name
            .strip_prefix(".rcode-wal-")
            .and_then(|name| name.strip_suffix(".stage"))
        else {
            return false;
        };
        uuid::Uuid::parse_str(uuid).is_ok_and(|id| {
            id.get_version_num() == 4
                && id.get_variant() == uuid::Variant::RFC4122
                && id.to_string() == uuid
        })
    }

    pub(crate) fn validate_ref(reference: &StageRef) -> Result<()> {
        ensure!(
            Self::valid_name(&reference.name),
            "Invalid workspace stage name"
        );
        ensure!(
            reference.guard.is_none() || reference.directory.is_some(),
            "Workspace stage guard has no directory identity"
        );
        ensure!(
            reference.payload.is_none()
                || (reference.directory.is_some() && reference.guard.is_some()),
            "Workspace stage payload has no verified guard"
        );
        Ok(())
    }

    /// Create only; an existing stage directory is never adopted by name.
    pub(crate) fn create_empty(parent: &Dir, name: &str) -> Result<Self> {
        ensure!(Self::valid_name(name), "Invalid workspace stage name");
        let parent_identity = directory_identity(parent)?;
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        parent
            .create_dir_with(name, &builder)
            .context("Не удалось создать workspace stage directory")?;
        sync_dir(parent)?;

        let named = parent.symlink_metadata(name)?;
        private_directory(&named)?;
        let dir = parent
            .open_dir_nofollow(name)
            .context("Не удалось открыть созданный workspace stage")?;
        ensure!(
            same(&named, &dir.dir_metadata()?),
            "Workspace stage changed during creation"
        );
        ensure!(
            directory_entries(&dir)?.is_some_and(|entries| entries.is_empty()),
            "New workspace stage is not empty"
        );

        Ok(Self {
            reference: StageRef {
                name: name.to_owned(),
                directory: Some(identity(&named)),
                guard: None,
                payload: None,
            },
            parent_identity,
            dir,
        })
    }

    /// Reopen a known stage without adopting a directory, guard, payload, or
    /// child entry that is absent from the persisted reference.
    pub(crate) fn open_checked(parent: &Dir, reference: &StageRef) -> Result<Self> {
        Self::validate_ref(reference)?;
        let expected_directory = reference
            .directory
            .context("Workspace stage has no saved directory identity")?;
        let expected_guard = reference
            .guard
            .context("Workspace stage has no saved guard identity")?;
        let parent_identity = directory_identity(parent)?;
        let named = parent
            .symlink_metadata(&reference.name)
            .context("Workspace stage directory is missing")?;
        private_directory(&named)?;
        ensure!(
            identity(&named) == expected_directory,
            "Workspace stage directory identity changed"
        );
        let dir = parent
            .open_dir_nofollow(&reference.name)
            .context("Workspace stage directory changed")?;
        ensure!(
            same(&named, &dir.dir_metadata()?),
            "Workspace stage directory changed"
        );

        verify_guard(&dir, expected_guard)?;
        let entries =
            directory_entries(&dir)?.context("Workspace stage contains too many entries")?;
        ensure!(
            entries.iter().all(|name| name == GUARD || name == PAYLOAD),
            "Unknown workspace stage entry"
        );
        if entries.iter().any(|name| name == PAYLOAD) {
            let expected_payload = reference
                .payload
                .context("Workspace stage contains an unknown payload")?;
            verify_payload_identity(&dir, expected_payload)?;
        }
        Ok(Self {
            reference: reference.clone(),
            parent_identity,
            dir,
        })
    }

    pub(crate) fn reference(&self) -> StageRef {
        self.reference.clone()
    }

    #[cfg(test)]
    pub(crate) fn dir(&self) -> &Dir {
        &self.dir
    }

    /// Install the exact Git ignore guard durably before any payload bytes can
    /// be written. On a partial failure the directory is left for conservative
    /// orphan accounting; it is never cleaned up by its name alone.
    pub(crate) fn install_guard(&mut self, parent: &Dir) -> Result<()> {
        ensure!(
            self.reference.guard.is_none(),
            "Workspace stage guard already installed"
        );
        ensure!(
            self.reference.payload.is_none(),
            "Cannot install a guard after payload creation"
        );
        self.check_directory_binding(parent)?;
        require_absent(&self.dir, GUARD)?;

        let mut file = create_private(&self.dir, GUARD)?;
        let file_identity = identity(&file.metadata()?);
        file.write_all(GUARD_BYTES)?;
        file.sync_all()
            .context("Не удалось синхронизировать workspace stage guard")?;
        drop(file);
        sync_dir(&self.dir)?;
        self.check_directory_binding(parent)?;
        verify_guard(&self.dir, file_identity)?;
        self.reference.guard = Some(file_identity);
        Ok(())
    }

    /// Write and sync the payload after verifying the guard. `perms` is the
    /// final target permission set; an absent value keeps the private 0600
    /// creation mode used for newly created targets.
    pub(crate) fn write_payload(
        &mut self,
        parent: &Dir,
        bytes: &[u8],
        perms: Option<&Permissions>,
    ) -> Result<Identity> {
        ensure!(
            bytes.len() <= MAX_STAGE_BYTES,
            "Workspace stage payload exceeds 1 MiB"
        );
        ensure!(
            self.reference.payload.is_none(),
            "Workspace stage payload already exists"
        );
        let expected_mode = perms.map(|perms| perms.mode() & 0o7777).unwrap_or(0o600);
        self.check_directory_binding(parent)?;
        self.verify_guard_bound()?;
        require_absent(&self.dir, PAYLOAD)?;

        let mut file = create_private(&self.dir, PAYLOAD)?;
        let file_identity = identity(&file.metadata()?);
        file.write_all(bytes)?;
        if let Some(perms) = perms {
            file.set_permissions(perms.clone())?;
        }
        file.sync_all()
            .context("Не удалось синхронизировать workspace stage payload")?;
        drop(file);
        sync_dir(&self.dir)?;
        self.check_directory_binding(parent)?;
        let proof = PayloadProof {
            sha256: sha256(bytes),
            len: bytes.len(),
            mode: expected_mode,
        };
        verify_payload(&self.dir, file_identity, &proof)?;
        self.reference.payload = Some(file_identity);
        Ok(file_identity)
    }

    /// Verify a known payload's bytes, length, inode and final mode before a
    /// caller's publication check. This opens nonblocking and never follows a
    /// symlink.
    pub(crate) fn verify_payload(&self, parent: &Dir, proof: &PayloadProof) -> Result<()> {
        self.check_directory_binding(parent)?;
        self.verify_guard_bound()?;
        let expected = self
            .reference
            .payload
            .context("Workspace stage payload has no saved identity")?;
        verify_payload(&self.dir, expected, proof)
    }

    /// Move only the known payload into the checked target parent. Workspace
    /// policy and target snapshot checks remain the caller's responsibility.
    pub(crate) fn rename_payload_to(&self, parent: &Dir, target_name: &OsStr) -> Result<()> {
        ensure!(
            valid_leaf(target_name),
            "Workspace target name must be one component"
        );
        self.check_directory_binding(parent)?;
        self.verify_guard_bound()?;
        let expected = self
            .reference
            .payload
            .context("Workspace stage payload has no saved identity")?;
        verify_payload_identity(&self.dir, expected)?;
        // This syscall is the commit point: after it succeeds there must be
        // no fallible helper work before returning success, so callers can
        // immediately record the applied publication in their WAL.
        match self.dir.rename(PAYLOAD, parent, Path::new(target_name)) {
            Ok(()) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Sync both namespace changes after publication. Attempt both syncs even
    /// when the source sync fails, then return the first error.
    pub(crate) fn sync_after_publication(&self, parent: &Dir) -> Result<()> {
        self.check_directory_binding(parent)?;
        self.verify_guard_bound()?;
        let source = sync_dir(&self.dir);
        let destination = sync_dir(parent);
        source?;
        destination?;
        self.check_directory_binding(parent)?;
        self.verify_guard_bound()?;
        Ok(())
    }

    /// Remove only a fully proven known payload and guard. Unknown names or
    /// payloads are left intact for durable orphan accounting; no recursive
    /// deletion is used.
    pub(crate) fn cleanup_known(
        parent: &Dir,
        reference: &StageRef,
        payload_proof: Option<&PayloadProof>,
    ) -> Result<bool> {
        Self::validate_ref(reference)?;
        let Some(expected_directory) = reference.directory else {
            return Ok(false);
        };
        let parent_identity = directory_identity(parent)?;
        let named = match parent.symlink_metadata(&reference.name) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
            Err(error) => return Err(error.into()),
        };
        private_directory(&named)?;
        ensure!(
            identity(&named) == expected_directory,
            "Workspace stage directory identity changed"
        );
        let dir = parent.open_dir_nofollow(&reference.name)?;
        ensure!(
            same(&named, &dir.dir_metadata()?),
            "Workspace stage directory changed"
        );

        let Some(entries) = directory_entries(&dir)? else {
            return Ok(false);
        };
        if entries.iter().any(|name| name != GUARD && name != PAYLOAD) {
            return Ok(false);
        }
        let has_guard = entries.iter().any(|name| name == GUARD);
        let has_payload = entries.iter().any(|name| name == PAYLOAD);
        if has_payload && !has_guard {
            return Ok(false);
        }
        if has_guard {
            let Some(expected_guard) = reference.guard else {
                return Ok(false);
            };
            verify_guard(&dir, expected_guard)?;
            verify_named_file_identity(&dir, GUARD, expected_guard)?;
        }
        if has_payload {
            let (Some(expected_payload), Some(proof)) = (reference.payload, payload_proof) else {
                return Ok(false);
            };
            verify_payload(&dir, expected_payload, proof)?;
            verify_named_file_identity(&dir, PAYLOAD, expected_payload)?;
            dir.remove_file(PAYLOAD)
                .context("Не удалось удалить проверенный stage payload")?;
            sync_dir(&dir)?;
            let Some(current_entries) = directory_entries(&dir)? else {
                return Ok(false);
            };
            if current_entries.iter().any(|name| name != GUARD) {
                return Ok(false);
            }
        }

        if has_guard {
            let Some(expected_guard) = reference.guard else {
                return Ok(false);
            };
            verify_guard(&dir, expected_guard)?;
            verify_named_file_identity(&dir, GUARD, expected_guard)?;
            // Re-scan immediately before guard removal; a child we do not own
            // keeps the whole directory and guard untouched.
            let Some(current_entries) = directory_entries(&dir)? else {
                return Ok(false);
            };
            if current_entries.iter().any(|name| name != GUARD) {
                return Ok(false);
            }
            dir.remove_file(GUARD)
                .context("Не удалось удалить проверенный stage guard")?;
            sync_dir(&dir)?;
        } else {
            // An empty pre-guard directory is safe to remove only when the
            // reference itself confirms that no guard was ever installed.
            if reference.guard.is_some() {
                return Ok(false);
            }
        }

        if !directory_entries(&dir)?.is_some_and(|entries| entries.is_empty()) {
            return Ok(false);
        }
        let current = parent.symlink_metadata(&reference.name)?;
        private_directory(&current)?;
        ensure!(
            identity(&current) == expected_directory,
            "Workspace stage directory changed before cleanup"
        );
        ensure!(
            directory_identity(parent)? == parent_identity,
            "Workspace parent directory changed"
        );
        parent
            .remove_dir(&reference.name)
            .context("Не удалось удалить пустой проверенный stage directory")?;
        sync_dir(parent)?;
        Ok(true)
    }

    fn check_directory_binding(&self, parent: &Dir) -> Result<()> {
        ensure!(
            directory_identity(parent)? == self.parent_identity,
            "Workspace stage parent directory changed"
        );
        let expected = self
            .reference
            .directory
            .context("Workspace stage has no saved directory identity")?;
        let named = parent
            .symlink_metadata(&self.reference.name)
            .context("Workspace stage directory is missing")?;
        private_directory(&named)?;
        ensure!(
            identity(&named) == expected,
            "Workspace stage directory identity changed"
        );
        ensure!(
            same(&named, &self.dir.dir_metadata()?),
            "Workspace stage directory changed"
        );
        let fresh = parent.open_dir_nofollow(&self.reference.name)?;
        ensure!(
            same(&fresh.dir_metadata()?, &self.dir.dir_metadata()?),
            "Workspace stage directory changed"
        );
        Ok(())
    }

    fn verify_guard_bound(&self) -> Result<()> {
        let expected = self
            .reference
            .guard
            .context("Workspace stage guard has no saved identity")?;
        verify_guard(&self.dir, expected)
    }
}

fn identity(metadata: &Metadata) -> Identity {
    Identity {
        device: MetadataExt::dev(metadata),
        inode: MetadataExt::ino(metadata),
    }
}

fn same(left: &Metadata, right: &Metadata) -> bool {
    identity(left) == identity(right)
}

fn directory_identity(dir: &Dir) -> Result<Identity> {
    Ok(identity(&dir.dir_metadata()?))
}

fn private_directory(metadata: &Metadata) -> Result<()> {
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "Workspace stage is not a directory"
    );
    ensure!(
        UnixMetadataExt::uid(metadata) == unsafe { libc::geteuid() },
        "Workspace stage owner changed"
    );
    ensure!(
        UnixMetadataExt::mode(metadata) & 0o7777 == 0o700,
        "Workspace stage directory must have mode 0700"
    );
    Ok(())
}

fn private_file(metadata: &Metadata, expected_mode: Option<u32>) -> Result<()> {
    ensure!(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && MetadataExt::nlink(metadata) == 1,
        "Workspace stage entry must be a regular file with one link"
    );
    ensure!(
        UnixMetadataExt::uid(metadata) == unsafe { libc::geteuid() },
        "Workspace stage file owner changed"
    );
    if let Some(mode) = expected_mode {
        ensure!(
            UnixMetadataExt::mode(metadata) & 0o7777 == mode,
            "Workspace stage file mode changed"
        );
    }
    Ok(())
}

fn create_private(dir: &Dir, name: &str) -> Result<cap_std::fs::File> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No)
        .nonblock(true)
        .mode(0o600);
    let file = dir
        .open_with(name, &options)
        .with_context(|| "Не удалось создать workspace stage entry")?;
    private_file(&file.metadata()?, Some(0o600))?;
    Ok(file)
}

fn open_regular(dir: &Dir, name: &str, expected_mode: Option<u32>) -> Result<cap_std::fs::File> {
    let before = dir.symlink_metadata(name)?;
    private_file(&before, expected_mode)?;
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = dir.open_with(name, &options)?;
    let after = file.metadata()?;
    private_file(&after, expected_mode)?;
    ensure!(
        same(&before, &after),
        "Workspace stage file changed while opening"
    );
    Ok(file)
}

fn verify_guard(dir: &Dir, expected: Identity) -> Result<()> {
    let metadata = dir.symlink_metadata(GUARD)?;
    private_file(&metadata, Some(0o600))?;
    ensure!(
        identity(&metadata) == expected,
        "Workspace stage guard identity changed"
    );
    ensure!(
        metadata.len() == GUARD_BYTES.len() as u64,
        "Workspace stage guard size changed"
    );
    let file = open_regular(dir, GUARD, Some(0o600))?;
    let mut bytes = Vec::with_capacity(GUARD_BYTES.len());
    file.take((GUARD_BYTES.len() + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes == GUARD_BYTES,
        "Workspace stage guard content changed"
    );
    let current = dir.symlink_metadata(GUARD)?;
    private_file(&current, Some(0o600))?;
    ensure!(
        identity(&current) == expected,
        "Workspace stage guard was replaced"
    );
    Ok(())
}

fn verify_payload_identity(dir: &Dir, expected: Identity) -> Result<()> {
    let metadata = dir.symlink_metadata(PAYLOAD)?;
    private_file(&metadata, None)?;
    ensure!(
        identity(&metadata) == expected,
        "Workspace stage payload identity changed"
    );
    let file = open_regular(dir, PAYLOAD, None)?;
    ensure!(
        identity(&file.metadata()?) == expected,
        "Workspace stage payload was replaced"
    );
    Ok(())
}

fn verify_payload(dir: &Dir, expected: Identity, proof: &PayloadProof) -> Result<()> {
    ensure!(
        proof.len <= MAX_STAGE_BYTES,
        "Workspace stage payload exceeds 1 MiB"
    );
    ensure!(
        proof.sha256.len() == 64
            && proof
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "Invalid workspace stage payload hash"
    );
    let metadata = dir.symlink_metadata(PAYLOAD)?;
    private_file(&metadata, Some(proof.mode))?;
    ensure!(
        identity(&metadata) == expected,
        "Workspace stage payload identity changed"
    );
    ensure!(
        metadata.len() == proof.len as u64,
        "Workspace stage payload size changed"
    );
    let file = open_regular(dir, PAYLOAD, Some(proof.mode))?;
    ensure!(
        identity(&file.metadata()?) == expected,
        "Workspace stage payload was replaced"
    );
    let mut bytes = Vec::with_capacity(proof.len);
    file.take((MAX_STAGE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() == proof.len && sha256(&bytes) == proof.sha256,
        "Workspace stage payload content changed"
    );
    let current = dir.symlink_metadata(PAYLOAD)?;
    private_file(&current, Some(proof.mode))?;
    ensure!(
        identity(&current) == expected,
        "Workspace stage payload was replaced while reading"
    );
    Ok(())
}

fn verify_named_file_identity(dir: &Dir, name: &str, expected: Identity) -> Result<()> {
    let metadata = dir.symlink_metadata(name)?;
    private_file(&metadata, None)?;
    ensure!(
        identity(&metadata) == expected,
        "Workspace stage entry identity changed"
    );
    Ok(())
}

fn require_absent(dir: &Dir, name: &str) -> Result<()> {
    match dir.symlink_metadata(name) {
        Ok(_) => Err(anyhow!("Workspace stage entry already exists")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn valid_leaf(name: &OsStr) -> bool {
    let mut components = Path::new(name).components();
    matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none()
}

fn directory_entries(dir: &Dir) -> Result<Option<Vec<OsString>>> {
    let mut names = Vec::new();
    for entry in dir.read_dir(".")? {
        let entry = entry?;
        names.push(entry.file_name());
        if names.len() > 3 {
            return Ok(None);
        }
    }
    Ok(Some(names))
}

fn sync_dir(dir: &Dir) -> Result<()> {
    dir.open(".")?
        .sync_all()
        .context("Не удалось синхронизировать workspace stage directory")
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt as StdPermissionsExt, process::Command};

    fn parent(path: &Path) -> Dir {
        Dir::open_ambient_dir(path, cap_std::ambient_authority()).unwrap()
    }

    fn git_command(home: &Path, hooks: &Path, repo_path: &Path, args: &[&str]) -> Command {
        let mut command = Command::new("git");
        command
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .current_dir(repo_path)
            .arg("-c")
            .arg(format!("core.hooksPath={}", hooks.display()))
            .arg("-c")
            .arg("core.fsmonitor=false")
            .args(args);
        command
    }

    fn proof(bytes: &[u8], mode: u32) -> PayloadProof {
        PayloadProof {
            sha256: sha256(bytes),
            len: bytes.len(),
            mode,
        }
    }

    fn create_guarded(parent: &Dir, payload: &[u8], mode: Option<u32>) -> StageDirectory {
        let mut stage = StageDirectory::create_empty(parent, &StageDirectory::plan_name()).unwrap();
        stage.install_guard(parent).unwrap();
        let permissions = mode.map(Permissions::from_mode);
        stage
            .write_payload(parent, payload, permissions.as_ref())
            .unwrap();
        stage
    }

    #[test]
    fn payload_cannot_be_written_until_guard_is_durable() {
        let temp = tempfile::tempdir().unwrap();
        let root = parent(temp.path());
        let mut stage = StageDirectory::create_empty(&root, &StageDirectory::plan_name()).unwrap();
        assert!(stage.write_payload(&root, b"secret", None).is_err());
        assert!(stage.dir().symlink_metadata(PAYLOAD).is_err());
        stage.install_guard(&root).unwrap();
        assert_eq!(
            stage.dir().open(GUARD).unwrap().metadata().unwrap().len(),
            2
        );
        let id = stage.write_payload(&root, b"secret", None).unwrap();
        assert_eq!(stage.reference().payload, Some(id));
        assert_eq!(
            stage
                .dir()
                .symlink_metadata(PAYLOAD)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
        stage
            .verify_payload(&root, &proof(b"secret", 0o600))
            .unwrap();
    }

    #[test]
    fn fresh_git_does_not_stage_private_payload() {
        let temp = tempfile::tempdir().unwrap();
        let repo_path = temp.path().join("repo");
        let home = temp.path().join("home");
        let hooks = temp.path().join("empty-hooks");
        fs::create_dir(&repo_path).unwrap();
        fs::create_dir(&home).unwrap();
        fs::create_dir(&hooks).unwrap();
        let init = git_command(
            &home,
            &hooks,
            &repo_path,
            &["init", "--quiet", "--template="],
        )
        .status()
        .expect("git must be installed for stage privacy test");
        assert!(init.success());
        fs::write(repo_path.join(".gitignore"), "!.rcode-wal-*.stage/**\n").unwrap();
        let root = parent(&repo_path);
        let stage = create_guarded(&root, b"WAL_SECRET_SENTINEL", Some(0o751));
        let reference = stage.reference();
        drop(stage);

        let status = git_command(
            &home,
            &hooks,
            &repo_path,
            &["status", "--porcelain", "--untracked-files=all"],
        )
        .output()
        .unwrap();
        assert!(status.status.success());
        let status = String::from_utf8_lossy(&status.stdout);
        assert!(
            !status.contains("payload"),
            "payload appeared in git status: {status}"
        );
        assert!(!status.contains("WAL_SECRET_SENTINEL"));

        let add = git_command(&home, &hooks, &repo_path, &["add", "-A"])
            .status()
            .unwrap();
        assert!(add.success());
        let indexed = git_command(&home, &hooks, &repo_path, &["ls-files", "--stage"])
            .output()
            .unwrap();
        assert!(indexed.status.success());
        let indexed = String::from_utf8_lossy(&indexed.stdout);
        assert!(
            !indexed.contains("payload"),
            "payload was staged: {indexed}"
        );
        assert!(!indexed.contains("WAL_SECRET_SENTINEL"));
        assert!(repo_path.join(&reference.name).join(GUARD).exists());
    }

    #[test]
    fn open_rejects_directory_mode_change() {
        let temp = tempfile::tempdir().unwrap();
        let root = parent(temp.path());
        let stage = create_guarded(&root, b"payload", Some(0o751));
        let reference = stage.reference();
        let permissions = fs::metadata(temp.path().join(&reference.name))
            .unwrap()
            .permissions();
        fs::set_permissions(
            temp.path().join(&reference.name),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(StageDirectory::open_checked(&root, &reference).is_err());
        fs::set_permissions(temp.path().join(&reference.name), permissions).unwrap();
    }

    #[test]
    fn open_rejects_guard_content_tampering() {
        let temp = tempfile::tempdir().unwrap();
        let root = parent(temp.path());
        let stage = create_guarded(&root, b"payload", Some(0o751));
        let reference = stage.reference();
        fs::write(temp.path().join(&reference.name).join(GUARD), b"!*\n").unwrap();
        assert!(StageDirectory::open_checked(&root, &reference).is_err());
    }

    #[test]
    fn open_rejects_guard_mode_tampering() {
        let temp = tempfile::tempdir().unwrap();
        let root = parent(temp.path());
        let stage = create_guarded(&root, b"payload", Some(0o751));
        let reference = stage.reference();
        let guard = temp.path().join(&reference.name).join(GUARD);
        fs::set_permissions(&guard, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(StageDirectory::open_checked(&root, &reference).is_err());
    }

    #[test]
    fn open_rejects_guard_inode_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let root = parent(temp.path());
        let stage = create_guarded(&root, b"payload", Some(0o751));
        let reference = stage.reference();
        let guard = temp.path().join(&reference.name).join(GUARD);
        let saved = temp.path().join(&reference.name).join("guard.saved");
        fs::rename(&guard, &saved).unwrap();
        fs::write(&guard, GUARD_BYTES).unwrap();
        fs::set_permissions(&guard, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(StageDirectory::open_checked(&root, &reference).is_err());
        assert!(saved.exists());
    }

    #[test]
    fn verify_payload_rejects_mode_change_with_intact_guard() {
        let temp = tempfile::tempdir().unwrap();
        let root = parent(temp.path());
        let stage = create_guarded(&root, b"payload", Some(0o751));
        let reference = stage.reference();
        fs::set_permissions(
            temp.path().join(&reference.name).join(PAYLOAD),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(
            stage
                .verify_payload(&root, &proof(b"payload", 0o751))
                .is_err()
        );
    }

    #[test]
    fn verify_payload_rejects_same_bytes_inode_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let root = parent(temp.path());
        let stage = create_guarded(&root, b"payload", Some(0o751));
        let reference = stage.reference();
        let payload = temp.path().join(&reference.name).join(PAYLOAD);
        let saved = temp.path().join(&reference.name).join("payload.saved");
        fs::rename(&payload, &saved).unwrap();
        fs::write(&payload, b"payload").unwrap();
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o751)).unwrap();
        assert!(
            stage
                .verify_payload(&root, &proof(b"payload", 0o751))
                .is_err()
        );
        assert!(saved.exists());
    }

    #[test]
    fn verify_payload_rejects_content_tampering_with_intact_guard() {
        let temp = tempfile::tempdir().unwrap();
        let root = parent(temp.path());
        let stage = create_guarded(&root, b"payload", Some(0o751));
        let reference = stage.reference();
        fs::write(temp.path().join(&reference.name).join(PAYLOAD), b"tampered").unwrap();
        assert!(
            stage
                .verify_payload(&root, &proof(b"payload", 0o751))
                .is_err()
        );
    }

    #[test]
    fn original_directory_descriptor_cannot_authorize_replaced_binding() {
        let temp = tempfile::tempdir().unwrap();
        let root = parent(temp.path());
        let stage = create_guarded(&root, b"payload", Some(0o751));
        let reference = stage.reference();
        let moved = temp.path().join("moved");
        fs::rename(temp.path().join(&reference.name), &moved).unwrap();
        let mut replacement_dir = DirBuilder::new();
        replacement_dir.mode(0o700);
        root.create_dir_with(&reference.name, &replacement_dir)
            .unwrap();
        assert!(StageDirectory::open_checked(&root, &reference).is_err());
        assert!(stage.check_directory_binding(&root).is_err());
        assert!(moved.exists());
    }

    #[test]
    fn stage_refuses_a_replaced_parent_binding() {
        let temp = tempfile::tempdir().unwrap();
        let parent_path = temp.path().join("parent");
        fs::create_dir(&parent_path).unwrap();
        fs::set_permissions(&parent_path, fs::Permissions::from_mode(0o700)).unwrap();
        let original_parent = parent(&parent_path);
        let mut stage =
            StageDirectory::create_empty(&original_parent, &StageDirectory::plan_name()).unwrap();
        let moved = temp.path().join("moved-parent");
        fs::rename(&parent_path, &moved).unwrap();
        fs::create_dir(&parent_path).unwrap();
        fs::set_permissions(&parent_path, fs::Permissions::from_mode(0o700)).unwrap();
        let replacement_parent = parent(&parent_path);
        assert!(stage.install_guard(&replacement_parent).is_err());
        assert!(!moved.join(stage.reference().name).join(PAYLOAD).exists());
    }

    #[test]
    fn cleanup_preserves_unknown_entries_and_removes_only_known_private_files() {
        let temp = tempfile::tempdir().unwrap();
        let root = parent(temp.path());
        let stage = create_guarded(&root, b"before image", Some(0o751));
        let reference = stage.reference();
        let proof = proof(b"before image", 0o751);
        fs::write(temp.path().join(&reference.name).join("foreign"), b"keep").unwrap();
        assert!(!StageDirectory::cleanup_known(&root, &reference, Some(&proof)).unwrap());
        assert!(temp.path().join(&reference.name).join(GUARD).exists());
        assert!(temp.path().join(&reference.name).join(PAYLOAD).exists());
        fs::remove_file(temp.path().join(&reference.name).join("foreign")).unwrap();
        drop(stage);

        assert!(StageDirectory::cleanup_known(&root, &reference, Some(&proof)).unwrap());
        assert!(!temp.path().join(&reference.name).exists());
    }

    #[test]
    fn hardlinked_payload_is_rejected_and_unknown_directory_is_never_adopted() {
        let temp = tempfile::tempdir().unwrap();
        let root = parent(temp.path());
        let stage = create_guarded(&root, b"contents", Some(0o600));
        let reference = stage.reference();
        let proof = proof(b"contents", 0o600);
        fs::hard_link(
            temp.path().join(&reference.name).join(PAYLOAD),
            temp.path().join("outside-link"),
        )
        .unwrap();
        assert!(StageDirectory::open_checked(&root, &reference).is_err());
        assert!(StageDirectory::cleanup_known(&root, &reference, Some(&proof)).is_err());
        assert!(temp.path().join(&reference.name).join(PAYLOAD).exists());
        assert!(temp.path().join("outside-link").exists());

        let unknown_name = StageDirectory::plan_name();
        let unknown = StageDirectory::create_empty(&root, &unknown_name).unwrap();
        drop(unknown);
        assert!(
            StageDirectory::open_checked(
                &root,
                &StageRef {
                    name: unknown_name,
                    directory: None,
                    guard: None,
                    payload: None,
                }
            )
            .is_err()
        );
    }

    #[test]
    fn cleanup_never_unlinks_a_replaced_guard_or_payload() {
        let temp = tempfile::tempdir().unwrap();
        let root = parent(temp.path());
        let stage = create_guarded(&root, b"payload", Some(0o600));
        let reference = stage.reference();
        let proof = proof(b"payload", 0o600);
        let guard = temp.path().join(&reference.name).join(GUARD);
        let old_guard = fs::File::open(&guard).unwrap();
        fs::remove_file(&guard).unwrap();
        fs::write(&guard, GUARD_BYTES).unwrap();
        drop(old_guard);
        fs::set_permissions(&guard, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(StageDirectory::cleanup_known(&root, &reference, Some(&proof)).is_err());
        assert!(guard.exists());
        assert!(temp.path().join(&reference.name).join(PAYLOAD).exists());
    }
}
