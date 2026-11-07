//! Private, durable primitives used by the filesystem write-ahead log.
//!
//! The blob store is a retained directory capability. Ambient paths are used
//! only while bootstrapping its component-by-component no-follow walk.

use std::{
    collections::HashMap,
    ffi::OsString,
    fs::File,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    sync::Mutex,
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use cap_fs_ext::{DirExt, FollowSymlinks, MetadataExt, OpenOptionsFollowExt, OpenOptionsSyncExt};
#[cfg(unix)]
use cap_std::fs::MetadataExt as CapUnixMetadataExt;
use cap_std::{
    ambient_authority,
    fs::{Dir, DirBuilder, DirBuilderExt, Metadata, OpenOptions, OpenOptionsExt},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub(crate) const MAX_IMAGE_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const MAX_STORE_BYTES: u64 = 128 * 1024 * 1024;
pub(crate) const MAX_STORE_ENTRIES: usize = 8192;
const MAX_MANAGED_BYTES: u64 = MAX_STORE_BYTES;
const MAX_MANAGED_ENTRIES: usize = MAX_STORE_ENTRIES;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ImageRef {
    pub id: String,
    pub sha256: String,
    pub len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Identity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ManifestVersion {
    identity: Option<Identity>,
    sha256: Option<String>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StoreFaultPoint {
    BlobFileSync,
    ManifestTempFileSync,
    ManifestBeforeRename,
    ManifestAfterRenameBeforeDirSync,
}

/// Capability to one WAL directory and its blob directory, bound to every
/// named ancestor from `/` down. Only the store and blob directories stay
/// open; each operation performs a short no-follow walk and checks the saved
/// identities, keeping descriptor use independent of path depth.
pub(crate) struct BlobStore {
    path: PathBuf,
    root: Dir,
    names: Vec<OsString>,
    ancestor_identities: Vec<Identity>,
    blobs: Dir,
    lock_identity: Mutex<Option<Identity>>,
    lock_file: Mutex<Option<File>>,
    manifest_version: Mutex<Option<ManifestVersion>>,
    owned_blobs: Mutex<HashMap<String, Identity>>,
    #[cfg(test)]
    next_fault: Mutex<Option<(StoreFaultPoint, i32)>>,
}

impl std::fmt::Debug for BlobStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlobStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl BlobStore {
    #[cfg(test)]
    pub(crate) fn fail_next(&self, point: StoreFaultPoint, errno: i32) -> Result<()> {
        let mut next = self
            .next_fault
            .lock()
            .map_err(|_| anyhow!("WAL test fault state is unavailable"))?;
        ensure!(next.is_none(), "WAL test fault already armed");
        *next = Some((point, errno));
        Ok(())
    }

    #[cfg(test)]
    fn maybe_fail(&self, point: StoreFaultPoint) -> Result<()> {
        let mut next = self
            .next_fault
            .lock()
            .map_err(|_| anyhow!("WAL test fault state is unavailable"))?;
        if next
            .as_ref()
            .is_some_and(|(expected, _)| *expected == point)
        {
            let (_, errno) = next.take().expect("fault checked");
            return Err(std::io::Error::from_raw_os_error(errno).into());
        }
        Ok(())
    }

    pub(crate) fn open(path: &Path) -> Result<Self> {
        let path = absolute_normalized(path)?;
        let mut current = Dir::open_ambient_dir("/", ambient_authority())
            .context("Не удалось закрепить корень файловой системы WAL")?;
        let mut names = Vec::new();
        let mut ancestor_identities = vec![identity_from(&current.dir_metadata()?)];
        let components = path
            .components()
            .filter_map(|component| match component {
                Component::Normal(name) => Some(name.to_owned()),
                _ => None,
            })
            .collect::<Vec<_>>();

        for (index, name) in components.iter().enumerate() {
            let is_store_root = index + 1 == components.len();
            let child = match current.open_dir_nofollow(name) {
                Ok(child) => child,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let mut builder = DirBuilder::new();
                    builder.mode(0o700);
                    current
                        .create_dir_with(name, &builder)
                        .with_context(|| "Не удалось создать каталог WAL")?;
                    sync_dir(&current)?;
                    current
                        .open_dir_nofollow(name)
                        .with_context(|| "Созданный каталог WAL изменился")?
                }
                Err(error) => {
                    return Err(error).with_context(|| "Не удалось безопасно открыть каталог WAL");
                }
            };
            let named = current
                .symlink_metadata(name)
                .with_context(|| "Не удалось проверить каталог WAL")?;
            ensure!(
                named.is_dir() && !named.file_type().is_symlink(),
                "Компонент каталога WAL не является обычным каталогом"
            );
            ensure!(
                same(&named, &child.dir_metadata()?),
                "Каталог WAL изменился во время открытия"
            );
            if is_store_root {
                ensure_private_dir(&child.dir_metadata()?)?;
            }
            names.push(name.clone());
            ancestor_identities.push(identity_from(&child.dir_metadata()?));
            current = child;
        }
        ensure!(
            !names.is_empty(),
            "Каталог WAL не может быть корнем файловой системы"
        );

        let root = &current;
        let blobs = match root.open_dir_nofollow("blobs") {
            Ok(blobs) => blobs,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut builder = DirBuilder::new();
                builder.mode(0o700);
                root.create_dir_with("blobs", &builder)
                    .context("Не удалось создать WAL blob store")?;
                sync_dir(root)?;
                root.open_dir_nofollow("blobs")
                    .context("Созданный WAL blob store изменился")?
            }
            Err(error) => return Err(error).context("Не удалось безопасно открыть WAL blob store"),
        };
        let named = root.symlink_metadata("blobs")?;
        ensure!(
            named.is_dir() && !named.file_type().is_symlink(),
            "WAL blob store не является каталогом"
        );
        ensure!(
            same(&named, &blobs.dir_metadata()?),
            "WAL blob store изменился во время открытия"
        );
        ensure_private_dir(&blobs.dir_metadata()?)?;

        let store = Self {
            path,
            root: current,
            names,
            ancestor_identities,
            blobs,
            lock_identity: Mutex::new(None),
            lock_file: Mutex::new(None),
            manifest_version: Mutex::new(None),
            owned_blobs: Mutex::new(HashMap::new()),
            #[cfg(test)]
            next_fault: Mutex::new(None),
        };
        store.check()?;
        store.scan_usage()?;
        Ok(store)
    }

    pub(crate) fn check(&self) -> Result<()> {
        ensure!(
            self.ancestor_identities.len() == self.names.len() + 1,
            "Некорректная WAL capability"
        );
        let mut current = Dir::open_ambient_dir("/", ambient_authority())
            .context("WAL ancestor binding changed")?;
        ensure!(
            identity_from(&current.dir_metadata()?) == self.ancestor_identities[0],
            "WAL ancestor binding changed"
        );
        for index in 0..self.names.len() {
            let name = &self.names[index];
            let named = current
                .symlink_metadata(name)
                .context("WAL ancestor binding changed")?;
            ensure!(
                named.is_dir() && !named.file_type().is_symlink(),
                "WAL ancestor is not a directory"
            );
            ensure!(
                identity_from(&named) == self.ancestor_identities[index + 1],
                "WAL ancestor binding changed"
            );
            let fresh = current
                .open_dir_nofollow(name)
                .context("WAL ancestor binding changed")?;
            ensure!(
                identity_from(&fresh.dir_metadata()?) == self.ancestor_identities[index + 1],
                "WAL ancestor binding changed"
            );
            current = fresh;
        }
        ensure!(
            same(&current.dir_metadata()?, &self.root.dir_metadata()?),
            "WAL store root binding changed"
        );
        ensure_private_dir(&self.root.dir_metadata()?)?;
        let named = self
            .root
            .symlink_metadata("blobs")
            .context("WAL blob directory binding changed")?;
        ensure!(
            named.is_dir() && !named.file_type().is_symlink(),
            "WAL blob directory is unsafe"
        );
        ensure!(
            same(&named, &self.blobs.dir_metadata()?),
            "WAL blob directory binding changed"
        );
        let fresh = self
            .root
            .open_dir_nofollow("blobs")
            .context("WAL blob directory binding changed")?;
        ensure!(
            same(&fresh.dir_metadata()?, &self.blobs.dir_metadata()?),
            "WAL blob directory binding changed"
        );
        ensure_private_dir(&self.blobs.dir_metadata()?)?;
        if let Some(expected) = *self
            .lock_identity
            .lock()
            .map_err(|_| anyhow!("WAL lock identity is unavailable"))?
        {
            verify_named_identity(&self.root, "wal.lock", expected)?;
        }
        Ok(())
    }

    pub(crate) fn acquire_lock(&self) -> Result<()> {
        self.check()?;
        ensure!(
            self.lock_file
                .lock()
                .map_err(|_| anyhow!("WAL lock state is unavailable"))?
                .is_none(),
            "WAL lock already acquired"
        );
        let file = match open_private_at(&self.root, "wal.lock", true, true) {
            Ok(file) => file,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::AlreadyExists) =>
            {
                self.check()?;
                open_private_at(&self.root, "wal.lock", true, false)?
            }
            Err(error) => return Err(error),
        };
        ensure!(file.metadata()?.len() == 0, "Повреждена блокировка WAL");
        let expected = identity_std(&file.metadata()?);
        verify_named_identity(&self.root, "wal.lock", expected)?;
        *self
            .lock_identity
            .lock()
            .map_err(|_| anyhow!("WAL lock identity is unavailable"))? = Some(expected);
        use fs2::FileExt;
        file.try_lock_exclusive()
            .map_err(|_| anyhow!("WAL store is already in use"))?;
        *self
            .lock_file
            .lock()
            .map_err(|_| anyhow!("WAL lock state is unavailable"))? = Some(file);
        self.check()?;
        Ok(())
    }

    pub(crate) fn reserve(&self, additional_bytes: u64, additional_entries: usize) -> Result<()> {
        self.check()?;
        let (bytes, entries) = self.scan_usage()?;
        ensure!(
            bytes
                .checked_add(additional_bytes)
                .is_some_and(|n| n <= MAX_MANAGED_BYTES),
            "WAL store quota exceeded"
        );
        ensure!(
            entries
                .checked_add(additional_entries)
                .is_some_and(|n| n <= MAX_MANAGED_ENTRIES),
            "WAL store entry limit reached"
        );
        Ok(())
    }

    pub(crate) fn read_image_checked(
        &self,
        image: &ImageRef,
        expected: Identity,
    ) -> Result<Vec<u8>> {
        validate_image_ref(image)?;
        self.check()?;
        let file = self.checked_open_blob(&image.id)?;
        let metadata = file.metadata()?;
        ensure!(
            identity_from(&metadata) == expected,
            "WAL image identity changed"
        );
        ensure!(
            metadata.len() == image.len as u64,
            "Размер WAL image не совпадает"
        );
        // Size is checked before allocating. `take` prevents growth during the
        // read from exceeding the format limit.
        let mut bytes = Vec::with_capacity(image.len);
        file.take((MAX_IMAGE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() == image.len && sha256(&bytes) == image.sha256,
            "WAL image повреждён"
        );
        self.check()?;
        Ok(bytes)
    }

    pub(crate) fn write_image(&self, bytes: &[u8]) -> Result<(ImageRef, Identity)> {
        ensure!(
            bytes.len() <= MAX_IMAGE_BYTES,
            "Файл превышает лимит WAL 1 MiB"
        );
        self.reserve(bytes.len() as u64, 1)?;
        let id = Uuid::new_v4().to_string();
        let hash = sha256(bytes);
        self.check()?;
        // O_EXCL is the no-overwrite publication primitive. An interrupted or
        // failed write leaves a counted private orphan; it is never reclaimed
        // based on a filename prefix.
        let mut file = create_private_at(&self.blobs, &id)?;
        let identity = identity_from(&file.metadata()?);
        file.write_all(bytes)?;
        #[cfg(test)]
        self.maybe_fail(StoreFaultPoint::BlobFileSync)?;
        file.sync_all()?;
        self.check()?;
        verify_named_identity(&self.blobs, &id, identity)?;
        sync_dir(&self.blobs)?;
        self.check()?;
        let image = ImageRef {
            id: id.clone(),
            sha256: hash,
            len: bytes.len(),
        };
        self.owned_blobs
            .lock()
            .map_err(|_| anyhow!("WAL ownership state is unavailable"))?
            .insert(id, identity);
        Ok((image, identity))
    }

    pub(crate) fn remove_verified_image(&self, image: &ImageRef, expected: Identity) -> Result<()> {
        validate_image_ref(image)?;
        self.check()?;
        if let Some(owned) = self
            .owned_blobs
            .lock()
            .map_err(|_| anyhow!("WAL ownership state is unavailable"))?
            .get(&image.id)
        {
            ensure!(*owned == expected, "WAL image identity changed");
        }
        let file = self.checked_open_blob(&image.id)?;
        let identity = identity_from(&file.metadata()?);
        ensure!(identity == expected, "WAL image identity changed");
        ensure!(
            file.metadata()?.len() == image.len as u64,
            "Размер WAL image не совпадает"
        );
        let mut bytes = Vec::with_capacity(image.len);
        file.take((MAX_IMAGE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() == image.len && sha256(&bytes) == image.sha256,
            "WAL image повреждён"
        );
        self.check()?;
        verify_named_identity(&self.blobs, &image.id, identity)?;
        // Do not remove on a failed identity/content check. The final name is
        // unlinked through the retained blob directory, never an ambient path.
        self.blobs
            .remove_file(&image.id)
            .context("Не удалось удалить проверенный WAL image")?;
        sync_dir(&self.blobs)?;
        self.check()?;
        if let Ok(mut owned) = self.owned_blobs.lock() {
            owned.remove(&image.id);
        }
        Ok(())
    }

    pub(crate) fn open_manifest(&self) -> Result<Option<Vec<u8>>> {
        let (bytes, version) = self.read_manifest_checked()?;
        *self
            .manifest_version
            .lock()
            .map_err(|_| anyhow!("WAL manifest version is unavailable"))? = Some(version);
        Ok(bytes)
    }

    fn read_manifest_checked(&self) -> Result<(Option<Vec<u8>>, ManifestVersion)> {
        self.check()?;
        let root = &self.root;
        let before = match root.symlink_metadata("checkpoints.json") {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok((
                    None,
                    ManifestVersion {
                        identity: None,
                        sha256: None,
                    },
                ));
            }
            Err(error) => return Err(error.into()),
            Ok(metadata) => metadata,
        };
        private_file(&before)?;
        ensure!(
            before.len() <= MAX_MANIFEST_BYTES as u64,
            "WAL manifest exceeds 4 MiB"
        );
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No).nonblock(true);
        let file = root
            .open_with("checkpoints.json", &options)
            .context("Не удалось безопасно открыть WAL manifest")?;
        let opened = file.metadata()?;
        private_file(&opened)?;
        ensure!(same(&before, &opened), "WAL manifest changed while opening");
        ensure!(
            opened.len() <= MAX_MANIFEST_BYTES as u64,
            "WAL manifest exceeds 4 MiB"
        );
        let mut bytes = Vec::with_capacity(opened.len() as usize);
        file.take((MAX_MANIFEST_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= MAX_MANIFEST_BYTES,
            "WAL manifest exceeds 4 MiB"
        );
        let current = root.symlink_metadata("checkpoints.json")?;
        private_file(&current)?;
        ensure!(
            same(&opened, &current),
            "WAL manifest changed while reading"
        );
        self.check()?;
        let version = ManifestVersion {
            identity: Some(identity_from(&opened)),
            sha256: Some(sha256(&bytes)),
        };
        Ok((Some(bytes), version))
    }

    pub(crate) fn write_manifest_atomic(&self, bytes: &[u8]) -> Result<()> {
        ensure!(
            bytes.len() <= MAX_MANIFEST_BYTES,
            "WAL manifest exceeds 4 MiB"
        );
        let expected = self
            .manifest_version
            .lock()
            .map_err(|_| anyhow!("WAL manifest version is unavailable"))?
            .clone()
            .ok_or_else(|| anyhow!("WAL manifest must be opened before writing"))?;
        ensure!(
            self.read_manifest_checked()?.1 == expected,
            "WAL manifest changed outside this session"
        );
        // Callers that add images reserve an 8 MiB safety margin before
        // writing them. Manifest replacement only needs its exact bytes and
        // temporary directory entry; charging the margin again here could
        // reject the intent after images had already consumed that reserve.
        self.reserve(bytes.len() as u64, 1)?;
        let root = &self.root;
        let temp_name = format!(".checkpoints.{}.tmp", Uuid::new_v4());
        self.check()?;
        let mut temp = create_private_at(root, &temp_name)?;
        let temp_identity = identity_from(&temp.metadata()?);
        temp.write_all(bytes)?;
        #[cfg(test)]
        self.maybe_fail(StoreFaultPoint::ManifestTempFileSync)?;
        temp.sync_all()?;
        verify_named_identity(root, &temp_name, temp_identity)?;
        self.check()?;
        match root.symlink_metadata("checkpoints.json") {
            Ok(metadata) => {
                private_file(&metadata)?;
                ensure!(
                    metadata.len() <= MAX_MANIFEST_BYTES as u64,
                    "WAL manifest exceeds 4 MiB"
                );
                let mut options = OpenOptions::new();
                options.read(true).follow(FollowSymlinks::No).nonblock(true);
                let existing = root.open_with("checkpoints.json", &options)?;
                ensure!(
                    same(&metadata, &existing.metadata()?),
                    "WAL manifest changed while opening"
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
        self.check()?;
        ensure!(
            self.read_manifest_checked()?.1 == expected,
            "WAL manifest changed outside this session"
        );
        #[cfg(test)]
        self.maybe_fail(StoreFaultPoint::ManifestBeforeRename)?;
        root.rename(&temp_name, root, "checkpoints.json")?;
        verify_named_identity(root, "checkpoints.json", temp_identity)?;
        *self
            .manifest_version
            .lock()
            .map_err(|_| anyhow!("WAL manifest version is unavailable"))? = Some(ManifestVersion {
            identity: Some(temp_identity),
            sha256: Some(sha256(bytes)),
        });
        #[cfg(test)]
        self.maybe_fail(StoreFaultPoint::ManifestAfterRenameBeforeDirSync)?;
        sync_dir(root)?;
        self.check()?;
        Ok(())
    }

    fn checked_open_blob(&self, id: &str) -> Result<cap_std::fs::File> {
        self.check()?;
        let before = self
            .blobs
            .symlink_metadata(id)
            .context("WAL image отсутствует")?;
        private_file(&before)?;
        ensure!(
            before.len() <= MAX_IMAGE_BYTES as u64,
            "Слишком большой WAL image"
        );
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No).nonblock(true);
        let file = self
            .blobs
            .open_with(id, &options)
            .context("Не удалось безопасно открыть WAL image")?;
        let after = file.metadata()?;
        private_file(&after)?;
        ensure!(same(&before, &after), "WAL image изменился при открытии");
        self.check()?;
        Ok(file)
    }

    fn scan_usage(&self) -> Result<(u64, usize)> {
        self.check()?;
        let mut bytes = 0u64;
        let mut entries = 0usize;
        let root = &self.root;
        for (dir, expected_dir) in [(root, Some(&self.blobs)), (&self.blobs, None)] {
            for entry in dir.read_dir(".")? {
                let entry = entry?;
                let name = entry.file_name();
                let metadata = dir.symlink_metadata(&name)?;
                entries = entries.saturating_add(1);
                ensure!(
                    entries <= MAX_MANAGED_ENTRIES + 1,
                    "WAL store scan limit exceeded"
                );
                if name == "blobs"
                    && let Some(expected_dir) = expected_dir
                {
                    ensure!(
                        metadata.is_dir() && !metadata.file_type().is_symlink(),
                        "Небезопасный WAL entry"
                    );
                    ensure!(
                        same(&metadata, &expected_dir.dir_metadata()?),
                        "WAL blob directory binding changed"
                    );
                    continue;
                }
                private_file(&metadata)?;
                bytes = bytes.saturating_add(metadata.len());
                ensure!(bytes <= MAX_MANAGED_BYTES, "WAL store quota exceeded");
            }
        }
        self.check()?;
        Ok((bytes, entries))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl BlobStore {
    pub(crate) fn open(_path: &Path) -> Result<Self> {
        bail!("Filesystem WAL поддерживается только на Linux и macOS")
    }
    pub(crate) fn check(&self) -> Result<()> {
        bail!("Filesystem WAL поддерживается только на Linux и macOS")
    }
    pub(crate) fn acquire_lock(&self) -> Result<()> {
        bail!("Filesystem WAL поддерживается только на Linux и macOS")
    }
    pub(crate) fn reserve(&self, _additional_bytes: u64, _additional_entries: usize) -> Result<()> {
        bail!("Filesystem WAL поддерживается только на Linux и macOS")
    }
    pub(crate) fn read_image_checked(
        &self,
        _image: &ImageRef,
        _expected: Identity,
    ) -> Result<Vec<u8>> {
        bail!("Filesystem WAL поддерживается только на Linux and macOS")
    }
    pub(crate) fn write_image(&self, _bytes: &[u8]) -> Result<(ImageRef, Identity)> {
        bail!("Filesystem WAL поддерживается только на Linux and macOS")
    }
    pub(crate) fn remove_verified_image(
        &self,
        _image: &ImageRef,
        _expected: Identity,
    ) -> Result<()> {
        bail!("Filesystem WAL поддерживается только на Linux and macOS")
    }
    pub(crate) fn open_manifest(&self) -> Result<Option<Vec<u8>>> {
        bail!("Filesystem WAL поддерживается только на Linux and macOS")
    }
    pub(crate) fn write_manifest_atomic(&self, _bytes: &[u8]) -> Result<()> {
        bail!("Filesystem WAL поддерживается только на Linux and macOS")
    }
}

fn absolute_normalized(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::from("/");
    for component in absolute.components() {
        match component {
            Component::RootDir | Component::CurDir => (),
            Component::Normal(name) => normalized.push(name),
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Prefix(_) => bail!("Некорректный абсолютный путь WAL"),
        }
    }
    // macOS exposes common roots such as /tmp and /var through symlinks.
    // Resolve only the existing parent prefix for bootstrap, then retain and
    // no-follow walk that physical path. The final store name is deliberately
    // excluded, so an existing symlink at the store leaf is still rejected.
    let leaf = normalized
        .file_name()
        .ok_or_else(|| anyhow!("Каталог WAL должен иметь имя"))?
        .to_owned();
    let mut parent = normalized
        .parent()
        .ok_or_else(|| anyhow!("У каталога WAL отсутствует родитель"))?
        .to_path_buf();
    let mut missing = vec![leaf];
    let physical_parent = loop {
        match std::fs::canonicalize(&parent) {
            Ok(path) => break path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let name = parent
                    .file_name()
                    .ok_or_else(|| anyhow!("Не найден родитель WAL"))?
                    .to_owned();
                missing.push(name);
                parent = parent
                    .parent()
                    .ok_or_else(|| anyhow!("Не найден корень WAL"))?
                    .to_path_buf();
            }
            Err(error) => return Err(error).context("Не удалось разрешить родитель WAL"),
        }
    };
    let mut resolved = physical_parent;
    for component in missing.iter().rev() {
        resolved.push(component);
    }
    Ok(resolved)
}

fn same(a: &Metadata, b: &Metadata) -> bool {
    MetadataExt::dev(a) == MetadataExt::dev(b) && MetadataExt::ino(a) == MetadataExt::ino(b)
}
fn identity_from(metadata: &Metadata) -> Identity {
    Identity {
        device: MetadataExt::dev(metadata),
        inode: MetadataExt::ino(metadata),
    }
}

fn identity_std(metadata: &std::fs::Metadata) -> Identity {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as StdMetadataExt;
        Identity {
            device: StdMetadataExt::dev(metadata),
            inode: StdMetadataExt::ino(metadata),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Identity {
            device: 0,
            inode: 0,
        }
    }
}

#[cfg(unix)]
fn current_uid() -> u32 {
    unsafe { libc::geteuid() }
}

fn ensure_private_dir(metadata: &Metadata) -> Result<()> {
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "WAL store path is not a directory"
    );
    #[cfg(unix)]
    {
        ensure!(
            CapUnixMetadataExt::uid(metadata) == current_uid(),
            "WAL directory owner changed"
        );
        ensure!(
            CapUnixMetadataExt::mode(metadata) & 0o7777 == 0o700,
            "WAL directories must have mode 0700"
        );
    }
    Ok(())
}

fn private_file(metadata: &Metadata) -> Result<()> {
    ensure!(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && MetadataExt::nlink(metadata) == 1,
        "WAL entry must be a regular file with one link"
    );
    #[cfg(unix)]
    {
        ensure!(
            CapUnixMetadataExt::uid(metadata) == current_uid(),
            "WAL file owner changed"
        );
        ensure!(
            CapUnixMetadataExt::mode(metadata) & 0o7777 == 0o600,
            "WAL files must have mode 0600"
        );
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn create_private_at(dir: &Dir, name: &str) -> Result<cap_std::fs::File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No)
        .nonblock(true)
        .mode(0o600);
    let file = dir
        .open_with(name, &options)
        .with_context(|| "Не удалось создать WAL image")?;
    private_file(&file.metadata()?)?;
    Ok(file)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn open_private_at(dir: &Dir, name: &str, write: bool, create: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(write)
        .follow(FollowSymlinks::No)
        .nonblock(true);
    if create {
        options.create_new(true).mode(0o600);
    }
    let file = dir
        .open_with(name, &options)
        .with_context(|| "Не удалось открыть private WAL entry")?;
    private_file(&file.metadata()?)?;
    Ok(file.into_std())
}

fn verify_named_identity(dir: &Dir, name: &str, expected: Identity) -> Result<()> {
    let metadata = dir.symlink_metadata(name)?;
    private_file(&metadata)?;
    ensure!(
        identity_from(&metadata) == expected,
        "WAL entry identity changed"
    );
    Ok(())
}

fn sync_dir(dir: &Dir) -> Result<()> {
    dir.open(".")?
        .sync_all()
        .context("Не удалось синхронизировать каталог WAL")
}

fn validate_image_ref(image: &ImageRef) -> Result<()> {
    ensure!(image.len <= MAX_IMAGE_BYTES, "Слишком большой WAL image");
    let id = Uuid::parse_str(&image.id).map_err(|_| anyhow!("Некорректный WAL image id"))?;
    ensure!(
        id.get_version_num() == 4
            && id.get_variant() == uuid::Variant::RFC4122
            && id.to_string() == image.id,
        "Некорректный WAL image id"
    );
    ensure!(
        image.sha256.len() == 64
            && image
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "Некорректный WAL image hash"
    );
    Ok(())
}

pub(crate) fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(all(test, unix))]
mod blob_store_tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt, path::Path};

    #[test]
    fn fd_limit_child() {
        if std::env::var_os("RCODE_TEST_WAL_FD_LIMIT_CHILD").is_none() {
            return;
        }
        let limit = libc::rlimit {
            rlim_cur: 64,
            rlim_max: 64,
        };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);

        let temp = tempfile::tempdir().unwrap();
        let mut base = temp.path().canonicalize().unwrap();
        for index in 0..8 {
            base.push(format!("deep-{index}"));
            fs::create_dir(&base).unwrap();
        }
        let mut stores = Vec::new();
        for index in 0..14 {
            let store = BlobStore::open(&base.join(format!("store-{index}"))).unwrap();
            store.acquire_lock().unwrap();
            stores.push(store);
        }
        assert_eq!(stores.len(), 14);
        for store in &stores {
            store.check().unwrap();
        }
    }

    #[test]
    fn many_deep_stores_fit_under_child_fd_limit() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "file_wal::blob_store_tests::fd_limit_child",
                "--nocapture",
            ])
            .env("RCODE_TEST_WAL_FD_LIMIT_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "low-FD WAL subprocess failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn blobs_are_private_exact_and_gc_checks_the_reference() {
        let temp = tempfile::tempdir().unwrap();
        let store = BlobStore::open(&temp.path().join("wal")).unwrap();
        let (image, identity) = store.write_image(b"secret exact bytes\0").unwrap();
        assert_eq!(
            store.read_image_checked(&image, identity).unwrap(),
            b"secret exact bytes\0"
        );
        assert_eq!(mode(&temp.path().join("wal")), 0o700);
        assert_eq!(mode(&temp.path().join("wal/blobs")), 0o700);
        assert_eq!(mode(&temp.path().join("wal/blobs").join(&image.id)), 0o600);
        store.remove_verified_image(&image, identity).unwrap();
        assert!(!temp.path().join("wal/blobs").join(&image.id).exists());
    }

    #[test]
    fn rejects_symlink_blob_store_and_fifo_blob_without_blocking() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("foreign");
        fs::create_dir(&target).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, temp.path().join("wal")).unwrap();
        assert!(BlobStore::open(&temp.path().join("wal")).is_err());

        let store = BlobStore::open(&temp.path().join("safe")).unwrap();
        let fifo_id = Uuid::new_v4().to_string();
        let c_path = std::ffi::CString::new(
            temp.path()
                .join("safe/blobs")
                .join(&fifo_id)
                .as_os_str()
                .as_encoded_bytes(),
        )
        .unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        let image = ImageRef {
            id: fifo_id,
            sha256: sha256(b""),
            len: 0,
        };
        assert!(
            store
                .read_image_checked(
                    &image,
                    Identity {
                        device: 0,
                        inode: 0
                    }
                )
                .is_err()
        );

        let symlink_store = BlobStore::open(&temp.path().join("symlink-safe")).unwrap();
        let (valid, _) = symlink_store.write_image(b"target").unwrap();
        let valid_path = temp.path().join("symlink-safe/blobs").join(&valid.id);
        fs::remove_file(&valid_path).unwrap();
        let link_id = Uuid::new_v4().to_string();
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            &target,
            temp.path().join("symlink-safe/blobs").join(&link_id),
        )
        .unwrap();
        let linked = ImageRef {
            id: link_id,
            sha256: sha256(b"target"),
            len: 6,
        };
        assert!(
            symlink_store
                .read_image_checked(
                    &linked,
                    Identity {
                        device: 0,
                        inode: 0
                    }
                )
                .is_err()
        );
    }

    #[test]
    fn rejects_hardlinks_corruption_oversize_and_replacement_during_gc() {
        let temp = tempfile::tempdir().unwrap();
        let store = BlobStore::open(&temp.path().join("wal")).unwrap();
        let (image, identity) = store.write_image(b"source").unwrap();
        let blob = temp.path().join("wal/blobs").join(&image.id);
        let alias = temp.path().join("alias");
        fs::hard_link(&blob, &alias).unwrap();
        assert!(store.read_image_checked(&image, identity).is_err());
        fs::remove_file(alias).unwrap();
        fs::write(&blob, b"broken").unwrap();
        assert!(store.read_image_checked(&image, identity).is_err());
        let too_big = ImageRef {
            len: MAX_IMAGE_BYTES + 1,
            ..image.clone()
        };
        assert!(store.read_image_checked(&too_big, identity).is_err());
        fs::OpenOptions::new()
            .write(true)
            .open(&blob)
            .unwrap()
            .set_len(MAX_IMAGE_BYTES as u64 + 1)
            .unwrap();
        assert!(store.read_image_checked(&image, identity).is_err());

        let replacement_name = format!(".replacement-{}", Uuid::new_v4());
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut replacement_file = store.blobs.open_with(&replacement_name, &options).unwrap();
        replacement_file.write_all(b"source").unwrap();
        replacement_file.sync_all().unwrap();
        store
            .blobs
            .rename(&replacement_name, &store.blobs, &image.id)
            .unwrap();
        let (replacement, replacement_identity) = store.write_image(b"source").unwrap();
        assert_eq!(replacement.sha256, image.sha256);
        let replacement_path = temp.path().join("wal/blobs").join(&replacement.id);
        // A ref that points at a different inode must not authorize GC.
        let mut stale = replacement.clone();
        stale.id = image.id;
        assert!(store.remove_verified_image(&stale, identity).is_err());
        assert_eq!(fs::read(blob).unwrap(), b"source");
        assert!(
            store
                .remove_verified_image(&replacement, replacement_identity)
                .is_ok()
        );
        assert!(!replacement_path.exists());
    }

    #[test]
    fn ancestor_binding_swap_and_quota_rejection_do_not_mutate_foreign_paths() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("parent");
        let store_path = parent.join("wal");
        fs::create_dir(&parent).unwrap();
        let store = BlobStore::open(&store_path).unwrap();
        let (image, identity) = store.write_image(b"x").unwrap();
        let moved_parent = temp.path().join("moved");
        fs::rename(&parent, &moved_parent).unwrap();
        fs::create_dir(&parent).unwrap();
        fs::rename(moved_parent.join("wal"), parent.join("wal")).unwrap();
        assert!(store.read_image_checked(&image, identity).is_err());

        let fresh = BlobStore::open(&temp.path().join("quota")).unwrap();
        assert!(fresh.reserve(MAX_STORE_BYTES + 1, 0).is_err());
        assert_eq!(
            fs::read_dir(temp.path().join("quota/blobs"))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn retained_lock_detects_named_inode_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let store = BlobStore::open(&temp.path().join("wal")).unwrap();
        store.acquire_lock().unwrap();
        let root = temp.path().join("wal");
        let saved = root.join("wal.lock.saved");
        fs::rename(root.join("wal.lock"), &saved).unwrap();
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("wal.lock"))
            .unwrap();
        assert!(store.check().is_err());
        assert!(saved.exists());
    }

    #[test]
    fn manifest_writes_are_private_and_compare_the_observed_version() {
        let temp = tempfile::tempdir().unwrap();
        let store = BlobStore::open(&temp.path().join("wal")).unwrap();
        store.acquire_lock().unwrap();
        assert_eq!(store.open_manifest().unwrap(), None);
        store.write_manifest_atomic(b"version one").unwrap();
        assert_eq!(
            store.open_manifest().unwrap(),
            Some(b"version one".to_vec())
        );
        let manifest = temp.path().join("wal/checkpoints.json");
        fs::write(&manifest, b"outside mutation").unwrap();
        assert!(store.write_manifest_atomic(b"version two").is_err());
        assert_eq!(fs::read(&manifest).unwrap(), b"outside mutation");
        assert_eq!(mode(&manifest), 0o600);
    }

    #[test]
    fn quota_admission_fails_before_creating_a_blob() {
        let temp = tempfile::tempdir().unwrap();
        let store_path = temp.path().join("wal");
        fs::create_dir(&store_path).unwrap();
        fs::set_permissions(&store_path, fs::Permissions::from_mode(0o700)).unwrap();
        let blobs = store_path.join("blobs");
        fs::create_dir(&blobs).unwrap();
        fs::set_permissions(&blobs, fs::Permissions::from_mode(0o700)).unwrap();
        use std::os::unix::fs::OpenOptionsExt;
        let filler = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(blobs.join("quota-filler"))
            .unwrap();
        filler.set_len(MAX_STORE_BYTES).unwrap();
        let store = BlobStore::open(&store_path).unwrap();
        assert!(store.write_image(b"x").is_err());
        assert_eq!(fs::read_dir(blobs).unwrap().count(), 1);
    }

    #[test]
    fn unsafe_preexisting_directory_is_rejected_without_chmod() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("wal");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(BlobStore::open(&path).is_err());
        assert_eq!(mode(&path), 0o755);
    }
}
