//! Workspace capabilities and durable, per-turn undo. Shell commands run with the
//! user's privileges; their side effects are deliberately not adopted by undo.
use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use std::process::{ExitStatus, Stdio};
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
#[cfg(unix)]
use cap_std::fs::PermissionsExt;
use cap_std::fs::{Dir, OpenOptions, Permissions};
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use regex::RegexBuilder;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio_util::sync::CancellationToken;

use crate::protocol::{ToolDefinition, ToolOutcome};

const MAX_FILE_BYTES: usize = 1024 * 1024;
const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_SCAN_BYTES: usize = 16 * 1024 * 1024;
const MAX_SCAN_FILES: usize = 5_000;
const MAX_ENTRIES: usize = 10_000;
const MAX_CHECKPOINT_ENTRIES: usize = 1_024;
const MAX_ORPHAN_STAGES: usize = 4_096;
const MAX_RESULTS: usize = 1_000;
#[cfg(test)]
const CHECKPOINT_FILE: &str = "checkpoints.json";
pub(crate) const SHELL_NOTE: &str = "Изменения shell-команд не управляются undo; изменения отслеживаемых файлов после записи вызывают конфликт.";

#[derive(Debug, thiserror::Error)]
#[error("Не удалось сохранить checkpoint: {0}")]
struct CheckpointFailure(String);

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoints {
    version: u32,
    root: PathBuf,
    #[serde(default)]
    root_identity: Option<crate::file_wal::Identity>,
    turns: Vec<Turn>,
    #[serde(default)]
    pending_write: Option<WriteIntent>,
    #[serde(default)]
    pending_undo: Option<UndoIntent>,
    #[serde(default)]
    orphan_stages: Vec<OrphanStage>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OrphanStage {
    root: PathBuf,
    parent: PathBuf,
    stage: crate::workspace_stage::StageRef,
    bytes: u64,
    binding: Vec<crate::file_wal::Identity>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyCheckpointsV1 {
    version: u32,
    root: PathBuf,
    turns: Vec<LegacyTurnV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyTurnV1 {
    entries: Vec<Value>,
    #[serde(default)]
    shell_used: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyCheckpointsV2 {
    version: u32,
    root: PathBuf,
    root_identity: crate::file_wal::Identity,
    turns: Vec<LegacyTurnV2>,
    #[serde(default)]
    pending_write: Option<Value>,
    #[serde(default)]
    pending_undo: Option<Value>,
    orphan_stages: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyTurnV2 {
    entries: Vec<Value>,
    #[serde(default)]
    shell_used: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteIntent {
    turn: usize,
    candidate: Change,
    before_image: Option<StoredImage>,
    before_sha256: Option<String>,
    before_identity: Option<crate::file_wal::Identity>,
    before_mode: Option<u32>,
    before_readonly: bool,
    before_binding: Vec<crate::file_wal::Identity>,
    stage: Option<crate::workspace_stage::StageRef>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UndoIntent {
    turn: usize,
    order: Vec<usize>,
    prepared: bool,
    entries: Vec<UndoProgress>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UndoProgress {
    stage: Option<crate::workspace_stage::StageRef>,
    done: Option<UndoDone>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "state", content = "identity", deny_unknown_fields)]
enum UndoDone {
    Restored(crate::file_wal::Identity),
    Deleted,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Turn {
    entries: Vec<Change>,
    #[serde(default)]
    shell_used: bool,
}

fn is_zero_usize(value: &usize) -> bool {
    *value == 0
}

fn parent_normal_component_count(path: &Path) -> usize {
    path.parent().map_or(0, |parent| {
        parent
            .components()
            .filter(|c| matches!(c, Component::Normal(_)))
            .count()
    })
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Change {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    root: Option<PathBuf>,
    path: PathBuf,
    before: Option<StoredImage>,
    mode: Option<u32>,
    readonly: bool,
    after_sha256: String,
    after_image: StoredImage,
    #[serde(default)]
    after_mode: Option<u32>,
    #[serde(default)]
    after_identity: Option<crate::file_wal::Identity>,
    #[serde(default)]
    binding: Option<Vec<crate::file_wal::Identity>>,
    #[serde(default, skip_serializing_if = "is_zero_usize")]
    created_parents: usize,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredImage {
    image: crate::file_wal::ImageRef,
    identity: crate::file_wal::Identity,
}

struct Snapshot {
    bytes: Vec<u8>,
    permissions: Permissions,
    #[cfg(unix)]
    identity: FileIdentity,
    #[cfg(unix)]
    nlink: u64,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
type PathBinding = Vec<FileIdentity>;

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct CreatedDirRecord {
    rel_dir: PathBuf,
    parent_binding: PathBinding,
    identity: FileIdentity,
}

struct ReadObservation {
    sha256: String,
    stale: bool,
    #[cfg(unix)]
    identity: FileIdentity,
    #[cfg(unix)]
    binding: PathBinding,
}

struct Prepared {
    root: Option<PathBuf>,
    path: PathBuf,
    parent: Dir,
    name: OsString,
    before: Option<Snapshot>,
    after: Vec<u8>,
    #[cfg(unix)]
    binding: PathBinding,
    missing_dirs: Vec<OsString>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ApprovedWrite {
    before_sha256: Option<String>,
    after_sha256: String,
    #[cfg(unix)]
    before_identity: Option<FileIdentity>,
    #[cfg(unix)]
    binding: PathBinding,
    missing_dirs: Vec<OsString>,
}

impl Prepared {
    fn approval_stamp(&self) -> ApprovedWrite {
        ApprovedWrite {
            before_sha256: self.before.as_ref().map(|s| sha256(&s.bytes)),
            after_sha256: sha256(&self.after),
            #[cfg(unix)]
            before_identity: self.before.as_ref().map(|s| s.identity),
            #[cfg(unix)]
            binding: self.binding.clone(),
            missing_dirs: self.missing_dirs.clone(),
        }
    }
}

struct UndoPrepared {
    entry_index: usize,
    #[cfg(unix)]
    binding: PathBinding,
    #[cfg(unix)]
    file_identity: FileIdentity,
}

pub struct Tools {
    root: PathBuf,
    dir: Dir,
    extra_dirs: BTreeMap<PathBuf, Dir>,
    checkpoint_path: PathBuf,
    blob_store: crate::file_wal::BlobStore,
    root_identity: crate::file_wal::Identity,
    checkpoints: Checkpoints,
    active_turn: Option<usize>,
    wal_poisoned: bool,
    // Host observations are ephemeral and private to each model context. A
    // worker cannot inherit another worker's or the coordinator's file reads.
    read_snapshots: HashMap<(Option<String>, PathBuf), ReadObservation>,
    #[cfg(all(test, unix))]
    before_publication_hook: Option<Box<dyn FnOnce() + Send + Sync>>,
    #[cfg(all(test, unix))]
    wal_fault_hook: Option<Box<dyn FnMut(WalFaultPoint) + Send + Sync>>,
    #[cfg(all(test, unix))]
    store_fault_schedule: Option<(WalFaultPoint, crate::file_wal::StoreFaultPoint, i32)>,
}

pub(crate) struct PreparedDirectoryGrants(BTreeMap<PathBuf, Dir>);

#[cfg(all(test, unix))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WalFaultPoint {
    DurableIntent,
    StageDirectoryCreated { index: usize },
    StageGuardDurable { index: usize },
    StagePayloadDurable { index: usize },
    StageCreated { index: usize },
    PreparedPersisted,
    BeforePreparedPersist,
    WorkspaceMutation { index: usize },
    NamespaceSynced { index: usize },
    ProgressPersisted { index: usize },
    Finalized,
    BeforeFinalPersist,
}

impl Tools {
    #[cfg(all(test, unix))]
    pub(crate) fn set_wal_fault_hook(&mut self, hook: Box<dyn FnMut(WalFaultPoint) + Send + Sync>) {
        self.wal_fault_hook = Some(hook);
    }

    #[cfg(all(test, unix))]
    pub(crate) fn fail_store_after_wal_point(
        &mut self,
        wal_point: WalFaultPoint,
        store_point: crate::file_wal::StoreFaultPoint,
        errno: i32,
    ) {
        self.store_fault_schedule = Some((wal_point, store_point, errno));
    }

    #[cfg(all(test, unix))]
    fn wal_fault(&mut self, point: WalFaultPoint) {
        if self
            .store_fault_schedule
            .as_ref()
            .is_some_and(|(scheduled, _, _)| *scheduled == point)
        {
            let (_, store_point, errno) = self.store_fault_schedule.take().unwrap();
            let _ = self.blob_store.fail_next(store_point, errno);
        }
        if let Some(hook) = &mut self.wal_fault_hook {
            hook(point);
        }
    }

    pub fn new(root: &Path, checkpoint_dir: &Path) -> Result<Self> {
        let root = std::fs::canonicalize(root).context("Рабочий каталог недоступен")?;
        ensure!(root.is_dir(), "Корень проекта должен быть каталогом");
        let checkpoint_absolute = std::path::absolute(checkpoint_dir)?;
        ensure!(
            !checkpoint_absolute.starts_with(&root),
            "Checkpoint должен храниться вне рабочего проекта"
        );
        let blob_store = crate::file_wal::BlobStore::open(checkpoint_dir)?;
        blob_store.check()?;
        let checkpoint_path = std::fs::canonicalize(checkpoint_dir)?;
        ensure!(
            !checkpoint_path.starts_with(&root),
            "Checkpoint должен храниться вне рабочего проекта"
        );
        let dir = Dir::open_ambient_dir(&root, cap_std::ambient_authority())?;
        let root_identity = {
            let id = directory_identity(&dir)?;
            crate::file_wal::Identity {
                device: id.device,
                inode: id.inode,
            }
        };
        blob_store.acquire_lock()?;
        let mut migrated_empty_legacy = false;
        let checkpoints = match blob_store.open_manifest()? {
            Some(saved) => {
                let envelope: Value =
                    serde_json::from_slice(&saved).context("Повреждён checkpoint")?;
                let version = envelope
                    .get("version")
                    .and_then(Value::as_u64)
                    .context("Checkpoint version missing")?;
                let state: Checkpoints = match version {
                    1 => {
                        let legacy: LegacyCheckpointsV1 = serde_json::from_value(envelope)
                            .context("Повреждён legacy checkpoint")?;
                        ensure!(legacy.version == 1, "Unsupported legacy checkpoint version");
                        ensure!(
                            legacy
                                .turns
                                .iter()
                                .all(|turn| turn.entries.is_empty() && !turn.shell_used),
                            "Непустой legacy checkpoint v1 не содержит безопасной identity; начните новую сессию, файл сохранён"
                        );
                        migrated_empty_legacy = true;
                        Checkpoints {
                            version: 3,
                            root: legacy.root,
                            root_identity: Some(root_identity),
                            turns: vec![],
                            pending_write: None,
                            pending_undo: None,
                            orphan_stages: vec![],
                        }
                    }
                    2 => {
                        let legacy: LegacyCheckpointsV2 = serde_json::from_value(envelope)
                            .context("Повреждён legacy checkpoint v2")?;
                        ensure!(legacy.version == 2, "Unsupported legacy checkpoint version");
                        let empty_turns = legacy
                            .turns
                            .iter()
                            .all(|turn| turn.entries.is_empty() && !turn.shell_used);
                        let no_pending =
                            legacy.pending_write.is_none() && legacy.pending_undo.is_none();
                        let no_orphans = legacy.orphan_stages.is_empty();
                        ensure!(
                            legacy.root == root
                                && legacy.root_identity == root_identity
                                && empty_turns
                                && no_pending
                                && no_orphans,
                            "Checkpoint v2 содержит историю или старые raw stages и не совместим с WAL v3; исходный файл оставлен без изменений, откройте его прежней версией"
                        );
                        migrated_empty_legacy = true;
                        Checkpoints {
                            version: 3,
                            root: legacy.root,
                            root_identity: Some(root_identity),
                            turns: vec![],
                            pending_write: None,
                            pending_undo: None,
                            orphan_stages: vec![],
                        }
                    }
                    3 => serde_json::from_value(envelope).context("Повреждён checkpoint v3")?,
                    _ => bail!("Неподдерживаемая версия checkpoint; файл оставлен без изменений"),
                };
                ensure!(
                    state.version == 3 && state.root == root,
                    "Checkpoint относится к другому корню или версии"
                );
                ensure!(
                    state.root_identity.is_some(),
                    "Checkpoint v3 не содержит identity корня"
                );
                if let Some(expected) = state.root_identity {
                    ensure!(
                        expected == root_identity,
                        "Корень workspace заменён после checkpoint"
                    );
                }
                ensure!(
                    state.turns.len() <= 1_000,
                    "Слишком много ходов в checkpoint"
                );
                ensure!(
                    state
                        .turns
                        .iter()
                        .map(|turn| turn.entries.len())
                        .sum::<usize>()
                        <= MAX_CHECKPOINT_ENTRIES,
                    "Too many WAL entries"
                );
                for turn in &state.turns {
                    ensure!(
                        turn.entries.len() <= MAX_CHECKPOINT_ENTRIES,
                        "Too many entries in one WAL turn"
                    );
                    let mut seen = std::collections::HashSet::new();
                    for change in &turn.entries {
                        ensure!(
                            normalized_path(&change.path, false)? == change.path,
                            "Некорректный путь в checkpoint"
                        );
                        if let Some(extra_root) = &change.root {
                            validate_external_root(extra_root, &checkpoint_path)?;
                            match std::fs::canonicalize(extra_root) {
                                Ok(canonical) => ensure!(
                                    canonical == *extra_root,
                                    "Неканонический корень checkpoint"
                                ),
                                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                                Err(error) => return Err(error.into()),
                            }
                            ensure!(
                                !extra_root.join(&change.path).starts_with(&root),
                                "Внешний корень checkpoint находится внутри проекта"
                            );
                        }
                        ensure!(
                            !change
                                .path
                                .components()
                                .any(|c| secret_component(c.as_os_str())),
                            "Секретный путь в checkpoint"
                        );
                        ensure!(
                            seen.insert(change.root.as_deref().unwrap_or(&root).join(&change.path)),
                            "Повтор пути в checkpoint"
                        );
                        ensure!(
                            change.before.as_ref().is_none_or(valid_image),
                            "Слишком большой preimage"
                        );
                        ensure!(
                            change.after_sha256.len() == 64
                                && change.after_sha256.bytes().all(|b| b.is_ascii_hexdigit()),
                            "Некорректный hash в checkpoint"
                        );
                        ensure!(
                            valid_image(&change.after_image)
                                && change.after_image.image.sha256 == change.after_sha256,
                            "Invalid final-after image"
                        );
                        ensure!(
                            change.mode.is_none_or(|m| m <= 0o7777),
                            "Некорректный mode в checkpoint"
                        );
                        if state.version == 3 && !change.after_sha256.is_empty() {
                            let parent_depth = parent_normal_component_count(&change.path);
                            ensure!(
                                change.after_identity.is_some()
                                    && change.after_mode.is_some_and(|mode| mode <= 0o7777)
                                    && change.binding.as_ref().is_some_and(|binding| {
                                        binding.len() == 1 + parent_depth && binding.len() <= 66
                                    })
                                    && change.before.is_some() == change.mode.is_some()
                                    && change.created_parents <= parent_depth
                                    && (change.created_parents == 0
                                        || (change.before.is_none()
                                            && change.mode.is_none()
                                            && !change.readonly)),
                                "Checkpoint v2 не содержит подтверждённую identity файла"
                            );
                        }
                    }
                }
                if let Some(pending) = &state.pending_write {
                    ensure!(
                        state.pending_undo.is_none(),
                        "Multiple WAL operations are pending"
                    );
                    ensure!(
                        state.version == 3,
                        "Legacy checkpoint cannot contain WAL intent"
                    );
                    ensure!(
                        pending.turn < state.turns.len(),
                        "WAL intent turn is out of range"
                    );
                    ensure!(
                        pending.turn + 1 == state.turns.len(),
                        "WAL write intent must reference the active final turn"
                    );
                    let candidate = &pending.candidate;
                    ensure!(
                        normalized_path(&candidate.path, false)? == candidate.path,
                        "Invalid WAL intent path"
                    );
                    ensure!(
                        !candidate
                            .path
                            .components()
                            .any(|c| secret_component(c.as_os_str())),
                        "Secret path in WAL intent"
                    );
                    if let Some(extra_root) = &candidate.root {
                        validate_external_root(extra_root, &checkpoint_path)?;
                        ensure!(
                            std::fs::canonicalize(extra_root)
                                .is_ok_and(|canonical| canonical == *extra_root),
                            "WAL intent external root changed"
                        );
                    }
                    ensure!(
                        candidate.before.as_ref().is_none_or(valid_image),
                        "WAL intent preimage too large"
                    );
                    ensure!(
                        valid_image(&candidate.after_image)
                            && candidate.after_image.image.sha256 == candidate.after_sha256,
                        "Invalid WAL after image"
                    );
                    ensure!(
                        pending.before_image.as_ref().is_none_or(valid_image),
                        "Invalid WAL immediate-before image"
                    );
                    ensure!(
                        candidate.after_sha256.len() == 64
                            && candidate
                                .after_sha256
                                .bytes()
                                .all(|b| b.is_ascii_hexdigit()),
                        "Invalid WAL intent hash"
                    );
                    ensure!(
                        pending
                            .before_sha256
                            .as_ref()
                            .is_none_or(|hash| hash.len() == 64
                                && hash.bytes().all(|b| b.is_ascii_hexdigit())),
                        "Invalid WAL before hash"
                    );
                    let candidate_parent_depth = parent_normal_component_count(&candidate.path);
                    ensure!(
                        pending.before_binding.len() == 1 + candidate_parent_depth
                            && pending.before_binding.len() <= 66,
                        "WAL path binding exceeds limit"
                    );
                    ensure!(
                        candidate.created_parents <= candidate_parent_depth
                            && (candidate.created_parents == 0
                                || (candidate.before.is_none()
                                    && candidate.mode.is_none()
                                    && !candidate.readonly)),
                        "Invalid created_parents in WAL candidate"
                    );
                    ensure!(
                        !pending.before_binding.is_empty()
                            && candidate.before.as_ref().is_some() == candidate.mode.is_some()
                            && pending.before_image.as_ref().is_some()
                                == pending.before_sha256.as_ref().is_some()
                            && pending.before_sha256.as_ref().is_some()
                                == pending.before_identity.is_some()
                            && pending.before_sha256.as_ref().is_some()
                                == pending.before_mode.is_some()
                            && (pending.before_sha256.is_some() || !pending.before_readonly),
                        "Inconsistent WAL immediate-before metadata"
                    );
                    if let (Some(image), Some(hash)) =
                        (&pending.before_image, &pending.before_sha256)
                    {
                        ensure!(
                            image.image.sha256 == *hash
                                && pending.before_mode.is_some_and(|mode| mode <= 0o7777),
                            "WAL immediate-before image and metadata differ"
                        );
                    }
                    let matching = state.turns[pending.turn]
                        .entries
                        .iter()
                        .filter(|change| {
                            change.root == candidate.root && change.path == candidate.path
                        })
                        .collect::<Vec<_>>();
                    ensure!(matching.len() <= 1, "Duplicate path in WAL candidate turn");
                    if let Some(previous) = matching.first() {
                        ensure!(
                            candidate.before == previous.before
                                && candidate.created_parents == previous.created_parents
                                && pending.before_image.as_ref() == Some(&previous.after_image)
                                && pending.before_sha256.as_ref() == Some(&previous.after_sha256)
                                && pending.before_identity == previous.after_identity
                                && pending.before_mode == previous.after_mode
                                && candidate.readonly == previous.readonly,
                            "Repeated-write WAL images do not match the committed change"
                        );
                    } else {
                        ensure!(
                            candidate.before.as_ref() == pending.before_image.as_ref()
                                && candidate.mode == pending.before_mode
                                && (candidate.created_parents == 0
                                    || (pending.before_image.is_none()
                                        && pending.before_sha256.is_none()
                                        && pending.before_identity.is_none()
                                        && pending.before_mode.is_none()
                                        && !pending.before_readonly)),
                            "Initial-write WAL images do not match the original preimage"
                        );
                    }
                    if let Some(stage) = &pending.stage {
                        crate::workspace_stage::StageDirectory::validate_ref(stage)?;
                    }
                    if let Some(stage) = pending
                        .stage
                        .as_ref()
                        .filter(|stage| stage.payload.is_some())
                    {
                        let stage_identity = stage.payload.unwrap();
                        ensure!(
                            candidate.after_identity == Some(stage_identity)
                                && stage.directory.is_some()
                                && stage.guard.is_some()
                                && candidate.after_mode.is_some_and(|mode| mode <= 0o7777)
                                && candidate.binding.as_ref().is_some_and(|binding| {
                                    binding.iter().map(|id| (id.device, id.inode)).eq(pending
                                        .before_binding
                                        .iter()
                                        .map(|id| (id.device, id.inode)))
                                }),
                            "Prepared write stage differs from WAL candidate"
                        );
                    } else {
                        ensure!(
                            candidate.after_identity.is_none()
                                && candidate.after_mode.is_none()
                                && candidate.binding.is_none(),
                            "Unprepared write has publication metadata"
                        );
                    }
                }
                if let Some(pending) = &state.pending_undo {
                    ensure!(
                        state.version == 3 && state.pending_write.is_none(),
                        "Invalid pending undo version/state"
                    );
                    ensure!(
                        pending.turn < state.turns.len(),
                        "WAL undo turn out of range"
                    );
                    let entry_count = state.turns[pending.turn].entries.len();
                    ensure!(
                        entry_count > 0
                            && !(pending.turn + 1..state.turns.len()).any(|later| {
                                state.turns[later].shell_used
                                    || !state.turns[later].entries.is_empty()
                            }),
                        "WAL undo must reference the latest non-empty turn"
                    );
                    ensure!(
                        pending.entries.len() == entry_count && pending.order.len() == entry_count,
                        "WAL undo entry/order count mismatch"
                    );
                    let mut order_seen = std::collections::HashSet::new();
                    for (index, order_index) in pending.order.iter().enumerate() {
                        ensure!(
                            *order_index < entry_count && order_seen.insert(*order_index),
                            "WAL undo order is not a permutation"
                        );
                        let progress = &pending.entries[index];
                        let change = &state.turns[pending.turn].entries[index];
                        if let Some(stage) = &progress.stage {
                            crate::workspace_stage::StageDirectory::validate_ref(stage)?;
                        }
                        ensure!(
                            pending.prepared || progress.done.is_none(),
                            "Undo stage/progress before Prepared"
                        );
                        if pending.prepared && change.before.is_some() {
                            ensure!(
                                progress.stage.as_ref().is_some_and(|stage| {
                                    stage.directory.is_some()
                                        && stage.guard.is_some()
                                        && stage.payload.is_some()
                                }),
                                "Prepared restore has no proven stage"
                            );
                        }
                        if !pending.prepared {
                            ensure!(
                                progress.done.is_none(),
                                "Undo cannot be Done before Prepared"
                            );
                        }
                        match &progress.done {
                            Some(UndoDone::Deleted) => ensure!(
                                pending.prepared && change.before.is_none(),
                                "Deleted progress is incompatible with restore action"
                            ),
                            Some(UndoDone::Restored(identity)) => ensure!(
                                pending.prepared
                                    && change.before.is_some()
                                    && progress.stage.as_ref().and_then(|stage| stage.payload)
                                        == Some(*identity),
                                "Restored progress is incompatible with stage"
                            ),
                            None => {}
                        }
                        if progress.stage.is_some() {
                            ensure!(
                                state.turns[pending.turn].entries[index].before.is_some(),
                                "Unexpected stage for created file"
                            );
                        }
                    }
                    ensure!(
                        pending.order == undo_order(&state.turns[pending.turn].entries),
                        "WAL undo order is not canonical"
                    );
                }
                ensure!(
                    state.orphan_stages.len() <= MAX_ORPHAN_STAGES,
                    "WAL orphan stage budget is exhausted"
                );
                let mut orphan_names = std::collections::HashSet::new();
                for orphan in &state.orphan_stages {
                    ensure!(orphan.root.is_absolute(), "Invalid orphan stage root");
                    if orphan.root != state.root {
                        validate_external_root(&orphan.root, &checkpoint_path)?;
                    }
                    ensure!(
                        normalized_path(&orphan.parent, true)? == orphan.parent
                            && crate::workspace_stage::StageDirectory::validate_ref(&orphan.stage)
                                .is_ok()
                            && orphan.bytes <= crate::file_wal::MAX_IMAGE_BYTES as u64
                            && !orphan.binding.is_empty()
                            && orphan.binding.len() <= 66
                            && orphan_names.insert((
                                orphan.root.clone(),
                                orphan.parent.clone(),
                                orphan.stage.name.clone(),
                            )),
                        "Invalid or duplicate orphan stage reference"
                    );
                }
                let pending_stage_count = state
                    .pending_write
                    .as_ref()
                    .is_some_and(|pending| pending.stage.is_some())
                    as usize
                    + state.pending_undo.as_ref().map_or(0, |pending| {
                        pending
                            .entries
                            .iter()
                            .filter(|entry| entry.stage.is_some())
                            .count()
                    });
                ensure!(
                    state
                        .orphan_stages
                        .len()
                        .saturating_add(pending_stage_count)
                        .saturating_mul(3)
                        <= crate::file_wal::MAX_STORE_ENTRIES,
                    "Workspace stage namespace budget is exhausted"
                );
                Checkpoints {
                    version: 3,
                    root: state.root,
                    root_identity: Some(root_identity),
                    turns: state.turns,
                    pending_write: state.pending_write,
                    pending_undo: state.pending_undo,
                    orphan_stages: state.orphan_stages,
                }
            }
            None => Checkpoints {
                version: 3,
                root: root.clone(),
                root_identity: Some(root_identity),
                turns: vec![],
                pending_write: None,
                pending_undo: None,
                orphan_stages: vec![],
            },
        };
        let verify_image = |stored: &StoredImage| -> Result<Vec<u8>> {
            ensure!(valid_image(stored), "Invalid WAL image reference");
            let bytes = blob_store.read_image_checked(&stored.image, stored.identity)?;
            ensure!(
                bytes.len() == stored.image.len && sha256(&bytes) == stored.image.sha256,
                "WAL image identity/content mismatch"
            );
            Ok(bytes)
        };
        for turn in &checkpoints.turns {
            for change in &turn.entries {
                if let Some(before) = &change.before {
                    let _ = verify_image(before)?;
                }
                let after = verify_image(&change.after_image)?;
                ensure!(
                    sha256(&after) == change.after_sha256,
                    "Checkpoint final-after hash mismatch"
                );
            }
        }
        if let Some(pending) = &checkpoints.pending_write {
            if let Some(before) = &pending.before_image {
                let _ = verify_image(before)?;
            }
            let after = verify_image(&pending.candidate.after_image)?;
            ensure!(
                sha256(&after) == pending.candidate.after_sha256,
                "WAL intent after image mismatch"
            );
        }
        let mut tools = Self {
            root,
            dir,
            extra_dirs: BTreeMap::new(),
            checkpoint_path,
            blob_store,
            root_identity,
            checkpoints,
            active_turn: None,
            wal_poisoned: false,
            read_snapshots: HashMap::new(),
            #[cfg(all(test, unix))]
            before_publication_hook: None,
            #[cfg(all(test, unix))]
            wal_fault_hook: None,
            #[cfg(all(test, unix))]
            store_fault_schedule: None,
        };
        tools.reconcile_pending_write()?;
        tools.reconcile_pending_undo()?;
        if migrated_empty_legacy {
            tools.persist()?;
        }
        Ok(tools)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Host-only grant. Tool arguments never modify the capability set, and
    /// these grants are deliberately absent from the persisted session.
    pub fn add_directory(&mut self, path: &Path) -> Result<()> {
        let absolute = std::path::absolute(path)?;
        safe_external_path(&absolute, false)?;
        let root = std::fs::canonicalize(&absolute)?;
        validate_external_root(&root, &self.checkpoint_path)?;
        ensure!(root.is_dir(), "Дополнительный путь должен быть каталогом");
        if root.starts_with(&self.root) || self.extra_dirs.keys().any(|r| root.starts_with(r)) {
            return Ok(());
        }
        let dir = open_external_directory(&root)?;
        // A broader explicit grant supersedes narrower roots so their ignore
        // rules cannot be bypassed by selecting a nested capability.
        self.extra_dirs.retain(|r, _| !r.starts_with(&root));
        self.extra_dirs.insert(root, dir);
        Ok(())
    }

    pub(crate) fn prepare_directory_grants(
        &self,
        paths: &[PathBuf],
    ) -> Result<PreparedDirectoryGrants> {
        let mut extra_dirs: BTreeMap<PathBuf, Dir> = BTreeMap::new();
        for path in paths {
            let absolute = std::path::absolute(path)?;
            safe_external_path(&absolute, false)?;
            let root = std::fs::canonicalize(&absolute)?;
            validate_external_root(&root, &self.checkpoint_path)?;
            ensure!(root.is_dir(), "Дополнительный путь должен быть каталогом");
            if root.starts_with(&self.root) || extra_dirs.keys().any(|r| root.starts_with(r)) {
                continue;
            }
            let dir = open_external_directory(&root)?;
            extra_dirs.retain(|r, _| !r.starts_with(&root));
            extra_dirs.insert(root, dir);
        }
        Ok(PreparedDirectoryGrants(extra_dirs))
    }

    pub(crate) fn replace_directory_grants(&mut self, grants: PreparedDirectoryGrants) {
        self.extra_dirs = grants.0;
        self.read_snapshots.clear();
    }

    pub fn extra_directory_for(&self, name: &str, args: &Value) -> Result<Option<PathBuf>> {
        if !file_tool(name) {
            return Ok(None);
        }
        validate_args(name, args)?;
        let Some(path) = args.get("path").and_then(Value::as_str).map(Path::new) else {
            return Ok(None);
        };
        if !path.is_absolute() {
            return Ok(None);
        }
        validate_absolute_path(path)?;
        if let Some((dir, root, relative)) =
            self.location(path, matches!(name, "list_files" | "search"))?
        {
            Policy::new(dir, root).check(
                &relative,
                if name == "write_file" {
                    MissingPolicy::AllowMissingSubtree
                } else {
                    MissingPolicy::Disallow
                },
            )?;
            return Ok(None);
        }
        safe_external_path(path, name == "write_file")?;
        let candidate = if matches!(name, "list_files" | "search") {
            ensure!(path.is_dir(), "Для доступа нужен существующий каталог");
            path
        } else {
            path.parent().context("Требуется родительский каталог")?
        };
        let root =
            std::fs::canonicalize(candidate).context("Родительский каталог должен существовать")?;
        validate_external_root(&root, &self.checkpoint_path)?;
        let dir = open_external_directory(&root)?;
        let relative = if matches!(name, "list_files" | "search") {
            Path::new(".")
        } else {
            Path::new(path.file_name().context("Требуется путь к файлу")?)
        };
        Policy::new(&dir, &root).check(
            relative,
            if name == "write_file" {
                MissingPolicy::AllowMissingLeaf
            } else {
                MissingPolicy::Disallow
            },
        )?;
        Ok(Some(root))
    }

    pub fn extra_directories(&self) -> Vec<PathBuf> {
        self.extra_dirs.keys().cloned().collect()
    }

    fn location(&self, path: &Path, allow_root: bool) -> Result<Option<(&Dir, &Path, PathBuf)>> {
        if !path.is_absolute() {
            return Ok(Some((
                &self.dir,
                &self.root,
                normalized_path(path, allow_root)?,
            )));
        }
        validate_absolute_path(path)?;
        // Most calls already carry a canonical root. Check all direct prefixes
        // before resolving aliases, especially during a large external search.
        for (root, dir) in std::iter::once((&self.root, &self.dir)).chain(self.extra_dirs.iter()) {
            if let Ok(relative) = path.strip_prefix(root) {
                return Ok(Some((dir, root, normalized_path(relative, allow_root)?)));
            }
        }
        for (root, dir) in std::iter::once((&self.root, &self.dir)).chain(self.extra_dirs.iter()) {
            if let Some(prefix) = root_prefix(path, root) {
                return Ok(Some((
                    dir,
                    root,
                    normalized_path(path.strip_prefix(prefix)?, allow_root)?,
                )));
            }
        }
        Ok(None)
    }

    fn required_location(&self, path: &Path, allow_root: bool) -> Result<(&Dir, &Path, PathBuf)> {
        self.location(path, allow_root)?
            .context("Путь вне разрешённых рабочих каталогов")
    }

    pub fn definitions() -> Vec<ToolDefinition> {
        let defs = [
            (
                "read_file",
                "Прочитать UTF-8 файл (до 1 MiB): SHA-256 файла, номера строк и пагинация. Относительные пути — в проекте; внешние абсолютные требуют разрешения host на каталог. Symlink, секретные и исключённые файлы закрыты. Не перечитывайте файл сразу после успешного write_file или edit_file для проверки записи.",
                json!({"path":{"type":"string"},"start_line":{"type":"integer","minimum":1},"max_lines":{"type":"integer","minimum":1,"maximum":500}}),
                vec!["path"],
            ),
            (
                "list_files",
                "Список разрешённых файлов проекта или внешнего каталога, явно разрешённого host, с рекурсией и ограничением обхода. Для внешнего каталога укажите абсолютный путь. Не показывает исключённые, секретные файлы и symlink.",
                json!({"path":{"type":"string"},"max_results":{"type":"integer","minimum":1,"maximum":1000},"offset":{"type":"integer","minimum":0,"maximum":10000}}),
                vec![],
            ),
            (
                "search",
                "Поиск Rust regex в UTF-8 файлах проекта или внешнего каталога, явно разрешённого host. Для внешнего каталога укажите абсолютный путь. Ограничены regex, размер файлов, общий объём сканирования и результаты. Бинарные файлы пропускаются.",
                json!({"pattern":{"type":"string","maxLength":4096},"path":{"type":"string"},"max_results":{"type":"integer","minimum":1,"maximum":1000},"case_sensitive":{"type":"boolean"}}),
                vec!["pattern"],
            ),
            (
                "write_file",
                "Атомарно записать UTF-8 файл в проекте или разрешённом host внешнем каталоге. Перед перезаписью вызовите read_file: host сверяет снимок чтения. Обычно опускайте expected_sha256 (явно — только read_file.sha256, не хеш артефакта; для нового файла опускайте). Для частичных правок — edit_file; перечитывать файл для проверки записи не нужно. Недостающие подкаталоги внутри корня создаются автоматически; доступно undo.",
                json!({"path":{"type":"string"},"content":{"type":"string"},"expected_sha256":{"type":"string","description":"Необязательно: обычно опускайте после read_file. Явное значение — только sha256 самого файла из read_file, не хеш сохранённого ответа инструмента."}}),
                vec!["path", "content"],
            ),
            (
                "edit_file",
                "Заменить точное непустое old_text в UTF-8 файле проекта или разрешённого host внешнего каталога (внешний путь — абсолютный). Не включайте префиксы номеров строк N\\t из read_file. Совпадение единственное, кроме replace_all=true. Успешный ответ подтверждает выполнение правки; перечитывать файл для проверки не нужно. Доступно undo.",
                json!({"path":{"type":"string"},"old_text":{"type":"string","minLength":1},"new_text":{"type":"string"},"replace_all":{"type":"boolean"}}),
                vec!["path", "old_text", "new_text"],
            ),
            (
                "run_command",
                "Выполнить shell-команду с правами пользователя после разрешения приложения. Рабочий каталог — проект, разрешены абсолютные пути в запрошенных пользователем внешних каталогах: mkdir и quoted heredoc создают файлы, cat читает. Ошибка outside_workspace у write_file означает использовать этот инструмент, не повторять write_file. Нельзя обходить отказ пользователя, ignore или ограничения секретных файлов. Это не OS sandbox. Env ограничен, вывод до 64 KiB, timeout 60 сек (макс. 300). Shell-изменения не управляются undo.",
                json!({"command":{"type":"string","maxLength":16384},"timeout_secs":{"type":"integer","minimum":1,"maximum":300}}),
                vec!["command"],
            ),
        ];
        defs.into_iter().map(|(name, description, properties, required)| ToolDefinition {
            name: name.into(), description: description.into(),
            parameters: json!({"type":"object","properties":properties,"required":required,"additionalProperties":false}),
        }).collect()
    }

    pub fn definitions_for_sandbox(
        policy: crate::sandbox::EffectiveSandboxPolicy,
    ) -> Vec<ToolDefinition> {
        let mut defs = Self::definitions();
        if !policy.is_active() {
            return defs;
        }
        let net = if policy.network { "on" } else { "off" };
        let run_desc = match policy.mode {
            crate::sandbox::SandboxMode::Off => unreachable!("checked is_active()"),
            crate::sandbox::SandboxMode::WorkspaceWrite => format!(
                "Выполнить shell-команду внутри активной OS-песочницы (режим workspace-write, сеть {net}) после разрешения приложения. Рабочий каталог — проект; чтение вне проекта/разрешённых каталогов и системного рантайма заблокировано, запись разрешена только в рабочем каталоге, разрешённых внешних каталогах и приватном TMPDIR команды. Ошибка outside_workspace у write_file означает запросить разрешение на внешний каталог или использовать разрешённый путь без обхода отказа пользователя, ignore, ограничений секретных файлов и OS-песочницы. Env ограничен, вывод до 64 KiB, timeout 60 сек (макс. 300). Shell-изменения не управляются undo."
            ),
            crate::sandbox::SandboxMode::ReadOnly => format!(
                "Выполнить shell-команду внутри активной read-only OS-песочницы (режим read-only, сеть {net}) после разрешения приложения. Рабочий каталог — проект; чтение вне проекта/разрешённых каталогов и системного рантайма заблокировано, запись в проект и внешние каталоги запрещена ядром ОС (доступна только в приватный TMPDIR команды). Для разрешённых изменений файлов используйте write_file/edit_file; нельзя обходить отказ пользователя, ignore, ограничения секретных файлов и OS-песочницы. Env ограничен, вывод до 64 KiB, timeout 60 сек (макс. 300). Shell-изменения не управляются undo."
            ),
        };
        for def in &mut defs {
            if def.name == "run_command" {
                def.description = run_desc;
                break;
            }
        }
        defs
    }

    pub fn preview(&self, name: &str, args: &Value) -> Result<Option<String>> {
        self.preview_for(name, args, None)
    }

    fn format_write_preview(
        &self,
        name: &str,
        args: &Value,
        actor: Option<&str>,
    ) -> Result<(String, ApprovedWrite)> {
        let prepared = self.prepare(name, args, actor)?;
        let stamp = prepared.approval_stamp();
        let before = prepared
            .before
            .as_ref()
            .map(|s| std::str::from_utf8(&s.bytes))
            .transpose()?
            .unwrap_or("");
        let after = std::str::from_utf8(&prepared.after)?;
        let diff = unified_diff(
            &display_path(prepared.root.as_deref(), &prepared.path),
            before,
            after,
        );
        Ok((diff, stamp))
    }

    pub(crate) fn preview_write_for(
        &self,
        name: &str,
        args: &Value,
        actor: Option<&str>,
    ) -> Result<(String, ApprovedWrite)> {
        ensure!(
            matches!(name, "write_file" | "edit_file"),
            "Неизвестная файловая операция: {name}"
        );
        validate_args(name, args)?;
        let args = self.workspace_args(name, args)?;
        self.format_write_preview(name, args.as_ref(), actor)
    }

    pub(crate) fn preview_for(
        &self,
        name: &str,
        args: &Value,
        actor: Option<&str>,
    ) -> Result<Option<String>> {
        validate_args(name, args)?;
        let args = self.workspace_args(name, args)?;
        let args = args.as_ref();
        match name {
            "write_file" | "edit_file" => {
                let (diff, _) = self.format_write_preview(name, args, actor)?;
                Ok(Some(diff))
            }
            "run_command" => {
                command_args(args)?;
                Ok(Some(format!(
                    "{}\n{}\n{}",
                    self.root.display(),
                    string_arg(args, "command")?,
                    SHELL_NOTE
                )))
            }
            "read_file" | "list_files" | "search" => Ok(None),
            _ => bail!("Неизвестный инструмент: {name}"),
        }
    }

    fn workspace_args<'a>(
        &self,
        name: &str,
        args: &'a Value,
    ) -> Result<std::borrow::Cow<'a, Value>> {
        use std::borrow::Cow;
        if !matches!(
            name,
            "read_file" | "write_file" | "edit_file" | "list_files" | "search"
        ) {
            return Ok(Cow::Borrowed(args));
        }
        let Some(path) = args.get("path").and_then(Value::as_str) else {
            return Ok(Cow::Borrowed(args));
        };
        let path = Path::new(path);
        if !path.is_absolute() {
            return Ok(Cow::Borrowed(args));
        }
        ensure!(
            !path.components().any(|c| matches!(c, Component::ParentDir)),
            "Путь с .. запрещён; укажите прямой путь без обхода каталогов"
        );
        ensure!(
            path.components().count() <= 64 && path.as_os_str().len() <= 4096,
            "Слишком длинный путь"
        );
        if let Some((_, root, relative)) =
            self.location(path, matches!(name, "list_files" | "search"))?
        {
            let mut normalized = args.clone();
            normalized["path"] = if root == self.root {
                json!(relative)
            } else {
                json!(root.join(relative))
            };
            return Ok(Cow::Owned(normalized));
        }
        ensure!(
            !path
                .components()
                .any(|c| matches!(c, Component::Normal(part) if secret_component(part))),
            "Доступ к секретным файлам и служебным каталогам запрещён"
        );
        bail!(json!({
            "error":"outside_workspace", "path":path, "workspace":self.root,
            "next_tool":"run_command",
            "message":"Файловые инструменты работают внутри workspace. Не повторяй этот вызов с внешним путём. Если пользователь попросил создать проект в этом внешнем каталоге, используй run_command: mkdir -p и cat с quoted heredoc для записи реальных файлов; shell запускается из workspace, поэтому укажи полный путь. Затем проверь проект тем же инструментом. Разрешение запрашивает host; эта ошибка не даёт новых разрешений. Не используй shell для обхода отказов пользователя, ignore, symlink или ограничений секретных файлов."
        }).to_string());
    }

    pub async fn execute(
        &mut self,
        name: &str,
        args: &Value,
        cancel: &CancellationToken,
    ) -> Result<ToolOutcome> {
        self.execute_for(name, args, cancel, None).await
    }

    pub(crate) async fn execute_for(
        &mut self,
        name: &str,
        args: &Value,
        cancel: &CancellationToken,
        actor: Option<&str>,
    ) -> Result<ToolOutcome> {
        self.execute_for_approved(name, args, cancel, actor, None)
            .await
    }

    pub(crate) async fn execute_for_approved(
        &mut self,
        name: &str,
        args: &Value,
        cancel: &CancellationToken,
        actor: Option<&str>,
        approved: Option<&ApprovedWrite>,
    ) -> Result<ToolOutcome> {
        let result = async {
            self.ensure_wal_healthy()?;
            validate_args(name, args)?;
            check_cancel(cancel)?;
            let args = self.workspace_args(name, args)?;
            let args = args.as_ref();
            match name {
                "read_file" => self.read_file(args, cancel, actor),
                "list_files" => self.list_files(args, cancel).await,
                "search" => self.search(args, cancel).await,
                "write_file" | "edit_file" => self.write(name, args, cancel, actor, approved),
                "run_command" => {
                    ensure!(
                        self.checkpoints.pending_write.is_none()
                            && self.checkpoints.pending_undo.is_none(),
                        "Незавершённая WAL-операция блокирует новые изменения"
                    );
                    self.run_command(args, cancel).await
                }
                _ => bail!("Неизвестный инструмент: {name}"),
            }
        }
        .await;
        match result {
            Ok(outcome) => Ok(outcome),
            Err(error) if error.downcast_ref::<CheckpointFailure>().is_some() => Err(error),
            Err(error) => Ok(ToolOutcome::error(bounded(&format!("{error:#}"), 4_096))),
        }
    }

    pub fn begin_turn(&mut self) -> Result<()> {
        self.ensure_wal_healthy()?;
        ensure!(
            self.checkpoints.pending_write.is_none() && self.checkpoints.pending_undo.is_none(),
            "Незавершённая WAL-операция требует явного recovery через undo"
        );
        let previous = self.checkpoints.clone();
        self.checkpoints
            .turns
            .retain(|t| !t.entries.is_empty() || t.shell_used);
        ensure!(
            self.checkpoints.turns.len() < 1_000,
            "Лимит ходов checkpoint; начните новую сессию"
        );
        self.checkpoints.turns.push(Turn::default());
        if let Err(error) = self.persist() {
            self.checkpoints = previous;
            return Err(error);
        }
        self.active_turn = Some(self.checkpoints.turns.len() - 1);
        self.read_snapshots.clear();
        Ok(())
    }

    pub fn undo(&mut self) -> Result<String> {
        self.ensure_wal_healthy()?;
        ensure!(
            self.checkpoints.pending_write.is_none(),
            "WAL обнаружил конфликт незавершённой записи; workspace не менялся, сначала разрешите конфликт вручную"
        );
        if self.checkpoints.pending_undo.is_some() {
            return self.resume_pending_undo();
        }
        let Some(index) = self
            .checkpoints
            .turns
            .iter()
            .rposition(|t| !t.entries.is_empty() || t.shell_used)
        else {
            return Ok(format!("Нет файловых правок для отмены. {SHELL_NOTE}"));
        };
        let turn = self.checkpoints.turns[index].clone();
        if turn.entries.is_empty() {
            // A shell-only turn has no workspace state to stage. Remove its
            // metadata directly so it cannot create an empty UndoIntent that
            // the strict loader would reject after a crash.
            let previous = self.checkpoints.clone();
            self.checkpoints.turns.truncate(index);
            if let Err(error) = self.persist() {
                self.checkpoints = previous;
                return Err(error);
            }
            self.active_turn = None;
            return Ok(format!("Отменены файловые правки: 0. {SHELL_NOTE}"));
        }
        ensure!(
            self.checkpoints.orphan_stages.len() + turn.entries.len() <= MAX_ORPHAN_STAGES
                && self
                    .checkpoints
                    .orphan_stages
                    .len()
                    .saturating_add(
                        turn.entries
                            .iter()
                            .filter(|change| change.before.is_some())
                            .count()
                    )
                    .saturating_mul(3)
                    <= crate::file_wal::MAX_STORE_ENTRIES,
            "WAL orphan budget has no reserved capacity for this undo group"
        );
        let group_before_bytes = turn
            .entries
            .iter()
            .filter_map(|change| change.before.as_ref())
            .map(|image| image.image.len as u64)
            .sum::<u64>();
        let orphan_bytes = self
            .checkpoints
            .orphan_stages
            .iter()
            .map(|orphan| orphan.bytes)
            .sum::<u64>();
        ensure!(
            group_before_bytes.saturating_add(orphan_bytes) <= crate::file_wal::MAX_STORE_BYTES,
            "WAL orphan byte budget reserves space for undo stages"
        );
        let stage_count = turn
            .entries
            .iter()
            .filter(|change| change.before.is_some())
            .count();
        ensure!(
            stage_count.saturating_mul(3) <= crate::file_wal::MAX_STORE_ENTRIES,
            "Undo stage namespace reservation exceeds WAL entry budget"
        );
        self.blob_store.reserve(
            group_before_bytes
                .saturating_add(orphan_bytes)
                .saturating_add((stage_count as u64).saturating_mul(2))
                .saturating_add(8 * 1024 * 1024),
            2,
        )?;
        // Check every entry before touching any file. A conflict keeps the
        // complete journal and all current user bytes unchanged.
        let mut batch = Vec::with_capacity(turn.entries.len());
        for (entry_index, change) in turn.entries.iter().enumerate() {
            let dir = self.change_directory(change)?;
            let root = change.root.as_deref().unwrap_or(&self.root);
            // A completed delete is already absent, and a completed restore
            // may have changed policy. Those entries are identity-checked
            // below and must not be run through policy again.
            let path = Policy::new(&dir, root).check(&change.path, MissingPolicy::Disallow)?;
            let displayed_path = display_path(change.root.as_deref(), &path);
            #[cfg(unix)]
            let (parent, name, binding) = bound_parent_handle(&dir, root, &path)?;
            #[cfg(not(unix))]
            let (parent, name) = parent_handle(&dir, &path)?;
            let current = snapshot(&parent, Path::new(&name), MAX_FILE_BYTES)?;
            ensure!(
                current
                    .as_ref()
                    .is_some_and(|s| sha256(&s.bytes) == change.after_sha256),
                "Конфликт undo: {} изменён или удалён после правки. {SHELL_NOTE}",
                displayed_path.display()
            );
            let current = current.unwrap();
            #[cfg(unix)]
            {
                ensure!(current.nlink == 1, "Hard-linked files cannot be undone");
                ensure!(
                    change
                        .after_identity
                        .is_some_and(|identity| identity.device == current.identity.device
                            && identity.inode == current.identity.inode),
                    "Конфликт undo: identity файла изменилась после записи"
                );
                let saved_binding = change
                    .binding
                    .as_ref()
                    .context("Checkpoint не содержит identity каталога")?;
                ensure!(
                    saved_binding
                        .iter()
                        .map(|id| (id.device, id.inode))
                        .eq(binding.iter().map(|id| (id.device, id.inode))),
                    "Конфликт undo: identity каталога изменилась после записи"
                );
            }
            if change.before.is_some() {
                ensure!(
                    permission_mode(&current.permissions) == change.mode
                        && current.permissions.readonly() == change.readonly,
                    "Конфликт undo: права {} изменены после правки",
                    displayed_path.display()
                );
            }
            #[cfg(unix)]
            ensure!(
                change
                    .after_mode
                    .is_some_and(|mode| permission_mode(&current.permissions) == Some(mode)),
                "Конфликт undo: mode файла изменён после записи"
            );
            #[cfg(unix)]
            let file_identity = current.identity;
            batch.push(UndoPrepared {
                entry_index,
                #[cfg(unix)]
                binding,
                #[cfg(unix)]
                file_identity,
            });
            drop((parent, name));
        }
        let old_state = self.checkpoints.clone();
        self.checkpoints.pending_undo = Some(UndoIntent {
            turn: index,
            order: undo_order(&turn.entries),
            prepared: false,
            entries: vec![UndoProgress::default(); turn.entries.len()],
        });
        if let Err(error) = self.persist() {
            self.checkpoints.pending_undo = None;
            return Err(error);
        }
        #[cfg(all(test, unix))]
        self.wal_fault(WalFaultPoint::DurableIntent);
        // Prepare every restore image before the first target mutation. A
        // permission or space failure in a later parent must leave the group
        // unchanged. This is recoverable group undo, not cross-filesystem
        // atomicity; each publication is still revalidated independently.
        let before_images = turn
            .entries
            .iter()
            .map(|change| {
                change
                    .before
                    .as_ref()
                    .map(|stored| {
                        self.blob_store
                            .read_image_checked(&stored.image, stored.identity)
                    })
                    .transpose()
            })
            .collect::<Result<Vec<_>>>()?;
        let order = self
            .checkpoints
            .pending_undo
            .as_ref()
            .unwrap()
            .order
            .clone();
        {
            let intent = self
                .checkpoints
                .pending_undo
                .as_mut()
                .context("Undo intent disappeared")?;
            for (entry_index, before) in before_images.iter().enumerate() {
                if before.is_some() {
                    intent.entries[entry_index].stage = Some(crate::workspace_stage::StageRef {
                        name: crate::workspace_stage::StageDirectory::plan_name(),
                        directory: None,
                        guard: None,
                        payload: None,
                    });
                }
            }
        }
        self.persist()?;
        for entry_index in order.iter().copied() {
            let item = &batch[entry_index];
            if let Some(before) = before_images[entry_index].as_deref() {
                let stage_ref = self.checkpoints.pending_undo.as_ref().unwrap().entries
                    [entry_index]
                    .stage
                    .as_ref()
                    .context("Undo stage plan missing")?
                    .clone();
                let change = &turn.entries[entry_index];
                let retained = self.change_directory(change)?;
                let root = change.root.as_deref().unwrap_or(&self.root);
                let path =
                    Policy::new(&retained, root).check(&change.path, MissingPolicy::Disallow)?;
                let (parent, name, binding) = bound_parent_handle(&retained, root, &path)?;
                ensure!(
                    binding == item.binding,
                    "Undo path binding changed while staging"
                );
                #[cfg(all(test, unix))]
                let sequence = order
                    .iter()
                    .position(|index| *index == entry_index)
                    .unwrap();
                let stage = match (|| -> Result<crate::workspace_stage::StageRef> {
                    let mut stage = crate::workspace_stage::StageDirectory::create_empty(
                        &parent,
                        &stage_ref.name,
                    )?;
                    #[cfg(all(test, unix))]
                    self.wal_fault(WalFaultPoint::StageDirectoryCreated { index: sequence });
                    stage.install_guard(&parent)?;
                    #[cfg(all(test, unix))]
                    self.wal_fault(WalFaultPoint::StageGuardDurable { index: sequence });
                    let permissions = change.mode.map(Permissions::from_mode);
                    stage.write_payload(&parent, before, permissions.as_ref())?;
                    #[cfg(all(test, unix))]
                    self.wal_fault(WalFaultPoint::StagePayloadDurable { index: sequence });
                    Ok(stage.reference())
                })() {
                    Ok(stage) => stage,
                    Err(error) => {
                        self.reconcile_pending_undo()?;
                        return Err(error);
                    }
                };
                #[cfg(all(test, unix))]
                {
                    self.wal_fault(WalFaultPoint::StageCreated { index: sequence });
                }
                self.checkpoints.pending_undo.as_mut().unwrap().entries[entry_index].stage =
                    Some(stage);
                self.persist()?;
                drop((parent, name));
            }
        }
        let before_prepared_persist = self.checkpoints.clone();
        {
            let intent = self
                .checkpoints
                .pending_undo
                .as_mut()
                .context("Undo intent disappeared")?;
            intent.prepared = true;
        }
        #[cfg(all(test, unix))]
        self.wal_fault(WalFaultPoint::BeforePreparedPersist);
        if let Err(error) = self.persist() {
            self.checkpoints = before_prepared_persist;
            return Err(error);
        }
        #[cfg(all(test, unix))]
        self.wal_fault(WalFaultPoint::PreparedPersisted);

        // Preflight prevents partial undo for pre-existing conflicts. Each
        // commit also checks again; concurrent external writers are not locked.
        #[cfg(all(test, unix))]
        if let Some(hook) = self.before_publication_hook.take() {
            hook();
        }

        // The legacy test hook and any concurrent writer can invalidate an
        // entry after Prepared. Before the first mutation we still know this
        // process has published nothing, so abandon the prepared transaction
        // safely and retain the user's replacement untouched.
        for item in &batch {
            let change = &turn.entries[item.entry_index];
            if let Err(error) = self.revalidate_undo(change, &item.binding, item.file_identity) {
                // Persist the abort and known orphan references before any
                // stage cleanup. If the manifest write fails, the durable
                // Prepared intent still has all of its evidence for reopen.
                let pending_state = self.checkpoints.clone();
                self.checkpoints = old_state.clone();
                for (entry_index, progress) in pending_state
                    .pending_undo
                    .as_ref()
                    .expect("Prepared undo intent exists")
                    .entries
                    .iter()
                    .enumerate()
                {
                    let Some(stage) = progress.stage.as_ref() else {
                        continue;
                    };
                    let change = &turn.entries[entry_index];
                    let root = change.root.clone().unwrap_or_else(|| self.root.clone());
                    if let Err(orphan_error) = self.record_orphan_stage(
                        &root,
                        &change.path,
                        stage,
                        change.before.as_ref().map_or(0, |image| image.image.len),
                        change.binding.as_deref().unwrap_or_default(),
                    ) {
                        self.checkpoints = pending_state;
                        return Err(orphan_error);
                    }
                }
                if let Err(persist_error) = self.persist() {
                    self.checkpoints = pending_state;
                    return Err(persist_error);
                }
                return Err(error);
            }
        }
        self.resume_pending_undo()
    }

    pub fn diff(&self) -> Result<String> {
        let mut changes = BTreeMap::<(Option<&Path>, &Path), &Change>::new();
        let mut shell_used = false;
        for turn in &self.checkpoints.turns {
            shell_used |= turn.shell_used;
            for change in &turn.entries {
                changes
                    .entry((change.root.as_deref(), &change.path))
                    .or_insert(change);
            }
        }
        let mut out = String::new();
        for ((root, relative), change) in changes {
            if out.len() >= MAX_OUTPUT_BYTES {
                break;
            }
            let path = display_path(root, relative);
            let current = self.change_directory(change).and_then(|dir| {
                let root = change.root.clone().unwrap_or_else(|| self.root.clone());
                let relative =
                    Policy::new(&dir, &root).check(relative, MissingPolicy::AllowMissingLeaf)?;
                let (parent, name) = parent_handle(&dir, &relative)?;
                snapshot(&parent, Path::new(&name), MAX_FILE_BYTES)
            });
            match current {
                Ok(current) => {
                    let before = change
                        .before
                        .as_ref()
                        .map(|image| {
                            self.blob_store
                                .read_image_checked(&image.image, image.identity)
                        })
                        .transpose()?;
                    let old = String::from_utf8_lossy(before.as_deref().unwrap_or_default());
                    let new = String::from_utf8_lossy(
                        current.as_ref().map_or(&[], |s| s.bytes.as_slice()),
                    );
                    out.push_str(&unified_diff(&path, &old, &new));
                }
                Err(error) => out.push_str(&format!("{}: {error}\n", path.display())),
            }
        }
        if out.is_empty() {
            out.push_str("Нет отслеживаемых файловых изменений.\n");
        }
        if shell_used {
            out.push_str(SHELL_NOTE);
            out.push('\n');
        }
        if !self.checkpoints.orphan_stages.is_empty() {
            out.push_str(&format!(
                "WAL оставил {} неизвестных служебных stage-каталогов без изменения; они не будут переиспользованы или удалены автоматически.\n",
                self.checkpoints.orphan_stages.len()
            ));
        }
        Ok(bounded(&out, MAX_OUTPUT_BYTES))
    }

    // Explicit /undo and /diff can access only journaled paths. Opening this
    // root never adds a capability for subsequent model tool calls.
    fn change_directory(&self, change: &Change) -> Result<Dir> {
        match &change.root {
            None => {
                #[cfg(unix)]
                return checked_root(&self.dir, &self.root).map(|(dir, _)| dir);
                #[cfg(not(unix))]
                Ok(self.dir.try_clone()?)
            }
            Some(root) => {
                validate_external_root(root, &self.checkpoint_path)?;
                safe_external_path(root, false)?;
                ensure!(
                    std::fs::canonicalize(root)? == *root,
                    "Корень checkpoint изменён"
                );
                #[cfg(unix)]
                if let Some(retained) = self.extra_dirs.get(root) {
                    return checked_root(retained, root).map(|(dir, _)| dir);
                }
                open_external_directory(root)
            }
        }
    }

    fn persist(&mut self) -> Result<()> {
        self.ensure_wal_healthy()?;
        ensure!(
            self.checkpoints.version == 3,
            "Unsupported WAL manifest version"
        );
        let (_, root_id) = checked_root(&self.dir, &self.root)?;
        ensure!(
            root_id.device == self.root_identity.device
                && root_id.inode == self.root_identity.inode
                && self.checkpoints.root_identity == Some(self.root_identity),
            "Workspace root identity changed"
        );
        self.blob_store.check()?;
        let bytes = serde_json::to_vec(&self.checkpoints)?;
        ensure!(
            bytes.len() <= crate::file_wal::MAX_MANIFEST_BYTES,
            "Превышен лимит WAL manifest (4 MiB)"
        );
        match self.blob_store.write_manifest_atomic(&bytes) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.wal_poisoned = true;
                Err(CheckpointFailure(format!("{error:#}")).into())
            }
        }
    }

    fn ensure_wal_healthy(&self) -> Result<()> {
        if self.wal_poisoned {
            return Err(CheckpointFailure(
                "WAL состояние неопределённо после ошибки durable записи; переоткройте checkpoint"
                    .to_owned(),
            )
            .into());
        }
        Ok(())
    }

    fn gc_unreferenced_from(&mut self, prior: &Checkpoints) {
        let prior_images = checkpoint_images(prior);
        let retained_images = checkpoint_images(&self.checkpoints);
        for (id, image) in prior_images {
            if !retained_images.contains_key(&id) {
                // A failed identity/content check leaves the file in place;
                // it remains a counted orphan rather than being removed by name.
                let _ = self
                    .blob_store
                    .remove_verified_image(&image.image, image.identity);
            }
        }
    }

    fn record_orphan_stage(
        &mut self,
        root: &Path,
        path: &Path,
        stage: &crate::workspace_stage::StageRef,
        bytes: usize,
        binding: &[crate::file_wal::Identity],
    ) -> Result<()> {
        crate::workspace_stage::StageDirectory::validate_ref(stage)?;
        ensure!(
            root.is_absolute() && !binding.is_empty() && binding.len() <= 66,
            "Invalid orphan stage binding"
        );
        let parent = path.parent().unwrap_or(Path::new("."));
        let reference = OrphanStage {
            root: root.to_path_buf(),
            parent: normalized_path(parent, true)?,
            stage: stage.clone(),
            // The durable intent binds this stage name to a known image, so
            // even a directory whose identity was not persisted can contain
            // at most this payload length.
            bytes: bytes as u64,
            binding: binding.to_vec(),
        };
        if let Some(existing) = self.checkpoints.orphan_stages.iter().find(|orphan| {
            orphan.root == reference.root
                && orphan.parent == reference.parent
                && orphan.stage.name == reference.stage.name
        }) {
            ensure!(
                existing.stage == reference.stage && existing.bytes == reference.bytes,
                "Orphan stage reference changed"
            );
            return Ok(());
        }
        ensure!(
            self.checkpoints.orphan_stages.len() < MAX_ORPHAN_STAGES
                && self
                    .checkpoints
                    .orphan_stages
                    .len()
                    .saturating_add(1)
                    .saturating_mul(3)
                    <= crate::file_wal::MAX_STORE_ENTRIES,
            "WAL orphan stage budget exhausted; new file writes are blocked"
        );
        let used_bytes = self
            .checkpoints
            .orphan_stages
            .iter()
            .map(|orphan| orphan.bytes)
            .sum::<u64>();
        ensure!(
            used_bytes.saturating_add(reference.bytes) <= crate::file_wal::MAX_STORE_BYTES,
            "WAL orphan byte budget exhausted"
        );
        self.checkpoints.orphan_stages.push(reference);
        Ok(())
    }

    fn cleanup_committed_stage(
        &mut self,
        change: &Change,
        stage: &crate::workspace_stage::StageRef,
        payload_proof: Option<&crate::workspace_stage::PayloadProof>,
    ) -> Result<bool> {
        let root = change.root.as_deref().unwrap_or(&self.root);
        let dir = self.change_directory(change)?;
        let (parent, _, binding) = bound_parent_handle(&dir, root, &change.path)?;
        let expected = change
            .binding
            .as_ref()
            .context("Checkpoint lacks stage parent binding")?;
        ensure!(
            expected
                .iter()
                .map(|id| (id.device, id.inode))
                .eq(binding.iter().map(|id| (id.device, id.inode))),
            "Workspace stage parent binding changed before cleanup"
        );
        if !crate::workspace_stage::StageDirectory::cleanup_known(&parent, stage, payload_proof)? {
            return Ok(false);
        }
        let parent_path = normalized_path(change.path.parent().unwrap_or(Path::new(".")), true)?;
        let prior_orphans = self.checkpoints.orphan_stages.clone();
        self.checkpoints.orphan_stages.retain(|orphan| {
            !(orphan.root == root
                && orphan.parent == parent_path
                && orphan.stage.name == stage.name)
        });
        if let Err(error) = self.persist() {
            self.checkpoints.orphan_stages = prior_orphans;
            return Err(error);
        }
        Ok(true)
    }

    #[cfg(unix)]
    fn checkpoints_reference_dir(&self, root: &Path, rel_dir: &Path) -> bool {
        if self.wal_poisoned
            || self.checkpoints.pending_write.is_some()
            || self.checkpoints.pending_undo.is_some()
        {
            return true;
        }
        let target_dir = root.join(rel_dir);
        for turn in &self.checkpoints.turns {
            for change in &turn.entries {
                let change_full = change
                    .root
                    .as_deref()
                    .unwrap_or(&self.root)
                    .join(&change.path);
                if change_full.starts_with(&target_dir) {
                    return true;
                }
            }
        }
        for orphan in &self.checkpoints.orphan_stages {
            let orphan_full =
                if orphan.parent == Path::new(".") || orphan.parent.as_os_str().is_empty() {
                    orphan.root.clone()
                } else {
                    orphan.root.join(&orphan.parent)
                };
            if orphan_full == target_dir || orphan_full.starts_with(&target_dir) {
                return true;
            }
        }
        false
    }

    #[cfg(unix)]
    fn cleanup_root_dir(&self, root_path: &Path) -> Result<(Dir, FileIdentity)> {
        if root_path == self.root {
            return checked_root(&self.dir, &self.root);
        }
        if let Some(retained) = self.extra_dirs.get(root_path) {
            return checked_root(retained, root_path);
        }
        validate_external_root(root_path, &self.checkpoint_path)?;
        safe_external_path(root_path, false)?;
        ensure!(
            std::fs::canonicalize(root_path)? == root_path,
            "Корень checkpoint изменён"
        );
        let dir = open_external_directory(root_path)?;
        let id = directory_identity(&dir)?;
        Ok((dir, id))
    }

    #[cfg(unix)]
    fn cleanup_created_dirs(&self, root_path: &Path, records: &[CreatedDirRecord]) {
        use cap_std::fs::MetadataExt as CapUnixMetadataExt;
        if self.wal_poisoned
            || self.checkpoints.pending_write.is_some()
            || self.checkpoints.pending_undo.is_some()
        {
            return;
        }
        for record in records.iter().rev() {
            if self.checkpoints_reference_dir(root_path, &record.rel_dir) {
                continue;
            }
            let Some(leaf) = record.rel_dir.file_name() else {
                continue;
            };
            let Ok((mut parent, root_identity)) = self.cleanup_root_dir(root_path) else {
                continue;
            };
            let mut actual_parent_binding = vec![root_identity];
            let parent_rel = record
                .rel_dir
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let mut walk_ok = true;
            for component in parent_rel.components() {
                match component {
                    Component::CurDir => continue,
                    Component::Normal(part) => {
                        let Ok(next) = open_child_directory(&parent, part) else {
                            walk_ok = false;
                            break;
                        };
                        let Ok(next_id) = directory_identity(&next) else {
                            walk_ok = false;
                            break;
                        };
                        actual_parent_binding.push(next_id);
                        parent = next;
                    }
                    _ => {
                        walk_ok = false;
                        break;
                    }
                }
            }
            if !walk_ok || actual_parent_binding != record.parent_binding {
                continue;
            }
            let Ok(named) = parent.symlink_metadata(leaf) else {
                continue;
            };
            if !named.is_dir()
                || named.file_type().is_symlink()
                || (FileIdentity {
                    device: named.dev(),
                    inode: named.ino(),
                }) != record.identity
            {
                continue;
            }
            let Ok(child) = open_child_directory(&parent, leaf) else {
                continue;
            };
            let child_matches = directory_identity(&child).ok() == Some(record.identity);
            drop(child);
            if !child_matches {
                continue;
            }
            if parent.remove_dir(leaf).is_ok()
                && let Ok(handle) = parent.open(".")
            {
                let _ = handle.sync_all();
            }
        }
    }

    /// Startup may classify a write intent, but it never publishes or removes
    /// workspace entries. An exact before-image permits metadata-only abort;
    /// an exact stage inode at the target proves the rename completed and lets
    /// us commit the recorded candidate. Anything else remains a conflict.
    fn reconcile_pending_write(&mut self) -> Result<()> {
        let Some(intent) = self.checkpoints.pending_write.clone() else {
            return Ok(());
        };
        let candidate = &intent.candidate;
        let root_path = candidate.root.clone().unwrap_or_else(|| self.root.clone());
        let root = root_path.as_path();
        let dir = self.change_directory(candidate)?;
        let path =
            Policy::new(&dir, root).check(&candidate.path, MissingPolicy::AllowMissingLeaf)?;
        let (parent, name, binding) = bound_parent_handle(&dir, root, &path)?;
        let binding: Vec<_> = binding
            .iter()
            .map(|id| crate::file_wal::Identity {
                device: id.device,
                inode: id.inode,
            })
            .collect();
        let current = snapshot(&parent, Path::new(&name), MAX_FILE_BYTES)?;
        let binding_matches = binding == intent.before_binding;
        let before_matches = if let Some(before_image) = &intent.before_image {
            let before = self
                .blob_store
                .read_image_checked(&before_image.image, before_image.identity)?;
            current.as_ref().is_some_and(|file| {
                Some(sha256(&file.bytes)) == intent.before_sha256
                    && file.bytes == before
                    && file.nlink == 1
                    && Some(crate::file_wal::Identity {
                        device: file.identity.device,
                        inode: file.identity.inode,
                    }) == intent.before_identity
                    && permission_mode(&file.permissions) == intent.before_mode
                    && file.permissions.readonly() == intent.before_readonly
            })
        } else {
            current.is_none()
        };
        if binding_matches && before_matches {
            if let Some(stage) = &intent.stage {
                self.record_orphan_stage(
                    root,
                    &candidate.path,
                    stage,
                    candidate.after_image.image.len,
                    &intent.before_binding,
                )?;
            }
            let recoverable = self.checkpoints.clone();
            self.checkpoints.pending_write = None;
            if let Err(error) = self.persist() {
                self.checkpoints = recoverable;
                return Err(error);
            }
            return Ok(());
        }
        let after_matches = binding_matches
            && intent
                .stage
                .as_ref()
                .and_then(|stage| stage.payload)
                .is_some_and(|expected| {
                    current.as_ref().is_some_and(|file| {
                        file.identity.device == expected.device
                            && file.identity.inode == expected.inode
                            && file.nlink == 1
                            && sha256(&file.bytes) == candidate.after_sha256
                            && candidate.after_image.image.len == file.bytes.len()
                            && self
                                .blob_store
                                .read_image_checked(
                                    &candidate.after_image.image,
                                    candidate.after_image.identity,
                                )
                                .is_ok_and(|bytes| bytes == file.bytes)
                            && permission_mode(&file.permissions) == candidate.after_mode
                            && file.permissions.readonly() == candidate.readonly
                    })
                });
        if after_matches {
            if let Some(stage_ref) = intent.stage.as_ref() {
                let stage_directory =
                    crate::workspace_stage::StageDirectory::open_checked(&parent, stage_ref)?;
                stage_directory.sync_after_publication(&parent)?;
            }
            let recoverable = self.checkpoints.clone();
            let turn = self
                .checkpoints
                .turns
                .get_mut(intent.turn)
                .context("WAL turn missing during recovery")?;
            let primary = self.root.clone();
            let full = candidate
                .root
                .as_deref()
                .unwrap_or(&primary)
                .join(&candidate.path);
            if let Some(existing) = turn.entries.iter_mut().find(|change| {
                change
                    .root
                    .as_deref()
                    .unwrap_or(&primary)
                    .join(&change.path)
                    == full
            }) {
                *existing = candidate.clone();
            } else {
                turn.entries.push(candidate.clone());
            }
            if let Some(stage) = &intent.stage {
                self.record_orphan_stage(
                    root,
                    &candidate.path,
                    stage,
                    candidate.after_image.image.len,
                    &intent.before_binding,
                )?;
            }
            self.checkpoints.pending_write = None;
            if let Err(error) = self.persist() {
                self.checkpoints = recoverable;
                return Err(error);
            }
            self.gc_unreferenced_from(&recoverable);
        }
        Ok(())
    }

    /// Abort a prepared write only when this live call path knows publication
    /// has not happened. The old checkpoint and a reference to the still
    /// untouched stage are made durable before returning control; on failure,
    /// the Prepared intent and stage remain available for reopen.
    fn abort_unpublished_write(&mut self, prior: &Checkpoints) -> Result<bool> {
        let pending_state = self.checkpoints.clone();
        let intent = pending_state
            .pending_write
            .as_ref()
            .context("Prepared write intent missing during abort")?;
        let cleanup_candidate = intent.candidate.clone();
        let cleanup_stage = intent.stage.clone();
        self.checkpoints = prior.clone();
        if let Some(stage) = cleanup_stage.as_ref() {
            let root = intent
                .candidate
                .root
                .clone()
                .unwrap_or_else(|| self.root.clone());
            if let Err(error) = self.record_orphan_stage(
                &root,
                &intent.candidate.path,
                stage,
                intent.candidate.after_image.image.len,
                &intent.before_binding,
            ) {
                self.checkpoints = pending_state;
                return Err(error);
            }
        }
        if let Err(error) = self.persist() {
            self.checkpoints = pending_state;
            return Err(error);
        }
        let stage_cleanup_durable = match cleanup_stage.as_ref() {
            Some(stage) => {
                let proof = crate::workspace_stage::PayloadProof {
                    sha256: cleanup_candidate.after_sha256.clone(),
                    len: cleanup_candidate.after_image.image.len,
                    mode: cleanup_candidate.after_mode.unwrap_or(0o600),
                };
                matches!(
                    self.cleanup_committed_stage(&cleanup_candidate, stage, Some(&proof)),
                    Ok(true)
                )
            }
            None => true,
        };
        self.gc_unreferenced_from(&pending_state);
        Ok(stage_cleanup_durable)
    }

    fn reconcile_pending_undo(&mut self) -> Result<()> {
        let Some(mut intent) = self.checkpoints.pending_undo.clone() else {
            return Ok(());
        };
        ensure!(
            intent.turn < self.checkpoints.turns.len(),
            "WAL undo turn is out of range"
        );
        let turn = self.checkpoints.turns[intent.turn].clone();
        ensure!(
            intent.entries.len() == turn.entries.len(),
            "WAL undo entry count mismatch"
        );
        if !intent.prepared {
            // Before Prepared, all workspace entries must still be exact
            // postimages. Unknown stages are intentionally left as orphans.
            for change in &turn.entries {
                let dir = self.change_directory(change)?;
                let root = change.root.clone().unwrap_or_else(|| self.root.clone());
                let (parent, name, binding) = bound_parent_handle(&dir, &root, &change.path)?;
                let current = snapshot(&parent, Path::new(&name), MAX_FILE_BYTES)?;
                ensure!(
                    current.as_ref().is_some_and(|file| {
                        Some(crate::file_wal::Identity {
                            device: file.identity.device,
                            inode: file.identity.inode,
                        }) == change.after_identity
                            && sha256(&file.bytes) == change.after_sha256
                            && file.nlink == 1
                            && permission_mode(&file.permissions) == change.after_mode
                            && file.permissions.readonly() == change.readonly
                            && change.binding.as_ref().is_some_and(|saved| {
                                saved
                                    .iter()
                                    .map(|id| (id.device, id.inode))
                                    .eq(binding.iter().map(|id| (id.device, id.inode)))
                            })
                    }),
                    "WAL undo cannot abort: a target changed before Prepared"
                );
            }
            for (entry_index, progress) in intent.entries.iter().enumerate() {
                let Some(stage) = &progress.stage else {
                    continue;
                };
                let change = &turn.entries[entry_index];
                let root = change.root.clone().unwrap_or_else(|| self.root.clone());
                let image_len = change.before.as_ref().map_or(0, |image| image.image.len);
                self.record_orphan_stage(
                    &root,
                    &change.path,
                    stage,
                    image_len,
                    change.binding.as_deref().unwrap_or_default(),
                )?;
            }
            let recoverable = self.checkpoints.clone();
            self.checkpoints.pending_undo = None;
            if let Err(error) = self.persist() {
                self.checkpoints = recoverable;
                return Err(error);
            }
            return Ok(());
        }
        let mut discovered_progress = false;
        for (index, change) in turn.entries.iter().enumerate() {
            let dir = self.change_directory(change)?;
            let root = change.root.as_deref().unwrap_or(&self.root);
            let (parent, name, binding) = bound_parent_handle(&dir, root, &change.path)?;
            let current = snapshot(&parent, Path::new(&name), MAX_FILE_BYTES)?;
            let binding_matches = change.binding.as_ref().is_some_and(|saved| {
                saved
                    .iter()
                    .map(|id| (id.device, id.inode))
                    .eq(binding.iter().map(|id| (id.device, id.inode)))
            });
            if let Some(done) = &intent.entries[index].done {
                match done {
                    UndoDone::Deleted => ensure!(
                        current.is_none() && binding_matches,
                        "Completed undo delete conflicts with a new file"
                    ),
                    UndoDone::Restored(expected) => ensure!(
                        binding_matches
                            && current.as_ref().is_some_and(|file| {
                                file.identity.device == expected.device
                                    && file.identity.inode == expected.inode
                                    && file.nlink == 1
                                    && change.before.as_ref().is_some_and(|before| {
                                        file.bytes.len() == before.image.len
                                            && sha256(&file.bytes) == before.image.sha256
                                    })
                                    && permission_mode(&file.permissions) == change.mode
                                    && file.permissions.readonly() == change.readonly
                            }),
                        "Completed undo restore conflicts with a changed file"
                    ),
                }
                continue;
            }
            if current.is_none() && change.before.is_none() {
                parent.open(".")?.sync_all()?;
                intent.entries[index].done = Some(UndoDone::Deleted);
                discovered_progress = true;
                continue;
            }
            let Some(stage_identity) = intent.entries[index]
                .stage
                .as_ref()
                .and_then(|stage| stage.payload)
            else {
                continue;
            };
            let Some(current) = current else {
                continue;
            };
            if binding_matches
                && current.identity.device == stage_identity.device
                && current.identity.inode == stage_identity.inode
                && current.nlink == 1
                && change.before.as_ref().is_some_and(|before| {
                    current.bytes.len() == before.image.len
                        && sha256(&current.bytes) == before.image.sha256
                })
                && permission_mode(&current.permissions) == change.mode
                && current.permissions.readonly() == change.readonly
            {
                let stage_ref = intent.entries[index]
                    .stage
                    .as_ref()
                    .context("Restored stage reference missing")?;
                let stage_directory =
                    crate::workspace_stage::StageDirectory::open_checked(&parent, stage_ref)?;
                stage_directory.sync_after_publication(&parent)?;
                intent.entries[index].done = Some(UndoDone::Restored(stage_identity));
                discovered_progress = true;
                continue;
            }
        }
        if discovered_progress {
            self.checkpoints.pending_undo = Some(intent);
            self.persist()?;
        }
        Ok(())
    }

    fn resume_pending_undo(&mut self) -> Result<String> {
        let mut intent = self
            .checkpoints
            .pending_undo
            .clone()
            .context("Undo WAL intent missing")?;
        ensure!(
            intent.prepared,
            "Undo WAL staging is incomplete; reopen the session to classify the plan"
        );
        let index = intent.turn;
        let turn = self
            .checkpoints
            .turns
            .get(index)
            .context("Undo WAL turn missing")?
            .clone();
        ensure!(
            intent.entries.len() == turn.entries.len(),
            "Undo WAL entry count mismatch"
        );
        let mut batch = Vec::<Option<UndoPrepared>>::with_capacity(turn.entries.len());

        // Preflight the entire remaining group, including entries whose rename
        // may have completed just before a crash. No target changes happen in
        // this pass.
        for (entry_index, change) in turn.entries.iter().enumerate() {
            let dir = self.change_directory(change)?;
            let root = change.root.as_deref().unwrap_or(&self.root);
            // Completed deletes are absent and completed restores may have
            // changed ignore rules; identity checks below decide whether those
            // entries are already complete.
            let done = intent.entries[entry_index].done.is_some();
            let allow_missing = change.before.is_none()
                || matches!(
                    intent.entries[entry_index].done.as_ref(),
                    Some(UndoDone::Deleted)
                );
            let path = if done {
                change.path.clone()
            } else {
                Policy::new(&dir, root).check(
                    &change.path,
                    if allow_missing {
                        MissingPolicy::AllowMissingLeaf
                    } else {
                        MissingPolicy::Disallow
                    },
                )?
            };
            let (parent, name, binding) = bound_parent_handle(&dir, root, &path)?;
            let current = snapshot(&parent, Path::new(&name), MAX_FILE_BYTES)?;
            let saved_binding = change
                .binding
                .as_ref()
                .context("Checkpoint lacks directory identity")?;
            ensure!(
                saved_binding
                    .iter()
                    .map(|id| (id.device, id.inode))
                    .eq(binding.iter().map(|id| (id.device, id.inode))),
                "Undo path binding changed"
            );
            if let Some(done) = &intent.entries[entry_index].done {
                match done {
                    UndoDone::Deleted => ensure!(
                        current.is_none(),
                        "Completed undo delete conflicts with a new file"
                    ),
                    UndoDone::Restored(identity) => ensure!(
                        current.as_ref().is_some_and(|file| {
                            file.identity.device == identity.device
                                && file.identity.inode == identity.inode
                                && file.nlink == 1
                                && change.before.as_ref().is_some_and(|before| {
                                    file.bytes.len() == before.image.len
                                        && sha256(&file.bytes) == before.image.sha256
                                })
                                && permission_mode(&file.permissions) == change.mode
                                && file.permissions.readonly() == change.readonly
                        }),
                        "Completed undo restore conflicts with a changed file"
                    ),
                }
                batch.push(None);
                continue;
            }
            let progress = &intent.entries[entry_index];
            if current.is_none() && change.before.is_none() {
                parent.open(".")?.sync_all()?;
                intent.entries[entry_index].done = Some(UndoDone::Deleted);
                self.checkpoints.pending_undo = Some(intent.clone());
                self.persist()?;
                batch.push(None);
                continue;
            }
            if let (Some(stage_id), Some(current_file)) = (
                progress.stage.as_ref().and_then(|stage| stage.payload),
                current.as_ref(),
            ) && current_file.identity.device == stage_id.device
                && current_file.identity.inode == stage_id.inode
                && current_file.nlink == 1
                && change.before.as_ref().is_some_and(|before| {
                    current_file.bytes.len() == before.image.len
                        && sha256(&current_file.bytes) == before.image.sha256
                })
                && permission_mode(&current_file.permissions) == change.mode
                && current_file.permissions.readonly() == change.readonly
            {
                let stage_ref = progress
                    .stage
                    .as_ref()
                    .context("Restored stage reference missing")?;
                let stage_directory =
                    crate::workspace_stage::StageDirectory::open_checked(&parent, stage_ref)?;
                stage_directory.sync_after_publication(&parent)?;
                intent.entries[entry_index].done = Some(UndoDone::Restored(stage_id));
                self.checkpoints.pending_undo = Some(intent.clone());
                self.persist()?;
                batch.push(None);
                continue;
            }
            let current = current.context("Undo target is missing")?;
            ensure!(
                change
                    .after_identity
                    .is_some_and(|id| id.device == current.identity.device
                        && id.inode == current.identity.inode)
                    && sha256(&current.bytes) == change.after_sha256
                    && current.nlink == 1
                    && permission_mode(&current.permissions) == change.after_mode
                    && current.permissions.readonly() == change.readonly,
                "Conflict: undo target changed after intent"
            );
            if change.before.is_some() {
                let stage_ref = progress
                    .stage
                    .as_ref()
                    .context("Prepared restore stage reference is missing")?;
                let before = change.before.as_ref().context("Restore image missing")?;
                let stage =
                    crate::workspace_stage::StageDirectory::open_checked(&parent, stage_ref)?;
                stage.verify_payload(
                    &parent,
                    &crate::workspace_stage::PayloadProof {
                        sha256: before.image.sha256.clone(),
                        len: before.image.len,
                        mode: change.mode.unwrap_or(0o600),
                    },
                )?;
            }
            batch.push(Some(UndoPrepared {
                entry_index,
                #[cfg(unix)]
                binding,
                #[cfg(unix)]
                file_identity: current.identity,
            }));
            drop((parent, name));
        }

        #[cfg(all(test, unix))]
        if let Some(hook) = self.before_publication_hook.take() {
            hook();
        }

        for entry_index in intent.order.iter().copied() {
            let Some(item) = batch[entry_index].as_ref() else {
                continue;
            };
            #[cfg(all(test, unix))]
            let sequence = intent
                .order
                .iter()
                .position(|index| *index == entry_index)
                .unwrap();
            let change = &turn.entries[item.entry_index];
            let fresh = self.revalidate_undo(change, &item.binding, item.file_identity)?;
            let name = change
                .path
                .file_name()
                .context("Undo path has no file name")?
                .to_os_string();
            if let Some(before_image) = &change.before {
                let before = self
                    .blob_store
                    .read_image_checked(&before_image.image, before_image.identity)?;
                let progress = &intent.entries[entry_index];
                let stage_ref = progress
                    .stage
                    .as_ref()
                    .context("Prepared restore stage reference missing")?;
                let stage_identity = stage_ref
                    .payload
                    .context("Prepared payload identity missing")?;
                let stage =
                    crate::workspace_stage::StageDirectory::open_checked(&fresh, stage_ref)?;
                stage.verify_payload(
                    &fresh,
                    &crate::workspace_stage::PayloadProof {
                        sha256: before_image.image.sha256.clone(),
                        len: before_image.image.len,
                        mode: change.mode.unwrap_or(0o600),
                    },
                )?;
                stage.rename_payload_to(&fresh, &name)?;
                #[cfg(all(test, unix))]
                self.wal_fault(WalFaultPoint::WorkspaceMutation { index: sequence });
                let restored = snapshot(&fresh, Path::new(&name), MAX_FILE_BYTES)?
                    .context("Restored file disappeared before progress commit")?;
                ensure!(
                    restored.identity.device == stage_identity.device
                        && restored.identity.inode == stage_identity.inode
                        && restored.nlink == 1
                        && restored.bytes == before
                        && permission_mode(&restored.permissions) == change.mode
                        && restored.permissions.readonly() == change.readonly,
                    "Restored file changed before progress commit"
                );
                stage
                    .sync_after_publication(&fresh)
                    .map_err(|error| CheckpointFailure(format!("Undo namespace sync: {error}")))?;
                #[cfg(all(test, unix))]
                self.wal_fault(WalFaultPoint::NamespaceSynced { index: sequence });
                intent.entries[entry_index].done = Some(UndoDone::Restored(stage_identity));
            } else {
                fresh.remove_file(&name)?;
                #[cfg(all(test, unix))]
                self.wal_fault(WalFaultPoint::WorkspaceMutation { index: sequence });
                fresh.open(".")?.sync_all().map_err(|error| {
                    CheckpointFailure(format!("Undo delete namespace sync: {error}"))
                })?;
                #[cfg(all(test, unix))]
                self.wal_fault(WalFaultPoint::NamespaceSynced { index: sequence });
                intent.entries[entry_index].done = Some(UndoDone::Deleted);
            }
            self.checkpoints.pending_undo = Some(intent.clone());
            self.persist().map_err(|error| {
                CheckpointFailure(format!(
                    "Undo progress persistence failed after namespace sync: {error:#}"
                ))
            })?;
            #[cfg(all(test, unix))]
            self.wal_fault(WalFaultPoint::ProgressPersisted { index: sequence });
        }

        // LIFO: the file restored by this turn is now the exact after-image
        // expected by the nearest earlier change for the same path.
        for (entry_index, change) in turn.entries.iter().enumerate() {
            let Some(UndoDone::Restored(identity)) = intent.entries[entry_index].done else {
                continue;
            };
            let restored = change.before.as_ref().context("Restored image missing")?;
            let full = change
                .root
                .as_deref()
                .unwrap_or(&self.root)
                .join(&change.path);
            for previous_turn in self.checkpoints.turns[..index].iter_mut().rev() {
                if let Some(previous) = previous_turn.entries.iter_mut().find(|entry| {
                    entry
                        .root
                        .as_deref()
                        .unwrap_or(&self.root)
                        .join(&entry.path)
                        == full
                }) {
                    if previous.after_sha256 == restored.image.sha256
                        && previous.after_mode == change.mode
                    {
                        previous.after_identity = Some(identity);
                        let expected_len = 1 + parent_normal_component_count(&previous.path);
                        if let Some(new_binding) = &change.binding {
                            let (updated_binding, shared_start) = if new_binding.len()
                                >= expected_len
                            {
                                (
                                    Some(new_binding[new_binding.len() - expected_len..].to_vec()),
                                    0,
                                )
                            } else if let Some(prev_binding) = previous.binding.as_ref()
                                && prev_binding.len() == expected_len
                            {
                                let prefix_len = expected_len - new_binding.len();
                                let mut merged = prev_binding.clone();
                                merged[prefix_len..].copy_from_slice(new_binding);
                                (Some(merged), prefix_len)
                            } else {
                                (None, 0)
                            };
                            if let Some(updated) = updated_binding {
                                let same_dirs = previous.binding.as_ref().is_some_and(|old| {
                                    old.len() == expected_len
                                        && old[shared_start..] == updated[shared_start..]
                                });
                                if !same_dirs {
                                    previous.created_parents = 0;
                                }
                                previous.binding = Some(updated);
                            }
                        }
                    }
                    break;
                }
            }
        }
        let count = turn.entries.len();
        for (entry_index, progress) in intent.entries.iter().enumerate() {
            if !matches!(progress.done.as_ref(), Some(UndoDone::Restored(_))) {
                continue;
            }
            let Some(stage) = progress.stage.as_ref() else {
                continue;
            };
            let change = &turn.entries[entry_index];
            let root = change.root.clone().unwrap_or_else(|| self.root.clone());
            self.record_orphan_stage(
                &root,
                &change.path,
                stage,
                change.before.as_ref().map_or(0, |image| image.image.len),
                change.binding.as_deref().unwrap_or_default(),
            )?;
        }
        let recoverable = self.checkpoints.clone();
        self.checkpoints.turns.truncate(index);
        self.checkpoints.pending_undo = None;
        self.active_turn = None;
        #[cfg(all(test, unix))]
        self.wal_fault(WalFaultPoint::BeforeFinalPersist);
        if let Err(error) = self.persist() {
            self.checkpoints = recoverable;
            return Err(error);
        }
        for (entry_index, progress) in intent.entries.iter().enumerate() {
            if matches!(progress.done.as_ref(), Some(UndoDone::Restored(_)))
                && let Some(stage) = progress.stage.as_ref()
            {
                let _ = self.cleanup_committed_stage(&turn.entries[entry_index], stage, None);
            }
        }
        self.gc_unreferenced_from(&recoverable);
        #[cfg(unix)]
        self.cleanup_turn_created_dirs(&turn.entries);
        #[cfg(all(test, unix))]
        self.wal_fault(WalFaultPoint::Finalized);
        Ok(format!("Отменены файловые правки: {count}. {SHELL_NOTE}"))
    }

    #[cfg(unix)]
    fn cleanup_turn_created_dirs(&self, entries: &[Change]) {
        let mut by_key: BTreeMap<(PathBuf, PathBuf), Option<CreatedDirRecord>> = BTreeMap::new();
        for change in entries {
            if change.created_parents == 0 {
                continue;
            }
            let Some(saved_binding) = change.binding.as_ref() else {
                continue;
            };
            let parts = change
                .path
                .parent()
                .map(|p| {
                    p.components()
                        .filter_map(|c| match c {
                            Component::Normal(part) => Some(part),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if saved_binding.len() != 1 + parts.len() || change.created_parents > parts.len() {
                continue;
            }
            let full_binding = saved_binding
                .iter()
                .map(|id| FileIdentity {
                    device: id.device,
                    inode: id.inode,
                })
                .collect::<Vec<_>>();
            let entry_root = change.root.clone().unwrap_or_else(|| self.root.clone());
            let start_depth = parts.len() - change.created_parents + 1;
            for depth in start_depth..=parts.len() {
                let mut rel_dir = PathBuf::new();
                for part in &parts[..depth] {
                    rel_dir.push(part);
                }
                let record = CreatedDirRecord {
                    rel_dir: rel_dir.clone(),
                    parent_binding: full_binding[..depth].to_vec(),
                    identity: full_binding[depth],
                };
                match by_key.entry((entry_root.clone(), rel_dir)) {
                    std::collections::btree_map::Entry::Vacant(slot) => {
                        slot.insert(Some(record));
                    }
                    std::collections::btree_map::Entry::Occupied(mut slot) => {
                        if slot.get().as_ref() != Some(&record) {
                            slot.insert(None);
                        }
                    }
                }
            }
        }
        let mut ordered = by_key
            .into_iter()
            .filter_map(|((root, _), record)| record.map(|r| (root, r)))
            .collect::<Vec<_>>();
        ordered.sort_by(|left, right| {
            left.1
                .rel_dir
                .components()
                .count()
                .cmp(&right.1.rel_dir.components().count())
        });
        for (root, record) in ordered.into_iter().rev() {
            self.cleanup_created_dirs(&root, std::slice::from_ref(&record));
        }
    }

    fn ensure_turn(&mut self) -> Result<usize> {
        if self.active_turn.is_none() {
            self.begin_turn()?;
        }
        Ok(self.active_turn.unwrap())
    }

    #[cfg(unix)]
    fn allowed_snapshot(
        &self,
        path: &Path,
        allow_missing: bool,
    ) -> Result<Option<(Snapshot, PathBinding, PathBuf)>> {
        let (dir, root, path) = self.required_location(path, false)?;
        let (fresh_root, _) = checked_root(dir, root)?;
        let path = Policy::new(&fresh_root, root).check(
            &path,
            if allow_missing {
                MissingPolicy::AllowMissingLeaf
            } else {
                MissingPolicy::Disallow
            },
        )?;
        let (parent, name, binding) = bound_parent_handle(dir, root, &path)?;
        Ok(snapshot(&parent, Path::new(&name), MAX_FILE_BYTES)?
            .map(|file| (file, binding, root.join(path))))
    }

    #[cfg(not(unix))]
    fn allowed_snapshot(&self, path: &Path, allow_missing: bool) -> Result<Option<Snapshot>> {
        let (dir, root, path) = self.required_location(path, false)?;
        let path = Policy::new(dir, root).check(
            &path,
            if allow_missing {
                MissingPolicy::AllowMissingLeaf
            } else {
                MissingPolicy::Disallow
            },
        )?;
        let (parent, name) = parent_handle(dir, &path)?;
        snapshot(&parent, Path::new(&name), MAX_FILE_BYTES)
    }

    fn read_file(
        &mut self,
        args: &Value,
        cancel: &CancellationToken,
        actor: Option<&str>,
    ) -> Result<ToolOutcome> {
        let path = Path::new(string_arg(args, "path")?);
        #[cfg(unix)]
        let (file, binding, snapshot_key) = self
            .allowed_snapshot(path, false)?
            .context("Файл не найден")?;
        #[cfg(not(unix))]
        let file = self
            .allowed_snapshot(path, false)?
            .context("Файл не найден")?;
        let text = std::str::from_utf8(&file.bytes)
            .context("Файл не является UTF-8; бинарные файлы недоступны")?;
        let start = usize_arg(args, "start_line", 1, 1, usize::MAX)?;
        let max_lines = usize_arg(args, "max_lines", 200, 1, 500)?;
        let total_lines = text.lines().count();
        let mut content = String::new();
        let mut count = 0;
        for (i, line) in text
            .lines()
            .enumerate()
            .skip(start.saturating_sub(1))
            .take(max_lines)
        {
            check_cancel(cancel)?;
            let numbered = format!("{}\t{}\n", i + 1, line);
            if content.len() + numbered.len() > MAX_OUTPUT_BYTES / 2 {
                ensure!(
                    count > 0,
                    "Строка слишком длинная для read_file; используйте search"
                );
                break;
            }
            content.push_str(&numbered);
            count += 1;
        }
        let next = if count > 0 && start.saturating_add(count) <= total_lines {
            Some(start + count)
        } else {
            None
        };
        check_cancel(cancel)?;
        let hash = sha256(&file.bytes);
        let outcome = ToolOutcome::success(json!({"path":path,"sha256":hash,"start_line":start,"total_lines":total_lines,"next_line":next,"ends_with_newline":text.ends_with('\n'),"content":content}).to_string());
        #[cfg(unix)]
        {
            self.read_snapshots.insert(
                (actor.map(str::to_owned), snapshot_key),
                ReadObservation {
                    sha256: hash,
                    stale: false,
                    identity: file.identity,
                    binding,
                },
            );
        }
        #[cfg(not(unix))]
        {
            let (_, root, relative) = self.required_location(path, false)?;
            self.read_snapshots.insert(
                (actor.map(str::to_owned), root.join(relative)),
                ReadObservation {
                    sha256: hash,
                    stale: false,
                },
            );
        }
        Ok(outcome)
    }

    async fn list_files(&self, args: &Value, cancel: &CancellationToken) -> Result<ToolOutcome> {
        let max = usize_arg(args, "max_results", 200, 1, MAX_RESULTS)?;
        let offset = usize_arg(args, "offset", 0, 0, MAX_ENTRIES)?;
        let (files, scan_limited) = self.files(args, cancel).await?;
        let mut output = Vec::new();
        let mut size = 0;
        for file in files.iter().skip(offset).take(max) {
            size += file.as_os_str().len();
            if size > MAX_OUTPUT_BYTES / 4 {
                break;
            }
            output.push(file);
        }
        let next = offset.saturating_add(output.len());
        let truncated = next < files.len() || scan_limited;
        Ok(ToolOutcome::success(json!({"files":output,"truncated":truncated,"next_offset":if next < files.len() {Some(next)} else {None},"scan_limited":scan_limited}).to_string()))
    }

    async fn search(&self, args: &Value, cancel: &CancellationToken) -> Result<ToolOutcome> {
        let pattern = string_arg(args, "pattern")?;
        ensure!(pattern.len() <= 4096, "Regex превышает лимит 4096 байт");
        let case_sensitive = bool_arg(args, "case_sensitive", true)?;
        let regex = RegexBuilder::new(pattern)
            .case_insensitive(!case_sensitive)
            .size_limit(1024 * 1024)
            .dfa_size_limit(2 * 1024 * 1024)
            .build()
            .context("Некорректный regex")?;
        let max_results = usize_arg(args, "max_results", 200, 1, MAX_RESULTS)?;
        let (files, mut truncated) = self.files(args, cancel).await?;
        let mut matches = Vec::new();
        let mut scanned_bytes = 0;
        let mut scanned_files = 0;
        let mut output_bytes = 0;
        for path in files {
            tokio::task::yield_now().await;
            check_cancel(cancel)?;
            if scanned_files >= MAX_SCAN_FILES || scanned_bytes >= MAX_SCAN_BYTES {
                truncated = true;
                break;
            }
            scanned_files += 1;
            let (parent, name) = match self
                .required_location(&path, false)
                .and_then(|(dir, _, path)| parent_handle(dir, &path))
            {
                Ok(x) => x,
                Err(_) => continue,
            };
            // Check the size before opening and bound the read as well, so a
            // concurrently growing file cannot bypass either byte budget.
            let metadata = match parent.symlink_metadata(&name) {
                Ok(m) if m.is_file() && !m.file_type().is_symlink() => m,
                _ => continue,
            };
            if metadata.len() > MAX_FILE_BYTES as u64 {
                continue;
            }
            let remaining = MAX_SCAN_BYTES - scanned_bytes;
            if metadata.len() > remaining as u64 {
                truncated = true;
                break;
            }
            let file = match snapshot(&parent, Path::new(&name), MAX_FILE_BYTES.min(remaining)) {
                Ok(Some(f)) => f,
                _ => continue,
            };
            scanned_bytes += file.bytes.len();
            if file.bytes.contains(&0) {
                continue;
            }
            let text = match std::str::from_utf8(&file.bytes) {
                Ok(t) => t,
                Err(_) => continue,
            };
            for (i, line) in text.lines().enumerate() {
                if i % 128 == 0 {
                    tokio::task::yield_now().await;
                }
                check_cancel(cancel)?;
                if !regex.is_match(line) {
                    continue;
                }
                let row = json!({"path":path,"line":i + 1,"text":bounded(line, 2000)});
                let size = row.to_string().len();
                if matches.len() == max_results || output_bytes + size > MAX_OUTPUT_BYTES / 2 {
                    truncated = true;
                    break;
                }
                output_bytes += size;
                matches.push(row);
            }
            if truncated
                && (matches.len() >= max_results || output_bytes > MAX_OUTPUT_BYTES / 2 - 2500)
            {
                break;
            }
        }
        Ok(ToolOutcome::success(json!({"matches":matches,"truncated":truncated,"scanned_files":scanned_files,"scanned_bytes":scanned_bytes}).to_string()))
    }

    async fn files(
        &self,
        args: &Value,
        cancel: &CancellationToken,
    ) -> Result<(Vec<PathBuf>, bool)> {
        let path = args
            .get("path")
            .map_or(Ok("."), |v| v.as_str().context("path должен быть строкой"))?;
        let (dir, root, path) = self.required_location(Path::new(path), true)?;
        let external_root = (root != self.root).then_some(root);
        let mut policy = Policy::new(dir, root);
        policy.check(&path, MissingPolicy::Disallow)?;
        if dir.symlink_metadata(&path)?.is_file() {
            return Ok((vec![display_path(external_root, &path)], false));
        }
        let mut stack = vec![path];
        let mut files = vec![];
        let mut seen = 0;
        let mut limited = false;
        while let Some(path) = stack.pop() {
            tokio::task::yield_now().await;
            check_cancel(cancel)?;
            let directory = open_directory(dir, &path)?;
            let mut entries = Vec::new();
            for entry in directory.entries()? {
                if seen % 32 == 0 {
                    tokio::task::yield_now().await;
                }
                check_cancel(cancel)?;
                seen += 1;
                if seen > MAX_ENTRIES {
                    limited = true;
                    break;
                }
                let entry = entry?;
                let child = path.join(entry.file_name());
                let Ok(child) = normalized_path(&child, false) else {
                    continue;
                };
                if policy.check(&child, MissingPolicy::Disallow).is_err() {
                    continue;
                }
                let file_type = entry.file_type()?;
                if file_type.is_symlink() {
                    continue;
                }
                if file_type.is_file() {
                    files.push(child);
                } else if file_type.is_dir() && child.components().count() < 64 {
                    entries.push(child);
                }
            }
            entries.sort();
            stack.extend(entries.into_iter().rev());
            if limited || files.len() >= MAX_SCAN_FILES {
                limited = true;
                break;
            }
        }
        files.sort();
        files.truncate(MAX_SCAN_FILES);
        Ok((
            files
                .into_iter()
                .map(|p| display_path(external_root, &p))
                .collect(),
            limited,
        ))
    }

    fn prepare(&self, name: &str, args: &Value, actor: Option<&str>) -> Result<Prepared> {
        let (dir, root, path) =
            self.required_location(Path::new(string_arg(args, "path")?), false)?;
        let policy_mode = if name == "write_file" {
            MissingPolicy::AllowMissingSubtree
        } else {
            MissingPolicy::Disallow
        };
        #[cfg(unix)]
        let (policy_root, _) = checked_root(dir, root)?;
        #[cfg(unix)]
        let path = Policy::new(&policy_root, root).check(&path, policy_mode)?;
        #[cfg(not(unix))]
        let path = Policy::new(dir, root).check(&path, policy_mode)?;
        #[cfg(unix)]
        let (parent, file_name, binding, missing_dirs) = if name == "write_file" {
            bound_write_parent_handle(dir, root, &path)?
        } else {
            let (parent, file_name, binding) = bound_parent_handle(dir, root, &path)?;
            (parent, file_name, binding, Vec::new())
        };
        #[cfg(not(unix))]
        let (parent, file_name, missing_dirs) = if name == "write_file" {
            write_parent_handle(dir, &path)?
        } else {
            let (parent, file_name) = parent_handle(dir, &path)?;
            (parent, file_name, Vec::new())
        };
        let before = if missing_dirs.is_empty() {
            snapshot(&parent, Path::new(&file_name), MAX_FILE_BYTES)?
        } else {
            None
        };
        if let Some(file) = &before {
            std::str::from_utf8(&file.bytes)
                .context("Редактирование бинарного или не UTF-8 файла запрещено")?;
        }
        let after = match name {
            "write_file" => {
                let content = string_arg(args, "content")?;
                let observation = self
                    .read_snapshots
                    .get(&(actor.map(str::to_owned), root.join(&path)));
                if observation.is_some() {
                    ensure!(
                        before.is_some(),
                        "Файл удалён после чтения; перечитайте путь перед записью"
                    );
                }
                let expected = match args.get("expected_sha256") {
                    None | Some(Value::Null) if before.is_some() => {
                        observation.map(|value| value.sha256.as_str())
                    }
                    None | Some(Value::Null) => None,
                    Some(Value::String(s)) => Some(s.as_str()),
                    _ => bail!("expected_sha256 должен быть строкой"),
                };
                let actual_sha256 = before.as_ref().map(|file| sha256(&file.bytes));
                if let (Some(observation), Some(file), Some(actual)) =
                    (observation, before.as_ref(), actual_sha256.as_deref())
                {
                    #[cfg(unix)]
                    ensure!(
                        !observation.stale
                            && observation.identity == file.identity
                            && observation.binding == binding,
                        "Файл или каталог был заменён после чтения; перечитайте файл"
                    );
                    #[cfg(not(unix))]
                    {
                        let _ = file;
                        ensure!(
                            !observation.stale,
                            "Файл изменён после чтения; перечитайте файл"
                        );
                    }
                    ensure!(
                        observation.sha256 == actual,
                        "Файл не прочитан в этом контексте или изменён после чтения, либо expected_sha256 неверен. Перечитайте файл через read_file и подготовьте правку по актуальному содержимому; не повторяйте прежнюю запись без проверки"
                    );
                }
                match actual_sha256.as_deref() {
                    Some(actual) => ensure!(
                        expected == Some(actual),
                        "Файл не прочитан в этом контексте или изменён после чтения, либо expected_sha256 неверен. Перечитайте файл через read_file и подготовьте правку по актуальному содержимому; не повторяйте прежнюю запись без проверки"
                    ),
                    None => ensure!(
                        expected.is_none(),
                        "Файл отсутствует, но указан expected_sha256"
                    ),
                }
                content.as_bytes().to_vec()
            }
            "edit_file" => {
                let file = before.as_ref().context("Файл для edit_file не найден")?;
                let text = std::str::from_utf8(&file.bytes)?;
                let old = string_arg(args, "old_text")?;
                let new = string_arg(args, "new_text")?;
                let all = bool_arg(args, "replace_all", false)?;
                crate::text_edit::apply_edit_text(text, old, new, all, MAX_FILE_BYTES)?
            }
            _ => bail!("Неизвестная файловая операция"),
        };
        ensure!(after.len() <= MAX_FILE_BYTES, "Файл превышает лимит 1 MiB");
        Ok(Prepared {
            root: (root != self.root).then(|| root.to_path_buf()),
            path,
            parent,
            name: file_name,
            before,
            after,
            #[cfg(unix)]
            binding,
            missing_dirs,
        })
    }

    #[cfg(unix)]
    fn revalidate_prepared(&self, prepared: &Prepared) -> Result<Dir> {
        let root_path = prepared.root.as_deref().unwrap_or(&self.root);
        let retained = if root_path == self.root {
            &self.dir
        } else {
            self.extra_dirs
                .get(root_path)
                .context("Разрешённый корень каталога заменён или отозван")?
        };
        let (fresh_root, _) = checked_root(retained, root_path)?;
        Policy::new(&fresh_root, root_path).check(
            &prepared.path,
            if prepared.before.is_none() {
                MissingPolicy::AllowMissingLeaf
            } else {
                MissingPolicy::Disallow
            },
        )?;
        let (parent, name, binding) = bound_parent_handle(retained, root_path, &prepared.path)?;
        ensure!(
            binding == prepared.binding,
            "Каталог в пути был заменён перед записью"
        );
        let current = snapshot(&parent, Path::new(&name), MAX_FILE_BYTES)?;
        match (&prepared.before, &current) {
            (Some(before), Some(current)) => {
                ensure!(
                    current.identity == before.identity
                        && current.bytes == before.bytes
                        && current.nlink == 1
                        && permission_mode(&current.permissions)
                            == permission_mode(&before.permissions)
                        && current.permissions.readonly() == before.permissions.readonly(),
                    "Файл изменился перед публикацией"
                );
            }
            (None, None) => {}
            _ => bail!("Наличие файла изменилось перед публикацией"),
        }
        Ok(parent)
    }

    #[cfg(unix)]
    fn revalidate_undo(
        &self,
        change: &Change,
        binding: &PathBinding,
        file_identity: FileIdentity,
    ) -> Result<Dir> {
        let root_path = change.root.as_deref().unwrap_or(&self.root);
        let retained = self.change_directory(change)?;
        let path =
            Policy::new(&retained, root_path).check(&change.path, MissingPolicy::Disallow)?;
        let (parent, name, current_binding) = bound_parent_handle(&retained, root_path, &path)?;
        ensure!(
            current_binding == *binding,
            "Каталог в пути изменился во время undo"
        );
        let current = snapshot(&parent, Path::new(&name), MAX_FILE_BYTES)?
            .context("Конфликт undo: файл удалён во время отмены")?;
        ensure!(
            current.identity == file_identity
                && current.nlink == 1
                && sha256(&current.bytes) == change.after_sha256
                && permission_mode(&current.permissions) == change.after_mode
                && current.permissions.readonly() == change.readonly,
            "Конфликт undo: файл изменён непосредственно перед отменой"
        );
        Ok(parent)
    }

    fn ensure_manifest_headroom(
        &self,
        prepared: &Prepared,
        turn_index: usize,
        existing: Option<&Change>,
    ) -> Result<()> {
        let parent_depth = parent_normal_component_count(&prepared.path);
        let max_id = crate::file_wal::Identity {
            device: u64::MAX,
            inode: u64::MAX,
        };
        let max_binding = vec![max_id; 1 + parent_depth];
        let max_stored = StoredImage {
            image: crate::file_wal::ImageRef {
                id: "ffffffff-ffff-4fff-bfff-ffffffffffff".to_owned(),
                sha256: "f".repeat(64),
                len: MAX_FILE_BYTES,
            },
            identity: max_id,
        };
        let max_stage = crate::workspace_stage::StageRef {
            name: crate::workspace_stage::StageDirectory::plan_name(),
            directory: Some(max_id),
            guard: Some(max_id),
            payload: Some(max_id),
        };
        let max_candidate = Change {
            root: prepared.root.clone(),
            path: prepared.path.clone(),
            before: existing
                .and_then(|c| c.before.clone())
                .or_else(|| prepared.before.as_ref().map(|_| max_stored.clone())),
            mode: Some(0o7777),
            readonly: false,
            after_sha256: "f".repeat(64),
            after_image: max_stored.clone(),
            after_mode: Some(0o7777),
            after_identity: Some(max_id),
            binding: Some(max_binding.clone()),
            created_parents: existing.map_or(prepared.missing_dirs.len(), |c| c.created_parents),
        };

        let mut prepared_state = self.checkpoints.clone();
        prepared_state.pending_write = Some(WriteIntent {
            turn: turn_index,
            candidate: max_candidate.clone(),
            before_image: Some(max_stored.clone()),
            before_sha256: Some("f".repeat(64)),
            before_identity: Some(max_id),
            before_mode: Some(0o7777),
            before_readonly: false,
            before_binding: max_binding.clone(),
            stage: Some(max_stage.clone()),
        });
        ensure!(
            serde_json::to_vec(&prepared_state)?.len() <= crate::file_wal::MAX_MANIFEST_BYTES,
            "Превышен лимит WAL manifest (4 MiB)"
        );

        let mut committed_state = self.checkpoints.clone();
        let primary_root = self.root.clone();
        let full_target = prepared
            .root
            .as_deref()
            .unwrap_or(&primary_root)
            .join(&prepared.path);
        if let Some(slot) = committed_state.turns[turn_index]
            .entries
            .iter_mut()
            .find(|c| c.root.as_deref().unwrap_or(&primary_root).join(&c.path) == full_target)
        {
            *slot = max_candidate;
        } else {
            committed_state.turns[turn_index]
                .entries
                .push(max_candidate);
        }
        let orphan_root = prepared.root.clone().unwrap_or(primary_root);
        let orphan_parent =
            normalized_path(prepared.path.parent().unwrap_or(Path::new(".")), true)?;
        committed_state.orphan_stages.push(OrphanStage {
            root: orphan_root,
            parent: orphan_parent,
            stage: max_stage.clone(),
            bytes: u64::MAX,
            binding: max_binding,
        });
        let entries_len = committed_state.turns[turn_index].entries.len();
        committed_state.pending_undo = Some(UndoIntent {
            turn: turn_index,
            order: (0..entries_len).collect(),
            prepared: true,
            entries: vec![
                UndoProgress {
                    stage: Some(max_stage),
                    done: Some(UndoDone::Restored(max_id)),
                };
                entries_len
            ],
        });
        ensure!(
            serde_json::to_vec(&committed_state)?.len() <= crate::file_wal::MAX_MANIFEST_BYTES,
            "Превышен лимит WAL manifest (4 MiB)"
        );
        Ok(())
    }

    #[cfg(unix)]
    fn materialize_missing_dirs(&self, prepared: &mut Prepared) -> Result<Vec<CreatedDirRecord>> {
        use cap_std::fs::{DirBuilder, DirBuilderExt, MetadataExt as CapUnixMetadataExt};
        if prepared.missing_dirs.is_empty() {
            return Ok(Vec::new());
        }
        let root_path = prepared.root.as_deref().unwrap_or(&self.root);
        let retained = if root_path == self.root {
            &self.dir
        } else {
            self.extra_dirs
                .get(root_path)
                .context("Разрешённый корень каталога заменён или отозван")?
        };
        let (fresh_root, root_identity) = checked_root(retained, root_path)?;
        Policy::new(&fresh_root, root_path)
            .check(&prepared.path, MissingPolicy::AllowMissingSubtree)?;

        let all_parts = prepared
            .path
            .parent()
            .map(|parent| {
                parent
                    .components()
                    .filter_map(|c| match c {
                        Component::Normal(part) => Some(part.to_os_string()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        ensure!(
            prepared.missing_dirs.len() <= all_parts.len(),
            "Некорректный суффикс создаваемых каталогов"
        );
        let existing_len = all_parts.len() - prepared.missing_dirs.len();
        ensure!(
            all_parts[existing_len..] == prepared.missing_dirs[..],
            "Суффикс создаваемых каталогов не совпадает с путём"
        );
        let mut current = fresh_root;
        let mut current_binding = vec![root_identity];
        let mut rel_prefix = PathBuf::new();
        for part in &all_parts[..existing_len] {
            current = open_child_directory(&current, part)?;
            current_binding.push(directory_identity(&current)?);
            rel_prefix.push(part);
        }
        ensure!(
            current_binding == prepared.binding,
            "Каталог в пути был заменён перед записью"
        );
        match current.symlink_metadata(&prepared.missing_dirs[0]) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) => bail!("Каталог в пути появился перед записью"),
            Err(error) => return Err(error.into()),
        }

        let mut created = Vec::with_capacity(prepared.missing_dirs.len());
        for part in &prepared.missing_dirs {
            let mut builder = DirBuilder::new();
            builder.mode(0o777);
            let step = (|| -> Result<(Dir, FileIdentity)> {
                current.create_dir_with(part, &builder)?;
                {
                    let handle = current.open(".")?;
                    handle.sync_all()?;
                }
                let child = open_child_directory(&current, part)?;
                let named = current.symlink_metadata(part)?;
                ensure!(
                    named.is_dir() && !named.file_type().is_symlink(),
                    "Созданный компонент пути не является обычным каталогом"
                );
                let child_id = directory_identity(&child)?;
                ensure!(
                    (FileIdentity {
                        device: named.dev(),
                        inode: named.ino(),
                    }) == child_id,
                    "Созданный каталог изменился во время открытия"
                );
                Ok((child, child_id))
            })();
            match step {
                Ok((child, child_id)) => {
                    rel_prefix.push(part);
                    created.push(CreatedDirRecord {
                        rel_dir: rel_prefix.clone(),
                        parent_binding: current_binding.clone(),
                        identity: child_id,
                    });
                    current_binding.push(child_id);
                    current = child;
                }
                Err(error) => {
                    self.cleanup_created_dirs(root_path, &created);
                    return Err(error);
                }
            }
        }
        prepared.parent = current;
        prepared.binding = current_binding;
        prepared.missing_dirs.clear();
        Ok(created)
    }

    fn write(
        &mut self,
        name: &str,
        args: &Value,
        cancel: &CancellationToken,
        actor: Option<&str>,
        approved: Option<&ApprovedWrite>,
    ) -> Result<ToolOutcome> {
        self.ensure_wal_healthy()?;
        ensure!(
            self.checkpoints.pending_write.is_none(),
            "Незавершённая WAL-запись блокирует новые изменения"
        );
        ensure!(
            self.checkpoints.pending_undo.is_none(),
            "Незавершённая WAL-группа отмены блокирует новые изменения"
        );
        let mut prepared = self.prepare(name, args, actor)?;
        if let Some(expected) = approved {
            ensure!(
                prepared.approval_stamp() == *expected,
                "Файл изменился после подготовки diff; перечитайте файл через read_file и повторите правку"
            );
        }
        ensure!(
            self.checkpoints.orphan_stages.len()
                < MAX_ORPHAN_STAGES.saturating_sub(MAX_CHECKPOINT_ENTRIES),
            "WAL orphan budget reserves the remaining capacity for undo"
        );
        ensure!(
            self.checkpoints
                .orphan_stages
                .len()
                .saturating_add(1)
                .saturating_mul(3)
                <= crate::file_wal::MAX_STORE_ENTRIES,
            "WAL orphan budget reserves the remaining capacity for undo"
        );
        check_cancel(cancel)?;
        let current_hash = prepared.before.as_ref().map(|s| sha256(&s.bytes));
        let primary_root = self.root.clone();
        let absolute = prepared
            .root
            .as_deref()
            .unwrap_or(&primary_root)
            .join(&prepared.path);
        let snapshot_key = (actor.map(str::to_owned), absolute.clone());
        let had_matching_observation = match (
            &prepared.before,
            &current_hash,
            self.read_snapshots.get(&snapshot_key),
        ) {
            (Some(before), Some(hash), Some(observation)) => {
                #[cfg(unix)]
                {
                    !observation.stale
                        && observation.sha256 == *hash
                        && observation.identity == before.identity
                        && observation.binding == prepared.binding
                }
                #[cfg(not(unix))]
                {
                    let _ = before;
                    !observation.stale && observation.sha256 == *hash
                }
            }
            _ => false,
        };
        let record_observation =
            name == "write_file" || (name == "edit_file" && had_matching_observation);
        if let Some(before) = prepared
            .before
            .as_ref()
            .filter(|b| b.bytes == prepared.after)
        {
            #[cfg(unix)]
            if name == "write_file" && before.nlink == 1 {
                self.read_snapshots.insert(
                    snapshot_key,
                    ReadObservation {
                        sha256: current_hash.expect("before hash present"),
                        stale: false,
                        identity: before.identity,
                        binding: prepared.binding,
                    },
                );
            } else if name == "edit_file"
                && !had_matching_observation
                && let Some(observation) = self.read_snapshots.get_mut(&snapshot_key)
            {
                observation.stale = true;
            }
            #[cfg(not(unix))]
            if name == "write_file" {
                let _ = before;
                self.read_snapshots.insert(
                    snapshot_key,
                    ReadObservation {
                        sha256: current_hash.expect("before hash present"),
                        stale: false,
                    },
                );
            } else if name == "edit_file"
                && !had_matching_observation
                && let Some(observation) = self.read_snapshots.get_mut(&snapshot_key)
            {
                observation.stale = true;
            }
            return Ok(ToolOutcome::success(
                "Содержимое уже совпадает; файл не изменён",
            ));
        }
        #[cfg(unix)]
        ensure!(
            prepared
                .before
                .as_ref()
                .is_none_or(|before| before.nlink == 1),
            "Hard-linked files cannot be modified by file tools"
        );
        let turn_index = self.ensure_turn()?;
        let old_state = self.checkpoints.clone();
        let after_hash = sha256(&prepared.after);
        let existing = self.checkpoints.turns[turn_index]
            .entries
            .iter()
            .find(|c| c.root.as_deref().unwrap_or(&primary_root).join(&c.path) == absolute)
            .cloned();
        if let Some(change) = &existing {
            ensure!(
                current_hash.as_ref() == Some(&change.after_sha256),
                "Конфликт: файл изменён вне файловых инструментов в этом ходе; исходные пользовательские правки сохранены"
            );
            let before = prepared
                .before
                .as_ref()
                .context("Tracked file disappeared before write")?;
            ensure!(
                change
                    .after_identity
                    .is_some_and(|id| id.device == before.identity.device
                        && id.inode == before.identity.inode),
                "Conflict: tracked file identity changed outside file tools"
            );
            ensure!(
                change.after_mode == permission_mode(&before.permissions),
                "Conflict: tracked file mode changed outside file tools"
            );
            let saved_binding = change
                .binding
                .as_ref()
                .context("Tracked file has no path identity")?;
            ensure!(
                saved_binding
                    .iter()
                    .map(|id| (id.device, id.inode))
                    .eq(prepared.binding.iter().map(|id| (id.device, id.inode))),
                "Conflict: tracked parent directory identity changed"
            );
        }
        let total_entries = self
            .checkpoints
            .turns
            .iter()
            .map(|turn| turn.entries.len())
            .sum::<usize>();
        ensure!(
            existing.is_some()
                || total_entries < MAX_CHECKPOINT_ENTRIES
                    && self.checkpoints.turns[turn_index].entries.len() < MAX_CHECKPOINT_ENTRIES,
            "Лимит файловых WAL entries (1024)"
        );
        let orphan_bytes = self
            .checkpoints
            .orphan_stages
            .iter()
            .map(|orphan| orphan.bytes)
            .sum::<u64>();
        let pending_turn_before_bytes = self.checkpoints.turns[turn_index]
            .entries
            .iter()
            .filter_map(|change| change.before.as_ref())
            .map(|image| image.image.len as u64)
            .sum::<u64>()
            + if existing.is_none() {
                prepared
                    .before
                    .as_ref()
                    .map_or(0, |before| before.bytes.len() as u64)
            } else {
                0
            };
        let future_undo_stage_count = self.checkpoints.turns[turn_index]
            .entries
            .iter()
            .filter(|change| change.before.is_some())
            .count()
            .saturating_add(usize::from(existing.is_none() && prepared.before.is_some()));
        ensure!(
            self.checkpoints
                .orphan_stages
                .len()
                .saturating_add(future_undo_stage_count)
                .saturating_add(1)
                .saturating_mul(3)
                <= crate::file_wal::MAX_STORE_ENTRIES,
            "WAL stage namespace budget reserves capacity for the active undo group"
        );
        ensure!(
            orphan_bytes
                .saturating_add(pending_turn_before_bytes)
                .saturating_add(prepared.after.len() as u64)
                <= crate::file_wal::MAX_STORE_BYTES,
            "WAL orphan budget reserves space for undoing the active turn"
        );
        self.ensure_manifest_headroom(&prepared, turn_index, existing.as_ref())?;
        let before_snapshot = prepared.before.as_ref();
        let new_preimage_bytes = existing
            .is_none()
            .then(|| before_snapshot.map(|s| s.bytes.as_slice()))
            .flatten();
        let reserve_bytes = (prepared.after.len() as u64).saturating_mul(2)
            + new_preimage_bytes.map_or(0, |bytes| bytes.len() as u64)
            + pending_turn_before_bytes
            + orphan_bytes
            + (future_undo_stage_count as u64).saturating_mul(2)
            // The checkpoint is replaced repeatedly as the active group is
            // built and undone; reserve the full bounded manifest growth,
            // which can exceed the one-byte after-image near a full store.
            + crate::file_wal::MAX_MANIFEST_BYTES as u64
            + 2
            + 8 * 1024 * 1024;
        let reserve_entries = 1 + usize::from(new_preimage_bytes.is_some());
        // Keep two namespace slots available: one for an interrupted atomic
        // manifest temp and one for its metadata-only abort/recovery. Undo
        // must remain writable when unknown private-store entries consume
        // the rest of the quota.
        self.blob_store
            .reserve(reserve_bytes, reserve_entries.saturating_add(5))?;
        let (after_ref, after_identity) = self.blob_store.write_image(&prepared.after)?;
        let after_image = StoredImage {
            image: after_ref,
            identity: after_identity,
        };
        let before_image = if let Some(change) = &existing {
            Some(change.after_image.clone())
        } else if let Some(bytes) = new_preimage_bytes {
            let (image, identity) = self.blob_store.write_image(bytes)?;
            Some(StoredImage { image, identity })
        } else {
            None
        };
        #[cfg(unix)]
        let created_in_call = match self.materialize_missing_dirs(&mut prepared) {
            Ok(records) => records,
            Err(error) => {
                let _ = self
                    .blob_store
                    .remove_verified_image(&after_image.image, after_image.identity);
                if existing.is_none()
                    && let Some(stored) = &before_image
                {
                    let _ = self
                        .blob_store
                        .remove_verified_image(&stored.image, stored.identity);
                }
                return Err(error);
            }
        };
        #[cfg(unix)]
        let cleanup_root = prepared.root.clone().unwrap_or_else(|| self.root.clone());
        let mut candidate = if let Some(change) = existing {
            change
        } else {
            Change {
                root: prepared.root.clone(),
                path: prepared.path.clone(),
                before: before_image.clone(),
                mode: prepared
                    .before
                    .as_ref()
                    .and_then(|s| permission_mode(&s.permissions)),
                readonly: prepared
                    .before
                    .as_ref()
                    .is_some_and(|s| s.permissions.readonly()),
                after_sha256: after_hash.clone(),
                after_image: after_image.clone(),
                after_mode: None,
                after_identity: None,
                binding: None,
                #[cfg(unix)]
                created_parents: created_in_call.len(),
                #[cfg(not(unix))]
                created_parents: 0,
            }
        };
        candidate.after_sha256 = after_hash.clone();
        candidate.after_image = after_image.clone();
        candidate.after_mode = None;
        candidate.after_identity = None;
        candidate.binding = None;
        let before = prepared.before.as_ref();
        let pending = WriteIntent {
            turn: turn_index,
            candidate,
            before_image,
            before_sha256: before.map(|s| sha256(&s.bytes)),
            before_identity: before.map(|s| crate::file_wal::Identity {
                device: s.identity.device,
                inode: s.identity.inode,
            }),
            before_mode: before.and_then(|s| permission_mode(&s.permissions)),
            before_readonly: before.is_some_and(|s| s.permissions.readonly()),
            before_binding: prepared
                .binding
                .iter()
                .map(|id| crate::file_wal::Identity {
                    device: id.device,
                    inode: id.inode,
                })
                .collect(),
            stage: None,
        };
        self.checkpoints.pending_write = Some(pending);
        if let Err(error) = self.persist() {
            self.checkpoints = old_state;
            return Err(error);
        }
        #[cfg(all(test, unix))]
        self.wal_fault(WalFaultPoint::DurableIntent);
        let stage_name = crate::workspace_stage::StageDirectory::plan_name();
        self.checkpoints
            .pending_write
            .as_mut()
            .context("WAL write intent disappeared")?
            .stage = Some(crate::workspace_stage::StageRef {
            name: stage_name.clone(),
            directory: None,
            guard: None,
            payload: None,
        });
        self.persist()?;
        #[cfg(unix)]
        {
            let stage = match (|| -> Result<crate::workspace_stage::StageRef> {
                let mut stage = crate::workspace_stage::StageDirectory::create_empty(
                    &prepared.parent,
                    &stage_name,
                )?;
                #[cfg(all(test, unix))]
                self.wal_fault(WalFaultPoint::StageDirectoryCreated { index: 0 });
                stage.install_guard(&prepared.parent)?;
                #[cfg(all(test, unix))]
                self.wal_fault(WalFaultPoint::StageGuardDurable { index: 0 });
                let permissions = prepared
                    .before
                    .as_ref()
                    .map(|snapshot| snapshot.permissions.clone());
                stage.write_payload(&prepared.parent, &prepared.after, permissions.as_ref())?;
                #[cfg(all(test, unix))]
                self.wal_fault(WalFaultPoint::StagePayloadDurable { index: 0 });
                Ok(stage.reference())
            })() {
                Ok(stage) => stage,
                Err(error) => {
                    self.reconcile_pending_write()?;
                    if !created_in_call.is_empty() {
                        self.cleanup_created_dirs(&cleanup_root, &created_in_call);
                    }
                    return Err(error);
                }
            };
            #[cfg(all(test, unix))]
            self.wal_fault(WalFaultPoint::StageCreated { index: 0 });
            let stage_identity = stage.payload.context("Staged payload identity missing")?;
            {
                let intent = self
                    .checkpoints
                    .pending_write
                    .as_mut()
                    .context("WAL write intent disappeared")?;
                intent.stage = Some(stage.clone());
                intent.candidate.after_identity = Some(stage_identity);
                intent.candidate.after_mode = Some(
                    prepared
                        .before
                        .as_ref()
                        .and_then(|snapshot| permission_mode(&snapshot.permissions))
                        .unwrap_or(0o600),
                );
                intent.candidate.binding = Some(intent.before_binding.clone());
            }
            #[cfg(all(test, unix))]
            self.wal_fault(WalFaultPoint::BeforePreparedPersist);
            self.persist()
                .map_err(|error| CheckpointFailure(format!("WAL stage preparation: {error:#}")))?;
            #[cfg(all(test, unix))]
            self.wal_fault(WalFaultPoint::PreparedPersisted);
            #[cfg(all(test, unix))]
            if let Some(hook) = self.before_publication_hook.take() {
                hook();
            }
            if let Err(error) = check_cancel(cancel) {
                let stage_cleaned = self.abort_unpublished_write(&old_state)?;
                if stage_cleaned && !created_in_call.is_empty() {
                    self.cleanup_created_dirs(&cleanup_root, &created_in_call);
                }
                return Err(error);
            }
            let target = match self.revalidate_prepared(&prepared) {
                Ok(target) => target,
                Err(error) => {
                    let stage_cleaned = self.abort_unpublished_write(&old_state)?;
                    if stage_cleaned && !created_in_call.is_empty() {
                        self.cleanup_created_dirs(&cleanup_root, &created_in_call);
                    }
                    return Err(error);
                }
            };
            let prepared_candidate = &self
                .checkpoints
                .pending_write
                .as_ref()
                .context("WAL write intent disappeared")?
                .candidate;
            let candidate = prepared_candidate.clone();
            let stage_directory =
                crate::workspace_stage::StageDirectory::open_checked(&target, &stage)?;
            stage_directory.verify_payload(
                &target,
                &crate::workspace_stage::PayloadProof {
                    sha256: candidate.after_sha256.clone(),
                    len: candidate.after_image.image.len,
                    mode: candidate.after_mode.unwrap_or(0o600),
                },
            )?;
            stage_directory.rename_payload_to(&target, &prepared.name)?;
            #[cfg(all(test, unix))]
            self.wal_fault(WalFaultPoint::WorkspaceMutation { index: 0 });
            stage_directory
                .sync_after_publication(&target)
                .map_err(|error| {
                    CheckpointFailure(format!(
                        "Workspace namespace sync failed after publication: {error}"
                    ))
                })?;
            #[cfg(all(test, unix))]
            self.wal_fault(WalFaultPoint::NamespaceSynced { index: 0 });
            let published = snapshot(&target, Path::new(&prepared.name), MAX_FILE_BYTES)?
                .context("Published file disappeared before WAL commit")?;
            ensure!(
                published.identity.device == stage_identity.device
                    && published.identity.inode == stage_identity.inode
                    && published.nlink == 1
                    && published.bytes == prepared.after
                    && sha256(&published.bytes) == candidate.after_sha256
                    && published.bytes.len() == candidate.after_image.image.len
                    && permission_mode(&published.permissions) == candidate.after_mode
                    && published.permissions.readonly()
                        == prepared
                            .before
                            .as_ref()
                            .is_some_and(|s| s.permissions.readonly()),
                "Published file identity does not match prepared stage"
            );
            let published_identity = published.identity;
            drop(stage_directory);
            let recoverable = self.checkpoints.clone();
            let turn = self
                .checkpoints
                .turns
                .get_mut(turn_index)
                .context("WAL turn disappeared")?;
            if let Some(change) = turn.entries.iter_mut().find(|change| {
                change
                    .root
                    .as_deref()
                    .unwrap_or(&primary_root)
                    .join(&change.path)
                    == absolute
            }) {
                *change = candidate;
            } else {
                turn.entries.push(candidate);
            }
            let committed_change = turn
                .entries
                .iter()
                .find(|change| {
                    change
                        .root
                        .as_deref()
                        .unwrap_or(&primary_root)
                        .join(&change.path)
                        == absolute
                })
                .cloned()
                .context("Committed WAL change disappeared")?;
            let committed_root = committed_change
                .root
                .clone()
                .unwrap_or_else(|| self.root.clone());
            self.record_orphan_stage(
                &committed_root,
                &committed_change.path,
                &stage,
                prepared.after.len(),
                committed_change.binding.as_deref().unwrap_or_default(),
            )?;
            self.checkpoints.pending_write = None;
            #[cfg(all(test, unix))]
            self.wal_fault(WalFaultPoint::BeforeFinalPersist);
            if let Err(error) = self.persist() {
                self.checkpoints = recoverable;
                return Err(CheckpointFailure(format!(
                    "WAL finalize after workspace publication: {error:#}"
                ))
                .into());
            }
            let _ = self.cleanup_committed_stage(&committed_change, &stage, None);
            self.gc_unreferenced_from(&old_state);
            #[cfg(all(test, unix))]
            self.wal_fault(WalFaultPoint::ProgressPersisted { index: 0 });
            #[cfg(all(test, unix))]
            self.wal_fault(WalFaultPoint::Finalized);
            for (key, observation) in &mut self.read_snapshots {
                if key.1 == absolute {
                    observation.stale = true;
                }
            }
            if record_observation {
                self.read_snapshots.insert(
                    snapshot_key,
                    ReadObservation {
                        sha256: after_hash.clone(),
                        stale: false,
                        identity: published_identity,
                        binding: prepared.binding.clone(),
                    },
                );
            }
        }
        #[cfg(not(unix))]
        {
            let _ = record_observation;
            bail!("Filesystem WAL is unsupported on this platform");
        }
        let display_path = display_path(prepared.root.as_deref(), &prepared.path);
        Ok(ToolOutcome {
            is_error: false,
            content: json!({"path":display_path,"sha256":after_hash,"bytes":prepared.after.len()})
                .to_string(),
            changed_paths: vec![display_path.to_string_lossy().into_owned()],
            recorded_operation: None,
            recorded_output: None,
        })
    }

    pub(crate) fn mark_shell_used(&mut self) -> Result<()> {
        self.ensure_wal_healthy()?;
        ensure!(
            self.checkpoints.pending_write.is_none() && self.checkpoints.pending_undo.is_none(),
            "Незавершённая WAL-операция блокирует shell"
        );
        let turn = self.ensure_turn()?;
        self.checkpoints.turns[turn].shell_used = true;
        self.persist()
    }

    async fn run_command(
        &mut self,
        args: &Value,
        cancel: &CancellationToken,
    ) -> Result<ToolOutcome> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            crate::foreground::standalone(self, args, cancel).await
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let (command, timeout) = command_args(args)?;
            check_cancel(cancel)?;
            self.mark_shell_used()?;
            #[cfg(unix)]
            let mut process = {
                let mut c = tokio::process::Command::new("/bin/sh");
                c.arg("-c");
                c.process_group(0);
                c
            };
            #[cfg(windows)]
            let mut process = {
                let mut c = tokio::process::Command::new("cmd.exe");
                c.args(["/D", "/S", "/C"]);
                c
            };
            #[cfg(not(any(unix, windows)))]
            bail!("run_command не поддерживается на этой платформе");
            process
                .arg(command)
                .current_dir(&self.root)
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            for (key, value) in std::env::vars_os() {
                if allowed_env(&key.to_string_lossy()) {
                    process.env(key, value);
                }
            }
            process.env("PWD", &self.root);
            process.env("RCODE_MODEL_SHELL", "1");
            let mut child = process.spawn().context("Не удалось запустить shell")?;
            let mut group = ProcessGroup::new(child.id());
            let stdout = child.stdout.take().context("stdout pipe отсутствует")?;
            let stderr = child.stderr.take().context("stderr pipe отсутствует")?;
            let budget = Arc::new(AtomicUsize::new(0));
            let limit = CancellationToken::new();
            let streams = async {
                tokio::join!(
                    capture(stdout, budget.clone(), limit.clone()),
                    capture(stderr, budget.clone(), limit.clone())
                )
            };
            tokio::pin!(streams);
            let timer = tokio::time::sleep(Duration::from_secs(timeout as u64));
            tokio::pin!(timer);
            let mut output = None;
            let (mut status, reason) = loop {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => break (None, Some("cancelled")),
                    _ = &mut timer => break (None, Some("timeout")),
                    _ = limit.cancelled() => break (None, Some("output_limit")),
                    result = child.wait() => break (Some(result?), None),
                    result = &mut streams, if output.is_none() => { output = Some(result); }
                }
            };
            // Also terminate descendants retaining pipes after their shell exits.
            group.kill();
            if status.is_none() {
                let _ = child.start_kill();
                status = Some(child.wait().await?);
            }
            let output = match output {
                Some(output) => output,
                None => tokio::time::timeout(Duration::from_secs(1), &mut streams)
                    .await
                    .unwrap_or_else(|_| (Ok(Vec::new()), Ok(Vec::new()))),
            };
            let (stdout, stderr) = (output.0?, output.1?);
            let stdout_lossy = std::str::from_utf8(&stdout).is_err();
            let stderr_lossy = std::str::from_utf8(&stderr).is_err();
            let status = status.context("Статус процесса отсутствует")?;
            let reason = reason.or_else(|| {
                if budget.load(Ordering::Relaxed) > MAX_OUTPUT_BYTES {
                    Some("output_limit")
                } else {
                    None
                }
            });
            let output_truncated = reason == Some("output_limit");
            let content = json!({"exit_code":status.code(),"signal":exit_signal(&status),"stdout":String::from_utf8_lossy(&stdout),"stderr":String::from_utf8_lossy(&stderr),"reason":reason,"output_truncated":output_truncated,"stdout_lossy":stdout_lossy,"stderr_lossy":stderr_lossy,"shell_changes_managed":false,"note":SHELL_NOTE,"termination":if cfg!(unix) {"process_group"} else {"best_effort_child_only"}}).to_string();
            Ok(ToolOutcome {
                is_error: reason.is_some() || !status.success(),
                content,
                changed_paths: vec![],
                recorded_operation: None,
                recorded_output: None,
            })
        }
    }
}

fn file_tool(name: &str) -> bool {
    matches!(
        name,
        "read_file" | "write_file" | "edit_file" | "list_files" | "search"
    )
}

fn display_path(root: Option<&Path>, path: &Path) -> PathBuf {
    root.map_or_else(|| path.to_path_buf(), |r| r.join(path))
}

fn validate_absolute_path(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && path.to_str().is_some(),
        "Требуется абсолютный UTF-8 путь"
    );
    ensure!(
        !path.components().any(|c| matches!(c, Component::ParentDir))
            && !path.as_os_str().to_string_lossy().contains('\0'),
        "Путь с .. или NUL запрещён"
    );
    ensure!(
        path.components().count() <= 64 && path.as_os_str().len() <= 4096,
        "Слишком длинный путь"
    );
    Ok(())
}

// Canonicalize only prefixes that resolve to an already granted root. Child
// components stay lexical so ignore rules and symlink denial remain effective.
fn root_prefix<'a>(path: &'a Path, root: &Path) -> Option<&'a Path> {
    if path.starts_with(root) {
        return path.ancestors().find(|p| *p == root);
    }
    path.ancestors()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .find(|p| std::fs::canonicalize(p).is_ok_and(|canonical| canonical == root))
}

fn validate_external_root(root: &Path, checkpoint: &Path) -> Result<()> {
    validate_absolute_path(root)?;
    ensure!(
        root.components().any(|c| matches!(c, Component::Normal(_)))
            && !root.components().any(|c| secret_component(c.as_os_str())),
        "Доступ к секретным файлам и служебным каталогам запрещён"
    );
    ensure!(
        !checkpoint.starts_with(root) && !root.starts_with(checkpoint),
        "Дополнительный каталог не должен содержать checkpoint или находиться внутри него"
    );
    for service in [
        "/bin",
        "/sbin",
        "/usr",
        "/etc",
        "/dev",
        "/proc",
        "/sys",
        "/run",
        "/boot",
        "/System",
        "/Library",
        "/Applications",
        "/private/etc",
        "/var/run",
        "/private/var/run",
        "/var/log",
        "/private/var/log",
    ] {
        ensure!(
            !root.starts_with(service),
            "Системный или служебный каталог недоступен"
        );
    }
    for broad in [
        "/tmp",
        "/private/tmp",
        "/var",
        "/private/var",
        "/home",
        "/Users",
        "/private",
    ] {
        ensure!(
            root != Path::new(broad),
            "Выберите отдельный каталог проекта"
        );
    }
    Ok(())
}

fn safe_external_path(path: &Path, allow_missing_file: bool) -> Result<()> {
    validate_absolute_path(path)?;
    ensure!(
        !path.components().any(|c| secret_component(c.as_os_str())),
        "Доступ к секретным файлам и служебным каталогам запрещён"
    );
    let mut prefix = PathBuf::new();
    for component in path.components() {
        prefix.push(component.as_os_str());
        // A Windows prefix such as `C:` or `\\?\C:` is not the filesystem
        // root yet. Only inspect it after RootDir has made it a complete path.
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        match std::fs::symlink_metadata(&prefix) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    // macOS public temporary directory aliases are the only
                    // implicit symlink exceptions for a new grant.
                    let system_alias = cfg!(target_os = "macos")
                        && ["/tmp", "/var"].iter().any(|p| prefix == Path::new(p))
                        && std::fs::canonicalize(&prefix).is_ok_and(|p| {
                            p == Path::new("/private").join(prefix.strip_prefix("/").unwrap())
                        });
                    ensure!(system_alias, "Symlink недоступен файловым инструментам");
                }
            }
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    && allow_missing_file
                    && prefix == path => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn open_external_directory(root: &Path) -> Result<Dir> {
    let filesystem_root = root
        .ancestors()
        .last()
        .context("Некорректный корень каталога")?;
    let dir = Dir::open_ambient_dir(filesystem_root, cap_std::ambient_authority())?;
    open_directory(&dir, root.strip_prefix(filesystem_root)?)
}

#[cfg(unix)]
fn identity(metadata: &std::fs::Metadata) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(unix)]
fn directory_identity(dir: &Dir) -> Result<FileIdentity> {
    let handle = dir.open(".")?;
    let metadata = handle.into_std().metadata()?;
    ensure!(metadata.is_dir(), "Корень файлового инструмента изменён");
    Ok(identity(&metadata))
}

#[cfg(unix)]
fn checked_root(retained: &Dir, root: &Path) -> Result<(Dir, FileIdentity)> {
    let current =
        open_external_directory(root).context("Корень файлового инструмента недоступен")?;
    let expected = directory_identity(retained)?;
    let actual = directory_identity(&current)?;
    ensure!(actual == expected, "Корень файлового инструмента заменён");
    Ok((current, actual))
}

#[cfg(unix)]
fn bound_write_parent_handle(
    retained_root: &Dir,
    root_path: &Path,
    relative: &Path,
) -> Result<(Dir, OsString, PathBinding, Vec<OsString>)> {
    let (root, root_identity) = checked_root(retained_root, root_path)?;
    let name = relative
        .file_name()
        .context("Требуется путь к файлу")?
        .to_os_string();
    let parent_path = relative
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut parent = root;
    let mut binding = vec![root_identity];
    let mut missing_dirs = Vec::new();
    for component in parent_path.components() {
        let Component::Normal(part) = component else {
            if matches!(component, Component::CurDir) {
                continue;
            }
            bail!("Некорректный компонент пути")
        };
        if !missing_dirs.is_empty() {
            missing_dirs.push(part.to_os_string());
            continue;
        }
        match parent.symlink_metadata(part) {
            Ok(metadata) => {
                ensure!(
                    !metadata.file_type().is_symlink(),
                    "Symlink в пути запрещён"
                );
                ensure!(metadata.is_dir(), "Компонент пути не является каталогом");
                parent = open_child_directory(&parent, part)?;
                binding.push(directory_identity(&parent)?);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing_dirs.push(part.to_os_string());
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok((parent, name, binding, missing_dirs))
}

#[cfg(not(unix))]
fn write_parent_handle(root: &Dir, path: &Path) -> Result<(Dir, OsString, Vec<OsString>)> {
    let name = path
        .file_name()
        .context("Требуется путь к файлу")?
        .to_os_string();
    let parent_path = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut parent = root.try_clone()?;
    let mut missing_dirs = Vec::new();
    for component in parent_path.components() {
        let Component::Normal(part) = component else {
            if matches!(component, Component::CurDir) {
                continue;
            }
            bail!("Некорректный компонент пути")
        };
        if !missing_dirs.is_empty() {
            missing_dirs.push(part.to_os_string());
            continue;
        }
        match parent.symlink_metadata(part) {
            Ok(metadata) => {
                ensure!(
                    !metadata.file_type().is_symlink(),
                    "Symlink в пути запрещён"
                );
                ensure!(metadata.is_dir(), "Компонент пути не является каталогом");
                parent = open_child_directory(&parent, part)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing_dirs.push(part.to_os_string());
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok((parent, name, missing_dirs))
}

#[cfg(unix)]
fn bound_parent_handle(
    retained_root: &Dir,
    root_path: &Path,
    relative: &Path,
) -> Result<(Dir, OsString, PathBinding)> {
    let (root, root_identity) = checked_root(retained_root, root_path)?;
    let name = relative
        .file_name()
        .context("Требуется путь к файлу")?
        .to_os_string();
    let parent_path = relative
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut parent = root.try_clone()?;
    let mut binding = vec![root_identity];
    for component in parent_path.components() {
        let Component::Normal(part) = component else {
            if matches!(component, Component::CurDir) {
                continue;
            }
            bail!("Некорректный компонент пути")
        };
        parent = open_child_directory(&parent, part)?;
        binding.push(directory_identity(&parent)?);
    }
    Ok((parent, name, binding))
}

fn normalized_path(path: &Path, allow_root: bool) -> Result<PathBuf> {
    ensure!(path.to_str().is_some(), "Имена файлов должны быть UTF-8");
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                ensure!(
                    !part.to_string_lossy().contains('\0'),
                    "NUL в пути запрещён"
                );
                clean.push(part);
            }
            Component::CurDir => {}
            _ => bail!("Путь должен быть относительным, без .. и абсолютных компонентов"),
        }
    }
    ensure!(
        clean.components().count() <= 64 && clean.as_os_str().len() <= 4096,
        "Слишком длинный путь"
    );
    ensure!(
        allow_root || !clean.as_os_str().is_empty(),
        "Требуется путь к файлу"
    );
    if clean.as_os_str().is_empty() {
        clean.push(".");
    }
    Ok(clean)
}

fn undo_order(entries: &[Change]) -> Vec<usize> {
    let mut order: Vec<_> = (0..entries.len()).collect();
    order.sort_by(|left, right| {
        let is_policy = |index: usize| {
            entries[index]
                .path
                .file_name()
                .is_some_and(|name| name == ".gitignore")
        };
        match (is_policy(*left), is_policy(*right)) {
            (false, false) | (true, true) => {
                if is_policy(*left) {
                    entries[*right]
                        .path
                        .components()
                        .count()
                        .cmp(&entries[*left].path.components().count())
                } else {
                    left.cmp(right)
                }
            }
            (false, true) => std::cmp::Ordering::Less,
            (true, false) => std::cmp::Ordering::Greater,
        }
    });
    order
}

fn valid_image(image: &StoredImage) -> bool {
    let reference = &image.image;
    let valid_id = uuid::Uuid::parse_str(&reference.id).is_ok_and(|id| {
        id.get_version_num() == 4
            && id.get_variant() == uuid::Variant::RFC4122
            && id.to_string() == reference.id
    });
    reference.len <= crate::file_wal::MAX_IMAGE_BYTES
        && valid_id
        && reference.sha256.len() == 64
        && reference
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        && image.identity.inode != 0
}

fn checkpoint_images(checkpoints: &Checkpoints) -> BTreeMap<String, StoredImage> {
    fn add_change(change: &Change, images: &mut BTreeMap<String, StoredImage>) {
        if let Some(before) = &change.before {
            images.insert(before.image.id.clone(), before.clone());
        }
        images.insert(
            change.after_image.image.id.clone(),
            change.after_image.clone(),
        );
    }

    let mut images = BTreeMap::new();
    for turn in &checkpoints.turns {
        for change in &turn.entries {
            add_change(change, &mut images);
        }
    }
    if let Some(pending) = &checkpoints.pending_write {
        if let Some(before) = &pending.before_image {
            images.insert(before.image.id.clone(), before.clone());
        }
        add_change(&pending.candidate, &mut images);
    }
    images
}

pub(crate) fn secret_component(name: &std::ffi::OsStr) -> bool {
    let name = name.to_string_lossy().to_ascii_lowercase();
    name.starts_with(".rcode-wal-")
        || matches!(
            name.as_str(),
            ".git"
                | ".ssh"
                | ".aws"
                | ".azure"
                | ".gnupg"
                | ".kube"
                | ".gcp"
                | "gcloud"
                | "keys"
                | "credentials"
                | ".credentials"
                | "secrets"
                | ".secrets"
                | "credentials.json"
                | "secrets.json"
                | "id_rsa"
                | "id_dsa"
                | "id_ecdsa"
                | "id_ed25519"
                | ".netrc"
                | ".npmrc"
                | ".pypirc"
        )
        || name.starts_with(".env")
        || [".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"]
            .iter()
            .any(|suffix| name.ends_with(suffix))
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum MissingPolicy {
    Disallow,
    AllowMissingLeaf,
    AllowMissingSubtree,
}

struct Policy<'a> {
    dir: &'a Dir,
    root: &'a Path,
    matchers: HashMap<PathBuf, Gitignore>,
}
impl<'a> Policy<'a> {
    fn new(dir: &'a Dir, root: &'a Path) -> Self {
        Self {
            dir,
            root,
            matchers: HashMap::new(),
        }
    }
    fn load_from_dir(&mut self, dir: &Dir, path: &Path, name: &Path, base: &Path) -> Result<()> {
        if self.matchers.contains_key(path) {
            return Ok(());
        }
        let mut builder = GitignoreBuilder::new(self.root.join(base));
        let text = match snapshot(dir, name, 256 * 1024) {
            Ok(Some(file)) => {
                Some(String::from_utf8(file.bytes).context("Ignore-файл не является UTF-8")?)
            }
            Ok(None) => None,
            Err(error)
                if error.downcast_ref::<io::Error>().is_some_and(|e| {
                    e.kind() == io::ErrorKind::NotFound || e.kind() == io::ErrorKind::NotADirectory
                }) =>
            {
                None
            }
            Err(error) => return Err(error.context("Не удалось безопасно прочитать ignore-файл")),
        };
        if let Some(text) = text {
            ensure!(
                text.lines().count() <= 10_000,
                "Слишком много ignore-правил"
            );
            for line in text.lines() {
                builder
                    .add_line(Some(path.into()), line)
                    .context("Некорректное ignore-правило")?;
            }
        }
        self.matchers.insert(path.into(), builder.build()?);
        Ok(())
    }
    fn load_root_exclude(&mut self) -> Result<()> {
        let path = Path::new(".git/info/exclude");
        if self.matchers.contains_key(path) {
            return Ok(());
        }
        let mut builder = GitignoreBuilder::new(self.root);
        let text = match open_child_directory(self.dir, std::ffi::OsStr::new(".git"))
            .and_then(|git| open_child_directory(&git, std::ffi::OsStr::new("info")))
            .and_then(|info| snapshot(&info, Path::new("exclude"), 256 * 1024))
        {
            Ok(Some(file)) => {
                Some(String::from_utf8(file.bytes).context("Ignore-файл не является UTF-8")?)
            }
            Ok(None) => None,
            Err(error)
                if error.downcast_ref::<io::Error>().is_some_and(|e| {
                    e.kind() == io::ErrorKind::NotFound || e.kind() == io::ErrorKind::NotADirectory
                }) =>
            {
                None
            }
            Err(error) => return Err(error.context("Не удалось безопасно прочитать ignore-файл")),
        };
        if let Some(text) = text {
            ensure!(
                text.lines().count() <= 10_000,
                "Слишком много ignore-правил"
            );
            for line in text.lines() {
                builder
                    .add_line(Some(path.into()), line)
                    .context("Некорректное ignore-правило")?;
            }
        }
        self.matchers.insert(path.into(), builder.build()?);
        Ok(())
    }
    fn check(&mut self, path: &Path, missing_policy: MissingPolicy) -> Result<PathBuf> {
        let path = normalized_path(
            path,
            !matches!(missing_policy, MissingPolicy::AllowMissingSubtree),
        )?;
        self.load_root_exclude()?;
        self.load_from_dir(
            self.dir,
            Path::new(".gitignore"),
            Path::new(".gitignore"),
            Path::new("."),
        )?;
        let mut layers = vec![
            PathBuf::from(".git/info/exclude"),
            PathBuf::from(".gitignore"),
        ];
        let mut prefix = PathBuf::new();
        let count = path
            .components()
            .filter(|c| !matches!(c, Component::CurDir))
            .count();
        let mut current_dir: Option<Dir> = Some(self.dir.try_clone()?);
        for (i, component) in path
            .components()
            .filter(|c| !matches!(c, Component::CurDir))
            .enumerate()
        {
            let part = component.as_os_str();
            ensure!(
                !secret_component(part),
                "Доступ к секретным файлам и служебным каталогам запрещён"
            );
            prefix.push(part);
            let metadata = if let Some(dir) = current_dir.as_ref() {
                match dir.symlink_metadata(part) {
                    Ok(metadata) => {
                        ensure!(
                            !metadata.file_type().is_symlink(),
                            "Symlink недоступен файловым инструментам"
                        );
                        Some(metadata)
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => match missing_policy {
                        MissingPolicy::AllowMissingSubtree => {
                            if i + 1 < count {
                                current_dir = None;
                            }
                            None
                        }
                        MissingPolicy::AllowMissingLeaf if i + 1 == count => None,
                        _ => return Err(error.into()),
                    },
                    Err(error) => return Err(error.into()),
                }
            } else {
                None
            };
            let existing_dir = metadata.as_ref().is_some_and(|m| m.is_dir());
            let match_as_dir = if i + 1 < count {
                metadata.as_ref().is_none_or(|m| m.is_dir())
            } else {
                existing_dir
            };
            let mut ignored = false;
            for layer in &layers {
                let matched = self.matchers[layer].matched(self.root.join(&prefix), match_as_dir);
                if !matched.is_none() {
                    ignored = matched.is_ignore();
                }
            }
            ensure!(
                !ignored,
                "Путь исключён правилами Git ignore: {}",
                prefix.display()
            );
            if i + 1 < count && metadata.is_some() {
                ensure!(existing_dir, "Компонент пути не является каталогом");
            }
            if existing_dir {
                let next_dir =
                    open_child_directory(current_dir.as_ref().expect("parent dir open"), part)?;
                let ignore_path = prefix.join(".gitignore");
                self.load_from_dir(&next_dir, &ignore_path, Path::new(".gitignore"), &prefix)?;
                layers.push(ignore_path);
                current_dir = Some(next_dir);
            }
        }
        Ok(path)
    }
}

fn open_child_directory(dir: &Dir, part: &std::ffi::OsStr) -> Result<Dir> {
    ensure!(
        !dir.symlink_metadata(part)?.file_type().is_symlink(),
        "Symlink в пути запрещён"
    );
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_NONBLOCK);
        Ok(Dir::from_std_file(
            dir.open_with(part, &options)?.into_std(),
        ))
    }
    #[cfg(not(unix))]
    {
        Ok(dir.open_dir(part)?)
    }
}

fn open_directory(root: &Dir, path: &Path) -> Result<Dir> {
    let mut dir = root.try_clone()?;
    for component in path.components() {
        match component {
            Component::CurDir => continue,
            Component::Normal(part) => dir = open_child_directory(&dir, part)?,
            _ => bail!("Некорректный компонент пути"),
        }
    }
    Ok(dir)
}

fn parent_handle(root: &Dir, path: &Path) -> Result<(Dir, OsString)> {
    let name = path
        .file_name()
        .context("Требуется путь к файлу")?
        .to_os_string();
    let parent = open_directory(
        root,
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?;
    Ok((parent, name))
}

fn snapshot(dir: &Dir, path: &Path, limit: usize) -> Result<Option<Snapshot>> {
    let metadata = match dir.symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "Доступны только обычные файлы, symlink запрещён"
    );
    ensure!(
        metadata.len() <= limit as u64,
        "Размер файла превышает лимит {limit} байт"
    );
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = dir.open_with(path, &options)?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "Доступны только обычные файлы");
    #[cfg(unix)]
    let native_before = file.try_clone()?.into_std().metadata()?;
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    #[cfg(unix)]
    let before_identity = identity(&native_before);
    #[cfg(unix)]
    let nlink = native_before.nlink();
    let mut bytes = Vec::new();
    (&mut file).take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= limit,
        "Размер файла превышает лимит {limit} байт"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let after = file.try_clone()?.into_std().metadata()?;
        ensure!(
            identity(&after) == before_identity
                && after.len() == native_before.len()
                && after.mtime() == native_before.mtime()
                && after.mtime_nsec() == native_before.mtime_nsec()
                && after.ctime() == native_before.ctime()
                && after.ctime_nsec() == native_before.ctime_nsec(),
            "Файл изменился во время чтения"
        );
        let current = dir.open_with(path, &options)?.into_std().metadata()?;
        ensure!(
            identity(&current) == before_identity,
            "Файл заменён во время чтения"
        );
    }
    Ok(Some(Snapshot {
        bytes,
        permissions: metadata.permissions(),
        #[cfg(unix)]
        identity: before_identity,
        #[cfg(unix)]
        nlink,
    }))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn permission_mode(permissions: &Permissions) -> Option<u32> {
    #[cfg(unix)]
    {
        use cap_std::fs::PermissionsExt;
        Some(permissions.mode() & 0o7777)
    }
    #[cfg(not(unix))]
    {
        let _ = permissions;
        None
    }
}

#[cfg(not(unix))]
fn ensure_hash(dir: &Dir, name: &std::ffi::OsStr, expected: Option<&str>) -> Result<()> {
    let current = snapshot(dir, Path::new(name), MAX_FILE_BYTES)?;
    ensure!(
        current.as_ref().map(|s| sha256(&s.bytes)).as_deref() == expected,
        "Конфликт: файл изменён непосредственно перед записью"
    );
    Ok(())
}

#[cfg(not(unix))]
fn atomic_workspace_write(
    dir: &Dir,
    name: &std::ffi::OsStr,
    bytes: &[u8],
    expected: Option<&str>,
    mode: Option<u32>,
    readonly: Option<bool>,
) -> Result<()> {
    atomic_write_checked(dir, name, bytes, mode, readonly, || {
        ensure_hash(dir, name, expected)?;
        Ok(dir.try_clone()?)
    })
}

#[cfg(not(unix))]
fn atomic_write(
    dir: &Dir,
    name: &std::ffi::OsStr,
    bytes: &[u8],
    mode: Option<u32>,
    readonly: Option<bool>,
) -> Result<()> {
    atomic_write_checked(dir, name, bytes, mode, readonly, || Ok(dir.try_clone()?))
}

#[cfg(not(unix))]
fn atomic_write_checked(
    dir: &Dir,
    name: &std::ffi::OsStr,
    bytes: &[u8],
    mode: Option<u32>,
    readonly: Option<bool>,
    recheck: impl FnOnce() -> Result<Dir>,
) -> Result<()> {
    let temporary = format!(".rcode-{}.tmp", uuid::Uuid::new_v4().simple());
    let result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(not(unix))]
        let _ = mode;
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            options.mode(mode.unwrap_or(0o666));
        }
        let mut file = dir.open_with(&temporary, &options)?;
        file.write_all(bytes)?;
        #[cfg(unix)]
        if let Some(mode) = mode {
            use cap_std::fs::PermissionsExt;
            file.set_permissions(Permissions::from_mode(mode))?;
        }
        #[cfg(not(unix))]
        if let Some(readonly) = readonly {
            let mut permissions = file.metadata()?.permissions();
            permissions.set_readonly(readonly);
            file.set_permissions(permissions)?;
        }
        #[cfg(unix)]
        let _ = readonly;
        file.sync_all()?;
        let target = recheck()?;
        dir.rename(&temporary, &target, name)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = dir.remove_file(&temporary);
    }
    result
}

fn bounded(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut end = max.saturating_sub(32);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n[вывод ограничен]\n", &text[..end])
}

fn unified_diff(path: &Path, before: &str, after: &str) -> String {
    let diff = similar::TextDiff::configure()
        .timeout(Duration::from_millis(200))
        .diff_lines(before, after);
    let name = path.to_string_lossy();
    let mut writer = LimitedWriter {
        bytes: vec![],
        max: MAX_OUTPUT_BYTES / 2,
    };
    let _ = diff
        .unified_diff()
        .header(&format!("a/{name}"), &format!("b/{name}"))
        .to_writer(&mut writer);
    String::from_utf8_lossy(&writer.bytes).into_owned()
}

struct LimitedWriter {
    bytes: Vec<u8>,
    max: usize,
}
impl Write for LimitedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let available = self.max.saturating_sub(self.bytes.len());
        if available == 0 {
            return Err(io::Error::other("Лимит diff"));
        }
        let count = available.min(bytes.len());
        self.bytes.extend_from_slice(&bytes[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn check_cancel(cancel: &CancellationToken) -> Result<()> {
    ensure!(!cancel.is_cancelled(), "cancelled: выполнение отменено");
    Ok(())
}
fn string_arg<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("{key} должен быть строкой"))
}
fn usize_arg(args: &Value, key: &str, default: usize, min: usize, max: usize) -> Result<usize> {
    let value = match args.get(key) {
        None => default,
        Some(value) => usize::try_from(
            value
                .as_u64()
                .with_context(|| format!("{key} должен быть неотрицательным целым"))?,
        )?,
    };
    ensure!(
        (min..=max).contains(&value),
        "{key} должен быть в диапазоне {min}..={max}"
    );
    Ok(value)
}
fn bool_arg(args: &Value, key: &str, default: bool) -> Result<bool> {
    args.get(key).map_or(Ok(default), |v| {
        v.as_bool()
            .with_context(|| format!("{key} должен быть boolean"))
    })
}
pub(crate) fn validate_args(name: &str, args: &Value) -> Result<()> {
    let definition = Tools::definitions()
        .into_iter()
        .find(|d| d.name == name)
        .with_context(|| format!("Неизвестный инструмент: {name}"))?;
    let object = args
        .as_object()
        .context("Аргументы инструмента должны быть JSON object")?;
    let properties = definition.parameters["properties"].as_object().unwrap();
    for key in object.keys() {
        ensure!(
            properties.contains_key(key),
            "Неизвестный аргумент {key} для {name}"
        );
    }
    for key in definition.parameters["required"].as_array().unwrap() {
        ensure!(
            object.contains_key(key.as_str().unwrap()),
            "Обязательный аргумент {key} отсутствует"
        );
    }
    Ok(())
}
pub(crate) fn command_args(args: &Value) -> Result<(&str, usize)> {
    let command = string_arg(args, "command")?;
    ensure!(
        !command.trim().is_empty() && command.len() <= 16_384 && !command.contains('\0'),
        "Команда пуста, содержит NUL или превышает 16 KiB"
    );
    Ok((command, usize_arg(args, "timeout_secs", 60, 1, 300)?))
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn allowed_env(key: &str) -> bool {
    #[cfg(windows)]
    let normalized_key = key.to_ascii_uppercase();
    #[cfg(windows)]
    let key = normalized_key.as_str();
    matches!(
        key,
        "PATH"
            | "HOME"
            | "USER"
            | "LOGNAME"
            | "LANG"
            | "TMPDIR"
            | "TEMP"
            | "TMP"
            | "SYSTEMROOT"
            | "COMSPEC"
            | "PATHEXT"
    ) || key.starts_with("LC_")
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
async fn capture(
    mut stream: impl AsyncRead + Unpin,
    budget: Arc<AtomicUsize>,
    limit: CancellationToken,
) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        let used = budget.fetch_add(count, Ordering::Relaxed);
        let available = MAX_OUTPUT_BYTES.saturating_sub(used).min(count);
        output.extend_from_slice(&buffer[..available]);
        if available < count {
            limit.cancel();
        }
    }
    Ok(output)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
struct ProcessGroup {
    pid: Option<u32>,
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl ProcessGroup {
    fn new(pid: Option<u32>) -> Self {
        Self { pid }
    }
    fn kill(&mut self) {
        #[cfg(unix)]
        if let Some(pid) = self.pid.take() {
            // SAFETY: a positive child PID is used as its private process-group
            // identifier (process_group(0)); no caller-provided PID is accepted.
            unsafe {
                libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
            }
        }
        #[cfg(not(unix))]
        {
            self.pid = None;
        }
    }
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        self.kill();
    }
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn exit_signal(status: &ExitStatus) -> Option<i32> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status.signal()
    }
    #[cfg(not(unix))]
    {
        let _ = status;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::fs;
    use tempfile::TempDir;

    #[cfg(unix)]
    #[test]
    fn externally_deleted_checkpoint_dir_fails_closed_without_recreation() {
        let mut f = Fixture::new();
        f.file("wip.rs", "user work");
        std::fs::remove_dir_all(&f.state).unwrap();
        assert!(f.tools.begin_turn().is_err());
        assert!(
            !f.state.exists(),
            "a deleted v2 store must not be recreated"
        );
        assert_eq!(
            fs::read_to_string(f.root.join("wip.rs")).unwrap(),
            "user work"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn empty_v2_manifest_migrates_but_nonempty_v2_is_untouched() {
        let mut empty = Fixture::new();
        empty.tools.begin_turn().unwrap();
        drop(empty.tools);
        let manifest_path = empty.state.join(CHECKPOINT_FILE);
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        manifest["version"] = json!(2);
        let v2 = serde_json::to_vec(&manifest).unwrap();
        fs::write(&manifest_path, &v2).unwrap();
        let migrated = Tools::new(&empty.root, &empty.state).unwrap();
        let saved: Value = serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        assert_eq!(saved["version"], 3);
        drop(migrated);

        let mut nonempty = Fixture::new();
        nonempty.file("wip", "user");
        let outcome = nonempty.write("wip", "agent").await;
        assert!(!outcome.is_error);
        drop(nonempty.tools);
        let manifest_path = nonempty.state.join(CHECKPOINT_FILE);
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        manifest["version"] = json!(2);
        let v2 = serde_json::to_vec(&manifest).unwrap();
        fs::write(&manifest_path, &v2).unwrap();
        let before = fs::read(&manifest_path).unwrap();
        assert!(Tools::new(&nonempty.root, &nonempty.state).is_err());
        assert_eq!(fs::read(&manifest_path).unwrap(), before);
        assert_eq!(fs::read(nonempty.root.join("wip")).unwrap(), b"agent");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn v2_migration_rejects_malformed_envelopes_without_rewriting_them() {
        let mut fixture = Fixture::new();
        fixture.tools.begin_turn().unwrap();
        drop(fixture.tools);
        let manifest_path = fixture.state.join(CHECKPOINT_FILE);
        let mut base: Value = serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        base["version"] = json!(2);

        let mut malformed = Vec::new();
        let mut wrong_shell_type = base.clone();
        wrong_shell_type["turns"][0]["shell_used"] = json!("true");
        malformed.push(wrong_shell_type);
        let mut unknown_top_level = base.clone();
        unknown_top_level["surprise"] = json!(true);
        malformed.push(unknown_top_level);
        let mut unknown_turn_field = base.clone();
        unknown_turn_field["turns"][0]["surprise"] = json!(true);
        malformed.push(unknown_turn_field);

        for envelope in malformed {
            let bytes = serde_json::to_vec(&envelope).unwrap();
            fs::write(&manifest_path, &bytes).unwrap();
            assert!(Tools::new(&fixture.root, &fixture.state).is_err());
            assert_eq!(fs::read(&manifest_path).unwrap(), bytes);
        }
    }

    #[cfg(all(test, unix))]
    #[tokio::test]
    async fn changed_stage_mode_after_durable_payload_does_not_publish() {
        use std::os::unix::fs::PermissionsExt;

        let mut fixture = Fixture::new();
        fixture.file("f", "user-original");
        fs::set_permissions(fixture.root.join("f"), fs::Permissions::from_mode(0o644)).unwrap();
        let root = fixture.root.clone();
        fixture.tools.set_wal_fault_hook(Box::new(move |point| {
            if point == (WalFaultPoint::StagePayloadDurable { index: 0 }) {
                let stage = fs::read_dir(&root)
                    .unwrap()
                    .filter_map(Result::ok)
                    .map(|entry| entry.path())
                    .find(|path| {
                        path.file_name()
                            .is_some_and(|name| name.to_string_lossy().ends_with(".stage"))
                    })
                    .expect("durable stage exists");
                fs::set_permissions(stage.join("payload"), fs::Permissions::from_mode(0o600))
                    .unwrap();
            }
        }));

        let outcome = fixture
            .call(
                "write_file",
                json!({"path":"f","content":"agent-change","expected_sha256":hash(b"user-original")}),
            )
            .await;
        assert!(outcome.is_error, "tampered stage mode must fail closed");
        assert_eq!(fs::read(fixture.root.join("f")).unwrap(), b"user-original");
        assert_eq!(
            fs::metadata(fixture.root.join("f"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn large_accepted_turn_keeps_its_undo_space_reserved() {
        const FILES: usize = 41;
        const SIZE: usize = 1024 * 1024;
        use std::os::unix::fs::PermissionsExt;

        let mut fixture = Fixture::new();
        for index in 0..FILES {
            let path = format!("file-{index:02}.bin");
            let mut before = vec![b'a' + (index % 20) as u8; SIZE];
            before[..4].copy_from_slice(format!("{index:04}").as_bytes());
            fixture.file(&path, std::str::from_utf8(&before).unwrap());
            fs::set_permissions(
                fixture.root.join(&path),
                fs::Permissions::from_mode(if index % 2 == 0 { 0o640 } else { 0o751 }),
            )
            .unwrap();
        }

        let mut accepted = 0;
        let mut refused_at = None;
        for index in 0..FILES {
            let path = format!("file-{index:02}.bin");
            let mut after = vec![b'A' + (index % 20) as u8; SIZE];
            after[..4].copy_from_slice(format!("{index:04}").as_bytes());
            let expected_sha256 = hash(&fs::read(fixture.root.join(&path)).unwrap());
            let outcome = fixture
                .call(
                    "write_file",
                    json!({"path":path,"content":String::from_utf8(after).unwrap(),"expected_sha256":expected_sha256}),
                )
                .await;
            if outcome.is_error {
                refused_at = Some(index);
                break;
            }
            accepted += 1;
        }
        assert!(
            accepted >= 35,
            "unexpectedly low safe admission: {accepted}"
        );

        if let Some(refused_at) = refused_at {
            for index in refused_at..FILES {
                let path = fixture.root.join(format!("file-{index:02}.bin"));
                let bytes = fs::read(&path).unwrap();
                assert_eq!(&bytes[..4], format!("{index:04}").as_bytes());
                assert!(
                    bytes[4..]
                        .iter()
                        .all(|byte| *byte == b'a' + (index % 20) as u8)
                );
                assert_eq!(
                    fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    if index % 2 == 0 { 0o640 } else { 0o751 }
                );
            }
        }

        let undo = fixture.tools.undo();
        assert!(
            undo.is_ok(),
            "accepted turn must retain undo capacity: {undo:?}"
        );
        for index in 0..FILES {
            let path = fixture.root.join(format!("file-{index:02}.bin"));
            let bytes = fs::read(&path).unwrap();
            assert_eq!(bytes.len(), SIZE);
            assert_eq!(&bytes[..4], format!("{index:04}").as_bytes());
            assert!(
                bytes[4..]
                    .iter()
                    .all(|byte| *byte == b'a' + (index % 20) as u8)
            );
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                if index % 2 == 0 { 0o640 } else { 0o751 }
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn write_admission_reserves_manifest_growth_for_future_undo() {
        use std::os::unix::fs::PermissionsExt;

        let mut fixture = Fixture::new();
        fixture.file("f", "u");
        fs::set_permissions(fixture.root.join("f"), fs::Permissions::from_mode(0o640)).unwrap();
        fixture.tools.begin_turn().unwrap();

        let mut current_store_bytes = 0u64;
        for entry in fs::read_dir(&fixture.state).unwrap() {
            let entry = entry.unwrap();
            if entry.file_name() != "blobs" {
                current_store_bytes += entry.metadata().unwrap().len();
            }
        }
        let blobs = fixture.state.join("blobs");
        for entry in fs::read_dir(&blobs).unwrap() {
            current_store_bytes += entry.unwrap().metadata().unwrap().len();
        }
        let write_and_undo_reserve = 8 * 1024 * 1024 + 8;
        let filler_len = crate::file_wal::MAX_STORE_BYTES
            .checked_sub(current_store_bytes + write_and_undo_reserve)
            .expect("fixture leaves room for a small admitted write");
        let filler = blobs.join("unknown-filler");
        let filler_file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&filler)
            .unwrap();
        filler_file
            .set_permissions(fs::Permissions::from_mode(0o600))
            .unwrap();
        filler_file.set_len(filler_len).unwrap();

        let outcome = fixture
            .call(
                "write_file",
                json!({"path":"f","content":"a","expected_sha256":hash(b"u")}),
            )
            .await;
        if outcome.is_error {
            assert!(
                outcome.content.contains("quota"),
                "unexpected refusal: {}",
                outcome.content
            );
            assert_eq!(fs::read(fixture.root.join("f")).unwrap(), b"u");
            let manifest: Value =
                serde_json::from_slice(&fs::read(fixture.state.join(CHECKPOINT_FILE)).unwrap())
                    .unwrap();
            assert!(manifest["pending_write"].is_null());
        } else {
            let undo = fixture.tools.undo();
            assert!(
                undo.is_ok(),
                "accepted write must retain undo capacity: {undo:?}"
            );
        }
        assert_eq!(fs::read(fixture.root.join("f")).unwrap(), b"u");
        assert_eq!(
            fs::metadata(fixture.root.join("f"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn write_admission_reserves_existing_orphan_namespace_for_future_undo() {
        use std::os::unix::fs::PermissionsExt;

        const ORPHANS: usize = 2_729;
        let mut fixture = Fixture::new();
        fixture.file("a", "user-a");
        fixture.file("b", "user-b");
        fs::set_permissions(fixture.root.join("a"), fs::Permissions::from_mode(0o751)).unwrap();
        fs::set_permissions(fixture.root.join("b"), fs::Permissions::from_mode(0o640)).unwrap();
        assert!(!fixture.write("a", "agent-a").await.is_error);

        let previous = fixture.tools.checkpoints.turns[0].entries[0].clone();
        let root = fixture.tools.checkpoints.root.clone();
        let binding = previous.binding.clone().unwrap();
        fixture.tools.checkpoints.orphan_stages = (0..ORPHANS)
            .map(|_| OrphanStage {
                root: root.clone(),
                parent: PathBuf::from("."),
                stage: crate::workspace_stage::StageRef {
                    name: crate::workspace_stage::StageDirectory::plan_name(),
                    directory: None,
                    guard: None,
                    payload: None,
                },
                bytes: 0,
                binding: binding.clone(),
            })
            .collect();
        fixture.tools.persist().unwrap();
        let manifest = fs::read(fixture.state.join(CHECKPOINT_FILE)).unwrap();
        assert!(manifest.len() < crate::file_wal::MAX_MANIFEST_BYTES);

        let outcome = fixture.write("b", "agent-b").await;
        if !outcome.is_error {
            let undo = fixture.tools.undo();
            assert!(
                undo.is_ok(),
                "a write admitted with orphan refs must remain undoable: {undo:?}"
            );
        }
        assert!(
            outcome.is_error,
            "write must reserve namespace for undoing both files"
        );
        assert_eq!(fs::read(fixture.root.join("b")).unwrap(), b"user-b");
        assert_eq!(
            fs::metadata(fixture.root.join("b"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );

        assert!(fixture.tools.undo().is_ok());
        assert_eq!(fs::read(fixture.root.join("a")).unwrap(), b"user-a");
        assert_eq!(fs::read(fixture.root.join("b")).unwrap(), b"user-b");
        assert_eq!(
            fs::metadata(fixture.root.join("a"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o751
        );
        assert_eq!(
            fs::metadata(fixture.root.join("b"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
        assert_eq!(fixture.tools.checkpoints.orphan_stages.len(), ORPHANS);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn undo_80_files_uses_constant_fds_under_limit_64() {
        const CHILD: &str = "RCODE_TEST_WAL_LOW_FD_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("tools::tests::undo_80_files_uses_constant_fds_under_limit_64")
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success(), "low-FD undo child failed: {status}");
            return;
        }

        let limit = libc::rlimit {
            rlim_cur: 64,
            rlim_max: 64,
        };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);

        let mut fixture = Fixture::new();
        let paths = (0..80)
            .map(|index| format!("parent-{index:02}/file.txt"))
            .collect::<Vec<_>>();
        for (index, path) in paths.iter().enumerate() {
            fs::create_dir_all(fixture.root.join(path).parent().unwrap()).unwrap();
            fixture.file(path, &format!("user-{index}"));
        }

        for path in &paths {
            let result = fixture.write(path, "agent").await;
            assert!(!result.is_error, "write {path}: {}", result.content);
        }
        let root = fixture.root.clone();
        let state = fixture.state.clone();
        drop(fixture.tools);
        fixture.tools = Tools::new(&root, &state).unwrap();
        fixture.tools.undo().unwrap();
        for (index, path) in paths.iter().enumerate() {
            assert_eq!(
                fs::read(root.join(path)).unwrap(),
                format!("user-{index}").as_bytes()
            );
        }

        for round in 0..2 {
            for path in &paths {
                let before = fs::read_to_string(root.join(path)).unwrap();
                let result = fixture
                    .write(path, &format!("round-{round}-{before}"))
                    .await;
                assert!(!result.is_error, "write {path}: {}", result.content);
            }
            drop(fixture.tools);
            fixture.tools = Tools::new(&root, &state).unwrap();
            fixture.tools.undo().unwrap();
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn staging_abort_records_unknown_orphan_and_keeps_previous_undo() {
        use crate::file_wal::StoreFaultPoint;

        let mut fixture = Fixture::new();
        fixture.file("a.rs", "user");
        assert!(!fixture.write("a.rs", "agent").await.is_error);
        fixture.tools.fail_store_after_wal_point(
            WalFaultPoint::StageCreated { index: 0 },
            StoreFaultPoint::ManifestTempFileSync,
            libc::EIO,
        );
        assert!(fixture.tools.undo().is_err());
        assert_eq!(
            fs::read_to_string(fixture.root.join("a.rs")).unwrap(),
            "agent"
        );

        let root = fixture.root.clone();
        let state = fixture.state.clone();
        drop(fixture.tools);
        let mut reopened = Tools::new(&root, &state).unwrap();
        let saved: Value =
            serde_json::from_slice(&fs::read(state.join(CHECKPOINT_FILE)).unwrap()).unwrap();
        let orphan = saved["orphan_stages"][0].clone();
        assert_eq!(saved["orphan_stages"].as_array().unwrap().len(), 1);
        assert!(saved["pending_undo"].is_null());
        assert!(orphan["stage"]["directory"].is_null());
        let orphan_path = root
            .join(orphan["parent"].as_str().unwrap())
            .join(orphan["stage"]["name"].as_str().unwrap());
        assert!(orphan_path.is_dir());
        assert!(orphan_path.join("payload").is_file());
        reopened.undo().unwrap();
        assert_eq!(fs::read_to_string(root.join("a.rs")).unwrap(), "user");
        assert!(orphan_path.is_dir(), "unknown orphan must remain untouched");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failed_durable_prepared_never_allows_same_tools_to_publish_undo() {
        use crate::file_wal::StoreFaultPoint;

        let mut fixture = Fixture::new();
        fixture.file("a.rs", "user");
        assert!(!fixture.write("a.rs", "agent").await.is_error);
        fixture.tools.fail_store_after_wal_point(
            WalFaultPoint::BeforePreparedPersist,
            StoreFaultPoint::ManifestTempFileSync,
            libc::EIO,
        );
        assert!(fixture.tools.undo().is_err());
        assert_eq!(
            fs::read_to_string(fixture.root.join("a.rs")).unwrap(),
            "agent"
        );
        let saved: Value =
            serde_json::from_slice(&fs::read(fixture.state.join(CHECKPOINT_FILE)).unwrap())
                .unwrap();
        assert_eq!(saved["pending_undo"]["prepared"], false);
        assert!(
            fixture.tools.undo().is_err(),
            "same Tools must stay poisoned"
        );
        assert_eq!(
            fs::read_to_string(fixture.root.join("a.rs")).unwrap(),
            "agent"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failed_undo_finalize_keeps_same_tools_blocked_until_reopen() {
        use crate::file_wal::StoreFaultPoint;

        let mut fixture = Fixture::new();
        fixture.file("a.rs", "user");
        assert!(!fixture.write("a.rs", "agent").await.is_error);
        fixture.tools.fail_store_after_wal_point(
            WalFaultPoint::BeforeFinalPersist,
            StoreFaultPoint::ManifestBeforeRename,
            libc::ENOSPC,
        );
        assert!(fixture.tools.undo().is_err());
        assert_eq!(
            fs::read_to_string(fixture.root.join("a.rs")).unwrap(),
            "user"
        );
        assert!(fixture.tools.begin_turn().is_err());

        let root = fixture.root.clone();
        let state = fixture.state.clone();
        drop(fixture.tools);
        let mut reopened = Tools::new(&root, &state).unwrap();
        reopened.undo().unwrap();
        assert_eq!(fs::read_to_string(root.join("a.rs")).unwrap(), "user");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn modified_prepared_write_stage_is_never_published() {
        use std::os::unix::fs::PermissionsExt;

        for mutation in ["bytes", "mode", "inode"] {
            let mut fixture = Fixture::new();
            fixture.file("a.rs", "user");
            fs::set_permissions(fixture.root.join("a.rs"), fs::Permissions::from_mode(0o644))
                .unwrap();
            let root = fixture.root.clone();
            let label = mutation.to_owned();
            let mutation = label.clone();
            fixture.tools.before_publication_hook = Some(Box::new(move || {
                let stage = fs::read_dir(&root)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .find(|path| {
                        path.file_name()
                            .and_then(|name| name.to_str())
                            .is_some_and(|name| name.starts_with(".rcode-wal-"))
                    })
                    .unwrap();
                let payload = stage.join("payload");
                match mutation.as_str() {
                    "bytes" => fs::write(&payload, b"tampered").unwrap(),
                    "mode" => {
                        fs::set_permissions(&payload, fs::Permissions::from_mode(0o600)).unwrap()
                    }
                    "inode" => {
                        let preserved = root.join("preserved-stage");
                        fs::rename(&payload, &preserved).unwrap();
                        fs::write(&payload, b"agent").unwrap();
                        fs::set_permissions(&payload, fs::Permissions::from_mode(0o644)).unwrap();
                    }
                    _ => unreachable!(),
                }
            }));

            let outcome = fixture
                .tools
                .execute(
                    "write_file",
                    &json!({
                        "path": "a.rs",
                        "content": "agent",
                        "expected_sha256": hash(b"user")
                    }),
                    &CancellationToken::new(),
                )
                .await
                .unwrap();
            assert!(outcome.is_error, "{label} mutation should conflict");
            assert_eq!(
                fs::read_to_string(fixture.root.join("a.rs")).unwrap(),
                "user"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancellation_after_prepared_durably_aborts_and_preserves_previous_undo() {
        let mut fixture = Fixture::new();
        fixture.file("f", "user\n");
        assert!(!fixture.write("f", "first agent\n").await.is_error);
        fixture.tools.begin_turn().unwrap();
        let cancel = CancellationToken::new();
        let hook_cancel = cancel.clone();
        fixture.tools.before_publication_hook = Some(Box::new(move || hook_cancel.cancel()));
        let outcome = fixture
            .tools
            .execute(
                "write_file",
                &json!({"path":"f","content":"second agent\n","expected_sha256":hash(b"first agent\n")}),
                &cancel,
            )
            .await
            .unwrap();
        assert!(outcome.is_error);
        assert_eq!(fs::read(fixture.root.join("f")).unwrap(), b"first agent\n");
        let manifest: Value =
            serde_json::from_slice(&fs::read(fixture.state.join(CHECKPOINT_FILE)).unwrap())
                .unwrap();
        assert!(manifest["pending_write"].is_null());
        assert_eq!(manifest["orphan_stages"].as_array().unwrap().len(), 0);
        assert!(fs::read_dir(&fixture.root).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".rcode-wal-")
        }));

        let root = fixture.root.clone();
        let state = fixture.state.clone();
        drop(fixture.tools);
        let mut reopened = Tools::new(&root, &state).unwrap();
        reopened.undo().unwrap();
        assert_eq!(fs::read(root.join("f")).unwrap(), b"user\n");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn final_write_revalidation_rejects_new_hardlink_without_losing_undo() {
        let mut fixture = Fixture::new();
        fixture.file("f", "user\n");
        let hardlink = fixture.root.join("hardlink");
        let linked_target = fixture.root.join("f");
        fixture.tools.before_publication_hook = Some(Box::new(move || {
            fs::hard_link(&linked_target, hardlink).unwrap();
        }));
        let outcome = fixture.write("f", "agent\n").await;
        assert!(outcome.is_error);
        assert_eq!(fs::read(fixture.root.join("f")).unwrap(), b"user\n");
        fs::remove_file(fixture.root.join("hardlink")).unwrap();
        assert!(
            fixture
                .tools
                .undo()
                .unwrap()
                .contains("Нет файловых правок")
        );
    }

    #[tokio::test]
    async fn shell_only_turn_undo_is_metadata_only_and_keeps_older_file_undo() {
        let mut fixture = Fixture::new();
        fixture.file("f", "user\n");
        assert!(!fixture.write("f", "agent\n").await.is_error);
        fixture.tools.begin_turn().unwrap();
        fixture.tools.mark_shell_used().unwrap();
        fixture.tools.undo().unwrap();
        let manifest: Value =
            serde_json::from_slice(&fs::read(fixture.state.join(CHECKPOINT_FILE)).unwrap())
                .unwrap();
        assert!(manifest["pending_undo"].is_null());

        let root = fixture.root.clone();
        let state = fixture.state.clone();
        drop(fixture.tools);
        let mut reopened = Tools::new(&root, &state).unwrap();
        reopened.undo().unwrap();
        assert_eq!(fs::read(root.join("f")).unwrap(), b"user\n");
    }

    pub(super) struct Fixture {
        _temp: TempDir,
        pub(super) root: PathBuf,
        pub(super) state: PathBuf,
        pub(super) tools: Tools,
    }
    impl Fixture {
        pub(super) fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("project");
            let state = temp.path().join("state");
            fs::create_dir(&root).unwrap();
            let tools = Tools::new(&root, &state).unwrap();
            Self {
                _temp: temp,
                root,
                state,
                tools,
            }
        }
        pub(super) fn file(&self, path: &str, content: &str) {
            fs::write(self.root.join(path), content).unwrap();
        }
        async fn call(&mut self, name: &str, args: Value) -> ToolOutcome {
            self.tools
                .execute(name, &args, &CancellationToken::new())
                .await
                .unwrap()
        }
        async fn write(&mut self, path: &str, content: &str) -> ToolOutcome {
            let old = fs::read(self.root.join(path)).ok();
            self.call("write_file", json!({"path":path,"content":content,"expected_sha256":old.as_ref().map(|b| hash(b))})).await
        }
    }
    pub(super) fn hash(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn prepublication_recheck_rejects_same_bytes_replacement_after_journal() {
        let mut f = Fixture::new();
        f.file("f", "user original\n");
        assert!(!f.call("read_file", json!({"path":"f"})).await.is_error);
        let path = f.root.join("f");
        let moved = f.root.join("preserved-user-file");
        let preserved = moved.clone();
        f.tools.before_publication_hook = Some(Box::new(move || {
            fs::rename(&path, &preserved).unwrap();
            fs::write(&path, "user original\n").unwrap();
        }));

        let outcome = f
            .call("write_file", json!({"path":"f","content":"agent change\n"}))
            .await;
        assert!(
            outcome.is_error,
            "prepublication identity change must reject the write"
        );
        assert_eq!(fs::read_to_string(&moved).unwrap(), "user original\n");
        assert_eq!(
            fs::read_to_string(f.root.join("f")).unwrap(),
            "user original\n"
        );
        assert!(f.tools.undo().unwrap().contains("Нет файловых правок"));

        assert!(!f.call("read_file", json!({"path":"f"})).await.is_error);
        assert!(!f.write("f", "subsequent change\n").await.is_error);
        f.tools.undo().unwrap();
        assert_eq!(
            fs::read_to_string(f.root.join("f")).unwrap(),
            "user original\n"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn prepublication_recheck_rejects_replaced_ancestor_after_journal() {
        let mut f = Fixture::new();
        fs::create_dir_all(f.root.join("a/b")).unwrap();
        fs::write(f.root.join("a/b/f"), "user original\n").unwrap();
        assert!(!f.call("read_file", json!({"path":"a/b/f"})).await.is_error);
        let moved_a = f.root.with_file_name("moved-a");
        let root = f.root.clone();
        f.tools.before_publication_hook = Some(Box::new(move || {
            fs::rename(root.join("a"), &moved_a).unwrap();
            fs::create_dir(root.join("a")).unwrap();
            fs::rename(moved_a.join("b"), root.join("a/b")).unwrap();
        }));

        let outcome = f
            .call(
                "write_file",
                json!({"path":"a/b/f","content":"agent change\n"}),
            )
            .await;
        assert!(
            outcome.is_error,
            "replaced ancestor must fail the publication check"
        );
        assert_eq!(
            fs::read_to_string(f.root.join("a/b/f")).unwrap(),
            "user original\n"
        );
        assert!(f.tools.undo().unwrap().contains("Нет файловых правок"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn undo_rejects_same_bytes_inode_replacement_after_preflight() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let mut f = Fixture::new();
        f.file("f", "user original\n");
        assert!(!f.write("f", "agent result\n").await.is_error);
        let path = f.root.join("f");
        let before_inode = fs::metadata(&path).unwrap().ino();
        let before_mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let checkpoint = fs::read(f.state.join(CHECKPOINT_FILE)).unwrap();
        let preserved = f.root.join("preserved-agent-file");
        let moved = preserved.clone();
        let replacement = path.clone();
        f.tools.before_publication_hook = Some(Box::new(move || {
            fs::rename(&replacement, &moved).unwrap();
            fs::write(&replacement, "agent result\n").unwrap();
            fs::set_permissions(&replacement, fs::Permissions::from_mode(before_mode)).unwrap();
        }));

        let result = f.tools.undo();
        assert!(
            result.is_err(),
            "undo must reject a post-preflight inode replacement"
        );
        assert_ne!(before_inode, fs::metadata(&path).unwrap().ino());
        assert_eq!(fs::read(&preserved).unwrap(), b"agent result\n");
        assert_eq!(fs::read(&path).unwrap(), b"agent result\n");
        let before: Value = serde_json::from_slice(&checkpoint).unwrap();
        let after: Value =
            serde_json::from_slice(&fs::read(f.state.join(CHECKPOINT_FILE)).unwrap()).unwrap();
        assert_eq!(after["turns"], before["turns"]);
        assert!(after["pending_undo"].is_null());
        assert_eq!(after["orphan_stages"].as_array().unwrap().len(), 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn undo_rejects_workspace_root_replacement_after_preflight() {
        let mut f = Fixture::new();
        f.file("f", "user original\n");
        assert!(!f.write("f", "agent result\n").await.is_error);
        let checkpoint = fs::read(f.state.join(CHECKPOINT_FILE)).unwrap();
        let root = f.root.clone();
        let moved_root = root.with_file_name("preserved-project");
        let replacement_root = root.clone();
        f.tools.before_publication_hook = Some(Box::new(move || {
            fs::rename(&root, &moved_root).unwrap();
            fs::create_dir(&replacement_root).unwrap();
            fs::write(replacement_root.join("f"), "agent result\n").unwrap();
        }));

        let result = f.tools.undo();
        assert!(
            result.is_err(),
            "undo must reject a stale retained root after preflight"
        );
        assert_eq!(
            fs::read(f.root.with_file_name("preserved-project/f")).unwrap(),
            b"agent result\n"
        );
        assert_eq!(fs::read(f.root.join("f")).unwrap(), b"agent result\n");
        let pending: Value =
            serde_json::from_slice(&fs::read(f.state.join(CHECKPOINT_FILE)).unwrap()).unwrap();
        assert!(pending["pending_undo"].is_object());
        assert_ne!(fs::read(f.state.join(CHECKPOINT_FILE)).unwrap(), checkpoint);
    }

    #[tokio::test]
    async fn host_file_observations_are_scoped_to_the_actor() {
        let mut f = Fixture::new();
        f.file("f", "original\n");
        let cancel = CancellationToken::new();
        let read = f
            .tools
            .execute_for("read_file", &json!({"path":"f"}), &cancel, Some("worker-a"))
            .await
            .unwrap();
        assert!(!read.is_error);
        let other_actor = f
            .tools
            .execute_for(
                "write_file",
                &json!({"path":"f","content":"worker b\n"}),
                &cancel,
                Some("worker-b"),
            )
            .await
            .unwrap();
        assert!(other_actor.is_error);
        let own_read = f
            .tools
            .execute_for("read_file", &json!({"path":"f"}), &cancel, Some("worker-b"))
            .await
            .unwrap();
        assert!(!own_read.is_error);
        let own_write = f
            .tools
            .execute_for(
                "write_file",
                &json!({"path":"f","content":"worker b\n"}),
                &cancel,
                Some("worker-b"),
            )
            .await
            .unwrap();
        assert!(!own_write.is_error);
        assert_eq!(fs::read_to_string(f.root.join("f")).unwrap(), "worker b\n");
    }

    #[tokio::test]
    async fn approved_external_directory_supports_all_file_tools_and_shared_undo() {
        let mut f = Fixture::new();
        let external = f._temp.path().join("external");
        fs::create_dir(&external).unwrap();
        let file = external.join("same.txt");
        fs::write(&file, "external original").unwrap();
        f.file("same.txt", "primary original");
        assert!(f.call("read_file", json!({"path":file})).await.is_error);
        assert_eq!(
            f.tools
                .extra_directory_for("write_file", &json!({"path":file,"content":"x"}))
                .unwrap(),
            Some(fs::canonicalize(&external).unwrap())
        );
        f.tools.add_directory(&external).unwrap();
        f.tools.begin_turn().unwrap();
        let args = json!({"path":file,"content":"external changed","expected_sha256":hash(b"external original")});
        assert!(
            f.tools
                .preview("write_file", &args)
                .unwrap()
                .unwrap()
                .contains("same.txt")
        );
        let out = f.call("write_file", args).await;
        assert!(!out.is_error, "{}", out.content);
        assert_eq!(
            out.changed_paths,
            vec![fs::canonicalize(&file).unwrap().to_string_lossy()]
        );
        assert!(!f.write("same.txt", "primary changed").await.is_error);
        let out = f
            .call(
                "edit_file",
                json!({"path":file,"old_text":"changed","new_text":"edited"}),
            )
            .await;
        assert!(!out.is_error, "{}", out.content);
        let out = f.call("read_file", json!({"path":file})).await;
        assert!(
            !out.is_error && out.content.contains("external edited"),
            "{}",
            out.content
        );
        for (tool, args) in [
            ("list_files", json!({"path":external})),
            (
                "search",
                json!({"path":external,"pattern":"external edited"}),
            ),
        ] {
            let out = f.call(tool, args).await;
            assert!(
                !out.is_error && out.content.contains("same.txt"),
                "{}",
                out.content
            );
        }
        let diff = f.tools.diff().unwrap();
        assert!(
            diff.contains("external original") && diff.contains("primary original"),
            "{diff}"
        );
        f.tools.undo().unwrap();
        assert_eq!(fs::read_to_string(&file).unwrap(), "external original");
        assert_eq!(
            fs::read_to_string(f.root.join("same.txt")).unwrap(),
            "primary original"
        );
    }

    #[tokio::test]
    async fn resumed_external_changes_allow_exact_undo_without_restoring_grants() {
        let mut f = Fixture::new();
        let external = f._temp.path().join("external");
        fs::create_dir(&external).unwrap();
        let file = external.join("new.txt");
        f.tools.add_directory(&external).unwrap();
        let out = f
            .call("write_file", json!({"path":file,"content":"created"}))
            .await;
        assert!(!out.is_error, "{}", out.content);
        drop(f.tools);
        f.tools = Tools::new(&f.root, &f.state).unwrap();
        assert!(f.tools.extra_directories().is_empty());
        assert!(f.call("read_file", json!({"path":file})).await.is_error);
        assert!(f.tools.diff().unwrap().contains("created"));
        f.tools.undo().unwrap();
        assert!(!file.exists());
    }

    #[test]
    fn external_path_checks_accept_canonical_directories() {
        let f = Fixture::new();
        let external = f._temp.path().join("external");
        fs::create_dir(&external).unwrap();
        fs::write(external.join("existing.txt"), "original").unwrap();
        let root = fs::canonicalize(&external).unwrap();
        safe_external_path(&root, false).unwrap();
        safe_external_path(&root.join("existing.txt"), false).unwrap();
        assert!(safe_external_path(&root.join("missing.txt"), false).is_err());
        safe_external_path(&root.join("missing.txt"), true).unwrap();
        assert!(safe_external_path(&root.join("missing/child.txt"), true).is_err());
        let dir = open_external_directory(&root).unwrap();
        assert_eq!(dir.read("existing.txt").unwrap(), b"original");
    }

    #[cfg(windows)]
    #[test]
    fn external_grants_reject_disk_and_unc_roots() {
        let checkpoint = Path::new(r"Y:\state");
        for root in [
            r"Z:\",
            r"\\?\Z:\",
            r"\\server\share\",
            r"\\?\UNC\server\share\",
        ] {
            assert!(
                validate_external_root(Path::new(root), checkpoint).is_err(),
                "filesystem root accepted: {root}"
            );
        }
    }

    #[tokio::test]
    async fn external_grants_preserve_policy_and_reject_protected_roots() {
        let mut f = Fixture::new();
        let external = f._temp.path().join("external");
        fs::create_dir(&external).unwrap();
        fs::write(external.join(".gitignore"), "ignored.txt\n").unwrap();
        fs::write(external.join("ignored.txt"), "hidden").unwrap();
        fs::write(external.join(".env"), "secret").unwrap();
        assert!(f.tools.add_directory(&f.state).is_err());
        assert!(f.tools.add_directory(f._temp.path()).is_err());
        assert!(f.tools.add_directory(Path::new("/")).is_err());
        assert!(
            f.tools
                .extra_directory_for("read_file", &json!({"path":external.join(".env")}))
                .is_err()
        );
        assert!(
            f.tools
                .extra_directory_for("read_file", &json!({"path":external.join("ignored.txt")}))
                .is_err()
        );
        assert!(
            f.tools
                .extra_directory_for(
                    "write_file",
                    &json!({"path":external.join("../oops"),"content":"x"})
                )
                .is_err()
        );
        f.tools.add_directory(&external).unwrap();
        for name in ["ignored.txt", ".env"] {
            assert!(
                f.call("read_file", json!({"path":external.join(name)}))
                    .await
                    .is_error
            );
            assert!(
                f.call(
                    "write_file",
                    json!({"path":external.join(name),"content":"x"})
                )
                .await
                .is_error
            );
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&f.state, external.join("link")).unwrap();
            assert!(
                f.call(
                    "read_file",
                    json!({"path":external.join("link/checkpoints.json")})
                )
                .await
                .is_error
            );
            assert!(
                f.tools
                    .extra_directory_for(
                        "read_file",
                        &json!({"path":external.join("link/checkpoints.json")})
                    )
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn mixed_external_undo_preflights_every_root_before_restoring() {
        let mut f = Fixture::new();
        let external = f._temp.path().join("external");
        fs::create_dir(&external).unwrap();
        f.tools.add_directory(&external).unwrap();
        f.file("a.txt", "primary original");
        fs::write(external.join("a.txt"), "external original").unwrap();
        assert!(!f.write("a.txt", "primary changed").await.is_error);
        let out = f.call("write_file", json!({"path":external.join("a.txt"),"content":"external changed","expected_sha256":hash(b"external original")})).await;
        assert!(!out.is_error, "{}", out.content);
        fs::write(external.join("a.txt"), "user edit").unwrap();
        assert!(f.tools.undo().is_err());
        assert_eq!(
            fs::read_to_string(f.root.join("a.txt")).unwrap(),
            "primary changed"
        );
        assert_eq!(
            fs::read_to_string(external.join("a.txt")).unwrap(),
            "user edit"
        );
        fs::write(external.join("a.txt"), "external changed").unwrap();
        f.tools.undo().unwrap();
        assert_eq!(
            fs::read_to_string(f.root.join("a.txt")).unwrap(),
            "primary original"
        );
    }

    #[tokio::test]
    async fn checkpoint_rejects_external_alias_duplicates_and_state_roots() {
        let mut f = Fixture::new();
        let external = f._temp.path().join("external");
        fs::create_dir_all(external.join("nested")).unwrap();
        f.tools.add_directory(&external).unwrap();
        let out = f
            .call(
                "write_file",
                json!({"path":external.join("nested/new.txt"),"content":"created"}),
            )
            .await;
        assert!(!out.is_error, "{}", out.content);
        let journal = f.state.join(CHECKPOINT_FILE);
        let saved: Value = serde_json::from_slice(&fs::read(&journal).unwrap()).unwrap();
        let mut altered = saved.clone();
        let mut duplicate = altered["turns"][0]["entries"][0].clone();
        duplicate["root"] = json!(fs::canonicalize(external.join("nested")).unwrap());
        duplicate["path"] = json!("new.txt");
        altered["turns"][0]["entries"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        fs::write(&journal, serde_json::to_vec(&altered).unwrap()).unwrap();
        assert!(
            Tools::new(&f.root, &f.state).is_err(),
            "Duplicate effective path accepted"
        );
        for invalid in [
            f.state.clone(),
            f._temp.path().to_path_buf(),
            external.join(".."),
            external.join(".ssh"),
        ] {
            let mut altered = saved.clone();
            altered["turns"][0]["entries"][0]["root"] = json!(invalid);
            fs::write(&journal, serde_json::to_vec(&altered).unwrap()).unwrap();
            assert!(Tools::new(&f.root, &f.state).is_err());
        }
    }

    #[tokio::test]
    async fn absolute_workspace_paths_work_and_external_paths_explain_the_supported_tool() {
        let mut f = Fixture::new();
        let root = f.tools.root().to_path_buf();
        let file = root.join("new.txt");
        let args = json!({"path":file,"content":"local file"});
        assert!(f.tools.preview("write_file", &args).is_ok());
        let out = f.call("write_file", args).await;
        assert!(!out.is_error, "{}", out.content);
        assert_eq!(fs::read_to_string(file).unwrap(), "local file");
        let out = f
            .call("read_file", json!({"path":root.join("new.txt")}))
            .await;
        assert!(!out.is_error, "{}", out.content);
        let external = f._temp.path().join("external.txt");
        let out = f
            .call(
                "write_file",
                json!({"path":external,"content":"must not write"}),
            )
            .await;
        assert!(out.is_error);
        let error: Value = serde_json::from_str(&out.content).expect("Structured path error");
        assert_eq!(error["error"], "outside_workspace");
        assert_eq!(error["next_tool"], "run_command");
        assert!(!external.exists());
        f.tools.undo().unwrap();
        assert!(!root.join("new.txt").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn workspace_root_alias_keeps_ignore_and_child_symlink_policy() {
        use std::os::unix::fs::symlink;
        let mut f = Fixture::new();
        let alias = f._temp.path().join("project-alias");
        symlink(f.tools.root(), &alias).unwrap();
        f.file(".gitignore", "ignored.txt\n");
        let out = f
            .call(
                "write_file",
                json!({"path":alias.join("ok.txt"),"content":"ok"}),
            )
            .await;
        assert!(!out.is_error, "{}", out.content);
        assert_eq!(fs::read_to_string(f.root.join("ok.txt")).unwrap(), "ok");
        let listed = f.call("list_files", json!({"path":alias})).await;
        assert!(
            !listed.is_error && listed.content.contains("ok.txt"),
            "{}",
            listed.content
        );
        let out = f
            .call(
                "write_file",
                json!({"path":alias.join("ignored.txt"),"content":"forbidden"}),
            )
            .await;
        assert!(
            out.is_error && !out.content.contains("outside_workspace"),
            "{}",
            out.content
        );
        assert!(!f.root.join("ignored.txt").exists());
        symlink(f.tools.root(), f.root.join("child-link")).unwrap();
        let out = f
            .call(
                "write_file",
                json!({"path":alias.join("child-link/forbidden.txt"),"content":"forbidden"}),
            )
            .await;
        assert!(
            out.is_error && !out.content.contains("outside_workspace"),
            "{}",
            out.content
        );
        assert!(!f.root.join("forbidden.txt").exists());
    }

    #[tokio::test]
    async fn read_returns_hash_utf8_and_bounded_line_pagination() {
        let mut f = Fixture::new();
        f.file("hello.rs", "Привет\nмир\nтретья\n");
        let out = f
            .call(
                "read_file",
                json!({"path":"hello.rs","start_line":2,"max_lines":1}),
            )
            .await;
        assert!(!out.is_error, "{}", out.content);
        let data: Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(data["sha256"], hash("Привет\nмир\nтретья\n".as_bytes()));
        assert_eq!(data["content"], "2\tмир\n");
        assert_eq!(data["next_line"], 3);
    }

    #[tokio::test]
    async fn invalid_utf8_and_missing_paths_are_regular_errors() {
        let mut f = Fixture::new();
        fs::write(f.root.join("bad.rs"), [0xff, 0xfe]).unwrap();
        assert!(f.call("read_file", json!({"path":"bad.rs"})).await.is_error);
        assert!(
            f.call("read_file", json!({"path":"missing.rs"}))
                .await
                .is_error
        );
        assert!(
            f.call("read_file", json!({"path":"../outside"}))
                .await
                .is_error
        );
        assert!(f.call("read_file", json!({"path":f.state})).await.is_error);
    }

    #[tokio::test]
    async fn ignore_and_secret_policy_applies_to_explicit_paths_and_search() {
        let mut f = Fixture::new();
        fs::create_dir_all(f.root.join(".git/info")).unwrap();
        fs::create_dir_all(f.root.join("nested")).unwrap();
        f.file(".git/info/exclude", "internal/\nlocal.rs\n");
        f.file(".gitignore", "ignored.rs\n");
        f.file("nested/.gitignore", "hidden.rs\n!keep.rs\n");
        for name in [
            "local.rs",
            "ignored.rs",
            ".env.example",
            "server.pem",
            "private.key",
            "nested/hidden.rs",
            "nested/keep.rs",
            "main.rs",
        ] {
            f.file(name, "needle");
        }
        for name in [
            "local.rs",
            "ignored.rs",
            ".env.example",
            "server.pem",
            "private.key",
            "nested/hidden.rs",
            ".git/info/exclude",
        ] {
            assert!(
                f.call("read_file", json!({"path":name})).await.is_error,
                "{name}"
            );
            assert!(f.write(name, "changed").await.is_error, "{name}");
        }
        let out = f.call("search", json!({"pattern":"needle"})).await;
        assert!(!out.is_error, "{}", out.content);
        let data: Value = serde_json::from_str(&out.content).unwrap();
        let found = data["matches"].as_array().unwrap();
        assert_eq!(found.len(), 2, "{}", out.content);
        assert!(
            !f.call("read_file", json!({"path":"main.rs"}))
                .await
                .is_error
        );
    }

    #[tokio::test]
    async fn workspace_wal_stage_prefix_is_denied_and_hidden_from_traversal() {
        let mut fixture = Fixture::new();
        let stage = ".rcode-wal-123e4567-e89b-42d3-a456-426614174000.stage";
        fs::create_dir(fixture.root.join(stage)).unwrap();
        fs::write(fixture.root.join(stage).join(".gitignore"), "*\n").unwrap();
        fs::write(fixture.root.join(stage).join("payload"), "private marker").unwrap();

        for path in [
            format!("{stage}/payload"),
            format!("{stage}/.gitignore"),
            stage.to_owned(),
        ] {
            assert!(
                fixture
                    .call("read_file", json!({"path":path}))
                    .await
                    .is_error
            );
            assert!(fixture.write(&path, "overwrite").await.is_error);
        }
        let listing = fixture.call("list_files", json!({"path":"."})).await;
        assert!(!listing.is_error, "{}", listing.content);
        assert!(!listing.content.contains(stage));
        let search = fixture
            .call("search", json!({"pattern":"private marker"}))
            .await;
        assert!(!search.is_error, "{}", search.content);
        assert!(!search.content.contains("private marker"));
        assert_eq!(
            fs::read(fixture.root.join(stage).join("payload")).unwrap(),
            b"private marker"
        );
    }

    #[test]
    fn workspace_wal_stage_prefix_is_a_reserved_component() {
        for component in [
            ".rcode-wal-123e4567-e89b-42d3-a456-426614174000.stage",
            ".RCode-Wal-user-file",
        ] {
            assert!(secret_component(std::ffi::OsStr::new(component)));
        }
        assert!(!secret_component(std::ffi::OsStr::new(
            "ordinary.rcode-wal-file"
        )));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_escape_and_alias_to_ignored_files_are_rejected() {
        use std::os::unix::fs::symlink;
        let mut f = Fixture::new();
        let outside = f._temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("secret"), "outside").unwrap();
        symlink(&outside, f.root.join("escape")).unwrap();
        f.file(".gitignore", "hidden.rs\n");
        f.file("hidden.rs", "private");
        symlink("hidden.rs", f.root.join("alias.rs")).unwrap();
        assert!(
            f.call("read_file", json!({"path":"escape/secret"}))
                .await
                .is_error
        );
        assert!(f.write("escape/new", "bad").await.is_error);
        assert!(!outside.join("new").exists());
        assert!(
            f.call("read_file", json!({"path":"alias.rs"}))
                .await
                .is_error
        );
    }

    #[tokio::test]
    async fn write_without_model_hash_uses_successful_read_snapshot_and_preserves_undo() {
        let mut f = Fixture::new();
        f.file("a.rs", "user original\n");
        f.tools.begin_turn().unwrap();
        let read = f.call("read_file", json!({"path":"a.rs"})).await;
        assert!(!read.is_error, "{}", read.content);
        let args = json!({"path":f.root.join("a.rs"),"content":"agent change\n"});
        assert!(f.tools.preview("write_file", &args).is_ok());
        let out = f.call("write_file", args).await;
        assert!(!out.is_error, "{}", out.content);
        assert_eq!(
            fs::read_to_string(f.root.join("a.rs")).unwrap(),
            "agent change\n"
        );
        f.tools.undo().unwrap();
        assert_eq!(
            fs::read_to_string(f.root.join("a.rs")).unwrap(),
            "user original\n"
        );
    }

    #[tokio::test]
    async fn read_snapshot_never_overrides_explicit_hash_or_changes_after_read() {
        let mut f = Fixture::new();
        f.file("a.rs", "old");
        assert!(!f.call("read_file", json!({"path":"a.rs"})).await.is_error);
        let bad_hash = f
            .call(
                "write_file",
                json!({"path":"a.rs","content":"bad","expected_sha256":hash(b"wrong")}),
            )
            .await;
        assert!(bad_hash.is_error);
        let args = json!({"path":"a.rs","content":"agent"});
        assert!(f.tools.preview("write_file", &args).is_ok());
        f.file("a.rs", "user changed after preview");
        assert!(f.call("write_file", args).await.is_error);
        assert_eq!(
            fs::read_to_string(f.root.join("a.rs")).unwrap(),
            "user changed after preview"
        );
    }

    #[tokio::test]
    async fn external_read_snapshot_matches_aliases_but_not_same_named_workspace_files() {
        let mut f = Fixture::new();
        let external = f._temp.path().join("external");
        fs::create_dir(&external).unwrap();
        fs::write(external.join("same.txt"), "external").unwrap();
        f.file("same.txt", "workspace");
        f.tools.add_directory(&external).unwrap();
        assert!(
            !f.call("read_file", json!({"path":external.join("same.txt")}))
                .await
                .is_error
        );
        assert!(
            f.call(
                "write_file",
                json!({"path":"same.txt","content":"must fail"})
            )
            .await
            .is_error
        );
        let out = f.call("write_file", json!({"path":external.join("same.txt"),"content":"changed","expected_sha256":null})).await;
        assert!(!out.is_error, "{}", out.content);
        assert_eq!(
            fs::read_to_string(f.root.join("same.txt")).unwrap(),
            "workspace"
        );
    }

    #[tokio::test]
    async fn read_snapshot_is_not_reused_across_turns_or_restored_from_disk() {
        let mut f = Fixture::new();
        f.file("a.rs", "user original");
        assert!(!f.call("read_file", json!({"path":"a.rs"})).await.is_error);
        f.tools.begin_turn().unwrap();
        let args = json!({"path":"a.rs","content":"must fail"});
        assert!(f.call("write_file", args.clone()).await.is_error);
        assert!(!f.call("read_file", json!({"path":"a.rs"})).await.is_error);
        drop(f.tools);
        f.tools = Tools::new(&f.root, &f.state).unwrap();
        assert!(f.call("write_file", args).await.is_error);
        assert_eq!(
            fs::read_to_string(f.root.join("a.rs")).unwrap(),
            "user original"
        );
    }

    #[tokio::test]
    async fn stale_write_requires_fresh_read_hash_at_execution() {
        let mut f = Fixture::new();
        f.file("a.rs", "old");
        let args = json!({"path":"a.rs","content":"agent","expected_sha256":hash(b"old")});
        assert!(f.tools.preview("write_file", &args).unwrap().is_some());
        f.file("a.rs", "user");
        assert!(f.call("write_file", args).await.is_error);
        assert_eq!(fs::read_to_string(f.root.join("a.rs")).unwrap(), "user");
        assert!(
            f.call("write_file", json!({"path":"a.rs","content":"no hash"}))
                .await
                .is_error
        );
    }

    #[tokio::test]
    async fn edit_is_exact_unique_unless_replace_all_explicit() {
        let mut f = Fixture::new();
        f.file("a.rs", "кот кот\n");
        assert!(
            f.call(
                "edit_file",
                json!({"path":"a.rs","old_text":"кот","new_text":"пёс"})
            )
            .await
            .is_error
        );
        assert!(
            f.call(
                "edit_file",
                json!({"path":"a.rs","old_text":"","new_text":"x"})
            )
            .await
            .is_error
        );
        assert!(
            !f.call(
                "edit_file",
                json!({"path":"a.rs","old_text":"кот","new_text":"пёс","replace_all":true})
            )
            .await
            .is_error
        );
        assert_eq!(
            fs::read_to_string(f.root.join("a.rs")).unwrap(),
            "пёс пёс\n"
        );
    }

    #[tokio::test]
    async fn undo_keeps_original_wip_across_multiple_writes_and_resume() {
        let mut f = Fixture::new();
        f.file("wip.rs", "user uncommitted");
        f.tools.begin_turn().unwrap();
        assert!(!f.write("wip.rs", "first").await.is_error);
        assert!(!f.write("wip.rs", "second").await.is_error);
        drop(f.tools);
        let mut resumed = Tools::new(&f.root, &f.state).unwrap();
        assert!(resumed.diff().unwrap().contains("user uncommitted"));
        resumed.undo().unwrap();
        assert_eq!(
            fs::read_to_string(f.root.join("wip.rs")).unwrap(),
            "user uncommitted"
        );
    }

    #[tokio::test]
    async fn undo_new_file_and_turns_are_lifo() {
        let mut f = Fixture::new();
        f.tools.begin_turn().unwrap();
        assert!(!f.write("new.rs", "one").await.is_error);
        f.tools.begin_turn().unwrap();
        assert!(!f.write("new.rs", "two").await.is_error);
        f.tools.undo().unwrap();
        assert_eq!(fs::read_to_string(f.root.join("new.rs")).unwrap(), "one");
        f.tools.undo().unwrap();
        assert!(!f.root.join("new.rs").exists());
    }

    #[tokio::test]
    async fn undo_preflight_rejects_whole_batch_on_any_conflict() {
        let mut f = Fixture::new();
        f.file("a.rs", "A");
        f.file("b.rs", "B");
        f.tools.begin_turn().unwrap();
        assert!(!f.write("a.rs", "agent A").await.is_error);
        assert!(!f.write("b.rs", "agent B").await.is_error);
        f.file("b.rs", "user B");
        assert!(f.tools.undo().is_err());
        assert_eq!(fs::read_to_string(f.root.join("a.rs")).unwrap(), "agent A");
        assert_eq!(fs::read_to_string(f.root.join("b.rs")).unwrap(), "user B");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn atomic_write_and_undo_preserve_executable_mode_and_private_checkpoint() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mut f = Fixture::new();
        f.file("script.sh", "original");
        fs::set_permissions(f.root.join("script.sh"), fs::Permissions::from_mode(0o751)).unwrap();
        assert!(!f.write("script.sh", "changed").await.is_error);
        assert_eq!(
            fs::metadata(f.root.join("script.sh")).unwrap().mode() & 0o777,
            0o751
        );
        f.tools.undo().unwrap();
        assert_eq!(
            fs::metadata(f.root.join("script.sh")).unwrap().mode() & 0o777,
            0o751
        );
        assert_eq!(fs::metadata(&f.state).unwrap().mode() & 0o777, 0o700);
        for file in fs::read_dir(&f.state).unwrap() {
            let metadata = file.unwrap().metadata().unwrap();
            if metadata.is_file() {
                assert_eq!(metadata.mode() & 0o777, 0o600);
            }
        }
    }

    #[tokio::test]
    async fn bounded_search_listing_and_cancellation() {
        let mut f = Fixture::new();
        for i in 0..8 {
            f.file(&format!("file{i}.rs"), "x\nx\nx\n");
        }
        let out = f.call("list_files", json!({"max_results":2})).await;
        assert!(!out.is_error, "{}", out.content);
        let data: Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(data["files"].as_array().unwrap().len(), 2);
        assert_eq!(data["truncated"], true);
        let out = f
            .call("search", json!({"pattern":"x","max_results":2}))
            .await;
        let data: Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(data["matches"].as_array().unwrap().len(), 2);
        assert!(
            f.call("search", json!({"pattern":"x".repeat(5000)}))
                .await
                .is_error
        );
        let cancel = CancellationToken::new();
        cancel.cancel();
        let out = f
            .tools
            .execute("search", &json!({"pattern":"x"}), &cancel)
            .await
            .unwrap();
        assert!(out.is_error);
    }

    #[tokio::test]
    async fn search_cooperatively_observes_cancellation_during_the_walk() {
        let mut f = Fixture::new();
        for i in 0..100 {
            f.file(&format!("file{i}.rs"), "needle\n");
        }
        let cancel = CancellationToken::new();
        let trigger = cancel.clone();
        let args = json!({"pattern":"needle"});
        let (out, _) = tokio::join!(f.tools.execute("search", &args, &cancel), async move {
            tokio::task::yield_now().await;
            trigger.cancel();
        });
        assert!(out.unwrap().is_error);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn command_captures_stderr_nonzero_and_only_allowlisted_environment() {
        let mut f = Fixture::new();
        let out = f
            .call(
                "run_command",
                json!({"command":"printf hello; printf problem >&2; exit 7"}),
            )
            .await;
        assert!(out.is_error);
        let data: Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(data["exit_code"], 7);
        assert_eq!(data["stdout"], "hello");
        assert_eq!(data["stderr"], "problem");
        let out = f
            .call("run_command", json!({"command":"/usr/bin/env"}))
            .await;
        assert!(!out.is_error, "{}", out.content);
        let data: Value = serde_json::from_str(&out.content).unwrap();
        for line in data["stdout"].as_str().unwrap().lines() {
            let (key, _) = line.split_once('=').unwrap();
            assert!(
                matches!(
                    key,
                    "PATH"
                        | "HOME"
                        | "USER"
                        | "LOGNAME"
                        | "LANG"
                        | "TMPDIR"
                        | "TEMP"
                        | "TMP"
                        | "SYSTEMROOT"
                        | "COMSPEC"
                        | "PATHEXT"
                        | "PWD"
                        | "SHLVL"
                        | "RCODE_MODEL_SHELL"
                        | "_"
                ) || key.starts_with("LC_"),
                "unexpected {key}"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn command_timeout_cancellation_and_output_limit_do_not_hang() {
        let mut f = Fixture::new();
        let out = f
            .call(
                "run_command",
                json!({"command":"sleep 20","timeout_secs":1}),
            )
            .await;
        assert!(out.is_error);
        assert!(out.content.contains("timeout"));
        let cancel = CancellationToken::new();
        let trigger = cancel.clone();
        let started = std::time::Instant::now();
        let args = json!({"command":"sleep 20"});
        let (_, out) = tokio::join!(
            async move {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                trigger.cancel();
            },
            f.tools.execute("run_command", &args, &cancel)
        );
        assert!(out.unwrap().is_error);
        assert!(started.elapsed().as_secs() < 5);
        let out = f.call("run_command", json!({"command":"yes x"})).await;
        assert!(out.is_error);
        assert!(out.content.contains("output_limit"));
        assert!(out.content.len() < 140_000);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn shell_changes_to_tracked_files_remain_undo_conflicts() {
        let mut f = Fixture::new();
        f.file("a.rs", "user");
        assert!(!f.write("a.rs", "agent").await.is_error);
        assert!(
            !f.call("run_command", json!({"command":"printf shell > a.rs"}))
                .await
                .is_error
        );
        assert!(f.tools.undo().is_err());
        assert_eq!(fs::read_to_string(f.root.join("a.rs")).unwrap(), "shell");
        assert!(f.tools.diff().unwrap().contains("shell"));
    }

    #[tokio::test]
    async fn overlapping_edit_matches_are_ambiguous() {
        let mut f = Fixture::new();
        f.file("a.rs", "aaa");
        let out = f
            .call(
                "edit_file",
                json!({"path":"a.rs","old_text":"aa","new_text":"b"}),
            )
            .await;
        assert!(out.is_error);
        assert_eq!(fs::read_to_string(f.root.join("a.rs")).unwrap(), "aaa");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn listing_skips_non_utf8_names_without_panicking() {
        use std::os::unix::ffi::OsStringExt;
        let mut f = Fixture::new();
        fs::write(
            f.root
                .join(OsString::from_vec(vec![0xff, b'.', b'r', b's'])),
            "x",
        )
        .unwrap();
        f.file("valid.rs", "x");
        let out = f.call("list_files", json!({})).await;
        assert!(!out.is_error, "{}", out.content);
        let data: Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(data["files"], json!(["valid.rs"]));
    }

    #[tokio::test]
    async fn checkpoint_failure_is_fatal_and_prevents_workspace_write() {
        let mut f = Fixture::new();
        f.file("a.rs", "user");
        fs::create_dir(f.state.join(CHECKPOINT_FILE)).unwrap();
        let out = f
            .tools
            .execute(
                "write_file",
                &json!({"path":"a.rs","content":"agent","expected_sha256":hash(b"user")}),
                &CancellationToken::new(),
            )
            .await;
        assert!(out.is_err(), "write должен упасть на checkpoint: {out:?}");
        assert_eq!(fs::read_to_string(f.root.join("a.rs")).unwrap(), "user");
    }

    #[tokio::test]
    async fn ignored_parent_cannot_be_reincluded_by_nested_ignore() {
        let mut f = Fixture::new();
        fs::create_dir(f.root.join("private")).unwrap();
        f.file(".gitignore", "private/\n");
        f.file("private/.gitignore", "!visible.rs\n");
        f.file("private/visible.rs", "user");
        assert!(
            f.call("read_file", json!({"path":"private/visible.rs"}))
                .await
                .is_error
        );
        assert!(f.write("private/new.rs", "agent").await.is_error);
        assert!(!f.root.join("private/new.rs").exists());
    }

    #[tokio::test]
    async fn undo_never_deletes_a_user_modified_new_file() {
        let mut f = Fixture::new();
        assert!(!f.write("new.rs", "agent").await.is_error);
        f.file("new.rs", "user");
        assert!(f.tools.undo().is_err());
        assert_eq!(fs::read_to_string(f.root.join("new.rs")).unwrap(), "user");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn user_chmod_on_tracked_file_is_an_undo_conflict() {
        use std::os::unix::fs::PermissionsExt;
        let mut f = Fixture::new();
        f.file("a.rs", "before");
        fs::set_permissions(f.root.join("a.rs"), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!f.write("a.rs", "agent").await.is_error);
        fs::set_permissions(f.root.join("a.rs"), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(f.tools.undo().is_err());
        assert_eq!(fs::read_to_string(f.root.join("a.rs")).unwrap(), "agent");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn command_drains_both_streams_and_kills_background_descendants() {
        let mut f = Fixture::new();
        let out = f.call("run_command", json!({"command":"i=0; while [ $i -lt 1000 ]; do printf 'out\\n'; printf 'err\\n' >&2; i=$((i+1)); done"})).await;
        assert!(!out.is_error, "{}", out.content);
        let data: Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(data["stdout"].as_str().unwrap().lines().count(), 1000);
        assert_eq!(data["stderr"].as_str().unwrap().lines().count(), 1000);
        let out = f.call("run_command", json!({"command":"(sleep 0.3; printf alive > escaped.txt) & wait", "timeout_secs":1})).await;
        assert!(!out.is_error, "{}", out.content);
        fs::remove_file(f.root.join("escaped.txt")).unwrap();
        let out = f
            .call(
                "run_command",
                json!({"command":"(sleep 0.3; printf alive > escaped.txt) &"}),
            )
            .await;
        assert!(!out.is_error, "{}", out.content);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(!f.root.join("escaped.txt").exists());
    }

    #[tokio::test]
    async fn write_observations_stay_isolated_per_actor_and_skip_uncommitted_wal_writes() {
        let mut f = Fixture::new();
        let cancel = CancellationToken::new();

        // Worker A creates a file and can overwrite it, while Worker B has no observation.
        let created = f
            .tools
            .execute_for(
                "write_file",
                &json!({"path":"shared.py","content":"v1\n"}),
                &cancel,
                Some("worker-a"),
            )
            .await
            .unwrap();
        assert!(!created.is_error, "{}", created.content);

        let worker_b_blind = f
            .tools
            .execute_for(
                "write_file",
                &json!({"path":"shared.py","content":"hijack\n"}),
                &cancel,
                Some("worker-b"),
            )
            .await
            .unwrap();
        assert!(worker_b_blind.is_error);

        // Worker B reads v1, then Worker A writes v2: Worker B's observation stays stale
        // and blocks even an explicit expected_sha256 for v2 until Worker B re-reads.
        let worker_b_read = f
            .tools
            .execute_for(
                "read_file",
                &json!({"path":"shared.py"}),
                &cancel,
                Some("worker-b"),
            )
            .await
            .unwrap();
        assert!(!worker_b_read.is_error);

        let worker_a_v2 = f
            .tools
            .execute_for(
                "write_file",
                &json!({"path":"shared.py","content":"v2\n"}),
                &cancel,
                Some("worker-a"),
            )
            .await
            .unwrap();
        assert!(!worker_a_v2.is_error, "{}", worker_a_v2.content);

        let worker_b_explicit = f
            .tools
            .execute_for(
                "write_file",
                &json!({
                    "path": "shared.py",
                    "content": "v3\n",
                    "expected_sha256": hash(b"v2\n"),
                }),
                &cancel,
                Some("worker-b"),
            )
            .await
            .unwrap();
        assert!(
            worker_b_explicit.is_error,
            "stale actor observation must not be deleted or updated by another actor's write"
        );

        // If WAL final persistence fails after workspace publication, no new observation is granted.
        f.tools.fail_store_after_wal_point(
            WalFaultPoint::BeforeFinalPersist,
            crate::file_wal::StoreFaultPoint::ManifestBeforeRename,
            libc::EIO,
        );
        let uncommitted = f
            .tools
            .execute_for(
                "write_file",
                &json!({"path":"uncommitted.py","content":"staged\n"}),
                &cancel,
                Some("worker-a"),
            )
            .await;
        assert!(uncommitted.is_err());
        assert!(
            !f.tools
                .read_snapshots
                .contains_key(&(Some("worker-a".into()), f.root.join("uncommitted.py"))),
            "failed WAL finalize must never record a read observation"
        );
    }

    #[tokio::test]
    async fn edit_file_two_stage_fallback_preserves_crlf_and_observation_chain() {
        let mut f = Fixture::new();
        fs::write(
            f.root.join("service.rs"),
            b"fn a() {\r\n    let x = 1;   \r\n}\r\n",
        )
        .unwrap();
        assert!(
            !f.call("read_file", json!({"path": "service.rs"}))
                .await
                .is_error
        );

        let first = f
            .call(
                "edit_file",
                json!({
                    "path": "service.rs",
                    "old_text": "fn a() {\n    let x = 1;\n}",
                    "new_text": "fn a() {\n    let x = 2;\n    let y = 3;\n}",
                }),
            )
            .await;
        assert!(!first.is_error, "{}", first.content);
        assert_eq!(
            fs::read(f.root.join("service.rs")).unwrap(),
            b"fn a() {\r\n    let x = 2;\r\n    let y = 3;\r\n}\r\n"
        );

        let second = f
            .call(
                "edit_file",
                json!({
                    "path": "service.rs",
                    "old_text": "    let y = 3;\n",
                    "new_text": "    let y = 42;\n",
                }),
            )
            .await;
        assert!(!second.is_error, "{}", second.content);
        assert_eq!(
            fs::read(f.root.join("service.rs")).unwrap(),
            b"fn a() {\r\n    let x = 2;\r\n    let y = 42;\r\n}\r\n"
        );
    }

    #[tokio::test]
    async fn approved_write_rejects_concurrent_modification_between_preview_and_execute() {
        let mut f = Fixture::new();
        let cancel = CancellationToken::new();

        // 1) edit_file where old_text still uniquely matches after a concurrent operator edit:
        //    prepare() alone would succeed, so ApprovedWrite must reject the changed diff/hash.
        f.file("service.toml", "port = 8080\n");
        let args_edit = json!({
            "path": "service.toml",
            "old_text": "port = 8080",
            "new_text": "port = 9090",
        });
        let (preview, approved_edit) = f
            .tools
            .preview_write_for("edit_file", &args_edit, None)
            .unwrap();
        assert!(preview.contains("+++ b/service.toml"), "{preview}");
        fs::write(
            f.root.join("service.toml"),
            "# operator comment\nport = 8080\n",
        )
        .unwrap();

        let rejected_diff = f
            .tools
            .execute_for_approved("edit_file", &args_edit, &cancel, None, Some(&approved_edit))
            .await
            .unwrap();
        assert!(rejected_diff.is_error, "{}", rejected_diff.content);
        assert!(
            rejected_diff
                .content
                .contains("Файл изменился после подготовки diff"),
            "{}",
            rejected_diff.content
        );
        assert_eq!(
            fs::read_to_string(f.root.join("service.toml")).unwrap(),
            "# operator comment\nport = 8080\n"
        );
        assert!(f.tools.undo().unwrap().contains("Нет файловых правок"));

        // 2) Brand-new file previewed while absent, then concurrently created before write().
        let args_new = json!({"path": "created.toml", "content": "agent = true\n"});
        let (_, approved_new) = f
            .tools
            .preview_write_for("write_file", &args_new, None)
            .unwrap();
        assert!(approved_new.before_sha256.is_none());
        fs::write(f.root.join("created.toml"), "operator = true\n").unwrap();

        let rejected_new = f
            .tools
            .execute_for_approved("write_file", &args_new, &cancel, None, Some(&approved_new))
            .await
            .unwrap();
        assert!(rejected_new.is_error, "{}", rejected_new.content);
        assert_eq!(
            fs::read_to_string(f.root.join("created.toml")).unwrap(),
            "operator = true\n"
        );

        // 3) Existing unread file replaced at a new inode with identical bytes on Unix.
        #[cfg(unix)]
        {
            f.file("config.toml", "port = 8080\n");
            let args_inode = json!({
                "path": "config.toml",
                "old_text": "port = 8080",
                "new_text": "port = 9090",
            });
            let (_, approved_inode) = f
                .tools
                .preview_write_for("edit_file", &args_inode, None)
                .unwrap();
            let replacement = f.root.join("config.toml.tmp");
            fs::write(&replacement, "port = 8080\n").unwrap();
            fs::rename(&replacement, f.root.join("config.toml")).unwrap();

            let rejected_inode = f
                .tools
                .execute_for_approved(
                    "edit_file",
                    &args_inode,
                    &cancel,
                    None,
                    Some(&approved_inode),
                )
                .await
                .unwrap();
            assert!(rejected_inode.is_error, "{}", rejected_inode.content);
            assert!(
                rejected_inode
                    .content
                    .contains("Файл изменился после подготовки diff"),
                "{}",
                rejected_inode.content
            );
            assert_eq!(
                fs::read_to_string(f.root.join("config.toml")).unwrap(),
                "port = 8080\n"
            );
        }
    }

    #[tokio::test]
    async fn write_file_creates_missing_parents_only_after_approval_and_cleans_empty_dirs_on_undo()
    {
        let mut f = Fixture::new();
        let cancel = CancellationToken::new();

        // 1) preview_write_for is strictly side-effect free (simulating operator denial).
        let nested_args = json!({
            "path": "app/api/v1/main.py",
            "content": "def health():\n    return {'ok': True}\n",
        });
        let (diff, approved) = f
            .tools
            .preview_write_for("write_file", &nested_args, None)
            .unwrap();
        assert!(diff.contains("+++ b/app/api/v1/main.py"), "{diff}");
        assert!(!f.root.join("app").exists());

        // 2) TOCTOU: if first missing dir appears before execute_for_approved, reject without mutating.
        fs::create_dir(f.root.join("app")).unwrap();
        let raced = f
            .tools
            .execute_for_approved("write_file", &nested_args, &cancel, None, Some(&approved))
            .await
            .unwrap();
        assert!(raced.is_error, "{}", raced.content);
        assert!(
            raced
                .content
                .contains("Файл изменился после подготовки diff"),
            "{}",
            raced.content
        );
        assert!(!f.root.join("app/api").exists());
        fs::remove_dir(f.root.join("app")).unwrap();

        // 3) TOCTOU: replacing an existing ancestor inode before execute_for_approved is also rejected.
        #[cfg(unix)]
        {
            fs::create_dir(f.root.join("existing")).unwrap();
            let sub_args = json!({"path": "existing/sub/mod.py", "content": "x = 1\n"});
            let (_, sub_approved) = f
                .tools
                .preview_write_for("write_file", &sub_args, None)
                .unwrap();
            fs::rename(f.root.join("existing"), f.root.join("existing_old")).unwrap();
            fs::create_dir(f.root.join("existing")).unwrap();
            let inode_raced = f
                .tools
                .execute_for_approved("write_file", &sub_args, &cancel, None, Some(&sub_approved))
                .await
                .unwrap();
            assert!(inode_raced.is_error, "{}", inode_raced.content);
            assert!(!f.root.join("existing/sub").exists());
            fs::remove_dir(f.root.join("existing")).unwrap();
            fs::remove_dir(f.root.join("existing_old")).unwrap();
        }

        // 4) Approved execution creates missing parents, records observation, and preserves
        //    created_parents across a same-turn edit/overwrite; undo removes file + empty dirs.
        let created = f
            .tools
            .execute_for_approved("write_file", &nested_args, &cancel, None, Some(&approved))
            .await
            .unwrap();
        assert!(!created.is_error, "{}", created.content);
        assert!(f.root.join("app/api/v1/main.py").is_file());

        let edited = f
            .call(
                "edit_file",
                json!({
                    "path": "app/api/v1/main.py",
                    "old_text": "return {'ok': True}",
                    "new_text": "return {'status': 'ok'}",
                }),
            )
            .await;
        assert!(!edited.is_error, "{}", edited.content);
        f.tools.undo().unwrap();
        assert!(!f.root.join("app").exists());

        // 5) Writing into an already-existing directory omits created_parents from manifest JSON.
        f.tools.begin_turn().unwrap();
        assert!(
            !f.call(
                "write_file",
                json!({"path": "root_file.txt", "content": "hi\n"})
            )
            .await
            .is_error
        );
        let raw_manifest = fs::read_to_string(f.state.join(CHECKPOINT_FILE)).unwrap();
        assert!(
            !raw_manifest.contains("created_parents"),
            "created_parents=0 must be omitted: {raw_manifest}"
        );
        f.tools.undo().unwrap();

        // 6) User-created file inside a created directory keeps the non-empty ancestors on undo.
        f.tools.begin_turn().unwrap();
        assert!(
            !f.call(
                "write_file",
                json!({"path": "pkg/deep/leaf/gen.py", "content": "v = 1\n"}),
            )
            .await
            .is_error
        );
        fs::write(f.root.join("pkg/deep/user_notes.md"), "keep me\n").unwrap();
        f.tools.undo().unwrap();
        assert!(!f.root.join("pkg/deep/leaf").exists());
        assert_eq!(
            fs::read_to_string(f.root.join("pkg/deep/user_notes.md")).unwrap(),
            "keep me\n"
        );

        // 7) Earlier committed turn referencing a parent directory keeps that parent on partial undo.
        f.tools.begin_turn().unwrap();
        assert!(
            !f.call(
                "write_file",
                json!({"path": "shared/first.txt", "content": "1\n"}),
            )
            .await
            .is_error
        );
        f.tools.begin_turn().unwrap();
        assert!(
            !f.call(
                "write_file",
                json!({"path": "shared/sub/second.txt", "content": "2\n"}),
            )
            .await
            .is_error
        );
        f.tools.undo().unwrap();
        assert!(!f.root.join("shared/sub").exists());
        assert!(f.root.join("shared/first.txt").is_file());
        f.tools.undo().unwrap();
        assert!(!f.root.join("shared").exists());
    }

    #[tokio::test]
    async fn write_file_missing_parents_enforce_gitignore_secrets_symlinks_and_grant_boundaries() {
        let mut f = Fixture::new();
        f.file(".gitignore", "target/\nbuild/\n");
        f.file("README.md", "hello\n");

        // Directory-only gitignore rules (`target/`, `build/`) must block missing subtrees before mkdir.
        for blocked in [
            "target/out.txt",
            "build/nested/artifact.json",
            "newdir/.env",
            "newdir/.git/config",
            "newdir/secrets/key.txt",
            "newdir/.rcode-wal-fake/x.txt",
            "README.md/sub/file.txt",
            ".",
        ] {
            let out = f
                .call("write_file", json!({"path": blocked, "content": "bad\n"}))
                .await;
            assert!(out.is_error, "expected {blocked} to fail: {}", out.content);
        }
        assert!(!f.root.join("target").exists());
        assert!(!f.root.join("build").exists());
        assert!(!f.root.join("newdir").exists());

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(f.state.as_path(), f.root.join("symdir")).unwrap();
            let sym = f
                .call(
                    "write_file",
                    json!({"path": "symdir/sub/escape.txt", "content": "no\n"}),
                )
                .await;
            assert!(sym.is_error);
            assert!(!f.state.join("sub").exists());
        }

        // edit_file and read_file still require existing directories.
        assert!(
            f.call(
                "edit_file",
                json!({"path": "missing/file.txt", "old_text": "a", "new_text": "b"}),
            )
            .await
            .is_error
        );
        assert!(!f.root.join("missing").exists());

        // External grant boundary: ungranted missing parent still fails; granted external root allows subdirs.
        let ext_holder = tempfile::tempdir().unwrap();
        let ext_root = fs::canonicalize(ext_holder.path()).unwrap();
        let ungranted_nested = ext_root.join("ungranted_sub/file.txt");
        assert!(
            f.tools
                .extra_directory_for(
                    "write_file",
                    &json!({"path": ungranted_nested, "content": "x\n"}),
                )
                .is_err()
        );
        assert!(!ext_root.join("ungranted_sub").exists());

        f.tools.add_directory(&ext_root).unwrap();
        let granted_nested = ext_root.join("created_ext/deep/file.txt");
        assert_eq!(
            f.tools
                .extra_directory_for(
                    "write_file",
                    &json!({"path": granted_nested, "content": "x\n"}),
                )
                .unwrap(),
            None
        );
        let ext_write = f
            .call(
                "write_file",
                json!({"path": granted_nested, "content": "ext-ok\n"}),
            )
            .await;
        assert!(!ext_write.is_error, "{}", ext_write.content);
        assert_eq!(fs::read_to_string(&granted_nested).unwrap(), "ext-ok\n");
        f.tools.undo().unwrap();
        assert!(!ext_root.join("created_ext").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn write_file_missing_parents_preserve_wal_recovery_and_orphan_stage_invariants() {
        // 1) Cancellation before publication cleans stage and newly created empty directories.
        let mut f = Fixture::new();
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        f.tools.before_publication_hook = Some(Box::new(move || {
            cancel_clone.cancel();
        }));
        let cancelled = f
            .tools
            .execute(
                "write_file",
                &json!({"path": "cancelled/sub/file.txt", "content": "data\n"}),
                &cancel,
            )
            .await
            .unwrap();
        assert!(cancelled.is_error);
        assert!(!f.root.join("cancelled").exists());

        // 2) Pre-write_manifest_atomic persist error inside cleanup_committed_stage restores
        //    in-memory orphan_stages and preserves the created parent directory for reopen.
        let mut f2 = Fixture::new();
        assert!(
            !f2.call(
                "write_file",
                json!({"path": "orphan_keep/sub/a.txt", "content": "ok\n"}),
            )
            .await
            .is_error
        );
        let fake_stage = crate::workspace_stage::StageDirectory::plan_name();
        let committed = f2.tools.checkpoints.turns[0].entries[0].clone();
        let root_path = f2.tools.root().to_path_buf();
        let parent_dir = Dir::open_ambient_dir(
            f2.root.join("orphan_keep/sub"),
            cap_std::ambient_authority(),
        )
        .unwrap();
        let real_stage =
            crate::workspace_stage::StageDirectory::create_empty(&parent_dir, &fake_stage)
                .unwrap()
                .reference();
        drop(parent_dir);
        f2.tools
            .record_orphan_stage(
                &root_path,
                &committed.path,
                &real_stage,
                5,
                committed.binding.as_deref().unwrap(),
            )
            .unwrap();
        f2.tools.persist().unwrap();
        // Widen state dir permissions so blob_store.check() fails BEFORE write_manifest_atomic
        // without setting wal_poisoned!
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&f2.state, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let cleanup_err = f2
            .tools
            .cleanup_committed_stage(&committed, &real_stage, None)
            .unwrap_err();
        assert!(
            !f2.tools.wal_poisoned,
            "precheck error must not poison WAL: {cleanup_err:#}"
        );
        assert_eq!(
            f2.tools.checkpoints.orphan_stages.len(),
            1,
            "failed persist in cleanup_committed_stage must restore prior_orphans"
        );
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&f2.state, fs::Permissions::from_mode(0o700)).unwrap();
        }
        // Because orphan_stages still references orphan_keep/sub (even though physical stage was removed),
        // undo removes a.txt but keeps orphan_keep/sub!
        f2.tools.undo().unwrap();
        assert!(!f2.root.join("orphan_keep/sub/a.txt").exists());
        assert!(
            f2.root.join("orphan_keep/sub").is_dir(),
            "directory referenced by orphan_stages (even without physical stage) must be kept"
        );
        let root2 = f2.root.clone();
        let state2 = f2.state.clone();
        drop(f2.tools);
        let _reopened2 = Tools::new(&root2, &state2).unwrap();

        // 3) Post-rename persist failure (`ManifestAfterRenameBeforeDirSync` -> `wal_poisoned`)
        //    preserves created directories so reopen + reconcile_pending_write succeeds.
        let mut f3 = Fixture::new();
        f3.tools.fail_store_after_wal_point(
            WalFaultPoint::StageCreated { index: 0 },
            crate::file_wal::StoreFaultPoint::ManifestAfterRenameBeforeDirSync,
            libc::EIO,
        );
        let poisoned_res = f3
            .tools
            .execute(
                "write_file",
                &json!({"path": "poisoned/deep/file.txt", "content": "hello\n"}),
                &CancellationToken::new(),
            )
            .await;
        assert!(poisoned_res.is_err());
        assert!(f3.tools.wal_poisoned);
        assert!(f3.root.join("poisoned/deep").is_dir());
        let root3 = f3.root.clone();
        let state3 = f3.state.clone();
        drop(f3.tools);
        let reopened3 = Tools::new(&root3, &state3).unwrap();
        assert!(reopened3.checkpoints.pending_write.is_none());

        // 4) Manifest headroom precheck with JSON-escaped `\u{0001}` path segments rejects BEFORE mkdir.
        let mut f4 = Fixture::new();
        f4.tools.begin_turn().unwrap();
        let root_id = f4.tools.root_identity;
        let canonical_root4 = f4.tools.root().to_path_buf();
        let long_parent = PathBuf::from("\u{0001}".repeat(600));
        let one_orphan = OrphanStage {
            root: canonical_root4,
            parent: long_parent,
            stage: crate::workspace_stage::StageRef {
                name: crate::workspace_stage::StageDirectory::plan_name(),
                directory: Some(root_id),
                guard: Some(root_id),
                payload: Some(root_id),
            },
            bytes: 0,
            binding: vec![root_id; 16],
        };
        let one_len = serde_json::to_vec(&one_orphan).unwrap().len() + 1;
        let base_len = serde_json::to_vec(&f4.tools.checkpoints).unwrap().len();
        let count = (crate::file_wal::MAX_MANIFEST_BYTES - 4_500 - base_len) / one_len;
        for _ in 0..count {
            let mut item = one_orphan.clone();
            item.stage.name = crate::workspace_stage::StageDirectory::plan_name();
            f4.tools.checkpoints.orphan_stages.push(item);
        }
        f4.tools.persist().unwrap();
        let escaped_dir = format!("esc-{}", "\u{0001}".repeat(240));
        let escaped_leaf = format!("{escaped_dir}/{}/f.txt", "\u{0001}".repeat(240));
        let over_limit = f4
            .call("write_file", json!({"path": escaped_leaf, "content": "x"}))
            .await;
        assert!(over_limit.is_error, "{}", over_limit.content);
        assert!(
            over_limit.content.contains("WAL manifest"),
            "{}",
            over_limit.content
        );
        assert!(
            !f4.root.join(&escaped_dir).exists(),
            "manifest overflow must be caught before creating any directory"
        );

        // 5) Same-turn external deletion of a tracked nested file + directory is rejected BEFORE mkdir.
        let mut f5 = Fixture::new();
        let first5 = f5
            .tools
            .execute_for(
                "write_file",
                &json!({"path": "vanished/sub/file.txt", "content": "v1\n"}),
                &CancellationToken::new(),
                Some("worker-1"),
            )
            .await
            .unwrap();
        assert!(!first5.is_error, "{}", first5.content);
        fs::remove_dir_all(f5.root.join("vanished")).unwrap();
        let conflict5 = f5
            .tools
            .execute_for(
                "write_file",
                &json!({"path": "vanished/sub/file.txt", "content": "v2\n"}),
                &CancellationToken::new(),
                Some("worker-2"),
            )
            .await
            .unwrap();
        assert!(conflict5.is_error, "{}", conflict5.content);
        assert!(
            !f5.root.join("vanished").exists(),
            "same-turn conflict check must reject before creating missing directories"
        );

        // 6) Cross-root checkpoints_reference_dir protects `/ext/narrow` + `created` when an orphan uses `/ext` + `narrow/created`.
        let ext_base = tempfile::tempdir().unwrap();
        let ext_wide = fs::canonicalize(ext_base.path()).unwrap();
        let ext_narrow = ext_wide.join("narrow");
        fs::create_dir_all(&ext_narrow).unwrap();
        let mut f6 = Fixture::new();
        f6.tools.add_directory(&ext_narrow).unwrap();
        let ext_file = ext_narrow.join("created/leaf.txt");
        let w6 = f6
            .call(
                "write_file",
                json!({"path": ext_file.display().to_string(), "content": "ext\n"}),
            )
            .await;
        assert!(!w6.is_error, "{}", w6.content);
        f6.tools.checkpoints.orphan_stages.push(OrphanStage {
            root: ext_wide.clone(),
            parent: PathBuf::from("narrow/created"),
            stage: crate::workspace_stage::StageRef {
                name: crate::workspace_stage::StageDirectory::plan_name(),
                directory: None,
                guard: None,
                payload: None,
            },
            bytes: 0,
            binding: vec![f6.tools.root_identity; 3],
        });
        f6.tools.persist().unwrap();
        assert!(
            f6.tools
                .checkpoints_reference_dir(&ext_narrow, Path::new("created")),
            "cross-root orphan reference must block empty-dir removal"
        );
        f6.tools.undo().unwrap();
        assert!(!ext_file.exists());
        assert!(
            ext_narrow.join("created").is_dir(),
            "directory referenced by wider-root orphan_stages must remain on disk"
        );

        // 7) `write → widen grant → write → undo → reopen → undo` (and reverse wide → narrow) preserves binding length invariants.
        let ext7_base = tempfile::tempdir().unwrap();
        let ext7_wide = fs::canonicalize(ext7_base.path()).unwrap();
        let ext7_narrow = ext7_wide.join("narrow");
        fs::create_dir_all(&ext7_narrow).unwrap();
        let mut f7 = Fixture::new();
        f7.tools.add_directory(&ext7_narrow).unwrap();
        let ext7_file = ext7_narrow.join("sub/f.txt");
        let w7_1 = f7
            .call(
                "write_file",
                json!({"path": ext7_file.display().to_string(), "content": "turn1\n"}),
            )
            .await;
        assert!(!w7_1.is_error, "{}", w7_1.content);

        f7.tools.begin_turn().unwrap();
        f7.tools.add_directory(&ext7_wide).unwrap();
        let r7 = f7
            .call(
                "read_file",
                json!({"path": ext7_file.display().to_string()}),
            )
            .await;
        assert!(!r7.is_error, "{}", r7.content);
        let w7_2 = f7
            .call(
                "write_file",
                json!({"path": ext7_file.display().to_string(), "content": "turn2\n"}),
            )
            .await;
        assert!(!w7_2.is_error, "{}", w7_2.content);

        f7.tools.undo().unwrap();
        assert_eq!(fs::read_to_string(&ext7_file).unwrap(), "turn1\n");
        let root7 = f7.root.clone();
        let state7 = f7.state.clone();
        drop(f7.tools);
        let mut reopened7 = Tools::new(&root7, &state7).unwrap();
        reopened7.undo().unwrap();
        assert!(!ext7_file.exists());
        assert!(!ext7_narrow.join("sub").exists());

        // Reverse direction: wide grant in turn 1 -> reopen -> narrow grant in turn 2 -> undo -> reopen -> undo.
        reopened7.begin_turn().unwrap();
        reopened7.add_directory(&ext7_wide).unwrap();
        let w7_wide = reopened7
            .execute(
                "write_file",
                &json!({"path": ext7_file.display().to_string(), "content": "wide1\n"}),
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert!(!w7_wide.is_error, "{}", w7_wide.content);
        drop(reopened7);

        let mut reopened7_narrow = Tools::new(&root7, &state7).unwrap();
        reopened7_narrow.begin_turn().unwrap();
        reopened7_narrow.add_directory(&ext7_narrow).unwrap();
        let r7_narrow = reopened7_narrow
            .execute(
                "read_file",
                &json!({"path": ext7_file.display().to_string()}),
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert!(!r7_narrow.is_error, "{}", r7_narrow.content);
        let w7_narrow = reopened7_narrow
            .execute(
                "write_file",
                &json!({"path": ext7_file.display().to_string(), "content": "narrow2\n"}),
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert!(!w7_narrow.is_error, "{}", w7_narrow.content);
        reopened7_narrow.undo().unwrap();
        drop(reopened7_narrow);

        let mut reopened7_final = Tools::new(&root7, &state7).unwrap();
        reopened7_final.undo().unwrap();
        assert!(!ext7_file.exists());
        assert!(!ext7_narrow.join("sub").exists());

        // 8) User replaces created directory `a` between turns: undo T2 + undo T1 removes `f` but preserves user's directory `a`.
        let mut f8 = Fixture::new();
        let w8_1 = f8
            .call("write_file", json!({"path": "a/f.txt", "content": "v1\n"}))
            .await;
        assert!(!w8_1.is_error, "{}", w8_1.content);
        fs::rename(f8.root.join("a"), f8.root.join("saved")).unwrap();
        fs::create_dir(f8.root.join("a")).unwrap();
        fs::copy(f8.root.join("saved/f.txt"), f8.root.join("a/f.txt")).unwrap();
        let user_dir_ino = {
            use std::os::unix::fs::MetadataExt;
            fs::symlink_metadata(f8.root.join("a")).unwrap().ino()
        };

        f8.tools.begin_turn().unwrap();
        let r8 = f8.call("read_file", json!({"path": "a/f.txt"})).await;
        assert!(!r8.is_error, "{}", r8.content);
        let w8_2 = f8
            .call("write_file", json!({"path": "a/f.txt", "content": "v2\n"}))
            .await;
        assert!(!w8_2.is_error, "{}", w8_2.content);

        f8.tools.undo().unwrap();
        assert_eq!(f8.tools.checkpoints.turns[0].entries[0].created_parents, 0);
        f8.tools.undo().unwrap();
        assert!(!f8.root.join("a/f.txt").exists());
        assert!(
            f8.root.join("a").is_dir(),
            "user-recreated directory `a` must not be deleted by T1 undo"
        );
        let after_dir_ino = {
            use std::os::unix::fs::MetadataExt;
            fs::symlink_metadata(f8.root.join("a")).unwrap().ino()
        };
        assert_eq!(after_dir_ino, user_dir_ino);
        assert_eq!(
            fs::read_to_string(f8.root.join("saved/f.txt")).unwrap(),
            "v1\n"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn deep_nested_mkdirs_and_undo_work_under_rlimit_nofile_64() {
        const CHILD: &str = "RCODE_TEST_WAL_DEEP_MKDIR_LOW_FD_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("tools::tests::deep_nested_mkdirs_and_undo_work_under_rlimit_nofile_64")
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success(), "low-FD deep mkdir child failed: {status}");
            return;
        }

        let limit = libc::rlimit {
            rlim_cur: 64,
            rlim_max: 64,
        };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);

        let mut fixture = Fixture::new();
        // Max allowed normalized component count is 64 (63 nested dirs + 1 leaf file).
        let deep_path = format!(
            "{}/leaf.txt",
            (0..63)
                .map(|i| format!("d{i:02}"))
                .collect::<Vec<_>>()
                .join("/")
        );
        let deep_out = fixture
            .call(
                "write_file",
                json!({"path": deep_path, "content": "deep\n"}),
            )
            .await;
        assert!(!deep_out.is_error, "{}", deep_out.content);

        for index in 0..30 {
            let p = format!("multi-{index:02}/a/b/c/file.txt");
            let res = fixture
                .call("write_file", json!({"path": p, "content": "ok\n"}))
                .await;
            assert!(!res.is_error, "{p}: {}", res.content);
        }

        // Also exercise unpublished abort cleanup under RLIMIT_NOFILE=64.
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        fixture.tools.before_publication_hook = Some(Box::new(move || {
            cancel_clone.cancel();
        }));
        let aborted = fixture
            .tools
            .execute(
                "write_file",
                &json!({"path": "aborted/a/b/c/d/file.txt", "content": "x\n"}),
                &cancel,
            )
            .await
            .unwrap();
        assert!(aborted.is_error);
        assert!(!fixture.root.join("aborted").exists());

        let root = fixture.root.clone();
        let state = fixture.state.clone();
        drop(fixture.tools);
        let mut reopened = Tools::new(&root, &state).unwrap();
        reopened.undo().unwrap();
        assert!(!root.join("d00").exists());
        for index in 0..30 {
            assert!(!root.join(format!("multi-{index:02}")).exists());
        }
    }
}

#[cfg(all(test, unix))]
#[path = "file_wal_tests.rs"]
mod file_wal_tests;

#[cfg(all(test, unix))]
#[path = "file_wal_failure_tests.rs"]
mod file_wal_failure_tests;
