//! Durable intent/receipt storage. Callers still own authorization and task-state
//! reconciliation; a successful start receipt does not mean a process has exited.
//! The exclusive lease must be released before activating a replacement runtime.
//! Advisory locking cannot provide filesystem CAS against a hostile same-UID writer.
use crate::artifacts::{ArtifactMeta, ArtifactOrigin, ArtifactStore};
use anyhow::{Result, anyhow, ensure};
use cap_fs_ext::{DirExt, FollowSymlinks, MetadataExt, OpenOptionsFollowExt, OpenOptionsSyncExt};
#[cfg(unix)]
use cap_std::fs::{DirBuilderExt, MetadataExt as UnixMetadataExt, OpenOptionsExt};
use cap_std::{
    ambient_authority,
    fs::{Dir, DirBuilder, File, Metadata, OpenOptions},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    ffi::OsString,
    io::{Read, Write},
    path::Path,
};
use uuid::Uuid;

const INDEX_MAX: usize = 4 * 1024 * 1024;
const ENVELOPE_MAX: usize = 256 * 1024;
const OPERATIONS_MAX: usize = 2048;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Succeeded,
    Failed,
    Interrupted,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct OperationRecord {
    pub operation_id: String,
    pub origin: ArtifactOrigin,
    pub intent: ArtifactMeta,
    pub terminal: Option<ArtifactMeta>,
    pub outcome: Outcome,
    pub task_revision: Option<u64>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    operation_id: String,
    origin: ArtifactOrigin,
    intent: ArtifactMeta,
    terminal: Option<ArtifactMeta>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    version: u32,
    session_id: String,
    records: Vec<Record>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    version: u32,
    operation_id: String,
    request: Value,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Terminal {
    version: u32,
    operation_id: String,
    intent_id: String,
    intent_sha256: String,
    outcome: Outcome,
    task_revision: u64,
    payload: Value,
}
struct ExpectedIndex {
    file: File,
    sha256: String,
}

pub struct OperationJournal {
    anchor: Dir,
    session_name: OsString,
    session: Dir,
    dir: Dir,
    lock: std::fs::File,
    lock_meta: Metadata,
    expected: Option<ExpectedIndex>,
    index: Index,
    poisoned: bool,
    index_limit: usize,
    operation_limit: usize,
    #[cfg(test)]
    fault: Option<&'static str>,
}

impl Drop for OperationJournal {
    fn drop(&mut self) {
        // CLOEXEC closes an inherited descriptor only after exec. Explicitly
        // release the shared open-file-description lock so unrelated concurrent
        // forks cannot retain our lease after the owning runtime has closed.
        let _ = fs2::FileExt::unlock(&self.lock);
    }
}

fn io<T>(result: std::io::Result<T>) -> Result<T> {
    result.map_err(|_| anyhow!("Ошибка файлового журнала операций"))
}
fn same(a: &Metadata, b: &Metadata) -> bool {
    MetadataExt::dev(a) == MetadataExt::dev(b) && MetadataExt::ino(a) == MetadataExt::ino(b)
}
fn private_file(meta: &Metadata) -> Result<()> {
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink() && MetadataExt::nlink(meta) == 1,
        "Небезопасный файл журнала"
    );
    #[cfg(unix)]
    ensure!(
        meta.mode() & 0o7777 == 0o600,
        "Небезопасные права файла журнала"
    );
    Ok(())
}
fn private_dir(meta: &Metadata) -> Result<()> {
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "Небезопасный каталог журнала"
    );
    #[cfg(unix)]
    ensure!(
        meta.mode() & 0o7777 == 0o700,
        "Небезопасные права каталога журнала"
    );
    Ok(())
}
fn checked_file(dir: &Dir, name: &str) -> Result<File> {
    let before = io(dir.symlink_metadata(name))?;
    private_file(&before)?;
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = io(dir.open_with(name, &options))?;
    let opened = io(file.metadata())?;
    private_file(&opened)?;
    ensure!(same(&before, &opened), "Файл журнала изменился");
    Ok(file)
}
fn create_file(dir: &Dir, name: &str) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No)
        .nonblock(true);
    #[cfg(unix)]
    options.mode(0o600);
    io(dir.open_with(name, &options))
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn valid_id(id: &str) -> Result<()> {
    let uuid = Uuid::parse_str(id).map_err(|_| anyhow!("Некорректный ID операции"))?;
    ensure!(
        uuid.get_version_num() == 4
            && uuid.get_variant() == uuid::Variant::RFC4122
            && uuid.to_string() == id,
        "Некорректный ID операции"
    );
    Ok(())
}
fn bounded_read(mut file: &File, max: usize) -> Result<Vec<u8>> {
    ensure!(
        io(file.metadata())?.len() <= max as u64,
        "Превышен размер журнала"
    );
    let mut bytes = Vec::new();
    io((&mut file).take(max as u64 + 1).read_to_end(&mut bytes))?;
    ensure!(bytes.len() <= max, "Превышен размер журнала");
    Ok(bytes)
}
struct Bounded {
    bytes: Vec<u8>,
    limit: usize,
}
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("Превышен лимит записи журнала"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn encode(value: &impl Serialize, max: usize) -> Result<Vec<u8>> {
    let mut writer = Bounded {
        bytes: Vec::new(),
        limit: max,
    };
    serde_json::to_writer(&mut writer, value)
        .map_err(|_| anyhow!("Запись журнала превышает лимит или не сериализуется"))?;
    Ok(writer.bytes)
}
fn redact(text: &str, secrets: &[String]) -> Result<String> {
    let mut redactor = crate::redaction::StreamingRedactor::new(secrets)?;
    let mut bytes = redactor.push(text.as_bytes())?;
    bytes.extend(redactor.finish()?);
    String::from_utf8(bytes).map_err(|_| anyhow!("Некорректный текст после удаления секретов"))
}
fn origin_valid(origin: &ArtifactOrigin) -> Result<()> {
    ensure!(
        origin.actor.as_ref().is_none_or(|a| !a.is_empty()
            && a.len() <= 128
            && a.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))),
        "Некорректный actor журнала"
    );
    ensure!(
        !origin.tool.is_empty()
            && origin.tool.len() <= 128
            && !origin.call_id.is_empty()
            && origin.call_id.len() <= 256,
        "Некорректное происхождение операции"
    );
    Ok(())
}

impl OperationJournal {
    pub fn open(session_dir: &Path, session_id: &str, artifacts: &ArtifactStore) -> Result<Self> {
        ensure!(
            cfg!(unix),
            "Журнал операций пока поддерживается только на Unix"
        );
        ensure!(
            !session_id.is_empty() && session_id.len() <= 4096,
            "Некорректная сессия журнала"
        );
        let path = io(session_dir.canonicalize())?;
        let name = path
            .file_name()
            .ok_or_else(|| anyhow!("У сессии отсутствует родитель"))?
            .to_owned();
        let anchor = io(Dir::open_ambient_dir(
            path.parent()
                .ok_or_else(|| anyhow!("У сессии отсутствует родитель"))?,
            ambient_authority(),
        ))?;
        let session = io(anchor.open_dir_nofollow(&name))?;
        ensure!(
            same(
                &io(anchor.symlink_metadata(&name))?,
                &io(session.dir_metadata())?
            ),
            "Каталог сессии изменился"
        );
        let mut builder = DirBuilder::new();
        #[cfg(unix)]
        builder.mode(0o700);
        let created = match session.create_dir_with("operations", &builder) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(_) => return Err(anyhow!("Не удалось создать каталог журнала")),
        };
        let before = io(session.symlink_metadata("operations"))?;
        private_dir(&before)?;
        let dir = io(session.open_dir_nofollow("operations"))?;
        ensure!(
            same(&before, &io(dir.dir_metadata())?),
            "Каталог журнала изменился"
        );
        let lock_file = if created {
            create_file(&dir, ".lock")?
        } else {
            checked_file(&dir, ".lock")?
        };
        let lock_meta = io(lock_file.metadata())?;
        private_file(&lock_meta)?;
        ensure!(lock_meta.len() == 0, "Повреждена блокировка журнала");
        let lock = lock_file.into_std();
        fs2::FileExt::try_lock_exclusive(&lock)
            .map_err(|_| anyhow!("Журнал занят другой сессией исполнения"))?;
        let mut journal = Self {
            anchor,
            session_name: name,
            session,
            dir,
            lock,
            lock_meta,
            expected: None,
            index: Index {
                version: 1,
                session_id: session_id.into(),
                records: Vec::new(),
            },
            poisoned: false,
            index_limit: INDEX_MAX,
            operation_limit: OPERATIONS_MAX,
            #[cfg(test)]
            fault: None,
        };
        journal.check_binding()?;
        // Publish a possibly newly created session and its ancestors before any
        // required artifact is accepted. fsync(session) alone misses its name.
        #[cfg(unix)]
        for ancestor in path.ancestors().skip(1) {
            let dir = io(Dir::open_ambient_dir(ancestor, ambient_authority()))?;
            io(io(dir.open("."))?.sync_all())?;
        }
        if created {
            journal.persist(&journal.index.clone())?;
        } else {
            let file = checked_file(&journal.dir, "index.json")?;
            let bytes = bounded_read(&file, INDEX_MAX)?;
            let index: Index =
                serde_json::from_slice(&bytes).map_err(|_| anyhow!("Повреждён журнал операций"))?;
            ensure!(
                index.version == 1 && index.session_id == session_id,
                "Несовместимый журнал операций"
            );
            journal.validate_index(&index, artifacts)?;
            io(file.sync_all())?;
            journal.sync_dirs()?;
            journal.index = index;
            journal.expected = Some(ExpectedIndex {
                file,
                sha256: hash(&bytes),
            });
            journal.check()?;
            journal.recover_staging()?;
        }
        Ok(journal)
    }

    /// Only names reserved by persist() are staging. No committed reference
    /// points to them. The lifetime lease excludes every cooperating writer.
    /// Unknown names are preserved; unsafe staging blocks activation.
    fn recover_staging(&self) -> Result<()> {
        self.check()?;
        let mut staging = Vec::new();
        for (number, entry) in io(self.dir.read_dir("."))?.enumerate() {
            ensure!(number < 64, "Слишком много файлов в каталоге журнала");
            let entry = io(entry)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(id) = name.strip_prefix('.').and_then(|n| n.strip_suffix(".tmp")) else {
                continue;
            };
            if valid_id(id).is_err() {
                continue;
            }
            let file = checked_file(&self.dir, name)?;
            ensure!(
                io(file.metadata())?.len() <= INDEX_MAX as u64,
                "Слишком большой staging журнала"
            );
            staging.push((name.to_owned(), file));
        }
        for (name, file) in &staging {
            self.check_binding()?;
            let current = io(self.dir.symlink_metadata(name))?;
            private_file(&current)?;
            ensure!(
                same(&current, &io(file.metadata())?),
                "Staging журнала изменился"
            );
            io(self.dir.remove_file(name))?;
        }
        if !staging.is_empty() {
            io(io(self.dir.open("."))?.sync_all())?;
        }
        self.check()?;
        Ok(())
    }

    fn check_binding(&self) -> Result<()> {
        ensure!(
            !self.poisoned,
            "Журнал заблокирован после ошибки обязательной записи; требуется повторное открытие"
        );
        let session = io(self.anchor.symlink_metadata(&self.session_name))?;
        ensure!(
            session.is_dir()
                && !session.file_type().is_symlink()
                && same(&session, &io(self.session.dir_metadata())?),
            "Каталог сессии изменился"
        );
        let dir = io(self.session.symlink_metadata("operations"))?;
        private_dir(&dir)?;
        ensure!(
            same(&dir, &io(self.dir.dir_metadata())?),
            "Каталог журнала изменился"
        );
        let lock = io(self.dir.symlink_metadata(".lock"))?;
        private_file(&lock)?;
        ensure!(
            lock.len() == 0 && same(&lock, &self.lock_meta),
            "Блокировка журнала изменена"
        );
        // Holding this handle (not a pathname) owns the OS lock until Drop.
        ensure!(
            io(self.lock.metadata())?.len() == 0,
            "Блокировка журнала повреждена"
        );
        Ok(())
    }
    fn check(&self) -> Result<()> {
        self.check_binding()?;
        if let Some(expected) = &self.expected {
            let file = checked_file(&self.dir, "index.json")?;
            ensure!(
                same(&io(file.metadata())?, &io(expected.file.metadata())?)
                    && hash(&bounded_read(&file, self.index_limit)?) == expected.sha256,
                "Журнал изменён вне владельца"
            );
        } else {
            match self.dir.symlink_metadata("index.json") {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                _ => return Err(anyhow!("Неожиданный индекс при создании журнала")),
            }
        }
        Ok(())
    }
    fn sync_dirs(&self) -> Result<()> {
        #[cfg(unix)]
        for dir in [&self.dir, &self.session, &self.anchor] {
            io(io(dir.open("."))?.sync_all())?;
        }
        Ok(())
    }
    fn point(&mut self, name: &'static str) -> Result<()> {
        #[cfg(test)]
        if self.fault == Some(name) {
            self.fault = None;
            return Err(anyhow!("Внесённая ошибка записи журнала"));
        }
        let _ = name;
        Ok(())
    }
    fn reserve(&self, index: &Index) -> Result<()> {
        ensure!(
            index.records.len() <= self.operation_limit,
            "Превышено число операций журнала"
        );
        let mut worst = index.clone();
        for record in &mut worst.records {
            if record.terminal.is_none() {
                let mut meta = record.intent.clone();
                meta.id = "00000000-0000-4000-8000-000000000000".into();
                meta.bytes = 16 * 1024 * 1024;
                meta.sha256 = "0".repeat(64);
                meta.truncated = false;
                record.terminal = Some(meta);
            }
        }
        encode(&worst, self.index_limit)?;
        Ok(())
    }
    fn persist(&mut self, index: &Index) -> Result<()> {
        self.check()?;
        self.reserve(index)?;
        let bytes = encode(index, self.index_limit)?;
        let result = (|| {
            let name = format!(".{}.tmp", Uuid::new_v4());
            let mut file = create_file(&self.dir, &name)?;
            self.point("write")?;
            io(file.write_all(&bytes))?;
            self.point("file_sync")?;
            io(file.sync_all())?;
            self.check()?;
            self.point("before_rename")?;
            io(self.dir.rename(&name, &self.dir, "index.json"))?;
            self.point("after_rename")?;
            self.point("directory_sync")?;
            self.sync_dirs()?;
            self.check_binding()?;
            self.expected = Some(ExpectedIndex {
                file,
                sha256: hash(&bytes),
            });
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn validate_index(&self, index: &Index, artifacts: &ArtifactStore) -> Result<()> {
        self.reserve(index)?;
        let mut ids = HashSet::new();
        for record in &index.records {
            valid_id(&record.operation_id)?;
            ensure!(
                ids.insert(&record.operation_id),
                "Повторный ID операции в журнале"
            );
            origin_valid(&record.origin)?;
            self.check_meta(&record.intent, &record.origin)?;
            let text = artifacts.verify_required(&record.intent)?;
            let intent: Intent = serde_json::from_str(&text)
                .map_err(|_| anyhow!("Повреждено намерение операции"))?;
            ensure!(
                text.len() <= ENVELOPE_MAX
                    && intent.version == 1
                    && intent.operation_id == record.operation_id,
                "Намерение не соответствует операции"
            );
            if let Some(meta) = &record.terminal {
                self.terminal(record, meta, artifacts)?;
            }
        }
        Ok(())
    }
    fn check_meta(&self, meta: &ArtifactMeta, origin: &ArtifactOrigin) -> Result<()> {
        ensure!(
            meta.session_id == self.index.session_id
                && meta.origin == *origin
                && !meta.truncated
                && meta.bytes <= ENVELOPE_MAX,
            "Артефакт не соответствует журналу"
        );
        Ok(())
    }
    fn terminal(
        &self,
        record: &Record,
        meta: &ArtifactMeta,
        artifacts: &ArtifactStore,
    ) -> Result<Terminal> {
        self.check_meta(meta, &record.origin)?;
        let text = artifacts.verify_required(meta)?;
        let terminal: Terminal =
            serde_json::from_str(&text).map_err(|_| anyhow!("Повреждён результат операции"))?;
        ensure!(
            terminal.version == 1
                && terminal.operation_id == record.operation_id
                && terminal.intent_id == record.intent.id
                && terminal.intent_sha256 == record.intent.sha256,
            "Результат не соответствует намерению"
        );
        Ok(terminal)
    }
    fn identity(
        &self,
        operation_id: &str,
        origin: &ArtifactOrigin,
        secrets: &[String],
    ) -> Result<()> {
        valid_id(operation_id)?;
        origin_valid(origin)?;
        for field in [
            Some(self.index.session_id.as_str()),
            Some(operation_id),
            origin.actor.as_deref(),
            Some(&origin.tool),
            Some(&origin.call_id),
        ]
        .into_iter()
        .flatten()
        {
            ensure!(
                redact(field, secrets)? == field,
                "Секрет в идентификаторе журнала"
            );
        }
        Ok(())
    }
    fn prepared<T: Serialize + for<'a> Deserialize<'a>>(
        value: &T,
        secrets: &[String],
    ) -> Result<(String, T)> {
        let raw = String::from_utf8(encode(value, ENVELOPE_MAX)?)?;
        let clean = redact(&raw, secrets)?;
        ensure!(
            clean.len() <= ENVELOPE_MAX,
            "Обязательная запись превышает лимит после удаления секретов"
        );
        let verified = serde_json::from_str(&clean)
            .map_err(|_| anyhow!("Удаление секрета изменило формат обязательной записи"))?;
        Ok((raw, verified))
    }
    pub fn begin(
        &mut self,
        operation_id: &str,
        origin: ArtifactOrigin,
        request: &Value,
        artifacts: &ArtifactStore,
        secrets: &[String],
    ) -> Result<ArtifactMeta> {
        self.check()?;
        self.identity(operation_id, &origin, secrets)?;
        ensure!(
            !self
                .index
                .records
                .iter()
                .any(|r| r.operation_id == operation_id),
            "Операция уже зарегистрирована"
        );
        ensure!(
            self.index.records.len() < self.operation_limit,
            "Превышено число операций журнала"
        );
        encode(request, ENVELOPE_MAX)?;
        let intent = Intent {
            version: 1,
            operation_id: operation_id.into(),
            request: request.clone(),
        };
        let (raw, clean) = Self::prepared(&intent, secrets)?;
        ensure!(
            clean.version == 1 && clean.operation_id == operation_id,
            "Секрет затронул идентификатор намерения"
        );
        // Conservative metadata reservation happens before artifact publication.
        let mut next = self.index.clone();
        let placeholder = ArtifactMeta {
            version: 1,
            id: "00000000-0000-4000-8000-000000000000".into(),
            session_id: self.index.session_id.clone(),
            origin: origin.clone(),
            bytes: ENVELOPE_MAX,
            sha256: "0".repeat(64),
            truncated: false,
        };
        next.records.push(Record {
            operation_id: operation_id.into(),
            origin: origin.clone(),
            intent: placeholder,
            terminal: None,
        });
        self.reserve(&next)?;
        let result = (|| {
            let meta = artifacts.capture_required(origin, &raw, secrets)?;
            self.check_meta(
                &meta,
                &next.records.last().expect("record just inserted").origin,
            )?;
            next.records
                .last_mut()
                .expect("record just inserted")
                .intent = meta.clone();
            self.persist(&next)?;
            self.index = next;
            Ok(meta)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    pub fn finish(
        &mut self,
        operation_id: &str,
        outcome: Outcome,
        payload: &Value,
        task_revision: u64,
        artifacts: &ArtifactStore,
        secrets: &[String],
    ) -> Result<ArtifactMeta> {
        self.check()?;
        let position = self
            .index
            .records
            .iter()
            .position(|r| r.operation_id == operation_id)
            .ok_or_else(|| anyhow!("Операция отсутствует в журнале"))?;
        let record = &self.index.records[position];
        self.identity(operation_id, &record.origin, secrets)?;
        self.check_meta(&record.intent, &record.origin)?;
        let intent: Intent = serde_json::from_str(&artifacts.verify_required(&record.intent)?)
            .map_err(|_| anyhow!("Повреждено намерение операции"))?;
        ensure!(
            intent.version == 1 && intent.operation_id == operation_id,
            "Намерение не соответствует операции"
        );
        encode(payload, ENVELOPE_MAX)?;
        let terminal = Terminal {
            version: 1,
            operation_id: operation_id.into(),
            intent_id: record.intent.id.clone(),
            intent_sha256: record.intent.sha256.clone(),
            outcome,
            task_revision,
            payload: payload.clone(),
        };
        let (raw, clean) = Self::prepared(&terminal, secrets)?;
        ensure!(
            clean.version == 1
                && clean.operation_id == terminal.operation_id
                && clean.intent_id == terminal.intent_id
                && clean.intent_sha256 == terminal.intent_sha256
                && clean.outcome == outcome
                && clean.task_revision == task_revision,
            "Секрет затронул идентификаторы результата"
        );
        if let Some(meta) = &record.terminal {
            let existing = self.terminal(record, meta, artifacts)?;
            ensure!(
                serde_json::to_value(existing)? == serde_json::to_value(clean)?,
                "Операция уже завершена другим результатом"
            );
            return Ok(meta.clone());
        }
        let origin = record.origin.clone();
        let result = (|| {
            let meta = artifacts.capture_required(origin.clone(), &raw, secrets)?;
            self.check_meta(&meta, &origin)?;
            let mut next = self.index.clone();
            next.records[position].terminal = Some(meta.clone());
            self.persist(&next)?;
            self.index = next;
            Ok(meta)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    /// Pending means unknown, never a retry instruction or proof of failure.
    pub fn records(&self, artifacts: &ArtifactStore) -> Result<Vec<OperationRecord>> {
        self.check()?;
        self.validate_index(&self.index, artifacts)?;
        self.index
            .records
            .iter()
            .map(|record| {
                let terminal = record
                    .terminal
                    .as_ref()
                    .map(|m| self.terminal(record, m, artifacts))
                    .transpose()?;
                Ok(OperationRecord {
                    operation_id: record.operation_id.clone(),
                    origin: record.origin.clone(),
                    intent: record.intent.clone(),
                    terminal: record.terminal.clone(),
                    outcome: terminal.as_ref().map_or(Outcome::Unknown, |t| t.outcome),
                    task_revision: terminal.map(|t| t.task_revision),
                })
            })
            .collect()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};
    fn origin() -> ArtifactOrigin {
        ArtifactOrigin {
            actor: None,
            turn: 1,
            tool: "start_command".into(),
            call_id: "reused-provider-id".into(),
        }
    }
    fn setup() -> (tempfile::TempDir, ArtifactStore, OperationJournal) {
        let temp = tempfile::tempdir().unwrap();
        let artifacts = ArtifactStore::open(temp.path(), "test-session").unwrap();
        let journal = OperationJournal::open(temp.path(), "test-session", &artifacts).unwrap();
        (temp, artifacts, journal)
    }
    fn begin(j: &mut OperationJournal, a: &ArtifactStore) -> String {
        let id = Uuid::new_v4().to_string();
        j.begin(
            &id,
            origin(),
            &serde_json::json!({"command":"true"}),
            a,
            &[],
        )
        .unwrap();
        id
    }
    #[test]
    fn restart_unknown_and_completed_receipts_are_distinct() {
        let (t, a, mut j) = setup();
        let pending = begin(&mut j, &a);
        let completed = begin(&mut j, &a);
        let receipt = j
            .finish(
                &completed,
                Outcome::Succeeded,
                &serde_json::json!({"running":true}),
                3,
                &a,
                &[],
            )
            .unwrap();
        assert_eq!(
            receipt,
            j.finish(
                &completed,
                Outcome::Succeeded,
                &serde_json::json!({"running":true}),
                3,
                &a,
                &[]
            )
            .unwrap()
        );
        assert!(
            j.finish(&completed, Outcome::Failed, &Value::Null, 3, &a, &[])
                .is_err()
        );
        drop(j);
        let j = OperationJournal::open(t.path(), "test-session", &a).unwrap();
        let records = j.records(&a).unwrap();
        assert_eq!(records[0].operation_id, pending);
        assert_eq!(records[0].outcome, Outcome::Unknown);
        assert!(records[0].terminal.is_none());
        assert_eq!(records[1].outcome, Outcome::Succeeded);
        assert_eq!(records[1].task_revision, Some(3));
        assert_eq!(records[1].terminal.as_ref(), Some(&receipt));
    }
    #[test]
    fn exclusive_lock_and_host_identity_not_provider_call_id() {
        let (t, a, mut j) = setup();
        assert!(OperationJournal::open(t.path(), "test-session", &a).is_err());
        let id = begin(&mut j, &a);
        assert!(j.begin(&id, origin(), &Value::Null, &a, &[]).is_err());
        begin(&mut j, &a);
        assert_eq!(j.records(&a).unwrap().len(), 2);
    }

    #[test]
    fn unrelated_fork_cannot_retain_a_closed_journal_lease() {
        struct Child(libc::pid_t);
        impl Drop for Child {
            fn drop(&mut self) {
                // This is our still-unreaped child; its PID cannot be reused.
                unsafe {
                    libc::kill(self.0, libc::SIGKILL);
                    while libc::waitpid(self.0, std::ptr::null_mut(), 0) == -1
                        && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
                    {
                    }
                }
            }
        }
        let (t, a, j) = setup();
        // Only async-signal-safe libc calls execute in the child, which models
        // an unrelated spawn between fork and exec (before CLOEXEC takes effect).
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            loop {
                unsafe {
                    libc::pause();
                }
            }
        }
        let child = Child(pid);
        drop(j);
        let reopened = OperationJournal::open(t.path(), "test-session", &a);
        drop(child);
        assert!(
            reopened.is_ok(),
            "lease retained across unrelated fork: {:?}",
            reopened.err()
        );
    }
    #[test]
    fn boundaries_reserve_terminal_and_do_not_publish_rejected_intents() {
        let (_t, a, mut j) = setup();
        j.operation_limit = 2;
        let first = begin(&mut j, &a);
        let second = begin(&mut j, &a);
        assert!(
            j.begin(&Uuid::new_v4().to_string(), origin(), &Value::Null, &a, &[])
                .is_err()
        );
        j.finish(&first, Outcome::Succeeded, &Value::Null, 1, &a, &[])
            .unwrap();
        j.finish(&second, Outcome::Unknown, &Value::Null, 1, &a, &[])
            .unwrap();
        let records = j.records(&a).unwrap();
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|r| r.terminal.is_some()));
    }
    #[test]
    fn secrets_and_oversize_refused_before_intent() {
        let (t, a, mut j) = setup();
        let secret = "private-journal-key".to_owned();
        let mut o = origin();
        o.call_id = secret.clone();
        assert!(
            j.begin(
                &Uuid::new_v4().to_string(),
                o,
                &Value::Null,
                &a,
                std::slice::from_ref(&secret)
            )
            .is_err()
        );
        assert!(
            j.begin(
                &Uuid::new_v4().to_string(),
                origin(),
                &Value::String("x".repeat(ENVELOPE_MAX)),
                &a,
                &[]
            )
            .is_err()
        );
        let id = Uuid::new_v4().to_string();
        j.begin(
            &id,
            origin(),
            &serde_json::json!({"key":secret}),
            &a,
            std::slice::from_ref(&secret),
        )
        .unwrap();
        j.finish(
            &id,
            Outcome::Succeeded,
            &Value::String(secret.clone()),
            1,
            &a,
            std::slice::from_ref(&secret),
        )
        .unwrap();
        for dir in ["operations", "artifacts"] {
            for item in fs::read_dir(t.path().join(dir)).unwrap() {
                let bytes = fs::read(item.unwrap().path()).unwrap();
                assert!(!bytes.windows(secret.len()).any(|w| w == secret.as_bytes()));
            }
        }
    }
    #[test]
    fn every_required_index_fault_poison_and_reopen_never_replays() {
        for point in [
            "write",
            "file_sync",
            "before_rename",
            "after_rename",
            "directory_sync",
        ] {
            let (t, a, mut j) = setup();
            let id = begin(&mut j, &a);
            j.fault = Some(point);
            assert!(
                j.finish(&id, Outcome::Succeeded, &Value::Null, 1, &a, &[])
                    .is_err()
            );
            assert!(
                j.finish(&id, Outcome::Succeeded, &Value::Null, 1, &a, &[])
                    .is_err()
            );
            assert!(
                j.begin(&Uuid::new_v4().to_string(), origin(), &Value::Null, &a, &[])
                    .is_err()
            );
            drop(j);
            let restored = OperationJournal::open(t.path(), "test-session", &a)
                .unwrap()
                .records(&a)
                .unwrap();
            assert_eq!(restored.len(), 1);
            let published = matches!(point, "after_rename" | "directory_sync");
            assert_eq!(restored[0].terminal.is_some(), published);
            assert_eq!(
                restored[0].outcome,
                if published {
                    Outcome::Succeeded
                } else {
                    Outcome::Unknown
                }
            );
        }
    }
    #[test]
    fn replacement_and_corruption_fail_closed() {
        for field in ["index.json", ".lock"] {
            let (t, a, mut j) = setup();
            begin(&mut j, &a);
            let path = t.path().join("operations").join(field);
            let bytes = fs::read(&path).unwrap();
            fs::rename(&path, path.with_extension("old")).unwrap();
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(j.records(&a).is_err());
        }
        let (t, a, mut j) = setup();
        let id = begin(&mut j, &a);
        let meta = j
            .finish(&id, Outcome::Succeeded, &Value::Null, 1, &a, &[])
            .unwrap();
        drop(j);
        let path = t.path().join("artifacts").join(meta.id);
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() = b'x';
        fs::write(path, bytes).unwrap();
        assert!(OperationJournal::open(t.path(), "test-session", &a).is_err());
    }
    #[test]
    fn renamed_journal_or_session_invalidates_owner() {
        let (t, a, mut j) = setup();
        begin(&mut j, &a);
        fs::rename(t.path().join("operations"), t.path().join("moved")).unwrap();
        assert!(j.records(&a).is_err());
        let parent = tempfile::tempdir().unwrap();
        let session = parent.path().join("session");
        fs::create_dir(&session).unwrap();
        let a = ArtifactStore::open(&session, "test-session").unwrap();
        let j = OperationJournal::open(&session, "test-session", &a).unwrap();
        fs::rename(&session, parent.path().join("other")).unwrap();
        assert!(j.records(&a).is_err());
    }

    #[test]
    fn idempotent_finish_does_not_hide_a_lost_intent() {
        let (t, a, mut j) = setup();
        let id = begin(&mut j, &a);
        j.finish(&id, Outcome::Succeeded, &Value::Null, 1, &a, &[])
            .unwrap();
        let meta = j.records(&a).unwrap().remove(0).intent;
        fs::remove_file(t.path().join("artifacts").join(meta.id)).unwrap();
        assert!(
            j.finish(&id, Outcome::Succeeded, &Value::Null, 1, &a, &[])
                .is_err()
        );
    }

    #[test]
    fn byte_limit_reserves_room_for_the_terminal_record() {
        let (t, a, mut j) = setup();
        let id = Uuid::new_v4().to_string();
        let mut accepted = false;
        for limit in (256..4096).step_by(16) {
            j.index_limit = limit;
            let count = fs::read_dir(t.path().join("artifacts")).unwrap().count();
            if j.begin(&id, origin(), &Value::Null, &a, &[]).is_ok() {
                accepted = true;
                j.finish(
                    &id,
                    Outcome::Succeeded,
                    &Value::String("я".repeat(32_000)),
                    u64::MAX,
                    &a,
                    &[],
                )
                .unwrap();
                assert!(
                    fs::metadata(t.path().join("operations/index.json"))
                        .unwrap()
                        .len()
                        <= limit as u64
                );
                break;
            }
            assert_eq!(
                fs::read_dir(t.path().join("artifacts")).unwrap().count(),
                count
            );
            assert!(!j.poisoned);
        }
        assert!(accepted);
    }

    #[test]
    fn interrupted_index_publications_do_not_accumulate_staging() {
        let (t, a, mut j) = setup();
        let id = begin(&mut j, &a);
        for _ in 0..4 {
            j.fault = Some("before_rename");
            assert!(
                j.finish(&id, Outcome::Succeeded, &Value::Null, 1, &a, &[])
                    .is_err()
            );
            drop(j);
            j = OperationJournal::open(t.path(), "test-session", &a).unwrap();
            assert_eq!(j.records(&a).unwrap()[0].outcome, Outcome::Unknown);
            assert_eq!(
                fs::read_dir(t.path().join("operations")).unwrap().count(),
                2
            );
        }
    }

    #[test]
    fn staging_cleanup_preserves_unknown_and_rejects_unsafe_names() {
        for kind in ["regular", "symlink", "hardlink", "permissions"] {
            let (t, a, j) = setup();
            drop(j);
            let directory = t.path().join("operations");
            let unknown = directory.join("user-note.tmp");
            fs::write(&unknown, b"preserve").unwrap();
            let staging = directory.join(format!(".{}.tmp", Uuid::new_v4()));
            if kind == "symlink" {
                std::os::unix::fs::symlink(&unknown, &staging).unwrap();
            } else {
                fs::write(&staging, b"partial index").unwrap();
                fs::set_permissions(
                    &staging,
                    fs::Permissions::from_mode(if kind == "permissions" { 0o644 } else { 0o600 }),
                )
                .unwrap();
                if kind == "hardlink" {
                    fs::hard_link(&staging, directory.join("external-link")).unwrap();
                }
            }
            let reopened = OperationJournal::open(t.path(), "test-session", &a);
            assert_eq!(reopened.is_ok(), kind == "regular");
            assert_eq!(fs::read(&unknown).unwrap(), b"preserve");
            assert_eq!(fs::symlink_metadata(&staging).is_ok(), kind != "regular");
        }
    }

    #[test]
    fn uncertain_begin_leaves_only_explicit_index_references() {
        for point in ["before_rename", "after_rename"] {
            let (t, a, mut j) = setup();
            let id = Uuid::new_v4().to_string();
            j.fault = Some(point);
            assert!(j.begin(&id, origin(), &Value::Null, &a, &[]).is_err());
            assert!(j.records(&a).is_err());
            drop(j);
            let j = OperationJournal::open(t.path(), "test-session", &a).unwrap();
            let records = j.records(&a).unwrap();
            assert_eq!(records.len(), usize::from(point == "after_rename"));
            assert!(
                records
                    .iter()
                    .all(|r| r.outcome == Outcome::Unknown && r.terminal.is_none())
            );
            assert!(fs::read_dir(t.path().join("artifacts")).unwrap().count() >= 2);
        }
    }

    #[test]
    fn artifact_storage_failure_blocks_further_writes() {
        let (t, a, mut j) = setup();
        let foreign = t.path().join("artifacts/foreign");
        fs::write(&foreign, b"untouched").unwrap();
        assert!(
            j.begin(&Uuid::new_v4().to_string(), origin(), &Value::Null, &a, &[])
                .is_err()
        );
        fs::remove_file(foreign).unwrap();
        assert!(
            j.begin(&Uuid::new_v4().to_string(), origin(), &Value::Null, &a, &[])
                .is_err()
        );
        drop(j);
        let mut j = OperationJournal::open(t.path(), "test-session", &a).unwrap();
        assert!(j.records(&a).unwrap().is_empty());
        begin(&mut j, &a);
    }

    #[test]
    fn unsafe_or_unrecognized_index_is_never_replaced() {
        for variant in [
            "version",
            "field",
            "oversized",
            "missing",
            "symlink",
            "hardlink",
            "fifo",
            "permissions",
        ] {
            let (t, a, j) = setup();
            drop(j);
            let path = t.path().join("operations/index.json");
            match variant {
                "version" | "field" => {
                    let mut value: Value =
                        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                    if variant == "version" {
                        value["version"] = 2.into();
                    } else {
                        value["unknown"] = true.into();
                    }
                    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
                }
                "oversized" => {
                    fs::OpenOptions::new()
                        .write(true)
                        .open(&path)
                        .unwrap()
                        .set_len(INDEX_MAX as u64 + 1)
                        .unwrap();
                }
                "missing" => fs::remove_file(&path).unwrap(),
                "symlink" => {
                    fs::rename(&path, path.with_extension("target")).unwrap();
                    std::os::unix::fs::symlink(path.with_extension("target"), &path).unwrap();
                }
                "hardlink" => fs::hard_link(&path, path.with_extension("other")).unwrap(),
                "fifo" => {
                    use std::os::unix::ffi::OsStrExt;
                    fs::remove_file(&path).unwrap();
                    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
                }
                _ => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            }
            let before = fs::symlink_metadata(&path)
                .ok()
                .map(|m| (m.len(), m.permissions().mode()));
            assert!(
                OperationJournal::open(t.path(), "test-session", &a).is_err(),
                "{variant}"
            );
            let after = fs::symlink_metadata(&path)
                .ok()
                .map(|m| (m.len(), m.permissions().mode()));
            assert_eq!(before, after);
        }
    }
}
