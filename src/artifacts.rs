//! Private immutable receipts. Unix uses 0700/0600; Windows inherits the session directory ACL.
//! Pagination is one-based. Query pages prefix each matching line with `N: `.
use anyhow::{Result, anyhow, ensure};
use cap_fs_ext::{DirExt, FollowSymlinks, MetadataExt, OpenOptionsFollowExt, OpenOptionsSyncExt};
#[cfg(unix)]
use cap_std::fs::{DirBuilderExt, MetadataExt as UnixMetadataExt, OpenOptionsExt};
use cap_std::{
    ambient_authority,
    fs::{Dir, DirBuilder, Metadata, OpenOptions},
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
};
use uuid::Uuid;

#[cfg(test)]
thread_local! { static TEST_READ_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
#[cfg(test)]
pub(crate) fn reset_read_bytes() {
    TEST_READ_BYTES.with(|v| v.set(0));
}
#[cfg(test)]
pub(crate) fn read_bytes_count() -> usize {
    TEST_READ_BYTES.with(|v| v.get())
}

const ARTIFACT_MAX: usize = 16 * 1024 * 1024;
const SESSION_MAX: usize = 128 * 1024 * 1024;
const PAGE_MAX: usize = 64 * 1024;
const META_MAX: usize = 16 * 1024;
const MAGIC: &[u8; 8] = b"ARTIF001";

#[cfg(test)]
thread_local! { static FAIL_AFTER_PUBLISH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactOrigin {
    pub actor: Option<String>,
    pub turn: u64,
    pub tool: String,
    pub call_id: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactMeta {
    pub version: u32,
    pub id: String,
    pub session_id: String,
    pub origin: ArtifactOrigin,
    pub bytes: usize,
    pub sha256: String,
    pub truncated: bool,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ArtifactPage {
    pub meta: ArtifactMeta,
    pub start_line: usize,
    pub content: String,
    pub next_line: Option<usize>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ArtifactBytePage {
    pub meta: ArtifactMeta,
    pub offset: usize,
    pub content: String,
    pub next_offset: Option<usize>,
}

#[derive(Debug)]
pub struct ArtifactStore {
    parent: Dir,
    dir: Dir,
    session_id: String,
    quota: std::sync::Arc<crate::artifact_quota::Pool>,
    reservation: Option<Uuid>,
}

/// Резерв квоты хоста, не физическое резервирование диска. Все экземпляры store
/// этого процесса учитывают его; runtime дополнительно держит session lease.
pub struct ArtifactReservation(crate::artifact_quota::Reservation);

/// Borrow не позволяет вернуть остаток резерва до завершения всех записей view.
pub struct ReservedArtifacts<'a> {
    store: ArtifactStore,
    _reservation: &'a ArtifactReservation,
}
impl std::ops::Deref for ReservedArtifacts<'_> {
    type Target = ArtifactStore;
    fn deref(&self) -> &Self::Target {
        &self.store
    }
}

fn disk<T>(r: std::io::Result<T>) -> Result<T> {
    r.map_err(|_| anyhow!("Ошибка файлового хранилища артефактов"))
}
fn valid_id(id: &str) -> Result<()> {
    let u = Uuid::parse_str(id).map_err(|_| anyhow!("Некорректный идентификатор артефакта"))?;
    ensure!(
        u.get_version_num() == 4
            && u.get_variant() == uuid::Variant::RFC4122
            && u.to_string() == id,
        "Некорректный идентификатор артефакта"
    );
    Ok(())
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn same(a: &Metadata, b: &Metadata) -> bool {
    MetadataExt::dev(a) == MetadataExt::dev(b) && MetadataExt::ino(a) == MetadataExt::ino(b)
}
fn private_file(m: &Metadata) -> Result<()> {
    ensure!(
        m.is_file() && !m.file_type().is_symlink() && MetadataExt::nlink(m) == 1,
        "Небезопасный файл артефакта"
    );
    #[cfg(unix)]
    ensure!(m.mode() & 0o7777 == 0o600, "Небезопасные права артефакта");
    Ok(())
}
fn cut(s: &mut String, limit: usize) {
    let mut n = limit.min(s.len());
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    s.truncate(n);
}

fn redact_bounded(text: &str, secrets: &[String]) -> Result<(String, usize)> {
    let mut redactor = crate::redaction::StreamingRedactor::new(secrets)?;
    let mut bytes = Vec::new();
    let mut total = 0usize;
    let mut accept = |clean: Vec<u8>| {
        total = total.saturating_add(clean.len());
        let take = clean.len().min(ARTIFACT_MAX.saturating_sub(bytes.len()));
        bytes.extend_from_slice(&clean[..take]);
    };
    for chunk in text.as_bytes().chunks(8192) {
        accept(redactor.push(chunk)?);
    }
    accept(redactor.finish()?);
    if let Err(error) = std::str::from_utf8(&bytes) {
        ensure!(
            error.error_len().is_none(),
            "Редактор секретов вернул некорректный UTF-8"
        );
        bytes.truncate(error.valid_up_to());
    }
    Ok((String::from_utf8(bytes)?, total))
}

impl ArtifactStore {
    /// Полная обязательная запись для intent/receipt: усечение и изменение
    /// идентификаторов запрещены. Ошибку записи caller считает неопределённым
    /// исходом хранения и не начинает зависимое внешнее действие.
    /// До вызова владелец обязан durable-опубликовать каталог сессии и новых
    /// предков: синхронизация самого session_dir не фиксирует его имя в родителе.
    pub fn capture_required(
        &self,
        origin: ArtifactOrigin,
        text: &str,
        secrets: &[String],
    ) -> Result<ArtifactMeta> {
        ensure!(
            cfg!(unix),
            "Durable receipts пока поддерживаются только на Unix"
        );
        self.capture_inner(origin, text, secrets, true)
    }

    /// Внутреннее чтение хоста, не модельный инструмент и не разрешение.
    /// Проверяет весь файл и точное metadata, затем синхронизирует файл/каталог.
    /// Требует той же предварительной публикации session_dir, что capture_required.
    pub fn verify_required(&self, meta: &ArtifactMeta) -> Result<String> {
        ensure!(
            cfg!(unix),
            "Durable receipts пока поддерживаются только на Unix"
        );
        ensure!(!meta.truncated, "Обязательный артефакт усечён");
        self.verify_output(meta)
    }

    /// Проверка сохранённого вывода хостом. Явно усечённый вывод допустим,
    /// но его флаг, происхождение и все сохранённые байты должны совпасть.
    /// Эта проверка не заменяет verify_required для intent/terminal.
    pub fn verify_output(&self, meta: &ArtifactMeta) -> Result<String> {
        ensure!(
            cfg!(unix),
            "Durable receipts пока поддерживаются только на Unix"
        );
        let _lock = self.lock()?;
        Ok(self.load_checked(&meta.id, Some(meta))?.1)
    }

    pub fn open(session_dir: &Path, session_id: &str) -> Result<Self> {
        ensure!(
            !session_id.is_empty() && session_id.len() <= 4096,
            "Некорректный идентификатор сессии"
        );
        // Only bootstrap directory creation is ambient; all artifact I/O is confined.
        let parent = disk(Dir::open_ambient_dir(session_dir, ambient_authority()))?;
        let mut builder = DirBuilder::new();
        #[cfg(unix)]
        builder.mode(0o700);
        match parent.create_dir_with("artifacts", &builder) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(_) => return Err(anyhow!("Не удалось создать каталог артефактов")),
        }
        let before = disk(parent.symlink_metadata("artifacts"))?;
        ensure!(
            before.is_dir() && !before.file_type().is_symlink(),
            "Небезопасный каталог артефактов"
        );
        #[cfg(unix)]
        ensure!(
            before.mode() & 0o7777 == 0o700,
            "Небезопасные права каталога артефактов"
        );
        let dir = disk(parent.open_dir_nofollow("artifacts"))?;
        ensure!(
            same(&before, &disk(dir.dir_metadata())?),
            "Каталог артефактов изменился"
        );
        let metadata = disk(dir.dir_metadata())?;
        let quota = crate::artifact_quota::shared((
            MetadataExt::dev(&metadata),
            MetadataExt::ino(&metadata),
        ))?;
        let store = Self {
            parent,
            dir,
            session_id: session_id.into(),
            quota,
            reservation: None,
        };
        let _lock = store.lock()?;
        store.recover_staging()?;
        store.used()?;
        Ok(store)
    }

    pub fn reserve_capacity(&self, bytes: usize) -> Result<ArtifactReservation> {
        ensure!(
            self.reservation.is_none(),
            "Нельзя создавать резерв из reserved view"
        );
        let _lock = self.lock()?;
        self.recover_staging()?;
        Ok(ArtifactReservation(self.quota.reserve(
            self.used()?,
            bytes,
            SESSION_MAX,
        )?))
    }

    pub fn reserved<'a>(
        &self,
        reservation: &'a ArtifactReservation,
    ) -> Result<ReservedArtifacts<'a>> {
        ensure!(
            reservation.0.belongs_to(&self.quota),
            "Резерв принадлежит другому хранилищу"
        );
        self.check_bound()?;
        Ok(ReservedArtifacts {
            store: Self {
                parent: disk(self.parent.try_clone())?,
                dir: disk(self.dir.try_clone())?,
                session_id: self.session_id.clone(),
                quota: self.quota.clone(),
                reservation: Some(reservation.0.id()),
            },
            _reservation: reservation,
        })
    }

    fn check_bound(&self) -> Result<()> {
        let current = disk(self.parent.symlink_metadata("artifacts"))?;
        ensure!(
            current.is_dir()
                && !current.file_type().is_symlink()
                && same(&current, &disk(self.dir.dir_metadata())?),
            "Каталог артефактов изменился"
        );
        #[cfg(unix)]
        ensure!(
            current.mode() & 0o7777 == 0o700,
            "Небезопасные права каталога артефактов"
        );
        Ok(())
    }

    fn checked_open(&self, name: &str) -> Result<cap_std::fs::File> {
        self.check_bound()?;
        let before = disk(self.dir.symlink_metadata(name))?;
        private_file(&before)?;
        let mut opts = OpenOptions::new();
        opts.read(true).follow(FollowSymlinks::No).nonblock(true);
        let file = disk(self.dir.open_with(name, &opts))?;
        let after = disk(file.metadata())?;
        private_file(&after)?;
        ensure!(same(&before, &after), "Файл артефакта изменился");
        Ok(file)
    }

    fn lock(&self) -> Result<fs::File> {
        self.check_bound()?;
        let mut opts = OpenOptions::new();
        opts.read(true)
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No)
            .nonblock(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let file = match self.dir.open_with(".lock", &opts) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                self.checked_open(".lock")?
            }
            Err(_) => return Err(anyhow!("Не удалось создать блокировку артефактов")),
        };
        let opened = disk(file.metadata())?;
        let file = file.into_std();
        disk(FileExt::lock_exclusive(&file))?;
        let current = disk(self.dir.symlink_metadata(".lock"))?;
        private_file(&current)?;
        ensure!(
            same(&current, &opened) && opened.len() == 0,
            "Повреждена блокировка артефактов"
        );
        Ok(file)
    }

    fn load(&self, id: &str) -> Result<(ArtifactMeta, String, usize)> {
        self.load_checked(id, None)
    }

    fn load_checked(
        &self,
        id: &str,
        required: Option<&ArtifactMeta>,
    ) -> Result<(ArtifactMeta, String, usize)> {
        valid_id(id)?;
        let mut f = self.checked_open(id)?;
        let opened = disk(f.metadata())?;
        let len = opened.len();
        ensure!(
            len >= 12 && len <= (12 + META_MAX + ARTIFACT_MAX) as u64,
            "Недопустимый размер артефакта"
        );
        let mut header = [0u8; 12];
        disk(f.read_exact(&mut header))?;
        ensure!(&header[..8] == MAGIC, "Повреждён формат артефакта");
        let n = u32::from_le_bytes(
            header[8..12]
                .try_into()
                .map_err(|_| anyhow!("Повреждён заголовок"))?,
        ) as usize;
        ensure!(
            n <= META_MAX && 12 + n <= len as usize,
            "Повреждены метаданные артефакта"
        );
        let mut json = vec![0; n];
        disk(f.read_exact(&mut json))?;
        let meta: ArtifactMeta = serde_json::from_slice(&json)
            .map_err(|_| anyhow!("Повреждены метаданные артефакта"))?;
        ensure!(
            meta.version == 1
                && meta.id == id
                && meta.session_id == self.session_id
                && meta.bytes <= ARTIFACT_MAX
                && 12 + n + meta.bytes == len as usize,
            "Несовместимые метаданные артефакта"
        );
        if let Some(expected) = required {
            // Compare the immutable reference before allocating or reading the
            // body. A same-UID replacement with different metadata must not
            // turn a small expected output into an unbounded read.
            ensure!(
                meta == *expected,
                "Метаданные сохранённого артефакта не совпадают"
            );
        }
        #[cfg(test)]
        TEST_READ_BYTES.with(|v| v.set(v.get().saturating_add(meta.bytes)));
        let mut bytes = vec![0; meta.bytes];
        disk(f.read_exact(&mut bytes))?;
        let mut extra = [0];
        ensure!(
            disk(f.read(&mut extra))? == 0,
            "Артефакт изменился во время чтения"
        );
        ensure!(
            hash(&bytes) == meta.sha256,
            "Контрольная сумма артефакта не совпадает"
        );
        let text = String::from_utf8(bytes)
            .map_err(|_| anyhow!("Артефакт содержит некорректный UTF-8"))?;
        if let Some(expected) = required {
            let _ = expected;
            disk(f.sync_all())?;
            #[cfg(unix)]
            {
                disk(disk(self.dir.open("."))?.sync_all())?;
                disk(disk(self.parent.open("."))?.sync_all())?;
            }
        }
        self.check_bound()?;
        let current = disk(self.dir.symlink_metadata(id))?;
        private_file(&current)?;
        ensure!(
            same(&opened, &current) && current.len() == len,
            "Артефакт изменился во время чтения"
        );
        Ok((meta, text, len as usize))
    }

    /// Only canonical names minted by capture are staging. No receipt refers
    /// to them. An exclusive lock ensures no cooperating publisher is active.
    fn recover_staging(&self) -> Result<()> {
        let mut removed = false;
        for entry in disk(self.dir.read_dir("."))? {
            let entry = disk(entry)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(id) = name.strip_prefix('.').and_then(|s| s.strip_suffix(".tmp")) else {
                continue;
            };
            if valid_id(id).is_err() {
                continue;
            }
            let mut options = OpenOptions::new();
            options.read(true).follow(FollowSymlinks::No).nonblock(true);
            let file = disk(self.dir.open_with(name, &options))?;
            let metadata = disk(file.metadata())?;
            ensure!(
                metadata.is_file()
                    && MetadataExt::nlink(&metadata) <= 2
                    && metadata.len() <= (ARTIFACT_MAX + META_MAX + 12) as u64,
                "Небезопасный staging артефакта"
            );
            #[cfg(unix)]
            ensure!(
                metadata.mode() & 0o7777 == 0o600,
                "Небезопасные права staging артефакта"
            );
            let current = disk(self.dir.symlink_metadata(name))?;
            ensure!(same(&metadata, &current), "Staging артефакта изменился");
            drop(file);
            disk(self.dir.remove_file(name))?;
            removed = true;
        }
        #[cfg(unix)]
        if removed {
            disk(disk(self.dir.open("."))?.sync_all())?;
        }
        #[cfg(not(unix))]
        let _ = removed;
        Ok(())
    }

    fn used(&self) -> Result<usize> {
        let mut total = 0usize;
        for entry in disk(self.dir.read_dir("."))? {
            let entry = disk(entry)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow!("Неизвестный файл в хранилище"))?;
            if name == ".lock" {
                continue;
            }
            valid_id(&name)?;
            let size = disk(self.dir.symlink_metadata(&name))?.len();
            ensure!(size <= SESSION_MAX as u64, "Превышена квота сессии");
            let next = total
                .checked_add(size as usize)
                .ok_or_else(|| anyhow!("Переполнение квоты"))?;
            ensure!(next <= SESSION_MAX, "Превышена квота сессии");
            self.load(&name)?;
            total = next;
        }
        Ok(total)
    }

    pub fn capture(
        &self,
        origin: ArtifactOrigin,
        text: &str,
        secrets: &[String],
    ) -> Result<ArtifactMeta> {
        self.capture_inner(origin, text, secrets, false)
    }

    fn capture_inner(
        &self,
        origin: ArtifactOrigin,
        text: &str,
        secrets: &[String],
        required: bool,
    ) -> Result<ArtifactMeta> {
        ensure!(
            origin.actor.as_ref().is_none_or(|a| !a.is_empty()
                && a.len() <= 128
                && a.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')),
            "Некорректный actor артефакта"
        );
        ensure!(
            origin.tool.len() <= 128 && origin.call_id.len() <= 256,
            "Слишком большие идентификаторы receipt"
        );
        ensure!(
            redact_bounded(&self.session_id, secrets)?.0 == self.session_id,
            "Секрет в идентификаторе сессии"
        );
        let mut origin = origin;
        // Origin IDs have host semantics: do not silently change an ACL principal.
        if let Some(actor) = &origin.actor {
            let (clean, _) = redact_bounded(actor, secrets)?;
            ensure!(clean == *actor, "Секрет в идентификаторе actor");
        }
        let clean_tool = redact_bounded(&origin.tool, secrets)?.0;
        let clean_call_id = redact_bounded(&origin.call_id, secrets)?.0;
        if required {
            ensure!(
                !origin.tool.is_empty() && !origin.call_id.is_empty(),
                "Пустой идентификатор обязательного receipt"
            );
            ensure!(
                clean_tool == origin.tool && clean_call_id == origin.call_id,
                "Секрет в идентификаторе обязательного receipt"
            );
        }
        origin.tool = clean_tool;
        origin.call_id = clean_call_id;
        let (mut content, original_len) = redact_bounded(text, secrets)?;
        ensure!(
            !required || content.len() == original_len,
            "Обязательный артефакт превышает лимит размера"
        );
        let _lock = self.lock()?;
        self.recover_staging()?;
        let available = self
            .quota
            .available(self.used()?, SESSION_MAX, self.reservation)?;
        let id = Uuid::new_v4().to_string();
        let mut meta = ArtifactMeta {
            version: 1,
            id: id.clone(),
            session_id: self.session_id.clone(),
            origin,
            bytes: 0,
            sha256: String::new(),
            truncated: false,
        };
        let json = loop {
            meta.bytes = content.len();
            meta.sha256 = hash(content.as_bytes());
            meta.truncated = content.len() < original_len;
            let json =
                serde_json::to_vec(&meta).map_err(|_| anyhow!("Не удалось записать метаданные"))?;
            ensure!(
                json.len() <= META_MAX,
                "Слишком большие метаданные артефакта"
            );
            let overhead = 12 + json.len();
            ensure!(available >= overhead, "Квота сессии исчерпана");
            if overhead + content.len() <= available {
                break json;
            }
            ensure!(
                !required,
                "Недостаточно квоты для полного обязательного артефакта"
            );
            cut(&mut content, available - overhead);
        };
        let tmp = format!(".{}.tmp", Uuid::new_v4());
        let mut opts = OpenOptions::new();
        opts.write(true)
            .create_new(true)
            .follow(FollowSymlinks::No)
            .nonblock(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut file = disk(self.dir.open_with(&tmp, &opts))?;
        let written = (|| -> Result<()> {
            disk(file.write_all(MAGIC))?;
            disk(file.write_all(&(json.len() as u32).to_le_bytes()))?;
            disk(file.write_all(&json))?;
            disk(file.write_all(content.as_bytes()))?;
            disk(file.sync_all())?;
            Ok(())
        })();
        drop(file);
        if let Err(e) = written {
            disk(self.dir.remove_file(&tmp))?;
            return Err(e);
        }
        self.check_bound()?;
        // Linking publishes the complete blob atomically and cannot replace an existing ID.
        if let Err(e) = self.dir.hard_link(&tmp, &self.dir, &id) {
            disk(self.dir.remove_file(&tmp))?;
            return disk::<ArtifactMeta>(Err(e));
        }
        if let Some(reservation) = self.reservation {
            self.quota
                .consume(reservation, 12 + json.len() + content.len())?;
        }
        #[cfg(test)]
        ensure!(
            !FAIL_AFTER_PUBLISH.with(|fault| fault.replace(false)),
            "Ошибка после публикации артефакта"
        );
        disk(self.dir.remove_file(&tmp))?;
        #[cfg(unix)]
        {
            disk(disk(self.dir.open("."))?.sync_all())?;
            if required {
                disk(disk(self.parent.open("."))?.sync_all())?;
            }
        }
        Ok(meta)
    }

    /// UTF-8-safe byte cursor, including single lines longer than a page.
    pub fn read_bytes(
        &self,
        actor: Option<&str>,
        id: &str,
        offset: usize,
        max_bytes: usize,
    ) -> Result<ArtifactBytePage> {
        ensure!(
            (1..=PAGE_MAX).contains(&max_bytes),
            "Размер страницы должен быть от 1 до 65536 байт"
        );
        let (meta, text, _) = self.load(id)?;
        ensure!(
            actor.is_none()
                || meta.origin.tool != "command_lifetime"
                || serde_json::from_str::<serde_json::Value>(&text)
                    .ok()
                    .is_none_or(|v| v["version"] != 2 || v.get("handoff").is_none()),
            "Epoch manifest requires typed poll_command; raw worker access denied"
        );
        ensure!(
            actor.is_none() || actor == meta.origin.actor.as_deref(),
            "Доступ к артефакту запрещён"
        );
        ensure!(
            offset <= text.len() && text.is_char_boundary(offset),
            "Некорректное смещение UTF-8"
        );
        let mut end = offset.saturating_add(max_bytes).min(text.len());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        ensure!(
            end > offset || offset == text.len(),
            "Размер страницы меньше одного символа UTF-8"
        );
        Ok(ArtifactBytePage {
            meta,
            offset,
            content: text[offset..end].to_owned(),
            next_offset: (end < text.len()).then_some(end),
        })
    }

    pub fn read(
        &self,
        actor: Option<&str>,
        id: &str,
        start_line: usize,
        max_lines: usize,
        query: Option<&str>,
    ) -> Result<ArtifactPage> {
        valid_id(id)?;
        ensure!(
            start_line >= 1 && (1..=500).contains(&max_lines),
            "Недопустимые параметры страницы"
        );
        ensure!(
            query.is_none_or(|q| q.len() <= ARTIFACT_MAX),
            "Слишком длинный поисковый запрос"
        );
        let (meta, text, _) = self.load(id)?;
        ensure!(
            actor.is_none()
                || meta.origin.tool != "command_lifetime"
                || serde_json::from_str::<serde_json::Value>(&text)
                    .ok()
                    .is_none_or(|v| v["version"] != 2 || v.get("handoff").is_none()),
            "Epoch manifest requires typed poll_command; raw worker access denied"
        );
        ensure!(
            actor.is_none() || actor == meta.origin.actor.as_deref(),
            "Доступ к артефакту запрещён"
        );
        let mut content = String::new();
        let mut count = 0;
        let mut next_line = None;
        let mut lines = text.split_inclusive('\n').enumerate().peekable();
        while let Some((index, line)) = lines.next() {
            let number = index + 1;
            if number < start_line {
                continue;
            }
            ensure!(
                line.len() <= PAGE_MAX,
                "Строка превышает допустимые 64 КиБ; чтение остановлено"
            );
            if query.is_some_and(|q| !line.contains(q)) {
                continue;
            }
            let rendered = if query.is_some() {
                format!("{number}: {line}")
            } else {
                line.to_owned()
            };
            ensure!(
                rendered.len() <= PAGE_MAX,
                "Строка с номером превышает допустимый размер страницы"
            );
            if content.len() + rendered.len() > PAGE_MAX {
                next_line = Some(number);
                break;
            }
            content.push_str(&rendered);
            count += 1;
            if count == max_lines {
                next_line = lines.peek().map(|(i, _)| i + 1);
                break;
            }
        }
        Ok(ArtifactPage {
            meta,
            start_line,
            content,
            next_line,
        })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    fn setup() -> (tempfile::TempDir, ArtifactStore) {
        let t = tempfile::tempdir().unwrap();
        let s = ArtifactStore::open(t.path(), "session").unwrap();
        (t, s)
    }
    fn origin(actor: Option<&str>) -> ArtifactOrigin {
        ArtifactOrigin {
            actor: actor.map(str::to_owned),
            turn: 1,
            tool: "tool".into(),
            call_id: "call".into(),
        }
    }
    fn receipt(s: &ArtifactStore, text: &str) -> ArtifactMeta {
        s.capture(origin(Some("worker")), text, &[]).unwrap()
    }
    #[test]
    fn reservation_protects_output_budget_across_store_handles_and_releases_unused_bytes() {
        let (t, s) = setup();
        let reserved = s.reserve_capacity(SESSION_MAX - 4096).unwrap();
        let other = ArtifactStore::open(t.path(), "session").unwrap();
        let large = "x".repeat(8192);
        assert!(other.capture_required(origin(None), &large, &[]).is_err());
        let (_foreign_dir, foreign) = setup();
        assert!(foreign.reserved(&reserved).is_err());
        {
            let view = s.reserved(&reserved).unwrap();
            let meta = view.capture_required(origin(None), &large, &[]).unwrap();
            assert_eq!(s.verify_required(&meta).unwrap(), large);
            assert!(other.capture_required(origin(None), &large, &[]).is_err());
        }
        drop(reserved);
        other.capture_required(origin(None), &large, &[]).unwrap();
    }

    #[test]
    fn failed_post_publish_sync_does_not_spend_another_reservation() {
        let (_temp, s) = setup();
        let first = s.reserve_capacity(SESSION_MAX - 4096).unwrap();
        let second = s.reserve_capacity(4096).unwrap();
        let view = s.reserved(&first).unwrap();
        FAIL_AFTER_PUBLISH.with(|fault| fault.set(true));
        assert!(
            view.capture_required(origin(None), &"x".repeat(1024), &[])
                .is_err()
        );
        let other = s.reserved(&second).unwrap();
        let meta = other
            .capture_required(origin(None), &"y".repeat(3500), &[])
            .unwrap();
        assert_eq!(other.verify_required(&meta).unwrap(), "y".repeat(3500));
    }
    #[test]
    fn required_capture_preserves_origin_and_complete_redacted_content() {
        let (t, s) = setup();
        let secret = "private-required-secret".to_owned();
        let supplied = origin(Some("worker"));
        let m = s
            .capture_required(
                supplied.clone(),
                &format!("ёж {secret}"),
                std::slice::from_ref(&secret),
            )
            .unwrap();
        assert_eq!(
            serde_json::to_value(&m.origin).unwrap(),
            serde_json::to_value(&supplied).unwrap()
        );
        assert!(!m.truncated);
        let text = s.verify_required(&m).unwrap();
        assert!(text.starts_with("ёж ") && !text.contains(&secret));
        for field in ["actor", "tool", "call_id"] {
            let mut o = origin(None);
            match field {
                "actor" => o.actor = Some(secret.clone()),
                "tool" => o.tool = secret.clone(),
                _ => o.call_id = secret.clone(),
            }
            assert!(
                s.capture_required(o, "payload", std::slice::from_ref(&secret))
                    .is_err()
            );
        }
        let before = fs::read_dir(t.path().join("artifacts")).unwrap().count();
        assert!(
            s.capture_required(origin(None), &"я".repeat(ARTIFACT_MAX / 2 + 1), &[])
                .is_err()
        );
        assert_eq!(
            fs::read_dir(t.path().join("artifacts")).unwrap().count(),
            before
        );
    }

    #[test]
    fn required_verifier_rejects_forged_metadata_and_truncation() {
        let (t, s) = setup();
        let m = s.capture_required(origin(None), "payload", &[]).unwrap();
        for field in ["turn", "tool", "call_id", "sha256", "bytes", "truncated"] {
            let mut forged = m.clone();
            match field {
                "turn" => forged.origin.turn += 1,
                "tool" => forged.origin.tool.push('x'),
                "call_id" => forged.origin.call_id.push('x'),
                "sha256" => forged.sha256 = "0".repeat(64),
                "bytes" => forged.bytes += 1,
                _ => forged.truncated = true,
            }
            assert!(s.verify_required(&forged).is_err(), "{field}");
        }
        let truncated = s
            .capture(origin(None), &"x".repeat(ARTIFACT_MAX + 1), &[])
            .unwrap();
        assert!(truncated.truncated);
        assert!(s.verify_required(&truncated).is_err());
        let path = t.path().join("artifacts").join(&m.id);
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() = b'x';
        fs::write(path, bytes).unwrap();
        assert!(s.verify_required(&m).is_err());
    }

    #[test]
    fn output_verification_preserves_truncation_and_rejects_forgery_or_corruption() {
        let (t, s) = setup();
        let meta = s
            .capture(origin(Some("worker")), &"x".repeat(ARTIFACT_MAX + 1), &[])
            .unwrap();
        assert!(meta.truncated);
        assert_eq!(s.verify_output(&meta).unwrap().len(), ARTIFACT_MAX);
        assert!(s.verify_required(&meta).is_err());
        let mut forged = meta.clone();
        forged.truncated = false;
        assert!(s.verify_output(&forged).is_err());
        forged = meta.clone();
        forged.origin.actor = None;
        assert!(s.verify_output(&forged).is_err());
        let path = t.path().join("artifacts").join(&meta.id);
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() = b'y';
        fs::write(path, bytes).unwrap();
        assert!(s.verify_output(&meta).is_err());
    }

    #[test]
    fn required_metadata_mismatch_is_rejected_before_reading_artifact_body() {
        let (_t, s) = setup();
        let meta = s
            .capture(origin(Some("worker")), &"x".repeat(1024 * 1024), &[])
            .unwrap();
        let mut forged = meta.clone();
        forged.bytes -= 1;
        reset_read_bytes();
        assert!(s.verify_output(&forged).is_err());
        assert_eq!(
            read_bytes_count(),
            0,
            "mismatched reference must fail before body allocation/read"
        );
    }

    #[test]
    fn required_capture_refuses_session_quota_without_publishing_partial_json() {
        let (t, s) = setup();
        let text = "x".repeat(ARTIFACT_MAX);
        for _ in 0..7 {
            s.capture_required(origin(None), &text, &[]).unwrap();
        }
        let before = fs::read_dir(t.path().join("artifacts")).unwrap().count();
        assert!(s.capture_required(origin(None), &text, &[]).is_err());
        assert_eq!(
            fs::read_dir(t.path().join("artifacts")).unwrap().count(),
            before
        );
        let m = s.capture(origin(None), &text, &[]).unwrap();
        assert!(m.truncated);
    }

    #[test]
    fn replaced_artifact_directory_invalidates_required_receipts() {
        let (t, s) = setup();
        let m = s.capture_required(origin(None), "payload", &[]).unwrap();
        fs::rename(t.path().join("artifacts"), t.path().join("old-artifacts")).unwrap();
        let _replacement = ArtifactStore::open(t.path(), "session").unwrap();
        assert!(s.verify_required(&m).is_err());
        assert!(s.capture_required(origin(None), "new", &[]).is_err());
        assert_eq!(
            fs::read_dir(t.path().join("old-artifacts"))
                .unwrap()
                .count(),
            2
        );
    }
    #[test]
    fn acl_and_session_binding() {
        let (t, s) = setup();
        let m = receipt(&s, "private");
        assert!(s.read(None, &m.id, 1, 1, None).is_ok());
        assert!(s.read(Some("worker"), &m.id, 1, 1, None).is_ok());
        assert!(s.read(Some("other"), &m.id, 1, 1, None).is_err());
        let main = s.capture(origin(None), "main", &[]).unwrap();
        assert!(s.read(Some("worker"), &main.id, 1, 1, None).is_err());
        assert!(ArtifactStore::open(t.path(), "different").is_err());
        assert!(ArtifactStore::open(t.path(), "session").is_ok());
    }
    #[test]
    fn identifiers_symlinks_and_permissions() {
        let (t, s) = setup();
        for id in [
            "../outside",
            "/etc/passwd",
            ".lock",
            "00000000-0000-0000-0000-000000000000",
        ] {
            assert!(s.read(None, id, 1, 1, None).is_err());
        }
        let m = receipt(&s, "safe");
        let dir = t.path().join("artifacts");
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(dir.join(&m.id)).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let alias = Uuid::new_v4().to_string();
        symlink(dir.join(&m.id), dir.join(&alias)).unwrap();
        assert!(s.read(None, &alias, 1, 1, None).is_err());
        assert!(s.capture(origin(None), "x", &[]).is_err());
        fs::remove_file(dir.join(alias)).unwrap();
        let name = Uuid::new_v4().to_string();
        fs::create_dir(dir.join(&name)).unwrap();
        assert!(s.read(None, &name, 1, 1, None).is_err());
        let other = tempfile::tempdir().unwrap();
        symlink(&dir, other.path().join("artifacts")).unwrap();
        assert!(ArtifactStore::open(other.path(), "session").is_err());
    }
    #[test]
    fn utf8_pages_literal_queries_and_long_lines() {
        let (_t, s) = setup();
        let m = receipt(&s, "ёж\na.*\nещё\na.* конец\n");
        let p = s.read(None, &m.id, 1, 2, None).unwrap();
        assert_eq!(p.content, "ёж\na.*\n");
        assert_eq!(p.next_line, Some(3));
        let p = s.read(None, &m.id, 1, 1, Some("a.*")).unwrap();
        assert_eq!(p.content, "2: a.*\n");
        assert_eq!(p.next_line, Some(3));
        assert_eq!(
            s.read(None, &m.id, 3, 5, Some("a.*")).unwrap().content,
            "4: a.* конец\n"
        );
        assert!(s.read(None, &m.id, 0, 1, None).is_err());
        assert!(s.read(None, &m.id, 1, 501, None).is_err());
        let m = receipt(&s, &format!("{}\n{}", "я".repeat(16384), "я".repeat(16384)));
        let p = s.read(None, &m.id, 1, 500, None).unwrap();
        assert!(p.content.len() <= PAGE_MAX);
        assert_eq!(p.next_line, Some(2));
        let m = receipt(&s, &"x".repeat(PAGE_MAX + 1));
        assert!(s.read(None, &m.id, 1, 1, None).is_err());
    }
    #[test]
    fn real_quotas_and_explicit_truncation() {
        let (_t, s) = setup();
        let text = "я".repeat(ARTIFACT_MAX / 2 + 1);
        for i in 0..8 {
            let m = receipt(&s, &text);
            assert!(m.truncated && m.bytes <= ARTIFACT_MAX);
            if i == 0 {
                assert_eq!(m.bytes, ARTIFACT_MAX);
            }
            if i == 7 {
                assert!(m.bytes < ARTIFACT_MAX);
            }
        }
        assert!(s.used().unwrap() <= SESSION_MAX);
        assert!(s.capture(origin(None), "x", &[]).is_err());
    }
    #[test]
    fn corruption_and_unknown_files_fail_closed() {
        let (t, s) = setup();
        let m = receipt(&s, "payload");
        let path = t.path().join("artifacts").join(&m.id);
        let original = fs::read(&path).unwrap();
        let n = u32::from_le_bytes(original[8..12].try_into().unwrap()) as usize;
        for field in ["version", "id", "session_id", "sha256", "bytes"] {
            let mut json: serde_json::Value =
                serde_json::from_slice(&original[12..12 + n]).unwrap();
            json[field] = match field {
                "version" => 2.into(),
                "bytes" => 999.into(),
                "id" => Uuid::new_v4().to_string().into(),
                _ => "wrong".into(),
            };
            let json = serde_json::to_vec(&json).unwrap();
            let mut blob = MAGIC.to_vec();
            blob.extend_from_slice(&(json.len() as u32).to_le_bytes());
            blob.extend_from_slice(&json);
            blob.extend_from_slice(&original[12 + n..]);
            fs::write(&path, blob).unwrap();
            assert!(s.read(None, &m.id, 1, 1, None).is_err());
            assert!(s.capture(origin(None), "x", &[]).is_err());
        }
        fs::write(&path, original).unwrap();
        fs::write(t.path().join("artifacts/.abandoned.tmp"), b"partial").unwrap();
        assert!(s.capture(origin(None), "x", &[]).is_err());
    }
    #[test]
    fn redaction_and_atomic_completed_publication() {
        let (t, s) = setup();
        let secret = "private-credential-123456";
        let m = s
            .capture(
                origin(None),
                &format!("before {secret} after"),
                &[secret.into()],
            )
            .unwrap();
        let p = s.read(None, &m.id, 1, 1, None).unwrap();
        assert!(!p.content.contains(secret));
        let dir = t.path().join("artifacts");
        let raw = fs::read(dir.join(&m.id)).unwrap();
        assert!(!raw.windows(secret.len()).any(|w| w == secret.as_bytes()));
        let mut bad = origin(None);
        bad.tool = "x".repeat(META_MAX * 2);
        assert!(s.capture(bad, secret, &[secret.into()]).is_err());
        let mut names: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        names.sort();
        assert_eq!(names.len(), 2);
        assert!(
            names
                .iter()
                .all(|n| n == ".lock" || n.to_str() == Some(&m.id))
        );
        assert_eq!(s.load(&m.id).unwrap().0.sha256, hash(p.content.as_bytes()));
    }
}
