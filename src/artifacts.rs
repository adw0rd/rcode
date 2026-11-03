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

const ARTIFACT_MAX: usize = 16 * 1024 * 1024;
const SESSION_MAX: usize = 128 * 1024 * 1024;
const PAGE_MAX: usize = 64 * 1024;
const META_MAX: usize = 16 * 1024;
const MAGIC: &[u8; 8] = b"ARTIF001";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactOrigin {
    pub actor: Option<String>,
    pub turn: u64,
    pub tool: String,
    pub call_id: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    dir: Dir,
    session_id: String,
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
        let store = Self {
            dir,
            session_id: session_id.into(),
        };
        let _lock = store.lock()?;
        store.recover_staging()?;
        store.used()?;
        Ok(store)
    }

    fn checked_open(&self, name: &str) -> Result<cap_std::fs::File> {
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
        valid_id(id)?;
        let mut f = self.checked_open(id)?;
        let len = disk(f.metadata())?.len();
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
        origin.tool = redact_bounded(&origin.tool, secrets)?.0;
        origin.call_id = redact_bounded(&origin.call_id, secrets)?.0;
        let (mut content, original_len) = redact_bounded(text, secrets)?;
        let _lock = self.lock()?;
        self.recover_staging()?;
        let available = SESSION_MAX - self.used()?;
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
        // Linking publishes the complete blob atomically and cannot replace an existing ID.
        if let Err(e) = self.dir.hard_link(&tmp, &self.dir, &id) {
            disk(self.dir.remove_file(&tmp))?;
            return disk::<ArtifactMeta>(Err(e));
        }
        disk(self.dir.remove_file(&tmp))?;
        #[cfg(unix)]
        disk(disk(self.dir.open("."))?.sync_all())?;
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
