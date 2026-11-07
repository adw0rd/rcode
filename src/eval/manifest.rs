//! Suite input is data. Validation never executes probes, discovery or hooks.
use anyhow::{Context, Result, ensure};
use cap_fs_ext::{DirExt, FollowSymlinks, MetadataExt, OpenOptionsFollowExt, OpenOptionsSyncExt};
#[cfg(unix)]
use cap_std::fs::MetadataExt as UnixMetadataExt;
use cap_std::fs::{Dir, OpenOptions};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::{Component, Path},
};

const FILE: usize = 2 * 1024 * 1024;
const TOTAL: usize = 64 * 1024 * 1024;
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Case {
    pub id: String,
    pub language: String,
    pub category: String,
    pub project: String,
    pub task: String,
    pub oracle: String,
    pub max_steps: u32,
    #[serde(default = "requests")]
    pub max_requests: u32,
    pub timeout_secs: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<Lifecycle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_tool_success: Option<String>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Lifecycle {
    pub interrupt_after_file: String,
    pub resume_prompt: String,
}
fn requests() -> u32 {
    24
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    cases: Vec<Case>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Command {
    pub argv: Vec<String>,
    #[serde(default)]
    pub stdin: String,
    #[serde(default = "probe_timeout")]
    pub timeout_secs: u64,
}
fn probe_timeout() -> u64 {
    30
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Check {
    pub id: String,
    pub argv: Vec<String>,
    #[serde(default)]
    pub stdin: String,
    #[serde(default = "probe_timeout")]
    pub timeout_secs: u64,
    pub expected_exit: i32,
    #[serde(default)]
    pub expected_stdout: Option<String>,
    #[serde(default, deserialize_with = "present_json")]
    pub expected_json: Option<Value>,
}
fn present_json<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<Value>, D::Error> {
    Value::deserialize(d).map(Some)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Oracle {
    pub version: u32,
    #[serde(default)]
    pub prepare: Vec<Command>,
    pub checks: Vec<Check>,
}
pub(crate) struct Fixture {
    pub path: String,
    pub bytes: Vec<u8>,
    pub executable: bool,
}
pub(crate) struct ValidatedCase {
    pub case: Case,
    pub task: String,
    pub oracle: Oracle,
    pub files: Vec<Fixture>,
    pub sha256: String,
}
pub(crate) struct Suite {
    pub cases: Vec<ValidatedCase>,
    pub sha256: String,
}
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}
pub(crate) fn relative(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty()
            && path.len() <= 1024
            && !path.contains('\\')
            && !path.contains('\0')
            && path
                .split('/')
                .all(|s| !s.is_empty() && s != "." && s != ".."),
        "Недопустимый относительный путь"
    );
    ensure!(
        Path::new(path)
            .components()
            .all(|c| matches!(c, Component::Normal(_))),
        "Путь выходит из набора"
    );
    Ok(())
}
fn directory(root: &Dir, path: &str) -> Result<Dir> {
    relative(path)?;
    let mut d = root.try_clone()?;
    for c in Path::new(path).components() {
        d = d.open_dir_nofollow(c.as_os_str())?;
    }
    Ok(d)
}
fn read(root: &Dir, path: &str, total: &mut usize) -> Result<Vec<u8>> {
    relative(path)?;
    let p = Path::new(path);
    let parent = match p.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(v) => directory(root, v.to_str().context("UTF-8 path")?)?,
        None => root.try_clone()?,
    };
    let name = p.file_name().context("file name")?;
    let before = parent.symlink_metadata(name)?;
    ensure!(
        before.is_file() && !before.file_type().is_symlink() && before.len() <= FILE as u64,
        "Небезопасный файл набора или лимит"
    );
    ensure!(
        MetadataExt::nlink(&before) == 1,
        "Hardlink в наборе запрещён"
    );
    let mut opts = OpenOptions::new();
    opts.read(true).follow(FollowSymlinks::No).nonblock(true);
    let mut f = parent.open_with(name, &opts)?;
    let meta = f.metadata()?;
    ensure!(
        meta.is_file()
            && MetadataExt::dev(&meta) == MetadataExt::dev(&before)
            && MetadataExt::ino(&meta) == MetadataExt::ino(&before),
        "Файл изменился при открытии"
    );
    ensure!(MetadataExt::nlink(&meta) == 1, "Hardlink в наборе запрещён");
    let mut bytes = Vec::new();
    (&mut f).take((FILE + 1) as u64).read_to_end(&mut bytes)?;
    *total = total.checked_add(bytes.len()).context("Размер набора")?;
    ensure!(
        bytes.len() <= FILE && *total <= TOTAL,
        "Превышен размер набора"
    );
    Ok(bytes)
}
fn collect(
    root: &Dir,
    path: &str,
    local: &str,
    depth: usize,
    total: &mut usize,
    entries: &mut usize,
    out: &mut Vec<Fixture>,
) -> Result<()> {
    ensure!(
        depth <= 32 && out.len() < 10_000,
        "Превышен размер дерева проекта"
    );
    let d = directory(root, path)?;
    let mut names = Vec::new();
    for entry in d.entries()? {
        ensure!(names.len() < 10_000, "Слишком много файлов");
        *entries += 1;
        ensure!(*entries <= 10_000, "Превышен размер дерева набора");
        names.push(
            entry?
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("Не UTF-8 имя файла"))?,
        );
    }
    names.sort();
    for name in names {
        ensure!(
            name != "." && name != ".." && !name.contains(['\\', '/']),
            "Имя файла"
        );
        let full = format!("{path}/{name}");
        let rel = if local.is_empty() {
            name.clone()
        } else {
            format!("{local}/{name}")
        };
        let m = d.symlink_metadata(&name)?;
        if m.is_dir() && !m.file_type().is_symlink() {
            collect(root, &full, &rel, depth + 1, total, entries, out)?;
        } else {
            let bytes = read(root, &full, total)?;
            ensure!(out.len() < 10_000, "Слишком много файлов");
            #[cfg(unix)]
            let executable = m.mode() & 0o111 != 0;
            #[cfg(not(unix))]
            let executable = false;
            out.push(Fixture {
                path: rel,
                bytes,
                executable,
            });
        }
    }
    Ok(())
}
fn command(argv: &[String], stdin: &str, seconds: u64) -> Result<()> {
    ensure!(
        !argv.is_empty()
            && argv.len() <= 128
            && !argv[0].is_empty()
            && argv.iter().all(|s| !s.contains('\0')),
        "Некорректный argv"
    );
    ensure!(
        argv.iter().map(|a| a.len() + 1).sum::<usize>() <= 64 * 1024 && stdin.len() <= 64 * 1024,
        "Размер probe"
    );
    ensure!((1..=60).contains(&seconds), "Probe timeout вне 1–60");
    Ok(())
}
fn load_json<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_value(super::json::parse(bytes)?)
        .map_err(|_| anyhow::anyhow!("Неизвестные поля или неверная схема eval"))
}
fn hash(parts: &BTreeMap<String, Vec<u8>>) -> String {
    let mut h = Sha256::new();
    for (k, v) in parts {
        h.update((k.len() as u64).to_le_bytes());
        h.update(k);
        h.update((v.len() as u64).to_le_bytes());
        h.update(v);
    }
    format!("{:x}", h.finalize())
}
pub(crate) fn validate(path: &Path) -> Result<Suite> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let root = crate::instructions::root_dir(&std::fs::canonicalize(parent)?)?;
    let filename = path
        .file_name()
        .and_then(|s| s.to_str())
        .context("Имя manifest")?;
    let mut total = 0;
    let raw = read(&root, filename, &mut total)?;
    let m: Manifest = load_json(&raw)?;
    ensure!(m.version == 1, "Неизвестная версия manifest");
    ensure!(
        !m.cases.is_empty() && m.cases.len() <= 100,
        "Требуется 1–100 кейсов"
    );
    let mut ids = BTreeSet::new();
    for c in &m.cases {
        ensure!(
            valid_id(&c.id) && ids.insert(c.id.clone()),
            "Некорректный или повторный ID"
        );
        for p in [&c.project, &c.task, &c.oracle] {
            relative(p)?;
        }
        ensure!(
            matches!(
                c.language.as_str(),
                "python" | "rust" | "typescript" | "multifile"
            ),
            "Неизвестный язык"
        );
        ensure!(valid_id(&c.category), "Категория");
        if let Some(tool) = &c.require_tool_success {
            ensure!(
                !tool.is_empty()
                    && tool.len() <= 64
                    && tool.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                "Имя required tool"
            );
        }
        if let Some(lifecycle) = &c.lifecycle {
            relative(&lifecycle.interrupt_after_file)?;
            ensure!(
                !lifecycle.resume_prompt.is_empty() && lifecycle.resume_prompt.len() <= 4096,
                "Размер resume prompt"
            );
        }
        ensure!(
            (1..=64).contains(&c.max_steps)
                && (1..=128).contains(&c.max_requests)
                && (30..=600).contains(&c.timeout_secs),
            "Бюджет кейса вне границ"
        );
        for other in &m.cases {
            ensure!(
                !Path::new(&other.oracle).starts_with(&c.project),
                "Oracle попадает в проект модели"
            );
            if other.id != c.id {
                ensure!(
                    !Path::new(&other.project).starts_with(&c.project),
                    "Проекты кейсов пересекаются"
                );
            }
        }
    }
    let mut all = BTreeMap::from([(filename.to_owned(), raw)]);
    let mut cases = Vec::new();
    let mut entries = 0;
    for c in m.cases {
        let task = read(&root, &c.task, &mut total)?;
        ensure!(!task.is_empty() && task.len() <= 16 * 1024, "Размер задачи");
        let text = String::from_utf8(task.clone()).context("Задача не UTF-8")?;
        let raw = read(&root, &c.oracle, &mut total)?;
        let oracle: Oracle = load_json(&raw)?;
        ensure!(
            oracle.version == 1
                && !oracle.checks.is_empty()
                && oracle.checks.len() <= 32
                && oracle.prepare.len() <= 8,
            "Неверная версия/размер oracle"
        );
        let mut check_ids = BTreeSet::new();
        for p in &oracle.prepare {
            command(&p.argv, &p.stdin, p.timeout_secs)?;
        }
        for check in &oracle.checks {
            ensure!(
                valid_id(&check.id) && check_ids.insert(&check.id),
                "ID проверки"
            );
            command(&check.argv, &check.stdin, check.timeout_secs)?;
            ensure!(
                check.expected_stdout.is_some() != check.expected_json.is_some(),
                "Нужен ровно один тип expected"
            );
            ensure!(
                check
                    .expected_stdout
                    .as_ref()
                    .is_none_or(|s| s.len() <= 64 * 1024),
                "Размер expected"
            );
            ensure!(
                (0..=255).contains(&check.expected_exit),
                "Неверный expected exit"
            );
        }
        let mut files = Vec::new();
        collect(
            &root,
            &c.project,
            "",
            0,
            &mut total,
            &mut entries,
            &mut files,
        )?;
        ensure!(!files.is_empty(), "Пустой исходный проект");
        let mut parts = BTreeMap::from([
            ("case".into(), serde_json::to_vec(&c)?),
            ("task".into(), task),
            ("oracle".into(), raw),
        ]);
        for f in &files {
            let mut bytes = vec![u8::from(f.executable)];
            bytes.extend_from_slice(&f.bytes);
            parts.insert(format!("project/{}", f.path), bytes);
        }
        let digest = hash(&parts);
        for (k, v) in parts {
            all.insert(format!("{}/{k}", c.id), v);
        }
        cases.push(ValidatedCase {
            case: c,
            task: text,
            oracle,
            files,
            sha256: digest,
        });
    }
    Ok(Suite {
        cases,
        sha256: hash(&all),
    })
}
