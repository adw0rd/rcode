//! Workspace capabilities and durable, per-turn undo. Shell commands run with the
//! user's privileges; their side effects are deliberately not adopted by undo.
use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use cap_std::fs::{Dir, OpenOptions, Permissions};
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use regex::RegexBuilder;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio_util::sync::CancellationToken;

use crate::protocol::{ToolDefinition, ToolOutcome};

const MAX_FILE_BYTES: usize = 1024 * 1024;
const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_SCAN_BYTES: usize = 16 * 1024 * 1024;
const MAX_SCAN_FILES: usize = 5_000;
const MAX_ENTRIES: usize = 10_000;
const MAX_RESULTS: usize = 1_000;
const MAX_CHECKPOINT_BYTES: usize = 64 * 1024 * 1024;
const CHECKPOINT_FILE: &str = "checkpoints.json";
const SHELL_NOTE: &str = "Изменения shell-команд не управляются undo; изменения отслеживаемых файлов после записи вызывают конфликт.";

#[derive(Debug, thiserror::Error)]
#[error("Не удалось сохранить checkpoint: {0}")]
struct CheckpointFailure(String);

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoints {
    version: u32,
    root: PathBuf,
    turns: Vec<Turn>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Turn {
    entries: Vec<Change>,
    #[serde(default)]
    shell_used: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Change {
    path: PathBuf,
    before: Option<Vec<u8>>,
    mode: Option<u32>,
    readonly: bool,
    after_sha256: String,
}

struct Snapshot {
    bytes: Vec<u8>,
    permissions: Permissions,
}

struct Prepared {
    path: PathBuf,
    parent: Dir,
    name: OsString,
    before: Option<Snapshot>,
    after: Vec<u8>,
}

pub struct Tools {
    root: PathBuf,
    dir: Dir,
    checkpoint_dir: Dir,
    checkpoints: Checkpoints,
    active_turn: Option<usize>,
}

impl Tools {
    pub fn new(root: &Path, checkpoint_dir: &Path) -> Result<Self> {
        let root = std::fs::canonicalize(root).context("Рабочий каталог недоступен")?;
        ensure!(root.is_dir(), "Корень проекта должен быть каталогом");
        let checkpoint_absolute = std::path::absolute(checkpoint_dir)?;
        ensure!(
            !checkpoint_absolute.starts_with(&root),
            "Checkpoint должен храниться вне рабочего проекта"
        );
        std::fs::create_dir_all(checkpoint_dir)?;
        let checkpoint_path = std::fs::canonicalize(checkpoint_dir)?;
        ensure!(
            !checkpoint_path.starts_with(&root),
            "Checkpoint должен храниться вне рабочего проекта"
        );
        let dir = Dir::open_ambient_dir(&root, cap_std::ambient_authority())?;
        let checkpoint_dir = Dir::open_ambient_dir(checkpoint_path, cap_std::ambient_authority())?;
        #[cfg(unix)]
        {
            use cap_std::fs::PermissionsExt;
            checkpoint_dir.set_permissions(".", Permissions::from_mode(0o700))?;
        }
        let checkpoints = match snapshot(
            &checkpoint_dir,
            Path::new(CHECKPOINT_FILE),
            MAX_CHECKPOINT_BYTES,
        )? {
            Some(saved) => {
                #[cfg(unix)]
                {
                    use cap_std::fs::PermissionsExt;
                    checkpoint_dir
                        .set_permissions(CHECKPOINT_FILE, Permissions::from_mode(0o600))?;
                }
                let state: Checkpoints =
                    serde_json::from_slice(&saved.bytes).context("Повреждён checkpoint")?;
                ensure!(
                    state.version == 1 && state.root == root,
                    "Checkpoint относится к другому корню или версии"
                );
                ensure!(
                    state.turns.len() <= 1_000,
                    "Слишком много ходов в checkpoint"
                );
                for turn in &state.turns {
                    let mut seen = std::collections::HashSet::new();
                    for change in &turn.entries {
                        ensure!(
                            normalized_path(&change.path, false)? == change.path,
                            "Некорректный путь в checkpoint"
                        );
                        ensure!(seen.insert(&change.path), "Повтор пути в checkpoint");
                        ensure!(
                            change
                                .before
                                .as_ref()
                                .is_none_or(|b| b.len() <= MAX_FILE_BYTES),
                            "Слишком большой preimage"
                        );
                        ensure!(
                            change.after_sha256.len() == 64
                                && change.after_sha256.bytes().all(|b| b.is_ascii_hexdigit()),
                            "Некорректный hash в checkpoint"
                        );
                        ensure!(
                            change.mode.is_none_or(|m| m <= 0o7777),
                            "Некорректный mode в checkpoint"
                        );
                    }
                }
                state
            }
            None => Checkpoints {
                version: 1,
                root: root.clone(),
                turns: vec![],
            },
        };
        Ok(Self {
            root,
            dir,
            checkpoint_dir,
            checkpoints,
            active_turn: None,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn definitions() -> Vec<ToolDefinition> {
        let defs = [
            (
                "read_file",
                "Прочитать UTF-8 файл: SHA-256 полного файла, номера строк и пагинация. Не более 1 MiB на файл; пути относительно проекта, symlink и исключённые файлы недоступны.",
                json!({"path":{"type":"string"},"start_line":{"type":"integer","minimum":1},"max_lines":{"type":"integer","minimum":1,"maximum":500}}),
                vec!["path"],
            ),
            (
                "list_files",
                "Список разрешённых файлов проекта с рекурсией и ограничением обхода. Не показывает исключённые, секретные файлы и symlink.",
                json!({"path":{"type":"string"},"max_results":{"type":"integer","minimum":1,"maximum":1000},"offset":{"type":"integer","minimum":0,"maximum":10000}}),
                vec![],
            ),
            (
                "search",
                "Поиск Rust regex в UTF-8 файлах. Ограничены regex, размер файлов, общий объём сканирования и результаты. Бинарные файлы пропускаются.",
                json!({"pattern":{"type":"string","maxLength":4096},"path":{"type":"string"},"max_results":{"type":"integer","minimum":1,"maximum":1000},"case_sensitive":{"type":"boolean"}}),
                vec!["pattern"],
            ),
            (
                "write_file",
                "Атомарно записать UTF-8 файл внутри проекта. Путь относительно рабочего каталога; абсолютный путь разрешён только внутри него. Для внешнего проекта, например /tmp/game, используйте run_command с подтверждением host: mkdir и quoted heredoc. Для существующего файла обязателен expected_sha256 из read_file; для нового не указывайте hash. Родительский каталог должен существовать.",
                json!({"path":{"type":"string"},"content":{"type":"string"},"expected_sha256":{"type":["string","null"]}}),
                vec!["path", "content"],
            ),
            (
                "edit_file",
                "Заменить точное непустое old_text в UTF-8 файле внутри проекта. Для пользовательского внешнего каталога используйте run_command после разрешения host. Совпадение должно быть единственным, кроме явно указанного replace_all=true. Проверка повторяется перед записью.",
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

    pub fn preview(&self, name: &str, args: &Value) -> Result<Option<String>> {
        validate_args(name, args)?;
        let args = self.workspace_args(name, args)?;
        let args = args.as_ref();
        match name {
            "write_file" | "edit_file" => {
                let prepared = self.prepare(name, args)?;
                let before = prepared
                    .before
                    .as_ref()
                    .map(|s| std::str::from_utf8(&s.bytes))
                    .transpose()?
                    .unwrap_or("");
                let after = std::str::from_utf8(&prepared.after)?;
                Ok(Some(unified_diff(&prepared.path, before, after)))
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
        // Resolve only the workspace prefix, never its children. In particular,
        // macOS /tmp and /var aliases must preserve ignore and symlink checks.
        let mut workspace_prefix = path
            .strip_prefix(&self.root)
            .ok()
            .map(|_| self.root.as_path());
        if workspace_prefix.is_none() {
            let ancestors = path.ancestors().collect::<Vec<_>>();
            for ancestor in ancestors.into_iter().rev() {
                if std::fs::canonicalize(ancestor).is_ok_and(|resolved| resolved == self.root) {
                    workspace_prefix = Some(ancestor);
                    break;
                }
            }
        }
        if let Some(prefix) = workspace_prefix {
            let relative = path.strip_prefix(prefix)?;
            let relative = normalized_path(relative, matches!(name, "list_files" | "search"))?;
            let mut normalized = args.clone();
            normalized["path"] = json!(relative);
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
        let result = async {
            validate_args(name, args)?;
            check_cancel(cancel)?;
            let args = self.workspace_args(name, args)?;
            let args = args.as_ref();
            match name {
                "read_file" => self.read_file(args, cancel),
                "list_files" => self.list_files(args, cancel).await,
                "search" => self.search(args, cancel).await,
                "write_file" | "edit_file" => self.write(name, args, cancel),
                "run_command" => self.run_command(args, cancel).await,
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
        Ok(())
    }

    pub fn undo(&mut self) -> Result<String> {
        let Some(index) = self
            .checkpoints
            .turns
            .iter()
            .rposition(|t| !t.entries.is_empty() || t.shell_used)
        else {
            return Ok(format!("Нет файловых правок для отмены. {SHELL_NOTE}"));
        };
        let turn = self.checkpoints.turns[index].clone();
        // Check every entry before touching any file. A conflict keeps the
        // complete journal and all current user bytes unchanged.
        let mut batch = Vec::new();
        let mut policy = Policy::new(&self.dir, &self.root);
        for change in &turn.entries {
            let path = policy.check(&change.path, false)?;
            let (parent, name) = parent_handle(&self.dir, &path)?;
            let current = snapshot(&parent, Path::new(&name), MAX_FILE_BYTES)?;
            ensure!(
                current
                    .as_ref()
                    .is_some_and(|s| sha256(&s.bytes) == change.after_sha256),
                "Конфликт undo: {} изменён или удалён после правки. {SHELL_NOTE}",
                path.display()
            );
            let current = current.unwrap();
            if change.before.is_some() {
                ensure!(
                    permission_mode(&current.permissions) == change.mode
                        && current.permissions.readonly() == change.readonly,
                    "Конфликт undo: права {} изменены после правки",
                    path.display()
                );
            }
            batch.push((change, parent, name, current));
        }
        // Preflight prevents partial undo for pre-existing conflicts. Each
        // commit also checks again; concurrent external writers are not locked.
        for (change, parent, name, _) in &batch {
            if let Some(before) = &change.before {
                atomic_workspace_write(
                    parent,
                    name,
                    before,
                    Some(&change.after_sha256),
                    change.mode,
                    Some(change.readonly),
                )?;
            } else {
                ensure_hash(parent, name, Some(&change.after_sha256))?;
                parent.remove_file(name)?;
            }
        }
        self.checkpoints.turns.truncate(index);
        self.active_turn = None;
        self.persist()?;
        Ok(format!(
            "Отменены файловые правки: {}. {SHELL_NOTE}",
            turn.entries.len()
        ))
    }

    pub fn diff(&self) -> Result<String> {
        let mut changes = BTreeMap::<&Path, &Change>::new();
        let mut shell_used = false;
        for turn in &self.checkpoints.turns {
            shell_used |= turn.shell_used;
            for change in &turn.entries {
                changes.entry(&change.path).or_insert(change);
            }
        }
        let mut out = String::new();
        for (path, change) in changes {
            if out.len() >= MAX_OUTPUT_BYTES {
                break;
            }
            let current = self.allowed_snapshot(path, true);
            match current {
                Ok(current) => {
                    let old = String::from_utf8_lossy(change.before.as_deref().unwrap_or_default());
                    let new = String::from_utf8_lossy(
                        current.as_ref().map_or(&[], |s| s.bytes.as_slice()),
                    );
                    out.push_str(&unified_diff(path, &old, &new));
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
        Ok(bounded(&out, MAX_OUTPUT_BYTES))
    }

    fn persist(&self) -> Result<()> {
        let result = (|| -> Result<()> {
            let bytes = serde_json::to_vec(&self.checkpoints)?;
            ensure!(
                bytes.len() <= MAX_CHECKPOINT_BYTES,
                "Превышен лимит checkpoint (64 MiB)"
            );
            atomic_write(
                &self.checkpoint_dir,
                OsString::from(CHECKPOINT_FILE).as_os_str(),
                &bytes,
                Some(0o600),
                None,
            )?;
            self.checkpoint_dir
                .try_clone()?
                .into_std_file()
                .sync_all()?;
            Ok(())
        })();
        result.map_err(|e| CheckpointFailure(format!("{e:#}")).into())
    }

    fn ensure_turn(&mut self) -> Result<usize> {
        if self.active_turn.is_none() {
            self.begin_turn()?;
        }
        Ok(self.active_turn.unwrap())
    }

    fn allowed_snapshot(&self, path: &Path, allow_missing: bool) -> Result<Option<Snapshot>> {
        let path = Policy::new(&self.dir, &self.root).check(path, allow_missing)?;
        let (parent, name) = parent_handle(&self.dir, &path)?;
        snapshot(&parent, Path::new(&name), MAX_FILE_BYTES)
    }

    fn read_file(&self, args: &Value, cancel: &CancellationToken) -> Result<ToolOutcome> {
        let path = normalized_path(Path::new(string_arg(args, "path")?), false)?;
        let file = self
            .allowed_snapshot(&path, false)?
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
        Ok(ToolOutcome::success(json!({"path":path,"sha256":sha256(&file.bytes),"start_line":start,"total_lines":total_lines,"next_line":next,"ends_with_newline":text.ends_with('\n'),"content":content}).to_string()))
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
            let (parent, name) = match parent_handle(&self.dir, &path) {
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
        let path = normalized_path(Path::new(path), true)?;
        let mut policy = Policy::new(&self.dir, &self.root);
        policy.check(&path, false)?;
        if self.dir.symlink_metadata(&path)?.is_file() {
            return Ok((vec![path], false));
        }
        let mut stack = vec![path];
        let mut files = vec![];
        let mut seen = 0;
        let mut limited = false;
        while let Some(path) = stack.pop() {
            tokio::task::yield_now().await;
            check_cancel(cancel)?;
            let directory = open_directory(&self.dir, &path)?;
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
                if policy.check(&child, false).is_err() {
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
        Ok((files, limited))
    }

    fn prepare(&self, name: &str, args: &Value) -> Result<Prepared> {
        let path = Policy::new(&self.dir, &self.root)
            .check(Path::new(string_arg(args, "path")?), name == "write_file")?;
        let (parent, file_name) = parent_handle(&self.dir, &path)?;
        let before = snapshot(&parent, Path::new(&file_name), MAX_FILE_BYTES)?;
        if let Some(file) = &before {
            std::str::from_utf8(&file.bytes)
                .context("Редактирование бинарного или не UTF-8 файла запрещено")?;
        }
        let after = match name {
            "write_file" => {
                let content = string_arg(args, "content")?;
                let expected = match args.get("expected_sha256") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(s)) => Some(s.as_str()),
                    _ => bail!("expected_sha256 должен быть строкой"),
                };
                match &before {
                    Some(file) => ensure!(
                        expected == Some(sha256(&file.bytes).as_str()),
                        "Для существующего файла требуется актуальный expected_sha256 из read_file; файл изменён или hash отсутствует"
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
                ensure!(!old.is_empty(), "old_text не должен быть пустым");
                ensure!(
                    old.len() <= MAX_FILE_BYTES && new.len() <= MAX_FILE_BYTES,
                    "Слишком большой текст замены"
                );
                let all = bool_arg(args, "replace_all", false)?;
                let count = text
                    .match_indices(old)
                    .take(if all { usize::MAX } else { 2 })
                    .count();
                ensure!(count > 0, "old_text не найден; перечитайте файл");
                let overlapping = if !all {
                    let first = text.find(old).unwrap();
                    let next = first + text[first..].chars().next().unwrap().len_utf8();
                    text[next..].contains(old)
                } else {
                    false
                };
                ensure!(
                    !overlapping && (count == 1 || all),
                    "old_text неоднозначен; уточните контекст или явно укажите replace_all=true"
                );
                let length = text
                    .len()
                    .checked_sub(count * old.len())
                    .and_then(|n| {
                        count
                            .checked_mul(new.len())
                            .and_then(|added| n.checked_add(added))
                    })
                    .context("Слишком большая замена")?;
                ensure!(
                    length <= MAX_FILE_BYTES,
                    "Результат превышает лимит файла 1 MiB"
                );
                text.replace(old, new).into_bytes()
            }
            _ => bail!("Неизвестная файловая операция"),
        };
        ensure!(after.len() <= MAX_FILE_BYTES, "Файл превышает лимит 1 MiB");
        Ok(Prepared {
            path,
            parent,
            name: file_name,
            before,
            after,
        })
    }

    fn write(
        &mut self,
        name: &str,
        args: &Value,
        cancel: &CancellationToken,
    ) -> Result<ToolOutcome> {
        let prepared = self.prepare(name, args)?;
        check_cancel(cancel)?;
        if prepared
            .before
            .as_ref()
            .is_some_and(|b| b.bytes == prepared.after)
        {
            return Ok(ToolOutcome::success(
                "Содержимое уже совпадает; файл не изменён",
            ));
        }
        let turn_index = self.ensure_turn()?;
        let old_state = self.checkpoints.clone();
        let current_hash = prepared.before.as_ref().map(|s| sha256(&s.bytes));
        let after_hash = sha256(&prepared.after);
        let turn = &mut self.checkpoints.turns[turn_index];
        if let Some(change) = turn.entries.iter_mut().find(|c| c.path == prepared.path) {
            ensure!(
                current_hash.as_ref() == Some(&change.after_sha256),
                "Конфликт: файл изменён вне файловых инструментов в этом ходе; исходные пользовательские правки сохранены"
            );
            if change.before.is_some() {
                let permissions = &prepared.before.as_ref().unwrap().permissions;
                ensure!(
                    permission_mode(permissions) == change.mode
                        && permissions.readonly() == change.readonly,
                    "Конфликт: права файла изменены вне файловых инструментов в этом ходе"
                );
            }
            change.after_sha256 = after_hash.clone();
        } else {
            turn.entries.push(Change {
                path: prepared.path.clone(),
                before: prepared.before.as_ref().map(|s| s.bytes.clone()),
                mode: prepared
                    .before
                    .as_ref()
                    .and_then(|s| permission_mode(&s.permissions)),
                readonly: prepared
                    .before
                    .as_ref()
                    .is_some_and(|s| s.permissions.readonly()),
                after_sha256: after_hash.clone(),
            });
        }
        // Journal the complete preimage and expected result before the first
        // side effect. A crash between journal and rename fails undo safely.
        if let Err(error) = self.persist() {
            self.checkpoints = old_state;
            return Err(error);
        }
        let mode = prepared
            .before
            .as_ref()
            .and_then(|s| permission_mode(&s.permissions));
        let readonly = prepared.before.as_ref().map(|s| s.permissions.readonly());
        let result = check_cancel(cancel).and_then(|()| {
            atomic_workspace_write(
                &prepared.parent,
                &prepared.name,
                &prepared.after,
                current_hash.as_deref(),
                mode,
                readonly,
            )
        });
        if let Err(error) = result {
            self.checkpoints = old_state;
            self.persist()?;
            return Err(error);
        }
        Ok(ToolOutcome {
            is_error: false,
            content: json!({"path":prepared.path,"sha256":after_hash,"bytes":prepared.after.len()})
                .to_string(),
            changed_paths: vec![prepared.path.to_string_lossy().into_owned()],
        })
    }

    async fn run_command(
        &mut self,
        args: &Value,
        cancel: &CancellationToken,
    ) -> Result<ToolOutcome> {
        let (command, timeout) = command_args(args)?;
        check_cancel(cancel)?;
        let turn = self.ensure_turn()?;
        self.checkpoints.turns[turn].shell_used = true;
        self.persist()?;
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
        let status = status.context("Статус процесса отсутствует")?;
        let reason = reason.or_else(|| {
            if budget.load(Ordering::Relaxed) > MAX_OUTPUT_BYTES {
                Some("output_limit")
            } else {
                None
            }
        });
        let content = json!({"exit_code":status.code(),"signal":exit_signal(&status),"stdout":String::from_utf8_lossy(&stdout),"stderr":String::from_utf8_lossy(&stderr),"reason":reason,"shell_changes_managed":false,"note":SHELL_NOTE,"termination":if cfg!(unix) {"process_group"} else {"best_effort_child_only"}}).to_string();
        Ok(ToolOutcome {
            is_error: reason.is_some() || !status.success(),
            content,
            changed_paths: vec![],
        })
    }
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

fn secret_component(name: &std::ffi::OsStr) -> bool {
    let name = name.to_string_lossy().to_ascii_lowercase();
    matches!(
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
    ) || name.starts_with(".env")
        || [".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"]
            .iter()
            .any(|suffix| name.ends_with(suffix))
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
    fn load(&mut self, path: &Path, base: &Path) -> Result<()> {
        if self.matchers.contains_key(path) {
            return Ok(());
        }
        let mut builder = GitignoreBuilder::new(self.root.join(base));
        let text = match parent_handle(self.dir, path)
            .and_then(|(parent, name)| snapshot(&parent, Path::new(&name), 256 * 1024))
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
    fn check(&mut self, path: &Path, allow_missing: bool) -> Result<PathBuf> {
        let path = normalized_path(path, true)?;
        self.load(Path::new(".git/info/exclude"), Path::new("."))?;
        self.load(Path::new(".gitignore"), Path::new("."))?;
        let mut layers = vec![
            PathBuf::from(".git/info/exclude"),
            PathBuf::from(".gitignore"),
        ];
        let mut prefix = PathBuf::new();
        let count = path
            .components()
            .filter(|c| !matches!(c, Component::CurDir))
            .count();
        for (i, component) in path
            .components()
            .filter(|c| !matches!(c, Component::CurDir))
            .enumerate()
        {
            ensure!(
                !secret_component(component.as_os_str()),
                "Доступ к секретным файлам и служебным каталогам запрещён"
            );
            prefix.push(component.as_os_str());
            let metadata = match self.dir.symlink_metadata(&prefix) {
                Ok(metadata) => {
                    ensure!(
                        !metadata.file_type().is_symlink(),
                        "Symlink недоступен файловым инструментам"
                    );
                    Some(metadata)
                }
                Err(error)
                    if error.kind() == io::ErrorKind::NotFound
                        && allow_missing
                        && i + 1 == count =>
                {
                    None
                }
                Err(error) => return Err(error.into()),
            };
            let is_dir = metadata.as_ref().is_some_and(|m| m.is_dir());
            let mut ignored = false;
            for layer in &layers {
                let matched = self.matchers[layer].matched(self.root.join(&prefix), is_dir);
                if !matched.is_none() {
                    ignored = matched.is_ignore();
                }
            }
            ensure!(
                !ignored,
                "Путь исключён правилами Git ignore: {}",
                prefix.display()
            );
            if i + 1 < count {
                ensure!(is_dir, "Компонент пути не является каталогом");
            }
            if is_dir {
                let ignore_path = prefix.join(".gitignore");
                self.load(&ignore_path, &prefix)?;
                layers.push(ignore_path);
            }
        }
        Ok(path)
    }
}

fn open_directory(root: &Dir, path: &Path) -> Result<Dir> {
    let mut dir = root.try_clone()?;
    for part in path.components() {
        match part {
            Component::CurDir => continue,
            Component::Normal(part) => {
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
                    dir = Dir::from_std_file(dir.open_with(part, &options)?.into_std());
                }
                #[cfg(not(unix))]
                {
                    dir = dir.open_dir(part)?;
                }
            }
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
    let file = dir.open_with(path, &options)?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "Доступны только обычные файлы");
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= limit,
        "Размер файла превышает лимит {limit} байт"
    );
    Ok(Some(Snapshot {
        bytes,
        permissions: metadata.permissions(),
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

fn ensure_hash(dir: &Dir, name: &std::ffi::OsStr, expected: Option<&str>) -> Result<()> {
    let current = snapshot(dir, Path::new(name), MAX_FILE_BYTES)?;
    ensure!(
        current.as_ref().map(|s| sha256(&s.bytes)).as_deref() == expected,
        "Конфликт: файл изменён непосредственно перед записью"
    );
    Ok(())
}

fn atomic_workspace_write(
    dir: &Dir,
    name: &std::ffi::OsStr,
    bytes: &[u8],
    expected: Option<&str>,
    mode: Option<u32>,
    readonly: Option<bool>,
) -> Result<()> {
    atomic_write_checked(dir, name, bytes, mode, readonly, || {
        ensure_hash(dir, name, expected)
    })
}

fn atomic_write(
    dir: &Dir,
    name: &std::ffi::OsStr,
    bytes: &[u8],
    mode: Option<u32>,
    readonly: Option<bool>,
) -> Result<()> {
    atomic_write_checked(dir, name, bytes, mode, readonly, || Ok(()))
}

fn atomic_write_checked(
    dir: &Dir,
    name: &std::ffi::OsStr,
    bytes: &[u8],
    mode: Option<u32>,
    readonly: Option<bool>,
    recheck: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let temporary = format!(".rcode-{}.tmp", uuid::Uuid::new_v4().simple());
    let result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
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
        recheck()?;
        dir.rename(&temporary, dir, name)?;
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
fn validate_args(name: &str, args: &Value) -> Result<()> {
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
fn command_args(args: &Value) -> Result<(&str, usize)> {
    let command = string_arg(args, "command")?;
    ensure!(
        !command.trim().is_empty() && command.len() <= 16_384 && !command.contains('\0'),
        "Команда пуста, содержит NUL или превышает 16 KiB"
    );
    Ok((command, usize_arg(args, "timeout_secs", 60, 1, 300)?))
}
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

struct ProcessGroup {
    pid: Option<u32>,
}
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
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        self.kill();
    }
}
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

    struct Fixture {
        _temp: TempDir,
        root: PathBuf,
        state: PathBuf,
        tools: Tools,
    }
    impl Fixture {
        fn new() -> Self {
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
        fn file(&self, path: &str, content: &str) {
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
    fn hash(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
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
            assert_eq!(file.unwrap().metadata().unwrap().mode() & 0o777, 0o600);
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
        assert!(out.is_err());
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
}
