//! Локальная история редактора, отдельная от контекста и восстановления диалога.
use crate::{
    config::{self, ConfigStore},
    state::Session,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
};

const MAX_TEXT_BYTES: usize = 2 * 1024 * 1024;
const MAX_FILE_BYTES: usize = 16 * 1024 * 1024;
const MIGRATION_SESSIONS: usize = 20;

#[derive(Clone)]
pub(crate) struct InputHistory {
    root: PathBuf,
    path: PathBuf,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    version: u32,
    root: PathBuf,
    entries: Vec<String>,
}

impl InputHistory {
    pub(crate) fn load(
        store: &ConfigStore,
        root: &Path,
        redact: impl Fn(&str) -> String,
    ) -> Result<(Self, Vec<String>)> {
        let root = root.canonicalize()?;
        let hash = format!("{:x}", Sha256::digest(serde_json::to_vec(&root)?));
        let directory = store.root().join("input-history");
        config::ensure_private_directory(&directory)?;
        let history = Self {
            root,
            path: directory.join(format!("{hash}.json")),
        };
        let _lock = history.lock()?;
        let mut saved = match history.read()? {
            Some(saved) => saved,
            None => Saved {
                version: 1,
                root: history.root.clone(),
                entries: history.migrate(store)?,
            },
        };
        saved.entries = normalized(saved.entries, &redact);
        config::write_private_json(&history.path, &saved)?;
        Ok((history, saved.entries))
    }

    pub(crate) fn record(&self, input: &str, redact: impl Fn(&str) -> String) -> Result<()> {
        if input.trim().is_empty() || matches!(input.trim(), "/exit" | "/quit") {
            return Ok(());
        }
        let _lock = self.lock()?;
        // Another process may have appended since this editor started.
        let mut saved = self.read()?.unwrap_or_else(|| Saved {
            version: 1,
            root: self.root.clone(),
            entries: Vec::new(),
        });
        saved.entries.push(input.into());
        saved.entries = normalized(saved.entries, &redact);
        config::write_private_json(&self.path, &saved)
    }

    fn lock(&self) -> Result<File> {
        config::lock_state_file(&self.path.with_extension("lock"))
    }

    fn read(&self) -> Result<Option<Saved>> {
        if !config::check_file(&self.path)? {
            return Ok(None);
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options
            .open(&self.path)
            .context("Не удалось прочитать историю ввода")?;
        ensure!(
            file.metadata()?.is_file(),
            "История должна быть обычным файлом"
        );
        let mut bytes = Vec::new();
        file.take((MAX_FILE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= MAX_FILE_BYTES,
            "Файл истории ввода слишком большой"
        );
        let saved: Saved = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("Повреждён файл истории ввода"))?;
        ensure!(
            saved.version == 1 && saved.root == self.root,
            "История ввода относится к другой папке или версии"
        );
        Ok(Some(saved))
    }

    fn migrate(&self, store: &ConfigStore) -> Result<Vec<String>> {
        let mut sessions = Session::list(store)?
            .into_iter()
            .filter(|session| session.root == self.root)
            .take(MIGRATION_SESSIONS)
            .collect::<Vec<_>>();
        sessions.reverse();
        let mut entries = Vec::new();
        for info in sessions {
            let Ok(session) = Session::load(store, &info.id, &self.root) else {
                continue;
            };
            for message in session.messages {
                if message.role == "user"
                    && message
                        .provider_meta
                        .as_ref()
                        .is_none_or(|meta| meta.kind != "rcode_runtime")
                    && let Some(text) = message.content
                {
                    if text.starts_with("Пользователь выполнил /undo: ")
                        && text.ends_with(". Перечитай файлы перед изменениями.")
                    {
                        continue;
                    }
                    entries.push(text);
                }
            }
        }
        Ok(entries)
    }
}

fn normalized(entries: Vec<String>, redact: &impl Fn(&str) -> String) -> Vec<String> {
    let mut output = std::collections::VecDeque::new();
    let mut bytes = 0;
    for entry in entries {
        let mut entry = redact(&entry).trim().to_owned();
        if entry.is_empty() || matches!(entry.as_str(), "/exit" | "/quit") {
            continue;
        }
        if entry.len() > crate::terminal::MAX_INPUT {
            let mut end = crate::terminal::MAX_INPUT;
            while !entry.is_char_boundary(end) {
                end -= 1;
            }
            entry.truncate(end);
        }
        if output.back() == Some(&entry) {
            continue;
        }
        bytes += entry.len();
        output.push_back(entry);
        while output.len() > crate::terminal::MAX_HISTORY || bytes > MAX_TEXT_BYTES {
            bytes -= output.pop_front().unwrap().len();
        }
    }
    output.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{ProviderKind, ProviderSettings},
        protocol::{Message, ProviderMeta},
    };
    use serde_json::json;

    fn fixture() -> (tempfile::TempDir, ConfigStore, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("project");
        std::fs::create_dir(&root).unwrap();
        let store = ConfigStore::at(temp.path().join("state")).unwrap();
        (temp, store, root)
    }

    #[test]
    fn persisted_multiline_entries_are_redacted_private_and_skip_exit_and_duplicates() {
        let (_temp, store, root) = fixture();
        let redact = |text: &str| text.replace("secret-key", "[REDACTED]");
        let (history, entries) = InputHistory::load(&store, &root, redact).unwrap();
        assert!(entries.is_empty());
        for text in [
            "Привет\nsecret-key",
            "Привет\nsecret-key",
            "/exit",
            "/quit",
            "   ",
        ] {
            history.record(text, redact).unwrap();
        }
        let (_, entries) = InputHistory::load(&store, &root, redact).unwrap();
        assert_eq!(entries, ["Привет\n[REDACTED]"]);
        assert!(
            !std::fs::read_to_string(&history.path)
                .unwrap()
                .contains("secret-key")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&history.path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(history.path.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
    }

    #[test]
    fn first_load_imports_only_user_inputs_of_this_project_and_not_runtime_feedback() {
        let (temp, store, root) = fixture();
        let mut session = Session::new(&root, ProviderSettings::new(ProviderKind::Custom)).unwrap();
        session
            .messages
            .push(Message::user("старый промпт\nстрока 2"));
        session.messages.push(Message::text(
            "assistant",
            "ответ не относится к истории ввода",
        ));
        let mut feedback = Message::user("служебное сообщение");
        feedback.provider_meta = Some(ProviderMeta {
            kind: "rcode_runtime".into(),
            data: json!({}),
        });
        session.messages.push(feedback);
        session.messages.push(Message::user("Пользователь выполнил /undo: Отменены файловые правки: 1. Перечитай файлы перед изменениями."));
        session.save(&store).unwrap();
        let other = temp.path().join("other");
        std::fs::create_dir(&other).unwrap();
        let mut other_session =
            Session::new(&other, ProviderSettings::new(ProviderKind::Custom)).unwrap();
        other_session.messages.push(Message::user("другой проект"));
        other_session.save(&store).unwrap();
        let (_, entries) = InputHistory::load(&store, &root, str::to_owned).unwrap();
        assert_eq!(entries, ["старый промпт\nстрока 2"]);
        let (_, entries) = InputHistory::load(&store, &other, str::to_owned).unwrap();
        assert_eq!(entries, ["другой проект"]);
    }

    #[test]
    fn parallel_instances_merge_the_latest_file_instead_of_overwriting_each_other() {
        let (_temp, store, root) = fixture();
        let (first, _) = InputHistory::load(&store, &root, str::to_owned).unwrap();
        let (second, _) = InputHistory::load(&store, &root, str::to_owned).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut threads = Vec::new();
        for (name, history) in [("first", first), ("second", second)] {
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                for i in 0..6 {
                    history
                        .record(&format!("{name}-{i}"), str::to_owned)
                        .unwrap();
                }
            }));
        }
        barrier.wait();
        for thread in threads {
            thread.join().unwrap();
        }
        let (_, entries) = InputHistory::load(&store, &root, str::to_owned).unwrap();
        assert_eq!(entries.len(), 12);
        for name in ["first", "second"] {
            for i in 0..6 {
                assert!(entries.contains(&format!("{name}-{i}")));
            }
        }
    }

    #[test]
    fn bounds_preserve_recent_entries_unicode_and_total_size() {
        let entries = normalized(
            (0..1100).map(|i| format!("prompt {i}")).collect(),
            &str::to_owned,
        );
        assert_eq!(entries.len(), crate::terminal::MAX_HISTORY);
        assert_eq!(entries.first().unwrap(), "prompt 100");
        let entries = normalized(
            (0..100)
                .map(|i| format!("{i}{}", "я".repeat(40000)))
                .collect(),
            &str::to_owned,
        );
        assert!(
            entries
                .iter()
                .all(|e| e.len() <= crate::terminal::MAX_INPUT)
        );
        assert!(entries.iter().map(String::len).sum::<usize>() <= MAX_TEXT_BYTES);
        assert!(entries.last().unwrap().starts_with("99"));
    }

    #[test]
    fn corrupt_history_is_reported_without_overwriting_it() {
        let (_temp, store, root) = fixture();
        let (history, _) = InputHistory::load(&store, &root, str::to_owned).unwrap();
        std::fs::write(&history.path, b"corrupt data").unwrap();
        assert!(InputHistory::load(&store, &root, str::to_owned).is_err());
        assert!(history.record("new input", str::to_owned).is_err());
        assert_eq!(std::fs::read(&history.path).unwrap(), b"corrupt data");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_history_and_lock_files_are_refused() {
        use std::os::unix::fs::symlink;
        let (temp, store, root) = fixture();
        let (history, _) = InputHistory::load(&store, &root, str::to_owned).unwrap();
        let target = temp.path().join("outside");
        std::fs::write(&target, b"unchanged").unwrap();
        std::fs::remove_file(&history.path).unwrap();
        symlink(&target, &history.path).unwrap();
        assert!(
            history
                .record("do not follow symlink", str::to_owned)
                .is_err()
        );
        std::fs::remove_file(&history.path).unwrap();
        std::fs::remove_file(history.path.with_extension("lock")).unwrap();
        symlink(&target, history.path.with_extension("lock")).unwrap();
        assert!(
            history
                .record("do not follow lock symlink", str::to_owned)
                .is_err()
        );
        assert_eq!(std::fs::read(target).unwrap(), b"unchanged");
    }
}
