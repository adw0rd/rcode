use crate::{
    config::{ConfigStore, ProviderSettings, write_private_json},
    protocol::{Message, ToolCall, Usage},
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub version: u32,
    pub id: String,
    pub root: PathBuf,
    pub provider: ProviderSettings,
    pub messages: Vec<Message>,
    pub created_at: u64,
    pub updated_at: u64,
    pub title: String,
    pub turn_index: u64,
    pub usage: Usage,
    #[serde(default)]
    pub last_usage: Usage,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agents: Vec<crate::agents::AgentRecord>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionInfo {
    pub id: String,
    pub title: String,
    pub root: PathBuf,
    pub provider: String,
    pub updated_at: u64,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn shorten(text: &str, limit: usize) -> String {
    let mut chars = text.chars();
    let mut output: String = chars.by_ref().take(limit).collect();
    if chars.next().is_some() {
        output.push_str("\n[сокращено командой /compact]");
    }
    output
}

impl Session {
    pub fn new(root: &Path, provider: ProviderSettings) -> Result<Self> {
        Ok(Self {
            version: 1,
            id: uuid::Uuid::new_v4().to_string(),
            root: root.canonicalize()?,
            provider,
            messages: Vec::new(),
            created_at: now(),
            updated_at: now(),
            title: String::new(),
            turn_index: 0,
            usage: Usage::default(),
            last_usage: Usage::default(),
            agents: Vec::new(),
        })
    }
    pub fn dir(&self, store: &ConfigStore) -> PathBuf {
        store.sessions_dir().join(&self.id)
    }
    pub fn save(&mut self, store: &ConfigStore) -> Result<()> {
        self.updated_at = now();
        write_private_json(&self.dir(store).join("session.json"), self)
    }
    fn read(path: &Path) -> Result<Self> {
        let meta = fs::symlink_metadata(path)?;
        if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 8 * 1024 * 1024 {
            bail!("Небезопасный или слишком большой файл сессии");
        }
        let session: Self =
            serde_json::from_slice(&fs::read(path)?).context("Повреждённый файл сессии")?;
        if session.version != 1 {
            bail!("Неподдерживаемая версия сессии {}", session.version);
        }
        uuid::Uuid::parse_str(&session.id).context("Некорректный ID сессии")?;
        Ok(session)
    }
    pub fn load(store: &ConfigStore, id: &str, root: &Path) -> Result<Self> {
        let root = root.canonicalize()?;
        let id = if id == "latest" {
            Self::list(store)?
                .into_iter()
                .find(|s| s.root == root)
                .map(|s| s.id)
                .context("Для этой папки ещё нет сессий")?
        } else {
            uuid::Uuid::parse_str(id)
                .context("ID сессии должен быть UUID или latest")?
                .to_string()
        };
        let dir = store.sessions_dir().join(&id);
        if fs::symlink_metadata(&dir)?.file_type().is_symlink() {
            bail!("Каталог сессии не может быть символьной ссылкой");
        }
        let mut session = Self::read(&dir.join("session.json"))?;
        if session.id != id || session.root != root {
            bail!(
                "Сессия принадлежит другой рабочей папке: {}",
                session.root.display()
            );
        }
        session.repair_pending()?;
        for agent in &mut session.agents {
            if agent.status == crate::agents::AgentStatus::Running {
                agent.status = crate::agents::AgentStatus::Interrupted;
                agent.result = "Процесс завершился; задача не возобновлялась автоматически.".into();
            }
        }
        Ok(session)
    }
    pub fn list(store: &ConfigStore) -> Result<Vec<SessionInfo>> {
        let mut result = Vec::new();
        if !store.sessions_dir().exists() {
            return Ok(result);
        }
        for entry in fs::read_dir(store.sessions_dir())? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            if let Ok(s) = Self::read(&entry.path().join("session.json")) {
                result.push(SessionInfo {
                    id: s.id,
                    title: s.title,
                    root: s.root,
                    provider: s.provider.kind.to_string(),
                    updated_at: s.updated_at,
                });
            }
        }
        result.sort_by_key(|s| std::cmp::Reverse(s.updated_at));
        Ok(result)
    }
    pub fn repair_pending(&mut self) -> Result<usize> {
        let mut repaired = Vec::new();
        let mut pending: Vec<ToolCall> = Vec::new();
        let mut count = 0;
        let close = |pending: &mut Vec<ToolCall>, output: &mut Vec<Message>, count: &mut usize| {
            for call in pending.drain(..) {
                output.push(Message::tool(&call, r#"{"error":"interrupted","outcome":"unknown","hint":"Inspect files before retry; never replay automatically"}"#));
                *count += 1;
            }
        };
        for message in &self.messages {
            if message.role == "tool" {
                let id = message
                    .tool_call_id
                    .as_deref()
                    .context("У результата инструмента отсутствует ID")?;
                let index = pending
                    .iter()
                    .position(|c| c.id == id)
                    .context("Результат инструмента без соответствующего вызова")?;
                pending.remove(index);
            } else {
                close(&mut pending, &mut repaired, &mut count);
                let mut ids = HashSet::new();
                for call in &message.tool_calls {
                    if !ids.insert(&call.id) {
                        bail!("Повторяющийся ID вызова инструмента");
                    }
                    pending.push(call.clone());
                }
            }
            repaired.push(message.clone());
        }
        close(&mut pending, &mut repaired, &mut count);
        self.messages = repaired;
        Ok(count)
    }
    pub fn context_chars(&self) -> usize {
        self.messages
            .iter()
            .map(|m| {
                m.content.as_ref().map_or(0, |s| s.chars().count())
                    + m.tool_calls
                        .iter()
                        .map(|c| c.function.arguments.len())
                        .sum::<usize>()
            })
            .sum()
    }
    pub fn compact(&mut self) -> Result<usize> {
        self.repair_pending()?;
        let before = self.context_chars();
        let starts: Vec<usize> = self
            .messages
            .iter()
            .enumerate()
            .filter(|(_, m)| m.role == "user")
            .map(|(i, _)| i)
            .collect();
        if starts.len() > 2 {
            let boundary = starts[starts.len() - 2];
            let mut summary = String::from(
                "Память предыдущих ходов (может быть неполной; проверь файлы перед изменениями):\n",
            );
            for m in &self.messages[..boundary] {
                if m.role == "user" || (m.role == "assistant" && m.tool_calls.is_empty()) {
                    summary.push_str(&format!(
                        "{}: {}\n",
                        m.role,
                        shorten(m.content.as_deref().unwrap_or_default(), 700)
                    ));
                }
            }
            let mut recent = self.messages.split_off(boundary);
            self.messages = vec![Message::text("assistant", shorten(&summary, 6000))];
            self.messages.append(&mut recent);
        }
        for m in &mut self.messages {
            if m.role == "tool" {
                m.content = m.content.as_deref().map(|s| shorten(s, 4000));
            }
        }
        // Compaction is an explicit lossy operation. Drop a whole completed
        // call/result batch when its arguments alone would retain huge file
        // contents; never leave an orphan tool result or replay these calls.
        let collapse_all = self.context_chars() > 120_000;
        let previous = std::mem::take(&mut self.messages);
        let mut iter = previous.into_iter();
        while let Some(mut message) = iter.next() {
            let arguments: usize = message
                .tool_calls
                .iter()
                .map(|c| c.function.arguments.len())
                .sum();
            if !message.tool_calls.is_empty() && (arguments > 4000 || collapse_all) {
                let names = message
                    .tool_calls
                    .iter()
                    .map(|c| c.function.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                let mut summary = format!(
                    "[Результаты завершённых инструментов сокращены командой /compact: {}. Перед изменениями перечитай файлы.]",
                    shorten(&names, 500)
                );
                for _ in 0..message.tool_calls.len() {
                    if let Some(result) = iter.next() {
                        summary.push('\n');
                        summary
                            .push_str(&shorten(result.content.as_deref().unwrap_or_default(), 200));
                    }
                }
                self.messages
                    .push(Message::text("assistant", shorten(&summary, 2000)));
            } else {
                if message.role != "tool" {
                    message.content = message
                        .content
                        .as_deref()
                        .map(|s| shorten(s, if collapse_all { 1000 } else { 8000 }));
                }
                self.messages.push(message);
            }
        }
        self.repair_pending()?;
        Ok(before.saturating_sub(self.context_chars()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{ConfigStore, ProviderKind, ProviderSettings},
        protocol::{Completion, ToolCall},
    };
    use serde_json::json;
    use tempfile::tempdir;

    #[test]
    fn session_round_trip_is_bound_to_workspace() {
        let base = tempdir().unwrap();
        let project = base.path().join("project");
        let other = base.path().join("other");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        let store = ConfigStore::at(base.path().join("state")).unwrap();
        let mut session =
            Session::new(&project, ProviderSettings::new(ProviderKind::OpenRouter)).unwrap();
        session
            .messages
            .push(Message::user("Сохрани незавершённую работу"));
        session.save(&store).unwrap();
        let loaded = Session::load(&store, &session.id, &project).unwrap();
        assert_eq!(
            loaded.messages[0].content.as_deref(),
            Some("Сохрани незавершённую работу")
        );
        assert!(Session::load(&store, &session.id, &other).is_err());
        assert!(Session::load(&store, "../credentials", &project).is_err());
    }

    #[test]
    fn interrupted_tool_calls_are_closed_without_replaying() {
        let project = tempdir().unwrap();
        let mut session =
            Session::new(project.path(), ProviderSettings::new(ProviderKind::Custom)).unwrap();
        let first = ToolCall::new("write_file", json!({"path":"a.txt","content":"a"}));
        let second = ToolCall::new("run_command", json!({"command":"echo no"}));
        session.messages.push(Message::assistant(&Completion {
            tool_calls: vec![first.clone(), second.clone()],
            ..Completion::default()
        }));
        session.messages.push(Message::tool(&first, "done"));
        assert_eq!(session.repair_pending().unwrap(), 1);
        assert_eq!(session.messages.len(), 3);
        let repaired = &session.messages[2];
        assert_eq!(repaired.tool_call_id.as_deref(), Some(second.id.as_str()));
        assert!(repaired.content.as_deref().unwrap().contains("unknown"));
        assert_eq!(session.repair_pending().unwrap(), 0);
    }

    #[test]
    fn orphan_tool_result_is_rejected() {
        let project = tempdir().unwrap();
        let mut session =
            Session::new(project.path(), ProviderSettings::new(ProviderKind::Custom)).unwrap();
        session.messages.push(Message::tool(
            &ToolCall::new("read_file", json!({})),
            "orphan",
        ));
        assert!(session.repair_pending().is_err());
    }

    #[test]
    fn compact_keeps_recent_turns_and_valid_tool_pairs() {
        let project = tempdir().unwrap();
        let mut session =
            Session::new(project.path(), ProviderSettings::new(ProviderKind::Custom)).unwrap();
        for index in 0..8 {
            session
                .messages
                .push(Message::user(format!("request-{index}")));
            let call = ToolCall::new("read_file", json!({"path":"a.txt"}));
            session.messages.push(Message::assistant(&Completion {
                tool_calls: vec![call.clone()],
                ..Completion::default()
            }));
            session
                .messages
                .push(Message::tool(&call, "x".repeat(10_000)));
            session
                .messages
                .push(Message::text("assistant", format!("finished-{index}")));
        }
        let before = session.context_chars();
        session.compact().unwrap();
        assert!(session.context_chars() < before / 2);
        assert!(
            session
                .messages
                .iter()
                .any(|m| m.content.as_deref() == Some("request-7"))
        );
        assert_eq!(session.repair_pending().unwrap(), 0);
    }
    #[test]
    fn compact_recovers_even_when_latest_turn_contains_large_write_arguments() {
        let project = tempdir().unwrap();
        let mut session =
            Session::new(project.path(), ProviderSettings::new(ProviderKind::Custom)).unwrap();
        session.messages.push(Message::user("large task"));
        let call = ToolCall::new(
            "write_file",
            json!({"path":"large.txt","content":"x".repeat(200_000)}),
        );
        session.messages.push(Message::assistant(&Completion {
            tool_calls: vec![call.clone()],
            ..Completion::default()
        }));
        session.messages.push(Message::tool(&call, "written"));
        session.compact().unwrap();
        assert!(session.context_chars() < 20_000);
        assert_eq!(session.repair_pending().unwrap(), 0);
    }
}
