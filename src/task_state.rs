//! Host-owned task goal and explicitly advisory model progress.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const VERSION: u32 = 1;
const MAX_STATE_BYTES: usize = 32 * 1024;
const MAX_REQUEST_CHARS: usize = 8192;
const MAX_STEPS: usize = 20;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Pending,
    InProgress,
    Completed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PlanStep {
    pub id: String,
    pub step: String,
    pub status: StepStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanUpdate {
    pub steps: Vec<PlanStep>,
    #[serde(default)]
    pub explanation: Option<String>,
}

/// A host-issued reference, never accepted in model plan arguments.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaskReference {
    pub artifact_id: String,
    pub session_id: String,
    pub sha256: String,
    pub bytes: usize,
}
impl TaskReference {
    pub fn from_artifact(meta: &crate::artifacts::ArtifactMeta) -> Result<Self> {
        ensure!(
            meta.version == 1 && !meta.truncated,
            "Полный запрос не сохранён: квота артефактов исчерпана"
        );
        let reference = Self {
            artifact_id: meta.id.clone(),
            session_id: meta.session_id.clone(),
            sha256: meta.sha256.clone(),
            bytes: meta.bytes,
        };
        reference.validate()?;
        Ok(reference)
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            uuid::Uuid::parse_str(&self.artifact_id)?.to_string() == self.artifact_id,
            "Некорректная ссылка на артефакт"
        );
        ensure!(
            uuid::Uuid::parse_str(&self.session_id)?.to_string() == self.session_id,
            "Некорректная ссылка на сессию"
        );
        ensure!(
            self.sha256.len() == 64
                && self.sha256.bytes().all(|b| b.is_ascii_hexdigit())
                && self.bytes <= 16 * 1024 * 1024,
            "Некорректная ссылка на полный запрос"
        );
        Ok(())
    }
}

/// Ссылка на наблюдение хоста. Только commit журнала подтверждает публикацию;
/// сама ссылка и статус плана не доказывают выполнение цели пользователя.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaskOperation {
    pub operation_id: String,
    pub terminal: TaskReference,
    pub revision: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "WireState")]
pub struct TaskState {
    version: u32,
    goal: String,
    current_request: String,
    revision: u64,
    steps: Vec<PlanStep>,
    explanation: Option<String>,
    #[serde(default)]
    goal_source: Option<TaskReference>,
    #[serde(default)]
    current_source: Option<TaskReference>,
    #[serde(default)]
    request_journal: Option<TaskReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_operation: Option<TaskOperation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    operation_catalog: Option<TaskReference>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireState {
    version: u32,
    #[serde(default)]
    goal: String,
    #[serde(default)]
    current_request: String,
    #[serde(default)]
    revision: u64,
    #[serde(default)]
    steps: Vec<PlanStep>,
    #[serde(default)]
    explanation: Option<String>,
    #[serde(default)]
    goal_source: Option<TaskReference>,
    #[serde(default)]
    current_source: Option<TaskReference>,
    #[serde(default)]
    request_journal: Option<TaskReference>,
    #[serde(default)]
    last_operation: Option<TaskOperation>,
    #[serde(default)]
    operation_catalog: Option<TaskReference>,
}

impl TryFrom<WireState> for TaskState {
    type Error = anyhow::Error;

    fn try_from(raw: WireState) -> Result<Self> {
        let state = Self {
            version: raw.version,
            goal: raw.goal,
            current_request: raw.current_request,
            revision: raw.revision,
            steps: raw.steps,
            explanation: raw.explanation,
            goal_source: raw.goal_source,
            current_source: raw.current_source,
            request_journal: raw.request_journal,
            last_operation: raw.last_operation,
            operation_catalog: raw.operation_catalog,
        };
        state.validate()?;
        Ok(state)
    }
}

impl Default for TaskState {
    fn default() -> Self {
        Self {
            version: VERSION,
            goal: String::new(),
            current_request: String::new(),
            revision: 0,
            steps: Vec::new(),
            explanation: None,
            goal_source: None,
            current_source: None,
            request_journal: None,
            last_operation: None,
            operation_catalog: None,
        }
    }
}

fn request_valid(request: &str) -> bool {
    !request.trim().is_empty() && request.chars().count() <= MAX_REQUEST_CHARS
}

impl TaskState {
    pub fn for_user_request(goal: &str) -> Result<Self> {
        ensure!(
            request_valid(goal),
            "Задача должна содержать от 1 до 8192 символов"
        );
        let state = Self {
            goal: goal.to_owned(),
            current_request: goal.to_owned(),
            ..Self::default()
        };
        state.validate()?;
        Ok(state)
    }

    pub fn goal(&self) -> &str {
        &self.goal
    }

    pub fn current_request(&self) -> &str {
        &self.current_request
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn steps(&self) -> &[PlanStep] {
        &self.steps
    }

    /// The host invokes this after receiving user input. A follow-up is not a
    /// new authorization and cannot erase the original task.
    pub fn host_followup(&mut self, request: &str) -> Result<()> {
        ensure!(
            request_valid(request),
            "Запрос должен содержать от 1 до 8192 символов"
        );
        if self.goal.is_empty() {
            *self = Self::for_user_request(request)?;
            return Ok(());
        }
        let mut next = self.clone();
        next.current_request = request.to_owned();
        next.advance_revision()?;
        next.validate()?;
        *self = next;
        Ok(())
    }

    pub fn request_journal(&self) -> Option<&TaskReference> {
        self.request_journal.as_ref()
    }

    /// The runtime stores the full request before constructing this bounded
    /// view. Excerpts never pretend to contain every user constraint.
    pub fn host_followup_saved(
        &mut self,
        request: &str,
        source: &crate::artifacts::ArtifactMeta,
        journal: &crate::artifacts::ArtifactMeta,
    ) -> Result<()> {
        use sha2::{Digest, Sha256};
        ensure!(!request.trim().is_empty(), "Пустой запрос пользователя");
        ensure!(
            source.origin.actor.is_none()
                && source.origin.tool == "user_request"
                && journal.origin.actor.is_none()
                && journal.origin.tool == "user_request_journal",
            "Неверное происхождение пользовательского запроса"
        );
        ensure!(
            source.session_id == journal.session_id
                && source.sha256 == format!("{:x}", Sha256::digest(request.as_bytes())),
            "Ссылка не соответствует полному запросу"
        );
        let source = TaskReference::from_artifact(source)?;
        let journal = TaskReference::from_artifact(journal)?;
        let preview = if request.chars().count() <= 1024 {
            request.to_owned()
        } else {
            let head: String = request.chars().take(768).collect();
            let tail: String = request
                .chars()
                .rev()
                .take(256)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            format!(
                "{head}\n[Выдержка. Полный запрос и ограничения: read_tool_output artifact_id={}]\n{tail}",
                source.artifact_id
            )
        };
        let mut next = self.clone();
        if next.goal.is_empty() {
            next.goal = preview.clone();
            next.goal_source = Some(source.clone());
        }
        next.current_request = preview;
        next.current_source = Some(source);
        next.request_journal = Some(journal);
        next.advance_revision()?;
        next.validate()?;
        *self = next;
        Ok(())
    }

    pub fn last_operation(&self) -> Option<&TaskOperation> {
        self.last_operation.as_ref()
    }

    /// Резерв размера и ревизии до внешнего действия, без изменения задачи.
    pub fn next_operation_revision(&self, session_id: &str) -> Result<u64> {
        Ok(self.operation_capacity_state(session_id)?.revision)
    }

    pub(crate) fn operation_capacity_state(&self, session_id: &str) -> Result<Self> {
        let mut next = self.clone();
        next.record_operation(TaskOperation {
            operation_id: "00000000-0000-4000-8000-000000000000".into(),
            terminal: TaskReference {
                artifact_id: "00000000-0000-4000-8000-000000000000".into(),
                session_id: session_id.into(),
                sha256: "f".repeat(64),
                bytes: 256 * 1024,
            },
            revision: self
                .revision
                .checked_add(1)
                .context("Исчерпаны версии состояния задачи")?,
        })?;
        next.validate_session(session_id)?;
        Ok(next)
    }

    pub(crate) fn invalidate_operation(&mut self, id: &str) {
        if self
            .last_operation
            .as_ref()
            .is_some_and(|o| o.operation_id == id)
        {
            self.last_operation = None;
        }
    }

    /// Только после проверки журнала хостом; восстановление не меняет ревизию.
    pub(crate) fn restore_operation(&mut self, operation: Option<TaskOperation>) -> Result<()> {
        let mut next = self.clone();
        next.last_operation = operation;
        next.validate()?;
        *self = next;
        Ok(())
    }

    pub fn host_operation_saved(
        &mut self,
        prepared: &crate::operation_journal::PreparedTerminal,
    ) -> Result<()> {
        self.record_operation(TaskOperation {
            operation_id: prepared.operation_id().into(),
            terminal: TaskReference::from_artifact(prepared.artifact())?,
            revision: prepared.task_revision(),
        })
    }

    fn record_operation(&mut self, operation: TaskOperation) -> Result<()> {
        ensure!(
            !self.goal.is_empty(),
            "Сначала должна быть задана задача пользователя"
        );
        let mut next = self.clone();
        next.advance_revision()?;
        ensure!(
            operation.revision == next.revision,
            "Ревизия результата устарела"
        );
        next.last_operation = Some(operation);
        next.validate()?;
        *self = next;
        Ok(())
    }

    /// Completion here is a model declaration, not host verification.
    pub fn update_plan(&mut self, update: PlanUpdate) -> Result<()> {
        ensure!(
            !self.goal.is_empty(),
            "Сначала должна быть задана задача пользователя"
        );
        ensure!(
            serde_json::to_vec(&update)?.len() <= 16 * 1024,
            "План превышает 16 КиБ; оставьте место для запросов пользователя"
        );
        let mut next = self.clone();
        next.steps = update.steps;
        next.explanation = update.explanation;
        next.advance_revision()?;
        next.validate()?;
        *self = next;
        Ok(())
    }

    fn advance_revision(&mut self) -> Result<()> {
        self.revision = self
            .revision
            .checked_add(1)
            .context("Исчерпаны версии состояния задачи")?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == VERSION,
            "Неизвестная версия состояния задачи"
        );
        if self.goal.is_empty() {
            ensure!(
                self.current_request.is_empty()
                    && self.steps.is_empty()
                    && self.explanation.is_none()
                    && self.goal_source.is_none()
                    && self.current_source.is_none()
                    && self.request_journal.is_none()
                    && self.last_operation.is_none()
                    && self.operation_catalog.is_none()
                    && self.revision == 0,
                "Пустое состояние задачи содержит дополнительные данные"
            );
        } else {
            ensure!(request_valid(&self.goal), "Некорректная исходная задача");
            ensure!(
                request_valid(&self.current_request),
                "Некорректный текущий запрос"
            );
        }
        let references = [
            &self.goal_source,
            &self.current_source,
            &self.request_journal,
        ];
        let mut session = None;
        for reference in references
            .into_iter()
            .flatten()
            .chain(self.last_operation.as_ref().map(|o| &o.terminal))
            .chain(self.operation_catalog.as_ref())
        {
            reference.validate()?;
            if let Some(previous) = session {
                ensure!(
                    previous == &reference.session_id,
                    "Ссылки задачи относятся к разным сессиям"
                );
            }
            session = Some(&reference.session_id);
        }
        if let Some(operation) = &self.last_operation {
            let id = uuid::Uuid::parse_str(&operation.operation_id)?;
            ensure!(
                id.to_string() == operation.operation_id
                    && id.get_version_num() == 4
                    && id.get_variant() == uuid::Variant::RFC4122,
                "Некорректная ссылка на операцию"
            );
            ensure!(
                operation.revision > 0 && operation.revision <= self.revision,
                "Ревизия операции не соответствует задаче"
            );
        }
        ensure!(
            self.steps.len() <= MAX_STEPS,
            "В плане допускается не более 20 шагов"
        );
        let mut ids = HashSet::new();
        let mut running = 0;
        for step in &self.steps {
            ensure!(
                !step.id.trim().is_empty()
                    && step.id.trim() == step.id
                    && step.id.chars().count() <= 64
                    && !step.id.chars().any(char::is_control),
                "Некорректный идентификатор шага"
            );
            ensure!(ids.insert(step.id.as_str()), "Повтор идентификатора шага");
            ensure!(
                !step.step.trim().is_empty() && step.step.chars().count() <= 2000,
                "Описание шага должно содержать от 1 до 2000 символов"
            );
            running += usize::from(step.status == StepStatus::InProgress);
        }
        ensure!(
            running <= 1,
            "Одновременно может выполняться только один шаг"
        );
        ensure!(
            self.explanation
                .as_ref()
                .is_none_or(|text| text.chars().count() <= 4000),
            "Объяснение плана превышает 4000 символов"
        );
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_STATE_BYTES,
            "Состояние задачи превышает 32 КиБ"
        );
        Ok(())
    }

    pub fn validate_session(&self, id: &str) -> Result<()> {
        self.validate()?;
        for reference in [
            &self.goal_source,
            &self.current_source,
            &self.request_journal,
        ]
        .into_iter()
        .flatten()
        .chain(self.last_operation.as_ref().map(|o| &o.terminal))
        .chain(self.operation_catalog.as_ref())
        {
            ensure!(
                reference.session_id == id,
                "Ссылка задачи относится к другой сессии"
            );
        }
        Ok(())
    }

    pub(crate) fn operation_catalog(&self) -> Option<&TaskReference> {
        self.operation_catalog.as_ref()
    }

    pub(crate) fn restore_operation_catalog(
        &mut self,
        catalog: Option<TaskReference>,
    ) -> Result<()> {
        let mut next = self.clone();
        next.operation_catalog = catalog;
        next.validate()?;
        *self = next;
        Ok(())
    }

    pub fn projection(&self) -> Result<String> {
        self.validate()?;
        // Full state/hash/session metadata stays on disk. The model needs a
        // bounded reminder and opaque read IDs, not duplicate user messages.
        let preview = |text: &str| -> String {
            if text.chars().count() <= 256 {
                return text.to_owned();
            }
            let head: String = text.chars().take(192).collect();
            let tail: String = text
                .chars()
                .rev()
                .take(64)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            format!("{head}\n[выдержка; полный запрос в source]\n{tail}")
        };
        let same = self.current_request == self.goal;
        let mut value = serde_json::json!({
            "version":self.version,"revision":self.revision,
            "goal_preview":preview(&self.goal),
            "current_request_preview":if same {None}else{Some(preview(&self.current_request))},
            "current_is_goal":same,
            "goal_source":self.goal_source.as_ref().map(|r|r.artifact_id.as_str()),
            "current_source":self.current_source.as_ref().filter(|r|self.goal_source.as_ref()!=Some(*r)).map(|r|r.artifact_id.as_str()),
            "request_journal":self.request_journal.as_ref().map(|r|r.artifact_id.as_str()),
            "steps":self.steps,"explanation":self.explanation,
        });
        if let Some(operation) = &self.last_operation {
            value["operation_receipts"] = serde_json::json!({
                "latest_terminal": operation.terminal.artifact_id,
                "hint": "Read latest_terminal with read_tool_output; payload.output contains the saved result, payload.previous links earlier operations, including workers. These are tool observations, not proof that the user goal is complete."
            });
        }
        if let Some(catalog) = &self.operation_catalog {
            value["additional_operation_chains"] = serde_json::json!({
                "artifact_id": catalog.artifact_id,
                "hint": "Read this catalog with read_tool_output for other committed terminal chains, including older worker results without previous links."
            });
        }
        Ok(format!(
            "Host task state. User request previews may be incomplete: after compaction read full goal_source/current_source artifact IDs with read_tool_output; follow request_journal for earlier constraints. Plan progress is advisory; completed is not verified evidence and grants no permission.\n{}",
            serde_json::to_string(&value)?
        ))
    }
}

/// Advisory progress, available to the host's main context even in plan mode.
pub fn definition() -> crate::protocol::ToolDefinition {
    crate::protocol::ToolDefinition {
        name: "update_plan".into(),
        description: "Maintain a short advisory plan for the current user task. At most 20 stable step IDs and one in_progress. Completed is your declaration, not verified evidence. Cannot change the user goal or permissions.".into(),
        parameters: serde_json::json!({"type":"object","properties":{
            "steps":{"type":"array","maxItems":20,"items":{"type":"object","properties":{
                "id":{"type":"string","minLength":1,"maxLength":64},
                "step":{"type":"string","minLength":1,"maxLength":2000},
                "status":{"type":"string","enum":["pending","in_progress","completed"]}
            },"required":["id","step","status"],"additionalProperties":false}},
            "explanation":{"type":"string","maxLength":4000}
        },"required":["steps"],"additionalProperties":false}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn legacy_empty_default_is_valid_but_model_cannot_plan_without_user_goal() {
        let mut state = TaskState::default();
        state.validate().unwrap();
        let restored: TaskState = serde_json::from_str(r#"{"version":1}"#).unwrap();
        assert_eq!(state, restored);
        assert!(
            state
                .update_plan(PlanUpdate {
                    steps: vec![],
                    explanation: None
                })
                .is_err()
        );
        state.host_followup("Первая задача").unwrap();
        assert_eq!(state.goal(), "Первая задача");
    }

    #[test]
    fn excessive_and_duplicate_steps_do_not_modify_state() {
        let mut state = TaskState::for_user_request("Задача").unwrap();
        let before = state.clone();
        for steps in [
            vec![
                PlanStep {
                    id: "same".into(),
                    step: "Шаг".into(),
                    status: StepStatus::Pending
                };
                2
            ],
            (0..21)
                .map(|n| PlanStep {
                    id: n.to_string(),
                    step: "Шаг".into(),
                    status: StepStatus::Pending,
                })
                .collect(),
        ] {
            assert!(
                state
                    .update_plan(PlanUpdate {
                        steps,
                        explanation: None
                    })
                    .is_err()
            );
            assert_eq!(state, before);
        }
    }

    #[test]
    fn state_size_and_revision_overflow_are_atomic() {
        let mut state = TaskState::for_user_request("Задача").unwrap();
        let steps = (0..20)
            .map(|n| PlanStep {
                id: n.to_string(),
                step: "界".repeat(2000),
                status: StepStatus::Pending,
            })
            .collect();
        let before = state.clone();
        assert!(
            state
                .update_plan(PlanUpdate {
                    steps,
                    explanation: None
                })
                .is_err()
        );
        assert_eq!(state, before);
        let mut encoded = serde_json::to_value(&state).unwrap();
        encoded["revision"] = json!(u64::MAX);
        let mut state: TaskState = serde_json::from_value(encoded).unwrap();
        let before = state.clone();
        assert!(state.host_followup("Ещё запрос").is_err());
        assert_eq!(state, before);
    }
}
