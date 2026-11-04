//! Владение ресурсами одной сессии. Это host API, не разрешение на исполнение.
use crate::{artifacts::ArtifactStore, jobs::JobsSupervisor, operation_journal::OperationJournal};
use anyhow::{Result, ensure};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub struct SessionRuntime {
    incarnation: uuid::Uuid,
    session_id: String,
    session_dir: PathBuf,
    artifacts: ArtifactStore,
    jobs: JobsSupervisor,
    journal: Option<OperationJournal>,
    managed: crate::managed_jobs::ManagedJobs,
    cancel: CancellationToken,
    active: Arc<AtomicBool>,
    last_turn: Option<u64>,
    closed: bool,
}

/// Независимая область процессов: обычный конец хода не равен отмене.
/// Потерянный guard отменяет область; успешно завершённый отсоединяет её
/// от model/worker root, который app отменяет после каждого хода.
pub struct TurnScope {
    jobs: crate::jobs::TurnControl,
    incarnation: uuid::Uuid,
    turn: u64,
    cancel: CancellationToken,
    interrupt: CancellationToken,
    relay: Option<JoinHandle<()>>,
    active: Arc<AtomicBool>,
    finished: bool,
}
impl TurnScope {
    pub fn cancellation(&self) -> CancellationToken {
        self.cancel.clone()
    }
}
impl Drop for TurnScope {
    fn drop(&mut self) {
        if let Some(relay) = self.relay.take() {
            relay.abort();
        }
        if !self.finished {
            self.cancel.cancel();
            self.jobs.cancel();
        }
        self.active.store(false, Ordering::Release);
    }
}
impl SessionRuntime {
    pub fn new(session_dir: &Path, session_id: &str, secrets: Vec<String>) -> Result<Self> {
        Ok(Self {
            incarnation: uuid::Uuid::new_v4(),
            session_id: session_id.into(),
            session_dir: session_dir.to_path_buf(),
            artifacts: ArtifactStore::open(session_dir, session_id)?,
            jobs: JobsSupervisor::new_for_session(session_id, secrets)?,
            journal: None,
            managed: Default::default(),
            cancel: CancellationToken::new(),
            active: Arc::new(AtomicBool::new(false)),
            last_turn: None,
            closed: false,
        })
    }
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    pub fn artifacts(&self) -> &ArtifactStore {
        &self.artifacts
    }
    pub(crate) fn receipt_resources(
        &mut self,
    ) -> Result<(&ArtifactStore, Option<&mut OperationJournal>)> {
        self.activate()?;
        Ok((&self.artifacts, self.journal.as_mut()))
    }

    pub fn reconcile_receipts(&mut self, session: &mut crate::state::Session) -> Result<()> {
        anyhow::ensure!(
            session.id == self.session_id,
            "Runtime относится к другой сессии"
        );
        self.activate()?;
        if let Some(journal) = self.journal.as_ref() {
            if self.managed.pending() {
                crate::operation_receipts::reconcile_background(
                    journal,
                    &self.artifacts,
                    session,
                    &self.managed.owned(),
                )?;
            } else {
                crate::operation_receipts::reconcile(journal, &self.artifacts, session)?;
            }
        }
        Ok(())
    }

    pub fn jobs(&self) -> &JobsSupervisor {
        &self.jobs
    }

    /// Host-only: permission and role checks precede this call. Model arguments
    /// must not supply JobSpec's argv/environment/origin/cancellation authority.
    #[allow(clippy::too_many_arguments)]
    pub async fn start_approved_job(
        &mut self,
        session: &mut crate::state::Session,
        store: &crate::config::ConfigStore,
        call: &crate::protocol::ToolCall,
        args: &serde_json::Value,
        spec: crate::jobs::JobSpec,
        cancel: CancellationToken,
        secrets: &[String],
    ) -> Result<crate::jobs::JobSnapshot> {
        self.activate()?;
        ensure!(
            session.id == self.session_id
                && self.active.load(Ordering::Acquire)
                && self.last_turn == Some(session.turn_index)
                && spec.origin.turn == session.turn_index,
            "Запуск не принадлежит активному ходу сессии"
        );
        self.jobs.refresh_credentials(secrets).await?;
        let journal = self
            .journal
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Durable запуск недоступен на этой платформе"))?;
        self.managed
            .start(
                &self.jobs,
                journal,
                &self.artifacts,
                session,
                store,
                call,
                args,
                spec,
                cancel,
                secrets,
            )
            .await
    }

    pub async fn settle_jobs(
        &mut self,
        session: &mut crate::state::Session,
        store: &crate::config::ConfigStore,
        secrets: &[String],
    ) -> Result<Vec<crate::operation_receipts::BackgroundReceipt>> {
        ensure!(
            session.id == self.session_id,
            "Runtime относится к другой сессии"
        );
        if !self.managed.pending() {
            return Ok(Vec::new());
        }
        ensure!(!self.closed, "Исполнение сессии завершено");
        self.jobs.refresh_credentials(secrets).await?;
        self.persist_jobs(session, store, secrets).await
    }

    async fn persist_jobs(
        &mut self,
        session: &mut crate::state::Session,
        store: &crate::config::ConfigStore,
        secrets: &[String],
    ) -> Result<Vec<crate::operation_receipts::BackgroundReceipt>> {
        if !self.managed.pending() {
            return Ok(Vec::new());
        }
        let journal = self
            .journal
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Потерян журнал процессов"))?;
        self.managed
            .settle(
                &self.jobs,
                journal,
                &self.artifacts,
                session,
                store,
                secrets,
            )
            .await
    }

    pub async fn finish_turn_saved(
        &mut self,
        scope: TurnScope,
        failed: bool,
        session: &mut crate::state::Session,
        store: &crate::config::ConfigStore,
        secrets: &[String],
    ) -> Result<()> {
        ensure!(
            session.id == self.session_id,
            "Runtime относится к другой сессии"
        );
        let cleanup = self.finish_turn(scope, failed).await;
        let persistence = self.settle_jobs(session, store, secrets).await.map(|_| ());
        combine(cleanup, persistence)
    }

    pub async fn shutdown_saved(
        &mut self,
        session: &mut crate::state::Session,
        store: &crate::config::ConfigStore,
        secrets: &[String],
    ) -> Result<()> {
        ensure!(
            session.id == self.session_id,
            "Runtime относится к другой сессии"
        );
        let refresh = if self.managed.pending() {
            if self.closed {
                Err(anyhow::anyhow!(
                    "Закрытые процессы требуют восстановления; публикация без обновления ключей запрещена"
                ))
            } else {
                self.jobs.refresh_credentials(secrets).await.map(|_| ())
            }
        } else {
            Ok(())
        };
        self.closed = true;
        self.cancel.cancel();
        let cleanup = self.jobs.shutdown().await;
        let persistence = if refresh.is_ok() {
            self.persist_jobs(session, store, secrets).await.map(|_| ())
        } else {
            if let Some(journal) = self.journal.as_mut() {
                journal.fail_closed();
            }
            Ok(())
        };
        let result = combine(combine(refresh, cleanup), persistence);
        if result.is_ok() {
            self.journal.take();
        }
        result
    }

    /// Подготовка replacement не забирает lease старой сессии. Активация
    /// выполняется после её shutdown и до записи истории/нового исполнения.
    pub fn activate(&mut self) -> Result<()> {
        ensure!(!self.closed, "Исполнение сессии завершено");
        // Legacy CLI remains available where the new durable backend is not
        // implemented. New managed tools must require an active journal.
        if !cfg!(unix) {
            return Ok(());
        }
        if let Some(journal) = &self.journal {
            return journal.check_active();
        }
        let journal = OperationJournal::open(&self.session_dir, &self.session_id, &self.artifacts)?;
        self.jobs.attach_cleanup_guard(journal.cleanup_guard())?;
        self.journal = Some(journal);
        Ok(())
    }

    pub fn begin_turn(&mut self, turn: u64, interrupt: &CancellationToken) -> Result<TurnScope> {
        ensure!(!self.closed, "Исполнение сессии завершено");
        ensure!(
            self.last_turn.is_none_or(|last| turn > last),
            "Номер хода уже использован"
        );
        self.activate()?;
        ensure!(
            self.active
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok(),
            "Предыдущий ход ещё исполняется"
        );
        self.last_turn = Some(turn);
        let cancel = self.cancel.child_token();
        let signal = interrupt.clone();
        let target = cancel.clone();
        let relay = tokio::spawn(async move {
            signal.cancelled().await;
            target.cancel();
        });
        if interrupt.is_cancelled() {
            cancel.cancel();
        }
        Ok(TurnScope {
            jobs: self.jobs.turn_control(turn),
            incarnation: self.incarnation,
            turn,
            cancel,
            interrupt: interrupt.clone(),
            relay: Some(relay),
            active: self.active.clone(),
            finished: false,
        })
    }

    /// Вызывается до служебной отмены AgentPool root. Ошибки/настоящая
    /// отмена закрывают main jobs; обычный конец закрывает только worker jobs.
    pub async fn finish_turn(&mut self, mut scope: TurnScope, failed: bool) -> Result<()> {
        ensure!(
            scope.incarnation == self.incarnation,
            "Ход относится к другой runtime-сессии"
        );
        let cancelled = failed || scope.interrupt.is_cancelled() || scope.cancel.is_cancelled();
        if cancelled {
            scope.cancel.cancel();
        }
        let result = self.jobs.finish_turn(scope.turn, cancelled).await;
        // Keep forwarding real interrupts while worker cleanup awaits. Only
        // disconnect immediately before the normal-completion boundary.
        if let Some(relay) = scope.relay.take() {
            relay.abort();
            let _ = relay.await;
        }
        let late_cancel =
            result.is_err() || scope.interrupt.is_cancelled() || scope.cancel.is_cancelled();
        let late_cleanup = if !cancelled && late_cancel {
            scope.cancel.cancel();
            self.jobs.finish_turn(scope.turn, true).await
        } else {
            Ok(())
        };
        scope.finished = true;
        match (result, late_cleanup) {
            (Ok(()), result) | (result, Ok(())) => result,
            (Err(error), Err(cleanup)) => {
                Err(error.context(format!("Дополнительное завершение процессов: {cleanup:#}")))
            }
        }
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        ensure!(
            !self.managed.pending(),
            "Результаты процессов нужно сохранить через shutdown_saved"
        );
        self.closed = true;
        self.cancel.cancel();
        let result = self.jobs.shutdown().await;
        if result.is_ok() {
            self.journal.take();
        }
        result
    }
}
fn combine(cleanup: Result<()>, persistence: Result<()>) -> Result<()> {
    match (cleanup, persistence) {
        (Ok(()), result) | (result, Ok(())) => result,
        (Err(error), Err(save)) => {
            Err(error.context(format!("Сохранение результатов процессов: {save:#}")))
        }
    }
}
impl Drop for SessionRuntime {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
