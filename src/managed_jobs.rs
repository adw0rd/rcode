//! Host ownership of durable lifetimes. Permissions remain in ToolExecutor.
use crate::{
    artifacts::{ArtifactReservation, ArtifactStore},
    config::ConfigStore,
    jobs::{JobOrigin, JobSnapshot, JobSpec, JobStatus, JobsSupervisor},
    operation_journal::OperationJournal,
    operation_receipts::{BackgroundOperation, BackgroundReceipt},
    protocol::{ToolCall, ToolOutcome},
    state::Session,
};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use tokio_util::sync::CancellationToken;

// Native retained output is globally bounded at 32 MiB, with at most 128 records
// before explicit payload acknowledgement. Includes page frames, manifests and
// lifetime terminals. Ordinary artifact writers cannot spend this reservation.
const OUTPUT_RESERVE: usize = 56 * 1024 * 1024;

struct Entry {
    operation: BackgroundOperation,
    origin: JobOrigin,
}

#[derive(Default)]
pub(crate) struct ManagedJobs {
    entries: BTreeMap<String, Entry>,
    budget: Option<ArtifactReservation>,
}

impl ManagedJobs {
    pub(crate) fn pending(&self) -> bool {
        !self.entries.is_empty()
    }
    pub(crate) fn owned(&self) -> Vec<&BackgroundOperation> {
        self.entries
            .values()
            .map(|entry| &entry.operation)
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn start(
        &mut self,
        jobs: &JobsSupervisor,
        journal: &mut OperationJournal,
        artifacts: &ArtifactStore,
        session: &mut Session,
        store: &ConfigStore,
        call: &ToolCall,
        args: &Value,
        spec: JobSpec,
        cancel: CancellationToken,
        secrets: &[String],
    ) -> Result<JobSnapshot> {
        journal.check_session(&session.id)?;
        ensure!(!cancel.is_cancelled(), "Ход отменён до запуска");
        let reservation = jobs.reserve_start()?;
        let id = reservation.id().to_owned();
        if self.budget.is_none() {
            self.budget = Some(artifacts.reserve_capacity(OUTPUT_RESERVE)?);
        }
        let origin = spec.origin.clone();
        let mut lifetime = ToolCall::new("command_lifetime", Value::Null);
        lifetime.id = call.id.clone();
        let request = json!({"command_id":id,"arguments":args,"origin":origin,"kind":spec.kind,
            "argv":spec.argv,"cwd":spec.cwd,"stdin":spec.stdin,
            "lifetime_ms":spec.lifetime.as_millis(),"idle_ms":spec.idle_timeout.as_millis()});
        let operation = match crate::operation_receipts::begin_background(
            journal,
            artifacts,
            session,
            store,
            &lifetime,
            origin.actor.as_deref(),
            &request,
            secrets,
        ) {
            Ok(operation) => operation,
            Err(error) => {
                if self.entries.is_empty() {
                    self.budget.take();
                }
                return Err(error);
            }
        };
        self.entries.insert(id.clone(), Entry { operation, origin });
        // Ownership exists before the first await. No path reconstructs this
        // capability or retries native spawn from a persisted command UUID.
        match jobs.start_reserved(reservation, spec, cancel).await {
            Ok(snapshot) => Ok(snapshot),
            Err(error) => {
                // The intent remains Unknown. Absence of a native record is
                // not evidence authorizing a retry or a fabricated terminal.
                self.entries.remove(&id);
                if self.entries.is_empty() {
                    self.budget.take();
                }
                Err(error.context(
                    "Запуск не подтверждён; намерение сохранено без автоматического повтора",
                ))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn settle(
        &mut self,
        jobs: &JobsSupervisor,
        journal: &mut OperationJournal,
        artifacts: &ArtifactStore,
        session: &mut Session,
        store: &ConfigStore,
        secrets: &[String],
    ) -> Result<Vec<BackgroundReceipt>> {
        let result = async {
            journal.check_session(&session.id)?;
            let mut completed = Vec::new();
            let ids: Vec<_> = self.entries.keys().cloned().collect();
            for id in ids {
                let entry = &self.entries[&id];
                let snapshot = jobs.poll_snapshot(entry.origin.actor.as_deref(), &id, 0, 0, 4)?;
                ensure!(
                    snapshot.origin == entry.origin && snapshot.ownership_epoch == 0,
                    "Владение процессом изменилось вне durable runtime"
                );
                if snapshot.status == JobStatus::Running {
                    continue;
                }
                let reserved = artifacts.reserved(
                    self.budget
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("Потерян резерв вывода"))?,
                )?;
                let receipt = jobs
                    .publish_snapshot(&snapshot, |view| {
                        let manifest = crate::job_manifest::capture(jobs, &reserved, view)?;
                        let mut outcome = ToolOutcome::success(manifest);
                        outcome.is_error = view.status != JobStatus::Exited
                            || view.exit_code != Some(0)
                            || !view.cleanup_complete;
                        crate::operation_receipts::finish_command_manifest(
                            &entry.operation,
                            journal,
                            &reserved,
                            session,
                            store,
                            outcome,
                            secrets,
                        )
                    })
                    .await?;
                drop(reserved);
                self.entries.remove(&id);
                completed.push(receipt);
            }
            if self.entries.is_empty() {
                self.budget.take();
            }
            Ok(completed)
        }
        .await;
        if result.is_err() {
            journal.fail_closed();
        }
        result
    }
}
