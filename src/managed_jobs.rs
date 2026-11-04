//! Host ownership of durable lifetimes. Permissions remain in ToolExecutor.
use crate::{
    artifacts::{ArtifactReservation, ArtifactStore},
    config::ConfigStore,
    jobs::{
        InputDelivery, InputStatus, InputTicket, JobOrigin, JobSnapshot, JobSpec, JobStatus,
        JobsSupervisor,
    },
    operation_journal::OperationJournal,
    operation_receipts::{BackgroundOperation, BackgroundReceipt},
    protocol::{ToolCall, ToolOutcome},
    state::Session,
};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::collections::{BTreeMap, VecDeque};
use tokio_util::sync::CancellationToken;

// Native retained output is globally bounded at 32 MiB, with at most 128 records
// before explicit payload acknowledgement. Includes page frames, manifests and
// lifetime terminals. Ordinary artifact writers cannot spend this reservation.
const OUTPUT_RESERVE: usize = 56 * 1024 * 1024;
const INPUT_RESERVE: usize = 256 * 1024;
const MAX_PENDING_INPUTS: usize = 32;
const MAX_INPUT_RECEIPTS: usize = 128;

struct Entry {
    operation: BackgroundOperation,
    origin: JobOrigin,
}

// Ready deliveries remain owned until finish_background commits. In particular,
// consuming a native ticket must not lose its result if persistence fails.
enum InputCompletion {
    Admitting,
    Ticket(InputTicket),
    Ready(InputDelivery),
}

struct InputEntry {
    operation: BackgroundOperation,
    command_id: String,
    actor: Option<String>,
    reservation: ArtifactReservation,
    completion: InputCompletion,
}

struct InputReceipt {
    command_id: String,
    actor: Option<String>,
    value: Value,
}

#[derive(Default)]
struct InputHistory(VecDeque<InputReceipt>);

impl InputHistory {
    fn push(&mut self, receipt: InputReceipt) {
        if self.0.len() == MAX_INPUT_RECEIPTS {
            self.0.pop_front();
        }
        self.0.push_back(receipt);
    }

    fn for_command(&self, command_id: &str, actor: Option<&str>) -> Value {
        let mut values: Vec<_> = self
            .0
            .iter()
            .rev()
            .filter(|receipt| receipt.command_id == command_id && receipt.actor.as_deref() == actor)
            .take(16)
            .map(|receipt| receipt.value.clone())
            .collect();
        values.reverse();
        Value::Array(values)
    }
}

fn delivery_value(command_id: &str, input_id: &str, delivery: &InputDelivery) -> Value {
    let status = match delivery.status {
        InputStatus::Delivered => "delivered",
        InputStatus::Rejected => "rejected",
        InputStatus::Cancelled => "cancelled",
        InputStatus::IoError => "io_error",
    };
    json!({"command_id":command_id,"input_id":input_id,"delivery":status,
        "written":delivery.written,"total":delivery.total})
}

#[derive(Default)]
pub(crate) struct ManagedJobs {
    entries: BTreeMap<String, Entry>,
    budget: Option<ArtifactReservation>,
    inputs: BTreeMap<String, InputEntry>,
    input_history: InputHistory,
}

impl ManagedJobs {
    pub(crate) fn pending(&self) -> bool {
        !self.entries.is_empty() || !self.inputs.is_empty()
    }
    pub(crate) fn owned(&self) -> Vec<&BackgroundOperation> {
        self.entries
            .values()
            .map(|entry| &entry.operation)
            .chain(self.inputs.values().map(|entry| &entry.operation))
            .collect()
    }

    pub(crate) fn input_receipts(&self, command_id: &str, actor: Option<&str>) -> Value {
        self.input_history.for_command(command_id, actor)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn send_input(
        &mut self,
        jobs: &JobsSupervisor,
        journal: &mut OperationJournal,
        artifacts: &ArtifactStore,
        session: &mut Session,
        store: &ConfigStore,
        call: &ToolCall,
        args: &crate::job_tools::InputArgs,
        actor: Option<&str>,
        cancel: &CancellationToken,
        secrets: &[String],
    ) -> Result<Value> {
        journal.check_session(&session.id)?;
        let exact_args = json!({"command_id":args.command_id,"text":args.text,"close":args.close});
        let command_id = exact_args["command_id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing command_id"))?
            .to_owned();
        let text = exact_args["text"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing input text"))?;
        let close = exact_args["close"]
            .as_bool()
            .ok_or_else(|| anyhow::anyhow!("Missing input close flag"))?;
        // Native authorization is authoritative, even for a command not started
        // through this owner. No intent or capacity allocation precedes the ACL.
        jobs.poll_snapshot(actor, &command_id, 0, 0, 4)?;
        ensure!(
            self.inputs.len() < MAX_PENDING_INPUTS,
            "Too many pending inputs"
        );
        let reservation = artifacts.reserve_capacity(INPUT_RESERVE)?;
        let mut lifetime = ToolCall::new("command_input_lifetime", Value::Null);
        lifetime.id = call.id.clone();
        let operation = {
            let reserved = artifacts.reserved(&reservation)?;
            crate::operation_receipts::begin_background(
                journal,
                &reserved,
                session,
                store,
                &lifetime,
                actor,
                &exact_args,
                secrets,
            )?
        };
        let input_id = operation.operation_id().to_owned();
        self.inputs.insert(
            input_id.clone(),
            InputEntry {
                operation,
                command_id: command_id.clone(),
                actor: actor.map(str::to_owned),
                reservation,
                completion: InputCompletion::Admitting,
            },
        );
        // The capability and a separate input reservation survive both await
        // cancellation and admission failure. Never retry an Admitting entry.
        if cancel.is_cancelled() {
            self.inputs
                .get_mut(&input_id)
                .expect("retained input")
                .completion = InputCompletion::Ready(InputDelivery {
                written: 0,
                total: text.len(),
                status: InputStatus::Cancelled,
            });
            anyhow::bail!("Input admission cancelled");
        }
        // Native admission itself decides acceptance. Do not race this future
        // against cancellation: dropping an admission future could hide acceptance.
        match jobs
            .send_input(actor, &command_id, text.as_bytes(), close)
            .await
        {
            Ok(ticket) => {
                self.inputs
                    .get_mut(&input_id)
                    .expect("retained input")
                    .completion = InputCompletion::Ticket(ticket);
                Ok(json!({"command_id":command_id,"input_id":input_id,"delivery":"accepted"}))
            }
            Err(error) => {
                self.inputs
                    .get_mut(&input_id)
                    .expect("retained input")
                    .completion = InputCompletion::Ready(InputDelivery {
                    written: 0,
                    total: text.len(),
                    status: InputStatus::Rejected,
                });
                Err(error)
            }
        }
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
        admission: &CancellationToken,
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
        // Native admission has no suspension points. Check the call token
        // directly after durable I/O, independently of the lifetime relay.
        let started = if admission.is_cancelled() {
            Err(anyhow::anyhow!("Запуск отменён после сохранения намерения"))
        } else {
            jobs.start_reserved(reservation, spec, cancel).await
        };
        match started {
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
            // Drain ready input receipts before publishing command terminals.
            let input_ids: Vec<_> = self.inputs.keys().cloned().collect();
            for id in input_ids {
                let entry = self.inputs.get_mut(&id).expect("retained input");
                if let InputCompletion::Ticket(ticket) = &mut entry.completion
                    && let Some(delivery) = ticket.try_delivery()?
                {
                    entry.completion = InputCompletion::Ready(delivery);
                }
                let InputCompletion::Ready(delivery) = &entry.completion else {
                    continue;
                };
                let value = delivery_value(&entry.command_id, &id, delivery);
                let mut outcome = ToolOutcome::success(value.to_string());
                // Cancellation is not inferred from byte counts: all bytes may
                // have been written even though the final status is cancelled.
                outcome.is_error = !matches!(delivery.status, InputStatus::Delivered);
                let reserved = artifacts.reserved(&entry.reservation)?;
                let receipt = crate::operation_receipts::finish_background(
                    &entry.operation,
                    journal,
                    &reserved,
                    session,
                    store,
                    outcome,
                    secrets,
                )?;
                drop(reserved);
                self.input_history.push(InputReceipt {
                    command_id: entry.command_id.clone(),
                    actor: entry.actor.clone(),
                    value,
                });
                self.inputs.remove(&id);
                completed.push(receipt);
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_does_not_imply_partial_delivery() {
        let value = delivery_value(
            "command",
            "input",
            &InputDelivery {
                written: 42,
                total: 42,
                status: InputStatus::Cancelled,
            },
        );
        assert_eq!(
            value,
            json!({"command_id":"command","input_id":"input",
            "delivery":"cancelled","written":42,"total":42})
        );
        assert_eq!(value.as_object().unwrap().len(), 5);
    }

    #[test]
    fn delivery_statuses_are_explicit_and_contain_no_payload() {
        for (status, expected) in [
            (InputStatus::Delivered, "delivered"),
            (InputStatus::Rejected, "rejected"),
            (InputStatus::Cancelled, "cancelled"),
            (InputStatus::IoError, "io_error"),
        ] {
            let value = delivery_value(
                "c",
                "i",
                &InputDelivery {
                    written: 0,
                    total: 123,
                    status,
                },
            );
            assert_eq!(value["delivery"], expected);
            assert!(value.get("text").is_none());
            assert!(value.get("environment").is_none());
        }
    }

    #[test]
    fn history_is_bounded_and_returns_last_sixteen_in_completion_order() {
        let mut history = InputHistory::default();
        for n in 0..200 {
            history.push(InputReceipt {
                command_id: "c".into(),
                actor: Some("worker".into()),
                value: json!(n),
            });
        }
        assert_eq!(history.0.len(), 128);
        assert_eq!(history.0.front().unwrap().value, json!(72));
        assert_eq!(
            history.for_command("c", Some("worker")),
            Value::Array((184..200).map(|n| json!(n)).collect())
        );
        assert_eq!(history.for_command("c", None), json!([]));
        assert_eq!(history.for_command("other", Some("worker")), json!([]));
        assert_eq!(history.for_command("c", Some("other")), json!([]));
    }

    #[test]
    fn receipt_actor_filter_is_exact_including_root() {
        let mut history = InputHistory::default();
        for actor in [None, Some("a"), Some("b")] {
            history.push(InputReceipt {
                command_id: "c".into(),
                actor: actor.map(str::to_owned),
                value: json!(actor),
            });
        }
        assert_eq!(history.for_command("c", None), json!([null]));
        assert_eq!(history.for_command("c", Some("a")), json!(["a"]));
        assert_eq!(history.for_command("c", Some("b")), json!(["b"]));
    }

    #[test]
    fn input_capacity_is_independent_of_command_output_capacity() {
        assert_eq!(INPUT_RESERVE, 256 * 1024);
        assert_eq!(MAX_PENDING_INPUTS, 32);
        let managed = ManagedJobs::default();
        assert!(!managed.pending());
        assert!(managed.owned().is_empty());
        assert!(managed.budget.is_none());
        assert_eq!(managed.input_receipts("missing", None), json!([]));
    }
}
