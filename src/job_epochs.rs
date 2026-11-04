//! Immutable, epoch-aware output manifests for jobs transferred from a worker to
//! its parent. The caller must hold `JobsSupervisor::publish_snapshot` while
//! capturing so the snapshot and its epoch boundaries cannot change.
use crate::{
    artifacts::{ArtifactMeta, ArtifactOrigin, ArtifactStore},
    jobs::{JobSnapshot, JobStatus, JobsSupervisor},
    operation_receipts::{CommittedHandoff, HandoffReference},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const PAGE_BYTES: usize = 64 * 1024;
const MAX_BYTES: usize = 32 * 1024 * 1024;
const MAX_PAGES: usize = 516;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EpochPage {
    offset: usize,
    end: usize,
    epoch: u8,
    artifact: ArtifactMeta,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    command_id: String,
    origin: ArtifactOrigin,
    terminal: Value,
    handoff: HandoffReference,
    stdout: Vec<EpochPage>,
    stderr: Vec<EpochPage>,
}

fn command_origin(job: &JobSnapshot) -> ArtifactOrigin {
    ArtifactOrigin {
        actor: job.origin.actor.clone(),
        turn: job.origin.turn,
        tool: "command_output".into(),
        call_id: job.id.clone(),
    }
}

fn cuts(job: &JobSnapshot) -> Result<[(usize, usize); 2]> {
    ensure!(
        job.epoch_boundaries.len() == 2,
        "Invalid job epoch boundaries"
    );
    let first = &job.epoch_boundaries[0];
    let final_epoch = &job.epoch_boundaries[1];
    ensure!(
        first.epoch == 0
            && first.owner == job.origin.actor
            && final_epoch.epoch == 1
            && final_epoch.owner.is_none()
            && first.stdout_offset == 0
            && first.stderr_offset == 0
            && job.origin.actor.is_some()
            && job.owner.is_none()
            && final_epoch.stdout_offset >= first.stdout_offset
            && final_epoch.stderr_offset >= first.stderr_offset,
        "Invalid job ownership epochs"
    );
    Ok([
        (final_epoch.stdout_offset, job.next_stdout_offset),
        (final_epoch.stderr_offset, job.next_stderr_offset),
    ])
}

fn check_handoff(
    job: &JobSnapshot,
    handoff: &CommittedHandoff,
    origin: &ArtifactOrigin,
) -> Result<()> {
    let data = handoff.data();
    ensure!(
        handoff.reference().operation_id == data.operation_id
            && data.command_id == job.id
            && data.worker == origin.actor.as_deref().unwrap_or_default()
            && data.expected_epoch == 0
            && data.ownership_epoch == 1
            && data.stdout_offset == job.epoch_boundaries[1].stdout_offset
            && data.stderr_offset == job.epoch_boundaries[1].stderr_offset,
        "Handoff does not match job epochs"
    );
    Ok(())
}

fn push_pages(
    artifacts: &ArtifactStore,
    origin: &ArtifactOrigin,
    content: &str,
    start: usize,
    epoch: u8,
    pages: &mut Vec<EpochPage>,
) -> Result<()> {
    if content.is_empty() {
        return Ok(());
    }
    let mut at = 0;
    while at < content.len() {
        let mut end = content.len().min(at.saturating_add(PAGE_BYTES));
        while !content.is_char_boundary(end) {
            end -= 1;
        }
        ensure!(end > at, "Output page cannot split UTF-8 content");
        let artifact = artifacts.capture_required(origin.clone(), &content[at..end], &[])?;
        ensure!(
            artifacts.verify_required(&artifact)? == content[at..end],
            "Output page changed during capture"
        );
        pages.push(EpochPage {
            offset: start + at,
            end: start + end,
            epoch,
            artifact,
        });
        at = end;
    }
    Ok(())
}

pub(crate) fn capture(
    jobs: &JobsSupervisor,
    artifacts: &ArtifactStore,
    expected: &JobSnapshot,
    handoff: &CommittedHandoff,
) -> Result<String> {
    ensure!(
        expected.status != JobStatus::Running,
        "Process is still running"
    );
    ensure!(
        expected.ownership_epoch == 1,
        "Job has not completed ownership transfer"
    );
    let origin = command_origin(expected);
    let stream_cuts = cuts(expected)?;
    check_handoff(expected, handoff, &origin)?;

    let mut pages: [Vec<EpochPage>; 2] = [Vec::new(), Vec::new()];
    let mut offsets = [0usize; 2];
    let mut terminal = None;
    for _ in 0..=MAX_PAGES {
        let snapshot = jobs.poll_snapshot(
            expected.owner.as_deref(),
            &expected.id,
            offsets[0],
            offsets[1],
            PAGE_BYTES,
        )?;
        ensure!(
            snapshot.id == expected.id
                && snapshot.session_id == expected.session_id
                && snapshot.origin == expected.origin
                && snapshot.owner == expected.owner
                && snapshot.ownership_epoch == expected.ownership_epoch
                && snapshot.credential_epoch == expected.credential_epoch
                && snapshot.status == expected.status
                && !snapshot.payload_unavailable,
            "Job snapshot changed during capture"
        );
        let content = [&snapshot.stdout, &snapshot.stderr];
        let next = [snapshot.next_stdout_offset, snapshot.next_stderr_offset];
        for index in 0..2 {
            ensure!(
                next[index].checked_sub(offsets[index]) == Some(content[index].len()),
                "Gap in captured output"
            );
            let cut = stream_cuts[index].0;
            let current = offsets[index];
            let mut consumed = 0;
            while consumed < content[index].len() {
                let absolute = current + consumed;
                let epoch = if absolute < cut { 0 } else { 1 };
                let boundary = if epoch == 0 { cut } else { usize::MAX };
                let available = content[index].len() - consumed;
                let mut take = available.min(boundary.saturating_sub(absolute));
                if take == 0 {
                    take = available;
                }
                ensure!(
                    content[index].is_char_boundary(consumed + take),
                    "Invalid UTF-8 epoch boundary"
                );
                let piece = &content[index][consumed..consumed + take];
                let mut page_origin = origin.clone();
                if epoch == 1 {
                    page_origin.actor = None;
                }
                push_pages(
                    artifacts,
                    &page_origin,
                    piece,
                    absolute,
                    epoch,
                    &mut pages[index],
                )?;
                consumed += take;
            }
        }
        ensure!(
            next[0].checked_add(next[1]).is_some_and(|n| n <= MAX_BYTES),
            "Captured output exceeds limit"
        );
        terminal = Some(snapshot);
        if next == offsets {
            break;
        }
        offsets = next;
    }
    let mut snapshot = terminal.ok_or_else(|| anyhow::anyhow!("No job snapshot captured"))?;
    ensure!(
        snapshot.next_stdout_offset >= stream_cuts[0].0
            && snapshot.next_stderr_offset >= stream_cuts[1].0
            && snapshot.stdout.is_empty()
            && snapshot.stderr.is_empty(),
        "Output changed before capture completed"
    );
    snapshot.stdout.clear();
    snapshot.stderr.clear();
    let manifest = Manifest {
        version: 2,
        command_id: expected.id.clone(),
        origin,
        terminal: serde_json::to_value(snapshot)?,
        handoff: handoff.reference().clone(),
        stdout: std::mem::take(&mut pages[0]),
        stderr: std::mem::take(&mut pages[1]),
    };
    ensure!(
        manifest.stdout.len() + manifest.stderr.len() <= MAX_PAGES,
        "Too many output pages"
    );
    let text = serde_json::to_string(&manifest)?;
    verify(artifacts, &text, &expected.session_id)?;
    ensure!(
        manifest.handoff == *handoff.reference(),
        "Handoff reference changed"
    );
    Ok(text)
}

fn validate_reference(
    reference: &HandoffReference,
    origin: &ArtifactOrigin,
    session: &str,
) -> Result<()> {
    let id = uuid::Uuid::parse_str(&reference.operation_id)?;
    ensure!(
        id.get_version_num() == 4
            && id.to_string() == reference.operation_id
            && reference.terminal.session_id == session
            && reference.terminal.origin.actor == origin.actor
            && reference.terminal.origin.turn == origin.turn
            && reference.terminal.origin.tool == "handoff_command"
            && !reference.terminal.truncated,
        "Invalid handoff reference"
    );
    Ok(())
}

pub(crate) fn reference(text: &str) -> Result<HandoffReference> {
    let manifest: Manifest = serde_json::from_str(text)?;
    ensure!(manifest.version == 2, "Unsupported output manifest version");
    validate_reference(
        &manifest.handoff,
        &manifest.origin,
        &manifest.handoff.terminal.session_id,
    )?;
    Ok(manifest.handoff)
}

fn validate(
    artifacts: &ArtifactStore,
    text: &str,
    session_id: &str,
    payloads: bool,
) -> Result<Manifest> {
    let manifest: Manifest = serde_json::from_str(text)?;
    let id = uuid::Uuid::parse_str(&manifest.command_id)?;
    ensure!(
        manifest.version == 2
            && id.get_version_num() == 4
            && id.to_string() == manifest.command_id
            && manifest.origin.tool == "command_output"
            && manifest.origin.call_id == manifest.command_id
            && manifest.terminal["id"] == manifest.command_id
            && manifest.terminal["session_id"] == session_id
            && manifest.terminal["origin"]["turn"] == manifest.origin.turn
            && manifest.terminal["origin"]["actor"]
                == serde_json::to_value(&manifest.origin.actor)?
            && manifest.terminal["stdout"] == ""
            && manifest.terminal["stderr"] == ""
            && manifest.terminal["owner"].is_null()
            && manifest.terminal["ownership_epoch"] == 1
            && manifest.terminal["payload_unavailable"] == false
            && matches!(
                manifest.terminal["status"].as_str(),
                Some("exited" | "stopped" | "timed_out" | "cancelled" | "failed" | "unknown")
            ),
        "Invalid output manifest terminal state"
    );
    validate_reference(&manifest.handoff, &manifest.origin, session_id)?;
    ensure!(
        manifest.stdout.len() + manifest.stderr.len() <= MAX_PAGES,
        "Too many output pages"
    );
    let boundaries = manifest.terminal["epoch_boundaries"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Missing job epoch boundaries"))?;
    ensure!(
        boundaries.len() == 2
            && manifest.origin.actor.is_some()
            && boundaries[0]["epoch"] == 0
            && boundaries[0]["owner"] == serde_json::to_value(&manifest.origin.actor)?
            && boundaries[0]["stdout_offset"] == 0
            && boundaries[0]["stderr_offset"] == 0
            && boundaries[1]["epoch"] == 1
            && boundaries[1]["owner"].is_null(),
        "Invalid job epoch boundaries"
    );
    for (index, pages, next_field, cut_field) in [
        (0, &manifest.stdout, "next_stdout_offset", "stdout_offset"),
        (1, &manifest.stderr, "next_stderr_offset", "stderr_offset"),
    ] {
        let cut = boundaries[1][cut_field]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Invalid epoch cut"))? as usize;
        let mut at = 0usize;
        for page in pages {
            let mut page_origin = manifest.origin.clone();
            if page.epoch == 1 {
                page_origin.actor = None;
            }
            ensure!(
                page.offset == at
                    && page.end > at
                    && page.end - at <= PAGE_BYTES
                    && page.artifact.bytes == page.end - at
                    && !page.artifact.truncated
                    && page.artifact.origin == page_origin
                    && page.artifact.session_id == session_id
                    && page.epoch == if page.end <= cut { 0 } else { 1 }
                    && ((page.epoch == 0 && page.end <= cut)
                        || (page.epoch == 1 && page.offset >= cut)),
                "Invalid or out-of-epoch output page"
            );
            if payloads {
                artifacts.verify_required(&page.artifact)?;
            }
            at = page.end;
        }
        ensure!(cut <= at, "Epoch boundary exceeds output");
        ensure!(
            manifest.terminal[next_field].as_u64() == Some(at as u64),
            "Incomplete output manifest"
        );
        if index == 0 {
            ensure!(
                boundaries[1]["epoch"] == 1 && boundaries[1]["owner"].is_null(),
                "Invalid final epoch owner"
            );
        }
    }
    let total = manifest.terminal["next_stdout_offset"]
        .as_u64()
        .unwrap_or(0)
        .saturating_add(
            manifest.terminal["next_stderr_offset"]
                .as_u64()
                .unwrap_or(0),
        );
    ensure!(
        total <= MAX_BYTES as u64,
        "Output manifest exceeds size limit"
    );
    Ok(manifest)
}

pub(crate) fn verify(artifacts: &ArtifactStore, text: &str, session_id: &str) -> Result<()> {
    validate(artifacts, text, session_id, true).map(|_| ())
}

pub(crate) fn bind(
    artifacts: &ArtifactStore,
    text: &str,
    session_id: &str,
    lifetime: &ArtifactOrigin,
    command_id: &str,
    proof: &CommittedHandoff,
) -> Result<()> {
    let manifest = validate(artifacts, text, session_id, true)?;
    bind_manifest(&manifest, lifetime, command_id, proof)
}
fn bind_manifest(
    manifest: &Manifest,
    lifetime: &ArtifactOrigin,
    command_id: &str,
    proof: &CommittedHandoff,
) -> Result<()> {
    let data = proof.data();
    ensure!(
        manifest.command_id == command_id
            && manifest.origin.actor == lifetime.actor
            && manifest.origin.turn == lifetime.turn
            && manifest.handoff == *proof.reference()
            && data.command_id == command_id
            && Some(data.worker.as_str()) == lifetime.actor.as_deref()
            && manifest.terminal["epoch_boundaries"][1]["stdout_offset"] == data.stdout_offset
            && manifest.terminal["epoch_boundaries"][1]["stderr_offset"] == data.stderr_offset,
        "Epoch manifest differs from committed lifetime/handoff proof"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn page(
    artifacts: &ArtifactStore,
    text: &str,
    session_id: &str,
    lifetime: &ArtifactOrigin,
    request: &crate::job_tools::PollArgs,
    proof: &CommittedHandoff,
    worker_scope: bool,
    secrets: &[String],
) -> Result<Value> {
    ensure!(
        (4..=65536).contains(&request.max_bytes),
        "Invalid output page size"
    );
    let manifest = validate(artifacts, text, session_id, false)?;
    bind_manifest(&manifest, lifetime, &request.command_id, proof)?;
    let mut terminal: Value = serde_json::from_str(&crate::redaction::redact_text(
        &manifest.terminal.to_string(),
        secrets,
    )?)?;
    ensure!(
        terminal["id"] == request.command_id
            && terminal["session_id"] == session_id
            && terminal["origin"]["actor"] == serde_json::to_value(&lifetime.actor)?,
        "Redaction changed command identity"
    );
    for (pages, requested, field, next_field, cut_field) in [
        (
            &manifest.stdout,
            request.stdout_offset,
            "stdout",
            "next_stdout_offset",
            "stdout_offset",
        ),
        (
            &manifest.stderr,
            request.stderr_offset,
            "stderr",
            "next_stderr_offset",
            "stderr_offset",
        ),
    ] {
        let total = manifest.terminal[next_field]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Missing stream length"))? as usize;
        let cut = manifest.terminal["epoch_boundaries"][1][cut_field]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Missing epoch cut"))? as usize;
        let limit = if worker_scope { cut } else { total };
        ensure!(requested <= limit, "Output offset exceeds caller scope");
        let descriptors: Vec<_> = pages
            .iter()
            .map(|p| (p.offset, p.end, &p.artifact))
            .collect();
        let (mut output, mut next) = crate::job_manifest::render_pages(
            artifacts,
            &descriptors,
            total,
            requested,
            request.max_bytes,
            secrets,
        )?;
        if worker_scope && next > limit {
            output.truncate(limit - requested);
            next = limit;
        }
        terminal[field] = Value::String(output);
        terminal[next_field] = Value::from(next);
    }
    terminal["command_id"] = Value::String(request.command_id.clone());
    terminal["persisted"] = Value::Bool(true);
    terminal["scope_epoch"] = Value::from(if worker_scope { 0 } else { 1 });
    Ok(terminal)
}
