//! Required output pages. Caller holds JobsSupervisor::publish_snapshot throughout capture.
use crate::{
    artifacts::{ArtifactMeta, ArtifactOrigin, ArtifactStore},
    jobs::{JobSnapshot, JobStatus, JobsSupervisor},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    offset: usize,
    end: usize,
    artifact: ArtifactMeta,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    command_id: String,
    origin: ArtifactOrigin,
    terminal: Value,
    stdout: Vec<Page>,
    stderr: Vec<Page>,
}

pub(crate) fn capture(
    jobs: &JobsSupervisor,
    artifacts: &ArtifactStore,
    expected: &JobSnapshot,
) -> Result<String> {
    ensure!(
        expected.status != JobStatus::Running,
        "Процесс ещё работает"
    );
    let origin = ArtifactOrigin {
        actor: expected.owner.clone(),
        turn: expected.origin.turn,
        tool: "command_output".into(),
        call_id: expected.id.clone(),
    };
    let mut pages: [Vec<Page>; 2] = [Vec::new(), Vec::new()];
    let mut offsets = [0usize; 2];
    for _ in 0..=514 {
        let page = jobs.poll_snapshot(
            expected.owner.as_deref(),
            &expected.id,
            offsets[0],
            offsets[1],
            65536,
        )?;
        ensure!(
            page.id == expected.id
                && page.session_id == expected.session_id
                && page.origin == expected.origin
                && page.owner == expected.owner
                && page.ownership_epoch == expected.ownership_epoch
                && page.credential_epoch == expected.credential_epoch
                && page.status == expected.status
                && !page.payload_unavailable,
            "Состояние вывода изменилось до сохранения"
        );
        let next = [page.next_stdout_offset, page.next_stderr_offset];
        let content = [&page.stdout, &page.stderr];
        for i in 0..2 {
            ensure!(
                next[i].checked_sub(offsets[i]) == Some(content[i].len()),
                "Разрыв страницы вывода"
            );
            if !content[i].is_empty() {
                let artifact = artifacts.capture_required(origin.clone(), content[i], &[])?;
                ensure!(
                    artifacts.verify_required(&artifact)? == *content[i],
                    "Страница вывода изменилась"
                );
                pages[i].push(Page {
                    offset: offsets[i],
                    end: next[i],
                    artifact,
                });
            }
        }
        ensure!(
            next[0]
                .checked_add(next[1])
                .is_some_and(|n| n <= 32 * 1024 * 1024),
            "Превышен размер сохранённого вывода"
        );
        if next == offsets {
            let [stdout, stderr] = pages;
            let manifest = Manifest {
                version: 1,
                command_id: page.id.clone(),
                origin,
                terminal: serde_json::to_value(page)?,
                stdout,
                stderr,
            };
            let text = serde_json::to_string(&manifest)?;
            verify(artifacts, &text, &expected.session_id)?;
            return Ok(text);
        }
        offsets = next;
    }
    anyhow::bail!("Слишком много страниц вывода")
}

/// Recovery verifies nested page bytes as well as the outer manifest hash.
pub(crate) fn verify(artifacts: &ArtifactStore, text: &str, session_id: &str) -> Result<()> {
    let manifest: Manifest = serde_json::from_str(text)?;
    let id = uuid::Uuid::parse_str(&manifest.command_id)?;
    ensure!(
        id.get_version_num() == 4
            && id.to_string() == manifest.command_id
            && manifest.version == 1
            && manifest.origin.tool == "command_output"
            && manifest.origin.call_id == manifest.command_id
            && manifest.terminal["id"] == manifest.command_id
            && manifest.terminal["session_id"] == session_id
            && manifest.terminal["owner"] == serde_json::to_value(&manifest.origin.actor)?
            && manifest.terminal["origin"]["turn"] == manifest.origin.turn
            && manifest.terminal["stdout"] == ""
            && manifest.terminal["stderr"] == ""
            && manifest.terminal["payload_unavailable"] == false
            && matches!(
                manifest.terminal["status"].as_str(),
                Some("exited" | "stopped" | "timed_out" | "cancelled" | "failed" | "unknown")
            ),
        "Повреждён manifest процесса"
    );
    ensure!(
        manifest.stdout.len() + manifest.stderr.len() <= 514,
        "Слишком много страниц manifest"
    );
    let mut total = 0usize;
    for (pages, field) in [
        (&manifest.stdout, "next_stdout_offset"),
        (&manifest.stderr, "next_stderr_offset"),
    ] {
        let mut offset = 0;
        for page in pages {
            ensure!(
                page.offset == offset
                    && page.end > offset
                    && page.end - offset <= 65536
                    && page.artifact.bytes == page.end - offset
                    && !page.artifact.truncated
                    && page.artifact.origin == manifest.origin
                    && page.artifact.session_id == session_id,
                "Разрыв или чужая страница manifest"
            );
            artifacts.verify_required(&page.artifact)?;
            offset = page.end;
        }
        ensure!(
            manifest.terminal[field].as_u64() == Some(offset as u64),
            "Неполный manifest вывода"
        );
        total = total
            .checked_add(offset)
            .ok_or_else(|| anyhow::anyhow!("Переполнение вывода"))?;
    }
    ensure!(total <= 32 * 1024 * 1024, "Превышен размер вывода manifest");
    Ok(())
}
