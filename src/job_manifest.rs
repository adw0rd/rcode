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
            && manifest.terminal["origin"]["actor"]
                == serde_json::to_value(&manifest.origin.actor)?
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

/// Immutable durable view in the original stored byte coordinates.
pub(crate) fn page(
    artifacts: &ArtifactStore,
    text: &str,
    session_id: &str,
    lifetime: &ArtifactOrigin,
    request: &crate::job_tools::PollArgs,
    secrets: &[String],
) -> Result<Value> {
    verify(artifacts, text, session_id)?;
    let manifest: Manifest = serde_json::from_str(text)?;
    ensure!(
        manifest.command_id == request.command_id
            && manifest.origin.actor == lifetime.actor
            && manifest.origin.turn == lifetime.turn,
        "Manifest не принадлежит операции процесса"
    );
    ensure!(
        (4..=65536).contains(&request.max_bytes),
        "Недопустимый размер страницы"
    );
    let credentials = crate::redaction::SecretDictionary::new(secrets)?;
    let dictionary = crate::retained_redaction::RetainedDictionary::new(&credentials)?;
    // Metadata must remain parseable; identity fields cannot be silently masked.
    let clean = crate::redaction::redact_text(&manifest.terminal.to_string(), secrets)?;
    let mut terminal: Value = serde_json::from_str(&clean)?;
    ensure!(
        terminal["id"] == request.command_id
            && terminal["session_id"] == session_id
            && terminal["owner"] == serde_json::to_value(&lifetime.actor)?,
        "Redaction изменила identity процесса"
    );
    for (pages, offset, field, next) in [
        (
            &manifest.stdout,
            request.stdout_offset,
            "stdout",
            "next_stdout_offset",
        ),
        (
            &manifest.stderr,
            request.stderr_offset,
            "stderr",
            "next_stderr_offset",
        ),
    ] {
        let mut bytes = Vec::new();
        for page in pages {
            bytes.extend_from_slice(artifacts.verify_required(&page.artifact)?.as_bytes());
        }
        let original = std::str::from_utf8(&bytes)?;
        ensure!(
            offset <= bytes.len() && original.is_char_boundary(offset),
            "Недопустимое смещение вывода"
        );
        let mut end = bytes.len().min(offset.saturating_add(request.max_bytes));
        while !original.is_char_boundary(end) {
            end -= 1;
        }
        ensure!(
            end > offset || offset == bytes.len(),
            "Размер страницы не вмещает символ"
        );
        let mut retained = StoredText(bytes);
        let mut cursor = dictionary.cursor(retained.0.len(), &[])?;
        while !cursor.step(&mut retained, 4096)? {}
        let output = std::str::from_utf8(&retained.0[offset..end])?;
        // Downstream event/receipt redaction must not change byte coordinates.
        ensure!(
            crate::redaction::redact_text(output, secrets)? == output,
            "Маска вывода совпала с ключом"
        );
        terminal[field] = Value::String(output.to_owned());
        terminal[next] = Value::from(end);
    }
    terminal["command_id"] = Value::String(request.command_id.clone());
    terminal["persisted"] = Value::Bool(true);
    Ok(terminal)
}

/// Verify only immutable pages intersecting the window plus bounded secret context.
/// Full nested verification remains mandatory at capture and recovery boundaries.
pub(crate) fn render_pages(
    artifacts: &ArtifactStore,
    pages: &[(usize, usize, &ArtifactMeta)],
    total: usize,
    offset: usize,
    maximum: usize,
    secrets: &[String],
) -> Result<(String, usize)> {
    ensure!(
        (4..=65536).contains(&maximum) && offset <= total,
        "Invalid output window"
    );
    if offset == total {
        return Ok((String::new(), offset));
    }
    let keys = crate::redaction::SecretDictionary::new(secrets)?;
    let context = keys.max_pattern_len().saturating_sub(1);
    ensure!(context <= 49152, "Redaction context too large");
    let low = offset.saturating_sub(context);
    let high = offset
        .saturating_add(maximum)
        .min(total)
        .saturating_add(context)
        .min(total);
    let selected: Vec<_> = pages
        .iter()
        .filter(|(start, end, _)| *end > low && *start < high)
        .collect();
    let base = selected
        .first()
        .ok_or_else(|| anyhow::anyhow!("Missing output window pages"))?
        .0;
    let mut bytes = Vec::new();
    let mut at = base;
    for &&(start, end, meta) in &selected {
        ensure!(
            start == at && end > start && end - start <= 65536,
            "Output window page gap"
        );
        let text = artifacts.verify_required(meta)?;
        ensure!(text.len() == end - start, "Output window length mismatch");
        bytes.extend_from_slice(text.as_bytes());
        at = end;
    }
    ensure!(
        base <= low && at >= high && bytes.len() <= maximum + 2 * context + 2 * 65536,
        "Incomplete output window context"
    );
    let (text, next) = render_window(bytes, offset - base, maximum, secrets)?;
    Ok((text, base + next))
}

pub(crate) fn render_window(
    bytes: Vec<u8>,
    offset: usize,
    maximum: usize,
    secrets: &[String],
) -> Result<(String, usize)> {
    ensure!((4..=65536).contains(&maximum), "Invalid output page size");
    let original = std::str::from_utf8(&bytes)?;
    ensure!(
        offset <= bytes.len() && original.is_char_boundary(offset),
        "Invalid UTF-8 offset"
    );
    let mut end = bytes.len().min(offset.saturating_add(maximum));
    while !original.is_char_boundary(end) {
        end -= 1;
    }
    ensure!(
        end > offset || offset == bytes.len(),
        "Page cannot contain next scalar"
    );
    let keys = crate::redaction::SecretDictionary::new(secrets)?;
    let dictionary = crate::retained_redaction::RetainedDictionary::new(&keys)?;
    let mut retained = StoredText(bytes);
    let mut cursor = dictionary.cursor(retained.0.len(), &[])?;
    while !cursor.step(&mut retained, 4096)? {}
    let output = String::from_utf8(retained.0[offset..end].to_vec())?;
    ensure!(
        crate::redaction::redact_text(&output, secrets)? == output,
        "Mask matches known secret"
    );
    Ok((output, end))
}

struct StoredText(Vec<u8>);
impl crate::retained_redaction::RetainedText for StoredText {
    fn len(&self) -> usize {
        self.0.len()
    }
    fn byte(&self, index: usize) -> Option<u8> {
        self.0.get(index).copied()
    }
    fn mask(&mut self, range: std::ops::Range<usize>) -> crate::retained_redaction::Result<()> {
        let bytes = self
            .0
            .get_mut(range)
            .ok_or(crate::retained_redaction::RemaskError::InvalidMaskBounds)?;
        bytes.fill(b'*');
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use serde_json::json;
    const ID: &str = "12345678-abcd-4abc-8abc-123456789abc";
    fn fixture(text: &str) -> (tempfile::TempDir, ArtifactStore, Manifest, ArtifactOrigin) {
        let temp = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(temp.path(), "session").unwrap();
        let origin = ArtifactOrigin {
            actor: Some("worker".into()),
            turn: 3,
            tool: "command_output".into(),
            call_id: ID.into(),
        };
        let mut pages = Vec::new();
        let mut at = 0;
        while at < text.len() {
            let mut end = text.len().min(at + 65536);
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            let artifact = store
                .capture_required(origin.clone(), &text[at..end], &[])
                .unwrap();
            pages.push(Page {
                offset: at,
                end,
                artifact,
            });
            at = end;
        }
        let manifest = Manifest {
            version: 1,
            command_id: ID.into(),
            origin: origin.clone(),
            terminal: json!({"id":ID,"session_id":"session","owner":"worker","origin":{"actor":"worker","turn":3},
                "status":"exited","stdout":"","stderr":"","next_stdout_offset":text.len(),"next_stderr_offset":0,
                "payload_unavailable":false,"cleanup_complete":true}),
            stdout: pages,
            stderr: vec![],
        };
        let lifetime = ArtifactOrigin {
            tool: "command_lifetime".into(),
            call_id: "start-call".into(),
            ..origin
        };
        (temp, store, manifest, lifetime)
    }
    fn request(offset: usize, maximum: usize) -> crate::job_tools::PollArgs {
        crate::job_tools::PollArgs {
            command_id: ID.into(),
            stdout_offset: offset,
            stderr_offset: 0,
            max_bytes: maximum,
        }
    }
    #[test]
    fn persisted_page_masks_cross_page_unicode_secret_without_changing_coordinates_or_artifacts() {
        let secret = "SECRET-привет";
        let text = format!("{}{}!", "x".repeat(65530), secret);
        let (_temp, store, manifest, lifetime) = fixture(&text);
        let saved = serde_json::to_string(&manifest).unwrap();
        let keys = vec![secret.to_owned()];
        let result = page(
            &store,
            &saved,
            "session",
            &lifetime,
            &request(65530, secret.len()),
            &keys,
        )
        .unwrap();
        assert_eq!(result["stdout"], "*".repeat(secret.len()));
        assert_eq!(result["next_stdout_offset"], 65530 + secret.len());
        assert_eq!(
            result,
            page(
                &store,
                &saved,
                "session",
                &lifetime,
                &request(65530, secret.len()),
                &keys
            )
            .unwrap()
        );
        let mut cursor = 65530;
        let mut pieces = String::new();
        while cursor < 65530 + secret.len() {
            let part = page(
                &store,
                &saved,
                "session",
                &lifetime,
                &request(cursor, 4),
                &keys,
            )
            .unwrap();
            let next = part["next_stdout_offset"].as_u64().unwrap() as usize;
            assert!(next > cursor && next - cursor <= 4);
            pieces.push_str(part["stdout"].as_str().unwrap());
            cursor = next;
        }
        // A page may include the trailing nonsecret byte after the last scalar.
        assert_eq!(pieces.trim_end_matches('!'), "*".repeat(secret.len()));
        assert_eq!(
            store.verify_required(&manifest.stdout[1].artifact).unwrap(),
            text[65536..]
        );
        assert_eq!(
            store.verify_required(&manifest.stdout[0].artifact).unwrap(),
            text[..65536]
        );
        assert_eq!(
            page(
                &store,
                &saved,
                "session",
                &lifetime,
                &request(text.len(), 4),
                &keys
            )
            .unwrap()["stdout"],
            ""
        );
        assert!(
            page(
                &store,
                &saved,
                "session",
                &lifetime,
                &request(65538, 4),
                &keys
            )
            .is_err()
        ); // inside Cyrillic scalar
    }
    #[test]
    fn persisted_page_rejects_foreign_origin_and_corrupted_nested_page() {
        let (temp, store, mut manifest, lifetime) = fixture("content");
        manifest.terminal["origin"]["actor"] = json!("impostor");
        assert!(
            page(
                &store,
                &serde_json::to_string(&manifest).unwrap(),
                "session",
                &lifetime,
                &request(0, 4),
                &[]
            )
            .is_err()
        );
        manifest.terminal["origin"]["actor"] = json!("worker");
        let saved = serde_json::to_string(&manifest).unwrap();
        let mut wrong = lifetime.clone();
        wrong.actor = None;
        assert!(page(&store, &saved, "session", &wrong, &request(0, 4), &[]).is_err());
        wrong = lifetime.clone();
        wrong.turn += 1;
        assert!(page(&store, &saved, "session", &wrong, &request(0, 4), &[]).is_err());
        assert!(page(&store, &saved, "foreign", &lifetime, &request(0, 4), &[]).is_err());
        std::fs::write(
            temp.path()
                .join("artifacts")
                .join(&manifest.stdout[0].artifact.id),
            "changed",
        )
        .unwrap();
        assert!(page(&store, &saved, "session", &lifetime, &request(0, 4), &[]).is_err());
    }
}
