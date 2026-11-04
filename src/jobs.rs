//! Bounded process-group supervisor; not an approval, journal, artifact, or sandbox layer.
//! Trusted host code supplies actor, operation, and cancellation-scope identities.
//! Deliberate setsid/setpgid escape is NOT contained. An escaped pipe holder makes
//! cleanup unknown; an escape which closes all inherited pipes is not detectable.
//! See the platform module for enumeration assumptions. Do not install an external
//! SIGCHLD reaper for these children. Explicit shutdown is required for confirmation.
//! Host integration: new() installs the process-wide panic-hook adapter exactly once,
//! before jobs can spawn. The central host hook owner must install its previous hook
//! first, serialize that installation with this adapter, and never replace the adapter.
//! The previous hook remains responsible for unmarked host panics. This module does
//! not establish the host-wide no-terminal-output contract outside managed polls.
//! Linux admission requires an unrestricted procfs for the current PID namespace.
//! The host must not change mounts/namespaces concurrently with admission or cleanup;
//! descendants must remain in that PID namespace as well as the original group.
use crate::job_output::{OutputChunk, OutputStream};
use anyhow::Context as _;
use anyhow::{Result, bail, ensure};
use serde::Serialize;
use std::{
    cell::Cell,
    collections::{HashMap, VecDeque},
    future::Future,
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, Once},
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite},
    sync::{Notify, Semaphore, mpsc, oneshot},
};
use tokio_util::sync::CancellationToken;

const STREAM: usize = 16 * 1024 * 1024;
const GLOBAL: usize = 32 * 1024 * 1024;
const BLOCK: usize = 4096;
const INPUT: usize = 16 * 1024;
const INPUT_LOOKBEHIND: usize = 8192 * 6 - 1;
const PAGE: usize = 64 * 1024;
const HISTORY: usize = 128;
const TICK: Duration = Duration::from_millis(20);
const CLEANUP: Duration = Duration::from_secs(3);
const TERM_GRACE: Duration = Duration::from_millis(500);
const PIPE_WAIT: Duration = Duration::from_secs(1);

static PANIC_ADAPTER: Once = Once::new();
thread_local! {
    static MANAGED_POLL: Cell<bool> = const { Cell::new(false) };
}

/// Install once, before spawning jobs. Central host hook ownership is required:
/// install the host hook first, do not race take_hook/set_hook with this function,
/// and do not subsequently replace this adapter. Do not call from a panic hook.
/// Unmarked panics are delegated unchanged; their terminal/secrecy policy is the
/// host's responsibility, not an assurance provided by this module.
pub fn install_managed_job_panic_adapter() {
    PANIC_ADAPTER.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let managed = MANAGED_POLL.try_with(Cell::get).unwrap_or(false);
            if !managed {
                previous(info);
            }
            // Managed recovery persists a static diagnostic. Do not inspect the
            // payload, format anything, lock the registry, or perform any I/O here.
        }));
    });
}

struct ManagedPollGuard {
    previous: bool,
}
impl ManagedPollGuard {
    fn enter() -> Self {
        Self {
            previous: MANAGED_POLL.with(|marked| marked.replace(true)),
        }
    }
}
impl Drop for ManagedPollGuard {
    fn drop(&mut self) {
        MANAGED_POLL.with(|marked| marked.set(self.previous));
    }
}

#[derive(Clone, Debug)]
pub struct JobSpec {
    /// Host-selected execution kind. Never deserialize this from model arguments.
    pub kind: JobKind,
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub env: Vec<(String, String)>,
    pub origin: JobOrigin,
    pub lifetime: Duration,
    pub idle_timeout: Duration,
    pub stdin: bool,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    /// start_command: operator-facing settings are 1–120 minutes.
    Managed,
    /// Compatibility backend for synchronous run_command, 1–300 seconds.
    Foreground,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct JobOrigin {
    pub actor: Option<String>,
    pub turn: u64,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Running,
    Exited,
    Stopped,
    TimedOut,
    Cancelled,
    Failed,
    Unknown,
}
#[derive(Clone, Debug, Serialize)]
pub struct EpochBoundary {
    pub epoch: u64,
    pub owner: Option<String>,
    pub stdout_offset: usize,
    pub stderr_offset: usize,
}
#[derive(Clone, Debug, Serialize)]
pub struct JobSnapshot {
    pub kind: JobKind,
    pub id: String,
    pub session_id: String,
    pub origin: JobOrigin,
    pub owner: Option<String>,
    pub ownership_epoch: u64,
    pub credential_epoch: u64,
    pub status: JobStatus,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub next_stdout_offset: usize,
    pub next_stderr_offset: usize,
    pub output_truncated: bool,
    pub payload_unavailable: bool,
    pub redaction_incomplete: bool,
    pub utf8_lossy: bool,
    pub cleanup_complete: bool,
    pub cleanup_warning: Option<String>,
    pub reason: Option<String>,
    pub epoch_boundaries: Vec<EpochBoundary>,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct HandoffReceipt {
    pub operation_id: String,
    pub actor: String,
    pub parent_scope_id: String,
    pub expected_epoch: u64,
    pub ownership_epoch: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputStatus {
    Delivered,
    Rejected,
    Cancelled,
    IoError,
}
#[derive(Clone, Debug, Serialize)]
pub struct InputDelivery {
    pub written: usize,
    pub total: usize,
    pub status: InputStatus,
}
/// Admission is not delivery. The host retains this ticket until its receipt is durable.
pub struct InputTicket {
    completion: oneshot::Receiver<InputDelivery>,
}
impl InputTicket {
    pub(crate) fn try_delivery(&mut self) -> Result<Option<InputDelivery>> {
        match self.completion.try_recv() {
            Ok(delivery) => Ok(Some(delivery)),
            Err(oneshot::error::TryRecvError::Empty) => Ok(None),
            Err(oneshot::error::TryRecvError::Closed) => {
                anyhow::bail!("input delivery unavailable")
            }
        }
    }

    pub async fn wait(self) -> Result<InputDelivery> {
        self.completion
            .await
            .map_err(|_| anyhow::anyhow!("input delivery unavailable"))
    }
}
struct Input {
    bytes: Vec<u8>,
    written: usize,
    checked_epoch: Option<u64>,
    close: bool,
    completion: Option<oneshot::Sender<InputDelivery>>,
    _permit: Option<tokio::sync::OwnedSemaphorePermit>,
}
impl Input {
    fn complete(&mut self, status: InputStatus) {
        if let Some(sender) = self.completion.take() {
            let _ = sender.send(InputDelivery {
                written: self.written,
                total: self.bytes.len(),
                status,
            });
        }
    }
}
impl Drop for Input {
    fn drop(&mut self) {
        self.complete(InputStatus::Cancelled);
    }
}
// Payload allocation, not just length, is charged in BLOCK-byte units. Vec
// descriptors are separately bounded: <=4096 boxes/stream, <=132 records.
#[derive(Default)]
struct Payload {
    blocks: Vec<Box<[u8; BLOCK]>>,
    // One bit per 64 retained bytes; bounded local conservative provenance.
    marks: Vec<u64>,
    len: usize,
}
impl Payload {
    fn append(&mut self, bytes: &[u8], allocated: &mut usize) -> usize {
        let mut n = bytes.len().min(STREAM - self.len);
        let existing = self.blocks.len() * BLOCK - self.len;
        n = n.min(existing + GLOBAL - *allocated);
        let text = std::str::from_utf8(bytes).expect("decoder invariant");
        while !text.is_char_boundary(n) {
            n -= 1;
        }
        let mut copied = 0;
        while copied < n {
            let index = self.len / BLOCK;
            let offset = self.len % BLOCK;
            if index == self.blocks.len() {
                // The global bound is a multiple of BLOCK.
                if *allocated == GLOBAL {
                    break;
                }
                self.blocks.push(Box::new([0; BLOCK]));
                self.marks.push(0);
                *allocated += BLOCK;
            }
            let take = (BLOCK - offset).min(n - copied);
            self.blocks[index][offset..offset + take]
                .copy_from_slice(&bytes[copied..copied + take]);
            self.len += take;
            copied += take;
        }
        copied
    }
    fn byte(&self, offset: usize) -> u8 {
        self.blocks[offset / BLOCK][offset % BLOCK]
    }
    fn boundary(&self, offset: usize) -> bool {
        offset == self.len || (offset < self.len && self.byte(offset) & 0xc0 != 0x80)
    }
    fn page(&self, offset: usize, maximum: usize) -> Result<(String, usize)> {
        ensure!(
            offset <= self.len && self.boundary(offset),
            "invalid output offset"
        );
        let mut end = self.len.min(offset.saturating_add(maximum));
        while !self.boundary(end) {
            end -= 1;
        }
        let mut bytes = Vec::with_capacity(end - offset);
        let mut at = offset;
        while at < end {
            let n = (BLOCK - at % BLOCK).min(end - at);
            bytes.extend_from_slice(&self.blocks[at / BLOCK][at % BLOCK..at % BLOCK + n]);
            at += n;
        }
        Ok((String::from_utf8(bytes).expect("stored UTF-8"), end))
    }
    fn mark(&mut self, range: std::ops::Range<usize>) {
        let end = range.end.min(self.len);
        if range.start >= end {
            return;
        }
        for unit in range.start / 64..=(end - 1) / 64 {
            self.marks[unit / 64] |= 1_u64 << (unit % 64);
        }
    }
    fn append_chunk(&mut self, chunk: &OutputChunk, allocated: &mut usize) -> usize {
        let offset = self.len;
        let n = self.append(chunk.text.as_bytes(), allocated);
        for span in &chunk.sensitive {
            self.mark(offset + span.start.min(n)..offset + span.end.min(n));
        }
        n
    }
    fn release(&mut self) -> usize {
        let capacity = self.blocks.len() * BLOCK;
        *self = Self::default();
        capacity
    }
}
// Host-only adapter: the refresh coordinator must gate the whole payload
// during a pass. This adapter alone does not provide an epoch/publication gate.
impl crate::retained_redaction::RetainedText for Payload {
    fn len(&self) -> usize {
        self.len
    }
    fn byte(&self, index: usize) -> Option<u8> {
        (index < self.len).then(|| self.byte(index))
    }
    fn mask(&mut self, range: std::ops::Range<usize>) -> crate::retained_redaction::Result<()> {
        use crate::retained_redaction::RemaskError;
        if range.start >= range.end
            || range.end > self.len
            || range.len() > 4
            || !self.boundary(range.start)
            || !self.boundary(range.end)
        {
            return Err(RemaskError::InvalidMaskBounds);
        }
        self.mark(range.clone());
        for index in range {
            self.blocks[index / BLOCK][index % BLOCK] = b'*';
        }
        Ok(())
    }
}
struct Record {
    view: JobSnapshot,
    out: Payload,
    err: Payload,
    streams: [Option<OutputStream>; 2],
    scope: CancellationToken,
    stop: bool,
    cause: Option<JobStatus>,
    last_activity: Instant,
    foreground_raw_bytes: usize,
    input: Option<mpsc::Sender<Input>>,
    input_budget: Arc<Semaphore>,
    input_tail: Vec<u8>,
    input_written: VecDeque<u8>,
    input_closing: bool,
    receipt: Option<HandoffReceipt>,
    done: bool,
    // A slot survives task completion whenever cleanup remains unconfirmed.
    resource: bool,
    // Once evidence is missing, later observations cannot silently repair it.
    cleanup_uncertain: bool,
    pgid: Option<i32>,
    #[cfg(test)]
    panic_run: bool,
}
struct Registry {
    credentials: Arc<crate::redaction::SecretDictionary>,
    credential_epoch: u64,
    refreshing: bool,
    credential_failed: bool,
    records: HashMap<String, Record>,
    completed: VecDeque<String>,
    allocated: usize,
    running: usize,
    closing: bool,
    sticky_unknown: bool,
    closed_through: Option<u64>,
    cleanup_guard: Option<Arc<dyn Send + Sync>>,
}
struct Core {
    session: String,
    require_cleanup_guard: bool,
    state: Mutex<Registry>,
    cancel: CancellationToken,
    changed: Notify,
    refresh_serial: tokio::sync::Mutex<()>,
    publication: tokio::sync::RwLock<()>,
    #[cfg(test)]
    finalization_gate: Mutex<Option<(Arc<Notify>, Arc<Notify>)>>,
    #[cfg(test)]
    refresh_gate: Mutex<Option<(Arc<Notify>, Arc<Notify>)>>,
}
struct RefreshGuard {
    core: Arc<Core>,
    armed: bool,
}
impl Drop for RefreshGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut state = lock(&self.core.state);
        state.credential_failed = true;
        state.refreshing = false;
        for r in state.records.values_mut().filter(|r| !r.done) {
            request(r, JobStatus::Failed, "credential refresh failed");
        }
        drop(state);
        self.core.changed.notify_waiters();
    }
}
fn provenance_spans(marks: &[u64], length: usize, boundary: usize) -> Vec<std::ops::Range<usize>> {
    let mut spans: Vec<std::ops::Range<usize>> = Vec::new();
    for (block, &bits) in marks.iter().enumerate() {
        for bit in 0..64 {
            if bits & (1_u64 << bit) == 0 {
                continue;
            }
            let start = block * BLOCK + bit * 64;
            let end = (start + 64).min(length);
            if start >= end {
                continue;
            }
            if let Some(last) = spans.last_mut()
                && last.end == start
            {
                last.end = end;
                continue;
            }
            spans.push(start..end);
        }
    }
    if boundary > 0 && length > 0 {
        let start = length.saturating_sub(boundary);
        let first = spans.partition_point(|span| span.end < start);
        let start = spans.get(first).map_or(start, |span| start.min(span.start));
        spans.truncate(first);
        spans.push(start..length);
    }
    spans
}
pub struct JobsSupervisor {
    core: Arc<Core>,
}

/// Одноразовый host ID до durable intent. Не резервирует процесс или ресурсный
/// слот; не восстанавливается из строки и не переносится в другой supervisor.
pub struct StartReservation {
    id: String,
    core: std::sync::Weak<Core>,
}
impl StartReservation {
    pub fn id(&self) -> &str {
        &self.id
    }
}
/// Cloneable cancellation authority for a host-owned turn guard, without
/// duplicating JobsSupervisor's emergency Drop ownership.
pub(crate) struct TurnControl {
    core: Arc<Core>,
    turn: u64,
}
impl TurnControl {
    pub(crate) fn cancel(&self) {
        close_turn(&mut lock(&self.core.state), self.turn, true);
    }
}
fn close_turn(state: &mut Registry, turn: u64, cancel_main: bool) {
    state.closed_through = Some(state.closed_through.map_or(turn, |last| last.max(turn)));
    for r in state
        .records
        .values_mut()
        .filter(|r| r.view.origin.turn == turn && (cancel_main || r.view.owner.is_some()))
    {
        request(r, JobStatus::Cancelled, "origin turn finished");
    }
}
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}
fn request(r: &mut Record, status: JobStatus, reason: &str) {
    if r.done {
        return;
    }
    if r.cause.is_none() {
        r.cause = Some(status);
        r.view.reason = Some(reason.into());
    }
    r.stop = true;
}
fn require_credentials(state: &Registry) -> Result<()> {
    ensure!(
        !state.credential_failed,
        "credential refresh failed; output and input blocked"
    );
    ensure!(!state.refreshing, "credential refresh in progress");
    Ok(())
}
// Already written bytes cannot be recalled. Reject only matches using NEW bytes.
fn new_input_contains_secret(bytes: &[u8], tail_len: usize, patterns: &[Vec<u8>]) -> bool {
    patterns.iter().any(|p| {
        bytes[tail_len.saturating_sub(p.len().saturating_sub(1))..]
            .windows(p.len())
            .any(|window| window == p)
    })
}
fn has_secret(bytes: &[u8], patterns: &[Vec<u8>]) -> bool {
    patterns
        .iter()
        .any(|p| bytes.windows(p.len()).any(|w| w == p))
}
fn validate_identity(value: &str, patterns: &[Vec<u8>]) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 256
            && !value.bytes().any(|byte| byte.is_ascii_control())
            && !has_secret(value.as_bytes(), patterns),
        "identity rejected"
    );
    Ok(())
}
pub(crate) fn allowed_env(key: &str) -> bool {
    matches!(
        key,
        "PATH" | "HOME" | "USER" | "LOGNAME" | "LANG" | "TMPDIR" | "TEMP" | "TMP" | "SYSTEMROOT"
    ) || (key.starts_with("LC_")
        && key.len() > 3
        && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
}
fn validate(spec: &mut JobSpec, patterns: &[Vec<u8>]) -> Result<()> {
    ensure!(
        !spec.argv.is_empty() && spec.argv.len() <= 128 && !spec.argv[0].is_empty(),
        "invalid argv"
    );
    ensure!(
        spec.argv
            .iter()
            .map(|s| s.len().saturating_add(1))
            .sum::<usize>()
            // Foreground reserves 16 KiB for the shell command itself; the
            // host's /bin/sh, -c and NUL separators add twelve bytes.
            <= INPUT + if spec.kind == JobKind::Foreground { 12 } else { 0 },
        "argv too large"
    );
    ensure!(spec.env.len() <= 128, "environment too large");
    spec.env
        .iter()
        .try_fold(0usize, |total, (key, value)| {
            total
                .checked_add(key.len())
                .and_then(|n| n.checked_add(value.len()))
                .filter(|total| *total <= 65536)
        })
        .context("environment too large")?;
    for arg in &spec.argv {
        ensure!(
            !arg.contains('\0') && !has_secret(arg.as_bytes(), patterns),
            "argument rejected"
        );
    }
    let (minimum, maximum) = match spec.kind {
        JobKind::Managed => (60, 7200),
        JobKind::Foreground => (1, 300),
    };
    for duration in [spec.lifetime, spec.idle_timeout] {
        ensure!(
            (Duration::from_secs(minimum)..=Duration::from_secs(maximum)).contains(&duration),
            "invalid timeout"
        );
    }
    if let Some(actor) = &spec.origin.actor {
        validate_identity(actor, patterns)?;
    }
    for (key, value) in &spec.env {
        ensure!(
            allowed_env(key) && !key.contains('\0') && !value.contains('\0'),
            "environment rejected"
        );
        ensure!(
            !has_secret(key.as_bytes(), patterns) && !has_secret(value.as_bytes(), patterns),
            "environment rejected"
        );
    }
    spec.cwd = std::fs::canonicalize(&spec.cwd)
        .map_err(|_| anyhow::anyhow!("invalid working directory"))?;
    ensure!(spec.cwd.is_dir(), "invalid working directory");
    ensure!(
        !has_secret(spec.cwd.as_os_str().as_encoded_bytes(), patterns),
        "working directory rejected"
    );
    Ok(())
}
fn authorized<'a>(
    state: &'a mut Registry,
    actor: Option<&str>,
    id: &str,
) -> Result<&'a mut Record> {
    let r = state
        .records
        .get_mut(id)
        .ok_or_else(|| anyhow::anyhow!("job not found"))?;
    ensure!(r.view.owner.as_deref() == actor, "job access denied");
    Ok(r)
}
fn snapshot(r: &Record, out: usize, err: usize, maximum: usize) -> Result<JobSnapshot> {
    ensure!(
        (4..=PAGE).contains(&maximum),
        "page must be 4..=65536 bytes per stream"
    );
    let mut view = r.view.clone();
    if view.payload_unavailable {
        ensure!(
            out <= r.out.len && err <= r.err.len,
            "invalid output offset"
        );
        view.next_stdout_offset = r.out.len;
        view.next_stderr_offset = r.err.len;
    } else {
        (view.stdout, view.next_stdout_offset) = r.out.page(out, maximum)?;
        (view.stderr, view.next_stderr_offset) = r.err.page(err, maximum)?;
    }
    Ok(view)
}
impl JobsSupervisor {
    pub fn new(session_id: &str, secrets: Vec<String>) -> Result<Self> {
        Self::build(session_id, secrets, false)
    }

    pub(crate) fn new_for_session(session_id: &str, secrets: Vec<String>) -> Result<Self> {
        Self::build(session_id, secrets, true)
    }

    fn build(session_id: &str, secrets: Vec<String>, require_cleanup_guard: bool) -> Result<Self> {
        ensure!(session_id.len() <= 256, "session identity too long");
        ensure!(
            secrets.len() <= 64
                && secrets.iter().all(|s| !s.is_empty())
                && secrets.iter().map(String::len).sum::<usize>() <= INPUT,
            "invalid secret set"
        );
        let credentials = crate::redaction::SecretDictionary::new(&secrets)?;
        let _ = credentials.stream()?;
        validate_identity(session_id, credentials.patterns())?;
        install_managed_job_panic_adapter();
        Ok(Self {
            core: Arc::new(Core {
                session: session_id.into(),
                require_cleanup_guard,
                state: Mutex::new(Registry {
                    credentials: Arc::new(credentials),
                    credential_epoch: 0,
                    refreshing: false,
                    credential_failed: false,
                    records: HashMap::new(),
                    completed: VecDeque::new(),
                    allocated: 0,
                    running: 0,
                    closing: false,
                    sticky_unknown: false,
                    closed_through: None,
                    cleanup_guard: None,
                }),
                cancel: CancellationToken::new(),
                changed: Notify::new(),
                refresh_serial: tokio::sync::Mutex::new(()),
                publication: tokio::sync::RwLock::new(()),
                #[cfg(test)]
                finalization_gate: Mutex::new(None),
                #[cfg(test)]
                refresh_gate: Mutex::new(None),
            }),
        })
    }
    /// Host lifetime guard only, installed before any process is admitted.
    /// Worker cleanup owns the guard through Core even if the runtime drops.
    pub(crate) fn attach_cleanup_guard(&self, guard: Arc<dyn Send + Sync>) -> Result<()> {
        let mut state = lock(&self.core.state);
        ensure!(
            !state.closing && state.records.is_empty() && state.cleanup_guard.is_none(),
            "session lease must be attached before job admission"
        );
        state.cleanup_guard = Some(guard);
        Ok(())
    }

    /// Host-only monotone refresh. Call before exposing newly accepted credentials
    /// to a live session. A failed/abandoned refresh blocks output and new I/O;
    /// stop/cancellation/shutdown retain their independent cleanup authority.
    pub async fn refresh_credentials(&self, additions: &[String]) -> Result<u64> {
        let _serial = self.core.refresh_serial.lock().await;
        let (previous, epoch) = {
            let state = lock(&self.core.state);
            require_credentials(&state)?;
            ensure!(!state.closing, "supervisor closing");
            (Arc::clone(&state.credentials), state.credential_epoch)
        };
        let mut guard = RefreshGuard {
            core: Arc::clone(&self.core),
            armed: true,
        };
        ensure!(
            additions.len() <= 64 && additions.iter().map(String::len).sum::<usize>() <= INPUT,
            "invalid secret additions"
        );
        let additions = additions.to_vec();
        let old = Arc::clone(&previous);
        let (candidate, matcher) = tokio::task::spawn_blocking(move || -> Result<_> {
            let candidate = old.extended(&additions)?;
            ensure!(
                candidate.key_count() <= 64
                    && candidate.key_bytes() <= INPUT
                    && candidate.max_pattern_len() <= INPUT_LOOKBEHIND + 1,
                "invalid secret union"
            );
            let matcher = crate::retained_redaction::RetainedDictionary::new(&candidate)?;
            Ok((Arc::new(candidate), matcher))
        })
        .await
        .map_err(|_| anyhow::anyhow!("credential preparation failed"))??;
        if candidate.patterns() == previous.patterns() {
            guard.armed = false;
            return Ok(epoch);
        }
        let next_epoch = epoch
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("credential epoch exhausted"))?;
        // Existing publication may finish before this barrier. Copied snapshots
        // waiting to publish afterwards must pass the epoch check below.
        let _publication = self.core.publication.write().await;
        let records = {
            let mut state = lock(&self.core.state);
            require_credentials(&state)?;
            ensure!(!state.closing, "supervisor closing");
            validate_identity(&self.core.session, candidate.patterns())?;
            for (id, r) in &state.records {
                validate_identity(id, candidate.patterns())?;
                for identity in [r.view.owner.as_deref(), r.view.origin.actor.as_deref()]
                    .into_iter()
                    .flatten()
                {
                    validate_identity(identity, candidate.patterns())?;
                }
                if let Some(receipt) = &r.receipt {
                    for identity in [
                        &receipt.operation_id,
                        &receipt.actor,
                        &receipt.parent_scope_id,
                    ] {
                        validate_identity(identity, candidate.patterns())?;
                    }
                }
            }
            state.refreshing = true;
            state.records.keys().cloned().collect::<Vec<_>>()
        };
        self.core.changed.notify_waiters();
        #[cfg(test)]
        {
            let gate = lock(&self.core.refresh_gate).take();
            if let Some((ready, release)) = gate {
                ready.notify_one();
                release.notified().await;
            }
        }
        let maximum = candidate.max_pattern_len();
        for id in records {
            for index in 0..2 {
                let saved = {
                    let state = lock(&self.core.state);
                    let r = &state.records[&id];
                    if r.view.payload_unavailable {
                        None
                    } else {
                        let payload = if index == 0 { &r.out } else { &r.err };
                        Some((payload.len, payload.marks.clone()))
                    }
                };
                if let Some((length, marks)) = saved {
                    // Clone only bounded bitmap metadata under the lock. Expanded
                    // ranges and cursor allocation happen outside the registry.
                    let provenance = provenance_spans(&marks, length, maximum.saturating_sub(1));
                    let mut cursor = matcher.cursor(length, &provenance)?;
                    loop {
                        let complete = {
                            let mut state = lock(&self.core.state);
                            let r = state.records.get_mut(&id).expect("paused record retained");
                            cursor.step(if index == 0 { &mut r.out } else { &mut r.err }, 1024)?
                        };
                        if complete {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                }
                let present = lock(&self.core.state).records[&id].streams[index].is_some();
                if present {
                    let dictionary = Arc::clone(&candidate);
                    let prepared = tokio::task::spawn_blocking(move || dictionary.stream())
                        .await
                        .map_err(|_| anyhow::anyhow!("stream preparation failed"))??;
                    let mut state = lock(&self.core.state);
                    // A cancelled process may finalize during preparation. It
                    // discards its private tails, but never mutates retained bytes.
                    let r = state.records.get_mut(&id).expect("paused record retained");
                    if let Some(stream) = r.streams[index].as_mut() {
                        let chunk = stream.cutover(prepared, maximum)?;
                        sink(&mut state, &id, index == 1, chunk);
                    }
                }
            }
        }
        {
            let mut state = lock(&self.core.state);
            ensure!(!state.credential_failed, "credential refresh failed");
            state.credentials = candidate;
            state.credential_epoch = next_epoch;
            state.refreshing = false;
            for r in state.records.values_mut() {
                r.view.credential_epoch = next_epoch;
                r.input_tail = r.input_written.iter().copied().collect();
            }
        }
        guard.armed = false;
        self.core.changed.notify_waiters();
        Ok(next_epoch)
    }

    /// All external artifact/event/model sinks must use this gate. A stale
    /// copied page is rejected; the host may poll again using its original offsets.
    /// The callback must synchronously hand off the response, not enqueue a raw
    /// snapshot for unguarded later publication. No registry lock is held in it.
    pub async fn publish_snapshot<R>(
        &self,
        snapshot: &JobSnapshot,
        publish: impl FnOnce(&JobSnapshot) -> Result<R>,
    ) -> Result<R> {
        let _publication = self.core.publication.read().await;
        {
            let state = lock(&self.core.state);
            require_credentials(&state)?;
            let record = state
                .records
                .get(&snapshot.id)
                .ok_or_else(|| anyhow::anyhow!("job not found"))?;
            ensure!(
                snapshot.session_id == self.core.session
                    && snapshot.credential_epoch == state.credential_epoch
                    && snapshot.ownership_epoch == record.view.ownership_epoch
                    && snapshot.owner == record.view.owner,
                "stale job snapshot"
            );
        }
        publish(snapshot)
    }

    /// Snapshot preflight, not a reservation. Native start repeats admission
    /// under the registry lock immediately before spawn.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn check_start_capacity(&self) -> Result<()> {
        let state = lock(&self.core.state);
        require_credentials(&state)?;
        ensure!(
            !state.closing && !self.core.cancel.is_cancelled(),
            "supervisor closing"
        );
        ensure!(
            state.records.values().filter(|r| r.resource).count() < 4,
            "Все четыре слота процессов заняты; остановите команду через stop_command или дождитесь её завершения"
        );
        Ok(())
    }

    pub fn reserve_start(&self) -> Result<StartReservation> {
        let state = lock(&self.core.state);
        require_credentials(&state)?;
        ensure!(
            !state.closing && !self.core.cancel.is_cancelled(),
            "supervisor closing"
        );
        let id = uuid::Uuid::new_v4().to_string();
        validate_identity(&id, state.credentials.patterns())?;
        Ok(StartReservation {
            id,
            core: Arc::downgrade(&self.core),
        })
    }

    pub async fn start(&self, spec: JobSpec, cancel: CancellationToken) -> Result<JobSnapshot> {
        self.start_reserved(self.reserve_start()?, spec, cancel)
            .await
    }

    pub async fn start_reserved(
        &self,
        reservation: StartReservation,
        spec: JobSpec,
        cancel: CancellationToken,
    ) -> Result<JobSnapshot> {
        self.start_reserved_now(reservation, spec, cancel)
    }

    // Synchronous native admission point: the worker reply gate may cover
    // validation, spawn and ownership installation without an intervening await.
    pub(crate) fn start_reserved_now(
        &self,
        reservation: StartReservation,
        mut spec: JobSpec,
        cancel: CancellationToken,
    ) -> Result<JobSnapshot> {
        ensure!(
            reservation.core.ptr_eq(&Arc::downgrade(&self.core)),
            "foreign start reservation"
        );
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (&mut spec, cancel);
            bail!("managed jobs unavailable on this OS");
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            ensure!(!cancel.is_cancelled(), "scope cancelled");
            ensure!(!self.core.cancel.is_cancelled(), "supervisor closing");
            let (credentials, credential_epoch) = {
                let state = lock(&self.core.state);
                require_credentials(&state)?;
                (Arc::clone(&state.credentials), state.credential_epoch)
            };
            validate(&mut spec, credentials.patterns())?;
            ensure!(!cancel.is_cancelled(), "scope cancelled");
            // Includes actual Linux mount/namespace visibility validation before spawn.
            platform::members_gone(0, Instant::now() + CLEANUP)?;
            let out_redactor = credentials.stream()?;
            let err_redactor = credentials.stream()?;
            let id = reservation.id;
            validate_identity(&id, credentials.patterns())?;
            let (tx, rx) = mpsc::channel(1);
            let mut state = lock(&self.core.state);
            require_credentials(&state)?;
            ensure!(!state.records.contains_key(&id), "job ID already used");
            ensure!(
                state.credential_epoch == credential_epoch,
                "credentials changed before spawn"
            );
            ensure!(
                !state.closing && !self.core.cancel.is_cancelled(),
                "supervisor closing"
            );
            ensure!(
                !self.core.require_cleanup_guard || state.cleanup_guard.is_some(),
                "session runtime is not activated"
            );
            ensure!(
                state
                    .closed_through
                    .is_none_or(|last| spec.origin.turn > last),
                "origin turn closed"
            );
            ensure!(
                state.records.values().filter(|r| r.resource).count() < 4,
                "four resource slots occupied"
            );
            // Only acknowledged, confirmed records may disappear. No implicit payload eviction.
            while state.records.len() >= HISTORY {
                let pos = state
                    .completed
                    .iter()
                    .position(|key| {
                        let r = &state.records[key];
                        r.view.payload_unavailable && r.view.cleanup_complete
                    })
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "acknowledge durable completed payloads before starting more jobs"
                        )
                    })?;
                let old = state.completed.remove(pos).expect("position exists");
                state.records.remove(&old);
            }
            ensure!(!cancel.is_cancelled(), "scope cancelled");
            let mut process = platform::spawn(&spec)?;
            let view = JobSnapshot {
                kind: spec.kind,
                id: id.clone(),
                session_id: self.core.session.clone(),
                origin: spec.origin.clone(),
                owner: spec.origin.actor.clone(),
                ownership_epoch: 0,
                credential_epoch,
                status: JobStatus::Running,
                exit_code: None,
                signal: None,
                stdout: String::new(),
                stderr: String::new(),
                next_stdout_offset: 0,
                next_stderr_offset: 0,
                output_truncated: false,
                payload_unavailable: false,
                redaction_incomplete: false,
                utf8_lossy: false,
                cleanup_complete: false,
                cleanup_warning: None,
                reason: None,
                epoch_boundaries: vec![EpochBoundary {
                    epoch: 0,
                    owner: spec.origin.actor.clone(),
                    stdout_offset: 0,
                    stderr_offset: 0,
                }],
            };
            state.records.insert(
                id.clone(),
                Record {
                    view: view.clone(),
                    out: Payload::default(),
                    err: Payload::default(),
                    streams: [
                        Some(OutputStream::new(out_redactor)),
                        Some(OutputStream::new(err_redactor)),
                    ],
                    scope: cancel,
                    stop: false,
                    cause: None,
                    last_activity: Instant::now(),
                    foreground_raw_bytes: 0,
                    input: spec.stdin.then_some(tx),
                    input_budget: Arc::new(Semaphore::new(INPUT)),
                    input_tail: Vec::new(),
                    input_written: VecDeque::with_capacity(INPUT_LOOKBEHIND),
                    input_closing: false,
                    receipt: None,
                    done: false,
                    resource: true,
                    cleanup_uncertain: false,
                    pgid: Some(process.pgid),
                    #[cfg(test)]
                    panic_run: false,
                },
            );
            state.running += 1;
            process.lease = Some((self.core.clone(), id.clone()));
            let core = self.core.clone();
            // Spawn and ownership installation have no intervening await.
            tokio::spawn(async move {
                let result = Catch::new(platform::run(&mut process, &spec, &core, &id, rx)).await;
                let outcome = match result {
                    Ok(outcome) => outcome,
                    Err(()) => {
                        // The unwound future has already dropped every pipe future.
                        mark_unknown(&core, &id);
                        {
                            let mut state = lock(&core.state);
                            let r = state.records.get_mut(&id).expect("record retained");
                            request(
                                r,
                                JobStatus::Failed,
                                "managed worker panic; cleanup unconfirmed",
                            );
                            r.view.reason =
                                Some("managed worker panic; cleanup unconfirmed".into());
                        }
                        let _recovered = platform::cleanup(&mut process, &core, &id).await;
                        RunOutcome {
                            cleanup_complete: false,
                            tails: [false, false],
                        }
                    }
                };
                drop(process); // kill-before-child-drop fallback; never writes to a terminal
                finalize(&core, id, outcome).await;
            });
            Ok(view)
        }
    }
    pub async fn poll(
        &self,
        actor: Option<&str>,
        id: &str,
        stdout_offset: usize,
        stderr_offset: usize,
        max_bytes: usize,
    ) -> Result<JobSnapshot> {
        self.poll_snapshot(actor, id, stdout_offset, stderr_offset, max_bytes)
    }

    // Used by the host's synchronous persistence callback under publish_snapshot.
    pub(crate) fn poll_snapshot(
        &self,
        actor: Option<&str>,
        id: &str,
        stdout_offset: usize,
        stderr_offset: usize,
        max_bytes: usize,
    ) -> Result<JobSnapshot> {
        let mut state = lock(&self.core.state);
        require_credentials(&state)?;
        snapshot(
            authorized(&mut state, actor, id)?,
            stdout_offset,
            stderr_offset,
            max_bytes,
        )
    }
    pub async fn send_input(
        &self,
        actor: Option<&str>,
        id: &str,
        bytes: &[u8],
        close: bool,
    ) -> Result<InputTicket> {
        ensure!(bytes.len() <= INPUT, "input too large");
        let mut state = lock(&self.core.state);
        require_credentials(&state)?;
        ensure!(
            !state.closing && !self.core.cancel.is_cancelled(),
            "supervisor closing"
        );
        let credentials = Arc::clone(&state.credentials);
        let r = authorized(&mut state, actor, id)?;
        ensure!(
            !r.done && !r.stop && !r.input_closing && !r.scope.is_cancelled(),
            "job not accepting input"
        );
        let mut check = r.input_tail.clone();
        check.extend_from_slice(bytes);
        ensure!(
            !new_input_contains_secret(&check, r.input_tail.len(), credentials.patterns()),
            "input rejected"
        );
        let permit = if bytes.is_empty() {
            None
        } else {
            Some(
                r.input_budget
                    .clone()
                    .try_acquire_many_owned(bytes.len() as u32)
                    .map_err(|_| anyhow::anyhow!("input quota"))?,
            )
        };
        let (completion, delivery) = oneshot::channel();
        r.input
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("input closed"))?
            .try_send(Input {
                bytes: bytes.to_vec(),
                written: 0,
                checked_epoch: None,
                completion: Some(completion),
                close,
                _permit: permit,
            })
            .map_err(|_| anyhow::anyhow!("input queue unavailable"))?;
        let tail = INPUT_LOOKBEHIND;
        r.input_tail = check[check.len().saturating_sub(tail)..].to_vec();
        if close {
            r.input_closing = true;
        }
        Ok(InputTicket {
            completion: delivery,
        })
    }
    /// Scope IDs and operation IDs are trusted host identities, not model inputs.
    /// The exact retry is recognized before ACL checking; no other former-owner operation is allowed.
    pub fn handoff_to_parent(
        &self,
        actor: &str,
        id: &str,
        operation_id: &str,
        expected_epoch: u64,
        parent_scope_id: &str,
        parent_cancel: CancellationToken,
    ) -> Result<HandoffReceipt> {
        let _publication = self
            .core
            .publication
            .try_write()
            .map_err(|_| anyhow::anyhow!("job publication in progress"))?;
        let mut state = lock(&self.core.state);
        require_credentials(&state)?;
        for value in [actor, operation_id, parent_scope_id] {
            validate_identity(value, state.credentials.patterns())?;
        }
        let proposed = HandoffReceipt {
            actor: actor.into(),
            operation_id: operation_id.into(),
            parent_scope_id: parent_scope_id.into(),
            expected_epoch,
            ownership_epoch: expected_epoch.saturating_add(1),
        };
        let closed_through = state.closed_through;
        let closing = state.closing;
        let r = state
            .records
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("job not found"))?;
        if let Some(receipt) = &r.receipt {
            ensure!(receipt == &proposed, "handoff replay mismatch");
            return Ok(receipt.clone());
        }
        ensure!(
            !closing
                && closed_through.is_none_or(|last| r.view.origin.turn > last)
                && r.view.kind == JobKind::Managed
                && r.view.owner.as_deref() == Some(actor)
                && r.view.ownership_epoch == expected_epoch
                && expected_epoch == 0
                && !r.done
                && !r.stop
                && !r.scope.is_cancelled()
                && !parent_cancel.is_cancelled()
                && !self.core.cancel.is_cancelled(),
            "handoff denied"
        );
        r.scope = parent_cancel;
        r.view.owner = None;
        r.view.ownership_epoch = 1;
        r.view.epoch_boundaries.push(EpochBoundary {
            epoch: 1,
            owner: None,
            stdout_offset: r.out.len,
            stderr_offset: r.err.len,
        });
        r.receipt = Some(proposed.clone());
        Ok(proposed)
    }
    /// Call only after immutable artifacts are durable. Returns an explicit payload-unavailable receipt.
    /// Cleanup failures and resource obligations are never acknowledged away.
    pub fn acknowledge_payload(&self, actor: Option<&str>, id: &str) -> Result<JobSnapshot> {
        let mut state = lock(&self.core.state);
        require_credentials(&state)?;
        let r = authorized(&mut state, actor, id)?;
        ensure!(r.done, "job still running");
        ensure!(r.view.cleanup_complete, "job cleanup not confirmed");
        let (out_len, err_len) = (r.out.len, r.err.len);
        let released = r.out.release() + r.err.release();
        // Preserve immutable offsets even though bytes are no longer available.
        r.out.len = out_len;
        r.err.len = err_len;
        r.view.payload_unavailable = true;
        r.view.output_truncated = true;
        let receipt = snapshot(r, 0, 0, PAGE)?;
        state.allocated -= released;
        Ok(receipt)
    }
    pub async fn stop(&self, actor: Option<&str>, id: &str) -> Result<JobSnapshot> {
        request(
            authorized(&mut lock(&self.core.state), actor, id)?,
            JobStatus::Stopped,
            "stopped by owner",
        );
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let notified = self.core.changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                {
                    let mut state = lock(&self.core.state);
                    let blocked = state.refreshing || state.credential_failed;
                    let r = authorized(&mut state, actor, id)?;
                    if r.done {
                        if blocked {
                            let mut view = r.view.clone();
                            view.payload_unavailable = true;
                            view.next_stdout_offset = r.out.len;
                            view.next_stderr_offset = r.err.len;
                            return Ok(view);
                        }
                        return snapshot(r, 0, 0, PAGE);
                    }
                }
                notified.await;
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("stop deadline; cleanup unconfirmed"))?
    }
    /// Host-only parent-turn boundary. A handed-off job has owner=None and
    /// survives ordinary worker completion. Real turn cancellation closes all
    /// jobs created by that turn, regardless of their current owner.
    pub(crate) async fn finish_turn(&self, turn: u64, cancel_main: bool) -> Result<()> {
        let selected =
            |r: &Record| r.view.origin.turn == turn && (cancel_main || r.view.owner.is_some());
        {
            let mut state = lock(&self.core.state);
            close_turn(&mut state, turn, cancel_main);
        }
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let notified = self.core.changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                {
                    let state = lock(&self.core.state);
                    let mut pending = false;
                    for r in state.records.values().filter(|r| selected(r)) {
                        pending |= !r.done;
                        if r.done {
                            ensure!(r.view.cleanup_complete, "turn cleanup unconfirmed");
                        }
                    }
                    if !pending {
                        return Ok(());
                    }
                }
                notified.await;
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("turn cleanup deadline; cleanup unconfirmed"))?
    }

    pub(crate) fn turn_control(&self, turn: u64) -> TurnControl {
        TurnControl {
            core: self.core.clone(),
            turn,
        }
    }

    pub async fn shutdown(&self) -> Result<()> {
        lock(&self.core.state).closing = true;
        self.core.cancel.cancel();
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let notified = self.core.changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                let finished = {
                    let mut state = lock(&self.core.state);
                    if state.running == 0 {
                        ensure!(
                            !state.sticky_unknown && state.records.values().all(|r| !r.resource),
                            "sticky cleanup obligation remains"
                        );
                        Some(state.cleanup_guard.take())
                    } else {
                        None
                    }
                };
                if let Some(guard) = finished {
                    // Never run a host-owned destructor under the registry mutex.
                    drop(guard);
                    return Ok(());
                }
                notified.await;
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("shutdown deadline; cleanup unconfirmed"))?
    }
}
impl Drop for JobsSupervisor {
    fn drop(&mut self) {
        self.core.cancel.cancel();
        let mut state = lock(&self.core.state);
        state.closing = true;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        for r in state.records.values_mut() {
            if let Some(pgid) = r.pgid {
                // Reaping and removal of this lease use this same mutex.
                if platform::signal(pgid, libc::SIGKILL).is_err() {
                    r.view.reason = Some("drop signal failed; cleanup unconfirmed".into());
                }
            }
        }
    }
}
fn mark_unknown(core: &Core, id: &str) {
    let mut state = lock(&core.state);
    state.sticky_unknown = true;
    let r = state.records.get_mut(id).expect("record retained");
    r.view.cleanup_complete = false;
    r.cleanup_uncertain = true;
    r.view.redaction_incomplete = true;
}
// Catch the complete worker future, not detached pipe tasks. Unwinding drops the
// worker and all its I/O futures before the recovery path starts.
struct Catch<F> {
    future: Pin<Box<F>>,
}
impl<F> Catch<F> {
    fn new(future: F) -> Self {
        Self {
            future: Box::pin(future),
        }
    }
}
impl<F: Future> Future for Catch<F> {
    type Output = std::result::Result<F::Output, ()>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Mark only this synchronous poll, never the task's suspended lifetime:
        // Tokio may resume the future on a different worker thread.
        let result = {
            let _marked = ManagedPollGuard::enter();
            catch_unwind(AssertUnwindSafe(|| self.future.as_mut().poll(cx)))
        };
        match result {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(value)) => Poll::Ready(Ok(value)),
            Err(_) => Poll::Ready(Err(())),
        }
    }
}
fn sink(state: &mut Registry, id: &str, stderr: bool, mut chunk: OutputChunk) {
    let Registry {
        records, allocated, ..
    } = state;
    let r = records.get_mut(id).expect("record retained");
    r.view.utf8_lossy |= chunk.lossy;
    let original_len = chunk.text.len();
    if r.view.kind == JobKind::Foreground {
        let mut take = PAGE.saturating_sub(r.out.len + r.err.len).min(original_len);
        while !chunk.text.is_char_boundary(take) {
            take -= 1;
        }
        chunk.text.truncate(take);
        // append_chunk clips provenance to the admitted bytes.
    }
    let target = if stderr { &mut r.err } else { &mut r.out };
    let n = target.append_chunk(&chunk, allocated);
    if n < original_len {
        r.view.output_truncated = true;
        request(r, JobStatus::Cancelled, "retained output quota");
    }
}
async fn ingest(core: &Core, id: &str, stderr: bool, raw: &[u8]) -> Result<()> {
    loop {
        let changed = core.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        {
            let mut state = lock(&core.state);
            let refreshing = state.refreshing;
            let failed = state.credential_failed;
            let r = state.records.get_mut(id).expect("record retained");
            if failed || r.stop || r.scope.is_cancelled() || core.cancel.is_cancelled() {
                // Continue draining after cancellation so paused redaction cannot
                // turn known process/pipe cleanup into an unknown obligation.
                r.view.redaction_incomplete = true;
                return Ok(());
            }
            if !refreshing {
                let chunk = r.streams[usize::from(stderr)]
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("output stream unavailable"))?
                    .push(raw)?;
                sink(&mut state, id, stderr, chunk);
                return Ok(());
            }
        }
        tokio::select! { _ = &mut changed => (), _ = tokio::time::sleep(TICK) => () }
    }
}
#[cfg(test)]
async fn finalization_gate(core: &Core) {
    let gate = lock(&core.finalization_gate).take();
    if let Some((ready, release)) = gate {
        ready.notify_one();
        release.notified().await;
    }
}

struct RunOutcome {
    cleanup_complete: bool,
    // Reader EOF is private; stream state remains under the registry barrier.
    tails: [bool; 2],
}
fn tail_capacity(payload: &Payload, bytes: usize) -> Option<usize> {
    let len = payload.len.checked_add(bytes)?;
    if len > STREAM {
        return None;
    }
    Some(len.div_ceil(BLOCK).saturating_sub(payload.blocks.len()) * BLOCK)
}
async fn finalize(core: &Core, id: String, outcome: RunOutcome) {
    loop {
        let changed = core.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        if finalize_ready(core, &id, &outcome) {
            return;
        }
        tokio::select! { _ = &mut changed => (), _ = tokio::time::sleep(TICK) => () }
    }
}
fn finalize_ready(core: &Core, id: &str, outcome: &RunOutcome) -> bool {
    let mut state = lock(&core.state);
    let r = &state.records[id];
    if state.refreshing
        && !state.credential_failed
        && !r.stop
        && !r.scope.is_cancelled()
        && !core.cancel.is_cancelled()
    {
        return false;
    }
    let failed = state.credential_failed;
    let Registry {
        records, allocated, ..
    } = &mut *state;
    let r = records.get_mut(id).expect("live record retained");
    if failed {
        request(r, JobStatus::Failed, "credential refresh failed");
    }
    let confirmed = outcome.cleanup_complete && !r.cleanup_uncertain;
    if core.cancel.is_cancelled() || r.scope.is_cancelled() {
        request(r, JobStatus::Cancelled, "scope cancelled");
    }
    let clean = confirmed
        && !r.stop
        && r.cause.is_none()
        && r.view.exit_code == Some(0)
        && r.view.signal.is_none();
    let mut published = false;
    if clean {
        let prepared = std::array::from_fn::<_, 2, _>(|i| {
            if outcome.tails[i] {
                r.streams[i].take().map(OutputStream::finish)
            } else {
                None
            }
        });
        if let [Some(Ok(out)), Some(Ok(err))] = prepared {
            let capacity =
                tail_capacity(&r.out, out.text.len()).zip(tail_capacity(&r.err, err.text.len()));
            let fits = capacity.is_some_and(|(a, b)| a + b <= GLOBAL - *allocated)
                && (r.view.kind != JobKind::Foreground
                    || r.out.len + r.err.len + out.text.len() + err.text.len() <= PAGE);
            // This observation is the cancellation acceptance boundary. stop() uses
            // this same mutex; cancellation after this point sees a terminal record.
            // Both tails and done/status publish under the lock, with no await.
            if core.cancel.is_cancelled() || r.scope.is_cancelled() {
                request(r, JobStatus::Cancelled, "scope cancelled");
            } else if !fits {
                r.view.output_truncated = true;
                request(r, JobStatus::Cancelled, "retained output quota");
            } else {
                let out_written = r.out.append_chunk(&out, allocated);
                let err_written = r.err.append_chunk(&err, allocated);
                debug_assert_eq!((out_written, err_written), (out.text.len(), err.text.len()));
                r.view.utf8_lossy |= out.lossy || err.lossy;
                published = true;
            }
        } else {
            request(r, JobStatus::Failed, "output finalization failure");
        }
    }
    // Dropping uncommitted tails discards private redactor/UTF8 lookbehind.
    r.streams = [None, None];
    r.view.redaction_incomplete |= !published;
    r.done = true;
    r.input = None;
    r.input_tail = Vec::new();
    r.input_written = VecDeque::new();
    r.view.cleanup_complete = confirmed;
    r.resource = !confirmed;
    r.view.status = if confirmed {
        r.cause.unwrap_or(JobStatus::Exited)
    } else {
        JobStatus::Unknown
    };
    if !confirmed && r.view.reason.is_none() {
        r.view.reason = Some(
            "cleanup unknown; group observation or pipe completion failed; escape is not contained"
                .into(),
        );
    }
    state.sticky_unknown |= !confirmed;
    state.running -= 1;
    state.completed.push_back(id.to_owned());
    drop(state);
    core.changed.notify_waiters();
    true
}
async fn drain<R: AsyncRead + Unpin>(
    mut pipe: R,
    core: &Core,
    id: &str,
    stderr: bool,
) -> Result<()> {
    let mut buffer = [0; BLOCK];
    let mut total = 0usize;
    let result: Result<()> = async {
        loop {
            let n = pipe
                .read(&mut buffer)
                .await
                .map_err(|_| anyhow::anyhow!("output read failure"))?;
            if n == 0 {
                break;
            }
            let (admitted, overflow) = {
                let mut state = lock(&core.state);
                let r = state.records.get_mut(id).expect("record retained");
                r.last_activity = Instant::now();
                if r.view.kind == JobKind::Foreground {
                    let admitted = n.min(PAGE.saturating_sub(r.foreground_raw_bytes));
                    r.foreground_raw_bytes += admitted;
                    (admitted, admitted < n)
                } else {
                    (n, false)
                }
            };
            total = total.saturating_add(n);
            // Foreground excess is discarded while the readers keep draining
            // through cleanup. A quota stop is not a pipe I/O failure.
            if admitted != 0 {
                ensure!(total <= STREAM, "raw output quota");
                ingest(core, id, stderr, &buffer[..admitted]).await?;
            }
            if overflow {
                let mut state = lock(&core.state);
                let r = state.records.get_mut(id).expect("record retained");
                r.view.output_truncated = true;
                request(r, JobStatus::Cancelled, "foreground raw output quota");
            }
        }
        Ok(())
    }
    .await;
    if result.is_err() {
        let mut state = lock(&core.state);
        let r = state.records.get_mut(id).expect("record retained");
        r.view.redaction_incomplete = true;
        if total > STREAM {
            r.view.output_truncated = true;
        }
        request(
            r,
            JobStatus::Failed,
            "output I/O, quota, or redaction failure",
        );
    }
    result?;
    Ok(())
}

// One poll_write and its actual-byte accounting share the credential barrier.
// Pending readiness never retains the registry mutex. Refresh notifications wake
// a blocked pipe so an unsafe in-flight remainder is rejected even without I/O readiness.
async fn deliver_input<W: AsyncWrite + Unpin>(
    pipe: &mut W,
    packet: &mut Input,
    core: &Core,
    id: &str,
) -> std::io::Result<()> {
    loop {
        let changed = core.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        let progress = std::future::poll_fn(|cx| {
            let mut state = lock(&core.state);
            if state.refreshing {
                return Poll::Pending;
            }
            let epoch = state.credential_epoch;
            let failed = state.credential_failed;
            let credentials = Arc::clone(&state.credentials);
            let r = state.records.get_mut(id).expect("record retained");
            if r.stop || r.scope.is_cancelled() || core.cancel.is_cancelled() {
                packet.complete(InputStatus::Cancelled);
                return Poll::Ready(Ok(true));
            }
            if packet.checked_epoch != Some(epoch) || failed {
                let mut check: Vec<u8> = r.input_written.iter().copied().collect();
                let prefix = check.len();
                check.extend_from_slice(&packet.bytes[packet.written..]);
                if failed || new_input_contains_secret(&check, prefix, credentials.patterns()) {
                    if packet.close {
                        r.input_closing = false;
                    }
                    // Accepted-but-unwritten history is advisory. The writer checks
                    // every following packet against the actual stream before writing.
                    r.input_tail = r.input_written.iter().copied().collect();
                    packet.complete(InputStatus::Rejected);
                    return Poll::Ready(Ok(true));
                }
                packet.checked_epoch = Some(epoch);
            }
            if packet.written < packet.bytes.len() {
                let end = packet.bytes.len().min(packet.written + BLOCK);
                match Pin::new(&mut *pipe).poll_write(cx, &packet.bytes[packet.written..end]) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(error)) => {
                        packet.complete(InputStatus::IoError);
                        Poll::Ready(Err(error))
                    }
                    Poll::Ready(Ok(0)) => {
                        packet.complete(InputStatus::IoError);
                        Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::WriteZero)))
                    }
                    Poll::Ready(Ok(n)) => {
                        for byte in &packet.bytes[packet.written..packet.written + n] {
                            if r.input_written.len() == INPUT_LOOKBEHIND {
                                r.input_written.pop_front();
                            }
                            r.input_written.push_back(*byte);
                        }
                        packet.written += n;
                        r.last_activity = Instant::now();
                        Poll::Ready(Ok(false))
                    }
                }
            } else if packet.close {
                match Pin::new(&mut *pipe).poll_shutdown(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(error)) => {
                        packet.complete(InputStatus::IoError);
                        Poll::Ready(Err(error))
                    }
                    Poll::Ready(Ok(())) => {
                        r.input = None;
                        packet.complete(InputStatus::Delivered);
                        Poll::Ready(Ok(true))
                    }
                }
            } else {
                packet.complete(InputStatus::Delivered);
                Poll::Ready(Ok(true))
            }
        });
        let done = tokio::select! {
            biased;
            _ = &mut changed => continue,
            result = progress => result?,
        };
        if done {
            return Ok(());
        }
        tokio::task::yield_now().await;
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod platform {
    use super::*;
    use std::os::unix::process::CommandExt;
    use tokio::process::{Child, Command};
    const ENUM_LIMIT: usize = 32768;
    pub(super) struct Process {
        pub child: Child,
        pub pgid: i32,
        pub lease: Option<(Arc<Core>, String)>,
        reaped: bool,
    }
    pub(super) fn signal(pgid: i32, sig: i32) -> Result<()> {
        ensure!(pgid > 0, "invalid process group");
        if unsafe { libc::kill(-pgid, sig) } == 0 {
            return Ok(());
        }
        ensure!(
            std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH),
            "group signal failed"
        );
        Ok(())
    }
    impl Drop for Process {
        fn drop(&mut self) {
            if self.reaped {
                return;
            }
            if let Some((core, id)) = &self.lease {
                let mut state = lock(&core.state);
                state.sticky_unknown = true;
                if let Some(r) = state.records.get_mut(id) {
                    r.cleanup_uncertain = true;
                    if r.pgid.take().is_some() && signal(self.pgid, libc::SIGKILL).is_err() {
                        r.view.reason = Some("emergency signal failed".into());
                    }
                }
            } else {
                // No host record exists yet. Failure propagates via the failed start;
                // no terminal diagnostic is emitted in this best-effort fallback.
                let _delivery = signal(self.pgid, libc::SIGKILL);
            }
            // tokio owns orphan reaping after Child drop. The numeric lease is gone.
        }
    }
    pub(super) fn spawn(spec: &JobSpec) -> Result<Process> {
        let mut cmd = Command::new(&spec.argv[0]);
        cmd.args(&spec.argv[1..])
            .current_dir(&spec.cwd)
            .env_clear()
            .envs(spec.env.iter().cloned())
            .env("PWD", &spec.cwd)
            .env("RCODE_MODEL_SHELL", "1");
        cmd.stdin(if spec.stdin {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        });
        cmd.stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        unsafe {
            cmd.as_std_mut().pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd
            .spawn()
            .map_err(|_| anyhow::anyhow!("job spawn failed"))?;
        let pgid = child.id().expect("new child has PID") as i32;
        Ok(Process {
            child,
            pgid,
            lease: None,
            reaped: false,
        })
    }
    fn exited(pid: i32) -> Result<bool> {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if rc != 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                return Ok(false);
            }
            bail!(
                "leader observation failed: {}",
                std::io::Error::last_os_error()
            );
        }
        #[cfg(target_os = "linux")]
        let found = unsafe { info.si_pid() };
        #[cfg(target_os = "macos")]
        let found = info.si_pid;
        Ok(found == pid)
    }
    // Linux visibility is established from the actual mount table, procfs type,
    // and PID-namespace identities, not merely successful reads of our own PID.
    // This deliberately conservative backend rejects all submounts below /proc,
    // even benign ones, and unknown procfs superblock options. An unavailable or
    // restricted backend refuses admission; there is no enumeration fallback.
    #[cfg(target_os = "linux")]
    fn mount_path(field: &str) -> Result<Vec<u8>> {
        let bytes = field.as_bytes();
        let mut decoded = Vec::with_capacity(bytes.len());
        let mut at = 0;
        while at < bytes.len() {
            if bytes[at] != b'\\' {
                decoded.push(bytes[at]);
                at += 1;
            } else {
                ensure!(at + 4 <= bytes.len(), "invalid mount path escape");
                let value = match &bytes[at + 1..at + 4] {
                    b"040" => b' ',
                    b"011" => b'\t',
                    b"012" => b'\n',
                    b"134" => b'\\',
                    _ => bail!("invalid mount path escape"),
                };
                decoded.push(value);
                at += 4;
            }
        }
        Ok(decoded)
    }
    #[cfg(target_os = "linux")]
    fn unrestricted_proc_mount(table: &str, deadline: Instant) -> Result<()> {
        let mut found = false;
        for (index, line) in table.lines().enumerate() {
            ensure!(
                index < ENUM_LIMIT && line.len() <= 16384 && Instant::now() < deadline,
                "mount enumeration limit"
            );
            let fields: Vec<_> = line.split_ascii_whitespace().take(257).collect();
            ensure!(fields.len() <= 256, "mount field limit");
            let separator = fields
                .iter()
                .position(|field| *field == "-")
                .ok_or_else(|| anyhow::anyhow!("invalid mountinfo"))?;
            ensure!(
                separator >= 6 && fields.len() == separator + 4,
                "invalid mountinfo"
            );
            let root = mount_path(fields[3])?;
            let point = mount_path(fields[4])?;
            if let Some(relative) = point.strip_prefix(b"/proc/") {
                let first = relative.split(|byte| *byte == b'/').next().unwrap();
                // Docker's read-only/masked sys, irq, bus and similar mounts
                // cannot hide numeric process entries. PID records and self
                // aliases must remain entirely on the original procfs.
                ensure!(
                    !first.is_empty()
                        && !first.iter().all(u8::is_ascii_digit)
                        && !matches!(first, b"self" | b"thread-self" | b"." | b".."),
                    "procfs submount obscures visibility"
                );
            }
            if point != b"/proc" {
                continue;
            }
            ensure!(
                !found && root == b"/" && fields[separator + 1] == "proc",
                "incompatible procfs mount"
            );
            found = true;
            for option in fields[5].split(',') {
                ensure!(
                    matches!(
                        option,
                        "rw" | "ro"
                            | "nosuid"
                            | "nodev"
                            | "noexec"
                            | "relatime"
                            | "noatime"
                            | "nodiratime"
                            | "strictatime"
                            | "lazytime"
                    ),
                    "unsupported procfs mount option"
                );
            }
            for option in fields[separator + 3].split(',') {
                let harmless_gid = option.strip_prefix("gid=").is_some_and(|value| {
                    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
                });
                // hidepid=invisible/noaccess/ptraceable and subset=pid are not
                // acceptable, regardless of current credentials or group access.
                ensure!(
                    matches!(option, "rw" | "ro" | "hidepid=0") || harmless_gid,
                    "restricted or unsupported procfs superblock option"
                );
            }
        }
        ensure!(
            found && Instant::now() < deadline,
            "procfs mount unavailable"
        );
        Ok(())
    }
    #[cfg(target_os = "linux")]
    fn pidfd_process_gone(pid: i32, deadline: Instant) -> Result<bool> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        ensure!(
            pid > 0 && Instant::now() < deadline,
            "pidfd observation deadline"
        );
        let descriptor = loop {
            // flags=0 refers to the complete thread group, never PIDFD_THREAD.
            // The kernel returns a fresh close-on-exec descriptor on success.
            let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
            if descriptor >= 0 {
                break unsafe { OwnedFd::from_raw_fd(descriptor as i32) };
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                return Ok(true);
            }
            if error.raw_os_error() == Some(libc::EINTR) && Instant::now() < deadline {
                continue;
            }
            bail!("pidfd_open unavailable or failed: {error}");
        };
        let mut event = libc::pollfd {
            fd: descriptor.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            ensure!(Instant::now() < deadline, "pidfd observation deadline");
            let result = unsafe { libc::poll(&mut event, 1, 0) };
            if result >= 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINTR) {
                return Err(error.into());
            }
        }
        ensure!(
            event.revents & (libc::POLLERR | libc::POLLNVAL) == 0,
            "invalid pidfd observation"
        );
        Ok(event.revents & (libc::POLLIN | libc::POLLHUP) != 0)
    }
    #[cfg(target_os = "linux")]
    fn proc_visibility(deadline: Instant) -> Result<()> {
        use std::{io::Read, os::unix::fs::MetadataExt};
        ensure!(Instant::now() < deadline, "procfs visibility deadline");
        ensure!(
            std::fs::symlink_metadata("/proc")?.file_type().is_dir(),
            "invalid procfs path"
        );
        let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
        ensure!(
            unsafe { libc::statfs(b"/proc\0".as_ptr().cast(), &mut filesystem) } == 0
                && filesystem.f_type as u64 == 0x9fa0,
            "procfs unavailable"
        );
        const MOUNT_BYTES: usize = 1024 * 1024;
        let file = std::fs::File::open("/proc/self/mountinfo")?;
        let mut bytes = Vec::new();
        file.take((MOUNT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= MOUNT_BYTES && Instant::now() < deadline,
            "mountinfo limit"
        );
        unrestricted_proc_mount(std::str::from_utf8(&bytes)?, deadline)?;
        let own = std::fs::metadata("/proc/self/ns/pid")?;
        let init = std::fs::metadata("/proc/1/ns/pid")?;
        ensure!(
            own.dev() == init.dev() && own.ino() == init.ino(),
            "procfs belongs to another PID namespace"
        );
        ensure!(
            std::fs::read_link("/proc/self")? == PathBuf::from(std::process::id().to_string()),
            "procfs PID mapping mismatch"
        );
        // Probe the required kernel API before any managed spawn. There is no
        // fallback to interpreting a zombie thread-group leader as process exit.
        ensure!(
            !pidfd_process_gone(std::process::id() as i32, deadline)?,
            "invalid self pidfd state"
        );
        ensure!(Instant::now() < deadline, "procfs visibility deadline");
        Ok(())
    }
    // Linux 5.3+ pidfd_open(flags=0) and poll prove whole-thread-group exit;
    // /proc/<tgid>/stat is used only to identify group membership. A zombie
    // main thread can coexist with live workers and is never enough evidence.
    // ENOENT alone denotes a vanished entry; all
    // other read/parse/permission failures refuse confirmation. Per-stat reads
    // are <=4097 bytes, table reads <=1 MiB+1, and entry counts/time are bounded.
    // Kernel procfs operations themselves are assumed to return promptly.
    //
    // These are non-atomic observations, not a snapshot or a general containment
    // proof. Confirmation assumes truthful kernel enumeration does not omit a
    // continuously live in-group process, stable host mounts/PID namespace, and
    // fatal signalling followed by two complete scans without surviving-member
    // churn defeating enumeration. No numeric group signal follows leader reap.
    // Deliberate group/PID-namespace escape remains outside this contract.
    #[cfg(target_os = "linux")]
    pub(super) fn members_gone(pgid: i32, deadline: Instant) -> Result<bool> {
        use std::io::Read;
        // Revalidate during cleanup as well as at pre-spawn admission. Concurrent
        // host mount/namespace changes are forbidden by the integration contract.
        proc_visibility(deadline)?;
        let mut gone = true;
        for (index, entry) in std::fs::read_dir("/proc")?.enumerate() {
            ensure!(
                index < ENUM_LIMIT && Instant::now() < deadline,
                "process enumeration limit"
            );
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                bail!("invalid proc entry");
            };
            if !name.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let file = match std::fs::File::open(entry.path().join("stat")) {
                Ok(file) => file,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            let mut bytes = Vec::with_capacity(4097);
            file.take(4097).read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= 4096, "proc stat overflow");
            let close = bytes
                .iter()
                .rposition(|b| *b == b')')
                .ok_or_else(|| anyhow::anyhow!("invalid proc stat"))?;
            let tail = std::str::from_utf8(&bytes[close + 1..])?;
            let mut fields = tail.split_ascii_whitespace();
            fields
                .next()
                .ok_or_else(|| anyhow::anyhow!("missing process state"))?;
            fields
                .next()
                .ok_or_else(|| anyhow::anyhow!("missing parent"))?;
            let group: i32 = fields
                .next()
                .ok_or_else(|| anyhow::anyhow!("missing group"))?
                .parse()?;
            if group == pgid && !pidfd_process_gone(name.parse()?, deadline)? {
                gone = false;
            }
        }
        ensure!(Instant::now() < deadline, "process enumeration deadline");
        Ok(gone)
    }
    // Darwin assumptions, to verify against the deployment SDK's libproc.h and
    // sys/proc_info.h: PROC_PGRP_ONLY=2, PROC_PIDT_SHORTBSDINFO=13; the C layout
    // below is proc_bsdshortinfo (64 bytes), SZOMB=5. proc_listpids returns bytes,
    // possibly including zero padding. A full buffer is treated as overflow.
    // Nonleader zombies hold no live process resources and are excluded.
    #[cfg(target_os = "macos")]
    pub(super) fn members_gone(pgid: i32, deadline: Instant) -> Result<bool> {
        #[repr(C)]
        struct ShortInfo {
            pid: u32,
            ppid: u32,
            pgid: u32,
            status: u32,
            comm: [u8; 16],
            flags: u32,
            uid: u32,
            gid: u32,
            ruid: u32,
            rgid: u32,
            svuid: u32,
            svgid: u32,
            rfu: u32,
        }
        unsafe extern "C" {
            fn proc_listpids(kind: u32, info: u32, buffer: *mut libc::c_void, size: i32) -> i32;
            fn proc_pidinfo(
                pid: i32,
                flavor: i32,
                arg: u64,
                buffer: *mut libc::c_void,
                size: i32,
            ) -> i32;
        }
        let mut pids = vec![0i32; ENUM_LIMIT + 1];
        // Preflight enumerates all processes; real verification filters by group.
        let kind = if pgid == 0 { 1 } else { 2 };
        let size = (pids.len() * 4) as i32;
        let n = unsafe { proc_listpids(kind, pgid as u32, pids.as_mut_ptr().cast(), size) };
        ensure!(
            n > 0 && n < size && n % 4 == 0,
            "Darwin process enumeration failed/overflowed"
        );
        let mut gone = true;
        for pid in pids.into_iter().take(n as usize / 4).filter(|pid| *pid > 0) {
            ensure!(Instant::now() < deadline, "enumeration deadline");
            let mut info: ShortInfo = unsafe { std::mem::zeroed() };
            let n = unsafe {
                proc_pidinfo(
                    pid,
                    13,
                    0,
                    (&mut info as *mut ShortInfo).cast(),
                    std::mem::size_of::<ShortInfo>() as i32,
                )
            };
            if n <= 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                continue;
            }
            ensure!(
                n == std::mem::size_of::<ShortInfo>() as i32 && info.pid == pid as u32,
                "Darwin process observation failed"
            );
            if info.pgid == pgid as u32 && info.status != 5 {
                gone = false;
            }
        }
        Ok(gone)
    }
    #[cfg(all(test, target_os = "linux"))]
    mod visibility_tests {
        use super::*;
        fn check(table: &str) -> Result<()> {
            unrestricted_proc_mount(table, Instant::now() + CLEANUP)
        }
        #[test]
        fn mountinfo_escapes_and_visibility_options() {
            assert_eq!(
                mount_path(r"/a\040b\011c\012d\134e").unwrap(),
                b"/a b\tc\nd\\e"
            );
            assert!(mount_path(r"/bad\041").is_err());
            let ordinary = "20 1 0:4 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n";
            assert!(check(ordinary).is_ok());
            for options in [
                "rw,hidepid=1",
                "rw,hidepid=2",
                "rw,hidepid=4",
                "rw,hidepid=invisible",
                "rw,subset=pid",
                "rw,unknown=1",
            ] {
                assert!(
                    check(&ordinary.replace("proc proc rw", &format!("proc proc {options}")))
                        .is_err()
                );
            }
            assert!(
                check(&format!(
                    "{ordinary}21 20 0:5 / /proc/123 rw - tmpfs tmpfs rw\n"
                ))
                .is_err()
            );
            // A nonnumeric component does not shadow /proc/123.
            assert!(
                check(&format!(
                    "{ordinary}21 20 0:5 / /proc/123\\040hidden rw - tmpfs tmpfs rw\n"
                ))
                .is_ok()
            );
            assert!(check(&ordinary.replace(" / /proc ", " /subtree /proc ")).is_err());
            assert!(check(&ordinary.replace(" - proc ", " - tmpfs ")).is_err());
            assert!(check(&format!("{ordinary}{ordinary}")).is_err());
            assert!(check("").is_err());
        }
        #[test]
        fn benign_non_pid_mounts_do_not_hide_members() {
            let ordinary = "20 1 0:4 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n";
            for path in [
                "/proc/bus",
                "/proc/fs",
                "/proc/irq",
                "/proc/sys",
                "/proc/sysrq-trigger",
                "/proc/acpi",
                "/proc/kcore",
                "/proc/keys",
                "/proc/timer_list",
            ] {
                assert!(
                    check(&format!(
                        "{ordinary}21 20 0:5 / {path} ro - tmpfs tmpfs rw\n"
                    ))
                    .is_ok(),
                    "{path}"
                );
            }
            for path in [
                "/proc/123",
                "/proc/123/task",
                "/proc/self",
                "/proc/self/mountinfo",
                "/proc/thread-self",
            ] {
                assert!(
                    check(&format!(
                        "{ordinary}21 20 0:5 / {path} ro - tmpfs tmpfs rw\n"
                    ))
                    .is_err(),
                    "{path}"
                );
            }
        }
    }
    fn signal_owned(process: &Process, core: &Core, id: &str, signal_number: i32) -> bool {
        let mut state = lock(&core.state);
        if process.reaped || state.records[id].pgid != Some(process.pgid) {
            return false;
        }
        if signal(process.pgid, signal_number).is_err() {
            state.records.get_mut(id).unwrap().view.cleanup_warning = Some(
                "Group signal was rejected; cleanup requires independent completion evidence"
                    .into(),
            );
        }
        true
    }
    async fn observe_termination(process: &Process, deadline: Instant) -> Result<bool> {
        let mut observations = 0;
        while Instant::now() < deadline {
            if exited(process.pgid)? && members_gone(process.pgid, deadline)? {
                observations += 1;
                if observations == 2 {
                    return Ok(true);
                }
            } else {
                observations = 0;
            }
            tokio::time::sleep(TICK).await;
        }
        Ok(false)
    }
    pub(super) async fn cleanup(process: &mut Process, core: &Core, id: &str) -> bool {
        // Never signal a numeric group after our Child has been reaped, including
        // recovery after a panic later in run(). Reap and lease removal below use
        // this same mutex as supervisor Drop.
        if !signal_owned(process, core, id, libc::SIGTERM) {
            return false;
        }
        let graceful = match observe_termination(process, Instant::now() + TERM_GRACE).await {
            Ok(complete) => complete,
            Err(_) => {
                lock(&core.state).records.get_mut(id).unwrap().view.cleanup_warning.get_or_insert_with(||
                    "Grace-period observation was incomplete; final cleanup needs fresh evidence".into());
                false
            }
        };
        let mut known = if graceful {
            true
        } else {
            if !signal_owned(process, core, id, libc::SIGKILL) {
                return false;
            }
            match observe_termination(process, Instant::now() + CLEANUP).await {
                Ok(complete) => complete,
                Err(_) => {
                    lock(&core.state)
                        .records
                        .get_mut(id)
                        .unwrap()
                        .view
                        .reason
                        .get_or_insert_with(|| {
                            "Final process-group observation failed; cleanup is unknown".into()
                        });
                    false
                }
            }
        };
        // Signal delivery alone proves nothing. Conversely, Darwin EPERM for
        // an already-dead group does not invalidate complete exit observations.
        if !known {
            mark_unknown(core, id);
        }
        // Tokio must observe the reap too: a raw waitpid would leave Child with
        // an outstanding orphan-reaping obligation against a reusable PID.
        // try_wait is synchronous. Child state, our state, and the numeric lease
        // change under the same mutex, with no await or intervening group signal.
        use std::os::unix::process::ExitStatusExt;
        let mut state = lock(&core.state);
        let r = state.records.get_mut(id).expect("record retained");
        match process.child.try_wait() {
            Ok(Some(status)) => {
                process.reaped = true;
                r.pgid = None;
                r.view.exit_code = status.code();
                r.view.signal = status.signal();
            }
            Ok(None) | Err(_) => {
                known = false;
                r.cleanup_uncertain = true;
                state.sticky_unknown = true;
            }
        }
        known
    }
    pub(super) async fn run(
        process: &mut Process,
        spec: &JobSpec,
        core: &Core,
        id: &str,
        mut input: mpsc::Receiver<Input>,
    ) -> RunOutcome {
        let out = process.child.stdout.take().expect("piped stdout");
        let err = process.child.stderr.take().expect("piped stderr");
        let stdin = process.child.stdin.take();
        let writer_cancel = CancellationToken::new();
        let writer_token = writer_cancel.clone();
        let out_tail = Mutex::new(false);
        let err_tail = Mutex::new(false);
        let reader_out = async {
            drain(out, core, id, false).await?;
            *lock(&out_tail) = true;
            Ok::<(), anyhow::Error>(())
        };
        let reader_err = async {
            drain(err, core, id, true).await?;
            *lock(&err_tail) = true;
            Ok::<(), anyhow::Error>(())
        };
        let writer = async {
            let work = async {
                if let Some(mut pipe) = stdin {
                    while let Some(mut packet) = input.recv().await {
                        deliver_input(&mut pipe, &mut packet, core, id).await?;
                        // A rejected close packet must not close interactive stdin.
                        if lock(&core.state).records[id].input.is_none() {
                            break;
                        }
                    }
                }
                Ok::<(), std::io::Error>(())
            };
            let result =
                tokio::select! { biased; _ = writer_token.cancelled() => Ok(()), r = work => r };
            if result.is_err() {
                request(
                    lock(&core.state)
                        .records
                        .get_mut(id)
                        .expect("record retained"),
                    JobStatus::Failed,
                    "stdin I/O failure",
                );
            }
            // A write failure is an operation failure, already recorded above,
            // not missing process/pipe cleanup evidence. Completing this future
            // destroys its stdin pipe even on EPIPE. Readers remain conservative:
            // their errors still make io_ok false and mark output incomplete.
            true
        };
        tokio::pin!(reader_out, reader_err, writer);
        let (mut out_done, mut err_done, mut writer_done) = (false, false, false);
        let mut io_ok = true;
        let started = Instant::now();
        loop {
            {
                let mut state = lock(&core.state);
                let r = state.records.get_mut(id).expect("record retained");
                #[cfg(test)]
                if r.panic_run {
                    panic!("injected worker panic");
                }
                if core.cancel.is_cancelled() || r.scope.is_cancelled() {
                    request(r, JobStatus::Cancelled, "scope cancelled");
                }
                if started.elapsed() >= spec.lifetime
                    || r.last_activity.elapsed() >= spec.idle_timeout
                {
                    request(r, JobStatus::TimedOut, "execution timeout");
                }
                if r.stop {
                    break;
                }
            }
            match exited(process.pgid) {
                Ok(true) => break,
                Ok(false) => (),
                Err(error) => {
                    lock(&core.state).records.get_mut(id).unwrap().view.reason =
                        Some(format!("initial leader observation failed: {error:#}"));
                    mark_unknown(core, id);
                    break;
                }
            }
            tokio::select! {
                result = &mut reader_out, if !out_done => { out_done = true; io_ok &= result.is_ok(); }
                result = &mut reader_err, if !err_done => { err_done = true; io_ok &= result.is_ok(); }
                ok = &mut writer, if !writer_done => { writer_done = true; io_ok &= ok; }
                _ = tokio::time::sleep(TICK) => ()
            }
        }
        writer_cancel.cancel();
        let group = cleanup(process, core, id);
        tokio::pin!(group);
        let group_ok = loop {
            tokio::select! {
                result = &mut group => break result,
                result = &mut reader_out, if !out_done => { out_done = true; io_ok &= result.is_ok(); }
                result = &mut reader_err, if !err_done => { err_done = true; io_ok &= result.is_ok(); }
                ok = &mut writer, if !writer_done => { writer_done = true; io_ok &= ok; }
            }
        };
        let joined = tokio::time::timeout(PIPE_WAIT, async {
            while !out_done || !err_done || !writer_done {
                tokio::select! {
                    result = &mut reader_out, if !out_done => { out_done = true; io_ok &= result.is_ok(); }
                    result = &mut reader_err, if !err_done => { err_done = true; io_ok &= result.is_ok(); }
                    ok = &mut writer, if !writer_done => { writer_done = true; io_ok &= ok; }
                }
            }
        }).await.is_ok();
        if !joined {
            mark_unknown(core, id);
        }
        #[cfg(test)]
        finalization_gate(core).await;
        // Returning drops unfinished readers before the terminal commit.
        RunOutcome {
            cleanup_complete: group_ok && joined && io_ok,
            tails: [*lock(&out_tail), *lock(&err_tail)],
        }
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    fn spec(dir: &std::path::Path, script: &str) -> JobSpec {
        JobSpec {
            kind: JobKind::Managed,
            argv: vec!["/bin/sh".into(), "-c".into(), script.into()],
            cwd: dir.into(),
            env: vec![],
            origin: JobOrigin {
                actor: None,
                turn: 17,
            },
            lifetime: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(60),
            stdin: false,
        }
    }
    async fn terminal(s: &JobsSupervisor, id: &str) -> JobSnapshot {
        terminal_for(s, None, id).await
    }
    async fn terminal_for(s: &JobsSupervisor, actor: Option<&str>, id: &str) -> JobSnapshot {
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let v = s.poll(actor, id, 0, 0, PAGE).await.unwrap();
                if v.status != JobStatus::Running {
                    return v;
                }
                tokio::time::sleep(TICK).await;
            }
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn reserved_start_uses_preallocated_id_and_rejects_foreign_or_cancelled_capability() {
        let d = tempfile::tempdir().unwrap();
        let s = JobsSupervisor::new("reserved-session", vec![]).unwrap();
        let foreign = JobsSupervisor::new("reserved-session", vec![]).unwrap();
        let reservation = s.reserve_start().unwrap();
        assert!(
            foreign
                .start_reserved(
                    reservation,
                    spec(d.path(), "touch forbidden"),
                    CancellationToken::new()
                )
                .await
                .is_err()
        );
        assert!(!d.path().join("forbidden").exists());
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert!(
            s.start_reserved(
                s.reserve_start().unwrap(),
                spec(d.path(), "touch forbidden"),
                cancel
            )
            .await
            .is_err()
        );
        assert!(!d.path().join("forbidden").exists());
        let reservation = s.reserve_start().unwrap();
        let id = reservation.id().to_owned();
        let started = s
            .start_reserved(
                reservation,
                spec(d.path(), "printf reserved"),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(started.id, id);
        let done = terminal(&s, &id).await;
        assert_eq!(done.stdout, "reserved");
        assert!(done.cleanup_complete);
        s.shutdown().await.unwrap();
        foreign.shutdown().await.unwrap();
        assert!(s.reserve_start().is_err());
    }

    #[tokio::test]
    async fn retained_remask_preserves_native_output_pages_and_allocations() {
        use crate::redaction::SecretDictionary;
        use crate::retained_redaction::RetainedDictionary;
        let dir = tempfile::tempdir().unwrap();
        let raw = format!("{}key/猫-tail!\n", "x".repeat(BLOCK - 4));
        std::fs::write(dir.path().join("fixture.txt"), &raw).unwrap();
        let supervisor = JobsSupervisor::new("retained-remask", vec![]).unwrap();
        let started = supervisor
            .start(
                spec(dir.path(), "cat fixture.txt"),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        let before = terminal(&supervisor, &started.id).await;
        assert_eq!(before.status, JobStatus::Exited);
        assert!(before.cleanup_complete);
        assert_eq!(before.stdout, raw);
        let credentials = SecretDictionary::new(&["key/猫-tail".into()]).unwrap();
        let dictionary = RetainedDictionary::new(&credentials).unwrap();
        let (length, allocated, blocks) = {
            let state = lock(&supervisor.core.state);
            (
                state.records[&started.id].out.len,
                state.allocated,
                state.records[&started.id].out.blocks.len(),
            )
        };
        let mut cursor = dictionary.cursor(length, &[]).unwrap();
        loop {
            let done = {
                let mut state = lock(&supervisor.core.state);
                cursor
                    .step(&mut state.records.get_mut(&started.id).unwrap().out, 17)
                    .unwrap()
            };
            if done {
                break;
            }
            tokio::task::yield_now().await;
        }
        let expected = format!(
            "{}{}!\n",
            "x".repeat(BLOCK - 4),
            "*".repeat("key/猫-tail".len())
        );
        let after = terminal(&supervisor, &started.id).await;
        assert_eq!(after.stdout, expected);
        assert_eq!(after.next_stdout_offset, before.next_stdout_offset);
        assert_eq!(after.ownership_epoch, before.ownership_epoch);
        for offset in raw.char_indices().map(|(i, _)| i).chain([raw.len()]) {
            let page = supervisor
                .poll(None, &started.id, offset, 0, 7)
                .await
                .unwrap();
            assert_eq!(page.stdout, expected[offset..page.next_stdout_offset]);
        }
        {
            let state = lock(&supervisor.core.state);
            assert_eq!(state.allocated, allocated);
            assert_eq!(state.records[&started.id].out.blocks.len(), blocks);
        }
        supervisor.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn refresh_retained_history_preserves_cursors_and_rejects_stale_publication() {
        let d = tempfile::tempdir().unwrap();
        let original = format!(
            "{} leftOLDTOKENright new/key猫 {}",
            "q".repeat(2000),
            "z".repeat(2000)
        );
        std::fs::write(d.path().join("fixture"), &original).unwrap();
        let s = JobsSupervisor::new("refresh-history", vec!["OLDTOKEN".into()]).unwrap();
        let start = s
            .start(spec(d.path(), "cat fixture"), CancellationToken::new())
            .await
            .unwrap();
        let before = terminal(&s, &start.id).await;
        assert!(before.stdout.contains("left[REDACTED]right"));
        let allocated = lock(&s.core.state).allocated;
        let epoch = s
            .refresh_credentials(&["leftOLDTOKENright".into(), "new/key猫".into()])
            .await
            .unwrap();
        assert_eq!(epoch, 1);
        assert_eq!(
            s.refresh_credentials(&["new/key猫".into()]).await.unwrap(),
            epoch
        );
        assert_eq!(s.refresh_credentials(&[]).await.unwrap(), epoch);
        let after = s.poll(None, &start.id, 0, 0, PAGE).await.unwrap();
        assert_eq!(after.stdout.len(), before.stdout.len());
        assert_eq!(after.next_stdout_offset, before.next_stdout_offset);
        assert_eq!(after.ownership_epoch, before.ownership_epoch);
        assert_eq!(lock(&s.core.state).allocated, allocated);
        assert!(after.stdout.starts_with(&"q".repeat(1000)));
        assert!(after.stdout.contains(&"z".repeat(1000)));
        for forbidden in ["left", "right", "new/key猫"] {
            assert!(!after.stdout.contains(forbidden));
        }
        for offset in before
            .stdout
            .char_indices()
            .map(|(offset, _)| offset)
            .chain([before.stdout.len()])
        {
            s.poll(None, &start.id, offset, 0, 9).await.unwrap();
        }
        let published = std::sync::atomic::AtomicBool::new(false);
        assert!(
            s.publish_snapshot(&before, |_| {
                published.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            })
            .await
            .is_err()
        );
        assert!(!published.load(std::sync::atomic::Ordering::SeqCst));
        s.publish_snapshot(&after, |_| {
            published.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        })
        .await
        .unwrap();
        assert!(published.load(std::sync::atomic::Ordering::SeqCst));
        s.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn refresh_keeps_safe_interactive_stdin_and_blocks_new_secret_continuation() {
        let d = tempfile::tempdir().unwrap();
        let s = JobsSupervisor::new("refresh-stdin", vec![]).unwrap();
        let mut job = spec(
            d.path(),
            "while IFS= read -r line; do printf '%s\\n' \"$line\"; done",
        );
        job.stdin = true;
        let start = s.start(job, CancellationToken::new()).await.unwrap();
        let first = s
            .send_input(None, &start.id, b"new-", false)
            .await
            .unwrap()
            .wait()
            .await
            .unwrap();
        assert_eq!(first.status, InputStatus::Delivered);
        assert_eq!(first.written, 4);
        s.refresh_credentials(&["new-secret".into()]).await.unwrap();
        assert!(
            s.send_input(None, &start.id, b"secret\n", true)
                .await
                .is_err()
        );
        let safe = format!("safe{}\n", "x".repeat(100));
        assert_eq!(
            s.send_input(None, &start.id, safe.as_bytes(), false)
                .await
                .unwrap()
                .wait()
                .await
                .unwrap()
                .status,
            InputStatus::Delivered
        );
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if s.poll(None, &start.id, 0, 0, PAGE)
                    .await
                    .unwrap()
                    .next_stdout_offset
                    > 50
                {
                    break;
                }
                tokio::time::sleep(TICK).await;
            }
        })
        .await
        .unwrap();
        let last = s
            .send_input(None, &start.id, b"AFTER\n", true)
            .await
            .unwrap()
            .wait()
            .await
            .unwrap();
        assert_eq!(last.status, InputStatus::Delivered);
        let done = terminal(&s, &start.id).await;
        assert!(done.cleanup_complete);
        assert_eq!(done.exit_code, Some(0));
        assert!(done.stdout.ends_with("AFTER\n"), "{}", done.stdout);
        assert!(!done.stdout.contains("new-secret"));
        s.shutdown().await.unwrap();
    }

    struct LimitedWriter {
        bytes: Arc<Mutex<Vec<u8>>>,
        limit: usize,
        closed: Arc<std::sync::atomic::AtomicBool>,
    }
    impl AsyncWrite for LimitedWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            input: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let mut bytes = lock(&self.bytes);
            if bytes.len() == self.limit {
                return Poll::Pending;
            }
            let n = input.len().min(self.limit - bytes.len());
            bytes.extend_from_slice(&input[..n]);
            Poll::Ready(Ok(n))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
            Poll::Ready(Ok(()))
        }
    }
    #[tokio::test]
    async fn refresh_rechecks_inflight_partial_packet_without_closing_stdin() {
        let d = tempfile::tempdir().unwrap();
        let s = Arc::new(JobsSupervisor::new("refresh-packet", vec![]).unwrap());
        let mut job = spec(d.path(), "sleep 20");
        job.stdin = true;
        let start = s.start(job, CancellationToken::new()).await.unwrap();
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut writer = LimitedWriter {
            bytes: Arc::clone(&bytes),
            limit: 4,
            closed: Arc::clone(&closed),
        };
        let (completion, receipt) = oneshot::channel();
        let mut packet = Input {
            bytes: b"new-secret".to_vec(),
            written: 0,
            checked_epoch: None,
            close: true,
            completion: Some(completion),
            _permit: None,
        };
        let core = Arc::clone(&s.core);
        let id = start.id.clone();
        let writing = tokio::spawn(async move {
            deliver_input(&mut writer, &mut packet, &core, &id)
                .await
                .unwrap();
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while lock(&bytes).len() != 4 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        s.refresh_credentials(&["new-secret".into()]).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), writing)
            .await
            .unwrap()
            .unwrap();
        let receipt = receipt.await.unwrap();
        assert_eq!(
            (receipt.status, receipt.written),
            (InputStatus::Rejected, 4)
        );
        assert_eq!(&*lock(&bytes), b"new-");
        assert!(!closed.load(std::sync::atomic::Ordering::SeqCst));
        assert!(lock(&s.core.state).records[&start.id].input.is_some());
        assert!(s.stop(None, &start.id).await.unwrap().cleanup_complete);
        s.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn stop_and_cancel_remain_live_during_refresh_and_abandonment_fails_closed() {
        for abandon in [false, true] {
            let d = tempfile::tempdir().unwrap();
            let s = Arc::new(JobsSupervisor::new("refresh-stop", vec![]).unwrap());
            let start = s
                .start(
                    spec(d.path(), "printf ready; sleep 20"),
                    CancellationToken::new(),
                )
                .await
                .unwrap();
            let ready = Arc::new(Notify::new());
            let release = Arc::new(Notify::new());
            *lock(&s.core.refresh_gate) = Some((Arc::clone(&ready), Arc::clone(&release)));
            let copy = Arc::clone(&s);
            let refreshing =
                tokio::spawn(async move { copy.refresh_credentials(&["new-key".into()]).await });
            tokio::time::timeout(Duration::from_secs(3), ready.notified())
                .await
                .unwrap();
            assert!(s.poll(None, &start.id, 0, 0, PAGE).await.is_err());
            if abandon {
                refreshing.abort();
            }
            let stopped = tokio::time::timeout(Duration::from_secs(3), s.stop(None, &start.id))
                .await
                .unwrap()
                .unwrap();
            assert!(stopped.cleanup_complete);
            assert!(stopped.stdout.is_empty());
            assert!(!lock(&s.core.state).sticky_unknown);
            if abandon {
                assert!(refreshing.await.unwrap_err().is_cancelled());
                assert!(s.poll(None, &start.id, 0, 0, PAGE).await.is_err());
                assert!(
                    s.start(spec(d.path(), "true"), CancellationToken::new())
                        .await
                        .is_err()
                );
            } else {
                release.notify_one();
                assert_eq!(refreshing.await.unwrap().unwrap(), 1);
            }
            s.shutdown().await.unwrap();
        }
    }

    #[test]
    fn old_written_match_does_not_poison_safe_future_input() {
        let patterns = vec![b"new-secret".to_vec()];
        assert!(!new_input_contains_secret(b"new-secretSAFE", 10, &patterns));
        assert!(new_input_contains_secret(b"new-secret", 4, &patterns));
        assert!(!new_input_contains_secret(b"new-secret", 10, &patterns));
        assert!(new_input_contains_secret(b"safe new-secret", 5, &patterns));
    }

    #[tokio::test]
    async fn refresh_protects_real_output_crossing_cutover_and_then_releases_normal_text() {
        let d = tempfile::tempdir().unwrap();
        let s = JobsSupervisor::new("refresh-output", vec![]).unwrap();
        let script = "printf new-; while [ ! -f continue ]; do sleep 0.01; done; printf secret; i=0; while [ $i -lt 100 ]; do printf .; i=$((i+1)); done; while [ ! -f finish ]; do sleep 0.01; done; printf VISIBLE";
        let start = s
            .start(spec(d.path(), script), CancellationToken::new())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if s.poll(None, &start.id, 0, 0, PAGE).await.unwrap().stdout == "new-" {
                    break;
                }
                tokio::time::sleep(TICK).await;
            }
        })
        .await
        .unwrap();
        s.refresh_credentials(&["new-secret".into()]).await.unwrap();
        std::fs::write(d.path().join("continue"), b"go").unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if s.poll(None, &start.id, 0, 0, PAGE)
                    .await
                    .unwrap()
                    .next_stdout_offset
                    >= 110
                {
                    break;
                }
                tokio::time::sleep(TICK).await;
            }
        })
        .await
        .unwrap();
        std::fs::write(d.path().join("finish"), b"go").unwrap();
        let done = terminal(&s, &start.id).await;
        assert!(done.cleanup_complete);
        assert_eq!(done.exit_code, Some(0));
        assert!(done.stdout.starts_with("****"));
        assert!(!done.stdout.contains("secret"));
        assert!(done.stdout.ends_with("VISIBLE"));
        s.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refresh_commit_waits_for_existing_publication_without_blocking_cleanup() {
        let d = tempfile::tempdir().unwrap();
        let s = Arc::new(JobsSupervisor::new("refresh-publication", vec![]).unwrap());
        let start = s
            .start(spec(d.path(), "printf gate-key"), CancellationToken::new())
            .await
            .unwrap();
        let before = terminal(&s, &start.id).await;
        let entered = Arc::new(Notify::new());
        let (release, wait) = std::sync::mpsc::channel();
        let copy = Arc::clone(&s);
        let signal = Arc::clone(&entered);
        let publishing = tokio::spawn(async move {
            copy.publish_snapshot(&before, move |_| {
                signal.notify_one();
                wait.recv_timeout(Duration::from_secs(3)).unwrap();
                Ok(())
            })
            .await
            .unwrap();
        });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .unwrap();
        let copy = Arc::clone(&s);
        let refreshing =
            tokio::spawn(async move { copy.refresh_credentials(&["gate-key".into()]).await });
        // A queued writer excludes fresh read permits: prove refresh has reached
        // the publication barrier, rather than assuming scheduling from a sleep.
        tokio::time::timeout(Duration::from_secs(2), async {
            while s.core.publication.try_read().is_ok() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!refreshing.is_finished());
        assert!(!lock(&s.core.state).refreshing);
        assert!(s.stop(None, &start.id).await.unwrap().cleanup_complete);
        release.send(()).unwrap();
        publishing.await.unwrap();
        assert_eq!(refreshing.await.unwrap().unwrap(), 1);
        s.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn rejected_credential_union_blocks_io_but_preserves_cleanup_proof() {
        let d = tempfile::tempdir().unwrap();
        let s = JobsSupervisor::new("refresh-invalid", vec![]).unwrap();
        let mut job = spec(d.path(), "sleep 20");
        job.stdin = true;
        let start = s.start(job, CancellationToken::new()).await.unwrap();
        let error = s
            .refresh_credentials(&["private-oversized-marker".repeat(INPUT)])
            .await
            .unwrap_err();
        assert!(!error.to_string().contains("private-oversized-marker"));
        assert!(s.poll(None, &start.id, 0, 0, PAGE).await.is_err());
        assert!(s.send_input(None, &start.id, b"safe", false).await.is_err());
        assert!(s.publish_snapshot(&start, |_| Ok(())).await.is_err());
        let done = s.stop(None, &start.id).await.unwrap();
        assert!(done.cleanup_complete);
        assert_eq!(done.status, JobStatus::Failed);
        assert!(!lock(&s.core.state).sticky_unknown);
        s.shutdown().await.unwrap();
    }

    #[test]
    fn host_session_identity_cannot_serialize_a_known_secret() {
        for value in ["abcdef", "%61%62%63%64%65%66"] {
            assert!(JobsSupervisor::new(value, vec!["abcdef".into()]).is_err());
        }
    }
    #[tokio::test]
    async fn native_environment_contains_host_marker_and_canonical_pwd() {
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let alias = d.path().join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        for kind in [JobKind::Managed, JobKind::Foreground] {
            let s = JobsSupervisor::new("environment-session", vec![]).unwrap();
            let mut job = spec(&alias, "unused");
            job.kind = kind;
            job.argv = vec!["/usr/bin/env".into()];
            let started = s.start(job, CancellationToken::new()).await.unwrap();
            let result = terminal(&s, &started.id).await;
            assert_eq!(result.status, JobStatus::Exited);
            let values: std::collections::HashMap<_, _> = result
                .stdout
                .lines()
                .map(|line| line.split_once('=').unwrap())
                .collect();
            assert_eq!(values.get("RCODE_MODEL_SHELL"), Some(&"1"));
            assert_eq!(
                values.get("PWD"),
                Some(&real.canonicalize().unwrap().to_str().unwrap())
            );
            assert_eq!(values.len(), 2, "Ambient environment must not be inherited");
            s.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn native_host_environment_cannot_be_spoofed_or_contain_known_key_in_pwd() {
        let d = tempfile::tempdir().unwrap();
        let s = JobsSupervisor::new("environment-session", vec!["private-cwd-key".into()]).unwrap();
        for key in ["RCODE_MODEL_SHELL", "PWD"] {
            let mut job = spec(d.path(), "touch forbidden");
            job.env.push((key.into(), "override".into()));
            assert!(s.start(job, CancellationToken::new()).await.is_err());
        }
        let secret = d.path().join("private-cwd-key");
        std::fs::create_dir(&secret).unwrap();
        assert!(
            s.start(spec(&secret, "touch forbidden"), CancellationToken::new())
                .await
                .is_err()
        );
        assert!(!secret.join("forbidden").exists());
        assert!(!d.path().join("forbidden").exists());
        s.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn host_actor_identity_is_rejected_before_spawn() {
        let d = tempfile::tempdir().unwrap();
        let s = JobsSupervisor::new("identity-session", vec!["abcdef".into()]).unwrap();
        for value in ["abcdef", "%61%62%63%64%65%66"] {
            let mut job = spec(d.path(), "touch forbidden");
            job.origin.actor = Some(value.into());
            assert!(s.start(job, CancellationToken::new()).await.is_err());
            assert!(lock(&s.core.state).records.is_empty());
            assert!(!d.path().join("forbidden").exists());
        }
    }
    #[tokio::test]
    async fn handoff_identity_cannot_leak_or_change_owner_on_rejection() {
        for (operation, parent) in [("abcdef", "parent"), ("operation", "%61%62%63%64%65%66")] {
            let d = tempfile::tempdir().unwrap();
            let s = JobsSupervisor::new("identity-session", vec!["abcdef".into()]).unwrap();
            let mut job = spec(d.path(), "sleep 20");
            job.origin.actor = Some("worker".into());
            let started = s.start(job, CancellationToken::new()).await.unwrap();
            assert!(
                s.handoff_to_parent(
                    "worker",
                    &started.id,
                    operation,
                    0,
                    parent,
                    CancellationToken::new()
                )
                .is_err()
            );
            let view = s
                .poll(Some("worker"), &started.id, 0, 0, PAGE)
                .await
                .unwrap();
            assert_eq!(view.owner.as_deref(), Some("worker"));
            assert_eq!(view.ownership_epoch, 0);
            let encoded = serde_json::to_string(&view).unwrap();
            assert!(!encoded.contains("abcdef") && !encoded.contains("%61%62%63%64%65%66"));
            s.stop(Some("worker"), &started.id).await.unwrap();
            s.shutdown().await.unwrap();
        }
    }
    #[test]
    fn oversized_env_is_rejected_before_content_inspection() {
        let d = tempfile::tempdir().unwrap();
        let mut job = spec(d.path(), "true");
        job.env = vec![("PATH".into(), format!("\0{}", "x".repeat(65536)))];
        let error = validate(&mut job, &[]).unwrap_err();
        assert_eq!(error.to_string(), "environment too large");
    }
    #[tokio::test]
    async fn already_cancelled_start_does_not_validate_or_touch_paths() {
        let d = tempfile::tempdir().unwrap();
        let s = JobsSupervisor::new("cancelled-session", vec![]).unwrap();
        let mut job = spec(d.path(), "touch forbidden");
        job.cwd = d.path().join("does-not-exist");
        let cancel = CancellationToken::new();
        cancel.cancel();
        let error = s.start(job, cancel).await.unwrap_err();
        assert_eq!(error.to_string(), "scope cancelled");
        assert!(lock(&s.core.state).records.is_empty());
    }
    #[test]
    fn managed_timeout_bounds_are_minutes() {
        let d = tempfile::tempdir().unwrap();
        for (seconds, accepted) in [(59, false), (60, true), (7200, true), (7201, false)] {
            let mut job = spec(d.path(), "true");
            job.lifetime = Duration::from_secs(seconds);
            job.idle_timeout = Duration::from_secs(seconds);
            assert_eq!(validate(&mut job, &[]).is_ok(), accepted, "{seconds}");
        }
    }
    #[test]
    fn foreground_timeout_bounds_preserve_run_command_seconds() {
        let d = tempfile::tempdir().unwrap();
        for (seconds, accepted) in [(0, false), (1, true), (300, true), (301, false)] {
            let mut job = spec(d.path(), "true");
            job.kind = JobKind::Foreground;
            job.lifetime = Duration::from_secs(seconds);
            job.idle_timeout = Duration::from_secs(seconds);
            assert_eq!(validate(&mut job, &[]).is_ok(), accepted, "{seconds}");
        }
    }
    #[tokio::test]
    async fn foreground_combines_raw_and_retained_output_limits() {
        let d = tempfile::tempdir().unwrap();
        // Both individual streams fit below 64 KiB; together they must stop.
        for (name, bytes) in [("dual", vec![b'x'; 40_000]), ("lossy", vec![0xff; 30_000])] {
            std::fs::write(d.path().join("output"), &bytes).unwrap();
            let s = JobsSupervisor::new(name, vec![]).unwrap();
            let mut job = spec(
                d.path(),
                if name == "dual" {
                    "cat output; cat output >&2"
                } else {
                    "cat output"
                },
            );
            job.kind = JobKind::Foreground;
            let started = s.start(job, CancellationToken::new()).await.unwrap();
            let done = terminal(&s, &started.id).await;
            assert!(done.cleanup_complete, "{done:?}");
            assert!(done.output_truncated, "foreground limit was not applied");
            assert!(done.stdout.len() + done.stderr.len() <= PAGE);
            assert!(done.next_stdout_offset + done.next_stderr_offset <= PAGE);
            if name == "lossy" {
                assert!(done.utf8_lossy);
            }
            s.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn foreground_raw_limit_applies_even_when_redaction_shrinks_output() {
        let d = tempfile::tempdir().unwrap();
        let s = JobsSupervisor::new("raw-foreground", vec!["a".repeat(128)]).unwrap();
        std::fs::write(d.path().join("output"), vec![b'a'; PAGE + 1]).unwrap();
        let mut job = spec(d.path(), "cat output");
        job.kind = JobKind::Foreground;
        let started = s.start(job, CancellationToken::new()).await.unwrap();
        let done = terminal(&s, &started.id).await;
        assert!(done.cleanup_complete, "{done:?}");
        assert!(
            done.output_truncated,
            "raw cap bypassed by redaction contraction"
        );
        assert!(done.stdout.len() + done.stderr.len() <= PAGE);
        assert!(!done.stdout.contains(&"a".repeat(128)));
        s.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn foreground_eof_expansion_is_bounded_and_exact_limit_is_accepted() {
        let d = tempfile::tempdir().unwrap();
        for (tail, truncated) in [("secret", true), ("xxxxxx", false)] {
            let s = JobsSupervisor::new(
                "foreground-eof-cap",
                vec!["secret".into(), "secret-ending-long".into()],
            )
            .unwrap();
            std::fs::write(
                d.path().join("output"),
                format!("{}{tail}", "x".repeat(PAGE - tail.len())),
            )
            .unwrap();
            let mut job = spec(d.path(), "cat output");
            job.kind = JobKind::Foreground;
            let started = s.start(job, CancellationToken::new()).await.unwrap();
            let done = terminal(&s, &started.id).await;
            assert!(done.cleanup_complete);
            assert_eq!(done.output_truncated, truncated);
            assert!(done.stdout.len() + done.stderr.len() <= PAGE);
            if !truncated {
                assert_eq!(done.stdout.len(), PAGE);
            }
            assert!(!done.stdout.contains("secret"));
            s.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn foreground_limits_do_not_reduce_managed_output() {
        let d = tempfile::tempdir().unwrap();
        let s = JobsSupervisor::new("managed-output-bound", vec![]).unwrap();
        std::fs::write(d.path().join("output"), vec![b'x'; PAGE + 4096]).unwrap();
        let started = s
            .start(spec(d.path(), "cat output"), CancellationToken::new())
            .await
            .unwrap();
        let done = terminal(&s, &started.id).await;
        assert!(done.cleanup_complete && !done.output_truncated);
        assert_eq!(done.next_stdout_offset, PAGE);
        let rest = s.poll(None, &started.id, PAGE, 0, PAGE).await.unwrap();
        assert_eq!(rest.stdout.len(), 4096);
        s.shutdown().await.unwrap();
    }

    #[test]
    fn foreground_shell_keeps_full_16k_command_budget() {
        let d = tempfile::tempdir().unwrap();
        let mut job = spec(d.path(), &format!(": #{}", "x".repeat(INPUT - 3)));
        job.kind = JobKind::Foreground;
        assert_eq!(job.argv[2].len(), INPUT);
        assert!(validate(&mut job, &[]).is_ok());
        job.argv[2].push('x');
        assert!(validate(&mut job, &[]).is_err());
    }

    #[tokio::test]
    async fn foreground_timeout_is_real_and_cannot_handoff() {
        let d = tempfile::tempdir().unwrap();
        let s = JobsSupervisor::new("foreground-timeout", vec![]).unwrap();
        let mut job = spec(d.path(), "trap '' TERM; sleep 20");
        job.kind = JobKind::Foreground;
        job.origin.actor = Some("worker".into());
        job.lifetime = Duration::from_secs(1);
        job.idle_timeout = Duration::from_secs(1);
        let started = s.start(job, CancellationToken::new()).await.unwrap();
        assert!(
            s.handoff_to_parent(
                "worker",
                &started.id,
                "handoff",
                0,
                "parent",
                CancellationToken::new()
            )
            .is_err()
        );
        let done = terminal_for(&s, Some("worker"), &started.id).await;
        assert_eq!(done.status, JobStatus::TimedOut);
        assert_eq!(done.signal, Some(libc::SIGKILL));
        assert!(done.cleanup_complete, "{done:?}");
        s.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn cancellation_never_flushes_a_partial_known_secret() {
        let d = tempfile::tempdir().unwrap();
        let s = JobsSupervisor::new("cancelled-output", vec!["abcdef".into()]).unwrap();
        let started = s
            .start(
                spec(d.path(), "printf abc; printf ready > ready; sleep 20"),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while !d.path().join("ready").exists() {
                tokio::time::sleep(TICK).await;
            }
        })
        .await
        .unwrap();
        let done = s.stop(None, &started.id).await.unwrap();
        assert!(done.cleanup_complete, "{done:?}");
        assert!(!done.stdout.contains("abc"), "cancelled raw prefix escaped");
        assert!(done.redaction_incomplete);
        s.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn closed_output_waits_for_the_real_error_status_before_flushing_tail() {
        let d = tempfile::tempdir().unwrap();
        let s = JobsSupervisor::new("failed-output", vec!["abcdef".into()]).unwrap();
        let started = s
            .start(
                spec(
                    d.path(),
                    "printf abc; exec 1>&-; printf ready > ready; sleep 0.1; exit 7",
                ),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while !d.path().join("ready").exists() {
                tokio::time::sleep(TICK).await;
            }
        })
        .await
        .unwrap();
        let during = s.poll(None, &started.id, 0, 0, PAGE).await.unwrap();
        assert!(
            !during.stdout.contains("abc"),
            "closed stream tail was released before process outcome"
        );
        let done = terminal(&s, &started.id).await;
        assert_eq!(done.exit_code, Some(7));
        assert!(done.cleanup_complete);
        assert!(!done.stdout.contains("abc"));
        assert!(done.redaction_incomplete);
        s.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn eof_quota_failure_discards_both_private_tails() {
        let d = tempfile::tempdir().unwrap();
        let s = JobsSupervisor::new("eof-quota", vec!["abcdef".into()]).unwrap();
        // Retain actual output from completed processes, leaving exactly two blocks.
        for count in [STREAM, STREAM - 2 * BLOCK] {
            let script = format!("head -c {count} /dev/zero | tr '\\000' x");
            let v = s
                .start(spec(d.path(), &script), CancellationToken::new())
                .await
                .unwrap();
            let done = terminal(&s, &v.id).await;
            assert_eq!(done.exit_code, Some(0));
            assert!(!done.output_truncated);
        }
        let v = s.start(spec(d.path(), "head -c 4096 /dev/zero | tr '\\000' x; printf abc; head -c 64 /dev/zero | tr '\\000' y >&2; printf abc >&2"), CancellationToken::new()).await.unwrap();
        let done = terminal(&s, &v.id).await;
        assert_eq!(done.status, JobStatus::Cancelled);
        assert!(done.cleanup_complete && done.output_truncated);
        assert!(
            !done.stdout.contains("abc") && !done.stderr.contains("abc"),
            "private EOF tails escaped after quota failure: {done:?}"
        );
        assert!(done.redaction_incomplete);
        s.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stop_before_eof_commit_discards_both_private_tails() {
        let d = tempfile::tempdir().unwrap();
        let s = JobsSupervisor::new("eof-stop", vec!["abcdef".into()]).unwrap();
        let ready = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        *lock(&s.core.finalization_gate) = Some((ready.clone(), release.clone()));
        let v = s
            .start(
                spec(d.path(), "printf abc; printf abc >&2"),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), ready.notified())
            .await
            .unwrap();
        let stopping = s.stop(None, &v.id);
        tokio::pin!(stopping);
        tokio::select! {
            _ = &mut stopping => panic!("stop cannot finish before finalization"),
            _ = tokio::time::sleep(TICK) => (),
        }
        assert!(lock(&s.core.state).records[&v.id].stop);
        release.notify_one();
        let done = stopping.await.unwrap();
        assert_eq!(done.status, JobStatus::Stopped);
        assert!(done.cleanup_complete);
        assert!(
            done.stdout.is_empty() && done.stderr.is_empty(),
            "stopped EOF tail escaped: {done:?}"
        );
        assert!(done.redaction_incomplete);
        s.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn successful_eof_still_preserves_an_incomplete_nonsecret_suffix() {
        let d = tempfile::tempdir().unwrap();
        let s = JobsSupervisor::new("successful-output", vec!["abcdef".into()]).unwrap();
        let started = s
            .start(spec(d.path(), "printf abc"), CancellationToken::new())
            .await
            .unwrap();
        let done = terminal(&s, &started.id).await;
        assert_eq!(done.stdout, "abc");
        assert_eq!(done.exit_code, Some(0));
        assert!(done.cleanup_complete && !done.redaction_incomplete);
        s.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn concurrent_saturation_is_fully_pageable_without_restart() {
        let d = tempfile::tempdir().unwrap();
        let s = JobsSupervisor::new("saturation", vec![]).unwrap();
        let command = "awk 'BEGIN { for (i=0;i<1048576;i++) printf \"x\" }' & awk 'BEGIN { for (i=0;i<1048576;i++) printf \"y\" }' >&2 & wait";
        let v = s
            .start(spec(d.path(), command), CancellationToken::new())
            .await
            .unwrap();
        let done = terminal(&s, &v.id).await;
        assert_eq!(done.exit_code, Some(0));
        assert!(done.cleanup_complete && !done.output_truncated);
        let (mut out, mut err) = (0, 0);
        loop {
            let page = s.poll(None, &v.id, out, err, PAGE).await.unwrap();
            assert!(page.stdout.bytes().all(|b| b == b'x'));
            assert!(page.stderr.bytes().all(|b| b == b'y'));
            assert_eq!(page.next_stdout_offset, out + page.stdout.len());
            assert_eq!(page.next_stderr_offset, err + page.stderr.len());
            if page.next_stdout_offset == out && page.next_stderr_offset == err {
                break;
            }
            out = page.next_stdout_offset;
            err = page.next_stderr_offset;
        }
        assert_eq!((out, err), (1048576, 1048576));
        {
            let state = lock(&s.core.state);
            assert!(state.allocated <= GLOBAL);
            assert!(state.records.len() <= 132);
            assert_eq!(state.running, 0);
        }
        s.shutdown().await.unwrap();
    }
    #[test]
    fn aggregate_capacity_and_unicode_pages() {
        let mut allocated = 0;
        let text = "x".repeat(BLOCK);
        let mut payloads: Vec<Payload> = (0..8).map(|_| Payload::default()).collect();
        for p in &mut payloads {
            for _ in 0..GLOBAL / 8 / BLOCK {
                assert_eq!(p.append(text.as_bytes(), &mut allocated), BLOCK);
            }
        }
        assert_eq!(allocated, GLOBAL);
        assert_eq!(Payload::default().append(b"extra", &mut allocated), 0);
        allocated -= payloads[0].release();
        let mut p = Payload::default();
        assert_eq!(p.append("😀éz".as_bytes(), &mut allocated), 7);
        let (a, next) = p.page(0, 4).unwrap();
        assert_eq!((a.as_str(), next), ("😀", 4));
        assert_eq!(p.page(next, 4).unwrap().0, "éz");
        assert!(p.page(1, 4).is_err());
        assert!(allocated <= GLOBAL);
        assert_eq!(
            serde_json::to_string(&JobStatus::TimedOut).unwrap(),
            "\"timed_out\""
        );
    }
    #[tokio::test]
    async fn exact_handoff_retry_and_scope_move() {
        let d = tempfile::tempdir().unwrap();
        let s = JobsSupervisor::new("s", vec![]).unwrap();
        let worker = CancellationToken::new();
        let parent = CancellationToken::new();
        let mut job = spec(d.path(), "sleep 20");
        job.origin.actor = Some("w".into());
        let v = s.start(job, worker.clone()).await.unwrap();
        let a = s
            .handoff_to_parent("w", &v.id, "op", 0, "parent", parent.clone())
            .unwrap();
        worker.cancel();
        let b = s
            .handoff_to_parent("w", &v.id, "op", 0, "parent", parent.clone())
            .unwrap();
        assert_eq!(a, b);
        assert!(
            s.handoff_to_parent("w", &v.id, "op", 0, "different", parent.clone())
                .is_err()
        );
        assert!(
            s.handoff_to_parent("w", &v.id, "new", 1, "parent", parent.clone())
                .is_err()
        );
        tokio::time::sleep(TICK * 3).await;
        let moved = s.poll(None, &v.id, 0, 0, 4).await.unwrap();
        assert_eq!(moved.status, JobStatus::Running);
        assert_eq!(moved.ownership_epoch, 1);
        assert_eq!(moved.origin.actor.as_deref(), Some("w"));
        parent.cancel();
        assert_eq!(terminal(&s, &v.id).await.status, JobStatus::Cancelled);
        // Exact replay remains valid after both scopes are cancelled and the
        // job is terminal; it neither rechecks former-owner ACL nor moves scope.
        assert_eq!(
            s.handoff_to_parent("w", &v.id, "op", 0, "parent", parent.clone())
                .unwrap(),
            a
        );
        assert!(
            s.handoff_to_parent("other", &v.id, "op", 0, "parent", parent.clone())
                .is_err()
        );
        let final_view = s.poll(None, &v.id, 0, 0, 4).await.unwrap();
        assert_eq!(final_view.epoch_boundaries.len(), 2);
        assert_eq!(final_view.ownership_epoch, 1);
        s.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn acknowledgement_refuses_unconfirmed_cleanup_without_releasing_bytes() {
        let d = tempfile::tempdir().unwrap();
        let s = JobsSupervisor::new("cleanup-ack", vec![]).unwrap();
        let v = s
            .start(spec(d.path(), "printf retained"), CancellationToken::new())
            .await
            .unwrap();
        let done = terminal(&s, &v.id).await;
        assert!(done.cleanup_complete);
        let allocated = {
            let mut state = lock(&s.core.state);
            state.records.get_mut(&v.id).unwrap().view.cleanup_complete = false;
            state.allocated
        };
        assert!(s.acknowledge_payload(None, &v.id).is_err());
        assert_eq!(lock(&s.core.state).allocated, allocated);
        assert_eq!(
            s.poll(None, &v.id, 0, 0, PAGE).await.unwrap().stdout,
            "retained"
        );
        lock(&s.core.state)
            .records
            .get_mut(&v.id)
            .unwrap()
            .view
            .cleanup_complete = true;
        s.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn redaction_rejection_ack_and_pages() {
        let d = tempfile::tempdir().unwrap();
        let s = JobsSupervisor::new("s", vec!["abcdef".into()]).unwrap();
        assert!(
            s.start(spec(d.path(), "printf abcdef"), CancellationToken::new())
                .await
                .is_err()
        );
        let v = s
            .start(
                spec(
                    d.path(),
                    "printf abc; sleep 0.05; printf def; printf '😀éz' >&2",
                ),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        let done = terminal(&s, &v.id).await;
        assert!(done.cleanup_complete, "{done:?}");
        assert_eq!(done.stdout, "[REDACTED]");
        assert_eq!(done.stderr, "😀éz");
        assert!(s.poll(None, &v.id, 0, 0, 3).await.is_err());
        assert_eq!(s.poll(None, &v.id, 0, 0, 4).await.unwrap().stderr, "😀");
        let receipt = s.acknowledge_payload(None, &v.id).unwrap();
        assert!(receipt.payload_unavailable && receipt.output_truncated);
        assert_eq!(receipt.next_stderr_offset, 7);
        assert_eq!(lock(&s.core.state).allocated, 0);
        assert!(
            s.acknowledge_payload(None, &v.id)
                .unwrap()
                .payload_unavailable
        );
        s.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn graceful_stop_delivers_term_before_kill() {
        let d = tempfile::tempdir().unwrap();
        let s = JobsSupervisor::new("term-grace", vec![]).unwrap();
        let v = s.start(spec(d.path(), "trap 'printf term > term-seen; exit 0' TERM; printf ready > ready; while :; do sleep 0.02; done"), CancellationToken::new()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while !d.path().join("ready").exists() {
                tokio::time::sleep(TICK).await;
            }
        })
        .await
        .unwrap();
        let done = s.stop(None, &v.id).await.unwrap();
        assert!(done.cleanup_complete, "{done:?}");
        assert_eq!(
            std::fs::read_to_string(d.path().join("term-seen")).unwrap(),
            "term"
        );
        assert_eq!(done.exit_code, Some(0));
        assert_eq!(done.signal, None);
        s.shutdown().await.unwrap();
    }
    struct Broken;
    impl AsyncRead for Broken {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Err(std::io::Error::other("injected")))
        }
    }
    #[tokio::test]
    async fn read_failure_requests_immediate_cleanup() {
        let d = tempfile::tempdir().unwrap();
        let s = JobsSupervisor::new("s", vec![]).unwrap();
        let v = s
            .start(spec(d.path(), "sleep 20"), CancellationToken::new())
            .await
            .unwrap();
        assert!(drain(Broken, &s.core, &v.id, false).await.is_err());
        assert!(lock(&s.core.state).records[&v.id].stop);
        let done = terminal(&s, &v.id).await;
        assert_eq!(done.status, JobStatus::Failed);
        assert!(done.cleanup_complete);
        s.shutdown().await.unwrap();
    }
    // Re-executed fixtures produce no terminal output of their own. The test
    // harness output is captured by the managed pipes, not written by this module.
    #[test]
    #[ignore]
    fn port_helper() {
        if std::path::Path::new("escape").exists() {
            assert!(unsafe { libc::setsid() } >= 0);
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        std::fs::write("pid", std::process::id().to_string()).unwrap();
        std::fs::write("port", listener.local_addr().unwrap().port().to_string()).unwrap();
        loop {
            std::thread::sleep(Duration::from_secs(1));
            std::hint::black_box(&listener);
        }
    }
    fn helper_spec(dir: &std::path::Path, escape: bool) -> JobSpec {
        let script = if escape {
            "\"$1\" --ignored --exact jobs::tests::port_helper --nocapture & while [ ! -f port ]; do sleep 0.02; done; exit 0"
        } else {
            "trap '' TERM; \"$1\" --ignored --exact jobs::tests::port_helper --nocapture & wait"
        };
        let mut job = spec(dir, script);
        job.argv.push("fixture".into());
        job.argv
            .push(std::env::current_exe().unwrap().to_str().unwrap().into());
        job
    }
    async fn port(dir: &std::path::Path) -> std::net::SocketAddr {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(text) = std::fs::read_to_string(dir.join("port"))
                    && let Ok(port) = text.parse()
                {
                    break std::net::SocketAddr::from(([127, 0, 0, 1], port));
                }
                tokio::time::sleep(TICK).await;
            }
        })
        .await
        .unwrap()
    }
    #[tokio::test]
    async fn group_port_is_closed_at_publication() {
        let d = tempfile::tempdir().unwrap();
        let s = JobsSupervisor::new("s", vec![]).unwrap();
        let v = s
            .start(helper_spec(d.path(), false), CancellationToken::new())
            .await
            .unwrap();
        let address = port(d.path()).await;
        assert!(std::net::TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok());
        let done = s.stop(None, &v.id).await.unwrap();
        assert!(done.cleanup_complete);
        assert_eq!(done.signal, Some(libc::SIGKILL));
        // No retry loop or delayed fixture cleanup between publication and check.
        assert!(
            std::net::TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_err()
        );
        s.shutdown().await.unwrap();
    }
    struct EscapeGuard(i32);
    impl Drop for EscapeGuard {
        fn drop(&mut self) {
            unsafe {
                libc::kill(self.0, libc::SIGKILL);
            }
        }
    }
    #[tokio::test]
    async fn escaped_pipe_unknown_is_sticky_and_occupies_slot() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("escape"), b"yes").unwrap();
        let s = JobsSupervisor::new("s", vec![]).unwrap();
        let v = s
            .start(helper_spec(d.path(), true), CancellationToken::new())
            .await
            .unwrap();
        let _address = port(d.path()).await;
        let pid = std::fs::read_to_string(d.path().join("pid"))
            .unwrap()
            .parse()
            .unwrap();
        let _fixture = EscapeGuard(pid);
        let done = terminal(&s, &v.id).await;
        assert_eq!(done.status, JobStatus::Unknown);
        assert!(!done.cleanup_complete && done.redaction_incomplete);
        assert!(s.acknowledge_payload(None, &v.id).is_err());
        for _ in 0..3 {
            s.start(spec(d.path(), "sleep 20"), CancellationToken::new())
                .await
                .unwrap();
        }
        assert!(
            s.start(spec(d.path(), "touch forbidden"), CancellationToken::new())
                .await
                .is_err()
        );
        assert!(!d.path().join("forbidden").exists());
        assert!(s.shutdown().await.is_err());
        assert!(s.shutdown().await.is_err());
        // Even after the excluded fixture is killed, acknowledgement and later
        // shutdowns cannot retroactively manufacture the missing cleanup proof.
        drop(_fixture);
        tokio::time::sleep(TICK * 2).await;
        assert!(s.shutdown().await.is_err());
        let state = lock(&s.core.state);
        assert!(state.sticky_unknown);
        assert!(state.records[&v.id].resource);
        assert!(state.records[&v.id].cleanup_uncertain);
        assert!(!state.records[&v.id].view.cleanup_complete);
    }
    #[tokio::test]
    async fn panic_drops_structured_io_and_retains_obligation() {
        let d = tempfile::tempdir().unwrap();
        let s = JobsSupervisor::new("s", vec![]).unwrap();
        let mut job = spec(d.path(), "sleep 20");
        job.stdin = true;
        let v = s.start(job, CancellationToken::new()).await.unwrap();
        s.send_input(None, &v.id, &vec![b'x'; INPUT], false)
            .await
            .unwrap();
        lock(&s.core.state)
            .records
            .get_mut(&v.id)
            .unwrap()
            .panic_run = true;
        let done = terminal(&s, &v.id).await;
        assert_eq!(done.status, JobStatus::Unknown);
        assert!(s.shutdown().await.is_err());
        let state = lock(&s.core.state);
        assert_eq!(state.running, 0);
        assert!(state.records[&v.id].input.is_none());
        assert!(state.records[&v.id].pgid.is_none());
    }
    #[tokio::test]
    async fn stdin_epipe_releases_slot_but_preserves_failure_and_real_exit() {
        let d = tempfile::tempdir().unwrap();
        let s = JobsSupervisor::new("s", vec![]).unwrap();
        // More than four sequential failures must be possible: a completed
        // stdin operation failure is not a permanently occupied resource slot.
        for _ in 0..5 {
            let mut job = spec(d.path(), "exec 0<&-; printf ready; sleep 20");
            job.stdin = true;
            let v = s.start(job, CancellationToken::new()).await.unwrap();
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if s.poll(None, &v.id, 0, 0, PAGE).await.unwrap().stdout == "ready" {
                        break;
                    }
                    tokio::time::sleep(TICK).await;
                }
            })
            .await
            .unwrap();
            s.send_input(None, &v.id, b"must fail", false)
                .await
                .unwrap();
            let done = terminal(&s, &v.id).await;
            assert_eq!(done.status, JobStatus::Failed);
            assert_eq!(done.reason.as_deref(), Some("stdin I/O failure"));
            assert!(done.cleanup_complete);
            assert!(done.redaction_incomplete);
            assert_eq!(done.exit_code, None);
            assert_eq!(done.signal, Some(libc::SIGTERM));
            let state = lock(&s.core.state);
            let r = &state.records[&v.id];
            assert!(!r.resource && !r.cleanup_uncertain);
            assert!(r.pgid.is_none() && r.input.is_none());
            assert!(!state.sticky_unknown);
        }
        s.shutdown().await.unwrap();
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_backend_requires_real_complete_visibility() {
        // This must fail, not skip or report success, on a restricted deployment.
        // Run the platform integration suite in a genuinely unrestricted procfs.
        assert!(platform::members_gone(0, Instant::now() + CLEANUP).unwrap());
        assert!(
            !platform::members_gone(unsafe { libc::getpgrp() }, Instant::now() + CLEANUP).unwrap()
        );
    }
    #[test]
    fn managed_panic_is_silent_and_external_hook_is_delegated() {
        // Each hook policy lives in its own process. No parent test changes a
        // global hook, and no other test runs concurrently inside either fixture.
        for mode in ["managed", "external"] {
            let d = tempfile::tempdir().unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "jobs::tests::panic_hook_fixture",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("JOBS_HOOK_FIXTURE", mode)
                .env("JOBS_HOOK_DIRECTORY", d.path())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "isolated panic-hook fixture failed"
            );
            let stdout = std::fs::read(d.path().join("host-stdout")).unwrap();
            let stderr = std::fs::read(d.path().join("host-stderr")).unwrap();
            if mode == "managed" {
                assert!(stdout.is_empty());
                assert!(stderr.is_empty());
            } else {
                assert_eq!(stdout, b"external stdout\n");
                assert_eq!(stderr, b"external stderr\n");
            }
        }
    }
    #[test]
    #[ignore]
    fn panic_hook_fixture() {
        use std::{io::Write, os::fd::AsRawFd};
        let mode = std::env::var("JOBS_HOOK_FIXTURE").unwrap();
        let directory = PathBuf::from(std::env::var_os("JOBS_HOOK_DIRECTORY").unwrap());
        // Only this isolated subprocess owns the global hook. The adapter must
        // preserve it for unmarked panics and suppress it for managed polls.
        std::panic::set_hook(Box::new(|_| {
            std::io::stdout().write_all(b"external stdout\n").unwrap();
            std::io::stdout().flush().unwrap();
            std::io::stderr().write_all(b"external stderr\n").unwrap();
            std::io::stderr().flush().unwrap();
        }));
        let s = JobsSupervisor::new("s", vec![]).unwrap();
        install_managed_job_panic_adapter(); // Must not wrap or replace twice.
        struct Restore([i32; 2]);
        impl Drop for Restore {
            fn drop(&mut self) {
                unsafe {
                    libc::dup2(self.0[0], libc::STDOUT_FILENO);
                    libc::dup2(self.0[1], libc::STDERR_FILENO);
                    libc::close(self.0[0]);
                    libc::close(self.0[1]);
                }
            }
        }
        let out = std::fs::File::create(directory.join("host-stdout")).unwrap();
        let err = std::fs::File::create(directory.join("host-stderr")).unwrap();
        let saved = unsafe {
            [
                libc::dup(libc::STDOUT_FILENO),
                libc::dup(libc::STDERR_FILENO),
            ]
        };
        assert!(saved.iter().all(|fd| *fd >= 0));
        let restore = Restore(saved);
        assert!(unsafe { libc::dup2(out.as_raw_fd(), libc::STDOUT_FILENO) } >= 0);
        assert!(unsafe { libc::dup2(err.as_raw_fd(), libc::STDERR_FILENO) } >= 0);
        if mode == "managed" {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let v = s
                    .start(spec(&directory, "sleep 20"), CancellationToken::new())
                    .await
                    .unwrap();
                lock(&s.core.state)
                    .records
                    .get_mut(&v.id)
                    .unwrap()
                    .panic_run = true;
                let done = terminal(&s, &v.id).await;
                assert_eq!(done.status, JobStatus::Unknown);
                assert_eq!(
                    done.reason.as_deref(),
                    Some("managed worker panic; cleanup unconfirmed")
                );
                assert!(s.shutdown().await.is_err());
                // The TLS marker must not leak out of a caught poll.
                assert!(!MANAGED_POLL.with(Cell::get));
            });
        } else {
            assert_eq!(mode, "external");
            assert!(catch_unwind(|| panic!("external fixture payload")).is_err());
        }
        drop(s);
        drop(restore); // Restore before the test harness writes its own result.
    }
    #[tokio::test]
    async fn catch_unwind_drops_pending_reader_and_writer() {
        install_managed_job_panic_adapter();
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Guard(Arc<AtomicUsize>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let count = Arc::new(AtomicUsize::new(0));
        let a = Guard(count.clone());
        let b = Guard(count.clone());
        let worker = async move {
            let reader = async move {
                let _guard = a;
                std::future::pending::<()>().await;
            };
            let writer = async move {
                let _guard = b;
                std::future::pending::<()>().await;
            };
            tokio::pin!(reader, writer);
            tokio::select! {
                _ = &mut reader => (), _ = &mut writer => (),
                _ = tokio::time::sleep(TICK) => panic!("injected")
            }
        };
        assert!(Catch::new(worker).await.is_err());
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod independent_zombie_regression {
    use super::*;
    use std::os::unix::process::CommandExt;

    struct OwnedGroup {
        child: std::process::Child,
        reaped: bool,
    }
    impl OwnedGroup {
        fn stop(&mut self) {
            if !self.reaped {
                // No wait/try_wait has released this child's PID yet.
                unsafe {
                    libc::kill(-(self.child.id() as i32), libc::SIGKILL);
                }
                self.reaped = true;
                self.child.wait().unwrap();
            }
        }
    }
    impl Drop for OwnedGroup {
        fn drop(&mut self) {
            self.stop();
        }
    }

    #[test]
    fn a_zombie_main_thread_with_a_live_worker_is_not_a_gone_process() {
        // /tmp may deliberately be noexec in the validation container. Cargo's
        // own executable output directory already permits test binaries.
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("target"));
        std::fs::create_dir_all(&target).unwrap();
        let dir = tempfile::tempdir_in(target).unwrap();
        let source = dir.path().join("zombie-main.c");
        let binary = dir.path().join("zombie-main");
        std::fs::write(&source, r#"
#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
static int listener;
static void *worker(void *unused) { (void)unused; for (;;) pause(); return NULL; }
int main(int argc, char **argv) {
    if (argc != 2) return 1;
    listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof(address)) || listen(listener, 4)) return 2;
    socklen_t size = sizeof(address);
    if (getsockname(listener, (struct sockaddr *)&address, &size)) return 3;
    pthread_t thread;
    if (pthread_create(&thread, NULL, worker, NULL)) return 4;
    FILE *ready = fopen(argv[1], "w");
    if (!ready) return 5;
    fprintf(ready, "%u", (unsigned)ntohs(address.sin_port));
    if (fclose(ready)) return 6;
    pthread_exit(NULL);
}
"#).unwrap();
        let output = std::process::Command::new("cc")
            .args(["-pthread", "-O0"])
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .output()
            .expect("C compiler is required for the live Linux regression");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let port_file = dir.path().join("port");
        let child = std::process::Command::new(&binary)
            .arg(&port_file)
            .process_group(0)
            .env_clear()
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let mut group = OwnedGroup {
            child,
            reaped: false,
        };
        let pid = group.child.id();
        let deadline = Instant::now() + Duration::from_secs(3);
        let port = loop {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
            let state = stat
                .rsplit_once(')')
                .unwrap()
                .1
                .split_ascii_whitespace()
                .next()
                .unwrap();
            if state == "Z"
                && let Ok(text) = std::fs::read_to_string(&port_file)
                && let Ok(port) = text.parse::<u16>()
            {
                break port;
            }
            assert!(
                Instant::now() < deadline,
                "main thread did not become zombie"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        let address = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        assert!(
            std::net::TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_ok(),
            "worker must still hold a listener"
        );
        assert!(
            platform::members_gone(0, Instant::now() + CLEANUP).is_ok(),
            "backend visibility preflight must work"
        );
        let observed = platform::members_gone(pid as i32, Instant::now() + Duration::from_secs(3));
        group.stop();
        assert!(
            std::net::TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_err()
        );
        assert!(
            !matches!(observed, Ok(true)),
            "zombie leader still had a live worker/listener: {observed:?}"
        );
    }
}
