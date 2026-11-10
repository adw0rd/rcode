# Eval Formal Diagnostics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Добавить opt-in local-only JSONL diagnostics formal violations с точными tool receipts, fail-closed целостностью и неизменным обычным report.

**Architecture:** Rust создаёт новый sidecar и передаёт trusted host `(path, dev, ino)` вне comparison key. `policy.py` возвращает канонически упорядоченные категории каждого tool start и опционально формирует bounded events; `host.py` записывает case buffers через один проверенный descriptor, откатывает частичную запись и публикует только summary.

**Tech Stack:** Rust 2024, clap, serde_json, Unix `OpenOptionsExt`/`MetadataExt`, Python 3.12 stdlib, unittest, Docker fixtures.

**Specification:** `docs/specs/2026-11-10-eval-formal-diagnostics-design.md`

---

## Карта файлов

- `src/cli.rs` — `EvalRun.diagnostics: Option<PathBuf>` и Clap test.
- `src/eval/runner.rs` — безопасное создание sidecar, invocation identity, spawn cleanup, report summary validation.
- `evals/policy.py` — чистая классификация одного tool start и bounded diagnostic events без хранения команд при выключенном флаге.
- `evals/host.py` — descriptor validation, `DiagnosticsWriter`, generation propagation, per-case commit, poisoned skip и summary.
- `tests/eval_policy.py` — категории, повторы, limits, Unicode и opt-out secrecy.
- `tests/eval_host.py` — writer identity/integrity, multi-case failure и Docker sidecar.
- `docs/usage.md`, `AGENTS.md` — операторский интерфейс, security boundaries и команды проверки.

### Task 1: CLI и diagnostics target

**Files:**
- Modify: `src/cli.rs:376-414,482-520`
- Modify: `src/eval/runner.rs:103-140,714-771`

- [ ] **Step 1: Добавить failing Clap и Unix target tests**

В `src/cli.rs` добавить test рядом с `eval_run_parses_snapshots`:

```rust
#[test]
fn eval_run_parses_diagnostics() {
    let cli = Cli::try_parse_from([
        "rcode", "eval", "run", "--suite", "suite", "--report", "report",
        "--agent-binary", "agent", "--image",
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "--docker-socket", "socket", "--series", "series", "--diagnostics", "events.jsonl",
    ]).unwrap();
    let Some(Command::Eval { command: EvalCommand::Run(args) }) = cli.command else {
        panic!("expected eval run")
    };
    assert_eq!(args.diagnostics, Some(PathBuf::from("events.jsonl")));
    assert_eq!(args.snapshots, None);
}
```

В `src/eval/runner.rs::tests` импортировать `MetadataExt` и добавить:

```rust
#[test]
fn diagnostics_target_is_new_private_and_identified() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("events.jsonl");
    let target = super::diagnostics_target(
        Some(&path), &temp.path().join("report.json"), None,
    ).unwrap().unwrap();
    let metadata = std::fs::metadata(&path).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(metadata.len(), 0);
    assert_eq!(target.dev, metadata.dev());
    assert_eq!(target.ino, metadata.ino());
    assert!(target.path.ends_with("/events.jsonl"));
    assert!(super::diagnostics_target(
        Some(&path), &temp.path().join("report.json"), None,
    ).is_err());
    assert!(super::diagnostics_target(None, &temp.path().join("report.json"), None).unwrap().is_none());
}

#[test]
fn diagnostics_target_rejects_alias_collision_and_snapshots_nesting() {
    let temp = tempfile::tempdir().unwrap();
    let real = temp.path().join("real");
    std::fs::create_dir(&real).unwrap();
    std::os::unix::fs::symlink(&real, temp.path().join("alias")).unwrap();
    assert!(super::diagnostics_target(
        Some(&temp.path().join("alias/report.json")), &real.join("report.json"), None,
    ).is_err());
    let snapshots = temp.path().join("snapshots");
    std::fs::create_dir(&snapshots).unwrap();
    let root = std::fs::canonicalize(&snapshots).unwrap().to_str().unwrap().to_owned();
    let nested = snapshots.join("events.jsonl");
    assert!(super::diagnostics_target(
        Some(&nested), &temp.path().join("report.json"), Some(&root),
    ).is_err());
    assert!(!nested.exists());
}

#[test]
fn invocation_diagnostics_contains_only_path_and_identity() {
    let mut invocation = serde_json::json!({"version":1});
    super::attach_diagnostics(&mut invocation, None);
    assert!(invocation.get("diagnostics").is_none());
    super::attach_diagnostics(&mut invocation, Some(super::DiagnosticsTarget {
        path: "/absolute/events.jsonl".into(), dev: 11, ino: 12,
    }));
    assert_eq!(invocation["diagnostics"], serde_json::json!({
        "path":"/absolute/events.jsonl", "dev":11, "ino":12,
    }));
}
```

- [ ] **Step 2: Подтвердить RED**

Run: `cargo test --lib diagnostics -- --nocapture`

Expected: компиляция падает из-за отсутствующих `EvalRun.diagnostics`, `DiagnosticsTarget`, `diagnostics_target` и `attach_diagnostics`.

- [ ] **Step 3: Реализовать CLI и target**

В `EvalRun` после `snapshots` добавить:

```rust
#[arg(long, help = "Сохранить formal violation receipts в новый local-only JSONL файл")]
pub diagnostics: Option<PathBuf>,
```

В `src/eval/runner.rs` добавить:

```rust
#[derive(Debug, Clone)]
struct DiagnosticsTarget {
    path: String,
    dev: u64,
    ino: u64,
}

#[cfg(unix)]
fn normalized_output(path: &Path) -> Result<PathBuf> {
    let name = path.file_name().context("Нужен путь к новому файлу")?;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    Ok(fs::canonicalize(parent)?.join(name))
}

#[cfg(unix)]
fn diagnostics_target(
    path: Option<&Path>, report: &Path, snapshots: Option<&str>,
) -> Result<Option<DiagnosticsTarget>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let Some(path) = path else { return Ok(None) };
    let expected = normalized_output(path)?;
    ensure!(expected != normalized_output(report)?, "Diagnostics и report должны различаться");
    if let Some(root) = snapshots {
        ensure!(!expected.starts_with(root), "Diagnostics должен находиться вне snapshots");
    }
    let path = expected.to_str().context("Путь diagnostics должен быть UTF-8")?.to_owned();
    let file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&expected)?;
    let metadata = file.metadata()?;
    ensure!(metadata.permissions().mode() & 0o777 == 0o600, "Некорректные права diagnostics");
    Ok(Some(DiagnosticsTarget { path, dev: metadata.dev(), ino: metadata.ino() }))
}

#[cfg(not(unix))]
fn diagnostics_target(
    path: Option<&Path>, _report: &Path, _snapshots: Option<&str>,
) -> Result<Option<DiagnosticsTarget>> {
    if path.is_some() { anyhow::bail!("Защищённый eval поддерживается только на Unix host") }
    Ok(None)
}

fn attach_diagnostics(invocation: &mut Value, target: Option<DiagnosticsTarget>) {
    if let Some(target) = target {
        invocation["diagnostics"] = json!({
            "path": target.path, "dev": target.dev, "ino": target.ino,
        });
    }
}
```

В tests импортировать `OpenOptionsExt` не требуется; `PermissionsExt` уже есть. `normalized_output` не создаёт report и работает с canonical existing parent.

- [ ] **Step 4: Подтвердить GREEN**

Run: `cargo test --lib diagnostics -- --nocapture && cargo test --test eval_cli`

Expected: новые target/invocation/Clap tests и существующие eval CLI tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cli.rs src/eval/runner.rs
git commit -m "feat(eval): добавить diagnostics target"
```

### Task 2: Канонические policy receipts

**Files:**
- Modify: `evals/policy.py:153-167,264-293`
- Test: `tests/eval_policy.py`

- [ ] **Step 1: Добавить failing policy tests**

Импортировать `tool_violations` и добавить:

```python
def diagnostic_state():
    return {'skills': {}, 'violations': set(), 'diagnostics': [], 'diagnostics_dropped': 0}

class DiagnosticsPolicyTests(unittest.TestCase):
    def test_receipt_has_canonical_categories_generation_and_exact_command(self):
        state = diagnostic_state()
        command = 'git status; python3 -m pip install pytest'
        observe_tool_start(state, {'id':'call-1','name':'run_command',
            'arguments':json.dumps({'command':command})}, generation=7)
        self.assertEqual([event['category'] for event in state['diagnostics']],
            ['package_install', 'git'])
        self.assertTrue(all(event['generation'] == 7 for event in state['diagnostics']))
        self.assertTrue(all(event['command'] == command for event in state['diagnostics']))
        self.assertEqual(tool_violations({'name':'spawn_agent','arguments':'{}'}), ('subagent',))

    def test_repeated_violations_are_retained_but_opt_out_retains_no_command(self):
        state = diagnostic_state()
        for command in ('git status', 'pip install pytest'):
            observe_tool_start(state, {'id':'call','name':'run_command',
                'arguments':json.dumps({'command':command})}, generation=1)
        self.assertEqual(len(state['diagnostics']), 2)
        plain = {'skills': {}, 'violations': set()}
        observe_tool_start(plain, {'id':'call','name':'run_command',
            'arguments':json.dumps({'command':'git status synthetic-secret'})})
        self.assertNotIn('synthetic-secret', repr(plain))

    def test_limits_unicode_and_malformed_arguments(self):
        state = diagnostic_state()
        command = 'pip install #' + 'a' * 4090 + '\U0001f642' + '\ud800'
        observe_tool_start(state, {'id':'x' * 300,'name':'run_command',
            'arguments':json.dumps({'command':command})}, generation=1)
        event = state['diagnostics'][0]
        self.assertLessEqual(len(event['command'].encode('utf-8')), 4096)
        self.assertTrue(event['command_truncated'])
        self.assertTrue(event['call_id_truncated'])
        self.assertLessEqual(len(event['call_id'].encode('utf-8')), 256)
        self.assertNotIn('\ud800', repr(event['command']))
        for receipt in ({'name':'run_command','arguments':'{'},
                {'name':'run_command','arguments':'{"command":null}'}):
            self.assertEqual(tool_violations(receipt), ())

    def test_category_limit_is_deterministic_at_63_plus_2(self):
        state = diagnostic_state()
        state['diagnostics'] = [{} for _ in range(63)]
        observe_tool_start(state, {'id':'call','name':'run_command',
            'arguments':json.dumps({'command':'git status; pip install pytest'})}, generation=2)
        self.assertEqual(len(state['diagnostics']), 64)
        self.assertEqual(state['diagnostics_dropped'], 1)
        self.assertEqual(state['diagnostics'][-1]['category'], 'package_install')
```

- [ ] **Step 2: Подтвердить RED**

Run: `python3 tests/eval_policy.py`

Expected: import `tool_violations` падает; после добавления импорта новые tests падают из-за отсутствующего `generation` и diagnostics.

- [ ] **Step 3: Реализовать единый classifier и bounded events**

В `policy.py` добавить:

```python
CATEGORY_ORDER = ('package_install', 'git', 'network', 'subagent')
DIAGNOSTICS_LIMIT = 64


def tool_violations(receipt):
    if not isinstance(receipt, dict):
        return ()
    name = receipt.get('name')
    if name in ('spawn_agent', 'wait_agent'):
        return ('subagent',)
    if name != 'run_command':
        return ()
    arguments = _arguments(receipt)
    command = arguments.get('command') if arguments else None
    if not isinstance(command, str):
        return ()
    temporary = {'violations': set()}
    _classify_shell(command, temporary)
    return tuple(category for category in CATEGORY_ORDER if category in temporary['violations'])


def _bounded_text(value, limit):
    raw = value.encode('utf-8', errors='replace')
    truncated = len(raw) > limit
    return raw[:limit].decode('utf-8', errors='ignore'), truncated


def _record_diagnostics(state, receipt, categories, generation):
    events = state.get('diagnostics')
    if events is None:
        return
    arguments = _arguments(receipt)
    command = arguments.get('command') if arguments else None
    command, command_truncated = _bounded_text(command, 4096) if isinstance(command, str) else (None, False)
    identity = receipt.get('id')
    identity, identity_truncated = _bounded_text(identity, 256) if isinstance(identity, str) else (None, False)
    for category in categories:
        if len(events) >= DIAGNOSTICS_LIMIT:
            state['diagnostics_dropped'] = state.get('diagnostics_dropped', 0) + 1
            continue
        events.append({'version':1, 'generation':generation if type(generation) is int and generation >= 1 else None,
            'category':category, 'tool':receipt['name'], 'call_id':identity,
            'call_id_truncated':identity_truncated, 'command':command,
            'command_truncated':command_truncated})
```

Заменить `observe_tool_start` целиком, сохранив существующую обработку `load_skill`:

```python
def observe_tool_start(state, receipt, generation=None):
    if not isinstance(receipt, dict):
        return
    name = receipt.get('name')
    call_id = receipt.get('id')
    arguments = _arguments(receipt)
    if name == 'load_skill':
        if not isinstance(call_id, str):
            return
        seen = state.setdefault('skill_calls', set())
        if call_id in seen:
            state.setdefault('quarantined_skills', set()).add(call_id)
            state['skills'].pop(call_id, None)
            state.setdefault('skill_successes', set()).discard(call_id)
            state.setdefault('pending_skills', set()).discard(call_id)
            return
        seen.add(call_id)
        skill = arguments.get('name') if arguments else None
        if isinstance(skill, str) and skill:
            state['skills'][call_id] = skill
            state.setdefault('pending_skills', set()).add(call_id)
        return
    categories = tool_violations(receipt)
    state['violations'].update(categories)
    if categories:
        _record_diagnostics(state, receipt, categories, generation)
```

- [ ] **Step 4: Подтвердить GREEN и отсутствие регрессий**

Run:

```bash
python3 tests/eval_policy.py
for seed in 1 2 3; do PYTHONHASHSEED="$seed" python3 tests/eval_policy.py; done
```

Expected: все прежние и новые tests PASS при каждом seed; порядок категорий не меняется, команды по-прежнему не сохраняются в state без `diagnostics`.

- [ ] **Step 5: Commit**

```bash
git add evals/policy.py tests/eval_policy.py
git commit -m "feat(eval): записывать formal violation receipts"
```

### Task 3: Fail-closed DiagnosticsWriter

**Files:**
- Modify: `evals/host.py:5-25` и после `AssessmentFailure`
- Test: `tests/eval_host.py`

- [ ] **Step 1: Добавить failing writer fixtures**

В `HostConfigTests` добавить helper и tests:

```python
def make_diagnostics(self, root):
    path = root / 'events.jsonl'
    path.touch(mode=0o600)
    path.chmod(0o600)
    stat = path.stat()
    return path, {'path':str(path), 'dev':stat.st_dev, 'ino':stat.st_ino}

def test_writer_commits_empty_and_exact_jsonl_digest(self):
    import host
    with tempfile.TemporaryDirectory() as temp:
        path, spec = self.make_diagnostics(Path(temp))
        writer = host.DiagnosticsWriter(spec)
        self.assertTrue(writer.commit('case-1', [], 0))
        summary = writer.finish()
        self.assertEqual(summary, {'complete':True,'sha256':hashlib.sha256(b'').hexdigest(),
            'events':0,'dropped':0})
        self.assertEqual(path.read_bytes(), b'')

def test_writer_rolls_back_partial_case_and_poisons_summary(self):
    import host
    from unittest.mock import patch
    with tempfile.TemporaryDirectory() as temp:
        path, spec = self.make_diagnostics(Path(temp))
        writer = host.DiagnosticsWriter(spec)
        event = {'version':1,'generation':1,'category':'git','tool':'run_command','call_id':'a',
            'call_id_truncated':False,'command':'git status','command_truncated':False}
        self.assertTrue(writer.commit('first', [event], 0))
        original = host.os.write
        def partial(fd, data):
            original(fd, bytes(data[:max(1, len(data)//2)]))
            raise OSError('synthetic /secret/path/events.jsonl')
        with patch.object(host.os, 'write', side_effect=partial):
            self.assertFalse(writer.commit('second', [event], 0))
        summary = writer.finish()
        self.assertFalse(summary['complete'])
        self.assertIsNone(summary['sha256'])
        self.assertEqual(summary['error'], 'diagnostics_io_error')
        self.assertEqual(summary['events'], 1)
        lines = path.read_text().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])['case'], 'first')
        self.assertNotIn('/secret/path', json.dumps(summary))

def test_writer_rejects_path_substitution_and_wrong_identity(self):
    import host
    from unittest.mock import patch
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp); path, spec = self.make_diagnostics(root)
        other = root/'other'; other.write_text('do not overwrite'); other.chmod(0o600)
        path.unlink(); path.symlink_to(other)
        with self.assertRaises(Failure):
            host.DiagnosticsWriter(spec)
        self.assertEqual(other.read_text(), 'do not overwrite')
        path.unlink(); path.touch(mode=0o600); path.chmod(0o600)
        os.link(path, root/'hardlink')
        spec['dev'] = path.stat().st_dev; spec['ino'] = path.stat().st_ino
        with self.assertRaises(Failure):
            host.DiagnosticsWriter(spec)
        (root/'hardlink').unlink(); path.chmod(0o644)
        with self.assertRaises(Failure):
            host.DiagnosticsWriter(spec)
        path.chmod(0o600); path.write_text('nonempty')
        with self.assertRaises(Failure):
            host.DiagnosticsWriter(spec)
        path.write_text('')
        with patch.object(host.os, 'geteuid', return_value=os.geteuid() + 1):
            with self.assertRaises(Failure):
                host.DiagnosticsWriter(spec)
```

Добавить `import hashlib` в начало `tests/eval_host.py`.

- [ ] **Step 2: Подтвердить RED**

Run: `python3 tests/eval_host.py`

Expected: `AttributeError: module 'host' has no attribute 'DiagnosticsWriter'`; существующие tests не затрагиваются.

- [ ] **Step 3: Реализовать descriptor validation и writer**

В `host.py` добавить `import stat` и следующий класс. `flush` отсутствует как отдельная операция, потому что используется небуферизованный `os.write`; durability обеспечивает `fsync`.

```python
class DiagnosticsWriter:
    def __init__(self, spec):
        if not isinstance(spec, dict) or set(spec) != {'path','dev','ino'}:
            raise Failure('diagnostics invocation')
        if not isinstance(spec['path'], str) or type(spec['dev']) is not int or type(spec['ino']) is not int:
            raise Failure('diagnostics invocation')
        self.path = spec['path']; self.fd = None; self.poisoned = False
        self.offset = 0; self.events = 0; self.dropped = 0; self.sha256 = hashlib.sha256()
        flags = os.O_RDWR | os.O_APPEND | getattr(os, 'O_NOFOLLOW', 0)
        try:
            self.fd = os.open(self.path, flags)
            value = os.fstat(self.fd)
            valid = (stat.S_ISREG(value.st_mode) and value.st_dev == spec['dev']
                and value.st_ino == spec['ino'] and value.st_nlink == 1
                and value.st_uid == os.geteuid() and stat.S_IMODE(value.st_mode) == 0o600
                and value.st_size == 0)
            if not valid:
                raise Failure('diagnostics identity')
        except (Failure, OSError, ValueError):
            if self.fd is not None:
                try:
                    os.close(self.fd)
                except OSError:
                    pass
                self.fd = None
            raise Failure('diagnostics open failed')

    def summary(self):
        if self.poisoned:
            return {'complete':False,'sha256':None,'events':self.events,'dropped':self.dropped,
                'error':'diagnostics_io_error'}
        return {'complete':True,'sha256':self.sha256.hexdigest(),'events':self.events,'dropped':self.dropped}

    def poison(self):
        self.poisoned = True
        if self.fd is None:
            return
        try:
            os.ftruncate(self.fd, self.offset); os.fsync(self.fd)
        except (OSError, TypeError, ValueError):
            pass

    def commit(self, case, events, dropped):
        if self.poisoned:
            return False
        try:
            raw = bytearray()
            for event in events:
                record = {**event, 'case':case}
                raw.extend(json.dumps(record, ensure_ascii=True, allow_nan=False,
                    separators=(',',':')).encode('utf-8') + b'\n')
            view = memoryview(raw)
            while view:
                written = os.write(self.fd, view)
                if written <= 0:
                    raise OSError('short diagnostics write')
                view = view[written:]
            os.fsync(self.fd)
        except (OSError, TypeError, ValueError):
            self.poison(); return False
        self.sha256.update(raw); self.offset += len(raw)
        self.events += len(events); self.dropped += dropped
        return True

    def finish(self):
        if self.fd is None:
            return self.summary()
        try:
            if not self.poisoned:
                os.fsync(self.fd); os.lseek(self.fd, 0, os.SEEK_SET)
                actual = hashlib.sha256(); size = 0; lines = 0
                while True:
                    chunk = os.read(self.fd, 65536)
                    if not chunk:
                        break
                    actual.update(chunk); size += len(chunk); lines += chunk.count(b'\n')
                if size != self.offset or lines != self.events or actual.digest() != self.sha256.digest():
                    raise Failure('diagnostics final digest')
                os.close(self.fd); self.fd = None
                directory = os.open(str(Path(self.path).parent), os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        except (Failure, OSError, ValueError):
            self.poison()
        finally:
            if self.fd is not None:
                try:
                    os.close(self.fd)
                except OSError:
                    pass
                self.fd = None
        return self.summary()
```

`case` приходит из строго валидированного manifest; policy уже нормализовала strings. `version` остаётся в каждой записи, `case` добавляется writer.

- [ ] **Step 4: Подтвердить GREEN**

Run: `python3 tests/eval_host.py`

Expected: writer fixtures и все прежние non-Docker tests PASS; Docker tests могут пропускаться только без явных Docker env и не считаются Docker-проверкой.

- [ ] **Step 5: Commit**

```bash
git add evals/host.py tests/eval_host.py
git commit -m "feat(eval): сохранять diagnostics fail-closed"
```

### Task 4: Host integration и report schema

**Files:**
- Modify: `evals/host.py:25,264-304,311-453`
- Modify: `src/eval/runner.rs:278-323,333-409`
- Test: `tests/eval_host.py`
- Test: `src/eval/runner.rs:714-771`

- [ ] **Step 1: Добавить failing integration tests**

В `test_agent_phase_observes_start_and_every_result` инициализировать state через `diagnostic_state()` из policy tests не импортируя другой test module:

```python
state={'skills':{},'violations':set(),'diagnostics':[],'diagnostics_dropped':0}
```

После `receipt_phase` проверить:

```python
self.assertEqual(state['diagnostics'][0]['generation'], 1)
```

Добавить host main test с poisoned writer и тремя кейсами, используя fake Docker без inference:

```python
def test_poisoned_diagnostics_prevents_remaining_inference(self):
    import host
    from unittest.mock import patch
    class FakeDocker:
        def __init__(self,*_args): self.active={}; self.volumes={}; self.cleanup_deadline=None
        def cleanup(self,_deadline): pass
    class Writer:
        poisoned = True
        def finish(self):
            return {'complete':False,'sha256':None,'events':0,'dropped':0,'error':'diagnostics_io_error'}
    invocation={'version':1,'comparison_key':{},'artifact':{},'docker':'/docker','socket':'/docker.sock',
        'image':'image','runtime':str(ROOT/'evals/runtime'),'diagnostics':{'path':'unused','dev':1,'ino':1},
        'cases':[{'case':{'id':str(n)},'sha256':'f'*64} for n in range(3)]}
    stdin=io.TextIOWrapper(io.BytesIO(json.dumps(invocation).encode())); stdout=io.StringIO(); stderr=io.StringIO()
    with patch.object(host,'Docker',FakeDocker),patch.object(host,'check_isolation',return_value=None),patch.object(
        host,'DiagnosticsWriter',return_value=Writer()),patch.object(host,'run_case') as run_case,patch.object(
        host.sys,'stdin',stdin),patch.object(host.sys,'stdout',stdout),patch.object(host.sys,'stderr',stderr):
        code=host.main()
    report=json.loads(stdout.getvalue()); run_case.assert_not_called()
    self.assertEqual(code,1)
    self.assertEqual([row['status'] for row in report['cases']], ['not_run'] * 3)
    self.assertFalse(report['diagnostics']['complete'])
```

В Rust tests добавить unit для новой `validate_diagnostics_summary`:

```rust
#[test]
fn diagnostics_summary_schema_is_strict_and_fail_closed() {
    let complete = serde_json::json!({"complete":true,"sha256":"0".repeat(64),"events":0,"dropped":0});
    assert!(super::validate_diagnostics_summary(Some(&complete), 0).is_ok());
    let invalid = serde_json::json!({"complete":true,"sha256":null,"events":1,"dropped":0});
    assert!(super::validate_diagnostics_summary(Some(&invalid), 0).is_err());
    let failed = serde_json::json!({"complete":false,"sha256":null,"events":1,"dropped":0,
        "error":"diagnostics_io_error"});
    assert!(super::validate_diagnostics_summary(Some(&failed), 0).is_ok());
    assert!(super::validate_diagnostics_summary(Some(&failed), 1).is_err());
    assert!(super::validate_diagnostics_summary(None, 1).is_ok());
}
```

- [ ] **Step 2: Подтвердить RED**

Run: `python3 tests/eval_host.py && cargo test --lib diagnostics_summary -- --nocapture`

Expected: generation отсутствует, host не пропускает poisoned cases, Rust функция не определена.

- [ ] **Step 3: Передать diagnostics через host**

В `agent_phase` заменить вызов:

```python
observe_tool_start(policy_state, event,
    generation=gateway.generations if type(getattr(gateway, 'generations', None)) is int else None)
```

В `run_case` добавить аргумент `diagnostics=None`; при активном writer инициализировать:

```python
policy_state={'skills':{},'violations':set()}
if diagnostics is not None:
    policy_state.update({'diagnostics':[],'diagnostics_dropped':0})
```

В конце `run_case::finally`, после существующего verdict/cleanup adjudication:

```python
if diagnostics is not None:
    committed = diagnostics.commit(case['id'], policy_state['diagnostics'], policy_state['diagnostics_dropped'])
    if not committed and result['status'] != 'unknown':
        result['status'] = 'blocked'
        result['reason'] = 'diagnostics I/O failure'
```

В `main` после parsing invocation создать writer:

```python
diagnostics = DiagnosticsWriter(invocation['diagnostics']) if 'diagnostics' in invocation else None
```

В loop перед обычным `run_case` добавить:

```python
if diagnostics is not None and diagnostics.poisoned:
    report['cases'].append({'id':item['case']['id'],'case_sha256':item['sha256'],
        'status':'not_run','reason':'diagnostics unavailable','cleanup':'confirmed_absent'})
    continue
row = run_case(docker, invocation, item, root, diagnostics=diagnostics)
```

После Docker cleanup и до `print(json.dumps(report...))`:

```python
if diagnostics is not None:
    report['diagnostics'] = diagnostics.finish()
```

При отсутствии флага invocation и report не получают новых ключей.

- [ ] **Step 4: Подключить Rust invocation и spawn cleanup**

После `attach_snapshots` использовать `snapshots` по ссылке для создания target и затем attach:

```rust
attach_snapshots(&mut invocation, snapshots.clone());
let diagnostics = diagnostics_target(
    args.diagnostics.as_deref(), &args.report, snapshots.as_deref(),
)?;
attach_diagnostics(&mut invocation, diagnostics.clone());
```

В `spawn_blocking` захватить `diagnostics_path = diagnostics.map(|value| PathBuf::from(value.path))`. Собрать команду отдельной переменной и при ошибке `spawn()` удалить только пустой созданный файл:

```rust
let mut command = Command::new(python);
command
    .args(["-I","-S","-c","import sys;sys.path[:0]=[sys.argv[1],sys.argv[2]];import host;raise SystemExit(host.main())"])
    .arg(&path)
    .arg(&runtime_path)
    .env_clear()
    .env("PATH","/usr/bin:/bin")
    .env("HOME",&path)
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::inherit());
let mut child = match command.spawn() {
    Ok(child) => child,
    Err(error) => {
        if let Some(path) = &diagnostics_path {
            if std::fs::metadata(path).map(|m| m.len() == 0).unwrap_or(false) {
                let _ = std::fs::remove_file(path);
            }
        }
        return Err(error.into());
    }
};
```

Сохранить существующие env_clear, stdin/stdout bounds и ожидание процесса.

- [ ] **Step 5: Валидировать summary**

Добавить `"diagnostics"` в разрешённые top-level keys и функцию:

```rust
fn validate_diagnostics_summary(summary: Option<&Value>, passed: u64) -> Result<()> {
    let Some(summary) = summary else { return Ok(()) };
    let fields = summary.as_object().context("Diagnostics summary")?;
    ensure!(fields.keys().all(|key| matches!(key.as_str(),
        "complete" | "sha256" | "events" | "dropped" | "error")),
        "Неизвестные поля diagnostics");
    ensure!(summary["events"].as_u64().is_some() && summary["dropped"].as_u64().is_some(),
        "Счётчики diagnostics");
    if summary["complete"] == true {
        ensure!(summary["sha256"].as_str().is_some_and(hex) && summary.get("error").is_none(),
            "Некорректная complete diagnostics");
        return Ok(());
    }
    ensure!(summary["complete"] == false && summary["sha256"].is_null()
        && summary["error"] == "diagnostics_io_error" && passed == 0,
        "PASS с неполной diagnostics");
    Ok(())
}
```

`hex` проверяет полный 64-символьный digest, включая SHA-256 пустого файла. В `validate_report` после `counts` вызвать:

```rust
validate_diagnostics_summary(report.get("diagnostics"), counts["passed"])?;
```

- [ ] **Step 6: Подтвердить GREEN**

Run: `python3 tests/eval_host.py && cargo test --lib diagnostics -- --nocapture && cargo test --test eval_cli`

Expected: все integration/unit tests PASS; no-flag tests сохраняют прежнее поведение.

- [ ] **Step 7: Commit**

```bash
git add evals/host.py src/eval/runner.rs tests/eval_host.py
git commit -m "feat(eval): подключить diagnostics к report"
```

### Task 5: Docker fixture, документация и live diagnostics

**Files:**
- Modify: `tests/eval_host.py:527-560`
- Modify: `docs/usage.md` в разделе eval run
- Modify: `AGENTS.md` в разделе изолированного eval
- Modify: `docs/specs/2026-11-10-eval-formal-diagnostics-design.md`

- [ ] **Step 1: Добавить Docker sidecar regression test**

Добавить полностью самостоятельный test с реальным Docker archive, без mock `extract_frozen`:

```python
def test_diagnostics_sidecar_matches_policy_and_survives_cleanup(self):
    import host
    from unittest.mock import patch
    fixture = self.root/'fixture'; fixture.mkdir(mode=0o755)
    (fixture/'value.txt').write_text('original')
    temporary = self.root/'temporary'; temporary.mkdir(mode=0o700)
    diagnostics_path, spec = self.make_diagnostics(self.root)
    writer = host.DiagnosticsWriter(spec)
    profile = {'base_url':'http://127.0.0.1:9/v1','model':'fixture','max_output_tokens':8,
        'request_timeout_secs':5,'idle_timeout_secs':5}
    item = {'case':{'id':'diagnostics','language':'python','category':'fixture','timeout_secs':30,
        'max_steps':2,'max_requests':2},'sha256':'f'*64,'fixture':str(fixture),'task':'fixture',
        'oracle':{'prepare':[],'checks':[]}}
    def phase(docker,_invocation,_item,volumes,gateway,deadline,**kwargs):
        name = docker.create({'/fixture':fixture}, deadline, volumes=volumes)
        channel = docker.start(name, {'mode':'agent','uid':10001,'gid':10001,'timeout_secs':10,
            'seed_project':True,'hold':True,'model':'fixture','profile_config':None,
            'argv':['python3','-I','-S','-c',"from pathlib import Path;Path('value.txt').write_text('changed')"]}, deadline)
        try:
            while True:
                done = channel.receive()
                if done['type'] == 'agent_done':
                    break
            docker.remove(name, deadline)
            gateway.generations = 1; gateway.attempts = 1
            gateway.receipts = [{'generation':1,'status':'received','http_status':200,'usage':None}]
            host.observe_tool_start(kwargs['policy_state'], {'id':'pip','name':'run_command',
                'arguments':json.dumps({'command':'python3 -m pip install pytest'})}, generation=1)
            return {'done':done,'agent_reported_tool_successes':{},'session_id':None,
                'sentinel':False,'cancel_sent':False}
        finally:
            channel.close()
    with patch.object(host,'agent_phase',phase):
        result = host.run_case(self.docker, {'effective_profile':profile}, item, temporary, diagnostics=writer)
    summary = writer.finish(); raw = diagnostics_path.read_bytes()
    self.assertEqual(result['formal_violations'], ['package_install'])
    self.assertEqual(result['status'], 'failed')
    self.assertTrue(summary['complete'])
    self.assertEqual(summary['sha256'], hashlib.sha256(raw).hexdigest())
    events = [json.loads(line) for line in raw.splitlines()]
    self.assertEqual(len(events), summary['events'])
    self.assertEqual(events[0]['command'], 'python3 -m pip install pytest')
    self.assertEqual(events[0]['generation'], 1)
    self.assertNotIn('pip install', json.dumps(result))
    self.assertEqual((temporary/'diagnostics/value.txt').read_text(), 'changed')
    self.assertFalse(self.docker.active or self.docker.volumes)
```

- [ ] **Step 2: Проверить Docker regression с явным Docker**

Run:

```bash
RCODE_EVAL_DOCKER=/Users/colinfrl/.local/bin/docker \
RCODE_EVAL_SOCKET="$HOME/.orbstack/run/docker.sock" \
RCODE_EVAL_IMAGE=sha256:98de9b6855a361f8caaca0b266ce4b1f5eeef5ce803857127a339296e513f57e \
python3 tests/eval_host.py
```

Expected: новый и все прежние Docker tests PASS без пропусков. При failure вернуться к Task 4 и исправить причину до live.

- [ ] **Step 3: Документировать операторский контракт**

В `docs/usage.md` добавить к `--snapshots` пример:

```bash
rcode --profile gigachat eval run \
  --suite evals/todo-api/manifest.json \
  --agent-binary /absolute/rcode-linux \
  --series gigachat-todo-diagnostics \
  --image sha256:POLNOE_IMAGE_ID \
  --docker-socket /absolute/docker.sock \
  --report /absolute/artifacts/report.json \
  --snapshots /absolute/artifacts/snapshots \
  --diagnostics /absolute/artifacts/formal-violations.jsonl \
  --non-streaming --yes
```

Текст должен указать: новый файл `0600`, только formal violation tool starts, команды потенциально чувствительны, путь не попадает в report/comparison key, summary `complete/sha256/events/dropped`, при I/O error PASS запрещён, пустой sidecar валиден, публикация не выполняется.

В `AGENTS.md` добавить краткое правило и проверки `python3 tests/eval_policy.py`, `python3 tests/eval_host.py`; отметить, что `os.write` небуферизован, поэтому отдельный userspace `flush` не требуется.

В design spec заменить нормальный per-case `flush + fsync` на `os.write + fsync`, а список ошибок `write, flush или fsync` — на `write или fsync`, чтобы документация совпадала с реализацией.

- [ ] **Step 4: Локальные и стандартные проверки**

Run:

```bash
python3 tests/eval_policy.py
python3 tests/eval_host.py
python3 evals/host_snapshot.py
python3 tests/eval_security.py
python3 tests/eval_provider.py
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo build --release --locked
target/release/rcode eval validate --suite evals/todo-api/manifest.json
```

Expected: все команды exit 0; live API не вызывается.

- [ ] **Step 5: Собрать и проверить новый Linux binary**

Run:

```bash
mkdir -p artifacts/todo-eval/build-target
/Users/colinfrl/.local/bin/docker run --rm --network=none --platform linux/arm64 \
  -v "$PWD:/src:ro" -v "$PWD/artifacts/todo-eval/build-target:/target" \
  -v "$HOME/.cargo:/cargo:ro" -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/target \
  -w /src rust:1.88-slim cargo build --offline --release --locked --package rcode-cli --bin rcode
cp artifacts/todo-eval/build-target/release/rcode artifacts/todo-eval/rcode-linux
file artifacts/todo-eval/rcode-linux
shasum -a 256 artifacts/todo-eval/rcode-linux
/Users/colinfrl/.local/bin/docker run --rm --network=none --platform linux/arm64 \
  --entrypoint /agent/rcode -v "$PWD/artifacts/todo-eval/rcode-linux:/agent/rcode:ro" \
  rcode-eval-runtime --version
```

Expected: Linux ELF запускается и новый SHA-256 зафиксирован; `artifacts` остаётся в `.git/info/exclude`, не добавляется в Git.

- [ ] **Step 6: Docker controls**

Run с явными env:

```bash
export RCODE_EVAL_DOCKER=/Users/colinfrl/.local/bin/docker
export RCODE_EVAL_SOCKET="$HOME/.orbstack/run/docker.sock"
export RCODE_EVAL_IMAGE=sha256:98de9b6855a361f8caaca0b266ce4b1f5eeef5ce803857127a339296e513f57e
python3 tests/eval_runtime.py
python3 tests/eval_host.py
python3 tests/eval_todo_controls.py
python3 tests/eval_controls.py
```

Expected: Docker runtime/host и все controls PASS; последняя команда запускает все 30 кейсов без `RCODE_EVAL_CASES`. `evals/Dockerfile` не меняется, поэтому image digest остаётся тем же.

- [ ] **Step 7: Commit implementation и docs**

```bash
git add tests/eval_host.py docs/usage.md AGENTS.md docs/specs/2026-11-10-eval-formal-diagnostics-design.md docs/specs/2026-11-11-eval-formal-diagnostics-plan.md
git commit -m "test(eval): проверить diagnostics в Docker"
```

- [ ] **Step 8: Один GigaChat diagnostic live-run**

Run:

```bash
mkdir -p artifacts/todo-eval/gigachat-diagnostics
target/release/rcode --profile gigachat eval run \
  --suite evals/todo-api/manifest.json \
  --agent-binary "$PWD/artifacts/todo-eval/rcode-linux" \
  --series gigachat-todo-diagnostics \
  --image sha256:98de9b6855a361f8caaca0b266ce4b1f5eeef5ce803857127a339296e513f57e \
  --docker-socket "$HOME/.orbstack/run/docker.sock" \
  --report "$PWD/artifacts/todo-eval/gigachat-diagnostics/report.json" \
  --snapshots "$PWD/artifacts/todo-eval/gigachat-diagnostics/snapshots" \
  --diagnostics "$PWD/artifacts/todo-eval/gigachat-diagnostics/formal-violations.jsonl" \
  --non-streaming --yes \
  > "$PWD/artifacts/todo-eval/gigachat-diagnostics/run.stdout" \
  2> "$PWD/artifacts/todo-eval/gigachat-diagnostics/run.stderr"
```

Expected: команда может вернуть 1 из-за model verdict; это не transport failure диагностики. Обязательно проверить sidecar:

```bash
python3 - <<'PY'
import hashlib, json
from pathlib import Path
root = Path('artifacts/todo-eval/gigachat-diagnostics')
report_text = (root/'report.json').read_text()
report = json.loads(report_text)
raw = (root/'formal-violations.jsonl').read_bytes()
summary = report['diagnostics']
assert summary['complete'] is True
assert summary['sha256'] == hashlib.sha256(raw).hexdigest()
events = [json.loads(line) for line in raw.splitlines()]
assert len(events) == summary['events']
diagnostics_path = root/'formal-violations.jsonl'
assert str(diagnostics_path) not in report_text
assert str(diagnostics_path.resolve()) not in report_text
assert not report['residual_resources']['containers']
assert not report['residual_resources']['volumes']
for event in events:
    if event['command'] is not None:
        assert event['command'] not in report_text
print(json.dumps({'summary':summary,'events':events,'cases':[{'id':c['id'],'status':c['status'],
    'reason':c.get('reason'),'formal_violations':c.get('formal_violations')} for c in report['cases']]}, ensure_ascii=False, indent=2))
PY
```

Expected: digest и число events совпадают; при `package_install` видна точная команда; report не содержит diagnostics path/command; cleanup confirmed. Если нарушений нет, sidecar пуст и empty digest валиден. Qwen не запускать.
