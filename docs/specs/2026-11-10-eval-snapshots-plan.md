# Eval Snapshots Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Добавить опциональное сохранение исходников eval-кейсов через `rcode eval run --snapshots <новый-каталог>` без изменения verdict, report protocol и Docker cleanup.

**Architecture:** Rust runner создаёт и валидирует новый корневой каталог, затем передаёт его абсолютный путь trusted Python host в invocation. `run_case` заменяет только destination существующего `extract_frozen`; тот же постоянный каталог остаётся read-only источником для oracle и доступен оператору для code review.

**Tech Stack:** Rust 2024, clap, serde_json, tempfile, Python 3.12 host fixtures, unittest, Docker integration tests.

**Specification:** `docs/specs/2026-11-10-eval-snapshots-design.md`

---

## Структура изменений

- `src/cli.rs` — публичный CLI-аргумент `EvalRun.snapshots: Option<PathBuf>`.
- `src/eval/runner.rs` — fail-closed создание нового root `0700`, canonical path и добавление поля `snapshots` в host invocation.
- `evals/host.py` — выбор постоянного или временного snapshot destination; существующие экспорт, hash и oracle не меняются.
- `tests/eval_host.py` — unit fixture выбора destination и Docker end-to-end сохранения исходников.
- `docs/usage.md`, `AGENTS.md` — операторский интерфейс, границы безопасности и команды проверки.

### Task 1: CLI и безопасный snapshots root

**Files:**
- Modify: `src/cli.rs:377-409`
- Modify: `src/eval/runner.rs:103-147,245,673-684`

- [ ] **Step 1: Добавить failing unit tests для root и invocation**

Добавить в `src/eval/runner.rs` в существующий `#[cfg(all(test, unix))] mod tests` импорты `PermissionsExt`, `OsStringExt` и tests:

```rust
    #[test]
    fn snapshots_root_is_new_private_and_canonical() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("snapshots");
        let root = super::snapshots_root(Some(&path)).unwrap().unwrap();
        assert_eq!(root, std::fs::canonicalize(&path).unwrap().to_str().unwrap());
        assert_eq!(std::fs::metadata(&root).unwrap().permissions().mode() & 0o777, 0o700);
        assert!(super::snapshots_root(Some(&path)).is_err());
        assert!(super::snapshots_root(None).unwrap().is_none());
    }

    #[test]
    fn snapshots_root_rejects_symlinks_and_docker_unsafe_paths() {
        let temp = tempfile::tempdir().unwrap();
        let broken = temp.path().join("broken");
        std::os::unix::fs::symlink(temp.path().join("missing"), &broken).unwrap();
        assert!(super::snapshots_root(Some(&broken)).is_err());
        let target = temp.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let valid = temp.path().join("valid");
        std::os::unix::fs::symlink(&target, &valid).unwrap();
        assert!(super::snapshots_root(Some(&valid)).is_err());
        assert!(super::snapshots_root(Some(&temp.path().join("with,comma"))).is_err());
        let non_utf8 = temp.path().join(std::ffi::OsString::from_vec(vec![b's', 0xff]));
        assert!(super::snapshots_root(Some(&non_utf8)).is_err());
    }

    #[test]
    fn invocation_snapshots_are_opt_in() {
        let mut invocation = serde_json::json!({"version":1});
        super::attach_snapshots(&mut invocation, None);
        assert!(invocation.get("snapshots").is_none());
        super::attach_snapshots(&mut invocation, Some("/absolute/snapshots".to_owned()));
        assert_eq!(invocation["snapshots"], "/absolute/snapshots");
    }
```

В `src/cli.rs` добавить Clap parsing test через типизированные subcommands:

```rust
    #[test]
    fn eval_run_parses_snapshots() {
        let cli = Cli::try_parse_from([
            "rcode", "eval", "run", "--suite", "suite", "--report", "report",
            "--agent-binary", "agent", "--image", "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "--docker-socket", "socket", "--series", "series", "--snapshots", "output",
        ]).unwrap();
        let Some(Command::Eval { command: EvalCommand::Run(args) }) = cli.command else {
            panic!("expected eval run")
        };
        assert_eq!(args.snapshots, Some(PathBuf::from("output")));
    }
```

- [ ] **Step 2: Запустить tests и подтвердить RED**

Run: `cargo test --lib snapshots -- --nocapture`

Expected: компиляция падает, потому что `snapshots_root`, `attach_snapshots` и `EvalRun.snapshots` ещё не определены.

- [ ] **Step 3: Добавить CLI-поле и fail-closed реализацию**

В `EvalRun` после `report` добавить:

```rust
    #[arg(long, help = "Сохранить исходники кейсов в новый каталог для локального review")]
    pub snapshots: Option<PathBuf>,
```

В `src/eval/runner.rs` перед `run` добавить Unix implementation и stub для остальных targets:

```rust
#[cfg(unix)]
fn snapshots_root(path: Option<&Path>) -> Result<Option<String>> {
    use std::os::unix::fs::DirBuilderExt;
    let Some(path) = path else { return Ok(None) };
    let name = path.file_name().context("Нужен новый каталог snapshots")?;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let expected = fs::canonicalize(parent)?.join(name);
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path).context("Создание нового каталога snapshots")?;
    let root = fs::canonicalize(path)?;
    ensure!(root == expected, "Путь snapshots изменился при создании");
    let root = root.to_str().context("Путь snapshots должен быть UTF-8")?.to_owned();
    ensure!(!root.contains(','), "Путь snapshots не должен содержать запятую");
    Ok(Some(root))
}

#[cfg(not(unix))]
fn snapshots_root(_path: Option<&Path>) -> Result<Option<String>> {
    anyhow::bail!("Защищённый eval поддерживается только на Unix host")
}

fn attach_snapshots(invocation: &mut Value, snapshots: Option<String>) {
    if let Some(path) = snapshots {
        invocation["snapshots"] = json!(path);
    }
}
```

`DirBuilderExt::mode` задаёт `0700` атомарно с созданием; существующий file/dir/symlink отклоняется `create`. Canonical path сравнивается с ожидаемым, а UTF-8 и отсутствие запятой проверяются до provider setup и Docker case. Windows продолжает компилироваться и получает контролируемую ошибку вместо Unix-only символов.

В `run` сразу после проверки `args.report` добавить `let snapshots = snapshots_root(args.snapshots.as_deref())?;`. Создать `let mut invocation = json!(...)` с прежними полями и вызвать `attach_snapshots(&mut invocation, snapshots);` перед сериализацией.

- [ ] **Step 4: Проверить CLI и unit tests**

Run: `cargo test --lib snapshots -- --nocapture && cargo test --test eval_cli`

Expected: root/invocation/Clap tests и все существующие `eval_cli` tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cli.rs src/eval/runner.rs
git commit -m "feat(eval): добавить каталог для snapshots"
```

### Task 2: Постоянный snapshot в host runner

**Files:**
- Modify: `evals/host.py:343-349`
- Test: `tests/eval_host.py:239-303`

- [ ] **Step 1: Добавить failing host fixture**

Добавить в `HostConfigTests` test, который использует один настоящий `run_case` flow с fake Docker и проверяет destination и bind observer:

```python
    def test_run_case_uses_persistent_snapshot_for_observer_when_enabled(self):
        import host
        from unittest.mock import patch
        observation={'type':'observation','exit_code':0,'signal':None,'prepare_failed':False,
            'truncated':False,'timed_out':False,'cancelled':False,'leader_reaped':True,
            'pipes_complete':True,'stdout':base64.b64encode(b'true\n').decode()}
        class Channel:
            def __init__(self,frames):self.frames=frames
            def receive(self,timeout=None):return self.frames.pop(0)
            def close(self):pass
        class FakeDocker:
            uid=10001;cleanup_deadline=None
            def __init__(self):self.binds=[];self.channels=[[{'type':'storage_ready'}],[observation]]
            def volume(self,_size,_deadline):return 'volume'
            def create(self,binds,_deadline,**_kwargs):self.binds.append(binds);return 'container'
            def start(self,*_args,**_kwargs):return Channel(self.channels.pop(0))
            def archive(self,*_args):return b''
            def remove(self,*_args):pass
            def cleanup(self,*_args):pass
        done={'type':'agent_done','exit_code':0,'signal':None,'leader_reaped':True,'pipes_complete':True,
            'timed_out':False,'cancelled':False,'truncated':False,'forced':False}
        def phase(_docker,_invocation,_item,_volumes,gateway,_deadline,**_kwargs):
            gateway.generations=1;gateway.attempts=1
            gateway.receipts=[{'generation':1,'status':'received','http_status':200,'usage':None}]
            return {'done':done,'agent_reported_tool_successes':{},'session_id':None,'sentinel':False,'cancel_sent':False}
        case={'id':'persistent','language':'python','category':'fixture','timeout_secs':30,'max_steps':2,'max_requests':2}
        check={'id':'contract','argv':['true'],'stdin':'','timeout_secs':1,'expected_exit':0,'expected_json':True}
        item={'case':case,'sha256':'f'*64,'fixture':'/unused/fixture','task':'fixture','oracle':{'prepare':[],'checks':[check]}}
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);snapshots=root/'snapshots';snapshots.mkdir(mode=0o700)
            invocation={'effective_profile':{'kind':'local','model':'fixture','base_url':'http://127.0.0.1:9/v1','local':{}},'snapshots':str(snapshots)}
            docker=FakeDocker()
            with patch.object(host,'agent_phase',phase),patch.object(host,'extract_frozen',return_value='f'*64):
                result=host.run_case(docker,invocation,item,root/'temporary')
            expected=snapshots/'persistent'
            self.assertEqual(result['status'],'passed')
            self.assertTrue(expected.is_dir())
            self.assertEqual(docker.binds[1],{'/snapshot':expected})
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);temporary=root/'temporary';temporary.mkdir(mode=0o700)
            invocation={'effective_profile':{'kind':'local','model':'fixture','base_url':'http://127.0.0.1:9/v1','local':{}}}
            docker=FakeDocker()
            with patch.object(host,'agent_phase',phase),patch.object(host,'extract_frozen',return_value='f'*64):
                result=host.run_case(docker,invocation,item,temporary)
            self.assertEqual(result['status'],'passed')
            self.assertEqual(docker.binds[1],{'/snapshot':temporary/'persistent'})
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);snapshots=root/'snapshots';snapshots.mkdir(mode=0o700)
            temporary=root/'temporary';temporary.mkdir(mode=0o700)
            invocation={'effective_profile':{'kind':'local','model':'fixture','base_url':'http://127.0.0.1:9/v1','local':{}},'snapshots':str(snapshots)}
            docker=FakeDocker()
            with patch.object(host,'agent_phase',phase),patch.object(host,'extract_frozen',side_effect=OSError('synthetic write failure')):
                result=host.run_case(docker,invocation,item,temporary)
            self.assertEqual(result['status'],'blocked')
            self.assertIsNone(result['snapshot_sha256'])
            self.assertEqual(result['cleanup'],'confirmed_absent')
            self.assertFalse((temporary/'persistent').exists())
```

- [ ] **Step 2: Запустить fixture и подтвердить RED**

Run: `python3 tests/eval_host.py HostConfigTests.test_run_case_uses_persistent_snapshot_for_observer_when_enabled`

Expected: FAIL, потому что текущий host создаёт `<temporary>/persistent`, а не `<snapshots>/persistent`.

- [ ] **Step 3: Выбрать destination через invocation**

В `run_case` заменить только создание snapshot:

```python
        snapshot_root=Path(invocation['snapshots']) if invocation.get('snapshots') is not None else temporary
        snapshot=snapshot_root/case['id'];snapshot.mkdir(mode=0o700)
        result['snapshot_sha256']=extract_frozen(raw,snapshot)
```

Не менять `docker.archive`, порядок удаления keeper, `extract_frozen`, observer bind и verdict.

- [ ] **Step 4: Проверить host fixtures**

Run: `python3 tests/eval_host.py HostConfigTests && cargo test --test eval_cli`

Expected: новый fixture и все прежние HostConfigTests PASS; CLI tests не регрессируют.

- [ ] **Step 5: Commit**

```bash
git add evals/host.py tests/eval_host.py
git commit -m "feat(eval): сохранять исходники кейсов"
```

### Task 3: Docker end-to-end сохранение и документация

**Files:**
- Test: `tests/eval_host.py:468-503`
- Modify: `docs/usage.md:248-254`
- Modify: `AGENTS.md:45-49`

- [ ] **Step 1: Добавить failing Docker test**

Добавить в `HostTests`:

```python
    def test_persistent_snapshot_survives_case_and_matches_oracle(self):
        import host
        from unittest.mock import patch
        fixture=self.root/'fixture';fixture.mkdir(mode=0o755);(fixture/'value.txt').write_text('original')
        snapshots=self.root/'snapshots';snapshots.mkdir(mode=0o700)
        temporary=self.root/'temporary';temporary.mkdir(mode=0o700)
        profile={'base_url':'http://127.0.0.1:9/v1','model':'fixture','max_output_tokens':8,'request_timeout_secs':5,'idle_timeout_secs':5}
        item={'case':{'id':'persistent','language':'python','category':'fixture','timeout_secs':30,'max_steps':2,'max_requests':2},'sha256':'f'*64,'fixture':str(fixture),'task':'fixture',
            'oracle':{'prepare':[],'checks':[{'id':'value','argv':['python3','-I','-S','-c',"print(open('value.txt').read())"],'stdin':'','timeout_secs':3,'expected_exit':0,'expected_stdout':'changed\n'}]}}
        def phase(docker,_invocation,_item,volumes,gateway,deadline,**_kwargs):
            name=docker.create({'/fixture':fixture},deadline,volumes=volumes)
            channel=docker.start(name,{'mode':'agent','uid':10001,'gid':10001,'timeout_secs':10,'seed_project':True,'hold':True,'model':'fixture','profile_config':None,
                'argv':['python3','-I','-S','-c',"from pathlib import Path;Path('value.txt').write_text('changed')"]},deadline)
            try:
                while True:
                    done=channel.receive()
                    if done['type']=='agent_done':break
                docker.remove(name,deadline)
                gateway.generations=1;gateway.attempts=1
                gateway.receipts=[{'generation':1,'status':'received','http_status':200,'usage':None}]
                return {'done':done,'agent_reported_tool_successes':{},'session_id':None,'sentinel':False,'cancel_sent':False}
            finally:channel.close()
        with patch.object(host,'agent_phase',phase):
            result=host.run_case(self.docker,{'effective_profile':profile,'snapshots':str(snapshots)},item,temporary)
        self.assertEqual(result['status'],'passed')
        self.assertEqual((snapshots/'persistent/value.txt').read_text(),'changed')
        self.assertEqual((fixture/'value.txt').read_text(),'original')
        self.assertEqual(len(result['snapshot_sha256']),64)
        self.assertFalse(self.docker.active or self.docker.volumes)
```

- [ ] **Step 2: Запустить Docker end-to-end test**

Этот test подтверждает сохранение реального изменённого `/workspace`, использование того же snapshot oracle и очистку Docker. Unit RED для нового destination уже зафиксирован в Task 2; здесь ожидается end-to-end PASS без ослабления assertions.

Run:

```bash
RCODE_EVAL_DOCKER="$HOME/.local/bin/docker" \
RCODE_EVAL_SOCKET="$HOME/.orbstack/run/docker.sock" \
RCODE_EVAL_IMAGE=sha256:98de9b6855a361f8caaca0b266ce4b1f5eeef5ce803857127a339296e513f57e \
python3 tests/eval_host.py HostTests.test_persistent_snapshot_survives_case_and_matches_oracle
```

Expected: PASS; snapshot содержит `changed`, fixture остаётся `original`, Docker resources очищены.

- [ ] **Step 3: Задокументировать операторский сценарий**

Добавить в `docs/usage.md` перед «Хранение и ограничения»:

```markdown
## Snapshots изолированного eval

Для локального сравнения исходников добавьте `--snapshots` с новым каталогом к обычной команде `rcode eval run`. Каждый кейс сохраняется как `<каталог>/<case-id>/`; этот же snapshot используется независимым oracle. Существующий путь отклоняется, перезапись невозможна.

Сохраняется только `/workspace`, без `/agent-home`, credentials, OAuth-токенов и истории провайдера. Snapshots — локальные артефакты: выбирайте исключённый из Git каталог и не публикуйте их автоматически. Без `--snapshots` исходники по-прежнему удаляются вместе с временным каталогом. Для review используйте только кейсы с заполненным `snapshot_sha256`: частичный каталог после ошибки не является завершённым snapshot.
```

Добавить в раздел «Изолированный eval» `AGENTS.md`:

```markdown
- `--snapshots <новый-каталог>` сохраняет только `/workspace` каждого кейса для локального review через тот же `extract_frozen`, что и oracle. Существующий путь отклоняется; snapshots не входят в comparison key, не публикуются автоматически и не содержат `/agent-home` или credentials.
```

- [ ] **Step 4: Повторить полные проверки**

Run:

```bash
python3 evals/host_snapshot.py
python3 tests/eval_security.py
python3 tests/eval_provider.py
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo build --release --locked
```

Затем с теми же `RCODE_EVAL_*`:

```bash
python3 tests/eval_runtime.py
python3 tests/eval_host.py
python3 tests/eval_todo_controls.py
python3 tests/eval_controls.py
```

Expected: все команды PASS; TODO controls 1/1, прежние controls 30/30, residual containers/volumes отсутствуют.

- [ ] **Step 5: Commit**

```bash
git add tests/eval_host.py docs/usage.md AGENTS.md
git commit -m "test(eval): проверить сохранение snapshots"
```

### Task 4: Живая проверка сохранения и подготовка сравнения

**Files:**
- Local only: `artifacts/todo-eval/*/snapshots/` через существующий `.git/info/exclude`; не добавлять в Git.

- [ ] **Step 1: Проверить release binary identity**

Run: `target/release/rcode --version && git status --short --branch`

Expected: `rcode 0.9.3`; tracked/untracked source changes отсутствуют, локальные reports и snapshots исключены.

- [ ] **Step 2: Повторить один GigaChat run с новым флагом**

Сначала создать только parent: `mkdir -p artifacts/todo-eval/gigachat-snapshots`; сам `snapshots` должен создать CLI. Использовать прежние suite, Linux agent binary, image, budgets и profile; добавить только `--snapshots "$PWD/artifacts/todo-eval/gigachat-snapshots/snapshots"` и новые report/series. Не менять provider transport и не делать retry автоматически.

Expected: runner завершается сам; независимо от model PASS/FAIL при успешном экспорте `snapshots/todo-api/` содержит исходники, `snapshot_sha256` соответствует сохранённому дереву, cleanup подтверждён либо честно отмечен unknown.

- [ ] **Step 3: Проверить результат без публикации артефактов**

Run self-compare нового report и независимо вычислить digest сохранённого дерева тем же length-prefixed алгоритмом `D/X/F`, что использует `host_snapshot`, через локальный Python-скрипт: пройти каталог без следования symlink, собрать относительные UTF-8 пути, executable bit и содержимое файлов, затем сравнить SHA-256 с `cases[0].snapshot_sha256`. Также проверить отсутствие `rcode-eval-*` containers/volumes. Не читать credentials, не печатать provider responses и не добавлять snapshots в Git. Для review использовать дерево только при наличии валидного hash и совпадении digest.

- [ ] **Step 4: Зафиксировать ограничения и открыть PR**

Проверить владельца и `gh api user --jq .login` перед push. Открыть PR с изменениями Tasks 1–3, дождаться CI. Live model result приложить только как локальное резюме без публикации исходников или reports; сравнение качества Qwen/GigaChat выполнять после отдельного Qwen run с теми же настройками.

## Plan-eng-review resolutions

- Root создаётся атомарно с `0700`; existing file/dir/symlink, подмена canonical path, non-UTF-8 и comma отклоняются до provider setup. Descriptor-relative refactor `extract_frozen` не входит в план: Docker bind всё равно работает по пути, а параллельный процесс того же пользователя не является новой security boundary.
- Добавлены Clap/invocation, default destination и fail-closed fixtures, включая отсутствие fallback после `OSError`.
- Документация отличает завершённый snapshot с `snapshot_sha256` от частичного каталога после ошибки.
- В проверки добавлены `python3 evals/host_snapshot.py` и `python3 tests/eval_security.py`.
- Live-проверка создаёт parent заранее и независимо пересчитывает digest сохранённого дерева.
