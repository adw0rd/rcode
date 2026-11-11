# Выравнивание задания TODO API и HTTP oracle

## Контекст

Live-прогон GigaChat завершился со статусом `failed`, потому что независимый `http-crud-contract` не прошёл. На сохранённом snapshot oracle воспроизводимо останавливается после 10 секунд ожидания health-check. При этом задание не требует endpoint `/health`, который oracle проверяет первым.

Дополнительные запросы к snapshot подтвердили нарушения уже видимого задания: принятие `completed: null` и проверку максимальной длины title до trim. Отсутствие `/health` и возврат `400` вместо ожидаемых oracle `422` нельзя отнести к дефектам модели: этих требований в задании не было. Старый report сохраняется как материал разбора, но не является чистой оценкой качества модели или сопоставимым baseline. Snapshot и прошлый report не исправляются.

Инженерное ревью также обнаружило недокументированные требования oracle: статус 201 для POST, статусы 200 для GET/PATCH, ровно три поля объекта, порядок создания в списке и приоритет 404 для отсутствующего ID над проверкой тела PATCH.

## Решение

Выровнять видимое задание под существующий строгий oracle. Не ослаблять проверки и не менять сгенерированные snapshots или прошлые reports.

В `evals/todo-api/cases/todo-api/task.md` явно указать весь проверяемый HTTP-контракт:

- `GET /health` возвращает статус 200 и ровно JSON `{"status":"ok"}`;
- POST возвращает 201, GET и PATCH возвращают 200, DELETE возвращает 204 без тела;
- объект TODO содержит ровно `id`, `title`, `completed`, а список сохраняет порядок создания;
- отсутствие ключа `title` в теле POST возвращает 422;
- строковый `title` с длиной после trim вне диапазона 1–200 возвращает 422 при POST и PATCH;
- явный `null` для `title` или `completed` возвращает 400 при POST и PATCH; это отдельное правило, не входящее в предыдущие статусы 422;
- пустой PATCH существующего ID возвращает 400;
- для отсутствующего ID GET, PATCH и DELETE возвращают 404 независимо от тела запроса: проверка ID предшествует проверке PATCH.

Изменение документирует уже существующие проверки и не добавляет новых требований к oracle. `/health` остаётся служебным endpoint для readiness и проверки eval, а не новым доменным объектом.

## Regression test

В `tests/eval_todo_controls.py` добавить host-only тест `test_task_documents_observable_http_contract`. Он читает `task.md` и через `assertIn` проверяет точные полные строки, добавленные для каждого правила из раздела «Решение»: health, CRUD-статусы, ровно три поля, порядок создания, отсутствие ключа title, 422 для строковых значений, 400 для явного null и приоритет 404. Точные строки здесь являются публичным prompt-контрактом, поэтому их изменение должно быть осознанным, а не случайным перефразированием.

До изменения `task.md` тест должен падать на первом отсутствующем правиле, после — проходить. Существующий тест продолжит проверять идентичность встроенного oracle-скрипта и `check_api.py`. Функциональные HTTP assertions остаются в oracle и Docker controls; новый host-only тест защищает именно видимость контракта модели. AST/regex-парсинг oracle не добавляется: он усложняет тест, но не доказывает смысловое соответствие естественно-язычного задания и HTTP assertions.

## Проверка

1. Запустить новый contract test до исправления и зафиксировать RED.
2. Обновить задание и получить GREEN через `python3 tests/eval_todo_controls.py TodoOracleContractTests`.
3. Запустить TODO controls с явными `RCODE_EVAL_DOCKER`, `RCODE_EVAL_SOCKET` и полным `RCODE_EVAL_IMAGE=sha256:…`; потребовать вывод `1/1 functional controls`. Пропуски без этих env не засчитывать как Docker GREEN.
4. Запустить общий eval controls corpus, host tests и `rcode eval validate --suite evals/todo-api/manifest.json`.
5. Выполнить стандартные проверки проекта для итоговой ветки.
6. После публикации изменения выполнить новые GigaChat и Qwen live-прогоны с одинаковыми commit и Linux binary SHA-256, immutable image, suite/case hashes, skill-sources, бюджетами шагов/запросов/времени, настройками thinking/effort и включённым diagnostics. Зафиксировать способ запуска Qwen и выбранный local profile; provider и model различаются по условию эксперимента.
7. Сравнивать свежие reports вручную по HTTP oracle, formal violations, генерациям, вызовам инструментов и коду: `rcode eval compare` намеренно отклоняет разные provider/model comparison keys. Один прогон на модель — качественный пример, а не статистическая оценка; старый GigaChat report не использовать как baseline.

`manifest.json` содержит пути и бюджеты, но не pinned digest кейса, поэтому обновление digest или `suite_version` в manifest не требуется. Runner сам вычисляет `suite_sha256` и `case_sha256` и помещает их в comparison key; разные suite keys не проходят встроенное сравнение.

## Ограничения

- `evals/todo-api/oracles/check_api.py`, встроенный oracle JSON и positive control не меняются.
- Код GigaChat в `artifacts/` не исправляется и не публикуется.
- Дефекты преобразования неподдерживаемых типов, которые oracle не проверяет, не добавляются в эту задачу.
- Live-прогоны отличаются от локальных Docker controls и не заменяются ими.

## Engineering review 2026-11-11

Target: эта спецификация и существующие `task.md`, `check_api.py`, positive control и `eval_todo_controls.py`.

Scope Challenge: scope accepted as-is. Два предполагаемых файла реализации, новых классов и сервисов нет. Вопросы декомпозиции не требуются.

### Findings and dispositions

1. [P1] (confidence: 9/10) `task.md:6`, `check_api.py:80` — скрытый статус 201 для POST. Принято Claude и Carbon; добавлено в T1.
2. [P1] (confidence: 9/10) `task.md:12-13`, `check_api.py:172-177` — приоритет 404 для пустого PATCH отсутствующего ID. Принято Claude и Carbon; добавлено в T1.
3. [P2] (confidence: 8/10) `check_api.py:82-103` — ровно три поля, порядок создания и статусы 200 не были видимы. Принято; добавлено в T1.
4. [P2] (confidence: 9/10) исходный раздел «Regression test» — проверка только health/422 пропускала остальные prompt-правила. Исправлено: T2 покрывает все добавленные строки. AST/regex-парсинг oracle отклонён как более сложный, но не доказывающий semantic parity.
5. [P2] (confidence: 10/10) предложение обновлять pinned digest в manifest отклонено: `manifest.json:1-21` не содержит digest, а `src/eval/runner.rs:380` и `src/eval/runner.rs:866` вычисляют и сравнивают hashes.
6. [P2] (confidence: 9/10) условия live-сравнения были неполными. Добавлены binary/image/suite/skill/budget/thinking/profile инварианты и ограничение одного качественного прогона.
7. [P2] (confidence: 10/10) `tests/eval_todo_controls.py:26` — Docker проверка может быть пропущена без env. В проверку добавлены обязательные env и явный success marker.
8. [P2] (confidence: 9/10) исходный контекст смешивал дефекты модели и последствия скрытого контракта. Формулировки разделены; отсутствие ключа title отделено от явного null.

### Architecture review

Три finding: скрытые CRUD-статусы, форма ответов и приоритет 404. Runtime-архитектура не меняется; исправления находятся на границе prompt → модель → независимый HTTP oracle. Новых интеграций и production failure paths нет.

### Code quality review

Один finding: неоднозначная атрибуция ошибок модели и пересечение null/422. Исправлено в контексте и правилах. Shared code, новые abstractions и implementation code не предлагаются.

### Test review

Framework: Python `unittest` для host/Docker controls, независимый HTTP oracle и live eval для prompt-изменения.

```
CODE PATHS                                           USER FLOWS
[+] evals/todo-api/cases/todo-api/task.md            [+] Модель читает задание
  ├── [GAP → T2] health + точный JSON                  ├── [→EVAL] Реализация /health
  ├── [GAP → T2] CRUD statuses + форма ответа          ├── [→EVAL] CRUD и список
  ├── [GAP → T2] missing key / null / 422              ├── [→EVAL] Validation errors
  └── [GAP → T2] 404 до проверки PATCH                 └── [→EVAL] Missing ID + empty body
[+] tests/eval_todo_controls.py
  ├── [★★★ TESTED] embedded oracle == check_api.py
  └── [GAP → T2] точные строки prompt-контракта
[+] Docker controls
  ├── [★★★ TESTED] negative fixture rejected
  └── [★★★ TESTED] positive control passed

COVERAGE: 0/4 новых prompt-групп пока имеют assertions; 2 Docker controls существуют
GAPS: 4 prompt-группы и 2 свежих live eval; производственные E2E не требуются
```

Value: protects=видимый prompt-контракт; fails_when=удалено обязательное правило; why_new=текущий тест сверяет только oracle-скрипт; seam=none.

Tests made obsolete: none. Test Plan Artifact: `/Users/colinfrl/.gstack/projects/rcode/colinfrl-fix-todo-api-oracle-contract-eng-review-test-plan-20261111-103218.md`.

### Performance review

No issues found. Изменяются Markdown и линейные проверки подстрок; runtime и объём обрабатываемых данных не меняются.

### Outside voice

Claude Sonnet 5.5 High через `agy`: completed, 8 findings. Carbon High: timeout без findings. Carbon Medium: timeout после 5 полных findings и начала шестого; результат учтён только как partial, completed coverage не засчитан. Пересечения Claude и partial Carbon по 201, 404, regression test и live-сопоставимости подтверждены независимым чтением кода. Согласие моделей не использовалось как доказательство без source evidence.

### NOT in scope

- Изменение oracle или ослабление assertions: выбрано документирование существующего контракта.
- Исправление старых model snapshots: артефакты остаются доказательством исходного прогона.
- Дополнительные типы и новые HTTP-требования: oracle их не проверяет.
- Несколько платных повторов для статистики: текущая цель — качественный пример на свежем suite.

### What already exists

- `check_api.py` и встроенный oracle JSON проверяют поведение через реальные HTTP calls.
- Positive/negative Docker controls подтверждают, что oracle отклоняет исходник и принимает эталон.
- `TodoOracleContractTests` сверяет embedded script с файлом.
- Runner вычисляет suite/case hashes; обновление manifest digest не требуется.

### Failure modes

Неверный или неполный prompt приводит к видимому `failed` независимого oracle, а не к молчаливому production сбою. После T1/T2 все выявленные скрытые требования получают prompt assertions. Critical gaps: 0.

### Worktree parallelization strategy

Sequential implementation, no parallelization opportunity.

## Implementation Tasks

- [x] **T1 (P1, human: ~30min / CC: ~5min)** — eval contract — документировать полный HTTP-контракт TODO API
  - Surfaced by: Architecture findings 1–3
  - Files: `evals/todo-api/cases/todo-api/task.md`, эта спецификация
  - Verify: `python3 tests/eval_todo_controls.py TodoOracleContractTests`
- [x] **T2 (P1, human: ~30min / CC: ~5min)** — tests — добавить prompt-contract regression test
  - Surfaced by: Test review finding 4
  - Files: `tests/eval_todo_controls.py`
  - Verify: RED до T1, GREEN после T1, затем Docker controls с success marker
- [x] **T3 (P2, human: ~1h / CC: ~15min)** — eval — проверить controls и сопоставимые live-прогоны
  - Surfaced by: Test review findings 6–7
  - Files: эта спецификация; manifest только читается
  - Verify: общий controls corpus, host tests, eval validate и свежие GigaChat/Qwen runs

JSONL: `/Users/colinfrl/.gstack/projects/rcode/tasks-eng-review-20261111-103218.jsonl`.

## Decision ledger

R1–R8: исходное решение пользователя «вариант 1» уже одобряет выравнивание задания с существующим oracle и необходимые tests/docs. Принятые уточнения не меняют runtime и не расширяют oracle. Отклонённые предложения: manifest digest update и AST/regex-парсинг oracle.

Approval readiness: PASS; R1–R8 покрыты исходным approval и подтверждены source evidence. Pending remedies: none.

## Completion summary

- Step 0: Scope Challenge — scope accepted as-is
- Architecture Review: 3 issues found and mapped
- Code Quality Review: 1 issue found and mapped
- Test Review: diagram produced, 3 gaps groups identified
- Performance Review: 0 issues found
- NOT in scope: written
- What already exists: written
- TODOS.md updates: 0 items proposed
- Failure modes: 0 critical gaps flagged
- Unresolved decisions: 0 in this review
- Outside voice: Claude completed; Carbon unavailable after two timeouts, partial findings retained
- Parallelization: 1 lane, 0 parallel / 3 sequential tasks
- Lake Score: N/A, coverage choices не задавались
- Durable learning: hidden oracle assertions должны быть отражены в видимом prompt-контракте; записано в gstack learnings

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | — | Scope & strategy | 0 | — | — |
| Outside Review | Claude + Carbon via `agy` | Independent 2nd opinion | 3 | completed / partial unavailable | Claude: 8; Carbon: 5 partial |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 1 | COMPLETE | 7 issues mapped to T1–T3 и закрыты реализацией, 0 critical gaps |
| Design Review | — | UI/UX gaps | 0 | — | — |
| DX Review | — | Developer experience gaps | 0 | — | — |

- **OUTSIDE COVERAGE:** Claude via `agy`, plan review completed with 8 findings; Carbon high/medium unavailable by timeout, 5 partial findings retained without completed coverage.
- **CROSS-MODEL:** Claude и partial Carbon совпали по 201, 404, regression test и live inputs; каждое совпадение проверено по исходникам.
- **VERDICT:** IMPLEMENTATION COMPLETE — T1–T3 выполнены и опубликованы в PR #8, merge commit `c5965cfc82e0760aab5267adf24b6d3bf857c92f`.

## Implementation result 2026-11-12

- Regression-тест дал RED по восьми отсутствующим строкам до изменения задания и GREEN после него. Host contract tests: 2 теста OK.
- TODO Docker controls: `1/1 functional controls`; общий corpus: `30/30`; runtime: 11 тестов OK; host: 34 теста OK.
- `eval validate`, `cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings` и `cargo test --all-targets` прошли на итоговом implementation diff. Все CI checks PR #8 зелёные перед merge.
- Свежие live-прогоны использовали одинаковые binary SHA-256, image, suite/case hashes, helpers и budgets. У обоих observed required skills и ноль formal violations; cleanup `confirmed_absent`.
- GigaChat: независимый HTTP oracle PASS, но общий verdict failed из-за исчерпания 48 генераций. Собственные тесты snapshot: 4 failed, 20 passed; отдельно подтверждено частичное изменение title при PATCH, который возвращает 400 из-за `completed: null`.
- Qwen: общий verdict failed из-за 600-секундного deadline после 8 полученных и 1 отменённой генерации. Snapshot содержит только пустое FastAPI-приложение и fixture, HTTP oracle FAIL, тестов нет. Это timeout, а не exchange failure; budgets не изменялись.
- Live-прогоны являются одним качественным примером на модель, а не статистической оценкой. Старый GigaChat report не использовался как baseline.

NO UNRESOLVED DECISIONS
