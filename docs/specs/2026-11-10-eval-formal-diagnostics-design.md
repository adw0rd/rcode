# Диагностика formal violations изолированных eval-прогонов

## Контекст

TODO eval фиксирует категории `package_install`, `git`, `network` и `subagent`, но не сохраняет tool call, который их вызвал. В report остаются только `formal_violations` и SHA-256 потока agent log. После завершения runner невозможно отличить намеренный `pip install` модели от ошибки классификации конкретной команды.

Нужен явно включённый оператором локальный диагностический артефакт, который сохраняет минимальный receipt нарушения и при исправном I/O не меняет существующий report protocol, isolation, formal verdict или comparison key.

## Выбранный подход

Добавить `rcode eval run --diagnostics <новый-файл>`. Trusted host записывает в JSONL только события formal violations. Обычный report содержит summary с состоянием целостности, SHA-256 и счётчиками, но не команды и не host-путь.

Рассмотренные альтернативы:

- Добавить команды непосредственно в report: отклонено, поскольку report специально не содержит произвольный вывод и потенциально чувствительные аргументы модели.
- Сохранять полный agent JSONL: отклонено из-за объёма и наличия prompt history, tool output и других данных, не нужных для проверки policy.
- Записывать diagnostics всегда: отклонено; сохранение команд должно быть явным выбором оператора, как и сохранение snapshots.

## Интерфейс и безопасное открытие

- Аргумент `--diagnostics` принимает путь к новому файлу. Существующий file, directory или symlink не перезаписывается.
- После остальных preflight-проверок Rust создаёт файл через `OpenOptions::create_new` с правами `0600`. Родительский каталог должен уже существовать.
- Rust нормализует пути через canonical existing parent + `file_name`, проверяет UTF-8, отсутствие совпадения с `--report` и невложенность в `--snapshots`. Diagnostics не может находиться внутри snapshots case или попасть в их digest.
- В invocation по stdin передаются `path`, `dev` и `ino`; путь и identity не входят в report или comparison key.
- Host один раз открывает файл до первого кейса через `os.open` с `O_RDWR | O_APPEND | O_NOFOLLOW`, без `O_CREAT`, и держит descriptor весь прогон.
- `fstat` должен подтвердить regular file, совпадение `(dev, ino)`, `st_nlink == 1`, владельца текущего пользователя, права `0600` и нулевой начальный размер. Несовпадение отклоняет запуск до модели.
- Файл создаётся последним шагом перед запуском host. Если spawn не удался, Rust удаляет только созданный им пустой diagnostics file. Без `--diagnostics` invocation и report сохраняют прежнюю структуру.

Параллельный процесс с правами того же пользователя не является отдельной security boundary; identity-проверки предотвращают случайную подмену пути и запись не в тот файл между Rust и host.

## Формат событий

Каждая строка — самостоятельный JSON object с полями:

- `version`: всегда `1`;
- `case`: валидированный ID кейса;
- `generation`: 1-based номер последней доставленной контейнеру model generation, к чьему ответу относится tool start, либо `null`, если источник не связан с generation; следующий запрос в flight не увеличивает это значение;
- `category`: одна из категорий formal violation;
- `tool`: фактическое имя инструмента из `tool_start`;
- `call_id`: строковый ID tool call либо `null` для отсутствующего или невалидного ID;
- `call_id_truncated`: признак ограничения `call_id` до 256 байтов UTF-8 по корректной границе символа;
- `command`: исходная shell-команда для `run_command`, иначе `null`;
- `command_truncated`: признак ограничения длины команды.

Sidecar покрывает все текущие источники `formal_violations` в `policy.py`: shell-классификатор `run_command`, а также `spawn_agent` и `wait_agent`. Других post-case источников violations в текущей реализации нет. При добавлении нового источника policy обязан одновременно включить его в общую классификацию diagnostics и tests.

Для одного tool call с несколькими категориями создаётся отдельная строка на категорию. Повторные нарушающие вызовы тоже записываются. Категории имеют канонический порядок `package_install`, `git`, `network`, `subagent`, не зависящий от `PYTHONHASHSEED`.

Команда кодируется как UTF-8 с заменой lone surrogates, ограничивается ровно 4096 байтами и декодируется только до корректной границы символа. JSONL сериализуется с `ensure_ascii=True`, `allow_nan=False` и компактными separators, поэтому ANSI controls и Unicode line separators не создают дополнительных строк или terminal injection при просмотре.

Невалидный JSON arguments или нестроковый `command` не вызывает падение classifier/writer. Такой `run_command` не создаёт shell violation без подтверждённой запрещённой команды.

## Классификация

Общая чистая функция `tool_violations(receipt)` возвращает tuple категорий конкретного tool start в каноническом порядке. Для shell она использует временный state только внутри существующего `_classify_shell`; `observe_tool_start` не вызывает повторно обработку skills и не мутирует unrelated state.

`observe_tool_start` объединяет возвращённые категории с основным `violations` и из того же tuple формирует diagnostics. Это единственный источник категорий для report и sidecar. Обработка `load_skill`, `observe_tool_result` и `required_skills_met` не меняется.

## Лимиты и сериализация

- Для каждого кейса сохраняется не более 64 строк-событий; переполнение увеличивает `dropped` на число отброшенных категорий, а не tool calls.
- Если на границе лимита доступно меньше мест, чем категорий у вызова, категории обрабатываются в каноническом порядке: доступные строки записываются, остальные учитываются в `dropped`.
- Все события кейса сериализуются в один bounded bytes-buffer в памяти и записываются одной логической операцией append с циклом для partial writes.
- `events` в summary — ровно число полностью записанных JSONL строк. При `complete == true` он равен числу строк файла.
- `dropped` учитывает только превышение явного лимита событий. I/O errors не маскируются под `dropped`.

В sidecar не записываются environment, provider request/response, OAuth token, credentials, tool result, stdout/stderr или agent history. Команда всё равно может содержать чувствительные данные, поэтому файл является local-only артефактом `0600`; оператор выбирает исключённый из Git каталог и отдельно решает вопрос публикации.

## Запись, ошибки и финализация

Writer хранит `committed_offset`, инкрементальный SHA-256 и счётчики только для полностью завершённых case buffers. После каждого кейса он использует небуферизованный `os.write` и выполняет `fsync`; только после успешного `fsync` обновляет `committed_offset`, digest и число записанных событий.

При любой ошибке `write` или `fsync`:

1. Best-effort `ftruncate(committed_offset)` откатывает незавершённый case buffer, чтобы следующие записи не склеивались с оборванной JSON строкой.
2. Writer переходит в `poisoned`; дальнейшие writes запрещены.
3. Текущий кейс получает `blocked` с фиксированной причиной `diagnostics I/O failure` без host-пути, команды или текста `OSError`; Docker cleanup продолжается.
4. Оставшиеся кейсы получают `not_run` без нового model inference, поскольку явно запрошенный diagnostics artifact больше не может быть полным.
5. Итоговый summary имеет `complete: false`, `sha256: null`, `error: "diagnostics_io_error"` и счётчики только подтверждённо записанных/отброшенных лимитом событий.
6. При incomplete summary после `finish` все прежние `passed` дополнительно переводятся в `blocked` с той же причиной до подсчёта `counts`, поэтому Rust принимает и сохраняет честный fail-closed report.

При исправном I/O diagnostics не меняет formal/functional verdict. Fail-closed при ошибке explicitly requested artifact — отдельное поведение, а не скрытое изменение policy.

После последнего кейса неpoisoned writer выполняет финальный `fsync`, перечитывает descriptor с offset 0, проверяет размер, SHA-256 и число строк, закрывает descriptor и делает `fsync` родительского каталога. Только после успешной финализации host добавляет в stdout report `diagnostics` с `complete: true`, SHA-256, `events`, `dropped` и без `error`. Существующий Rust runner затем валидирует и атомарно сохраняет report через temp + `fsync` + `persist_noclobber`, как и прежде.

Прогон с нулём violations создаёт валидный пустой файл: `complete: true`, `events: 0`, `dropped: 0` и SHA-256 пустого содержимого `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Частичный sidecar с `complete: false` или без итогового summary не считается завершённым диагностическим артефактом. Fallback в report или другой файл отсутствует.

## Совместимость

- Версия report protocol и состав comparison key не меняются; SHA-256 `host.py` и `policy.py` обновляются как обычное отражение новой версии helpers.
- `validate_report` принимает top-level `diagnostics` только с описанной summary-схемой; PASS запрещён при `complete != true`, если diagnostics был запрошен. Runner отдельно проверяет `report.contains("diagnostics") == args.diagnostics.is_some()`; без флага поле отсутствует.
- Наличие флага не меняет comparison key для того же binary, suite, image и profile.
- С `--diagnostics` report не содержит команд, tool call arguments или абсолютного diagnostics path.
- Diagnostics не меняет policy classification, oracle, model budgets, transport или Docker cleanup и не делает красный кейс зелёным.

## Проверки

- Rust CLI: parsing, поздний `create_new`, права `0600`, существующий и dangling symlink, collision с report через symlink parent, запрет вложенности в snapshots, opt-in invocation и одинаковый comparison key с флагом/без него.
- Host open: подмена path на symlink/hardlink перед `os.open`, несовпадение `(dev, ino)`, wrong owner/mode/nlink/size.
- Policy fixtures: точная команда `python3 -m pip install …`, multi-category, повторные вызовы, 1-based generation, malformed arguments, детерминированный digest при разных `PYTHONHASHSEED`.
- Serialization: UTF-8 символ на границе 4095–4097 байт, lone surrogates, `U+2028`, ANSI controls, truncation и граница `63 + 2 категории -> events=64, dropped=1`.
- Host fixtures: sidecar/report separation, no-flag behavior, валидный empty sidecar, отсутствие path в container argv/env/mounts/snapshots и report.
- Multi-case failure: ошибка записи на втором кейсе из трёх, rollback до валидных строк первого, `blocked` второй, `not_run` третий без inference, cleanup, `complete:false`, `sha256:null` и отсутствие пути/команды в report.
- Docker fixture: digest независимо пересчитывается, report не содержит команду, контейнеры и volumes отсутствуют.
- Стандартные проверки: `cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --all-targets`, `cargo build --release --locked`, Python policy/security/provider.
- Собрать новый Linux binary и зафиксировать его SHA-256. Если `evals/Dockerfile` не изменился, использовать прежний полный `RCODE_EVAL_IMAGE=sha256:…`; при изменении image сначала пересобрать и зафиксировать новый digest.
- С явными `RCODE_EVAL_DOCKER`, `RCODE_EVAL_SOCKET` и полным `RCODE_EVAL_IMAGE` выполнить Docker runtime/host, TODO controls и все 30 основных controls без `RCODE_EVAL_CASES`; Docker-пропуски не считаются проверкой.
- После fixture-проверок выполнить один GigaChat TODO live с тем же image digest, новым Linux binary, `--snapshots` и `--diagnostics`; отдельно обозначить его как live, а не fixture.

## Не входит в задачу

- Изменение policy classification, task prompt, timeouts или model parameters.
- Сохранение полного agent JSONL, tool results или provider payloads.
- Автоматическая публикация diagnostics или snapshots.
- Обязательная пересборка Docker image без изменения `Dockerfile`.
- Повторный Qwen live-прогон без отдельной проверяемой гипотезы.
