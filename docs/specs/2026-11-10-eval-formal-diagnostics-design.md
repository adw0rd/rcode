# Диагностика formal violations изолированных eval-прогонов

## Контекст

TODO eval фиксирует категории `package_install`, `git`, `network` и `subagent`, но не сохраняет tool call, который их вызвал. В report остаются только `formal_violations` и SHA-256 потока agent log. После завершения runner невозможно отличить намеренный `pip install` модели от ошибки классификации конкретной команды.

Нужен явно включённый оператором локальный диагностический артефакт, который сохраняет минимальный receipt нарушения и не меняет существующий report, isolation, verdict или comparison key.

## Выбранный подход

Добавить `rcode eval run --diagnostics <новый-файл>`. Trusted host записывает в JSONL только события formal violations. Публичный report содержит SHA-256 и технические счётчики diagnostics, но не команды и не host-путь.

Рассмотренные альтернативы:

- Добавить команды непосредственно в report: отклонено, поскольку report специально не содержит произвольный вывод и потенциально чувствительные аргументы модели.
- Сохранять полный agent JSONL: отклонено из-за объёма и наличия prompt history, tool output и других данных, не нужных для проверки policy.
- Записывать diagnostics всегда: отклонено; сохранение команд должно быть явным выбором оператора, как и сохранение snapshots.

## Интерфейс и жизненный цикл файла

- Аргумент `--diagnostics` принимает путь к новому файлу. Существующий file, directory или symlink не перезаписывается.
- Rust runner создаёт файл с правами `0600` через `create_new` до запуска модели, проверяет canonical path, UTF-8 и отсутствие совпадения с `--report`. Родительский каталог должен уже существовать.
- Trusted host получает путь только через invocation по stdin. Путь не входит в report и comparison key.
- Host дописывает JSONL после каждого кейса, вызывает `flush` и `fsync`; после успешного завершения всех кейсов report получает `diagnostics` с полями `sha256`, `events` и `dropped`.
- Без `--diagnostics` поле invocation отсутствует, файл не создаётся, а структура report остаётся прежней.
- Частичный sidecar без итогового `diagnostics.sha256` не считается завершённым диагностическим артефактом.

## Формат событий

Каждая строка — самостоятельный JSON object с полями:

- `version`: всегда `1`;
- `case`: валидированный ID кейса;
- `generation`: номер model generation на момент tool start;
- `category`: одна из категорий formal violation;
- `tool`: `run_command`, `spawn_agent` или `wait_agent`;
- `call_id`: ID tool call;
- `command`: исходная shell-команда для `run_command`, иначе `null`;
- `command_truncated`: признак ограничения длины команды.

Для одного tool call с несколькими категориями создаётся отдельная строка на категорию. Повторные нарушающие вызовы тоже записываются: diagnostics не должна терять более позднюю команду только потому, что категория уже встречалась.

События сохраняются в порядке наблюдения. Для каждого кейса сохраняется не более 64 событий; команда ограничивается 4096 байтами UTF-8 с корректной границей символа. Превышение лимита событий увеличивает `dropped`, а не удаляет уже записанные данные и не меняет formal verdict.

В sidecar не записываются environment, provider request/response, OAuth token, credentials, tool result, stdout/stderr или agent history. Команда всё равно может содержать чувствительные данные, поэтому файл является local-only артефактом `0600`; оператор выбирает исключённый из Git каталог и отдельно решает вопрос публикации.

## Поток данных

1. `agent_phase` получает `tool_start` и передаёт в policy текущий generation.
2. Policy классифицирует shell-команду в отдельном temporary violation state, объединяет категории с основным state и формирует diagnostics для категорий конкретного вызова.
3. Основной state по-прежнему вычисляет `formal_violations` и `required_skills_observed` без изменений.
4. После кейса host сериализует bounded events в JSONL, обновляет общий SHA-256 и счётчики, затем освобождает память кейса.
5. Runner проверяет, что report не содержит diagnostics commands, и сохраняет прежний report с дополнительным техническим `diagnostics` summary при включённой опции.

## Обработка ошибок

- Невозможность безопасно создать diagnostics файл отклоняет запуск до модели и Docker case.
- Ошибка append, flush или `fsync` делает diagnostics незавершённой и запрещает PASS для затронутого кейса; причина публикуется как фиксированный класс без текста команды или host-пути. Docker cleanup продолжается.
- Незаметного fallback в report или другой файл нет.
- Лимиты diagnostics не скрываются: потерянные события отражаются в `dropped`.
- Включение diagnostics не меняет policy, oracle, model budgets, transport и не ослабляет удаление контейнеров и volumes.

## Совместимость

- Версия report protocol и состав comparison key не меняются; SHA-256 `host.py` и `policy.py` в comparison key обновляются как обычное отражение новой версии helpers.
- Без флага поведение invocation и report сохраняется.
- С `--diagnostics` report не содержит самих команд, tool call arguments или абсолютного diagnostics path.
- Наличие diagnostics само по себе не делает красный кейс зелёным: это наблюдение, а не исправление модели или policy.

## Проверки

- Rust CLI: parsing `--diagnostics`, `create_new`, права `0600`, отказ существующего пути и совпадения с report, opt-in invocation.
- Policy fixtures: точная команда `python3 -m pip install …`, несколько категорий одного вызова, повторные вызовы, generation, UTF-8 truncation и лимит событий.
- Host fixtures: JSONL записывается отдельно, report содержит только summary, без флага diagnostics отсутствует, ошибка записи не даёт PASS и не мешает cleanup.
- Docker fixture: после кейса sidecar доступен на host, digest независимо пересчитывается, report не содержит команду, контейнеры и volumes отсутствуют.
- Стандартные проверки проекта: `cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --all-targets`, `cargo build --release --locked`, Python policy/security/provider, Docker runtime/host и controls.
- После fixture-проверок выполнить один диагностический live-прогон GigaChat TODO с новым Linux binary, `--snapshots` и `--diagnostics`; отдельно обозначить его как live, а не fixture.

## Не входит в задачу

- Изменение policy classification, task prompt, timeouts или model parameters.
- Сохранение полного agent JSONL, tool results или provider payloads.
- Автоматическая публикация diagnostics или snapshots.
- Повторный Qwen live-прогон без отдельной проверяемой гипотезы.
