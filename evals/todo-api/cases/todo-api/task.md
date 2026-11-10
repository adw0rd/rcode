Создай в `/workspace` FastAPI TODO API с ASGI-приложением `app.main:app` и хранением данных только в памяти процесса.

Перед реализацией явно вызови `load_skill` для всех трёх ID: `superpowers:using-superpowers`, `superpowers:test-driven-development`, `superpowers:verification-before-completion`. Их read-only источник подключён как `/workspace/skill-sources/superpowers`. Примени TDD: сначала тест и наблюдаемый RED, затем минимальная реализация и GREEN. Перед завершением выполни проверку результата по verification-before-completion.

Реализуй CRUD:
- `POST /todos` создаёт TODO; `GET /todos` возвращает список; `GET /todos/{id}` возвращает один элемент.
- `PATCH /todos/{id}` частично обновляет `title` и/или `completed`, включая переход `completed` из `true` в `false`.
- `DELETE /todos/{id}` удаляет элемент и возвращает ровно 204 без тела.
- Объект TODO содержит `id`, `title`, `completed`. ID — последовательные положительные целые, начиная с 1; удалённые ID не переиспользуются.
- `title` обязателен при создании. Обрезай пробельные символы по краям (`trim`) при POST и PATCH и сохраняй обрезанное значение. Длина после trim — от 1 до 200 символов включительно.
- `completed` при создании по умолчанию `false`.
- Пустой PATCH `{}` отклоняй со статусом 400. Явный `null` для `title` или `completed` в POST/PATCH отклоняй со статусом 400.
- Для отсутствующего ID при GET, PATCH и DELETE возвращай ровно статус 404 и JSON `{"detail":"Todo not found"}`.
- Невалидный POST и любой невалидный DELETE, включая DELETE отсутствующего ID, не должны расходовать следующий ID.

Напиши и сохрани тесты в проекте. Команда запуска тестов — строго `python3 -m pytest -q`, без других аргументов. Зависимости FastAPI, pytest и httpx уже установлены в image; создавать `requirements.txt` не требуется.

Запрещены network, pip и любые package installs, git, субагенты и изменения вне `/workspace`. Не изменяй `README.md` и ничего в `skill-sources`.
