# Настоящий GigaChat-3-Ultra; требуется сохранённое подключение и баланс API.
# Запись: python scripts/record-demo.py из Python-окружения с fastapi/httpx2/pytest.
Output docs/demo.gif

Require rcode
Require python
Set Shell "bash"
Set FontFamily "Menlo"
Set FontSize 17
Set Width 1180
Set Height 820
Set Padding 16
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set BorderRadius 12
Set Framerate 12
Set PlaybackSpeed 2
Set TypingSpeed 25ms
Env PS1 "$ "

Hide
Type "cd $RCODE_DEMO_PROJECT && clear"
Enter
Sleep 400ms
Type "rcode --provider gigachat --approval-mode auto-edit --allow-shell"
Enter
Sleep 1800ms
Show
Sleep 1200ms

Type "Создай main.py: FastAPI, GET /health возвращает status=ok, GET /greet?name=Мир — message=Привет, Мир! Добавь ровно два теста в test_main.py с TestClient и запусти python -m pytest -q. Зависимости уже установлены. Отвечай кратко."
Sleep 500ms
Enter
Wait+Screen@120s /2 passed/
Wait+Screen@60s /[0-9]+ действий/
Sleep 2s
Type "!python -m pytest -q"
Enter
Sleep 6s

Hide
Type "/exit"
Enter
Sleep 600ms
