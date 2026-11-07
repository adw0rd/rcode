"""User-defined commands in a real PTY: menu completion, expansion with
arguments, builtin shadowing, unsupported syntax notice, /help and /skill.
Loopback fixtures only; no live model."""

import fcntl
import http.server
import json
import os
from pathlib import Path
import pty
import signal
import struct
import sys
import tempfile
import termios
import threading
import time
import traceback

sys.dont_write_bytecode = True
from terminal_pty import LoopbackHTTPServer, Terminal, interrupted


class CommandTerminal(Terminal):
    def __init__(self, binary, workspace, home, args):
        self.buffer = bytearray()
        self.offset = 0
        self.status = None
        self.grid = __import__("viewport_vt", fromlist=["Viewport"]).Viewport(140, 30)
        self.snapshots = {}
        self.control_tail = b""
        self.used_alternate_screen = False
        self.queried_cursor = False
        self.pid, self.master = pty.fork()
        if self.pid == 0:
            try:
                fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 140, 0, 0))
                os.environ.clear()
                os.environ.update({"PATH": "/usr/bin:/bin", "TERM": "xterm-256color",
                                   "LANG": "C.UTF-8", "RCODE_HOME": str(home),
                                   "RCODE_CUSTOM_API_KEY": "cmd-pty-synthetic-key"})
                os.execv(binary, [binary, "-C", str(workspace), *args])
            finally:
                os._exit(127)
        self.initial_termios = termios.tcgetattr(self.master)

    def finished(self, code=0):
        end = time.monotonic() + 4
        while self.status is None and time.monotonic() < end:
            self.pump()
        assert self.status == code, f"Exit {self.status}, expected {code}: {self.text()}"
        self.pump(0)
        assert termios.tcgetattr(self.master) == self.initial_termios, "TTY mode not restored"


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path != "/v1/models":
            return self.reply(404, {"error": "not found"})
        self.reply(200, {"data": [{"id": "cloud-model"}]})

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        self.server.requests.append(json.loads(body))
        # Each turn has a distinct response: old screen contents must never
        # satisfy a wait for a request that has not reached the server yet.
        response = f"CMD_PTY_OK_{len(self.server.requests)}"
        self.reply(200, {"choices": [{"message": {"role": "assistant", "content": response},
                                      "finish_reason": "stop"}],
                         "usage": {"prompt_tokens": 900, "completion_tokens": 3}})


def last_user_prompt(server):
    posts = [r for r in server.requests if r.get("model")]
    return next(message["content"] for message in reversed(posts[-1]["messages"])
                if message["role"] == "user")


def main(binary):
    fixture = LoopbackHTTPServer(("127.0.0.1", 0), Handler)
    fixture.daemon_threads = True
    fixture.requests = []
    worker = threading.Thread(target=fixture.serve_forever, daemon=True)
    worker.start()
    try:
        with tempfile.TemporaryDirectory(prefix="rcode-commands-pty-") as temporary:
            root = Path(temporary)
            workspace = root / "project"
            workspace.mkdir()
            home = root / "home"
            home.mkdir(mode=0o700)
            config = {"version": 1, "active": "custom",
                      "providers": {"custom": {"kind": "custom", "model": "cloud-model",
                                               "base_url": f"http://127.0.0.1:{fixture.server_port}/v1"}}}
            (home / "config.json").write_text(json.dumps(config))
            (home / "config.json").chmod(0o600)

            commands = home / "commands"
            (commands / "git").mkdir(parents=True)
            (commands / "git" / "pr.md").write_text(
                "Подготовь PR для задачи $1. Дополнительно учти: $ARGUMENTS\n")
            (commands / "deploy.md").write_text(
                "---\ndescription: Задеплоить ветку\nargument-hint: \"[окружение]\"\n---\n"
                "Задеплоить $ARGUMENTS\n")
            project_commands = workspace / ".rcode" / "commands"
            project_commands.mkdir(parents=True)
            (project_commands / "run.md").write_text(
                "Запусти !`touch MARKER` и все тесты $ARGUMENTS\n")
            (project_commands / "permissions.md").write_text("подмена разрешений\n")
            skill = home / "skills" / "writer" / "SKILL.md"
            skill.parent.mkdir(parents=True)
            skill.write_text("---\nname: writer\ndescription: Пишет тексты\n---\nТело скилла\n")
            browse = home / "skill-sources" / "rstack" / "browse" / "SKILL.md"
            browse.parent.mkdir(parents=True)
            browse.write_text("---\nname: browse\ndescription: Открыть браузер\n---\nТело скилла\n")
            (home / "skills.json").write_text(json.dumps({
                "version": 1,
                "sources": {"rstack": {
                    "kind": "dir", "url": "/fixture/rstack", "ref": None,
                    "commit": "fixture", "skills_root": "", "tree_sha256": "fixture",
                    "package_version": None, "installed_at": 0, "updated_at": 0, "only": [],
                }},
            }))

            terminal = CommandTerminal(binary, workspace, home, [])
            try:
                terminal.until(terminal.editor_ready, "initial composer")
                terminal.assert_footer("cloud-model", "custom")

                # 1. Menu shows the custom command; Tab completes it.
                terminal.send("/gi")
                terminal.until(lambda: any("/git:pr" in row for row in terminal.grid.rows()),
                               "menu with the custom command")
                menu_rows = [row for row in terminal.grid.rows() if "/git:pr" in row]
                assert menu_rows, terminal.dump()
                terminal.send("\t")
                terminal.until(lambda: any("/git:pr" in row for row in terminal.grid.rows())
                               and not any("Команды ·" in row for row in terminal.grid.rows()),
                               "Tab completed the command name")
                terminal.send(" 42 \"две части\"\r")
                terminal.expect_body("CMD_PTY_OK_1")
                terminal.until(terminal.editor_ready, "composer after the expanded command")
                assert last_user_prompt(fixture) == (
                    "Подготовь PR для задачи 42. Дополнительно учти: 42 \"две части\""), fixture.requests

                # Mentioning the short alias without Tab is ordinary prose.
                terminal.send("Что делает /browse?\r")
                terminal.expect_body("CMD_PTY_OK_2")
                terminal.until(terminal.editor_ready, "composer after ordinary alias mention")
                assert last_user_prompt(fixture) == "Что делает /browse?", fixture.requests

                # The short alias is a command only at the beginning of a line.
                terminal.send("/browse открой сайт\r")
                terminal.expect_body("CMD_PTY_OK_3")
                terminal.until(terminal.editor_ready, "composer after start-of-line skill alias")
                prompt = last_user_prompt(fixture)
                assert "rstack:browse" in prompt and "открой сайт" in prompt, prompt
                browse_messages = [r for r in fixture.requests if r.get("model")][-1]["messages"]
                assert browse_messages[-2]["role"] == "assistant", browse_messages
                assert browse_messages[-2]["tool_calls"][0]["function"]["name"] == "load_skill", browse_messages
                assert browse_messages[-1]["role"] == "tool", browse_messages
                assert "Тело скилла" in browse_messages[-1]["content"], browse_messages

                # Inline skills complete from a unique alias to their canonical ID.
                terminal.send("Пожалуйста, открой /bro")
                terminal.send("\t")
                terminal.until(
                    lambda: any("Пожалуйста, открой /rstack:browse" in row
                                 for row in terminal.grid.rows()),
                    "inline skill alias completed to canonical ID",
                )
                terminal.send(" потом продолжи\r")
                terminal.expect_body("CMD_PTY_OK_4")
                terminal.until(terminal.editor_ready, "composer after inline skill request")
                prompt = last_user_prompt(fixture)
                assert prompt == "Пожалуйста, открой /rstack:browse потом продолжи", prompt

                # 2. Unsupported syntax is passed literally and reported once.
                terminal.send("/run проверь\r")
                terminal.expect_body("CMD_PTY_OK_5")
                terminal.until(terminal.editor_ready, "composer after /run")
                assert last_user_prompt(fixture) == "Запусти !`touch MARKER` и все тесты проверь", fixture.requests
                assert "не исполняется" in terminal.text(), terminal.dump()
                assert not (workspace / "MARKER").exists(), "inline shell must not run"

                # 3. The builtin permissions command is not shadowed by a file.
                mark = terminal.mark()
                terminal.send("/permissions\r")
                terminal.until(lambda: "Разрешения" in terminal.text(mark),
                               "builtin permissions picker")
                assert "подмена разрешений" not in terminal.text(mark), terminal.text(mark)
                terminal.send("\x1b")
                terminal.until(terminal.editor_ready, "composer after permissions")

                # 4. /skill names the resolved skill in the request and preloads it.
                terminal.send("/skill writer проверь текст\r")
                terminal.expect_body("CMD_PTY_OK_6")
                terminal.until(terminal.editor_ready, "composer after /skill")
                assert "writer" in last_user_prompt(fixture), fixture.requests
                writer_messages = [r for r in fixture.requests if r.get("model")][-1]["messages"]
                assert writer_messages[-2]["role"] == "assistant", writer_messages
                assert writer_messages[-2]["tool_calls"][0]["function"]["name"] == "load_skill", writer_messages
                assert writer_messages[-1]["role"] == "tool", writer_messages
                assert "Тело скилла" in writer_messages[-1]["content"], writer_messages

                # 5. /help lists custom commands.
                mark = terminal.mark()
                terminal.send("/help\r")
                terminal.until(lambda: "Пользовательские команды" in terminal.text(mark),
                               "/help custom section")
                help_text = terminal.text(mark)
                assert "/git:pr" in help_text and "/deploy" in help_text, help_text
                assert "· проект" in help_text, help_text
                assert "подмена разрешений" not in help_text, help_text
                terminal.until(terminal.editor_ready, "composer after /help")

                terminal.send("/exit\r")
                terminal.finished()

                assert not (workspace / "MARKER").exists()
                posts = [r for r in fixture.requests if r.get("model")]
                assert len(posts) == 6, len(posts)
                assert all(r["model"] == "cloud-model" for r in posts)
            finally:
                terminal.close()

            plain = CommandTerminal(binary, workspace, home, ["--plain"])
            try:
                plain.expect("rcode ›")
                mark = plain.mark()
                plain.send("Пожалуйста, открой /bro\t")
                plain.expect("Пожалуйста, открой /rstack:browse", mark)
                plain.send(" потом продолжи\r")
                plain.expect_body("CMD_PTY_OK_7")
                assert last_user_prompt(fixture) == "Пожалуйста, открой /rstack:browse потом продолжи"
                plain.send("/exit\r")
                plain.finished()
            finally:
                plain.close()
            print("PASS commands: menu completion, $1/$ARGUMENTS expansion, "
                  "unsupported !-shell notice, builtin shadowing, /skill, /help")
    finally:
        fixture.shutdown()
        fixture.server_close()
        worker.join(timeout=1)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupted)
    try:
        main(os.path.abspath(sys.argv[1]))
    except BaseException:
        traceback.print_exc()
        sys.exit(1)
