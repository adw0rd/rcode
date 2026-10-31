"""Local profiles in a real PTY: /provider local picker, connect wizard without
a key and with a 401 prompt. Loopback fixtures only; no live model."""

import fcntl
import http.server
import json
import os
from pathlib import Path
import pty
import re
import signal
import socket
import struct
import sys
import tempfile
import termios
import threading
import time
import traceback

sys.dont_write_bytecode = True
from terminal_pty import LoopbackHTTPServer, Terminal, interrupted
from viewport_vt import Viewport

KEY = "sk-local-pty-synthetic-0005"
ORPHAN = "sk-local-pty-orphan-synthetic-0006"
CLOUD = "pty-cloud-env-marker"


class LocalTerminal(Terminal):
    def __init__(self, binary, workspace, home, args):
        self.buffer = bytearray()
        self.offset = 0
        self.status = None
        self.grid = Viewport(140, 28)
        self.snapshots = {}
        self.control_tail = b""
        self.used_alternate_screen = False
        self.queried_cursor = False
        self.pid, self.master = pty.fork()
        if self.pid == 0:
            try:
                fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 28, 140, 0, 0))
                os.environ.clear()
                os.environ.update({"PATH": "/usr/bin:/bin", "TERM": "xterm-256color",
                                   "LANG": "C.UTF-8", "RCODE_HOME": str(home),
                                   "RCODE_CUSTOM_API_KEY": CLOUD + "-custom",
                                   "OPENAI_API_KEY": CLOUD + "-openai"})
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

    def authorized(self):
        return not self.server.require_key or self.headers.get("Authorization") == "Bearer " + KEY

    def do_GET(self):
        self.server.requests.append(("GET", self.path, self.headers.get("Authorization"), ""))
        if self.path != "/v1/models":
            return self.reply(404, {"error": "not found"})
        if not self.authorized():
            return self.reply(401, {"error": "unauthorized"})
        self.reply(200, {"data": [{"id": model} for model in self.server.models]})

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        self.server.requests.append(("POST", self.path, self.headers.get("Authorization"), body))
        if not self.authorized():
            return self.reply(401, {"error": "unauthorized"})
        self.reply(200, {"choices": [{"message": {"role": "assistant", "content": "LOCAL_PTY_OK"},
                                      "finish_reason": "stop"}],
                         "usage": {"prompt_tokens": 900, "completion_tokens": 3}})


def profile(name, base, model):
    return {"kind": "local", "model": model, "base_url": base,
            "local": {"profile": name, "runtime": "openai"}}


def write_config(home, config):
    path = home / "config.json"
    path.write_text(json.dumps(config))
    path.chmod(0o600)


def seed_orphan(home, name):
    """A key left under a profile name whose profile no longer exists."""
    path = home / "credentials.json"
    path.write_text(json.dumps({"version": 1, "providers": {"local:" + name: ORPHAN}}))
    path.chmod(0o600)


def closed_base():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return f"http://127.0.0.1:{probe.getsockname()[1]}/v1"


def token_footer(terminal):
    return re.search(r"~[0-9.,k ]+/[0-9.,k ]+ ток\.", terminal.grid.rows()[-1]) is not None


def main(binary):
    fixture = LoopbackHTTPServer(("127.0.0.1", 0), Handler)
    fixture.daemon_threads = True
    fixture.requests, fixture.require_key = [], False
    fixture.models = ["model-b", "model-x"]
    worker = threading.Thread(target=fixture.serve_forever, daemon=True)
    worker.start()
    try:
        with tempfile.TemporaryDirectory(prefix="rcode-local-pty-") as temporary:
            root = Path(temporary)
            workspace = root / "project"
            workspace.mkdir()
            base = f"http://127.0.0.1:{fixture.server_port}/v1"

            # 1. /provider local: active profile first, Enter keeps the previous model.
            home = root / "picker"
            home.mkdir(mode=0o700)
            config = {"version": 1, "active": "custom",
                      "providers": {"custom": {"kind": "custom", "model": "cloud-model", "base_url": base}},
                      "local": {"active": "beta", "profiles": {
                          "alpha": profile("alpha", base, "model-a"),
                          "beta": profile("beta", base, "model-b")}}}
            (home / "config.json").write_text(json.dumps(config))
            (home / "config.json").chmod(0o600)
            terminal = LocalTerminal(binary, workspace, home, [])
            try:
                terminal.until(terminal.editor_ready, "initial full-screen composer")
                terminal.assert_footer("cloud-model", "custom")
                assert not token_footer(terminal), "cloud footer stays in characters"
                terminal.send("/provider local\r")
                terminal.until(lambda: any("beta" in row and "профиль beta" in row for row in terminal.grid.rows()),
                               "profile picker with the active profile")
                rows = terminal.grid.rows()
                beta = next(i for i, row in enumerate(rows) if "профиль beta" in row)
                alpha = next(i for i, row in enumerate(rows) if "профиль alpha" in row)
                assert beta < alpha, f"active profile must be first:\n{terminal.dump()}"
                terminal.send("\r")
                terminal.until(lambda: any("model-x" in row for row in terminal.grid.rows()),
                               "model picker of the profile endpoint")
                terminal.send("\r")
                terminal.until(terminal.editor_ready, "composer after choosing the local model")
                terminal.assert_footer("model-b", "local")
                terminal.until(lambda: token_footer(terminal), "estimated-token footer for local")
                terminal.send("привет\r")
                terminal.expect_body("LOCAL_PTY_OK")
                terminal.until(terminal.editor_ready, "composer after the local answer")
                terminal.assert_footer("model-b", "local")
                assert token_footer(terminal), f"footer must count tokens:\n{terminal.dump()}"
                terminal.send("/exit\r")
                terminal.finished()
            finally:
                terminal.close()
            saved = json.loads((home / "config.json").read_text())
            assert saved["active"] == "local" and saved["local"]["active"] == "beta", saved
            assert "local" not in saved["providers"], saved
            posts = [r for r in fixture.requests if r[0] == "POST"]
            assert len(posts) == 1 and json.loads(posts[0][3])["model"] == "model-b", posts
            assert "reasoning_effort" not in posts[0][3]
            assert all(r[2] is None for r in fixture.requests), fixture.requests
            assert all(CLOUD not in r[3] for r in fixture.requests)

            # 2. connect local, manual address, server without a key: no key prompt.
            fixture.requests.clear()
            home = root / "manual"
            home.mkdir(mode=0o700)
            seed_orphan(home, "openai")
            terminal = LocalTerminal(binary, workspace, home, ["--plain", "connect", "local"])
            try:
                terminal.expect("Номер")
                terminal.send("2\r")
                terminal.expect("Адрес API")
                terminal.send(base + "\r")
                terminal.expect("Сервер")
                terminal.drain()
                terminal.send("\r")
                terminal.expect("Имя профиля")
                terminal.send("\r")
                terminal.expect("Выберите модель")
                terminal.drain()
                terminal.send("\r")
                terminal.finished()
                assert "Ключ" not in terminal.text(), "no key prompt for a server without auth"
            finally:
                terminal.close()
            saved = json.loads((home / "config.json").read_text())
            assert saved["active"] == "local" and saved["local"]["active"] == "openai", saved
            assert saved["local"]["profiles"]["openai"]["model"] == "model-b", saved
            assert not (home / "credentials.json").exists() or "local:" not in (home / "credentials.json").read_text()
            assert all(r[2] is None for r in fixture.requests), fixture.requests

            # 3. connect local against a server that answers 401: hidden key prompt.
            fixture.requests.clear()
            fixture.require_key = True
            home = root / "keyed"
            home.mkdir(mode=0o700)
            seed_orphan(home, "keyed")
            terminal = LocalTerminal(binary, workspace, home, ["--plain", "connect", "local"])
            try:
                terminal.expect("Номер")
                terminal.send("2\r")
                terminal.expect("Адрес API")
                terminal.send(base + "\r")
                terminal.expect("Сервер")
                terminal.drain()
                terminal.send("\r")
                terminal.expect("Имя профиля")
                terminal.send("keyed\r")
                terminal.expect("Сервер требует ключ")
                terminal.send(KEY + "\r")
                terminal.expect("Выберите модель")
                terminal.drain()
                terminal.send("\r")
                terminal.finished()
                assert KEY not in terminal.text(), "key echoed"
            finally:
                terminal.close()
            saved = json.loads((home / "config.json").read_text())
            assert saved["local"]["profiles"]["keyed"]["local"]["key_required"] is True, saved
            assert KEY not in (home / "config.json").read_text()
            credentials = json.loads((home / "credentials.json").read_text())
            assert credentials["providers"]["local:keyed"] == KEY
            assert oct((home / "credentials.json").stat().st_mode & 0o777) == "0o600"
            assert [r[2] for r in fixture.requests] == [None, "Bearer " + KEY], fixture.requests
            assert ORPHAN not in (home / "credentials.json").read_text()

            # 4. The profile moves while its key is being typed: the key is not
            # saved under the name and is not sent anywhere. Then /model with the
            # stale snapshot (moved, then deleted) never asks for a key.
            fixture.requests.clear()
            home = root / "stale"
            home.mkdir(mode=0o700)
            write_config(home, {"version": 1, "active": "local", "providers": {},
                                "local": {"active": "p", "profiles": {"p": profile("p", base, "model-b")}}})
            moved = {"version": 1, "active": "local", "providers": {},
                     "local": {"active": "p", "profiles": {"p": profile("p", closed_base(), "model-b")}}}
            terminal = LocalTerminal(binary, workspace, home, [])
            try:
                terminal.until(terminal.editor_ready, "composer of the local session")
                mark = terminal.mark()
                terminal.send("/provider local\r")
                terminal.until(lambda: any("профиль p" in row for row in terminal.grid.rows()),
                               "profile picker")
                terminal.send("\r")
                terminal.expect("Сервер требует ключ", mark)
                write_config(home, moved)
                terminal.send(KEY + "\r")
                terminal.expect("изменился", mark)
                terminal.until(terminal.editor_ready, "composer after the moved profile")
                assert not (home / "credentials.json").exists(), (home / "credentials.json").read_text()
                assert all(r[2] is None for r in fixture.requests), fixture.requests
                for config, error in [(moved, "изменился"),
                                      ({"version": 1, "active": "local", "providers": {},
                                        "local": {"profiles": {}}}, "больше не сохранён")]:
                    write_config(home, config)
                    fixture.requests.clear()
                    mark = terminal.mark()
                    terminal.send("/model\r")
                    terminal.expect(error, mark)
                    terminal.until(terminal.editor_ready, f"composer after {error}")
                    assert "Ключ" not in terminal.text(mark), terminal.text(mark)
                    assert fixture.requests == [], fixture.requests
                    assert not (home / "credentials.json").exists()
                terminal.send("/exit\r")
                terminal.finished()
                assert KEY not in terminal.text(), "key echoed"
            finally:
                terminal.close()
            print("PASS local: profile picker, previous model on Enter, token footer, noauth wizard, 401 key prompt, no orphan or stale-snapshot keys")
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
