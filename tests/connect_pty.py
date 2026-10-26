"""Мастер подключения: настоящий PTY, OAuth/каталог fixtures, без платных API."""

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
from viewport_vt import Viewport


class ConnectTerminal(Terminal):
    def __init__(self, binary, workspace, home, args, extra_env=None):
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
                                   "LANG": "C.UTF-8", "RCODE_HOME": str(home)})
                os.environ.update(extra_env or {})
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

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        self.server.requests.append(("POST", self.path, self.headers.get("Authorization"), body))
        assert self.path == "/oauth", "Wizard must not invoke a paid generation"
        self.reply(200, {"access_token": "fixture-access", "expires_at": int(time.time()*1000)+60000})

    def do_GET(self):
        self.server.requests.append(("GET", self.path, self.headers.get("Authorization"), ""))
        self.server.projects.append(self.headers.get("OpenAI-Project"))
        assert self.path == "/v1/models"
        if self.server.reject:
            self.reply(401, {"error": "fixture-key-must-never-echo"})
        else:
            self.reply(200, {"data": self.server.models})


def main(binary):
    fixture = LoopbackHTTPServer(("127.0.0.1", 0), Handler)
    fixture.daemon_threads = True
    fixture.requests, fixture.reject = [], False
    fixture.projects = []
    fixture.models = [
        {"id": "GigaChat", "name": "GigaChat Lite"},
        {"id": "GigaChat-3-Ultra", "name": "GigaChat 3 Ultra"},
        {"id": "Embeddings", "name": "Embedding model"},
        {"id": "text-embedding-3-small", "name": "OpenAI embedding fixture"},
        {"id": "whisper-1", "name": "OpenAI speech fixture"},
        {"id": "dall-e-3", "name": "OpenAI image fixture"},
    ]
    worker = threading.Thread(target=fixture.serve_forever, daemon=True)
    worker.start()
    try:
        with tempfile.TemporaryDirectory(prefix="rcode-connect-pty-") as temporary:
            root = Path(temporary)
            workspace = root / "project"
            workspace.mkdir()
            endpoint = f"http://127.0.0.1:{fixture.server_port}"

            def prepare(name, kind, with_key=False):
                home = root / name
                home.mkdir(mode=0o700)
                config = {"version": 1, "active": kind, "providers": {kind: {
                    "kind": kind, "model": "GigaChat", "base_url": endpoint+"/v1",
                    "auth_url": endpoint+"/oauth" if kind == "gigachat" else None,
                    "stream": False,
                }}}
                (home / "config.json").write_text(json.dumps(config))
                if with_key:
                    (home / "credentials.json").write_text(json.dumps({
                        "version": 1, "providers": {kind: "fixture-key-must-never-echo"}}))
                for path in home.iterdir():
                    path.chmod(0o600)
                return home

            home = prepare("gigachat", "gigachat")
            terminal = ConnectTerminal(binary, workspace, home, ["connect", "gigachat"])
            try:
                terminal.expect("Scope")
                terminal.send("\r")
                terminal.expect("Ключ (ввод скрыт):")
                assert "PEM CA-файл" not in terminal.text(), "Ordinary login asks for a CA path"
                terminal.send("fixture-key-must-never-echo\r")
                terminal.expect("GigaChat 3 Ultra")
                assert "Embedding model" not in terminal.text(), "Non-chat model offered"
                assert "OpenAI embedding fixture" not in terminal.text(), "Embedding model offered"
                assert "OpenAI speech fixture" not in terminal.text(), "Speech model offered"
                assert "OpenAI image fixture" not in terminal.text(), "Image model offered"
                assert "fixture-key-must-never-echo" not in terminal.text(), "Secret echoed"
                terminal.send("GigaChat-3-Ultra")
                terminal.drain()
                terminal.send("\r")
                terminal.finished()
                config = json.loads((home / "config.json").read_text())
                assert config["providers"]["gigachat"]["model"] == "GigaChat-3-Ultra"
                assert config["providers"]["gigachat"]["ca_file"] is None
                assert "fixture-key-must-never-echo" not in (home / "config.json").read_text()
                assert json.loads((home / "credentials.json").read_text())["providers"]["gigachat"] == "fixture-key-must-never-echo"
                assert fixture.requests[:2] == [
                    ("POST", "/oauth", "Basic fixture-key-must-never-echo", "scope=GIGACHAT_API_PERS"),
                    ("GET", "/v1/models", "Bearer fixture-access", ""),
                ], fixture.requests
            finally:
                terminal.close()
            # Explicit CA remains available without adding a question to normal login.
            home = prepare("gigachat-custom-ca", "gigachat")
            ca = Path(__file__).parent / "fixtures" / "russian-trusted-root-ca.pem"
            terminal = ConnectTerminal(binary, workspace, home, [
                "--plain", "--ca-file", str(ca), "connect", "gigachat"])
            try:
                terminal.expect("Scope")
                terminal.send("\r")
                terminal.expect("Ключ (ввод скрыт):")
                terminal.send("fixture-key-must-never-echo\r")
                terminal.expect("Номер")
                terminal.send("1\r")
                terminal.finished()
                assert json.loads((home / "config.json").read_text())["providers"]["gigachat"]["ca_file"] == str(ca)
                assert "PEM CA-файл" not in terminal.text()
            finally:
                terminal.close()
            # Yandex uses full model URIs; speech/embedding models are not chat choices.
            chat_models = fixture.models
            fixture.models = [
                {"id": "gpt://fixture-folder/aliceai-llm/latest", "name": "Alice fixture"},
                {"id": "gpt://fixture-folder/speech-realtime-250923/latest", "name": "Speech fixture"},
                {"id": "emb://fixture-folder/text-search-query/latest", "name": "Embedding fixture"},
            ]
            home = prepare("yandex", "yandex")
            terminal = ConnectTerminal(binary, workspace, home, ["connect", "yandex"])
            try:
                terminal.expect("ID каталога (Folder ID) или полный gpt:// URI")
                terminal.send("gpt://fixture-folder/aliceai-llm/latest\r")
                terminal.expect("Секретный ключ AI Studio (ввод скрыт):")
                terminal.send("fixture-key-must-never-echo\r")
                terminal.expect("Alice fixture")
                assert "Speech fixture" not in terminal.text(), "Realtime speech offered as chat model"
                assert "Embedding fixture" not in terminal.text(), "Embedding offered as chat model"
                terminal.send("\r")
                terminal.finished()
                config = json.loads((home / "config.json").read_text())["providers"]["yandex"]
                assert config["model"] == "gpt://fixture-folder/aliceai-llm/latest"
                assert config["folder_id"] == "fixture-folder"
                assert fixture.projects[-1] == "fixture-folder", fixture.projects
                assert fixture.requests[-1][2] == "Api-Key fixture-key-must-never-echo"
            finally:
                terminal.close()

            # Cancelling a first connection must not save its staged credential.
            fixture.models = chat_models
            home = prepare("cancel", "custom")
            before = (home / "config.json").read_bytes()
            terminal = ConnectTerminal(binary, workspace, home, ["connect", "custom"])
            try:
                terminal.expect("Адрес API")
                terminal.send("\r")
                terminal.expect("Ключ (ввод скрыт):")
                terminal.send("fixture-key-must-never-echo\r")
                terminal.expect("GigaChat 3 Ultra")
                terminal.send("\x1b")
                terminal.finished(130)
                assert (home / "config.json").read_bytes() == before
                assert not (home / "credentials.json").exists(), "Cancelled wizard stored a key"
            finally:
                terminal.close()

            # A failed catalog still offers an explicit, unverified manual ID.
            fixture.reject = True
            home = prepare("fallback", "custom")
            terminal = ConnectTerminal(binary, workspace, home, ["--plain", "connect", "custom"])
            try:
                terminal.expect("Адрес API")
                terminal.send("\r")
                terminal.expect("Ключ (ввод скрыт):")
                terminal.send("fixture-key-must-never-echo\r")
                terminal.expect("Каталог моделей недоступен")
                terminal.expect("Номер")
                assert "fixture-key-must-never-echo" not in terminal.text()
                terminal.send("2\r")
                terminal.expect("ID модели")
                terminal.send("my-new-model\r")
                terminal.finished()
                assert json.loads((home / "config.json").read_text())["providers"]["custom"]["model"] == "my-new-model"
            finally:
                terminal.close()

            # /connect must resume Screen before opening its picker.
            fixture.reject = False
            home = prepare("fullscreen", "custom", with_key=True)
            terminal = ConnectTerminal(binary, workspace, home, [])
            try:
                terminal.until(terminal.editor_ready, "initial full-screen composer")
                terminal.send("/connect custom\r")
                terminal.expect("Адрес API")
                terminal.send("\r")
                terminal.expect("Заменить сохранённый ключ?")
                terminal.send("\r")
                terminal.until(lambda: terminal.grid.alternate and any(
                    "GigaChat 3 Ultra" in row for row in terminal.grid.rows()), "full-screen model picker")
                terminal.assert_footer()
                terminal.send("GigaChat-3-Ultra")
                terminal.drain()
                terminal.send("\r")
                terminal.until(terminal.editor_ready, "composer after connection")
                terminal.assert_footer("GigaChat-3-Ultra", "custom")
                terminal.send("/exit\r")
                terminal.finished()
            finally:
                terminal.close()
            print("PASS connect: authenticated catalog, selection, cancellation, manual fallback, full-screen footer, hidden keys")
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
