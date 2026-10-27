"""Локальная PTY-проверка настоящего бинарника без сторонних модулей и API."""

import contextlib
import errno
import fcntl
import http.server
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import socketserver
import struct
import sys
import tempfile
import termios
import threading
import time
import traceback

sys.dont_write_bytecode = True
from viewport_vt import Viewport, verify_viewport


DEADLINE = time.monotonic() + 51
ANSI = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07]*(?:\x07|\x1b\\)")


class Terminal:
    def __init__(self, binary, workspace, home, args=()):
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
                os.environ.update({
                    "PATH": "/usr/bin:/bin",
                    "TERM": "xterm-256color",
                    "LANG": "C.UTF-8",
                    "RCODE_HOME": str(home),
                    "RCODE_CUSTOM_API_KEY": "pty-custom-fixture",
                    "RCODE_OPENROUTER_API_KEY": "pty-router-fixture",
                })
                os.execv(binary, [binary, "-C", str(workspace), *args])
            finally:
                os._exit(127)
        self.initial_termios = termios.tcgetattr(self.master)

    def mark(self):
        self.pump(0)
        return self.offset + len(self.buffer)

    def text(self, mark=0):
        start = max(0, mark - self.offset)
        return ANSI.sub(b"", bytes(self.buffer[start:])).decode("utf-8", "replace")

    def pump(self, delay=0.025):
        if select.select([self.master], [], [], delay)[0]:
            try:
                data = os.read(self.master, 65536)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                data = b""
            self.buffer.extend(data)
            self.grid.feed(data)
            controls = self.control_tail + data
            self.used_alternate_screen |= b"\x1b[?1049h" in controls
            self.queried_cursor |= b"\x1b[6n" in controls
            self.control_tail = controls[-16:]
            if len(self.buffer) > 1024 * 1024:
                dropped = len(self.buffer) - 512 * 1024
                del self.buffer[:dropped]
                self.offset += dropped
        if self.status is None:
            waited, status = os.waitpid(self.pid, os.WNOHANG)
            if waited:
                self.status = os.waitstatus_to_exitcode(status)

    def until(self, predicate, label, seconds=4):
        end = min(DEADLINE, time.monotonic() + seconds)
        while time.monotonic() < end:
            # Drain PTY output even while waiting for HTTP/config. TCSADRAIN in
            # the child's raw-mode guard otherwise blocks on macOS.
            self.pump()
            if self.grid.frame_complete and predicate():
                return
            if self.status is not None:
                raise AssertionError(f"rcode exited {self.status} while waiting for {label}\n{self.dump()}")
        limit = "fixture deadline" if end == DEADLINE else f"{seconds}-second wait"
        raise AssertionError(
            f"Timed out waiting for {label} ({limit}); "
            f"frame_complete={self.grid.frame_complete}, alternate={self.grid.alternate}, "
            f"cursor=({self.grid.row}, {self.grid.col}), visible={self.grid.cursor_visible}, "
            f"pending={self.grid.pending!r}\n{self.dump()}")

    def expect(self, text, mark=0):
        self.until(lambda: text in self.text(mark), repr(text))

    def editor_after(self, text, mark=0):
        def ready():
            return text in self.text(mark) and self.editor_ready()
        self.until(ready, f"composer after {text!r}")
        self.assert_footer()

    def editor_ready(self):
        rows = self.grid.rows()
        return (self.grid.frame_complete and self.grid.alternate and "Контекст" in rows[-1]
                and self.grid.cursor_visible and self.grid.row == self.grid.height - 4
                and self.grid.col == 2 and not rows[-4].strip("│ ")
                and rows[-5].startswith("╭ rcode") and rows[-4].startswith("│ ")
                and rows[-3].startswith("╰"))

    def busy_ready(self):
        rows = self.grid.rows()
        return (self.grid.frame_complete and self.grid.alternate and "Контекст" in rows[-1]
                and not self.grid.cursor_visible and rows[-5].startswith("╭ rcode")
                and rows[-4].startswith("│ ") and rows[-3].startswith("╰"))

    def expect_body(self, text):
        self.until(lambda: any(text in row for row in self.grid.rows()[:-5]),
                   f"{text!r} in body above composer")

    def drain(self, seconds=0.1):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self.pump(0.01)
        self.until(lambda: self.grid.frame_complete, "completed synchronized update after drain")

    def assert_footer(self, *expected):
        def version_is_right():
            match = re.search(r'(?:rcode |v)\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$', self.grid.rows()[-2])
            return (match is not None and self.grid.cells[-2][-2] == match.group()[-1]
                    and self.grid.cells[-2][-1] == ' ')
        self.until(lambda: "Контекст" in self.grid.rows()[-1]
                   and all(value in self.grid.rows()[-2] for value in expected)
                   and version_is_right(),
                   f"footer in last two rows ({', '.join(expected)})")
        rows = self.grid.rows()
        assert "Контекст" in rows[-1], f"Footer must occupy last row:\n{self.dump()}"
        assert version_is_right(), f"Version must stay aligned to the right:\n{self.dump()}"
        for value in expected:
            assert value in rows[-2], f"{value!r} absent from penultimate row:\n{self.dump()}"
        assert all("Контекст [" not in row for row in rows[:-1]), f"Stale footer above last row:\n{self.dump()}"
        assert {1002, 1006}.issubset(self.grid.mouse_modes), "Wheel and drag capture must stay enabled"

    def dump(self):
        return "\n".join(f"{index + 1:02d}|{row}" for index, row in enumerate(self.grid.rows()))

    def capture(self, name):
        self.snapshots[name] = {"width": self.grid.width, "height": self.grid.height,
                                "cursor": [self.grid.row, self.grid.col],
                                "cursor_visible": self.grid.cursor_visible,
                                "completed_frames": self.grid.completed_frames,
                                "rows": self.grid.rows()}

    def send(self, text):
        if time.monotonic() >= DEADLINE:
            raise AssertionError("PTY fixture exceeded its 51-second deadline")
        data = text.encode("utf-8") if isinstance(text, str) else text
        while data:
            written = os.write(self.master, data)
            data = data[written:]

    def command(self, command, expected):
        self.until(self.editor_ready, f"idle composer before {command!r}")
        mark = self.mark()
        # Submit a prepared command as one paste. Explicit send() scenarios
        # below still exercise individual keys, completion, paste and resize.
        self.send("\x1b[200~" + command + "\x1b[201~\r")
        if command in ["/model", "/effort", "/provider", "/permissions"]:
            self.expect(expected, mark)
            self.until(lambda: self.grid.cursor_visible
                       and any(expected in row for row in self.grid.rows()[:-2])
                       and "Контекст" in self.grid.rows()[-1],
                       f"picker {expected!r} above footer")
            self.assert_footer()
        else:
            self.editor_after(expected, mark)
        return mark

    def resize(self, width, height):
        self.grid.resize(width, height)
        fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", height, width, 0, 0))
        os.kill(self.pid, signal.SIGWINCH)

    def close(self):
        if self.status is None:
            try:
                os.killpg(self.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            end = time.monotonic() + 2
            while self.status is None and time.monotonic() < end:
                # On macOS an exiting process may still drain the PTY. Reap
                # without blocking while consuming its remaining output.
                self.pump(0.01)
        if self.master is not None:
            os.close(self.master)
            self.master = None
        if self.status is None:
            end = time.monotonic() + 1
            while self.status is None and time.monotonic() < end:
                waited, status = os.waitpid(self.pid, os.WNOHANG)
                if waited:
                    self.status = os.waitstatus_to_exitcode(status)
                else:
                    time.sleep(0.01)
            assert self.status is not None, "Failed to reap PTY child after SIGKILL and master close"


class LoopbackHTTPServer(http.server.ThreadingHTTPServer):
    def server_bind(self):
        # HTTPServer asks getfqdn() for metadata after binding. Loopback tests
        # need no reverse DNS, which can block for tens of seconds on macOS.
        socketserver.TCPServer.server_bind(self)
        self.server_name = "localhost"
        self.server_port = self.server_address[1]


class Fixture(LoopbackHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self):
        self.requests = []
        self.balance_requests = []
        self.fail_balance = False
        self.balance_started = threading.Event()
        self.release_balance = threading.Event()
        self.release_balance.set()
        self.lock = threading.Lock()
        self.cancel_started = threading.Event()
        self.release_cancel = threading.Event()
        self.stream_first = threading.Event()
        self.stream_second = threading.Event()
        self.release_stream_first = threading.Event()
        self.release_stream_second = threading.Event()
        self.agent_started = threading.Event()
        self.release_agent = threading.Event()
        super().__init__(("127.0.0.1", 0), Handler)

    def recorded(self):
        with self.lock:
            return list(self.requests)


class Handler(http.server.BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(2)

    def log_message(self, *_):
        pass

    def reply(self, value):
        body = json.dumps(value, ensure_ascii=False).encode("utf-8")
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass  # A cancelled request deliberately closes the HTTP connection.

    def do_GET(self):
        if self.path in ["/v1/key", "/v1/credits"]:
            self.server.balance_requests.append(self.path)
            if self.server.fail_balance:
                data=b'{"error":"upstream-balance-secret-must-not-appear"}'
                self.send_response(401);self.send_header("Content-Length",str(len(data)))
                self.end_headers();self.wfile.write(data)
                return
            if self.path.endswith("/credits"):
                self.server.balance_started.set()
                self.server.release_balance.wait(timeout=3)
            self.reply({"data": {"limit": None, "limit_remaining": None, "usage": 5.0}
                        if self.path.endswith("/key") else {"total_credits": 25.0, "total_usage": 5.0}})
            return
        assert self.path == "/v1/models", self.path
        self.reply({"data": [
            {"id": model, "name": name, "context_length": 32768,
             "supported_parameters": ["tools", "reasoning"],
             "supports_reasoning": True,
             "reasoning": {"supported_efforts": ["low", "high"]}}
            for model, name in [
                ("alpha-one", "Alpha current"),
                ("beta-choice", "Beta choice"),
                ("gamma-choice", "Gamma choice"),
            ]
        ]})

    def do_POST(self):
        assert self.path == "/v1/chat/completions", self.path
        length = int(self.headers.get("Content-Length", "0"))
        assert 0 < length <= 512 * 1024, "Unexpected fixture request size"
        body = json.loads(self.rfile.read(length))
        with self.server.lock:
            self.server.requests.append(body)
        prompt = next(message["content"] for message in reversed(body["messages"])
                      if message["role"] == "user")
        if prompt == "PTY_AGENT_VIEW_CHILD":
            self.server.agent_started.set()
            self.server.release_agent.wait(timeout=6)
            self.reply({
                "choices": [{"message": {"role": "assistant", "content": "PTY_AGENT_VIEW_RESULT"},
                             "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 13, "completion_tokens": 3},
            })
            return
        if prompt == "AGENT_VIEW_REQUEST":
            last = body["messages"][-1]
            if last["role"] != "tool":
                name, arguments = "spawn_agent", {
                    "task": "PTY_AGENT_VIEW_CHILD", "name": "PTY_EXPLORER", "role": "explorer",
                }
            elif last.get("name") == "spawn_agent":
                receipt = json.loads(last["content"])
                assert receipt.get("agent_id"), "spawn_agent did not return an agent ID"
                name, arguments = "wait_agent", {"agent_id": receipt["agent_id"]}
            else:
                assert last.get("name") == "wait_agent", last
                receipt = json.loads(last["content"])
                assert receipt.get("status") == "completed", receipt
                assert receipt.get("result") == "PTY_AGENT_VIEW_RESULT", receipt
                self.reply({"choices": [{"message": {"role": "assistant", "content": "AGENT_VIEW_FINISHED"},
                                         "finish_reason": "stop"}]})
                return
            self.reply({"choices": [{"message": {"role": "assistant", "content": None,
                       "tool_calls": [{"id": "call_pty_" + name, "type": "function", "function": {
                           "name": name, "arguments": json.dumps(arguments)}}]},
                       "finish_reason": "tool_calls"}]})
            return
        if body["messages"][-1]["role"] == "tool":
            self.reply({"choices": [{"message": {"role": "assistant", "content": "TOOL_FINISHED_" + prompt},
                                     "finish_reason": "stop"}]})
            return
        if prompt == "STREAM_REQUEST":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Connection", "close")
            self.end_headers()
            def event(value):
                self.wfile.write(("data: " + json.dumps(value, ensure_ascii=False) + "\n\n").encode())
                self.wfile.flush()
            try:
                # Longer than the credential-redaction lookbehind, so each
                # fragment must become visible before the stream finishes.
                event({"choices": [{"delta": {"content": "STREAM_FIRST " + "." * 48 + "\n"}, "finish_reason": None}]})
                self.server.stream_first.set()
                self.server.release_stream_first.wait(timeout=6)
                event({"choices": [{"delta": {"content": "STREAM_SECOND " + "." * 48 + "\n"}, "finish_reason": None}]})
                self.server.stream_second.set()
                self.server.release_stream_second.wait(timeout=6)
                event({"choices": [{"delta": {}, "finish_reason": "stop"}],
                       "usage": {"prompt_tokens": 23, "completion_tokens": 5}})
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        if prompt in ("APPROVAL_DENY", "APPROVAL_YES"):
            filename = "denied.txt" if prompt == "APPROVAL_DENY" else "approved.txt"
            self.reply({"choices": [{"message": {"role": "assistant", "content": None,
                       "tool_calls": [{"id": "call_" + prompt, "type": "function", "function": {
                           "name": "write_file", "arguments": json.dumps({"path": filename, "content": "approved via PTY\n"})}}]},
                       "finish_reason": "tool_calls"}]})
            return
        if prompt == "CANCEL_REQUEST":
            self.server.cancel_started.set()
            self.server.release_cancel.wait(timeout=6)
            answer = "CANCELLED_RESPONSE_MUST_NOT_APPEAR"
        elif prompt == "AFTER_CANCEL":
            answer = "READY_RECOVERED"
        elif prompt == "ROUTER_REQUEST":
            answer = "READY_ROUTER"
        elif prompt == "HISTORY_REQUEST":
            answer = "\n".join(f"HISTORY_{index:03d}" for index in range(65)) + "\nLATEST_HISTORY_VISIBLE"
        else:
            answer = "READY_CUSTOM"
        self.reply({
            "choices": [{"message": {"role": "assistant", "content": answer},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 23, "completion_tokens": 5, "cost": 0.001},
        })


def load_json(path):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def session_provider(home):
    saved = list((home / "sessions").glob("*/session.json"))
    if len(saved) != 1:
        return None
    session = load_json(saved[0])
    return session and session["provider"]


def verify_fixture_bind():
    from unittest.mock import patch
    with patch("socket.getfqdn", side_effect=AssertionError("Loopback fixture must not query DNS")):
        with Fixture() as fixture:
            assert fixture.server_address[0] == "127.0.0.1"
            assert fixture.server_port > 0


def main(binary):
    started = previous = time.monotonic()

    def phase(label):
        nonlocal previous
        now = time.monotonic()
        print(f"PTY phase {label}: total={now-started:.3f}s, delta={now-previous:.3f}s", flush=True)
        previous = now

    phase("start")
    verify_viewport()
    verify_fixture_bind()
    phase("viewport and DNS independence verified")
    fixture = Fixture()
    phase("fixture bound")
    worker = threading.Thread(target=fixture.serve_forever, kwargs={"poll_interval": 0.025}, daemon=True)
    worker.start()
    terminal = None
    try:
        with contextlib.ExitStack() as cleanup:
            temporary = cleanup.enter_context(tempfile.TemporaryDirectory(prefix="rcode-pty-"))
            root = Path(temporary)
            workspace, home = root / "project", root / "config"
            workspace.mkdir(mode=0o700)
            home.mkdir(mode=0o700)
            endpoint = f"http://127.0.0.1:{fixture.server_port}/v1"
            config_path = home / "config.json"
            config_path.write_text(json.dumps({
                "version": 1, "active": "custom",
                "providers": {
                    kind: {"kind": kind, "model": "alpha-one", "base_url": endpoint,
                           "stream": False, "idle_timeout_secs": 8}
                    for kind in ["custom", "openrouter"]
                },
            }))
            config_path.chmod(0o600)
            terminal = Terminal(binary, workspace, home)
            phase("child forked")
            terminal.until(terminal.editor_ready, "full-height editor with footer in last two rows")
            phase("first editor ready")
            assert terminal.grid.completed_frames > 0, "Viewport never completed a synchronized update"
            terminal.assert_footer("alpha-one", "custom", "auto", "ask")
            assert "↑0 ↓0" in terminal.grid.rows()[-1], terminal.dump()
            assert sum(not row for row in terminal.grid.rows()[:20]) >= 10, terminal.dump()
            terminal.capture("initial")
            assert terminal.grid.keyboard_stack[-1] & 1, "Shift+Enter requires keyboard protocol opt-in"

            # Slash suggestions and Tab must complete a real command.
            mark = terminal.mark()
            terminal.send("/he")
            terminal.expect("/help", mark)
            terminal.until(lambda: any("/help" in row for row in terminal.grid.rows()[:-2]),
                           "slash palette above footer")
            terminal.assert_footer("alpha-one", "custom", "auto", "ask")
            terminal.capture("palette")
            terminal.send("\t\r")
            # The renderer may coalesce the whole help into one frame. Its
            # heading can already be above the viewport; assert a lasting row.
            terminal.editor_after("Изменения файлов — через diff/подтверждение", mark)
            terminal.command("/agents", "субагенты ещё не запускались")

            terminal.command("/model", "Модель · custom")
            terminal.capture("picker")
            mark = terminal.mark()
            terminal.send("choice\x1b[B\r")
            terminal.until(lambda: (load_json(config_path) or {}).get("providers", {}).get("custom", {}).get("model") == "gamma-choice",
                           "arrow-selected model persisted in config")
            terminal.until(lambda: (session_provider(home) or {}).get("model") == "gamma-choice",
                           "arrow-selected model persisted in session")
            terminal.expect("gamma-choice · custom · auto · ask", mark)

            terminal.command("/effort", "Глубина рассуждений")
            mark = terminal.mark()
            terminal.send("\x1b[B\x1b[B\r")
            terminal.until(lambda: (session_provider(home) or {}).get("effort") == "high",
                           "high effort persisted in session")
            assert load_json(config_path)["providers"]["custom"]["effort"] == "high"
            terminal.expect("gamma-choice · custom · high · ask", mark)

            # Escape closes the picker without mutating either persisted source.
            before_config = load_json(config_path)
            before_provider = session_provider(home)
            terminal.command("/model", "Модель · custom")
            mark = terminal.mark()
            terminal.send("\x1b[B\x1b")
            terminal.expect("gamma-choice · custom · high · ask", mark)
            assert load_json(config_path) == before_config, "Escape changed config"
            assert session_provider(home) == before_provider, "Escape changed session"
            terminal.command("/context", "локальный бюджет CLI")
            terminal.command("/cost", "Токены API за сессию")
            phase("menus complete")

            # Resize+paste arrive together in an already raw composer. Do not
            # wait for the resized frame: that could conceal dropped input.
            sizes = [(36, 10), (80, 24), (42, 14), (140, 28), (36, 10)]
            for index, (width, height) in enumerate(sizes + sizes):
                terminal.until(lambda: termios.tcgetattr(terminal.master)[3] & (termios.ICANON | termios.ISIG) == 0,
                               "raw composer with ICANON=0 and ISIG=0")
                pasted = f"Привет 👩🏽‍💻 {index}\nвторая строка"
                mark = terminal.mark()
                terminal.resize(width, height)
                immediate_enter = index >= len(sizes)
                terminal.send("\x1b[200~" + pasted + "\x1b[201~" + ("\r" if immediate_enter else ""))
                if not immediate_enter:
                    drain_until = time.monotonic() + 0.08
                    while time.monotonic() < drain_until:
                        terminal.pump(0.01)
                    terminal.send("\r")
                terminal.editor_after("READY_CUSTOM", mark)
                terminal.expect_body("READY_CUSTOM")
                terminal.assert_footer("high", "ask")
                terminal.expect(f"↑{23 * (index + 1)} ↓{5 * (index + 1)}", mark)
                terminal.until(lambda: terminal.editor_ready()
                               and f"↑{23 * (index + 1)} ↓{5 * (index + 1)}" in terminal.grid.rows()[-1],
                               f"idle composer after resize+paste response {index}")
                request = fixture.recorded()[-1]
                assert request["model"] == "gamma-choice"
                assert request["reasoning_effort"] == "high"
                assert "reasoning" not in request
                assert request["messages"][-1]["content"] == pasted, f"Resize+paste {index} lost UTF-8/newline"
                print(f"Resize+paste {index}: raw ICANON=0 ISIG=0, {width}x{height}, immediate Enter={immediate_enter}, HTTP text preserved")
            terminal.resize(140, 28)
            terminal.until(terminal.editor_ready, "full-height composer after final resize")
            phase("resize and paste complete")

            # Ghostty/kitty distinguish Shift+Enter only after protocol opt-in.
            # A modified Enter inserts a line; only bare Enter sends the request.
            before_multiline = len(fixture.recorded())
            mark = terminal.mark()
            terminal.send("SHIFT_Привет\x1b[13;2uвторая\x1b\rтретья\x0aчетвёртая"
                          "\x1b[13;3uпятая\x1b[106;5uшестая")
            terminal.until(lambda: terminal.grid.cursor_visible
                           and terminal.grid.col == 2 + len("шестая")
                           and any("SHIFT_Привет" in row for row in terminal.grid.rows()),
                           "multiline draft after Shift+Enter, Alt+Enter and Ctrl+J")
            assert len(fixture.recorded()) == before_multiline, "Modified Enter submitted the draft"
            terminal.send("\r")
            terminal.editor_after("READY_CUSTOM", mark)
            assert len(fixture.recorded()) == before_multiline + 1
            assert fixture.recorded()[-1]["messages"][-1]["content"] == "SHIFT_Привет\nвторая\nтретья\nчетвёртая\nпятая\nшестая"
            assert terminal.grid.keyboard_stack[-1] & 1

            # Legacy password/line forms temporarily leave Screen's keyboard mode.
            terminal.send("/connect custom\r")
            terminal.expect("Адрес API")
            assert not terminal.grid.alternate
            assert terminal.grid.keyboard_stack == [0]
            terminal.send("\x03")
            terminal.until(terminal.editor_ready, "editor after cancelled connection form")
            assert terminal.grid.keyboard_stack == [0, 1], "Keyboard mode was not restored after suspend"

            terminal.command("HISTORY_REQUEST", "LATEST_HISTORY_VISIBLE")
            terminal.expect_body("LATEST_HISTORY_VISIBLE")
            latest_body = terminal.grid.rows()[:-5]
            terminal.send("\x1b[5~")  # PageUp scrolls conversation, not the input.
            terminal.until(lambda: terminal.grid.rows()[:-5] != latest_body
                           and "Ctrl+End вниз" in terminal.grid.rows()[-1],
                           "PageUp changes visible conversation")
            assert "LATEST_HISTORY_VISIBLE" not in "\n".join(terminal.grid.rows()[:-5]), terminal.dump()
            terminal.assert_footer("gamma-choice", "custom", "high", "ask")
            terminal.capture("history_scrolled")
            terminal.send("\x1b[1;5F")  # Ctrl+End returns to the latest message.
            terminal.expect_body("LATEST_HISTORY_VISIBLE")
            terminal.until(lambda: "PgUp/PgDn история" in terminal.grid.rows()[-1],
                           "Ctrl+End resets history scroll offset")
            terminal.assert_footer()
            phase("history complete")

            mark = terminal.mark()
            terminal.send("STREAM_REQUEST\r")
            terminal.until(fixture.stream_first.is_set, "first SSE fragment sent")
            terminal.expect_body("STREAM_FIRST")
            terminal.until(terminal.busy_ready, "busy panel during unfinished SSE")
            terminal.assert_footer("gamma-choice", "custom", "high", "ask")
            terminal.capture("stream_first")
            terminal.send("foo")
            terminal.drain()
            assert terminal.busy_ready(), "Typing during SSE replaced busy panel with editor"
            fixture.release_stream_first.set()
            terminal.until(fixture.stream_second.is_set, "second SSE fragment sent")
            terminal.expect_body("STREAM_SECOND")
            assert terminal.busy_ready(), "Second SSE fragment prematurely restored editor"
            for width, height in [(80, 24), (36, 10), (140, 28)]:
                terminal.resize(width, height)
                terminal.until(lambda: "Контекст" in terminal.grid.rows()[-1],
                               f"footer at bottom during SSE after resize to {width}x{height}")
                terminal.assert_footer("high", "ask")
                assert terminal.busy_ready(), terminal.dump()
                terminal.capture(f"stream_{width}x{height}")
            fixture.release_stream_second.set()
            terminal.editor_after("STREAM_SECOND", mark)
            terminal.expect_body("STREAM_SECOND")
            phase("stream complete")

            mark = terminal.mark()
            terminal.send("CANCEL_REQUEST\r")
            terminal.until(fixture.cancel_started.is_set, "pending HTTP request")
            terminal.until(terminal.busy_ready, "busy panel during pending HTTP")
            terminal.assert_footer("gamma-choice", "custom", "high", "ask")
            terminal.send("foo")
            terminal.drain()
            assert terminal.busy_ready(), "Typing during HTTP request restored editor"
            terminal.capture("pending_http")
            terminal.send(b"\x03")
            terminal.editor_after("Ход прерван", mark)
            fixture.release_cancel.set()
            terminal.command("AFTER_CANCEL", "READY_RECOVERED")
            assert "CANCELLED_RESPONSE_MUST_NOT_APPEAR" not in terminal.text(mark)
            phase("cancellation and recovery complete")

            # Provider arrows must lead to the provider's real wire format.
            fixture.release_balance.clear()
            terminal.command("/provider", "Провайдер")
            mark = terminal.mark()
            terminal.send("\x1b[A\r")  # custom -> openrouter
            terminal.expect("Модель · openrouter", mark)
            terminal.send("\r")
            terminal.until(lambda: (load_json(config_path) or {}).get("active") == "openrouter",
                           "provider persisted in config")
            terminal.until(lambda: (session_provider(home) or {}).get("kind") == "openrouter",
                           "provider persisted in session")
            terminal.expect("alpha-one · openrouter · auto · ask", mark)
            terminal.until(terminal.editor_ready, "composer while metadata is pending")
            terminal.send("BALANCE_DRAFT")
            terminal.until(lambda: "BALANCE_DRAFT" in terminal.grid.rows()[-4], "draft while balance request is pending")
            terminal.until(fixture.balance_started.is_set, "background balance request")
            fixture.release_balance.set()
            terminal.until(lambda: "Баланс $20.00" in terminal.grid.rows()[-1], "balance arrives while draft is open")
            assert "BALANCE_DRAFT" in terminal.grid.rows()[-4], "Balance refresh lost pending input"
            terminal.send("\x03")
            terminal.until(terminal.editor_ready, "composer after clearing balance test draft")
            terminal.command("/effort", "Глубина рассуждений")
            mark = terminal.mark()
            terminal.send("\x1b[B\x1b[B\r")
            terminal.until(lambda: (session_provider(home) or {}).get("effort") == "high",
                           "OpenRouter effort persisted")
            assert load_json(config_path)["providers"]["openrouter"]["effort"] == "high"
            terminal.expect("alpha-one · openrouter · high · ask", mark)
            terminal.until(lambda: "Баланс $20.00" in terminal.grid.rows()[-1], "live OpenRouter balance in footer")
            before_balance = len(fixture.recorded())
            terminal.command("/balance", "Счёт OpenRouter: $20.0000")
            assert len(fixture.recorded()) == before_balance, "/balance must not invoke the model"
            assert fixture.balance_requests.count("/v1/credits") >= 2
            terminal.assert_footer("openrouter", "high")
            fixture.fail_balance = True
            error_mark = terminal.command("/balance", "API отклонил авторизацию")
            assert "Баланс $20.00" in terminal.grid.rows()[-1] and "устар." in terminal.grid.rows()[-1]
            assert "upstream-balance-secret" not in terminal.text(error_mark)
            fixture.fail_balance = False
            terminal.command("/balance", "Счёт OpenRouter: $20.0000")
            terminal.until(lambda: "устар." not in terminal.grid.rows()[-1] and terminal.editor_ready(),
                           "fresh balance after transient failure")
            terminal.command("ROUTER_REQUEST", "READY_ROUTER")
            request = fixture.recorded()[-1]
            assert request["reasoning"] == {"effort": "high"}
            assert "reasoning_effort" not in request
            phase("provider complete")

            # Enter denies by default; an explicit Y permits only this action.
            for prompt, answer, filename in [("APPROVAL_DENY", "\r", "denied.txt"),
                                             ("APPROVAL_YES", "Y\r", "approved.txt")]:
                mark = terminal.mark()
                terminal.send(prompt + "\r")
                terminal.until(lambda: "› Отклонить" in terminal.grid.rows()[-4]
                               and "Контекст" in terminal.grid.rows()[-1],
                               "approval panel above footer")
                terminal.assert_footer("alpha-one", "openrouter", "high", "ask")
                assert "Разрешить один раз" in terminal.grid.rows()[-4], terminal.dump()
                terminal.capture(prompt.lower())
                terminal.send(answer)
                terminal.editor_after("TOOL_FINISHED_" + prompt, mark)
                if prompt == "APPROVAL_DENY":
                    assert not (workspace / filename).exists(), "Default approval executed write_file"
                else:
                    assert (workspace / filename).read_text() == "approved via PTY\n"
                terminal.assert_footer("alpha-one", "openrouter", "high", "ask")

            phase("approvals complete")
            # A real child API request stays pending while agent_update renders
            # in the viewport. Worker output must never displace the footer.
            mark = terminal.mark()
            terminal.send("AGENT_VIEW_REQUEST\r")
            terminal.until(fixture.agent_started.is_set, "independent child API request")
            terminal.until(terminal.busy_ready, "busy panel while subagent is pending")
            terminal.expect_body("PTY_EXPLORER")
            terminal.assert_footer("alpha-one", "openrouter", "high", "ask")
            terminal.capture("agent_running")
            fixture.release_agent.set()
            terminal.editor_after("AGENT_VIEW_FINISHED", mark)
            terminal.expect("PTY_AGENT_VIEW_RESULT", mark)
            terminal.until(lambda: any("PTY_EXPLORER" in row and "готово" in row
                                      for row in terminal.grid.rows()[:-5]),
                           "completed agent_update in history above footer")
            terminal.assert_footer("alpha-one", "openrouter", "high", "ask")
            terminal.capture("agent_completed")
            terminal.command("/agents", "Субагенты · 1 задач")
            terminal.expect_body("PTY_AGENT_VIEW_RESULT")

            # Resume loads records without restarting child tasks. Seed one
            # finished result and one task left running when its process died.
            saved = list((home / "sessions").glob("*/session.json"))
            assert len(saved) == 1, saved
            session_path = saved[0]
            session = load_json(session_path)
            assert session["agents"][0]["status"] == "completed", session["agents"]
            completed_id = "a11c0011-0000-4000-8000-000000000001"
            interrupted_id = "a11c0022-0000-4000-8000-000000000002"
            session["agents"] = [
                {"id": completed_id, "name": "RESUME_REVIEWER", "task": "Review the saved project",
                 "role": "reviewer", "status": "completed",
                 "result": "RESUME_RESULT_VISIBLE\ncredential=pty-router-fixture",
                 "usage": {"input_tokens": 7, "output_tokens": 2, "cached_input_tokens": 0}},
                {"id": interrupted_id, "name": "RESUME_INTERRUPTED", "task": "Never restart this task",
                 "role": "worker", "status": "running", "result": "INCOMPLETE_RESULT",
                 "usage": {"input_tokens": 5, "output_tokens": 1, "cached_input_tokens": 0}},
            ]
            session_path.write_text(json.dumps(session))
            before_resume_requests = len(fixture.recorded())
            terminal.command("/resume latest", "Сессия восстановлена")
            restored = load_json(session_path)
            assert restored["agents"][0]["status"] == "completed", restored["agents"]
            assert restored["agents"][1]["status"] == "interrupted", restored["agents"]
            terminal.command("/agents", "Субагенты · 2 задач")
            terminal.expect_body("RESUME_INTERRUPTED")
            terminal.expect_body("прерван")
            terminal.assert_footer("alpha-one", "openrouter", "high", "ask")
            terminal.capture("agents_resumed")
            details_mark = terminal.command("/agents a11c0011", "RESUME_RESULT_VISIBLE")
            terminal.expect(completed_id, details_mark)
            terminal.expect_body("credential=[REDACTED]")
            assert "pty-router-fixture" not in terminal.text(details_mark), "Saved agent result leaked a credential"
            terminal.assert_footer("alpha-one", "openrouter", "high", "ask")
            terminal.capture("agent_details")
            terminal.command("/agents a11c0022", "задача не возобновлялась автоматически")
            terminal.expect_body("прерван")
            terminal.assert_footer("alpha-one", "openrouter", "high", "ask")
            terminal.capture("agent_interrupted")
            terminal.command("/agents a11c", "Префикс ID неоднозначен")
            terminal.assert_footer("alpha-one", "openrouter", "high", "ask")
            assert len(fixture.recorded()) == before_resume_requests, "Reading/resuming agent records restarted an API task"
            phase("agents and resume complete")

            terminal.command("/permissions", "Разрешения")
            mark = terminal.mark()
            terminal.send("\x1b[B\r")
            terminal.editor_after("✓ Разрешения: auto-edit", mark)
            terminal.command("/status", "Режим        auto-edit · shell по подтверждению")
            mark = terminal.mark()
            terminal.send(b"\x04")
            terminal.until(lambda: terminal.status is not None, "Ctrl+D exit")
            assert terminal.status == 0, f"rcode exited {terminal.status}"
            assert terminal.grid.used_alternate, "Never entered alternate screen"
            assert terminal.grid.left_alternate and not terminal.grid.alternate, "Alternate screen was not restored"
            assert not terminal.queried_cursor, "Queried DSR cursor position"
            assert terminal.grid.cursor_visible, "Cursor not restored on exit"
            assert not terminal.grid.bracketed_paste, "Bracketed paste not disabled on exit"
            assert not terminal.grid.mouse_modes, "Mouse reporting not disabled on exit"
            assert terminal.grid.keyboard_stack == [0], "Keyboard protocol leaked after exit"
            assert terminal.grid.keyboard_stacks[True] == [0], "Alternate keyboard stack leaked after exit"
            restored = termios.tcgetattr(terminal.master)
            assert restored == terminal.initial_termios, "termios not restored on exit"
            phase("child exited and terminal restored")
            # The legacy readline handler must not swallow SIGINT during API I/O.
            plain = Terminal(binary, workspace, home, args=("--plain",))
            try:
                plain.expect("rcode ›")
                plain_mark=plain.mark()
                plain.send("PLAIN_HISTORY_ENTRY\r")
                plain.expect("READY_CUSTOM",plain_mark)
                plain.expect("rcode ›",plain_mark)
                fixture.balance_started.clear()
                fixture.release_balance.clear()
                plain_mark=plain.mark()
                plain.send("/balance\r")
                plain.until(fixture.balance_started.is_set,"plain balance request")
                plain.send("\x03")
                plain.until(lambda:"Обновление баланса отменено" in plain.text(plain_mark),
                            "Ctrl+C cancels plain balance",seconds=2)
                fixture.release_balance.set()
                plain.expect("rcode ›",plain_mark)
                plain_mark=plain.mark()
                plain.send("\x1b[A\x1b[A\r")
                plain.expect("READY_CUSTOM",plain_mark)
                assert fixture.recorded()[-1]["messages"][-1]["content"] == "PLAIN_HISTORY_ENTRY"
                plain.send("/exit\r")
                plain.until(lambda:plain.status is not None,"plain exit")
                assert plain.status == 0
            finally:
                fixture.release_balance.set()
                plain.close()
            fixture.balance_started.clear()
            fixture.release_balance.clear()
            direct=Terminal(binary,workspace,home,args=("balance","--json"))
            try:
                direct.until(fixture.balance_started.is_set,"standalone balance request")
                direct.send("\x03")
                direct.until(lambda:direct.status is not None,"SIGINT stops balance CLI",seconds=2)
                assert direct.status == 130
                assert '"type":"cancelled"' in direct.text()
            finally:
                fixture.release_balance.set()
                direct.close()
            print("PTY OK: viewport coordinates, menus, persistence, effort payloads, streaming, history, approvals, subagents, resumed records, paste, resize, Ctrl+C, Ctrl+D, terminal restoration")
    except BaseException:
        if terminal is not None:
            print("PTY grid:\n" + terminal.dump(), file=sys.stderr)
            print("PTY transcript tail:\n" + terminal.text()[-18000:], file=sys.stderr)
        raise
    finally:
        phase("cleanup start")
        fixture.release_cancel.set()
        fixture.release_stream_first.set()
        fixture.release_stream_second.set()
        fixture.release_agent.set()
        fixture.release_balance.set()
        if terminal is not None:
            capture_path = os.environ.get("RCODE_PTY_DUMP_GRID")
            if capture_path:
                path = Path(capture_path).resolve()
                internal = Path(__file__).resolve().parents[1] / "internal"
                assert path.is_relative_to(internal), "PTY artifacts must remain in internal/"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(terminal.snapshots, ensure_ascii=False, indent=2))
            terminal.close()
        phase("child closed")
        fixture.shutdown()
        fixture.server_close()
        worker.join(timeout=1)
        phase("cleanup complete")


def interrupted(signum, _frame):
    raise RuntimeError(f"PTY fixture terminated by signal {signum}")


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupted)
    try:
        main(os.path.abspath(sys.argv[1]))
    except BaseException:
        traceback.print_exc()
        sys.exit(1)
