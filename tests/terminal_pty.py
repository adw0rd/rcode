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
import subprocess
import sys
import tempfile
import termios
import threading
import time
import traceback

sys.dont_write_bytecode = True
from viewport_vt import Viewport, verify_viewport


DEADLINE = time.monotonic() + 90
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
                    "RCODE_GIGACHAT_AUTH_KEY": "pty-giga-fixture",
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

    def editor_after(self, text, mark=0, wait=4.0):
        def ready():
            return text in self.text(mark) and self.editor_ready()
        self.until(ready, f"composer after {text!r}", seconds=wait)
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
        tail = rows[-6:]
        return (self.grid.frame_complete and self.grid.alternate and "Контекст" in rows[-1]
                and not self.grid.cursor_visible and any(r.startswith("╭ rcode") for r in tail)
                and any(r.startswith("╰") for r in tail)
                and not any(r.startswith("❯") and r.endswith("код") for r in tail))

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
        grid = "\n".join(f"{index + 1:02d}|{row}" for index, row in enumerate(self.grid.rows()))
        return f"{grid}\nRAW TAIL:\n{self.text().replace(chr(13), chr(10))[-1200:]}"

    def capture(self, name):
        self.snapshots[name] = {"width": self.grid.width, "height": self.grid.height,
                                "cursor": [self.grid.row, self.grid.col],
                                "cursor_visible": self.grid.cursor_visible,
                                "completed_frames": self.grid.completed_frames,
                                "rows": self.grid.rows(),
                                "backgrounds": [row[:] for row in self.grid.backgrounds]}

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
        self.oauth_credentials = []
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
        self.busy_started = threading.Event()
        self.release_busy = threading.Event()
        self.detail_started = threading.Event()
        self.release_detail = threading.Event()
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
        if self.path == "/giga/v1/balance":
            assert self.headers["Authorization"] == "Bearer pty-giga-token"
            self.reply({"balance": [{"usage": "GigaChat-Ultra", "value": 1234567},
                                    {"usage": "GigaChat-Max", "value": 9000000}]})
            return
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
        if self.path == "/giga/oauth":
            self.server.oauth_credentials.append(self.headers["Authorization"])
            assert self.headers["Authorization"] == "Basic pty-giga-fixture"
            self.rfile.read(int(self.headers["Content-Length"]))
            self.reply({"access_token": "pty-giga-token", "expires_at": int(time.time() + 3600) * 1000})
            return
        assert self.path == "/v1/chat/completions", self.path
        length = int(self.headers.get("Content-Length", "0"))
        assert 0 < length <= 512 * 1024, "Unexpected fixture request size"
        body = json.loads(self.rfile.read(length))
        with self.server.lock:
            self.server.requests.append(body)
        prompt = next(message["content"] for message in reversed(body["messages"])
                      if message["role"] == "user")
        actual_user = next((index for index in reversed(range(len(body["messages"])))
                            if body["messages"][index]["role"] == "user"
                            and not body["messages"][index]["content"].startswith("[rcode runtime feedback")), None)
        loop_prompt = body["messages"][actual_user]["content"] if actual_user is not None else None
        if loop_prompt in ("LOOP_ABORT", "LOOP_CONTINUE"):
            turn = body["messages"][actual_user + 1:]
            final_step = any(message["role"] == "assistant"
                             and "ЛИМИТ ХОДА" in (message.get("content") or "") for message in turn)
            reads = sum(message["role"] == "tool" for message in turn)
            if final_step or (loop_prompt == "LOOP_CONTINUE" and reads >= 4):
                if final_step:
                    assert "tools" not in body, body
                answer = "LOOP_SUMMARY_ABORT" if final_step else "LOOP_CONTINUED"
                self.reply({"choices": [{"message": {"role": "assistant", "content": answer},
                                         "finish_reason": "stop"}]})
            else:
                self.reply({"choices": [{"message": {"role": "assistant", "content": None,
                           "tool_calls": [{"id": "loop_read_" + str(reads), "type": "function",
                                           "function": {"name": "list_files", "arguments": "{}"}}]},
                           "finish_reason": "tool_calls"}]})
            return
        if prompt == "PTY_AGENT_VIEW_CHILD":
            self.server.agent_started.set()
            self.server.release_agent.wait(timeout=6)
            self.reply({
                "choices": [{"message": {"role": "assistant", "content": "PTY_AGENT_VIEW_RESULT"},
                             "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 13, "completion_tokens": 3},
            })
            return
        if loop_prompt in ("ASK_USER_SELECT", "ASK_USER_CUSTOM", "ASK_USER_ESC_AFTER_ERROR", "ASK_USER_CTRL_C"):
            tool_names = [tool["function"]["name"] for tool in body.get("tools", [])]
            assert "ask_user" in tool_names, f"interactive PTY request must advertise ask_user: {tool_names}"
            turn = body["messages"][actual_user + 1:]
            tool_msgs = [m for m in turn if m["role"] == "tool"]
            if loop_prompt == "ASK_USER_CTRL_C":
                assert not tool_msgs, f"Ctrl+C during ask_user must stop turn without follow-up request: {turn}"
                self.reply({"choices": [{"message": {"role": "assistant", "content": None,
                           "tool_calls": [{"id": "call_ask_ctrlc", "type": "function", "function": {
                               "name": "ask_user",
                               "arguments": json.dumps({"questions": [{
                                   "question": "Канал уведомлений?",
                                   "options": ["Email (Рекомендуется)", "Webhook"],
                               }]})}}]},
                           "finish_reason": "tool_calls"}]})
                return
            if loop_prompt == "ASK_USER_SELECT":
                if not tool_msgs:
                    self.reply({"choices": [{"message": {"role": "assistant", "content": None,
                               "tool_calls": [{"id": "call_ask_sel", "type": "function", "function": {
                                   "name": "ask_user",
                                   "arguments": json.dumps({"questions": [{
                                       "question": "Формат отчёта?",
                                       "options": ["JSON (Рекомендуется)", "Markdown"],
                                   }]})}}]},
                               "finish_reason": "tool_calls"}]})
                else:
                    receipt = json.loads(tool_msgs[-1]["content"])
                    assert receipt["status"] == "answered", receipt
                    assert receipt["answers"][0]["source"] == "option", receipt
                    assert receipt["answers"][0]["option_index"] == 2, receipt
                    assert receipt["answers"][0]["answer"] == "Markdown", receipt
                    self.reply({"choices": [{"message": {"role": "assistant", "content": "ASK_USER_SELECT_DONE"},
                                             "finish_reason": "stop"}]})
                return
            if loop_prompt == "ASK_USER_CUSTOM":
                if not tool_msgs:
                    self.reply({"choices": [{"message": {"role": "assistant", "content": None,
                               "tool_calls": [{"id": "call_ask_custom", "type": "function", "function": {
                                   "name": "ask_user",
                                   "arguments": json.dumps({"questions": [{
                                       "question": "Целевой стек?",
                                       "options": ["Rust (Рекомендуется)", "Python"],
                                   }]})}}]},
                               "finish_reason": "tool_calls"}]})
                else:
                    receipt = json.loads(tool_msgs[-1]["content"])
                    assert receipt["status"] == "answered", receipt
                    assert receipt["answers"][0]["source"] == "custom", receipt
                    assert receipt["answers"][0]["option_index"] is None, receipt
                    assert receipt["answers"][0]["answer"] == "Свой стек 👩🏽‍💻", receipt
                    self.reply({"choices": [{"message": {"role": "assistant", "content": "ASK_USER_CUSTOM_DONE"},
                                             "finish_reason": "stop"}]})
                return
            if loop_prompt == "ASK_USER_ESC_AFTER_ERROR":
                if len(tool_msgs) == 0:
                    self.reply({"choices": [{"message": {"role": "assistant", "content": None,
                               "tool_calls": [{"id": "call_missing_read", "type": "function", "function": {
                                   "name": "read_file",
                                   "arguments": json.dumps({"path": "missing_before_ask.txt"})}}]},
                               "finish_reason": "tool_calls"}]})
                elif len(tool_msgs) == 1:
                    self.reply({"choices": [{"message": {"role": "assistant", "content": None,
                               "tool_calls": [{"id": "call_ask_esc", "type": "function", "function": {
                                   "name": "ask_user",
                                   "arguments": json.dumps({"questions": [{
                                       "question": "Создать шаблон?",
                                       "options": ["Да (Рекомендуется)", "Нет"],
                                   }]})}}]},
                               "finish_reason": "tool_calls"}]})
                else:
                    assert not any(m["role"] == "user" for m in turn), f"unexpected recovery message: {turn}"
                    receipt = json.loads(tool_msgs[-1]["content"])
                    assert receipt["status"] == "cancelled", receipt
                    assert receipt["answered_count"] == 0, receipt
                    self.reply({"choices": [{"message": {"role": "assistant", "content": "ASK_USER_ESC_CLEAN_DONE"},
                                             "finish_reason": "stop"}]})
                return
        if loop_prompt == "ASK_USER_R13_EXEC":
            tool_names = [tool["function"]["name"] for tool in body.get("tools", [])]
            assert "ask_user" in tool_names, f"resumed exec session with ask_user history must declare schema (R13): {tool_names}"
            assert "Use ask_user" not in body["messages"][0]["content"], "non-interactive exec must not advertise ask_user in system prompt"
            turn = body["messages"][actual_user + 1:]
            tool_msgs = [m for m in turn if m["role"] == "tool"]
            if len(tool_msgs) == 0:
                self.reply({"choices": [{"message": {"role": "assistant", "content": None,
                           "tool_calls": [{"id": "call_ask_r13", "type": "function", "function": {
                               "name": "ask_user",
                               "arguments": json.dumps({"questions": [{
                                   "question": "Ветка в exec?",
                                   "options": ["main", "dev"],
                               }]})}}]},
                           "finish_reason": "tool_calls"}]})
            elif len(tool_msgs) == 1:
                err = json.loads(tool_msgs[-1]["content"])
                assert err.get("error") == "non_interactive", err
                self.reply({"choices": [{"message": {"role": "assistant", "content": None,
                           "tool_calls": [{"id": "call_list_r13", "type": "function", "function": {
                               "name": "list_files",
                               "arguments": json.dumps({"path": "."})}}]},
                           "finish_reason": "tool_calls"}]})
            else:
                self.reply({"choices": [{"message": {"role": "assistant", "content": "ASK_USER_R13_EXEC_OK"},
                                         "finish_reason": "stop"}]})
            return
        if loop_prompt == "MEMORY_AUTOEDIT_APPROVAL":
            tool_names = [tool["function"]["name"] for tool in body.get("tools", [])]
            turn = body["messages"][actual_user + 1:]
            tool_msgs = [m for m in turn if m["role"] == "tool"]
            if len(tool_msgs) == 0:
                assert "write_memory" in tool_names, tool_names
                assert "read_memory" not in tool_names, tool_names
                self.reply({"choices": [{"message": {"role": "assistant", "content": None,
                           "tool_calls": [{"id": "call_pty_mem_w", "type": "function", "function": {
                               "name": "write_memory",
                               "arguments": json.dumps({
                                   "op": "create",
                                   "scope": "project",
                                   "name": "conventions",
                                   "description": "PTY conventions",
                                   "content": "- [stated] Always run PTY smoke.\n",
                               })}}]},
                           "finish_reason": "tool_calls"}]})
            elif len(tool_msgs) == 1:
                receipt = json.loads(tool_msgs[-1]["content"])
                assert receipt.get("id") == "project/conventions", receipt
                assert "read_memory" in tool_names, tool_names
                assert "<rcode_memory_index>" in body["messages"][0]["content"]
                self.reply({"choices": [{"message": {"role": "assistant", "content": None,
                           "tool_calls": [{"id": "call_pty_mem_r", "type": "function", "function": {
                               "name": "read_memory",
                               "arguments": json.dumps({"id": "project/conventions"})}}]},
                           "finish_reason": "tool_calls"}]})
            else:
                receipt = json.loads(tool_msgs[-1]["content"])
                assert "Always run PTY smoke." in receipt.get("content", ""), receipt
                self.reply({"choices": [{"message": {"role": "assistant", "content": "MEMORY_PTY_DONE"},
                                         "finish_reason": "stop"}]})
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
            if loop_prompt == "TOOL_DETAILS_TOGGLE":
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Connection", "close")
                self.end_headers()

                def detail_event(value):
                    self.wfile.write(("data: " + json.dumps(value, ensure_ascii=False) + "\n\n").encode())
                    self.wfile.flush()

                try:
                    detail_event({"choices": [{"delta": {"content": "TOOL_DETAIL_WAITING"}, "finish_reason": None}]})
                    self.server.detail_started.set()
                    self.server.release_detail.wait(timeout=6)
                    detail_event({"choices": [{"delta": {}, "finish_reason": "stop"}]})
                    self.wfile.write(b"data: [DONE]\n\n")
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    pass
                return
            self.reply({"choices": [{"message": {"role": "assistant", "content": "TOOL_FINISHED_" + prompt},
                                     "finish_reason": "stop"}]})
            return
        if prompt == "queued вопрос":
            self.reply({"choices": [{"message": {"role": "assistant",
                                                 "content": "QUEUED_TURN_DONE"},
                                      "finish_reason": "stop"}],
                        "usage": {"prompt_tokens": 9, "completion_tokens": 3}})
            return
        if prompt == "BUSY_TYPE_PROMPT":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Connection", "close")
            self.end_headers()

            def event(value):
                self.wfile.write(("data: " + json.dumps(value, ensure_ascii=False) + "\n\n").encode())
                self.wfile.flush()
            try:
                event({"choices": [{"delta": {"content": "BUSY_FIRST " + "." * 48 + "\n"}, "finish_reason": None}]})
                self.server.busy_started.set()
                self.server.release_busy.wait(timeout=6)
                event({"choices": [{"delta": {"content": "BUSY_SECOND\n"}, "finish_reason": None}]})
                event({"choices": [{"delta": {}, "finish_reason": "stop"}],
                       "usage": {"prompt_tokens": 21, "completion_tokens": 4}})
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
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
        if prompt in ("APPROVAL_DENY", "APPROVAL_YES", "APPROVAL_RIGHT"):
            filename = {"APPROVAL_DENY": "denied.txt", "APPROVAL_YES": "approved.txt",
                        "APPROVAL_RIGHT": "right.txt"}[prompt]
            self.reply({"choices": [{"message": {"role": "assistant", "content": None,
                       "tool_calls": [{"id": "call_" + prompt, "type": "function", "function": {
                           "name": "write_file", "arguments": json.dumps({"path": filename, "content": "approved via PTY\n"})}}]},
                       "finish_reason": "tool_calls"}]})
            return
        if prompt in ("WEBSEARCH_CHOICE", "WEBSEARCH_SETUP"):
            self.reply({"choices": [{"message": {"role": "assistant", "content": None,
                       "tool_calls": [{"id": "call_" + prompt, "type": "function", "function": {
                           "name": "web_search", "arguments": json.dumps({"query": "gstack rcode"})}}]},
                       "finish_reason": "tool_calls"}]})
            return
        if prompt == "APPROVAL_ALWAYS":
            self.reply({"choices": [{"message": {"role": "assistant", "content": None,
                       "tool_calls": [{"id": "call_" + prompt, "type": "function", "function": {
                           "name": "run_command", "arguments": json.dumps({"command": "printf 'always via PTY\n' > always.txt"})}}]},
                       "finish_reason": "tool_calls"}]})
            return
        if prompt == "APPROVAL_LEFT":
            self.reply({"choices": [{"message": {"role": "assistant", "content": None,
                       "tool_calls": [{"id": "call_" + prompt, "type": "function", "function": {
                           "name": "run_command", "arguments": json.dumps({"command": "touch arrow-left.txt\n# comment"})}}]},
                       "finish_reason": "tool_calls"}]})
            return
        if prompt == "TOOL_DETAILS_TOGGLE" and body["messages"][-1]["role"] == "user":
            self.reply({"choices": [{"message": {"role": "assistant", "content": None,
                       "tool_calls": [{"id": "call_tool_details", "type": "function", "function": {
                           "name": "run_command", "arguments": json.dumps({"command": "printf 'first output\\nsecond output\\nthird output\\n'"})}}]},
                       "finish_reason": "tool_calls"}]})
            return
        if prompt == "ALWAYS_REPEAT":
            self.reply({"choices": [{"message": {"role": "assistant", "content": None,
                       "tool_calls": [{"id": "call_" + prompt, "type": "function", "function": {
                           "name": "run_command", "arguments": json.dumps({"command": "printf 'repeat\n' > always.txt"})}}]},
                       "finish_reason": "tool_calls"}]})
            return
        if body["messages"][0]["content"].startswith("Ты выполняешь отдельное финальное ревью"):
            answer = "FINAL_REVIEW_VISIBLE"
        elif prompt == "CANCEL_REQUEST":
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
            config = load_json(config_path)
            config["providers"]["gigachat"] = {
                "kind": "gigachat", "model": "GigaChat-3-Ultra",
                "base_url": f"http://127.0.0.1:{fixture.server_port}/giga/v1",
                "auth_url": f"http://127.0.0.1:{fixture.server_port}/giga/oauth",
            }
            config_path.write_text(json.dumps(config))
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

            # Review target selection is local configuration only; the
            # per-run toggle controls whether a later user turn gets one
            # separate text-only request to the selected route.
            before_review_settings = len(fixture.recorded())
            terminal.command("/review-model openrouter review-fixture-model", "Цель финального ревью сохранена")
            config = load_json(config_path)
            assert config["active"] == "custom", "selecting a reviewer must preserve the main provider"
            assert config["providers"]["openrouter"]["model"] == "alpha-one"
            assert config["final_review"]["selected"]["snapshot"]["model"] == "review-fixture-model"
            terminal.command("/review-model same", "Цель финального ревью: текущая основная модель")
            terminal.command("/review-model status", "выключено")
            terminal.command("/final-review status", "выключено")
            terminal.command("/final-review on", "включено для последующих ходов")
            terminal.command("/review-model status", "включено")
            terminal.command("/final-review off", "Финальное ревью выключено")
            assert len(fixture.recorded()) == before_review_settings, "review configuration and toggles must not call a model"

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
            rows = terminal.grid.rows()
            search_row = next(i for i, row in enumerate(rows) if row.startswith("Поиск:"))
            assert rows[search_row + 1].startswith("› Gamma choice"), "Saved model must be first and selected: " + terminal.dump()
            terminal.send("\r")
            terminal.until(terminal.editor_ready, "Enter accepts the saved model")
            assert load_json(config_path) == before_config, "Accepting saved model changed settings"
            assert session_provider(home) == before_provider, "Accepting saved model reset effort"
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
            terminal.send("\x15")
            terminal.drain()
            assert terminal.busy_ready(), "Ctrl+U during busy must keep the busy panel"
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

            phase("queued typing during turn")

            # Печатаем во время хода: черновик виден в панели, Enter — в очередь.
            mark = terminal.mark()
            terminal.send("BUSY_TYPE_PROMPT\r")
            terminal.until(fixture.busy_started.is_set, "busy turn started for queued typing")
            terminal.expect_body("BUSY_FIRST")
            terminal.until(terminal.busy_ready, "busy panel for queued typing")
            terminal.send("queued вопрос")
            terminal.drain()
            terminal.until(lambda: "▸ queued вопрос" in terminal.text(mark),
                           "draft row shown in the busy panel")
            terminal.send("\r")
            terminal.until(lambda: "в очереди: 1" in terminal.text(mark),
                           "queued message counter")
            fixture.release_busy.set()
            terminal.editor_after("BUSY_SECOND", mark)
            # После хода очередь отправляется сама: новый ход с этим сообщением.
            terminal.until(lambda: "QUEUED_TURN_DONE" in terminal.text(mark),
                           "queued turn executed automatically")
            terminal.expect_body("QUEUED_TURN_DONE")
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

            # Metadata must arrive without a keypress, preserving typed search
            # and the highlighted provider. Cancelling never switches accounts.
            before_config = load_json(config_path)
            before_provider = session_provider(home)
            before_models = len(fixture.recorded())
            fixture.balance_started.clear()
            fixture.release_balance.clear()
            terminal.command("/provider", "Провайдер")
            terminal.send("openrouter")
            terminal.until(lambda: any(row.startswith("Поиск: openrouter") for row in terminal.grid.rows()),
                           "search while provider balances are pending")
            terminal.until(fixture.balance_started.is_set, "provider menu requests real metadata")
            fixture.release_balance.set()
            terminal.until(lambda: any(row.startswith("› openrouter") and "(Баланс $20.00)" in row
                                       for row in terminal.grid.rows()), "OpenRouter balance updates selected row")
            assert any(row.startswith("Поиск: openrouter") for row in terminal.grid.rows()), "Balance refresh lost search"
            terminal.send("\x15")
            terminal.until(lambda: any("gigachat" in row and "(Остаток 1.2m ток.)" in row
                                       for row in terminal.grid.rows()), "GigaChat balance uses saved Ultra pool")
            terminal.send("\x1b")
            terminal.until(terminal.editor_ready, "provider menu cancellation")
            assert load_json(config_path) == before_config, "Balance menu changed config"
            assert session_provider(home) == before_provider, "Balance menu switched provider"
            assert len(fixture.recorded()) == before_models, "Balance menu called a model"
            fixture.fail_balance = True
            mark = terminal.command("/provider", "Провайдер")
            terminal.until(lambda: any("openrouter" in row and "(Баланс: недоступен)" in row
                                       for row in terminal.grid.rows()), "provider balance error is local to row")
            assert "upstream-balance-secret" not in terminal.text(mark)
            terminal.send("\x1b")
            terminal.until(terminal.editor_ready, "provider menu after balance error")
            fixture.fail_balance = False

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

            mark = terminal.mark()
            terminal.send("APPROVAL_RIGHT\r")
            terminal.until(lambda: "› Отклонить" in terminal.grid.rows()[-4]
                           and "Разрешить один раз" in terminal.grid.rows()[-4],
                           "two-option approval before Right")
            terminal.send("\x1b[C")
            terminal.until(lambda: "  Отклонить" in terminal.grid.rows()[-4]
                           and "› Разрешить один раз" in terminal.grid.rows()[-4],
                           "Right selects one-time approval")
            terminal.send("\r")
            terminal.editor_after("TOOL_FINISHED_APPROVAL_RIGHT", mark)
            assert (workspace / "right.txt").read_text() == "approved via PTY\n"

            phase("always rule")

            # Left wraps from the default deny choice to the final choice.
            # Enter must therefore save the "touch" shell rule, not approve once.
            mark = terminal.mark()
            terminal.send("APPROVAL_LEFT\r")
            terminal.until(lambda: "› Отклонить" in terminal.grid.rows()[-4]
                           and "Разрешить «touch» всегда" in terminal.grid.rows()[-4],
                           "approval panel before left navigation")
            terminal.expect_body("╭─ sh")
            terminal.expect_body("touch arrow-left.txt")
            terminal.expect_body("# comment")
            code_row = next(index for index, row in enumerate(terminal.grid.rows())
                            if "touch arrow-left.txt" in row)
            code_start = terminal.grid.rows()[code_row].index("touch arrow-left.txt")
            code_end = code_start + len("touch arrow-left.txt")
            assert all(color is not None and color.startswith("48;5;236")
                       for color in terminal.grid.backgrounds[code_row][code_start:code_end]), terminal.dump()
            terminal.send("\x1b[D")
            terminal.until(lambda: "  Отклонить" in terminal.grid.rows()[-4]
                           and "  Разрешить один раз" in terminal.grid.rows()[-4]
                           and "› Разрешить «touch» всегда" in terminal.grid.rows()[-4],
                           "Left selects the previous approval option")
            row = terminal.grid.rows()[-4]
            selected_start = row.index("› Разрешить «touch» всегда")
            selected_end = selected_start + len("› Разрешить «touch» всегда")
            selected_backgrounds = terminal.grid.backgrounds[-4][selected_start:selected_end]
            assert selected_backgrounds and all(color is not None for color in selected_backgrounds), terminal.dump()
            denied_start = row.index("Отклонить")
            denied_end = denied_start + len("Отклонить")
            assert all(color is None for color in terminal.grid.backgrounds[-4][denied_start:denied_end]), terminal.dump()
            terminal.send("\x1b[B")
            terminal.until(lambda: "› Отклонить" in terminal.grid.rows()[-4], "Down wraps to deny")
            terminal.send("\x1b[C")
            terminal.until(lambda: "› Разрешить один раз" in terminal.grid.rows()[-4], "Right selects the next option")
            terminal.send("\t")
            terminal.until(lambda: "› Разрешить «touch» всегда" in terminal.grid.rows()[-4], "Tab selects the next option")
            terminal.send("\x1b[Z")
            terminal.until(lambda: "› Разрешить один раз" in terminal.grid.rows()[-4], "BackTab selects the previous option")
            terminal.send("\x1b[A")
            terminal.until(lambda: "› Отклонить" in terminal.grid.rows()[-4], "Up selects the previous option")
            terminal.send("\x1b[D")
            terminal.until(lambda: "› Разрешить «touch» всегда" in terminal.grid.rows()[-4], "Left wraps to the final option")
            terminal.capture("approval_left_selected")
            terminal.send("\r")
            terminal.editor_after("TOOL_FINISHED_APPROVAL_LEFT", mark)
            assert (workspace / "arrow-left.txt").exists(), terminal.dump()
            assert any("touch" in rules for rules in
                       json.loads((home / "permissions.json").read_text())["shell_allow"].values())

            # «Разрешить похожие»: a сохраняет первый токен команды в
            # permissions.json; повторная команда с тем же токеном идёт без панели.
            mark = terminal.mark()
            terminal.send("APPROVAL_ALWAYS\r")
            terminal.until(lambda: "› Отклонить" in terminal.grid.rows()[-4]
                           and "Разрешить «printf» всегда" in terminal.grid.rows()[-4],
                           "approval panel with the always option")
            terminal.send("a")
            terminal.editor_after("TOOL_FINISHED_APPROVAL_ALWAYS", mark)
            assert (workspace / "always.txt").read_text() == "always via PTY\n", terminal.dump()

            # Ctrl+O changes only the visible receipt detail while the next
            # model response is held; the receipt remains available in history.
            mark = terminal.mark()
            terminal.send("TOOL_DETAILS_TOGGLE\r")
            terminal.until(fixture.detail_started.is_set, "tool receipt before held model response")
            terminal.until(lambda: "exit 0 · успешно" in "\n".join(terminal.grid.rows())
                           and "first output" in "\n".join(terminal.grid.rows())
                           and "Ctrl+O подробности" in terminal.grid.rows()[-1],
                           "compact receipt and expansion hint")
            assert "third output" not in "\n".join(terminal.grid.rows()), terminal.dump()
            terminal.capture("tool_receipt_compact")
            terminal.send("\x0f")
            terminal.until(lambda: "third output" in "\n".join(terminal.grid.rows())
                           and "Ctrl+O свернуть вывод" in terminal.grid.rows()[-1],
                           "expanded command receipt")
            terminal.capture("tool_receipt_expanded")
            terminal.send("\x0f")
            terminal.until(lambda: "third output" not in "\n".join(terminal.grid.rows())
                           and "Ctrl+O подробности" in terminal.grid.rows()[-1],
                           "collapsed command receipt")
            fixture.release_detail.set()
            terminal.resize(80, 24)
            terminal.editor_after("TOOL_DETAIL_WAITING", mark)
            terminal.until(lambda: "Ctrl+O детали" in terminal.grid.rows()[-1],
                           "idle toggle hint on an 80-column terminal")
            terminal.capture("tool_receipt_compact_idle_80")
            terminal.send("\x0f")
            terminal.until(lambda: "third output" in "\n".join(terminal.grid.rows())
                           and "Ctrl+O свернуть" in terminal.grid.rows()[-1],
                           "idle expansion shortcut")
            assert terminal.editor_ready(), "Idle Ctrl+O must not alter the editor cursor"
            terminal.capture("tool_receipt_expanded_idle_80")
            terminal.send("\x0f")
            terminal.until(lambda: "third output" not in "\n".join(terminal.grid.rows())
                           and "Ctrl+O детали" in terminal.grid.rows()[-1],
                           "idle collapse shortcut")
            terminal.resize(140, 28)
            terminal.until(terminal.editor_ready, "wide composer after detail preview")

            import json as _json
            rules = _json.loads((home / "permissions.json").read_text())
            saved = [rules_ for rules_ in rules["shell_allow"].values()
                     if "printf" in rules_]
            assert saved, rules
            repeat_mark = terminal.mark()
            terminal.send("ALWAYS_REPEAT\r")
            terminal.editor_after("TOOL_FINISHED_ALWAYS_REPEAT", repeat_mark)
            assert (workspace / "always.txt").read_text() == "repeat\n", terminal.dump()
            # Если бы правило не сработало, ход застрял бы на панели: попасть
            # в editor_after без нажатий стало бы невозможно.
            assert not any(
                "› Отклонить" in row for row in terminal.grid.rows()[-6:]
            ), terminal.dump()

            phase("loop choice panel")
            for prompt, answer, expected in [("LOOP_ABORT", "\r", "LOOP_SUMMARY_ABORT"),
                                             ("LOOP_CONTINUE", "\x1b[B\r", "LOOP_CONTINUED")]:
                mark = terminal.mark()
                before = len(fixture.recorded())
                terminal.send(prompt + "\r")
                terminal.until(lambda: any("› Прервать ход и получить резюме" in row
                                           for row in terminal.grid.rows()[:-2])
                               and any("Продолжить ход (разрешаю повторы)" in row
                                       for row in terminal.grid.rows()[:-2]),
                               "loop choice above pinned footer")
                terminal.assert_footer("openrouter", "ask")
                assert len(fixture.recorded()) == before + 4, "Панель должна остановить генерации после четырёх повторов"
                terminal.capture(prompt.lower())
                terminal.send(answer)
                terminal.editor_after(expected, mark)
                assert len(fixture.recorded()) == before + 5, "Выбор должен вызвать ровно один следующий запрос"

            phase("websearch choice panel")

            # Esc в панели выбора — «Пропустить»: ход получает not_configured.
            mark = terminal.mark()
            terminal.send("WEBSEARCH_CHOICE\r")
            terminal.until(lambda: "Пропустить — настроить позже" in terminal.text(mark),
                           "websearch provider choice panel")
            terminal.pump(0)
            time.sleep(0.2)
            terminal.pump(0)
            terminal.send("\x1b")
            terminal.editor_after("TOOL_FINISHED_WEBSEARCH_CHOICE", mark)
            config_path = home / "config.json"
            assert not config_path.exists() or "websearch" not in config_path.read_text(), \
                "Esc не должен менять конфигурацию"

            # Enter выбирает первого провайдера (Yandex); ключ ещё не задан.
            mark = terminal.mark()
            terminal.send("WEBSEARCH_SETUP\r")
            terminal.until(lambda: "Пропустить — настроить позже" in terminal.text(mark),
                           "websearch provider choice panel again")
            terminal.pump(0)
            time.sleep(0.2)
            terminal.pump(0)
            terminal.send("\r")
            terminal.editor_after("TOOL_FINISHED_WEBSEARCH_SETUP", mark)
            import json as _json
            config = _json.loads(config_path.read_text())
            assert config["websearch"]["provider"] == "yandex", config

            phase("ask_user panel")
            # 1. Выбор варианта стрелкой + Enter; нижний колонтитул остаётся на последних 2 строках.
            mark = terminal.mark()
            terminal.send("ASK_USER_SELECT\r")
            terminal.until(lambda: "Формат отчёта?" in terminal.text(mark) and "Свой вариант…" in terminal.text(mark),
                           "ask_user option list panel")
            terminal.assert_footer("alpha-one", "openrouter", "high", "ask")
            terminal.pump(0)
            time.sleep(0.18)
            terminal.pump(0)
            terminal.send("\x1b[B\r")
            terminal.editor_after("ASK_USER_SELECT_DONE", mark)

            # 2. Inline «Свой вариант…»: Unicode paste -> Esc в список с сохранением черновика -> Enter -> отправка.
            mark = terminal.mark()
            terminal.send("ASK_USER_CUSTOM\r")
            terminal.until(lambda: "Целевой стек?" in terminal.text(mark) and "Свой вариант…" in terminal.text(mark),
                           "ask_user custom option list")
            terminal.pump(0)
            time.sleep(0.18)
            terminal.pump(0)
            terminal.send("3\r")
            terminal.until(
                lambda: any("Свой ответ · Уточнение" in row for row in terminal.grid.rows())
                and terminal.grid.cursor_visible,
                "ask_user inline custom editor",
            )
            terminal.assert_footer("alpha-one", "openrouter", "high", "ask")
            terminal.send("\x1b[200~Свой стек 👩🏽‍💻\x1b[201~")
            terminal.until(
                lambda: any("Свой стек" in row for row in terminal.grid.rows()),
                "pasted custom text visible",
            )
            terminal.send("\x1b")
            terminal.until(
                lambda: any("↑/↓ — выбор" in row for row in terminal.grid.rows())
                and not terminal.grid.cursor_visible,
                "escape returns from custom input to option list",
            )
            time.sleep(0.18)
            terminal.pump(0)
            terminal.send("\r")
            terminal.until(
                lambda: any("Свой стек" in row for row in terminal.grid.rows())
                and terminal.grid.cursor_visible,
                "re-entering custom input preserves draft",
            )
            time.sleep(0.18)
            terminal.pump(0)
            terminal.send("\r")
            terminal.editor_after("ASK_USER_CUSTOM_DONE", mark)

            # 3. Ошибка инструмента перед ask_user + Esc в ask_user не вызывает лишний recovery-запрос.
            before_esc = len(fixture.recorded())
            mark = terminal.mark()
            terminal.send("ASK_USER_ESC_AFTER_ERROR\r")
            terminal.until(lambda: "Создать шаблон?" in terminal.text(mark),
                           "ask_user panel after read_file error")
            terminal.pump(0)
            time.sleep(0.18)
            terminal.pump(0)
            terminal.send("\x1b")
            terminal.editor_after("ASK_USER_ESC_CLEAN_DONE", mark)
            assert len(fixture.recorded()) == before_esc + 3, (
                f"expected exactly 3 requests without recovery, got {len(fixture.recorded()) - before_esc}"
            )

            # 4. Ctrl+C внутри открытой панели ask_user мгновенно прерывает ход и возвращает редактор.
            before_ask_ctrlc = len(fixture.recorded())
            mark = terminal.mark()
            terminal.send("ASK_USER_CTRL_C\r")
            terminal.until(lambda: "Канал уведомлений?" in terminal.text(mark),
                           "ask_user panel before Ctrl+C")
            terminal.pump(0)
            time.sleep(0.12)
            terminal.pump(0)
            terminal.send("\x03")
            terminal.editor_after("Ход прерван", mark)
            assert len(fixture.recorded()) == before_ask_ctrlc + 1, (
                f"Ctrl+C inside ask_user must not send a second model request, got {len(fixture.recorded()) - before_ask_ctrlc}"
            )
            mark = terminal.mark()
            terminal.send("AFTER_CANCEL\r")
            terminal.editor_after("READY_RECOVERED", mark)

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
            terminal.expect_body("Память")

            # Даже в режиме auto-edit запись межсессионной памяти через write_memory
            # требует отдельного diff-подтверждения оператора!
            phase("memory auto-edit diff approval and /memory commands")
            mark = terminal.mark()
            terminal.send("MEMORY_AUTOEDIT_APPROVAL\r")
            terminal.until(
                lambda: "Межсессионная память rcode" in terminal.text(mark)
                and "› Отклонить" in terminal.grid.rows()[-4],
                "write_memory diff approval panel even in auto-edit mode",
            )
            terminal.assert_footer("openrouter", "auto-edit")
            terminal.send("Y\r")
            terminal.editor_after("MEMORY_PTY_DONE", mark)
            terminal.command("/memory", "Межсессионная память: включена")
            terminal.expect_body("project/conventions")
            terminal.command("/memory show project/conventions", "Always run PTY smoke.")
            terminal.command("/memory log project/conventions", "История ревизий project/conventions")
            terminal.command("/memory undo project/conventions", "✓ Откат заметки project/conventions выполнен.")
            terminal.command("/memory off --project", "выключена")
            terminal.command("/memory on --project", "включена")

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
            # Exercise the enabled/disabled interactive stage in an isolated
            # PTY home so its requests do not alter earlier token assertions.
            review_workspace, review_home = root / "review-project", root / "review-config"
            review_workspace.mkdir(mode=0o700)
            review_home.mkdir(mode=0o700)
            review_config_path = review_home / "config.json"
            review_config_path.write_text(json.dumps({
                "version": 1, "active": "custom",
                "providers": {
                    "custom": {"kind":"custom","model":"review-primary","base_url":endpoint,"stream":False},
                    "openrouter": {"kind":"openrouter","model":"review-default","base_url":endpoint,"stream":False},
                },
            }))
            review_config_path.chmod(0o600)
            review_terminal = Terminal(binary, review_workspace, review_home)
            try:
                review_terminal.until(review_terminal.editor_ready, "isolated final-review PTY editor")
                review_terminal.command("/review-model openrouter review-selected", "Цель финального ревью сохранена")
                assert (load_json(review_config_path) or {})["active"] == "custom"
                requests_before = len(fixture.recorded())
                review_terminal.command("/final-review on", "включено для последующих ходов")
                turn_mark = review_terminal.mark()
                review_terminal.send("FINAL_REVIEW_PTY_ON\r")
                review_terminal.until(lambda: len(fixture.recorded()) == requests_before + 2,
                                      "interactive review adds exactly one selected-provider request")
                review_terminal.editor_after("READY_CUSTOM", turn_mark)
                review_terminal.expect_body("Ответ финального ревью · openrouter / review-selected")
                review_terminal.expect_body("FINAL_REVIEW_VISIBLE")
                request_pair = fixture.recorded()[requests_before:]
                selected_request = next(request for request in request_pair
                                        if request["messages"][0]["content"].startswith("Ты выполняешь отдельное финальное ревью"))
                assert selected_request["model"] == "review-selected", selected_request
                assert len(selected_request["messages"]) == 2, selected_request
                assert not selected_request.get("tools"), selected_request
                saved_review = list((review_home / "sessions").glob("*/session.json"))
                assert len(saved_review) == 1
                assert load_json(saved_review[0])["final_reviews"][-1]["status"] == "completed"
                review_terminal.command("/final-review off", "Финальное ревью выключено")
                before_off = len(fixture.recorded())
                turn_mark = review_terminal.mark()
                review_terminal.send("FINAL_REVIEW_PTY_OFF\r")
                review_terminal.until(lambda: len(fixture.recorded()) == before_off + 1,
                                      "disabled interactive turn makes only its primary request")
                review_terminal.editor_after("READY_CUSTOM", turn_mark)
                assert len(load_json(saved_review[0])["final_reviews"]) == 1
                review_terminal.send("\x04")
                review_terminal.until(lambda: review_terminal.status is not None, "final-review PTY exits")
                assert review_terminal.status == 0
            finally:
                review_terminal.close()
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
                saved_before = set((home / "sessions").glob("*/session.json"))
                requests_before = len(fixture.recorded())
                plain_mark = plain.mark()
                plain.send("/new\r")
                plain.expect("Новая сессия:", plain_mark)
                plain.expect("rcode ›", plain_mark)
                created = set((home / "sessions").glob("*/session.json")) - saved_before
                assert len(created) == 1, "New runtime did not publish exactly one session"
                new_session = next(iter(created)).parent.name
                plain_mark = plain.mark()
                plain.send(f"/resume {new_session}\r")
                plain.expect("Сессия восстановлена:", plain_mark)
                plain.expect("rcode ›", plain_mark)
                assert len(fixture.recorded()) == requests_before, "Session lease handoff triggered generation"
                plain_mark = plain.mark()
                plain.send("AFTER_SESSION_LEASE_HANDOFF\r")
                plain.expect("READY_CUSTOM", plain_mark)
                plain.expect("rcode ›", plain_mark)
                assert fixture.recorded()[-1]["messages"][-1]["content"] == "AFTER_SESSION_LEASE_HANDOFF"
                # --plain interactive ask_user: выбор по номеру и немедленный выход по Ctrl+C (SIGINT).
                plain_mark = plain.mark()
                plain.send("ASK_USER_SELECT\r")
                plain.expect("Номер 1–3 (0 — отмена):", plain_mark)
                plain.send("2\r")
                plain.expect("ASK_USER_SELECT_DONE", plain_mark)
                plain.expect("rcode ›", plain_mark)

                before_plain_ctrlc = len(fixture.recorded())
                plain_mark = plain.mark()
                plain.send("ASK_USER_CTRL_C\r")
                plain.expect("Номер 1–3 (0 — отмена):", plain_mark)
                plain.send("\x03")
                plain.expect("Ход прерван", plain_mark)
                plain.expect("rcode ›", plain_mark)
                assert len(fixture.recorded()) == before_plain_ctrlc + 1

                plain.send("/exit\r")
                plain.until(lambda:plain.status is not None,"plain exit")
                assert plain.status == 0

                # R13 end-to-end: rcode exec --json --resume <session> объявляет схему ask_user без guidance и возвращает non_interactive.
                resumed_exec = subprocess.run(
                    [binary, "-C", str(workspace), "exec", "--json", "--resume", new_session, "ASK_USER_R13_EXEC"],
                    cwd=workspace,
                    env={
                        "PATH": "/usr/bin:/bin",
                        "TERM": "xterm-256color",
                        "LANG": "C.UTF-8",
                        "RCODE_HOME": str(home),
                        "RCODE_CUSTOM_API_KEY": "pty-custom-fixture",
                        "RCODE_OPENROUTER_API_KEY": "pty-router-fixture",
                        "RCODE_GIGACHAT_AUTH_KEY": "pty-giga-fixture",
                    },
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                assert resumed_exec.returncode == 0, f"exec --resume failed ({resumed_exec.returncode}): {resumed_exec.stdout}\n{resumed_exec.stderr}"
                assert "ASK_USER_R13_EXEC_OK" in resumed_exec.stdout, resumed_exec.stdout
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
            # A copied provider entry must never forward another account's key
            # merely because its row is visible in the provider menu.
            config = load_json(config_path)
            config["active"] = "custom"
            config["providers"]["openrouter"] = config["providers"]["gigachat"].copy()
            config_path.write_text(json.dumps(config))
            oauth_before = len(fixture.oauth_credentials)
            mismatch = Terminal(binary, workspace, home)
            try:
                mismatch.until(mismatch.editor_ready, "composer with inactive mismatched provider config")
                mismatch.command("/provider", "Провайдер")
                mismatch.until(lambda: any("openrouter" in row and "(Баланс: недоступен)" in row
                                          for row in mismatch.grid.rows()) and
                                      any("gigachat" in row and "(Остаток 1.2m ток.)" in row
                                          for row in mismatch.grid.rows()), "mismatched provider metadata rejected")
                assert "Basic pty-router-fixture" not in fixture.oauth_credentials[oauth_before:], "Menu forwarded another provider's credential"
                mismatch.send("\x1b")
                mismatch.until(mismatch.editor_ready, "cancel mismatched provider menu")
                mismatch.send("\x04")
                mismatch.until(lambda: mismatch.status is not None, "mismatch fixture exit")
                assert mismatch.status == 0
            finally:
                mismatch.close()
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
        fixture.release_detail.set()
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
