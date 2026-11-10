"""Small, loopback-only HTTP adapter for the root protocol gateway."""
from __future__ import annotations

import http.client
import json
import socket
import socketserver
import threading
import unittest
import urllib.parse

_MAX_BODY = 2 * 1024 * 1024
_MAX_RESPONSE = 4 * 1024 * 1024
_MAX_HEADER_BYTES = 65536
_MAX_HEADER_LINE = 8192
_MAX_HEADERS = 64


class _HTTPError(Exception):
    def __init__(self, status: int):
        self.status = status


class _Reader:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = bytearray()

    def _more(self) -> None:
        chunk = self.sock.recv(4096)
        if not chunk:
            raise _HTTPError(400)
        self.buf.extend(chunk)

    def line(self, limit: int) -> bytes:
        while True:
            pos = self.buf.find(b"\n")
            if pos >= 0:
                if pos == 0 or self.buf[pos - 1] != 13:
                    raise _HTTPError(400)
                if pos + 1 > limit:
                    raise _HTTPError(431)
                result = bytes(self.buf[:pos - 1])
                del self.buf[:pos + 1]
                return result
            if len(self.buf) >= limit:
                raise _HTTPError(431)
            self._more()

    def exact(self, size: int) -> bytes:
        while len(self.buf) < size:
            self._more()
        result = bytes(self.buf[:size])
        del self.buf[:size]
        return result


class _ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    block_on_close = False
    request_queue_size = 4
    allow_reuse_address = False

    def __init__(self, address, handler, model, parse_json, relay, provider, oauth_scope):
        self._slots = threading.BoundedSemaphore(4)
        self.model = model
        self.parse_json = parse_json
        self.relay = relay
        self.provider = provider
        self.oauth_scope = oauth_scope
        super().__init__(address, handler, bind_and_activate=True)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            try:
                self.finish_request(request, client_address)
            except Exception:
                self.handle_error(request, client_address)
            finally:
                self.shutdown_request(request)
        finally:
            self._slots.release()

    def handle_error(self, request, client_address):
        # Do not let framework tracebacks expose callback or request details.
        pass


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3.0)
        try:
            self._serve()
        except socket.timeout:
            self._respond(408, {"error": "request timeout"})
        except _HTTPError as exc:
            messages = {400: "bad request", 413: "request too large", 431: "headers too large"}
            self._respond(exc.status, {"error": messages.get(exc.status, "bad request")})
        except (OSError, ValueError):
            # I/O failures may make a response impossible; malformed input is
            # answered with a fixed, non-reflective error when the socket allows.
            try:
                self._respond(400, {"error": "bad request"})
            except OSError:
                pass
        except Exception:
            self._respond(502, {"error": "gateway failure"})

    def _serve(self):
        reader = _Reader(self.request)
        request_line = reader.line(_MAX_HEADER_LINE)
        try:
            request_line.decode("ascii")
        except UnicodeDecodeError:
            raise _HTTPError(400)
        parts = request_line.split(b" ")
        if len(parts) != 3 or not all(parts):
            raise _HTTPError(400)
        method, target, version = parts
        if version not in (b"HTTP/1.0", b"HTTP/1.1"):
            raise _HTTPError(400)

        headers = {}
        total = len(request_line) + 2
        while True:
            line = reader.line(_MAX_HEADER_LINE)
            total += len(line) + 2
            if total > _MAX_HEADER_BYTES:
                raise _HTTPError(431)
            if not line:
                break
            if line[:1] in (b" ", b"\t") or b":" not in line:
                raise _HTTPError(400)
            name, value = line.split(b":", 1)
            if not name or any(c not in b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" for c in name):
                raise _HTTPError(400)
            try:
                value.decode("ascii")
            except UnicodeDecodeError:
                raise _HTTPError(400)
            key = name.decode("ascii").lower()
            if key in headers:
                raise _HTTPError(400)
            headers[key] = value.strip(b" \t")
            if len(headers) > _MAX_HEADERS:
                raise _HTTPError(431)

        if "transfer-encoding" in headers:
            raise _HTTPError(400)
        if method not in (b"GET", b"POST"):
            self._respond(405, {"error": "method not allowed"})
            return
        if method == b"GET":
            if "content-length" in headers:
                raw = headers["content-length"]
                if not raw.isdigit() or int(raw) != 0:
                    raise _HTTPError(400)
            if target == b"/v1/models":
                self._respond(200, {"object": "list", "data": [{"id": self.server.model, "object": "model"}]})
            else:
                self._respond(404, {"error": "not found"})
            return

        if "content-length" not in headers:
            raise _HTTPError(400)
        raw_length = headers["content-length"]
        if not raw_length or any(c < 48 or c > 57 for c in raw_length):
            raise _HTTPError(400)
        length = int(raw_length)
        if length > _MAX_BODY:
            raise _HTTPError(413)
        body = reader.exact(length)
        if target == b"/api/v2/oauth" and self.server.provider == "gigachat":
            if headers.get("content-type") != b"application/x-www-form-urlencoded":
                raise _HTTPError(400)
            try:
                form = urllib.parse.parse_qs(
                    body.decode("ascii"), keep_blank_values=True,
                    strict_parsing=True, max_num_fields=2,
                )
            except (UnicodeError, ValueError):
                raise _HTTPError(400)
            if form != {"scope": [self.server.oauth_scope]}:
                raise _HTTPError(400)
            self._respond(200, {
                "access_token": "eval-placeholder-token",
                "expires_at": 4_000_000_000_000,
            })
            return
        if target != b"/v1/chat/completions":
            self._respond(404, {"error": "not found"})
            return
        try:
            value = self.server.parse_json(body)
        except ValueError:
            raise _HTTPError(400)
        if not isinstance(value, dict):
            raise _HTTPError(400)
        if value.get("model") != self.server.model or value.get("stream") is not False:
            raise _HTTPError(400)
        try:
            result = self.server.relay(value)
            if not isinstance(result, tuple) or len(result) != 2:
                raise ValueError("invalid gateway result")
            status, payload = result
            if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
                raise ValueError("invalid gateway status")
            self._respond(status, payload)
        except Exception:
            self._respond(502, {"error": "gateway failure"})

    def _respond(self, status: int, payload) -> None:
        try:
            body = json.dumps(payload, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
            if len(body) > _MAX_RESPONSE:
                raise ValueError("response too large")
        except (TypeError, ValueError, UnicodeError):
            status = 502
            body = b'{"error":"gateway failure"}'
        reasons = {200: "OK", 400: "Bad Request", 404: "Not Found", 405: "Method Not Allowed", 408: "Request Timeout", 413: "Payload Too Large", 431: "Request Header Fields Too Large", 502: "Bad Gateway"}
        reason = reasons.get(status, "Response")
        head = (f"HTTP/1.1 {status} {reason}\r\n"
                f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
                "Connection: close\r\n\r\n").encode("ascii")
        self.request.sendall(head + body)


def make_server(model: str, parse_json, relay, port: int = 18080,
                provider: str = "local", oauth_scope: str | None = None) -> socketserver.TCPServer:
    """Fixed container loopback endpoint; tests may request an ephemeral port."""
    if not isinstance(model, str):
        raise TypeError("model must be a string")
    if type(port) is not int or not (port == 0 or 1024 <= port <= 65535):
        raise ValueError("invalid loopback port")
    if provider not in ("local", "gigachat"):
        raise ValueError("invalid eval provider")
    return _ThreadedServer(
        ("127.0.0.1", port), _Handler, model, parse_json, relay,
        provider, oauth_scope,
    )


class _AdapterTests(unittest.TestCase):
    def setUp(self):
        self.seen = []
        self.gigachat_seen = []
        self.server = self.start_server("local", self.seen)
        self.gigachat_server = self.start_server("gigachat", self.gigachat_seen)

    def start_server(self, provider, seen):
        server = make_server(
            "test-model", json.loads,
            lambda body: (200, self._relay(seen, body)), port=0,
            provider=provider, oauth_scope="GIGACHAT_API_PERS",
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        server.test_thread = thread
        return server

    def tearDown(self):
        for server in (self.server, self.gigachat_server):
            server.shutdown()
            server.server_close()
            server.test_thread.join(timeout=2)

    def _relay(self, seen, body):
        seen.append(body)
        return {"ok": True}

    def request(self, method, path, body=None, headers=None, server=None):
        server = server or self.server
        conn = http.client.HTTPConnection(*server.server_address, timeout=2)
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        data = response.read()
        result = response.status, json.loads(data)
        conn.close()
        return result

    def test_models_route(self):
        self.assertEqual(self.request("GET", "/v1/models"), (200, {"object": "list", "data": [{"id": "test-model", "object": "model"}]}))

    def test_post_forwards_only_json_body(self):
        body = '{"model":"test-model","stream":false,"x":1}'
        self.assertEqual(self.request("POST", "/v1/chat/completions", body, {"Authorization": "secret"}), (200, {"ok": True}))
        self.assertEqual(self.seen, [{"model": "test-model", "stream": False, "x": 1}])

    def test_gigachat_oauth_returns_placeholder_without_retaining_authorization(self):
        headers = {
            "Authorization": "Basic synthetic-container-key",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        status, value = self.request(
            "POST", "/api/v2/oauth", "scope=GIGACHAT_API_PERS", headers,
            server=self.gigachat_server,
        )
        self.assertEqual(status, 200)
        self.assertEqual(value, {"access_token": "eval-placeholder-token", "expires_at": 4_000_000_000_000})
        self.assertEqual(self.gigachat_seen, [])
        self.assertNotIn("synthetic-container-key", json.dumps(value))

    def test_gigachat_oauth_rejects_wrong_scope_and_files_route(self):
        headers = {
            "Authorization": "Basic synthetic-container-key",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        self.assertEqual(self.request(
            "POST", "/api/v2/oauth", "scope=OTHER", headers,
            server=self.gigachat_server,
        )[0], 400)
        self.assertEqual(self.request(
            "POST", "/v1/files", "{}", {"Content-Type": "application/json"},
            server=self.gigachat_server,
        )[0], 404)
        self.assertEqual(self.gigachat_seen, [])

    def test_model_mismatch_and_streaming_are_rejected_before_relay(self):
        for body in ('{"model":"other","stream":false}', '{"model":"test-model","stream":true}'):
            with self.subTest(body=body):
                self.assertEqual(self.request("POST", "/v1/chat/completions", body)[0], 400)
        self.assertEqual(self.seen, [])

    def test_unknown_route(self):
        self.assertEqual(self.request("GET", "/elsewhere")[0], 404)

    def test_duplicate_content_length_and_transfer_encoding_rejected(self):
        for headers in (b"Content-Length: 0\r\ncontent-length: 0\r\n", b"Transfer-Encoding: chunked\r\n"):
            with socket.create_connection(self.server.server_address, timeout=2) as sock:
                sock.sendall(b"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\n" + headers + b"\r\n")
                response = sock.recv(1024)
                self.assertIn(b" 400 ", response)


if __name__ == "__main__":
    unittest.main()
