"""Markdown, streaming, resume и обычное выделение: настоящий PTY, локальный API."""
import http.server
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import traceback

sys.dont_write_bytecode = True
from connect_pty import ConnectTerminal
from terminal_pty import LoopbackHTTPServer, interrupted


MARKDOWN = """## Запуск игры

**Готово**: запустите `saper.py`.

- Первый пункт
  - Вложенный пункт

| Модель | Статус |
| --- | --- |
| Ultra | Готова |

```bash
python3 /tmp/saper/saper.py
```

[Справка](https://example.com/help)
MARKDOWN_DONE
"""


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        self.server.requests.append(request)
        if request.get('stream'):
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Connection', 'close')
            self.end_headers()
            def event(value):
                self.wfile.write(('data: ' + json.dumps(value, ensure_ascii=False) + '\n\n').encode())
                self.wfile.flush()
            try:
                # Split the opening and closing delimiters across real SSE chunks.
                before, after = MARKDOWN.split('```bash\n', 1)
                for chunk in [before + '`', '``ba', 'sh\n', after[:25], after[25:27], after[27:55], after[55:-20]]:
                    event({'choices': [{'delta': {'content': chunk}, 'finish_reason': None}]})
                self.server.streaming.set()
                self.server.finish.wait(timeout=6)
                event({'choices': [{'delta': {'content': after[-20:]}, 'finish_reason': None}]})
                event({'choices': [{'delta': {}, 'finish_reason': 'stop'}]})
                self.wfile.write(b'data: [DONE]\n\n'); self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
        else:
            body = json.dumps({'choices': [{'message': {'role': 'assistant', 'content': MARKDOWN}, 'finish_reason': 'stop'}]}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers(); self.wfile.write(body)


def assert_markdown(terminal):
    rows = terminal.grid.rows()[:-5]
    body = '\n'.join(rows)
    assert 'Запуск игры' in body and '## Запуск' not in body, terminal.dump()
    assert '**Готово**' not in body and 'Готово' in body, terminal.dump()
    assert '`saper.py`' not in body and 'saper.py' in body, terminal.dump()
    assert '• Первый пункт' in body and '• Вложенный пункт' in body, terminal.dump()
    assert '| --- |' not in body and 'Ultra' in body, terminal.dump()
    assert '```' not in body and '╭─ bash' in body, terminal.dump()
    assert any(row.startswith('│ python3 /tmp/saper/saper.py') for row in rows), terminal.dump()
    assert '[Справка](' not in body and 'https://example.com/help' in body, terminal.dump()
    assert {1002, 1006}.issubset(terminal.grid.mouse_modes), 'Mouse wheel and text selection must remain available'
    terminal.assert_footer()


def main(binary):
    server = LoopbackHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    server.requests = []
    server.streaming, server.finish = threading.Event(), threading.Event()
    worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
    try:
        with tempfile.TemporaryDirectory(prefix='rcode-markdown-pty-') as temp:
            base = Path(temp)
            project, home = base/'project', base/'state'
            for p in (project, home): p.mkdir(mode=0o700)
            (home/'config.json').write_text(json.dumps({'version': 1, 'active': 'custom', 'providers': {'custom': {
                'kind': 'custom', 'model': 'markdown-fixture', 'base_url': f'http://127.0.0.1:{server.server_port}/v1', 'stream': True}}}))
            (home/'credentials.json').write_text(json.dumps({'version': 1, 'providers': {'custom': 'md-fixture-secret-key-42'}}))
            for p in home.iterdir(): p.chmod(0o600)
            terminal = ConnectTerminal(binary, project, home, [])
            try:
                terminal.until(terminal.editor_ready, 'Markdown editor')
                terminal.send('Show formatted answer\r')
                terminal.until(lambda: server.streaming.is_set(), 'stream chunks')
                terminal.expect_body('python3 /tmp/saper/saper.py')
                assert '```' not in '\n'.join(terminal.grid.rows()[:-5]), terminal.dump()
                assert any('╭─ bash' in row for row in terminal.grid.rows()[:-5]), terminal.dump()
                terminal.assert_footer()
                server.finish.set()
                terminal.editor_after('MARKDOWN_DONE')
                assert_markdown(terminal)
                assert b'\x1b[1m' in terminal.buffer, 'Headings/bold must have actual terminal styling'
                assert b'\x1b[48;5;236m' in terminal.buffer, 'Code block must have a distinct background'
                terminal.capture('formatted')
                for width, height in [(42, 18), (100, 40), (140, 28)]:
                    terminal.resize(width, height)
                    terminal.until(lambda: 'Контекст' in terminal.grid.rows()[-1], 'Markdown resize footer')
                    terminal.drain()
                    assert all('```' not in row for row in terminal.grid.rows()), terminal.dump()
                    assert {1002, 1006}.issubset(terminal.grid.mouse_modes)
                terminal.send('/exit\r'); terminal.finished()
            finally:
                server.finish.set(); terminal.close()
            sessions = sorted((home/'sessions').glob('*/session.json'))
            assert sessions, 'Session must be saved'
            session = json.loads(sessions[-1].read_text())
            assert any(m.get('content') == MARKDOWN for m in session['messages']), 'Stored Markdown was altered'
            resumed = ConnectTerminal(binary, project, home, ['--resume', session['id']])
            try:
                resumed.until(resumed.editor_ready, 'resumed Markdown editor')
                assert_markdown(resumed)
                resumed.capture('resumed')
                resumed.send('/exit\r'); resumed.finished()
            finally:
                resumed.close()
            env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'RCODE_HOME': str(home)}
            for mode in ['--plain', '--json']:
                result = subprocess.run([binary, '-C', str(project), mode, 'exec', 'Show source'],
                                        env=env, capture_output=True, text=True, timeout=8)
                assert result.returncode == 0, result.stderr
                if mode == '--plain':
                    assert MARKDOWN in result.stdout
                else:
                    events = [json.loads(line) for line in result.stdout.splitlines()]
                    assert ''.join(e.get('text', '') for e in events if e['type'] == 'text') == MARKDOWN
                assert '\x1b' not in result.stdout
            dump = os.environ.get('RCODE_PTY_DUMP_GRID')
            if dump:
                Path(dump).write_text(json.dumps(terminal.snapshots | resumed.snapshots, ensure_ascii=False, indent=2))
            print('PASS Markdown: live SSE chunks, code, inline styles, lists, tables, links, resize, resume, raw plain/JSON, mouse interaction available')
    finally:
        server.finish.set(); server.shutdown(); server.server_close(); worker.join(timeout=1)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, interrupted)
    try: main(os.path.abspath(sys.argv[1]))
    except BaseException: traceback.print_exc(); sys.exit(1)
