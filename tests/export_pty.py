"""Экспорт через настоящий PTY: Markdown, приватность, неизменность, ноль API."""
import http.server
import json
import os
from pathlib import Path
import signal
import stat
import sys
import tempfile
import threading
import traceback
import uuid

sys.dont_write_bytecode = True
from connect_pty import ConnectTerminal
from terminal_pty import LoopbackHTTPServer, interrupted


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def do_POST(self):
        self.server.requests.append(self.path)
        self.rfile.read(int(self.headers.get('Content-Length', '0')))
        body = b'{"choices":[{"message":{"role":"assistant","content":"UNEXPECTED_GENERATION"},"finish_reason":"stop"}]}'
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main(binary):
    server = LoopbackHTTPServer(('127.0.0.1', 0), Handler)
    server.requests = []
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        with tempfile.TemporaryDirectory(prefix='rcode-export-pty-') as temporary:
            base = Path(temporary)
            project, home = base/'project', base/'state'
            project.mkdir()
            home.mkdir(mode=0o700)
            provider = {'kind': 'custom', 'model': 'export-fixture',
                        'base_url': f'http://127.0.0.1:{server.server_port}/v1', 'stream': False}
            key = 'export-key-never-publish'
            (home/'config.json').write_text(json.dumps({'version': 1, 'active': 'custom', 'providers': {'custom': provider}}))
            (home/'credentials.json').write_text(json.dumps({'version': 1, 'providers': {'custom': key}}))
            for path in home.iterdir(): path.chmod(0o600)
            identifier = str(uuid.uuid4())
            directory = home/'sessions'/identifier
            directory.mkdir(parents=True, mode=0o700)
            messages = [
                {'role': 'user', 'content': 'EXPORT_ПРИВЕТ\n```rust\nfn main() {}\n```'},
                {'role': 'assistant', 'content': 'EXPORT_ОТВЕТ ' + key,
                 'tool_calls': [{'id': 'call_read', 'type': 'function', 'function': {'name': 'read_file', 'arguments': '{"path":"main.rs"}'}}]},
                {'role': 'tool', 'name': 'read_file', 'tool_call_id': 'call_read', 'content': '{"content":"EXPORT_TOOL_OK"}'},
                {'role': 'assistant', 'content': 'EXPORT_ГОТОВО'}]
            value = {'version': 1, 'id': identifier, 'root': str(project.resolve()),
                     'provider': provider, 'messages': messages, 'created_at': 1, 'updated_at': 1,
                     'title': 'Export fixture', 'turn_index': 1,
                     'usage': {'input_tokens': 123, 'output_tokens': 45, 'cached_input_tokens': 0}}
            session_path = directory/'session.json'
            session_path.write_text(json.dumps(value))
            session_path.chmod(0o600)
            source = project/'source.rs'
            source.write_text('SOURCE_MUST_SURVIVE')
            (project/'export-link.md').symlink_to(source)

            def check_export(path):
                text = path.read_text()
                for expected in ['# Диалог rcode', 'EXPORT_ПРИВЕТ', 'EXPORT_ОТВЕТ', 'EXPORT_TOOL_OK', 'EXPORT_ГОТОВО', r'export\-fixture', '[REDACTED]']:
                    assert expected in text, (expected, text)
                assert key not in text and identifier not in text, text
                assert stat.S_IMODE(path.stat().st_mode) == 0o600, oct(path.stat().st_mode)

            terminal = ConnectTerminal(binary, project, home, ['--resume', identifier])
            try:
                terminal.until(terminal.editor_ready, 'restored composer')
                before = session_path.read_bytes()
                terminal.send('/exp')
                terminal.until(lambda: any('/export' in row and 'Сохранить диалог' in row for row in terminal.grid.rows()[:-2]), 'export completion menu')
                terminal.send('\t')
                terminal.until(lambda: '/export' in terminal.grid.rows()[-4], 'Tab completed export command')
                terminal.assert_footer('custom')
                mark = terminal.mark()
                terminal.send('\r')
                terminal.editor_after('Диалог сохранён', mark)
                exports = list(project.glob('rcode-export-*.md'))
                assert len(exports) == 1, exports
                check_export(exports[0])
                terminal.command('/export', 'Диалог сохранён')
                terminal.until(lambda: len(list(project.glob('rcode-export-*.md'))) == 2 and terminal.editor_ready(), 'second unique export and restored footer')
                terminal.command('/export "мой диалог.md"', 'Диалог сохранён')
                terminal.until(lambda: (project/'мой диалог.md').exists() and terminal.editor_ready(), 'quoted export saved')
                check_export(project/'мой диалог.md')
                terminal.command('/export source.rs', 'уже существует')
                terminal.command('/export export-link.md', 'уже существует')
                terminal.command('/export missing/export.md', 'каталог')
                assert source.read_text() == 'SOURCE_MUST_SURVIVE'
                assert (project/'export-link.md').is_symlink()
                assert session_path.read_bytes() == before, 'Export changed conversation/usage/session time'
                assert server.requests == [], server.requests
                terminal.command('/help', '/export')
                terminal.assert_footer('custom')
                assert key not in terminal.text(), 'Secret leaked into terminal output'
                terminal.send('/exit\r')
                terminal.finished()
            finally: terminal.close()

            terminal = ConnectTerminal(binary, project, home, ['--plain', '--resume', identifier])
            try:
                terminal.expect('rcode ›')
                before = session_path.read_bytes()
                mark = terminal.mark()
                terminal.send('/export "plain export.md"\r')
                terminal.expect('Диалог сохранён', mark)
                check_export(project/'plain export.md')
                assert session_path.read_bytes() == before, 'Plain export mutated session'
                assert server.requests == [], server.requests
                terminal.send('/exit\r')
                terminal.finished()
            finally: terminal.close()
            print('PASS export: default unique + quoted custom, 0600, no-clobber/symlink, redaction, rich footer + plain, unchanged session, API requests=0')
    finally:
        server.shutdown(); server.server_close(); worker.join(timeout=1)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, interrupted)
    try: main(os.path.abspath(sys.argv[1]))
    except BaseException:
        traceback.print_exc(); sys.exit(1)
