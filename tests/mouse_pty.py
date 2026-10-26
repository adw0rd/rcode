"""Колесо, Unicode selection и clipboard в настоящем PTY, без доступа к clipboard ОС."""
import http.server
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import threading
import traceback
import unicodedata

sys.dont_write_bytecode = True
from connect_pty import ConnectTerminal
from terminal_pty import interrupted


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        self.server.requests.append(request)
        if request['messages'][-1].get('content') == 'WAIT_MOUSE_CANCEL':
            self.server.waiting.set(); self.server.release.wait(timeout=6)
        response = '\n\n'.join(f'MOUSE_ROW_{i:02d} привет 世界' for i in range(60))
        body = json.dumps({'choices': [{'message': {'role': 'assistant', 'content': response}, 'finish_reason': 'stop'}]}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        try: self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError): pass


def mouse(terminal, button, column, row, release=False):
    terminal.send(f'\x1b[<{button};{column + 1};{row + 1}{"m" if release else "M"}')


def width(text):
    return sum(0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in ('W', 'F') else 1 for c in text)


def main(binary):
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True; server.requests = []
    server.waiting, server.release = threading.Event(), threading.Event()
    worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
    try:
        with tempfile.TemporaryDirectory(prefix='rcode-mouse-pty-') as temp:
            base = Path(temp); project, home = base/'project', base/'state'
            for p in (project, home): p.mkdir(mode=0o700)
            (home/'config.json').write_text(json.dumps({'version': 1, 'active': 'custom', 'providers': {'custom': {
                'kind': 'custom', 'model': 'mouse-fixture', 'base_url': f'http://127.0.0.1:{server.server_port}/v1', 'stream': False}}}))
            (home/'credentials.json').write_text(json.dumps({'version': 1, 'providers': {'custom': 'mouse-fixture-private-key'}}))
            for p in home.iterdir(): p.chmod(0o600)
            # Force terminal clipboard transport: never overwrite the real OS clipboard in tests.
            terminal = ConnectTerminal(binary, project, home, [], {'SSH_TTY': '/dev/rcode-pty-fixture'})
            try:
                terminal.until(terminal.editor_ready, 'mouse editor')
                assert {1002, 1006}.issubset(terminal.grid.mouse_modes), 'Wheel and drag reports must be enabled'
                terminal.send('Show rows\r'); terminal.editor_after('MOUSE_ROW_59')
                assert not terminal.grid.clipboard_writes, 'Reply must not write clipboard'
                before = terminal.grid.rows()[0]
                mouse(terminal, 64, 12, 6)
                terminal.until(lambda: terminal.grid.rows()[0] != before, 'wheel scroll up')
                terminal.assert_footer()
                mouse(terminal, 65, 12, 6)
                terminal.until(lambda: terminal.grid.rows()[0] == before, 'wheel scroll down')
                terminal.assert_footer()
                row = next(i for i, text in enumerate(terminal.grid.rows()[:-5]) if text.startswith('MOUSE_ROW_'))
                selected = terminal.grid.rows()[row]
                mouse(terminal, 0, 0, row)
                mouse(terminal, 32, width(selected), row)
                terminal.drain()
                assert not terminal.grid.clipboard_writes, 'Drag must not copy before release'
                assert b'\x1b[7m' in terminal.buffer, 'Selected cells must be highlighted'
                mouse(terminal, 0, width(selected), row, release=True)
                terminal.until(lambda: terminal.grid.clipboard_writes == [selected], 'Unicode text copied on release')
                terminal.assert_footer()
                terminal.send('\x03')
                terminal.until(lambda: terminal.grid.clipboard_writes == [selected, selected], 'Ctrl+C copies selection')
                assert terminal.status is None
                terminal.send('\x1b'); terminal.drain()
                assert terminal.editor_ready(), terminal.dump()
                # Reverse selection has the same content; a click alone must not copy.
                mouse(terminal, 0, width(selected), row)
                mouse(terminal, 32, 0, row)
                mouse(terminal, 0, 0, row, release=True)
                terminal.until(lambda: len(terminal.grid.clipboard_writes) == 3, 'reverse drag copy')
                assert terminal.grid.clipboard_writes[-1] == selected
                mouse(terminal, 0, 0, row); mouse(terminal, 0, 0, row, release=True)
                terminal.drain(); assert len(terminal.grid.clipboard_writes) == 3
                # Mouse coordinates below history must not copy prompts or footer.
                mouse(terminal, 0, 0, terminal.grid.height - 4)
                mouse(terminal, 32, 20, terminal.grid.height - 2)
                mouse(terminal, 0, 20, terminal.grid.height - 2, release=True)
                terminal.drain(); assert len(terminal.grid.clipboard_writes) == 3
                terminal.resize(90, 22); terminal.drain()
                terminal.assert_footer()
                assert {1002, 1006}.issubset(terminal.grid.mouse_modes)
                terminal.resize(140, 28); terminal.drain()
                terminal.command('/permissions', 'Разрешения')
                row = next(i for i, text in enumerate(terminal.grid.rows()[:-7]) if text.startswith('MOUSE_ROW_'))
                count = len(terminal.grid.clipboard_writes)
                mouse(terminal, 0, 0, row); mouse(terminal, 32, 6, row)
                mouse(terminal, 0, 6, row, release=True)
                terminal.until(lambda: len(terminal.grid.clipboard_writes) == count + 1, 'copy while picker open')
                terminal.send('\x1b'); terminal.drain()
                assert not terminal.editor_ready(), 'First Esc clears selection, keeping picker active'
                terminal.send('\x1b')
                terminal.until(terminal.editor_ready, 'second Esc closes picker without trapping input')
                terminal.assert_footer()
                # Invisible selection to the right of a short line must not swallow cancellation.
                count = len(terminal.grid.clipboard_writes)
                terminal.send('WAIT_MOUSE_CANCEL\r')
                terminal.until(lambda: server.waiting.is_set() and terminal.busy_ready(), 'busy cancellation fixture')
                mouse(terminal, 0, 120, 0); mouse(terminal, 32, 130, 0)
                mouse(terminal, 0, 130, 0, release=True)
                terminal.send('\x03')
                terminal.until(terminal.editor_ready, 'Ctrl+C after empty selection cancels request')
                assert len(terminal.grid.clipboard_writes) == count
                server.release.set()
                terminal.send('/exit\r'); terminal.finished()
                assert not terminal.grid.mouse_modes
                assert len(server.requests) == 2, 'Mouse gestures sent a new model request'
                print('PASS mouse: wheel up/down, pinned footer/editor, Unicode drag+reverse, highlight, release copy, Ctrl+C, click/no footer copy, resize, cleanup')
            finally: terminal.close()
    finally:
        server.release.set(); server.shutdown(); server.server_close(); worker.join(timeout=1)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, interrupted)
    try: main(os.path.abspath(sys.argv[1]))
    except BaseException: traceback.print_exc(); sys.exit(1)
