"""Вставка скриншота, snapshot/resume и Files API GigaChat в настоящем PTY."""
import base64
import http.server
import json
import os
from pathlib import Path
import signal
import struct
import sys
import tempfile
import threading
import traceback

sys.dont_write_bytecode = True
from connect_pty import ConnectTerminal
from terminal_pty import LoopbackHTTPServer, interrupted

PNG = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+j2ioAAAAASUVORK5CYII=')


def tiff_rgb(width=1, height=1):
    """Несжатый TIFF RGB, как формат clipboard macOS; без сторонних библиотек."""
    count = 10
    bits_offset = 8 + 2 + count * 12 + 4
    pixels_offset = bits_offset + 6
    tags = [(256, 4, 1, width), (257, 4, 1, height), (258, 3, 3, bits_offset),
            (259, 3, 1, 1), (262, 3, 1, 2), (273, 4, 1, pixels_offset),
            (277, 3, 1, 3), (278, 4, 1, height), (279, 4, 1, width * height * 3), (284, 3, 1, 1)]
    return b'II*\x00' + struct.pack('<I', 8) + struct.pack('<H', count) + b''.join(struct.pack('<HHII', *tag) for tag in tags) + struct.pack('<IHHH', 0, 8, 8, 8) + b'\xff\x00\x00' * min(width * height, 1000)


def paste_prompt(terminal, text):
    # Long absolute paths are one paste, not hundreds of key events and redraws.
    terminal.send('\x1b[200~'+text+'\x1b[201~\r')


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def do_POST(self):
        status = 200
        raw = self.rfile.read(int(self.headers['Content-Length']))
        self.server.requests.append((self.path, dict(self.headers), raw))
        if self.path == '/oauth':
            value = {'access_token': 'image-access', 'expires_at': 4102444800}
        elif self.path == '/v1/files':
            count = sum(path == '/v1/files' for path, _, _ in self.server.requests)
            assert b'\x89PNG\r\n\x1a\n' in raw
            assert b'name="purpose"' in raw and b'general' in raw
            assert self.headers['Authorization'] == 'Bearer image-access'
            value = {'id': f'uploaded-image-{count}'}
        else:
            assert self.path == '/v1/chat/completions'
            request = json.loads(raw)
            invalid = next((name for function in request.get('functions', [])
                            for name, prop in function['parameters'].get('properties', {}).items()
                            if isinstance(prop.get('type'), list)), None)
            if invalid:
                status = 422
                value = {'status': status, 'message': f"Field 'properties.{invalid}.type' is of a wrong type. Expected: stringValue, actual: arrayValue"}
            else:
                count = sum(path == '/v1/chat/completions' for path, _, _ in self.server.requests)
                value = {'choices': [{'message': {'role': 'assistant', 'content': f'IMAGE_RESPONSE_DONE_{count}'}, 'finish_reason': 'stop'}]}
        data = json.dumps(value).encode()
        self.send_response(status); self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data))); self.end_headers(); self.wfile.write(data)


def main(binary):
    server = LoopbackHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True; server.requests = []
    threading.Thread(target=server.serve_forever, daemon=True).start()
    def next_reply():
        count = sum(path == '/v1/chat/completions' for path, _, _ in server.requests)
        return f'IMAGE_RESPONSE_DONE_{count + 1}'
    try:
        with tempfile.TemporaryDirectory(prefix='rcode-images-pty-') as tmp:
            root = Path(tmp)
            for kind, extension in [('custom', 'png'), ('gigachat', 'png'), ('custom', 'tiff'), ('gigachat', 'tiff')]:
                project, home = root/(kind+'-'+extension), root/(kind+'-'+extension+'-state')
                project.mkdir(); home.mkdir(mode=0o700)
                name = 'скрин с пробелом.png' if extension == 'png' else '2026-10-26_00-57-54.tiff'
                parent = root if extension == 'png' else root/'Library/Metadata/CoreSpotlight/PasteboardHistory'
                parent.mkdir(parents=True, exist_ok=True)
                image = parent/name; image.write_bytes(PNG if extension == 'png' else tiff_rgb())
                provider = {'kind': kind, 'model': 'image-fixture', 'base_url': f'http://127.0.0.1:{server.server_port}/v1', 'stream': False}
                if kind == 'gigachat': provider['auth_url'] = f'http://127.0.0.1:{server.server_port}/oauth'
                (home/'config.json').write_text(json.dumps({'version': 1, 'active': kind, 'providers': {kind: provider}}))
                (home/'credentials.json').write_text(json.dumps({'version': 1, 'providers': {kind: 'image-fixture-key'}}))
                for path in home.iterdir(): path.chmod(0o600)
                mark = len(server.requests)
                terminal = ConnectTerminal(binary, project, home, [])
                try:
                    terminal.until(terminal.editor_ready, f'{kind}/{extension} image composer')
                    # A terminal can paste an absolute filename, including spaces, as one input.
                    reply = next_reply()
                    paste_prompt(terminal, str(image)+(' что тут нарисовано?' if extension == 'tiff' else ''))
                    terminal.editor_after(reply)
                    terminal.expect_body('Изображение: '+name)
                    session_path = next((home/'sessions').glob('*/session.json'))
                    saved = json.loads(session_path.read_text())
                    attached = next(m for m in saved['messages'] if m.get('images'))['images'][0]
                    assert 'data' not in attached and 'base64' not in json.dumps(saved)
                    snapshots = list((session_path.parent/'images').iterdir())
                    assert len(snapshots) == 1
                    expected = snapshots[0].read_bytes()
                    assert expected.startswith(b'\x89PNG\r\n\x1a\n')
                    if extension == 'png': assert expected == PNG
                    if os.name == 'posix': assert snapshots[0].stat().st_mode & 0o777 == 0o600
                    # Two copies in a single prompt must retain the caption; Giga gets one per message.
                    response_mark = terminal.mark()
                    reply = next_reply()
                    paste_prompt(terminal, '/attach "'+str(image)+'" "'+str(image)+'" Объясни ошибку')
                    terminal.editor_after(reply, response_mark)
                    terminal.until(lambda: sum(p == '/v1/chat/completions' for p,_,_ in server.requests[mark:]) == 2, 'second image request')
                    count = len(server.requests)
                    broken = root/'broken.tiff'; broken.write_bytes(b'II*\x00bad')
                    error_mark = terminal.mark()
                    paste_prompt(terminal, str(broken)+' что тут нарисовано?')
                    terminal.editor_after('Не удалось прочитать TIFF', error_mark)
                    assert len(server.requests) == count
                    paste_prompt(terminal, '/attach /definitely-missing.png')
                    terminal.editor_after('Не удалось прочитать изображение')
                    assert len(server.requests) == count
                    terminal.command('/export images.md', 'Диалог сохранён')
                    terminal.until(lambda: (project/'images.md').exists(), 'image export')
                    assert name in (project/'images.md').read_text()
                    terminal.send('/exit\r'); terminal.finished()
                finally: terminal.close()
                image.unlink()
                restored = ConnectTerminal(binary, project, home, ['--resume', saved['id']])
                try:
                    restored.until(restored.editor_ready, f'resumed {kind}/{extension} image')
                    restored.expect_body('Изображение: '+name)
                    new_mark = restored.mark()
                    reply = next_reply()
                    paste_prompt(restored, 'Что видно на предыдущем скрине?')
                    restored.editor_after(reply, new_mark)
                    restored.send('/exit\r'); restored.finished()
                finally: restored.close()
                requests = server.requests[mark:]
                completions = [json.loads(raw) for path, _, raw in requests if path.endswith('/chat/completions')]
                assert len(completions) == 3
                for request in completions:
                    users = [m for m in request['messages'] if m['role'] == 'user']
                    if kind == 'gigachat':
                        assert any(m.get('attachments') for m in users)
                        assert all(len(m.get('attachments', [])) <= 1 for m in users)
                    else:
                        images = [part for m in users if isinstance(m.get('content'), list) for part in m['content'] if part['type'] == 'image_url']
                        assert images and all(base64.b64decode(part['image_url']['url'].split(',', 1)[1]) == expected for part in images)
                if extension == 'tiff':
                    assert 'что тут нарисовано?' in json.dumps(completions[0]['messages'], ensure_ascii=False)
                assert any('Объясни ошибку' in json.dumps(m, ensure_ascii=False) for m in completions[1]['messages'])
                if kind == 'gigachat':
                    # Shared bytes are uploaded once per client; after restart the saved snapshot is uploaded anew.
                    assert sum(path == '/v1/files' for path,_,_ in requests) == 2
        print('PASS image attachment: pasted absolute path, caption, Giga Files API/cache, snapshots/resume, export, missing file')
    finally:
        server.shutdown(); server.server_close()


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, interrupted)
    try: main(sys.argv[1])
    except BaseException:
        traceback.print_exc(); sys.exit(1)
