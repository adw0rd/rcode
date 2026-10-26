"""Восстановление полной сессии: немедленный автокомпакт без генерации API."""

import json
import os
from pathlib import Path
import signal
import socket
import sys
import tempfile
import traceback
import uuid

sys.dont_write_bytecode = True
from connect_pty import ConnectTerminal
from terminal_pty import interrupted


def context_chars(messages):
    return sum(len(message.get('content') or '') + sum(
        len(call['function']['arguments'].encode()) for call in message.get('tool_calls', []))
        for message in messages)


def main(binary):
    with tempfile.TemporaryDirectory(prefix='rcode-auto-compact-pty-') as temporary, socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen()
        listener.setblocking(False)
        base = Path(temporary)
        project, home = base / 'project', base / 'state'
        project.mkdir()
        home.mkdir(mode=0o700)
        provider = {'kind': 'custom', 'model': 'compact-fixture',
                    'base_url': f'http://127.0.0.1:{listener.getsockname()[1]}/v1', 'stream': False}
        (home / 'config.json').write_text(json.dumps({'version': 1, 'active': 'custom', 'providers': {'custom': provider}}))
        (home / 'credentials.json').write_text(json.dumps({'version': 1, 'providers': {'custom': 'fixture-key'}}))
        for path in home.iterdir():
            path.chmod(0o600)

        def full_session():
            identifier = str(uuid.uuid4())
            directory = home / 'sessions' / identifier
            directory.mkdir(parents=True, mode=0o700)
            messages = []
            for index in range(24):
                messages.extend([{'role': 'user', 'content': f'Previous task {index}'},
                                 {'role': 'assistant', 'content': f'Analysis {index}: ' + 'x' * 8000}])
            messages.append({'role': 'user', 'content': 'Current exact request: preserve user work'})
            assert context_chars(messages) > 180000
            value = {'version': 1, 'id': identifier, 'root': str(project.resolve()),
                     'provider': provider, 'messages': messages, 'created_at': 1, 'updated_at': 1,
                     'title': 'Restore full context', 'turn_index': 24,
                     'usage': {'input_tokens': 123, 'output_tokens': 45, 'cached_input_tokens': 0}}
            path = directory / 'session.json'
            path.write_text(json.dumps(value))
            path.chmod(0o600)
            return identifier, path

        def assert_compacted(terminal, path, mark=0):
            value = json.loads(path.read_text())
            chars = context_chars(value['messages'])
            assert chars < 150000, f'Restored session is still full: {chars}'
            assert value['messages'][-1]['content'] == 'Current exact request: preserve user work'
            assert value['usage']['input_tokens'] == 123
            assert value['turn_index'] == 24
            terminal.expect('Автокомпакт', mark)
            terminal.assert_footer()
            percent = chars * 100 // 180000
            assert f'{percent}% лок.' in terminal.grid.rows()[-1], terminal.dump()
            assert 'restricted_receipts' not in terminal.text(mark), 'Internal memory JSON leaked into restored UI'

        first, first_path = full_session()
        terminal = ConnectTerminal(binary, project, home, ['--resume', first])
        try:
            terminal.until(terminal.editor_ready, 'editor after CLI resume')
            assert_compacted(terminal, first_path)
            terminal.send('/exit\r')
            terminal.finished()
        finally:
            terminal.close()

        second, second_path = full_session()
        terminal = ConnectTerminal(binary, project, home, [])
        try:
            terminal.until(terminal.editor_ready, 'new session editor')
            mark = terminal.command('/resume ' + second, 'Сессия восстановлена')
            assert_compacted(terminal, second_path, mark)
            terminal.send('/exit\r')
            terminal.finished()
        finally:
            terminal.close()
        try:
            connection, _ = listener.accept()
        except BlockingIOError:
            pass
        else:
            connection.close()
            raise AssertionError('Restoring a session must not invoke API generation')
        print('PASS auto compact on CLI --resume and interactive /resume: persisted history, exact task, footer, notice, no API')


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, interrupted)
    try:
        main(os.path.abspath(sys.argv[1]))
    except BaseException:
        traceback.print_exc()
        sys.exit(1)
