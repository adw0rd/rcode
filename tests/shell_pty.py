"""Ручные !команды: настоящий PTY, локальный shell, ноль API до обычного запроса."""
import http.server
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import threading
import time
import traceback

sys.dont_write_bytecode = True
from connect_pty import ConnectTerminal
from terminal_pty import interrupted


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        self.server.requests.append(request)
        body = json.dumps({'choices': [{'message': {'role': 'assistant', 'content': '!touch model-must-not-execute\nMODEL_RESPONSE_DONE'}, 'finish_reason': 'stop'}]}).encode()
        self.send_response(200); self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)


def main(binary):
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True; server.requests = []
    worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
    try:
        with tempfile.TemporaryDirectory(prefix='rcode-shell-pty-') as temp:
            root = Path(temp); project, home = root/'project', root/'state'
            project.mkdir(); home.mkdir(mode=0o700)
            provider = {'kind':'custom','model':'shell-fixture','base_url':f'http://127.0.0.1:{server.server_port}/v1','stream':False}
            (home/'config.json').write_text(json.dumps({'version':1,'active':'custom','providers':{'custom':provider}}))
            (home/'credentials.json').write_text(json.dumps({'version':1,'providers':{'custom':'shell-private-fixture-key'}}))
            for path in home.iterdir(): path.chmod(0o600)
            terminal = ConnectTerminal(binary,project,home,[])
            try:
                terminal.until(terminal.editor_ready,'shell composer')
                terminal.send("!printf 'SHELL_STDOUT\\n'; printf 'SHELL_STDERR\\n' >&2; exit 7")
                terminal.until(lambda:any('rcode · shell' in row for row in terminal.grid.rows()),'red shell composer')
                assert b'\x1b[38;5;9m!\x1b[0m' in terminal.buffer, 'Actual ! marker must be red'
                mark=terminal.mark();terminal.send('\r')
                terminal.editor_after('↳ exit 7',mark)
                terminal.expect_body('SHELL_STDOUT');terminal.expect_body('SHELL_STDERR')
                assert server.requests==[], 'Manual shell was sent to the model'
                terminal.assert_footer('ask')
                terminal.send("!pwd; printf '%s' \"$RCODE_CUSTOM_API_KEY\" > child-key.txt; printf 'host-ok' > host.txt\r")
                terminal.editor_after('↳ exit 0')
                assert (project/'host.txt').read_text()=='host-ok'
                assert (project/'child-key.txt').read_text()==''
                terminal.expect_body(str(project.resolve()))
                session_path=next((home/'sessions').glob('*/session.json'))
                session=json.loads(session_path.read_text())
                assert session['usage']['input_tokens']==0 and session['usage']['output_tokens']==0
                assert any((m.get('provider_meta') or {}).get('kind')=='rcode_user_shell' for m in session['messages'])
                # Plan constrains the model; an explicitly typed local command remains an operator action.
                terminal.command('/plan on','Режим плана: включён')
                terminal.send("!printf 'explicit-user-action' > plan-host.txt\r")
                terminal.until(lambda:(project/'plan-host.txt').exists(),'explicit manual command in plan mode')
                terminal.editor_after('↳ exit 0')
                assert (project/'plan-host.txt').read_text()=='explicit-user-action'
                assert server.requests==[]
                terminal.send("!printf started > running.txt; (sleep 1; printf bad > escaped.txt) & wait\r")
                terminal.until(lambda:(project/'running.txt').exists() and terminal.busy_ready(),'running shell before cancellation')
                terminal.send('\x03')
                terminal.editor_after('↳ прервано')
                terminal.drain(1.1)
                assert not (project/'escaped.txt').exists(), 'Cancelled shell left a running descendant'
                assert server.requests==[]
                terminal.send('Summarize the manual shell results\r')
                terminal.editor_after('MODEL_RESPONSE_DONE')
                assert len(server.requests)==1
                messages=server.requests[0]['messages']
                assert any(m['role']=='tool' and 'SHELL_STDOUT' in m.get('content','') for m in messages)
                assert not (project/'model-must-not-execute').exists()
                terminal.command('/export shell.md','Диалог сохранён')
                terminal.until(lambda:(project/'shell.md').exists(),'export contains manual shell receipts')
                assert 'SHELL_STDOUT' in (project/'shell.md').read_text()
                terminal.send('/exit\r');terminal.finished()
            finally:terminal.close()
            # Restart: input history and results survive; a pending receipt is repaired without replay.
            session=json.loads(session_path.read_text());identifier=session['id']
            session['messages'].append({'role':'assistant','content':'Команда пользователя','provider_meta':{'kind':'rcode_user_shell','data':{}},'tool_calls':[{'id':'pending-shell','type':'function','function':{'name':'run_command','arguments':json.dumps({'command':'printf bad > replayed.txt'})}}]})
            session_path.write_text(json.dumps(session))
            resumed=ConnectTerminal(binary,project,home,['--resume',identifier])
            try:
                resumed.until(resumed.editor_ready,'resumed shell history')
                assert not (project/'replayed.txt').exists()
                resumed.send('\x10')
                resumed.until(lambda:any('/export shell.md' in row for row in resumed.grid.rows()[-8:]),'persisted input history')
                resumed.send('\x03')
                resumed.until(resumed.editor_ready,'empty editor after history clear')
                assert len(server.requests)==1
                resumed.send('/exit\r');resumed.finished()
            finally:resumed.close()
            plain=ConnectTerminal(binary,project,home,['--plain','--resume',identifier])
            try:
                plain.expect('rcode ›')
                mark=plain.mark();plain.send("!printf 'PLAIN_SHELL_OK\\n'\r")
                plain.expect('↳ exit 0',mark)
                assert 'PLAIN_SHELL_OK' in plain.text(mark)
                emitted=plain.buffer[max(0,mark-plain.offset):]
                # Rustyline still moves its editing cursor in a TTY; application
                # shell formatting must not enable red color or alternate screen.
                assert b'\x1b[38;5;9m' not in emitted and b'\x1b[31m' not in emitted
                assert not plain.used_alternate_screen
                assert len(server.requests)==1
                plain.send('/exit\r');plain.finished()
            finally:plain.close()
            print('PASS !shell: red prompt, stdout/stderr+exit, cwd, private env, zero API, plan/operator isolation, process-group cancellation, history/resume/no replay, model text not executed, export, plain')
    finally:
        server.shutdown();server.server_close();worker.join(timeout=1)


if __name__=='__main__':
    signal.signal(signal.SIGTERM,interrupted)
    try:main(os.path.abspath(sys.argv[1]))
    except BaseException:traceback.print_exc();sys.exit(1)
