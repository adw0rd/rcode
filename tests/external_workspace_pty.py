"""Явное разрешение внешнего каталога в настоящем терминале; файловый undo."""
import http.server
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import threading
import traceback

sys.dont_write_bytecode = True
from connect_pty import ConnectTerminal
from terminal_pty import interrupted


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*_):pass
    def do_POST(self):
        request=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        self.server.requests.append(request)
        if not any(m['role']=='tool' for m in request['messages']):
            message={'role':'assistant','content':None,'tool_calls':[{'id':'external-file','type':'function','function':{
                'name':'write_file','arguments':json.dumps({'path':str(self.server.target),'content':'EXTERNAL_FILE_OK\n'})}}]}
            finish='tool_calls'
        else:
            message={'role':'assistant','content':'EXTERNAL_TURN_DONE'}
            finish='stop'
        body=json.dumps({'choices':[{'message':message,'finish_reason':finish}]}).encode()
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(body)))
        self.end_headers();self.wfile.write(body)


def main(binary):
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    server.requests=[]
    worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
    try:
        with tempfile.TemporaryDirectory(prefix='rcode-external-pty-') as temp:
            base=Path(temp)
            for allowed in [False,True]:
                case=base/('allowed' if allowed else 'denied');case.mkdir()
                project,external,home=case/'project',case/'external',case/'state'
                for p in (project,external,home):p.mkdir(mode=0o700)
                server.target=external/'main.py'
                (home/'config.json').write_text(json.dumps({'version':1,'active':'custom','providers':{'custom':{
                    'kind':'custom','model':'scope-fixture','base_url':f'http://127.0.0.1:{server.server_port}/v1','stream':False}}}))
                (home/'credentials.json').write_text(json.dumps({'version':1,'providers':{'custom':'scope-fixture-key'}}))
                for p in home.iterdir():p.chmod(0o600)
                terminal=ConnectTerminal(binary,project,home,['--approval-mode','auto-edit'])
                try:
                    terminal.until(terminal.editor_ready,'external test editor')
                    mark=terminal.mark();before=len(server.requests)
                    terminal.send('Create file in the external directory\r')
                    terminal.expect('Дополнительный каталог:',mark)
                    terminal.until(lambda:any('Разрешить один раз' in r for r in terminal.grid.rows()[-6:]),'directory approval panel')
                    assert not server.target.exists(),'External file written before approval'
                    assert len(server.requests)==before+1,'Pending permission caused a model retry'
                    terminal.assert_footer()
                    terminal.send('Y\r' if allowed else '\r')
                    terminal.editor_after('EXTERNAL_TURN_DONE',mark)
                    assert server.target.exists()==allowed
                    assert 'outside_workspace' not in terminal.text(mark),'Unnecessary outside_workspace round trip'
                    if allowed:
                        assert server.target.read_text()=='EXTERNAL_FILE_OK\n'
                        terminal.command('/undo','Отменены файловые правки')
                        assert not server.target.exists(),'Undo did not include the external file'
                    else:
                        receipt=server.requests[-1]['messages'][-1]['content']
                        assert 'denied' in receipt,receipt
                    terminal.send('/exit\r');terminal.finished()
                finally:terminal.close()
            print('PASS external workspace: approve/deny before write, no error retry, pinned footer, shared undo')
    finally:
        server.shutdown();server.server_close();worker.join(timeout=1)


if __name__=='__main__':
    signal.signal(signal.SIGTERM,interrupted)
    try:main(os.path.abspath(sys.argv[1]))
    except BaseException:traceback.print_exc();sys.exit(1)
