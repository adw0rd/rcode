"""Полный доступ: выбор в меню, сохранение проекта, отсутствие запросов, отзыв."""
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
        messages=request['messages']
        last=max(i for i,m in enumerate(messages) if m['role']=='user')
        prompt=messages[last]['content']
        tools=sum(m['role']=='tool' for m in messages[last+1:])
        if tools==0:
            name,args='write_file',{'path':str(self.server.target),'content':'FULL_PTY_OK\n'}
        elif tools==1 and prompt.startswith('FULL_WORK'):
            name,args='run_command',{'command':"printf 'SHELL_FULL_OK' > shell-full.txt"}
        else:
            name,args=None,None
        if name:
            message={'role':'assistant','content':None,'tool_calls':[{'id':'full-permission','type':'function','function':{'name':name,'arguments':json.dumps(args)}}]}
        else:message={'role':'assistant','content':'FULL_PTY_DONE'}
        body=json.dumps({'choices':[{'message':message,'finish_reason':'tool_calls' if name else 'stop'}]}).encode()
        self.send_response(200);self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)


def main(binary):
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);server.requests=[]
    worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
    try:
        with tempfile.TemporaryDirectory(prefix='rcode-full-permissions-') as temp:
            base=Path(temp);project,external,other,home=base/'project',base/'external',base/'other',base/'state'
            for p in (project,external,other,home):p.mkdir(mode=0o700)
            (home/'config.json').write_text(json.dumps({'version':1,'active':'custom','providers':{'custom':{
                'kind':'custom','model':'full-fixture','base_url':f'http://127.0.0.1:{server.server_port}/v1','stream':False}}}))
            (home/'credentials.json').write_text(json.dumps({'version':1,'providers':{'custom':'full-fixture-key'}}))
            for p in home.iterdir():p.chmod(0o600)
            terminal=ConnectTerminal(binary,project,home,[])
            try:
                terminal.until(terminal.editor_ready,'initial editor')
                terminal.assert_footer('ask')
                mark=terminal.command('/permissions','Разрешения')
                terminal.expect('Полный доступ',mark)
                terminal.send('\x1b[B\x1b[B\r')
                terminal.editor_after('✓ Разрешения: full-access',mark)
                terminal.assert_footer('full-access')
                values=json.loads((home/'permissions.json').read_text())['projects']
                assert values[str(project.resolve())]=='full-access',values
                server.target=external/'first.txt'
                mark=terminal.mark();terminal.send('FULL_WORK first\r')
                terminal.editor_after('FULL_PTY_DONE',mark)
                assert server.target.read_text()=='FULL_PTY_OK\n'
                assert (project/'shell-full.txt').read_text()=='SHELL_FULL_OK'
                assert 'Подтверждение действия' not in terminal.text(mark),'Full mode asked for confirmation'
                terminal.send('/exit\r');terminal.finished()
            finally:terminal.close()

            # The grant is project-specific, not a global privilege escalation.
            terminal=ConnectTerminal(binary,other,home,[])
            try:
                terminal.until(terminal.editor_ready,'different project editor')
                terminal.assert_footer('ask')
                terminal.send('/exit\r');terminal.finished()
            finally:terminal.close()

            terminal=ConnectTerminal(binary,project,home,[])
            try:
                terminal.until(terminal.editor_ready,'editor after restart')
                terminal.assert_footer('full-access')
                server.target=external/'second.txt'
                mark=terminal.mark();terminal.send('FULL_WORK after restart\r')
                terminal.editor_after('FULL_PTY_DONE',mark)
                assert server.target.read_text()=='FULL_PTY_OK\n'
                assert 'Подтверждение действия' not in terminal.text(mark)
                terminal.command('/permissions ask','✓ Разрешения: ask')
                terminal.assert_footer('ask')
                assert json.loads((home/'permissions.json').read_text())['projects'][str(project.resolve())]=='ask'
                server.target=external/'must-not-exist.txt'
                mark=terminal.mark();terminal.send('ASK_WORK after downgrade\r')
                terminal.expect('Дополнительный каталог:',mark)
                terminal.until(lambda:any('Разрешить один раз' in r for r in terminal.grid.rows()[-6:]),'scope reapproval after downgrade')
                assert not server.target.exists(),'Stale full grant survived downgrade'
                terminal.send('\r')
                terminal.editor_after('FULL_PTY_DONE',mark)
                assert not server.target.exists()
                terminal.send('/exit\r');terminal.finished()
            finally:terminal.close()
            print('PASS full access: picker, project persistence, restart, file+shell without approval, other project ask, downgrade revokes grants')
    finally:
        server.shutdown();server.server_close();worker.join(timeout=1)


if __name__=='__main__':
    signal.signal(signal.SIGTERM,interrupted)
    try:main(os.path.abspath(sys.argv[1]))
    except BaseException:traceback.print_exc();sys.exit(1)
