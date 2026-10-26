"""История ввода сохраняется между настоящими процессами CLI, без платного API."""
import http.server
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import termios
import threading
import traceback

sys.dont_write_bytecode = True
from connect_pty import ConnectTerminal
from terminal_pty import LoopbackHTTPServer, interrupted


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        self.server.requests.append(request)
        body = json.dumps({'choices':[{'message':{'role':'assistant','content':'HISTORY_REPLY'},'finish_reason':'stop'}]}).encode()
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main(binary):
    server = LoopbackHTTPServer(('127.0.0.1',0),Handler)
    server.requests=[]
    worker=threading.Thread(target=server.serve_forever,daemon=True)
    worker.start()
    try:
        with tempfile.TemporaryDirectory(prefix='rcode-input-history-') as temporary:
            base=Path(temporary)
            project, other, home=base/'project',base/'other',base/'state'
            for p in (project,other,home): p.mkdir(mode=0o700)
            (home/'config.json').write_text(json.dumps({'version':1,'active':'custom','providers':{'custom':{
                'kind':'custom','model':'history-fixture','base_url':f'http://127.0.0.1:{server.server_port}/v1','stream':False}}}))
            (home/'credentials.json').write_text(json.dumps({'version':1,'providers':{'custom':'history-key-never-store'}}))
            for p in home.iterdir():p.chmod(0o600)
            prompt='HISTORY_ПРИВЕТ строка 1\nстрока 2'
            terminal=ConnectTerminal(binary,project,home,[])
            try:
                terminal.until(terminal.editor_ready,'first composer')
                terminal.send('\x1b[200~'+prompt+'\x1b[201~\r')
                terminal.editor_after('HISTORY_REPLY')
                terminal.send('/exit\r')
                terminal.finished()
            finally:terminal.close()
            count=len(server.requests)

            terminal=ConnectTerminal(binary,project,home,[])
            try:
                terminal.until(terminal.editor_ready,'composer after restart')
                terminal.send('\x1b[A')
                terminal.until(lambda:any('HISTORY_ПРИВЕТ строка 1' in r for r in terminal.grid.rows()[-9:]),'persisted prompt recalled with Up')
                assert any('строка 2' in r for r in terminal.grid.rows()[-9:]), terminal.dump()
                assert len(server.requests)==count,'History recall replayed an API request'
                terminal.send('\x0e')
                terminal.until(terminal.editor_ready,'Ctrl+N restores empty draft after multiline history')
                terminal.send('UNSENT_DRAFT\x10')
                terminal.until(lambda:any('HISTORY_ПРИВЕТ' in r for r in terminal.grid.rows()[-9:]),'Ctrl+P recalls history')
                terminal.send('\x0e')
                terminal.until(lambda:any('UNSENT_DRAFT' in r for r in terminal.grid.rows()[-5:]),'Ctrl+N restores draft')
                terminal.send('\x03')
                terminal.until(terminal.editor_ready,'cleared draft')
                terminal.send('/exit\r')
                terminal.finished()
            finally:terminal.close()

            terminal=ConnectTerminal(binary,other,home,[])
            try:
                terminal.until(terminal.editor_ready,'other project')
                terminal.send('\x10')
                terminal.drain()
                assert 'HISTORY_ПРИВЕТ' not in terminal.text(),'History crossed workspace boundary'
                terminal.send('/exit\r')
                terminal.finished()
            finally:terminal.close()

            # The same persisted entries must be available to rustyline --plain.
            terminal=ConnectTerminal(binary,project,home,['--plain'])
            try:
                terminal.expect('rcode ›')
                mark=terminal.mark()
                terminal.send('\x10')
                terminal.expect('HISTORY_ПРИВЕТ',mark)
                assert len(server.requests)==count,'Plain history triggered API traffic'
                mark=terminal.mark()
                terminal.send('\x03')
                terminal.expect('Ещё раз Ctrl+C',mark)
                terminal.until(lambda:not(termios.tcgetattr(terminal.master)[3] & termios.ICANON),'plain editor ready after interrupt')
                terminal.send('/exit\r')
                terminal.finished()
            finally:terminal.close()
            print('PASS input history: restart, multiline, arrows, Ctrl+P/N, draft, workspace isolation, plain, no replay')
    finally:
        server.shutdown();server.server_close();worker.join(timeout=1)


if __name__=='__main__':
    signal.signal(signal.SIGTERM,interrupted)
    try:main(os.path.abspath(sys.argv[1]))
    except BaseException:
        traceback.print_exc();sys.exit(1)
