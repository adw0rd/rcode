#!/usr/bin/env python3
"""Trusted container supervisor, never a test adjudicator. Expected values stay on host."""
import base64
import errno
import json
import math
import os
from pathlib import Path
import queue
import signal
import socket
import subprocess
import sys
import threading
import time

sys.dont_write_bytecode=True
MAX_FRAME=4*1024*1024
WRITE_LOCK=threading.Lock()
STOP=threading.Event()
HOST_GONE=threading.Event()
RELEASE=threading.Event()

def strict(data,limit=MAX_FRAME):
    if len(data)>limit:raise ValueError('frame limit')
    def pairs(items):
        out={}
        for k,v in items:
            if k in out:raise ValueError('duplicate key')
            out[k]=v
        return out
    def constant(_):raise ValueError('invalid number')
    try:value=json.loads(data,object_pairs_hook=pairs,parse_constant=constant)
    except RecursionError:raise ValueError('JSON complexity') from None
    count=0
    def walk(v,depth=0):
        nonlocal count
        count+=1
        if depth>32 or count>65536:raise ValueError('complexity')
        if isinstance(v,float) and not math.isfinite(v):raise ValueError('number')
        if isinstance(v,dict):
            for k,x in v.items():
                if len(k)>4096:raise ValueError('key')
                walk(x,depth+1)
        if isinstance(v,list):
            for x in v:walk(x,depth+1)
    walk(value)
    return value

def frame():
    line=sys.stdin.buffer.readline(MAX_FRAME+1)
    if not line:return None
    if len(line)>MAX_FRAME or not line.endswith(b'\n'):raise ValueError('frame')
    v=strict(line)
    if not isinstance(v,dict):raise ValueError('object required')
    return v

def send(v):
    raw=json.dumps(v,ensure_ascii=True,allow_nan=False,separators=(',',':')).encode()+b'\n'
    if len(raw)>MAX_FRAME:raise ValueError('outbound frame')
    with WRITE_LOCK:
        sys.stdout.buffer.write(raw);sys.stdout.buffer.flush()

def bounded_int(v,low,high):
    if type(v) is not int or not low<=v<=high:raise ValueError('integer bounds')
    return v

def command(c):
    if not isinstance(c,dict) or set(c)-{'argv','stdin','timeout_secs'}:raise ValueError('command fields')
    argv=c.get('argv')
    if not isinstance(argv,list) or not 1<=len(argv)<=128 or not isinstance(argv[0],str) or not argv[0]:raise ValueError('argv')
    if any(not isinstance(a,str) or '\0' in a for a in argv) or sum(len(a.encode())+1 for a in argv)>65536:raise ValueError('argv bounds')
    stdin=c.get('stdin','')
    if not isinstance(stdin,str) or len(stdin.encode())>65536:raise ValueError('stdin')
    return {'argv':argv,'stdin':stdin,'timeout_secs':bounded_int(c.get('timeout_secs',30),1,60)}

def environment():
    return {'PATH':'/opt/rcode-toolchain/bin:/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin','HOME':'/agent-home',
        'RCODE_HOME':'/agent-home/state','TMPDIR':'/tmp','LANG':'C.UTF-8','TERM':'dumb',
        'CARGO_HOME':'/agent-tmp/cargo-home','CARGO_TARGET_DIR':'/agent-tmp/cargo-target','RUSTUP_HOME':'/usr/local/rustup'}

def child(path):
    if os.geteuid()==0:raise ValueError('child must be unprivileged')
    cfg=strict(Path(path).read_bytes(),65536)
    env=environment();os.environ.clear();os.environ.update(env);os.umask(0o077)
    if cfg.get('profile_config') is not None:
        state=Path(env['RCODE_HOME']);state.mkdir(parents=True,exist_ok=True)
        # The host supplies credential-free settings. The same container URL
        # is reused for resume; no user's credentials or settings are copied.
        (state/'config.json').write_text(json.dumps(cfg['profile_config']))
    os.chdir(cfg['cwd'])
    os.execvpe(cfg['argv'][0],cfg['argv'],env)

def execute(argv,cwd,uid,gid,seconds,limit=65536,profile_config=None,agent=False):
    Path('/control').mkdir(exist_ok=True);path=Path('/control/child.json')
    if path.exists():path.chmod(0o600)
    raw=json.dumps({'argv':argv,'cwd':cwd,'profile_config':profile_config},ensure_ascii=True).encode()
    if len(raw)>65536:raise ValueError('child bootstrap limit')
    path.write_bytes(raw);path.chmod(0o444)
    p=subprocess.Popen(['python3','-I','-S','/eval/runtime.py','--child',str(path)],
        cwd='/',env=environment(),user=uid,group=gid,extra_groups=[],start_new_session=True,
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True)
    # A separate writer prevents a child which never reads stdin from blocking
    # the supervisor. The command's stdin is supplied below by capture().
    return p

def capture(p,stdin,seconds,limit=65536,agent=False,log_kind='agent_log'):
    buffers=[bytearray(),bytearray()];truncated=[False,False];eof=[False,False]
    halt=threading.Event()
    def reader(index,pipe):
        os.set_blocking(pipe.fileno(),False)
        while not halt.is_set():
            try:chunk=os.read(pipe.fileno(),4096)
            except BlockingIOError:time.sleep(.005);continue
            if not chunk:eof[index]=True;return
            admitted=min(len(chunk),limit-len(buffers[index]))
            buffers[index].extend(chunk[:admitted]);truncated[index]|=admitted<len(chunk)
            if agent and admitted:
                send({'type':log_kind,'channel':['stdout','stderr'][index],
                      'data':base64.b64encode(chunk[:admitted]).decode()})
    def writer():
        try:
            if stdin:p.stdin.write(stdin.encode());p.stdin.flush()
        except (BrokenPipeError,OSError):pass
        finally:p.stdin.close()
    threads=[threading.Thread(target=reader,args=(i,s),daemon=True) for i,s in enumerate([p.stdout,p.stderr])]
    for t in threads:t.start()
    threading.Thread(target=writer,daemon=True).start()
    start=time.monotonic();cancel_at=None;timed_out=False;forced=False;owned=True;cancel_signal_sent=False
    while True:
        # WNOWAIT retains the leader identity until all numeric group signals
        # are complete. Popen.poll()/wait() must not reap it before signalling.
        try:info=os.waitid(os.P_PID,p.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
        except ChildProcessError:owned=False;break
        if info and info.si_pid:break
        now=time.monotonic()
        if now-start>=seconds:timed_out=True
        if timed_out or STOP.is_set() or HOST_GONE.is_set():
            if cancel_at is None:
                cancel_at=now
                try:
                    sig=signal.SIGINT if agent and not timed_out else signal.SIGTERM
                    os.killpg(p.pid,sig)
                    cancel_signal_sent=sig==signal.SIGINT
                except ProcessLookupError:pass
            grace=8 if agent and not timed_out else .2
            if now-cancel_at>=grace:
                forced=True
                try:os.killpg(p.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                if now-cancel_at>=grace+2:break
        time.sleep(.01)
    if owned:
        # Kill pipe holders while the original leader is still unreaped.
        try:os.killpg(p.pid,signal.SIGKILL)
        except ProcessLookupError:pass
    try:code=p.wait(timeout=2)
    except subprocess.TimeoutExpired:code=None
    deadline=time.monotonic()+.5
    while not all(eof) and time.monotonic()<deadline:time.sleep(.005)
    halt.set()
    for t in threads:t.join(timeout=.2)
    for pipe in [p.stdout,p.stderr]:pipe.close()
    return {'exit_code':code if code is not None and code>=0 else None,
            'signal':-code if code is not None and code<0 else None,
            'stdout':base64.b64encode(buffers[0]).decode(), 'stderr':base64.b64encode(buffers[1]).decode(),
            'truncated':any(truncated),'timed_out':timed_out,'cancelled':STOP.is_set(),
            'cancel_signal_sent':cancel_signal_sent,
            'forced':forced,'pipes_complete':all(eof),'leader_reaped':code is not None}

def run_command(c,uid,gid,cwd='/agent-tmp/work'):
    c=command(c);p=execute(c['argv'],cwd,uid,gid,c['timeout_secs'])
    return capture(p,c['stdin'],c['timeout_secs'])

COPY_CODE="""
import shutil,sys,os
shutil.copytree(sys.argv[1],sys.argv[2],dirs_exist_ok=True)
for directory,dirs,files in os.walk(sys.argv[2]):
    os.chmod(directory,0o700)
    for name in files:
        path=os.path.join(directory,name)
        os.chmod(path,0o700 if os.stat(path).st_mode&0o111 else 0o600)
if sys.argv[2]=='/workspace':os.chmod(sys.argv[2],0o755)
"""

PROBE_CODE="""
import json,os,socket
f=dict(line.split(':',1) for line in open('/proc/self/status') if ':' in line)
r={'interfaces':sorted(os.listdir('/sys/class/net')),'uid':os.getuid(),'gid':os.getgid(),'groups':os.getgroups(),
'capabilities_empty':int(f['CapEff'].strip(),16)==0,'no_new_privileges':f['NoNewPrivs'].strip()=='1',
'seccomp_active':f['Seccomp'].strip()=='2'}
try:
 fd=os.open('/proc/1/fd/1',os.O_WRONLY|os.O_CLOEXEC);os.close(fd);r['root_stdout_denied']=False
except PermissionError:r['root_stdout_denied']=True
try:os.kill(1,0);r['signal_probe_denied']=False
except PermissionError:r['signal_probe_denied']=True
s=socket.socket();s.settimeout(.2)
try:s.connect(('192.0.2.1',9));r['external_network_denied']=False
except OSError:r['external_network_denied']=r['interfaces']==['lo']
finally:s.close()
print(json.dumps(r))
"""

def main():
    if len(sys.argv)==3 and sys.argv[1]=='--child':child(sys.argv[2]);return 2
    if os.geteuid()!=0:raise ValueError('supervisor uid')
    for fd in [0,1,2]:os.set_inheritable(fd,False)
    send({'type':'ready','protocol':1,'uid':0})
    bootstrap_expiry=threading.Timer(30,lambda:os._exit(124));bootstrap_expiry.daemon=True;bootstrap_expiry.start()
    cfg=frame()
    bootstrap_expiry.cancel()
    if cfg is None:raise ValueError('bootstrap EOF')
    uid=bounded_int(cfg.get('uid'),1,65535);gid=bounded_int(cfg.get('gid'),1,65535)
    timeout=bounded_int(cfg.get('timeout_secs'),1,600);mode=cfg.get('mode')
    # Last-resort lifetime bound even if an attached host disappears while
    # stdin stays open. Normal work and host-owned cleanup finish earlier.
    expiry=threading.Timer(timeout+2,lambda:os._exit(124));expiry.daemon=True;expiry.start()
    if mode=='probe':
        if set(cfg)-{'mode','uid','gid','timeout_secs'}:raise ValueError('probe fields')
        result=run_command({'argv':['python3','-I','-S','-c',PROBE_CODE],'timeout_secs':min(timeout,5)},uid,gid,'/')
        if result['exit_code']!=0 or result['truncated'] or not result['pipes_complete']:raise ValueError('probe failed')
        send({'type':'probe_result',**strict(base64.b64decode(result['stdout']))});return 0
    if mode=='observe':
        if set(cfg)-{'mode','uid','gid','timeout_secs','prepare','check'}:raise ValueError('observer fields')
        prepare=cfg.get('prepare',[])
        if not isinstance(prepare,list) or len(prepare)>8:raise ValueError('prepare bounds')
        prepare=[command(c) for c in prepare];check=command(cfg.get('check'))
        copied=run_command({'argv':['python3','-I','-S','-c',COPY_CODE,'/snapshot','/agent-tmp/work'],'timeout_secs':10},uid,gid,'/')
        if copied['exit_code']!=0:raise ValueError('snapshot copy failed')
        deadline=time.monotonic()+timeout
        for c in prepare:
            if time.monotonic()>=deadline:raise ValueError('observer budget')
            c['timeout_secs']=min(c['timeout_secs'],max(1,int(deadline-time.monotonic())))
            result=run_command(c,uid,gid)
            if result['exit_code']!=0 or result['truncated'] or result['timed_out'] or not result['pipes_complete']:
                send({'type':'observation','prepare_failed':True,**result});return 0
        check['timeout_secs']=min(check['timeout_secs'],max(1,int(deadline-time.monotonic())))
        send({'type':'observation','prepare_failed':False,**run_command(check,uid,gid)});return 0
    if mode=='storage':
        if set(cfg)-{'mode','uid','gid','timeout_secs'}:raise ValueError('storage fields')
        # This container only holds bounded tmpfs-backed Docker volumes alive.
        # The host requests export after independently observing agent absence.
        # It mounts these volumes readonly and cannot run project code.
        deadline=time.monotonic()+timeout
        send({'type':'storage_ready'})
        while time.monotonic()<deadline:
            request=frame()
            if request is None or request=={'type':'release'}:return 0
            if set(request)!={'type','path'} or request['type']!='export' or request['path'] not in ('workspace','agent-home'):raise ValueError('storage request')
            source='/'+request['path']
            code="import sys,tarfile; t=tarfile.open(fileobj=sys.stdout.buffer,mode='w|',dereference=False); t.add(sys.argv[1],arcname='workspace'); t.close()"
            seconds=max(1,min(60,int(deadline-time.monotonic())))
            p=execute(['python3','-I','-S','-c',code,source],'/',uid,gid,seconds)
            result=capture(p,'',seconds,limit=80*1024*1024,agent=True,log_kind='archive_chunk')
            result.pop('stdout');result.pop('stderr');send({'type':'archive_done',**result})
        return 0
    if mode!='agent':raise ValueError('runtime mode')
    if set(cfg)-{'mode','uid','gid','timeout_secs','argv','model','profile_config','seed_project','resume_state','hold','sentinel','agent_timeout_secs'}:raise ValueError('agent fields')
    for flag in ['seed_project','resume_state','hold']:
        if type(cfg.get(flag,False)) is not bool:raise ValueError('agent flag')
    sentinel=cfg.get('sentinel')
    if sentinel is not None:
        if not isinstance(sentinel,str) or len(sentinel)>1024 or '\\' in sentinel or '\0' in sentinel or any(p in ('','.','..') for p in sentinel.split('/')):raise ValueError('sentinel path')
    agent_timeout=bounded_int(cfg.get('agent_timeout_secs',timeout),1,timeout)
    cmd=command({'argv':cfg.get('argv'),'timeout_secs':min(timeout,60)})
    model=cfg.get('model')
    if not isinstance(model,str) or not model or len(model.encode())>1024:raise ValueError('model')
    sys.path.insert(0,'/eval')
    import runtime_http
    pending={};pending_lock=threading.Lock();next_id=0
    def responses():
        try:
            while True:
                response=frame()
                if response is None:HOST_GONE.set();break
                if response=={'type':'cancel'}:STOP.set();continue
                if response=={'type':'release'}:RELEASE.set();continue
                if set(response)!={'type','id','status','body'} or response['type']!='response':raise ValueError('response')
                i=bounded_int(response['id'],1,128);status=bounded_int(response['status'],100,599)
                with pending_lock:
                    target=pending.get(i)
                    if target is None or not target.empty():raise ValueError('response id')
                    target.put_nowait((status,response['body']))
        except (ValueError,OSError,EOFError):HOST_GONE.set()
    threading.Thread(target=responses,daemon=True).start()
    deadline=time.monotonic()+timeout
    def relay(body):
        nonlocal next_id
        with pending_lock:
            if len(pending)>=4 or next_id>=128:raise ValueError('request budget')
            next_id+=1;i=next_id;target=queue.Queue(maxsize=1);pending[i]=target
        try:
            send({'type':'request','id':i,'body':body})
            while time.monotonic()<deadline and not STOP.is_set() and not HOST_GONE.is_set():
                try:return target.get(timeout=.1)
                except queue.Empty:continue
            raise ValueError('request cancelled')
        finally:
            with pending_lock:pending.pop(i,None)
    server=runtime_http.make_server(model,strict,relay,port=18080)
    server_thread=threading.Thread(target=server.serve_forever,daemon=True);server_thread.start()
    def substitute(v):
        if v=='{base_url}':return 'http://127.0.0.1:18080/v1'
        if isinstance(v,dict):return {k:substitute(x) for k,x in v.items()}
        if isinstance(v,list):return [substitute(x) for x in v]
        return v
    try:
        for enabled,source,target in [(cfg.get('seed_project'),'/fixture','/workspace'),(cfg.get('resume_state'),'/resume-state','/agent-home')]:
            if enabled:
                copied=run_command({'argv':['python3','-I','-S','-c',COPY_CODE,source,target],'timeout_secs':10},uid,gid,'/')
                if copied['exit_code']!=0 or copied['timed_out']:raise ValueError('agent seed failed')
        if sentinel is not None:
            def watch():
                import stat
                while not STOP.is_set() and not HOST_GONE.is_set() and time.monotonic()<deadline:
                    fds=[]
                    try:
                        fd=os.open('/workspace',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(fd)
                        for name in sentinel.split('/')[:-1]:
                            fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);fds.append(fd)
                        entry=os.stat(sentinel.split('/')[-1],dir_fd=fd,follow_symlinks=False)
                        if stat.S_ISREG(entry.st_mode):send({'type':'sentinel'});return
                    except (FileNotFoundError,NotADirectoryError):pass
                    except OSError:send({'type':'sentinel_unavailable'});return
                    finally:
                        for fd in fds:os.close(fd)
                    time.sleep(.05)
            threading.Thread(target=watch,daemon=True).start()
        p=execute(cmd['argv'],'/workspace',uid,gid,timeout,profile_config=substitute(cfg.get('profile_config')),agent=True)
        result=capture(p,'',agent_timeout,limit=4*1024*1024,agent=True)
        result.pop('stdout');result.pop('stderr');send({'type':'agent_done',**result})
        if cfg.get('hold'):
            while not RELEASE.is_set() and not HOST_GONE.is_set() and time.monotonic()<deadline:time.sleep(.02)
    finally:STOP.set();server.shutdown();server.server_close();server_thread.join(timeout=1)
    return 0

if __name__=='__main__':
    try:raise SystemExit(main())
    except (ValueError,OSError,EOFError,KeyError,TypeError,RecursionError):
        try:send({'type':'error','reason':'invalid runtime request or execution failure'})
        except (BrokenPipeError,OSError,ValueError):pass
        raise SystemExit(2)
