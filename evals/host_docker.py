"""Trusted Docker transport. This module never executes project commands on host."""
import json
import base64
import os
from pathlib import Path
import queue
import signal
import subprocess
import threading
import time
import uuid

from runtime import strict

CAPS={'SETUID','SETGID','KILL'}
LIMIT=4*1024*1024

class Failure(Exception):pass

class Docker:
    def __init__(self,executable,socket,config,image,runtime,uid=10001,cancel_requested=None):
        if not Path(executable).is_absolute() or not Path(socket).is_absolute():raise Failure('absolute Docker executable/socket required')
        self.prefix=[executable,'--config',str(config),'--host','unix://'+socket]
        self.env={'PATH':'/usr/bin:/bin','HOME':str(config),'LANG':'C.UTF-8'}
        self.image=image;self.runtime=Path(runtime);self.uid=uid;self.active={};self.volumes={}
        self.cancel_requested=cancel_requested or (lambda:False);self.finalizing=False
    def call(self,args,deadline,limit=65536,input=None):
        remaining=deadline-time.monotonic()
        if remaining<=0:raise Failure('Docker deadline exhausted')
        p=subprocess.Popen(self.prefix+args,env=self.env,stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True,start_new_session=True)
        buffers=[bytearray(),bytearray()];overflow=threading.Event()
        def read(i,pipe):
            while True:
                chunk=pipe.read(65536)
                if not chunk:break
                room=(limit if i==0 else 16384)-len(buffers[i]);buffers[i].extend(chunk[:max(0,room)])
                if len(chunk)>room:overflow.set()
        readers=[threading.Thread(target=read,args=(i,s),daemon=True) for i,s in enumerate([p.stdout,p.stderr])]
        for t in readers:t.start()
        try:
            if input is not None:p.stdin.write(input);p.stdin.close()
            while p.poll() is None:
                if overflow.is_set() or time.monotonic()>=deadline or (self.cancel_requested() and not self.finalizing):
                    os.killpg(p.pid,signal.SIGKILL);p.wait();raise Failure('Docker output/deadline limit')
                time.sleep(.01)
            for t in readers:t.join(timeout=1)
            if any(t.is_alive() for t in readers) or overflow.is_set():raise Failure('Docker output incomplete or oversized')
            return p.returncode,bytes(buffers[0]),bytes(buffers[1])
        finally:
            if p.poll() is None:os.killpg(p.pid,signal.SIGKILL);p.wait()
            for s in [p.stdout,p.stderr]:s.close()
    def checked(self,args,deadline,limit=65536):
        code,out,_=self.call(args,deadline,limit)
        if code:raise Failure('Docker operation failed: '+args[0])
        return out
    def inspect(self,name,deadline):
        raw=self.checked(['inspect',name],deadline)
        data=strict(raw)
        if not isinstance(data,list) or len(data)!=1:raise Failure('Docker inspect shape')
        return data[0]
    def volume(self,size_mib,deadline):
        if size_mib not in (64,128):raise Failure('volume size')
        name='rcode-eval-volume-'+uuid.uuid4().hex;owner=uuid.uuid4().hex
        options={'type':'tmpfs','device':'tmpfs','o':f'rw,nosuid,nodev,size={size_mib}m,uid={self.uid},gid={self.uid},mode=0755'+(',noexec' if size_mib==64 else '')}
        self.volumes[name]={'owner':owner,'options':options}
        args=['volume','create','--driver','local','--label','rcode.eval.owner='+owner]
        for key,value in options.items():args+=['--opt',key+'='+value]
        self.checked(args+[name],deadline)
        values=strict(self.checked(['volume','inspect',name],deadline))
        if not isinstance(values,list) or len(values)!=1:raise Failure('volume inspect shape')
        data=values[0]
        if data['Name']!=name or data['Driver']!='local' or data['Options']!=options or data.get('Labels',{}).get('rcode.eval.owner')!=owner:raise Failure('volume isolation mismatch')
        return name
    def create(self,binds,deadline,volumes=None,volumes_readonly=False):
        volumes=volumes or {}
        if set(volumes)-{'/workspace','/agent-home'} or any(v not in self.volumes for v in volumes.values()):raise Failure('unowned volume')
        name='rcode-eval-'+uuid.uuid4().hex;owner=uuid.uuid4().hex
        self.active[name]={'owner':owner,'id':None,'mode':None} # Register BEFORE create, including ambiguous failures.
        args=['create','--pull=never','--name',name,'--label','rcode.eval.owner='+owner,
            '--network=none','--read-only','--cap-drop=ALL','--cap-add=SETUID','--cap-add=SETGID','--cap-add=KILL',
            '--security-opt=no-new-privileges','--pids-limit=128','--memory=2g','--cpus=2','--ipc=private',
            '--tmpfs','/control:rw,noexec,nosuid,nodev,size=16m,mode=0755',
            '--tmpfs',f'/agent-tmp:rw,exec,nosuid,nodev,size=256m,mode=0700,uid={self.uid},gid={self.uid}',
            '--tmpfs','/tmp:rw,exec,nosuid,nodev,size=256m,mode=1777']
        for dst,size,flags in [('/workspace',128,'exec'),('/agent-home',64,'noexec')]:
            if dst in volumes:
                args+=['--mount',f'type=volume,source={volumes[dst]},destination={dst},volume-nocopy'+(',readonly' if volumes_readonly else '')]
            else:args+=['--tmpfs',f'{dst}:rw,{flags},nosuid,nodev,size={size}m,mode=0755,uid={self.uid},gid={self.uid}']
        all_binds={**binds,'/eval':self.runtime}
        for dst,src in sorted(all_binds.items()):
            if ',' in str(src) or not Path(src).is_absolute():raise Failure('invalid bind path')
            args+=['--mount',f'type=bind,src={src},dst={dst},readonly']
        args+=['--entrypoint','python3','-i',self.image,'-I','-S','/eval/runtime.py']
        self.checked(args,deadline)
        data=self.inspect(name,deadline);h=data['HostConfig'];c=data['Config']
        self.active[name]['id']=data['Id']
        caps={s.removeprefix('CAP_') for s in h.get('CapAdd',[])}
        mounts=data.get('Mounts',[])
        if not (data['Image']==self.image and c.get('Labels',{}).get('rcode.eval.owner')==owner
                and h['NetworkMode']=='none' and h['ReadonlyRootfs'] is True and h['Privileged'] is False
                and h.get('PidMode','')=='' and h['IpcMode']=='private' and not h.get('Devices')
                and not h.get('PortBindings') and not h.get('Binds') and caps==CAPS
                and h['CapDrop']==['ALL'] and 'no-new-privileges' in h['SecurityOpt']
                and h['Memory']==2147483648 and h['NanoCpus']==2000000000 and h['PidsLimit']==128
                and h['RestartPolicy']['Name'] in ('no','')
                and {m['Destination']:m['Source'] for m in mounts if m['Type']=='bind'}=={k:str(v) for k,v in all_binds.items()}
                and all(not m['RW'] for m in mounts if m['Type']=='bind')
                and {m['Destination']:(m.get('Name'),m['RW']) for m in mounts if m['Type']=='volume'}=={k:(v,not volumes_readonly) for k,v in volumes.items()}
                and set(h['Tmpfs'])=={'/workspace','/agent-home','/agent-tmp','/tmp','/control'}-set(volumes)
                and h['Tmpfs']['/tmp']=='rw,exec,nosuid,nodev,size=256m,mode=1777'):
            raise Failure('container isolation inspect mismatch')
        return name
    def remove(self,name,deadline):
        record=self.active[name];owner=record['owner'];identity=record['id'] or name
        # A failed inspect is not proof of absence; a responsive independent list
        # must show no exact name. A matching name is removed only if label matches.
        selector='id='+identity if record['id'] else 'name=^/'+name+'$'
        rows=self.checked(['ps','-a','--filter',selector,'--format','{{.Names}}'],deadline).decode().splitlines()
        ambiguous_absence=record['id'] is None and not rows
        if rows:
            if rows!=[name]:raise Failure('container identity ambiguity')
            data=self.inspect(identity,deadline)
            if data['Config'].get('Labels',{}).get('rcode.eval.owner')!=owner:raise Failure('container ownership mismatch')
            self.checked(['rm','-f',identity],deadline)
        rows=self.checked(['ps','-a','--filter',selector,'--format','{{.ID}}'],deadline).strip()
        if rows:raise Failure('container still present')
        if ambiguous_absence:
            if deadline-time.monotonic()<1.0:raise Failure('container cleanup settling deadline')
            time.sleep(1.0)
            rows=self.checked(['ps','-a','--filter',selector,'--format','{{.ID}}'],deadline).strip()
            if rows:raise Failure('container appeared after interrupted create')
        del self.active[name]
    def cleanup(self,deadline):
        previous=self.finalizing;self.finalizing=True
        try:return self._cleanup(deadline)
        finally:self.finalizing=previous
    def _cleanup(self,deadline):
        failures=[]
        for name in list(self.active):
            try:self.remove(name,deadline)
            except (Failure,OSError,ValueError):failures.append(name)
        if failures:raise Failure('container cleanup unknown')
        for name in list(self.volumes):
            try:
                rows=self.checked(['volume','ls','--filter','name=^'+name+'$','--format','{{.Name}}'],deadline).decode().splitlines()
                if rows:
                    if rows!=[name]:raise Failure('volume name ambiguity')
                    data=strict(self.checked(['volume','inspect',name],deadline))[0]
                    if data.get('Labels',{}).get('rcode.eval.owner')!=self.volumes[name]['owner']:raise Failure('volume ownership mismatch')
                    self.checked(['volume','rm',name],deadline)
                if self.checked(['volume','ls','--filter','name=^'+name+'$','--format','{{.Name}}'],deadline).strip():raise Failure('volume still present')
                del self.volumes[name]
            except (Failure,OSError,ValueError):failures.append(name)
        if failures:raise Failure('volume cleanup unknown')
    def archive(self,channel,path):
        if any(record['mode']=='agent' for record in self.active.values()):raise Failure('agent must be independently absent before export')
        data=self.inspect(channel.identity,channel.deadline)
        if data['State'].get('Running') is not True or data.get('RestartCount')!=0:raise Failure('storage keeper lost')
        for volume in self.volumes:
            users=self.checked(['ps','-a','--no-trunc','--filter','volume='+volume,'--format','{{.ID}}'],channel.deadline).decode().splitlines()
            if users!=[channel.identity]:raise Failure('volume has another container reference')
        channel.send({'type':'export','path':path});out=bytearray()
        while True:
            frame=channel.receive()
            if frame.get('type')=='archive_chunk':
                if set(frame)!={'type','channel','data'}:raise Failure('archive frame shape')
                raw=base64.b64decode(frame['data'],validate=True)
                if frame['channel']=='stderr':raise Failure('archive exporter stderr')
                if frame['channel']!='stdout' or len(out)+len(raw)>80*1024*1024:raise Failure('archive bounds')
                out.extend(raw)
            elif frame.get('type')=='archive_done':
                if frame.get('exit_code')!=0 or frame.get('signal') is not None or any(frame.get(k) is not False for k in ['truncated','timed_out','cancelled','forced']) or frame.get('pipes_complete') is not True or frame.get('leader_reaped') is not True:raise Failure('archive incomplete')
                return bytes(out)
            else:raise Failure('archive protocol')
    def start(self,name,bootstrap,deadline):
        self.active[name]['mode']=bootstrap['mode']
        return Channel(self,self.active[name]['id'],bootstrap,deadline)

class Channel:
    def __init__(self,docker,name,bootstrap,deadline):
        self.docker=docker
        self.identity=name;self.deadline=deadline;self.frames=queue.Queue(maxsize=16);self.error=None;self.done=threading.Event();self.stderr=bytearray();self.write_lock=threading.Lock()
        self.process=subprocess.Popen(docker.prefix+['start','-a','-i',name],env=docker.env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True,start_new_session=True)
        def output():
            try:
                while True:
                    line=self.process.stdout.readline(LIMIT+1)
                    if not line:break
                    if len(line)>LIMIT or not line.endswith(b'\n'):raise Failure('Root frame bounds')
                    v=strict(line)
                    if not isinstance(v,dict):raise Failure('Root frame shape')
                    while not self.done.is_set():
                        try:self.frames.put(v,timeout=.1);break
                        except queue.Full:continue
            except (Failure,ValueError,OSError) as e:self.error=type(e).__name__
            finally:self.done.set()
        def errors():
            try:
                while True:
                    raw=self.process.stderr.read(4096)
                    if not raw:return
                    self.stderr.extend(raw[:max(0,16384-len(self.stderr))])
            except OSError:pass
        self.readers=[threading.Thread(target=output,daemon=True),threading.Thread(target=errors,daemon=True)]
        for t in self.readers:t.start()
        try:
            if self.receive()!= {'type':'ready','protocol':1,'uid':0}:raise Failure('Root readiness mismatch')
            self.send(bootstrap)
        except BaseException:self.close();raise
    def send(self,value):
        raw=json.dumps(value,ensure_ascii=True,allow_nan=False,separators=(',',':')).encode()+b'\n'
        if len(raw)>LIMIT:raise Failure('outbound Root frame bound')
        with self.write_lock:
            # Frames are at most4MiB; the supervisor continuously drains input.
            # A bounded writer thread keeps a broken helper from blocking cleanup.
            result=[]
            def write():
                try:self.process.stdin.write(raw);self.process.stdin.flush()
                except (OSError,ValueError):result.append(False)
            t=threading.Thread(target=write,daemon=True);t.start()
            while t.is_alive() and time.monotonic()<self.deadline:
                if self.docker.cancel_requested() and not self.docker.finalizing:raise Failure('operator cancellation')
                t.join(min(.05,max(.001,self.deadline-time.monotonic())))
            if t.is_alive() or result:raise Failure('Root write failed/deadline')
    def receive(self,timeout=None):
        poll_deadline=min(self.deadline,time.monotonic()+timeout) if timeout is not None else self.deadline
        while time.monotonic()<poll_deadline:
            if self.docker.cancel_requested() and not self.docker.finalizing:raise Failure('operator cancellation')
            try:return self.frames.get(timeout=min(.1,max(.001,poll_deadline-time.monotonic())))
            except queue.Empty:
                if self.done.is_set():raise Failure('Root channel closed or invalid')
        if time.monotonic()>=self.deadline:raise Failure('case work deadline')
        return None
    def close(self):
        self.done.set()
        p=self.process
        if p.poll() is None:
            try:os.killpg(p.pid,signal.SIGKILL)
            except ProcessLookupError:pass
        p.wait(timeout=3)
        for pipe in [p.stdin,p.stdout,p.stderr]:
            try:pipe.close()
            except OSError:pass
        for t in self.readers:t.join(timeout=.2)
