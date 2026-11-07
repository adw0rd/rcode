"""Opt-in corpus controls; no model API and no project execution on host.

RCODE_EVAL_DOCKER=/absolute/docker RCODE_EVAL_SOCKET=/absolute/docker.sock \
RCODE_EVAL_IMAGE=sha256:... python3 tests/eval_controls.py
"""
import base64
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.dont_write_bytecode=True
sys.path[:0]=[str(ROOT/'evals'),str(ROOT/'evals/runtime')]
from host_docker import Docker,Failure
from host import observe_matches,probe_command
from runtime import strict

class OracleContractTests(unittest.TestCase):
    @staticmethod
    def observation(raw, **changes):
        return {'type':'observation','exit_code':0,'signal':None,'prepare_failed':False,
            'truncated':False,'timed_out':False,'cancelled':False,'leader_reaped':True,
            'pipes_complete':True,'stdout':base64.b64encode(raw).decode(),**changes}

    def test_rust_parse_contract_accepts_json_formatting_without_changing_values(self):
        oracle=json.loads((ROOT/'evals/oracles/rust-parse-integer-list.json').read_text())
        checks={c['id']:{'expected_exit':0,**c} for c in oracle['checks']}
        examples={'space-and-comma':b'[12, -3, 8]\n',
            'int32-limits':b'[\n -2147483648,\n 2147483647\n]\n'}
        for name,raw in examples.items():
            with self.subTest(check=name):
                self.assertTrue(observe_matches(self.observation(raw),checks[name]))
        for raw in (b'[12, 8, -3]',b'[12, -3]',b'[true, -3, 8]',b'[12.0,-3,8]'):
            self.assertFalse(observe_matches(self.observation(raw),checks['space-and-comma']))

    def test_json_comparison_preserves_types_and_rejects_ambiguous_documents(self):
        check={'expected_exit':0,'expected_json':{'items':[1,2],'ok':True}}
        self.assertTrue(observe_matches(self.observation(b' {"ok": true, "items": [1, 2]}\n'),check))
        for raw in (b'{"items":[2,1],"ok":true}',b'{"items":[true,2],"ok":true}',
            b'{"items":[1,2],"ok":1}',b'{"items":[1,2],"ok":true,"ok":true}',
            b'{"items":[NaN,2],"ok":true}',b'{"items":[1,2],"ok":true}\ndiagnostic',
            b'{"items":[1,2],"ok":true}\n{}'):
            self.assertFalse(observe_matches(self.observation(raw),check))

    def test_byte_sentinels_and_observer_failure_remain_strict(self):
        for text in ('x\n','ValueError\n'):
            check={'expected_exit':0,'expected_stdout':text}
            self.assertTrue(observe_matches(self.observation(text.encode()),check))
            self.assertFalse(observe_matches(self.observation(text.rstrip().encode()),check))
        check={'expected_exit':0,'expected_json':[1,2]}
        for changes in ({'exit_code':1},{'signal':15},{'prepare_failed':True},
            {'truncated':True},{'timed_out':True},{'cancelled':True},
            {'leader_reaped':False},{'pipes_complete':False}):
            self.assertFalse(observe_matches(self.observation(b'[1, 2]',**changes),check))

    def test_corpus_value_checks_accept_formatted_json_and_only_text_sentinels_use_bytes(self):
        manifest=json.loads((ROOT/'evals/manifest.json').read_text())
        text_checks={('python-tree-max-depth','first-command-executed-once'),
            ('python-refactor-chunk-api','invalid-size')}
        seen_text=set()
        for case in manifest['cases']:
            oracle=json.loads((ROOT/'evals'/case['oracle']).read_text())
            for check in oracle['checks']:
                key=(case['id'],check['id'])
                with self.subTest(case=key):
                    if key in text_checks:
                        self.assertIn('expected_stdout',check)
                        seen_text.add(key)
                    else:
                        self.assertIn('expected_json',check)
                        raw=json.dumps(check['expected_json'],ensure_ascii=False,sort_keys=True,indent=2).encode()+b'\n'
                        self.assertTrue(observe_matches(self.observation(raw),{'expected_exit':0,**check}))
        self.assertEqual(seen_text,text_checks)

def parts(path):
    if not isinstance(path,str) or len(path)>1024 or '\\' in path or '\0' in path:raise ValueError('fixture path')
    names=path.split('/')
    if not names or len(names)>32 or any(p in ('','.','..') for p in names):raise ValueError('fixture path')
    return names

class Fixtures:
    def __init__(self):self.fd=os.open(ROOT/'evals',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    def directory(self,path):
        fd=os.dup(self.fd)
        try:
            for name in parts(path):
                child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
            return fd
        except BaseException:os.close(fd);raise
    def read(self,path):
        names=parts(path);parent=self.directory('/'.join(names[:-1])) if len(names)>1 else os.dup(self.fd)
        try:
            fd=os.open(names[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
            try:
                meta=os.fstat(fd)
                if not stat.S_ISREG(meta.st_mode) or meta.st_nlink!=1 or meta.st_size>2*1024*1024:raise ValueError('unsafe fixture file')
                with os.fdopen(os.dup(fd),'rb') as stream:raw=stream.read(2*1024*1024+1)
                if len(raw)>2*1024*1024:raise ValueError('fixture file bound')
                return raw,bool(meta.st_mode&0o111)
            finally:os.close(fd)
        finally:os.close(parent)
    def stage(self,source,target,skip_control=False):
        budget=[0,0];target.mkdir(mode=0o755,parents=True,exist_ok=True)
        def walk(source,dest,depth):
            if depth>32:raise ValueError('fixture depth')
            fd=self.directory(source)
            try:
                names=[]
                with os.scandir(fd) as entries:
                    for entry in entries:
                        budget[0]+=1
                        if budget[0]>10000:raise ValueError('fixture entries')
                        names.append(entry.name)
                for name in sorted(names):
                    relative=source+'/'+name;parts(relative)
                    if skip_control and depth==0 and name=='CONTROL.json':continue
                    meta=os.stat(name,dir_fd=fd,follow_symlinks=False);out=dest/name
                    if stat.S_ISDIR(meta.st_mode):
                        out.mkdir(mode=0o755,exist_ok=True);walk(relative,out,depth+1)
                    elif stat.S_ISREG(meta.st_mode):
                        raw,executable=self.read(relative);budget[1]+=len(raw)
                        if budget[1]>64*1024*1024:raise ValueError('fixture aggregate size')
                        if out.exists():out.unlink()
                        handle=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                        with os.fdopen(handle,'wb') as stream:stream.write(raw)
                        out.chmod(0o555 if executable else 0o444)
                    else:raise ValueError('fixture link or special file')
            finally:os.close(fd)
        walk(source,target,0)
    def corrected(self,case,target):
        self.stage(case['project'],target)
        control='controls/'+case['id']
        try:raw,_=self.read(control+'/CONTROL.json')
        except FileNotFoundError:raw=None
        if raw is not None:
            data=strict(raw)
            if not isinstance(data,dict) or set(data)!={'delete'} or not isinstance(data['delete'],list) or len(data['delete'])>128:raise ValueError('control metadata')
            for path in data['delete']:
                dest=target.joinpath(*parts(path))
                if not dest.is_file() or dest.is_symlink():raise ValueError('control deletion')
                dest.unlink()
        self.stage(control,target,skip_control=True)

@unittest.skipUnless(os.environ.get('RCODE_EVAL_IMAGE') and os.environ.get('RCODE_EVAL_SOCKET'),'opt-in Docker controls: set RCODE_EVAL_IMAGE and RCODE_EVAL_SOCKET')
class CorpusControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory(prefix='rcode-eval-controls-');cls.addClassCleanup(cls.temporary.cleanup)
        cls.root=Path(cls.temporary.name);config=cls.root/'docker';config.mkdir(mode=0o700)
        cls.fixtures=Fixtures();cls.addClassCleanup(os.close,cls.fixtures.fd)
        image=os.environ['RCODE_EVAL_IMAGE'];socket=os.environ['RCODE_EVAL_SOCKET']
        executable=os.environ.get('RCODE_EVAL_DOCKER') or shutil.which('docker')
        if not re.fullmatch(r'sha256:[0-9a-f]{64}',image) or not executable or not Path(executable).is_absolute() or not Path(socket).is_absolute():raise ValueError('explicit local Docker configuration required')
        cls.docker=Docker(executable,socket,config,image,ROOT/'evals/runtime');cls.addClassCleanup(lambda:cls.docker.cleanup(time.monotonic()+15))
        manifest=strict(cls.fixtures.read('manifest.json')[0]);cls.cases=manifest['cases']
        if manifest['version']!=1 or len(cls.cases)!=30:raise ValueError('fixed corpus version/size')
        selected=set(filter(None,os.environ.get('RCODE_EVAL_CASES','').split(',')))
        if selected and not selected<={c['id'] for c in cls.cases}:raise ValueError('unknown selected case')
        cls.selected=selected
        seen=set()
        for c in cls.cases:
            name=c['id']
            if not isinstance(name,str) or not re.fullmatch('[a-z0-9_-]{1,64}',name) or name in seen:raise ValueError('case ID')
            seen.add(name)
            if c['project']!='cases/'+name+'/project' or c['oracle']!='oracles/'+name+'.json':raise ValueError('fixed corpus paths')
    def observe(self,snapshot,oracle,check):
        deadline=time.monotonic()+105;channel=None
        command=lambda c:probe_command({'stdin':'','timeout_secs':30,**c})
        try:
            name=self.docker.create({'/snapshot':snapshot},deadline)
            bootstrap={'mode':'observe','uid':10001,'gid':10001,'timeout_secs':90,'prepare':[command(c) for c in oracle.get('prepare',[])],'check':command(check)}
            channel=self.docker.start(name,bootstrap,deadline);observation=channel.receive()
            self.docker.remove(name,deadline)
            return observe_matches(observation,check)
        finally:
            try:self.docker.cleanup(deadline)
            finally:
                if channel:channel.close()
    def test_negative_and_corrected_controls(self):
        completed=0
        for case in self.cases:
            if self.selected and case['id'] not in self.selected:continue
            if self.docker.active or self.docker.volumes:raise Failure('previous cleanup unknown; corpus stopped')
            with self.subTest(case=case['id']):
                oracle=strict(self.fixtures.read(case['oracle'])[0])
                negative=self.root/(case['id']+'-negative');positive=self.root/(case['id']+'-corrected')
                self.fixtures.stage(case['project'],negative);self.fixtures.corrected(case,positive)
                rejected=any(not self.observe(negative,oracle,c) for c in oracle['checks'])
                failed=[c['id'] for c in oracle['checks'] if not self.observe(positive,oracle,c)]
                self.assertTrue(rejected,'unchanged source passed every hidden check')
                self.assertFalse(failed,'corrected control failed: '+','.join(failed))
                completed+=1
                print('control '+case['id']+': negative rejected, corrected passed',flush=True)
        expected=len(self.selected) if self.selected else 30
        self.assertEqual(completed,expected)
        print(str(completed)+'/'+str(expected)+' functional controls; no model inference performed',flush=True)

if __name__=='__main__':unittest.main()
