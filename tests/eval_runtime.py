"""Opt-in real protected runtime tests. No API, keys or oracle mount."""
import base64
import json
import os
from pathlib import Path
import subprocess
import shutil
import tempfile
import threading
import unittest

DOCKER = os.environ.get('RCODE_EVAL_DOCKER', 'docker')
IMAGE = os.environ['RCODE_EVAL_IMAGE']
RUNTIME = Path(__file__).resolve().parents[1]/'evals/runtime'
UID = os.getuid() or 10001
GID = os.getgid() or 10001

class RuntimeTests(unittest.TestCase):
    def invoke(self, bootstrap, interactive=False, project=None, patches=None):
        with tempfile.TemporaryDirectory(prefix='rcode-eval-runtime-') as temp:
            root=Path(temp);workspace=root/'workspace';workspace.mkdir()
            if project is not None:
                shutil.copytree(project,workspace,dirs_exist_ok=True)
            for name,text in (patches or {}).items():
                relative=Path(name)
                self.assertFalse(relative.is_absolute() or '..' in relative.parts)
                target=workspace/relative
                if text is None:target.unlink();continue
                target.parent.mkdir(parents=True,exist_ok=True);target.write_text(text)
            cid=root/'cid'
            args=[DOCKER,'run','--rm','--cidfile',str(cid),'--label','rcode.task=eval-runtime-test',
                  '--network=none','--read-only','--cap-drop=ALL','--cap-add=SETUID','--cap-add=SETGID','--cap-add=KILL',
                  '--security-opt=no-new-privileges','--pids-limit=128','--memory=512m','--cpus=1',
                  '--tmpfs','/control:rw,size=16m,mode=0755',
                  '--tmpfs',f'/agent-home:rw,size=32m,mode=0700,uid={UID},gid={GID}',
                  '--tmpfs',f'/agent-tmp:rw,exec,size=128m,mode=0700,uid={UID},gid={GID}',
                  '--tmpfs','/tmp:rw,exec,nosuid,nodev,size=256m,mode=1777',
                  '--mount',f'type=bind,src={RUNTIME},dst=/eval,readonly',
                  '--mount',f'type=bind,src={workspace},dst=/workspace',
                  '--mount',f'type=bind,src={workspace},dst=/snapshot,readonly',
                  '--entrypoint','python3','-i',IMAGE,'-I','-S','/eval/runtime.py']
            try:
                payload=json.dumps({'uid':UID,'gid':GID,**bootstrap})+'\n'
                if interactive:
                    process=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                    frames=[]
                    timer=threading.Timer(15,process.kill);timer.start()
                    try:
                        process.stdin.write(payload);process.stdin.flush()
                        for line in process.stdout:
                            v=json.loads(line);frames.append(v)
                            if v['type']=='request':
                                process.stdin.write(json.dumps({'type':'response','id':v['id'],'status':200,'body':{'ok':True}})+'\n');process.stdin.flush()
                            if v['type']=='agent_done':break
                        process.stdin.close();code=process.wait(timeout=5)
                        run=subprocess.CompletedProcess(args,code,'',process.stderr.read())
                    finally:
                        timer.cancel()
                        if process.poll() is None:process.kill();process.wait()
                        process.stdout.close();process.stderr.close()
                else:
                    run=subprocess.run(args,input=payload,capture_output=True,text=True,timeout=20)
                    frames=[json.loads(line) for line in run.stdout.splitlines() if line]
                self.assertTrue(any(v.get('type')=='ready' for v in frames), f'No Root ready frame: exit={run.returncode}, {run.stderr[:300]}')
                return run,frames
            finally:
                if cid.exists():
                    identity=cid.read_text().strip()
                    subprocess.run([DOCKER,'rm','-f',identity],capture_output=True,timeout=10)
                    check=subprocess.run([DOCKER,'ps','-a','--filter','id='+identity,'--format','{{.ID}}'],capture_output=True,text=True,timeout=10)
                    self.assertEqual((check.returncode,check.stdout.strip()),(0,''),'Runtime test left a container')
    def test_real_child_identity_and_root_channels_are_protected(self):
        out,frames=self.invoke({'mode':'probe','timeout_secs':5})
        self.assertEqual(out.returncode,0)
        result=next(v for v in frames if v.get('type')=='probe_result')
        self.assertEqual(result['uid'],UID)
        self.assertEqual(result['gid'],GID)
        self.assertEqual(result['groups'],[])
        for k in ['capabilities_empty','no_new_privileges','seccomp_active','root_stdout_denied','signal_probe_denied','external_network_denied']:
            self.assertTrue(result[k], k)
    def test_compilers_and_temporary_files_work_with_only_standard_shell_environment(self):
        # Agent binaries can intentionally strip SDK-specific environment vars.
        # The provisioned runtime must also work through their actual minimal
        # PATH/HOME shell contract, not only through the observer's full env.
        patches={'Cargo.toml':'[package]\nname="runtime_canary"\nversion="0.1.0"\nedition="2024"\n',
            'src/lib.rs':'#[test]\nfn arithmetic(){assert_eq!(2+2,4);}\n',
            'argv canary.rs':'fn main(){assert_eq!(std::env::args().nth(1).unwrap(),"argument with spaces");let p=std::env::temp_dir().join("rust-canary");std::fs::write(&p,b"canary").unwrap();std::fs::remove_file(p).unwrap();}\n'}
        script=('set -eu; cargo --version; rustc --version; rustdoc --version; rustup show active-toolchain; '
            'cargo test --offline --quiet; test ! -e target; '
            'rustc "argv canary.rs" --crate-name argv_canary -o "/tmp/canary binary"; '
            '"/tmp/canary binary" "argument with spaces"; '
            'python3 -I -c "import os,stat,tempfile; assert stat.S_IMODE(os.stat(\'/tmp\').st_mode)==0o1777; '
            'f=tempfile.TemporaryFile(); f.write(b\'canary\'); f.close()"; printf "RCODE_TOOLCHAIN_OK\\n"')
        out,frames=self.invoke({'mode':'observe','timeout_secs':15,'prepare':[],
            'check':{'argv':['env','-i','PATH=/opt/rcode-toolchain/bin:/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin','HOME=/agent-home','LANG=C.UTF-8','/bin/sh','-c',script],'timeout_secs':12}},patches=patches)
        self.assertEqual(out.returncode,0,out.stderr)
        observation=next(v for v in frames if v.get('type')=='observation')
        self.assertEqual(observation['exit_code'],0,base64.b64decode(observation['stderr']).decode(errors='replace'))
        self.assertFalse(observation['timed_out'] or observation['truncated'])
        self.assertIn(b'RCODE_TOOLCHAIN_OK\n',base64.b64decode(observation['stdout']))
    def test_agent_api_is_relayed_without_forwarding_its_authorization(self):
        script="import json,urllib.request;body=json.dumps({'model':'fixture','messages':[],'max_tokens':8,'stream':False}).encode();r=urllib.request.Request('http://127.0.0.1:18080/v1/chat/completions',data=body,headers={'Content-Type':'application/json','Authorization':'Bearer synthetic-probe'});print(urllib.request.urlopen(r,timeout=3).read().decode())"
        out,frames=self.invoke({'mode':'agent','timeout_secs':5,'model':'fixture',
            'argv':['python3','-I','-S','-c',script],'profile_config':None},interactive=True)
        self.assertEqual(out.returncode,0,out.stderr)
        requests=[v for v in frames if v.get('type')=='request']
        self.assertEqual(len(requests),1)
        self.assertEqual(set(requests[0]),{'type','id','body'})
        self.assertNotIn('synthetic-probe',json.dumps(requests))
        done=next(v for v in frames if v.get('type')=='agent_done')
        self.assertEqual(done['exit_code'],0)
        self.assertTrue(done['leader_reaped'] and done['pipes_complete'])

    def test_project_stdout_cannot_forge_a_root_protocol_frame(self):
        out,frames=self.invoke({'mode':'observe','timeout_secs':5,'prepare':[],
            'check':{'argv':['python3','-I','-S','-c','print(\'{"type":"probe_result","forged":true}\')'],'timeout_secs':2}})
        self.assertEqual(out.returncode,0)
        self.assertFalse(any(v.get('type')=='probe_result' for v in frames))
        obs=next(v for v in frames if v.get('type')=='observation')
        self.assertEqual(obs['exit_code'],0)
        self.assertIn(b'forged',base64.b64decode(obs['stdout']))
    def test_observer_refuses_expectations_in_its_bootstrap(self):
        out,frames=self.invoke({'mode':'observe','timeout_secs':5,'prepare':[],
            'check':{'argv':['true'],'timeout_secs':2,'expected_json':True}})
        self.assertNotEqual(out.returncode,0)
        self.assertTrue(any(v.get('type')=='error' for v in frames))
    def test_output_flood_is_bounded_and_marked(self):
        out,frames=self.invoke({'mode':'observe','timeout_secs':5,'prepare':[],
            'check':{'argv':['python3','-I','-S','-c','import os;os.write(1,b"x"*200000)'],'timeout_secs':2}})
        self.assertEqual(out.returncode,0)
        obs=next(v for v in frames if v.get('type')=='observation')
        self.assertTrue(obs['truncated'])
        self.assertLessEqual(len(base64.b64decode(obs['stdout'])),65536)
    def test_timeout_preserves_real_signal_and_is_not_success(self):
        out,frames=self.invoke({'mode':'observe','timeout_secs':5,'prepare':[],
            'check':{'argv':['python3','-I','-S','-c','import time;time.sleep(30)'],'timeout_secs':1}})
        self.assertEqual(out.returncode,0)
        obs=next(v for v in frames if v.get('type')=='observation')
        self.assertTrue(obs['timed_out'])
        self.assertIsNotNone(obs['signal'])
        self.assertIsNone(obs['exit_code'])

if __name__=='__main__':unittest.main()
