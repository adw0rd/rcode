"""Opt-in real protected runtime tests. No API, keys or oracle mount."""
import base64
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

DOCKER = os.environ.get('RCODE_EVAL_DOCKER', 'docker')
IMAGE = os.environ.get('RCODE_EVAL_IMAGE')
RUNTIME = Path(__file__).resolve().parents[1]/'evals/runtime'
sys.path.insert(0,str(RUNTIME))
from runtime import child
UID = os.getuid() or 10001
GID = os.getgid() or 10001


class ChildBootstrapTests(unittest.TestCase):
    def run_child(self,profile_credential):
        with tempfile.TemporaryDirectory(prefix='rcode-eval-child-') as temp:
            root=Path(temp);home=root/'home';work=root/'work';work.mkdir()
            config={'kind':'gigachat','base_url':'http://127.0.0.1:18080/v1'}
            bootstrap={'cwd':str(work),'argv':['/bin/echo'],'profile_config':config}
            if profile_credential is not None:bootstrap['profile_credential']=profile_credential
            path=root/'child.json';path.write_text(json.dumps(bootstrap))
            env={'PATH':'/usr/bin:/bin','HOME':str(home),'RCODE_HOME':str(home/'state')}
            previous=Path.cwd();calls=[]
            try:
                with patch('runtime.os.geteuid',return_value=10001),patch('runtime.environment',return_value=env),patch(
                    'runtime.os.execvpe',side_effect=lambda *args:calls.append(args)),patch.dict(os.environ,{},clear=True):
                    child(str(path))
            finally:os.chdir(previous)
            state=home/'state';credentials=state/'credentials.json'
            saved=json.loads(credentials.read_text()) if credentials.exists() else None
            mode=credentials.stat().st_mode&0o777 if credentials.exists() else None
            return json.loads((state/'config.json').read_text()),saved,mode,calls,env

    def test_gigachat_child_writes_only_placeholder_credential_with_private_mode(self):
        config,credentials,mode,calls,env=self.run_child('eval-placeholder-key')
        self.assertEqual(config['kind'],'gigachat')
        self.assertEqual(credentials,{'version':1,'providers':{'gigachat':'eval-placeholder-key'}})
        self.assertEqual(mode,0o600)
        self.assertNotIn('synthetic-real-key',json.dumps(calls))
        self.assertNotIn('synthetic-real-key',json.dumps(env))

    def test_local_child_remains_credential_free(self):
        _config,credentials,mode,_calls,_env=self.run_child(None)
        self.assertIsNone(credentials)
        self.assertIsNone(mode)


@unittest.skipUnless(IMAGE,'RCODE_EVAL_IMAGE is required for opt-in Docker runtime tests')
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

    def test_gigachat_bootstrap_contains_only_loopback_config_and_placeholder(self):
        profile={'kind':'gigachat','model':'fixture','scope':'GIGACHAT_API_PERS',
            'base_url':'http://127.0.0.1:18080/v1','auth_url':'http://127.0.0.1:18080/api/v2/oauth',
            'ca_file':None,'stream':False}
        config={'version':1,'active':'gigachat','providers':{'gigachat':profile},'local':{'active':None,'profiles':{}}}
        script=("import json,os;from pathlib import Path;state=Path(os.environ['RCODE_HOME']);"
            "config=json.loads((state/'config.json').read_text());credentials=json.loads((state/'credentials.json').read_text());"
            "assert 'synthetic-real-key' not in json.dumps(dict(os.environ));"
            "print(json.dumps({'config':config,'credentials':credentials,'mode':(state/'credentials.json').stat().st_mode&0o777,'env':dict(os.environ)}))")
        bootstrap={'mode':'agent','timeout_secs':5,'model':'fixture','profile_config':config,
            'profile_credential':'eval-placeholder-key','argv':['python3','-I','-S','-c',script]}
        self.assertNotIn('synthetic-real-key',json.dumps(bootstrap))
        out,frames=self.invoke(bootstrap)
        self.assertEqual(out.returncode,0,out.stderr)
        self.assertNotIn('synthetic-real-key',json.dumps(frames))
        raw=b''.join(base64.b64decode(v['data']) for v in frames if v.get('type')=='agent_log' and v.get('channel')=='stdout')
        result=json.loads(raw)
        effective=result['config']['providers']['gigachat']
        self.assertEqual(result['config']['active'],'gigachat')
        self.assertEqual(effective['kind'],'gigachat')
        self.assertEqual(effective['base_url'],'http://127.0.0.1:18080/v1')
        self.assertEqual(effective['auth_url'],'http://127.0.0.1:18080/api/v2/oauth')
        self.assertIsNone(effective['ca_file'])
        self.assertFalse(effective['stream'])
        self.assertEqual(result['credentials'],{'version':1,'providers':{'gigachat':'eval-placeholder-key'}})
        self.assertEqual(result['mode'],0o600)
        self.assertNotIn('synthetic-real-key',json.dumps(result['env']))

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
