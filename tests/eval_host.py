"""Opt-in real Docker tests of host orchestration; no model API required."""
import base64
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'evals'),str(ROOT/'evals/runtime')]
from host_docker import Docker,Failure
from host_snapshot import extract_frozen


class HostConfigTests(unittest.TestCase):
    def test_gigachat_model_config_uses_native_loopback_provider(self):
        import host
        profile={'kind':'gigachat','model':'GigaChat-3-Ultra','scope':'GIGACHAT_API_PERS',
            'auth_url':'https://ngw.devices.sberbank.ru:9443/api/v2/oauth','folder_id':None,
            'base_url':'https://api.giga.chat/v1','ca_file':'/host/only/ca.pem','stream':True,
            'max_output_tokens':8,'request_timeout_secs':5,'idle_timeout_secs':5,'local':None}
        expected={'version':1,'active':'gigachat','providers':{'gigachat':{**profile,
            'base_url':'http://127.0.0.1:18080/v1','auth_url':'http://127.0.0.1:18080/api/v2/oauth',
            'ca_file':None,'stream':False}},'local':{'active':None,'profiles':{}}}
        config=host.model_config(profile)
        self.assertEqual(config,expected)
        self.assertNotIn('provider_credential',config)
        self.assertNotIn('eval-placeholder-key',json.dumps(config))

    def test_local_model_config_remains_credential_free(self):
        import host
        profile={'kind':'local','model':'fixture','base_url':'http://127.0.0.1:9/v1',
            'local':{'profile':'eval','key_required':False}}
        config=host.model_config(profile)
        self.assertEqual(config['active'],'local')
        self.assertEqual(config['providers'],{})
        self.assertEqual(config['local']['active'],'eval')
        self.assertFalse(config['local']['profiles']['eval']['local']['key_required'])
        self.assertNotIn('profile_credential',config)

    def test_native_gigachat_request_and_response_are_not_converted_twice(self):
        import host
        from unittest.mock import patch
        responses=[(200,{'access_token':'host-token','expires_at':4_000_000_000}),
            (200,{'model':'GigaChat-3-Ultra','choices':[{'message':{'role':'assistant','content':'',
                'function_call':{'name':'read_file','arguments':{'path':'a.rs'}},
                'functions_state_id':'state-2'},'finish_reason':'function_call'}]})]
        calls=[]
        def exchange(operation,authorization,body):
            calls.append((operation,authorization,body))
            return responses.pop(0)
        profile={'kind':'gigachat','model':'GigaChat-3-Ultra','scope':'GIGACHAT_API_PERS','stream':False,
            'max_output_tokens':8,'request_timeout_secs':5,'idle_timeout_secs':5}
        body={'model':'GigaChat-3-Ultra','max_tokens':8,'stream':False,
            'functions':[{'name':'read_file','description':'Read','parameters':{'type':'object'}}],
            'function_call':'auto','messages':[{'role':'user','content':'read'},
                {'role':'assistant','content':'','function_call':{'name':'read_file','arguments':{'path':'a.rs'}},
                    'functions_state_id':'state-1'},
                {'role':'function','name':'read_file','content':'{"ok":true}'}]}
        with patch.object(host,'HttpsExchange',return_value=exchange):
            gateway=host.Gateway(profile,{'max_steps':1,'max_requests':1},time.monotonic()+5,'Basic synthetic-key')
            status,value=gateway.relay(body)
        self.assertEqual(status,200)
        self.assertIs(calls[1][2],body)
        self.assertEqual(value['choices'][0]['message']['functions_state_id'],'state-2')
        self.assertIn('function_call',value['choices'][0]['message'])
        self.assertNotIn('tool_calls',value['choices'][0]['message'])
        self.assertEqual(gateway.receipts[0]['requested_tool_names'],{'read_file':1})

    def test_gigachat_agent_bootstrap_uses_provider_and_placeholder_only(self):
        import host
        from unittest.mock import patch
        captured=[]
        class Channel:
            def receive(self,timeout=None):return {'type':'agent_done','exit_code':0}
            def send(self,_value):pass
            def close(self):pass
        class FakeDocker:
            uid=10001
            def create(self,*_args,**_kwargs):return 'agent'
            def start(self,_name,bootstrap,_deadline):captured.append(bootstrap);return Channel()
            def remove(self,*_args):pass
        class Pump:
            def __init__(self,_gateway):pass
            def deliver(self,_channel):pass
            def close(self):pass
        profile={'kind':'gigachat','model':'GigaChat-3-Ultra','scope':'GIGACHAT_API_PERS','stream':False}
        invocation={'binary':'/unused/rcode','effective_profile':profile,'provider_credential':'Basic synthetic-real-key'}
        item={'case':{'max_steps':1},'fixture':'/unused/fixture','task':'fixture'}
        with patch.object(host,'RequestPump',Pump):
            host.agent_phase(FakeDocker(),invocation,item,{},object(),time.monotonic()+5)
        bootstrap=captured[0]
        self.assertIn('--provider',bootstrap['argv'])
        self.assertEqual(bootstrap['argv'][bootstrap['argv'].index('--provider')+1],'gigachat')
        self.assertNotIn('--profile',bootstrap['argv'])
        self.assertEqual(bootstrap['profile_credential'],'eval-placeholder-key')
        self.assertNotIn('synthetic-real-key',json.dumps(bootstrap))
        self.assertNotIn('skills_config',bootstrap)

    def test_agent_bootstrap_adds_linked_config_for_required_skills(self):
        import host
        from unittest.mock import patch
        captured=[]
        class Channel:
            def receive(self,timeout=None):return {'type':'agent_done','exit_code':0}
            def send(self,_value):pass
            def close(self):pass
        class FakeDocker:
            uid=10001
            def create(self,*_args,**_kwargs):return 'agent'
            def start(self,_name,bootstrap,_deadline):captured.append(bootstrap);return Channel()
            def remove(self,*_args):pass
        class Pump:
            def __init__(self,_gateway):pass
            def deliver(self,_channel):pass
            def close(self):pass
        profile={'kind':'local','model':'fixture','base_url':'http://127.0.0.1:9/v1','local':{}}
        invocation={'binary':'/unused/rcode','effective_profile':profile}
        item={'case':{'max_steps':1,'require_skills':['superpowers:using-superpowers',
            'superpowers:test-driven-development','superpowers:verification-before-completion']},
            'fixture':'/unused/fixture','task':'fixture'}
        with patch.object(host,'RequestPump',Pump):
            host.agent_phase(FakeDocker(),invocation,item,{},object(),time.monotonic()+5)
        self.assertEqual(captured[0].get('skills_config'),{'version':1,'linked':{'superpowers':{
            'path':'/workspace/skill-sources/superpowers'}}})

    def test_ambiguous_create_absence_is_rechecked_before_cleanup_is_confirmed(self):
        from unittest.mock import patch
        name='rcode-eval-delayed'
        docker=Docker('/docker','/docker.sock',Path('/unused'),'sha256:'+'0'*64,Path('/runtime'))
        docker.active[name]={'owner':'fixture-owner','id':None,'mode':None}
        with patch.object(docker,'checked',side_effect=[b'',b'',name.encode()+b'\n']) as checked,patch('host_docker.time.sleep') as sleep:
            with self.assertRaises(Failure):docker.remove(name,time.monotonic()+5)
        self.assertEqual(checked.call_count,3)
        sleep.assert_called_once_with(1.0)
        self.assertIn(name,docker.active)

    def test_setup_timeout_gets_a_fresh_cleanup_deadline(self):
        import host
        from unittest.mock import patch
        class FakeDocker:
            def __init__(self,*_args,**_kwargs):
                self.active={};self.volumes={};self.cleanup_deadline=None
            def cleanup(self,deadline):
                if deadline<=time.monotonic():raise Failure('expired cleanup deadline')
        def expire(_docker,_deadline):
            raise Failure('simulated setup timeout')
        invocation={'version':1,'comparison_key':{},'artifact':{},
            'docker':'/docker','socket':'/docker.sock','image':'image','runtime':str(ROOT/'evals/runtime'),
            'cases':[{'case':{'id':'setup-timeout'},'sha256':'f'*64}]}
        stdin=io.TextIOWrapper(io.BytesIO(json.dumps(invocation).encode()))
        stdout=io.StringIO();stderr=io.StringIO()
        monotonic=host.time.monotonic
        def expired(_docker,deadline):
            host.time.monotonic=lambda:deadline+1
            expire(_docker,deadline)
        try:
            with patch.object(host,'Docker',FakeDocker),patch.object(host,'check_isolation',expired),patch.object(
                host.sys,'stdin',stdin),patch.object(host.sys,'stdout',stdout),patch.object(host.sys,'stderr',stderr):
                code=host.main()
        finally:host.time.monotonic=monotonic
        report=json.loads(stdout.getvalue())
        self.assertEqual(code,1)
        self.assertEqual(report['cleanup'],'confirmed_absent')

    def test_gigachat_failure_receipt_has_safe_operation_status_and_category(self):
        import host
        from unittest.mock import patch
        class Exchange:
            operation=None;status=None;error_type='RemoteDisconnected'
            def __call__(self,operation,_authorization,_body):
                self.operation=operation;self.status=401
                return 401,{'error':'synthetic-response-body'}
        exchange=Exchange()
        profile={'kind':'gigachat','model':'GigaChat-3-Ultra','scope':'GIGACHAT_API_PERS',
            'stream':False,'max_output_tokens':8,'request_timeout_secs':5,'idle_timeout_secs':5}
        with patch.object(host,'HttpsExchange',return_value=exchange):
            gateway=host.Gateway(profile,{'max_steps':1,'max_requests':1},time.monotonic()+5,'Basic synthetic-key')
            status,_value=gateway.relay({'model':'GigaChat-3-Ultra','max_tokens':8,'stream':False,'messages':[]})
        self.assertEqual(status,502)
        receipt=gateway.receipts[0]
        self.assertEqual(receipt['failure'],'oauth response')
        self.assertEqual(receipt['upstream_operation'],'oauth')
        self.assertEqual(receipt['http_status'],401)
        self.assertEqual(receipt['failure_type'],'RemoteDisconnected')
        self.assertNotIn('synthetic-response-body',json.dumps(receipt))

    def receipt_phase(self,events,state,resume_id=None):
        import host
        from unittest.mock import patch
        class Channel:
            def __init__(self,frames):self.frames=list(frames)
            def receive(self,timeout=None):return self.frames.pop(0)
            def send(self,_value):pass
            def close(self):pass
        class FakeDocker:
            uid=10001
            def create(self,*_args,**_kwargs):return 'agent'
            def start(self,_name,_bootstrap,_deadline):
                raw=b''.join(json.dumps(event).encode()+b'\n' for event in events)
                return Channel([{'type':'agent_log','channel':'stdout','data':base64.b64encode(raw).decode()},
                    {'type':'agent_done','exit_code':0}])
            def remove(self,*_args):pass
        class Pump:
            def __init__(self,_gateway):pass
            def deliver(self,_channel):pass
            def close(self):pass
        invocation={'binary':'/unused/rcode','effective_profile':{'kind':'local','model':'fixture','local':{}}}
        item={'case':{'max_steps':1},'fixture':'/unused/fixture','task':'fixture'}
        with patch.object(host,'RequestPump',Pump):
            return host.agent_phase(FakeDocker(),invocation,item,{},object(),time.monotonic()+5,
                resume_id=resume_id,resume_prompt='continue' if resume_id else None,policy_state=state)

    def test_agent_phase_observes_start_and_every_result(self):
        from evals.policy import required_skills_met
        state={'skills':{},'violations':set()};skill='superpowers:test-driven-development'
        self.receipt_phase([
            {'type':'tool_start','id':'shell','name':'run_command','arguments':'{"command":"git status"}'},
            {'type':'tool_result','id':'shell','name':'run_command','is_error':True},
            {'type':'tool_start','id':'call-1','name':'load_skill','arguments':json.dumps({'name':skill})},
            {'type':'tool_result','id':'call-1','name':'load_skill','is_error':False}],state)
        self.assertEqual(state['violations'],{'git'})
        self.assertTrue(required_skills_met(state,[skill]))

    def test_agent_phase_preserves_policy_state_across_resume(self):
        from evals.policy import required_skills_met
        state={'skills':{},'violations':set()};skill='superpowers:test-driven-development'
        self.receipt_phase([{'type':'tool_start','id':'call-1','name':'load_skill',
            'arguments':json.dumps({'name':skill})}],state)
        self.assertFalse(required_skills_met(state,[skill]))
        self.receipt_phase([{'type':'tool_result','id':'call-1','name':'load_skill','is_error':False}],
            state,resume_id='00000000-0000-0000-0000-000000000001')
        self.assertTrue(required_skills_met(state,[skill]))

    def test_run_case_uses_persistent_snapshot_for_observer_when_enabled(self):
        import host
        from unittest.mock import patch
        observation={'type':'observation','exit_code':0,'signal':None,'prepare_failed':False,
            'truncated':False,'timed_out':False,'cancelled':False,'leader_reaped':True,
            'pipes_complete':True,'stdout':base64.b64encode(b'true\n').decode()}
        class Channel:
            def __init__(self,frames):self.frames=frames
            def receive(self,timeout=None):return self.frames.pop(0)
            def close(self):pass
        class FakeDocker:
            uid=10001;cleanup_deadline=None
            def __init__(self):self.binds=[];self.channels=[[{'type':'storage_ready'}],[observation]]
            def volume(self,_size,_deadline):return 'volume'
            def create(self,binds,_deadline,**_kwargs):self.binds.append(binds);return 'container'
            def start(self,*_args,**_kwargs):return Channel(self.channels.pop(0))
            def archive(self,*_args):return b''
            def remove(self,*_args):pass
            def cleanup(self,*_args):pass
        done={'type':'agent_done','exit_code':0,'signal':None,'leader_reaped':True,'pipes_complete':True,
            'timed_out':False,'cancelled':False,'truncated':False,'forced':False}
        def phase(_docker,_invocation,_item,_volumes,gateway,_deadline,**_kwargs):
            gateway.generations=1;gateway.attempts=1
            gateway.receipts=[{'generation':1,'status':'received','http_status':200,'usage':None}]
            return {'done':done,'agent_reported_tool_successes':{},'session_id':None,'sentinel':False,'cancel_sent':False}
        case={'id':'persistent','language':'python','category':'fixture','timeout_secs':30,'max_steps':2,'max_requests':2}
        check={'id':'contract','argv':['true'],'stdin':'','timeout_secs':1,'expected_exit':0,'expected_json':True}
        item={'case':case,'sha256':'f'*64,'fixture':'/unused/fixture','task':'fixture','oracle':{'prepare':[],'checks':[check]}}
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);snapshots=root/'snapshots';snapshots.mkdir(mode=0o700)
            temporary=root/'temporary';temporary.mkdir(mode=0o700)
            invocation={'effective_profile':{'kind':'local','model':'fixture','base_url':'http://127.0.0.1:9/v1','local':{}},'snapshots':str(snapshots)}
            docker=FakeDocker()
            with patch.object(host,'agent_phase',phase),patch.object(host,'extract_frozen',return_value='f'*64):
                result=host.run_case(docker,invocation,item,temporary)
            expected=snapshots/'persistent'
            self.assertEqual(result['status'],'passed')
            self.assertTrue(expected.is_dir())
            self.assertEqual(docker.binds[1],{'/snapshot':expected})
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);temporary=root/'temporary';temporary.mkdir(mode=0o700)
            invocation={'effective_profile':{'kind':'local','model':'fixture','base_url':'http://127.0.0.1:9/v1','local':{}}}
            docker=FakeDocker()
            with patch.object(host,'agent_phase',phase),patch.object(host,'extract_frozen',return_value='f'*64):
                result=host.run_case(docker,invocation,item,temporary)
            self.assertEqual(result['status'],'passed')
            self.assertEqual(docker.binds[1],{'/snapshot':temporary/'persistent'})
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);snapshots=root/'snapshots';snapshots.mkdir(mode=0o700)
            temporary=root/'temporary';temporary.mkdir(mode=0o700)
            invocation={'effective_profile':{'kind':'local','model':'fixture','base_url':'http://127.0.0.1:9/v1','local':{}},'snapshots':str(snapshots)}
            docker=FakeDocker()
            with patch.object(host,'agent_phase',phase),patch.object(host,'extract_frozen',side_effect=OSError('synthetic write failure')):
                result=host.run_case(docker,invocation,item,temporary)
            self.assertEqual(result['status'],'blocked')
            self.assertIsNone(result['snapshot_sha256'])
            self.assertEqual(result['cleanup'],'confirmed_absent')
            self.assertFalse((temporary/'persistent').exists())

    def test_run_case_reports_policy_fields_and_exact_failure_reasons(self):
        import host
        from unittest.mock import patch
        from evals.policy import observe_tool_start,observe_tool_result
        skill='superpowers:test-driven-development'
        class Channel:
            def receive(self,timeout=None):return {'type':'storage_ready'}
            def close(self):pass
        class FakeDocker:
            uid=10001;cleanup_deadline=None
            def volume(self,_size,_deadline):return 'volume'
            def create(self,*_args,**_kwargs):return 'container'
            def start(self,*_args,**_kwargs):return Channel()
            def archive(self,*_args):return b''
            def remove(self,*_args):pass
            def cleanup(self,*_args):pass
        done={'type':'agent_done','exit_code':0,'signal':None,'leader_reaped':True,'pipes_complete':True,
            'timed_out':False,'cancelled':False,'truncated':False,'forced':False}
        def run(policy):
            def phase(_docker,_invocation,_item,_volumes,gateway,_deadline,**kwargs):
                gateway.generations=1;gateway.attempts=1
                gateway.receipts=[{'generation':1,'status':'received','http_status':200,'usage':None}]
                state=kwargs['policy_state']
                if policy=='violation':
                    observe_tool_start(state,{'id':'shell','name':'run_command','arguments':'{"command":"git status synthetic-receipt-secret"}'})
                    observe_tool_result(state,{'id':'shell','name':'run_command','is_error':True})
                if policy in ('skill','replay'):
                    observe_tool_start(state,{'id':'call-1','name':'load_skill','arguments':json.dumps({'name':skill})})
                    observe_tool_result(state,{'id':'call-1','name':'load_skill','is_error':False})
                if policy=='replay':
                    observe_tool_start(state,{'id':'call-1','name':'load_skill','arguments':json.dumps({'name':'superpowers:using-superpowers'})})
                agent_done=done
                if policy=='timeout':
                    agent_done={**done,'exit_code':None,'signal':15,'timed_out':True}
                    gateway.receipts=[{'generation':1,'status':'failed_or_incomplete','usage':None}]
                return {'done':agent_done,'agent_reported_tool_successes':{},'session_id':None,'sentinel':False,'cancel_sent':False}
            required=None if policy=='timeout' else ('superpowers:using-superpowers' if policy=='replay' else skill)
            case={'id':'policy-'+policy,'language':'python','category':'fixture','timeout_secs':30,
                'max_steps':2,'max_requests':2,'require_skills':[] if required is None else [required]}
            item={'case':case,'sha256':'f'*64,'fixture':'/unused/fixture','task':'fixture','oracle':{'prepare':[],'checks':[]}}
            invocation={'effective_profile':{'kind':'local','model':'fixture','base_url':'http://127.0.0.1:9/v1','local':{}}}
            with tempfile.TemporaryDirectory() as temp,patch.object(host,'agent_phase',phase),patch.object(host,'extract_frozen',return_value='f'*64):
                return host.run_case(FakeDocker(),invocation,item,Path(temp))
        violation=run('violation')
        self.assertEqual(violation['status'],'failed')
        self.assertEqual(violation['reason'],'formal task constraints violated')
        self.assertEqual(violation['formal_violations'],['git'])
        self.assertNotIn('synthetic-receipt-secret',json.dumps(violation))
        missing=run('missing')
        self.assertEqual(missing['status'],'failed')
        self.assertEqual(missing['reason'],'required skills were not observed')
        self.assertFalse(missing['required_skills_observed'])
        replay=run('replay')
        self.assertEqual(replay['status'],'failed')
        self.assertEqual(replay['reason'],'required skills were not observed')
        self.assertFalse(replay['required_skills_observed'])
        passed=run('skill')
        self.assertEqual(passed['status'],'passed')
        self.assertEqual(passed['required_skills'],[skill])
        self.assertTrue(passed['required_skills_observed'])
        self.assertEqual(passed['formal_violations'],[])
        timeout=run('timeout')
        self.assertEqual(timeout['status'],'failed',timeout)
        self.assertEqual(timeout['reason'],'agent time budget exhausted; verification incomplete')


@unittest.skipUnless(all(os.environ.get(name) for name in ('RCODE_EVAL_DOCKER','RCODE_EVAL_SOCKET','RCODE_EVAL_IMAGE')),
    'RCODE_EVAL_DOCKER, RCODE_EVAL_SOCKET and RCODE_EVAL_IMAGE are required for opt-in Docker host tests')
class HostTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        config=self.root/'docker-config';config.mkdir(mode=0o700)
        self.docker=Docker(os.environ['RCODE_EVAL_DOCKER'],os.environ['RCODE_EVAL_SOCKET'],config,os.environ['RCODE_EVAL_IMAGE'],ROOT/'evals/runtime')
    def tearDown(self):
        try:self.docker.cleanup(time.monotonic()+15)
        finally:self.temp.cleanup()
    def test_actual_runtime_has_isolation_and_independently_confirmed_cleanup(self):
        deadline=time.monotonic()+20
        name=self.docker.create({},deadline)
        channel=self.docker.start(name,{'mode':'probe','uid':10001,'gid':10001,'timeout_secs':5},deadline)
        try:frame=channel.receive()
        finally:channel.close()
        self.assertEqual(frame['type'],'probe_result')
        self.assertTrue(frame['root_stdout_denied'] and frame['capabilities_empty'] and frame['external_network_denied'])
        self.docker.remove(name,deadline)
        self.assertFalse(self.docker.active)
    def test_agent_volume_survives_removal_and_exporter_is_removed_before_adjudication(self):
        fixture=self.root/'fixture';fixture.mkdir(mode=0o755);(fixture/'input.txt').write_text('original')
        deadline=time.monotonic()+30
        volumes={dst:self.docker.volume(size,deadline) for dst,size in [('/workspace',128),('/agent-home',64)]}
        keeper=self.docker.create({},deadline,volumes=volumes,volumes_readonly=True)
        storage=self.docker.start(keeper,{'mode':'storage','uid':10001,'gid':10001,'timeout_secs':25},deadline)
        self.assertEqual(storage.receive(),{'type':'storage_ready'})
        name=self.docker.create({'/fixture':fixture},deadline,volumes=volumes)
        bootstrap={'mode':'agent','uid':10001,'gid':10001,'timeout_secs':15,'hold':True,'seed_project':True,'model':'fixture','profile_config':None,
            'argv':['python3','-I','-S','-c',"import os;from pathlib import Path;Path('result.txt').write_text('changed');print(os.statvfs('/workspace').f_blocks*os.statvfs('/workspace').f_frsize)"]}
        channel=self.docker.start(name,bootstrap,deadline)
        try:
            while True:
                done=channel.receive()
                if done['type']=='agent_done':break
            self.assertEqual(done['exit_code'],0)
            with self.assertRaises(Failure):self.docker.archive(storage,'workspace')
            self.docker.remove(name,deadline)
            raw=self.docker.archive(storage,'workspace')
            self.docker.remove(keeper,deadline)
            self.docker.cleanup(deadline)
            self.assertFalse(self.docker.active or self.docker.volumes)
            dest=self.root/'snapshot';dest.mkdir()
            digest=extract_frozen(raw,dest)
            self.assertEqual(len(digest),64)
            self.assertEqual((dest/'result.txt').read_text(),'changed')
            self.assertEqual((fixture/'input.txt').read_text(),'original')
        finally:channel.close();storage.close()
    def test_cancellation_sends_a_real_signal_before_new_container_uses_case_state(self):
        deadline=time.monotonic()+25
        volumes={dst:self.docker.volume(size,deadline) for dst,size in [('/workspace',128),('/agent-home',64)]}
        keeper=self.docker.create({},deadline,volumes=volumes,volumes_readonly=True)
        storage=self.docker.start(keeper,{'mode':'storage','uid':10001,'gid':10001,'timeout_secs':20},deadline)
        self.assertEqual(storage.receive(),{'type':'storage_ready'})
        name=self.docker.create({},deadline,volumes=volumes)
        script="from pathlib import Path;import time;Path('once.txt').write_text('x');Path('ready').write_text('1');time.sleep(30)"
        channel=self.docker.start(name,{'mode':'agent','uid':10001,'gid':10001,'timeout_secs':15,'model':'fixture','hold':True,'sentinel':'ready','argv':['python3','-I','-S','-c',script],'profile_config':None},deadline)
        try:
            while True:
                value=channel.receive()
                if value['type']=='sentinel':channel.send({'type':'cancel'})
                if value['type']=='agent_done':break
            self.assertTrue(value['cancelled'] and value['cancel_signal_sent'])
            self.assertFalse(value['forced'])
            self.assertTrue(value['leader_reaped'] and value['pipes_complete'])
            self.docker.remove(name,deadline)
            second=self.docker.create({},deadline,volumes=volumes)
            resumed=self.docker.start(second,{'mode':'agent','uid':10001,'gid':10001,'timeout_secs':8,'model':'fixture','hold':True,'argv':['python3','-I','-S','-c',"from pathlib import Path;assert Path('once.txt').read_text()=='x'"],'profile_config':None},deadline)
            try:
                while True:
                    value=resumed.receive()
                    if value['type']=='agent_done':break
                self.assertEqual(value['exit_code'],0)
            finally:self.docker.remove(second,deadline);resumed.close()
        finally:channel.close();self.docker.remove(keeper,deadline);storage.close()
    def test_observer_build_copy_is_writable_but_frozen_source_is_not_changed(self):
        snapshot=self.root/'snapshot';snapshot.mkdir(mode=0o755);source=snapshot/'value.txt';source.write_text('frozen');source.chmod(0o444);snapshot.chmod(0o555)
        deadline=time.monotonic()+15;name=self.docker.create({'/snapshot':snapshot},deadline)
        channel=self.docker.start(name,{'mode':'observe','uid':10001,'gid':10001,'timeout_secs':8,
            'prepare':[{'argv':['python3','-I','-S','-c',"from pathlib import Path;Path('value.txt').write_text('build');Path('generated').mkdir()"],'timeout_secs':3}],
            'check':{'argv':['python3','-I','-S','-c',"print(open('value.txt').read())"],'timeout_secs':3}},deadline)
        try:obs=channel.receive()
        finally:self.docker.remove(name,deadline);channel.close()
        self.assertFalse(obs['prepare_failed'])
        self.assertEqual(base64.b64decode(obs['stdout']),b'build\n')
        self.assertEqual(source.read_text(),'frozen')
    def test_http_header_drip_is_cut_off_at_absolute_deadline(self):
        import socketserver,threading
        from host import Gateway
        class Drip(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.recv(65536)
                try:
                    for chunk in [b'HTTP/1.1 200 OK\r\n']+[b'X-Header: x\r\n']*20:
                        self.request.sendall(chunk);time.sleep(.08)
                    self.request.sendall(b'Content-Length: 2\r\n\r\n{}')
                except OSError:pass
        server=socketserver.ThreadingTCPServer(('127.0.0.1',0),Drip);server.daemon_threads=True
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            profile={'base_url':'http://127.0.0.1:'+str(server.server_address[1])+'/v1','model':'fixture','max_output_tokens':8,'request_timeout_secs':5,'idle_timeout_secs':5}
            start=time.monotonic();gateway=Gateway(profile,{'max_steps':1,'max_requests':2},start+.3)
            code,_=gateway.relay({'model':'fixture','max_tokens':8,'stream':False})
            elapsed=time.monotonic()-start
            self.assertEqual(code,502)
            self.assertLess(elapsed,1,'header drip exceeded absolute deadline')
            self.assertIsNone(gateway.receipts[0]['usage'])
        finally:server.shutdown();server.server_close();thread.join()
    def test_request_pump_remains_responsive_while_endpoint_is_waiting(self):
        import http.server,threading
        from host import Gateway,RequestPump
        entered=threading.Event();release=threading.Event()
        class Slow(http.server.BaseHTTPRequestHandler):
            def log_message(self,*_args):pass
            def do_POST(self):
                entered.set();release.wait(3)
                try:self.send_response(200);self.end_headers();self.wfile.write(b'{}')
                except OSError:pass
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Slow);server.daemon_threads=True
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        pump=None
        try:
            profile={'base_url':'http://127.0.0.1:'+str(server.server_address[1])+'/v1','model':'fixture','max_output_tokens':8,'request_timeout_secs':5,'idle_timeout_secs':5}
            gateway=Gateway(profile,{'max_steps':2,'max_requests':2},time.monotonic()+5);pump=RequestPump(gateway)
            pump.submit(1,{'model':'fixture','max_tokens':8,'stream':False})
            self.assertTrue(entered.wait(1))
            start=time.monotonic();pump.cancel();pump.close()
            self.assertLess(time.monotonic()-start,1)
            self.assertEqual(gateway.generations,1)
            self.assertEqual(gateway.receipts[0]['status'],'cancelled_by_case')
            self.assertIsNone(gateway.receipts[0]['usage'])
        finally:
            if pump:pump.close()
            release.set();server.shutdown();server.server_close();thread.join()
    def test_ambiguous_create_is_reconciled_by_registered_name_and_owner(self):
        checked=self.docker.checked
        def lost_reply(args,deadline,limit=65536):
            output=checked(args,deadline,limit)
            if args[0]=='create':raise Failure('simulated lost create reply')
            return output
        self.docker.checked=lost_reply
        with self.assertRaises(Failure):self.docker.create({},time.monotonic()+10)
        self.assertEqual(len(self.docker.active),1)
        self.assertIsNone(next(iter(self.docker.active.values()))['id'])
        self.docker.checked=checked
        self.docker.cleanup(time.monotonic()+10)
        self.assertFalse(self.docker.active)
    def test_wrong_owner_or_unavailable_absence_probe_cannot_authorize_removal(self):
        deadline=time.monotonic()+15;name=self.docker.create({},deadline)
        owner=self.docker.active[name]['owner'];self.docker.active[name]['owner']='different'
        with self.assertRaises(Failure):self.docker.remove(name,deadline)
        self.assertIn(name,self.docker.active)
        self.assertEqual(self.docker.inspect(self.docker.active[name]['id'],deadline)['Config']['Labels']['rcode.eval.owner'],owner)
        self.docker.active[name]['owner']=owner
        checked=self.docker.checked
        def unavailable(args,deadline,limit=65536):
            if args[0]=='ps':raise Failure('simulated unavailable daemon observation')
            return checked(args,deadline,limit)
        self.docker.checked=unavailable
        try:
            with self.assertRaises(Failure):self.docker.remove(name,deadline)
            self.assertIn(name,self.docker.active)
        finally:self.docker.checked=checked
    def test_persistent_snapshot_survives_case_and_matches_oracle(self):
        import host
        from unittest.mock import patch
        fixture=self.root/'fixture';fixture.mkdir(mode=0o755);(fixture/'value.txt').write_text('original')
        snapshots=self.root/'snapshots';snapshots.mkdir(mode=0o700)
        temporary=self.root/'temporary';temporary.mkdir(mode=0o700)
        profile={'base_url':'http://127.0.0.1:9/v1','model':'fixture','max_output_tokens':8,'request_timeout_secs':5,'idle_timeout_secs':5}
        item={'case':{'id':'persistent','language':'python','category':'fixture','timeout_secs':30,'max_steps':2,'max_requests':2},'sha256':'f'*64,'fixture':str(fixture),'task':'fixture',
            'oracle':{'prepare':[],'checks':[{'id':'value','argv':['python3','-I','-S','-c',"print(open('value.txt').read())"],'stdin':'','timeout_secs':3,'expected_exit':0,'expected_stdout':'changed\n'}]}}
        def phase(docker,_invocation,_item,volumes,gateway,deadline,**_kwargs):
            name=docker.create({'/fixture':fixture},deadline,volumes=volumes)
            channel=docker.start(name,{'mode':'agent','uid':10001,'gid':10001,'timeout_secs':10,'seed_project':True,'hold':True,'model':'fixture','profile_config':None,
                'argv':['python3','-I','-S','-c',"from pathlib import Path;Path('value.txt').write_text('changed')"]},deadline)
            try:
                while True:
                    done=channel.receive()
                    if done['type']=='agent_done':break
                docker.remove(name,deadline)
                gateway.generations=1;gateway.attempts=1
                gateway.receipts=[{'generation':1,'status':'received','http_status':200,'usage':None}]
                return {'done':done,'agent_reported_tool_successes':{},'session_id':None,'sentinel':False,'cancel_sent':False}
            finally:channel.close()
        with patch.object(host,'agent_phase',phase):
            result=host.run_case(self.docker,{'effective_profile':profile,'snapshots':str(snapshots)},item,temporary)
        self.assertEqual(result['status'],'passed')
        self.assertEqual((snapshots/'persistent/value.txt').read_text(),'changed')
        self.assertEqual((fixture/'value.txt').read_text(),'original')
        self.assertEqual(len(result['snapshot_sha256']),64)
        self.assertFalse(self.docker.active or self.docker.volumes)

    def test_real_sigint_during_cleanup_preserves_current_case_observations(self):
        import host,signal
        from unittest.mock import patch
        fixture=self.root/'fixture';fixture.mkdir(mode=0o755);(fixture/'value.txt').write_text('ok')
        profile={'base_url':'http://127.0.0.1:9/v1','model':'fixture','max_output_tokens':8,'request_timeout_secs':5,'idle_timeout_secs':5}
        item={'case':{'id':'cleanup-cancel','language':'python','category':'fixture','timeout_secs':30,'max_steps':2,'max_requests':2},'sha256':'f'*64,'fixture':str(fixture),'task':'fixture',
            'oracle':{'prepare':[],'checks':[{'id':'value','argv':['python3','-I','-S','-c',"print(open('value.txt').read())"],'stdin':'','timeout_secs':3,'expected_exit':0,'expected_stdout':'ok\n'}]}}
        def phase(docker,invocation,item,volumes,gateway,deadline,**_kwargs):
            name=docker.create({'/fixture':fixture},deadline,volumes=volumes)
            channel=docker.start(name,{'mode':'agent','uid':10001,'gid':10001,'timeout_secs':10,'seed_project':True,'hold':True,'model':'fixture','profile_config':None,'argv':['python3','-I','-S','-c','pass']},deadline)
            try:
                while True:
                    done=channel.receive()
                    if done['type']=='agent_done':break
                docker.remove(name,deadline)
                return {'done':done,'agent_reported_tool_successes':{},'session_id':None,'sentinel':False,'cancel_sent':False}
            finally:channel.close()
        cleanup=self.docker.cleanup;calls=0
        def interrupted_cleanup(deadline):
            nonlocal calls
            calls+=1
            if calls==2:os.kill(os.getpid(),signal.SIGINT)
            return cleanup(deadline)
        previous=signal.signal(signal.SIGINT,host.request_cancel);host.CONTROL.cancelled=False
        self.docker.cancel_requested=lambda:host.CONTROL.cancelled
        try:
            with patch.object(host,'agent_phase',phase),patch.object(self.docker,'cleanup',interrupted_cleanup):
                result=host.run_case(self.docker,{'effective_profile':profile},item,self.root)
            self.assertEqual(len(result['checks']),1)
            self.assertTrue(result['checks'][0]['passed'])
            self.assertTrue(result['operator_cancelled'])
            self.assertEqual(result['cleanup'],'confirmed_absent')
            self.assertEqual(result['requests'],[])
            self.assertIsNotNone(result['seconds'])
            self.assertNotEqual(result['status'],'passed','fixture without inference must not count as live inference')
        finally:host.CONTROL.cancelled=False;signal.signal(signal.SIGINT,previous)
    def test_final_completion_with_null_tool_calls_is_relayed_without_retry(self):
        import http.server,threading
        from host import Gateway
        value={'id':'fixture','object':'chat.completion','model':'fixture','choices':[{'index':0,'message':{'role':'assistant','content':'done','tool_calls':None},'finish_reason':'stop'}],'usage':{'prompt_tokens':3,'completion_tokens':1,'total_tokens':4}}
        raw=json.dumps(value).encode()
        class Final(http.server.BaseHTTPRequestHandler):
            def log_message(self,*_args):pass
            def do_POST(self):
                self.rfile.read(int(self.headers['Content-Length']))
                self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Final);server.daemon_threads=True
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            profile={'base_url':'http://127.0.0.1:'+str(server.server_address[1])+'/v1','model':'fixture','max_output_tokens':8,'request_timeout_secs':5,'idle_timeout_secs':5}
            gateway=Gateway(profile,{'max_steps':2,'max_requests':2},time.monotonic()+5)
            status,response=gateway.relay({'model':'fixture','max_tokens':8,'stream':False})
            self.assertEqual((status,response),(200,value))
            self.assertEqual(gateway.generations,1)
            self.assertEqual(gateway.receipts[0]['status'],'received')
            self.assertEqual(gateway.receipts[0]['requested_tool_names'],{})
            self.assertEqual(gateway.receipts[0]['usage']['total_tokens'],4)
        finally:server.shutdown();server.server_close();thread.join()
    def test_ready_skipped_tests_and_forged_oracles_do_not_pass_hidden_checks(self):
        import host
        from unittest.mock import patch
        for attack in ['ready','skip-tests','forge-oracle']:
            with self.subTest(attack=attack):
                case_root=self.root/attack;case_root.mkdir()
                fixture=case_root/'fixture';fixture.mkdir(mode=0o755)
                (fixture/'solution.py').write_text('def add(a,b): return a-b\n')
                (fixture/'test_solution.py').write_text('raise AssertionError("failing project test")\n')
                host_oracle=case_root/'host-oracle.json';host_oracle.write_text('protected-canary')
                output_canary=case_root/'host-output.json';output_canary.write_text('protected-output')
                script='print("ready")'
                if attack=='skip-tests':script="from pathlib import Path;Path('test_solution.py').unlink();print('all project tests skipped, ready')"
                if attack=='forge-oracle':script="import os,json;from pathlib import Path;Path('oracle.json').write_text('{\"expected_json\":-1}');print(json.dumps({'secret_seen':any(k in os.environ for k in ['OPENAI_API_KEY','TAVILY_API_KEY','RCODE_EVAL_OUTPUT_SENTINEL']),'host_oracle_seen':Path("+repr(str(host_oracle))+").exists(),'host_output_seen':Path("+repr(str(output_canary))+").exists()}))"
                observations=[]
                def phase(docker,invocation,item,volumes,gateway,deadline,**_kwargs):
                    name=docker.create({'/fixture':fixture},deadline,volumes=volumes)
                    channel=docker.start(name,{'mode':'agent','uid':10001,'gid':10001,'timeout_secs':10,'seed_project':True,'hold':True,'model':'fixture','profile_config':None,'argv':['python3','-I','-S','-c',script]},deadline)
                    try:
                        while True:
                            frame=channel.receive()
                            if frame['type']=='agent_log' and frame['channel']=='stdout':observations.append(base64.b64decode(frame['data']))
                            if frame['type']=='agent_done':break
                        docker.remove(name,deadline)
                        # Fixture injection exercises the oracle gate independently
                        # of the no-inference gate; this is not a model/live run.
                        gateway.generations=1;gateway.attempts=1;gateway.receipts=[{'status':'received','http_status':200,'usage':None,'fixture_no_inference':True}]
                        return {'done':frame,'agent_reported_tool_successes':{},'session_id':None,'sentinel':False,'cancel_sent':False}
                    finally:channel.close()
                item={'case':{'id':'adversarial-'+attack,'language':'python','category':'fixture','timeout_secs':30,'max_steps':2,'max_requests':2},'sha256':'f'*64,'fixture':str(fixture),'task':'fixture','oracle':{'prepare':[],'checks':[{'id':'hidden-addition','argv':['python3','-I','-S','-c',"import sys;sys.path.insert(0,'.');from solution import add;print(add(2,3))"],'stdin':'','timeout_secs':3,'expected_exit':0,'expected_stdout':'5\n'}]}}
                profile={'base_url':'http://127.0.0.1:9/v1','model':'fixture','max_output_tokens':8,'request_timeout_secs':5,'idle_timeout_secs':5}
                with patch.object(host,'agent_phase',phase),patch.dict(os.environ,{'OPENAI_API_KEY':'synthetic-canary','TAVILY_API_KEY':'synthetic-canary','RCODE_EVAL_OUTPUT_SENTINEL':'synthetic-canary'}):
                    result=host.run_case(self.docker,{'effective_profile':profile},item,case_root)
                self.assertEqual(result['status'],'failed')
                self.assertEqual(result['cleanup'],'confirmed_absent')
                self.assertEqual(len(result['checks']),1)
                self.assertFalse(result['checks'][0]['passed'])
                self.assertEqual(host_oracle.read_text(),'protected-canary')
                self.assertEqual(output_canary.read_text(),'protected-output')
                if attack=='forge-oracle':self.assertEqual(json.loads(b''.join(observations)),{'secret_seen':False,'host_oracle_seen':False,'host_output_seen':False})
    def test_host_does_not_accept_json_bool_as_numeric_result(self):
        from host import json_equal
        self.assertFalse(json_equal(True,1))
        self.assertFalse(json_equal(1,1.0))
        self.assertTrue(json_equal({'a':[1,None]},{'a':[1,None]}))

if __name__=='__main__':unittest.main()
