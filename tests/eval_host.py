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
sys.path[:0]=[str(ROOT/'evals'),str(ROOT/'evals/runtime')]
from host_docker import Docker,Failure
from host_snapshot import extract_frozen

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
