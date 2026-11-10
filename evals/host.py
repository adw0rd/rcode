"""Trusted opt-in eval host. Only Docker CLI is executed on the host.

Expectations live here and never enter a container bootstrap or mount.
"""
import base64
import hashlib
import http.client
import json
import os
import queue
from pathlib import Path
import signal
import ssl
import socket
import sys
import tempfile
import threading
import time
import urllib.parse

from runtime import strict
from host_docker import Docker,Failure
from host_provider import GigaChatUpstream,HttpsExchange,giga_request,openai_response
from host_snapshot import extract_frozen
from policy import observe_tool_start,observe_tool_result,required_skills_met

PROTOCOL=2

class Control:
    cancelled=False

CONTROL=Control()

def request_cancel(_signum=None,_frame=None):
    CONTROL.cancelled=True

class AssessmentFailure(Failure):pass

def json_equal(a,b):
    if type(a) is not type(b):return False
    if isinstance(a,dict):return a.keys()==b.keys() and all(json_equal(a[k],b[k]) for k in a)
    if isinstance(a,list):return len(a)==len(b) and all(json_equal(x,y) for x,y in zip(a,b))
    return a==b

def observe_matches(observation,check):
    good=(observation.get('type')=='observation' and observation.get('exit_code')==check['expected_exit']
        and observation.get('signal') is None and observation.get('prepare_failed') is False
        and observation.get('truncated') is False and observation.get('timed_out') is False
        and observation.get('cancelled') is False and observation.get('leader_reaped') is True
        and observation.get('pipes_complete') is True)
    raw=base64.b64decode(observation['stdout'],validate=True)
    if len(raw)>65536:raise Failure('observation output limit')
    if 'expected_json' in check:
        try:equal=json_equal(strict(raw,65536),check['expected_json'])
        except (ValueError,RecursionError):equal=False
    else:equal=raw==check['expected_stdout'].encode()
    return good and equal

def probe_command(command):
    # Construct a new transport object; never serialize-then-delete expected.
    return {'argv':command['argv'],'stdin':command['stdin'],'timeout_secs':command['timeout_secs']}

class Gateway:
    def __init__(self,profile,case,deadline,credential=None):
        self.profile=profile;self.case=case;self.deadline=deadline;self.attempts=0;self.generations=0;self.receipts=[];self.function_states={}
        self.gigachat=profile.get('kind')=='gigachat'
        if self.gigachat:
            exchange=HttpsExchange(deadline,profile['request_timeout_secs'],profile['idle_timeout_secs'],strict)
            exchange.cancelled=lambda:CONTROL.cancelled
            self.upstream=GigaChatUpstream(credential,profile.get('scope','GIGACHAT_API_PERS'),exchange)
        else:
            self.url=urllib.parse.urlsplit(profile['base_url'])
            if self.url.scheme not in ('http','https') or self.url.username or self.url.password or self.url.query or self.url.fragment:raise Failure('endpoint shape')
            if self.url.hostname not in ('127.0.0.1','::1','localhost'):raise Failure('local literal loopback endpoint required')
    def sensitive(self,value):
        if not self.gigachat:return False
        secrets={secret for secret in self.upstream.secrets if secret}
        def walk(item):
            if isinstance(item,dict):return any(walk(key) or walk(nested) for key,nested in item.items())
            if isinstance(item,list):return any(walk(nested) for nested in item)
            if isinstance(item,str):return any(secret in item for secret in secrets)
            return False
        return walk(value)
    def relay(self,body,cancelled=None):
        self.attempts+=1
        if self.attempts>self.case['max_requests']:return 429,{'error':{'message':'eval request limit'}}
        if not isinstance(body,dict) or body.get('model')!=self.profile['model'] or body.get('stream') is not False:return 400,{'error':{'message':'eval model/transport mismatch'}}
        tokens=body.get('max_tokens')
        if type(tokens) is not int or not 1<=tokens<=self.profile['max_output_tokens']:return 400,{'error':{'message':'eval token bound'}}
        if self.generations>=self.case['max_steps']:return 429,{'error':{'message':'eval generation limit'}}
        self.generations+=1
        record={'generation':self.generations,'status':'unknown','usage':None,'seconds':None}
        self.receipts.append(record);start=time.monotonic();connection=None;watcher=None;transport=[];stop_watch=threading.Event()
        try:
            if self.gigachat:
                native='function_call' in body or 'functions' in body
                if native:status,value=self.upstream.chat(body,cancelled)
                else:status,value=self.upstream.chat(giga_request(body,self.function_states),cancelled)
                if self.sensitive(value):raise Failure('sensitive upstream payload')
                if not native:value=openai_response(value,self.function_states)
            else:
                remaining=self.deadline-time.monotonic()
                if remaining<=0:raise Failure('generation deadline')
                host='127.0.0.1' if self.url.hostname=='localhost' else self.url.hostname
                connection_class=http.client.HTTPSConnection if self.url.scheme=='https' else http.client.HTTPConnection
                # Connect/handshake has a short independent bound so cancellation
                # can join the exchange even before a transport becomes available.
                kwargs={'timeout':min(1,remaining,self.profile['request_timeout_secs'])}
                if self.url.scheme=='https':kwargs['context']=ssl.create_default_context()
                connection=connection_class(host,self.url.port or (443 if self.url.scheme=='https' else 80),**kwargs)
                # Socket timeouts alone do not bound a peer dripping header bytes.
                # Keep the actual transport reference even if HTTPConnection drops
                # its reference for a Connection: close response.
                exchange_deadline=min(self.deadline,start+self.profile['request_timeout_secs'])
                def abort():
                    if transport:
                        try:transport[0].shutdown(socket.SHUT_RDWR)
                        except OSError:pass
                        transport[0].close()
                def watch():
                    while not stop_watch.wait(.02):
                        if time.monotonic()>=exchange_deadline or (CONTROL.cancelled or (cancelled is not None and cancelled.is_set())):abort();return
                watcher=threading.Thread(target=watch,daemon=True);watcher.start()
                connection.connect();transport.append(connection.sock)
                if time.monotonic()>=exchange_deadline or (CONTROL.cancelled or (cancelled is not None and cancelled.is_set())):raise Failure('connect deadline/cancellation')
                connection.sock.settimeout(min(exchange_deadline-time.monotonic(),self.profile['request_timeout_secs']))
                payload=json.dumps(body,ensure_ascii=True,allow_nan=False,separators=(',',':')).encode()
                if len(payload)>2*1024*1024:raise Failure('request size')
                connection.request('POST',self.url.path.rstrip('/')+'/chat/completions',body=payload,headers={'Content-Type':'application/json','Accept':'application/json'})
                response=connection.getresponse();raw=bytearray()
                while True:
                    remaining=self.deadline-time.monotonic()
                    if remaining<=0:raise Failure('response deadline')
                    if connection.sock:connection.sock.settimeout(min(remaining,self.profile['idle_timeout_secs']))
                    chunk=response.read1(min(65536,4*1024*1024+1-len(raw)))
                    if not chunk:break
                    raw.extend(chunk)
                    if len(raw)>4*1024*1024:raise Failure('response size')
                if time.monotonic()>=exchange_deadline:raise Failure('response deadline')
                if CONTROL.cancelled or (cancelled is not None and cancelled.is_set()):raise Failure('response cancelled')
                value=strict(raw)
                if not isinstance(value,dict):raise Failure('response shape')
                # Never forward redirects, headers, cookies, or a second endpoint.
                if 300<=response.status<400:raise Failure('redirect refused')
                status=response.status
            usage=value.get('usage')
            if isinstance(usage,dict):
                record['usage']={k:v for k,v in usage.items() if k in ('prompt_tokens','completion_tokens','total_tokens') and type(v) is int and v>=0} or None
            record['status']='received';record['http_status']=status
            model=value.get('model')
            if self.gigachat:model=model if model==self.profile['model'] and len(model)<=1024 and not self.sensitive(model) else None
            else:model=model if isinstance(model,str) and len(model)<=1024 else None
            record['response_model']=model
            record['requested_tools']=sum(len(c.get('message',{}).get('tool_calls',[])) for c in value.get('choices',[]) if isinstance(c,dict) and isinstance(c.get('message'),dict) and isinstance(c['message'].get('tool_calls',[]),list))
            record['requested_tools']+=sum(1 for c in value.get('choices',[]) if isinstance(c,dict) and isinstance(c.get('message'),dict) and c['message'].get('function_call') is not None)
            names={}
            for choice in value.get('choices',[]):
                if not isinstance(choice,dict):continue
                message=choice.get('message',{}) if isinstance(choice.get('message'),dict) else {}
                calls=message.get('tool_calls',[])
                if calls is None:calls=[]
                if not isinstance(calls,list) or len(calls)>128:raise Failure('model tool call bound')
                native=message.get('function_call')
                native_name=native.get('name') if isinstance(native,dict) else None
                if isinstance(native_name,str) and 0<len(native_name)<=64 and native_name.isascii() and native_name.replace('_','').isalnum() and not self.sensitive(native_name):names[native_name]=names.get(native_name,0)+1
                for call in calls:
                    name=call.get('function',{}).get('name') if isinstance(call,dict) and isinstance(call.get('function'),dict) else None
                    if isinstance(name,str) and 0<len(name)<=64 and name.isascii() and name.replace('_','').isalnum() and not self.sensitive(name):names[name]=names.get(name,0)+1
            record['requested_tool_names']=names
            return status,value
        except (Failure,OSError,ValueError,http.client.HTTPException):
            record['status']='cancelled_by_case' if CONTROL.cancelled or (cancelled is not None and cancelled.is_set()) else 'failed_or_incomplete'
            return 502,{'error':{'message':'eval selected endpoint request failed or incomplete'}}
        finally:
            record['seconds']=round(time.monotonic()-start,3)
            if connection:connection.close()
            stop_watch.set()
            if watcher:watcher.join(timeout=1)

class RequestPump:
    """One upstream exchange at a time; Root control frames remain responsive."""
    def __init__(self,gateway):
        self.gateway=gateway;self.jobs=queue.Queue(maxsize=4);self.results=queue.Queue(maxsize=4);self.stop=threading.Event();self.ids=set();self.submitted=0;self.failed=threading.Event()
        def work():
            while not self.stop.is_set():
                try:identity,body=self.jobs.get(timeout=.05)
                except queue.Empty:continue
                try:
                    status,response=gateway.relay(body,self.stop)
                    if not self.stop.is_set():self.results.put_nowait((identity,status,response))
                except Exception:
                    self.failed.set();return
        self.worker=threading.Thread(target=work,daemon=True);self.worker.start()
    def submit(self,identity,body):
        if identity in self.ids or len(self.ids)>=128:raise Failure('Root request identity bound')
        self.ids.add(identity);self.submitted+=1
        try:self.jobs.put_nowait((identity,body))
        except queue.Full:raise Failure('Root request concurrency bound') from None
    def deliver(self,channel):
        if self.failed.is_set():raise Failure('upstream worker failed')
        while not self.stop.is_set():
            try:identity,status,body=self.results.get_nowait()
            except queue.Empty:return
            channel.send({'type':'response','id':identity,'status':status,'body':body})
    def cancel(self):self.stop.set()
    def close(self):
        self.cancel();self.worker.join(timeout=2)
        if self.worker.is_alive():raise Failure('upstream exchange did not stop')

def model_config(profile):
    if profile.get('kind')=='gigachat':
        effective={**profile,'base_url':'http://127.0.0.1:18080/v1',
            'auth_url':'http://127.0.0.1:18080/api/v2/oauth','ca_file':None,'stream':False}
        return {'version':1,'active':'gigachat','providers':{'gigachat':effective},
            'local':{'active':None,'profiles':{}}}
    effective=dict(profile);effective['base_url']='{base_url}'
    effective['local']={**(profile.get('local') or {}),'profile':'eval','key_required':False}
    return {'version':1,'active':'local','providers':{},'local':{'active':'eval','profiles':{'eval':effective}}}

def check_isolation(docker,deadline):
    name=docker.create({},deadline);channel=None
    try:
        channel=docker.start(name,{'mode':'probe','uid':docker.uid,'gid':docker.uid,'timeout_secs':5},deadline)
        frame=channel.receive()
        if frame.get('type')!='probe_result' or frame.get('uid')!=docker.uid or frame.get('gid')!=docker.uid or frame.get('groups')!=[]:raise Failure('isolation probe identity')
        for key in ['capabilities_empty','no_new_privileges','seccomp_active','root_stdout_denied','signal_probe_denied','external_network_denied']:
            if frame.get(key) is not True:raise Failure('isolation probe failed')
        return frame
    finally:
        try:docker.remove(name,deadline)
        finally:
            if channel:channel.close()

def agent_phase(docker,invocation,item,volumes,gateway,deadline,sentinel=None,resume_id=None,resume_prompt=None,policy_state=None):
    import uuid
    case=item['case'];channel=None;pump=None
    if policy_state is None:policy_state={'skills':{},'violations':set()}
    name=docker.create({'/fixture':Path(item['fixture']),'/agent/rcode':Path(invocation['binary'])},deadline,volumes=volumes)
    gigachat=invocation['effective_profile'].get('kind')=='gigachat'
    selection=['--provider','gigachat'] if gigachat else ['--profile','eval']
    argv=['/agent/rcode','-C','/workspace',*selection,'--json','--approval-mode','auto-edit','--allow-shell','--max-steps',str(case['max_steps'])]
    if resume_id:argv+=['--resume',resume_id]
    argv+=['exec',resume_prompt if resume_id else item['task']]
    root_timeout=max(1,min(600,int(deadline-time.monotonic())))
    agent_timeout=max(1,root_timeout-25)
    if sentinel:agent_timeout=min(agent_timeout,90)
    bootstrap={'mode':'agent','uid':docker.uid,'gid':docker.uid,'timeout_secs':root_timeout,'agent_timeout_secs':agent_timeout,
        'seed_project':not bool(resume_id),'hold':True,'model':invocation['effective_profile']['model'],
        'profile_config':model_config(invocation['effective_profile']),'argv':argv}
    if case.get('require_skills'):
        bootstrap['skills_config']={'version':1,'linked':{'superpowers':{'path':'/workspace/skill-sources/superpowers'}}}
    if gigachat:bootstrap['profile_credential']='eval-placeholder-key'
    if sentinel:bootstrap['sentinel']=sentinel
    logs=hashlib.sha256();log_bytes=0;pending=bytearray();session_id=None;seen=False;cancel_sent=False;reported_tools={}
    try:
        pump=RequestPump(gateway)
        channel=docker.start(name,bootstrap,deadline)
        while True:
            pump.deliver(channel)
            frame=channel.receive(timeout=.05)
            if frame is None:continue
            kind=frame.get('type')
            if kind=='request':
                if set(frame)!={'type','id','body'} or type(frame['id']) is not int:raise Failure('request protocol')
                pump.submit(frame['id'],frame['body'])
            elif kind=='agent_log':
                if set(frame)!={'type','channel','data'} or frame['channel'] not in ('stdout','stderr'):raise Failure('log protocol')
                raw=base64.b64decode(frame['data'],validate=True);log_bytes+=len(raw)
                if log_bytes>8*1024*1024:raise Failure('agent log bound')
                logs.update(frame['channel'].encode());logs.update(raw)
                if frame['channel']=='stdout':
                    pending.extend(raw)
                    while b'\n' in pending:
                        line,_,rest=pending.partition(b'\n');pending=bytearray(rest)
                        try:event=strict(line)
                        except ValueError:continue
                        if isinstance(event,dict) and event.get('type')=='start' and isinstance(event.get('session_id'),str):
                            value=str(uuid.UUID(event['session_id']))
                            if session_id is not None and session_id!=value:raise Failure('multiple session bindings')
                            session_id=value
                        if isinstance(event,dict) and event.get('type')=='tool_start':observe_tool_start(policy_state,event)
                        if isinstance(event,dict) and event.get('type')=='tool_result':
                            observe_tool_result(policy_state,event)
                            if event.get('is_error') is False:
                                tool=event.get('name')
                                if isinstance(tool,str) and 0<len(tool)<=64 and tool.isascii() and tool.replace('_','').isalnum():
                                    if tool not in reported_tools and len(reported_tools)>=128:raise Failure('reported tool names limit')
                                    reported_tools[tool]=reported_tools.get(tool,0)+1
            elif kind=='sentinel' and sentinel:
                if seen:raise Failure('duplicate sentinel')
                seen=True;pump.cancel();channel.send({'type':'cancel'});cancel_sent=True
            elif kind=='agent_done':
                done={**frame,'log_sha256':logs.hexdigest(),'log_bytes':log_bytes};break
            else:raise Failure('unexpected Root frame')
        docker.remove(name,deadline)
        return {'done':done,'agent_reported_tool_successes':reported_tools,'session_id':session_id,'sentinel':seen,'cancel_sent':cancel_sent}
    finally:
        try:
            if pump:pump.close()
        finally:
            if channel:channel.close()

def run_case(docker,invocation,item,temporary):
    case=item['case'];start=time.monotonic();deadline=start+case['timeout_secs'];work_deadline=deadline-12;docker.cleanup_deadline=deadline
    policy_state={'skills':{},'violations':set()};required_skills=case.get('require_skills',[])
    result={'id':case['id'],'case_sha256':item['sha256'],'language':case['language'],'category':case['category'],
        'status':'blocked','reason':None,'checks':[],'cleanup':'unknown','agent':None,'requests':[],'snapshot_sha256':None,'seconds':None,
        'required_skills':required_skills,'required_skills_observed':required_skills_met(policy_state,required_skills),'formal_violations':[]}
    profile=invocation['effective_profile']
    credential=invocation.get('provider_credential') if profile.get('kind')=='gigachat' else None
    storage=None;gateway=Gateway(profile,case,work_deadline-20,credential)
    try:
        volumes={dst:docker.volume(size,work_deadline) for dst,size in [('/workspace',128),('/agent-home',64)]}
        keeper=docker.create({},work_deadline,volumes=volumes,volumes_readonly=True)
        storage=docker.start(keeper,{'mode':'storage','uid':docker.uid,'gid':docker.uid,'timeout_secs':min(600,case['timeout_secs'])},work_deadline)
        if storage.receive()!={'type':'storage_ready'}:raise Failure('storage readiness')
        lifecycle=case.get('lifecycle')
        first=agent_phase(docker,invocation,item,volumes,gateway,work_deadline,
            sentinel=lifecycle['interrupt_after_file'] if lifecycle else None,policy_state=policy_state)
        result['agent']=first['done'];result['agent_reported_tool_successes']=first['agent_reported_tool_successes']
        if lifecycle:
            result['lifecycle']={'sentinel_observed':first['sentinel'],'cancel_sent':first['cancel_sent'],
                'cancel_signal_sent':first['done'].get('cancel_signal_sent') is True,
                'first_container_absent':True,'first_forced':first['done'].get('forced'), 'explicit_resume_argument':False,'agent_reported_same_session':False}
            if not (first['sentinel'] and first['cancel_sent'] and first['done'].get('cancel_signal_sent') is True
                    and first['done'].get('cancelled') is True and first['done'].get('forced') is False
                    and first['done'].get('leader_reaped') is True and first['done'].get('pipes_complete') is True
                    and first['session_id']):raise AssessmentFailure('lifecycle interruption not established')
            second=agent_phase(docker,invocation,item,volumes,gateway,work_deadline,
                resume_id=first['session_id'],resume_prompt=lifecycle['resume_prompt'],policy_state=policy_state)
            result['lifecycle']['explicit_resume_argument']=True
            for name,count in second['agent_reported_tool_successes'].items():result['agent_reported_tool_successes'][name]=result['agent_reported_tool_successes'].get(name,0)+count
            result['agent']=second['done'];result['lifecycle']['agent_reported_same_session']=second['session_id']==first['session_id']
            if not result['lifecycle']['agent_reported_same_session']:raise AssessmentFailure('resume session mismatch')
        raw=docker.archive(storage,'workspace')
        docker.remove(keeper,work_deadline)
        storage.close();storage=None
        docker.cleanup(work_deadline)
        snapshot=temporary/case['id'];snapshot.mkdir(mode=0o700)
        result['snapshot_sha256']=extract_frozen(raw,snapshot)
        del raw
        for check in item['oracle']['checks']:
            if time.monotonic()>=work_deadline:raise Failure('verification deadline')
            observer=docker.create({'/snapshot':snapshot},work_deadline);observer_channel=None
            try:
                bootstrap={'mode':'observe','uid':docker.uid,'gid':docker.uid,'timeout_secs':max(1,min(600,int(work_deadline-time.monotonic()))),
                    'prepare':[probe_command(p) for p in item['oracle']['prepare']],'check':probe_command(check)}
                observer_channel=docker.start(observer,bootstrap,work_deadline);observation=observer_channel.receive()
            finally:
                try:docker.remove(observer,work_deadline)
                finally:
                    if observer_channel:observer_channel.close()
            # Adjudication happens only after independently observed absence.
            passed=observe_matches(observation,check)
            result['checks'].append({'id':check['id'],'passed':passed,'exit_code':observation.get('exit_code'),
                'signal':observation.get('signal'),'timed_out':observation.get('timed_out'),
                'truncated':observation.get('truncated'),'prepare_failed':observation.get('prepare_failed'),
                'stdout_sha256':hashlib.sha256(base64.b64decode(observation['stdout'],validate=True)).hexdigest()})
        done=result['agent']
        success=(done.get('exit_code')==0 and done.get('signal') is None and done.get('leader_reaped') is True and done.get('pipes_complete') is True
                 and done.get('timed_out') is False and done.get('cancelled') is False and done.get('truncated') is False)
        tool=case.get('require_tool_success')
        tool_requirement=not tool or (result['agent_reported_tool_successes'].get(tool,0)>0 and any(r.get('requested_tool_names',{}).get(tool,0)>0 for r in gateway.receipts))
        result['tool_requirement_observed']=tool_requirement
        result['required_skills_observed']=required_skills_met(policy_state,required_skills)
        result['formal_violations']=sorted(policy_state['violations'])
        functional=tool_requirement and success and all(c['passed'] for c in result['checks']) and gateway.generations>0 and all(r['status']=='received' or (lifecycle and r['status']=='cancelled_by_case') for r in gateway.receipts)
        result['status']='passed' if functional and not result['formal_violations'] and result['required_skills_observed'] else 'failed'
        if result['formal_violations']:result['reason']='formal task constraints violated'
        elif not result['required_skills_observed']:result['reason']='required skills were not observed'
        elif not success:result['reason']='agent did not finish successfully'
        elif gateway.generations==0:result['reason']='no model inference observed'
    except AssessmentFailure:
        result['status']='failed';result['reason']='required interruption/resume behavior was not observed'
    except (Failure,OSError,ValueError,KeyError,TypeError) as error:
        # Exception strings can contain project output or paths. Publish a fixed
        # class, never raw exception text or endpoint bodies.
        if result.get('agent') and result['agent'].get('timed_out') is True:
            result['status']='failed';result['reason']='agent time budget exhausted; verification incomplete'
        else:
            result['status']='blocked';result['reason']='runner '+type(error).__name__
    finally:
        try:
            docker.cleanup(deadline);result['cleanup']='confirmed_absent'
        except (Failure,OSError,ValueError):
            result['cleanup']='unknown';result['status']='unknown';result['reason']='container cleanup could not be confirmed'
        finally:
            try:
                if storage:storage.close()
            except (Failure,OSError,ValueError):
                result['cleanup']='unknown';result['status']='unknown';result['reason']='local attachment cleanup could not be confirmed'
            finally:
                result['required_skills_observed']=required_skills_met(policy_state,required_skills)
                result['formal_violations']=sorted(policy_state['violations'])
                result['requests']=gateway.receipts;result['request_attempts']=gateway.attempts;result['generations']=gateway.generations
                result['seconds']=round(time.monotonic()-start,3)
                if result['status']!='unknown' and any(r['status']=='failed_or_incomplete' or (r.get('http_status') is not None and not 200<=r['http_status']<300) for r in gateway.receipts):
                    result['status']='blocked';result['reason']='selected endpoint exchange failed or incomplete'
                result['operator_cancelled']=CONTROL.cancelled
                if CONTROL.cancelled and result['status']=='passed':
                    result['status']='blocked';result['reason']='operator cancelled during finalization'
                if result['seconds']>case['timeout_secs'] and result['status']=='passed':
                    result['status']='blocked';result['reason']='total case deadline exceeded'
    return result

def main():
    if sys.version_info<(3,12):raise Failure('Python 3.12 or newer required')
    invocation=strict(sys.stdin.buffer.read(16*1024*1024+1),16*1024*1024)
    if invocation.get('version')!=1:raise Failure('host invocation version')
    CONTROL.cancelled=False
    # A flag cannot unwind a finally block or lose an in-progress report.
    # Bounded transport loops observe it; cleanup deliberately ignores it.
    signal.signal(signal.SIGINT,request_cancel);signal.signal(signal.SIGTERM,request_cancel)
    report={'version':1,'comparison_key':invocation['comparison_key'],'artifact':invocation['artifact'],'isolation':None,'cases':[],'cleanup':'unknown'}
    with tempfile.TemporaryDirectory(prefix='rcode-eval-host-') as temp:
        root=Path(temp);config=root/'docker';config.mkdir(mode=0o700)
        docker=Docker(invocation['docker'],invocation['socket'],config,invocation['image'],Path(invocation['runtime']),cancel_requested=lambda:CONTROL.cancelled)
        docker.cleanup_deadline=time.monotonic()+20
        try:
            report['isolation']=check_isolation(docker,docker.cleanup_deadline)
            for item in invocation['cases']:
                if CONTROL.cancelled or docker.active or docker.volumes:
                    report['cases'].append({'id':item['case']['id'],'case_sha256':item['sha256'],'status':'not_run','reason':'previous cleanup or cancellation','cleanup':'unknown' if docker.active or docker.volumes else 'confirmed_absent'})
                    continue
                row=run_case(docker,invocation,item,root);report['cases'].append(row)
                print('eval '+row['id']+': '+row['status'],file=sys.stderr,flush=True)
        except (Failure,OSError,ValueError,KeyError,TypeError):
            done={c['id'] for c in report['cases']}
            for item in invocation['cases']:
                if item['case']['id'] not in done:report['cases'].append({'id':item['case']['id'],'case_sha256':item['sha256'],'status':'blocked','reason':'isolation/setup/cancellation failed','cleanup':'unknown'})
        finally:
            signal.signal(signal.SIGINT,signal.SIG_IGN);signal.signal(signal.SIGTERM,signal.SIG_IGN)
            try:docker.cleanup(docker.cleanup_deadline);report['cleanup']='confirmed_absent'
            except (Failure,OSError,ValueError):report['cleanup']='unknown'
    counts={k:sum(c['status']==k for c in report['cases']) for k in ['passed','failed','blocked','unknown','not_run']}
    report['counts']=counts
    report['residual_resources']={'containers':[{'name':name,**record} for name,record in docker.active.items()], 'volumes':[{'name':name,'owner':record['owner']} for name,record in docker.volumes.items()]}
    print(json.dumps(report,ensure_ascii=True,allow_nan=False,separators=(',',':')),flush=True)
    return 0 if counts['passed']==len(report['cases']) and report['cleanup']=='confirmed_absent' else 1

if __name__=='__main__':
    try:raise SystemExit(main())
    except (Failure,OSError,ValueError,KeyError,TypeError):
        print('eval host failed before a complete report',file=sys.stderr);raise SystemExit(2)
