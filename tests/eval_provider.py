"""GigaChat host relay fixtures; no live API or real credentials."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tarfile
import time
import unittest
from unittest.mock import patch
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'evals'),str(ROOT/'evals/runtime')]
from runtime import strict
from host_provider import GigaChatUpstream,HttpsExchange,Failure


class GigaChatOAuthTests(unittest.TestCase):
    def test_chat_refreshes_expired_token_once(self):
        responses=[
            (200,{'access_token':'real-token-1','expires_at':4_000_000_000}),
            (401,{'error':'expired'}),
            (200,{'access_token':'real-token-2','expires_at':4_000_000_000}),
            (200,{'choices':[]}),
        ]
        calls=[]
        def exchange(operation,authorization,body):
            calls.append((operation,authorization,body))
            return responses.pop(0)
        upstream=GigaChatUpstream('Basic synthetic-key','GIGACHAT_API_PERS',exchange)
        body={'model':'GigaChat-3-Ultra'}
        self.assertEqual(upstream.chat(body),(200,{'choices':[]}))
        self.assertEqual([call[0] for call in calls],['oauth','chat','oauth','chat'])
        self.assertEqual([call[1] for call in calls],[
            'Basic synthetic-key','Bearer real-token-1','Basic synthetic-key','Bearer real-token-2',
        ])
        self.assertEqual(calls[0][2],{'scope':'GIGACHAT_API_PERS'})
        self.assertIs(calls[1][2],body)
        self.assertIs(calls[3][2],body)

    def test_second_chat_unauthorized_is_returned_without_another_retry(self):
        responses=[
            (200,{'access_token':'real-token-1','expires_at':4_000_000_000}),
            (401,{'error':'expired'}),
            (200,{'access_token':'real-token-2','expires_at':4_000_000_000}),
            (401,{'error':'expired'}),
        ]
        calls=[]
        def exchange(operation,authorization,body):
            calls.append((operation,authorization,body))
            return responses.pop(0)
        upstream=GigaChatUpstream('Basic synthetic-key','GIGACHAT_API_PERS',exchange)
        status,value=upstream.chat({'model':'GigaChat-3-Ultra'})
        self.assertEqual(status,401)
        self.assertEqual(value,{'error':'expired'})
        self.assertEqual(len([call for call in calls if call[0]=='chat']),2)
        self.assertEqual(len(calls),4)
        self.assertEqual(responses,[])

    def test_credential_shape_failures_are_fixed(self):
        for credential in ['',None,'Basic ','Basic x','Basic 1234567','Basic fixture\r','fixture\n']:
            with self.subTest(shape='invalid'):
                with self.assertRaises(Failure) as caught:GigaChatUpstream(credential,'GIGACHAT_API_PERS',lambda *_args:None)
                self.assertEqual(str(caught.exception),'credential shape')

    def test_oauth_response_and_expiry_failures_are_fixed(self):
        valid={'access_token':'real-token-1','expires_at':4_000_000_000}
        cases=[
            ((201,valid),'oauth response'),((200,[]),'oauth response'),((200,{}),'oauth response'),
            ((200,{**valid,'access_token':''}),'oauth response'),
            ((200,{**valid,'access_token':'x'}),'oauth response'),
            ((200,{**valid,'access_token':'1234567'}),'oauth response'),
            ((200,{**valid,'expires_at':True}),'oauth response'),
            ((200,{**valid,'expires_at':1000}),'oauth expiry'),
        ]
        for response,message in cases:
            with self.subTest(message=message):
                upstream=GigaChatUpstream('Basic synthetic-key','GIGACHAT_API_PERS',lambda *_args:response,now=lambda:1000)
                with self.assertRaises(Failure) as caught:upstream.refresh()
                self.assertEqual(str(caught.exception),message)

    def test_millisecond_oauth_expiry_is_normalized(self):
        upstream=GigaChatUpstream('Basic synthetic-key','GIGACHAT_API_PERS',lambda *_args:(
            200,{'access_token':'real-token-1','expires_at':4_000_000_000_000}),now=lambda:1000)
        upstream.refresh()
        self.assertEqual(upstream.expires_at,4_000_000_000)


class FakeSocket:
    def __init__(self):self.timeouts=[]
    def settimeout(self,value):self.timeouts.append(value)
    def shutdown(self,_how):pass
    def close(self):pass


class FakeResponse:
    def __init__(self,raw,status=200):
        self.raw=io.BytesIO(raw);self.status=status
    def read1(self,size):return self.raw.read(size)


class FakeConnection:
    def __init__(self,raw=b'{}',status=200):
        self.response=FakeResponse(raw,status);self.sock=FakeSocket();self.requests=[];self.closed=False
    def connect(self):pass
    def request(self,method,path,body=None,headers=None):
        self.requests.append((method,path,body,headers))
    def getresponse(self):return self.response
    def close(self):self.closed=True


class HttpsExchangeTests(unittest.TestCase):
    def exchange(self,connection,deadline=None):
        context=object()
        with patch('host_provider.ssl.create_default_context',return_value=context),patch(
            'host_provider.http.client.HTTPSConnection',return_value=connection) as constructor:
            transport=HttpsExchange(time.monotonic()+5 if deadline is None else deadline,5,5,strict)
            yield constructor,context,transport

    def test_official_endpoints_payloads_headers_and_timeouts(self):
        oauth=FakeConnection(b'{"access_token":"fixture","expires_at":4000000000}')
        chat=FakeConnection(b'{"choices":[]}')
        for operation,connection,host,port,path,content_type,payload in [
            ('oauth',oauth,'ngw.devices.sberbank.ru',9443,'/api/v2/oauth','application/x-www-form-urlencoded',b'scope=GIGACHAT_API_PERS'),
            ('chat',chat,'api.giga.chat',443,'/v1/chat/completions','application/json',b'{"stream":false}'),
        ]:
            with self.subTest(operation=operation):
                for constructor,context,transport in self.exchange(connection):
                    status,value=transport(operation,'Bearer fixture',{'scope':'GIGACHAT_API_PERS'} if operation=='oauth' else {'stream':False})
                    self.assertEqual(status,200)
                    self.assertIsInstance(value,dict)
                    constructor.assert_called_once_with(host,port,timeout=1.0,context=context)
                    method,actual_path,body,headers=connection.requests[0]
                    self.assertEqual((method,actual_path,body),('POST',path,payload))
                    expected={'Authorization':'Bearer fixture','Content-Type':content_type,'Accept':'application/json'}
                    if operation=='oauth':
                        self.assertEqual(set(headers),set(expected)|{'RqUID'})
                        self.assertEqual({k:headers[k] for k in expected},expected)
                        parsed=uuid.UUID(headers['RqUID'])
                        self.assertEqual(parsed.version,4)
                        self.assertEqual(str(parsed),headers['RqUID'])
                    else:self.assertEqual(headers,expected)
                    self.assertTrue(connection.closed)
                    self.assertTrue(all(0<timeout<=5 for timeout in connection.sock.timeouts))

    def test_oauth_rquid_is_unique_per_request(self):
        connections=[FakeConnection(b'{"access_token":"fixture","expires_at":4000000000}') for _ in range(2)]
        with patch('host_provider.http.client.HTTPSConnection',side_effect=connections):
            transport=HttpsExchange(time.monotonic()+5,5,5,strict)
            values=[]
            for _ in range(2):transport('oauth','Basic fixture',{'scope':'GIGACHAT_API_PERS'})
            for connection in connections:
                headers=connection.requests[0][3]
                parsed=uuid.UUID(headers['RqUID'])
                self.assertEqual(parsed.version,4)
                values.append(headers['RqUID'])
            self.assertEqual(len(set(values)),2)

    def test_fixed_failures_cover_redirect_shape_parse_size_and_operation(self):
        cases=[
            (FakeConnection(b'{}',302),'chat',{'stream':False},'upstream redirect'),
            (FakeConnection(b'[]'),'chat',{'stream':False},'upstream response shape'),
            (FakeConnection(b'{"x":1,"x":2}'),'chat',{'stream':False},'upstream exchange'),
            (FakeConnection(b'{"x":NaN}'),'chat',{'stream':False},'upstream exchange'),
            (FakeConnection(b' '*(4*1024*1024+1)),'chat',{'stream':False},'upstream response size'),
            (FakeConnection(),'other',{},'upstream operation'),
        ]
        for connection,operation,body,message in cases:
            with self.subTest(message=message):
                for _constructor,_context,transport in self.exchange(connection):
                    with self.assertRaises(Failure) as caught:transport(operation,'Bearer fixture',body)
                    self.assertEqual(str(caught.exception),message)
                    self.assertEqual(connection.closed,operation!='other')

    def test_non_finite_chat_json_is_a_fixed_exchange_failure(self):
        connection=FakeConnection()
        for _constructor,_context,transport in self.exchange(connection):
            with self.assertRaises(Failure) as caught:transport('chat','Bearer fixture',{'value':float('nan')})
            self.assertEqual(str(caught.exception),'upstream exchange')

    def test_deadline_request_size_and_transport_errors_are_fixed(self):
        for deadline,body,message in [
            (time.monotonic()-1,{'stream':False},'upstream deadline/size'),
            (time.monotonic()+5,{'content':'x'*(2*1024*1024)},'upstream deadline/size'),
        ]:
            with self.subTest(message=message):
                connection=FakeConnection()
                with patch('host_provider.http.client.HTTPSConnection') as constructor:
                    transport=HttpsExchange(deadline,5,5,strict)
                    with self.assertRaises(Failure) as caught:transport('chat','Bearer fixture',body)
                    self.assertEqual(str(caught.exception),message)
                    constructor.assert_not_called()
        connection=FakeConnection()
        connection.request=lambda *_args,**_kwargs:(_ for _ in ()).throw(OSError('sensitive transport detail'))
        for _constructor,_context,transport in self.exchange(connection):
            with self.assertRaises(Failure) as caught:transport('chat','Bearer fixture',{'stream':False})
            self.assertEqual(str(caught.exception),'upstream exchange')
            self.assertTrue(connection.closed)


class HttpsCancellationTests(unittest.TestCase):
    def test_request_deadline_is_checked_after_response_read(self):
        connection=FakeConnection()
        original=connection.response.read1;reads=0
        def slow_read(size):
            nonlocal reads
            reads+=1
            if reads==1:time.sleep(.06)
            return original(size)
        connection.response.read1=slow_read
        start=time.monotonic()
        transport=HttpsExchange(start+5,.02,5,strict)
        with patch('host_provider.http.client.HTTPSConnection',return_value=connection):
            with self.assertRaises(Failure) as caught:transport('chat','Bearer fixture',{'stream':False})
        self.assertEqual(str(caught.exception),'upstream deadline/size')

    def test_connection_close_slow_body_uses_independent_transport_reference(self):
        import http.client
        import socketserver
        import threading
        class SlowBody(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.recv(65536)
                try:
                    self.request.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n')
                    time.sleep(.7);self.request.sendall(b'{}')
                except OSError:pass
        server=socketserver.ThreadingTCPServer(('127.0.0.1',0),SlowBody);server.daemon_threads=True
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            connection=http.client.HTTPConnection('127.0.0.1',server.server_address[1],timeout=1)
            start=time.monotonic()
            with patch('host_provider.http.client.HTTPSConnection',return_value=connection):
                transport=HttpsExchange(start+5,.12,5,strict)
                with self.assertRaises(Failure) as caught:transport('chat','Bearer fixture',{'stream':False})
            self.assertIn(str(caught.exception),{'upstream exchange','upstream deadline/size'})
            self.assertLess(time.monotonic()-start,.5,'Connection: close made the body watchdog ineffective')
        finally:server.shutdown();server.server_close();thread.join()

    def test_slow_headers_are_cut_off_at_absolute_deadline(self):
        import http.client
        import socketserver
        import threading
        class Drip(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.recv(65536)
                try:
                    self.request.sendall(b'HTTP/1.1 200 OK\r\n')
                    for _ in range(20):
                        self.request.sendall(b'X-Header: x\r\n');time.sleep(.08)
                    self.request.sendall(b'Content-Length: 2\r\n\r\n{}')
                except OSError:pass
        server=socketserver.ThreadingTCPServer(('127.0.0.1',0),Drip);server.daemon_threads=True
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            connection=http.client.HTTPConnection('127.0.0.1',server.server_address[1],timeout=1)
            start=time.monotonic()
            with patch('host_provider.http.client.HTTPSConnection',return_value=connection):
                transport=HttpsExchange(start+.3,5,5,strict)
                with self.assertRaises(Failure) as caught:transport('chat','Bearer fixture',{'stream':False})
            self.assertIn(str(caught.exception),{'upstream exchange','upstream deadline/size'})
            self.assertLess(time.monotonic()-start,1.0,'slow headers exceeded the absolute deadline')
        finally:server.shutdown();server.server_close();thread.join()

    def test_case_cancellation_interrupts_gigachat_headers_and_marks_receipt(self):
        import http.client
        import socketserver
        import threading
        import host
        cancelled=threading.Event()
        class Drip(socketserver.BaseRequestHandler):
            def handle(self):
                request=self.request.recv(65536)
                try:
                    if b'/api/v2/oauth' in request:
                        raw=b'{"access_token":"real-token-1","expires_at":4000000000}'
                        self.request.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(raw)).encode()+b'\r\n\r\n'+raw)
                        return
                    cancelled.set();self.request.sendall(b'HTTP/1.1 200 OK\r\n')
                    for _ in range(20):
                        self.request.sendall(b'X-Header: x\r\n');time.sleep(.08)
                    self.request.sendall(b'Content-Length: 2\r\n\r\n{}')
                except OSError:pass
        server=socketserver.ThreadingTCPServer(('127.0.0.1',0),Drip);server.daemon_threads=True
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        def connection(*_args,**_kwargs):return http.client.HTTPConnection('127.0.0.1',server.server_address[1],timeout=1)
        profile={'kind':'gigachat','model':'GigaChat-3-Ultra','scope':'GIGACHAT_API_PERS','stream':False,
            'max_output_tokens':8,'request_timeout_secs':5,'idle_timeout_secs':5}
        try:
            with patch('host_provider.http.client.HTTPSConnection',side_effect=connection):
                gateway=host.Gateway(profile,{'max_steps':1,'max_requests':1},time.monotonic()+5,'Basic synthetic-key')
                start=time.monotonic()
                status,_value=gateway.relay({'model':'GigaChat-3-Ultra','max_tokens':8,'stream':False,'messages':[]},cancelled)
            self.assertTrue(cancelled.is_set())
            self.assertEqual(status,502)
            self.assertLess(time.monotonic()-start,1.0,'case cancellation did not interrupt slow headers')
            self.assertEqual(gateway.receipts[0]['status'],'cancelled_by_case')
        finally:server.shutdown();server.server_close();thread.join()


class GigaChatToolsTests(unittest.TestCase):
    def test_tool_turn_round_trip_and_following_native_history(self):
        import host
        responses=[
            (200,{'access_token':'real-token-1','expires_at':4_000_000_000}),
            (200,{'choices':[{'message':{'role':'assistant','content':'','function_call':{
                'name':'read_file','arguments':{'path':'a.rs'}}},'finish_reason':'function_call'}]}),
            (200,{'choices':[{'message':{'role':'assistant','content':'done'},'finish_reason':'stop'}]}),
        ]
        calls=[]
        def exchange(operation,authorization,body):
            calls.append((operation,authorization,body))
            return responses.pop(0)
        tools=[{'type':'function','function':{'name':'read_file','description':'Read a file','parameters':{
            'type':'object','properties':{'path':{'type':'string','allOf':[{'minLength':1}],'not':{'const':''}}}}}}]
        profile={'kind':'gigachat','model':'GigaChat-3-Ultra','scope':'GIGACHAT_API_PERS','stream':False,
            'max_output_tokens':8,'request_timeout_secs':5,'idle_timeout_secs':5}
        with patch.object(host,'HttpsExchange',return_value=exchange):
            gateway=host.Gateway(profile,{'max_steps':2,'max_requests':2},time.monotonic()+5,'Basic synthetic-key')
            request={'model':'GigaChat-3-Ultra','max_tokens':8,'stream':False,
                'messages':[{'role':'user','content':'read'}],'tools':tools,'tool_choice':'auto'}
            status,first=gateway.relay(request)
            self.assertEqual(status,200)
            native=calls[1][2]
            self.assertNotIn('tools',native)
            self.assertNotIn('tool_choice',native)
            self.assertEqual(native['function_call'],'auto')
            self.assertEqual(native['functions'][0]['name'],'read_file')
            self.assertEqual(native['functions'][0]['parameters'],{
                'type':'object','properties':{'path':{'type':'string'}}})
            message=first['choices'][0]['message']
            self.assertNotIn('function_call',message)
            self.assertEqual(first['choices'][0]['finish_reason'],'tool_calls')
            self.assertEqual(len(message['tool_calls']),1)
            call=message['tool_calls'][0]
            self.assertEqual(call['type'],'function')
            self.assertEqual(call['function']['name'],'read_file')
            self.assertEqual(json.loads(call['function']['arguments']),{'path':'a.rs'})
            self.assertTrue(call['id'].startswith('call_'))
            self.assertEqual(len(call['id']),37)
            uuid.UUID(hex=call['id'][5:])
            second_request={**request,'messages':request['messages']+[message,{
                'role':'tool','tool_call_id':call['id'],'name':'read_file','content':'{"ok":true}'}]}
            status,second=gateway.relay(second_request)
            self.assertEqual(status,200)
            self.assertEqual(second['choices'][0]['message']['content'],'done')
            history=calls[2][2]['messages']
            self.assertEqual(len(history),3)
            self.assertEqual(history[1]['role'],'assistant')
            self.assertEqual(history[1]['function_call'],{'name':'read_file','arguments':{'path':'a.rs'}})
            self.assertNotIn('tool_calls',history[1])
            self.assertEqual(history[2],{'role':'function','name':'read_file','content':'{"ok":true}'})
            self.assertEqual(gateway.receipts[0]['requested_tool_names'],{'read_file':1})
            self.assertEqual(gateway.receipts[1]['requested_tool_names'],{})

    def test_raw_message_state_cannot_override_trusted_tool_call_mapping(self):
        from host_provider import giga_request
        call={'id':'call_trusted','type':'function','function':{'name':'read_file','arguments':'{"path":"a.rs"}'}}
        body={'model':'GigaChat-3-Ultra','messages':[
            {'role':'assistant','content':'','tool_calls':[call],'functions_state_id':'untrusted-state'},
            {'role':'tool','tool_call_id':'call_trusted','content':'{"ok":true}'},
        ]}
        native=giga_request(body,{'call_trusted':'state-1'})
        self.assertEqual(native['messages'][0]['functions_state_id'],'state-1')
        native=giga_request(body,{})
        self.assertNotIn('functions_state_id',native['messages'][0])

    def test_function_call_none_and_unsupported_required(self):
        from host_provider import giga_request
        base={'model':'GigaChat-3-Ultra','messages':[],'stream':False}
        none=giga_request(base)
        self.assertEqual(none['function_call'],'none')
        self.assertNotIn('functions',none)
        tools=[{'type':'function','function':{'name':'read_file','description':'','parameters':{'type':'object'}}}]
        explicit_none=giga_request({**base,'tools':tools,'tool_choice':'none'})
        self.assertEqual(explicit_none['function_call'],'none')
        self.assertEqual(len(explicit_none['functions']),1)
        with self.assertRaises(Failure) as caught:giga_request({**base,'tools':tools,'tool_choice':'required'})
        self.assertEqual(str(caught.exception),'tool choice unsupported')


class SensitivePayloadTests(unittest.TestCase):
    profile={'kind':'gigachat','model':'GigaChat-3-Ultra','scope':'GIGACHAT_API_PERS','stream':False,
        'max_output_tokens':8,'request_timeout_secs':5,'idle_timeout_secs':5}
    safe_error={'error':{'message':'eval selected endpoint request failed or incomplete'}}

    def gateway(self,responses,credential='Basic synthetic-credential'):
        import host
        calls=[]
        def exchange(operation,authorization,body,cancelled=None):
            calls.append((operation,authorization,body))
            return responses.pop(0)
        with patch.object(host,'HttpsExchange',return_value=exchange):
            gateway=host.Gateway(self.profile,{'max_steps':2,'max_requests':2},time.monotonic()+5,credential)
        return gateway,calls

    def request(self,native=False):
        body={'model':'GigaChat-3-Ultra','max_tokens':8,'stream':False,'messages':[]}
        if native:body['function_call']='none'
        return body

    def assert_safe_rejection(self,gateway,status,value,secrets):
        serialized=json.dumps({'response':value,'receipts':gateway.receipts},ensure_ascii=True)
        for secret in secrets:
            self.assertFalse(secret in serialized,'OAuth material reached an agent-visible payload or receipt')
        self.assertEqual((status,value),(502,self.safe_error))

    def test_request_pump_frame_rejects_current_token_in_error_message(self):
        import host
        secret='current-token-123'
        gateway,_calls=self.gateway([(200,{'access_token':secret,'expires_at':4_000_000_000}),
            (400,{'error':{'message':'upstream reflected '+secret}})])
        frames=[]
        class Channel:
            def send(self,value):frames.append(value)
        pump=host.RequestPump(gateway)
        try:
            pump.submit(1,self.request())
            deadline=time.monotonic()+2
            while not frames and time.monotonic()<deadline:
                pump.deliver(Channel())
                time.sleep(.01)
            self.assertEqual(len(frames),1)
            serialized=json.dumps(frames,ensure_ascii=True)
            for value in [secret,'synthetic-credential']:
                self.assertFalse(value in serialized,'OAuth material reached an agent-visible response frame')
            self.assertEqual(frames[0],{'type':'response','id':1,'status':502,'body':self.safe_error})
            receipts=json.dumps(gateway.receipts,ensure_ascii=True)
            for value in [secret,'synthetic-credential']:
                self.assertFalse(value in receipts,'OAuth material reached host report receipts')
        finally:pump.close()

    def test_openai_success_rejects_token_before_tool_conversion(self):
        secret='current-token-123'
        gateway,_calls=self.gateway([(200,{'access_token':secret,'expires_at':4_000_000_000}),
            (200,{'choices':[{'message':{'role':'assistant','content':'','function_call':{
                'name':'read_file','arguments':{'path':'nested/'+secret}}},'finish_reason':'function_call'}]})])
        status,value=gateway.relay(self.request())
        self.assert_safe_rejection(gateway,status,value,[secret,'synthetic-credential'])

    def test_native_success_rejects_token_in_functions_state(self):
        secret='current-token-123'
        gateway,_calls=self.gateway([(200,{'access_token':secret,'expires_at':4_000_000_000}),
            (200,{'choices':[{'message':{'role':'assistant','content':'','function_call':{
                'name':'read_file','arguments':{'path':'a.rs'}},'functions_state_id':secret},
                'finish_reason':'function_call'}]})])
        status,value=gateway.relay(self.request(native=True))
        self.assert_safe_rejection(gateway,status,value,[secret,'synthetic-credential'])

    def test_native_error_rejects_previous_token_in_nested_key_after_refresh(self):
        previous='previous-token-123';current='current-token-456'
        gateway,calls=self.gateway([(200,{'access_token':previous,'expires_at':4_000_000_000}),
            (401,{'error':'expired'}),(200,{'access_token':current,'expires_at':4_000_000_000}),
            (400,{'error':{'details':[{'nested-'+previous:'safe'}]}})])
        status,value=gateway.relay(self.request(native=True))
        self.assertEqual([call[0] for call in calls],['oauth','chat','oauth','chat'])
        self.assert_safe_rejection(gateway,status,value,[previous,current,'synthetic-credential'])

    def test_request_pump_rejects_short_token_before_bearer_reflection(self):
        import host
        gateway,calls=self.gateway([(200,{'access_token':'x','expires_at':4_000_000_000}),
            (400,{'error':{'message':'Bearer x'}})])
        frames=[]
        class Channel:
            def send(self,value):frames.append(value)
        pump=host.RequestPump(gateway)
        try:
            pump.submit(1,self.request())
            deadline=time.monotonic()+2
            while not frames and time.monotonic()<deadline:
                pump.deliver(Channel())
                time.sleep(.01)
            self.assertEqual(len(frames),1)
            serialized=json.dumps(frames,ensure_ascii=True)
            self.assertFalse('Bearer x' in serialized,'Short OAuth token reached an agent-visible response frame')
            self.assertEqual(frames[0],{'type':'response','id':1,'status':502,'body':self.safe_error})
            self.assertEqual([call[0] for call in calls],['oauth'])
        finally:pump.close()


class LocalGatewayRegressionTests(unittest.TestCase):
    def test_local_loopback_relay_is_unchanged_and_has_no_authorization(self):
        import http.server
        import threading
        from host import Gateway
        seen=[]
        class Local(http.server.BaseHTTPRequestHandler):
            def log_message(self,*_args):pass
            def do_POST(self):
                seen.append(self.headers.get('Authorization'))
                self.rfile.read(int(self.headers['Content-Length']))
                raw=b'{"model":"upstream-local-model","choices":[],"usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}'
                self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Local);server.daemon_threads=True
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            profile={'base_url':'http://127.0.0.1:'+str(server.server_address[1])+'/v1','model':'fixture',
                'max_output_tokens':8,'request_timeout_secs':5,'idle_timeout_secs':5}
            gateway=Gateway(profile,{'max_steps':1,'max_requests':1},time.monotonic()+5)
            status,value=gateway.relay({'model':'fixture','max_tokens':8,'stream':False})
            self.assertEqual(status,200)
            self.assertEqual(value['choices'],[])
            self.assertEqual(gateway.receipts[0]['usage']['total_tokens'],3)
            self.assertEqual(gateway.receipts[0]['response_model'],'upstream-local-model')
            self.assertEqual(seen,[None])
        finally:server.shutdown();server.server_close();thread.join()

    def relay(self,connection,cancelled=None):
        import host
        profile={'base_url':'http://127.0.0.1:80/v1','model':'fixture','max_output_tokens':8,
            'request_timeout_secs':1,'idle_timeout_secs':5}
        with patch('host.http.client.HTTPConnection',return_value=connection):
            gateway=host.Gateway(profile,{'max_steps':1,'max_requests':1},time.monotonic()+5)
            status,value=gateway.relay({'model':'fixture','max_tokens':8,'stream':False},cancelled)
        return gateway,status,value

    def test_local_complete_body_after_request_deadline_is_not_received(self):
        connection=FakeConnection(b'{"choices":[]}')
        original=connection.response.read1;reads=0
        def delayed_read(size):
            nonlocal reads
            reads+=1
            if reads==1:time.sleep(1.1)
            return original(size)
        connection.response.read1=delayed_read
        gateway,status,value=self.relay(connection)
        self.assertEqual((status,value),(502,{'error':{'message':'eval selected endpoint request failed or incomplete'}}))
        self.assertEqual(gateway.receipts[0]['status'],'failed_or_incomplete')
        self.assertIsNone(gateway.receipts[0].get('http_status'))
        self.assertTrue(connection.closed)

    def test_local_cancellation_immediately_after_body_is_not_received(self):
        import threading
        cancelled=threading.Event();connection=FakeConnection(b'{"choices":[]}')
        original=connection.response.read1;reads=0
        def cancelling_read(size):
            nonlocal reads
            reads+=1
            if reads==1:cancelled.set()
            return original(size)
        connection.response.read1=cancelling_read
        gateway,status,value=self.relay(connection,cancelled)
        self.assertEqual((status,value),(502,{'error':{'message':'eval selected endpoint request failed or incomplete'}}))
        self.assertEqual(gateway.receipts[0]['status'],'cancelled_by_case')
        self.assertIsNone(gateway.receipts[0].get('http_status'))
        self.assertTrue(connection.closed)


class HostProviderBoundaryTests(unittest.TestCase):
    def test_gigachat_agent_profile_is_native_loopback_relay(self):
        import host
        profile={'kind':'gigachat','model':'GigaChat-3-Ultra','scope':'GIGACHAT_API_PERS',
            'auth_url':'https://ngw.devices.sberbank.ru:9443/api/v2/oauth','folder_id':None,
            'base_url':'https://api.giga.chat/v1','stream':False,'max_output_tokens':8,
            'request_timeout_secs':5,'idle_timeout_secs':5,'local':None}
        config=host.model_config(profile)
        effective=config['providers']['gigachat']
        self.assertEqual(config['active'],'gigachat')
        self.assertEqual(config['local'],{'active':None,'profiles':{}})
        self.assertEqual(effective['kind'],'gigachat')
        self.assertEqual(effective['base_url'],'http://127.0.0.1:18080/v1')
        self.assertEqual(effective['auth_url'],'http://127.0.0.1:18080/api/v2/oauth')
        self.assertIsNone(effective['ca_file'])
        self.assertFalse(effective['stream'])
        self.assertNotIn('provider_credential',config)

    def test_reflected_credential_and_current_token_fail_closed_before_receipts(self):
        import host
        for reflected,expected in [('synthetic-key',None),('synthetic-access-token',None),('GigaChat-3-Ultra','GigaChat-3-Ultra')]:
            with self.subTest(metadata='rejected' if expected is None else 'selected model'):
                responses=[(200,{'access_token':'synthetic-access-token','expires_at':4_000_000_000}),
                    (200,{'model':reflected,'choices':[]})]
                def exchange(_operation,_authorization,_body):return responses.pop(0)
                profile={'kind':'gigachat','model':'GigaChat-3-Ultra','scope':'GIGACHAT_API_PERS','stream':False,
                    'max_output_tokens':8,'request_timeout_secs':5,'idle_timeout_secs':5}
                with patch.object(host,'HttpsExchange',return_value=exchange):
                    gateway=host.Gateway(profile,{'max_steps':1,'max_requests':1},time.monotonic()+5,'Basic synthetic-key')
                    status,value=gateway.relay({'model':'GigaChat-3-Ultra','max_tokens':8,'stream':False,'messages':[]})
                receipt=gateway.receipts[0]
                if expected is None:
                    self.assertEqual((status,value),(502,SensitivePayloadTests.safe_error))
                    self.assertEqual(receipt['status'],'failed_or_incomplete')
                    self.assertIsNone(receipt.get('response_model'))
                else:
                    self.assertEqual(status,200)
                    self.assertEqual(receipt.get('response_model'),expected)
                serialized=json.dumps({'response':value,'receipts':gateway.receipts},ensure_ascii=True)
                for secret in ['synthetic-key','synthetic-access-token']:
                    self.assertFalse(secret in serialized,'OAuth material leaked into response or request receipts')

    def test_real_host_report_and_comparison_key_exclude_oauth_material(self):
        import host
        responses=[
            (200,{'access_token':'real-token-1','expires_at':4_000_000_000}),
            (401,{'error':'expired'}),
            (200,{'access_token':'real-token-2','expires_at':4_000_000_000}),
            (200,{'model':'GigaChat-3-Ultra','choices':[]}),
        ]
        operations=[]
        def exchange(operation,authorization,body):
            operations.append(operation)
            return responses.pop(0)
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w'):pass
        archive=stream.getvalue()
        class Storage:
            def receive(self):return {'type':'storage_ready'}
            def close(self):pass
        class Docker:
            def __init__(self,*_args,**_kwargs):self.active={};self.volumes={};self.uid=10001;self.gid=10001
            def volume(self,_size,_deadline):return 'volume'
            def create(self,*_args,**_kwargs):return 'keeper'
            def start(self,*_args,**_kwargs):return Storage()
            def archive(self,_storage,_path):return archive
            def remove(self,*_args):pass
            def cleanup(self,_deadline):pass
        def phase(_docker,_invocation,_item,_volumes,gateway,_deadline,**_kwargs):
            status,value=gateway.relay({'model':'GigaChat-3-Ultra','max_tokens':8,'stream':False})
            if status!=200 or value!={'model':'GigaChat-3-Ultra','choices':[]}:raise AssertionError('synthetic relay failed')
            return {'done':{'type':'agent_done','exit_code':0,'signal':None,'leader_reaped':True,'pipes_complete':True,
                'timed_out':False,'cancelled':False,'truncated':False,'forced':False},
                'agent_reported_tool_successes':{},'session_id':None,'sentinel':False,'cancel_sent':False}
        profile={'kind':'gigachat','model':'GigaChat-3-Ultra','scope':'GIGACHAT_API_PERS','stream':False,
            'max_output_tokens':8,'request_timeout_secs':5,'idle_timeout_secs':5}
        invocation={'version':1,'comparison_key':{'selected_profile':profile,'effective_profile':profile},
            'artifact':{'series':'fixture'},'effective_profile':profile,'provider_credential':'Basic synthetic-key',
            'docker':'/unused/docker','socket':'/unused/socket','image':'sha256:'+'0'*64,'runtime':'/unused/runtime','binary':'/unused/rcode',
            'cases':[{'case':{'id':'provider','language':'python','category':'fixture','timeout_secs':60,'max_steps':2,'max_requests':4},
                'sha256':'f'*64,'fixture':'/unused/fixture','task':'fixture','oracle':{'prepare':[],'checks':[]}}]}
        def transport(deadline,request_timeout,idle_timeout,parse):
            if not deadline>time.monotonic() or request_timeout!=5 or idle_timeout!=5 or parse is not strict:
                raise AssertionError('profile transport bounds were not preserved')
            return exchange
        stdin=io.TextIOWrapper(io.BytesIO(json.dumps(invocation).encode()))
        stdout=io.StringIO();stderr=io.StringIO()
        with patch.object(host,'Docker',Docker),patch.object(host,'check_isolation',return_value={}),patch.object(
            host,'agent_phase',phase),patch.object(host,'HttpsExchange',transport),patch.object(
            sys,'stdin',stdin),contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
            code=host.main()
        self.assertEqual(code,0)
        report=json.loads(stdout.getvalue())
        self.assertEqual(report['cases'][0]['status'],'passed')
        self.assertEqual(report['cases'][0]['generations'],1)
        self.assertEqual(operations,['oauth','chat','oauth','chat'])
        serialized=json.dumps(report,ensure_ascii=True,separators=(',',':'))
        for secret in ['synthetic-key','real-token-1','real-token-2']:
            self.assertFalse(secret in serialized,'OAuth material leaked into host report or comparison key')
        self.assertNotIn('provider_credential',report)


if __name__=='__main__':unittest.main()
