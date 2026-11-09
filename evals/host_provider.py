"""Host-only GigaChat OAuth and bounded HTTPS transport."""
import copy
import http.client
import json
import socket
import ssl
import threading
import time
import urllib.parse
import uuid

from host_docker import Failure
from runtime import strict


def giga_parameters(parameters):
    def project(schema):
        if not isinstance(schema,dict):return
        schema.pop('allOf',None);schema.pop('not',None)
        properties=schema.get('properties')
        if isinstance(properties,dict):
            for child in properties.values():project(child)
        for keyword in ['items','additionalProperties']:
            if keyword in schema:project(schema[keyword])
    out=copy.deepcopy(parameters);project(out)
    return out


def giga_request(body,function_states=None):
    if not isinstance(body,dict):raise Failure('tool protocol')
    out=dict(body);tools=out.pop('tools',[]);choice=out.pop('tool_choice',None)
    if not isinstance(tools,list):raise Failure('tool protocol')
    functions=[]
    for tool in tools:
        function=tool.get('function') if isinstance(tool,dict) and tool.get('type')=='function' else None
        if not isinstance(function,dict):raise Failure('tool protocol')
        name=function.get('name');description=function.get('description');parameters=function.get('parameters')
        if not isinstance(name,str) or not name or not isinstance(description,str) or not isinstance(parameters,dict):raise Failure('tool protocol')
        functions.append({'name':name,'description':description,'parameters':giga_parameters(parameters)})
    if choice is None:choice='auto' if functions else 'none'
    if choice=='auto' and not functions:choice='none'
    if choice not in ('auto','none'):raise Failure('tool choice unsupported')
    out['function_call']=choice
    if functions:out['functions']=functions
    if 'messages' in out:out['messages']=giga_messages(out['messages'],function_states)
    return out


def giga_messages(messages,function_states=None):
    if not isinstance(messages,list):raise Failure('tool protocol')
    output=[];index=0
    while index<len(messages):
        message=messages[index]
        if not isinstance(message,dict):raise Failure('tool protocol')
        role=message.get('role');calls=message.get('tool_calls')
        if role=='assistant' and calls:
            if not isinstance(calls,list) or len(calls)>128:raise Failure('tool protocol')
            results=messages[index+1:index+1+len(calls)]
            if len(results)!=len(calls) or any(not isinstance(result,dict) or result.get('role')!='tool' for result in results):raise Failure('tool protocol')
            used=set()
            for position,call in enumerate(calls):
                function=call.get('function') if isinstance(call,dict) else None
                identity=call.get('id') if isinstance(call,dict) else None
                if not isinstance(identity,str) or not identity or identity in used or not isinstance(function,dict):raise Failure('tool protocol')
                used.add(identity)
                matching=[result for result in results if result.get('tool_call_id')==identity]
                if len(matching)!=1:raise Failure('tool protocol')
                name=function.get('name');arguments=function.get('arguments')
                if not isinstance(name,str) or not name or not isinstance(arguments,str):raise Failure('tool protocol')
                try:arguments=strict(arguments.encode(),2*1024*1024)
                except (ValueError,UnicodeError):raise Failure('tool protocol') from None
                if not isinstance(arguments,dict):raise Failure('tool protocol')
                content=message.get('content') if position==0 else ''
                if content is None:content=''
                if not isinstance(content,str):raise Failure('tool protocol')
                assistant={'role':'assistant','content':content,'function_call':{'name':name,'arguments':arguments}}
                if function_states is not None and identity in function_states:assistant['functions_state_id']=function_states[identity]
                output.append(assistant)
                text=matching[0].get('content')
                if text is None:text=''
                if not isinstance(text,str):raise Failure('tool protocol')
                try:parsed=strict(text.encode(),4*1024*1024)
                except (ValueError,UnicodeError):parsed=text
                if not isinstance(parsed,dict):parsed={'result':parsed}
                output.append({'role':'function','name':name,'content':json.dumps(parsed,ensure_ascii=True,allow_nan=False,separators=(',',':'))})
            index+=len(calls)+1
        else:
            if role=='tool' or calls not in (None,[]):raise Failure('tool protocol')
            content=message.get('content')
            if content is None:content=''
            if not isinstance(role,str) or not isinstance(content,str):raise Failure('tool protocol')
            value={'role':role,'content':content}
            output.append(value);index+=1
    return output


def openai_response(value,function_states=None):
    if not isinstance(value,dict) or not isinstance(value.get('choices'),list):return value
    output=dict(value);choices=[]
    for original in output['choices']:
        choice=original
        if isinstance(choice,dict) and isinstance(choice.get('message'),dict) and choice['message'].get('function_call') is not None:
            call=choice['message']['function_call']
            if not isinstance(call,dict):raise Failure('tool protocol')
            name=call.get('name');arguments=call.get('arguments')
            if not isinstance(name,str) or not name or not isinstance(arguments,dict):raise Failure('tool protocol')
            choice=dict(choice);message=dict(choice['message']);message.pop('function_call',None)
            identity='call_'+uuid.uuid4().hex;state=message.pop('functions_state_id',None)
            if function_states is not None and state is not None:
                if not isinstance(state,str) or not state or len(state)>4096:raise Failure('tool protocol')
                if identity not in function_states and len(function_states)>=128:raise Failure('tool state bound')
                function_states[identity]=state
            message['tool_calls']=[{'id':identity,'type':'function','function':{
                'name':name,'arguments':json.dumps(arguments,ensure_ascii=True,allow_nan=False,separators=(',',':'))}}]
            choice['message']=message
            if choice.get('finish_reason')=='function_call':choice['finish_reason']='tool_calls'
        choices.append(choice)
    output['choices']=choices
    return output


class HttpsExchange:
    def __init__(self,deadline,request_timeout,idle_timeout,parse):
        self.deadline=deadline;self.request_timeout=request_timeout;self.idle_timeout=idle_timeout;self.parse=parse;self.cancelled=None

    def __call__(self,operation,authorization,body,cancelled=None):
        def is_cancelled():
            for source in (self.cancelled,cancelled):
                if source is None:continue
                if source.is_set() if hasattr(source,'is_set') else source():return True
            return False
        connection=None;response=None;watcher=None;transport=[];stop_watch=threading.Event()
        try:
            if operation=='oauth':
                host='ngw.devices.sberbank.ru';port=9443;path='/api/v2/oauth';content_type='application/x-www-form-urlencoded'
                payload=urllib.parse.urlencode(body).encode()
            elif operation=='chat':
                host='api.giga.chat';port=443;path='/v1/chat/completions';content_type='application/json'
                payload=json.dumps(body,ensure_ascii=True,allow_nan=False,separators=(',',':')).encode()
            else:raise Failure('upstream operation')
            remaining=self.deadline-time.monotonic()
            if remaining<=0 or len(payload)>2*1024*1024:raise Failure('upstream deadline/size')
            if is_cancelled():raise Failure('upstream cancelled')
            connection=http.client.HTTPSConnection(host,port,timeout=min(1.0,remaining,self.request_timeout),context=ssl.create_default_context())
            exchange_deadline=min(self.deadline,time.monotonic()+self.request_timeout)
            def abort():
                sock=transport[0] if transport else connection.sock
                if sock:
                    try:sock.shutdown(socket.SHUT_RDWR)
                    except OSError:pass
                    try:sock.close()
                    except OSError:pass
            def watch():
                while not stop_watch.wait(.02):
                    if time.monotonic()>=exchange_deadline or is_cancelled():abort();return
            watcher=threading.Thread(target=watch,daemon=True);watcher.start()
            headers={'Authorization':authorization,'Content-Type':content_type,'Accept':'application/json'}
            if operation=='oauth':headers['RqUID']=str(uuid.uuid4())
            connection.request('POST',path,body=payload,headers=headers)
            if connection.sock:transport.append(connection.sock)
            response=connection.getresponse();raw=bytearray()
            while True:
                remaining=min(self.deadline,exchange_deadline)-time.monotonic()
                if remaining<=0:raise Failure('upstream deadline/size')
                if is_cancelled():raise Failure('upstream cancelled')
                sock=transport[0] if transport else connection.sock
                if sock:sock.settimeout(min(remaining,self.idle_timeout))
                chunk=response.read1(min(65536,4*1024*1024+1-len(raw)))
                if not chunk:break
                raw.extend(chunk)
                if len(raw)>4*1024*1024:raise Failure('upstream response size')
            if time.monotonic()>=exchange_deadline:raise Failure('upstream deadline/size')
            if is_cancelled():raise Failure('upstream cancelled')
            if 300<=response.status<400:raise Failure('upstream redirect')
            value=self.parse(bytes(raw),4*1024*1024)
            if not isinstance(value,dict):raise Failure('upstream response shape')
            return response.status,value
        except (OSError,ValueError,http.client.HTTPException):
            raise Failure('upstream exchange') from None
        finally:
            stop_watch.set()
            if watcher:watcher.join(timeout=1)
            if response and hasattr(response,'close'):
                try:response.close()
                except OSError:pass
            if transport:
                try:transport[0].close()
                except OSError:pass
            if connection:
                try:connection.close()
                except OSError:pass


class GigaChatUpstream:
    def __init__(self,credential,scope,exchange,now=time.time):
        if not isinstance(credential,str) or not credential or '\r' in credential or '\n' in credential:raise Failure('credential shape')
        original=credential;credential=credential.removeprefix('Basic ')
        if len(credential)<8:raise Failure('credential shape')
        self.credential=credential;self.scope=scope;self.exchange=exchange;self.now=now;self.secrets={original,credential}
        self.token=None;self.expires_at=0

    def call(self,operation,authorization,body,cancelled):
        if cancelled is None:return self.exchange(operation,authorization,body)
        return self.exchange(operation,authorization,body,cancelled=cancelled)

    def refresh(self,cancelled=None):
        status,value=self.call('oauth','Basic '+self.credential,{'scope':self.scope},cancelled)
        if status!=200 or not isinstance(value,dict):raise Failure('oauth response')
        token=value.get('access_token');expires=value.get('expires_at')
        if not isinstance(token,str) or len(token)<8 or type(expires) is not int:raise Failure('oauth response')
        if expires>100_000_000_000:expires//=1000
        if expires<=self.now():raise Failure('oauth expiry')
        self.token=token;self.expires_at=expires;self.secrets.add(token)

    def chat(self,body,cancelled=None):
        for attempt in range(2):
            if self.token is None or self.expires_at<=self.now()+60:self.refresh(cancelled)
            status,value=self.call('chat','Bearer '+self.token,body,cancelled)
            if status!=401 or attempt==1:return status,value
            self.token=None
        raise AssertionError('unreachable')
