"""Host-only GigaChat OAuth and bounded HTTPS transport."""
import http.client
import json
import ssl
import time
import urllib.parse

from host_docker import Failure


class HttpsExchange:
    def __init__(self,deadline,request_timeout,idle_timeout,parse):
        self.deadline=deadline;self.request_timeout=request_timeout;self.idle_timeout=idle_timeout;self.parse=parse

    def __call__(self,operation,authorization,body):
        connection=None
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
            connection=http.client.HTTPSConnection(host,port,timeout=min(1.0,remaining,self.request_timeout),context=ssl.create_default_context())
            connection.request('POST',path,body=payload,headers={'Authorization':authorization,'Content-Type':content_type,'Accept':'application/json'})
            response=connection.getresponse();raw=bytearray()
            while True:
                remaining=self.deadline-time.monotonic()
                if remaining<=0:raise Failure('upstream deadline/size')
                if connection.sock:connection.sock.settimeout(min(remaining,self.idle_timeout))
                chunk=response.read1(min(65536,4*1024*1024+1-len(raw)))
                if not chunk:break
                raw.extend(chunk)
                if len(raw)>4*1024*1024:raise Failure('upstream response size')
            if 300<=response.status<400:raise Failure('upstream redirect')
            value=self.parse(bytes(raw),4*1024*1024)
            if not isinstance(value,dict):raise Failure('upstream response shape')
            return response.status,value
        except (OSError,ValueError,http.client.HTTPException):
            raise Failure('upstream exchange') from None
        finally:
            if connection:
                try:connection.close()
                except OSError:pass


class GigaChatUpstream:
    def __init__(self,credential,scope,exchange,now=time.time):
        if not isinstance(credential,str) or not credential or '\r' in credential or '\n' in credential:raise Failure('credential shape')
        credential=credential.removeprefix('Basic ')
        if not credential:raise Failure('credential shape')
        self.credential=credential;self.scope=scope;self.exchange=exchange;self.now=now
        self.token=None;self.expires_at=0

    def refresh(self):
        status,value=self.exchange('oauth','Basic '+self.credential,{'scope':self.scope})
        if status!=200 or not isinstance(value,dict):raise Failure('oauth response')
        token=value.get('access_token');expires=value.get('expires_at')
        if not isinstance(token,str) or not token or type(expires) is not int:raise Failure('oauth response')
        if expires>100_000_000_000:expires//=1000
        if expires<=self.now():raise Failure('oauth expiry')
        self.token=token;self.expires_at=expires

    def chat(self,body):
        for attempt in range(2):
            if self.token is None or self.expires_at<=self.now()+60:self.refresh()
            status,value=self.exchange('chat','Bearer '+self.token,body)
            if status!=401 or attempt==1:return status,value
            self.token=None
        raise AssertionError('unreachable')
