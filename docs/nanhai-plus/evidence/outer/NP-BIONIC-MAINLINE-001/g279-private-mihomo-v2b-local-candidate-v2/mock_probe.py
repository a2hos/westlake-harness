#!/usr/bin/env python3
"""Credential-free exact-binary rule oracle; loopback SOCKS only."""
import datetime,hashlib,json,os,pathlib,secrets,shutil,signal,socket,subprocess,sys,time

HERE=pathlib.Path(__file__).resolve().parent
ROOT=HERE.parents[5]
os.environ.setdefault('NANHAI_PROJECT_ROOT',str(ROOT))
import importlib.util
spec=importlib.util.spec_from_file_location('v2b',HERE/'runner.py')
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
up=v.load_upstream()
def sha(b):return hashlib.sha256(b).hexdigest()
def port():
 with socket.socket() as s:
  s.bind(('127.0.0.1',0));return s.getsockname()[1]
runtime=ROOT/'.nanhai-plus-runtime/bionic-oh7-aosp16/proxy-pilot-g279-v2b-v2-mock'
runtime.mkdir(mode=0o700,parents=True,exist_ok=True)
if runtime.is_symlink() or runtime.stat().st_uid!=os.getuid() or runtime.stat().st_mode&0o777!=0o700:raise SystemExit('unsafe_runtime')
d=runtime/('once-'+secrets.token_hex(8));d.mkdir(mode=0o700)
listen=port()
config={
 'mode':'rule','allow-lan':False,'bind-address':'127.0.0.1','mixed-port':listen,'ipv6':False,
 'log-level':'debug','dns':{'enable':False},'tun':{'enable':False},'profile':{'store-selected':False},
 'external-controller':'','external-controller-unix':'',
 'proxies':[{'name':'fixture-only-loopback','type':'socks5','server':'127.0.0.1','port':9}],
 'proxy-groups':[{'name':'PROXY','type':'select','proxies':['fixture-only-loopback']}],
 'rules':up.RULES.copy()}
data=up.yaml.safe_dump(config,sort_keys=False).encode()
up.write_once(d/'mock.yaml',data,0o600)
raw_out=d/'stdout.raw';raw_err=d/'stderr.raw';proc=None;answer=None;decision='NO_GO';clean=False
try:
 if up.file_sha(up.BIN)!=up.BIN_SHA or up.file_sha(up.SANDBOX)!=up.SANDBOX_SHA:raise ValueError('binary_drift')
 env={**os.environ,'HOME':str(d),'TMPDIR':str(d),'XDG_CONFIG_HOME':str(d),'XDG_CACHE_HOME':str(d)}
 for k in list(env):
  if 'proxy' in k.lower():env.pop(k)
 with raw_out.open('xb') as fo,raw_err.open('xb') as fe:
  proc=subprocess.Popen([str(up.SANDBOX),'-p',v.POLICY,str(up.BIN),'-d',str(d),'-f',str(d/'mock.yaml')],cwd=ROOT,env=env,stdout=fo,stderr=fe,start_new_session=True)
  for _ in range(50):
   if proc.poll() is not None:raise ValueError('mock_exit')
   rows=v.listener_rows(listen)
   if rows:
    v.listener_gate(listen,proc.pid);break
   time.sleep(.1)
  else:raise ValueError('mock_listener_timeout')
  with socket.create_connection(('127.0.0.1',listen),timeout=3) as s:
   s.settimeout(3)
   s.sendall(b'\x05\x01\x00')
   if v.recv_exact(s,2)!=b'\x05\x00':raise ValueError('mock_handshake')
   s.sendall(b'\x05\x01\x00\x01'+socket.inet_aton(v.NEGATIVE_IP)+v.NEGATIVE_PORT.to_bytes(2,'big'))
   reply=v.complete_reply(s)
   try:post=s.recv(1);post_state='eof' if post==b'' else 'data'
   except socket.timeout:post_state='timeout'
  answer=reply.hex()
  decision='OBSERVED_FULL_REPLY'
finally:
 if proc is not None:clean=up.stop_group(proc)
 if not clean or v.listener_rows(listen):
  decision='NO_GO_PROCESS_UNPROVEN_PRIVATE_RETAINED'
 else:
  (HERE/'MOCK-STDOUT.raw').write_bytes(raw_out.read_bytes())
  (HERE/'MOCK-STDERR.raw').write_bytes(raw_err.read_bytes())
  (HERE/'MOCK-CONFIG.yaml').write_bytes(data)
  receipt={'schema':'g279-v2b-v2-exact-binary-mock-oracle-v1','at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'decision':decision,'binary_sha256':up.BIN_SHA,'sandbox_sha256':up.SANDBOX_SHA,'policy_sha256':sha(v.POLICY.encode()),'config_sha256':sha(data),'rules':up.RULES,'mock_node':'socks5:127.0.0.1:9','target':v.NEGATIVE_IP+':'+str(v.NEGATIVE_PORT),'reply_hex':answer,'post_reply':locals().get('post_state'),'process_group_clean':clean,'listener_after_stop':False,'stdout_sha256':up.file_sha(raw_out) if raw_out.exists() else None,'stderr_sha256':up.file_sha(raw_err) if raw_err.exists() else None,'stdout_bytes':raw_out.stat().st_size if raw_out.exists() else None,'stderr_bytes':raw_err.stat().st_size if raw_err.exists() else None,'exact_route_event_sha256':v.route_event_digest(raw_out.read_bytes()+b'\n'+raw_err.read_bytes()),'real_node_credentials':False,'gz02_requests':0,'device_commands':0,'container_commands':0,'namespace_commands':0}
  (HERE/'MOCK-ORACLE.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
  shutil.rmtree(d)
print(json.dumps({'decision':decision,'reply_hex':answer,'post_reply':locals().get('post_state'),'process_group_clean':clean}))
sys.exit(0 if decision=='OBSERVED_FULL_REPLY' and clean else 2)
