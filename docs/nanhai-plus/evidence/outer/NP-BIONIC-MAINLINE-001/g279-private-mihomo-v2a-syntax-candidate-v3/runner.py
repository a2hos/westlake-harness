#!/usr/bin/env python3
"""G279 v2a: one-shot local private config plus mihomo -t only. Never starts a proxy."""
import datetime,hashlib,http.client,json,os,pathlib,re,secrets,shutil,signal,socket,stat,struct,subprocess,sys,time,urllib.parse
import yaml

HERE=pathlib.Path(__file__).resolve().parent
ROOT=pathlib.Path(os.environ['NANHAI_PROJECT_ROOT'])
SOURCE=pathlib.Path.home()/'Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml'
SOURCE_SHA='6d11128415287b191dff62c1d28095e01b4d559ef57847c78f188077b9c411a1'
BIN=pathlib.Path('/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo')
BIN_SHA='c15a8c12c461404f3f09368146538c5d32b1b728cd5e1b28885c103ffd7ed9d0'
PRIVATE_ROOT=ROOT/'.nanhai-plus-runtime/bionic-oh7-aosp16/proxy-pilot-g279-v2a-v3'
PEER=HERE/'peer-review-v1/REVIEW.json'
RELEASE=HERE/'root-release-v1/ROOT-RELEASE.json'
RULES=['IP-CIDR,1.95.90.207/32,PROXY,no-resolve','MATCH,REJECT']
SANDBOX=pathlib.Path('/usr/bin/sandbox-exec')
SANDBOX_SHA='abc5bb136d6b5cce8fa85d789f78e3326c51ca60cae637b2064adfb67a1dcd9a'
DENY_NETWORK='(version 1)(allow default)(deny network*)(deny process-fork)'
SOL_LOCAL=0;LOCAL_PEERCRED=1;LOCAL_PEERPID=2

def sha(b):return hashlib.sha256(b).hexdigest()
def file_sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def stable_read(p):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  a=os.fstat(fd)
  if not stat.S_ISREG(a.st_mode):raise ValueError('source_not_regular')
  chunks=[]
  while True:
   b=os.read(fd,1<<20)
   if not b:break
   chunks.append(b)
  z=os.fstat(fd)
  if any(getattr(a,k)!=getattr(z,k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_mode','st_uid')):raise ValueError('source_changed')
  return b''.join(chunks)
 finally:os.close(fd)
def write_once(p,b,mode):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
 try:
  v=memoryview(b)
  while v:
   n=os.write(fd,v)
   if n<=0:raise OSError('short_write')
   v=v[n:]
  os.fsync(fd)
 finally:os.close(fd)
def json_once(p,x,mode=0o644):
 b=(json.dumps(x,sort_keys=True,separators=(',',':'))+'\n').encode();write_once(p,b,mode);return sha(b)
def exact_release():
 raw=stable_read(RELEASE);x=json.loads(raw)
 cand=file_sha(HERE/'CANDIDATE.json');runner=file_sha(pathlib.Path(__file__));peer_raw=stable_read(PEER);peer=json.loads(peer_raw)
 if peer.get('decision')!='GO_V2A_SYNTAX_ONLY' or peer.get('candidate_sha256')!=cand:raise ValueError('peer_review_gate')
 want={'schema','decision','candidate_sha256','runner_sha256','peer_review_sha256','source_sha256','binary_sha256','sandbox_sha256','sandbox_policy_sha256','port','scope','no_proxy_start','no_gz02','no_device','no_container','network_attempts_unknown'}
 if set(x)!=want or x['schema']!='g279-private-mihomo-v2a-root-release-v3' or x['decision']!='ISSUE_EXACT_V2A_V3_LOCAL_CONFIG_TEST_ONCE' or x['candidate_sha256']!=cand or x['runner_sha256']!=runner or x['peer_review_sha256']!=sha(peer_raw) or x['source_sha256']!=SOURCE_SHA or x['binary_sha256']!=BIN_SHA or x['sandbox_sha256']!=SANDBOX_SHA or x['sandbox_policy_sha256']!=sha(DENY_NETWORK.encode()) or x['scope']!='private_config_and_sandboxed_mihomo_test_only' or any(x[k] is not True for k in ('no_proxy_start','no_gz02','no_device','no_container','network_attempts_unknown')) or not isinstance(x['port'],int) or not 20000<=x['port']<=60999:raise ValueError('root_release_gate')
 return x,sha(raw)
def active_process():
 pids=subprocess.check_output(['/usr/bin/pgrep','-x','verge-mihomo'],text=True,timeout=3).split()
 if len(pids)!=1:raise ValueError('process_count')
 pid=int(pids[0]);ps=subprocess.check_output(['/bin/ps','-p',str(pid),'-o','uid=','-o','ruid=','-o','comm=','-o','command='],text=True,timeout=3).strip()
 # ps emits one line; command contains spaces in the app bundle path.
 m=re.match(r'^\s*(\d+)\s+(\d+)\s+(.*?)\s+(.+)$',ps)
 if not m or int(m.group(1))!=0 or int(m.group(2))!=0:raise ValueError('process_owner')
 cmd=m.group(4)
 d=re.search(r' -d (.*?) -f ',cmd);f=re.search(r' -f (.*?) -ext-ctl-unix ',cmd)
 if not d or not f or d.group(1)!=str(SOURCE.parent) or f.group(1)!=str(SOURCE) or str(BIN) not in cmd:raise ValueError('process_source_or_binary')
 return pid
def source_structure(x):
 if x.get('mode')!='rule' or x.get('proxy-providers') or x.get('rule-providers'):raise ValueError('source_structure')
 proxies=x.get('proxies') or [];groups=x.get('proxy-groups') or []
 names=[p.get('name') for p in proxies]
 if not names or len(names)!=len(set(names)) or any(not all(p.get(k) for k in ('name','type','server','port')) for p in proxies):raise ValueError('proxy_identity')
 if len([g for g in groups if g.get('name')=='PROXY' and g.get('type')=='select'])!=1:raise ValueError('proxy_group')
 if any(any('file' in k.lower() or 'path' in k.lower() or 'certificate' in k.lower() or 'private-key' in k.lower() for k in p) for p in proxies):raise ValueError('external_proxy_file')
 return {p['name']:p for p in proxies},{g['name'] for g in groups}
ALLOWED={
 'hysteria2':{'name','type','server','port','password','skip-cert-verify','sni'},
 'tuic':{'name','type','server','port','password','uuid','sni','alpn','congestion-controller'},
 'vless':{'name','type','server','port','uuid','client-fingerprint','flow','network','reality-opts','servername','tls','udp','ws-opts'},
 'vmess':{'name','type','server','port','uuid','alterId','cipher','network','servername','tls','ws-opts'},
}
def selected_node_schema(node):
 """Exact local type/key tree; reject external dependencies anywhere in node."""
 if not isinstance(node,dict) or node.get('type') not in ALLOWED or set(node)-ALLOWED[node['type']]:raise ValueError('node_type_or_keys')
 if any(not node.get(k) for k in ('name','type','server','port')) or type(node['port']) is not int or not 1<=node['port']<=65535:raise ValueError('node_identity')
 def scalar(v,*,path=False):
  if not isinstance(v,str) or not v or '\x00' in v or '\n' in v or '\r' in v or 'file://' in v.lower():raise ValueError('node_scalar')
  if path and (not v.startswith('/') or '://' in v or '..' in v or '\\' in v):raise ValueError('ws_relative_path')
  return True
 for k,v in node.items():
  if k=='ws-opts':
   if not isinstance(v,dict) or set(v)!={'path'}:raise ValueError('ws_schema')
   scalar(v['path'],path=True)
  elif k=='reality-opts':
   if not isinstance(v,dict) or set(v)!={'public-key','short-id'}:raise ValueError('reality_schema')
   scalar(v['public-key']);scalar(v['short-id'])
  elif k=='alpn':
   if not isinstance(v,list) or not 1<=len(v)<=8:raise ValueError('alpn_schema')
   for item in v:scalar(item)
  elif k in ('port','alterId'):
   if type(v) is not int or v<0:raise ValueError('node_integer')
  elif k in ('skip-cert-verify','tls','udp'):
   if type(v) is not bool:raise ValueError('node_boolean')
  else:scalar(v)
 return True
def verify_socket_path(path):
 if not path.is_absolute() or path.is_symlink():raise ValueError('socket_path')
 st=path.lstat()
 if not stat.S_ISSOCK(st.st_mode) or st.st_uid!=0:raise ValueError('socket_root_identity')
 return (st.st_dev,st.st_ino,st.st_uid,st.st_mode)
def peer_identity(sock):
 # macOS SDK sys/un.h: SOL_LOCAL=0, LOCAL_PEERCRED=1, LOCAL_PEERPID=2.
 cred=sock.getsockopt(SOL_LOCAL,LOCAL_PEERCRED,256)
 pid_raw=sock.getsockopt(SOL_LOCAL,LOCAL_PEERPID,4)
 if len(cred)<8 or len(pid_raw)!=4:raise ValueError('kernel_peer_shape')
 version,uid=struct.unpack_from('=II',cred)
 pid=struct.unpack('=i',pid_raw)[0]
 if version!=0 or pid<=0:return (None,None)
 return (pid,uid)
def peer_gate(actual_pid,actual_uid,expected_pid):
 if actual_pid!=expected_pid or actual_uid!=0:raise ValueError('controller_peer_identity')
 return True
class UnixHTTP(http.client.HTTPConnection):
 def __init__(self,path,expected_pid):super().__init__('localhost',timeout=3);self.path=path;self.expected_pid=expected_pid
 def connect(self):
  before=verify_socket_path(self.path)
  s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(3)
  try:
   s.connect(str(self.path));pid,uid=peer_identity(s);peer_gate(pid,uid,self.expected_pid)
   if verify_socket_path(self.path)!=before:raise ValueError('socket_replaced')
   self.sock=s
  except BaseException:s.close();raise
def controller_now(path,pid,name):
 conn=UnixHTTP(path,pid)
 try:
  # The current local controller returns HTTP 200 without Authorization.
  # Identity therefore comes from kernel peer PID/UID, not the Bearer header.
  conn.request('GET','/proxies/'+urllib.parse.quote(name,safe=''),headers={'Accept':'application/json'})
  r=conn.getresponse();b=r.read(1<<20)
  if r.status!=200 or len(b)>=1<<20:raise ValueError('controller_auth_or_response')
  x=json.loads(b)
  if not isinstance(x,dict) or not isinstance(x.get('now'),str):raise ValueError('controller_shape')
  return x['now']
 finally:conn.close()
def resolve_leaf(start,lookup,raw_names,group_names):
 seen=set();name=start
 while True:
  if not isinstance(name,str) or not name or name in seen or name in ('DIRECT','REJECT','GLOBAL'):raise ValueError('unsafe_leaf')
  seen.add(name)
  if name in raw_names and name not in group_names:return name
  if name not in group_names:raise ValueError('unknown_leaf')
  name=lookup(name)
def current_leaf(x,pid,nodes,groups):
 path=pathlib.Path(x.get('external-controller-unix') or '')
 verify_socket_path(path)
 return resolve_leaf('PROXY',lambda name:controller_now(path,pid,name),set(nodes),groups)
def fresh_selected_node(initial_pid,initial_socket,initial_leaf):
 """Immediately before credential write, recheck all source/controller identities."""
 raw=stable_read(SOURCE)
 if sha(raw)!=SOURCE_SHA or active_process()!=initial_pid:raise ValueError('source_or_process_changed')
 x=yaml.safe_load(raw);nodes,groups=source_structure(x)
 path=pathlib.Path(x.get('external-controller-unix') or '')
 if verify_socket_path(path)!=initial_socket:raise ValueError('socket_changed')
 leaf=current_leaf(x,initial_pid,nodes,groups)
 if leaf!=initial_leaf or leaf not in nodes:raise ValueError('selection_changed')
 selected_node_schema(nodes[leaf])
 return nodes[leaf]
def minimal_config(node,port):
 if not 20000<=port<=60999 or node.get('name') in ('DIRECT','REJECT','PROXY','GLOBAL'):raise ValueError('node_or_port')
 selected_node_schema(node)
 return {'mode':'rule','allow-lan':False,'bind-address':'127.0.0.1','mixed-port':port,'ipv6':False,'log-level':'silent','dns':{'enable':False},'tun':{'enable':False},'profile':{'store-selected':False},'external-controller':'','external-controller-unix':'','proxies':[dict(node)],'proxy-groups':[{'name':'PROXY','type':'select','proxies':[node['name']]}],'rules':RULES.copy()}
def config_gate(x):
 if x.get('rules')!=RULES or x.get('mode')!='rule' or x.get('allow-lan') is not False or x.get('bind-address')!='127.0.0.1' or x.get('dns')!={'enable':False} or x.get('tun')!={'enable':False} or x.get('profile')!={'store-selected':False} or x.get('external-controller') or x.get('external-controller-unix') or x.get('secret') or x.get('prepend-rules'):raise ValueError('config_scope')
 p=x.get('proxies');g=x.get('proxy-groups')
 if not isinstance(p,list) or len(p)!=1 or not isinstance(g,list) or g!=[{'name':'PROXY','type':'select','proxies':[p[0].get('name')]}]:raise ValueError('config_node_count')
 if p[0].get('name') in ('DIRECT','REJECT','PROXY','GLOBAL'):raise ValueError('config_direct')
 return True
def private_dir(token):
 if not PRIVATE_ROOT.exists():PRIVATE_ROOT.mkdir(mode=0o700,parents=True)
 st=PRIVATE_ROOT.lstat()
 if not stat.S_ISDIR(st.st_mode) or PRIVATE_ROOT.is_symlink() or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)!=0o700:raise ValueError('private_root')
 q=subprocess.run(['/usr/bin/git','check-ignore','-q',str(PRIVATE_ROOT/'private.yaml')],cwd=ROOT,timeout=3)
 if q.returncode!=0:raise ValueError('git_ignore_absent')
 d=PRIVATE_ROOT/('once-'+token);d.mkdir(mode=0o700,exist_ok=False);return d
def syntax_category(stderr):
 low=stderr.lower()
 for key in (b'unsupported',b'invalid',b'parse',b'proxy',b'rule',b'port',b'permission',b'timeout'):
  if key in low:return key.decode()
 return 'other_or_empty'
def sandbox_denial_probe():
 """Local loopback attempt must be blocked by the exact no-network policy."""
 with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as listener:
  listener.bind(('127.0.0.1',0));listener.listen(1)
  port=listener.getsockname()[1]
  code='import socket,sys; s=socket.socket(); s.settimeout(1); s.connect(("127.0.0.1",int(sys.argv[1]))); print("CONNECTED")'
  p=subprocess.run([str(SANDBOX),'-p',DENY_NETWORK,sys.executable,'-I','-B','-c',code,str(port)],capture_output=True,timeout=5,check=False)
  if p.returncode==0 or b'CONNECTED' in p.stdout or b'Operation not permitted' not in p.stderr:raise ValueError('sandbox_network_denial')
  listener.settimeout(.1)
  try:
   c,_=listener.accept();c.close();raise ValueError('sandbox_connection_observed')
  except socket.timeout:pass
 return True
def process_spawn_denial_probe():
 """No-credential fork+setsid and posix_spawn attempts must both get EPERM."""
 fork_code='import os; p=os.fork();\nif p==0:\n os.setsid(); print("ESCAPED",flush=True); os._exit(0)\nos.waitpid(p,0)'
 spawn_code="import os,sys; p=os.posix_spawn(sys.executable,[sys.executable,'-c','print(12345)'],os.environ); os.waitpid(p,0)"
 for code,marker in ((fork_code,b'ESCAPED'),(spawn_code,b'12345')):
  p=subprocess.run([str(SANDBOX),'-p',DENY_NETWORK,sys.executable,'-I','-B','-c',code],capture_output=True,timeout=5,check=False)
  if p.returncode==0 or marker in p.stdout or b'Operation not permitted' not in p.stderr:raise ValueError('sandbox_process_spawn_denial')
 return True
def group_members(pgid):
 out=subprocess.check_output(['/bin/ps','-axo','pid=,pgid=,uid=,stat='],text=True,timeout=3)
 members=[]
 for row in out.splitlines():
  parts=row.split()
  if len(parts)!=4 or parts[1]!=str(pgid):continue
  if int(parts[2])!=os.getuid():raise ValueError('foreign_process_group_member')
  if 'Z' not in parts[3]:members.append(int(parts[0]))
 return members
def stop_group(proc):
 pgid=proc.pid
 for sig in (signal.SIGTERM,signal.SIGKILL):
  proc.poll()  # reap the direct child; a zombie is not a live descendant
  members=group_members(pgid)
  if not members:break
  try:os.killpg(pgid,sig)
  except ProcessLookupError:pass
  for _ in range(15):
   proc.poll()
   if not group_members(pgid):break
   time.sleep(.1)
 try:proc.wait(timeout=1)
 except subprocess.TimeoutExpired:pass
 return not group_members(pgid) and proc.poll() is not None
def syntax_group(d):
 """Seatbelt network denial is inherited by children; kill/read back one PGID."""
 env={**os.environ,'HOME':str(d),'XDG_CONFIG_HOME':str(d),'XDG_CACHE_HOME':str(d),'TMPDIR':str(d)}
 for k in list(env):
  if 'proxy' in k.lower():env.pop(k)
 cmd=[str(SANDBOX),'-p',DENY_NETWORK,str(BIN),'-t','-d',str(d),'-f',str(d/'private.yaml')]
 stdout=d/'syntax-stdout.raw';stderr=d/'syntax-stderr.raw'
 fo=os.open(stdout,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 fe=os.open(stderr,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 proc=None;timed_out=False;clean=False;rc=None
 try:
  proc=subprocess.Popen(cmd,cwd=ROOT,env=env,stdout=fo,stderr=fe,start_new_session=True)
  try:rc=proc.wait(timeout=20)
  except subprocess.TimeoutExpired:timed_out=True
 finally:
  os.close(fo);os.close(fe)
  if proc is not None:clean=stop_group(proc)
 if not clean:raise ValueError('syntax_descendants_survive')
 out=stdout.read_bytes();err=stderr.read_bytes()
 return {'rc':rc,'timed_out':timed_out,'group_clean':clean,'stdout_sha256':sha(out),'stderr_sha256':sha(err),'stdout_bytes':len(out),'stderr_bytes':len(err),'category':syntax_category(err)}
def cleanup(d):
 if d is None:return True
 st=d.lstat()
 if not stat.S_ISDIR(st.st_mode) or d.is_symlink() or st.st_uid!=os.getuid() or d.parent!=PRIVATE_ROOT:raise ValueError('cleanup_identity')
 shutil.rmtree(d)
 return not d.exists()
def execute():
 release,release_sha=exact_release()
 if (HERE/'START.json').exists():raise ValueError('one_shot_consumed')
 token=secrets.token_hex(16)
 json_once(HERE/'START.json',{'schema':'g279-private-v2a-start-v3','at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'nonce':token,'release_sha256':release_sha,'runner_sha256':file_sha(pathlib.Path(__file__)),'source_sha256':SOURCE_SHA,'binary_sha256':BIN_SHA,'sandbox_sha256':SANDBOX_SHA,'sandbox_policy_sha256':sha(DENY_NETWORK.encode()),'scope':'local_config_test_network_attempts_unknown_fork_denied'})
 d=None;stage='network_boundary';rc=None;category=None;log_sha=None;log_bytes=None;config_sha=None;config_bytes=None;cleanup_ok=False;decision='NO_GO';group_clean=True;denial_pass=False;spawn_denial_pass=False
 try:
  if file_sha(BIN)!=BIN_SHA or file_sha(SANDBOX)!=SANDBOX_SHA:raise ValueError('binary_drift')
  denial_pass=sandbox_denial_probe()
  stage='spawn_boundary';spawn_denial_pass=process_spawn_denial_probe()
  stage='source'
  raw=stable_read(SOURCE)
  if sha(raw)!=SOURCE_SHA:raise ValueError('source_drift')
  pid=active_process();x=yaml.safe_load(raw);nodes,groups=source_structure(x)
  stage='controller_leaf';socket_id=verify_socket_path(pathlib.Path(x.get('external-controller-unix') or ''));leaf=current_leaf(x,pid,nodes,groups)
  selected_node_schema(nodes[leaf])
  stage='private_config';d=private_dir(token)
  node=fresh_selected_node(pid,socket_id,leaf)
  config=minimal_config(node,release['port']);config_gate(config)
  b=yaml.safe_dump(config,sort_keys=False,allow_unicode=True).encode();write_once(d/'private.yaml',b,0o600)
  if stat.S_IMODE((d/'private.yaml').stat().st_mode)!=0o600 or file_sha(d/'private.yaml')!=sha(b):raise ValueError('private_config_readback')
  config_sha=sha(b);config_bytes=len(b)
  stage='mihomo_syntax'
  group_clean=False
  result=syntax_group(d);group_clean=result['group_clean']
  rc=result['rc'];log_sha={'stdout':result['stdout_sha256'],'stderr':result['stderr_sha256']};log_bytes={'stdout':result['stdout_bytes'],'stderr':result['stderr_bytes']};category=result['category']
  if result['timed_out'] or rc!=0:raise ValueError('mihomo_syntax_rc_or_timeout')
  decision='GO_V2A_LOCAL_SYNTAX_ONLY'
 except BaseException as e:
  decision='NO_GO_'+stage.upper();category=category or type(e).__name__
 finally:
  if stage=='mihomo_syntax' and not group_clean:
   cleanup_ok=False;decision='NO_GO_DESCENDANTS_UNPROVEN_PRIVATE_RETAINED'
  else:
   try:cleanup_ok=cleanup(d)
   except BaseException:cleanup_ok=False
   if not cleanup_ok:decision='NO_GO_CLEANUP'
  terminal={'schema':'g279-private-v2a-terminal-v3','at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'nonce':token,'decision':decision,'failed_stage':None if decision=='GO_V2A_LOCAL_SYNTAX_ONLY' else stage,'syntax_rc':rc,'syntax_category':category,'syntax_log_sha256':log_sha,'syntax_log_bytes':log_bytes,'private_config_sha256':config_sha,'private_config_bytes':config_bytes,'private_dir_removed':cleanup_ok,'syntax_process_group_clean':group_clean,'sandbox_denial_probe_pass':denial_pass,'sandbox_spawn_denial_pass':spawn_denial_pass,'sandbox_sha256':SANDBOX_SHA,'sandbox_policy_sha256':sha(DENY_NETWORK.encode()),'network_attempts_unknown':True,'release_sha256':release_sha,'source_sha256':SOURCE_SHA,'binary_sha256':BIN_SHA,'credentials_in_evidence':False,'proxy_instance_started':False,'gz02_connected':False,'device_commands':0,'container_commands':0,'namespace_commands':0}
  json_once(HERE/'TERMINAL.json',terminal)
 print(json.dumps({'decision':decision,'terminal_sha256':file_sha(HERE/'TERMINAL.json'),'nonce':token}))
 return 0 if decision=='GO_V2A_LOCAL_SYNTAX_ONLY' else 2
def main():
 if sys.argv[1:]!=['--execute']:raise SystemExit('usage: runner.py --execute')
 try:return execute()
 except BaseException as e:
  print(json.dumps({'decision':'NO_GO_BEFORE_START','failure_class':type(e).__name__}))
  return 2
if __name__=='__main__':sys.exit(main())
