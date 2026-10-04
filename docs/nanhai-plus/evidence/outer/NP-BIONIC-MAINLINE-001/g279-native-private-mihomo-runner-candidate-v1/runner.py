#!/usr/bin/env python3
"""One-shot native private proxy pilot. No action without exact root release."""
import base64,datetime,hashlib,http.client,ipaddress,json,os,pathlib,re,secrets,shutil,signal,socket,stat,subprocess,sys,time,urllib.parse
import yaml

HERE=pathlib.Path(__file__).resolve().parent
ROOT=pathlib.Path(os.environ['NANHAI_PROJECT_ROOT'])
SOURCE=pathlib.Path.home()/'Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml'
SOURCE_SHA='6d11128415287b191dff62c1d28095e01b4d559ef57847c78f188077b9c411a1'
BIN=pathlib.Path('/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo')
BIN_SHA='c15a8c12c461404f3f09368146538c5d32b1b728cd5e1b28885c103ffd7ed9d0'
PRIVATE_ROOT=ROOT/'.nanhai-plus-runtime/bionic-oh7-aosp16/proxy-pilot-g279'
KNOWN_HOSTS=pathlib.Path.home()/'.ssh/known_hosts'
ALIAS='[1.95.90.207]:58222'
HOST_FINGERPRINT='SHA256:RuAqHWgFJEIEcb4hC+WXULCRfV3uCsayP4Iw4aJvwzg'
RULES=['IP-CIDR,1.95.90.207/32,PROXY,no-resolve','MATCH,REJECT']

def sha(raw):return hashlib.sha256(raw).hexdigest()
def file_sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def safe_read(p):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  a=os.fstat(fd)
  if not stat.S_ISREG(a.st_mode):raise ValueError('not_regular')
  chunks=[]
  while True:
   b=os.read(fd,1<<20)
   if not b:break
   chunks.append(b)
  z=os.fstat(fd)
  if any(getattr(a,k)!=getattr(z,k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_mode','st_uid')):raise ValueError('source_changed')
  return b''.join(chunks)
 finally:os.close(fd)
def exclusive_json(p,x,mode=0o644):
 b=(json.dumps(x,sort_keys=True,separators=(',',':'))+'\n').encode()
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
 try:
  view=memoryview(b)
  while view:view=view[os.write(fd,view):]
  os.fsync(fd)
 finally:os.close(fd)
 return sha(b)
def nonce():return secrets.token_hex(16)

def active_source_path_is_exact(ps_text,source=SOURCE):
 d=re.search(r' -d (.*?) -f ',ps_text);f=re.search(r' -f (.*?) -ext-ctl-unix ',ps_text)
 return bool(d and f and d.group(1)==str(source.parent) and f.group(1)==str(source))
def validate_source_structure(x):
 if x.get('mode')!='rule' or x.get('proxy-providers') or x.get('rule-providers'):raise ValueError('source_structure')
 groups=x.get('proxy-groups') or [];proxies=x.get('proxies') or []
 if len([g for g in groups if g.get('name')=='PROXY' and g.get('type')=='select'])!=1:raise ValueError('source_proxy_group')
 names=[p.get('name') for p in proxies]
 if not names or len(names)!=len(set(names)):raise ValueError('source_proxy_names')
 if any(not all(p.get(k) for k in ('name','type','server','port')) for p in proxies):raise ValueError('source_proxy_fields')
 if any(any('file' in k.lower() or 'path' in k.lower() or 'certificate' in k.lower() or 'private-key' in k.lower() for k in p) for p in proxies):raise ValueError('source_external_file')
 return {p['name']:p for p in proxies},{g['name'] for g in groups}
def resolve_leaf(start,lookup,raw_names,group_names):
 seen=set();name=start
 while True:
  if not isinstance(name,str) or not name or name in seen or name in ('DIRECT','REJECT','GLOBAL'):raise ValueError('unsafe_leaf')
  seen.add(name)
  if name in raw_names and name not in group_names:return name
  if name not in group_names:raise ValueError('unknown_leaf')
  name=lookup(name)

class UnixHTTP(http.client.HTTPConnection):
 def __init__(self,path):super().__init__('localhost',timeout=3);self.path=path
 def connect(self):
  s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(3);s.connect(self.path);self.sock=s
def controller_now(sock_path,secret,name):
 path='/proxies/'+urllib.parse.quote(name,safe='')
 conn=UnixHTTP(str(sock_path))
 try:
  conn.request('GET',path,headers={'Authorization':'Bearer '+secret,'Accept':'application/json'})
  r=conn.getresponse();body=r.read(1<<20)
  if r.status!=200 or len(body)>=1<<20:raise ValueError('controller_response')
  x=json.loads(body)
  if not isinstance(x,dict) or not isinstance(x.get('now'),str):raise ValueError('controller_shape')
  return x['now']
 finally:conn.close()
def current_leaf(x,raw,groups):
 sock_path=pathlib.Path(x.get('external-controller-unix') or '')
 secret=x.get('secret')
 if not sock_path.is_absolute() or sock_path.is_symlink() or not isinstance(secret,str) or not secret:raise ValueError('controller_identity')
 st=sock_path.stat()
 if not stat.S_ISSOCK(st.st_mode) or st.st_uid!=os.getuid():raise ValueError('controller_socket')
 return resolve_leaf('PROXY',lambda name:controller_now(sock_path,secret,name),set(raw),groups)
def private_model(node,port):
 if not 20000<=port<=60999 or not isinstance(node,dict):raise ValueError('port_or_node')
 name=node.get('name')
 if not name or name in ('DIRECT','REJECT','PROXY','GLOBAL'):raise ValueError('node_name')
 return {'mode':'rule','allow-lan':False,'bind-address':'127.0.0.1','mixed-port':port,'ipv6':False,'log-level':'warning','dns':{'enable':False},'tun':{'enable':False},'profile':{'store-selected':False},'external-controller':'','external-controller-unix':'','proxies':[node],'proxy-groups':[{'name':'PROXY','type':'select','proxies':[name]}],'rules':RULES.copy()}
def validate_private_model(x):
 if x.get('rules')!=RULES or x.get('mode')!='rule' or x.get('allow-lan') is not False or x.get('bind-address')!='127.0.0.1':raise ValueError('rules_or_bind')
 if x.get('dns')!={'enable':False} or x.get('tun')!={'enable':False} or x.get('profile')!={'store-selected':False}:raise ValueError('background_feature')
 if x.get('external-controller') or x.get('external-controller-unix') or x.get('secret') or x.get('prepend-rules'):raise ValueError('controller_or_prepend')
 p=x.get('proxies');g=x.get('proxy-groups')
 if not isinstance(p,list) or len(p)!=1 or not isinstance(g,list) or len(g)!=1 or g[0]!={'name':'PROXY','type':'select','proxies':[p[0].get('name')]}:raise ValueError('node_cardinality')
 if p[0].get('name') in ('DIRECT','REJECT','PROXY','GLOBAL'):raise ValueError('direct_node')
 return True
def negative_route(ip):
 return 'PROXY' if ipaddress.ip_address(ip) in ipaddress.ip_network('1.95.90.207/32') else 'REJECT'

def release_check(path):
 raw=safe_read(path);x=json.loads(raw)
 expected={'schema','decision','candidate_sha256','runner_sha256','source_sha256','binary_sha256','port','nonce_policy','host','ssh_port','readonly_only','device','container','global_config_write'}
 if set(x)!=expected or x['schema']!='g279-private-mihomo-root-release-v1' or x['decision']!='ISSUE_EXACT_PRIVATE_PROXY_READONLY_HANDSHAKE_ONCE' or x['candidate_sha256']!=file_sha(HERE/'CANDIDATE.json') or x['runner_sha256']!=file_sha(pathlib.Path(__file__)) or x['source_sha256']!=SOURCE_SHA or x['binary_sha256']!=BIN_SHA or x['nonce_policy']!='fresh_runtime_generated' or x['host']!='1.95.90.207' or x['ssh_port']!=58222 or x['readonly_only'] is not True or any(x[k] is not False for k in ('device','container','global_config_write')) or not isinstance(x['port'],int) or not 20000<=x['port']<=60999:raise ValueError('release_drift')
 return x,sha(raw)
def ensure_known_host():
 if KNOWN_HOSTS.is_symlink() or KNOWN_HOSTS.resolve(strict=True)!=KNOWN_HOSTS:raise ValueError('known_hosts_path')
 rows=[r.split() for r in safe_read(KNOWN_HOSTS).decode().splitlines() if r.startswith(ALIAS+' ')]
 keys=[r[2] for r in rows if len(r)>=3 and r[1]=='ssh-ed25519']
 if len(keys)!=1:raise ValueError('host_key_count')
 key=base64.b64decode(keys[0],validate=True)
 got='SHA256:'+base64.b64encode(hashlib.sha256(key).digest()).decode().rstrip('=')
 if got!=HOST_FINGERPRINT:raise ValueError('host_fingerprint')
 return got
def ssh_argv(port):
 proxy=f'/usr/bin/nc -X 5 -x 127.0.0.1:{port} -w 8 1.95.90.207 58222'
 opts=['-F','/dev/null','-o','User=AlexYang','-o','HostName=1.95.90.207','-o','Port=58222','-o','ProxyCommand='+proxy,'-o','ProxyJump=none','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','HostKeyAlgorithms=ssh-ed25519','-o','ConnectTimeout=10','-o','UserKnownHostsFile='+str(KNOWN_HOSTS),'-o','GlobalKnownHostsFile=/dev/null','-o','CanonicalizeHostname=no','-o','CheckHostIP=no','-o','HostKeyAlias='+ALIAS,'-o','RequestTTY=no']
 return ['/usr/bin/ssh',*opts,'gz02','/usr/bin/true'],proxy
def verify_ssh_config(port):
 argv,proxy=ssh_argv(port)
 out=subprocess.run(['/usr/bin/ssh','-G',*argv[1:-1]],capture_output=True,timeout=5,check=True).stdout.decode().splitlines()
 values=dict(r.split(' ',1) for r in out if ' ' in r)
 want={'user':'AlexYang','hostname':'1.95.90.207','port':'58222','proxycommand':proxy,'proxyjump':'none','hostkeyalias':ALIAS,'canonicalizehostname':'false','globalknownhostsfile':'/dev/null','userknownhostsfile':str(KNOWN_HOSTS),'checkhostip':'no','hostkeyalgorithms':'ssh-ed25519','stricthostkeychecking':'true'}
 if any(values.get(k,'none')!=v for k,v in want.items()):raise ValueError('ssh_config_drift')
 return argv

def private_dir(token):
 if not PRIVATE_ROOT.exists():PRIVATE_ROOT.mkdir(mode=0o700,parents=True)
 st=PRIVATE_ROOT.lstat()
 if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)!=0o700 or PRIVATE_ROOT.is_symlink():raise ValueError('private_root_mode')
 check=subprocess.run(['/usr/bin/git','check-ignore','-q',str(PRIVATE_ROOT/'private.yaml')],cwd=ROOT)
 if check.returncode!=0:raise ValueError('runtime_not_gitignored')
 d=PRIVATE_ROOT/('once-'+token);d.mkdir(mode=0o700,exist_ok=False)
 return d
def private_write(p,raw):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  view=memoryview(raw)
  while view:view=view[os.write(fd,view):]
  os.fsync(fd)
 finally:os.close(fd)
 if stat.S_IMODE(p.stat().st_mode)!=0o600:raise ValueError('private_mode')
def command_gate(name,argv,d,timeout):
 proc=subprocess.run(argv,cwd=ROOT,env={**os.environ,'HOME':str(d),'XDG_CONFIG_HOME':str(d),'XDG_CACHE_HOME':str(d),'TMPDIR':str(d)},capture_output=True,timeout=timeout,check=False)
 private_write(d/(name+'-stdout.raw'),proc.stdout);private_write(d/(name+'-stderr.raw'),proc.stderr)
 return {'gate':name,'rc':proc.returncode,'stdout_sha256':sha(proc.stdout),'stderr_sha256':sha(proc.stderr),'stdout_bytes':len(proc.stdout),'stderr_bytes':len(proc.stderr)}
def listener_owned(pid,port):
 x=subprocess.run(['/usr/sbin/lsof','-nP','-iTCP:'+str(port),'-sTCP:LISTEN'],capture_output=True,text=True,timeout=3)
 rows=x.stdout.splitlines()[1:]
 return x.returncode==0 and len(rows)==1 and len(rows[0].split())>=9 and rows[0].split()[1]==str(pid) and rows[0].split()[-1]=='127.0.0.1:'+str(port)
def socks_reject(port):
 with socket.create_connection(('127.0.0.1',port),timeout=3) as s:
  s.settimeout(3);s.sendall(b'\x05\x01\x00')
  if s.recv(2)!=b'\x05\x00':raise ValueError('socks_auth')
  s.sendall(b'\x05\x01\x00\x01'+ipaddress.ip_address('203.0.113.1').packed+(9).to_bytes(2,'big'))
  b=s.recv(4)
  if len(b)<2 or b[0]!=5 or b[1]==0:raise ValueError('negative_not_rejected')
  return b[1]
def stop_child(child):
 if child is None:return True
 if child.poll() is None:
  os.killpg(child.pid,signal.SIGTERM)
  try:child.wait(timeout=3)
  except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=3)
 return child.poll() is not None

def execute(release_path):
 release,release_sha=release_check(release_path)
 if (HERE/'START.json').exists():raise ValueError('one_shot_consumed')
 token=nonce();port=release['port'];start={'schema':'g279-private-mihomo-start-v1','at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'nonce':token,'release_sha256':release_sha,'runner_sha256':file_sha(pathlib.Path(__file__)),'source_sha256':SOURCE_SHA,'binary_sha256':BIN_SHA,'port':port}
 exclusive_json(HERE/'START.json',start)
 gates=[];d=None;child=None;stage='source';decision='UNKNOWN';failure_class=None;cleanup_ok=False
 try:
  if file_sha(BIN)!=BIN_SHA:raise ValueError('binary_drift')
  raw=safe_read(SOURCE)
  if sha(raw)!=SOURCE_SHA:raise ValueError('source_drift')
  pids=subprocess.check_output(['pgrep','-x','verge-mihomo'],text=True,timeout=3).split()
  if len(pids)!=1:raise ValueError('global_process_count')
  ps=subprocess.check_output(['ps','-p',pids[0],'-o','command='],text=True,timeout=3)
  if not active_source_path_is_exact(ps.strip()):raise ValueError('global_source_path')
  x=yaml.safe_load(raw);nodes,groups=validate_source_structure(x)
  leaf=current_leaf(x,nodes,groups);model=private_model(nodes[leaf],port);validate_private_model(model)
  gates.append({'gate':'source_and_leaf','ok':True,'node_name_emitted':False})
  stage='private_config'
  with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:s.bind(('127.0.0.1',port))
  d=private_dir(token)
  private_write(d/'private.yaml',yaml.safe_dump(model,sort_keys=False,allow_unicode=True).encode())
  gates.append({'gate':'private_config','ok':True,'config_sha256':file_sha(d/'private.yaml'),'config_bytes':(d/'private.yaml').stat().st_size,'config_mode':'0600','private_dir_mode':'0700'})
  stage='mihomo_syntax'
  g=command_gate('syntax',[str(BIN),'-t','-d',str(d),'-f',str(d/'private.yaml')],d,15);gates.append(g)
  if g['rc']!=0:raise ValueError('syntax_rc')
  stage='ssh_preflight'
  ensure_known_host();ssh=verify_ssh_config(port);gates.append({'gate':'ssh_preflight','ok':True,'host_fingerprint':HOST_FINGERPRINT})
  stage='start'
  out=d/'mihomo-stdout.raw';err=d/'mihomo-stderr.raw'
  fo=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);fe=os.open(err,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  try:child=subprocess.Popen([str(BIN),'-d',str(d),'-f',str(d/'private.yaml')],cwd=ROOT,env={**os.environ,'HOME':str(d),'XDG_CONFIG_HOME':str(d),'XDG_CACHE_HOME':str(d),'TMPDIR':str(d)},stdout=fo,stderr=fe,start_new_session=True)
  finally:os.close(fo);os.close(fe)
  ready=False
  for _ in range(20):
   if child.poll() is not None:break
   if listener_owned(child.pid,port):ready=True;break
   time.sleep(.2)
  gates.append({'gate':'start_and_listener','ok':ready,'pid':child.pid,'only_pid_loopback':ready})
  if not ready:raise ValueError('listener')
  stage='negative_probe'
  reject_code=socks_reject(port);gates.append({'gate':'negative_probe','ok':True,'socks_reply_code':reject_code,'target':'203.0.113.1:9'})
  stage='gz02_readonly_handshake'
  g=command_gate('ssh',ssh,d,25);gates.append(g)
  if g['rc']!=0:raise ValueError('ssh_rc')
  decision='GO_GZ02_READONLY_HANDSHAKE_ONLY'
 except BaseException as e:
  decision='NO_GO_'+stage.upper();failure_class=type(e).__name__
 finally:
  stage='cleanup'
  try:
   stopped=stop_child(child)
   if not stopped:raise ValueError('child_not_stopped')
   no_listener=not listener_owned(child.pid,port) if child else True
   if d is not None:
    st=d.lstat()
    if not stat.S_ISDIR(st.st_mode) or d.is_symlink() or st.st_uid!=os.getuid():raise ValueError('cleanup_dir_identity')
    shutil.rmtree(d)
   cleanup_ok=stopped and no_listener and (d is None or not d.exists())
  except BaseException as e:
   failure_class=type(e).__name__;cleanup_ok=False
  gates.append({'gate':'cleanup','ok':cleanup_ok,'child_stopped':child is None or child.poll() is not None,'private_dir_absent':d is None or not d.exists()})
  if not cleanup_ok:decision='NO_GO_CLEANUP'
  terminal={'schema':'g279-private-mihomo-terminal-v1','at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'nonce':token,'decision':decision,'failure_class':failure_class,'gates':gates,'release_sha256':release_sha,'source_sha256':SOURCE_SHA,'binary_sha256':BIN_SHA,'credential_bytes_in_evidence':False,'global_config_writes':0,'device_commands':0,'container_commands':0}
  exclusive_json(HERE/'TERMINAL.json',terminal)
 print(json.dumps({'decision':decision,'terminal_sha256':file_sha(HERE/'TERMINAL.json'),'nonce':token}))
 return 0 if decision=='GO_GZ02_READONLY_HANDSHAKE_ONLY' else 2
def main():
 if len(sys.argv)!=3 or sys.argv[1]!='--execute':raise SystemExit('usage: runner.py --execute <exact-root-release.json>')
 try:return execute(pathlib.Path(sys.argv[2]))
 except BaseException as e:
  print(json.dumps({'decision':'NO_GO_BEFORE_START','failure_class':type(e).__name__}))
  return 2
if __name__=='__main__':sys.exit(main())
