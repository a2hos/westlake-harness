#!/usr/bin/env python3
import datetime, hashlib, json, os, socket, subprocess, sys, time
from pathlib import Path
root=Path(os.environ['NANHAI_PROJECT_ROOT']); env_file=root/'local_env.md'; ssh_cfg=Path.home()/'.ssh/config'; known=Path.home()/'.ssh/known_hosts'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def cmd(argv, timeout):
 st=datetime.datetime.now(datetime.timezone.utc).isoformat(); t=time.monotonic()
 try:
  p=subprocess.run(argv,capture_output=True,text=True,timeout=timeout)
  return {'argv':argv,'started_utc':st,'elapsed_s':round(time.monotonic()-t,3),'rc':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
 except subprocess.TimeoutExpired:
  return {'argv':argv,'started_utc':st,'elapsed_s':round(time.monotonic()-t,3),'rc':124,'stdout':'','stderr':'timeout'}
def dns(name): return cmd([sys.executable,'-c','import socket,sys; print(sorted({x[4][0] for x in socket.getaddrinfo(sys.argv[1],None,type=socket.SOCK_STREAM)}))',name],5)
def tcp(host,port):
 st=datetime.datetime.now(datetime.timezone.utc).isoformat();t=time.monotonic()
 try:
  with socket.create_connection((host,port),timeout=3) as s:
   s.settimeout(1); data=s.recv(256)
  return {'started_utc':st,'elapsed_s':round(time.monotonic()-t,3),'rc':0,'host':host,'port':port,'banner_prefix':data.decode(errors='replace')[:120]}
 except Exception as e: return {'started_utc':st,'elapsed_s':round(time.monotonic()-t,3),'rc':2,'host':host,'port':port,'error':type(e).__name__+': '+str(e)}
hosts={}
for alias in ('gz02','alexpc'):
 c=cmd(['ssh','-G',alias],5); fields=dict(x.split(' ',1) for x in c['stdout'].splitlines() if ' ' in x)
 host=fields.get('hostname'); port=int(fields.get('port','22')); d=dns(host) if host else {'rc':2,'stderr':'no hostname'}; ips=[]
 if d.get('rc')==0:
  try: ips=eval(d['stdout'].strip(),{'__builtins__':{}},{})
  except Exception: ips=[]
 t=tcp(ips[0],port) if ips else {'attempted':False}; query=f'[{host}]:{port}' if port!=22 else host; k=cmd(['ssh-keygen','-F',query,'-f',str(known),'-l'],5)
 hosts[alias]={'ssh_G':{'rc':c['rc'],'started_utc':c.get('started_utc'),'elapsed_s':c.get('elapsed_s')},'effective':{x:fields.get(x) for x in ('hostname','port','proxycommand','proxyjump','stricthostkeychecking','hostkeyalias','userknownhostsfile')},'dns':d,'tcp_or_banner':t,'known_hosts_query':{'query':query,'rc':k['rc'],'started_utc':k['started_utc'],'elapsed_s':k['elapsed_s'],'fingerprints':k['stdout']},'ssh_or_remote_commands':0}
out={'schema':'peer-native-linux-host-entry-v2','observed_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'inputs':{'local_env_sha256':sha(env_file),'ssh_config_sha256':sha(ssh_cfg),'known_hosts_sha256':sha(known)},'hosts':hosts,'remote_commands':0,'device_commands':0,'container_commands':0,'bridge_commands':0,'old_nonce_replays':0}
print(json.dumps(out,sort_keys=True,indent=2))
