#!/usr/bin/env python3
"""No real credentials, controller, proxy instance, or gz02 connection."""
import hashlib,importlib.util,json,os,pathlib,socket,subprocess,sys,tempfile
import yaml
H=pathlib.Path(__file__).parent;os.environ.setdefault('NANHAI_PROJECT_ROOT',str(H.parents[5]))
s=importlib.util.spec_from_file_location('v2a_v2',H/'runner.py');r=importlib.util.module_from_spec(s);s.loader.exec_module(r)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def bad(fn):
 try:fn()
 except (ValueError,KeyError):return True
 return False
def fresh(node):
 x={'mode':'rule','proxies':[node],'proxy-groups':[{'name':'PROXY','type':'select','proxies':[node['name']]}],'external-controller-unix':'/tmp/fake.sock'}
 raw=yaml.safe_dump(x).encode();old=(r.SOURCE,r.SOURCE_SHA,r.active_process,r.verify_socket_path,r.current_leaf)
 with tempfile.TemporaryDirectory() as td:
  p=pathlib.Path(td)/'config.yaml';p.write_bytes(raw);r.SOURCE=p;r.SOURCE_SHA=hashlib.sha256(raw).hexdigest()
  pid=[71];sock=[(1,2,0,0)];leaf=[node['name']]
  r.active_process=lambda:pid[0];r.verify_socket_path=lambda _:sock[0];r.current_leaf=lambda x,p,n,g:leaf[0]
  try:
   good=r.fresh_selected_node(71,sock[0],node['name'])==node
   p.write_bytes(raw+b'\n');source_bad=bad(lambda:r.fresh_selected_node(71,sock[0],node['name']));p.write_bytes(raw)
   pid[0]=72;pid_bad=bad(lambda:r.fresh_selected_node(71,sock[0],node['name']));pid[0]=71
   sock[0]=(1,3,0,0);socket_bad=bad(lambda:r.fresh_selected_node(71,(1,2,0,0),node['name']));sock[0]=(1,2,0,0)
   leaf[0]='other';leaf_bad=bad(lambda:r.fresh_selected_node(71,sock[0],node['name']))
  finally:r.SOURCE,r.SOURCE_SHA,r.active_process,r.verify_socket_path,r.current_leaf=old
 return {'fresh_good':good,'fresh_source_bad':source_bad,'fresh_pid_bad':pid_bad,'fresh_socket_bad':socket_bad,'fresh_leaf_bad':leaf_bad}
def main():
 assert not (H/'FIXTURE.json').exists()
 node={'name':'fake-node','type':'hysteria2','server':'example.invalid','port':443,'password':'fixture-only','sni':'example.invalid'}
 ws={'name':'fake-vless','type':'vless','server':'example.invalid','port':443,'uuid':'fixture-only','ws-opts':{'path':'/valid'},'reality-opts':{'public-key':'fixture','short-id':'abcd'}}
 cfg=r.minimal_config(node,20001)
 a,b=socket.socketpair()
 try:peer=r.peer_identity(a)
 finally:a.close();b.close()
 mock=H/'mock.yaml';mock.write_text(yaml.safe_dump(cfg,sort_keys=False))
 d=H/'mock-runtime';d.mkdir(mode=0o700,exist_ok=False);(d/'private.yaml').write_bytes(mock.read_bytes())
 syn=r.syntax_group(d)
 sleeper=subprocess.Popen([sys.executable,'-I','-B','-c','import time; time.sleep(30)'],start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 stopped=r.stop_group(sleeper)
 with socket.socket() as listener:
  listener.bind(('127.0.0.1',0));listener.listen(1);port=listener.getsockname()[1]
  code='import socket,sys; s=socket.socket(); s.connect(("127.0.0.1",int(sys.argv[1]))); print("CONNECTED")'
  denied=subprocess.run([str(r.SANDBOX),'-p',r.DENY_NETWORK,sys.executable,'-I','-B','-c',code,str(port)],capture_output=True,timeout=5)
  nested='import subprocess,sys; z=subprocess.run([sys.executable,"-I","-B","-c",'+repr(code)+',sys.argv[1]],capture_output=True); sys.stdout.buffer.write(z.stdout); sys.stderr.buffer.write(z.stderr); sys.exit(z.returncode)'
  denied_child=subprocess.run([str(r.SANDBOX),'-p',r.DENY_NETWORK,sys.executable,'-I','-B','-c',nested,str(port)],capture_output=True,timeout=5)
 checks={'selected_allowed':r.selected_node_schema(node),'nested_allowed':r.selected_node_schema(ws),'nested_file_key_rejected':bad(lambda:r.selected_node_schema({**ws,'ws-opts':{'path':'/valid','cert-file':'/tmp/x'}})),'nested_file_uri_rejected':bad(lambda:r.selected_node_schema({**ws,'ws-opts':{'path':'file:///tmp/x'}})),'nested_traversal_rejected':bad(lambda:r.selected_node_schema({**ws,'ws-opts':{'path':'/../../tmp/x'}})),'top_dependency_rejected':bad(lambda:r.selected_node_schema({**node,'dialer-proxy':'x'})),'unsupported_type_rejected':bad(lambda:r.selected_node_schema({**node,'type':'socks5'})),'config_exact':r.config_gate(cfg) and cfg['rules']==r.RULES,'extra_geoip_rejected':bad(lambda:r.config_gate({**cfg,'rules':['GEOIP,CN,DIRECT',*cfg['rules']]})),'kernel_peer':peer==(os.getpid(),os.getuid()),'nonroot_peer_rejected':bad(lambda:r.peer_gate(peer[0],peer[1],peer[0])),'wrong_pid_rejected':bad(lambda:r.peer_gate(peer[0],0,peer[0]+1)),'sandbox_hash':sha(r.SANDBOX)==r.SANDBOX_SHA,'sandbox_denial_probe':r.sandbox_denial_probe(),'sandbox_loopback_denied':denied.returncode!=0 and b'Operation not permitted' in denied.stderr and b'CONNECTED' not in denied.stdout,'sandbox_descendant_denied':denied_child.returncode!=0 and b'Operation not permitted' in denied_child.stderr and b'CONNECTED' not in denied_child.stdout,'mock_mihomo_t':syn['rc']==0 and syn['group_clean'] and not syn['timed_out'],'process_group_stopped':stopped,'no_release':not r.RELEASE.exists(),'no_start':not (H/'START.json').exists(),'no_terminal':not (H/'TERMINAL.json').exists()}
 checks.update(fresh(node))
 out={'schema':'g279-private-mihomo-v2a-v2-offline-fixtures','runner_sha256':sha(H/'runner.py'),'mock_sha256':sha(mock),'mock_syntax':syn,'checks':checks,'all_pass':all(checks.values()),'real_proxy_read':False,'real_controller_queried':False,'real_private_config_created':False,'proxy_instance_started':False,'gz02_connected':False,'container_used':False,'namespace_used':False}
 with (H/'FIXTURE.json').open('x') as f:json.dump(out,f,sort_keys=True,indent=2);f.write('\n')
 print(json.dumps({'all_pass':out['all_pass'],'passed':sum(checks.values()),'total':len(checks),'fixture_sha256':sha(H/'FIXTURE.json')}))
 return 0 if out['all_pass'] else 2
if __name__=='__main__':sys.exit(main())
