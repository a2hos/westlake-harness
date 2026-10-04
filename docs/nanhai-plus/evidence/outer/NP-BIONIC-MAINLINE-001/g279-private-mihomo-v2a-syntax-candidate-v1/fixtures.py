#!/usr/bin/env python3
"""No-credential local fixtures; do not call the real controller or execute runner."""
import ast,hashlib,importlib.util,json,os,pathlib,socket,subprocess,sys,tempfile
HERE=pathlib.Path(__file__).parent
os.environ.setdefault('NANHAI_PROJECT_ROOT',str(HERE.parents[5]))
spec=importlib.util.spec_from_file_location('g279_v2a',HERE/'runner.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def bad(fn):
 try:fn()
 except (ValueError,KeyError):return True
 return False
def main():
 assert not (HERE/'FIXTURE.json').exists()
 tree=ast.parse((HERE/'runner.py').read_text())
 node={'name':'fake-local-node','type':'socks5','server':'127.0.0.1','port':1080}
 source={'mode':'rule','proxies':[node],'proxy-groups':[{'name':'PROXY','type':'select','proxies':[node['name']]}]}
 nodes,groups=r.source_structure(source);cfg=r.minimal_config(node,20001)
 a,b=socket.socketpair()
 try:peer_pid,peer_uid=r.peer_identity(a)
 finally:a.close();b.close()
 mock_dir=HERE/'mock-runtime';mock_dir.mkdir(mode=0o700,exist_ok=False)
 mock_path=HERE/'mock.yaml';mock_path.write_text(__import__('yaml').safe_dump(cfg,sort_keys=False))
 x=subprocess.run([str(r.BIN),'-t','-d',str(mock_dir),'-f',str(mock_path)],capture_output=True,timeout=15,check=False)
 (HERE/'mock-stdout.raw').write_bytes(x.stdout);(HERE/'mock-stderr.raw').write_bytes(x.stderr)
 with tempfile.TemporaryDirectory(prefix='g279-v2a-fixture-') as td:
  path=pathlib.Path(td)/'fake.sock';sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.bind(str(path));sock.listen(1)
  try:nonroot_socket_rejected=bad(lambda:r.verify_socket_path(path))
  finally:sock.close()
 checks={
  'source_fake_complete':len(nodes)==1 and groups=={'PROXY'},
  'leaf_valid':r.resolve_leaf('PROXY',lambda _:node['name'],set(nodes),groups)==node['name'],
  'leaf_direct_rejected':bad(lambda:r.resolve_leaf('PROXY',lambda _:'DIRECT',set(nodes),groups)),
  'leaf_cycle_rejected':bad(lambda:r.resolve_leaf('PROXY',lambda _:'PROXY',set(nodes),groups)),
  'leaf_unknown_rejected':bad(lambda:r.resolve_leaf('PROXY',lambda _:'missing',set(nodes),groups)),
  'mac_kernel_peer_pid_uid':(peer_pid,peer_uid)==(os.getpid(),os.getuid()),
  'nonroot_peer_rejected':bad(lambda:r.peer_gate(peer_pid,peer_uid,peer_pid)),
  'wrong_pid_rejected':bad(lambda:r.peer_gate(peer_pid,0,peer_pid+1)),
  'exact_root_peer_contract':r.peer_gate(peer_pid,0,peer_pid),
  'nonroot_mock_socket_rejected':nonroot_socket_rejected,
  'config_valid':r.config_gate(cfg),
  'config_two_rules_only':cfg['rules']==r.RULES,
  'config_single_node':len(cfg['proxies'])==1 and cfg['proxy-groups'][0]['proxies']==[node['name']],
  'config_no_controller_dns_tun':not cfg['external-controller-unix'] and not cfg['dns']['enable'] and not cfg['tun']['enable'],
  'bad_extra_geoip_rejected':bad(lambda:r.config_gate({**cfg,'rules':['GEOIP,CN,DIRECT',*cfg['rules']]})),
  'bad_rule_order_rejected':bad(lambda:r.config_gate({**cfg,'rules':list(reversed(cfg['rules']))})),
  'bad_dns_rejected':bad(lambda:r.config_gate({**cfg,'dns':{'enable':True}})),
  'bad_controller_rejected':bad(lambda:r.config_gate({**cfg,'external-controller-unix':'/tmp/mock.sock'})),
  'bad_direct_group_rejected':bad(lambda:r.config_gate({**cfg,'proxy-groups':[{'name':'PROXY','type':'select','proxies':['DIRECT']}]})),
  'bad_port_rejected':bad(lambda:r.minimal_config(node,7897)),
  'mock_mihomo_test_rc0':x.returncode==0,
  'no_release':not r.RELEASE.exists(),
  'no_start':not (HERE/'START.json').exists(),
  'no_terminal':not (HERE/'TERMINAL.json').exists(),
  'no_proxy_launch_code':not any(isinstance(n,ast.Attribute) and n.attr=='Popen' for n in ast.walk(tree)),
 }
 out={'schema':'g279-private-mihomo-v2a-offline-fixtures-v1','runner_sha256':sha(HERE/'runner.py'),'mock_config_sha256':sha(mock_path),'mock_stdout_sha256':sha(HERE/'mock-stdout.raw'),'mock_stderr_sha256':sha(HERE/'mock-stderr.raw'),'mock_rc':x.returncode,'checks':checks,'all_pass':all(checks.values()),'real_source_proxies_read':False,'real_controller_queried':False,'real_private_config_created':False,'proxy_instance_started':False,'gz02_connected':False,'credentials_emitted':False}
 with (HERE/'FIXTURE.json').open('x') as f:json.dump(out,f,sort_keys=True,indent=2);f.write('\n')
 print(json.dumps({'all_pass':out['all_pass'],'checks':checks,'fixture_sha256':sha(HERE/'FIXTURE.json')}))
 return 0 if out['all_pass'] else 2
if __name__=='__main__':sys.exit(main())
