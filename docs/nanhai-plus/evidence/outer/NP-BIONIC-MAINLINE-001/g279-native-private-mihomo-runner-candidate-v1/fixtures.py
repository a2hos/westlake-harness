#!/usr/bin/env python3
"""No-secret, no-socket, no-proxy-start negative fixtures for proposed runner."""
import ast,hashlib,importlib.util,json,os,pathlib,sys
HERE=pathlib.Path(__file__).parent
os.environ.setdefault('NANHAI_PROJECT_ROOT',str(HERE.parents[5]))
spec=importlib.util.spec_from_file_location('g279_private_runner',HERE/'runner.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
def bad(fn):
 try:fn()
 except (ValueError,KeyError):return True
 return False
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 assert not (HERE/'FIXTURE.json').exists()
 ast.parse((HERE/'runner.py').read_text())
 node={'name':'mock-node','type':'socks5','server':'example.invalid','port':1080}
 source={'mode':'rule','proxy-groups':[{'name':'PROXY','type':'select','proxies':['mock-node']}],'proxies':[node]}
 raw,groups=r.validate_source_structure(source)
 model=r.private_model(node,20001)
 checks={
  'source_structure':len(raw)==1 and groups=={'PROXY'},
  'leaf_direct':bad(lambda:r.resolve_leaf('PROXY',lambda _: 'DIRECT',set(raw),groups)),
  'leaf_cycle':bad(lambda:r.resolve_leaf('PROXY',lambda _: 'PROXY',set(raw),groups)),
  'leaf_unknown':bad(lambda:r.resolve_leaf('PROXY',lambda _: 'unknown',set(raw),groups)),
  'leaf_valid':r.resolve_leaf('PROXY',lambda _: 'mock-node',set(raw),groups)=='mock-node',
  'private_model_valid':r.validate_private_model(model),
  'private_exact_rules':model['rules']==['IP-CIDR,1.95.90.207/32,PROXY,no-resolve','MATCH,REJECT'],
  'private_one_proxy':len(model['proxies'])==1 and model['proxy-groups'][0]['proxies']==['mock-node'],
  'negative_neighbor':r.negative_route('1.95.90.208')=='REJECT',
  'negative_other_cn':r.negative_route('1.95.90.206')=='REJECT',
  'positive_exact':r.negative_route('1.95.90.207')=='PROXY',
  'bad_port':bad(lambda:r.private_model(node,7897)),
  'bad_direct_node':bad(lambda:r.private_model({'name':'DIRECT','type':'direct','server':'x','port':1},20001)),
  'bad_rule_order':bad(lambda:r.validate_private_model({**model,'rules':list(reversed(model['rules']))})),
  'bad_extra_rule':bad(lambda:r.validate_private_model({**model,'rules':['GEOIP,CN,DIRECT',*model['rules']]})),
  'bad_dns':bad(lambda:r.validate_private_model({**model,'dns':{'enable':True}})),
  'bad_controller':bad(lambda:r.validate_private_model({**model,'external-controller-unix':'/tmp/mock.sock'})),
  'bad_direct_group':bad(lambda:r.validate_private_model({**model,'proxy-groups':[{'name':'PROXY','type':'select','proxies':['DIRECT']}]})),
  'active_source_path_positive':r.active_source_path_is_exact('binary -d '+str(r.SOURCE.parent)+' -f '+str(r.SOURCE)+' -ext-ctl-unix socket'),
  'active_source_path_negative':not r.active_source_path_is_exact('binary -d /tmp -f /tmp/config.yaml -ext-ctl-unix socket'),
  'host_fingerprint':r.ensure_known_host()==r.HOST_FINGERPRINT,
  'ssh_G_no_connect':bool(r.verify_ssh_config(20001)),
  'no_start_artifact':not (HERE/'START.json').exists(),
  'no_terminal_artifact':not (HERE/'TERMINAL.json').exists(),
 }
 out={'schema':'g279-private-mihomo-runner-fixtures-v1','runner_sha256':sha(HERE/'runner.py'),'checks':checks,'all_pass':all(checks.values()),'real_source_proxy_read':False,'real_controller_queried':False,'second_proxy_started':False,'gz02_connected':False,'credentials_emitted':False}
 with (HERE/'FIXTURE.json').open('x') as f:json.dump(out,f,sort_keys=True,indent=2);f.write('\n')
 print(json.dumps({'all_pass':out['all_pass'],'checks':checks,'fixture_sha256':sha(HERE/'FIXTURE.json')}))
 return 0 if out['all_pass'] else 2
if __name__=='__main__':sys.exit(main())
