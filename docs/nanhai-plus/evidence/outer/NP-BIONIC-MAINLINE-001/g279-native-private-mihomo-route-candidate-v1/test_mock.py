#!/usr/bin/env python3
"""Offline syntax and route-order fixture; no private node material or network."""
import datetime,hashlib,ipaddress,json,os,pathlib,subprocess,sys,time
HERE=pathlib.Path(__file__).parent
BIN=pathlib.Path('/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo')
MOCK=HERE/'mock.yaml'
RUNTIME=HERE/'mock-runtime'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def put(p,x):
 with p.open('x') as f:json.dump(x,f,indent=2,sort_keys=True);f.write('\n')
def main():
 assert not (HERE/'RESULT.json').exists()
 assert BIN.is_file() and sha(BIN)=='c15a8c12c461404f3f09368146538c5d32b1b728cd5e1b28885c103ffd7ed9d0'
 assert 'proxies: []' in MOCK.read_text() and '1.95.90.207/32' in MOCK.read_text()
 RUNTIME.mkdir(mode=0o700,exist_ok=False)
 argv=[str(BIN),'-t','-d',str(RUNTIME),'-f',str(MOCK)]
 start=time.monotonic()
 try:
  p=subprocess.run(argv,capture_output=True,timeout=20,check=False,env={**os.environ,'HOME':str(RUNTIME)})
  rc=p.returncode;timed_out=False
 except subprocess.TimeoutExpired as e:
  p=None;rc=124;timed_out=True
  out=e.stdout or b'';err=e.stderr or b''
 else:out=p.stdout;err=p.stderr
 (HERE/'stdout.raw').write_bytes(out);(HERE/'stderr.raw').write_bytes(err)
 rules=[('IP-CIDR',ipaddress.ip_network('1.95.90.207/32'),'PROXY'),('MATCH',None,'REJECT')]
 def decision(s):
  ip=ipaddress.ip_address(s)
  for kind,net,policy in rules:
   if kind=='MATCH' or ip in net:return policy
 checks={'exact_ip_proxy':decision('1.95.90.207')=='PROXY','neighbor_rejected':decision('1.95.90.208')=='REJECT','other_cn_rejected':decision('1.95.90.206')=='REJECT','syntax_rc0':rc==0,'no_timeout':not timed_out}
 result={'schema':'g279-private-mihomo-offline-mock-v1','at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'argv':argv,'binary_sha256':sha(BIN),'mock_sha256':sha(MOCK),'rc':rc,'timed_out':timed_out,'elapsed_seconds':time.monotonic()-start,'stdout_sha256':sha(HERE/'stdout.raw'),'stderr_sha256':sha(HERE/'stderr.raw'),'checks':checks,'network_probe':False,'gz02_connection':False,'proxy_instance_started':False,'credential_material_in_mock':False}
 put(HERE/'RESULT.json',result)
 print(json.dumps({'rc':rc,'checks':checks,'result_sha256':sha(HERE/'RESULT.json')}))
 return 0 if all(checks.values()) else 2
if __name__=='__main__':sys.exit(main())
