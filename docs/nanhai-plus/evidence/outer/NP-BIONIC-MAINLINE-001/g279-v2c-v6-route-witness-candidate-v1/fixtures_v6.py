#!/usr/bin/env python3
"""Offline v6 route-on-failure and local fake-marker fixtures."""
import hashlib,importlib.util,json,pathlib,sys
HERE=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('g279_v6',HERE/'runner.py')
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
checks={}
def rejects(fn):
 try:fn()
 except ValueError:return True
 return False

up=v.load_upstream();old=v.accepted_v5_failure(up)
checks['v5_consumed_failure_bound']=old[1]['decision']=='NO_GO_PRIVATE_LISTENER_AND_GZ02_IDENTITY' and old[3]['replay_allowed'] is False
probe=json.loads((v.V2/'LOOPBACK-FORMAT-PROBE.json').read_text())
line=probe['replayable_event']['raw_line'].encode()
nonzero=v.ssh_diagnostic_lengths(0,1462,255,False,'UNKNOWN','PRE_BANNER_CLOSED_LINE_SEEN')
def diag(stage='SSH_LOCAL_PROCESS_LAUNCHED'):
 return {'schema':'g279-v2c-v6-instance-diagnostic','last_complete_stage':stage,
         'failure_category':'SSH_NONZERO_EXIT' if stage=='SSH_LOCAL_PROCESS_LAUNCHED' else 'UNKNOWN',
         'ssh_outcome':nonzero if stage=='SSH_LOCAL_PROCESS_LAUNCHED' else None,
         'positive_route_status':'UNKNOWN','local_reject_status':'PROVEN'}
d=diag();event=v.failure_positive_witness(line+b'\n',d)
checks['failure_replayable_positive_line']=event==probe['replayable_event'] and v.replay_positive_event(event)
checks['failure_local_line_status_valid']=d['positive_route_status']=='LOCAL_LINE_OBSERVED' and v.validate_instance_diagnostic(d)
checks['failure_not_remote_proof']=d['last_complete_stage']=='SSH_LOCAL_PROCESS_LAUNCHED' and d['ssh_outcome']['child_rc']==255 and d['positive_route_status']!='PROVEN'
for name,bad in [('forged_prefix',b'noise '+line+b'\n'),('sensitive_suffix',line+b' secret=abc\n'),
                 ('duplicate',line+b'\n'+line+b'\n'),('wrong_target',line.replace(b'1.95.90.207:58222',b'192.0.2.2:2222')+b'\n'),
                 ('wrong_action',line.replace(b'using PROXY',b'using DIRECT')+b'\n')]:
 dd=diag();checks[name+'_unknown']=v.failure_positive_witness(bad,dd) is None and dd['positive_route_status']=='UNKNOWN'
pre={'schema':'g279-v2c-v6-instance-diagnostic','last_complete_stage':'LOCAL_REJECT_WITNESS','failure_category':'UNKNOWN','ssh_outcome':None,'positive_route_status':'UNKNOWN','local_reject_status':'PROVEN'}
checks['pre_ssh_line_not_exported']=v.failure_positive_witness(line+b'\n',pre) is None and pre['positive_route_status']=='UNKNOWN'
checks['line_cannot_claim_success']=rejects(lambda:v.validate_instance_diagnostic({**d,'last_complete_stage':'WITNESSES_REPLAYED'}))
checks['nonzero_ssh_cannot_prove_identity']=rejects(lambda:v.parse_ssh_proof(b'1000\n',b'debug1: Server host key: ssh-ed25519 '+v.HOST_FP.encode()+b'\n',255))
fake=json.loads((HERE/'FAKE-SOCKS-RESULT.json').read_text())
raw=(HERE/'FAKE-SSH-STDERR.raw').read_bytes()
checks['fake_raw_stderr_sha']=hashlib.sha256(raw).hexdigest()==fake['ssh_stderr_sha256']
checks['fake_no_target_outbound']=fake['fake_server_outbound_socket_calls']==0 and fake['real_gz02_connections']==0 and fake['fake_server']['requested_target']=='192.0.2.2'
checks['fake_same_marker_without_server']=fake['ssh_rc']==255 and v.ssh_error_marker(raw,39031)=='PRE_BANNER_CLOSED_LINE_SEEN'
checks['new_release_absent']=not (HERE/'root-release-v6/ROOT-RELEASE.json').exists() and not (HERE/'START.json').exists() and not (HERE/'TERMINAL.json').exists()
result={'schema':'g279-v2c-v6-route-on-failure-offline-fixtures-v1','checks':checks,'pass':all(checks.values()),
        'real_gz02_connections':0,'real_node_started':False,'device_commands':0,'container_commands':0}
print(json.dumps(result,sort_keys=True))
sys.exit(0 if result['pass'] else 2)
