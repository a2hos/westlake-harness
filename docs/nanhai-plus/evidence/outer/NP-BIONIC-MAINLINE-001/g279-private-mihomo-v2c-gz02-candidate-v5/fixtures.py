#!/usr/bin/env python3
"""No-credential, no-network v2c v5 fixed-marker diagnostic fixtures."""
import importlib.util
import json
import pathlib
import subprocess
import sys

HERE=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('v2c',HERE/'runner.py')
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
checks={}

def rejects(fn):
    try:fn()
    except ValueError:return True
    return False

node=v.SAFE_NODE_ALIAS
line=(b'time="2026-10-04T12:00:00.123456000-07:00" level=info msg="[TCP] '
      b'127.0.0.1:50123 --> 1.95.90.207:58222 match IPCIDR(1.95.90.207/32) '
      b'using PROXY[g279-v2c-selected]"')
event=v.positive_route_event(b'non-route\n'+line+b'\n')
checks['positive_exact_route']=event['action']=='PROXY' and event['rule']=='IPCIDR(1.95.90.207/32)' and event['target_ip']=='1.95.90.207' and event['target_port']==58222
checks['positive_safe_alias_only']=event['node_alias']==node and 'fixture-node' not in json.dumps(event)
sample={'name':'private-fixture-label','type':'vless','server':'127.0.0.1','port':443,'uuid':'fixture-uuid'}
aliased=v.private_alias(sample)
checks['selected_node_safe_rename']=aliased['name']==v.SAFE_NODE_ALIAS and sample['name']=='private-fixture-label' and 'private-fixture-label' not in json.dumps(aliased)
checks['selected_node_alias_collision_rejected']=rejects(lambda:v.private_alias({**sample,'name':v.SAFE_NODE_ALIAS}))
checks['positive_raw_line_replay']=event['raw_line']==line.decode() and event['raw_line_sha256']==v.sha(line) and v.replay_positive_event(event)
checks['positive_forged_prefix_rejected']=rejects(lambda:v.positive_route_event(b'noise '+line+b'\n'))
checks['positive_sensitive_suffix_rejected']=rejects(lambda:v.positive_route_event(line+b' password=secret\n'))
checks['positive_duplicate_rejected']=rejects(lambda:v.positive_route_event(line+b'\n'+line+b'\n'))
checks['positive_wrong_target_rejected']=rejects(lambda:v.positive_route_event(line.replace(b'1.95.90.207:58222',b'1.95.90.208:58222')+b'\n'))
checks['positive_wrong_rule_rejected']=rejects(lambda:v.positive_route_event(line.replace(b'match IPCIDR(',b'match Match(')+b'\n'))
checks['positive_wrong_action_rejected']=rejects(lambda:v.positive_route_event(line.replace(b'using PROXY[',b'using DIRECT[')+b'\n'))
checks['positive_wrong_node_rejected']=rejects(lambda:v.positive_route_event(line.replace(node.encode(),b'other-node')+b'\n'))
checks['positive_bad_port_rejected']=rejects(lambda:v.positive_route_event(line.replace(b':50123 ',b':99 ')+b'\n'))
checks['positive_tampered_witness_rejected']=rejects(lambda:v.replay_positive_event({**event,'action':'DIRECT'}))
probe=json.loads((v.V2/'LOOPBACK-FORMAT-PROBE.json').read_text())
checks['actual_binary_fake_node_line_replay']=probe['format_matches_candidate'] and len(probe['route_lines_ascii'])==1 and v.replay_positive_event(probe['replayable_event'])
checks['actual_binary_probe_scope']=probe['fake_node_loopback_only'] and probe['fake_node_requested_target']==v.TARGET_IP and probe['fake_node_requested_port']==v.TARGET_PORT and probe['real_gz02_connects']==0 and probe['real_ssh_connections']==0 and probe['real_node_credentials_loaded'] is False and probe['mihomo_process_stopped'] and probe['private_dir_removed']

safe_stderr=(b'debug1: Server host key: ssh-ed25519 '+v.HOST_FP.encode()+b'\n'
             b'Authenticated to 1.95.90.207 (via proxy) using "publickey".\n')
proof=v.parse_ssh_proof(b'1000\n',safe_stderr,0)
checks['ssh_hostkey_auth_uid_proof']=proof['host_key_pinned'] and proof['publickey_authenticated'] and proof['remote_uid']==1000
checks['ssh_witness_replay']=v.replay_ssh_proof(proof) and proof['witness']['uid_stdout']=='1000\n' and proof['host_key_line_sha256']==v.sha(proof['witness']['host_key_line'].encode())
checks['ssh_tampered_uid_rejected']=rejects(lambda:v.replay_ssh_proof({**proof,'remote_uid':1001}))
checks['ssh_tampered_auth_rejected']=rejects(lambda:v.replay_ssh_proof({**proof,'witness':{**proof['witness'],'auth_line':'Authenticated using password.'}}))
checks['ssh_bad_hostkey_rejected']=rejects(lambda:v.parse_ssh_proof(b'1000\n',safe_stderr.replace(v.HOST_FP.encode(),b'SHA256:wrong'),0))
checks['ssh_missing_auth_rejected']=rejects(lambda:v.parse_ssh_proof(b'1000\n',safe_stderr.splitlines()[0]+b'\n',0))
checks['ssh_bad_stdout_rejected']=rejects(lambda:v.parse_ssh_proof(b'1000\nextra\n',safe_stderr,0))
checks['ssh_nonzero_rc_rejected']=rejects(lambda:v.parse_ssh_proof(b'1000\n',safe_stderr,255))
unknown=v.ssh_diagnostic_lengths(0,19,255,False)
checks['ssh_fake_nonzero_unknown_transport']=unknown['category']=='NONZERO_EXIT' and unknown['last_ssh_stage']=='UNKNOWN' and v.replay_ssh_diagnostic(unknown)
timeout=v.ssh_diagnostic_lengths(0,0,-9,True)
checks['ssh_fake_timeout_unknown_transport']=timeout['category']=='TIMEOUT' and timeout['last_ssh_stage']=='UNKNOWN' and v.replay_ssh_diagnostic(timeout)
partial_stage=v.ssh_observed_stage(b'',b'debug1: Remote protocol version 2.0, remote software version OpenSSH_9.9\n'+safe_stderr.splitlines()[0]+b'\n')
partial=v.ssh_diagnostic_lengths(0,120,255,False,partial_stage)
checks['ssh_fake_banner_hostkey_only']=partial['last_ssh_stage']=='PINNED_KEY_LINE_SEEN' and partial['category']=='NONZERO_EXIT' and v.replay_ssh_diagnostic(partial)
checks['ssh_fake_auth_stage']=v.ssh_observed_stage(b'',safe_stderr)=='PUBLICKEY_AUTH_LINE_SEEN'
checks['ssh_fake_uid_stage']=v.ssh_observed_stage(b'1000\n',safe_stderr)=='NUMERIC_UID_STDOUT_SEEN'
checks['ssh_fake_forged_banner_unknown']=v.ssh_observed_stage(b'',b'debug1: Remote protocol version 2.0, remote software version fake-secret\n')=='UNKNOWN'
checks['ssh_reject_categories_fixed']=v.classify_ssh_proof_reject(ValueError('ssh_hostkey_debug_absent_or_ambiguous'))=='HOSTKEY_WITNESS_UNPROVEN' and v.classify_ssh_proof_reject(ValueError('ssh_auth_debug_absent_or_ambiguous'))=='AUTH_WITNESS_UNPROVEN' and v.classify_ssh_proof_reject(ValueError('ssh_remote_uid_absent_or_invalid'))=='UID_WITNESS_UNPROVEN' and v.classify_ssh_proof_reject(ValueError('secret arbitrary text'))=='PROOF_REJECTED_UNKNOWN'
checks['ssh_tampered_transport_rejected']=rejects(lambda:v.replay_ssh_diagnostic({**unknown,'last_ssh_stage':'TCP_CONNECTED'}))
checks['ssh_tampered_category_rejected']=rejects(lambda:v.replay_ssh_diagnostic({**timeout,'category':'PROOF_VERIFIED'}))
checks['ssh_tampered_raw_stream_rejected']=rejects(lambda:v.replay_ssh_diagnostic({**partial,'stderr_raw':'private'}))
diagnostic={'schema':'g279-v2c-v5-instance-diagnostic','last_complete_stage':'SSH_LOCAL_PROCESS_LAUNCHED','failure_category':'SSH_NONZERO_EXIT','ssh_outcome':unknown,'positive_route_status':'UNKNOWN','local_reject_status':'PROVEN'}
failure=v.InstanceFailure(True,1,diagnostic,{'route_reject_proven':True})
checks['instance_failure_carries_safe_progress']=failure.clean and failure.ssh_commands==1 and failure.diagnostic['ssh_outcome']['category']=='NONZERO_EXIT' and failure.safe_result['route_reject_proven'] and v.validate_instance_diagnostic(diagnostic)
checks['instance_tampered_raw_line_rejected']=rejects(lambda:v.validate_instance_diagnostic({**diagnostic,'raw_stderr':'secret'}))
checks['v3_peer_rc_size_counterexample_rejected']=rejects(lambda:v.replay_ssh_diagnostic({**unknown,'child_rc':-999999,'stdout_bytes':10**100,'stderr_bytes':10**100,'last_ssh_stage':'NUMERIC_UID_STDOUT_SEEN'}))
checks['v3_peer_stage_counterexample_rejected']=rejects(lambda:v.validate_instance_diagnostic({**diagnostic,'last_complete_stage':'NONE','failure_category':'UNKNOWN','ssh_outcome':None,'positive_route_status':'PROVEN','local_reject_status':'UNKNOWN'}))
checks['ssh_child_rc_lower_bound_rejected']=rejects(lambda:v.replay_ssh_diagnostic({**unknown,'child_rc':-32}))
checks['ssh_child_rc_upper_bound_rejected']=rejects(lambda:v.replay_ssh_diagnostic({**unknown,'child_rc':256}))
checks['ssh_stdout_bound_rejected']=rejects(lambda:v.replay_ssh_diagnostic({**unknown,'stdout_bytes':v.MAX_SSH_STDOUT_BYTES+1}))
checks['ssh_stderr_bound_rejected']=rejects(lambda:v.replay_ssh_diagnostic({**unknown,'stderr_bytes':v.MAX_SSH_STDERR_BYTES+1}))
checks['ssh_null_rc_without_timeout_rejected']=rejects(lambda:v.replay_ssh_diagnostic({**unknown,'child_rc':None}))
checks['ssh_uid_stage_nonzero_rejected']=rejects(lambda:v.replay_ssh_diagnostic({**unknown,'last_ssh_stage':'NUMERIC_UID_STDOUT_SEEN','stdout_bytes':5}))
checks['ssh_key_stage_without_stderr_rejected']=rejects(lambda:v.replay_ssh_diagnostic({**unknown,'last_ssh_stage':'PINNED_KEY_LINE_SEEN','stderr_bytes':0}))
checks['ssh_verified_without_uid_stage_rejected']=rejects(lambda:v.replay_ssh_diagnostic({**v.ssh_diagnostic_lengths(5,100,0,False),'category':'PROOF_VERIFIED','last_ssh_stage':'PUBLICKEY_AUTH_LINE_SEEN'}))
verified={**v.ssh_diagnostic_lengths(5,100,0,False,'NUMERIC_UID_STDOUT_SEEN'),'category':'PROOF_VERIFIED'}
checks['ssh_valid_verified_boundary']=v.replay_ssh_diagnostic(verified)
checks['ssh_valid_byte_upper_bounds']=v.replay_ssh_diagnostic(v.ssh_diagnostic_lengths(v.MAX_SSH_STDOUT_BYTES,v.MAX_SSH_STDERR_BYTES,255,False))
checks['ssh_valid_signal_lower_bound']=v.replay_ssh_diagnostic(v.ssh_diagnostic_lengths(0,0,-31,False))
checks['instance_ssh_outcome_before_launch_rejected']=rejects(lambda:v.validate_instance_diagnostic({**diagnostic,'last_complete_stage':'LOCAL_REJECT_WITNESS'}))
checks['instance_positive_before_postssh_rejected']=rejects(lambda:v.validate_instance_diagnostic({**diagnostic,'positive_route_status':'PROVEN'}))
checks['instance_identity_without_proof_rejected']=rejects(lambda:v.validate_instance_diagnostic({**diagnostic,'last_complete_stage':'SSH_IDENTITY_WITNESS'}))
checks['instance_local_reject_order_rejected']=rejects(lambda:v.validate_instance_diagnostic({**diagnostic,'local_reject_status':'UNKNOWN'}))
valid_success={**diagnostic,'last_complete_stage':'WITNESSES_REPLAYED','failure_category':'UNKNOWN','ssh_outcome':verified,'positive_route_status':'PROVEN'}
checks['instance_valid_success_order']=v.validate_instance_diagnostic(valid_success)
checks['instance_valid_postssh_failure_order']=v.validate_instance_diagnostic({**valid_success,'last_complete_stage':'POST_SSH_LOCAL_GUARDS','failure_category':'INSTANCE_GUARD_UNKNOWN','positive_route_status':'UNKNOWN'})

# Inject a fake child process; no SSH binary, socket, credentials, or remote is run.
class FakeSSH:
    pid=999999
    returncode=255
    def poll(self):return 255
    def communicate(self,timeout=None):return b'',b'connection refused\n'
original_popen=v.subprocess.Popen
original_gate=v.ssh_config_gate
v.subprocess.Popen=lambda *args,**kwargs:FakeSSH()
v.ssh_config_gate=lambda *args,**kwargs:True
fake_launch=[];fake_observed=[]
try:
    checks['ssh_fake_process_failure_raised']=rejects(lambda:v.ssh_probe(39029,
        lambda:fake_launch.append(True),lambda d:fake_observed.append(d)))
finally:
    v.subprocess.Popen=original_popen
    v.ssh_config_gate=original_gate
checks['ssh_fake_process_diagnostic_retained']=len(fake_launch)==1 and len(fake_observed)==1 and fake_observed[0]['child_rc']==255 and fake_observed[0]['category']=='NONZERO_EXIT' and fake_observed[0]['last_ssh_stage']=='UNKNOWN' and fake_observed[0]['error_marker']=='UNCLASSIFIED' and set(fake_observed[0])=={'schema','child_rc','timed_out','stdout_bytes','stderr_bytes','last_ssh_stage','error_marker','category'}

known=v.known_host_gate()  # local public key and executable SHA only
root_fact,term_fact=v.accepted_v2b(v.load_upstream())
checks['v2b_accepted_local_fact_only']=root_fact['command_pass'] is False and term_fact['gz02_ssh_commands']==0 and term_fact['private_dir_removed'] is True
v2_fact=v.accepted_v2_failure(v.load_upstream())
checks['v2_failure_locked_no_replay']=v2_fact['terminal']['gz02_ssh_commands']==1 and v2_fact['terminal']['negative'] is None and v2_fact['root']['replay_allowed'] is False
checks['v3_no_go_locked']=v.accepted_v3_rejection(v.load_upstream())['decision']=='NO_GO_V2C_V3_CODE_ONLY_DIAGNOSTIC_VALIDATOR'
v4_fact=v.accepted_v4_failure(v.load_upstream())
checks['v4_rc255_unknown_locked']=v4_fact['terminal']['diagnostic']['ssh_outcome']['child_rc']==255 and v4_fact['terminal']['diagnostic']['ssh_outcome']['stderr_bytes']==1462 and v4_fact['terminal']['diagnostic']['ssh_outcome']['last_ssh_stage']=='UNKNOWN'
checks['v4_length_alone_still_unknown']=v.ssh_diagnostic_lengths(0,1462,255,False)['error_marker']=='UNCLASSIFIED'
checks['marker_hostkey_exact']=v.ssh_error_marker(b'Host key verification failed.\n',39029)=='HOSTKEY_REJECTED_LINE_SEEN'
checks['marker_publickey_exact']=v.ssh_error_marker(b'Permission denied (publickey).\n',39029)=='PUBLICKEY_REJECTED_LINE_SEEN'
checks['marker_banner_timeout_exact']=v.ssh_error_marker(b'Connection timed out during banner exchange\n',39029)=='BANNER_TIMEOUT_LINE_SEEN'
checks['marker_prebanner_closed_exact']=v.ssh_error_marker(b'kex_exchange_identification: Connection closed by remote host\n',39029)=='PRE_BANNER_CLOSED_LINE_SEEN'
checks['marker_prebanner_reset_exact']=v.ssh_error_marker(b'kex_exchange_identification: read: Connection reset by peer\n',39029)=='PRE_BANNER_RESET_LINE_SEEN'
checks['marker_local_socks_refused_exact']=v.ssh_error_marker(b'nc: connectx to 127.0.0.1 port 39029 (tcp) failed: Connection refused\n',39029)=='LOCAL_SOCKS_REFUSED_LINE_SEEN'
checks['marker_wrong_port_unknown']=v.ssh_error_marker(b'nc: connectx to 127.0.0.1 port 39030 (tcp) failed: Connection refused\n',39029)=='UNCLASSIFIED'
checks['marker_sensitive_suffix_unknown']=v.ssh_error_marker(b'Permission denied (publickey). node-secret\n',39029)=='UNCLASSIFIED'
checks['marker_unrecognized_bytes_unknown']=v.ssh_error_marker(b'x'*1462,39029)=='UNCLASSIFIED'
checks['marker_conflict_unknown']=v.ssh_error_marker(b'Host key verification failed.\nPermission denied (publickey).\n',39029)=='MULTIPLE_MARKERS_UNKNOWN'
checks['marker_no_raw_export']=set(v.ssh_diagnostic_lengths(0,50,255,False,error_marker='PUBLICKEY_REJECTED_LINE_SEEN'))=={'schema','child_rc','timed_out','stdout_bytes','stderr_bytes','last_ssh_stage','error_marker','category'}
checks['marker_rc0_rejected']=rejects(lambda:v.replay_ssh_diagnostic({**v.ssh_diagnostic_lengths(0,50,0,False),'error_marker':'HOSTKEY_REJECTED_LINE_SEEN'}))
checks['marker_timeout_rejected']=rejects(lambda:v.replay_ssh_diagnostic({**v.ssh_diagnostic_lengths(0,50,-9,True),'error_marker':'BANNER_TIMEOUT_LINE_SEEN'}))
checks['marker_empty_stderr_rejected']=rejects(lambda:v.replay_ssh_diagnostic({**v.ssh_diagnostic_lengths(0,0,255,False),'error_marker':'PUBLICKEY_REJECTED_LINE_SEEN'}))
argv,proxy=v.ssh_argv(39029,known)
checks['host_pin_current_local']=str(known).endswith('/.ssh/known_hosts')
checks['ssh_exact_proxy_and_no_hk01']=proxy=='/usr/bin/nc -X 5 -x 127.0.0.1:39029 -w 8 %h %p' and '119.13.124.122' not in ' '.join(argv) and 'ProxyJump=none' in argv
checks['ssh_remote_read_only']=argv[-1]=='LC_ALL=C /usr/bin/id -u' and 'StrictHostKeyChecking=yes' in argv and 'HostKeyAlgorithms=ssh-ed25519' in argv
checks['ssh_G_local_configuration_only']=v.ssh_config_gate(argv,proxy,known) is True
checks['invalid_ssh_port_rejected']=rejects(lambda:v.ssh_argv(7897,known))

# sys.exit is outside the Exception handler. A successful execute result must
# remain 0; SystemExit is not swallowed and converted into the v2b rc2 bug.
checks['main_success_rc0']=v.main(['--execute'],run=lambda:0)==0
checks['main_failure_rc2']=v.main(['--execute'],run=lambda:2)==2
try:v.main(['--execute'],run=lambda:(_ for _ in ()).throw(SystemExit(0)))
except SystemExit as e:checks['main_does_not_catch_systemexit']=e.code==0
else:checks['main_does_not_catch_systemexit']=False
checks['main_no_release_execution']=not (HERE/'root-release-v5/ROOT-RELEASE.json').exists() and not (HERE/'START.json').exists() and not (HERE/'TERMINAL.json').exists()

result={'schema':'g279-v2c-v5-offline-diagnostic-fixtures','checks':checks,'pass':all(checks.values()),
        'real_mihomo_started':False,'real_ssh_connections':0,'network_commands':0,
        'gz02_requests':0,'hk01_hops':0,'remote_write_commands':0,'graph_commands':0,
        'device_commands':0,'container_commands':0}
print(json.dumps(result,sort_keys=True))
sys.exit(0 if result['pass'] else 2)
