#!/usr/bin/env python3
"""No-credential, no-network v2c route/SSH identity code fixtures."""
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

node='fixture-node'
line=(b'time="2026-10-04T12:00:00.123456000-07:00" level=info msg="[TCP] '
      b'127.0.0.1:50123 --> 1.95.90.207:58222 match IPCIDR(1.95.90.207/32) '
      b'using PROXY[fixture-node]"')
event=v.positive_route_event(b'non-route\n'+line+b'\n',node)
checks['positive_exact_route']=event['action']=='PROXY' and event['rule']=='IPCIDR(1.95.90.207/32)' and event['target_ip']=='1.95.90.207' and event['target_port']==58222
checks['positive_private_node_not_exported']=node not in json.dumps(event) and event['node_name_exported'] is False and event['raw_line_exported'] is False
checks['positive_raw_line_hash_only']=event['private_raw_line_sha256']==v.sha(line)
checks['positive_forged_prefix_rejected']=rejects(lambda:v.positive_route_event(b'noise '+line+b'\n',node))
checks['positive_sensitive_suffix_rejected']=rejects(lambda:v.positive_route_event(line+b' password=secret\n',node))
checks['positive_duplicate_rejected']=rejects(lambda:v.positive_route_event(line+b'\n'+line+b'\n',node))
checks['positive_wrong_target_rejected']=rejects(lambda:v.positive_route_event(line.replace(b'1.95.90.207:58222',b'1.95.90.208:58222')+b'\n',node))
checks['positive_wrong_rule_rejected']=rejects(lambda:v.positive_route_event(line.replace(b'match IPCIDR(',b'match Match(')+b'\n',node))
checks['positive_wrong_action_rejected']=rejects(lambda:v.positive_route_event(line.replace(b'using PROXY[',b'using DIRECT[')+b'\n',node))
checks['positive_wrong_node_rejected']=rejects(lambda:v.positive_route_event(line+b'\n','other-node'))
checks['positive_bad_port_rejected']=rejects(lambda:v.positive_route_event(line.replace(b':50123 ',b':99 ')+b'\n',node))

safe_stderr=(b'debug1: Server host key: ssh-ed25519 '+v.HOST_FP.encode()+b'\n'
             b'Authenticated to 1.95.90.207 (via proxy) using "publickey".\n')
proof=v.parse_ssh_proof(b'1000\n',safe_stderr,0)
checks['ssh_hostkey_auth_uid_proof']=proof['host_key_pinned'] and proof['publickey_authenticated'] and proof['remote_uid']==1000
checks['ssh_bad_hostkey_rejected']=rejects(lambda:v.parse_ssh_proof(b'1000\n',safe_stderr.replace(v.HOST_FP.encode(),b'SHA256:wrong'),0))
checks['ssh_missing_auth_rejected']=rejects(lambda:v.parse_ssh_proof(b'1000\n',safe_stderr.splitlines()[0]+b'\n',0))
checks['ssh_bad_stdout_rejected']=rejects(lambda:v.parse_ssh_proof(b'1000\nextra\n',safe_stderr,0))
checks['ssh_nonzero_rc_rejected']=rejects(lambda:v.parse_ssh_proof(b'1000\n',safe_stderr,255))

known=v.known_host_gate()  # local public key and executable SHA only
root_fact,term_fact=v.accepted_v2b(v.load_upstream())
checks['v2b_accepted_local_fact_only']=root_fact['command_pass'] is False and term_fact['gz02_ssh_commands']==0 and term_fact['private_dir_removed'] is True
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
checks['main_no_release_execution']=not (HERE/'root-release-v1/ROOT-RELEASE.json').exists() and not (HERE/'START.json').exists() and not (HERE/'TERMINAL.json').exists()

result={'schema':'g279-v2c-offline-fixtures-v1','checks':checks,'pass':all(checks.values()),
        'real_mihomo_started':False,'real_ssh_connections':0,'network_commands':0,
        'gz02_requests':0,'hk01_hops':0,'remote_write_commands':0,'graph_commands':0,
        'device_commands':0,'container_commands':0}
print(json.dumps(result,sort_keys=True))
sys.exit(0 if result['pass'] else 2)
