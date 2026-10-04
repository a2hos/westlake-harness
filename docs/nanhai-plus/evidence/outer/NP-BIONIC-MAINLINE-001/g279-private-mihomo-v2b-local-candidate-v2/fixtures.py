#!/usr/bin/env python3
"""No-credential, no-mihomo, loopback-only v2b fixtures."""
import importlib.util
import json
import os
import pathlib
import socket
import subprocess
import sys
import threading
import time

HERE=pathlib.Path(__file__).resolve().parent
os.environ.setdefault('NANHAI_PROJECT_ROOT',str(HERE.parents[5]))
spec=importlib.util.spec_from_file_location('v2b',HERE/'runner.py')
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
checks={}

def rejects(fn):
    try:fn()
    except ValueError:return True
    return False

checks['structured_positive']=v.parse_lsof_fields('p123\ncfoo\nf5u\nn127.0.0.1:39027\n')==[(123,'5u','127.0.0.1:39027')]
checks['human_table_rejected']=v.parse_lsof_fields('COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n')==[]
checks['orphan_name_rejected']=rejects(lambda:v.parse_lsof_fields('n127.0.0.1:39027\n'))
checks['false_pid_rejected']=rejects(lambda:v.parse_lsof_fields('pabc\nf5u\nn127.0.0.1:39027\n'))
from copy import deepcopy
node={'name':'fixture-node','type':'hysteria2','server':'127.0.0.1','port':443,'password':'fixture-only'}
cfg=v.load_upstream().minimal_config(node,39027)
checks['exact_rule_config']=v.load_upstream().config_gate(cfg) is True
bad=deepcopy(cfg);bad['rules'][0]='IP-CIDR,1.95.90.0/24,PROXY,no-resolve'
checks['broadened_cidr_rejected']=rejects(lambda:v.load_upstream().config_gate(bad))
bad=deepcopy(cfg);bad['rules'][1]='MATCH,DIRECT'
checks['fallback_direct_rejected']=rejects(lambda:v.load_upstream().config_gate(bad))

# Real kernel listener fixture: Python only, random loopback port, no proxy.
code='import socket,time; s=socket.socket(); s.bind(("127.0.0.1",0)); s.listen(); print(s.getsockname()[1],flush=True); time.sleep(5)'
p=subprocess.Popen([sys.executable,'-I','-B','-c',code],stdout=subprocess.PIPE,text=True,start_new_session=True)
try:
    port=int(p.stdout.readline().strip())
    rows=[]
    for _ in range(20):
        rows=v.listener_rows(port)
        if rows:break
        time.sleep(.05)
    checks['kernel_structured_listener']=len(rows)==1 and rows[0][0]==p.pid and rows[0][2]==f'127.0.0.1:{port}'
    checks['kernel_wrong_pid_rejected']=rejects(lambda:v.listener_gate(port,p.pid+1))
    checks['kernel_exact_owner_pass']=v.listener_gate(port,p.pid)[0]==p.pid
finally:
    p.terminate()
    try:p.wait(timeout=2)
    except subprocess.TimeoutExpired:p.kill();p.wait()

def serve(reply,expected_pass,tail=b''):
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0));listener.listen(1)
        port=listener.getsockname()[1]
        def worker():
            c,_=listener.accept()
            with c:
                c.settimeout(2)
                c.recv(3);c.sendall(b'\x05\x00')
                c.recv(10);c.sendall(reply+tail)
        t=threading.Thread(target=worker);t.start()
        try:
            if expected_pass:
                x=v.socks_negative(port)
                return x['connection_closed'] is True and x['route_reject_proven'] is False
            return rejects(lambda:v.socks_negative(port))
        finally:t.join(timeout=3)

complete_ok=bytes.fromhex('050000017f0000011234')
checks['exact_mock_shape_closure_recorded']=serve(complete_ok,True)
checks['generic_failure_rejected']=serve(bytes.fromhex('050500017f0000011234'),False)
checks['truncated_reply_rejected']=serve(bytes.fromhex('0501'),False)
checks['fake_success_with_data_rejected']=serve(complete_ok,False,b'X')
checks['malformed_atyp_rejected']=serve(bytes.fromhex('050000090000'),False)
mock_log=(HERE/'MOCK-STDOUT.raw').read_bytes()
mock_cfg=v.load_upstream().yaml.safe_load((HERE/'MOCK-CONFIG.yaml').read_bytes())
real_shape=deepcopy(cfg);real_shape['log-level']='debug'
checks['mock_same_non_node_config_and_rules']=all(mock_cfg[k]==real_shape[k] for k in real_shape if k not in ('mixed-port','proxies','proxy-groups')) and set(mock_cfg)==set(real_shape)
checks['exact_binary_mock_reject_log']=len(v.route_event_digest(mock_log))==64
checks['generic_word_reject_log_rejected']=rejects(lambda:v.route_event_digest(b'config rules: MATCH,REJECT\n'))
checks['wrong_target_route_log_rejected']=rejects(lambda:v.route_event_digest(b'[TCP] 127.0.0.1:1234 --> 192.0.2.1:9 match Match using REJECT\n'))
checks['proxy_route_log_rejected']=rejects(lambda:v.route_event_digest(b'[TCP] 127.0.0.1:1234 --> 203.0.113.1:9 match Match using PROXY\n'))
checks['duplicate_route_log_rejected']=rejects(lambda:v.route_event_digest(mock_log+mock_log))
result={'schema':'g279-v2b-local-fixtures-v2','checks':checks,'pass':all(checks.values()),'actual_proxy_started':False,'gz02_requests':0,'device_commands':0,'container_commands':0,'namespace_commands':0}
print(json.dumps(result,sort_keys=True))
sys.exit(0 if result['pass'] else 2)
