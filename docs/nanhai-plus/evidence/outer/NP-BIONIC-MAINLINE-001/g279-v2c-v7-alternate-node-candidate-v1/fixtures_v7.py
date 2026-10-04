#!/usr/bin/env python3
"""Offline, credential-free v7 gates; no private proxy or gz02 connection."""
import datetime
import importlib.util
import json
import pathlib
import sys

here=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('g279_v7',here/'runner.py')
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
checks={}
up=v.load_upstream()
v6_start,v6_term,v6_root=v.accepted_v6_failure(up)
checks['v6_failure_accepted_no_replay']=(v6_term['decision']=='NO_GO_PRIVATE_LISTENER_AND_GZ02_IDENTITY'
    and v6_root['replay_allowed'] is False and v6_root['nonce_consumed']==v6_start['nonce'])
sel=v.load_selection()
now=datetime.datetime.now(datetime.timezone.utc)
def metric(delay,age=30):
    return sel.history_metric([{'delay':delay,'time':(now-datetime.timedelta(seconds=age)).isoformat()}],now)
metrics=[metric(100+i) for i in range(15)]
metrics[1]=metric(51);metrics[9]=metric(40)
checks['non_current_index1_positive']=sel.choose(metrics,9)==1
def rejects(fn):
    try:fn()
    except ValueError:return True
    return False
checks['current_became_index1_negative']=rejects(lambda:sel.choose(metrics,1))
bad=[dict(m) for m in metrics];bad[2]['best_delay_ms']=30
checks['better_alternate_negative']=rejects(lambda:sel.choose(bad,9))
checks['stale_index1_negative']=sel.history_metric([{'delay':51,'time':(now-datetime.timedelta(seconds=7201)).isoformat()}],now) is None
line=(b'time="2026-10-04T20:00:00.123456+00:00" level=info msg="[TCP] '
      b'127.0.0.1:45678 --> 1.95.90.207:58222 match IPCIDR(1.95.90.207/32) '
      b'using PROXY[g279-v2c-alternate]"')
event=v.positive_route_event(line+b'\n')
checks['new_alias_exact_line_replay']=v.replay_positive_event(event) and event['node_alias']==v.SAFE_NODE_ALIAS
checks['old_alias_rejected']=rejects(lambda:v.positive_route_event(line.replace(b'g279-v2c-alternate',b'g279-v2c-selected')+b'\n'))
checks['forged_line_rejected']=rejects(lambda:v.positive_route_event(b'prefix '+line+b'\n'))
checks['no_release_or_execution_receipts']=(not v.PEER.exists() and not v.RELEASE.exists()
    and not v.START.exists() and not v.TERMINAL.exists())
checks['execute_not_invoked']=v.main([])==2
result={'schema':'g279-v2c-v7-offline-fixtures-v1','checks':checks,'pass':all(checks.values()),
        'credentials_read':False,'proxy_started':False,'gz02_connections':0,
        'global_proxy_writes':0,'device_commands':0,'container_commands':0}
print(json.dumps(result,sort_keys=True))
sys.exit(0 if result['pass'] else 2)
