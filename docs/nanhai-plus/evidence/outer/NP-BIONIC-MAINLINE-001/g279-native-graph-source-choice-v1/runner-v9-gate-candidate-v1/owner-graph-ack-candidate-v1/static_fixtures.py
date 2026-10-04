#!/usr/bin/env python3
"""Pure owner request/ACK preview tests; no Herdr or owner session calls."""
import importlib.util
import json
from pathlib import Path
import sys
from unittest import mock

sys.dont_write_bytecode=True
here=Path(__file__).resolve().parent
path=here/'consume_candidate.py'
spec=importlib.util.spec_from_file_location('owner_consume_candidate',path)
owner=importlib.util.module_from_spec(spec);spec.loader.exec_module(owner)
checks={}
request,template=owner.validate_candidate()
preview=owner.ack_candidate(request)
checks['new_nonce_and_run_id']=request['nonce']=='4117b3c9f5fcc2eeccdd8c0e7aec071d' and request['run_id']=='g279-native-graph-v7-once'
checks['exact_v7_and_spec']=request['runner']['sha256']==owner.RUNNER_SHA and request['runner']['bytes']==owner.RUNNER_BYTES and request['evo19_spec_template_sha256']==owner.sha(owner.SPEC)
checks['no_self_authorization']=preview['authorization_effect'] is False and preview['provenance_status']=='PENDING_ORIGINAL_SESSION_JSONL_AND_INDEPENDENT_PEER' and preview['graph_executed'] is False and preview['target_compiled'] is False and preview['device_commands']==0
checks['not_dispatchable']=request['dispatchable'] is False and template['dispatchable'] is False and any(row['bytes'] is None for row in template['remote_inputs'])
with mock.patch.object(sys,'argv',['consume_candidate.py','--consume']):
    checks['consume_cli_closed']=owner.main()==3
with mock.patch.object(owner,'RUNNER_SHA','0'*64):
    try:owner.validate_candidate()
    except ValueError:checks['runner_drift_rejected']=True
    else:checks['runner_drift_rejected']=False
assert all(checks.values()),checks
print(json.dumps({'status':'LOCAL_STATIC_FIXTURES_ONLY','checks':checks,
                  'herdr_dispatches':0,'owner_session_commands':0,'ssh_commands':0,
                  'graph_commands':0,'device_commands':0},sort_keys=True))
