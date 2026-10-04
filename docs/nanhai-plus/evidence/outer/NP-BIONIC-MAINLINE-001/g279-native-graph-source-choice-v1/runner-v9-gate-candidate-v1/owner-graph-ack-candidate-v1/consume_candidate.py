#!/usr/bin/env python3
"""Original-owner graph-only intent ACK candidate; actual consume is closed."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[7]
RUNNER = ROOT / 'scripts/nanhai_plus_native_graph_v7.py'
GATE = ROOT / 'scripts/nanhai_plus_native_graph_v9_gate.py'
REQUEST = HERE / 'REQUEST-CANDIDATE.json'
SPEC = HERE / 'SPEC-TEMPLATE.json'
RUNNER_SHA = '0b799e6864b6e76c2cfe7fa5a98cbb11d1611343f955205ab3bfc739096316a0'
RUNNER_BYTES = 41813
CONFIG_SHA = '5ce3a58541ef1711890aad8348c3a31a03203f584fa50f1f5c0cb4fd88b49718'


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_candidate() -> tuple[dict, dict]:
    request = json.loads(REQUEST.read_text())
    spec = json.loads(SPEC.read_text())
    if request.get('schema') != 'nanhai-g279-original-owner-graph-intent-request-v1' or \
       request.get('goal_id') != 'goal_01' or request.get('claim') != 'NP-MUSL16-ART-024' or \
       request.get('session') != 'oracle-kimi:local:nanhai-plus#inner' or \
       request.get('run_id') != 'g279-native-graph-v7-once' or \
       not isinstance(request.get('nonce'), str) or len(request['nonce']) != 32 or \
       request.get('environment_sha256') != CONFIG_SHA or \
       request.get('evo19_spec_template_sha256') != sha(SPEC) or \
       request.get('evo19_gate_script_sha256') != sha(GATE) or \
       request.get('graph_only_intent') is not True or \
       any(request.get(name) is not False for name in
           ('target_compile_authorized','device_authorized','container_authorized','graph_executed','target_compiled')) or \
       request.get('device_commands') != 0:
        raise ValueError('graph-only owner request drift')
    runner = request.get('runner', {})
    if runner != {'path':'scripts/nanhai_plus_native_graph_v7.py','sha256':RUNNER_SHA,
                  'bytes':RUNNER_BYTES,'intended_remote_mode':'0444'} or \
       sha(RUNNER) != RUNNER_SHA or RUNNER.stat().st_size != RUNNER_BYTES:
        raise ValueError('v7 runner candidate bytes drift')
    if spec.get('schema') != 'nanhai-g279-evo19-v9-spec-template-v1' or \
       spec.get('dispatchable') is not False or spec.get('graph_executed') is not False or \
       spec.get('target_compiled') is not False or spec.get('device_commands') != 0 or \
       spec.get('wrapper_candidate', {}).get('sha256') != sha(GATE):
        raise ValueError('EVO19 template drift or false release')
    return request, spec


def ack_candidate(request: dict) -> dict:
    return {'schema':'nanhai-g279-original-owner-graph-intent-ack-candidate-v1',
            'goal_id':request['goal_id'],'claim':request['claim'],
            'session_claim':request['session'],'run_id':request['run_id'],
            'nonce':request['nonce'],'request_sha256':sha(REQUEST),
            'evo19_spec_template_sha256':request['evo19_spec_template_sha256'],
            'runner_sha256':RUNNER_SHA,'graph_only_intent_ack':True,
            'authorization_effect':False,
            'provenance_status':'PENDING_ORIGINAL_SESSION_JSONL_AND_INDEPENDENT_PEER',
            'graph_executed':False,'target_compiled':False,'device_commands':0,
            'container_commands':0}


def main() -> int:
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--static-check', action='store_true')
    modes.add_argument('--consume', action='store_true')
    args = parser.parse_args()
    request, _ = validate_candidate()
    if args.consume:
        print(json.dumps({'status':'NO_GO_OWNER_REQUEST_NOT_DISPATCHABLE',
                          'request_sha256':sha(REQUEST),'ack_written':False,
                          'graph_authorized':False}), file=sys.stderr)
        return 3
    print(json.dumps({'status':'OWNER_INTENT_CANDIDATE_ONLY',
                      'request_sha256':sha(REQUEST),'spec_template_sha256':sha(SPEC),
                      'ack_preview':ack_candidate(request),'ack_written':False},sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
