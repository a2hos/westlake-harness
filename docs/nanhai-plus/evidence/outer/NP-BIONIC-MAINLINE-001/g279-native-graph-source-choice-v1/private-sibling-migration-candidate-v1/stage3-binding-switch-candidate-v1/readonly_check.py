#!/usr/bin/env python3
"""Read-only audit of the frozen stage-3 proposal; never switches bindings."""
import hashlib
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[7]
BASE = HERE.parent / 'stage2-candidate-v2'
PACKET = HERE / 'STAGE3-PACKET.json'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def config(path):
    text = path.read_text()
    match = re.search(r'<!-- NANHAI_ENV_BEGIN -->\s*```json\s*(.*?)\s*```\s*<!-- NANHAI_ENV_END -->', text, re.S)
    if not match:
        raise ValueError('env block missing')
    obj = json.loads(match.group(1))
    digest = hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return obj, digest


def check():
    packet = json.loads(PACKET.read_text())
    active = ROOT / packet['active_local_env']['path']
    proposed = ROOT / packet['proposed_local_env']['path']
    if sha(active) != packet['active_local_env']['raw_sha256'] or \
       sha(proposed) != packet['proposed_local_env']['raw_sha256']:
        raise ValueError('local env raw SHA drift')
    old, old_sha = config(active)
    new, new_sha = config(proposed)
    if old_sha != packet['active_local_env']['config_sha256'] or \
       new_sha != packet['proposed_local_env']['config_sha256']:
        raise ValueError('local env config SHA drift')
    expected_keys = set(packet['proposed_local_env']['changed_keys_exact'])
    if set(old) != set(new) or any(old[k] != new[k] for k in old if k != 'values') or \
       set(old['values']) != set(new['values']) or \
       {k for k in old['values'] if old['values'][k] != new['values'][k]} != expected_keys:
        raise ValueError('proposed env changed more than three keys')
    binding = ROOT / packet['remote_binding']['proposed_local_bytes_path']
    if sha(binding) != packet['remote_binding']['sha256']:
        raise ValueError('remote binding bytes drift')
    binding_json = json.loads(binding.read_text())
    if binding_json['env_config_sha256'] != new_sha or \
       binding_json['local_env_file_sha256'] != sha(proposed) or \
       binding_json['paths']['NANHAI_GZ02_NATIVE_PROJECT_ROOT'] != \
       packet['proposed_local_env']['project_root']:
        raise ValueError('remote binding relationship drift')
    nonce = packet['stage2_execution_evidence']['nonce']
    start = BASE / 'receipts' / (nonce + '.START.json')
    terminal = BASE / 'receipts' / (nonce + '.TERMINAL.json')
    release = BASE / 'ROOT-RELEASE.json'
    if sha(start) != packet['stage2_execution_evidence']['local_start_sha256'] or \
       sha(terminal) != packet['stage2_execution_evidence']['local_terminal_sha256'] or \
       sha(release) != packet['stage2_execution_evidence']['release_sha256']:
        raise ValueError('stage2 execution evidence SHA drift')
    result = json.loads(terminal.read_text())
    stdout = json.loads(result['stdout'])
    if result['ssh_rc'] != 0 or result['status'] != 'STAGED_READBACK_ONLY' or \
       stdout['nonce'] != nonce or stdout['links'] != 46 or \
       stdout['binding_sha256'] != sha(binding) or \
       stdout['binding_changed'] or stdout['graph'] or stdout['device'] or \
       stdout['container'] or stdout['namespace']:
        raise ValueError('stage2 terminal scope drift')
    peer_path = BASE / 'peer-postrun-v1/REVIEW.json'
    peer_sha = packet['stage2_execution_evidence']['independent_postrun_review_sha256']
    if sha(peer_path) != peer_sha or \
       not packet['stage2_execution_evidence']['independent_postrun_accepted']:
        raise ValueError('stage2 independent review SHA drift')
    peer = json.loads(peer_path.read_text())
    if peer['decision'] != 'ACCEPT_STAGE2_STAGED_READBACK_ONLY' or \
       peer['execution_chain']['local_terminal_sha256'] != sha(terminal) or \
       peer['independent_remote_readback']['source_view_links'] != 46 or \
       peer['independent_remote_readback']['remote_binding_sha256'] != sha(binding) or \
       peer['old_active_authority']['binding_switched']:
        raise ValueError('stage2 independent review scope drift')
    template = json.loads((HERE / 'OWNER-GRAPH-REQUEST-TEMPLATE.json').read_text())
    if template['dispatchable'] or template['ack_exists'] or \
       template['run_id'] is not None or \
       template['future_config_sha256'] != new_sha or \
       template['stage2_accepted_postrun_review_sha256'] != peer_sha or \
       template['future_remote_binding_sha256'] != sha(binding) or \
       template['stock_graph_top'] != old['values']['NANHAI_GZ02_AOSP_SOURCE_ROOT'] or \
       template['new_runner']['sha256'] is not None:
        raise ValueError('owner template falsely ready')
    if packet['switch_release']['local_env_changed'] or \
       packet['graph_generation_dependency']['new_runner_sha256'] is not None or \
       packet['graph_generation_dependency']['stock_graph_top'] != \
       old['values']['NANHAI_GZ02_AOSP_SOURCE_ROOT'] or \
       packet['original_owner_graph_ack_dependency']['ack_received']:
        raise ValueError('stage3 packet falsely ready')
    return {'schema': 'g279-stage3-readonly-check-v1',
            'status': 'CONSISTENT_WAIT_EXTERNAL_GATES',
            'active_config_sha256': old_sha, 'future_config_sha256': new_sha,
            'stage2_terminal_status': result['status'],
            'stage2_peer_postrun_accepted': True,
            'owner_ack_received': False, 'local_binding_changed': False,
            'remote_commands': 0, 'remote_writes': 0, 'graph': 0, 'device': 0}


if __name__ == '__main__':
    print(json.dumps(check(), sort_keys=True, indent=2))
