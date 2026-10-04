#!/usr/bin/env python3
"""Read-only G276 owner request audit; never invokes owner_entry or consume."""
import ast
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path

root = Path(os.environ['NANHAI_PROJECT_ROOT']).resolve(strict=True)
here = Path(__file__).resolve().parent
candidate_dir = here.parent


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


request = json.loads((here / 'OWNER-REQUEST.json').read_bytes())
candidate = json.loads((candidate_dir / 'PACKET-CANDIDATE.json').read_bytes())
state = json.loads((root / 'docs/nanhai-plus/OUTER-STATE.json').read_bytes())
entry = (here / 'owner_entry.py').read_text()
consumer = (here / 'consume.py').read_text()
entry_ast = ast.parse(entry)
consumer_ast = ast.parse(consumer)
assert len(request['inputs']) == 377 and len(candidate['inputs']) == 372
assert all(request['inputs'].get(key) == digest for key, digest in candidate['inputs'].items())
assert len(set(request['inputs']) - set(candidate['inputs'])) == 5
for reference, digest in request['inputs'].items():
    if reference.startswith('env:'):
        path = Path(os.environ[reference[4:]])
    else:
        relative = Path(reference)
        assert not relative.is_absolute() and '..' not in relative.parts
        path = root / relative
    assert sha(path) == digest, reference
assert request['_control']['claim'] == 'NP-MUSL16-ART-024'
assert request['_control']['goal_id'] == 'goal_01'
assert request['_control']['release_sequence'] == 276
assert request['_control']['return_to_outer'] is True
assert request['session'] == 'oracle-kimi:local:nanhai-plus#inner'
assert request['environment_sha256'] == os.environ['NANHAI_ENV_CONFIG_SHA256']
assert os.environ['NANHAI_LIBC'] == 'bionic'
assert request['owner_receipt'] == ('docs/nanhai-plus/evidence/inner/NP-BIONIC-MAINLINE-001/'
                                    'stock-bionic-target-graph-v20-g276-candidate-v1/OWNER-ACK.json')
assert sha(here / 'OWNER-REQUEST.json') == '2bb550200af0433cda0a0b4ab98e2f568dcf52bef5615a86ced55b38bb549556'
assert sha(here / 'consume.py') == '1ff563f756f375ad279aafef5d30605ea7b4938bfcfaaa23581cd0ae3a92bc76'
assert sha(here / 'owner_entry.py') == '0b8d9efe575284f6192c54431ebe6ec3b369c2bb2902d331ea0b51d5bf5f0cbf'
assert 'runpy.run_path' in entry and 'OWNER-REQUEST.json' in entry
assert not any(isinstance(node, (ast.Import, ast.ImportFrom)) and
               any(alias.name.split('.')[0] in ('subprocess', 'socket', 'docker') for alias in node.names)
               for tree in (entry_ast, consumer_ast) for node in ast.walk(tree))
claims = [c for c in state['claims'] if c['claim_id'] == 'NP-MUSL16-ART-024']
assert len(claims) == 1
claim = claims[0]
assert claim['status'] == 'ready' and claim['release_state'] == 'completed_reviewed'
assert claim['release_sequence'] == 275 and claim['goal_id'] == 'goal_01'
assert claim['native_session'] == request['session']
assert claim['runtime_state'] == 'g275_terminal_reviewed_new_g276_required'
g275 = candidate['g275_terminal']
assert claim['latest_actual_review'] == {'path': g275['review'], 'sha256': g275['sha256']}
assert sha(root / g275['review']) == g275['sha256']
assert sha(root / g275['result']) == g275['result_sha256']
assert state['inner']['token_budget'] == 20000000000
outbox = json.loads((root / 'docs/nanhai-plus/workpackages/kimi-outbox.json').read_bytes())
g276_outbox = [r for r in outbox['releases'] if 'g276' in r['event_id'].lower()]
assert not g276_outbox
assert not (root / request['owner_receipt']).exists()

print(json.dumps({
    'schema': 'nanhai.g276.pre-dispatch-review-candidate.v1',
    'at': datetime.now(timezone.utc).isoformat(),
    'decision': 'PREPARED_FOR_INDEPENDENT_REVIEW_NOT_DISPATCHED',
    'request_sha256': sha(here / 'OWNER-REQUEST.json'),
    'consumer_sha256': sha(here / 'consume.py'),
    'entry_sha256': sha(here / 'owner_entry.py'),
    'bound_inputs_rehashed': len(request['inputs']),
    'candidate_inputs_unchanged': len(candidate['inputs']),
    'extra_candidate_and_review_refs': 5,
    'goal_id': 'goal_01', 'claim': 'NP-MUSL16-ART-024',
    'session': request['session'], 'budget': state['inner']['token_budget'],
    'claim_state': {'status': claim['status'], 'release_state': claim['release_state'],
                    'release_sequence': claim['release_sequence'],
                    'g275_review_sha256': g275['sha256']},
    'pending_g276_outbox_messages': len(g276_outbox),
    'owner_ack_exists': False, 'docker_commands': 0, 'graph_executed': False,
    'device_commands': 0,
    'limits': 'No consumer invocation, owner ACK, monitor delivery, claim transition, or sealed G276 execution',
}, ensure_ascii=False, sort_keys=True, indent=2))
