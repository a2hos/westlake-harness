"""Original owner read-only G275 SHA consumption; no Docker/build/device call."""
import datetime
import hashlib
import json
import os
from pathlib import Path

root = Path(os.environ['NANHAI_PROJECT_ROOT'])
request = json.loads(Path(__file__).with_name('OWNER-REQUEST.json').read_text())
state = json.loads((root / 'docs/nanhai-plus/OUTER-STATE.json').read_text())
claims = [x for x in state['claims'] if x['claim_id'] == request['_control']['claim']]
assert len(claims) == 1
claim = claims[0]
assert claim['status'] == 'ready' and claim['release_state'] == 'completed_reviewed'
assert claim['release_sequence'] == 274 and request['_control']['release_sequence'] == 275
assert claim['goal_id'] == 'goal_01' and claim['native_session'] == request['session']
assert state['inner']['token_budget'] == 20000000000
assert os.environ['NANHAI_ENV_CONFIG_SHA256'] == request['environment_sha256']
assert os.environ['NANHAI_LIBC'] == 'bionic'
for reference, digest in request['inputs'].items():
    if reference.startswith('env:'):
        path = Path(os.environ[reference[4:]])
    else:
        relative = Path(reference)
        assert not relative.is_absolute() and '..' not in relative.parts
        path = root / relative
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            h.update(chunk)
    assert h.hexdigest() == digest, reference
receipt = root / request['owner_receipt']
assert receipt.parent.resolve().is_relative_to(root.resolve())
receipt.parent.mkdir(parents=True, exist_ok=True)
value = {
    'at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    '_control': request['_control'],
    'session': request['session'],
    'consumed': request['inputs'],
    'accepted_scope': request['accepted_scope'],
    'network_requests': 0,
    'compiler_commands': 0,
    'docker_commands': 0,
    'device_commands': 0,
    'business_complete': False,
}
if receipt.exists():
    previous = json.loads(receipt.read_text())
    assert previous['_control'] == value['_control']
    assert previous['consumed'] == value['consumed']
else:
    with receipt.open('x') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
print(json.dumps({'rc': 0, 'ack': request['owner_receipt'],
                  'sha256': hashlib.sha256(receipt.read_bytes()).hexdigest()}))
