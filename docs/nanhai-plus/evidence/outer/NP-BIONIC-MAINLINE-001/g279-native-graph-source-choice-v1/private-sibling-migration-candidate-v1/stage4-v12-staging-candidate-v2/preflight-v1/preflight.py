#!/usr/bin/env python3
"""Read-only exact Stage4 v12 remote identity preflight; never stages bytes."""
import hashlib
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
BASE = HERE.parent
packet_bytes = (BASE / 'PACKET.json').read_bytes()
packet = json.loads(packet_bytes)
remote = (BASE / 'remote_body.py').read_text()
review = json.loads((BASE / 'peer-review-v1/REVIEW.json').read_text())
assert review['decision'] == 'GO_V12_STAGING_ONCE'
assert packet['packet_sha256'] == review['packet_sha256']
assert hashlib.sha256((BASE / 'launcher.py').read_bytes()).hexdigest() == review['launcher_sha256']
assert hashlib.sha256(remote.encode()).hexdigest() == review['remote_body_sha256']

body = '''
host_guard()
assert PACKET['root'] == ROOT and PACKET['old_root'] == OLD
root_fd, root_id = directory(ROOT, 0o755)
control_fd, control_id = directory(ROOT + '/control', 0o700)
old_fd, old_id = directory(OLD, 0o775)
try:
    assert os.path.realpath(ROOT) == ROOT and os.path.realpath(OLD) == OLD
    assert root_id == PACKET['root_id'] and control_id == PACKET['control_id']
    assert old_id == PACKET['old_root_id']
    assert sorted(os.listdir(ROOT)) == ['control', 'out', 'source-view', 'staging', 'tmp']
    assert sorted(os.listdir(ROOT + '/control')) == PACKET['control_entries_before']
    assert sorted(os.listdir(ROOT + '/out')) == ['no-namespace-guard-v1', 'soong-ui-v1']
    for name in [PACKET['runner']['name'], 'STAGE4-V12-LEASE.json', 'STAGE4-V12-RECEIPT.json']:
        assert not os.path.lexists(ROOT + '/control/' + name), name
    assert len(PACKET['unchanged_files']) == 17
    for item in PACKET['unchanged_files']:
        assert regular(ROOT + '/' + item['path']) == item['identity'], item['path']
    view_fd, view_id = directory(ROOT + '/source-view', 0o755)
    os.close(view_fd)
    assert view_id == PACKET['source_view_id']
    print(json.dumps({'status':'EXACT_STAGE4_READ_ONLY_PREFLIGHT_PASS',
                      'nonce':PACKET['nonce'], 'packet_sha256':PACKET['packet_sha256'],
                      'unchanged_files':17, 'control_entries':len(PACKET['control_entries_before']),
                      'root_id':root_id,'control_id':control_id,'old_root_id':old_id,
                      'source_view_id':view_id,'writes':0,'graph':False,'device':False,
                      'container':False,'namespace':False},sort_keys=True))
finally:
    os.close(old_fd); os.close(control_fd); os.close(root_fd)
'''
program = ('PACKET = ' + repr(packet) + '\n__name__ = "nanhai_readonly_preflight"\n' + remote + '\n' + body).encode()
argv = ['/usr/bin/ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
        '-o','HostKeyAlgorithms=ssh-ed25519','-o','ConnectTimeout=10',
        '-o','UserKnownHostsFile=/Users/alexyang/.ssh/known_hosts',
        'gz02','/usr/bin/python3.12 -']
result = subprocess.run(argv,input=program,capture_output=True,timeout=120)
HERE.mkdir(parents=True,exist_ok=True)
(HERE/'stdout.raw').write_bytes(result.stdout)
(HERE/'stderr.raw').write_bytes(result.stderr)
receipt = {'schema':'g279-stage4-v12-fresh-readonly-preflight-v1',
           'packet_sha256':packet['packet_sha256'], 'review_sha256':hashlib.sha256((BASE/'peer-review-v1/REVIEW.json').read_bytes()).hexdigest(),
           'program_sha256':hashlib.sha256(program).hexdigest(), 'ssh_argv':argv,
           'ssh_rc':result.returncode,'stdout_sha256':hashlib.sha256(result.stdout).hexdigest(),
           'stderr_sha256':hashlib.sha256(result.stderr).hexdigest(),
           'status':'PASS' if result.returncode == 0 else 'FAIL',
           'remote_writes':0,'graph':False,'device':False,'container':False,'namespace':False}
(HERE/'RECEIPT.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
print(json.dumps(receipt,sort_keys=True))
sys.exit(result.returncode)
