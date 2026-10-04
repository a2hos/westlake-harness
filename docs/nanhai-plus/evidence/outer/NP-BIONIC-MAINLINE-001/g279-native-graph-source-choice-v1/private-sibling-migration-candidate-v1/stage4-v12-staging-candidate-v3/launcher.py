#!/usr/bin/env python3
"""Freeze/review or one-shot stage exact v12 under sibling; never run graph."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[7]
BASE = HERE.parent
V12 = ROOT / 'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g279-native-graph-source-choice-v1/runner-v12-authority-candidate-v1/nanhai_plus_native_graph_v12.py'
REMOTE = HERE / 'remote_body.py'
STAGE3 = BASE / 'stage3-v11-staging-candidate-v1/peer-postrun-v1/remote.stdout.raw'
STAGE3_PEER = BASE / 'stage3-v11-staging-candidate-v1/peer-postrun-v1/REVIEW.json'
STAGE3_ROOT = BASE / 'stage3-v11-staging-candidate-v1/ROOT-POSTRUN-ACCEPTANCE.json'
V12_PEER = V12.parent / 'peer-review-v1/REVIEW.json'
ROOT_PATH = '/data/source/.nanhai-plus-opaleye-native-v7'
OLD_PATH = '/data/source/.nanhai-plus-opaleye-native'
RUNNER_SHA = 'b3277b024ba258cc00c7fea1d9275672108970886c78b0c221f60aec16600a3b'
V12_PEER_SHA = '92ccc9f050bdb1771090af315f7973ded9b0dfbfb6af1eaa49899817b3769022'
STAGE3_PEER_SHA = '600c91a2b0a99b17dddffad6efabf8d85ddd0b4edc8d17b5595ee4c395c2ae36'
STAGE3_ROOT_SHA = '4e222d072b75c3a6785d284a5f492d2036db37cd2a45be55f495099f9ea4e4df'
STAGE3_PROBE_SHA = '9d5b2f02f816877512593d9d3e196bc70aeb7bfe62d0d2011d1483fec446e77c'
ACTIVE_ENV_SHA = '5fefb4ca26c218683df175452495b86a19b53e69168727adccd7eb365b22d35c'
SSH = ['/usr/bin/ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
       '-o', 'HostKeyAlgorithms=ssh-ed25519', '-o', 'ConnectTimeout=10',
       '-o', 'UserKnownHostsFile=/Users/alexyang/.ssh/known_hosts',
       'gz02', '/usr/bin/python3.12 -']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def enc(obj):
    return (json.dumps(obj, sort_keys=True, separators=(',', ':')) + '\n').encode()


def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        a = os.fstat(fd)
        parts = []
        while True:
            part = os.read(fd, 1048576)
            if not part:
                break
            parts.append(part)
        b = os.fstat(fd)
        if (a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns, a.st_ctime_ns) != \
           (b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns, b.st_ctime_ns):
            raise ValueError('local input changed: ' + str(path))
        return b''.join(parts)
    finally:
        os.close(fd)


def exact(path, digest):
    data = read(path)
    if sha(data) != digest:
        raise ValueError('evidence SHA drift: ' + str(path))
    return data


def freeze_packet(nonce):
    if len(nonce) != 32 or any(c not in '0123456789abcdef' for c in nonce):
        raise ValueError('bad nonce')
    if sha(read(ROOT / 'local_env.md')) != ACTIVE_ENV_SHA:
        raise ValueError('active v7 binding changed before v12 staging')
    runner = exact(V12, RUNNER_SHA)
    if len(runner) != 47610:
        raise ValueError('runner byte count drift')
    if json.loads(exact(V12_PEER, V12_PEER_SHA))['decision'] != 'GO_STATIC_ONLY':
        raise ValueError('v12 independent static review drift')
    if json.loads(exact(STAGE3_PEER, STAGE3_PEER_SHA))['decision'] != \
       'ACCEPT_STAGE3_STAGED_BYTES_ONLY':
        raise ValueError('stage3 peer review drift')
    if json.loads(exact(STAGE3_ROOT, STAGE3_ROOT_SHA))['decision'] != \
       'ACCEPT_STAGE3_STAGED_BYTES_ONLY':
        raise ValueError('stage3 root acceptance drift')
    third = json.loads(exact(STAGE3, STAGE3_PROBE_SHA))
    def directory(row):
        return {k: row[k] for k in ('dev', 'ino', 'uid', 'mode')}
    def identity(row):
        return {k: row[k] for k in ('dev', 'ino', 'uid', 'gid', 'mode', 'bytes', 'sha256')}
    files = [{'path': item['path'], 'identity': identity(item)}
             for item in third['files']]
    for key, name in [('runner', 'nanhai_plus_native_graph_v11.py'),
                      ('lease', 'STAGE3-V11-LEASE.json'),
                      ('receipt', 'STAGE3-V11-RECEIPT.json')]:
        files.append({'path': 'control/' + name, 'identity': identity(third[key])})
    files.sort(key=lambda x: x['path'])
    if len(files) != 17 or len({x['path'] for x in files}) != 17 or \
       third['link_count'] != 46 or len(third['control_entries']) != 15 or \
       third['runner']['sha256'] != '8b6484017d3679f4b14cde7c91e25a76f05289882fc390d3511180611714ffbe':
        raise ValueError('stage1/2/3 accepted input inventory drift')
    packet = {'schema': 'g279-stage4-v12-staging-packet-v1',
              'nonce': nonce, 'root': ROOT_PATH, 'old_root': OLD_PATH,
              'root_id': directory(third['directories']['root']),
              'control_id': directory(third['directories']['control']),
              'old_root_id': directory(third['directories']['old_root']),
              'source_view_id': directory(third['directories']['source_view']),
              'unchanged_files': files,
              'control_entries_before': sorted(third['control_entries']),
              'stage3_peer_sha256': STAGE3_PEER_SHA,
              'stage3_root_acceptance_sha256': STAGE3_ROOT_SHA,
              'v12_static_peer_sha256': V12_PEER_SHA,
              'runner': {'name': V12.name, 'sha256': RUNNER_SHA,
                         'bytes': len(runner), 'mode': 0o444},
              'active_binding_changed': False, 'graph': False, 'device': False,
              'container': False, 'namespace': False}
    packet['packet_sha256'] = sha(enc(packet))
    return packet, runner


def exclusive(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o444, dir_fd=parent)
        try:
            offset = 0
            while offset < len(data):
                offset += os.write(fd, data[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent)
    finally:
        os.close(parent)


def host_identity():
    lines = subprocess.run(['/usr/bin/ssh', '-G', 'gz02'], check=True,
                           capture_output=True, text=True).stdout.splitlines()
    settings = dict(line.split(' ', 1) for line in lines if ' ' in line)
    for key, value in {'user': 'AlexYang', 'hostname': '1.95.90.207',
                       'port': '58222', 'proxycommand': 'none', 'proxyjump': 'none'}.items():
        if settings.get(key, 'none') != value:
            raise ValueError('SSH route drift: ' + key)
    rows = [line.split() for line in read(Path('/Users/alexyang/.ssh/known_hosts')).decode().splitlines()
            if line.startswith('[1.95.90.207]:58222 ')]
    ed25519 = [row for row in rows if len(row) >= 2 and row[1] == 'ssh-ed25519']
    if len(ed25519) != 1 or len(ed25519[0]) < 3:
        raise ValueError('known host ed25519 row drift')
    key = base64.b64decode(ed25519[0][2], validate=True)
    fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(key).digest()).decode().rstrip('=')
    if fingerprint != 'SHA256:RuAqHWgFJEIEcb4hC+WXULCRfV3uCsayP4Iw4aJvwzg':
        raise ValueError('known host fingerprint drift')


def execute(review_path):
    host_identity()
    packet = json.loads(read(HERE / 'PACKET.json'))
    reconstructed, runner = freeze_packet(packet['nonce'])
    if packet != reconstructed:
        raise ValueError('frozen packet drift')
    review_data = read(review_path)
    review = json.loads(review_data)
    if review.get('decision') != 'GO_V12_STAGING_ONCE' or \
       review.get('packet_sha256') != packet['packet_sha256'] or \
       review.get('launcher_sha256') != sha(read(Path(__file__))) or \
       review.get('remote_body_sha256') != sha(read(REMOTE)) or \
       review.get('runner_sha256') != RUNNER_SHA or \
       review.get('independent_reviewer') in (None, '', 'candidate_author'):
        raise ValueError('independent exact-SHA staging release absent')
    nonce = packet['nonce']
    receipts = HERE / 'receipts'
    if (receipts / (nonce + '.START.json')).exists() or \
       (receipts / (nonce + '.TERMINAL.json')).exists():
        raise FileExistsError('nonce already started; reconcile, never replay')
    source = read(REMOTE)
    program = ('PACKET = ' + repr(packet) + '\nRUNNER_BYTES = bytes.fromhex(' +
               repr(runner.hex()) + ')\n').encode() + source
    start = {'schema': 'g279-stage4-v12-local-start-v1',
             'status': 'UNKNOWN_UNTIL_RECONCILED', 'nonce': nonce,
             'packet_sha256': packet['packet_sha256'],
             'launcher_sha256': sha(read(Path(__file__))),
             'remote_body_sha256': sha(source), 'runner_sha256': RUNNER_SHA,
             'review_sha256': sha(review_data), 'program_sha256': sha(program),
             'binding_changed': False, 'graph': False, 'replay_allowed': False}
    start_path = receipts / (nonce + '.START.json')
    exclusive(start_path, enc(start))
    try:
        process = subprocess.run(SSH, input=program, capture_output=True, timeout=120)
        rc, stdout, stderr = process.returncode, process.stdout, process.stderr
    except subprocess.TimeoutExpired as error:
        rc, stdout, stderr = 124, error.stdout or b'', error.stderr or b''
    accepted = False
    if rc == 0:
        try:
            output = json.loads(stdout)
            accepted = output['status'] == 'STAGED_READBACK_ONLY' and \
                       output['nonce'] == nonce and \
                       output['packet_sha256'] == packet['packet_sha256'] and \
                       output['runner']['sha256'] == RUNNER_SHA
        except (ValueError, KeyError, TypeError):
            pass
    terminal = {'schema': 'g279-stage4-v12-local-terminal-v1', 'nonce': nonce,
                'start_sha256': sha(read(start_path)), 'ssh_rc': rc,
                'stdout_sha256': sha(stdout), 'stderr_sha256': sha(stderr),
                'stdout': stdout.decode(errors='replace'),
                'stderr': stderr.decode(errors='replace'),
                'status': 'STAGED_READBACK_ONLY' if accepted else 'UNKNOWN_QUARANTINE',
                'graph': False, 'binding_changed': False, 'replay_allowed': False}
    exclusive(receipts / (nonce + '.TERMINAL.json'), enc(terminal))
    return terminal


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--freeze', action='store_true')
    mode.add_argument('--execute', action='store_true')
    parser.add_argument('--nonce')
    parser.add_argument('--review-file', type=Path)
    args = parser.parse_args()
    if args.freeze:
        packet, _ = freeze_packet(args.nonce or secrets.token_hex(16))
        exclusive(HERE / 'PACKET.json', (json.dumps(packet, sort_keys=True, indent=2) + '\n').encode())
        print(json.dumps({'status': 'CANDIDATE_ONLY', 'nonce': packet['nonce'],
                          'packet_sha256': packet['packet_sha256']}))
    else:
        if not args.review_file:
            parser.error('--execute requires --review-file')
        print(json.dumps(execute(args.review_file), sort_keys=True))


if __name__ == '__main__':
    main()
