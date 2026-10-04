#!/usr/bin/env python3
"""Freeze/review or one-shot stage exact v11 under sibling; never run graph."""
import argparse
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
V11 = ROOT / 'scripts/nanhai_plus_native_graph_v11.py'
REMOTE = HERE / 'remote_body.py'
STAGE1 = BASE / 'stage1-candidate-v3/peer-postrun-v1/remote.stdout.raw'
STAGE2 = BASE / 'stage2-candidate-v2/peer-postrun-v1/remote.stdout.raw'
STAGE2_PEER = BASE / 'stage2-candidate-v2/peer-postrun-v1/REVIEW.json'
STAGE2_ROOT = BASE / 'stage2-candidate-v2/ROOT-POSTRUN-ACCEPTANCE.json'
V11_PEER = ROOT / 'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g279-native-graph-source-choice-v1/runner-v11-sibling-candidate-v1/peer-review-v1/REVIEW.json'
ROOT_PATH = '/data/source/.nanhai-plus-opaleye-native-v7'
OLD_PATH = '/data/source/.nanhai-plus-opaleye-native'
RUNNER_SHA = '8b6484017d3679f4b14cde7c91e25a76f05289882fc390d3511180611714ffbe'
V11_PEER_SHA = 'dbc8ea685a623f5140c9015a73cca0cd6e2a42a46bafb4677acce00f950961cb'
STAGE2_PEER_SHA = '78d51ad3d3ae1c181cfc3619e428b793ad09b2d3d0ac897e2a415cc9668fb7ca'
STAGE2_ROOT_SHA = '7f6d198094fce2710f753f15af8f672fa743e17ebea84451c78ae4d210a898a3'
STAGE1_PROBE_SHA = '37e09400ee2191cd9cbb101d71f9d51181041aef035f7b2a65fc7ebff8f8ac3d'
STAGE2_PROBE_SHA = 'e6b0ed6b31789cdd898b8fefdd6153484dd2321196970e245a87c200f45fe29f'
ACTIVE_ENV_SHA = '497517ad575ed18a58b9bb58a3e07306d05a1ddf3b7c3a3be1a3850a9f73cee3'
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
        raise ValueError('active old binding changed before v11 staging')
    runner = exact(V11, RUNNER_SHA)
    if len(runner) != 45330:
        raise ValueError('runner byte count drift')
    if json.loads(exact(V11_PEER, V11_PEER_SHA))['decision'] != 'GO_STATIC':
        raise ValueError('v11 independent static review drift')
    if json.loads(exact(STAGE2_PEER, STAGE2_PEER_SHA))['decision'] != \
       'ACCEPT_STAGE2_STAGED_READBACK_ONLY':
        raise ValueError('stage2 peer review drift')
    if json.loads(exact(STAGE2_ROOT, STAGE2_ROOT_SHA))['decision'] != \
       'ACCEPT_STAGE2_STAGED_READBACK_ONLY':
        raise ValueError('stage2 root acceptance drift')
    first = json.loads(exact(STAGE1, STAGE1_PROBE_SHA))
    second = json.loads(exact(STAGE2, STAGE2_PROBE_SHA))
    def directory(row):
        return {k: row[k] for k in ('dev', 'ino', 'uid', 'mode')}
    def identity(row):
        return {k: row[k] for k in ('dev', 'ino', 'uid', 'gid', 'mode', 'bytes', 'sha256')}
    files = [{'path': item['path'], 'identity': identity(item)}
             for item in second['stage1_files']]
    for name in ('STAGE1-LEASE.json', 'STAGE1-RECEIPT.json'):
        files.append({'path': 'control/' + name,
                      'identity': identity(first['receipts'][name])})
    for key, name in [('binding', 'g279-native-graph-env.json'),
                      ('stage2_lease', 'STAGE2-LEASE.json'),
                      ('stage2_receipt', 'STAGE2-RECEIPT.json')]:
        files.append({'path': 'control/' + name,
                      'identity': identity(second[key])})
    files.sort(key=lambda x: x['path'])
    if len(files) != 14 or len({x['path'] for x in files}) != 14 or \
       second['link_count'] != 46 or \
       second['binding']['sha256'] != '9157f7d3e719c2fe1d2186bb79095500572049c4b7a3bc8d3befbdb98d47ae2f':
        raise ValueError('stage1/2 accepted input inventory drift')
    packet = {'schema': 'g279-stage3-v11-staging-packet-v1',
              'nonce': nonce, 'root': ROOT_PATH, 'old_root': OLD_PATH,
              'root_id': directory(second['directories']['root']),
              'control_id': directory(second['directories']['control']),
              'old_root_id': directory(second['directories']['old_root']),
              'source_view_id': directory(second['directories']['source_view']),
              'unchanged_files': files,
              'stage2_peer_sha256': STAGE2_PEER_SHA,
              'stage2_root_acceptance_sha256': STAGE2_ROOT_SHA,
              'v11_static_peer_sha256': V11_PEER_SHA,
              'runner': {'name': V11.name, 'sha256': RUNNER_SHA,
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


def execute(review_path):
    sys.path.insert(0, str(ROOT / 'scripts'))
    from nanhai_plus_g279_sibling_stage2_candidate_v2 import host_identity
    host_identity()
    packet = json.loads(read(HERE / 'PACKET.json'))
    reconstructed, runner = freeze_packet(packet['nonce'])
    if packet != reconstructed:
        raise ValueError('frozen packet drift')
    review_data = read(review_path)
    review = json.loads(review_data)
    if review.get('decision') != 'GO_V11_STAGING_ONCE' or \
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
    start = {'schema': 'g279-stage3-v11-local-start-v1',
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
    terminal = {'schema': 'g279-stage3-v11-local-terminal-v1', 'nonce': nonce,
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
