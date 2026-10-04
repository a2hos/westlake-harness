#!/usr/bin/env python3
"""Freeze or execute one reviewed G279 sibling stage-2; default is local only."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g279-native-graph-source-choice-v1/private-sibling-migration-candidate-v1'
OUT = BASE / 'stage2-candidate-v1'
MAP = BASE / 'SOURCE-VIEW-LINKS.tsv'
REMOTE = ROOT / 'scripts/nanhai_plus_g279_sibling_stage2_remote_v1.py'
OLD = '/data/source/.nanhai-plus-opaleye-native'
NEW = OLD + '-v7'
STAGE1_RECEIPT_SHA = '5ad4c321bf68bd50d84642684736dba4c345de3906720d31a92be6032e2d4b20'
MAP_SHA = 'f79646328e9f2fbdb4c6f00f32e0722ceb21424992c27820efc5fa28f79a458c'
OLD_CONFIG_SHA = '5ce3a58541ef1711890aad8348c3a31a03203f584fa50f1f5c0cb4fd88b49718'
SSH = ['/usr/bin/ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
       '-o', 'HostKeyAlgorithms=ssh-ed25519', '-o', 'ConnectTimeout=10',
       '-o', 'UserKnownHostsFile=/Users/alexyang/.ssh/known_hosts',
       'gz02', '/usr/bin/python3.12 -']


def sha(b):
    return hashlib.sha256(b).hexdigest()


def encoded(x):
    return (json.dumps(x, sort_keys=True, separators=(',', ':')) + '\n').encode()


def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        a = os.fstat(fd)
        if not os.path.isfile(path) or a.st_nlink != 1:
            raise ValueError('local input identity')
        b = bytearray()
        while True:
            chunk = os.read(fd, 1048576)
            if not chunk:
                break
            b.extend(chunk)
        c = os.fstat(fd)
        if (a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns, a.st_ctime_ns) != \
           (c.st_dev, c.st_ino, c.st_size, c.st_mtime_ns, c.st_ctime_ns):
            raise ValueError('local input changed')
        return bytes(b)
    finally:
        os.close(fd)


def proposal():
    current = read(ROOT / 'local_env.md')
    env = json.loads(subprocess.run(['python3', str(ROOT / 'scripts/nanhai_plus_env.py'), '--json'],
                                    check=True, capture_output=True).stdout)
    if env['NANHAI_ENV_CONFIG_SHA256'] != OLD_CONFIG_SHA or \
       env['NANHAI_GZ02_NATIVE_PROJECT_ROOT'] != OLD or \
       env['NANHAI_GZ02_NATIVE_SOURCE_VIEW'] != OLD + '/source-view' or \
       env['NANHAI_GZ02_SOONG_UI'] != OLD + '/out/soong-ui-v1/soong_ui' or \
       env['NANHAI_CONTAINER_POLICY'] != 'forbidden':
        raise ValueError('old authority drift')
    text = current.decode()
    for key, suffix in [('NANHAI_GZ02_NATIVE_PROJECT_ROOT', ''),
                        ('NANHAI_GZ02_NATIVE_SOURCE_VIEW', '/source-view'),
                        ('NANHAI_GZ02_SOONG_UI', '/out/soong-ui-v1/soong_ui')]:
        old_line = '"' + key + '": "' + OLD + suffix + '"'
        if text.count(old_line) != 1:
            raise ValueError('proposed key not unique: ' + key)
        text = text.replace(old_line, '"' + key + '": "' + NEW + suffix + '"')
    future = text.encode()
    block = re.search(r'<!-- NANHAI_ENV_BEGIN -->\s*```json\s*(.*?)\s*```\s*<!-- NANHAI_ENV_END -->', text, re.S)
    if block is None:
        raise ValueError('env block')
    config = json.loads(block.group(1))
    config_sha = sha(json.dumps(config, sort_keys=True, separators=(',', ':')).encode())
    paths = {k: env[k] for k in ('NANHAI_SOURCE_POOL_ROOT',
             'NANHAI_GZ02_AOSP_SOURCE_ROOT', 'NANHAI_GZ02_SOONG_WORKTREE')}
    paths.update(NANHAI_GZ02_NATIVE_PROJECT_ROOT=NEW,
                 NANHAI_GZ02_NATIVE_SOURCE_VIEW=NEW + '/source-view',
                 NANHAI_GZ02_SOONG_UI=NEW + '/out/soong-ui-v1/soong_ui')
    binding = {'schema': 'nanhai-g279-native-graph-env-v1',
               'env_config_sha256': config_sha,
               'local_env_file_sha256': sha(future), 'paths': paths}
    binding_bytes = (json.dumps(binding, sort_keys=True, indent=2) + '\n').encode()
    return current, future, config_sha, binding_bytes


def links():
    data = read(MAP)
    if sha(data) != MAP_SHA:
        raise ValueError('mapping SHA drift')
    lines = data.decode().splitlines()
    if lines[0] != 'relative\tsymlink_target\texpected_head\tresolved_target':
        raise ValueError('mapping header')
    rows = [dict(zip(lines[0].split('\t'), line.split('\t'))) for line in lines[1:]]
    if len(rows) != 46 or any(len(line.split('\t')) != 4 for line in lines[1:]) or \
       [r['relative'] for r in rows] != sorted(r['relative'] for r in rows):
        raise ValueError('mapping rows')
    return rows


def packet(nonce):
    if not re.fullmatch('[0-9a-f]{32}', nonce):
        raise ValueError('nonce')
    current, future, config_sha, binding = proposal()
    p = {'schema': 'g279-sibling-stage2-packet-v1', 'nonce': nonce,
         'old_root': OLD, 'new_root': NEW, 'stage1_receipt_sha256': STAGE1_RECEIPT_SHA,
         'old_local_env_sha256': sha(current), 'new_local_env_sha256': sha(future),
         'old_config_sha256': OLD_CONFIG_SHA, 'new_config_sha256': config_sha,
         'mapping_sha256': MAP_SHA, 'links': links(),
         'binding_sha256': sha(binding), 'binding_hex': binding.hex(),
         'binding_changed': False, 'graph': False, 'device': False,
         'container': False, 'namespace': False}
    p['packet_sha256'] = sha(encoded(p))
    return p, future, binding


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
    if len(rows) != 1 or rows[0][1] != 'ssh-ed25519':
        raise ValueError('known host row drift')
    key = base64.b64decode(rows[0][2], validate=True)
    fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(key).digest()).decode().rstrip('=')
    if fingerprint != 'SHA256:RuAqHWgFJEIEcb4hC+WXULCRfV3uCsayP4Iw4aJvwzg':
        raise ValueError('known host fingerprint drift')


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


def freeze(nonce):
    p, future, binding = packet(nonce)
    exclusive(OUT / 'PACKET.json', (json.dumps(p, sort_keys=True, indent=2) + '\n').encode())
    exclusive(OUT / 'local_env.proposed.md', future)
    exclusive(OUT / 'g279-native-graph-env.proposed.json', binding)
    return {'status': 'CANDIDATE_ONLY', 'packet_sha256': p['packet_sha256'],
            'new_config_sha256': p['new_config_sha256'],
            'binding_sha256': p['binding_sha256'], 'nonce': nonce}


def execute(review_path):
    host_identity()
    p = json.loads(read(OUT / 'PACKET.json'))
    expected, future, binding = packet(p['nonce'])
    if p != expected or read(OUT / 'local_env.proposed.md') != future or \
       read(OUT / 'g279-native-graph-env.proposed.json') != binding:
        raise ValueError('frozen packet/proposal drift')
    review_data = read(review_path)
    review = json.loads(review_data)
    if review.get('decision') != 'GO_STAGE2_REMOTE_WRITE_ONCE' or \
       review.get('packet_sha256') != p['packet_sha256'] or \
       review.get('launcher_sha256') != sha(read(Path(__file__))) or \
       review.get('remote_body_sha256') != sha(read(REMOTE)) or \
       review.get('independent_reviewer') in (None, '', 'candidate_author'):
        raise ValueError('independent exact-SHA release absent')
    nonce = p['nonce']
    receipt_dir = OUT / 'receipts'
    if (receipt_dir / (nonce + '.START.json')).exists() or \
       (receipt_dir / (nonce + '.TERMINAL.json')).exists():
        raise FileExistsError('nonce already started; reconcile, never replay')
    source = read(REMOTE)
    program = ('PACKET = ' + repr(p) + '\n').encode() + source
    start = {'schema': 'g279-stage2-local-start-v1', 'status': 'UNKNOWN_UNTIL_RECONCILED',
             'nonce': nonce, 'packet_sha256': p['packet_sha256'],
             'launcher_sha256': sha(read(Path(__file__))),
             'remote_body_sha256': sha(source), 'review_sha256': sha(review_data),
             'old_root': OLD, 'new_root': NEW, 'replay_allowed': False}
    start_path = receipt_dir / (nonce + '.START.json')
    exclusive(start_path, encoded(start))
    try:
        run = subprocess.run(SSH, input=program, capture_output=True, timeout=180)
        rc, stdout, stderr = run.returncode, run.stdout, run.stderr
    except subprocess.TimeoutExpired as e:
        rc, stdout, stderr = 124, e.stdout or b'', e.stderr or b''
    accepted = False
    if rc == 0:
        try:
            result = json.loads(stdout)
            accepted = result.get('status') == 'STAGED_READBACK_ONLY' and \
                       result.get('nonce') == nonce and result.get('links') == 46 and \
                       result.get('packet_sha256') == p['packet_sha256']
        except (ValueError, AttributeError):
            pass
    terminal = {'schema': 'g279-stage2-local-terminal-v1', 'nonce': nonce,
                'start_sha256': sha(read(start_path)), 'ssh_rc': rc,
                'stdout_sha256': sha(stdout), 'stderr_sha256': sha(stderr),
                'stdout': stdout.decode(errors='replace'), 'stderr': stderr.decode(errors='replace'),
                'status': 'STAGED_READBACK_ONLY' if accepted else 'UNKNOWN_QUARANTINE',
                'replay_allowed': False, 'binding_changed': False}
    exclusive(receipt_dir / (nonce + '.TERMINAL.json'), encoded(terminal))
    return terminal


def main():
    ap = argparse.ArgumentParser()
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument('--freeze', action='store_true')
    mode.add_argument('--execute', action='store_true')
    ap.add_argument('--nonce')
    ap.add_argument('--review-file', type=Path)
    args = ap.parse_args()
    if args.freeze:
        print(json.dumps(freeze(args.nonce or secrets.token_hex(16)), sort_keys=True))
    else:
        if not args.review_file:
            ap.error('--execute requires --review-file')
        print(json.dumps(execute(args.review_file), sort_keys=True))


if __name__ == '__main__':
    main()
