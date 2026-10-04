#!/usr/bin/env python3
"""Prepare or execute one G279 sibling stage-1, after independent release review.

The default command is read-only. --execute requires an external exact-SHA
release receipt; no such receipt is issued by this candidate.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g279-native-graph-source-choice-v1/private-sibling-migration-candidate-v1'
PLAN = BASE / 'MIGRATION-PLAN.json'
PLAN_SHA = '4ccfe0e18788c0301d01782926b06d564318f703fa3e434164d32c521182e565'
REMOTE = ROOT / 'scripts/nanhai_plus_g279_sibling_stage1_remote_v2.py'
RECEIPTS = BASE / 'stage1-candidate-v3/receipts'
EXPECTED_CONFIG = '5ce3a58541ef1711890aad8348c3a31a03203f584fa50f1f5c0cb4fd88b49718'
SSH = ['/usr/bin/ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
       '-o', 'HostKeyAlgorithms=ssh-ed25519', '-o', 'ConnectTimeout=10',
       '-o', 'UserKnownHostsFile=/Users/alexyang/.ssh/known_hosts',
       'gz02', '/usr/bin/python3.12 -']
KNOWN_HOST = '[1.95.90.207]:58222'
KNOWN_FINGERPRINT = 'SHA256:RuAqHWgFJEIEcb4hC+WXULCRfV3uCsayP4Iw4aJvwzg'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def stable_read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        a = os.fstat(fd)
        if not stat.S_ISREG(a.st_mode):
            raise ValueError('not a regular local input: ' + str(path))
        parts = []
        while True:
            data = os.read(fd, 1048576)
            if not data:
                break
            parts.append(data)
        b = os.fstat(fd)
        if (a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns, a.st_ctime_ns, a.st_mode) != \
           (b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns, b.st_ctime_ns, b.st_mode):
            raise ValueError('local input changed during read: ' + str(path))
        return b''.join(parts)
    finally:
        os.close(fd)


def authority():
    data = stable_read(PLAN)
    if digest(data) != PLAN_SHA:
        raise ValueError('migration plan SHA drift')
    plan = json.loads(data)
    env_result = subprocess.run([sys.executable, str(ROOT / 'scripts/nanhai_plus_env.py'), '--json'],
                                capture_output=True, text=True, check=True)
    env = json.loads(env_result.stdout)
    if env['NANHAI_ENV_CONFIG_SHA256'] != EXPECTED_CONFIG or \
       env['NANHAI_GZ02_NATIVE_PROJECT_ROOT'] != plan['old_root'] or \
       env['NANHAI_GZ02_BUILD_HOST'] != 'gz02' or \
       env['NANHAI_CONTAINER_POLICY'] != 'forbidden':
        raise ValueError('active old-root authority drift')
    if env['NANHAI_GZ02_NATIVE_SOURCE_VIEW'] != plan['old_root'] + '/source-view' or \
       env['NANHAI_GZ02_SOONG_UI'] != plan['old_root'] + '/out/soong-ui-v1/soong_ui':
        raise ValueError('active old-root path drift')
    return plan, env


def host_identity():
    setting = subprocess.run(['/usr/bin/ssh', '-G', 'gz02'], capture_output=True,
                             text=True, check=True)
    config = {}
    for line in setting.stdout.splitlines():
        key, _, value = line.partition(' ')
        if key in ('user', 'hostname', 'port', 'proxycommand', 'proxyjump'):
            config[key] = value.strip()
    if {k: config.get(k) for k in ('user', 'hostname', 'port')} != \
       {'user': 'AlexYang', 'hostname': '1.95.90.207', 'port': '58222'} or \
       config.get('proxycommand', 'none') != 'none' or config.get('proxyjump', 'none') != 'none':
        raise ValueError('gz02 SSH route drift')
    known = stable_read(Path('/Users/alexyang/.ssh/known_hosts')).decode()
    matches = [line.split() for line in known.splitlines()
               if line.startswith(KNOWN_HOST + ' ')]
    if len(matches) != 1 or len(matches[0]) < 3 or matches[0][1] != 'ssh-ed25519':
        raise ValueError('gz02 known_hosts entry drift')
    raw = base64.b64decode(matches[0][2], validate=True)
    fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip('=')
    if fingerprint != KNOWN_FINGERPRINT:
        raise ValueError('gz02 host key fingerprint drift')
    return {'ssh': config, 'host_key_fingerprint': fingerprint}


def file_specs(plan):
    seeds = plan['control_old_observed']
    if len(seeds) != 8:
        raise ValueError('control inventory count drift')
    selected = [x for x in seeds if x['name'] != 'g279-native-graph-env.json']
    if len(selected) != 7 or {x['name'] for x in selected} != set(plan['control_recreation']['exact_byte_seeds_to_restamp_by_sha']):
        raise ValueError('seven control seeds drift')
    files = []
    for x in selected:
        files.append({'kind': 'control', 'source': 'control/' + x['name'],
                      'dest': x['name'], 'sha256': x['sha256'], 'bytes': x['bytes'],
                      'uid': 1000, 'source_mode': int(x['mode'], 8), 'dest_mode': 0o444})
    tools = plan['host_tool_inputs']['observed_old_outputs']
    if len(tools) != 2:
        raise ValueError('host tool inventory drift')
    for x in tools:
        files.append({'kind': 'tool', 'source': x['relative'],
                      'dest': x['relative'].removeprefix('out/'),
                      'sha256': x['sha256'], 'bytes': x['bytes'], 'uid': 1000,
                      'source_mode': int(x['mode'], 8), 'dest_mode': 0o555})
    return files


def packet(nonce):
    plan, env = authority()
    host_identity()
    if len(nonce) != 32 or any(c not in '0123456789abcdef' for c in nonce):
        raise ValueError('bad nonce')
    base = {'schema': 'g279-sibling-stage1-packet-v1', 'host': 'GZ02', 'uid': 1000,
            'old_root': plan['old_root'], 'new_root': plan['proposed_new_root'],
            'nonce': nonce, 'old_env_config_sha256': env['NANHAI_ENV_CONFIG_SHA256'],
            'plan_sha256': PLAN_SHA, 'files': file_specs(plan)}
    base['packet_sha256'] = digest((json.dumps(base, sort_keys=True, separators=(',', ':')) + '\n').encode())
    return base


def program(p):
    source = stable_read(REMOTE)
    if b'PACKET' not in source or b'graph_command' in source or b'os.system' in source:
        raise ValueError('remote body guard failed')
    header = ('PACKET = ' + repr(p) + '\n').encode()
    return header + source


def exclusive_local_receipt(name, body):
    RECEIPTS.mkdir(parents=True, exist_ok=True)
    if RECEIPTS.is_symlink() or not RECEIPTS.is_dir():
        raise ValueError('receipt directory identity mismatch')
    path = RECEIPTS / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
    try:
        data = (json.dumps(body, sort_keys=True, indent=2) + '\n').encode()
        position = 0
        while position < len(data):
            position += os.write(fd, data[position:])
        os.fsync(fd)
    finally:
        os.close(fd)
    parent_fd = os.open(RECEIPTS, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    return path


def execute(p, review_file):
    review_data = stable_read(review_file)
    review = json.loads(review_data)
    me_sha = digest(stable_read(Path(__file__)))
    remote_sha = digest(stable_read(REMOTE))
    if review.get('decision') != 'ACCEPT_STAGE1_REMOTE_WRITE_ONCE' or \
       review.get('launcher_sha256') != me_sha or \
       review.get('remote_body_sha256') != remote_sha or \
       review.get('packet_sha256') != p['packet_sha256'] or \
       review.get('new_root') != p['new_root'] or \
       review.get('independent_reviewer') in (None, '', 'candidate_author'):
        raise ValueError('no exact independent stage-1 release')
    remote_program = program(p)
    nonce = p['nonce']
    if (RECEIPTS / (nonce + '.START.json')).exists() or \
       (RECEIPTS / (nonce + '.TERMINAL.json')).exists():
        raise FileExistsError('nonce already started or terminal; reconcile, never replay')
    start = {'schema': 'g279-sibling-stage1-local-start-v2',
             'status': 'UNKNOWN_UNTIL_RECONCILED', 'nonce': nonce,
             'packet_sha256': p['packet_sha256'], 'launcher_sha256': me_sha,
             'remote_body_sha256': remote_sha,
             'review_sha256': digest(review_data),
             'old_root': p['old_root'], 'new_root': p['new_root'],
             'ssh_argv': SSH, 'replay_allowed': False,
             'remote_writes_observed': 0, 'graph': False, 'device': False,
             'container': False}
    start_path = exclusive_local_receipt(nonce + '.START.json', start)
    try:
        run = subprocess.run(SSH, input=remote_program, capture_output=True, timeout=90)
        rc, stdout, stderr = run.returncode, run.stdout, run.stderr
    except subprocess.TimeoutExpired as error:
        rc, stdout, stderr = 124, error.stdout or b'', error.stderr or b''
    remote_receipt = None
    if rc == 0:
        try:
            candidate = json.loads(stdout)
            if candidate.get('schema') == 'g279-sibling-stage1-remote-receipt-v1' and \
               candidate.get('status') == 'STAGED_READBACK' and \
               candidate.get('nonce') == nonce and candidate.get('new_root') == p['new_root'] and \
               len(candidate.get('copied', [])) == 9:
                remote_receipt = candidate
        except (ValueError, TypeError, AttributeError):
            pass
    accepted = rc == 0 and remote_receipt is not None
    body = {'schema': 'g279-sibling-stage1-local-terminal-v2', 'nonce': nonce,
            'start_receipt': str(start_path), 'start_sha256': digest(stable_read(start_path)),
            'packet_sha256': p['packet_sha256'], 'ssh_argv': SSH,
            'ssh_rc': rc, 'stdout_sha256': digest(stdout),
            'stderr_sha256': digest(stderr), 'stdout': stdout.decode('utf-8', 'replace'),
            'stderr': stderr.decode('utf-8', 'replace'),
            'remote_receipt_status': remote_receipt['status'] if remote_receipt else None,
            'execution_uncertain': not accepted,
            'replay_allowed': False, 'old_root_preserved': True}
    path = exclusive_local_receipt(nonce + '.TERMINAL.json', body)
    return {'receipt': str(path), 'ssh_rc': rc,
            'status': 'READBACK_ONLY' if accepted else 'UNKNOWN_QUARANTINE'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--static-check', action='store_true')
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--review-file', type=Path)
    parser.add_argument('--nonce')
    args = parser.parse_args()
    if args.execute and not args.review_file:
        parser.error('--execute requires --review-file')
    if args.execute and not args.nonce:
        parser.error('--execute requires the reviewed --nonce')
    p = packet(args.nonce or secrets.token_hex(16))
    source = program(p)
    if not args.execute:
        print(json.dumps({'schema': 'g279-sibling-stage1-static-candidate-v3',
                          'status': 'READONLY_CANDIDATE', 'packet_sha256': p['packet_sha256'],
                          'remote_program_sha256': digest(source),
                          'remote_body_sha256': digest(stable_read(REMOTE)),
                          'files': len(p['files']), 'new_root': p['new_root'],
                          'remote_writes': 0, 'graph': False, 'device': False,
                          'container': False}, sort_keys=True))
        return 0
    print(json.dumps(execute(p, args.review_file), sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
