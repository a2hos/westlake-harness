#!/usr/bin/env python3
"""Prepare or one-shot switch only three G279 local env values after review."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[7]
BASE = HERE.parent
PROPOSED = BASE / 'stage2-candidate-v2/local_env.proposed.md'
STAGING = BASE / 'stage3-v11-staging-candidate-v1'
ACTIVE = ROOT / 'local_env.md'
OLD_SHA = '497517ad575ed18a58b9bb58a3e07306d05a1ddf3b7c3a3be1a3850a9f73cee3'
NEW_SHA = '5fefb4ca26c218683df175452495b86a19b53e69168727adccd7eb365b22d35c'
OLD_CONFIG = '5ce3a58541ef1711890aad8348c3a31a03203f584fa50f1f5c0cb4fd88b49718'
NEW_CONFIG = 'a4e742576589390209188cddf8d3278c294d9e87e8e9c4733e15eee0a951ddba'
STAGING_PACKET_SHA = '362394aa2bf7b20a0952af6297a1e11e047bdfa41e1388668ff5f3357a5d803b'
STAGE2_ROOT_SHA = '7f6d198094fce2710f753f15af8f672fa743e17ebea84451c78ae4d210a898a3'
V11_SHA = '8b6484017d3679f4b14cde7c91e25a76f05289882fc390d3511180611714ffbe'
CHANGED = ['NANHAI_GZ02_NATIVE_PROJECT_ROOT', 'NANHAI_GZ02_NATIVE_SOURCE_VIEW',
           'NANHAI_GZ02_SOONG_UI']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def enc(obj):
    return (json.dumps(obj, sort_keys=True, separators=(',', ':')) + '\n').encode()


def stable_read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        a = os.fstat(fd)
        if not stat.S_ISREG(a.st_mode):
            raise ValueError('not a regular file: ' + str(path))
        chunks = []
        while True:
            block = os.read(fd, 1048576)
            if not block:
                break
            chunks.append(block)
        b = os.fstat(fd)
        if (a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns, a.st_ctime_ns, a.st_mode) != \
           (b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns, b.st_ctime_ns, b.st_mode):
            raise ValueError('file changed while read: ' + str(path))
        return b''.join(chunks), b
    finally:
        os.close(fd)


def config(data):
    text = data.decode()
    match = re.search(r'<!-- NANHAI_ENV_BEGIN -->\s*```json\s*(.*?)\s*```\s*<!-- NANHAI_ENV_END -->', text, re.S)
    if not match:
        raise ValueError('env block')
    obj = json.loads(match.group(1))
    return obj, sha(json.dumps(obj, sort_keys=True, separators=(',', ':')).encode())


def compare(old, new):
    if sha(old) != OLD_SHA or sha(new) != NEW_SHA:
        raise ValueError('raw env bytes drift')
    a, a_sha = config(old)
    b, b_sha = config(new)
    if a_sha != OLD_CONFIG or b_sha != NEW_CONFIG or set(a) != set(b) or \
       any(a[k] != b[k] for k in a if k != 'values') or \
       set(a['values']) != set(b['values']) or \
       sorted(k for k in a['values'] if a['values'][k] != b['values'][k]) != sorted(CHANGED):
        raise ValueError('config identity or three-key diff drift')
    if b['values']['NANHAI_GZ02_NATIVE_PROJECT_ROOT'] != \
       '/data/source/.nanhai-plus-opaleye-native-v7' or \
       b['values']['NANHAI_GZ02_NATIVE_SOURCE_VIEW'] != \
       '/data/source/.nanhai-plus-opaleye-native-v7/source-view' or \
       b['values']['NANHAI_GZ02_SOONG_UI'] != \
       '/data/source/.nanhai-plus-opaleye-native-v7/out/soong-ui-v1/soong_ui' or \
       b['values']['NANHAI_GZ02_AOSP_SOURCE_ROOT'] != \
       '/opt/19.SourceCode/AOSP-16.0.0_r4/android-source':
        raise ValueError('future graph source or sibling path drift')


def packet(nonce):
    if not re.fullmatch('[0-9a-f]{32}', nonce):
        raise ValueError('nonce')
    old, old_stat = stable_read(ACTIVE)
    new, _ = stable_read(PROPOSED)
    compare(old, new)
    if sha(stable_read(STAGING / 'PACKET.json')[0]) != STAGING_PACKET_SHA:
        raise ValueError('v11 staging packet drift')
    if sha(stable_read(BASE / 'stage2-candidate-v2/ROOT-POSTRUN-ACCEPTANCE.json')[0]) != STAGE2_ROOT_SHA:
        raise ValueError('accepted stage2 root receipt drift')
    p = {'schema': 'g279-stage3-config-only-switch-packet-v2',
         'nonce': nonce, 'active_file_sha256': OLD_SHA, 'future_file_sha256': NEW_SHA,
         'active_config_sha256': OLD_CONFIG, 'future_config_sha256': NEW_CONFIG,
         'changed_keys_exact': CHANGED, 'active_mode': stat.S_IMODE(old_stat.st_mode),
         'active_uid': old_stat.st_uid, 'active_gid': old_stat.st_gid,
         'stage2_root_acceptance_sha256': STAGE2_ROOT_SHA,
         'v11_staging_packet_sha256': STAGING_PACKET_SHA,
         'v11_runner_sha256': V11_SHA,
         'graph_authorized': False, 'target_authorized': False,
         'device_authorized': False, 'container_authorized': False,
         'namespace_authorized': False}
    p['packet_sha256'] = sha(enc(p))
    return p


def exclusive(path, data, mode=0o444):
    path.parent.mkdir(parents=True, exist_ok=True)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     mode, dir_fd=parent)
        try:
            offset = 0
            while offset < len(data):
                offset += os.write(fd, data[offset:])
            os.fchmod(fd, mode)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent)
    finally:
        os.close(parent)


def staging_gate(review):
    nonce = '4637ba906d21480c910ebcb13f59d8e7'
    terminal_path = STAGING / 'receipts' / (nonce + '.TERMINAL.json')
    peer_path = STAGING / 'peer-postrun-v1/REVIEW.json'
    root_path = STAGING / 'ROOT-POSTRUN-ACCEPTANCE.json'
    terminal_sha = sha(stable_read(terminal_path)[0])
    peer_sha = sha(stable_read(peer_path)[0])
    root_sha = sha(stable_read(root_path)[0])
    if review.get('v11_staging_terminal_sha256') != terminal_sha or \
       review.get('v11_staging_peer_postrun_sha256') != peer_sha or \
       review.get('v11_staging_root_postrun_sha256') != root_sha:
        raise ValueError('v11 staging evidence SHA mismatch')
    terminal = json.loads(stable_read(terminal_path)[0])
    peer = json.loads(stable_read(peer_path)[0])
    root = json.loads(stable_read(root_path)[0])
    if terminal['ssh_rc'] != 0 or terminal['status'] != 'STAGED_READBACK_ONLY' or \
       terminal['nonce'] != nonce or \
       json.loads(terminal['stdout'])['runner']['sha256'] != V11_SHA or \
       peer.get('decision') != 'ACCEPT_STAGE3_STAGED_BYTES_ONLY' or \
       peer.get('independent_remote_readback', {}).get('runner_sha256') != V11_SHA or \
       root.get('decision') != 'ACCEPT_STAGE3_STAGED_BYTES_ONLY' or \
       root.get('one_shot_terminal_sha256') != terminal_sha or \
       root.get('independent_postrun_sha256') != peer_sha or \
       root.get('nonce') != nonce:
        raise ValueError('v11 staging review status mismatch')


def atomic_switch(root, old, new, nonce, receipts, expected_mode, expected_uid, expected_gid,
                  release_sha256, packet_sha256, after_replace=None):
    """One-shot local mutation; caller must preflight independent release."""
    active = root / 'local_env.md'
    if receipts.joinpath(nonce + '.START.json').exists() or \
       receipts.joinpath(nonce + '.TERMINAL.json').exists():
        raise FileExistsError('nonce started; reconcile, never replay')
    current, s = stable_read(active)
    if current != old or stat.S_IMODE(s.st_mode) != expected_mode or \
       s.st_uid != expected_uid or s.st_gid != expected_gid:
        raise ValueError('current file identity drift')
    compare(old, new)
    start = {'schema': 'g279-stage3-config-only-start-v2',
             'status': 'UNKNOWN_UNTIL_RECONCILED', 'nonce': nonce,
             'active_sha256': OLD_SHA, 'future_sha256': NEW_SHA,
             'release_sha256': release_sha256, 'packet_sha256': packet_sha256,
             'active_inode': s.st_ino, 'active_dev': s.st_dev,
             'replay_allowed': False, 'graph': False}
    start_path = receipts / (nonce + '.START.json')
    exclusive(start_path, enc(start))
    backup = receipts / ('local_env.old.' + OLD_SHA + '.md')
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temp_name = '.local_env.g279-' + nonce + '.tmp'
    replaced = False
    try:
        exclusive(backup, old)
        temp_fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                          0o600, dir_fd=root_fd)
        try:
            offset = 0
            while offset < len(new):
                offset += os.write(temp_fd, new[offset:])
            os.fchmod(temp_fd, expected_mode)
            os.fsync(temp_fd)
        finally:
            os.close(temp_fd)
        if stable_read(root / temp_name)[0] != new:
            raise ValueError('temporary file readback drift')
        latest, later = stable_read(active)
        if latest != old or (later.st_dev, later.st_ino, later.st_mtime_ns,
                             later.st_ctime_ns) != (s.st_dev, s.st_ino, s.st_mtime_ns, s.st_ctime_ns):
            raise ValueError('active file changed before replacement')
        os.replace(temp_name, 'local_env.md', src_dir_fd=root_fd, dst_dir_fd=root_fd)
        replaced = True
        os.fsync(root_fd)
        if after_replace:
            after_replace()
        actual, actual_stat = stable_read(active)
        if actual != new or stat.S_IMODE(actual_stat.st_mode) != expected_mode or \
           actual_stat.st_uid != expected_uid or actual_stat.st_gid != expected_gid:
            raise ValueError('postreplace file drift')
        terminal = {'schema': 'g279-stage3-config-only-terminal-v2',
                    'status': 'SWITCHED_READBACK', 'nonce': nonce,
                    'start_sha256': sha(stable_read(start_path)[0]),
                    'release_sha256': release_sha256,
                    'packet_sha256': packet_sha256,
                    'backup_sha256': sha(stable_read(backup)[0]),
                    'active_sha256': sha(actual), 'active_inode': actual_stat.st_ino,
                    'graph': False, 'device': False, 'container': False,
                    'replay_allowed': False}
        exclusive(receipts / (nonce + '.TERMINAL.json'), enc(terminal))
        return terminal
    except BaseException as error:
        marker = {'schema': 'g279-stage3-config-only-quarantine-v2',
                  'nonce': nonce, 'replaced_may_have_occurred': replaced,
                  'error': type(error).__name__ + ': ' + str(error),
                  'automatic_rollback': False, 'replay_allowed': False}
        try:
            exclusive(receipts / (nonce + '.QUARANTINE.json'), enc(marker))
        except BaseException:
            pass
        raise
    finally:
        os.close(root_fd)


def execute(review_file):
    p = json.loads(stable_read(HERE / 'PACKET.json')[0])
    if p != packet(p['nonce']):
        raise ValueError('packet drift')
    review_data, _ = stable_read(review_file)
    review = json.loads(review_data)
    if review.get('decision') != 'GO_CONFIG_ONLY_LOCAL_SWITCH_ONCE' or \
       review.get('packet_sha256') != p['packet_sha256'] or \
       review.get('switch_script_sha256') != sha(stable_read(Path(__file__))[0]) or \
       review.get('future_file_sha256') != NEW_SHA or \
       review.get('independent_reviewer') in (None, '', 'candidate_author'):
        raise ValueError('independent exact-SHA switch release absent')
    staging_gate(review)
    old, _ = stable_read(ACTIVE)
    new, _ = stable_read(PROPOSED)
    def env_postcheck():
        probe = subprocess.run([sys.executable, str(ROOT / 'scripts/nanhai_plus_env.py'), '--check'],
                               capture_output=True, text=True)
        if probe.returncode or json.loads(probe.stdout)['config_sha256'] != NEW_CONFIG:
            raise RuntimeError('post-switch env parser mismatch')
    outcome = atomic_switch(ROOT, old, new, p['nonce'], HERE / 'receipts',
                            p['active_mode'], p['active_uid'], p['active_gid'],
                            sha(review_data), p['packet_sha256'],
                            after_replace=env_postcheck)
    return {'status': outcome['status'], 'env_check_rc': 0,
            'terminal': str(HERE / 'receipts' / (p['nonce'] + '.TERMINAL.json'))}


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--freeze', action='store_true')
    mode.add_argument('--execute', action='store_true')
    parser.add_argument('--nonce')
    parser.add_argument('--review-file', type=Path)
    args = parser.parse_args()
    if args.freeze:
        p = packet(args.nonce or secrets.token_hex(16))
        exclusive(HERE / 'PACKET.json', (json.dumps(p, sort_keys=True, indent=2) + '\n').encode())
        print(json.dumps({'status': 'CANDIDATE_ONLY', 'nonce': p['nonce'],
                          'packet_sha256': p['packet_sha256']}))
    else:
        if not args.review_file:
            parser.error('--execute requires --review-file')
        print(json.dumps(execute(args.review_file), sort_keys=True))


if __name__ == '__main__':
    main()
