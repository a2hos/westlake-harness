#!/usr/bin/env python3
"""Local temporary-tree fixtures; no SSH or project tree mutation."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

import nanhai_plus_g279_sibling_stage1_remote_v2 as remote
import nanhai_plus_g279_sibling_stage1_candidate_v3 as launcher


def sha(data):
    return hashlib.sha256(data).hexdigest()


def packet(old, new, files):
    p = {'schema': 'g279-sibling-stage1-packet-v1', 'host': 'gz02',
         'uid': os.getuid(), 'old_root': str(old), 'new_root': str(new),
         'nonce': 'a' * 32, 'old_env_config_sha256': 'fixture',
         'plan_sha256': 'fixture', 'files': files}
    p['packet_sha256'] = sha(remote.json_bytes(p))
    return p


def setup_tree(base):
    parent = base / 'source'
    parent.mkdir(mode=0o755)
    old = parent / '.nanhai-plus-opaleye-native'
    old.mkdir(mode=0o775)
    (old / 'control').mkdir(mode=0o700)
    (old / 'out').mkdir(mode=0o755)
    (old / 'out/soong-ui-v1').mkdir(mode=0o755)
    (old / 'out/no-namespace-guard-v1').mkdir(mode=0o755)
    rows = []
    for kind, source, dest, data, source_mode, dest_mode in [
        ('control', 'control/ROUTE-AUDIT.json', 'ROUTE-AUDIT.json', b'{"a":1}\n', 0o644, 0o444),
        ('tool', 'out/soong-ui-v1/soong_ui', 'soong-ui-v1/soong_ui', b'ELF-ui', 0o775, 0o555),
        ('tool', 'out/no-namespace-guard-v1/no-namespace-exec', 'no-namespace-guard-v1/no-namespace-exec', b'ELF-guard', 0o775, 0o555),
    ]:
        path = old / source
        path.write_bytes(data)
        path.chmod(source_mode)
        rows.append({'kind': kind, 'source': source, 'dest': dest, 'sha256': sha(data),
                     'bytes': len(data), 'uid': os.getuid(),
                     'source_mode': source_mode, 'dest_mode': dest_mode})
    return old, parent / '.nanhai-plus-opaleye-native-v7', rows


def main():
    if os.getuid() == 0:
        raise SystemExit('fixture requires non-root UID')
    results = []
    with tempfile.TemporaryDirectory(prefix='g279-sibling-fixture-') as tmp:
        old, new, rows = setup_tree(Path(tmp).resolve())
        with patch.object(remote.sys, 'platform', 'linux'), patch.object(remote.os, 'uname', return_value=SimpleNamespace(nodename='GZ02')), patch.object(remote.os, 'listxattr', lambda fd: [], create=True):
            result = remote.stage(packet(old, new, rows))
            assert result['status'] == 'STAGED_READBACK'
            assert result['observed_host'] == 'GZ02'
            results.append('uppercase_GZ02_host_casefold')
            assert len(result['copied']) == 3
            assert stat.S_IMODE(new.stat().st_mode) == 0o755
            assert stat.S_IMODE((new / 'control').stat().st_mode) == 0o700
            assert stat.S_IMODE((new / 'out').stat().st_mode) == 0o755
            assert stat.S_IMODE((new / 'tmp').stat().st_mode) == 0o755
            assert stat.S_IMODE((new / 'staging').stat().st_mode) == 0o700
            assert (new / 'control/STAGE1-RECEIPT.json').is_file()
            results.append('success_readback')
            try:
                remote.stage(packet(old, new, rows))
            except FileExistsError:
                results.append('replay_rejected')
            else:
                raise AssertionError('replay accepted')
    with tempfile.TemporaryDirectory(prefix='g279-sibling-fixture-') as tmp:
        old, new, rows = setup_tree(Path(tmp).resolve())
        (old / rows[-1]['source']).write_bytes(b'bad')
        with patch.object(remote.sys, 'platform', 'linux'), patch.object(remote.os, 'uname', return_value=SimpleNamespace(nodename='GZ02')), patch.object(remote.os, 'listxattr', lambda fd: [], create=True):
            try:
                remote.stage(packet(old, new, rows))
            except ValueError:
                assert not new.exists()
                assert old.is_dir()
                results.append('source_drift_precreate_abort')
            else:
                raise AssertionError('drift accepted')
    with tempfile.TemporaryDirectory(prefix='g279-sibling-fixture-') as tmp:
        old, new, rows = setup_tree(Path(tmp).resolve())
        original = remote.exclusive_bytes
        def fail_second_copy(directory, name, data, file_mode):
            if name == 'soong_ui':
                raise OSError('fixture injected copy failure')
            return original(directory, name, data, file_mode)
        with patch.object(remote.sys, 'platform', 'linux'), patch.object(remote.os, 'uname', return_value=SimpleNamespace(nodename='GZ02')), patch.object(remote.os, 'listxattr', lambda fd: [], create=True), patch.object(remote, 'exclusive_bytes', fail_second_copy):
            try:
                remote.stage(packet(old, new, rows))
            except OSError:
                assert (new / 'control/QUARANTINE.json').is_file()
                assert not (new / 'control/STAGE1-RECEIPT.json').exists()
                assert old.is_dir()
                results.append('partial_failure_quarantined_old_preserved')
            else:
                raise AssertionError('injected failure accepted')
    with tempfile.TemporaryDirectory(prefix='g279-sibling-fixture-') as tmp:
        old, new, rows = setup_tree(Path(tmp).resolve())
        parent = new.parent
        parent.chmod(0o775)
        with patch.object(remote.sys, 'platform', 'linux'), patch.object(remote.os, 'uname', return_value=SimpleNamespace(nodename='GZ02')), patch.object(remote.os, 'listxattr', lambda fd: [], create=True):
            try:
                remote.stage(packet(old, new, rows))
            except ValueError:
                assert not new.exists()
                results.append('group_writable_parent_precreate_abort')
            else:
                raise AssertionError('unsafe parent accepted')
    with tempfile.TemporaryDirectory(prefix='g279-sibling-start-') as tmp:
        fixture_root = Path(tmp).resolve()
        nonce = 'b' * 32
        p = launcher.packet(nonce)
        review = {'decision': 'ACCEPT_STAGE1_REMOTE_WRITE_ONCE',
                  'launcher_sha256': sha(launcher.stable_read(Path(launcher.__file__))),
                  'remote_body_sha256': sha(launcher.stable_read(launcher.REMOTE)),
                  'packet_sha256': p['packet_sha256'], 'new_root': p['new_root'],
                  'independent_reviewer': 'fixture-peer'}
        review_file = fixture_root / 'review.json'
        review_file.write_text(json.dumps(review))
        receipt_dir = fixture_root / 'receipts'
        def interrupted_ssh(*args, **kwargs):
            start_path = receipt_dir / (nonce + '.START.json')
            assert start_path.is_file()
            start = json.loads(start_path.read_text())
            assert start['status'] == 'UNKNOWN_UNTIL_RECONCILED'
            assert start['nonce'] == nonce and start['packet_sha256'] == p['packet_sha256']
            assert start['review_sha256'] == sha(review_file.read_bytes())
            assert start['old_root'] == p['old_root'] and start['new_root'] == p['new_root']
            raise KeyboardInterrupt('fixture abrupt local death after START')
        with patch.object(launcher, 'RECEIPTS', receipt_dir), patch.object(launcher.subprocess, 'run', side_effect=interrupted_ssh):
            try:
                launcher.execute(p, review_file)
            except KeyboardInterrupt:
                pass
            else:
                raise AssertionError('interruption not observed')
            assert not (receipt_dir / (nonce + '.TERMINAL.json')).exists()
            try:
                launcher.execute(p, review_file)
            except FileExistsError:
                results.append('start_fsynced_before_ssh_and_nonce_replay_rejected')
            else:
                raise AssertionError('same nonce replay accepted')
    with tempfile.TemporaryDirectory(prefix='g279-sibling-terminal-') as tmp:
        fixture_root = Path(tmp).resolve()
        nonce = 'c' * 32
        p = launcher.packet(nonce)
        review = {'decision': 'ACCEPT_STAGE1_REMOTE_WRITE_ONCE',
                  'launcher_sha256': sha(launcher.stable_read(Path(launcher.__file__))),
                  'remote_body_sha256': sha(launcher.stable_read(launcher.REMOTE)),
                  'packet_sha256': p['packet_sha256'], 'new_root': p['new_root'],
                  'independent_reviewer': 'fixture-peer'}
        review_file = fixture_root / 'review.json'
        review_file.write_text(json.dumps(review))
        receipt_dir = fixture_root / 'receipts'
        class FakeRun:
            returncode = 0
            stdout = b'{"status":"incomplete"}'
            stderr = b''
        with patch.object(launcher, 'RECEIPTS', receipt_dir), patch.object(launcher.subprocess, 'run', return_value=FakeRun()):
            terminal = launcher.execute(p, review_file)
        assert terminal['status'] == 'UNKNOWN_QUARANTINE'
        assert (receipt_dir / (nonce + '.START.json')).is_file()
        assert (receipt_dir / (nonce + '.TERMINAL.json')).is_file()
        results.append('malformed_remote_rc0_kept_unknown')
    print(json.dumps({'schema': 'g279-sibling-stage1-fixtures-v3', 'rc': 0,
                      'cases': results, 'remote_writes': 0, 'graph': False,
                      'device': False, 'container': False}, sort_keys=True))


if __name__ == '__main__':
    main()
