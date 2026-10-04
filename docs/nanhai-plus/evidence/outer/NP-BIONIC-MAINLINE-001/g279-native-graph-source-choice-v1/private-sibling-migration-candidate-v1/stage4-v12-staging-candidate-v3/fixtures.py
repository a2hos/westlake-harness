#!/usr/bin/env python3
"""Isolated local v12 staging writer tests; no SSH, graph or shared writes."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def setup(base, remote):
    root, old = base / 'new', base / 'old'
    root.mkdir(mode=0o755)
    old.mkdir(mode=0o775)
    root.chmod(0o755)
    old.chmod(0o775)
    for name, mode in [('control', 0o700), ('out', 0o755),
                       ('source-view', 0o755), ('staging', 0o700), ('tmp', 0o755)]:
        (root / name).mkdir(mode=mode)
        (root / name).chmod(mode)
    specs = []
    names = ['control/' + x for x in (
        'MANIFEST-HEADS.tsv', 'ROUTE-AUDIT.json', 'generate_manifest_heads.py',
        'nanhai_plus_native_soong_ui.sh', 'nanhai_plus_native_source_view.py',
        'no-namespace-exec.c', 'soong-ui-no-nsjail.patch', 'STAGE1-LEASE.json',
        'STAGE1-RECEIPT.json', 'STAGE2-LEASE.json', 'STAGE2-RECEIPT.json',
        'STAGE3-V11-LEASE.json', 'STAGE3-V11-RECEIPT.json',
        'nanhai_plus_native_graph_v11.py', 'g279-native-graph-env.json')] + [
        'out/no-namespace-guard-v1/no-namespace-exec', 'out/soong-ui-v1/soong_ui']
    for i, name in enumerate(names):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(('frozen-fixture-' + str(i)).encode())
        path.chmod(0o555 if name.startswith('out/') else
                   0o400 if 'STAGE' in name or name.endswith('graph-env.json') else 0o444)
        specs.append({'path': name, 'identity': remote.regular(str(path))})
    def identity(path):
        s = path.stat()
        return {'dev': s.st_dev, 'ino': s.st_ino, 'uid': s.st_uid, 'mode': s.st_mode & 0o777}
    data = b'v12-fixture-runner\n'
    packet = {'schema': 'g279-stage4-v12-staging-packet-v1',
              'nonce': '33333333333333333333333333333333',
              'root': str(root), 'old_root': str(old),
              'root_id': identity(root), 'control_id': identity(root / 'control'),
              'old_root_id': identity(old),
              'source_view_id': identity(root / 'source-view'),
              'unchanged_files': sorted(specs, key=lambda x: x['path']),
              'control_entries_before': sorted(p.name for p in (root / 'control').iterdir()),
              'runner': {'name': 'nanhai_plus_native_graph_v12.py',
                         'sha256': hashlib.sha256(data).hexdigest(),
                         'bytes': len(data), 'mode': 0o444}}
    packet['packet_sha256'] = remote.sha(remote.enc(packet))
    return root, old, packet, data


def main():
    remote = load('remote_body')
    launcher = load('launcher')
    if not hasattr(remote.os, 'listxattr'):
        remote.os.listxattr = lambda _fd: []  # macOS fixture host
    checks = []
    frozen = json.loads((HERE / 'PACKET.json').read_text())
    checks.append(('reviewed v12 packet reconstructs exactly',
                   launcher.freeze_packet(frozen['nonce'])[0] == frozen and
                   len(frozen['unchanged_files']) == 17))
    with tempfile.TemporaryDirectory(prefix='.v12-review-fixture-', dir=launcher.ROOT) as td:
        bogus = Path(td) / 'review.json'
        bogus.write_text('{}')
        with mock.patch.object(launcher, 'host_identity', return_value=None):
            try:
                launcher.execute(bogus)
                denied = False
            except ValueError as error:
                denied = 'release absent' in str(error)
        checks.append(('unreleased execute denied before START/SSH',
                       denied and not (HERE / 'receipts').exists()))
    # Local route and pinned Ed25519 validation never opens a network connection.
    route = 'user AlexYang\nhostname 1.95.90.207\nport 58222\nproxycommand none\nproxyjump none\n'
    host_path = Path('/Users/alexyang/.ssh/known_hosts')
    live_rows = [line for line in host_path.read_text().splitlines()
                 if line.startswith('[1.95.90.207]:58222 ')]
    pinned = [line for line in live_rows if line.split()[1] == 'ssh-ed25519']
    def key_case(rows, route_text=route):
        original_read = launcher.read
        def local_read(path):
            return ('\n'.join(rows) + '\n').encode() if path == host_path else original_read(path)
        with mock.patch.object(launcher, 'read', side_effect=local_read), \
             mock.patch.object(launcher.subprocess, 'run', return_value=mock.Mock(stdout=route_text)):
            try:
                launcher.host_identity()
                return 'PASS'
            except ValueError as error:
                return str(error)
    checks.append(('one pinned Ed25519 with unrelated RSA/ECDSA rows accepted',
                   len(pinned) == 1 and key_case([pinned[0]] +
                   [r for r in live_rows if r not in pinned]) == 'PASS'))
    checks.append(('duplicate Ed25519 row denied',
                   key_case([pinned[0], pinned[0]]) == 'known host ed25519 row drift'))
    tokens = pinned[0].split()
    tokens[2] = 'AAAA'
    checks.append(('Ed25519 fingerprint drift denied',
                   key_case([' '.join(tokens)]) == 'known host fingerprint drift'))
    checks.append(('SSH route drift denied',
                   key_case([pinned[0]], route.replace('port 58222', 'port 22')) ==
                   'SSH route drift: port'))
    checks.append(('actual SSH remains strict Ed25519',
                   'StrictHostKeyChecking=yes' in launcher.SSH and
                   'HostKeyAlgorithms=ssh-ed25519' in launcher.SSH and
                   'UserKnownHostsFile=/Users/alexyang/.ssh/known_hosts' in launcher.SSH))
    with tempfile.TemporaryDirectory(prefix='.v12-stage-fixture-', dir=launcher.ROOT) as td:
        def run_case(label, mutation=None):
            base = Path(td) / label
            base.mkdir()
            root, old, packet, data = setup(base, remote)
            with mock.patch.object(remote, 'ROOT', str(root)), \
                 mock.patch.object(remote, 'OLD', str(old)), \
                 mock.patch.object(remote, 'host_guard', return_value=None), \
                 mock.patch.object(remote, 'EXPECTED_UID', os.getuid()):
                outcome = mutation(remote, root, packet, data) if mutation else remote.stage(packet, data)
            return root, old, outcome
        root, _, result = run_case('positive')
        row = remote.regular(str(root / 'control/nanhai_plus_native_graph_v12.py'))
        checks.append(('positive mode0444 exact runner and remote receipt',
                       result['status'] == 'STAGED_READBACK_ONLY' and
                       row['mode'] == 0o444 and
                       (root / 'control/STAGE4-V12-RECEIPT.json').is_file()))
        def substitute(remote, root, packet, data):
            path = root / packet['unchanged_files'][0]['path']
            content = path.read_bytes()
            mode = path.stat().st_mode & 0o777
            path.unlink()
            path.write_bytes(content)
            path.chmod(mode)
            try:
                remote.stage(packet, data)
            except ValueError as error:
                return str(error)
            return 'unexpected success'
        root2, _, message = run_case('substitution', substitute)
        checks.append(('same-byte inode replacement denied before lease',
                       'staged input drift' in message and
                       not (root2 / 'control/STAGE4-V12-LEASE.json').exists()))
        def inject(remote, root, packet, data):
            real_exclusive = remote.exclusive
            def fail_runner(fd, name, content, mode):
                if name == 'nanhai_plus_native_graph_v12.py':
                    raise OSError('injected runner write failure')
                return real_exclusive(fd, name, content, mode)
            with mock.patch.object(remote, 'exclusive', side_effect=fail_runner):
                try:
                    remote.stage(packet, data)
                except OSError as error:
                    return str(error)
            return 'unexpected success'
        root3, old3, message = run_case('quarantine', inject)
        checks.append(('partial lease quarantined without deletion or replay',
                       message == 'injected runner write failure' and old3.is_dir() and
                       (root3 / 'control/STAGE4-V12-LEASE.json').is_file() and
                       (root3 / 'control/STAGE4-V12-QUARANTINE.json').is_file() and
                       not (root3 / 'control/STAGE4-V12-RECEIPT.json').exists()))
    result = {'schema': 'g279-stage4-v12-staging-local-fixtures-v1',
              'status': 'PASS' if all(ok for _, ok in checks) else 'FAIL',
              'checks': [{'name': name, 'pass': ok} for name, ok in checks],
              'ssh': 0, 'remote_writes': 0, 'graph': 0, 'device': 0,
              'container': 0, 'namespace': 0}
    print(json.dumps(result, sort_keys=True, indent=2))
    if result['status'] != 'PASS':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
