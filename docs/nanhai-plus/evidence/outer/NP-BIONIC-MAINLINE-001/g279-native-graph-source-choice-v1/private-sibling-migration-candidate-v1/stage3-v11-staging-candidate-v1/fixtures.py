#!/usr/bin/env python3
"""Isolated local v11 staging writer tests; no SSH, graph or shared writes."""
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
        'g279-native-graph-env.json')] + [
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
    data = b'v11-fixture-runner\n'
    packet = {'schema': 'g279-stage3-v11-staging-packet-v1',
              'nonce': '33333333333333333333333333333333',
              'root': str(root), 'old_root': str(old),
              'root_id': identity(root), 'control_id': identity(root / 'control'),
              'old_root_id': identity(old),
              'source_view_id': identity(root / 'source-view'),
              'unchanged_files': sorted(specs, key=lambda x: x['path']),
              'runner': {'name': 'nanhai_plus_native_graph_v11.py',
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
    checks.append(('reviewed v11 packet reconstructs exactly',
                   launcher.freeze_packet(frozen['nonce'])[0] == frozen and
                   len(frozen['unchanged_files']) == 14))
    sys.path.insert(0, str(launcher.ROOT / 'scripts'))
    import nanhai_plus_g279_sibling_stage2_candidate_v2 as stage2
    with tempfile.TemporaryDirectory(prefix='.v11-review-fixture-', dir=launcher.ROOT) as td:
        bogus = Path(td) / 'review.json'
        bogus.write_text('{}')
        with mock.patch.object(stage2, 'host_identity', return_value=None):
            try:
                launcher.execute(bogus)
                denied = False
            except ValueError as error:
                denied = 'release absent' in str(error)
        checks.append(('unreleased execute denied before START/SSH',
                       denied and not (HERE / 'receipts').exists()))
    with tempfile.TemporaryDirectory(prefix='.v11-stage-fixture-', dir=launcher.ROOT) as td:
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
        row = remote.regular(str(root / 'control/nanhai_plus_native_graph_v11.py'))
        checks.append(('positive mode0444 exact runner and remote receipt',
                       result['status'] == 'STAGED_READBACK_ONLY' and
                       row['mode'] == 0o444 and
                       (root / 'control/STAGE3-V11-RECEIPT.json').is_file()))
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
                       not (root2 / 'control/STAGE3-V11-LEASE.json').exists()))
        def inject(remote, root, packet, data):
            real_exclusive = remote.exclusive
            def fail_runner(fd, name, content, mode):
                if name == 'nanhai_plus_native_graph_v11.py':
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
                       (root3 / 'control/STAGE3-V11-LEASE.json').is_file() and
                       (root3 / 'control/STAGE3-V11-QUARANTINE.json').is_file() and
                       not (root3 / 'control/STAGE3-V11-RECEIPT.json').exists()))
    result = {'schema': 'g279-stage3-v11-staging-local-fixtures-v1',
              'status': 'PASS' if all(ok for _, ok in checks) else 'FAIL',
              'checks': [{'name': name, 'pass': ok} for name, ok in checks],
              'ssh': 0, 'remote_writes': 0, 'graph': 0, 'device': 0,
              'container': 0, 'namespace': 0}
    print(json.dumps(result, sort_keys=True, indent=2))
    if result['status'] != 'PASS':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
