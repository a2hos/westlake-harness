#!/usr/bin/env python3
"""Local full-path G279 stage-2 v2 fixtures; no SSH/shared-source writes."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_tree(base, remote):
    root = base / 'new'
    old = base / 'old'
    old.mkdir(mode=0o775)
    old.chmod(0o775)
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    for name, mode in [('control', 0o700), ('out', 0o755),
                       ('staging', 0o700), ('tmp', 0o755)]:
        (root / name).mkdir(mode=mode)
        (root / name).chmod(mode)
    (root / 'out/soong-ui-v1').mkdir(mode=0o755)
    (root / 'out/no-namespace-guard-v1').mkdir(mode=0o755)
    copied = []
    names = [('control', f'seed-{n}.txt') for n in range(7)] + [
        ('tool', 'soong-ui-v1/soong_ui'),
        ('tool', 'no-namespace-guard-v1/no-namespace-exec')]
    for i, (kind, dest) in enumerate(names):
        rel = ('control/' if kind == 'control' else 'out/') + dest
        path = root / rel
        path.write_bytes(('frozen-stage1-' + str(i)).encode())
        path.chmod(0o444 if kind == 'control' else 0o555)
        copied.append({'kind': kind, 'dest': dest, 'new_id': remote.file_identity(str(path))})
    def directory(path):
        s = path.stat()
        return {'dev': s.st_dev, 'ino': s.st_ino, 'uid': s.st_uid,
                'gid': s.st_gid, 'mode': s.st_mode & 0o777}
    root_id, ctl_id, old_id = directory(root), directory(root / 'control'), directory(old)
    receipt = {'schema': 'g279-sibling-stage1-remote-receipt-v1',
               'status': 'STAGED_READBACK', 'new_root': str(root),
               'new_root_id': root_id, 'old_root_id': old_id,
               'nonce': '02add3542f7f57bff960919f7cd3ce55', 'copied': copied}
    receipt_bytes = remote.encoded(receipt)
    (root / 'control/STAGE1-RECEIPT.json').write_bytes(receipt_bytes)
    (root / 'control/STAGE1-RECEIPT.json').chmod(0o400)
    sources = base / 'sources'
    sources.mkdir()
    rows = []
    for i in range(46):
        target = sources / ('patched-soong' if i == 7 else f'input-{i:02}')
        target.mkdir()
        rows.append({'relative': 'build/soong' if i == 7 else f'input/{i:02}',
                     'symlink_target': str(target), 'resolved_target': str(target),
                     'expected_head': f'{i:040x}'})
    rows.sort(key=lambda x: x['relative'])
    binding = {'schema': 'nanhai-g279-native-graph-env-v1',
               'paths': {'NANHAI_GZ02_NATIVE_PROJECT_ROOT': str(root),
                         'NANHAI_GZ02_NATIVE_SOURCE_VIEW': str(root / 'source-view'),
                         'NANHAI_GZ02_SOONG_UI': str(root / 'out/soong-ui-v1/soong_ui')}}
    payload = json.dumps(binding, sort_keys=True).encode()
    accepted = {'root': {k: root_id[k] for k in ('dev', 'ino', 'uid', 'mode')},
                'control': {k: ctl_id[k] for k in ('dev', 'ino', 'uid', 'mode')},
                'old_root': {k: old_id[k] for k in ('dev', 'ino', 'uid', 'mode')},
                'receipt_root_id': root_id, 'receipt_old_root_id': old_id,
                'stage1_nonce': receipt['nonce'],
                'files': sorted([{'path': ('control/' if x['kind'] == 'control' else 'out/') + x['dest'],
                                  **x['new_id']} for x in copied], key=lambda x: x['path'])}
    packet = {'schema': 'g279-sibling-stage2-packet-v2',
              'nonce': '22222222222222222222222222222222',
              'old_root': str(old), 'new_root': str(root),
              'stage1_receipt_sha256': remote.sha(receipt_bytes),
              'accepted_stage1': accepted, 'links': rows,
              'binding_hex': payload.hex(), 'binding_sha256': remote.sha(payload)}
    packet['packet_sha256'] = remote.sha(remote.encoded(packet))
    return root, old, packet


def main():
    remote = load('nanhai_plus_g279_sibling_stage2_remote_v2')
    local = load('nanhai_plus_g279_sibling_stage2_candidate_v2')
    if not hasattr(remote.os, 'listxattr'):
        # macOS fixture host; Linux remote has os.listxattr(fd).
        remote.os.listxattr = lambda _fd: []
    original_checked_dir = remote.checked_dir
    checks = []
    acceptance = local.accepted_stage1()
    checks.append(('real stage1 acceptance pins three inodes and nine staged files',
                   len(acceptance['files']) == 9 and
                   [(acceptance[k]['dev'], acceptance[k]['ino'])
                    for k in ('root', 'control', 'old_root')] ==
                   [(64785, 47185921), (64785, 47185922), (64785, 29884417)]))
    frozen = json.loads((local.OUT / 'PACKET.json').read_text())
    checks.append(('frozen v2 packet reconstitutes exactly',
                   local.packet(frozen['nonce'])[0] == frozen))
    with tempfile.TemporaryDirectory(prefix='.stage2-v2-review-', dir=Path.cwd()) as review_dir:
        bogus_review = Path(review_dir) / 'bogus.json'
        bogus_review.write_text('{}')
        with mock.patch.object(local, 'host_identity', return_value=None):
            try:
                local.execute(bogus_review)
                denied = False
            except ValueError as e:
                denied = 'release absent' in str(e)
        checks.append(('unreleased v2 execution denied before local START/SSH',
                       denied and not (local.OUT / 'receipts').exists()))

    def fixture_source_check(row):
        if os.path.realpath(row['symlink_target']) != row['resolved_target'] or \
           not Path(row['symlink_target']).is_dir():
            raise ValueError('fixture source drift')

    def run_in_fixture(base, inject=None):
        root, old, p = make_tree(base, remote)
        def test_dir(path, uid, mode):
            return original_checked_dir(path, os.getuid(), mode)
        with mock.patch.object(remote, 'NEW_ROOT', str(root)), \
             mock.patch.object(remote, 'OLD_ROOT', str(old)), \
             mock.patch.object(remote, 'host_guard', return_value=None), \
             mock.patch.object(remote, 'checked_dir', side_effect=test_dir), \
             mock.patch.object(remote, 'source_check', side_effect=fixture_source_check):
            if inject is None:
                result = remote.run(p)
            else:
                result = inject(remote, root, old, p)
        return root, old, p, result

    with tempfile.TemporaryDirectory(prefix='.stage2-v2-fixture-', dir=Path.cwd()) as td:
        positive = Path(td) / 'positive'
        positive.mkdir()
        root, old, p, result = run_in_fixture(positive)
        links = [path for path in (root / 'source-view').rglob('*') if path.is_symlink()]
        checks.append(('full 46-link positive writer and receipt',
                       result['status'] == 'STAGED_READBACK_ONLY' and len(links) == 46 and
                       (root / 'control/STAGE2-RECEIPT.json').is_file() and
                       not (root / 'control/STAGE2-QUARANTINE.json').exists()))
        checks.append(('patched Soong link literal',
                       os.readlink(root / 'source-view/build/soong') ==
                       next(r['symlink_target'] for r in p['links'] if r['relative'] == 'build/soong')))

        replacement = Path(td) / 'replacement'
        replacement.mkdir()
        def replaced(remote, root, old, p):
            target = root / 'control/seed-0.txt'
            contents = target.read_bytes()
            target.unlink()
            target.write_bytes(contents)
            target.chmod(0o444)
            try:
                remote.run(p)
            except ValueError as e:
                return str(e)
            return 'UNEXPECTED_SUCCESS'
        root2, _, _, message = run_in_fixture(replacement, replaced)
        checks.append(('same-byte new-inode substitution denied before lease',
                       'staged file changed' in message and
                       not (root2 / 'control/STAGE2-LEASE.json').exists()))

        partial = Path(td) / 'partial'
        partial.mkdir()
        def failure(remote, root, old, p):
            real_symlink = os.symlink
            counter = {'n': 0}
            def fail_after_seven(*args, **kwargs):
                counter['n'] += 1
                if counter['n'] == 8:
                    raise OSError('injected link failure')
                return real_symlink(*args, **kwargs)
            with mock.patch.object(remote.os, 'symlink', side_effect=fail_after_seven):
                try:
                    remote.run(p)
                except OSError as e:
                    return str(e)
            return 'UNEXPECTED_SUCCESS'
        root3, old3, _, message = run_in_fixture(partial, failure)
        retained = [path for path in (root3 / 'source-view').rglob('*') if path.is_symlink()]
        checks.append(('partial failure quarantines without deletion/replay',
                       message == 'injected link failure' and len(retained) == 7 and
                       (root3 / 'control/STAGE2-LEASE.json').is_file() and
                       (root3 / 'control/STAGE2-QUARANTINE.json').is_file() and
                       not (root3 / 'control/STAGE2-RECEIPT.json').exists() and old3.is_dir()))

    result = {'schema': 'g279-stage2-local-fixtures-v2',
              'status': 'PASS' if all(ok for _, ok in checks) else 'FAIL',
              'checks': [{'name': name, 'pass': ok} for name, ok in checks],
              'remote_writes': 0, 'shared_source_writes': 0,
              'network': 0, 'graph': 0, 'device': 0, 'container': 0}
    print(json.dumps(result, sort_keys=True, indent=2))
    if result['status'] != 'PASS':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
