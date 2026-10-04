#!/usr/bin/env python3
"""Temporary-tree CONFIG-ONLY switch fixtures; authoritative env untouched."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent


def load():
    spec = importlib.util.spec_from_file_location('stage3_switch', HERE / 'switch.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    module = load()
    old = module.stable_read(module.ACTIVE)[0]
    new = module.stable_read(module.PROPOSED)[0]
    p = json.loads((HERE / 'PACKET.json').read_text())
    def reconcile(root, receipts, nonce):
        run = subprocess.run([sys.executable, str(HERE / 'reconcile.py'),
                              '--root', str(root), '--receipts', str(receipts),
                              '--nonce', nonce], capture_output=True, text=True, check=True)
        return json.loads(run.stdout)
    checks = [('frozen three-key packet reconstruction', module.packet(p['nonce']) == p)]
    with tempfile.TemporaryDirectory(prefix='.g279-config-switch-', dir=module.ROOT) as td:
        base = Path(td)
        unreleased = base / 'unreleased-review.json'
        unreleased.write_text(json.dumps({
            'decision': 'GO_CONFIG_ONLY_LOCAL_SWITCH_ONCE',
            'packet_sha256': p['packet_sha256'],
            'switch_script_sha256': module.sha((HERE / 'switch.py').read_bytes()),
            'future_file_sha256': module.NEW_SHA,
            'independent_reviewer': 'fixture-only',
            'v11_staging_terminal_sha256': '0' * 64,
            'v11_staging_peer_postrun_sha256': '0' * 64,
            'v11_staging_root_postrun_sha256': '0' * 64}))
        try:
            module.execute(unreleased)
            denied = False
        except (ValueError, FileNotFoundError):
            denied = True
        checks.append(('unreleased active switch denied before START',
                       denied and not (HERE / 'receipts').exists()))
        one = base / 'positive'
        one.mkdir()
        active = one / 'local_env.md'
        active.write_bytes(old)
        active.chmod(p['active_mode'])
        receipt_dir = one / 'receipts'
        terminal = module.atomic_switch(one, old, new, p['nonce'], receipt_dir,
                                         p['active_mode'], os.getuid(), os.getgid(),
                                         'a' * 64, p['packet_sha256'],
                                         after_replace=lambda: module.compare(old, active.read_bytes()))
        checks.append(('atomic exact-byte switch, backup and terminal',
                       terminal['status'] == 'SWITCHED_READBACK' and
                       active.read_bytes() == new and
                       (receipt_dir / ('local_env.old.' + module.OLD_SHA + '.md')).read_bytes() == old and
                       not (receipt_dir / (p['nonce'] + '.QUARANTINE.json')).exists()))
        checks.append(('read-only terminal reconciliation',
                       reconcile(one, receipt_dir, p['nonce'])['state'] ==
                       'SWITCHED_TERMINAL_READBACK'))
        try:
            module.atomic_switch(one, old, new, p['nonce'], receipt_dir,
                                 p['active_mode'], os.getuid(), os.getgid(),
                                 'a' * 64, p['packet_sha256'])
            replay_denied = False
        except FileExistsError:
            replay_denied = True
        checks.append(('same nonce replay denied', replay_denied))
        two = base / 'postreplace-failure'
        two.mkdir()
        active2 = two / 'local_env.md'
        active2.write_bytes(old)
        active2.chmod(p['active_mode'])
        receipts2 = two / 'receipts'
        def injected_failure():
            raise RuntimeError('injected parser failure')
        try:
            module.atomic_switch(two, old, new, 'f' * 32, receipts2,
                                 p['active_mode'], os.getuid(), os.getgid(),
                                 'b' * 64, p['packet_sha256'], after_replace=injected_failure)
            uncertain = False
        except RuntimeError as error:
            uncertain = str(error) == 'injected parser failure'
        checks.append(('postreplace failure preserves backup, START and quarantine',
                       uncertain and active2.read_bytes() == new and
                       (receipts2 / ('local_env.old.' + module.OLD_SHA + '.md')).read_bytes() == old and
                       (receipts2 / ('f' * 32 + '.START.json')).is_file() and
                       (receipts2 / ('f' * 32 + '.QUARANTINE.json')).is_file() and
                       not (receipts2 / ('f' * 32 + '.TERMINAL.json')).exists()))
        checks.append(('read-only unknown-state reconciliation',
                       reconcile(two, receipts2, 'f' * 32)['state'] ==
                       'NEW_ACTIVE_WITHOUT_TERMINAL_QUARANTINE'))
        three = base / 'preflight-failure'
        three.mkdir()
        bad = three / 'local_env.md'
        bad.write_bytes(old + b'\n')
        bad.chmod(p['active_mode'])
        try:
            module.atomic_switch(three, old, new, 'e' * 32, three / 'receipts',
                                 p['active_mode'], os.getuid(), os.getgid(),
                                 'c' * 64, p['packet_sha256'])
            bad_denied = False
        except ValueError:
            bad_denied = True
        checks.append(('drift denied before START',
                       bad_denied and not (three / 'receipts').exists()))
    result = {'schema': 'g279-stage3-config-only-switch-fixtures-v2',
              'status': 'PASS' if all(ok for _, ok in checks) else 'FAIL',
              'checks': [{'name': name, 'pass': ok} for name, ok in checks],
              'authoritative_env_edits': 0, 'remote_commands': 0,
              'graph': 0, 'device': 0, 'container': 0}
    print(json.dumps(result, sort_keys=True, indent=2))
    if result['status'] != 'PASS':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
