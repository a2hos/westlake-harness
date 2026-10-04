#!/usr/bin/env python3
"""Local-only static route and rejection fixtures; never runs SSH transport."""
import ast
import importlib.util
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('handshake_v4', HERE / 'controller.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def rejected(name, fn):
    try:
        fn()
    except ValueError:
        return name
    raise AssertionError('negative guard accepted: ' + name)


def main():
    ast.parse((HERE / 'controller.py').read_text())
    known = Path.home() / '.ssh/known_hosts'
    assert m.host_pin(known) == m.HOST_FP
    argv = m.ssh_argv(known)
    assert argv[-2:] == ['gz02', '/usr/bin/id -u']
    assert '/dev/null' in argv and 'BatchMode=yes' in argv and 'StrictHostKeyChecking=yes' in argv
    assert not (HERE / 'ROOT-RELEASE.json').exists()
    cfg = subprocess.run(['/usr/bin/ssh', '-G', *argv[1:-2], 'gz02'],
                         capture_output=True, text=True, timeout=5, check=True)
    m.validate_effective(cfg.stdout, known)
    good = b'debug1: Remote protocol version 2.0, remote software version OpenSSH_9\n'
    good += b'debug1: Server host key: ssh-ed25519 SHA256:RuAqHWgFJEIEcb4hC+WXULCRfV3uCsayP4Iw4aJvwzg\n'
    good += b'debug1: Authenticated to 1.95.90.207 ([1.95.90.207]:58222) using publickey.\n'
    m.validate_terminal(0, b'1000\n', good)
    negatives = [
        rejected('wrong_route', lambda: m.validate_effective(cfg.stdout.replace(m.HOST, '9.9.9.9'), known)),
        rejected('missing_banner', lambda: m.validate_terminal(0, b'1000\n', b'')),
        rejected('missing_hostkey', lambda: m.validate_terminal(0, b'1000\n', good.splitlines()[0] + b'\n' + good.splitlines()[2] + b'\n')),
        rejected('missing_auth', lambda: m.validate_terminal(0, b'1000\n', b'\n'.join(good.splitlines()[:2]) + b'\n')),
        rejected('socks_false_positive', lambda: m.validate_terminal(0, b'', b'')),
        rejected('nonzero_rc', lambda: m.validate_terminal(255, b'1000\n', good)),
        rejected('unexpected_remote_output', lambda: m.validate_terminal(0, b'garbage\n', good)),
    ]
    return {'schema': 'g279-proxy-readonly-handshake-static-fixtures-v4',
            'ssh_g_rc': cfg.returncode, 'host_fingerprint': m.HOST_FP,
            'remote_argv': argv[-2:], 'positive_synthetic': True,
            'negative_guards': negatives, 'release_absent': True,
            'ssh_connection_executed': False}


if __name__ == '__main__':
    print(json.dumps(main(), sort_keys=True))
