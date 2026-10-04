#!/usr/bin/env python3
"""Local-only negative tests. Never invokes ssh connection or remote code path."""
import importlib.util
import pathlib
import tempfile

HERE = pathlib.Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


remote = load('remote_audit')
runner = load('run_once')
assert runner.SSH[-2:] == ['alexyang@192.168.8.22', 'LC_ALL=C /usr/bin/python3 -B -']
assert runner.SSH[:4] == ['/usr/bin/ssh', '-F', '/dev/null', '-T']
assert 'HostKeyAlias=alexpc.local' in runner.SSH
assert 'StrictHostKeyChecking=yes' in runner.SSH
assert 'BatchMode=yes' in runner.SSH
assert 'ProxyCommand=none' in runner.SSH and 'ProxyJump=none' in runner.SSH
assert runner.pinned_key(), 'local known_hosts key differs from pinned ED25519 fingerprint'
with tempfile.TemporaryDirectory() as temp:
    base = pathlib.Path(temp)
    absent = remote.collect(base / 'missing-r4', base / 'nanhai-project')
    assert absent['gates']['r4'] is False
    assert absent['gates']['toolchain'] is False
    assert absent['all_four'] is False
    (base / 'fake-r4').mkdir()
    fake = remote.collect(base / 'fake-r4', base / 'nanhai-project')
    assert fake['manifest_sha256'] is None
    assert fake['gates']['r4'] is False and fake['gates']['toolchain'] is False
    (base / 'bad-project').symlink_to(base / 'fake-r4')
    symlink = remote.collect(base / 'fake-r4', base / 'bad-project')
    assert symlink['gates']['capacity'] is False
print('PASS_NO_NETWORK: pinned_local_key, argv, missing_R4, fake_R4, private_path_symlink')
