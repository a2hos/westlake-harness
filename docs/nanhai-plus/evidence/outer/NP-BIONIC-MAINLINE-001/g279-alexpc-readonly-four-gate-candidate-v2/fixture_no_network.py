#!/usr/bin/env python3
"""Local-only positive/negative contract fixtures; no SSH connection."""
import copy
import importlib.util
import json
import os
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
assert runner.pinned_key()
assert runner.ssh_g()[0], 'local ssh -G mismatch'
with tempfile.TemporaryDirectory() as temp:
    base = pathlib.Path(temp)
    absent = remote.collect(base / 'missing-r4', base / 'nanhai-project')
    assert absent['gates']['r4'] is False and absent['gates']['toolchain'] is False
    (base / 'fake-r4').mkdir()
    fake = remote.collect(base / 'fake-r4', base / 'nanhai-project')
    assert fake['manifest_sha256'] is None and fake['all_four'] is False
    project = base / 'project'
    project.mkdir()
    (project / 'out').mkdir()
    (project / 'tmp').mkdir()
    os.chmod(project / 'out', 0o500)
    not_writable = remote.collect(base / 'fake-r4', project)
    assert not_writable['capacity']['private_paths']['out']['writable'] is False
    assert not_writable['gates']['capacity'] is False
    os.chmod(project / 'out', 0o700)
    (base / 'bad-project').symlink_to(project)
    symlink = remote.collect(base / 'fake-r4', base / 'bad-project')
    assert symlink['gates']['capacity'] is False

candidate = json.loads((HERE / 'CANDIDATE.json').read_text())
root = candidate['source_root']
head = '7f454c4602010100000000000000000002003e00'
uid = 1000
fact = {'exists': False, 'is_symlink': False, 'is_dir': None, 'owner_uid': None, 'writable': None}
report = {'schema': 'g279-alexpc-four-gate-remote-v2',
          'host': {'hostname': 'alexyLinux', 'system': 'Linux', 'machine': 'x86_64',
                   'username': 'alexyang', 'uid': uid},
          'source_root': root, 'source_root_canonical': True,
          'manifest_sha256': candidate['manifest_sha256'],
          'heads': {k: {'rc': 0, 'head': v} for k, v in candidate['expected_heads'].items()},
          'toolchain': {'clang_default_version_from_soong': 'clang-r563880c',
                        'ninja_path': root + '/prebuilts/build-tools/linux-x86/bin/ninja',
                        'clang_path': root + '/prebuilts/clang/host/linux-x86/clang-r563880c/bin/clang',
                        'soong_ui_path': root + '/build/soong/soong_ui.bash',
                        'ninja_header20_hex': head, 'clang_header20_hex': head,
                        'ninja_elf_x86_64': True, 'clang_elf_x86_64': True,
                        'soong_ui_present': True, 'ninja_sha256': 'a'*64, 'clang_sha256': 'b'*64},
          'capacity': {'parent': '/data/source', 'free_bytes': 200*1024**3,
                       'parent_writable': True, 'private_paths_safe': True,
                       'private_paths': {k: copy.deepcopy(fact) for k in
                                         ('nanhai-plus-opaleye-native', 'out', 'tmp')},
                       'project_base_exists': False, 'out_exists': False, 'tmp_exists': False},
          'gates': {'identity': True, 'r4': True, 'toolchain': True, 'capacity': True},
          'all_four': True}
assert runner.verify_report(report, candidate) == (True, report['gates'])
for label, mutate in [
    ('wrong_system', lambda r: r['host'].__setitem__('system', 'Darwin')),
    ('wrong_manifest', lambda r: r.__setitem__('manifest_sha256', '0'*64)),
    ('missing_head', lambda r: r['heads'].pop('art')),
    ('wrong_head', lambda r: r['heads']['bionic'].__setitem__('head', '0'*40)),
    ('wrong_tool_header', lambda r: r['toolchain'].__setitem__('ninja_header20_hex', '0'*40)),
    ('zero_capacity', lambda r: r['capacity'].__setitem__('free_bytes', 0)),
    ('existing_nonwritable_out', lambda r: r['capacity']['private_paths'].__setitem__('out',
      {'exists': True, 'is_symlink': False, 'is_dir': True, 'owner_uid': uid, 'writable': False})),
    ('contradictory_gates', lambda r: r['gates'].__setitem__('r4', False)),
]:
    bad = copy.deepcopy(report)
    mutate(bad)
    assert runner.verify_report(bad, candidate)[0] is False, label
print('PASS_NO_NETWORK: local hostkey/ssh-G, missing R4, nonwritable OUT, symlink, positive report, 8 contradictory reports')
