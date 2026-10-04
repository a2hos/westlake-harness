#!/usr/bin/env python3
"""Read-only AlexPC R4 host census. Sent to python3 -B - over one SSH stdin."""
import hashlib
import json
import os
import pathlib
import platform
import re
import subprocess

ROOT = pathlib.Path('/data/source/aosp16-r4')
PROJECT_BASE = pathlib.Path('/data/source/nanhai-plus-opaleye-native')
EXPECTED_HEADS = {
    'build/make': 'b815dded1eafbf06191a6ae306956bb6ed6fb415',
    'build/soong': 'f389fa2a2a768a93bc99957e2288f3fbee032bff',
    'art': '1690c6912a7972c9e62c39b48c706de9b8b18b4a',
    'bionic': 'f22516cbc67e81c13cf943ce02f01b8929a98726',
    'frameworks/base': '45034f0663f960d9ee5fb0a101a4732b71f6e2f4',
    'frameworks/native': 'fcbde2bcff56ca1d7bec9cabf8bdca5e288bf103',
    'prebuilts/build-tools': '412724a805835d89234d67c363f7ada7f5f8a67f',
    'prebuilts/clang/host/linux-x86': '9916fb51ccb914d62d35ad9a7b9b21d2ef046928',
}
EXPECTED_MANIFEST_SHA = '19db4af44aa74ea4ed07bf602f5805476bab1c821d59ba818031022280ae055f'


def read_git_head(path):
    p = subprocess.run(['/usr/bin/git', '--no-optional-locks', '-C', str(path),
                        'rev-parse', '--verify', 'HEAD'], capture_output=True,
                       text=True, timeout=4, env={**os.environ, 'GIT_OPTIONAL_LOCKS': '0'})
    return {'rc': p.returncode, 'head': p.stdout.strip() if p.returncode == 0 else None}


def collect(root=ROOT, project_base=PROJECT_BASE):
    # No mkdir, build, network, device, git checkout, or source modification.
    root = pathlib.Path(root)
    project_base = pathlib.Path(project_base)
    host = {'hostname': platform.node(), 'system': platform.system(),
            'machine': platform.machine(), 'uid': os.getuid()}
    root_ok = root.is_dir() and not root.is_symlink() and root.resolve() == root
    manifest = root / '.repo/manifests/default.xml'
    manifest_sha = hashlib.sha256(manifest.read_bytes()).hexdigest() if root_ok and manifest.is_file() else None
    heads = {name: read_git_head(root / name) if root_ok else {'rc': None, 'head': None}
             for name in EXPECTED_HEADS}
    ninja = root / 'prebuilts/build-tools/linux-x86/bin/ninja'
    soong = root / 'build/soong/soong_ui.bash'
    clang_config = root / 'build/soong/cc/config/global.go'
    clang_match = re.search(r'ClangDefaultVersion\s*=\s*"(clang-r[0-9]+[a-z]?)"',
                            clang_config.read_text() if root_ok and clang_config.is_file() else '')
    clang_version = clang_match.group(1) if clang_match else None
    clang = root / 'prebuilts/clang/host/linux-x86' / (clang_version or 'absent') / 'bin/clang'
    ninja_magic = ninja.open('rb').read(20).hex() if root_ok and ninja.is_file() else None
    clang_magic = clang.open('rb').read(20).hex() if root_ok and clang.is_file() else None
    tool = {'clang_default_version_from_soong': clang_version,
            'ninja_elf_x86_64': ninja_magic is not None and ninja_magic.startswith('7f454c4602')
            and len(bytes.fromhex(ninja_magic)) >= 20 and bytes.fromhex(ninja_magic)[18:20] == b'\x3e\x00',
            'clang_elf_x86_64': clang_magic is not None and clang_magic.startswith('7f454c4602')
            and len(bytes.fromhex(clang_magic)) >= 20 and bytes.fromhex(clang_magic)[18:20] == b'\x3e\x00',
            'soong_ui_present': root_ok and soong.is_file(),
            'ninja_sha256': hashlib.sha256(ninja.read_bytes()).hexdigest() if root_ok and ninja.is_file() else None,
            'clang_sha256': hashlib.sha256(clang.read_bytes()).hexdigest() if root_ok and clang.is_file() else None}
    # Capacity is observed on the existing parent only. No OUT/TMP creation.
    parent = project_base.parent
    st = os.statvfs(parent) if parent.is_dir() else None
    private_paths = [project_base, project_base / 'out', project_base / 'tmp']
    private_paths_safe = all(not p.is_symlink() and (not p.exists() or
                             (p.is_dir() and p.stat().st_uid == os.getuid())) for p in private_paths)
    capacity = {'parent': str(parent), 'free_bytes': st.f_bavail * st.f_frsize if st else None,
                'parent_writable': os.access(parent, os.W_OK),
                'private_paths_safe': private_paths_safe,
                'project_base_exists': project_base.exists(), 'out_exists': (project_base / 'out').exists(),
                'tmp_exists': (project_base / 'tmp').exists()}
    gates = {
        'identity': host['hostname'] == 'alexyLinux' and host['system'] == 'Linux' and host['machine'] == 'x86_64',
        'r4': root_ok and manifest_sha == EXPECTED_MANIFEST_SHA and
              all(heads[n]['head'] == h and heads[n]['rc'] == 0 for n, h in EXPECTED_HEADS.items()),
        'toolchain': bool(tool['ninja_elf_x86_64'] and tool['clang_elf_x86_64'] and tool['soong_ui_present'] and
                          heads['prebuilts/build-tools']['head'] == EXPECTED_HEADS['prebuilts/build-tools'] and
                          heads['prebuilts/clang/host/linux-x86']['head'] == EXPECTED_HEADS['prebuilts/clang/host/linux-x86']),
        'capacity': bool(st and st.f_bavail * st.f_frsize >= 100 * 1024**3 and
                         os.access(parent, os.W_OK) and private_paths_safe),
    }
    return {'schema': 'g279-alexpc-four-gate-remote-v1', 'host': host, 'source_root': str(root),
            'source_root_canonical': root_ok, 'manifest_sha256': manifest_sha,
            'heads': heads, 'toolchain': tool, 'capacity': capacity, 'gates': gates,
            'all_four': all(gates.values()), 'claims': 'read_only_host_candidate_no_graph_no_launch'}


if __name__ == '__main__':
    print(json.dumps(collect(), sort_keys=True, separators=(',', ':')))
