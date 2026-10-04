#!/usr/bin/env python3
"""G289 v3 preparation checks only; never executes the inventory runner."""
import ast
import copy
import hashlib
import json
from pathlib import Path

L = Path(__file__).resolve().parent
R = L.parents[5]
I = json.loads((L / 'INPUTS.json').read_text())
def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            h.update(block)
    return h.hexdigest()

for name in ('common.py', 'scan_phase.py', 'run.py'):
    ast.parse((L / name).read_text())
apk = R / I['apks'][0]['path']
assert apk.is_file() and apk.stat().st_size == I['apks'][0]['bytes'] == 48413684
assert sha(apk) == I['apks'][0]['sha256'] == '37b528ba36ebcb1e6d4f642d144c5446352b5d19abebea7504e3654b9882b9f0'
assert all(sha(R / rel) == digest for rel, digest in I['source_sha256'].items())
assert sha(I['venv_manifest']['path']) == I['venv_manifest']['sha256']
assert sha(I['tool_mapping']['target']) == I['tool_mapping']['tool_sha256']
assert Path(I['tool_mapping']['alias']).is_symlink()
assert Path(I['tool_mapping']['alias']).resolve() == Path(I['tool_mapping']['target']).resolve()
assert I['apks'][0]['registry_package_label'] == 'com.tiktok.lite.go'
root = R / 'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g290-tiktok-lite-go-raw-supplement-v1/ROOT-RAW-INTAKE.json'
root_sha = 'ffd25a75b488981468cafad6f18ebf80a6e67e72e55e1df1aa1a8313281cc590'
assert I['root_acceptance']['path'] == str(root.relative_to(R))
assert I['root_acceptance']['sha256'] == root_sha == sha(root)
assert I['root_acceptance']['decision'] == 'ACCEPT_ONE_SEPARATE_OFFICIAL_CHANNEL_OBSERVED_SUPPLEMENTAL_RAW_APK'
assert I['root_acceptance']['schema'] == 'nanhai-g290-tiktok-lite-go-root-raw-intake-v1'
accepted = json.loads(root.read_text())
assert accepted['payload']['sha256'] == I['apks'][0]['sha256']
assert not any((L / name).exists() for name in ('STARTED.json', 'RESULT.json', 'phases', 'apk-view', 'tmp'))
assert I['inventory_expectations']['native_abis'] == ['arm64-v8a', 'armeabi-v7a']
assert I['inventory_expectations']['true_elf_entries'] == 69
assert I['inventory_expectations']['packed_non_elf_so_entries'] == 4
source = (L / 'run.py').read_text()
assert "sys.argv[1:] != ['--execute']" in source
assert "ROOT_SHA256 = 'ffd25a75b488981468cafad6f18ebf80a6e67e72e55e1df1aa1a8313281cc590'" in source
assert 'assert sha(acceptance) == ROOT_SHA256' in source
assert 'check_root_decision(accepted)' in source
release_path = R/'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g289-tiktoklite-static-release-v1/ROOT-RELEASE.json'
release_sha = '887a344997faab5eedc481f329dee10da75b41cef232ee12005ba1d9eebbcda2'
assert sha(release_path) == release_sha
assert f"ROOT_STATIC_RELEASE_SHA256 = '{release_sha}'" in source
assert 'assert path.is_file() and sha(path) == ROOT_STATIC_RELEASE_SHA256' in source
assert 'check_static_release()' in source and 'check_v3_peer()' in source
assert 'ARM64-compatible structural candidate, not ARM64-only' in source
tree = ast.parse(source)
check = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'check_root_decision')
namespace = {'I': I, 'ROOT_SCHEMA': I['root_acceptance']['schema'],
             'ROOT_DECISION': I['root_acceptance']['decision'], 'APK_SHA256': I['apks'][0]['sha256']}
exec(compile(ast.Module(body=[check], type_ignores=[]), str(L/'run.py'), 'exec'), namespace)
namespace['check_root_decision'](accepted)
for field, bad in [('decision', 'DENY'), ('package', 'wrong.package'),
                   ('version_code', 1), ('version_name', '0')]:
    changed = copy.deepcopy(accepted); changed[field] = bad
    try: namespace['check_root_decision'](changed)
    except AssertionError: pass
    else: raise AssertionError('root decision mutation accepted: ' + field)
for field, bad in [('path', 'other.apk'), ('bytes', 1), ('sha256', '0'*64),
                   ('native_abis', ['armeabi-v7a'])]:
    changed = copy.deepcopy(accepted); changed['payload'][field] = bad
    try: namespace['check_root_decision'](changed)
    except AssertionError: pass
    else: raise AssertionError('root payload mutation accepted: ' + field)
release = json.loads(release_path.read_text())
validate = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'validate_static_release')
v2 = L.parent/'g289-tiktoklite-static-v2'
v2_peer = L.parent/'g289-tiktoklite-static-v2-peer-review-v1/REVIEW.json'
release_ns = {'R': R, 'L': L, 'sha': sha, 'V2': v2, 'V2_PEER': v2_peer,
              'ROOT_STATIC_RELEASE_SCHEMA': release['schema'],
              'ROOT_STATIC_RELEASE_DECISION': release['decision'],
              'ROOT_RECEIPT': I['root_acceptance']['path'], 'ROOT_SHA256': root_sha,
              'APK_SHA256': I['apks'][0]['sha256'],
              'LIMITS': {'outer_seconds':1350,'zip_seconds':120,'metadata_seconds':180,
                         'elf_seconds':600,'dex_seconds':600,'parallel':1,'retries':0}}
exec(compile(ast.Module(body=[validate], type_ignores=[]), str(L/'run.py'), 'exec'), release_ns)
release_ns['validate_static_release'](release)
for top, bad in [('decision', 'DENY'), ('phase_order', ['dex']), ('attempts', 2),
                 ('network_authorized', True)]:
    changed = copy.deepcopy(release); changed[top] = bad
    try: release_ns['validate_static_release'](changed)
    except AssertionError: pass
    else: raise AssertionError('static release mutation accepted: ' + top)
for section, field, bad in [('apk','sha256','0'*64), ('root_raw_admission','sha256','0'*64),
                            ('limits_seconds','dex',1), ('reviewed_v2','inputs_sha256','0'*64)]:
    changed = copy.deepcopy(release); changed[section][field] = bad
    try: release_ns['validate_static_release'](changed)
    except AssertionError: pass
    else: raise AssertionError('static release mutation accepted: ' + section + '.' + field)
assert not (L.parent/'g289-tiktoklite-static-v3-peer-review-v1/REVIEW.json').exists()
phase = (L / 'scan_phase.py').read_text()
assert "for phase in ('zip', 'metadata', 'elf', 'dex')" in source
assert 'scanner.read_elf(data=archive.read(name)' in phase
assert 'scanner.inventory_dex(apk)' in phase
assert 'scanner.apk_metadata(apk)' in phase
assert "kinds['packed_so'].append" in phase
assert 'I[\'inventory_expectations\'][\'native_abis\']' in phase
out = {'schema': 'g289-tiktoklite-static-prep-fixture-v3', 'status': 'PASS',
       'apk_sha256': sha(apk), 'apk_bytes': apk.stat().st_size,
       'script_sha256': {name: sha(L / name) for name in ('common.py', 'scan_phase.py', 'run.py')},
       'input_sha256': sha(L / 'INPUTS.json'), 'root_receipt_sha256': sha(root),
       'root_static_release_sha256': sha(release_path),
       'checks': ['AST', 'RETAINED_APK_EXACT_BYTES', 'SCANNER_SOURCE_SHA', 'VENV_MANIFEST_SHA',
                  'READELF_TOOL_SHA_AND_ALIAS', 'ROOT_SHA_AND_DECISION',
                  'ROOT_MUTATIONS_REJECTED', 'STATIC_RELEASE_EXACT',
                  'STATIC_RELEASE_MUTATIONS_REJECTED', 'V3_PEER_PENDING',
                  'NO_SCAN_OUTPUT', 'EXPLICIT_EXECUTE_GUARD', 'FOUR_PROVEN_PHASES',
                  'MIXED_ABI_AND_OPAQUE_SO_HONEST'],
       'scan_executed': False, 'device': 0, 'container': 0, 'canonical_delta': 0}
(L / 'FIXTURE.json').write_text(json.dumps(out, indent=2) + '\n')
print(json.dumps(out))
