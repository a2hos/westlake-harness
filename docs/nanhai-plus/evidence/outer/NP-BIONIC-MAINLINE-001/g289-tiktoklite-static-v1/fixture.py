#!/usr/bin/env python3
"""G289 preparation checks only; never imports or executes the inventory runner."""
import ast
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
assert I['root_acceptance']['sha256'] is None and I['root_acceptance']['status'] is None
assert not (R / I['root_acceptance']['path']).exists()
assert not any((L / name).exists() for name in ('STARTED.json', 'RESULT.json', 'phases', 'apk-view', 'tmp'))
assert I['inventory_expectations']['native_abis'] == ['arm64-v8a', 'armeabi-v7a']
assert I['inventory_expectations']['true_elf_entries'] == 69
assert I['inventory_expectations']['packed_non_elf_so_entries'] == 4
source = (L / 'run.py').read_text()
assert "sys.argv[1:] != ['--execute']" in source
assert 'RAW_IDENTITY_DECISION_PENDING' in source
assert 'ARM64-compatible structural candidate, not ARM64-only' in source
phase = (L / 'scan_phase.py').read_text()
assert "for phase in ('zip', 'metadata', 'elf', 'dex')" in source
assert 'scanner.read_elf(data=archive.read(name)' in phase
assert 'scanner.inventory_dex(apk)' in phase
assert 'scanner.apk_metadata(apk)' in phase
assert "kinds['packed_so'].append" in phase
assert 'I[\'inventory_expectations\'][\'native_abis\']' in phase
out = {'schema': 'g289-tiktoklite-static-prep-fixture-v1', 'status': 'PASS',
       'apk_sha256': sha(apk), 'apk_bytes': apk.stat().st_size,
       'script_sha256': {name: sha(L / name) for name in ('common.py', 'scan_phase.py', 'run.py')},
       'input_sha256': sha(L / 'INPUTS.json'),
       'checks': ['AST', 'RETAINED_APK_EXACT_BYTES', 'SCANNER_SOURCE_SHA', 'VENV_MANIFEST_SHA',
                  'READELF_TOOL_SHA_AND_ALIAS', 'NO_RAW_IDENTITY_DECISION',
                  'NO_SCAN_OUTPUT', 'EXPLICIT_EXECUTE_GUARD', 'FOUR_PROVEN_PHASES',
                  'MIXED_ABI_AND_OPAQUE_SO_HONEST'],
       'scan_executed': False, 'device': 0, 'container': 0, 'canonical_delta': 0}
(L / 'FIXTURE.json').write_text(json.dumps(out, indent=2) + '\n')
print(json.dumps(out))
