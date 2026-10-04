#!/usr/bin/env python3
"""Small adversarial fixtures for receipt pinning and package/ABI dedupe."""
import hashlib
import json
import tempfile
from pathlib import Path

from aggregate import aggregate


def write(root, name, value):
    path = root / name
    path.write_text(json.dumps(value))
    return {'path': name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def main():
    checks = {}
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        receipt = write(root, 'receipt.json', {'status': 'ACCEPT_COMPLETE_STATIC_ONLY'})
        dex = write(root, 'dex.json', {'dex_entries': [{'name': 'classes.dex'}],
                                      'method_refs': [{'key': ['Landroid/content/Context;',
                                                               'getSystemService',
                                                               '(Ljava/lang/String;)Ljava/lang/Object;']}]})
        arm64 = {'machine': 'AArch64', 'abi': 'arm64-v8a', 'readelf_ok': True,
                 'undefined_symbols': ['__system_property_get'], 'needed': ['libc.so']}
        arm32 = {'machine': 'ARM', 'abi': 'armeabi-v7a', 'readelf_ok': True,
                 'undefined_symbols': ['ARM32_ONLY'], 'needed': ['libc.so']}
        elf = write(root, 'elf.json', [arm64, arm64, arm32])
        rows = [{'package': f'fixture.pkg.{i:02d}', 'receipt': receipt, 'dex': dex, 'elf': elf}
                for i in range(78)]
        manifest = {'schema': 'cross-apk-reference-input-v1', 'packages': rows}
        result = aggregate(root, manifest)
        checks['unique_package_dedup'] = (result['top_arm64_native_imports'][0]['unique_packages'] == 78)
        checks['arm32_excluded'] = all(r['reference'] != 'ARM32_ONLY'
                                       for r in result['top_arm64_native_imports'])
        checks['one_elf_entry_count_per_record'] = result['counts']['arm64_elf_entries'] == 156
        rows[1]['package'] = rows[0]['package']
        try:
            aggregate(root, manifest)
            checks['duplicate_package_rejected'] = False
        except ValueError:
            checks['duplicate_package_rejected'] = True
        rows[1]['package'] = 'fixture.pkg.01'
        (root / 'dex.json').write_text('{}')
        try:
            aggregate(root, manifest)
            checks['changed_inventory_rejected'] = False
        except ValueError:
            checks['changed_inventory_rejected'] = True
    if not all(checks.values()):
        raise SystemExit(json.dumps(checks))
    print(json.dumps({'status': 'PASS', 'checks': checks}, sort_keys=True))


if __name__ == '__main__':
    main()
