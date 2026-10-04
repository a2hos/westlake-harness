#!/usr/bin/env python3
"""Freeze the current 78 accepted package inventories; not a discovery crawler."""
import hashlib
import json
from pathlib import Path

BASE = Path('docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001')
OUT = BASE / 'cross-apk-reference-pilot-v1'
GROUPS = {
    'harness-stock-inventory-batch2-v1': 'root-review-v1/REVIEW.json',
    'harness-python-runtime-v1': 'root-review-v1/REVIEW.json',
    'harness-stock-inventory-batch3-v1': 'root-run-v1/ROOT-ACCEPTANCE.json',
    'harness-stock-inventory-batch4-v1': 'root-run-v1/ROOT-ACCEPTANCE.json',
    'harness-stock-inventory-batch5-v1': 'root-review-v1/ROOT-ACCEPTANCE.json',
    'harness-stock-inventory-batch6-v1': 'root-review-v1/ROOT-ACCEPTANCE.json',
    'harness-stock-inventory-batch7-v1': 'root-review-v1/ROOT-ACCEPTANCE.json',
    'harness-stock-inventory-batch8-v1': 'root-review-v1/ROOT-ACCEPTANCE.json',
    'harness-stock-inventory-batch9-v1': 'root-review-v1/ROOT-ACCEPTANCE.json',
    'harness-stock-inventory-batch10-v1': 'root-review-v1/ROOT-ACCEPTANCE.json',
    'harness-stock-inventory-batch11-v1': 'root-review-v1/ROOT-ACCEPTANCE.json',
    'harness-stock-inventory-batch12-v2': 'root-review-v1/ROOT-ACCEPTANCE.json',
    'harness-stock-inventory-batch12-v3-candidate': 'root-review-v1/ROOT-ACCEPTANCE.json',
    'harness-stock-inventory-a3-v1': 'root-review-v1/ROOT-ACCEPTANCE.json',
    'harness-stock-inventory-a4-v2': 'root-review-v1/ROOT-ACCEPTANCE.json',
    'harness-protonmeet-inventory-candidate-v1': 'root-review-v1/ROOT-ACCEPTANCE.json',
    'harness-vivaldi-inventory-candidate-v3': 'root-review-v1/ROOT-ACCEPTANCE.json',
    'g281-zoom-static-v1': 'ROOT-ADMISSION.json',
    'g285-elementx-static-v1': 'ROOT-ACCEPTANCE.json',
    'g289-tiktoklite-static-v3': 'ROOT-ACCEPTANCE.json',
    'g293-vector-static-v1': 'ROOT-STATIC-ADMISSION.json',
    'g294-vlc-static-candidate-v1': 'ROOT-STATIC-ADMISSION.json',
}


def pin(path):
    if not path.is_file():
        raise ValueError(f'missing {path}')
    return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def main():
    rows = []
    for group, receipt in GROUPS.items():
        directory = BASE / group
        for dex in directory.glob('**/DEX-INVENTORY.json'):
            s = str(dex)
            if any(t in s for t in ('/synthetic-checks/', '/native-collector-checks/',
                                    '/fixtures/', '/peer-review')):
                continue
            if group == 'harness-stock-inventory-batch5-v1' and 'org.sufficientlysecure.keychain' in s:
                continue  # recorded incomplete
            if group == 'harness-stock-inventory-batch12-v3-candidate' and '/java-trials/tuplefix-v2/' not in s:
                continue
            if '/phases/dex/' in s:
                manifest = json.loads((directory / 'phases/metadata/MANIFEST.json').read_text())
                package = manifest.get('package') or manifest.get('package_name')
                elf = directory / 'phases/elf/ELF-INVENTORY.json'
            else:
                package = dex.parent.name
                elf = dex.parent / 'ELF-INVENTORY.json'
            row = {'package': package, 'receipt': pin(directory / receipt), 'dex': pin(dex)}
            if group == 'harness-stock-inventory-batch12-v3-candidate':
                aggregate = json.loads((directory / 'AGGREGATE.json').read_text())
                fact = next(f for f in aggregate['facts'] if f['package'] == package)
                records = []
                for member in fact['native_member_receipts']:
                    matches = [p for p in directory.glob('member-trials/*/ELF-RECORD.json')
                               if hashlib.sha256(p.read_bytes()).hexdigest() == member['record_sha256']]
                    if len(matches) != 1:
                        raise ValueError(f'nonunique native record {package}: {member["name"]}')
                    records.append(pin(matches[0]))
                row['elf_records'] = records
                row['aggregate'] = pin(directory / 'AGGREGATE.json')
            else:
                row['elf'] = pin(elf)
            rows.append(row)
    rows.sort(key=lambda x: x['package'])
    if len(rows) != 78 or len({r['package'] for r in rows}) != 78 or not all(r['package'] for r in rows):
        raise ValueError(f'bad selected population: {len(rows)} rows')
    (OUT / 'INPUT-MANIFEST.json').write_text(json.dumps({
        'schema': 'cross-apk-reference-input-v1',
        'target': 'OH7.0.0.39-AOSP16.0.0_r4-arm64-Bionic',
        'packages': rows,
    }, indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
