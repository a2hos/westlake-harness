#!/usr/bin/env python3
"""Read-only, exact-input libandroid consumer contract scan of G339's frozen set."""
import hashlib
import importlib.util
import json
import os
import subprocess
from pathlib import Path

PROJECT = Path(os.environ['NANHAI_PROJECT_ROOT'])
POOL = Path(os.environ['NANHAI_SOURCE_POOL_ROOT'])
BASE = PROJECT / 'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001'
G339 = BASE / 'g339-cross-apk-exposure-cohort-v2'
INDEX = POOL / 'SOURCES.json'
SOURCE_REL = 'AOSP-16.0.0_r4/android-source/frameworks-base-r4-45034f0'
PREFIXES = ('AAsset', 'AChoreographer', 'ANativeWindow', 'AInput', 'AMotion',
            'AHardwareBuffer', 'AConfiguration', 'ALooper', 'AImage', 'ATrace')

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def source_record(node):
    if isinstance(node, dict):
        if node.get('path') == SOURCE_REL:
            yield node
        for value in node.values():
            yield from source_record(value)
    elif isinstance(node, list):
        for value in node:
            yield from source_record(value)

def main():
    records = list(source_record(json.loads(INDEX.read_text())))
    if len(records) != 1:
        raise ValueError('exact R4 source index record missing or ambiguous')
    record = records[0]
    if record.get('upstream_tag') != 'android-16.0.0_r4' or record.get('head') != '45034f0663f960d9ee5fb0a101a4732b71f6e2f4' or record.get('kind') != 'complete_pinned_readonly_source_checkout':
        raise ValueError('source index version or completeness mismatch')
    source = POOL / record['path']
    if not source.is_dir() or not source.resolve().is_relative_to(POOL.resolve()):
        raise ValueError('indexed source path missing or escapes registered root')
    bp_path = source / 'native/android/Android.bp'
    map_path = source / 'native/android/libandroid.map.txt'
    if not bp_path.is_file() or not map_path.is_file():
        raise ValueError('R4 provider definition input missing')
    spec = importlib.util.spec_from_file_location('g339_scan', G339 / 'analyze_lock.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    lock_path = G339 / 'LOCK.json'
    g339 = mod.analyze(lock_path)
    if g339 != json.loads((G339 / 'RESULT.json').read_text()):
        raise ValueError('G339 frozen replay differs from accepted result')
    lock = json.loads(lock_path.read_text())
    cluster = next(x for x in g339['cohorts'] if x['needed_soname'] == 'libandroid.so')
    if cluster['package_count'] != 48:
        raise ValueError('G339 libandroid count changed')
    split_root, split_records = mod.split_record_paths()
    rows = []
    for item in lock['identities']:
        package = item['package']
        if package not in cluster['packages']:
            continue
        if item.get('layout') == 'batch12-v3-split-native-members':
            aggregate = mod.checked(item['split_aggregate_ref'])
            facts = [x for x in aggregate['facts'] if x['package'] == package]
            if len(facts) != 1:
                raise ValueError('split fact identity mismatch')
            elf = [json.loads(split_records[m['record_sha256']].read_text())
                   for m in facts[0]['native_member_receipts']]
        else:
            ref = item['inputs']
            elf = mod.source(BASE, ref['elf'], ref['elf_sha256'])
            if item.get('native_elf_ref'):
                elf = mod.checked(item['native_elf_ref'])
        consumers = []
        for e in elf:
            if e['abi'] != 'arm64-v8a' or 'libandroid.so' not in e['needed']:
                continue
            if e['machine'] != 'AArch64' or not e.get('abi_matches_machine') or not e.get('readelf_ok'):
                raise ValueError('target ELF gate failed: ' + package)
            imports = sorted(set(s for s in e.get('undefined_symbols', []) if s.startswith(PREFIXES)))
            consumers.append({'elf': e['name'], 'sha256': e['sha256'],
                              'needed': e['needed'], 'ndk_symbol_candidates': imports})
        if not consumers:
            raise ValueError('cluster member lacks target ELF: ' + package)
        rows.append({'package': package, 'apk_sha256': item['apk_sha256'],
                     'arm64_consumers': consumers})
    if len(rows) != 48:
        raise ValueError('consumer count mismatch')
    head = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    status = subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain', '--', 'native/android/Android.bp', 'native/android/libandroid.map.txt'], text=True).strip()
    if head != '45034f0663f960d9ee5fb0a101a4732b71f6e2f4' or status:
        raise ValueError('R4 source identity or cleanliness mismatch')
    bp = bp_path.read_text()
    if bp.count('name: "libandroid"') != 2 or 'cc_library_shared {' not in bp or 'ndk_library {' not in bp:
        raise ValueError('R4 module definition changed')
    plans = {}
    for name in ('flutter-libandroid-n1', 'libandroid-9ccf64f8'):
        path = PROJECT / 'docs/nanhai-plus/tool-records' / name / 'targets/oh7.0.0.39-aosp16r4-arm64-bionic/plan.json'
        plan = json.loads(path.read_text())
        plans[name] = {'sha256': digest(path), 'decision': plan['decision'],
                       'state': plan['state'], 'source_build_accepted': plan['source_build_accepted']}
    groups = {}
    imported = set()
    for row in rows:
        for e in row['arm64_consumers']:
            for symbol in e['ndk_symbol_candidates']:
                imported.add(symbol)
                group = next((p for p in PREFIXES if symbol.startswith(p)), 'other')
                groups.setdefault(group, set()).add(row['package'])
    map_text = map_path.read_text()
    mapped = {line.strip().rstrip(';') for line in map_text.splitlines()
              if line.strip().endswith(';') and not line.strip().startswith('//')}
    result = {'schema': 'g341-libandroid-frozen-consumer-contract-v2',
              'status': 'HOST_STATIC_CONSUMER_EXPOSURE_ONLY',
              'lock_sha256': digest(lock_path), 'g339_result_sha256': digest(G339 / 'RESULT.json'),
              'frozen_packages_checked': lock['count'], 'declared_needed_packages': len(rows),
              'symbol_family_package_counts': {k: len(v) for k,v in sorted(groups.items())},
              'candidate_imports_in_r4_map': len(imported & mapped),
              'candidate_imports_outside_r4_map': sorted(imported - mapped),
              'exact_r4_provider_source': {'indexed_relative_path': record['path'],
                  'source_index_sha256': digest(INDEX), 'commit': head, 'tree': record['tree'],
                  'android_bp_sha256': digest(bp_path),
                  'libandroid_map_sha256': digest(map_path),
                  'definitions': ['ndk_library libandroid', 'cc_library_shared libandroid']},
              'target_plans': plans, 'consumers': rows,
              'limit': 'ELF declarations and unresolved names only; no provider ELF, linker mapping, reachability, cold start or device result'}
    print(json.dumps(result, indent=2, sort_keys=True))

if __name__ == '__main__':
    main()
