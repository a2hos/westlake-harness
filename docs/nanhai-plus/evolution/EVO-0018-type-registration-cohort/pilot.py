#!/usr/bin/env python3
"""Read-only cohort pilot: G275 graph diagnostics versus pinned Soong registrations."""
import hashlib
import json
import re
import tarfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

root = Path(__file__).resolve().parents[4]
base = root / 'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001'
run = base / 'stock-bionic-target-graph-v19-g275-candidate-v1/runtime-result'
result = json.loads((run / 'RESULT.json').read_bytes())
archive = run / 'export-out.stdout.log'
soong = Path('/opt/19.SourceCode/AOSP-16.0.0_r4/android-source/build-soong')
bp_hidl = Path('/opt/19.SourceCode/AOSP-16.0.0_r4/android-source/hardware-interfaces-r4-aa22955/audio/2.0/Android.bp')
bp_link = Path('/opt/19.SourceCode/AOSP-16.0.0_r4/android-source/modules-common-r4-deef1ed/sdk/Android.bp')
bp_roots = (bp_hidl.parents[2], bp_link.parents[1])

def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

assert result['rc'] == 2 and result['graph_generation_pass'] is False
assert result['target_compile_commands'] == 0
assert sha(archive) == result['exports']['out']['sha256']
with tarfile.open(archive) as t:
    member = t.getmember('./stock-steps/target-graph.stdout')
    raw = t.extractfile(member).read()
text = raw.decode('utf-8', errors='replace')
diagnostics = re.findall(r'^error: ([^:\n]+):\d+:\d+: unrecognized module type "([^"]+)"', text, re.M)
counts = Counter(kind for _, kind in diagnostics)
assert counts and {'hidl_interface', 'library_linking_strategy_apex_defaults',
                   'library_linking_strategy_cc_defaults'} <= set(counts)
registrations = set()
registration_sites = {}
for path in soong.rglob('*.go'):
    source = path.read_text(errors='replace')
    for kind in re.findall(r'RegisterModuleType\("([^"]+)"', source):
        registrations.add(kind)
        registration_sites.setdefault(kind, str(path.relative_to(soong)))
assert 'cc_library' in registrations
assert 'ctx.RegisterModuleType("cc_library", LibraryFactory)' in (soong / 'cc/library.go').read_text()
assert all(kind not in registrations for kind in counts)
assert 'hidl_interface {' in bp_hidl.read_text()
assert all(kind + ' {' in bp_link.read_text() for kind in counts if kind.startswith('library_linking_strategy_'))
source_type_counts = Counter()
bp_files = 0
for bp_root in bp_roots:
    for path in bp_root.rglob('Android.bp'):
        bp_files += 1
        for kind in re.findall(r'^\s*([A-Za-z_][A-Za-z_0-9]*)\s*\{',
                               path.read_text(errors='replace'), re.M):
            if kind in counts:
                source_type_counts[kind] += 1
assert set(source_type_counts) == set(counts)

print(json.dumps({
    'schema': 'nanhai.evo18.type-registration-cohort-pilot.v1',
    'at': datetime.now(timezone.utc).isoformat(),
    'g275_result_sha256': sha(run / 'RESULT.json'),
    'g275_target_graph_stdout_member_sha256': hashlib.sha256(raw).hexdigest(),
    'g275_target_graph_stdout_member_bytes': len(raw),
    'diagnostic_total': len(diagnostics),
    'unrecognized_type_counts': dict(sorted(counts.items())),
    'diagnostic_source_roots': dict(sorted(Counter(p.split('/')[0] + '/' + p.split('/')[1] for p, _ in diagnostics).items())),
    'pinned_soong_go_files_scanned': sum(1 for _ in soong.rglob('*.go')),
    'source_android_bp_files_scanned': bp_files,
    'pregraph_source_module_type_counts': dict(sorted(source_type_counts.items())),
    'negative_provider_lookup': {kind: 'no literal RegisterModuleType in pinned build-soong Go' for kind in sorted(counts)},
    'positive_control': {'type': 'cc_library', 'registration_site': 'cc/library.go'},
    'source_usage_checks': {'hidl_interface': str(bp_hidl),
                            'library_linking_strategy': str(bp_link)},
    'conclusion': 'three unregistered module-type families cluster diagnostic fanout; provider ownership and executable registration still unresolved',
    'graph_or_target_compiled_by_pilot': False,
    'device_commands': 0,
}, ensure_ascii=False, sort_keys=True, indent=2))
