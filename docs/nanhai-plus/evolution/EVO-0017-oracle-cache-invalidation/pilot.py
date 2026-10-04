#!/usr/bin/env python3
"""Read-only, isolated check of G274 oracle allowlist cache invalidation."""
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
POLICY = (ROOT / 'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/'
          'stock-bionic-target-graph-v18-full-candidate-v2/oracle_policy.py')
spec = importlib.util.spec_from_file_location('evo17_oracle_policy', POLICY)
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)

class ChangedCandidate:
    def candidate(self):
        raise ValueError('candidate identity changed')

class Old:
    pass

policy._allowed = frozenset({'sentinel/Android.bp'})
try:
    cached = policy.admitted_paths(Old(), ChangedCandidate())
    cached_case = {'returned_cached_paths': sorted(cached), 'identity_rechecked': False}
except ValueError as exc:
    cached_case = {'error': str(exc), 'identity_rechecked': True}

policy._allowed = None
try:
    policy.admitted_paths(Old(), ChangedCandidate())
    uncached_case = {'identity_rechecked': False}
except ValueError as exc:
    uncached_case = {'error': str(exc), 'identity_rechecked': True}

result = {
    'schema': 'nanhai.evo17.oracle-cache-pilot.v1',
    'source': str(POLICY.relative_to(ROOT)),
    'source_sha256': hashlib.sha256(POLICY.read_bytes()).hexdigest(),
    'test_kind': 'in-process isolated stub; no source or device access',
    'cached_case': cached_case,
    'uncached_negative_control': uncached_case,
    'invalidation_verified': cached_case['identity_rechecked'] and uncached_case['identity_rechecked'],
}
print(json.dumps(result, ensure_ascii=False, indent=2))
raise SystemExit(0 if result['invalidation_verified'] else 2)
