#!/usr/bin/env python3
"""Offline decision pilot over frozen G339/G340 receipts; no builds or devices."""
import hashlib
import json
from pathlib import Path

BASE = Path(__file__).resolve().parents[2] / 'evidence/outer/NP-BIONIC-MAINLINE-001'
G339 = BASE / 'g339-cross-apk-exposure-cohort-v2/RESULT.json'
G340 = BASE / 'g340-jnigraphics-exact-provider-loader-audit-v1/ROOT-REVIEW.json'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    cohort = json.loads(G339.read_text())
    audit = json.loads(G340.read_text())
    counts = {row['needed_soname']: row['package_count'] for row in cohort['cohorts']}
    assert counts['libc.so'] == 86 and counts['libjnigraphics.so'] == 34 and counts['libz.so'] == 22
    assert audit['exact_r4_source_module_seen'] is True
    assert audit['project_local_arm64_provider_artifact_seen'] is False
    assert audit['product_install_provider_absence_proven'] is False
    assert audit['runtime_loader_selection_proven'] is False
    # A candidate must offer a narrow next evidence edge. Population alone
    # never establishes that an APK reaches that provider at cold start.
    candidates = [
        {'soname': 'libc.so', 'declared_consumers': 86, 'narrow_next_edge': False,
         'reason': 'platform-wide Bionic base, not an isolated G340 provider verdict'},
        {'soname': 'libjnigraphics.so', 'declared_consumers': 34, 'narrow_next_edge': True,
         'reason': 'exact R4 module known; target ELF and product install manifest remain a binary next gate'},
        {'soname': 'libz.so', 'declared_consumers': 22, 'narrow_next_edge': False,
         'reason': 'exact source exists but native R4 Bionic toolchain/sysroot gate currently NO_GO'},
    ]
    eligible = [row for row in candidates if row['narrow_next_edge']]
    assert len(eligible) == 1 and eligible[0]['soname'] == 'libjnigraphics.so'
    print(json.dumps({'schema': 'evo56-offline-provider-consumer-pilot-v1',
                      'decision': 'SELECT_NEXT_EVIDENCE_EDGE_ONLY',
                      'selected': eligible[0], 'candidates': candidates,
                      'g339_sha256': sha(G339), 'g340_sha256': sha(G340),
                      'disposition': 'No provider absence, loader order, startup blocker, or APK unlock claimed',
                      'network_calls': 0, 'device_calls': 0, 'container_calls': 0,
                      'production_edits': 0}, sort_keys=True))


if __name__ == '__main__':
    main()
