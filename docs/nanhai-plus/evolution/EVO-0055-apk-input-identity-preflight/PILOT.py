#!/usr/bin/env python3
"""Offline pilot: freeze exact APK input identity and DEX consumer shape."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / 'evidence/outer/NP-BIONIC-MAINLINE-001'
CASES = (
    ('peer-apk-portfolio-pipepipe-static-v2', 'InfinityLoop1309.NewPipeEnhanced', '589bb89b777bf0a33a13ab6456d2c876c3b8814f40fa8f74b2c4f0285aa56bf1'),
    ('peer-apk-portfolio-ntfy-static-v1', 'io.heckel.ntfy', 'b4baa6f668bd57ad5df3b4e0e769165dcf25c5ee19fdb04f78077ee819616f2a'),
    ('peer-apk-portfolio-lichess-static-v1', 'org.lichess.mobileV2', '076c0310a0cb559b5d9bfe48d098d9dbba4b042060cf493805f4b00a6c82ffdd'),
)


def preflight(manifest, dex, expected_package, expected_sha, consumer_mode):
    if manifest.get('package') != expected_package or manifest.get('sha256') != expected_sha:
        return 'REJECT_IDENTITY'
    entries = dex.get('dex_entries')
    if not isinstance(entries, list) or not entries or not all(isinstance(e, dict) and isinstance(e.get('name'), str) for e in entries):
        return 'REJECT_DEX_SHAPE'
    if consumer_mode != 'mapping_key':
        return 'REJECT_CONSUMER_SHAPE'
    return 'PASS_FIXED_INPUT'


def main():
    outcomes = []
    for dirname, package, sha in CASES:
        directory = ROOT / dirname
        manifest_path, dex_path = directory / 'MANIFEST.json', directory / 'DEX-INVENTORY.json'
        manifest, dex = json.loads(manifest_path.read_text()), json.loads(dex_path.read_text())
        outcomes.append({'case': dirname, 'result': preflight(manifest, dex, package, sha, 'mapping_key'),
                         'manifest_sha256': hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                         'dex_sha256': hashlib.sha256(dex_path.read_bytes()).hexdigest()})
        if dirname.startswith('peer-apk-portfolio-pipepipe'):
            outcomes.append({'case': 'pipepipe-v1-attribute-access', 'result': preflight(manifest, dex, package, sha, 'attribute')})
            wrong = dict(manifest, package='wrong.package')
            outcomes.append({'case': 'g339-wrong-package', 'result': preflight(wrong, dex, package, sha, 'mapping_key')})
            wrong_sha = dict(manifest, sha256='0' * 64)
            outcomes.append({'case': 'same-package-wrong-apk', 'result': preflight(wrong_sha, dex, package, sha, 'mapping_key')})
    expected = ['PASS_FIXED_INPUT', 'REJECT_CONSUMER_SHAPE', 'REJECT_IDENTITY', 'REJECT_IDENTITY', 'PASS_FIXED_INPUT', 'PASS_FIXED_INPUT']
    assert [o['result'] for o in outcomes] == expected
    print(json.dumps({'schema': 'evo55-offline-pilot-v1', 'decision': 'PASS_OFFLINE_ONLY',
                      'outcomes': outcomes, 'network_calls': 0, 'device_calls': 0,
                      'container_calls': 0, 'common_ledger_edits': 0}, sort_keys=True))


if __name__ == '__main__':
    main()
