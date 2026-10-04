#!/usr/bin/env python3
"""One-shot, read-only identity probe for the accepted VLC APK."""

import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ['NANHAI_PROJECT_ROOT'])
SOURCE = Path(os.environ['NANHAI_R4_WORKSPACE_ROOT'])
APK = Path(os.environ['NANHAI_STAGING_ROOT']) / 'apk-stock-intake-v2/org.videolan.vlc/body.raw'
AAPT2 = SOURCE / 'prebuilts/sdk-r4/tools/darwin/bin/aapt2'
SIGNER = SOURCE / 'prebuilts/sdk-r4/tools/darwin/lib/apksigner.jar'
JAVA = Path(os.environ['NANHAI_HDC']).parents[4] / 'jbr/Contents/Home/bin/java'
EXPECTED = {
    'apk': ('355ff246a0348c094a256926ea31cbec92701a2faca3d41d49170798c550ee3b', 47990842),
    'aapt2': ('3c5920804724dfe9a43e0dbf1f5b5dcbf08c4a2e829bebdaa04d38bfe7d7ada4', None),
    'apksigner.jar': ('9469c60e5e40fc5c44a2f2338509cb6600cdf065e9b50f9fa3ca6c5be5bae6a9', None),
    'java': ('cd158e1a5328ff42b687b7c2f5c61c7c3be3cfee7f18226ee903169e97336158', None),
}


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def save(name, data):
    with (HERE / name).open('xb') as out:
        out.write(data)


def main():
    if sys.argv[1:] != ['--execute']:
        return 3
    items = {'apk': APK, 'aapt2': AAPT2, 'apksigner.jar': SIGNER, 'java': JAVA}
    locked = {}
    for name, path in items.items():
        digest, size = EXPECTED[name]
        assert path.is_file() and sha(path) == digest, name
        if size is not None:
            assert path.stat().st_size == size, name
        locked[name] = {'path': str(path), 'sha256': digest, 'bytes': path.stat().st_size}
    lock = ROOT / 'benchmark/2026-09-23-corpus2-blind/downloads.lock.json'
    lock_row = json.loads(lock.read_text())['apps']['org.videolan.vlc']
    assert lock_row['sha256'] == EXPECTED['apk'][0] and lock_row['bytes'] == EXPECTED['apk'][1]
    assert lock_row['version_code'] == 13070106 and lock_row['abis'] == ['arm64-v8a']
    receipt = ROOT / 'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/apk-stock-intake-v2/root-intake-v1/ROOT-ACCEPTANCE.json'
    rows = [x for x in json.loads(receipt.read_text())['payloads'] if x['registry_package_label'] == 'org.videolan.vlc']
    assert len(rows) == 1 and rows[0]['sha256'] == EXPECTED['apk'][0]
    commands = {
        'badging': [str(AAPT2), 'dump', 'badging', str(APK)],
        'signature': [str(JAVA), '-XX:-UsePerfData', '-Xmx512m', '-Djava.awt.headless=true', f'-Djava.io.tmpdir={HERE}', '-jar', str(SIGNER), 'verify', '--verbose', '--print-certs', str(APK)],
    }
    result = {'schema': 'nanhai.g294.vlc.identity_probe.v1', 'at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'inputs': locked, 'index_sha256': sha(lock), 'raw_acceptance_sha256': sha(receipt), 'commands': {}, 'checks': {}, 'scope': 'read-only host package and signature verification; no full static, startup or count credit'}
    for name, argv in commands.items():
        began = time.monotonic()
        try:
            proc = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=180, env={**os.environ, 'TMPDIR': str(HERE), 'LC_ALL': 'C'})
            row = {'argv': argv, 'rc': proc.returncode, 'timed_out': False, 'elapsed_seconds': time.monotonic() - began}
        except subprocess.TimeoutExpired as e:
            proc = None
            row = {'argv': argv, 'rc': None, 'timed_out': True, 'elapsed_seconds': time.monotonic() - began}
            stdout, stderr = e.stdout or b'', e.stderr or b''
        else:
            stdout, stderr = proc.stdout, proc.stderr
        save(name + '.stdout.raw', stdout)
        save(name + '.stderr.raw', stderr)
        row.update(stdout_sha256=sha(HERE / (name + '.stdout.raw')), stderr_sha256=sha(HERE / (name + '.stderr.raw')), stdout_bytes=len(stdout), stderr_bytes=len(stderr))
        result['commands'][name] = row
        if row['rc'] != 0 or row['timed_out']:
            break
    if 'badging' in result['commands'] and result['commands']['badging']['rc'] == 0:
        body = (HERE / 'badging.stdout.raw').read_text(errors='replace')
        package = re.search(r"(?m)^package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'", body)
        result['checks']['package_identity'] = bool(package and package.groups() == ('org.videolan.vlc', '13070106', '3.7.1'))
    if 'signature' in result['commands'] and result['commands']['signature']['rc'] == 0:
        body = (HERE / 'signature.stdout.raw').read_text(errors='replace')
        certs = re.findall(r'(?im)^Signer #\d+ certificate SHA-256 digest: ([0-9a-f]{64})\s*$', body)
        result['signer_certificate_sha256'] = certs
        result['checks']['signature_verified'] = bool(certs) and 'Verifies' in body
    result['checks']['input_unchanged'] = all(sha(path) == EXPECTED[name][0] for name, path in items.items())
    result['rc'] = 0 if len(result['commands']) == 2 and all(row['rc'] == 0 and not row['timed_out'] for row in result['commands'].values()) and all(result['checks'].values()) else 2
    save('RESULT.json', (json.dumps(result, indent=2) + '\n').encode())
    print(json.dumps({'rc': result['rc'], 'checks': result['checks'], 'signer_certificate_sha256': result.get('signer_certificate_sha256')}))
    return result['rc']


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as exc:
        print(repr(exc), file=sys.stderr)
        sys.exit(2)
