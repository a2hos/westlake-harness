#!/usr/bin/env python3
"""Acquire the publisher-hashed stable AIMP Android APK, host only."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT = Path(os.environ['NANHAI_PROJECT_ROOT'])
HERE = Path(__file__).parent
STAGING = Path(os.environ['NANHAI_STAGING_ROOT']) / 'peer-apk-portfolio-aimp-official-v2'
PAGE = 'https://aimp.ru/?do=download&os=android'
ENTRY = 'https://aimp.ru/?do=download.file&id=13'
EXPECTED = '2d70fb1cb519104826d825d2060289ad77fbd75b5b68c00ff93631ffafa06a46'
PACKAGE = 'com.aimp.player'

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()

def fetch(url, path, prefix, limit):
    argv = [os.environ['NANHAI_CURL'], '--fail', '--location', '--retry', '0',
            '--connect-timeout', '15', '--max-time', str(limit), '--output', str(path),
            '--dump-header', str(HERE / (prefix + '.headers.raw')), url]
    with (HERE / (prefix + '.stdout.raw')).open('xb') as out, (HERE / (prefix + '.stderr.raw')).open('xb') as err:
        rc = subprocess.run(argv, stdout=out, stderr=err, check=False).returncode
    return {'argv': argv, 'rc': rc, 'stdout_sha256': sha(HERE / (prefix + '.stdout.raw')),
            'stderr_sha256': sha(HERE / (prefix + '.stderr.raw')),
            'headers_sha256': sha(HERE / (prefix + '.headers.raw'))}

def main():
    if sys.argv[1:] != ['--execute'] or (HERE / 'RESULT.json').exists():
        return 2
    base = ROOT / 'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001'
    registry = base / 'upstream-apk-registry-v1/REGISTRY.json'
    lock = base / 'g339-cross-apk-exposure-cohort-v2/LOCK.json'
    if any(x['package'] == PACKAGE for x in json.loads(registry.read_text())['artifacts']):
        raise ValueError('duplicate package in upstream registry')
    if any(x['package'] == PACKAGE for x in json.loads(lock.read_text())['identities']):
        raise ValueError('duplicate package in frozen accepted corpus')
    STAGING.mkdir(mode=0o700, parents=True, exist_ok=False)
    page_path = HERE / 'publisher-page.html'
    page = fetch(PAGE, page_path, 'PAGE', 45)
    html = page_path.read_text()
    if page['rc'] or 'AIMP v4.31.1747' not in html or EXPECTED not in html or 'do=download.file&id=13' not in html:
        raise ValueError('publisher page version/hash/direct link mismatch')
    part = STAGING / 'aimp_4.31.1747.apk.part'
    download = fetch(ENTRY, part, 'APK', 180)
    if download['rc'] or sha(part) != EXPECTED:
        raise ValueError('download or publisher SHA mismatch')
    with zipfile.ZipFile(part) as z:
        names = z.namelist()
        bad = z.testzip()
    if bad is not None or len(names) != len(set(names)) or names.count('AndroidManifest.xml') != 1:
        raise ValueError('ZIP integrity mismatch')
    apk = STAGING / 'aimp_4.31.1747.apk'
    part.rename(apk)
    result = {'schema': 'aimp-official-raw-candidate-v1', 'package_expected': PACKAGE,
              'version_expected': '4.31.1747', 'publisher_page': PAGE, 'publisher_entry': ENTRY,
              'publisher_expected_sha256': EXPECTED, 'publisher_page_sha256': sha(page_path),
              'registry_sha256': sha(registry), 'g339_lock_sha256': sha(lock),
              'pre_acquisition_package_duplicates': 0, 'page_fetch': page, 'apk_fetch': download,
              'apk_path': str(apk.relative_to(ROOT)), 'apk_sha256': sha(apk), 'bytes': apk.stat().st_size,
              'zip_entries': len(names), 'zip_first_bad': bad, 'zip_duplicate_names': 0,
              'root_dex_entries': len([n for n in names if n.startswith('classes') and n.endswith('.dex') and '/' not in n]),
              'arm64_so_entries': len([n for n in names if n.startswith('lib/arm64-v8a/') and n.endswith('.so')]),
              'device_commands': 0, 'container_commands': 0, 'root_count_changed': False,
              'startup_proven': False}
    (HERE / 'RESULT.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    return 0

if __name__ == '__main__':
    sys.exit(main())
