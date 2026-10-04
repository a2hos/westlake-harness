#!/usr/bin/env python3
"""Verify downloaded publisher APK identity with host Android build tools."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

HERE = Path(__file__).parent
APK = Path(os.environ['NANHAI_STAGING_ROOT']) / 'peer-apk-portfolio-aimp-official-v2/aimp_4.31.1747.apk'
TOOLS = Path.home() / 'Library/Android/sdk/build-tools/36.1.0'
EXPECTED = '2d70fb1cb519104826d825d2060289ad77fbd75b5b68c00ff93631ffafa06a46'

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def command(name, argv):
    p = subprocess.run([str(a) for a in argv], capture_output=True, timeout=120, check=False)
    (HERE / (name + '.stdout.raw')).write_bytes(p.stdout)
    (HERE / (name + '.stderr.raw')).write_bytes(p.stderr)
    return {'argv': [str(a) for a in argv], 'rc': p.returncode,
            'stdout_sha256': hashlib.sha256(p.stdout).hexdigest(),
            'stderr_sha256': hashlib.sha256(p.stderr).hexdigest()}

def main():
    if sys.argv[1:] != ['--execute'] or (HERE / 'VERIFY-V2.json').exists():
        return 2
    acquire = json.loads((HERE / 'RESULT.json').read_text())
    if not (acquire['apk_sha256'] == sha(APK) == EXPECTED):
        return 2
    aapt = command('aapt2', [TOOLS / 'aapt2', 'dump', 'badging', APK])
    signer = command('apksigner', [TOOLS / 'apksigner', 'verify', '--verbose', '--print-certs', APK])
    badging = (HERE / 'aapt2.stdout.raw').read_text(errors='replace')
    cert_text = (HERE / 'apksigner.stdout.raw').read_text(errors='replace')
    match = re.search(r"^package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'", badging, re.M)
    sdk = re.search(r"^sdkVersion:'([^']+)'", badging, re.M)
    target = re.search(r"^targetSdkVersion:'([^']+)'", badging, re.M)
    certs = re.findall(r'Signer #\d+ certificate SHA-256 digest: ([0-9a-fA-F]+)', cert_text)
    arm64 = []
    with zipfile.ZipFile(APK) as z:
        for name in z.namelist():
            if name.startswith('lib/arm64-v8a/') and name.endswith('.so'):
                data = z.read(name)
                arm64.append({'name': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                              'true_elf64_aarch64': len(data) >= 20 and data[:4] == b'\x7fELF' and data[4] == 2 and data[5] == 1 and int.from_bytes(data[18:20], 'little') == 183})
    result = {'schema': 'aimp-official-verify-v1', 'apk_sha256': sha(APK),
              'package': match.groups() if match else None, 'min_sdk': sdk.group(1) if sdk else None,
              'target_sdk': target.group(1) if target else None, 'signer_cert_sha256': certs,
              'aapt2': aapt, 'apksigner': signer, 'aapt2_sha256': sha(TOOLS/'aapt2'),
              'apksigner_sha256': sha(TOOLS/'apksigner'), 'arm64_native': arm64,
              'publisher_version_label': '4.31.1747',
              'host_only': True, 'root_count_changed': False, 'startup_proven': False}
    result['candidate_pass'] = (aapt['rc'] == 0 and signer['rc'] == 0 and
                                result['package'] == ('com.aimp.player', '1747', 'v4.31.1747 (10.09.2026)') and
                                bool(certs) and len(arm64) == acquire['arm64_so_entries'] and
                                all(x['true_elf64_aarch64'] for x in arm64))
    (HERE / 'VERIFY-V2.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    return 0 if result['candidate_pass'] else 2

if __name__ == '__main__':
    sys.exit(main())
