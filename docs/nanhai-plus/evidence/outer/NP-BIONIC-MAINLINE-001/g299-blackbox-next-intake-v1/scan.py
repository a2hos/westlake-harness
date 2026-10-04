#!/usr/bin/env python3
"""Host-only raw APK candidate audit. Run through nanhai_plus_env.py --run."""
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import zipfile

HERE = Path(__file__).resolve().parent
STAGING = Path(os.environ['NANHAI_STAGING_ROOT']) / 'g299-blackbox-next-intake-v1'
INPUTS = {
    'nordvpn': {
        'file': 'NordVPN.apk',
        'official_page': 'https://nordvpn.com/download/android/',
        'download_url': 'https://downloads.nordcdn.com/apps/android/generic/nordvpn-sideload/latest/v2/NordVPN.apk',
        'effective_url': 'https://downloads77-android.nordcdn.com/apps/android/generic/nordvpn-sideload/latest/v2/NordVPN.apk',
        'play_url': 'https://play.google.com/store/apps/details?id=com.nordvpn.android',
        'expected_package': 'com.nordvpn.android',
        'publisher_listing': 'Nord Security',
        'play_download_floor': '100M+',
        'expected_size': 109609596,
        'transport_http': 200,
    },
    'surfshark': {
        'file': 'Surfshark.apk',
        'official_page': 'https://surfshark.com/download/android',
        'download_url': 'https://downloads.surfshark.com/android/Surfshark.apk',
        'effective_url': 'https://downloads.surfshark.com/android/Surfshark.apk',
        'play_url': 'https://play.google.com/store/apps/details?id=com.surfshark.vpnclient.android',
        'expected_package': 'com.surfshark.vpnclient.android',
        'publisher_listing': 'Surfshark B.V.',
        'play_download_floor': '10M+',
        'expected_size': 156032892,
        'transport_http': 200,
    },
}


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def manifest(text):
    row = next(line for line in text.splitlines() if line.startswith('package: '))
    values = dict(re.findall(r"(?:^|\s)(name|versionCode|versionName)='([^']+)'", row))
    return values


def signer(text):
    cert = re.search(r'^Signer #1 certificate SHA-256 digest: ([0-9a-f]{64})$', text, re.M)
    dn = re.search(r'^Signer #1 certificate DN: (.+)$', text, re.M)
    verified = {scheme: bool(re.search(r'^Verified using v' + scheme + r' scheme .*: true$', text, re.M))
                for scheme in ('1', '2', '3', '3.1', '4')}
    if not cert or not dn or not any(verified.values()):
        raise ValueError('cryptographic signer report incomplete')
    return {'certificate_sha256': cert.group(1), 'certificate_dn': dn.group(1),
            'verified_schemes': verified}


def inspect(name, spec):
    apk = STAGING / spec['file']
    badging = STAGING / (spec['file'].removesuffix('.apk') + '.badging.stdout')
    sig = STAGING / (spec['file'].removesuffix('.apk') + '.signer.stdout')
    bad_err = STAGING / (spec['file'].removesuffix('.apk') + '.badging.stderr')
    sig_err = STAGING / (spec['file'].removesuffix('.apk') + '.signer.stderr')
    headers = STAGING / ('nord.headers' if name == 'nordvpn' else 'surf.headers')
    assert apk.stat().st_size == spec['expected_size']
    assert bad_err.read_bytes() == sig_err.read_bytes() == b''
    values = manifest(badging.read_text())
    assert values['name'] == spec['expected_package']
    signature = signer(sig.read_text())
    with zipfile.ZipFile(apk) as z:
        infos = z.infolist()
        assert z.testzip() is None
        names = [i.filename for i in infos]
        assert len(names) == len(set(names))
        assert 'AndroidManifest.xml' in names and 'classes.dex' in names
        abis = sorted({n.split('/')[1] for n in names if n.startswith('lib/') and n.endswith('.so')})
        arm64 = [n for n in names if n.startswith('lib/arm64-v8a/') and n.endswith('.so')]
        assert arm64 and 'arm64-v8a' in abis
        for n in arm64:
            with z.open(n) as stream:
                first = stream.read(20)
            assert first[:4] == b'\x7fELF' and first[4] == 2 and struct.unpack('<H', first[18:20])[0] == 183
        dex = [n for n in names if re.fullmatch(r'classes(\d+)?\.dex', n)]
    content_length = [int(m.group(1)) for m in re.finditer(
        rb'(?im)^content-length:\s*(\d+)\s*$', headers.read_bytes())]
    assert content_length and content_length[-1] == spec['expected_size']
    return {**spec, 'artifact_path': str(apk), 'bytes': apk.stat().st_size,
            'sha256': sha(apk), 'manifest': values, 'signature': signature,
            'zip_crc': 'PASS_FULL', 'zip_entries': len(infos), 'dex_entries': len(dex),
            'abis': abis, 'arm64_elf_count': len(arm64),
            'transport_headers_sha256': sha(headers),
            'badging_sha256': sha(badging), 'signer_report_sha256': sha(sig),
            'publisher_certificate_binding': 'UNPROVEN_NO_OFFICIAL_CERT_FINGERPRINT',
            'cold_start': False, 'device_test': False}


def main():
    result = {'schema': 'g299-blackbox-next-raw-static-candidate-v1',
              'status': 'HOST_RAW_STATIC_CANDIDATE_ONLY',
              'current_accepted_raw_before': 83, 'accepted_raw_delta': 0,
              'qualified_blackbox_delta': 0, 'cold_start_delta': 0,
              'packages': {name: inspect(name, spec) for name, spec in INPUTS.items()},
              'device_commands': 0, 'container_commands': 0, 'graph_commands': 0}
    path = HERE / 'CANDIDATE.json'
    with path.open('x') as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps({'status': result['status'], 'packages': list(result['packages']),
                      'candidate_sha256': sha(path)}, sort_keys=True))


if __name__ == '__main__':
    main()
