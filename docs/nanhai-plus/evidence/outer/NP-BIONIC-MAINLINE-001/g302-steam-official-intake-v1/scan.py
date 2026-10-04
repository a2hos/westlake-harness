"""Read-only host intake of two exact Valve downloads; no canonical admission."""
import datetime
import hashlib
import json
import os
import pathlib
import re
import struct
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[6]
HERE = pathlib.Path(__file__).parent
STAGE = ROOT / '.nanhai-plus-runtime/bionic-oh7-aosp16/staging/g302-steam-official-intake-v1'
SPECS = [
    ('SteamMobile', 'com.valvesoftware.android.steam.community', '3.10.9', 10470850,
     'https://media.steampowered.com/apps/steam-android/steam-3.10.9.apk', 131986934),
    ('SteamLink', 'com.valvesoftware.steamlink', '1.3.32', 5000315,
     'https://media.steampowered.com/steamlink/android/latest/steamlink-android.apk', 132207126),
]


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for b in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


def scan(spec):
    stem, package, version, code, url, size = spec
    apk = STAGE / (stem + '.apk')
    bad = STAGE / (stem + '.badging.stdout')
    sig = STAGE / (stem + '.signer.stdout')
    headers = STAGE / ('steam-mobile.headers' if stem == 'SteamMobile' else 'steam-link.headers')
    assert apk.stat().st_size == size
    assert (STAGE / (stem + '.badging.stderr')).stat().st_size == 0
    assert (STAGE / (stem + '.signer.stderr')).stat().st_size == 0
    line = next(x for x in bad.read_text().splitlines() if x.startswith('package:'))
    values = dict(re.findall(r"(?:^|\s)(name|versionCode|versionName)='([^']*)'", line))
    assert values == {'name': package, 'versionCode': str(code), 'versionName': version}
    report = sig.read_text()
    cert = re.search(r'^Signer #1 certificate SHA-256 digest: ([0-9a-f]{64})$', report, re.M)
    dn = re.search(r'^Signer #1 certificate DN: (.+)$', report, re.M)
    schemes = {x: bool(re.search(r'^Verified using v' + x + r' scheme .*: true$', report, re.M)) for x in ('1', '2', '3', '3.1', '4')}
    assert cert and dn and any(schemes.values())
    header = headers.read_text()
    assert '200 OK' in header and f'Content-Length: {size}' in header
    with zipfile.ZipFile(apk) as z:
        entries = z.infolist()
        names = [e.filename for e in entries]
        assert len(names) == len(set(names)) and names.count('AndroidManifest.xml') == 1
        assert z.testzip() is None
        dex = [n for n in names if re.fullmatch(r'classes(\d+)?\.dex', n)]
        assert dex
        native = [n for n in names if n.startswith('lib/') and n.endswith('.so')]
        arm64 = [n for n in native if n.startswith('lib/arm64-v8a/')]
        assert arm64
        non_elf = []
        for n in arm64:
            with z.open(n) as stream:
                first = stream.read(20)
            if not (first[:4] == b'\x7fELF' and first[4] == 2 and len(first) >= 20 and struct.unpack_from('<H', first, 18)[0] == 183):
                non_elf.append(n)
        assert not non_elf
        abis = sorted({n.split('/')[1] for n in native})
    return {
        'package': package, 'version_name': version, 'version_code': code,
        'apk_path': str(apk.relative_to(ROOT)), 'bytes': size, 'sha256': sha(apk),
        'official_download_url': url, 'headers_sha256': sha(headers),
        'download_completed_file_mtime_utc': datetime.datetime.fromtimestamp(apk.stat().st_mtime, datetime.timezone.utc).isoformat(),
        'aapt2_badging_sha256': sha(bad), 'apksigner_report_sha256': sha(sig),
        'signature_schemes': schemes, 'certificate_sha256': cert.group(1), 'certificate_dn': dn.group(1),
        'zip_entries_crc_checked': len(entries), 'dex_entries': len(dex),
        'native_so_entries': len(native), 'arm64_elf_count': len(arm64), 'abis': abis,
        'publisher_signer_binding': 'UNPROVEN_NO_OFFICIAL_PUBLISHED_CERT_FINGERPRINT',
    }


def main():
    result = {'schema': 'g302-steam-two-raw-candidates-v1', 'observed_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'decision': 'HOST_RAW_CANDIDATES_ONLY_PENDING_PEER_AND_ROOT_ADMISSION',
              'canonical_raw_before': 85, 'canonical_raw_delta': 0, 'qualified_blackbox_delta': 0,
              'complete_static_delta': 0, 'cold_start_delta': 0,
              'packages': [scan(s) for s in SPECS], 'device_commands': 0, 'container_commands': 0,
              'namespace_commands': 0, 'bridge_writes': 0}
    with (HERE / 'CANDIDATE.json').open('x') as f:
        json.dump(result, f, indent=2)
        f.write('\n')
    print(json.dumps({'packages': [(x['package'], x['sha256']) for x in result['packages']], 'candidate_sha256': sha(HERE / 'CANDIDATE.json')}))


if __name__ == '__main__':
    main()
