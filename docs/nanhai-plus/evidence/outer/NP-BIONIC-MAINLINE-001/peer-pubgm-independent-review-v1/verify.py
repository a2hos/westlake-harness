import collections
import datetime
import hashlib
import json
import pathlib
import re
import struct
import subprocess
import zipfile

ROOT = pathlib.Path.cwd()
BASE = ROOT / 'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001'
HERE = pathlib.Path(__file__).parent
APK = ROOT / '.nanhai-plus-runtime/bionic-oh7-aosp16/staging/peer-pubgm-official-raw-v1/pubgm-official.apk'
RAW = BASE / 'peer-pubgm-official-raw-v1'
STATIC = BASE / 'peer-pubgm-four-static-v1'
QUAL = BASE / 'peer-pubgm-qualification-v1'

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def run(name, argv):
    p = subprocess.run(argv, capture_output=True, timeout=180)
    (HERE / (name + '.stdout.raw')).write_bytes(p.stdout)
    (HERE / (name + '.stderr.raw')).write_bytes(p.stderr)
    return {'argv': argv, 'rc': p.returncode,
            'stdout_sha256': sha(HERE / (name + '.stdout.raw')),
            'stderr_sha256': sha(HERE / (name + '.stderr.raw'))}

start = datetime.datetime.now(datetime.timezone.utc).isoformat()
names = []
dex = []
bad_dex = []
elf = collections.Counter()
with zipfile.ZipFile(APK) as z:
    infos = z.infolist()
    names = [i.filename for i in infos]
    crc_first_bad = z.testzip()
    for i in infos:
        n = i.filename
        if re.fullmatch(r'classes(?:[2-9]|[1-9][0-9]+)?\.dex', n):
            dex.append(n)
            with z.open(i) as f:
                if f.read(4) != b'dex\n':
                    bad_dex.append(n)
        if n.endswith('.so'):
            with z.open(i) as f:
                h = f.read(20)
            if h[:4] != b'\x7fELF':
                elf['non_elf'] += 1
            else:
                machine = struct.unpack('<H' if h[5] == 1 else '>H', h[18:20])[0]
                abi = n.split('/')[1] if n.startswith('lib/') else 'other'
                elf[f'{abi}:class{h[4]}:machine{machine}'] += 1

aapt = run('aapt2', [str(pathlib.Path.home() / 'Library/Android/sdk/build-tools/36.1.0/aapt2'), 'dump', 'badging', str(APK)])
sign = run('apksigner', [str(pathlib.Path.home() / 'Library/Android/sdk/build-tools/36.1.0/apksigner'), 'verify', '--verbose', '--print-certs', str(APK)])
page = (RAW / 'publisher-page.raw').read_text(errors='replace')
play = (QUAL / 'play.html').read_text(errors='replace')
url = 'https://f.gbcass.com/PUBGMOBILE_Global_4.6.0_uawebsite_livik01_5678FCFA.apk'
receipts = [RAW/'RESULT.json', RAW/'VERIFY.json', STATIC/'RESULT.json',
            STATIC/'ZIP-RESULT.json', STATIC/'METADATA-RESULT.json',
            STATIC/'DEX-RESULT.json', STATIC/'ELF-RESULT.json',
            QUAL/'QUALIFICATION.json', QUAL/'SOURCE-FETCH.json']
out = {
    'schema': 'peer-pubgm-independent-observation-v1',
    'started_at_utc': start,
    'finished_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'apk_path': str(APK.relative_to(ROOT)),
    'apk_bytes': APK.stat().st_size,
    'apk_sha256': sha(APK),
    'zip': {'entries': len(infos), 'duplicate_names': len(names)-len(set(names)),
            'crc_first_bad': crc_first_bad, 'manifest_entries': names.count('AndroidManifest.xml'),
            'root_dex': len(dex), 'bad_dex_magic': bad_dex,
            'so_entries': sum(elf.values()), 'elf_header_counts': dict(elf)},
    'aapt2': aapt, 'apksigner': sign,
    'source': {'publisher_page_sha256': sha(RAW/'publisher-page.raw'),
               'publisher_page_links_exact_apk': url in page,
               'head_headers_sha256': sha(RAW/'apk-head-headers.raw'),
               'get_headers_sha256': sha(RAW/'apk-get-headers.raw'),
               'play_page_sha256': sha(QUAL/'play.html'),
               'play_exact_package': 'id=com.tencent.ig' in play,
               'play_publisher': 'Level Infinite' in play,
               'play_1b_plus': '1B+' in play},
    'receipt_sha256': {str(p.relative_to(BASE)): sha(p) for p in receipts},
    'scope': 'Read-only local APK and candidate receipts; no network, download, device, container, Bridge or ledger action'
}
(HERE/'OBSERVATION.json').write_text(json.dumps(out, indent=2, sort_keys=True) + '\n')
print(json.dumps(out, indent=2, sort_keys=True))
