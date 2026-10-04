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
E = ROOT / 'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001'
HERE = pathlib.Path(__file__).parent
APK = ROOT / '.nanhai-plus-runtime/bionic-oh7-aosp16/staging/peer-bigo-official-raw-v1/bigo-official.apk'

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def run(name, argv):
    p = subprocess.run(argv, capture_output=True, timeout=60)
    (HERE / (name + '.stdout.raw')).write_bytes(p.stdout)
    (HERE / (name + '.stderr.raw')).write_bytes(p.stderr)
    return {'argv': argv, 'rc': p.returncode,
            'stdout_sha256': sha(HERE / (name + '.stdout.raw')),
            'stderr_sha256': sha(HERE / (name + '.stderr.raw'))}

start = datetime.datetime.now(datetime.timezone.utc).isoformat()
assert APK.is_file()
names = []
dex = []
so = []
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
                if f.read(8)[:4] != b'dex\n':
                    bad_dex.append(n)
        if n.endswith('.so'):
            so.append(n)
            with z.open(i) as f:
                h = f.read(20)
            if h[:4] != b'\x7fELF':
                elf['non_elf'] += 1
            else:
                machine = struct.unpack('<H' if h[5] == 1 else '>H', h[18:20])[0]
                abi = 'arm64-v8a' if n.startswith('lib/arm64-v8a/') else 'armeabi-v7a' if n.startswith('lib/armeabi-v7a/') else 'other'
                elf[f'{abi}:class{h[4]}:machine{machine}'] += 1

aapt = run('aapt2', [str(pathlib.Path.home() / 'Library/Android/sdk/build-tools/36.1.0/aapt2'), 'dump', 'badging', str(APK)])
sign = run('apksigner', [str(pathlib.Path.home() / 'Library/Android/sdk/build-tools/36.1.0/apksigner'), 'verify', '--verbose', '--print-certs', str(APK)])

raw = E / 'peer-bigo-official-raw-v1'
static = E / 'peer-bigo-four-static-v1'
qual = E / 'peer-bigo-qualification-v1'
page = (raw / 'publisher-page.raw').read_bytes()
play = (qual / 'play.html').read_bytes()
apk_url = b'https://static-web.bigolive.tv/as/bigo-static/apk/bigolive-bigotv.apk'
play_text = play.decode('utf-8', 'replace')
result = {
    'schema': 'peer-bigo-independent-observation-v1',
    'started_at_utc': start,
    'finished_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'apk_path': str(APK.relative_to(ROOT)),
    'apk_bytes': APK.stat().st_size,
    'apk_sha256': sha(APK),
    'zip': {'entries': len(infos), 'duplicate_names': len(names) - len(set(names)),
            'crc_first_bad': crc_first_bad, 'manifest_entries': names.count('AndroidManifest.xml'),
            'root_dex': len(dex), 'bad_root_dex_magic': bad_dex, 'so_entries': len(so),
            'elf_header_counts': dict(elf)},
    'aapt2': aapt, 'apksigner': sign,
    'source': {'publisher_page_sha256': sha(raw / 'publisher-page.raw'),
               'publisher_page_links_exact_apk': apk_url in page,
               'head_headers_sha256': sha(raw / 'apk-head-headers.raw'),
               'get_headers_sha256': sha(raw / 'apk-get-headers.raw'),
               'play_page_sha256': sha(qual / 'play.html'),
               'play_exact_package': 'id=sg.bigo.live' in play_text,
               'play_publisher': 'BIGO TECHNOLOGY PTE. LTD.' in play_text,
               'play_500m_plus': '500M+' in play_text},
    'candidate_receipt_sha256': {str(p.relative_to(E)): sha(p) for p in [
        raw/'RESULT.json', raw/'VERIFY.json', static/'RESULT.json',
        static/'ZIP-RESULT.json', static/'METADATA-RESULT.json',
        static/'DEX-RESULT.json', static/'ELF-RESULT.json',
        static/'NESTED-ARCHIVE.json', qual/'QUALIFICATION.json',
        qual/'SOURCE-FETCH.json']},
    'scope': 'Read-only local APK and candidate receipts; no network, download, device, container, Bridge or ledger action'
}
(HERE / 'OBSERVATION.json').write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + '\n')
print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
