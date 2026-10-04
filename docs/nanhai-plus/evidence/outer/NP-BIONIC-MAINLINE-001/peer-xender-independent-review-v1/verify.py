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
APK = ROOT / '.nanhai-plus-runtime/bionic-oh7-aosp16/staging/peer-xender-official-raw-v1/xender-official.apk'
RAW = BASE / 'peer-xender-official-raw-v1'
STATIC = BASE / 'peer-xender-four-static-v1'
QUAL = BASE / 'peer-xender-qualification-v1'

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
landing = (QUAL / 'landing.raw').read_text(errors='replace')
js = (QUAL / 'js.raw').read_text(errors='replace')
config = json.loads((QUAL / 'config.raw').read_text())
play = (QUAL / 'play.raw').read_text(errors='replace')
pkg = next((x for x in config['apps'] if x.get('pn') == 'cn.xender'), None)
assert pkg is not None
names = []
dex = []
elf = collections.Counter()
bad_dex_magic = []
with zipfile.ZipFile(APK) as z:
    infos = z.infolist()
    names = [x.filename for x in infos]
    crc_first_bad = z.testzip()
    for i in infos:
        n = i.filename
        if re.fullmatch(r'classes(?:[2-9]|[1-9][0-9]+)?\.dex', n):
            dex.append(n)
            with z.open(i) as f:
                if f.read(4) != b'dex\n':
                    bad_dex_magic.append(n)
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
receipts = [RAW/'RESULT.json', RAW/'VERIFY.json', STATIC/'RESULT.json',
            STATIC/'ZIP-RESULT.json', STATIC/'METADATA-RESULT.json',
            STATIC/'DEX-RESULT.json', STATIC/'ELF-RESULT.json',
            QUAL/'QUALIFICATION.json', QUAL/'SOURCE-FETCH.json']
out = {
  'schema': 'peer-xender-independent-observation-v1',
  'started_at_utc': start,
  'finished_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
  'apk_path': str(APK.relative_to(ROOT)),
  'apk_bytes': APK.stat().st_size,
  'apk_sha256': sha(APK),
  'zip': {'entries': len(infos), 'duplicate_names': len(names)-len(set(names)),
          'crc_first_bad': crc_first_bad, 'manifest_entries': names.count('AndroidManifest.xml'),
          'root_dex': len(dex), 'bad_dex_magic': bad_dex_magic,
          'so_entries': sum(elf.values()), 'elf_header_counts': dict(elf)},
  'aapt2': aapt, 'apksigner': sign,
  'official_chain': {
      'landing_sha256': sha(QUAL/'landing.raw'),
      'landing_links_js': '/js/index.22e6c96706269929b192.js' in landing,
      'js_sha256': sha(QUAL/'js.raw'),
      'js_declares_config_api': 'https://js.xdd-w-00tj3nsj.com/h5_upd_url' in js,
      'js_calls_config_with_app_xd': '?app=xd&platform=' in js,
      'config_sha256': sha(QUAL/'config.raw'),
      'config_xender_entry': pkg,
      'raw_page_matches_config_sha256': sha(RAW/'publisher-page.raw') == sha(QUAL/'config.raw'),
      'get_url_matches_config': pkg['download_url'] in json.loads((RAW/'RESULT.json').read_text())['get']['argv'],
      'head_url_matches_config': pkg['download_url'] in json.loads((RAW/'RESULT.json').read_text())['head']['argv'],
      'play_sha256': sha(QUAL/'play.raw'),
      'play_same_package': 'id=cn.xender' in play,
      'play_500m_plus': '500M+' in play,
  },
  'receipt_sha256': {str(p.relative_to(BASE)): sha(p) for p in receipts},
  'scope': 'Read-only local source/receipt/APK review; no network, download, device, container, Bridge or ledger action'
}
(HERE/'OBSERVATION.json').write_text(json.dumps(out, indent=2, sort_keys=True) + '\n')
print(json.dumps(out, indent=2, sort_keys=True))
