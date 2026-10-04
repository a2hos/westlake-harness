#!/usr/bin/env python3
"""Read-only G293 preparation checks. Never runs a scanner phase."""
import ast
import hashlib
import json
from pathlib import Path
import struct
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]
INPUTS = json.loads((HERE / 'INPUTS.json').read_text())

def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()

checks = []
def check(name, ok):
    if not ok:
        raise RuntimeError(name)
    checks.append(name)

for name in ('common.py', 'scan_phase.py', 'run.py'):
    ast.parse((HERE / name).read_text())
checks.append('three_scripts_AST')
apk_record = INPUTS['apks'][0]
apk = ROOT / apk_record['path']
check('exact retained APK', apk.is_file() and apk.stat().st_size == apk_record['bytes'] == 72422482
      and sha(apk) == apk_record['sha256'])
raw = ROOT / INPUTS['root_acceptance']['path']
accepted = json.loads(raw.read_text())
check('root raw admission', sha(raw) == INPUTS['root_acceptance']['sha256'] and
      accepted['decision'] == INPUTS['root_acceptance']['decision'] and
      accepted['apk_sha256'] == apk_record['sha256'] and accepted['package'] == 'im.vector.app')
check('scanner source hashes', all(sha(ROOT / rel) == digest
      for rel, digest in INPUTS['source_sha256'].items()))
check('venv manifest hash', sha(INPUTS['venv_manifest']['path']) == INPUTS['venv_manifest']['sha256'])
mapping = INPUTS['tool_mapping']
check('readelf tool and alias', sha(mapping['target']) == mapping['tool_sha256'] and
      Path(mapping['alias']).is_symlink() and
      Path(mapping['alias']).resolve() == Path(mapping['target']).resolve())
with zipfile.ZipFile(apk) as archive:
    entries = archive.infolist()
    names = [entry.filename for entry in entries]
    dex = [name for name in names if name == 'classes.dex' or
           (name.startswith('classes') and name.endswith('.dex') and name[7:-4].isdigit())]
    so = [entry for entry in entries if entry.filename.startswith('lib/') and
          entry.filename.endswith('.so')]
    formats = []
    for entry in so:
        with archive.open(entry) as stream:
            header = stream.read(20)
        formats.append((entry.filename.split('/')[1], header[:4], header[4],
                        struct.unpack_from('<H', header, 18)[0]))
check('preflight ZIP shape', len(entries) == 6839 and len(names) == len(set(names)) and
      names.count('AndroidManifest.xml') == 1 and len(dex) == 8 and len(so) == 21 and
      all(item == ('arm64-v8a', b'\x7fELF', 2, 183) for item in formats))
source = (HERE / 'run.py').read_text()
check('four ordered phases', "('zip', 'metadata', 'elf', 'dex')" in source and
      "sys.argv[1:] != ['--execute']" in source)
check('review and release gates', 'check_release()' in source and
      'peer_review_sha256' in source and 'raw_receipt_sha256' in source)
check('no scan output', not any((HERE / name).exists() for name in
      ('STARTED.json', 'RESULT.json', 'phases', 'apk-view', 'tmp')))
check('no network or device command sites', all(term not in source for term in
      ('curl ', 'requests.', 'http.client', 'socket.', 'hdc ', 'adb ', 'docker ', 'podman ')))
print(json.dumps({'status': 'PASS', 'checks': checks, 'apk_sha256': sha(apk),
                  'network_requests': 0, 'scan_executed': False, 'device_commands': 0,
                  'container_commands': 0, 'canonical_count_delta': 0}, sort_keys=True))
