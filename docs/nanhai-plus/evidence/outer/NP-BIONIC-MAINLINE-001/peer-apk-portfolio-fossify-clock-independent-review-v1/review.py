#!/usr/bin/env python3
"""Independent host-only review of the Fossify Clock raw and static handoffs."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

ROOT = Path(os.environ['NANHAI_PROJECT_ROOT'])
RUNTIME = Path(os.environ['NANHAI_RUNTIME_ROOT'])
VENV = RUNTIME / 'venvs/harness-python-v1'
VENV_RECEIPT = ROOT / 'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/harness-python-runtime-v1/INSTALLED-VENV-MANIFEST.json'
if Path(json.loads(VENV_RECEIPT.read_text())['venv']) != VENV:
    raise ValueError('registered scanner Python environment differs from project runtime')
if Path(sys.prefix) != VENV:
    interpreter = VENV / 'bin/python3'
    if not interpreter.is_file():
        raise ValueError('registered scanner Python interpreter missing')
    os.execv(str(interpreter), [str(interpreter), '-B', *sys.argv])
BASE = ROOT / 'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001'
RAW = BASE / 'peer-apk-portfolio-fossify-clock-v1'
STATIC = BASE / 'peer-apk-portfolio-fossify-clock-static-v1'
REG = BASE / 'upstream-apk-registry-v1/REGISTRY.json'
LOCK = BASE / 'upstream-apk-registry-v1/source-metadata/benchmark/2026-09-25-batch5-blind/downloads.lock.json'
APK = Path(os.environ['NANHAI_STAGING_ROOT']) / 'peer-apk-portfolio-fossify-clock-v1/fossify-clock-1.6.0.apk'
EXPECTED = '43cf9f0ec45f1f1ff2df47286622e5b8f3acedaeb07b7f7641b5243dbedca079'

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()

def read(path):
    return json.loads(path.read_text())

def verify_handoff(folder):
    handoff = read(folder / 'HANDOFF.json')
    for name, record in handoff['files'].items():
        path = folder / name
        if not path.is_file() or path.stat().st_size != record['bytes'] or sha(path) != record['sha256']:
            raise ValueError('handoff file mismatch: ' + str(path))
    return handoff

def run(argv):
    p = subprocess.run([str(a) for a in argv], capture_output=True, timeout=120, check=False)
    return {'rc': p.returncode, 'stdout_sha256': hashlib.sha256(p.stdout).hexdigest(),
            'stderr_sha256': hashlib.sha256(p.stderr).hexdigest(), 'stdout': p.stdout.decode(errors='replace')}

def main():
    artifact = [x for x in read(REG)['artifacts'] if x['package'] == 'org.fossify.clock']
    if len(artifact) != 1:
        raise ValueError('registry identity not unique')
    artifact = artifact[0]
    origin = read(LOCK)['fclock']
    raw_handoff = verify_handoff(RAW)
    static_handoff = verify_handoff(STATIC)
    raw = read(RAW / 'RESULT.json')
    verified = read(RAW / 'VERIFY.json')
    scan = read(STATIC / 'STATIC.json')
    if not (sha(REG) == raw['registry_sha256'] == raw_handoff['upstream_registry_sha256'] == static_handoff['upstream_registry_sha256']):
        raise ValueError('registry hash mismatch')
    if not (origin['package'] == artifact['package'] == raw_handoff['package'] == static_handoff['package'] == 'org.fossify.clock'
            and origin['version_name'] == artifact['versions'][0] == raw_handoff['version_name'] == '1.6.0'
            and origin['version_code'] == int(artifact['version_codes'][0]) == raw_handoff['version_code'] == 10
            and origin['url'] == artifact['source_urls'][0] == raw_handoff['source_url']
            and origin['sha256'] == artifact['sha256'] == EXPECTED):
        raise ValueError('upstream artifact identity mismatch')
    if not (sha(APK) == EXPECTED == raw['actual_sha256'] == verified['apk_sha256'] == scan['apk_sha256']
            and APK.stat().st_size == origin['bytes'] == raw['bytes'] == raw_handoff['apk_bytes']):
        raise ValueError('APK bytes/hash mismatch')
    if not (raw_handoff['phase_rc'] == static_handoff['phase_rc'] == {'zip': 0, 'metadata': 0, 'dex': 0, 'elf': 0}
            and scan['four_phase_rc0'] and all(x['rc'] == 0 and x['source_guard_equal'] and
            x['apk_sha_before'] == x['apk_sha_after'] == EXPECTED for x in scan['phases'].values())):
        raise ValueError('four phase receipt mismatch')
    for phase in ('zip', 'metadata', 'dex', 'elf'):
        if read(STATIC / (phase.upper() + '-RESULT.json')) != scan['phases'][phase]:
            raise ValueError('individual phase receipt mismatch: ' + phase)
    tools = ROOT / 'harness'
    sys.path.insert(0, str(tools))
    from westlake_gap import scanner
    spec = importlib.util.spec_from_file_location('candidate_scan', STATIC / 'scan.py')
    candidate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(candidate)
    readelf = ROOT / '.nanhai-plus-runtime/bionic-oh7-aosp16/inputs-view/harness-native-hosttool-v1/bin/readelf'
    if not readelf.is_symlink() or sha(readelf) != scan['phases']['elf']['readelf_sha256']:
        raise ValueError('readelf identity mismatch')
    os.environ['PATH'] = str(readelf.parent) + os.pathsep + os.environ.get('PATH', '')
    metadata = candidate.encode(scanner.apk_metadata(APK))
    dex = candidate.encode(scanner.inventory_dex(APK))
    with zipfile.ZipFile(APK) as archive:
        names = archive.namelist()
        bad = archive.testzip()
        native = [(name, archive.read(name)) for name in names if name.startswith('lib/arm64-v8a/') and name.endswith('.so')]
    elf = candidate.encode([scanner.read_elf(data=data, label=name, abi='arm64-v8a') for name,data in native])
    if metadata != read(STATIC / 'MANIFEST.json') or dex != read(STATIC / 'DEX-INVENTORY.json') or elf != read(STATIC / 'ELF-INVENTORY.json'):
        raise ValueError('independent scanner replay mismatch')
    if bad is not None or len(names) != len(set(names)) or names.count('AndroidManifest.xml') != 1:
        raise ValueError('APK ZIP integrity mismatch')
    if len(native) != 1 or len(dex['dex_entries']) != 1 or len(elf) != 1 or not elf[0]['readelf_ok'] or not elf[0]['abi_matches_machine']:
        raise ValueError('DEX/ELF completeness mismatch')
    aapt = run([Path.home() / 'Library/Android/sdk/build-tools/36.1.0/aapt2', 'dump', 'badging', APK])
    signer = run([Path.home() / 'Library/Android/sdk/build-tools/36.1.0/apksigner', 'verify', '--verbose', '--print-certs', APK])
    actual_pkg = re.search(r"^package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'", aapt['stdout'], re.M)
    certs = re.findall(r'Signer #\d+ certificate SHA-256 digest: ([0-9a-fA-F]+)', signer['stdout'])
    if aapt['rc'] or signer['rc'] or not actual_pkg or actual_pkg.groups() != ('org.fossify.clock', '10', '1.6.0') or certs != verified['signer_cert_sha256']:
        raise ValueError('package/signature verification mismatch')
    if aapt['stdout_sha256'] != verified['aapt2']['stdout_sha256'] or signer['stdout_sha256'] != verified['apksigner']['stdout_sha256']:
        raise ValueError('tool output differs from candidate')
    prior = read(BASE / 'g339-cross-apk-exposure-cohort-v2/LOCK.json')
    prior_hit = [x['package'] for x in prior['identities'] if x['package'] == 'org.fossify.clock' or x.get('apk_sha256') == EXPECTED]
    if prior_hit:
        raise ValueError('duplicate in frozen accepted cohort')
    result = {'schema': 'fossify-clock-independent-review-v1',
              'decision': 'ACCEPT_RAW_AND_FULL_HOST_STATIC_CANDIDATE_FOR_ROOT_REVIEW_ONLY',
              'package': 'org.fossify.clock', 'version': '1.6.0', 'version_code': 10,
              'artifact_id': artifact['id'], 'upstream_registry_sha256': sha(REG),
              'source_lock_sha256': sha(LOCK), 'apk_sha256': sha(APK), 'apk_bytes': APK.stat().st_size,
              'signer_cert_sha256': certs, 'aapt2_replay_rc': aapt['rc'], 'apksigner_replay_rc': signer['rc'],
              'phase_rc': raw_handoff['phase_rc'], 'phase_replay_equal': True,
              'zip_entries': len(names), 'root_dex_entries': len(dex['dex_entries']), 'true_arm64_elf_entries': len(elf),
              'prior_g339_105_duplicate_hits': prior_hit, 'raw_handoff_sha256': sha(RAW/'HANDOFF.json'),
              'static_handoff_sha256': sha(STATIC/'HANDOFF.json'),
              'scope': 'host raw identity and complete four phase static only; root counters unchanged; no startup or device acceptance',
              'device_commands': 0, 'container_commands': 0}
    print(json.dumps(result, indent=2, sort_keys=True))

if __name__ == '__main__':
    main()
