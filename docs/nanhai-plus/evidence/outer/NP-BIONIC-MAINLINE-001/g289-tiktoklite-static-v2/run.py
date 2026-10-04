import json
import os
import pathlib
import signal
import subprocess
import sys
import time
import zipfile

from common import I, L, P, Q, R, guard, now, put, sha

LIMITS = {'outer_seconds': 1350, 'zip_seconds': 120, 'metadata_seconds': 180, 'elf_seconds': 600, 'dex_seconds': 600, 'parallel': 1, 'retries': 0}
ROOT_RECEIPT = 'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g290-tiktok-lite-go-raw-supplement-v1/ROOT-RAW-INTAKE.json'
ROOT_SHA256 = 'ffd25a75b488981468cafad6f18ebf80a6e67e72e55e1df1aa1a8313281cc590'
ROOT_SCHEMA = 'nanhai-g290-tiktok-lite-go-root-raw-intake-v1'
ROOT_DECISION = 'ACCEPT_ONE_SEPARATE_OFFICIAL_CHANNEL_OBSERVED_SUPPLEMENTAL_RAW_APK'
APK_SHA256 = '37b528ba36ebcb1e6d4f642d144c5446352b5d19abebea7504e3654b9882b9f0'
ROOT_STATIC_RELEASE_SHA256 = None  # bind a separate reviewed release in a future generation

def check_root_decision(accepted):
    assert accepted.get('schema') == ROOT_SCHEMA and accepted.get('decision') == ROOT_DECISION
    assert accepted.get('package') == 'com.tiktok.lite.go'
    assert accepted.get('version_code') == 360961 and accepted.get('version_name') == '36.9.61'
    payload = accepted.get('payload') or {}
    assert payload.get('path') == I['apks'][0]['path']
    assert payload.get('bytes') == I['apks'][0]['bytes'] == 48413684
    assert payload.get('sha256') == I['apks'][0]['sha256'] == APK_SHA256
    assert payload.get('native_abis') == I['inventory_expectations']['native_abis']

def run_phase(phase, seconds):
    d = L / 'phases' / phase
    d.mkdir()
    t = time.monotonic()
    env = {k: v for k, v in os.environ.items() if not k.startswith(('PYTHON', 'PIP_')) and 'proxy' not in k.lower()}
    env.update(PATH=str(P(Q['alias']).parent)+':'+str(P(I['venv'])/'bin')+':/usr/bin:/bin:/usr/sbin:/sbin', TMPDIR=str((L/'tmp').resolve()), LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')
    argv = [str(P(I['venv'])/'bin/python3'), '-I', '-B', str(L/'scan_phase.py'), phase]
    row = {'phase': phase, 'argv': argv, 'cwd': str(R), 'environment': {k: env[k] for k in ('PATH', 'TMPDIR', 'LC_ALL', 'PYTHONDONTWRITEBYTECODE')}, 'started_at': now(), 'timeout_seconds': seconds, 'network_authorized': False}
    with (d/'stdout.raw').open('xb') as stdout, (d/'stderr.raw').open('xb') as stderr:
        proc = subprocess.Popen(argv, cwd=R, env=env, stdout=stdout, stderr=stderr, start_new_session=True)
        row['pid'] = proc.pid
        try:
            row['rc'] = proc.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            row['timed_out'] = True
            os.killpg(proc.pid, signal.SIGKILL)
            row['rc'] = proc.wait()
    row.update(finished_at=now(), elapsed_seconds=time.monotonic()-t, stdout_sha256=sha(d/'stdout.raw'), stderr_sha256=sha(d/'stderr.raw'))
    put(d/'COMMAND.json', row)
    return row

def main():
    if sys.argv[1:] != ['--execute']:
        raise RuntimeError('PREPARED_ONLY: explicit --execute required')
    start = time.monotonic()
    acceptance = R/ROOT_RECEIPT
    if not acceptance.is_file():
        raise RuntimeError('ROOT_RAW_RECEIPT_MISSING: no inventory execution')
    assert I['root_acceptance'] == {'path':ROOT_RECEIPT,'sha256':ROOT_SHA256,'decision':ROOT_DECISION,'schema':ROOT_SCHEMA}
    assert sha(acceptance) == ROOT_SHA256
    accepted = json.loads(acceptance.read_text())
    check_root_decision(accepted)
    assert len(I['apks']) == 1 and I['apks'][0]['registry_package_label'] == 'com.tiktok.lite.go'
    if ROOT_STATIC_RELEASE_SHA256 is None:
        raise RuntimeError('STATIC_SCAN_RELEASE_PENDING: prepared candidate only')
    for name in ('phases', 'tmp', 'apk-view'):
        (L/name).mkdir(exist_ok=False)
    (L/'apk-view/com.tiktok.lite.go.apk').symlink_to(R/I['apks'][0]['path'])
    before = guard(full=True)
    put(L/'SOURCE-BEFORE.json', before)
    put(L/'STARTED.json', {'at': now(), 'input_sha256': sha(L/'INPUTS.json'), 'acceptance_sha256': sha(acceptance), 'limits': LIMITS, 'source_before_sha256': sha(L/'SOURCE-BEFORE.json'), 'attempts': 1})
    rows = []
    for phase in ('zip', 'metadata', 'elf', 'dex'):
        if time.monotonic()-start >= LIMITS['outer_seconds']:
            break
        row = run_phase(phase, min(LIMITS[phase+'_seconds'], max(1, int(LIMITS['outer_seconds']-(time.monotonic()-start)))))
        rows.append(row)
        if row['rc'] != 0 or row.get('timed_out'):
            break
    after = guard(full=True)
    put(L/'SOURCE-AFTER.json', after)
    outcomes = {p: json.loads((L/'phases'/p/'RESULT.json').read_text()) for p in ('zip','metadata','elf','dex') if (L/'phases'/p/'RESULT.json').exists()}
    zipfacts = json.loads((L/'phases/zip/ZIP-FACTS.json').read_text()) if (L/'phases/zip/ZIP-FACTS.json').exists() else {}
    elf = json.loads((L/'phases/elf/ELF-INVENTORY.json').read_text()) if (L/'phases/elf/ELF-INVENTORY.json').exists() else []
    dex = json.loads((L/'phases/dex/DEX-INVENTORY.json').read_text()) if (L/'phases/dex/DEX-INVENTORY.json').exists() else {}
    checks = {
        'all_four_phases_terminal': len(rows)==4 and all(x['rc']==0 and not x.get('timed_out') for x in rows),
        'all_postguards': len(outcomes)==4 and all(x.get('source_apk_tool_postguard') is True for x in outcomes.values()),
        'full_source_apk_venv_tool_guard_equal': before==after,
        'all_zip_members_crc_scanned': zipfacts.get('entries_scanned')==I['inventory_expectations']['zip_entries'] and zipfacts.get('crc_all_ok') is True,
        'manifest_unique': zipfacts.get('manifest_count')==1,
        'dex_identity': {x.get('name'):(x.get('sha256'),x.get('bytes')) for x in dex.get('dex_entries',[])}=={x['name']:(x['sha256'],x['bytes']) for x in zipfacts.get('kinds',{}).get('dex',[])},
        'true_elf_identity': {x.get('archive_entry'):(x.get('sha256'),x.get('bytes')) for x in elf}=={x['name']:(x['sha256'],x['bytes']) for x in zipfacts.get('kinds',{}).get('elf',[])},
        'true_elf_valid': sum(x.get('archive_entry') in {e['name'] for e in zipfacts.get('kinds',{}).get('elf',[])} and x.get('readelf_ok') is True and x.get('abi_matches_machine') is True and not x.get('error') and not x.get('registration_scan_error') for x in elf)==I['inventory_expectations']['true_elf_entries'],
        'packed_so_opaque': len(zipfacts.get('kinds',{}).get('packed_so',[]))==I['inventory_expectations']['packed_non_elf_so_entries'] and not ({x.get('archive_entry') for x in elf} & {e['name'] for e in zipfacts.get('kinds',{}).get('packed_so',[])}),
        'native_unclassified_zero': not zipfacts.get('kinds',{}).get('other_so'),
        'mixed_abis_recorded': sorted({x.get('abi') for x in zipfacts.get('kinds',{}).get('elf',[])+zipfacts.get('kinds',{}).get('packed_so',[])})==I['inventory_expectations']['native_abis'],
    }
    true_names = {x['name'] for x in zipfacts.get('kinds',{}).get('elf',[])}
    result = {'schema':'g289-tiktoklite-static-inventory-candidate-v2','status':'TERMINAL_CANDIDATE_ONLY_REQUIRES_INDEPENDENT_AND_ROOT_REVIEW','at':now(),'elapsed_seconds':time.monotonic()-start,'rc':0 if all(checks.values()) and time.monotonic()-start<LIMITS['outer_seconds'] else 2,'checks':checks,'rows':rows,'zip_entries':zipfacts.get('entries_scanned'),'dex_entries':len(dex.get('dex_entries',[])),'true_elf_entries':len(true_names),'true_arm64_elf_entries':sum(x.get('abi')=='arm64-v8a' for x in zipfacts.get('kinds',{}).get('elf',[])),'true_arm32_elf_entries':sum(x.get('abi')=='armeabi-v7a' for x in zipfacts.get('kinds',{}).get('elf',[])),'opaque_packed_so_entries':len(zipfacts.get('kinds',{}).get('packed_so',[])),'native_abis':I['inventory_expectations']['native_abis'],'abi_claim':'mixed ARM64 and ARM32 libraries; ARM64-compatible structural candidate, not ARM64-only and no loadability claim','source_APK_venv_tool_pre_post_equal':before==after,'startup_verified':False,'blackbox_qualified':False,'device_commands':0,'authoritative_count_changed':False}
    put(L/'RESULT.json',result)
    print(json.dumps({k:v for k,v in result.items() if k!='rows'}),flush=True)
    return result['rc']

if __name__=='__main__':
    try: sys.exit(main())
    except Exception as e:
        print(repr(e),file=sys.stderr)
        if (L/'STARTED.json').exists() and not (L/'FATAL.json').exists():put(L/'FATAL.json',{'at':now(),'error':repr(e),'rc':2})
        sys.exit(2)
