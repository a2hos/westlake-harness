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
RAW_RECEIPT = R / I['root_acceptance']['path']
PEER_REVIEW = L / 'peer-review-v1/REVIEW.json'
ROOT_RELEASE = L / 'ROOT-RELEASE.json'

def check_release():
    if not PEER_REVIEW.is_file() or not ROOT_RELEASE.is_file():
        raise RuntimeError('INDEPENDENT_REVIEW_AND_ROOT_RELEASE_REQUIRED')
    peer = json.loads(PEER_REVIEW.read_text())
    release = json.loads(ROOT_RELEASE.read_text())
    assert peer.get('verdict') == 'GO_ONE_LOCAL_STATIC_INVENTORY'
    assert peer.get('runner_sha256') == sha(L/'run.py')
    assert peer.get('inputs_sha256') == sha(L/'INPUTS.json')
    assert peer.get('scan_phase_sha256') == sha(L/'scan_phase.py')
    assert release.get('schema') == 'nanhai.g293.vector.static.root_release.v1'
    assert release.get('decision') == 'GO_ONE_LOCAL_STATIC_INVENTORY'
    assert release.get('runner_sha256') == sha(L/'run.py')
    assert release.get('inputs_sha256') == sha(L/'INPUTS.json')
    assert release.get('common_sha256') == sha(L/'common.py')
    assert release.get('scan_phase_sha256') == sha(L/'scan_phase.py')
    assert release.get('peer_review_sha256') == sha(PEER_REVIEW)
    assert release.get('raw_receipt_sha256') == sha(RAW_RECEIPT)
    assert release.get('phase_order') == ['zip', 'metadata', 'elf', 'dex']
    assert release.get('limits_seconds') == LIMITS
    assert release.get('network_authorized') is False
    assert release.get('device_commands') == release.get('container_commands') == 0

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
    acceptance = RAW_RECEIPT
    if not acceptance.is_file() or not I['root_acceptance']['sha256']:
        raise RuntimeError('RAW_ADMISSION_PENDING: no inventory execution')
    assert sha(acceptance) == I['root_acceptance']['sha256']
    accepted = json.loads(acceptance.read_text())
    assert accepted['schema'] == I['root_acceptance']['schema']
    assert accepted['decision'] == I['root_acceptance']['decision']
    assert accepted['package'] == 'im.vector.app' and accepted['version_code'] == '40106622'
    assert accepted['version_name'] == '1.6.62' and accepted['abi'] == 'arm64-v8a'
    assert accepted['bytes'] == I['apks'][0]['bytes'] == 72422482
    assert accepted['apk_sha256'] == I['apks'][0]['sha256']
    check_release()
    assert len(I['apks']) == 1 and I['apks'][0]['registry_package_label'] == 'im.vector.app'
    for name in ('phases', 'tmp', 'apk-view'):
        (L/name).mkdir(exist_ok=False)
    (L/'apk-view/im.vector.app.apk').symlink_to(R/I['apks'][0]['path'])
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
        'all_zip_members_crc_scanned': zipfacts.get('entries_scanned')==6839 and zipfacts.get('crc_all_ok') is True,
        'manifest_unique': zipfacts.get('manifest_count')==1,
        'eight_dex_entries': len(zipfacts.get('kinds',{}).get('dex',[]))==8 and len(dex.get('dex_entries',[]))==8,
        'twenty_one_arm64_elf_entries': len(zipfacts.get('kinds',{}).get('elf',[]))==21 and sorted({x.get('abi') for x in zipfacts.get('kinds',{}).get('elf',[])})==['arm64-v8a'],
        'dex_identity': {x.get('name'):(x.get('sha256'),x.get('bytes')) for x in dex.get('dex_entries',[])}=={x['name']:(x['sha256'],x['bytes']) for x in zipfacts.get('kinds',{}).get('dex',[])},
        'true_elf_identity': {x.get('archive_entry'):(x.get('sha256'),x.get('bytes')) for x in elf}=={x['name']:(x['sha256'],x['bytes']) for x in zipfacts.get('kinds',{}).get('elf',[])},
        'true_elf_valid': len(elf)==21 and all(x.get('readelf_ok') is True and x.get('abi_matches_machine') is True and not x.get('error') and not x.get('registration_scan_error') for x in elf),
        'native_unclassified_zero': not zipfacts.get('kinds',{}).get('other_so') and not zipfacts.get('kinds',{}).get('zip_in_so'),
    }
    result = {'schema':'nanhai.g293.vector.static_inventory_result.v1','status':'TERMINAL_CANDIDATE_ONLY_REQUIRES_INDEPENDENT_AND_ROOT_REVIEW','at':now(),'elapsed_seconds':time.monotonic()-start,'rc':0 if all(checks.values()) and time.monotonic()-start<LIMITS['outer_seconds'] else 2,'checks':checks,'rows':rows,'zip_entries':zipfacts.get('entries_scanned'),'dex_entries':len(dex.get('dex_entries',[])),'true_elf_entries':len(elf),'true_arm64_elf_entries':sum(x.get('abi')=='arm64-v8a' for x in elf),'true_non_arm64_elf_entries':sum(x.get('abi')!='arm64-v8a' for x in elf),'zip_in_so_entries':len(zipfacts.get('kinds',{}).get('zip_in_so',[])),'source_APK_venv_tool_pre_post_equal':before==after,'startup_verified':False,'blackbox_qualified':False,'device_commands':0,'container_commands':0,'authoritative_count_changed':False}
    put(L/'RESULT.json',result)
    print(json.dumps({k:v for k,v in result.items() if k!='rows'}),flush=True)
    return result['rc']

if __name__=='__main__':
    try: sys.exit(main())
    except Exception as e:
        print(repr(e),file=sys.stderr)
        if (L/'STARTED.json').exists() and not (L/'FATAL.json').exists():put(L/'FATAL.json',{'at':now(),'error':repr(e),'rc':2})
        sys.exit(2)
