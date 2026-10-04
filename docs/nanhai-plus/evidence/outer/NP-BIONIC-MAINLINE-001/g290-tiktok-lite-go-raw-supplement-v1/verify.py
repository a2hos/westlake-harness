#!/usr/bin/env python3
"""Read-only, exact-byte G290 supplemental raw identity verification; no APK GET."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
from datetime import datetime, timezone
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]
BASE = HERE.parent
PACKAGE = 'com.tiktok.lite.go'
APK_SHA = '37b528ba36ebcb1e6d4f642d144c5446352b5d19abebea7504e3654b9882b9f0'
APK_BYTES = 48413684
CERT_SHA = 'd7811ec4166fea6cc720ba66699dc84b584ac9e6986613a76d4e43d8cbe32b27'
REGISTRY_SHA = '289dcdb499d5ff37e58a8e7d4fbd3d30e3fe9f77d4e7e8ba7139c927c890c1eb'
G288_RESULT_SHA = '260d17bdd4b3646c467625b16e7e4b17ff46b0bbaf24141dcb73dcf759e5e14b'
G288_ROOT_SHA = '6f987810e57527ebaab9b9a835a36f9943cdb167276fc6969e5aab15946f0e7b'
SCOUT_SHA = 'f372ce4703b71801ba07b6864ca7f1112ef144d2f63cbfe7d8a318669a74d8dc'
TOOL_SHA = {'aapt2':'3c5920804724dfe9a43e0dbf1f5b5dcbf08c4a2e829bebdaa04d38bfe7d7ada4',
            'apksigner':'9469c60e5e40fc5c44a2f2338509cb6600cdf065e9b50f9fa3ca6c5be5bae6a9',
            'java':'cd158e1a5328ff42b687b7c2f5c61c7c3be3cfee7f18226ee903169e97336158'}

def sha_file(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1048576), b''):
            h.update(block)
    return h.hexdigest()

def check(ok, why):
    if not ok:
        raise ValueError(why)

def field(line, name):
    m = re.search(r"\b" + re.escape(name) + r"='([^']+)'", line)
    check(m is not None, 'missing ' + name)
    return m.group(1)

def run_tool(name, argv, timeout):
    start, tick = datetime.now(timezone.utc).isoformat(), time.monotonic()
    p = subprocess.run(argv, capture_output=True, timeout=timeout, check=False,
                       env={'PATH':'/usr/bin:/bin','LC_ALL':'C','TZ':'UTC','TMPDIR':str(HERE)})
    (HERE / (name + '.stdout.raw')).write_bytes(p.stdout)
    (HERE / (name + '.stderr.raw')).write_bytes(p.stderr)
    return {'argv':argv,'started_utc':start,'ended_utc':datetime.now(timezone.utc).isoformat(),
            'elapsed_seconds':round(time.monotonic()-tick,3),'rc':p.returncode,
            'stdout_sha256':hashlib.sha256(p.stdout).hexdigest(),'stdout_bytes':len(p.stdout),
            'stderr_sha256':hashlib.sha256(p.stderr).hexdigest(),'stderr_bytes':len(p.stderr)}

def evaluate():
    spec = importlib.util.spec_from_file_location('nanhai_plus_env', ROOT / 'scripts/nanhai_plus_env.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    env, audit = module.load_environment(ROOT / 'local_env.md')
    check(audit['config_sha256']=='5ce3a58541ef1711890aad8348c3a31a03203f584fa50f1f5c0cb4fd88b49718', 'environment drift')
    apk = Path(env['NANHAI_STAGING_ROOT']) / 'g288-tiktoklite-hyphen-official-raw-candidate-v2/tiktok-lite-hyphen-360961.apk'
    check(apk.parent == Path(env['NANHAI_STAGING_ROOT']) / 'g288-tiktoklite-hyphen-official-raw-candidate-v2', 'staging binding drift')
    receipt_paths = {
        'g288_result': (BASE/'g288-tiktoklite-hyphen-official-raw-candidate-v2/RESULT.json',G288_RESULT_SHA),
        'g288_root_terminal': (BASE/'g288-tiktoklite-hyphen-official-raw-candidate-v2/ROOT-TERMINAL-ACCEPTANCE.json',G288_ROOT_SHA),
        'source_scout': (BASE/'g288-tiktok-lite-go-source-scout-v1/RESULT.json',SCOUT_SHA),
        'registry': (BASE/'upstream-apk-registry-v1/REGISTRY.json',REGISTRY_SHA)}
    for name,(path,want) in receipt_paths.items(): check(sha_file(path)==want, name+' receipt SHA drift')
    g288=json.loads(receipt_paths['g288_result'][0].read_text())
    root=json.loads(receipt_paths['g288_root_terminal'][0].read_text())
    scout=json.loads(receipt_paths['source_scout'][0].read_text())
    registry=json.loads(receipt_paths['registry'][0].read_text())
    check(g288['status']=='TERMINAL_FAILED' and g288['error']=='package mismatch' and
          g288['raw_accepted'] is False and g288['canonical_delta']==0, 'G288 failure classification drift')
    check(root['decision']=='ACCEPT_TERMINAL_FAILURE_ONLY_NEW_PACKAGE_REVIEW_SEPARATE' and
          root['count_delta']['accepted_raw']==0, 'G288 root terminal drift')
    check(scout['product']['actual_package']==PACKAGE and
          scout['official_channel']['actual_apk_sha256']==APK_SHA, 'source scout identity drift')
    check(not any(x.get('package')==PACKAGE for x in registry['records']) and
          not any(x.get('package')==PACKAGE for x in registry['apps']), 'frozen registry duplicate')
    check(not any(x.get('package')=='com.zhiliaoapp.musically.go' for x in registry['records']),
          'other Lite package registry surprise')
    fd=os.open(apk,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        before=os.fstat(fd)
        check(stat.S_ISREG(before.st_mode) and before.st_size==APK_BYTES, 'APK type/size drift')
        h=hashlib.sha256()
        while True:
            b=os.read(fd,1048576)
            if not b:break
            h.update(b)
        check(h.hexdigest()==APK_SHA, 'APK SHA drift')
        os.lseek(fd,0,os.SEEK_SET)
        with os.fdopen(os.dup(fd),'rb') as stream, zipfile.ZipFile(stream) as z:
            names=z.namelist()
            zip_row={'entries':len(names),'bad_entry':z.testzip(),
                     'manifest_count':names.count('AndroidManifest.xml'),
                     'lib_abis':sorted({m.group(1) for n in names if
                                        (m:=re.match(r'lib/([^/]+)/[^/]+\.so$',n))})}
        check(zip_row['bad_entry'] is None and zip_row['manifest_count']==1 and
              zip_row['lib_abis']==['arm64-v8a','armeabi-v7a'], 'ZIP/ABI drift')
        after=os.fstat(fd)
        check((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns,before.st_mode)==
              (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns,after.st_mode),
              'APK inode changed during read')
    finally:os.close(fd)
    pool=Path(env['NANHAI_SOURCE_POOL_ROOT'])
    tools={'aapt2':pool/'AOSP-16.0.0_r4/prebuilts/sdk-r4/tools/darwin/bin/aapt2',
           'apksigner':pool/'AOSP-16.0.0_r4/prebuilts/sdk-r4/tools/darwin/lib/apksigner.jar',
           'java':Path('/Applications/DevEco-Studio.app/Contents/jbr/Contents/Home/bin/java')}
    for name,path in tools.items():check(sha_file(path)==TOOL_SHA[name], 'tool SHA drift: '+name)
    commands={}
    commands['badging']=run_tool('badging',[str(tools['aapt2']),'dump','badging',str(apk)],90)
    check(commands['badging']['rc']==0, 'aapt2 failed')
    commands['signature']=run_tool('signature',[str(tools['java']),'-XX:-UsePerfData','-Xmx512m',
        '-Djava.awt.headless=true','-Djava.io.tmpdir='+str(HERE),'-jar',str(tools['apksigner']),
        'verify','--verbose','--print-certs',str(apk)],90)
    check(commands['signature']['rc']==0, 'apksigner failed')
    badging=(HERE/'badging.stdout.raw').read_text(errors='replace')
    signature=(HERE/'signature.stdout.raw').read_text(errors='replace')
    package_line=next((x for x in badging.splitlines() if x.startswith('package: ')),None)
    min_line=next((x for x in badging.splitlines() if x.startswith('minSdkVersion:')),None)
    target_line=next((x for x in badging.splitlines() if x.startswith('targetSdkVersion:')),None)
    native_line=next((x for x in badging.splitlines() if x.startswith('native-code:')),None)
    check(all([package_line,min_line,target_line,native_line]), 'badging identity incomplete')
    manifest={'package':field(package_line,'name'),'version_code':field(package_line,'versionCode'),
              'version_name':field(package_line,'versionName'),
              'min_sdk':re.search(r"'([^']+)'",min_line).group(1),
              'target_sdk':re.search(r"'([^']+)'",target_line).group(1),
              'native_code':native_line}
    check(manifest['package']==PACKAGE and manifest['version_code']=='360961' and
          manifest['version_name']=='36.9.61' and manifest['min_sdk']=='21' and
          manifest['target_sdk']=='34' and "'arm64-v8a'" in native_line and
          "'armeabi-v7a'" in native_line, 'manifest identity drift')
    cert=re.search(r'(?im)^Signer #1 certificate SHA-256 digest:\s*([0-9a-f]{64})\s*$',signature)
    check(cert is not None and cert.group(1).lower()==CERT_SHA and
          'Number of signers: 1' in signature and
          'Verified using v2 scheme (APK Signature Scheme v2): true' in signature and
          'Verified using v3 scheme (APK Signature Scheme v3): true' in signature,
          'signature identity drift')
    check(sha_file(apk)==APK_SHA, 'APK postguard drift')
    for name,path in tools.items():check(sha_file(path)==TOOL_SHA[name], 'tool postguard drift: '+name)
    return {'schema':'g290-tiktok-lite-go-exact-byte-readonly-verification-v1',
            'status':'EXACT_BYTE_RAW_SUPPLEMENT_CANDIDATE_READY_FOR_PEER',
            'apk':{'path':str(apk),'bytes':APK_BYTES,'sha256':APK_SHA,'sha256_role':'observed retained bytes; no publisher digest'},
            'g288_terminal_status':'TERMINAL_FAILED','g288_root_raw_delta':0,
            'source_scout_sha256':SCOUT_SHA,'registry_sha256':REGISTRY_SHA,
            'registry_duplicate':False,'package_count_delta':0,'candidate_raw_artifact_delta':0,
            'zip':zip_row,'manifest':manifest,
            'signature':{'verified':True,'observed_certificate_sha256':CERT_SHA,'publisher_certificate_anchor':None},
            'commands':commands,'tools_sha256':TOOL_SHA,
            'network_requests':0,'device_commands':0,'container_commands':0,'canonical_edits':0,
            'blackbox_qualified':False,'startup_proven':False,'static_complete_claim':False}

def main():
    try:result=evaluate()
    except BaseException as e:
        result={'schema':'g290-tiktok-lite-go-exact-byte-readonly-verification-v1',
                'status':'READONLY_VERIFICATION_FAILED_NO_ADMISSION',
                'error_type':type(e).__name__,'error':str(e)[:500],
                'network_requests':0,'device_commands':0,'container_commands':0,
                'canonical_edits':0,'candidate_raw_artifact_delta':0}
    result['ended_utc']=datetime.now(timezone.utc).isoformat()
    out=HERE/'VERIFICATION.json'
    with out.open('x') as stream:json.dump(result,stream,indent=2);stream.write('\n')
    print(json.dumps({'status':result['status'],'receipt':str(out)}))
    return 0 if result['status']=='EXACT_BYTE_RAW_SUPPLEMENT_CANDIDATE_READY_FOR_PEER' else 3

if __name__=='__main__':raise SystemExit(main())
