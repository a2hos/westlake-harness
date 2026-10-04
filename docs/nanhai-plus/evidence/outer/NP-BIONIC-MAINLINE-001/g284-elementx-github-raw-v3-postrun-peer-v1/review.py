#!/usr/bin/env python3
"""Read-only independent post-run review; never issues a network request."""
import datetime,hashlib,json,os,pathlib,re,subprocess,sys,zipfile
R=pathlib.Path(os.environ['NANHAI_PROJECT_ROOT'])
B=R/'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001'
C=B/'g284-elementx-github-raw-candidate-v3'
P=pathlib.Path(__file__).parent
APK=pathlib.Path(os.environ['NANHAI_STAGING_ROOT'])/'g284-elementx-github-raw-candidate-v3/elementx-v26.09.1-arm64.apk'
EXPECTED_SHA='ceb076564298cd0aef4688ad79058b55638d196b9beb5ac47ab421d757335bf3'
EXPECTED_BYTES=117664325
SCRIPT_SHA='830398248b9b4fa7ae17608018d2855177835dd903cfd62bc3fce49bdc128243'
checks=[]
def check(name,ok,detail=None):checks.append({'id':name,'pass':bool(ok),'detail':detail})
def sha(path):
 h=hashlib.sha256()
 with pathlib.Path(path).open('rb') as f:
  for part in iter(lambda:f.read(1048576),b''):h.update(part)
 return h.hexdigest()
def read(path):return json.loads(pathlib.Path(path).read_text())
start=read(C/'START.json');result=read(C/'RESULT.json');release=read(C/'ROOT-RELEASE.json')
check('script_same_as_root_release',sha(C/'run.py')==start['script_sha256']==release['runner_sha256']==SCRIPT_SHA)
check('start_to_result',sha(C/'START.json')==result['start_sha256'] and start['generation']==result['generation'])
check('start_before_terminal',start['at_utc']<result['ended_utc'] and result['status']=='RAW_CANDIDATE_STATIC_PASS')
check('candidate_only',result['candidate_only'] is True and result['raw_accepted'] is False and result['canonical_delta']==result['device_commands']==result['container_commands']==0)
check('root_release_scope',release['decision']=='AUTHORIZE_ONE_BOUNDED_OFFICIAL_APK_GET_AND_LOCAL_STATIC_CHECK_ONLY' and release['expected_sha256']==EXPECTED_SHA and release['expected_bytes']==EXPECTED_BYTES)
check('environment',result['environment']['config_sha256']=='5ce3a58541ef1711890aad8348c3a31a03203f584fa50f1f5c0cb4fd88b49718')
registry=B/'upstream-apk-registry-v1/REGISTRY.json'
record=[x for x in read(registry)['records'] if x['id']=='r-52d5e188c88dfba15c98']
check('registry_sha',sha(registry)==result['registry']['sha256']=='289dcdb499d5ff37e58a8e7d4fbd3d30e3fe9f77d4e7e8ba7139c927c890c1eb')
check('registry_record',len(record)==1 and record[0]['package']=='io.element.android.x' and record[0]['fields']['artifact_sha256']['value']==EXPECTED_SHA and record[0]['fields']['bytes']['value']==EXPECTED_BYTES)
api=read(C/'api.body.raw');assets=[a for a in api['assets'] if a['id']==539529327]
check('api_body',sha(C/'api.body.raw')==result['api_body']['sha256'] and (C/'api.body.raw').stat().st_size==result['api_body']['bytes']<=1048576)
check('api_asset',api['tag_name']=='v26.09.1' and len(assets)==1 and all(assets[0][k]==v for k,v in result['api_asset'].items()))
expected_names=['api','download','badging','signature'];commands=result['commands']
check('command_set_order',[x['name'] for x in commands]==expected_names)
for c in commands:
 name=c['name'];out=C/(name+'.stdout.raw');err=C/(name+'.stderr.raw')
 check('command_rc:'+name,c['rc']==0 and c['timed_out'] is False)
 check('streams:'+name,out.stat().st_size==c['stdout_bytes'] and err.stat().st_size==c['stderr_bytes'] and sha(out)==c['stdout_sha256'] and sha(err)==c['stderr_sha256'])
check('api_argv',commands[0]['argv'][0]=='/usr/bin/curl' and '--max-filesize' in commands[0]['argv'] and '1048576' in commands[0]['argv'])
get=commands[1]['argv'];check('one_bounded_get',get[0]=='/usr/bin/curl' and get.count('https://github.com/element-hq/element-x-android/releases/download/v26.09.1/app-fdroid-arm64-v8a-release-signed.apk')==1 and get[get.index('--max-filesize')+1]==str(EXPECTED_BYTES) and get[get.index('--retry')+1]=='0' and get[get.index('--max-time')+1]=='300')
check('transfer',result['transfer']==(C/'download.stdout.raw').read_text()=='http=200 tls=0 bytes=117664325 redirects=1')
check('apk_bytes_sha',APK.is_file() and APK.stat().st_size==EXPECTED_BYTES and sha(APK)==EXPECTED_SHA==result['part_sha256']==result['apk_sha256_after'])
check('part_renamed',not APK.with_suffix(APK.suffix+'.part').exists())
with zipfile.ZipFile(APK) as z:
 names=z.namelist();zip_data={'entries':len(names),'bad_entry':z.testzip(),'manifest_count':names.count('AndroidManifest.xml'),'lib_abis':sorted({m.group(1) for n in names if (m:=re.match(r'lib/([^/]+)/[^/]+\.so$',n))})}
check('zip_crc_manifest_abi',zip_data==result['zip'] and zip_data['bad_entry'] is None and zip_data['lib_abis']==['arm64-v8a'])
badging=(C/'badging.stdout.raw').read_text();signature=(C/'signature.stdout.raw').read_text()
check('manifest_identity',result['package_line'] in badging and "name='io.element.android.x'" in result['package_line'] and "versionCode='202609012'" in result['package_line'] and "versionName='26.09.1'" in result['package_line'])
check('native_abi',result['native_code_line'] in badging and result['native_code_line']=="native-code: 'arm64-v8a'")
check('signature_output',signature.startswith('Verifies\n') and 'Number of signers: 1' in signature and 'Verified using v2 scheme (APK Signature Scheme v2): true' in signature and 'Verified using v3 scheme (APK Signature Scheme v3): true' in signature and all(line in signature for line in result['signature_lines']))
source=pathlib.Path(os.environ['NANHAI_SOURCE_POOL_ROOT'])
tools={'curl':pathlib.Path(os.environ['NANHAI_CURL']),'aapt2':source/'AOSP-16.0.0_r4/prebuilts/sdk-r4/tools/darwin/bin/aapt2','apksigner':source/'AOSP-16.0.0_r4/prebuilts/sdk-r4/tools/darwin/lib/apksigner.jar','java':pathlib.Path('/Applications/DevEco-Studio.app/Contents/jbr/Contents/Home/bin/java')}
check('tool_hashes_before_after',result['tools_before']==result['tools_after']=={name:sha(path) for name,path in tools.items()})
check('no_device_container_commands',all(x['argv'][0] in {str(q) for q in tools.values()} for x in commands) and result['device_commands']==result['container_commands']==0)
review={'schema':'nanhai.g284.elementx_github_raw.postrun_peer.v1','reviewed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status':'ACCEPT_RAW_PAYLOAD_IDENTITY_ONLY' if all(x['pass'] for x in checks) else 'REJECT_RAW_PAYLOAD_IDENTITY','checks':checks,'passed':sum(x['pass'] for x in checks),'failed':[x['id'] for x in checks if not x['pass']],'start_sha256':sha(C/'START.json'),'result_sha256':sha(C/'RESULT.json'),'apk_path':str(APK.relative_to(R)),'apk_bytes':APK.stat().st_size,'apk_sha256':sha(APK),'zip':zip_data,'signer_cert_sha256':'6a2fdc3148049ce0d5c6e85010723b83fb207d20c7477f5c22ac53c877e92d47','raw_payload_delta_candidate':1 if all(x['pass'] for x in checks) else 0,'startup_delta':0,'blackbox_qualification_delta':0,'device_commands':0,'container_commands':0,'scope':'exact official GitHub raw APK bytes and local static checks only; root controls canonical acceptance'}
with (P/'REVIEW.json').open('x') as f:json.dump(review,f,indent=2,ensure_ascii=False);f.write('\n')
print(json.dumps({'status':review['status'],'passed':review['passed'],'failed':review['failed'],'apk_sha256':review['apk_sha256']}))
sys.exit(0 if not review['failed'] else 2)
