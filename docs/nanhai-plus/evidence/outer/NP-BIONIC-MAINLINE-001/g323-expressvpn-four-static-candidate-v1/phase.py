#!/usr/bin/env python3
"""Bounded host-only phases for one exact G322 ExpressVPN APK."""
import hashlib, json, os, pathlib, struct, sys, traceback, zipfile

ROOT=pathlib.Path(os.environ['NANHAI_PROJECT_ROOT'])
HERE=pathlib.Path(__file__).parent
APK=ROOT/'.nanhai-plus-runtime/bionic-oh7-aosp16/staging/g322-expressvpn-official-v1/ExpressVPN.apk'
SCANNER=ROOT/'harness/westlake_gap/scanner.py'
CENSUS=HERE/'CENSUS.json'
RAW=ROOT/'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g322-expressvpn-official-scout-v1/root-raw-admission-v1/ROOT-RAW-ADMISSION.json'
EXPECTED={'apk':'97f1d5e4c6441b241e0643e2ec640bb4dcd9935fb887ea5c373cc0087e43fcb8','scanner':'5ac937a7dcc425544dd4051368bfab6a3cdc1808024a505c20dfb09f2e187e3a','raw':'f6862686bd6e2e93a2625c9350a4de71c8e56047c5b077311c9809df04124364','census':'117c87e51dbf01f665528ec79bf887f0e0fcc7f2ec8c7e65f0a4110bef031f39'}
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def guard():
 paths={'apk':APK,'scanner':SCANNER,'raw':RAW,'census':CENSUS}
 d={k:sha(v) for k,v in paths.items()}
 if d!=EXPECTED:raise RuntimeError('source drift '+repr(d))
 if not json.loads(RAW.read_text())['decision'].startswith('ACCEPT'):raise RuntimeError('raw root admission drift')
 return d
def put(p,obj):
 with p.open('x') as f:json.dump(obj,f,sort_keys=True,ensure_ascii=False,indent=2);f.write('\n')
def encode(v):
 if isinstance(v,(set,frozenset)):return sorted((encode(x) for x in v),key=str)
 if isinstance(v,dict):
  if all(isinstance(k,str) for k in v):return {k:encode(x) for k,x in v.items()}
  return [{'key':encode(k),'value':encode(x)} for k,x in sorted(v.items(),key=lambda x:str(x[0]))]
 if isinstance(v,(list,tuple)):return [encode(x) for x in v]
 return v
def main():
 if len(sys.argv)!=2 or sys.argv[1] not in ('zip','metadata','elf','dex'):raise SystemExit(2)
 phase=sys.argv[1]; out=HERE/'phases'/phase; out.mkdir(parents=True,exist_ok=False)
 before=guard(); census=json.loads(CENSUS.read_text()); sys.path.insert(0,str(ROOT/'harness'))
 from westlake_gap import scanner
 result={'phase':phase,'rc':2,'source_before':before,'device_commands':0,'container_commands':0,'network_commands':0,'ssh_commands':0}
 try:
  if phase=='zip':
   with zipfile.ZipFile(APK) as z:
    names=z.namelist();bad=z.testzip();assert bad is None and len(names)==len(set(names))==3642
    assert {n for n in names if n.endswith('.dex')}=={x['name'] for x in census['dex']}
    assert {n for n in names if n.startswith('lib/') and n.endswith('.so')}=={x['name'] for x in census['so']}
    assert census['nested_archives']==[] and census['counts']['embedded_dex']==0
    put(out/'ZIP-FACTS.json',{'entries_scanned':len(names),'crc_all_ok':True,'manifest_count':names.count('AndroidManifest.xml'),'root_dex':census['counts']['root_dex'],'embedded_dex':census['counts']['embedded_dex'],'nested_archives':[{'path':x['path'],'sha256':x['sha256'],'members':x['members']} for x in census['nested_archives']],'true_arm64_elf':census['counts']['true_arm64_elf'],'non_elf_so':[x for x in census['so'] if x['kind']!='elf']})
  elif phase=='metadata':
   x=scanner.apk_metadata(APK);put(out/'MANIFEST.json',x)
   assert x.get('manifest_available') is True and x.get('package')=='com.expressvpn.vpn' and x.get('version_name')=='12.80.1' and str(x.get('version_code'))=='12800140'
   assert x.get('sha256')==EXPECTED['apk'] and x.get('bytes')==139584355 and str(x.get('target_sdk'))=='37'
  elif phase=='elf':
   records=[]
   with zipfile.ZipFile(APK) as z:
    for row in census['so']:
     if row['kind']!='elf':continue
     abi=row['name'].split('/')[1]
     expected_abi_header={'arm64-v8a':(2,183),'armeabi':(1,40),'armeabi-v7a':(1,40),'mips':(1,8),'mips64':(2,8),'x86':(1,3),'x86_64':(2,62)}
     assert abi in expected_abi_header and (row['class'],row['machine'])==expected_abi_header[abi]
     blob=z.read(row['name'])
     record=scanner.read_elf(data=blob,label=row['name'],abi=row['name'].split('/')[1])
     record['archive_entry']=row['name'];record['split_apk']=None
     records.append(record)
   put(out/'ELF-INVENTORY.json',records)
   assert len(records)==91 and sum(x['abi']=='arm64-v8a' for x in records)==22 and all(x.get('readelf_ok') is True for x in records)
   assert all(x.get('abi_matches_machine') is True and not x.get('registration_scan_error') for x in records if x['abi']=='arm64-v8a')
   put(out/'ELF-CLASSIFICATION.json',{'arm64_target_records':22,'other_abi_records':69,'non_elf_so':0,'scanner_abi_mismatches':[x['archive_entry'] for x in records if not x.get('abi_matches_machine')],'scanner_unknown_machine_abi':[x['archive_entry'] for x in records if not x.get('machine_abi')],'registration_scan_errors':[{'name':x['archive_entry'],'error':x['registration_scan_error']} for x in records if x.get('registration_scan_error')]})
  else:
   inv=scanner.inventory_dex(APK);put(out/'DEX-INVENTORY.json',encode(vars(inv)))
   assert {x['name'] for x in inv.dex_entries}=={x['name'] for x in census['dex']} and len(inv.dex_entries)==3
  result['rc']=0
 except BaseException as e:
  result.update(error=repr(e),traceback=traceback.format_exc())
 finally:
  try:result['source_after']=guard();result['source_guard_equal']=result['source_after']==before
  except BaseException as e:result.update(rc=2,guard_error=repr(e),source_guard_equal=False)
  put(out/'RESULT.json',result)
 print(json.dumps({k:v for k,v in result.items() if k!='traceback'},sort_keys=True),flush=True)
 return result['rc']
if __name__=='__main__':sys.exit(main())
