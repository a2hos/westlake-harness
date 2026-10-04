#!/usr/bin/env python3
"""Bounded host-only phases for one exact G324 Signal APK."""
import hashlib, json, os, pathlib, struct, sys, traceback, zipfile

ROOT=pathlib.Path(os.environ['NANHAI_PROJECT_ROOT'])
HERE=pathlib.Path(__file__).parent
APK=ROOT/'.nanhai-plus-runtime/bionic-oh7-aosp16/staging/mainstream-stock-intake-v2/org.thoughtcrime.securesms/body.raw'
SCANNER=ROOT/'harness/westlake_gap/scanner.py'
CENSUS=HERE/'CENSUS.json'
RAW=ROOT/'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/mainstream-stock-intake-v2/root-intake-v1/ROOT-ACCEPTANCE.json'
EXPECTED={'apk':'9fca2a1cd46ad805bd12d7bcc3930cc9388bffd5a1d01b0422c6149f1b702122','scanner':'5ac937a7dcc425544dd4051368bfab6a3cdc1808024a505c20dfb09f2e187e3a','raw':'1e14a8c22f028ff8ca9bc19f72a6cdab6821f70e92227166c18fbf588b5d8f79','census':'6ae84ba7af879621943b54e5594164494c1c767e7063e1caff5303d8d3e38fc5'}
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def guard():
 paths={'apk':APK,'scanner':SCANNER,'raw':RAW,'census':CENSUS}
 d={k:sha(v) for k,v in paths.items()}
 if d!=EXPECTED:raise RuntimeError('source drift '+repr(d))
 admission=json.loads(RAW.read_text())
 if admission['status']!='ROOT_ACCEPT_ONE_OFFICIAL_SIGNAL_RAW_SUPPLEMENT_ONLY' or not any(x.get('proposed_package_label')=='org.thoughtcrime.securesms' and x['sha256']==EXPECTED['apk'] for x in admission['payloads']):raise RuntimeError('raw root admission drift')
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
    names=z.namelist();bad=z.testzip();assert bad is None and len(names)==len(set(names))==4185
    assert {n for n in names if n.endswith('.dex')}=={x['name'] for x in census['dex']}
    assert {n for n in names if n.startswith('lib/') and n.endswith('.so')}=={x['name'] for x in census['so']}
    assert census['nested_archives']==[] and census['counts']['embedded_dex']==0
    put(out/'ZIP-FACTS.json',{'entries_scanned':len(names),'crc_all_ok':True,'manifest_count':names.count('AndroidManifest.xml'),'root_dex':census['counts']['root_dex'],'embedded_dex':census['counts']['embedded_dex'],'nested_archives':[{'path':x['path'],'sha256':x['sha256'],'members':x['members']} for x in census['nested_archives']],'true_arm64_elf':census['counts']['true_arm64_elf'],'non_elf_so':[x for x in census['so'] if x['kind']!='elf']})
  elif phase=='metadata':
   x=scanner.apk_metadata(APK);put(out/'MANIFEST.json',x)
   assert x.get('manifest_available') is True and x.get('package')=='org.thoughtcrime.securesms' and x.get('version_name')=='8.29.3' and str(x.get('version_code'))=='175901'
   assert x.get('sha256')==EXPECTED['apk'] and x.get('bytes')==114758484 and str(x.get('target_sdk'))=='36'
  elif phase=='elf':
   records=[];other=[]
   with zipfile.ZipFile(APK) as z:
    for row in census['so']:
     if row['kind']!='elf':continue
     abi=row['name'].split('/')[1]
     expected_abi_header={'arm64-v8a':(2,183),'armeabi-v7a':(1,40),'x86':(1,3),'x86_64':(2,62)}
     assert abi in expected_abi_header and (row['class'],row['machine'])==expected_abi_header[abi]
     if abi!='arm64-v8a':other.append({'name':row['name'],'class':row['class'],'machine':row['machine'],'bytes':row['bytes']});continue
     blob=z.read(row['name'])
     record=scanner.read_elf(data=blob,label=row['name'],abi=row['name'].split('/')[1])
     record['archive_entry']=row['name'];record['split_apk']=None
     records.append(record)
   put(out/'ELF-INVENTORY.json',records)
   assert len(records)==12 and len(other)==36 and all(x['abi']=='arm64-v8a' and x.get('readelf_ok') is True and x.get('abi_matches_machine') is True and not x.get('registration_scan_error') for x in records)
   put(out/'ELF-CLASSIFICATION.json',{'arm64_target_records':12,'other_abi_header_only_records':other,'non_elf_so':0,'scope':'ARM64 readelf/JNI scan only; other ABI ELF retained by header census without symbol scan'})
  else:
   inv=scanner.inventory_dex(APK);put(out/'DEX-INVENTORY.json',encode(vars(inv)))
   assert {x['name'] for x in inv.dex_entries}=={x['name'] for x in census['dex']} and len(inv.dex_entries)==6
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
