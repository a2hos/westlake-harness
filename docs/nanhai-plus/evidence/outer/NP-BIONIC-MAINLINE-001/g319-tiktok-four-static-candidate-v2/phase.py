#!/usr/bin/env python3
"""Bounded host-only phases for one exact G319 APK; no runtime or device actions."""
import hashlib, json, os, pathlib, struct, sys, traceback, zipfile

ROOT=pathlib.Path(os.environ['NANHAI_PROJECT_ROOT'])
HERE=pathlib.Path(__file__).parent
APK=ROOT/'.nanhai-plus-runtime/bionic-oh7-aosp16/staging/g319-tiktok-official-v1/TikTok.apk'
SCANNER=ROOT/'harness/westlake_gap/scanner.py'
CENSUS=HERE/'CENSUS.json'
RAW=ROOT/'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g319-tiktok-official-route-attempt-v1/root-raw-admission-v1/ROOT-RAW-ADMISSION.json'
EXPECTED={'apk':'ab8d9394d87ca046bda8f49031791cfaf75588a0830b5d54766e1bcf8ccdd6bc','scanner':'5ac937a7dcc425544dd4051368bfab6a3cdc1808024a505c20dfb09f2e187e3a','raw':'3f4e60a5de6c611a452640545ead7f18d640a05f5de9d14f05df5dbe26511ac4','census':'53f7841aac873dc6fec48c845b2b9794f2096b5d1b5f9c1c6c5eb2a485885cb5'}
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def guard():
 paths={'apk':APK,'scanner':SCANNER,'raw':RAW,'census':CENSUS}
 d={k:sha(v) for k,v in paths.items()}
 if d!=EXPECTED:raise RuntimeError('source drift '+repr(d))
 if json.loads(RAW.read_text())['decision']!='ACCEPT_EXACT_OFFICIAL_PAGE_LINKED_UNMODIFIED_HOST_RAW_ONLY':raise RuntimeError('raw root admission drift')
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
    names=z.namelist();bad=z.testzip();assert bad is None and len(names)==len(set(names))==20205
    assert {n for n in names if n.endswith('.dex')}=={x['name'] for x in census['dex']}
    assert {n for n in names if n.startswith('lib/') and n.endswith('.so')}=={x['name'] for x in census['so']}
    put(out/'ZIP-FACTS.json',{'entries_scanned':len(names),'crc_all_ok':True,'manifest_count':names.count('AndroidManifest.xml'),'root_dex':census['counts']['root_dex'],'embedded_dex':census['counts']['embedded_dex'],'true_arm64_elf':census['counts']['true_arm64_elf'],'non_elf_so':[x for x in census['so'] if x['kind']!='elf']})
  elif phase=='metadata':
   x=scanner.apk_metadata(APK);put(out/'MANIFEST.json',x)
   assert x.get('manifest_available') is True and x.get('package')=='com.zhiliaoapp.musically' and x.get('version_name')=='38.3.3' and str(x.get('version_code'))=='2023803030'
   assert x.get('sha256')==EXPECTED['apk'] and x.get('bytes')==429047484
  elif phase=='elf':
   records=[]
   with zipfile.ZipFile(APK) as z:
    for row in census['so']:
     if row['kind']!='elf':continue
     assert (row['name'].startswith('lib/arm64-v8a/') and row['class']==2 and row['machine']==183) or (row['name'].startswith('lib/armeabi-v7a/') and row['class']==1 and row['machine']==40)
     blob=z.read(row['name'])
     record=scanner.read_elf(data=blob,label=row['name'],abi=row['name'].split('/')[1])
     record['archive_entry']=row['name'];record['split_apk']=None
     records.append(record)
   put(out/'ELF-INVENTORY.json',records)
   assert len(records)==452 and sum(x['abi']=='arm64-v8a' for x in records)==227 and sum(x['abi']=='armeabi-v7a' for x in records)==225 and all(x.get('readelf_ok') is True and x.get('abi_matches_machine') is True and not x.get('registration_scan_error') for x in records)
  else:
   inv=scanner.inventory_dex(APK);put(out/'DEX-INVENTORY.json',encode(vars(inv)))
   assert {x['name'] for x in inv.dex_entries}=={x['name'] for x in census['dex']} and len(inv.dex_entries)==51
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
