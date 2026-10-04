#!/usr/bin/env python3
"""Four host-only phases against one pinned PureVPN APK."""
import hashlib,json,os,pathlib,sys,traceback,zipfile
ROOT=pathlib.Path(os.environ['NANHAI_PROJECT_ROOT']);HERE=pathlib.Path(__file__).parent
APK=pathlib.Path(os.environ['NANHAI_STAGING_ROOT'])/'g334-purevpn-official-v1/PureVPN.apk'
RAW=ROOT/'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g334-purevpn-official-raw-candidate-v1/ROOT-RAW-ADMISSION.json'
SCANNER=ROOT/'harness/westlake_gap/scanner.py';CENSUS=HERE/'CENSUS.json'
EXPECTED={'apk':'7389ee26e8c344cc62f790d4cef1a7f41ce1ddd1a582edf4f61e78b05df95e1f','raw':'8000810ec544bcbf6bf1a80097b733e8102cefc219226f17217b29464bc24ac4','scanner':'5ac937a7dcc425544dd4051368bfab6a3cdc1808024a505c20dfb09f2e187e3a'}
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def guard():
 if APK.suffix!='.apk' or APK.stat().st_size!=72731840:raise ValueError('APK suffix or size drift')
 d={'apk_bytes':APK.stat().st_size,'apk':sha(APK),'raw':sha(RAW),'scanner':sha(SCANNER),'census':sha(CENSUS)}
 if d['apk_bytes']!=72731840 or any(d[k]!=EXPECTED[k] for k in EXPECTED):raise ValueError('input drift '+repr(d))
 a=json.loads(RAW.read_text());c=json.loads(CENSUS.read_text())
 if a['decision']!='ACCEPT_ONE_EXACT_OFFICIAL_HOST_RAW_ONLY' or a['apk_sha256']!=EXPECTED['apk'] or c['apk_sha256']!=EXPECTED['apk']:raise ValueError('admission/census drift')
 return d
def put(p,obj):
 with p.open('x') as f:json.dump(obj,f,indent=2,ensure_ascii=False,sort_keys=True);f.write('\n')
def encode(v):
 if isinstance(v,(set,frozenset)):return sorted((encode(x) for x in v),key=str)
 if isinstance(v,dict):return {str(k):encode(x) for k,x in v.items()}
 if isinstance(v,(list,tuple)):return [encode(x) for x in v]
 if hasattr(v,'__dict__'):return encode(vars(v))
 return v
def main():
 if len(sys.argv)!=2 or sys.argv[1] not in ('zip','metadata','dex','elf'):raise SystemExit(2)
 phase=sys.argv[1];out=HERE/'phases'/phase;out.mkdir(parents=True,exist_ok=False)
 before=guard();c=json.loads(CENSUS.read_text());sys.path.insert(0,str(ROOT/'harness'))
 from westlake_gap import scanner
 result={'phase':phase,'rc':2,'source_before':before,'network_commands':0,'device_commands':0,'container_commands':0}
 try:
  if phase=='zip':
   with zipfile.ZipFile(APK) as z:
    names=z.namelist();assert len(names)==c['zip_entries'] and len(names)==len(set(names)) and z.testzip() is None
    assert names.count('AndroidManifest.xml')==1
    assert {n for n in names if n.endswith('.dex')}=={x['name'] for x in c['dex']}
    assert {n for n in names if n.startswith('lib/') and n.endswith('.so')}=={x['name'] for x in c['so']}
    put(out/'ZIP-FACTS.json',{'entries_scanned':len(names),'crc_all_ok':True,'manifest_count':1,'root_dex':c['counts']['root_dex'],'embedded_dex':c['counts']['embedded_dex'],'nested_archive_name_candidates':c['nested_archive_name_candidates'],'true_arm64_elf':c['counts']['true_arm64_elf'],'other_abi_true_elf':c['counts']['other_elf'],'non_elf_so':c['counts']['non_elf_so']})
  elif phase=='metadata':
   x=scanner.apk_metadata(APK);put(out/'MANIFEST.json',x)
   assert x.get('manifest_available') is True and x.get('package')=='com.gaditek.purevpnics' and x.get('version_name')=='8.44.223' and str(x.get('version_code'))=='5175'
   assert x.get('sha256')==EXPECTED['apk'] and x.get('bytes')==72731840 and str(x.get('target_sdk'))=='31'
  elif phase=='dex':
   inv=scanner.inventory_dex(APK);put(out/'DEX-INVENTORY.json',encode(inv))
   assert {x['name'] for x in inv.dex_entries}=={x['name'] for x in c['dex']} and len(inv.dex_entries)==2
  else:
   target=[];other=[];fake=[]
   with zipfile.ZipFile(APK) as z:
    for row in c['so']:
     if row['kind']!='elf':fake.append(row);continue
     name=row['name'];abi=name.split('/')[1]
     expected={'arm64-v8a':(2,1,183),'armeabi-v7a':(1,1,40),'x86':(1,1,3),'x86_64':(2,1,62),'armeabi':(1,1,40),'mips':(1,1,8),'mips64':(2,1,8)}
     assert abi in expected and (row['class'],row['endian'],row['machine'])==expected[abi]
     if abi!='arm64-v8a':other.append(row);continue
     record=scanner.read_elf(data=z.read(name),label=name,abi=abi)
     record['archive_entry']=name;record['split_apk']=None;target.append(record)
   put(out/'ELF-INVENTORY.json',target)
   put(out/'ELF-CLASSIFICATION.json',{'true_arm64_target_records':len(target),'non_target_abi_elf_header_records':other,'non_elf_so_records':fake,'scope':'ARM64 target readelf/JNI only; other ABI classified by ELF header'})
   assert len(target)==c['counts']['true_arm64_elf'] and len(other)==c['counts']['other_elf'] and len(fake)==c['counts']['non_elf_so']
   assert all(x.get('readelf_ok') is True and x.get('abi_matches_machine') is True and not x.get('registration_scan_error') for x in target)
  result['rc']=0
 except BaseException as e:result.update(error=repr(e),traceback=traceback.format_exc())
 finally:
  try:result['source_after']=guard();result['source_guard_equal']=result['source_after']==before
  except BaseException as e:result.update(rc=2,guard_error=repr(e),source_guard_equal=False)
  put(out/'RESULT.json',result)
 print(json.dumps({k:v for k,v in result.items() if k!='traceback'},sort_keys=True),flush=True)
 return result['rc']
if __name__=='__main__':sys.exit(main())
