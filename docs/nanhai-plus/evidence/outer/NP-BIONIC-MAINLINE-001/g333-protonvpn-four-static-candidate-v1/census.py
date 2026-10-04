#!/usr/bin/env python3
"""Read-only member/header census for the fixed Proton VPN APK."""
import hashlib, json, os, pathlib, struct, zipfile

ROOT=pathlib.Path(os.environ['NANHAI_PROJECT_ROOT'])
HERE=pathlib.Path(__file__).parent
APK=pathlib.Path(os.environ['NANHAI_STAGING_ROOT'])/'g332-protonvpn-official-v1/ProtonVPN-5.20.57.0.605205700.-production-vanilla-direct-release.apk'
RAW=ROOT/'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g332-protonvpn-official-raw-candidate-v1/ROOT-RAW-ADMISSION.json'
SCANNER=ROOT/'harness/westlake_gap/scanner.py'
EXPECTED_APK='57b06d74cb00fe73e26cc0232dbae98bbeed52738ef5ce5d7c8cafa2a9de20e6'
EXPECTED_RAW='bff10e8941a5f9b6bc30840c0ef118ce5b72e3629e21642527c24315fefa04be'
EXPECTED_SCANNER='5ac937a7dcc425544dd4051368bfab6a3cdc1808024a505c20dfb09f2e187e3a'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def main():
 assert not (HERE/'CENSUS.json').exists()
 assert APK.suffix=='.apk' and APK.stat().st_size==64238953 and sha(APK)==EXPECTED_APK
 assert sha(RAW)==EXPECTED_RAW and sha(SCANNER)==EXPECTED_SCANNER
 assert json.loads(RAW.read_text())['decision']=='ACCEPT_ONE_EXACT_OFFICIAL_HOST_RAW_ONLY'
 dex=[];so=[];nested=[]
 with zipfile.ZipFile(APK) as z:
  infos=z.infolist();names=[i.filename for i in infos]
  assert len(names)==len(set(names)) and names.count('AndroidManifest.xml')==1
  for i in infos:
   n=i.filename
   if n.endswith('.dex'):
    with z.open(i) as f:b=f.read()
    assert b.startswith(b'dex\n') and struct.unpack_from('<I',b,32)[0]==len(b)
    dex.append({'name':n,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'magic':b[:8].hex(),'embedded':'/' in n})
   if n.startswith('lib/') and n.endswith('.so'):
    with z.open(i) as f:b=f.read(20)
    if b.startswith(b'\x7fELF') and len(b)>=20:
     so.append({'name':n,'kind':'elf','bytes':i.file_size,'class':b[4],'endian':b[5],'machine':struct.unpack_from('<H',b,18)[0]})
    else:so.append({'name':n,'kind':'non_elf','bytes':i.file_size,'magic':b[:8].hex()})
   if n.lower().endswith(('.apk','.jar','.zip','.aab','.xapk')):nested.append({'name':n,'bytes':i.file_size})
  assert z.testzip() is None
 counts={'root_dex':sum(not x['embedded'] for x in dex),'embedded_dex':sum(x['embedded'] for x in dex),'true_arm64_elf':sum(x['kind']=='elf' and x['name'].startswith('lib/arm64-v8a/') and (x['class'],x['endian'],x['machine'])==(2,1,183) for x in so),'arm32_elf':sum(x['kind']=='elf' and x['name'].startswith('lib/armeabi-v7a/') for x in so),'other_elf':sum(x['kind']=='elf' and not x['name'].startswith('lib/arm64-v8a/') for x in so),'non_elf_so':sum(x['kind']!='elf' for x in so)}
 data={'schema':'g333-protonvpn-census-v1','apk_sha256':EXPECTED_APK,'apk_bytes':64238953,'root_raw_admission_sha256':EXPECTED_RAW,'scanner_sha256':EXPECTED_SCANNER,'zip_entries':len(infos),'zip_crc_all':True,'dex':dex,'so':so,'nested_archive_name_candidates':nested,'counts':counts,'device_commands':0,'container_commands':0}
 with (HERE/'CENSUS.json').open('x') as f:json.dump(data,f,indent=2);f.write('\n')
 print(json.dumps({'entries':len(infos),'counts':counts,'nested':len(nested)}))
if __name__=='__main__':main()
