#!/usr/bin/env python3
"""Read-only member/header census for the fixed Steam Chat APK."""
import hashlib, json, os, pathlib, struct, zipfile

ROOT=pathlib.Path(os.environ['NANHAI_PROJECT_ROOT'])
HERE=pathlib.Path(__file__).parent
APK=pathlib.Path(os.environ['NANHAI_STAGING_ROOT'])/'blackbox-steam-chat-official-intake-candidate-v1/steam-chat.apk'
RAW=ROOT/'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/blackbox-steam-chat-official-intake-candidate-v1/ROOT-RAW-ADMISSION.json'
SCANNER=ROOT/'harness/westlake_gap/scanner.py'
EXPECTED_APK='b83d6bfaf24ec5f79ddb7151c0136abe031b3d17d2852b85d37f9db226829307'
EXPECTED_RAW='830196efabf1feba308a48c58a4145bd49fcd27e7fa12e7f361542cd033c59d0'
EXPECTED_SCANNER='5ac937a7dcc425544dd4051368bfab6a3cdc1808024a505c20dfb09f2e187e3a'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def main():
 assert not (HERE/'CENSUS.json').exists()
 assert APK.suffix=='.apk' and APK.stat().st_size==94680962 and sha(APK)==EXPECTED_APK
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
 data={'schema':'g329-steamchat-census-v1','apk_sha256':EXPECTED_APK,'apk_bytes':94680962,'root_raw_admission_sha256':EXPECTED_RAW,'scanner_sha256':EXPECTED_SCANNER,'zip_entries':len(infos),'zip_crc_all':True,'dex':dex,'so':so,'nested_archive_name_candidates':nested,'counts':counts,'device_commands':0,'container_commands':0}
 with (HERE/'CENSUS.json').open('x') as f:json.dump(data,f,indent=2);f.write('\n')
 print(json.dumps({'entries':len(infos),'counts':counts,'nested':len(nested)}))
if __name__=='__main__':main()
