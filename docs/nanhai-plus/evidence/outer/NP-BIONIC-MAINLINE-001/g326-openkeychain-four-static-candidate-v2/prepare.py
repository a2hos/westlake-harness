#!/usr/bin/env python3
"""One-shot full APK member census, including bounded nested ZIP containers."""
import hashlib,io,json,os,pathlib,struct,zipfile

ROOT=pathlib.Path(os.environ['NANHAI_PROJECT_ROOT'])
HERE=pathlib.Path(__file__).parent
APK=ROOT/'.nanhai-plus-runtime/bionic-oh7-aosp16/staging/g326-openkeychain-v2/OpenKeychain.apk'
ORIGINAL=ROOT/'.nanhai-plus-runtime/bionic-oh7-aosp16/staging/apk-stock-intake-v7/org.sufficientlysecure.keychain/body.raw'
ALIAS=HERE/'ALIAS.json'
FIXTURE=HERE/'FIXTURE.json'
SCANNER=ROOT/'harness/westlake_gap/scanner.py'
RAW=ROOT/'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/apk-stock-intake-v7/root-intake-v1/ROOT-ACCEPTANCE.json'
MAX_NESTED_BYTES=50*1024*1024

def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def payload_sha(b):return hashlib.sha256(b).hexdigest()
def nested_scan(blob,label,depth=0):
 if depth>3:raise RuntimeError('nested depth exceeded')
 if len(blob)>MAX_NESTED_BYTES:raise RuntimeError('nested archive bytes exceeded: '+label)
 with zipfile.ZipFile(io.BytesIO(blob)) as z:
  names=z.namelist()
  if len(names)!=len(set(names)):raise RuntimeError('nested duplicate member: '+label)
  if z.testzip() is not None:raise RuntimeError('nested crc failure: '+label)
  found=[];children=[]
  for n in names:
   if n.endswith('/'):
    continue
   with z.open(n) as f:header=f.read(8)
   if n.lower().endswith('.dex') or header.startswith(b'dex\n'):
    b=z.read(n);found.append({'path':label+'!/'+n,'bytes':len(b),'sha256':payload_sha(b),'magic':b[:8].hex(),'header_consistent':len(b)>=36 and b.startswith(b'dex\n') and struct.unpack_from('<I',b,32)[0]==len(b)})
   if header.startswith(b'PK\x03\x04'):
    child=z.read(n);sub=nested_scan(child,label+'!/'+n,depth+1);children.append(sub)
  return {'path':label,'bytes':len(blob),'sha256':payload_sha(blob),'members':len(names),'dex':found,'nested':children}

def main():
 if (HERE/'CENSUS.json').exists():raise RuntimeError('one-shot census already exists')
 assert APK.suffix=='.apk' and APK.stat().st_size==ORIGINAL.stat().st_size==12043256
 assert sha(APK)==sha(ORIGINAL)=='f88374b9113aa9ddba865258bd989eb3ac2ca1577d92e59d6e84228e080674ce'
 assert sha(ALIAS) and json.loads(ALIAS.read_text())['alias_sha256']==sha(APK)
 fixture=json.loads(FIXTURE.read_text());assert fixture['rc']==0 and all(fixture['checks'].values())
 admission=json.loads(RAW.read_text())
 assert admission['status']=='ACCEPTED_EXACT_RAW_STOCK_PAYLOAD_BYTES_ONLY'
 assert any(x.get('registry_package_label')=='org.sufficientlysecure.keychain' and x['sha256']==sha(APK) for x in admission['payloads'])
 dex=[];so=[];nested=[];magic_nested_candidates=[]
 with zipfile.ZipFile(APK) as z:
  names=z.namelist()
  if len(names)!=len(set(names)):raise RuntimeError('duplicate root ZIP member')
  for n in names:
   if n.endswith('/'):continue
   info=z.getinfo(n)
   with z.open(n) as f:header=f.read(64)
   if n.lower().endswith('.dex') or header.startswith(b'dex\n'):
    b=z.read(n)
    dex.append({'name':n,'bytes':len(b),'sha256':payload_sha(b),'magic':b[:8].hex(),'header_consistent':len(b)>=36 and b.startswith(b'dex\n') and struct.unpack_from('<I',b,32)[0]==len(b)})
   if n.startswith('lib/') and n.endswith('.so'):
    if header.startswith(b'\x7fELF') and len(header)>=20:
     so.append({'name':n,'kind':'elf','bytes':info.file_size,'class':header[4],'machine':struct.unpack_from('<H',header,18)[0]})
    else:so.append({'name':n,'kind':'non_elf','bytes':info.file_size,'header_hex':header[:16].hex()})
   if header.startswith(b'PK\x03\x04'):
    magic_nested_candidates.append(n)
    nested.append(nested_scan(z.read(n),n))
  entries=len(names)
 all_nested_dex=[]
 def collect(x):
  all_nested_dex.extend(x['dex'])
  for y in x['nested']:collect(y)
 for x in nested:collect(x)
 counts={'root_dex':len(dex),'embedded_dex':len(all_nested_dex),'true_arm64_elf':sum(x['kind']=='elf' and x['name'].startswith('lib/arm64-v8a/') and x['class']==2 and x['machine']==183 for x in so),'arm32_elf':sum(x['kind']=='elf' and x['class']==1 and x['machine']==40 for x in so),'other_elf':sum(x['kind']=='elf' and not (x['class']==2 and x['machine']==183) for x in so),'non_elf_so':sum(x['kind']!='elf' for x in so)}
 out={'schema':'g326-openkeychain-full-member-census-v2','original_sha256':sha(ORIGINAL),'alias_receipt_sha256':sha(ALIAS),'suffix_fixture_sha256':sha(FIXTURE),'apk_sha256':sha(APK),'root_raw_sha256':sha(RAW),'scanner_sha256':sha(SCANNER),'entries':entries,'dex':dex,'so':so,'nested_archives':nested,'nested_magic_candidate_names':magic_nested_candidates,'counts':counts,'bounds':{'nested_archive_max_bytes':MAX_NESTED_BYTES,'nested_max_depth':3},'device_commands':0,'container_commands':0,'network_commands':0}
 with (HERE/'CENSUS.json').open('x') as f:json.dump(out,f,indent=2);f.write('\n')
 print(json.dumps({'entries':entries,'counts':counts,'nested_archives':len(nested)}))
if __name__=='__main__':main()
