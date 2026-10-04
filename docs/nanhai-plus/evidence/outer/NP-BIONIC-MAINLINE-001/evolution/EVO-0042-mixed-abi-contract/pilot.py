#!/usr/bin/env python3
"""Offline pre-scan classification contract; uses no scanner, network, or device."""
import hashlib, json, pathlib, struct, zipfile

B=pathlib.Path(__file__).resolve().parent
R=B.parents[6]
APK=R/'.nanhai-plus-runtime/bionic-oh7-aosp16/staging/g319-tiktok-official-v1/TikTok.apk'
CENSUS=B.parents[1]/'g319-tiktok-four-static-candidate-v2/CENSUS.json'

def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for x in iter(lambda:f.read(1<<20),b''):h.update(x)
 return h.hexdigest()

def classify(name,head):
 if not head.startswith(b'\x7fELF'):
  return 'non_elf_so'
 if len(head)<20: return 'invalid_elf'
 cls,machine=head[4],struct.unpack_from('<H',head,18)[0]
 if name.startswith('lib/arm64-v8a/') and (cls,machine)==(2,183): return 'arm64_elf'
 if name.startswith('lib/armeabi-v7a/') and (cls,machine)==(1,40): return 'arm32_elf'
 return 'unexpected_elf_abi'

def gate(expected,observed):
 if len(expected)!=len(set(expected)) or set(expected)!=set(observed): return 'REJECT_MEMBER_SET'
 if any(expected[n]!=observed[n] for n in expected): return 'REJECT_CLASS_MISMATCH'
 if any(v.startswith(('invalid','unexpected')) for v in observed.values()): return 'REJECT_UNSUPPORTED_CLASS'
 return 'PASS_PARTITION'

def main():
 c=json.loads(CENSUS.read_text())
 expected={x['name']:{'elf':('arm64_elf' if x['class']==2 and x['machine']==183 else 'arm32_elf'), 'other':'non_elf_so'}[x['kind']] for x in c['so']}
 with zipfile.ZipFile(APK) as z:
  names=[n for n in z.namelist() if n.startswith('lib/') and n.endswith('.so')]
  observed={n:classify(n,z.open(n).read(64)) for n in names}
 assert len(names)==456 and len(expected)==456
 assert {x:sum(v==x for v in observed.values()) for x in ['arm64_elf','arm32_elf','non_elf_so']}=={'arm64_elf':227,'arm32_elf':225,'non_elf_so':4}
 cases={'real_mixed_apk':gate(expected,observed)}
 tampered=dict(expected);arm32=next(n for n,v in observed.items() if v=='arm32_elf');tampered[arm32]='arm64_elf';cases['v1_all_elf_assumed_arm64']=gate(tampered,observed)
 tampered=dict(expected);non=next(n for n,v in observed.items() if v=='non_elf_so');tampered[non]='arm64_elf';cases['fake_so_assumed_elf']=gate(tampered,observed)
 tampered=dict(expected);del tampered[non];cases['missing_member']=gate(tampered,observed)
 assert cases=={'real_mixed_apk':'PASS_PARTITION','v1_all_elf_assumed_arm64':'REJECT_CLASS_MISMATCH','fake_so_assumed_elf':'REJECT_CLASS_MISMATCH','missing_member':'REJECT_MEMBER_SET'}
 out={'schema':'EVO42-offline-pilot-v1','inputs':{'apk_sha256':sha(APK),'census_sha256':sha(CENSUS)},'actual_partition':{'arm64_elf':227,'arm32_elf':225,'non_elf_so':4},'cases':cases,'pass':True,'effects':{'network':0,'ssh':0,'device':0,'container':0,'production_writes':0}}
 (B/'PILOT.json').write_text(json.dumps(out,indent=2)+'\n')
 print(json.dumps(cases))
if __name__=='__main__':main()
