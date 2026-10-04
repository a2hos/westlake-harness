#!/usr/bin/env python3
"""Offline content partition pilot; raw ZIP names are checked before map conversion."""
import hashlib,io,json,os,pathlib,struct,sys,warnings,zipfile

HERE=pathlib.Path(__file__).resolve().parent
ROOT=HERE.parents[7]
TIKTOK=ROOT/'.nanhai-plus-runtime/bionic-oh7-aosp16/staging/g319-tiktok-official-v1/TikTok.apk'
CAPCUT=ROOT/'.nanhai-plus-runtime/bionic-oh7-aosp16/staging/g316-capcut-official-v1/CapCut.apk'
CENSUS=ROOT/'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g319-tiktok-four-static-candidate-v2/CENSUS.json'
CAPCUT_RAW=ROOT/'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g316-capcut-official-raw-candidate-v2/root-raw-admission-v1/ROOT-RAW-ADMISSION.json'
EXPECTED_SHA={'tiktok':'ab8d9394d87ca046bda8f49031791cfaf75588a0830b5d54766e1bcf8ccdd6bc','capcut':'f2d5cf017bc4bf5a2d3e500a1a8c13cf0c83e3fa1bc707c6603e91af9b77612a','census':'53f7841aac873dc6fec48c845b2b9794f2096b5d1b5f9c1c6c5eb2a485885cb5','capcut_raw':'4e835511eb4cb07e7057197112449bc2aff0c83c0f3dfa097c860db7d094c1df'}

def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for block in iter(lambda:f.read(1<<20),b''):h.update(block)
 return h.hexdigest()

def classify(name,head):
 if not head.startswith(b'\x7fELF'):return 'non_elf_so'
 if len(head)<20:return 'invalid_elf'
 cls,machine=head[4],struct.unpack_from('<H',head,18)[0]
 if name.startswith('lib/arm64-v8a/') and (cls,machine)==(2,183):return 'arm64_elf'
 if name.startswith('lib/armeabi-v7a/') and (cls,machine)==(1,40):return 'arm32_elf'
 return 'unexpected_elf_abi'

def gate(expected,raw_rows):
 """raw_rows is the uncollapsed (name, classification) stream from ZipInfo."""
 names=[name for name,_ in raw_rows]
 if len(names)!=len(set(names)):return 'REJECT_DUPLICATE_MEMBER'
 observed=dict(raw_rows)
 if set(expected)!=set(observed):return 'REJECT_MEMBER_SET'
 if any(v.startswith(('invalid','unexpected')) for v in observed.values()):return 'REJECT_UNSUPPORTED_CLASS'
 if any(expected[n]!=observed[n] for n in expected):return 'REJECT_CLASS_MISMATCH'
 return 'PASS_PARTITION'

def rows_from_zip(path):
 with zipfile.ZipFile(path) as z:
  return [(info.filename,classify(info.filename,z.open(info).read(64))) for info in z.infolist() if info.filename.startswith('lib/') and info.filename.endswith('.so')]

def main():
 if sys.argv[1:]!=['--run'] or (HERE/'RESULT.json').exists():raise SystemExit('exact one-shot --run required')
 inputs={'tiktok':TIKTOK,'capcut':CAPCUT,'census':CENSUS,'capcut_raw':CAPCUT_RAW}
 before={k:sha(p) for k,p in inputs.items()}
 if before!=EXPECTED_SHA:raise RuntimeError('input SHA drift '+repr(before))
 census=json.loads(CENSUS.read_text());capcut_raw=json.loads(CAPCUT_RAW.read_text())
 assert capcut_raw['decision']=='ACCEPT_EXACT_CAPCUT_13_6_0_HOST_RAW_ONLY_WITH_ARM64_PATH_EXCEPTION'
 expected={x['name']:('arm64_elf' if x['kind']=='elf' and x['class']==2 and x['machine']==183 else 'arm32_elf' if x['kind']=='elf' else 'non_elf_so') for x in census['so']}
 tik=rows_from_zip(TIKTOK);cap=rows_from_zip(CAPCUT)
 assert len(tik)==456 and len(cap)==292
 tik_counts={x:sum(v==x for _,v in tik) for x in ('arm64_elf','arm32_elf','non_elf_so')}
 cap_counts={x:sum(v==x for _,v in cap) for x in ('arm64_elf','arm32_elf','non_elf_so','unexpected_elf_abi')}
 assert tik_counts=={'arm64_elf':227,'arm32_elf':225,'non_elf_so':4}
 assert cap_counts=={'arm64_elf':146,'arm32_elf':145,'non_elf_so':0,'unexpected_elf_abi':1}
 cases={'tiktok_real':gate(expected,tik),'capcut_real':gate(dict(cap),cap)}
 wrong=dict(expected);wrong[next(n for n,v in tik if v=='arm32_elf')]='arm64_elf';cases['v1_all_elf_assumed_arm64']=gate(wrong,tik)
 wrong=dict(expected);wrong[next(n for n,v in tik if v=='non_elf_so')]='arm64_elf';cases['fake_so_assumed_elf']=gate(wrong,tik)
 wrong=dict(expected);wrong.pop(next(n for n,v in tik if v=='non_elf_so'));cases['missing_member']=gate(wrong,tik)
 fake=io.BytesIO()
 with warnings.catch_warnings():
  warnings.simplefilter('ignore',UserWarning)
  with zipfile.ZipFile(fake,'w') as z:
   z.writestr('lib/arm64-v8a/a.so',b'\x7fELF\x02\x01'+b'\x00'*12+b'\xb7\x00'+b'\x00'*44)
   z.writestr('lib/arm64-v8a/a.so',b'\x7fELF\x02\x01'+b'\x00'*12+b'\xb7\x00'+b'\x00'*44)
 fake.seek(0)
 duplicate_raw=rows_from_zip(fake)
 assert len(duplicate_raw)==2 and duplicate_raw[0][0]==duplicate_raw[1][0]
 cases['duplicate_zip_member']=gate({'lib/arm64-v8a/a.so':'arm64_elf'},duplicate_raw)
 required={'tiktok_real':'PASS_PARTITION','capcut_real':'REJECT_UNSUPPORTED_CLASS','v1_all_elf_assumed_arm64':'REJECT_CLASS_MISMATCH','fake_so_assumed_elf':'REJECT_CLASS_MISMATCH','missing_member':'REJECT_MEMBER_SET','duplicate_zip_member':'REJECT_DUPLICATE_MEMBER'}
 if cases!=required:raise RuntimeError('case drift '+repr(cases))
 after={k:sha(p) for k,p in inputs.items()}
 if after!=before:raise RuntimeError('source changed during pilot')
 out={'schema':'evo42-offline-pilot-v2','inputs_sha256':before,'source_pre_post_equal':True,'tiktok_so_count':len(tik),'tiktok_partition':tik_counts,'capcut_so_count':len(cap),'capcut_partition':cap_counts,'cases':cases,'required':required,'pass':True,'capcut_exception_added':False,'production_scanner_changed':False,'authoritative_count_delta':0,'effects':{'network':0,'ssh':0,'device':0,'container':0,'namespace':0}}
 fd=os.open(HERE/'RESULT.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o444)
 try:os.write(fd,(json.dumps(out,ensure_ascii=False,indent=2,sort_keys=True)+'\n').encode());os.fsync(fd)
 finally:os.close(fd)
 print(json.dumps({'pass':out['pass'],'cases':cases,'tiktok_partition':tik_counts,'capcut_partition':cap_counts},sort_keys=True))

if __name__=='__main__':main()
