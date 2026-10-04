#!/usr/bin/env python3
import hashlib,io,json,pathlib,struct,time,zipfile,zlib
from datetime import datetime,timezone

HERE=pathlib.Path(__file__).resolve().parent
ROOT=HERE.parents[3]
CASES=[
 ('brave_positive','.nanhai-plus-runtime/bionic-oh7-aosp16/staging/g314-brave-official-v1/Bravearm64Universal.apk','df3fbad622954843ab03744e85765da0fe5c15a018069b8f0aaabab3eafe6bcc',6,1),
 ('vyprvpn_negative','.nanhai-plus-runtime/bionic-oh7-aosp16/staging/g311-vyprvpn-official-v1/VyprVPN.apk','be67f60356bac9811ca3419259cbb22ce3e3fb113aedc4e2cc6e3b40e2c1bae7',3,0),
]
def sha(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def dex_header_ok(b,size):
 return len(b)>=112 and b[:4]==b'dex\n' and b[7]==0 and struct.unpack_from('<I',b,32)[0]==size and struct.unpack_from('<I',b,36)[0]==112 and struct.unpack_from('<I',b,40)[0]==0x12345678
def census(z):
 names=z.namelist();dots=sorted(n for n in names if n.endswith('.dex'))
 roots=[];embedded=[];invalid=[]
 for n in dots:
  info=z.getinfo(n)
  with z.open(n) as f:header=f.read(112)
  if not dex_header_ok(header,info.file_size):
   invalid.append(n);continue
  if n=='classes.dex' or n.startswith('classes') and n.endswith('.dex') and n[7:-4].isdigit():roots.append(n)
  else:embedded.append(n)
 return {'dot_dex_entries':dots,'root_classes_dex':sorted(roots),'embedded_dex_candidates':sorted(embedded),'invalid_dot_dex':invalid,'requires_separate_semantic_inventory':bool(embedded or invalid)}
def main():
 t=time.monotonic_ns();out=[]
 for name,rel,expected,root_count,embedded_count in CASES:
  p=ROOT/rel;actual=sha(p)
  if actual!=expected:raise RuntimeError(name+' input SHA drift')
  with zipfile.ZipFile(p) as z:r=census(z)
  passed=len(r['root_classes_dex'])==root_count and len(r['embedded_dex_candidates'])==embedded_count and not r['invalid_dot_dex']
  out.append({'case':name,'apk_path':rel,'apk_sha256':actual,'result':r,'oracle_pass':passed})
 b=io.BytesIO()
 with zipfile.ZipFile(b,'w') as z:z.writestr('classes.dex',b'not a dex')
 with zipfile.ZipFile(io.BytesIO(b.getvalue())) as z:bad=census(z)
 out.append({'case':'invalid_dot_dex_negative','fixture_sha256':hashlib.sha256(b.getvalue()).hexdigest(),'result':bad,'oracle_pass':bad['invalid_dot_dex']==['classes.dex'] and not bad['root_classes_dex']})
 end=time.monotonic_ns()
 result={'schema':'evo40-embedded-dex-census-offline-trial-v1','started_monotonic_ns':t,'ended_monotonic_ns':end,'elapsed_seconds':(end-t)/1e9,'at_utc':datetime.now(timezone.utc).isoformat(),'cases':out,'all_oracles_pass':all(x['oracle_pass'] for x in out),'production_changes':0,'network_commands':0,'device_commands':0,'ssh_commands':0,'container_commands':0,'count_delta':0}
 (HERE/'TRIAL-RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps({'elapsed_seconds':result['elapsed_seconds'],'all_oracles_pass':result['all_oracles_pass'],'cases':[(x['case'],x['oracle_pass']) for x in out]}))
if __name__=='__main__':main()
