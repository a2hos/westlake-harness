#!/usr/bin/env python3
import collections,datetime,hashlib,json,os,pathlib,re,struct,subprocess,zipfile
root=pathlib.Path(os.environ['NANHAI_PROJECT_ROOT']);here=pathlib.Path(__file__).parent
name='ProtonVPN-5.20.57.0.605205700.-production-vanilla-direct-release.apk';apk=pathlib.Path(os.environ['NANHAI_STAGING_ROOT'])/'g332-protonvpn-official-v1'/name
api=json.loads((here/'release-api.raw').read_text());asset=next(a for a in api['assets'] if a['name']==name)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert apk.stat().st_size==asset['size'] and 'sha256:'+sha(apk)==asset['digest']
with zipfile.ZipFile(apk) as z:
 infos=z.infolist();names=[i.filename for i in infos];dup=len(names)-len(set(names));crc=z.testzip();counts=collections.Counter();false_so=[];root_dex=0;elf=[]
 for i in infos:
  n=i.filename
  if re.fullmatch(r'classes(?:[2-9][0-9]*)?\.dex',n):root_dex+=1
  if n.startswith('lib/') and n.endswith('.so'):
   with z.open(i) as f:b=f.read(20)
   if b.startswith(b'\x7fELF') and len(b)>=20:
    rec={'name':n,'abi_path':n.split('/')[1],'elf_class':b[4],'endian':b[5],'machine':struct.unpack_from('<H',b,18)[0]};elf.append(rec);counts[(rec['abi_path'],rec['elf_class'],rec['endian'],rec['machine'])]+=1
   else:false_so.append({'name':n,'magic':b[:8].hex()})
assert dup==0 and crc is None and names.count('AndroidManifest.xml')==1
sdk=pathlib.Path.home()/'Library/Android/sdk/build-tools/36.1.0';commands=[]
for tool,args in [('aapt2',['dump','badging']),('apksigner',['verify','--verbose','--print-certs'])]:
 path=sdk/tool;assert path.is_file()
 argv=[str(path),*args,str(apk)];r=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=root,timeout=60)
 (here/(tool+'.stdout.raw')).write_bytes(r.stdout);(here/(tool+'.stderr.raw')).write_bytes(r.stderr)
 commands.append({'argv':[str(path),*args,str(apk.relative_to(root))],'rc':r.returncode,'stdout_sha256':sha(here/(tool+'.stdout.raw')),'stderr_sha256':sha(here/(tool+'.stderr.raw'))})
output=(here/'aapt2.stdout.raw').read_text(errors='replace');sign=(here/'apksigner.stdout.raw').read_text(errors='replace')
package=re.search(r"^package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'",output,re.M)
assert package and all(x['rc']==0 for x in commands)
res={'schema':'g332-protonvpn-host-verify-v1','at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'apk_path':str(apk.relative_to(root)),'apk_sha256':sha(apk),'apk_bytes':apk.stat().st_size,'api_asset_digest':asset['digest'],'api_asset_bytes':asset['size'],'package':package.group(1),'version_code':package.group(2),'version_name':package.group(3),'zip_entries':len(infos),'duplicate_names':dup,'crc_all_ok':crc is None,'root_dex':root_dex,'elf_header_count_by_abi':[{ 'abi':k[0],'class':k[1],'endian':k[2],'machine':k[3],'count':v} for k,v in sorted(counts.items())],'arm64_true_elf':sum(v for k,v in counts.items() if k==( 'arm64-v8a',2,1,183)),'non_elf_so':false_so,'signer_certificate_sha256':re.findall(r'Signer #\d+ certificate SHA-256 digest: ([0-9a-f]+)',sign),'commands':commands,'device_commands':0,'container_commands':0}
with (here/'HOST-VERIFY.json').open('x') as f:json.dump(res,f,indent=2,sort_keys=True);f.write('\n')
print(json.dumps({k:res[k] for k in ('apk_sha256','apk_bytes','package','version_code','version_name','zip_entries','root_dex','elf_header_count_by_abi','arm64_true_elf','non_elf_so','signer_certificate_sha256','commands')},ensure_ascii=False))
