#!/usr/bin/env python3
"""One-shot project-owned filename alias for unchanged Signal raw APK bytes."""
import hashlib,json,os,pathlib,shutil,stat
R=pathlib.Path(os.environ['NANHAI_PROJECT_ROOT'])
H=pathlib.Path(__file__).parent
O=R/'.nanhai-plus-runtime/bionic-oh7-aosp16/staging/mainstream-stock-intake-v2/org.thoughtcrime.securesms/body.raw'
A=R/'.nanhai-plus-runtime/bionic-oh7-aosp16/staging/g324-signal-v2/Signal.apk'
RAW=R/'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/mainstream-stock-intake-v2/root-intake-v1/ROOT-ACCEPTANCE.json'
EXPECTED='9fca2a1cd46ad805bd12d7bcc3930cc9388bffd5a1d01b0422c6149f1b702122'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def main():
 assert not (H/'ALIAS.json').exists() and not A.exists()
 assert O.stat().st_size==114758484 and sha(O)==EXPECTED
 assert sha(RAW)=='1e14a8c22f028ff8ca9bc19f72a6cdab6821f70e92227166c18fbf588b5d8f79'
 x=json.loads(RAW.read_text());assert x['status']=='ROOT_ACCEPT_ONE_OFFICIAL_SIGNAL_RAW_SUPPLEMENT_ONLY'
 assert any(y.get('proposed_package_label')=='org.thoughtcrime.securesms' and y['sha256']==EXPECTED for y in x['payloads'])
 A.parent.mkdir(parents=True,exist_ok=True)
 with O.open('rb') as src,A.open('xb') as dst:shutil.copyfileobj(src,dst,1<<20)
 A.chmod(0o444)
 assert A.stat().st_size==O.stat().st_size and sha(A)==sha(O)==EXPECTED
 out={'schema':'g324-signal-alias-v2','original':str(O),'alias':str(A),'original_sha256':sha(O),'alias_sha256':sha(A),'original_bytes':O.stat().st_size,'alias_bytes':A.stat().st_size,'alias_mode':oct(stat.S_IMODE(A.stat().st_mode)),'root_raw_admission':str(RAW),'root_raw_admission_sha256':sha(RAW),'copy_kind':'independent_byte_copy','device_commands':0,'container_commands':0}
 with (H/'ALIAS.json').open('x') as f:json.dump(out,f,sort_keys=True,indent=2);f.write('\n')
 print(json.dumps({'alias_sha256':out['alias_sha256'],'bytes':out['alias_bytes'],'mode':out['alias_mode']}))
if __name__=='__main__':main()
