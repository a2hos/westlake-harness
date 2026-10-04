#!/usr/bin/env python3
"""Negative suffix contract: identical raw bytes produce different metadata branch."""
import hashlib,json,os,pathlib,sys
R=pathlib.Path(os.environ['NANHAI_PROJECT_ROOT']);H=pathlib.Path(__file__).parent
O=R/'.nanhai-plus-runtime/bionic-oh7-aosp16/staging/apk-stock-intake-v7/org.sufficientlysecure.keychain/body.raw'
A=R/'.nanhai-plus-runtime/bionic-oh7-aosp16/staging/g326-openkeychain-v2/OpenKeychain.apk'
sys.path.insert(0,str(R/'harness'))
from westlake_gap import scanner
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 assert not (H/'FIXTURE.json').exists()
 alias=json.loads((H/'ALIAS.json').read_text())
 assert alias['original_sha256']==alias['alias_sha256']==sha(O)==sha(A)
 old=scanner.apk_metadata(O);new=scanner.apk_metadata(A)
 checks={'raw_rejected_by_suffix':old.get('manifest_available') is False and old.get('package')=='body','apk_manifest_accepted':new.get('manifest_available') is True and new.get('package')=='org.sufficientlysecure.keychain','same_bytes':old.get('bytes')==new.get('bytes')==12043256 and old.get('sha256')==new.get('sha256')==alias['alias_sha256'],'version':new.get('version_name')=='6.0.4' and str(new.get('version_code'))=='60400','target_sdk':str(new.get('target_sdk'))=='34'}
 out={'schema':'g326-openkeychain-suffix-fixture-v2','checks':checks,'raw_metadata':old,'apk_metadata':new,'alias_receipt_sha256':sha(H/'ALIAS.json'),'scanner_sha256':sha(R/'harness/westlake_gap/scanner.py'),'rc':0 if all(checks.values()) else 2}
 with (H/'FIXTURE.json').open('x') as f:json.dump(out,f,sort_keys=True,indent=2);f.write('\n')
 print(json.dumps({'checks':checks,'rc':out['rc']},sort_keys=True));return out['rc']
if __name__=='__main__':sys.exit(main())
