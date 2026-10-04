#!/usr/bin/env python3
"""Read-only four-case APK capacity projection, not a canonical ledger."""
import hashlib,json,re
from pathlib import Path
H=Path(__file__).resolve().parent
B=H.parents[1]/'evidence/outer/NP-BIONIC-MAINLINE-001'
def load(rel):
 p=B/rel; raw=p.read_bytes(); return json.loads(raw),{'path':str(p.relative_to(H.parents[1])),'sha256':hashlib.sha256(raw).hexdigest()}
vy_raw,vy_raw_src=load('g311-vyprvpn-official-intake-v1/root-raw-admission-v1/ROOT-RAW-ADMISSION.json')
vy_qual,vy_qual_src=load('g311-vyprvpn-blackbox-qualification-candidate-v1/root-admission-v1/ROOT-ADMISSION.json')
brave,brave_src=load('g314-brave-official-raw-candidate-v1/root-raw-admission-v1/ROOT-RAW-ADMISSION.json')
wa,wa_src=load('g312-whatsapp-official-raw-candidate-v1/RESULT.json')
wa_badging=B/'g312-whatsapp-official-raw-candidate-v1/badging.stdout.raw'
wa_pkg=re.search(r"package: name='([^']+)'",wa_badging.read_text()).group(1)
telegram=B/'g313-telegram-official-raw-candidate-v1/apk-headers.raw'
tele_headers=telegram.read_text()
assert 'HTTP/1.1 500 Internal Server Error' in tele_headers
assert vy_raw['package']==vy_qual['package'] and vy_raw['apk_sha256']==vy_qual['apk_sha256']
assert vy_raw['raw_delta']==1 and vy_qual['qualified_delta']==1
assert brave['raw_delta']==1 and brave['blackbox_qualification_delta']==0
assert wa_pkg=='com.whatsapp' and wa['raw_admission_delta']==0
rows=[{'package':vy_raw['package'],'state':'raw_and_blackbox_qualified','new_raw_slots':1,'new_blackbox_slots':1,'sources':[vy_raw_src,vy_qual_src]}, {'package':brave['package'],'state':'raw_only','new_raw_slots':1,'new_blackbox_slots':0,'sources':[brave_src]}, {'package':wa_pkg,'state':'existing_package_version_candidate','new_raw_slots':0,'new_blackbox_slots':0,'sources':[wa_src,{'path':str(wa_badging.relative_to(H.parents[1])),'sha256':hashlib.sha256(wa_badging.read_bytes()).hexdigest()}]}, {'package':'org.telegram.messenger','state':'download_http_500_no_apk','new_raw_slots':0,'new_blackbox_slots':0,'sources':[{'path':str(telegram.relative_to(H.parents[1])),'sha256':hashlib.sha256(telegram.read_bytes()).hexdigest()}]}]
assert len({r['package'] for r in rows})==4
out={'schema':'evo38-four-case-capacity-projection-v1','rows':rows,'projected_new_raw_slots':sum(r['new_raw_slots'] for r in rows),'projected_new_blackbox_slots':sum(r['new_blackbox_slots'] for r in rows),'cold_start_slots':0,'scope':'local four-case projection only; root receipts retain authority; no canonical count change'}
assert out['projected_new_raw_slots']==2 and out['projected_new_blackbox_slots']==1
(H/'OBSERVATIONS.json').write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n')
print(json.dumps({k:out[k] for k in ('projected_new_raw_slots','projected_new_blackbox_slots','cold_start_slots')}))
