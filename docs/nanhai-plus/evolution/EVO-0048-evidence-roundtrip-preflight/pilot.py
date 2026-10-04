#!/usr/bin/env python3
"""Bounded, read-only evidence round-trip pilot; no candidate execution."""
import hashlib, json, pathlib
ROOT=pathlib.Path(__file__).resolve().parents[4]
E=ROOT/'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001'
def digest(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
v3=E/'g279-private-mihomo-v2b-local-candidate-v3'
m=json.loads((v3/'MOCK-ORACLE.json').read_text()); event=m['normalized_route_event']
raw=(v3/'MOCK-STDOUT.raw').read_bytes()
lines=[line for line in raw.splitlines() if b'[TCP]' in line and b' --> ' in line]
assert len(lines)==1
mock_line_sha_ok=hashlib.sha256(lines[0]).hexdigest()==event['raw_line_sha256']
event_sha_ok=hashlib.sha256(json.dumps(event,sort_keys=True,separators=(',',':')).encode()).hexdigest()==m['normalized_route_event_sha256']
# The real postrun would retain event only; timestamp/full line are not exported.
postrun_line_reconstructible='timestamp' in event or 'whitelisted_raw_line' in event
steam=E/'blackbox-steam-chat-official-intake-candidate-v1'
handoff=json.loads((steam/'HANDOFF.json').read_text())
apk=ROOT/'.nanhai-plus-runtime/bionic-oh7-aosp16/staging/blackbox-steam-chat-official-intake-candidate-v1/steam-chat.apk'
result={'schema':'evo48-evidence-roundtrip-pilot-v1','inputs':{
 'v2b_v1_review_sha256':digest(E/'g279-private-mihomo-v2b-local-candidate-v1/peer-review-v1/REVIEW.json'),
 'v2b_v2_review_sha256':digest(E/'g279-private-mihomo-v2b-local-candidate-v2/peer-review-v1/REVIEW.json'),
 'v2b_v3_review_sha256':digest(v3/'peer-review-v1/REVIEW.json'),
 'v2b_v3_mock_oracle_sha256':digest(v3/'MOCK-ORACLE.json'),
 'steam_raw_review_sha256':digest(steam/'independent-raw-review-v1/REVIEW.json'),
 'steam_qualification_review_sha256':digest(steam/'blackbox-qualification-peer-v1/REVIEW.json')},
 'checks':{'v3_mock_raw_line_sha_recomputed':mock_line_sha_ok,
 'v3_mock_event_sha_recomputed':event_sha_ok,
 'v3_real_postrun_raw_line_reconstructible_from_export':postrun_line_reconstructible,
 'steam_apk_present':apk.exists(),
 'steam_apk_sha_recomputed':apk.exists() and digest(apk)==handoff['sha256']},
 'decision':'PILOT_SIGNAL_ONLY_NO_PROMOTION','count_delta':0,'device_commands':0,'container_commands':0}
print(json.dumps(result,sort_keys=True,indent=2))
