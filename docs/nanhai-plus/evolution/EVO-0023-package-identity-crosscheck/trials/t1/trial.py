#!/usr/bin/env python3
import hashlib,json,pathlib,sys
B=pathlib.Path('docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001')
def read(path):
 p=B/path
 return json.loads(p.read_text()),{'path':str(p),'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
prior,prior_ref=read('g287-tiktoklite-peer-postrun-v1/ROOT-ACCEPTANCE.json')
freeze,freeze_ref=read('g288-tiktoklite-hyphen-official-raw-candidate-v2/PREPARE.json')
registry,registry_ref=read('upstream-apk-registry-v1/REGISTRY.json')
runner=B/'g284-elementx-github-raw-candidate-v3/run.py';runner_bytes=runner.read_bytes()
row=[x for x in registry['records'] if x.get('id')=='r-52d5e188c88dfba15c98']
assert len(row)==1 and row[0]['package']=='io.element.android.x'
assert b'need(row["package"] == "io.element.android.x"' in runner_bytes
cases=[{'case':'G288_before_GET','product':'TikTok Lite','prior_observed_package':prior['observed_apk']['manifest_package'],'frozen_expected_package':freeze['expected_package'],'decision':'CONFLICT_HOLD_TARGET_AND_OPEN_DISTINCT_PACKAGE_REVIEW' if prior['observed_apk']['manifest_package']!=freeze['expected_package'] else 'MATCH_CONTINUE','prior_sha256':prior_ref['sha256'],'freeze_sha256':freeze_ref['sha256']},{'case':'G284_before_GET','product':'Element X','prior_registered_package':row[0]['package'],'frozen_runner_expected_package':'io.element.android.x','decision':'MATCH_CONTINUE','registry_sha256':registry_ref['sha256'],'runner_sha256':hashlib.sha256(runner_bytes).hexdigest()}]
assert cases[0]['decision'].startswith('CONFLICT') and cases[1]['decision']=='MATCH_CONTINUE'
print(json.dumps({'status':'LOCAL_REPLAY_PASS','cases':cases,'network_requests':0,'apk_get':0,'ssh':0,'chmod':0,'graph':0,'device':0,'container':0,'canonical_edits':0},sort_keys=True))
