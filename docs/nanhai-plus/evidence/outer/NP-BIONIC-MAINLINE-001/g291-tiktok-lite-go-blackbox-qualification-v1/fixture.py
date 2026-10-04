#!/usr/bin/env python3
"""Local receipt consistency only: no network, APK GET, device or count edit."""
import hashlib
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
BASE=HERE.parent
def read(path):return json.loads(path.read_text())
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def need(ok,label):
    if not ok:raise ValueError(label)
    return label

def main():
    c=read(HERE/'CANDIDATE.json')
    rootpath=BASE/'g290-tiktok-lite-go-raw-supplement-v1/ROOT-RAW-INTAKE.json'
    root=read(rootpath)
    scoutpath=BASE/'g288-tiktok-lite-go-source-scout-v1/RESULT.json'
    scout=read(scoutpath)
    cases=[]
    cases.append(need(sha(rootpath)==c['criteria']['legal_original_package_and_version']['root_raw_receipt_sha256'],
                      'ROOT_G290_SHA_PIN'))
    cases.append(need(root['decision']=='ACCEPT_ONE_SEPARATE_OFFICIAL_CHANNEL_OBSERVED_SUPPLEMENTAL_RAW_APK' and
                      root['package']==c['actual_identity']['package'] and
                      root['payload']['sha256']==c['actual_identity']['apk_sha256'], 'ROOT_EXACT_RAW_IDENTITY'))
    cases.append(need(sha(scoutpath)==c['criteria']['blackbox_source_availability']['scout_sha256'] and
                      scout['product']['actual_package']=='com.tiktok.lite.go', 'SOURCE_SCOUT_EXACT_PACKAGE'))
    cases.append(need('id=com.tiktok.lite.go' in c['criteria']['overseas_use_and_market']['primary_url'] and
                      'not a measured U.S.-only' in c['criteria']['overseas_use_and_market']['candidate_evidence'],
                      'PLAY_BUCKET_NOT_US_ONLY'))
    cases.append(need(c['actual_identity']['publisher_published_apk_sha256'] is None and
                      c['actual_identity']['publisher_published_certificate_anchor'] is None,
                      'NO_INVENTED_PUBLISHER_ANCHOR'))
    cases.append(need(c['count_effect']=={'qualified_blackbox_delta':0,'raw_delta':0,'cold_start_delta':0} and
                      c['status'].endswith('NOT_COUNTED'), 'NO_COUNT_OR_STARTUP_CLAIM'))
    out={'schema':'g291-tiktok-lite-go-qualification-fixture-v1','status':'PASS','cases':cases,
         'candidate_sha256':sha(HERE/'CANDIDATE.json'),'root_raw_sha256':sha(rootpath),
         'source_scout_sha256':sha(scoutpath),'network_requests':0,'device_commands':0,
         'container_commands':0,'canonical_edits':0}
    with (HERE/'FIXTURE.json').open('x') as f:json.dump(out,f,indent=2);f.write('\n')
    print(json.dumps({'status':'PASS','cases':len(cases)}))

if __name__=='__main__':main()
