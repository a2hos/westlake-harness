#!/usr/bin/env python3
"""Metadata-only G290 candidate checks; no network, APK scan, or count edit."""
import hashlib
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
BASE=HERE.parent
def load(rel):return json.loads((BASE/rel).read_text())
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def need(ok,name):
    if not ok:raise RuntimeError(name)
    return name

def main():
    v=json.loads((HERE/'VERIFICATION.json').read_text())
    g288=load('g288-tiktoklite-hyphen-official-raw-candidate-v2/RESULT.json')
    g287=load('g287-tiktoklite-official-raw-candidate-v1/RESULT.json')
    root288=load('g288-tiktoklite-hyphen-official-raw-candidate-v2/ROOT-TERMINAL-ACCEPTANCE.json')
    scout=load('g288-tiktok-lite-go-source-scout-v1/RESULT.json')
    reg=load('upstream-apk-registry-v1/REGISTRY.json')
    exact='https://sf16-va.tiktokcdn.com/obj/eden-va2/lapshyasbrvarpa_kpvykuh_jnb/ljhwZthlaukjlkulzlp/US/Lite/TikTok-Lite_360961.apk'
    cases=[]
    cases.append(need(v['status']=='EXACT_BYTE_RAW_SUPPLEMENT_CANDIDATE_READY_FOR_PEER' and
        v['apk']['sha256']=='37b528ba36ebcb1e6d4f642d144c5446352b5d19abebea7504e3654b9882b9f0',
        'EXACT_BYTES_LOCAL_VERIFICATION'))
    cases.append(need(g288['status']=='TERMINAL_FAILED' and g288['error']=='package mismatch' and
        root288['count_delta']['accepted_raw']==0, 'G288_FAILURE_NOT_RELABELED'))
    cases.append(need(g288['official_lite_card']['link']==exact and
        g288['official_page_exact_apk_link']==exact and scout['official_channel']['exact_apk_url']==exact,
        'EXACT_OFFICIAL_PAGE_CARD_CDN_CHAIN'))
    cases.append(need(g288['page_transfer']['http']=='200' and g288['page_transfer']['tls']=='0' and
        g288['head_transfer']['http']=='200' and g288['head_transfer']['tls']=='0' and
        g288['head']['content_length']==48413684 and
        g288['download_transfer']['http']=='200' and g288['download_transfer']['tls']=='0' and
        g288['download_transfer']['bytes']=='48413684', 'G288_PAGE_HEAD_GET_RC_TLS_BYTES'))
    cases.append(need(g287['apk']['sha256']!=v['apk']['sha256'] and
        "name='com.tiktok.lite.go'" in g287['manifest']['package'] and
        v['manifest']['package']=='com.tiktok.lite.go' and
        g287['raw_accepted'] is False, 'G287_SAME_PACKAGE_DIFFERENT_FAILED_ARTIFACT'))
    cases.append(need(v['zip']['lib_abis']==['arm64-v8a','armeabi-v7a'] and
        v['manifest']['version_code']=='360961' and v['manifest']['version_name']=='36.9.61',
        'MIXED_ABI_ACTUAL_IDENTITY'))
    cases.append(need(not any(x.get('package') in ('com.tiktok.lite.go','com.zhiliaoapp.musically.go') for x in reg['records']),
        'FROZEN_REGISTRY_NO_LITE_DUPLICATE'))
    cases.append(need(scout['product']['actual_package']=='com.tiktok.lite.go' and
        scout['product']['play_url'].endswith('id=com.tiktok.lite.go') and
        'com.zhiliaoapp.musically.go' not in scout['product']['play_url'],
        'ACTUAL_PLAY_PACKAGE_NOT_CONFUSED'))
    cases.append(need(v['signature']['publisher_certificate_anchor'] is None and
        g288['publisher_artifact_digest'] is None and not v['blackbox_qualified'] and
        not v['startup_proven'], 'NO_UNSUPPORTED_PUBLISHER_OR_RUNTIME_CLAIM'))
    out={'schema':'g290-tiktok-lite-go-metadata-fixture-v1','status':'PASS',
         'cases':cases,'verification_sha256':sha(HERE/'VERIFICATION.json'),
         'source_scout_sha256':sha(BASE/'g288-tiktok-lite-go-source-scout-v1/RESULT.json'),
         'network_requests':0,'apk_get':0,'device_commands':0,'container_commands':0,
         'canonical_edits':0,'count_delta':0}
    with (HERE/'FIXTURE.json').open('x') as f:json.dump(out,f,indent=2);f.write('\n')
    print(json.dumps({'status':out['status'],'cases':len(cases)}))

if __name__=='__main__':main()
