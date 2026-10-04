#!/usr/bin/env python3
"""Offline pilot of one proposed pre-dispatch evidence gate; never invokes scan."""
import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).parent
ROOT = Path.cwd()

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()

def load():
    frozen = json.loads((HERE/'INPUTS.json').read_text())
    result = {}
    for key in ('hello_h1_h4','upstream_four_root','scanner_135_readiness','teamviewer_root'):
        rel, expected = frozen[key]
        p = ROOT/rel
        if sha(p) != expected: raise ValueError('input SHA drift: '+key)
        result[key] = json.loads(p.read_text())
    return result

def gate(index):
    if not isinstance(index, dict): return 'BLOCK_NO_TARGET_RUNTIME_INDEX'
    if index.get('target_abi') != 'arm64-v8a' or not index.get('source_r4_verified'):
        return 'BLOCK_RUNTIME_IDENTITY'
    bid = index.get('build_id')
    for key in ('ordered_bcp_sha256','bridge_elf_sha256','system_elf_sha256'):
        rows = index.get(key)
        if not isinstance(rows, list) or not rows or any(not isinstance(v,str) or len(v)!=64 for v in rows):
            return 'BLOCK_INCOMPLETE_'+key.upper()
    if not isinstance(bid,str) or not bid or index.get('bcp_build_id') != bid or index.get('bridge_build_id') != bid or index.get('system_build_id') != bid:
        return 'BLOCK_MIXED_BUILD_PROVENANCE'
    if not isinstance(index.get('runtime_lock_id'),str) or not index['runtime_lock_id'].startswith('sha256:'):
        return 'BLOCK_NO_RUNTIME_LOCK'
    return 'CONTRACT_READY_NOT_RUNTIME_PROVEN'

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--case',choices=['current','synthetic_complete','historical_empty_system'],default='current')
    args=ap.parse_args()
    x=load()
    assert x['hello_h1_h4']['decision']=='GO_LOCAL_STATIC_FIXTURE_ONLY_NO_GO_REMOTE_OR_GRAPH'
    assert x['upstream_four_root']['raw_delta']==4 and x['upstream_four_root']['full_static_delta']==4 and x['upstream_four_root']['cold_start_delta']==0
    assert x['scanner_135_readiness']['decision']=='INVENTORY_READY_RUNTIME_RESOLUTION_BLIND' and x['scanner_135_readiness']['runtime_scans_executed']==0
    assert x['teamviewer_root']['decision']=='ACCEPT_OFFICIAL_RAW_FOUR_PHASE_HOST_STATIC_AND_BOUNDED_BLACKBOX_TEST_INPUT_ONLY' and x['teamviewer_root']['cold_start_delta']==0
    if args.case=='current': idx=None
    else:
        h='a'*64
        idx={'target_abi':'arm64-v8a','source_r4_verified':True,'build_id':'synthetic-build',
             'bcp_build_id':'synthetic-build','bridge_build_id':'synthetic-build','system_build_id':'synthetic-build',
             'ordered_bcp_sha256':[h],'bridge_elf_sha256':[h],'system_elf_sha256':[h],
             'runtime_lock_id':'sha256:'+h}
        if args.case=='historical_empty_system': idx['system_elf_sha256']=[]
    decision=gate(idx)
    print(json.dumps({'schema':'evo62-runtime-scan-evidence-gate-pilot-v1','case':args.case,
        'decision':decision,'input_manifest_sha256':sha(HERE/'INPUTS.json'),
        'runtime_scan_commands':0,'device_commands':0,'container_commands':0,
        'claim':'Synthetic complete case tests contract shape only, not a real runtime index.'},sort_keys=True))
    return 0 if ((args.case=='current' and decision=='BLOCK_NO_TARGET_RUNTIME_INDEX') or
                 (args.case=='synthetic_complete' and decision=='CONTRACT_READY_NOT_RUNTIME_PROVEN') or
                 (args.case=='historical_empty_system' and decision=='BLOCK_INCOMPLETE_SYSTEM_ELF_SHA256')) else 2

if __name__=='__main__': raise SystemExit(main())
