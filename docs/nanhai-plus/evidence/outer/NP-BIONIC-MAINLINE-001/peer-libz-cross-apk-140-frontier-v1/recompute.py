#!/usr/bin/env python3
"""Read-only lower-bound libz DT_NEEDED cohort from frozen accepted receipts."""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path.cwd()
BASE = ROOT/'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001'
HERE = Path(__file__).parent
LOCK = BASE/'g339-cross-apk-exposure-cohort-v2/LOCK.json'
CHECKPOINT = ROOT/'docs/nanhai-plus/checkpoints/20261004-raw140-static140-blackbox29-upstream99-evo62/CHECKPOINT.json'
NEW = {
    'sg.bigo.live': ('bigo-four-static-v1','bigo-root-admission-v1/ROOT-STATIC-ADMISSION.json'),
    'cn.xender': ('xender-four-static-v1','xender-root-admission-v1/ROOT-STATIC-ADMISSION.json'),
    'com.tencent.ig': ('pubgm-four-static-v1','pubgm-root-admission-v1/ROOT-STATIC-ADMISSION.json'),
    'com.imo.android.imoim': ('imo-four-static-v1','imo-root-admission-v1/ROOT-STATIC-ADMISSION.json'),
    'com.imo.android.imous': ('imo-lite-four-static-v1','imo-lite-root-admission-v1/ROOT-STATIC-ADMISSION.json'),
    'com.teamviewer.quicksupport.market': ('teamviewer-qs-four-static-v1','teamviewer-qs-root-admission-v1/ROOT-ADMISSION.json'),
}

def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest()

def edges(rows):
    return [r for r in rows if isinstance(r,dict) and r.get('abi')=='arm64-v8a'
            and r.get('machine')=='AArch64' and 'libz.so' in r.get('needed',[])]

cp=json.loads(CHECKPOINT.read_text())
assert cp['raw_accepted']==cp['full_host_static_accepted']==140
lock=json.loads(LOCK.read_text())
assert lock['count']==len(lock['identities'])==105
cohort=[]
reviewed=[]
all_hit_shas=set()
for item in lock['identities']:
    receipt=ROOT/item['root_receipt']['path']
    assert sha(receipt)==item['root_receipt']['sha256']
    if 'inputs' in item:
        p=BASE/item['inputs']['elf']
        assert sha(p)==item['inputs']['elf_sha256']
        if item.get('native_elf_ref'):
            ref=item['native_elf_ref']
            p=ROOT/ref['path']
            assert sha(p)==ref['sha256']
        rows=json.loads(p.read_text())
        inventory_sha=sha(p)
    else:
        ref=item['split_aggregate_ref']
        p=ROOT/ref['path']
        assert sha(p)==ref['sha256']
        facts=[v for v in json.loads(p.read_text())['facts'] if v['package']==item['package']]
        assert len(facts)==1
        files={sha(q):q for q in (BASE/'harness-stock-inventory-batch12-v3-candidate/member-trials').glob('*/ELF-RECORD.json')}
        rows=[]
        for member in facts[0]['native_member_receipts']:
            q=files[member['record_sha256']]
            rows.append(json.loads(q.read_text()))
        inventory_sha=sha(p)
    hit=edges(rows)
    all_hit_shas.update(r['sha256'] for r in hit)
    reviewed.append(item['package'])
    if hit: cohort.append({'package':item['package'],'group':'frozen105','elf_edges':len(hit),
                           'distinct_elf_sha256':len({r['sha256'] for r in hit}),
                           'elf_inventory_sha256':inventory_sha,'root_receipt_sha256':sha(receipt)})

for package,(static_dir,receipt_rel) in NEW.items():
    p=BASE/('peer-'+static_dir)/'ELF-INVENTORY.json'
    d=BASE/('peer-'+static_dir)/'DEX-INVENTORY.json'
    receipt=BASE/('peer-'+receipt_rel)
    rows=json.loads(p.read_text())
    dex=json.loads(d.read_text())
    root=json.loads(receipt.read_text())
    hit=edges(rows)
    all_hit_shas.update(r['sha256'] for r in hit)
    assert hit and root.get('decision','').startswith('ACCEPT')
    assert package not in reviewed
    cohort.append({'package':package,'group':'post105_root_accepted','elf_edges':len(hit),
                   'distinct_elf_sha256':len({r['sha256'] for r in hit}),
                   'elf_inventory_sha256':sha(p),'dex_inventory_sha256':sha(d),
                   'dex_inventory_entries':len(dex) if isinstance(dex,list) else len(dex.get('dex_entries',[])),
                   'root_receipt_sha256':sha(receipt)})
    reviewed.append(package)

source=Path('/opt/19.SourceCode/AOSP-16.0.0_r4/android-source/zlib')
head=subprocess.run(['git','-C',str(source),'rev-parse','HEAD'],capture_output=True,text=True,check=True).stdout.strip()
status=subprocess.run(['git','-C',str(source),'status','--porcelain=v1','--untracked-files=all'],capture_output=True,text=True,check=True).stdout
assert head=='a6f47e8bd7c1ba412c4b5a3539aa77fe628d0172' and not status
bp=source/'Android.bp'
ledger=BASE/'g279-native-graph-source-choice-v1/MANIFEST-HEADS.tsv'
assert 'external/zlib\tplatform/external/zlib\trefs/tags/android-16.0.0_r4\t'+head in ledger.read_text()
assert 'cc_library {\n    name: "libz"' in bp.read_text()

out={'schema':'peer-libz-140-accepted-subset-frontier-v1','decision':'HOST_STATIC_LOWER_BOUND_ONLY',
     'checkpoint_sha256':sha(CHECKPOINT),'frozen105_lock_sha256':sha(LOCK),
     'accepted_total':140,'reviewed_distinct_package_labels':len(set(reviewed)),
     'reviewed_identity_scope':'105 frozen accepted package labels plus six disjoint later root-admitted labels; remaining 29 accepted artifacts not independently enumerated here',
     'cohort_packages_lower_bound':len(cohort),'cohort_elf_edges':sum(r['elf_edges'] for r in cohort),
     'cohort_distinct_elf_sha256':len(all_hit_shas),'rows':sorted(cohort,key=lambda r:r['package']),
     'source':{'manifest_path':'external/zlib','tag':'android-16.0.0_r4','head':head,
               'manifest_ledger_sha256':sha(ledger),'android_bp_sha256':sha(bp),
               'module':'cc_library name libz','worktree_clean':True},
     'provider_observed':False,'loader_failure_observed':False,
     'device_commands':0,'container_commands':0,'bridge_actions':0}
(HERE/'COHORT.json').write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
print(json.dumps({k:out[k] for k in ('accepted_total','reviewed_distinct_package_labels','cohort_packages_lower_bound','cohort_elf_edges')},sort_keys=True))
