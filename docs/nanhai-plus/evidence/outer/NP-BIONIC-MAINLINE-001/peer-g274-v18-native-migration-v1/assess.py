#!/usr/bin/env python3
import hashlib,json,os,sys
from pathlib import Path
root=Path(os.environ['NANHAI_PROJECT_ROOT']); b=root/'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest(); rd=lambda p:json.loads(p.read_text())
paths={
 'env':root/'local_env.md',
 'g274_review':b/'g274-v18-stock-input-peer-review-v1/REVIEW.json',
 'g274_candidate':b/'g274-v18-stock-input-candidate-v1/INPUT-CANDIDATE.json',
 'g274_admission':b/'g274-v18-stock-input-candidate-v1/root-input-admission-v1/ADMISSION.json',
 'g278_receipt':b/'g278-soong-native-worktree-v1/RECEIPT.json',
 'g278_result':b/'g278-soong-native-worktree-v1/HOST-TOOL-RESULT.json',
 'g278_review':b/'g278-soong-native-worktree-v1/host-tool-actual-peer-v1/REVIEW.json',
 'g18_review':b/'stock-bionic-target-graph-v18-independent-review-v1/REVIEW.json',
 'v18_packet':b/'stock-bionic-target-graph-v18-full-candidate-v2/PACKET-CANDIDATE.json',
 'v18_static':b/'stock-bionic-target-graph-v18-full-candidate-v2/STATIC-CHECK.json',
 'v18_material':b/'stock-bionic-target-graph-v18-full-candidate-v2/MATERIALIZATION.json',
 'v18_ready':b/'stock-bionic-target-graph-v18-full-candidate-v2/READY.json'}
assert all(p.is_file() for p in paths.values())
env=paths['env'].read_text(); g274=rd(paths['g274_candidate']); g274ready=rd(b/'g274-v18-stock-input-candidate-v1/READY.json'); adm=rd(paths['g274_admission']); g278=rd(paths['g278_result']); g18=rd(paths['g18_review']); static=rd(paths['v18_static']); mat=rd(paths['v18_material']); ready=rd(paths['v18_ready'])
checks={
 'no_container_policy':'"NANHAI_CONTAINER_POLICY": "forbidden"' in env and '"NANHAI_BUILD_EXECUTION_MODE": "host-native"' in env,
 'g274_input_only':g274['graph_executed'] is False and g274['target_compiled'] is False and adm['status']=='ROOT_ADMIT_G274_V18_INPUT_ONLY_NOT_EXECUTION',
 'g274_materializer_pending':adm.get('v17b_materializer_compatible') is False and adm.get('v18_materializer_independent_review') is False,
 'g278_host_tool_only':g278['ssh_batchmode_rc']==0 and g278['build_rc']==0 and g278['graph_commands']==0 and g278['target_compile_commands']==0,
 'g278_generated_actions_unknown':any('generated Ninja actions may still embed nsjail' in x for x in rd(paths['g278_receipt'])['limits']),
 'v18_not_released':g18['decision']=='PASS_STATIC_EXTENSION_ONLY_DO_NOT_DISPATCH_OR_EXECUTE' and static['status']=='STATIC_CANDIDATE_ONLY_NOT_RELEASED' and static['root_seal'] is False,
 'v18_allowlist_materialized':len(mat['readonly_root_mounts'])==38 and ready['new_roots']==9,
 'current_bionic_not_ready':'"NANHAI_BIONIC_BUILD_READY": "false"' in env}
out={'schema':'peer-g274-v18-native-migration-readiness-v1','decision':'NO_GO_NO_LOCAL_EXECUTABLE_NATIVE_PATH' if all(checks.values()) else 'CHECK_FAILED','checks':checks,'all_checks_pass':all(checks.values()),'inputs':{k:{'path':str(p.relative_to(root)),'sha256':sha(p)} for k,p in paths.items()},'observed':{'g274_source_roots':g274ready['nine_exact_source_roots'],'v18_allowlist_roots':len(mat['readonly_root_mounts']),'v18_new_source_roots':ready['new_roots'],'g278_source_view_links':g278['source_view_links']},'minimum_falsifier':{'name':'native_source_view_and_host_tool_falsifier','pass_condition':'Fresh Linux x86_64 receipt proves every v18 allowlist root resolves to registered exact source entries, patched soong_ui build rc0, execve has no forbidden executor, and generated actions have no nsjail/container/namespace invocation.','fail_condition':'Any missing root/hash/tree, unresolved symlink, non-Linux host, forbidden generated action, or absent fresh owner/host receipt => NO_GO; do not dispatch graph.'},'missing_inputs':['reachable authenticated Linux x86_64 host; G278 host receipt is historical and current route NO_GO','fresh owner ACK and non-replayed release packet','v18 materializer independent review and root seal (current root_seal=false)','proof generated Ninja actions avoid nsjail/container/namespace','fresh isolated OUT/TMP capacity and target toolchain/sysroot/CRT provenance'],'migration_design':['Preserve G274 nine-root and v18 allowlist as read-only source manifest.','Resolve NANHAI_SOURCE_POOL_ROOT-relative roots into an isolated native source view; verify HEAD/tree/blob and symlinks before materialization.','Apply the reviewed two sandbox switches only in a project worktree; build soong_ui as host tool, capture execve, inspect generated actions.','Freeze OUT/TMP, run one graph-only preflight, release only after owner ACK, fresh host identity, exact input hashes, and no forbidden executor.'],'command_rc':0,'graph_commands':0,'target_compile_commands':0,'container_commands':0,'namespace_commands':0,'device_commands':0,'bridge_commands':0}
print(json.dumps(out,sort_keys=True,indent=2)); sys.exit(0 if out['all_checks_pass'] else 2)
