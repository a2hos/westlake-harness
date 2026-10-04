#!/usr/bin/env python3
"""Generate deterministic synthetic H1-H4 fixtures and record local command receipts."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timezone

HERE = Path(__file__).parent
TOOL = HERE / 'preflight_packet.py'
FIX = HERE / 'fixtures'
FIX.mkdir(exist_ok=True)

def ident(name):
    return {'path': '/exact-r4/' + name, 'sha256': hashlib.sha256(name.encode()).hexdigest()}

positive = {
    'schema': 'nanhai-native-r4-readonly-preflight-fixture-v1',
    'authorization': {'goal_id': 'goal_01', 'claim': 'NP-MUSL16-ART-024',
                      'operation': 'read_only_preflight', 'one_use': True,
                      'nonce': '4e680afdb81d4c43a42e69a3397f2d19',
                      'nonce_freshness_ledger_checked': True,
                      'host_key_sha256': hashlib.sha256(b'synthetic_host_key').hexdigest()},
    'host': {'os': 'Linux', 'arch': 'x86_64', 'project_scoped': True,
             'authenticated': True, 'host_key_pinned': True, 'uid': 1000,
             'host_key_sha256': hashlib.sha256(b'synthetic_host_key').hexdigest()},
    'source': {'tag': 'android-16.0.0_r4', 'manifest_sha256': hashlib.sha256(b'synthetic_manifest').hexdigest(),
               'linux_projects': 1011, 'darwin_prebuilts_absent': 2,
               'all_heads_match': True, 'tracked_clean': True, 'untracked_clean': True,
               'bionic_commit': 'f22516cbc67e81c13cf943ce02f01b8929a98726',
               'bionic_full_checkout': True, 'soong_worktree_sha256': hashlib.sha256(b'synthetic_soong').hexdigest(),
               'sandbox_off_patch_pinned': True},
    'tools': {**{n: ident(n) for n in ('soong_ui','go','build_tools','clang','ld_lld','resource_dir','sysroot')},
              'clang_revision': 'clang-r563880c',
              'clang_source_commit': '9916fb51ccb914d62d35ad9a7b9b21d2ef046928',
              'target': 'aarch64-linux-android', 'candidate_toolchain_verified': True,
              'post_graph_action_readback_required': True},
    'boundary': {'source_root': '/exact-r4/source', 'project_root': '/project/opaleye',
                 'out_root': '/project/opaleye/out/new', 'tmp_root': '/project/opaleye/tmp/new',
                 'source_read_only_for_build_uid': True, 'out_tmp_new_generation': True,
                 'container_observed': False, 'namespace_observed': False,
                 'planned_argv': ['/project/opaleye/out/soong_ui', '--make-mode', '--soong-only', '--skip-ninja', '--skip-soong-tests', 'libc', 'libm', 'libdl', 'linker'],
                 'post_execution_trace_required': True}
}

cases = {'positive': (positive, 0, None)}
def negative(name, edit, door):
    x = copy.deepcopy(positive)
    edit(x)
    cases[name] = (x, 2, door)

negative('old_nonce', lambda x: x['authorization'].update(nonce='6f324a6cb4e1a5fe8ec594334c61d079'), 'H1_AUTH_HOST')
negative('host_key_mismatch', lambda x: x['host'].update(host_key_sha256='0'*64), 'H1_AUTH_HOST')
negative('host_key_unpinned', lambda x: x['host'].update(host_key_pinned=False), 'H1_AUTH_HOST')
negative('authorization_missing', lambda x: x['authorization'].update(one_use=False), 'H1_AUTH_HOST')
negative('source_incomplete', lambda x: x['source'].update(linux_projects=1010), 'H2_EXACT_R4_SOURCE')
negative('sysroot_missing', lambda x: x['tools'].pop('sysroot'), 'H3_TOOLCHAIN')
negative('post_graph_obligation_missing', lambda x: x['tools'].update(post_graph_action_readback_required=False), 'H3_TOOLCHAIN')
negative('container_observed', lambda x: x['boundary'].update(container_observed=True), 'H4_OUTPUT_EXEC_BOUNDARY')
negative('namespace_observed', lambda x: x['boundary'].update(namespace_observed=True), 'H4_OUTPUT_EXEC_BOUNDARY')
negative('namespace_launcher', lambda x: x['boundary']['planned_argv'].insert(0, 'unshare'), 'H4_OUTPUT_EXEC_BOUNDARY')
negative('output_overlap', lambda x: x['boundary'].update(out_root='/exact-r4/source/out'), 'H4_OUTPUT_EXEC_BOUNDARY')
negative('traversal_output', lambda x: x['boundary'].update(out_root='/project/opaleye/out/../source'), 'H4_OUTPUT_EXEC_BOUNDARY')

def sha(data): return hashlib.sha256(data).hexdigest()
results = []
for name, (fixture, want_rc, want_failure) in cases.items():
    f = FIX / (name + '.json')
    f.write_text(json.dumps(fixture, indent=2, sort_keys=True) + '\n')
    argv = [sys.executable, str(TOOL), '--fixture', str(f)]
    p = subprocess.run(argv, capture_output=True)
    (HERE / (name + '.stdout.raw')).write_bytes(p.stdout)
    (HERE / (name + '.stderr.raw')).write_bytes(p.stderr)
    parsed = json.loads(p.stdout)
    assert p.returncode == want_rc and parsed.get('first_failure') == want_failure
    results.append({'name': name, 'argv': argv, 'rc': p.returncode, 'input_sha256': sha(f.read_bytes()),
                    'stdout_sha256': sha(p.stdout), 'stderr_sha256': sha(p.stderr),
                    'first_failure': parsed.get('first_failure'), 'decision': parsed['decision']})

for name, extra, want_rc, decision in [('default_dry_run', [], 0, 'DRY_RUN_ONLY'),
                                      ('execute_rejected', ['--execute'], 4, 'NO_GO_REMOTE_EXECUTION_NOT_IMPLEMENTED')]:
    argv = [sys.executable, str(TOOL), *extra]
    p = subprocess.run(argv, capture_output=True)
    (HERE / (name + '.stdout.raw')).write_bytes(p.stdout)
    (HERE / (name + '.stderr.raw')).write_bytes(p.stderr)
    parsed = json.loads(p.stdout)
    assert p.returncode == want_rc and parsed['decision'] == decision
    results.append({'name': name, 'argv': argv, 'rc': p.returncode, 'input_sha256': None,
                    'stdout_sha256': sha(p.stdout), 'stderr_sha256': sha(p.stderr),
                    'first_failure': parsed.get('first_failure'), 'decision': decision})

report = {'schema': 'peer-native-preflight-offline-test-results-v1',
          'at_utc': datetime.now(timezone.utc).isoformat(),
          'tool_sha256': sha(TOOL.read_bytes()), 'test_sha256': sha(Path(__file__).read_bytes()),
          'cases': results, 'remote_calls': 0, 'device_commands': 0, 'container_commands': 0}
(HERE/'TEST-RESULTS.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
print(json.dumps({'cases': len(results), 'passed': len(results), 'remote_calls': 0}))
