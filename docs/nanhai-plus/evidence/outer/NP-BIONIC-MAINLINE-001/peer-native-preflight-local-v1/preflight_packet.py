#!/usr/bin/env python3
"""Offline H1-H4 receipt validator. No SSH or remote execution code exists."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

SCHEMA = 'nanhai-native-r4-readonly-preflight-fixture-v1'
OLD_NONCES = {'6f324a6cb4e1a5fe8ec594334c61d079'}
FORBIDDEN = {'docker', 'podman', 'oci', 'nsjail', 'unshare', 'chroot', 'bwrap',
             'bubblewrap', 'runc', 'crun', 'proot', 'systemd-nspawn'}
DOORS = ('H1_AUTH_HOST', 'H2_EXACT_R4_SOURCE', 'H3_TOOLCHAIN', 'H4_OUTPUT_EXEC_BOUNDARY')


def fail(message: str) -> None:
    raise ValueError(message)


def hex64(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def require(cond: bool, message: str) -> None:
    if not cond:
        fail(message)


def h1(x: dict) -> None:
    a, host = x['authorization'], x['host']
    require(a.get('goal_id') == 'goal_01' and a.get('claim') == 'NP-MUSL16-ART-024', 'wrong project scope')
    require(a.get('operation') == 'read_only_preflight' and a.get('one_use') is True,
            'new one-use read-only authorization missing')
    nonce = a.get('nonce')
    require(isinstance(nonce, str) and re.fullmatch(r'[0-9a-f]{32}', nonce) is not None
            and nonce not in OLD_NONCES and a.get('nonce_freshness_ledger_checked') is True,
            'new nonce or freshness-ledger assertion missing')
    require(host.get('os') == 'Linux' and host.get('arch') == 'x86_64', 'not native Linux x86_64')
    require(host.get('project_scoped') is True and host.get('authenticated') is True,
            'fresh project-scoped authentication absent')
    require(hex64(host.get('host_key_sha256')) and host.get('host_key_pinned') is True,
            'host-key pin absent')
    require(a.get('host_key_sha256') == host.get('host_key_sha256'), 'authorization/host-key pin mismatch')
    require(isinstance(host.get('uid'), int) and host['uid'] >= 0, 'remote UID missing')


def h2(x: dict) -> None:
    s = x['source']
    require(s.get('tag') == 'android-16.0.0_r4' and hex64(s.get('manifest_sha256')),
            'exact R4 manifest identity absent')
    require(s.get('linux_projects') == 1011 and s.get('darwin_prebuilts_absent') == 2,
            'R4 manifest project closure mismatch')
    require(s.get('all_heads_match') is True and s.get('tracked_clean') is True
            and s.get('untracked_clean') is True, 'source head or clean guard failed')
    require(s.get('bionic_commit') == 'f22516cbc67e81c13cf943ce02f01b8929a98726'
            and s.get('bionic_full_checkout') is True, 'full exact Bionic checkout unproven')
    require(hex64(s.get('soong_worktree_sha256')) and s.get('sandbox_off_patch_pinned') is True,
            'no-container Soong worktree pin absent')


def h3(x: dict) -> None:
    t = x['tools']
    for name in ('soong_ui', 'go', 'build_tools', 'clang', 'ld_lld', 'resource_dir', 'sysroot'):
        item = t.get(name)
        require(isinstance(item, dict) and isinstance(item.get('path'), str)
                and item['path'].startswith('/') and hex64(item.get('sha256')),
                f'{name} path/hash absent')
    require(t.get('clang_revision') == 'clang-r563880c'
            and t.get('clang_source_commit') == '9916fb51ccb914d62d35ad9a7b9b21d2ef046928',
            'R4 compiler identity mismatch')
    require(t.get('target') == 'aarch64-linux-android' and t.get('candidate_toolchain_verified') is True
            and t.get('post_graph_action_readback_required') is True,
            'R4 candidate toolchain or post-graph action-readback obligation absent')


def h4(x: dict) -> None:
    e = x['boundary']
    source, out, tmp = (e.get(k) for k in ('source_root', 'out_root', 'tmp_root'))
    require(all(isinstance(v, str) and v.startswith('/') for v in (source, out, tmp)),
            'absolute source/OUT/TMP path missing')
    project = e.get('project_root')
    require(isinstance(project, str) and project.startswith('/') and project not in (source, out, tmp),
            'project root missing or overlapping')
    require(all('..' not in Path(v).parts and '.' not in Path(v).parts for v in (source, project, out, tmp))
            and not source.startswith(project.rstrip('/') + '/')
            and not project.startswith(source.rstrip('/') + '/'), 'noncanonical or overlapping source/project path')
    require(out.startswith(project.rstrip('/') + '/') and tmp.startswith(project.rstrip('/') + '/')
            and out != tmp and not out.startswith(source.rstrip('/') + '/')
            and not tmp.startswith(source.rstrip('/') + '/'), 'OUT/TMP isolation failed')
    require(e.get('source_read_only_for_build_uid') is True and e.get('out_tmp_new_generation') is True,
            'source/output ownership or freshness failed')
    require(e.get('container_observed') is False and e.get('namespace_observed') is False,
            'container or namespace observation')
    argv = e.get('planned_argv')
    require(isinstance(argv, list) and all(isinstance(v, str) for v in argv), 'planned argv absent')
    require(not any(Path(v).name.casefold() in FORBIDDEN for v in argv), 'forbidden direct launcher')
    require(e.get('post_execution_trace_required') is True, 'process trace obligation missing')


CHECKS = (h1, h2, h3, h4)


def validate(x: dict) -> dict:
    require(isinstance(x, dict), 'fixture must be object')
    require(x.get('schema') == SCHEMA, 'fixture schema mismatch')
    rows = []
    for name, check in zip(DOORS, CHECKS, strict=True):
        try:
            check(x)
        except (AttributeError, KeyError, TypeError, ValueError) as error:
            rows.append({'door': name, 'status': 'FAIL', 'reason': str(error)})
            return {'decision': 'NO_GO_OFFLINE_FIXTURE', 'rows': rows, 'first_failure': name}
        rows.append({'door': name, 'status': 'PASS_OFFLINE_ASSERTION'})
    return {'decision': 'STATIC_FIXTURE_PASS_NOT_REMOTE_AUTHORIZATION', 'rows': rows,
            'first_failure': None}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', type=Path, help='offline synthetic readback JSON')
    parser.add_argument('--execute', action='store_true', help='always rejected: no remote call path')
    args = parser.parse_args()
    if args.execute:
        print(json.dumps({'decision': 'NO_GO_REMOTE_EXECUTION_NOT_IMPLEMENTED'}))
        return 4
    if not args.fixture:
        print(json.dumps({'decision': 'DRY_RUN_ONLY', 'doors': DOORS,
                          'remote_calls': 0, 'next': 'Provide offline fixture for static check; separate new signed release required for real SSH.'}))
        return 0
    raw = args.fixture.read_bytes()
    try:
        result = validate(json.loads(raw))
    except (json.JSONDecodeError, ValueError) as error:
        result = {'decision': 'NO_GO_INVALID_FIXTURE', 'first_failure': 'INPUT', 'reason': str(error), 'rows': []}
    result['input_sha256'] = hashlib.sha256(raw).hexdigest()
    result['remote_calls'] = 0
    print(json.dumps(result, sort_keys=True))
    return 0 if result['decision'] == 'STATIC_FIXTURE_PASS_NOT_REMOTE_AUTHORIZATION' else 2


if __name__ == '__main__':
    sys.exit(main())
