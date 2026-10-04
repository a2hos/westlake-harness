#!/usr/bin/env python3
"""Credential-free pilot for bounded failure-stage receipts; no real proxy/SSH."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
TERMINAL = HERE.parents[1] / 'evidence/outer/NP-BIONIC-MAINLINE-001/g279-private-mihomo-v2c-gz02-candidate-v2/TERMINAL.json'
STAGES = ('local_proxy_ready', 'local_reject_checked', 'ssh_spawned',
          'ssh_transport', 'ssh_hostkey', 'ssh_publickey', 'remote_uid',
          'positive_route', 'witness_replay')
CATEGORIES = ('timeout', 'nonzero_rc', 'parse_reject', 'guard_reject')

def safe_failure(stage, category, rc, timeout, stdout_bytes, stderr_bytes):
    if stage not in STAGES or category not in CATEGORIES:
        raise ValueError('unapproved_stage_or_category')
    if rc is not None and (type(rc) is not int or not -1 <= rc <= 255):
        raise ValueError('bad_rc')
    if type(timeout) is not bool or type(stdout_bytes) is not int or type(stderr_bytes) is not int:
        raise ValueError('bad_shape')
    if not 0 <= stdout_bytes <= 65536 or not 0 <= stderr_bytes <= 65536:
        raise ValueError('unbounded_stream_size')
    if (category == 'timeout') != timeout:
        raise ValueError('timeout_category_mismatch')
    return {'stage': stage, 'category': category, 'rc': rc, 'timeout': timeout,
            'stdout_bytes': stdout_bytes, 'stderr_bytes': stderr_bytes}

def rejects(fn):
    try:
        fn()
    except ValueError:
        return True
    return False

def main():
    raw = TERMINAL.read_bytes()
    actual = json.loads(raw)
    examples = [safe_failure('ssh_transport', 'timeout', None, True, 0, 128),
                safe_failure('ssh_publickey', 'nonzero_rc', 255, False, 0, 203),
                safe_failure('positive_route', 'parse_reject', 0, False, 5, 410)]
    checks = {
        'actual_v2c_failure_substage_unknown': actual['failure_class'] == 'InstanceFailure' and actual['negative'] is None and actual['private_log_metadata'] is None,
        'distinct_mock_failures_remain_distinct': len({(x['stage'], x['category']) for x in examples}) == 3,
        'serialized_witness_has_exact_five_safe_keys': all(set(x) == {'stage','category','rc','timeout','stdout_bytes','stderr_bytes'} for x in examples),
        'reject_private_node_or_raw_log_field': rejects(lambda: safe_failure('private-node-name', 'parse_reject', 2, False, 0, 0)),
        'reject_arbitrary_failure_text': rejects(lambda: safe_failure('ssh_transport', 'password=secret', 2, False, 0, 0)),
        'reject_unbounded_size': rejects(lambda: safe_failure('ssh_transport', 'nonzero_rc', 2, False, 0, 99999999)),
        'reject_bad_rc': rejects(lambda: safe_failure('ssh_transport', 'nonzero_rc', 999, False, 0, 0)),
        'reject_timeout_mismatch': rejects(lambda: safe_failure('ssh_transport', 'timeout', None, False, 0, 0)),
    }
    result = {'schema': 'evo-0050-private-failure-diagnostics-pilot-v1',
              'terminal_sha256': hashlib.sha256(raw).hexdigest(),
              'actual_substage': 'UNKNOWN', 'mock_receipts': examples,
              'checks': checks, 'pass': all(checks.values()),
              'real_proxy_or_ssh_commands': 0, 'device_commands': 0,
              'container_commands': 0}
    (HERE / 'PILOT.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    return 0 if result['pass'] else 2

if __name__ == '__main__':
    raise SystemExit(main())
