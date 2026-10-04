#!/usr/bin/env python3
"""Local-only G279 host identity fixture; never connects to gz02."""
from __future__ import annotations

import json
from pathlib import Path
import runpy
import subprocess
import sys


HERE = Path(__file__).resolve().parent
RUNNER = HERE / 'nanhai_plus_native_graph_v10_candidate.py'
SOURCE = RUNNER.read_text()
compile(SOURCE, str(RUNNER), 'exec')
scope = runpy.run_path(str(RUNNER), run_name='fixture_only')
check = scope['is_native_host']
cases = [
    ('GZ02', 'linux', 'x86_64', True),
    ('gz02', 'linux', 'x86_64', True),
    ('GZ02.example', 'linux', 'x86_64', True),
    ('gz02.example', 'linux', 'x86_64', True),
    ('gz020', 'linux', 'x86_64', False),
    ('other', 'linux', 'x86_64', False),
    ('GZ02', 'darwin', 'x86_64', False),
    ('GZ02', 'linux', 'aarch64', False),
]
for host, platform, machine, expected in cases:
    assert check(host, platform, machine) is expected, (host, platform, machine)
assert SOURCE.count('if not is_native_host(os.uname().nodename, sys.platform, os.uname().machine):') == 3
assert 'STAGE2_BINDING_FROZEN = False' in SOURCE
try:
    scope['release_gate']()
except ValueError as exc:
    assert str(exc) == 'stage-2 sibling environment and graph release are not frozen'
else:
    raise AssertionError('graph release gate unexpectedly open')
result = subprocess.run([sys.executable, '-B', str(RUNNER), '--run'],
                        text=True, capture_output=True, timeout=5, check=False)
assert result.returncode == 3, result
denial = json.loads(result.stderr)
assert denial['status'] == 'NO_GO_GRAPH_RELEASE_GATE'
assert denial['graph_execution'] is False
assert denial['target_compile_commands'] == 0
assert denial['device_commands'] == 0
assert 'stage-2 sibling environment' in denial['error']['message']
print(json.dumps({'status': 'PASS_LOCAL_ONLY', 'cases': len(cases),
                  'host_call_sites': 3, 'run_denial_rc': result.returncode,
                  'ssh': 0, 'graph': 0, 'target': 0, 'device': 0,
                  'container': 0, 'namespace': 0}, sort_keys=True))
