#!/usr/bin/env python3
"""Local-only tests for the isolated G279 v10 native graph candidate."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[7]
RUNNER = ROOT / 'scripts/nanhai_plus_native_graph_v10.py'
BASE = ROOT / 'scripts/nanhai_plus_native_graph_v7.py'
STAGE2 = ROOT / 'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g279-native-graph-source-choice-v1/private-sibling-migration-candidate-v1/stage2-candidate-v2'


def module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


def denied(fn):
    try:
        fn()
    except ValueError:
        return
    raise AssertionError('unsafe mutation accepted')


def main() -> None:
    new, old = module(RUNNER, 'g279_v10'), module(BASE, 'g279_v7')
    assert new.CONFIG_SHA == 'a4e742576589390209188cddf8d3278c294d9e87e8e9c4733e15eee0a951ddba'
    assert new.BINDING_SHA == '9157f7d3e719c2fe1d2186bb79095500572049c4b7a3bc8d3befbdb98d47ae2f'
    assert new.REQUIRED_BINDINGS == set(json.loads((STAGE2 / 'g279-native-graph-env.proposed.json').read_text())['paths'])
    assert new.RUNNER_FILE.name == 'nanhai_plus_native_graph_v10.py'
    assert new.PROJECT_ROOT / 'source-view' != new.SOURCE_TARGET

    # The native graph still runs from the complete stock source alias.
    source = inspect.getsource(new.execute_graph_candidate)
    assert "cwd=p['source_alias']" in source and "cwd=p['view']" not in source
    assert "'TOP': str(p['view'])" not in inspect.getsource(new.graph_command)
    # Preserve v7's bounded process-tree cleanup and namespace syscall audit.
    for name in ('child_tree', 'reap_tree', 'execute_graph_candidate', 'trace_audit'):
        before = inspect.getsource(getattr(old, name))
        after = inspect.getsource(getattr(new, name))
        assert before == after, name

    probe = json.loads((STAGE2 / 'peer-postrun-v1/remote.stdout.raw').read_text())
    records = {'STAGE2-LEASE.json': probe['lease_content'], 'STAGE2-RECEIPT.json': probe['receipt_content']}
    new.validate_stage2_records(records)
    for field, value in [('nonce', 'wrong'), ('links', 45), ('graph', True),
                         ('container', True), ('namespace', True), ('binding_sha256', '0' * 64)]:
        bad = copy.deepcopy(records)
        bad['STAGE2-RECEIPT.json'][field] = value
        denied(lambda bad=bad: new.validate_stage2_records(bad))
    bad = copy.deepcopy(records)
    bad['STAGE2-LEASE.json']['packet_sha256'] = '0' * 64
    denied(lambda: new.validate_stage2_records(bad))

    static = subprocess.run([sys.executable, '-B', str(RUNNER), '--static-check'], capture_output=True, text=True)
    assert static.returncode == 0, static.stderr
    assert json.loads(static.stdout)['graph_execution'] is False
    run = subprocess.run([sys.executable, '-B', str(RUNNER), '--run'], capture_output=True, text=True)
    assert run.returncode == 3 and json.loads(run.stderr)['status'] == 'NO_GO_V10_UNRELEASED'
    print(json.dumps({'status': 'LOCAL_FIXTURES_PASS', 'checks': 19,
                      'runner_sha256': hashlib.sha256(RUNNER.read_bytes()).hexdigest(),
                      'graph_executed': False, 'remote_commands': 0,
                      'device_commands': 0, 'container_commands': 0}, sort_keys=True))


if __name__ == '__main__':
    main()
