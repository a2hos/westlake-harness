#!/usr/bin/env python3
"""Local-only EVO19 v11 contract fixtures. Never opens SSH."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
module_spec = importlib.util.spec_from_file_location('evo19_v11_candidate', HERE / 'gate.py')
gate = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(gate)
spec = json.loads((HERE / 'SPEC.json').read_text())
observed = json.loads((HERE / 'PREP-READBACK-v3.json').read_text())['remote']
calls = []


def transport(argv, program):
    calls.append((argv, program))
    return subprocess.CompletedProcess(argv, 0, json.dumps(observed).encode(), b'')


def check():
    gate.validate_spec(spec)
    assert len(spec['remote_inputs']) == 11
    assert spec['intended_remote_argv'][2].endswith('/nanhai_plus_native_graph_v11.py')
    assert all(r['stable'] and r['match'] for r in observed['rows'])
    compile(gate.remote_probe_program(spec['remote_inputs']), '<remote-probe>', 'exec')
    result = gate.evaluate(spec, transport, local_wrapper=HERE / 'gate.py',
                           local_env_sha256=gate.sha(gate.ROOT / 'local_env.md'),
                           local_config_sha256=gate.CONFIG_SHA)
    assert result['status'] == 'STATIC_PREFLIGHT_MATCH_UNRELEASED'
    assert result['outer_ssh_rc'] == result['remote_rc'] == 0
    assert result['graph_executed'] is False and result['target_compiled'] is False
    assert len(calls) == 1

    bad = copy.deepcopy(observed)
    bad['rows'][0]['sha256'] = '0' * 64
    bad_calls = []

    def bad_transport(argv, program):
        bad_calls.append(1)
        return subprocess.CompletedProcess(argv, 0, json.dumps(bad).encode(), b'')

    denied = gate.evaluate(spec, bad_transport, local_wrapper=HERE / 'gate.py',
                           local_env_sha256=gate.sha(gate.ROOT / 'local_env.md'),
                           local_config_sha256=gate.CONFIG_SHA)
    assert denied['status'] == 'FAIL_CLOSED' and denied['graph_executed'] is False
    assert len(bad_calls) == 1

    wrong = gate.evaluate(spec, transport, local_wrapper=HERE / 'gate.py',
                          local_env_sha256='0' * 64, local_config_sha256=gate.CONFIG_SHA)
    assert wrong['status'] == 'FAIL_CLOSED' and len(calls) == 1
    altered = copy.deepcopy(spec)
    altered['remote_inputs'][0]['sha256'] = '0' * 64
    try:
        gate.validate_spec(altered)
    except ValueError:
        pass
    else:
        raise AssertionError('altered spec accepted')
    assert not (HERE / 'EVO19-GATE.json').exists()
    return {'status': 'PASS_LOCAL_ONLY', 'checks': 5, 'ssh_calls': 0,
            'graph_calls': 0, 'gate_receipt_created': False}


if __name__ == '__main__':
    print(json.dumps(check(), sort_keys=True))
