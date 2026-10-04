#!/usr/bin/env python3
"""No-network EVO19 gate fixtures; injected transport only."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from unittest import mock

sys.dont_write_bytecode = True
root = Path(__file__).resolve().parents[7]
sys.path.insert(0, str(root / 'scripts'))
path = root / 'scripts/nanhai_plus_native_graph_v6_gate.py'
spec_module = importlib.util.spec_from_file_location('v6_gate', path)
gate = importlib.util.module_from_spec(spec_module)
spec_module.loader.exec_module(gate)
checks = {}

with tempfile.TemporaryDirectory() as td:
    work = Path(td)
    wrapper = gate.identity(path)
    rows = []
    for name in sorted(gate.REQUIRED_FILES):
        remote_path = '/remote/' + name
        if name == 'runner': remote_path = '/remote/nanhai_plus_native_graph_v6.py'
        if name == 'interpreter': remote_path = '/usr/bin/python3'
        rows.append({'name': name, 'path': remote_path, 'sha256': 'a' * 64,
                     'bytes': 123, 'mode': 0o444})
    want = {r['name']: r for r in rows}
    base = {'schema': gate.SCHEMA, 'goal_id': 'goal_01', 'claim': 'NP-MUSL16-ART-024',
            'env_config_sha256': gate.CONFIG_SHA, 'local_env_sha256': 'b' * 64,
            'wrapper': wrapper, 'remote_host': 'gz02',
            'remote_interpreter': '/usr/bin/python3', 'remote_inputs': rows,
            'intended_remote_argv': ['/usr/bin/python3', '-B', want['runner']['path'], '--run'],
            'receipt_path': str(work / 'pass/EVO19-GATE.json')}
    def fake_result(mismatch=False):
        actual = [dict(row, stable=True, match=True) for row in rows]
        if mismatch:
            actual[0]['sha256'] = 'c' * 64
            actual[0]['match'] = False
        remote_rc = 23 if mismatch else 0
        output = {'schema': 'nanhai-g279-remote-input-readback-v1',
                  'remote_rc': remote_rc, 'rows': actual}
        return SimpleNamespace(returncode=remote_rc,
                               stdout=json.dumps(output).encode(), stderr=b'')
    pass_dir = work / 'pass'; pass_dir.mkdir()
    receipt = gate.preflight_once(base, pass_dir / 'EVO19-GATE.json',
                                  lambda argv, program: fake_result(),
                                  local_wrapper=path, local_env_sha256='b' * 64,
                                  local_config_sha256=gate.CONFIG_SHA)
    checks['pass_receipt_rc_separate'] = (receipt['status'] == 'PREFLIGHT_PASS_ONLY_NOT_GRAPH_RELEASE' and
                                          receipt['outer_ssh_rc'] == 0 and receipt['remote_rc'] == 0 and
                                          (pass_dir / 'EVO19-GATE.json').is_file())
    checks['expected_and_actual_one_receipt'] = (len(receipt['expected_remote_inputs']) == len(rows) and
                                                  len(receipt['remote_rows']) == len(rows) and
                                                  receipt['expected_wrapper'] == wrapper and
                                                  receipt['ssh_outer_argv'] ==
                                                  ['ssh', '-o', 'BatchMode=yes', 'gz02', '/usr/bin/python3', '-'])
    before = gate.sha(pass_dir / 'EVO19-GATE.json')
    repeat = gate.preflight_once(base, pass_dir / 'EVO19-GATE.json',
                                 lambda argv, program: fake_result(),
                                 local_wrapper=path, local_env_sha256='b' * 64,
                                 local_config_sha256=gate.CONFIG_SHA)
    checks['immutable_no_replace'] = (repeat['status'] == 'FAIL_CLOSED_NO_VALID_RECEIPT' and
                                      gate.sha(pass_dir / 'EVO19-GATE.json') == before)
    fail_dir = work / 'remote_mismatch'; fail_dir.mkdir()
    altered = dict(base, receipt_path=str(fail_dir / 'EVO19-GATE.json'))
    failed = gate.preflight_once(altered, fail_dir / 'EVO19-GATE.json',
                                 lambda argv, program: fake_result(mismatch=True),
                                 local_wrapper=path, local_env_sha256='b' * 64,
                                 local_config_sha256=gate.CONFIG_SHA)
    checks['remote_mismatch_persisted'] = (failed['status'] == 'FAIL_CLOSED' and
                                           failed['outer_ssh_rc'] == 23 and failed['remote_rc'] == 23 and
                                           json.loads((fail_dir / 'EVO19-GATE.json').read_text())['status'] == 'FAIL_CLOSED')
    ssh_dir = work / 'ssh_failure'; ssh_dir.mkdir()
    ssh_spec = dict(base, receipt_path=str(ssh_dir / 'EVO19-GATE.json'))
    ssh_failed = gate.preflight_once(ssh_spec, ssh_dir / 'EVO19-GATE.json',
                 lambda argv, program: SimpleNamespace(returncode=255, stdout=b'', stderr=b'connection failed'),
                 local_wrapper=path, local_env_sha256='b' * 64,
                 local_config_sha256=gate.CONFIG_SHA)
    checks['outer_ssh_failure_persisted'] = (ssh_failed['status'] == 'FAIL_CLOSED' and
                ssh_failed['outer_ssh_rc'] == 255 and ssh_failed['remote_rc'] is None and
                (ssh_dir / 'EVO19-GATE.json').is_file())
    env_dir = work / 'env_mismatch'; env_dir.mkdir()
    bad_env = dict(base, receipt_path=str(env_dir / 'EVO19-GATE.json'))
    never = mock.Mock(side_effect=AssertionError('transport should not run'))
    stopped = gate.preflight_once(bad_env, env_dir / 'EVO19-GATE.json', never,
                                  local_wrapper=path, local_env_sha256='d' * 64,
                                  local_config_sha256=gate.CONFIG_SHA)
    checks['env_mismatch_before_ssh'] = (stopped['status'] == 'FAIL_CLOSED' and
                                         stopped['outer_ssh_rc'] is None and never.call_count == 0)
    authority_dir = work / 'authority_mismatch'; authority_dir.mkdir()
    authority_spec = dict(base, receipt_path=str(authority_dir / 'EVO19-GATE.json'))
    authority_failed = gate.preflight_from_authority(authority_spec,
                      authority_dir / 'EVO19-GATE.json', never)
    checks['authoritative_local_env_before_ssh'] = (authority_failed['status'] == 'FAIL_CLOSED' and
                      (authority_dir / 'EVO19-GATE.json').is_file() and never.call_count == 0)
    path_dir = work / 'receipt_path_mismatch'; path_dir.mkdir()
    path_failed = gate.preflight_once(base, path_dir / 'EVO19-GATE.json', never,
                      local_wrapper=path, local_env_sha256='b' * 64,
                      local_config_sha256=gate.CONFIG_SHA)
    checks['receipt_path_mismatch_before_ssh'] = (path_failed['status'] == 'FAIL_CLOSED' and
                      path_failed['outer_ssh_rc'] is None and never.call_count == 0)
    checks['remote_probe_nofollow'] = 'os.O_NOFOLLOW' in gate.remote_probe_program(rows)

assert all(checks.values()), checks
print(json.dumps({'status': 'LOCAL_FIXTURES_ONLY', 'checks': checks,
                  'ssh_commands': 0, 'graph_commands': 0, 'device_commands': 0}, sort_keys=True))
