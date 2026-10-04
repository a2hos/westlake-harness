#!/usr/bin/env python3
"""Local-only adversarial fixtures for the closed v7 identity gate."""
import ast
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from unittest import mock

sys.dont_write_bytecode = True
root = Path(__file__).resolve().parents[7]
path = root / 'scripts/nanhai_plus_native_graph_v7_gate.py'
modspec = importlib.util.spec_from_file_location('v7_gate', path)
gate = importlib.util.module_from_spec(modspec)
modspec.loader.exec_module(gate)
checks = {}
rows = [{'name': name, 'path': str(path), 'sha256': digest or 'a'*64,
         'bytes': 1, 'mode': 0o444}
        for name, (path, digest) in sorted(gate.REMOTE_FILES.items())]
base = {'schema': gate.SCHEMA, 'goal_id': 'goal_01', 'claim': 'NP-MUSL16-ART-024',
        'env_config_sha256': gate.CONFIG_SHA, 'local_env_sha256': 'b'*64,
        'wrapper': gate.identity(path), 'remote_host': 'gz02',
        'remote_interpreter': gate.INTERPRETER, 'remote_inputs': rows,
        'intended_remote_argv': [gate.INTERPRETER, '-B', str(gate.REMOTE_FILES['runner'][0]), '--run'],
        'receipt_path': str(gate.RECEIPT_ROOT / 'EVO19-GATE.json')}
def rejects(spec):
    try: gate.validate_spec(spec)
    except ValueError: return True
    return False
checks['unadmitted_interpreter_blocks_all_transport'] = rejects(base)
injected = copy.deepcopy(base)
injected['remote_interpreter'] = '/usr/bin/python3; false #'
injected['intended_remote_argv'][0] = injected['remote_interpreter']
next(r for r in injected['remote_inputs'] if r['name']=='interpreter')['path'] = injected['remote_interpreter']
checks['shell_metacharacters_rejected'] = rejects(injected)
arbitrary = copy.deepcopy(base)
next(r for r in arbitrary['remote_inputs'] if r['name']=='runner')['path'] = '/tmp/arbitrary-runner.py'
arbitrary['intended_remote_argv'][2] = '/tmp/arbitrary-runner.py'
checks['arbitrary_runner_rejected'] = rejects(arbitrary)
other = copy.deepcopy(base)
other['receipt_path'] = '/tmp/EVO19-GATE.json'
checks['arbitrary_receipt_rejected'] = rejects(other)
checks['remote_command_literal'] = gate.SSH_ARGV == ['ssh','-o','BatchMode=yes','gz02','/usr/bin/python3 -']
program = gate.remote_probe_program(rows)
ast.parse(program)
checks['parent_fd_walk_and_mode_ctime'] = all(s in program for s in ('dir_fd=fds[-1]', 'os.O_NOFOLLOW', 'st_ctime_ns', 'st_mode'))
with tempfile.TemporaryDirectory() as td:
    dest = Path(td)/'EVO19-GATE.json'
    never = mock.Mock(side_effect=AssertionError('transport must stay closed'))
    result = gate.preflight_once(base, dest, never, local_wrapper=path,
                                 local_env_sha256='b'*64, local_config_sha256=gate.CONFIG_SHA)
    checks['arbitrary_destination_no_write_no_transport'] = result['status']=='FAIL_CLOSED_INVALID_RECEIPT_DESTINATION' and not dest.exists() and never.call_count==0
    real_fsync = gate.os.fsync
    calls = [0]
    def fsync_fail_after_link(fd):
        calls[0]+=1
        if calls[0]==2: raise OSError('injected directory fsync failure')
        return real_fsync(fd)
    with mock.patch.object(gate.os, 'fsync', side_effect=fsync_fail_after_link):
        try: gate.atomic_receipt(dest, {'status':'STATIC_PREFLIGHT_MATCH_UNRELEASED'})
        except OSError: pass
    checks['fsync_failure_removes_linked_file'] = not dest.exists() and calls[0]>=3
assert all(checks.values()), checks
print(json.dumps({'status':'LOCAL_STATIC_FIXTURES_ONLY', 'checks':checks,
                  'ssh_commands':0,'graph_commands':0,'device_commands':0},sort_keys=True))
