#!/usr/bin/env python3
"""No chmod or SSH: inspect frozen program and one-shot receipt protocol locally."""
import ast
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[7]
sys.path.insert(0, str(ROOT / 'scripts'))
script = ROOT / 'scripts/nanhai_plus_g279_mode_correction_v1.py'
spec = importlib.util.spec_from_file_location('mode_candidate', script)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
checks = {}
checks['ast_parse'] = bool(ast.parse(script.read_text()))
checks['authority_current'] = m.authority()['project'] == m.PROJECT
program = m.remote_program('a' * 32)
checks['exact_target_identity'] = all(x in program for x in
    [repr(m.PROJECT), repr(m.PROJECT_ID), repr(m.CONTROL_ID), repr(m.LEASE), repr(m.FINAL)])
checks['fd_only_two_chmods'] = (program.count('os.fchmod(control,0o755)') == 1 and
                                program.count('os.fchmod(project,0o755)') == 1 and
                                program.count('os.fchmod(') == 2)
checks['no_unlink_or_other_mutation'] = ('os.unlink(' not in program and
                                         'os.rename(' not in program and
                                         'os.mkdir(' not in program and
                                         'os.chown(' not in program)
checks['nofolow_acl_lease_guards'] = ('os.O_NOFOLLOW' in program and
    "'system.posix_acl_access'" in program and "P['lease'],P['final']" in program)
checks['fsync_postreadback'] = (program.count('os.fsync(') == 2 and
                                'named_match(parts,expected_after)' in program and
                                'mode(after_project)!=0o755' in program)
with tempfile.TemporaryDirectory() as scratch:
    release = Path(scratch)
    sent = []
    def fake(argv, text):
        sent.append(argv)
        assert (release / 'UNKNOWN.json').is_file()
        return SimpleNamespace(returncode=23, stdout=b'{"schema":"nanhai-g279-mode-correction-remote-v1","remote_rc":23}', stderr=b'')
    with mock.patch.object(m, 'RELEASE', release):
        first = m.stage_once(fake)
        second = m.stage_once(fake)
    checks['unknown_before_transport'] = (release / 'UNKNOWN.json').is_file()
    checks['failure_terminal_no_success'] = (first['status'] == 'REMOTE_FAILED_READ_ONLY_RECONCILE' and
                                              (release / 'TERMINAL.json').is_file())
    checks['one_shot_no_second_transport'] = second['status'] == 'FAIL_CLOSED_BEFORE_SSH' and len(sent) == 1
assert all(checks.values()), checks
print(json.dumps({'status':'LOCAL_STATIC_FIXTURES_ONLY','checks':checks,
                  'ssh_commands':0,'chmod_commands':0,'graph_commands':0,
                  'device_commands':0,'container_commands':0},sort_keys=True))
