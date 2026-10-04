#!/usr/bin/env python3
"""Only local temp-dir Python execution and injected transport; no SSH/graph."""
import importlib.util
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest import mock

sys.dont_write_bytecode = True
root = Path(__file__).resolve().parents[7]
sys.path.insert(0, str(root / 'scripts'))
source = root / 'scripts/nanhai_plus_stage_runner_v7_candidate_v4.py'
spec = importlib.util.spec_from_file_location('stage_v4', source)
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)
checks = {}
data = stage.source_bytes()
binding = stage.authority()
checks['authority_source'] = (binding['project'] == stage.PROJECT and
                              len(data) == 41813 and stage.digest(data) == stage.SOURCE_SHA)

def local(program):
    return subprocess.run([sys.executable, '-B', '-'], input=program.encode(),
                          capture_output=True, check=False)

with tempfile.TemporaryDirectory() as scratch:
    base = Path(scratch).resolve()
    project = base / 'project'
    control = project / 'control'
    control.mkdir(parents=True)
    nonce = 'a' * 32
    program = stage.remote_program(data, project=str(project), nonce=nonce)
    first = local(program)
    created = json.loads(first.stdout)
    final = control / stage.DEST_NAME
    lease = control / stage.LEASE_NAME
    checks['remote_lease_then_exact_final'] = (first.returncode == 0 and
        created['status'] == 'CREATED_READBACK_VERIFIED' and
        created['nonce'] == nonce and created['row']['sha256'] == stage.SOURCE_SHA and
        created['row']['bytes'] == 41813 and created['row']['mode'] == 0o444 and
        created['lease']['mode'] == 0o444 and final.read_bytes() == data and lease.is_file())
    second = local(program)
    checks['remote_lease_refuses_second'] = (second.returncode == 23 and
        json.loads(second.stdout)['state_uncertain'] is True and final.read_bytes() == data)

    # A fresh project can suffer a partial write; neither lease nor final is unlinked.
    partial_project = base / 'partial'
    partial_control = partial_project / 'control'
    partial_control.mkdir(parents=True)
    partial_program = stage.remote_program(data, project=str(partial_project), nonce='b' * 32)
    needle = "stream.write(payload);stream.flush();os.fchmod(stream.fileno(),P['mode']);os.fsync(stream.fileno())"
    assert partial_program.count(needle) == 1
    partial = local(partial_program.replace(needle,
        "stream.write(payload[:10]);stream.flush();raise OSError('injected')"))
    checks['partial_preserved_for_readonly_reconcile'] = (partial.returncode == 23 and
        (partial_control / stage.DEST_NAME).read_bytes() == data[:10] and
        (partial_control / stage.LEASE_NAME).is_file())

    symlink_project = base / 'symlink'
    symlink_project.mkdir()
    elsewhere = base / 'elsewhere'
    elsewhere.mkdir()
    (symlink_project / 'control').symlink_to(elsewhere, target_is_directory=True)
    symlink_program = stage.remote_program(data, project=str(symlink_project), nonce='c' * 32)
    symlink = local(symlink_program)
    checks['symlink_control_rejected_before_lease'] = (symlink.returncode == 23 and
        not (elsewhere / stage.LEASE_NAME).exists() and
        not (elsewhere / stage.DEST_NAME).exists())

    owner_project = base / 'owner'
    (owner_project / 'control').mkdir(parents=True)
    owner_program = stage.remote_program(data, project=str(owner_project), nonce='d' * 32)
    owner_needle = 'project_st.st_uid!=os.getuid()'
    assert owner_program.count(owner_needle) == 1
    owner = local(owner_program.replace(owner_needle, 'project_st.st_uid!=0'))
    checks['owner_mismatch_before_lease'] = (owner.returncode == 23 and
        not (owner_project / 'control' / stage.LEASE_NAME).exists())

    # Local receipt is durable before an injected transport and prevents retry.
    release = base / 'release'
    release.mkdir()
    calls = []
    def fake_transport(argv, text):
        calls.append(argv)
        unknown = json.loads((release / 'UNKNOWN.json').read_text())
        expected = unknown['expected']
        response = {'schema': stage.REMOTE_SCHEMA, 'remote_rc': 0,
            'project': stage.PROJECT, 'path': expected['path'],
            'lease_path': expected['lease_path'],
            'nonce': expected['nonce'], 'status': 'CREATED_READBACK_VERIFIED',
            'state_uncertain': False, 'runner_executed': False, 'graph_executed': False,
            'row': {'sha256': stage.SOURCE_SHA, 'bytes': stage.SOURCE_BYTES,
                    'mode': stage.DEST_MODE, 'uid': 1000, 'stable': True},
            'lease': {'sha256': expected['lease_sha256'], 'bytes': expected['lease_bytes'],
                      'mode': 0o444, 'uid': 1000, 'stable': True},
            'parents': [[1, i, 1000, 0o755] for i in range(len(stage.PROJECT.split('/')) + 1)]}
        return SimpleNamespace(returncode=0, stdout=json.dumps(response).encode(), stderr=b'')
    with mock.patch.object(stage, 'RELEASE_DIR', release):
        one = stage.stage_once(fake_transport)
        two = stage.stage_once(fake_transport)
    checks['unknown_before_transport_terminal_after'] = (one['status'] ==
        'STAGED_HASH_VERIFIED_NOT_EXECUTED' and (release / 'TERMINAL.json').is_file())
    checks['local_one_shot_no_retry'] = (two['status'] == 'FAIL_CLOSED_BEFORE_SSH'
                                         and len(calls) == 1)
    timeout_dir = base / 'timeout'
    timeout_dir.mkdir()
    with mock.patch.object(stage, 'RELEASE_DIR', timeout_dir):
        timeout = stage.stage_once(lambda _argv, _text: (_ for _ in ()).throw(TimeoutError('injected')))
    checks['timeout_unknown_terminal'] = (timeout['status'] ==
        'REMOTE_STATE_UNKNOWN_RECONCILE_READ_ONLY' and
        (timeout_dir / 'UNKNOWN.json').is_file() and
        (timeout_dir / 'TERMINAL.json').is_file())

    forged_dir = base / 'forged'
    forged_dir.mkdir()
    def forged_transport(argv, text):
        received = fake_transport(argv, text)
        body = json.loads(received.stdout)
        body['lease']['sha256'] = '0' * 64
        return SimpleNamespace(returncode=0, stdout=json.dumps(body).encode(), stderr=b'')
    release = forged_dir
    with mock.patch.object(stage, 'RELEASE_DIR', forged_dir):
        forged = stage.stage_once(forged_transport)
    checks['forged_lease_not_accepted'] = (forged['status'] ==
        'REMOTE_STATE_UNKNOWN_RECONCILE_READ_ONLY')

    # The real CLI branch is reachable, but here its transport is injected.
    cli_dir = base / 'cli'
    cli_dir.mkdir()
    release = cli_dir
    output = io.StringIO()
    with mock.patch.object(stage, 'RELEASE_DIR', cli_dir), \
         mock.patch.object(stage, 'actual_transport', side_effect=fake_transport), \
         mock.patch.object(sys, 'argv', ['stage-v4', '--stage']), \
         contextlib.redirect_stdout(output):
        cli_rc = stage.main()
    checks['cli_stage_reachable_only_with_injected_transport'] = (
        cli_rc == 0 and json.loads(output.getvalue())['status'] ==
        'STAGED_HASH_VERIFIED_NOT_EXECUTED' and (cli_dir / 'UNKNOWN.json').is_file())

assert all(checks.values()), checks
print(json.dumps({'status': 'LOCAL_FIXTURES_ONLY', 'checks': checks,
                  'ssh_commands': 0, 'remote_staging_commands': 0,
                  'graph_commands': 0, 'device_commands': 0, 'container_commands': 0}, sort_keys=True))
