#!/usr/bin/env python3
"""EVO19 one-receipt pre-execution identity gate candidate; no graph route exposed.

Only --static-check is reachable. Remote readback and dispatch helpers are
intentionally dormant until an independently reviewed release packet exists.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Callable

SCHEMA = 'nanhai-g279-evo19-gate-v6'
CONFIG_SHA = '5ce3a58541ef1711890aad8348c3a31a03203f584fa50f1f5c0cb4fd88b49718'
REQUIRED_FILES = {'runner', 'interpreter', 'binding', 'index', 'ui', 'guard',
                  'generator', 'ledger', 'manifest', 'go_version', 'go_executable'}


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def identity(path: Path) -> dict:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError('non-regular input: ' + str(path))
        h = hashlib.sha256()
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            h.update(block)
        after = os.fstat(fd)
        if (st.st_ino, st.st_dev, st.st_size, st.st_mtime_ns) != \
           (after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns):
            raise ValueError('input changed while reading: ' + str(path))
        return {'path': str(path), 'sha256': h.hexdigest(), 'bytes': st.st_size,
                'mode': stat.S_IMODE(st.st_mode)}
    finally:
        os.close(fd)


def validate_spec(spec: dict) -> None:
    required = {'schema', 'goal_id', 'claim', 'env_config_sha256', 'local_env_sha256',
                'wrapper', 'remote_host', 'remote_interpreter', 'remote_inputs',
                'intended_remote_argv', 'receipt_path'}
    if set(spec) != required or spec['schema'] != SCHEMA or spec['goal_id'] != 'goal_01' or \
       spec['claim'] != 'NP-MUSL16-ART-024' or spec['env_config_sha256'] != CONFIG_SHA:
        raise ValueError('release specification schema/identity drift')
    names = [item.get('name') for item in spec['remote_inputs']]
    if len(names) != len(set(names)) or set(names) != REQUIRED_FILES:
        raise ValueError('remote input set not closed')
    for item in spec['remote_inputs']:
        if set(item) != {'name', 'path', 'sha256', 'bytes', 'mode'} or \
           not isinstance(item['path'], str) or not item['path'].startswith('/') or \
           not isinstance(item['bytes'], int) or item['bytes'] <= 0 or \
           not isinstance(item['mode'], int) or item['mode'] < 0 or item['mode'] > 0o777 or \
           not isinstance(item['sha256'], str) or len(item['sha256']) != 64:
            raise ValueError('invalid remote input identity: ' + str(item.get('name')))
    wrapper = spec['wrapper']
    if set(wrapper) != {'path', 'sha256', 'bytes', 'mode'} or \
       not isinstance(wrapper['path'], str) or not wrapper['path'].startswith('/'):
        raise ValueError('invalid wrapper identity')
    by_name = {row['name']: row for row in spec['remote_inputs']}
    argv = spec['intended_remote_argv']
    if not isinstance(argv, list) or argv != [spec['remote_interpreter'], '-B', by_name['runner']['path'], '--run']:
        raise ValueError('intended remote argv not exact runner route')
    if by_name['interpreter']['path'] != spec['remote_interpreter'] or spec['remote_host'] != 'gz02':
        raise ValueError('interpreter/host binding drift')
    receipt = Path(spec['receipt_path'])
    if not receipt.is_absolute() or receipt.name != 'EVO19-GATE.json':
        raise ValueError('invalid immutable receipt destination')


def remote_probe_program(inputs: list[dict]) -> str:
    # All paths and expected values enter as JSON data, never as shell syntax.
    payload = json.dumps(inputs, sort_keys=True, separators=(',', ':'))
    return '''import hashlib,json,os,stat,sys\nexpected=json.loads(''' + repr(payload) + ''')\nrows=[]\nrc=0\nfor item in expected:\n try:\n  path=item["path"]\n  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)\n  try:\n   before=os.fstat(fd)\n   if not stat.S_ISREG(before.st_mode): raise ValueError("non-regular")\n   h=hashlib.sha256()\n   while True:\n    block=os.read(fd,1048576)\n    if not block: break\n    h.update(block)\n   after=os.fstat(fd)\n   row={"name":item["name"],"path":path,"sha256":h.hexdigest(),"bytes":before.st_size,"mode":stat.S_IMODE(before.st_mode),"stable":(before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)}\n  finally: os.close(fd)\n except BaseException as error:\n  row={"name":item["name"],"path":item["path"],"error":type(error).__name__+": "+str(error)}\n ok=all(row.get(key)==item[key] for key in ("name","path","sha256","bytes","mode")) and row.get("stable") is True\n row["match"]=ok\n rows.append(row)\n if not ok: rc=23\nprint(json.dumps({"schema":"nanhai-g279-remote-input-readback-v1","remote_rc":rc,"rows":rows},sort_keys=True))\nsys.exit(rc)\n'''


def atomic_receipt(destination: Path, body: dict) -> None:
    """Link a fully fsynced temporary file to the final name without replacement."""
    directory = destination.parent
    if not directory.is_dir() or directory.is_symlink() or destination.exists() or destination.is_symlink():
        raise ValueError('fresh receipt directory/final path required')
    data = (json.dumps(body, sort_keys=True, indent=2) + '\n').encode()
    dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temp = destination.name + '.partial-' + str(os.getpid())
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dir_fd)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(temp, destination.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd, follow_symlinks=False)
            os.fsync(dir_fd)
        finally:
            os.unlink(temp, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)


def evaluate(spec: dict, transport: Callable, *, local_wrapper: Path,
             local_env_sha256: str, local_config_sha256: str) -> dict:
    """Pure gate decision around an injected transport; returns all evidence fields."""
    receipt = {'schema': 'nanhai-g279-evo19-gate-result-v1', 'status': 'FAIL_CLOSED',
               'graph_executed': False, 'target_compiled': False, 'device_commands': 0,
               'outer_ssh_rc': None, 'remote_rc': None, 'remote_rows': None,
               'intended_remote_argv': spec.get('intended_remote_argv'),
               'remote_interpreter': spec.get('remote_interpreter'),
               'remote_host': spec.get('remote_host'),
               'expected_remote_inputs': spec.get('remote_inputs'),
               'expected_wrapper': spec.get('wrapper'),
               'expected_local_env_sha256': spec.get('local_env_sha256'),
               'error': None}
    try:
        validate_spec(spec)
        receipt['spec_sha256'] = hashlib.sha256((json.dumps(spec, sort_keys=True, separators=(',', ':')) + '\n').encode()).hexdigest()
        receipt['env_config_sha256'] = local_config_sha256
        receipt['local_env_sha256'] = local_env_sha256
        receipt['wrapper'] = identity(local_wrapper)
        if local_config_sha256 != spec['env_config_sha256'] or local_env_sha256 != spec['local_env_sha256'] or \
           receipt['wrapper'] != spec['wrapper']:
            raise ValueError('authoritative env or wrapper identity mismatch')
        program = remote_probe_program(spec['remote_inputs'])
        ssh_argv = ['ssh', '-o', 'BatchMode=yes', spec['remote_host'], spec['remote_interpreter'], '-']
        receipt['ssh_outer_argv'] = ssh_argv
        receipt['remote_probe_sha256'] = hashlib.sha256(program.encode()).hexdigest()
        completed = transport(ssh_argv, program)
        receipt['outer_ssh_rc'] = completed.returncode
        receipt['outer_stdout_sha256'] = hashlib.sha256(completed.stdout).hexdigest()
        receipt['outer_stderr_sha256'] = hashlib.sha256(completed.stderr).hexdigest()
        if completed.returncode != 0 and not completed.stdout:
            raise ValueError('SSH failed without remote receipt')
        remote = json.loads(completed.stdout)
        receipt['remote_rc'] = remote.get('remote_rc')
        receipt['remote_rows'] = remote.get('rows')
        if remote.get('schema') != 'nanhai-g279-remote-input-readback-v1' or \
           completed.returncode != 0 or remote.get('remote_rc') != 0:
            raise ValueError('outer SSH or remote readback rc failed')
        actual = remote['rows']
        if not isinstance(actual, list) or len(actual) != len(spec['remote_inputs']):
            raise ValueError('remote input row cardinality drift')
        for want, got in zip(spec['remote_inputs'], actual, strict=True):
            if not got.get('match') or any(got.get(k) != want[k] for k in ('name', 'path', 'sha256', 'bytes', 'mode')) or got.get('stable') is not True:
                raise ValueError('remote input mismatch: ' + want['name'])
        receipt['status'] = 'PREFLIGHT_PASS_ONLY_NOT_GRAPH_RELEASE'
    except BaseException as error:
        receipt['error'] = {'type': type(error).__name__, 'message': str(error)}
    return receipt


def preflight_once(spec: dict, destination: Path, transport: Callable, *,
                   local_wrapper: Path, local_env_sha256: str,
                   local_config_sha256: str) -> dict:
    """Persist exactly one pass/fail receipt; no graph dispatch is performed."""
    if str(destination) != spec.get('receipt_path'):
        result = {'schema': 'nanhai-g279-evo19-gate-result-v1', 'status': 'FAIL_CLOSED',
                  'phase': 'RECEIPT_PATH_BINDING', 'graph_executed': False,
                  'outer_ssh_rc': None, 'remote_rc': None,
                  'error': {'type': 'ValueError', 'message': 'receipt destination differs from release spec'}}
    else:
        result = evaluate(spec, transport, local_wrapper=local_wrapper,
                          local_env_sha256=local_env_sha256,
                          local_config_sha256=local_config_sha256)
    try:
        atomic_receipt(destination, result)
    except BaseException as error:
        return {'schema': 'nanhai-g279-evo19-gate-write-failure-v1',
                'status': 'FAIL_CLOSED_NO_VALID_RECEIPT',
                'error': {'type': type(error).__name__, 'message': str(error)},
                'graph_executed': False, 'outer_ssh_rc': result.get('outer_ssh_rc'),
                'remote_rc': result.get('remote_rc')}
    return result


def actual_readonly_transport(argv: list[str], program: str) -> subprocess.CompletedProcess:
    """Dormant SSH readback transport; never called by the current CLI."""
    return subprocess.run(argv, input=program.encode(), stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=90, check=False)


def preflight_from_authority(spec: dict, destination: Path,
                             transport: Callable = actual_readonly_transport) -> dict:
    """Future release entry: derive authority locally, then persist one gate result."""
    try:
        from nanhai_plus_env import load_environment
        local_env = Path(__file__).resolve().parents[1] / 'local_env.md'
        expected, audit = load_environment(local_env)
        if audit['config_sha256'] != CONFIG_SHA or expected['NANHAI_GZ02_BUILD_HOST'] != 'gz02':
            raise ValueError('authoritative local_env config/host drift')
        local_sha = sha(local_env)
        if spec.get('remote_host') != expected['NANHAI_GZ02_BUILD_HOST']:
            raise ValueError('spec host differs from authoritative local_env')
        return preflight_once(spec, destination, transport,
                              local_wrapper=Path(__file__).resolve(),
                              local_env_sha256=local_sha,
                              local_config_sha256=audit['config_sha256'])
    except BaseException as error:
        failed = {'schema': 'nanhai-g279-evo19-gate-result-v1', 'status': 'FAIL_CLOSED',
                  'phase': 'LOCAL_AUTHORITY',
                  'error': {'type': type(error).__name__, 'message': str(error)},
                  'outer_ssh_rc': None, 'remote_rc': None,
                  'graph_executed': False, 'target_compiled': False, 'device_commands': 0}
        try:
            atomic_receipt(destination, failed)
        except BaseException as write_error:
            return {'status': 'FAIL_CLOSED_NO_VALID_RECEIPT', 'graph_executed': False,
                    'error': {'type': type(write_error).__name__, 'message': str(write_error)}}
        return failed


def static_check() -> int:
    print(json.dumps({'schema': SCHEMA, 'status': 'STATIC_CANDIDATE_ONLY',
                      'wrapper_sha256': sha(Path(__file__)), 'graph_execution': False,
                      'preflight_ssh_executed': False, 'execution_enabled': False,
                      'required_remote_inputs': sorted(REQUIRED_FILES),
                      'unresolved': ['no reviewed release spec or original-owner graph ACK',
                                     'no fresh remote gate readback on this SHA',
                                     'runner --run remains hard closed']}, sort_keys=True))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--static-check', action='store_true')
    parser.add_argument('--preflight', action='store_true')
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    if sum((args.static_check, args.preflight, args.execute)) != 1:
        parser.error('choose one mode')
    if args.static_check:
        return static_check()
    print(json.dumps({'status': 'NO_GO_EVO19_GATE_UNRELEASED', 'graph_execution': False,
                      'ssh_executed': False, 'wrapper_sha256': sha(Path(__file__))}), file=sys.stderr)
    return 3


if __name__ == '__main__':
    raise SystemExit(main())
