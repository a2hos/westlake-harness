#!/usr/bin/env python3
"""EVO19 v7 static identity gate candidate; no SSH or graph route exposed.

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

SCHEMA = 'nanhai-g279-evo19-gate-v7'
CONFIG_SHA = '5ce3a58541ef1711890aad8348c3a31a03203f584fa50f1f5c0cb4fd88b49718'
RUNNER_SHA = 'c7b536a91adb22e2a6fbcebee07ed6f79e9d15b19d7a2e73b9a71b3f93c3a60f'
# Interpreter bytes and an executable handoff have not been independently admitted.
INTERPRETER_SHA = None
INTERPRETER = '/usr/bin/python3'
SSH_ARGV = ['ssh', '-o', 'BatchMode=yes', 'gz02', '/usr/bin/python3 -']
RECEIPT_ROOT = Path(__file__).resolve().parents[1] / 'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g279-native-graph-source-choice-v1/runner-v7-release-v1'
REMOTE_PROJECT = Path('/data/source/.nanhai-plus-opaleye-native')
REMOTE_SOURCE = Path('/opt/19.SourceCode/AOSP-16.0.0_r4/android-source')
REMOTE_FILES = {
    'runner': (REMOTE_PROJECT / 'control/nanhai_plus_native_graph_v6.py', RUNNER_SHA),
    'interpreter': (Path(INTERPRETER), INTERPRETER_SHA),
    'binding': (REMOTE_PROJECT / 'control/g279-native-graph-env.json', '0df4f6fa4f57ac2cda2998723b935fd89c9dfce8f10afd0e23c08a6f2ca9ab91'),
    'index': (Path('/opt/19.SourceCode/SOURCES.json'), '039f72bb0f25b6c611bd85874e0c3446449faaac2790cc9a6b56585f43f98d79'),
    'ui': (REMOTE_PROJECT / 'out/soong-ui-v1/soong_ui', '92d62e59e154846535684d339657b7305ad7186aaa795bfee89a81b500901624'),
    'guard': (REMOTE_PROJECT / 'out/no-namespace-guard-v1/no-namespace-exec', '04c24a88e2eb292b669a7c1fae0b42e9e9e3b0d66fa6dd0bf6e901ec7367df20'),
    'generator': (REMOTE_PROJECT / 'control/generate_manifest_heads.py', 'dafbc416c2b036ea8816591f408b24a8a99974827302968041474d54ef550634'),
    'ledger': (REMOTE_PROJECT / 'control/MANIFEST-HEADS.tsv', 'fe22e645511647b6b34dd83f5c0573ef1f8d45eaf380ac08b12c5120d1e13356'),
    'manifest': (REMOTE_SOURCE / '.repo/manifests/default.xml', '19db4af44aa74ea4ed07bf602f5805476bab1c821d59ba818031022280ae055f'),
    'go_version': (REMOTE_SOURCE / 'prebuilts/go/linux-x86/VERSION', '4407ffecd5b7e06b4f47ac38e68dcca9fc13dd173cc71a5cb228605f328af988'),
    'go_executable': (REMOTE_SOURCE / 'prebuilts/go/linux-x86/bin/go', '467614dc12ce73e28cc9aa8d28bdef259ada3bcc4392f205aaaed6fff44d8cab'),
}
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
        if (st.st_ino, st.st_dev, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_mode) != \
           (after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_mode):
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
        approved_path, approved_sha = REMOTE_FILES[item['name']]
        if item['path'] != str(approved_path) or approved_sha is None or item['sha256'] != approved_sha:
            raise ValueError('remote input not independently admitted: ' + item['name'])
    wrapper = spec['wrapper']
    if set(wrapper) != {'path', 'sha256', 'bytes', 'mode'} or \
       not isinstance(wrapper['path'], str) or not wrapper['path'].startswith('/'):
        raise ValueError('invalid wrapper identity')
    by_name = {row['name']: row for row in spec['remote_inputs']}
    argv = spec['intended_remote_argv']
    if not isinstance(argv, list) or argv != [spec['remote_interpreter'], '-B', by_name['runner']['path'], '--run']:
        raise ValueError('intended remote argv not exact runner route')
    if spec['remote_interpreter'] != INTERPRETER or by_name['interpreter']['path'] != INTERPRETER or spec['remote_host'] != 'gz02':
        raise ValueError('interpreter/host binding drift')
    receipt = Path(spec['receipt_path'])
    if receipt != RECEIPT_ROOT / 'EVO19-GATE.json':
        raise ValueError('invalid immutable receipt destination')


def remote_probe_program(inputs: list[dict]) -> str:
    """Remote stdin program: directory-fd walk rejects symlink components."""
    payload = json.dumps(inputs, sort_keys=True, separators=(',', ':'))
    return """import hashlib,json,os,stat,sys
expected=json.loads(%r)
rows=[]
rc=0
def identity(path):
 parts=path.split('/')[1:]
 if not path.startswith('/') or not parts or any(p in ('','.','..') for p in parts): raise ValueError('noncanonical path')
 root=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
 fds=[root]
 try:
  for part in parts[:-1]:
   fds.append(os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fds[-1]))
  parents=[(os.fstat(fd).st_dev,os.fstat(fd).st_ino,os.fstat(fd).st_mode,os.fstat(fd).st_ctime_ns) for fd in fds]
  fd=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fds[-1])
  try:
   before=os.fstat(fd)
   if not stat.S_ISREG(before.st_mode): raise ValueError('non-regular')
   h=hashlib.sha256()
   while True:
    block=os.read(fd,1048576)
    if not block: break
    h.update(block)
   after=os.fstat(fd)
   stable=(before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns,before.st_mode)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns,after.st_mode)
   stable=stable and parents==[(os.fstat(d).st_dev,os.fstat(d).st_ino,os.fstat(d).st_mode,os.fstat(d).st_ctime_ns) for d in fds]
   return {'sha256':h.hexdigest(),'bytes':before.st_size,'mode':stat.S_IMODE(before.st_mode),'stable':stable}
  finally: os.close(fd)
 finally:
  for fd in reversed(fds): os.close(fd)
for item in expected:
 try:
  row={'name':item['name'],'path':item['path'],**identity(item['path'])}
 except BaseException as error:
  row={'name':item['name'],'path':item['path'],'error':type(error).__name__+': '+str(error)}
 row['match']=all(row.get(k)==item[k] for k in ('name','path','sha256','bytes','mode')) and row.get('stable') is True
 rows.append(row)
 if not row['match']: rc=23
print(json.dumps({'schema':'nanhai-g279-remote-input-readback-v2','remote_rc':rc,'rows':rows},sort_keys=True))
sys.exit(rc)
""" % payload.__repr__()


def atomic_receipt(destination: Path, body: dict) -> None:
    """Link a fully fsynced temporary file to the final name without replacement."""
    directory = destination.parent
    if not directory.is_dir() or directory.is_symlink() or destination.exists() or destination.is_symlink():
        raise ValueError('fresh receipt directory/final path required')
    data = (json.dumps(body, sort_keys=True, indent=2) + '\n').encode()
    dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temp = destination.name + '.partial-' + str(os.getpid())
    linked = False
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dir_fd)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(temp, destination.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd, follow_symlinks=False)
            linked = True
            os.fsync(dir_fd)
        except BaseException:
            if linked:
                os.unlink(destination.name, dir_fd=dir_fd)
                os.fsync(dir_fd)
            raise
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
        ssh_argv = SSH_ARGV.copy()
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
        if remote.get('schema') != 'nanhai-g279-remote-input-readback-v2' or \
           completed.returncode != 0 or remote.get('remote_rc') != 0:
            raise ValueError('outer SSH or remote readback rc failed')
        actual = remote['rows']
        if not isinstance(actual, list) or len(actual) != len(spec['remote_inputs']):
            raise ValueError('remote input row cardinality drift')
        for want, got in zip(spec['remote_inputs'], actual, strict=True):
            if not got.get('match') or any(got.get(k) != want[k] for k in ('name', 'path', 'sha256', 'bytes', 'mode')) or got.get('stable') is not True:
                raise ValueError('remote input mismatch: ' + want['name'])
        # A readback is never permission to execute; no release status exists here.
        receipt['status'] = 'STATIC_PREFLIGHT_MATCH_UNRELEASED'
    except BaseException as error:
        receipt['error'] = {'type': type(error).__name__, 'message': str(error)}
    return receipt


def preflight_once(spec: dict, destination: Path, transport: Callable, *,
                   local_wrapper: Path, local_env_sha256: str,
                   local_config_sha256: str) -> dict:
    """Persist exactly one pass/fail receipt; no graph dispatch is performed."""
    if destination != RECEIPT_ROOT / 'EVO19-GATE.json':
        return {'schema': 'nanhai-g279-evo19-gate-write-failure-v2',
                'status': 'FAIL_CLOSED_INVALID_RECEIPT_DESTINATION',
                'graph_executed': False, 'outer_ssh_rc': None, 'remote_rc': None}
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
    if destination != RECEIPT_ROOT / 'EVO19-GATE.json':
        return {'status': 'FAIL_CLOSED_INVALID_RECEIPT_DESTINATION',
                'graph_executed': False, 'outer_ssh_rc': None, 'remote_rc': None}
    try:
        from nanhai_plus_env import load_environment
        local_env = Path(__file__).resolve().parents[1] / 'local_env.md'
        expected, audit = load_environment(local_env)
        if audit['config_sha256'] != CONFIG_SHA or expected['NANHAI_GZ02_BUILD_HOST'] != 'gz02':
            raise ValueError('authoritative local_env config/host drift')
        if expected['NANHAI_GZ02_NATIVE_PROJECT_ROOT'] != str(REMOTE_PROJECT) or \
           expected['NANHAI_GZ02_AOSP_SOURCE_ROOT'] != str(REMOTE_SOURCE) or \
           expected['NANHAI_SOURCE_POOL_ROOT'] != '/opt/19.SourceCode' or \
           expected['NANHAI_GZ02_SOONG_UI'] != str(REMOTE_FILES['ui'][0]):
            raise ValueError('authoritative remote path bindings drift')
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
                                     'interpreter SHA and full remote path chain not admitted',
                                     'readback-to-execution immutable handoff absent',
                                     'remote runner v6 bytes not staged or independently read back',
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
