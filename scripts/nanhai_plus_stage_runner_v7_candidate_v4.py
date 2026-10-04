#!/usr/bin/env python3
"""One-shot project-only staging of the exact G279 v7 graph runner."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
from pathlib import Path
import stat
import subprocess
import sys
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'scripts/nanhai_plus_native_graph_v7.py'
SOURCE_SHA = '0b799e6864b6e76c2cfe7fa5a98cbb11d1611343f955205ab3bfc739096316a0'
SOURCE_BYTES = 41813
SOURCE_MODE = 0o644
DEST_NAME = 'nanhai_plus_native_graph_v7.py'
DEST_MODE = 0o444
PROJECT = '/data/source/.nanhai-plus-opaleye-native'
LEASE_NAME = 'g279-native-graph-v7-stage-v4.lease'
ENV_CONFIG_SHA = '5ce3a58541ef1711890aad8348c3a31a03203f584fa50f1f5c0cb4fd88b49718'
SSH_ARGV = ['/usr/bin/ssh', '-o', 'BatchMode=yes', 'gz02', '/usr/bin/python3.12 -']
REMOTE_SCHEMA = 'nanhai-g279-v7-runner-staging-remote-v4'
RELEASE_DIR = ROOT / 'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g279-native-graph-source-choice-v1/runner-v7-staging-release-v4'


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source_bytes() -> bytes:
    fd = os.open(SOURCE, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != SOURCE_MODE:
            raise ValueError('local runner type/mode drift')
        chunks = []
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
        data = b''.join(chunks)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
            before.st_ctime_ns, before.st_mode) != (after.st_dev, after.st_ino,
            after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_mode):
            raise ValueError('local runner changed during read')
        if len(data) != SOURCE_BYTES or digest(data) != SOURCE_SHA:
            raise ValueError('local runner byte identity drift')
        return data
    finally:
        os.close(fd)


def remote_program(data: bytes, *, project: str, nonce: str) -> str:
    """Fixed stdin writer; local fixtures may substitute a temporary project."""
    if data != source_bytes():
        raise ValueError('payload differs from admitted local runner')
    if not project.startswith('/') or any(part in ('', '.', '..') for part in project.split('/')[1:]):
        raise ValueError('noncanonical project path')
    if len(nonce) != 32 or any(c not in '0123456789abcdef' for c in nonce):
        raise ValueError('invalid one-shot nonce')
    values = {'project': project, 'name': DEST_NAME, 'sha256': SOURCE_SHA,
              'bytes': SOURCE_BYTES, 'mode': DEST_MODE,
              'lease': LEASE_NAME, 'nonce': nonce,
              'payload_b64': base64.b64encode(data).decode('ascii')}
    return 'import base64,hashlib,json,os,stat,sys\nP='+repr(values)+'\n' + r'''
def tuple_id(st):return (st.st_dev,st.st_ino,st.st_uid,stat.S_IMODE(st.st_mode))
def open_chain(parts):
 fds=[os.open('/',os.O_RDONLY|os.O_DIRECTORY)]
 try:
  for part in parts:fds.append(os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fds[-1]))
  return fds
 except BaseException:
  for fd in reversed(fds):os.close(fd)
  raise
def chain_ids(fds):return [tuple_id(os.fstat(fd)) for fd in fds]
def check_chain(parts,expected):
 fds=open_chain(parts)
 try:
  if chain_ids(fds)!=expected:raise ValueError('named parent chain changed')
 finally:
  for fd in reversed(fds):os.close(fd)
def identity(fd):
 before=os.fstat(fd)
 if not stat.S_ISREG(before.st_mode):raise ValueError('non-regular runner')
 h=hashlib.sha256();os.lseek(fd,0,os.SEEK_SET)
 while True:
  block=os.read(fd,1048576)
  if not block:break
  h.update(block)
 after=os.fstat(fd)
 stable=(before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns,before.st_mode)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns,after.st_mode)
 return {'sha256':h.hexdigest(),'bytes':before.st_size,'mode':stat.S_IMODE(before.st_mode),'uid':before.st_uid,'stable':stable,'dev':before.st_dev,'ino':before.st_ino}
def accepted(row):
 return row['sha256']==P['sha256'] and row['bytes']==P['bytes'] and row['mode']==P['mode'] and row['uid']==os.getuid() and row['stable'] is True
def main():
 parts=P['project'].split('/')[1:]+['control']
 fds=open_chain(parts)
 lease_read=None
 try:
  directory=fds[-1];parents=chain_ids(fds)
  project_st=os.fstat(fds[-2]);control_st=os.fstat(directory)
  if os.getuid()==0 or project_st.st_uid!=os.getuid() or control_st.st_uid!=os.getuid() or \
     stat.S_IMODE(project_st.st_mode)&0o022 or stat.S_IMODE(control_st.st_mode)&0o022:
   raise ValueError('project/control owner or exclusive write boundary mismatch')
  check_chain(parts,parents)
  payload=base64.b64decode(P['payload_b64'],validate=True)
  if len(payload)!=P['bytes'] or hashlib.sha256(payload).hexdigest()!=P['sha256']:raise ValueError('payload mismatch')
  lease_data=(json.dumps({'schema':'nanhai-g279-runner-stage-lease-v4','nonce':P['nonce'],
                         'project':P['project'],'name':P['name'],'sha256':P['sha256'],
                         'bytes':P['bytes']},sort_keys=True,separators=(',',':'))+'\n').encode()
  # The project control lease is acquired before any destination read/write.
  # Neither the lease nor a partial final file is ever automatically removed.
  lease_fd=os.open(P['lease'],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
  with os.fdopen(lease_fd,'wb') as stream:
   stream.write(lease_data);stream.flush();os.fchmod(stream.fileno(),0o444);os.fsync(stream.fileno())
  os.fsync(directory);check_chain(parts,parents)
  lease_read=os.open(P['lease'],os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory)
  lease_row=identity(lease_read)
  if lease_row['sha256']!=hashlib.sha256(lease_data).hexdigest() or lease_row['bytes']!=len(lease_data) or \
     lease_row['mode']!=0o444 or lease_row['uid']!=os.getuid() or not lease_row['stable']:
   raise ValueError('lease identity mismatch')
  check_chain(parts,parents)
  def check_lease_name():
   named=os.stat(P['lease'],dir_fd=directory,follow_symlinks=False)
   if (named.st_dev,named.st_ino)!=(lease_row['dev'],lease_row['ino']) or \
      tuple_id(named)!=tuple_id(os.fstat(lease_read)):
    raise ValueError('lease pathname or owner changed')
  def check_final_name(row):
   named=os.stat(P['name'],dir_fd=directory,follow_symlinks=False)
   if (named.st_dev,named.st_ino)!=(row['dev'],row['ino']) or \
      stat.S_IMODE(named.st_mode)!=P['mode'] or named.st_uid!=row['uid']:
    raise ValueError('runner pathname or owner changed')
  try:fd=os.open(P['name'],os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory)
  except FileNotFoundError:fd=None
  if fd is not None:
   try:row=identity(fd)
   finally:os.close(fd)
   check_chain(parts,parents)
   if not accepted(row):raise ValueError('existing destination differs or UID mismatch; no overwrite')
   check_lease_name();check_final_name(row)
   return {'status':'ALREADY_PRESENT_VERIFIED','created':False,'row':row,'lease':lease_row,'nonce':P['nonce'],'parents':parents}
  # Direct O_EXCL final creation avoids any stat->unlink cleanup race. An
  # interrupted write leaves UNKNOWN for a separate read-only reconciliation.
  check_chain(parts,parents)
  fd=os.open(P['name'],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
  try:
   created=os.fstat(fd);created_id=(created.st_dev,created.st_ino)
   with os.fdopen(fd,'wb') as stream:
    stream.write(payload);stream.flush();os.fchmod(stream.fileno(),P['mode']);os.fsync(stream.fileno())
  except BaseException:
   # fdopen owns fd once entered; no pathname cleanup on any failure.
   raise
  os.fsync(directory)
  check_chain(parts,parents)
  read_fd=os.open(P['name'],os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory)
  try:row=identity(read_fd)
  finally:os.close(read_fd)
  check_chain(parts,parents)
  if (row['dev'],row['ino'])!=created_id or not accepted(row):raise ValueError('created runner readback mismatch; preserve path for read-only reconcile')
  check_lease_name();check_final_name(row)
  return {'status':'CREATED_READBACK_VERIFIED','created':True,'row':row,'lease':lease_row,'nonce':P['nonce'],'parents':parents}
 finally:
  if lease_read is not None:os.close(lease_read)
  for fd in reversed(fds):os.close(fd)
try:
 result=main();result.update({'schema':'nanhai-g279-v7-runner-staging-remote-v4','remote_rc':0,'project':P['project'],'path':P['project']+'/control/'+P['name'],'lease_path':P['project']+'/control/'+P['lease'],'runner_executed':False,'graph_executed':False,'state_uncertain':False})
except BaseException as error:
 result={'schema':'nanhai-g279-v7-runner-staging-remote-v4','status':'FAIL_CLOSED_RECONCILE_READ_ONLY','remote_rc':23,'error':type(error).__name__+': '+str(error),'runner_executed':False,'graph_executed':False,'state_uncertain':True}
print(json.dumps(result,sort_keys=True))
sys.exit(result['remote_rc'])
'''


def authority() -> dict:
    """Read current project authority; inherited NANHAI_* values are ignored."""
    from nanhai_plus_env import load_environment
    document = ROOT / 'local_env.md'
    bindings, audit = load_environment(document)
    project = bindings['NANHAI_GZ02_NATIVE_PROJECT_ROOT']
    if audit['config_sha256'] != ENV_CONFIG_SHA or bindings['NANHAI_GZ02_BUILD_HOST'] != 'gz02' or \
       project != PROJECT or \
       bindings['NANHAI_GZ02_SOONG_UI'] != project + '/out/soong-ui-v1/soong_ui' or \
       bindings['NANHAI_CONTAINER_POLICY'] != 'forbidden':
        raise ValueError('current local_env host/project/policy binding drift')
    return {'config_sha256': audit['config_sha256'],
            'local_env_sha256': digest(document.read_bytes()),
            'host': bindings['NANHAI_GZ02_BUILD_HOST'],
            'project': bindings['NANHAI_GZ02_NATIVE_PROJECT_ROOT'],
            'destination': bindings['NANHAI_GZ02_NATIVE_PROJECT_ROOT'] + '/control/' + DEST_NAME}


def exclusive_json(directory: Path, name: str, body: dict) -> None:
    """Create one durable receipt; existing name is never replaced."""
    if not directory.is_dir() or directory.is_symlink() or name not in ('UNKNOWN.json', 'TERMINAL.json'):
        raise ValueError('fresh project evidence directory required')
    data = (json.dumps(body, sort_keys=True, indent=2) + '\n').encode()
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def observe(completed: subprocess.CompletedProcess, program: str, expected: dict) -> dict:
    """Classify returned bytes. A timeout/transport exception remains UNKNOWN."""
    def parent_identity_ok(rows: object, uid: object) -> bool:
        if not isinstance(rows, list) or len(rows) != len(PROJECT.split('/')) + 1:
            return False
        if not all(isinstance(row, list) and len(row) == 4 and
                   all(isinstance(value, int) for value in row) for row in rows):
            return False
        return all(row[2] == uid and (row[3] & 0o022) == 0 for row in rows[-2:])

    result = {'schema': 'nanhai-g279-v7-runner-staging-observation-v4',
              'ssh_outer_argv': SSH_ARGV, 'outer_ssh_rc': completed.returncode,
              'remote_rc': None, 'stdout_sha256': digest(completed.stdout),
              'stderr_sha256': digest(completed.stderr),
              'remote_program_sha256': digest(program.encode()),
              'expected': expected,
              'runner_executed': False, 'graph_executed': False,
              'status': 'REMOTE_STATE_UNKNOWN_RECONCILE_READ_ONLY'}
    try:
        remote = json.loads(completed.stdout)
        result['remote_rc'] = remote.get('remote_rc')
        result['remote'] = remote
        row = remote.get('row')
        lease = remote.get('lease')
        if completed.returncode == 0 and remote.get('schema') == REMOTE_SCHEMA and remote.get('remote_rc') == 0 and \
           remote.get('runner_executed') is False and remote.get('graph_executed') is False and remote.get('state_uncertain') is False and \
           remote.get('project') == PROJECT and remote.get('path') == expected['path'] and \
           remote.get('lease_path') == expected['lease_path'] and \
           remote.get('nonce') == expected['nonce'] and remote.get('status') in ('CREATED_READBACK_VERIFIED','ALREADY_PRESENT_VERIFIED') and \
           isinstance(row,dict) and all(row.get(k)==expected[k] for k in ('sha256','bytes','mode')) and \
           isinstance(row.get('uid'),int) and row['uid'] > 0 and row.get('stable') is True and \
           isinstance(lease,dict) and lease.get('sha256') == expected['lease_sha256'] and \
           lease.get('bytes') == expected['lease_bytes'] and lease.get('mode') == 0o444 and \
           lease.get('uid') == row.get('uid') and lease.get('stable') is True and \
           parent_identity_ok(remote.get('parents'), row['uid']):
            result['status'] = 'STAGED_HASH_VERIFIED_NOT_EXECUTED'
        elif remote.get('schema') == REMOTE_SCHEMA and remote.get('remote_rc') == 23:
            result['status'] = 'REMOTE_FAILED_RECONCILE_READ_ONLY'
    except (ValueError, TypeError, AttributeError) as error:
        result['parse_error'] = type(error).__name__ + ': ' + str(error)
    return result


def stage_once(transport: Callable) -> dict:
    """One-shot protocol: durable UNKNOWN before the only transport attempt.

    UNKNOWN is durable before transport. Any ambiguous result blocks retries and
    requires read-only reconciliation; neither receipt is rewritten.
    """
    try:
        binding = authority()
        data = source_bytes()
        nonce = secrets.token_hex(16)
        program = remote_program(data, project=binding['project'], nonce=nonce)
        lease_data = (json.dumps({'schema': 'nanhai-g279-runner-stage-lease-v4',
                                  'nonce': nonce, 'project': PROJECT, 'name': DEST_NAME,
                                  'sha256': SOURCE_SHA, 'bytes': SOURCE_BYTES},
                                 sort_keys=True, separators=(',', ':')) + '\n').encode()
        expected = {'path': binding['destination'], 'sha256': SOURCE_SHA,
                    'bytes': SOURCE_BYTES, 'mode': DEST_MODE, 'nonce': nonce,
                    'lease_path': PROJECT + '/control/' + LEASE_NAME,
                    'lease_sha256': digest(lease_data), 'lease_bytes': len(lease_data)}
        unknown = {'schema': 'nanhai-g279-v7-runner-staging-unknown-v4',
                   'status': 'REMOTE_STATE_UNKNOWN_RECONCILE_READ_ONLY',
                   'authority': binding, 'expected': expected,
                   'source': {'sha256': SOURCE_SHA, 'bytes': SOURCE_BYTES, 'mode': SOURCE_MODE},
                   'ssh_outer_argv': SSH_ARGV,
                   'remote_program_sha256': digest(program.encode()),
                   'runner_executed': False, 'graph_executed': False}
        exclusive_json(RELEASE_DIR, 'UNKNOWN.json', unknown)
    except BaseException as error:
        return {'status': 'FAIL_CLOSED_BEFORE_SSH', 'outer_ssh_rc': None,
                'remote_rc': None, 'error': type(error).__name__+': '+str(error),
                'runner_executed': False, 'graph_executed': False}
    try:
        completed = transport(SSH_ARGV.copy(), program)
        terminal = observe(completed, program, expected)
    except BaseException as error:
        terminal = {'schema': 'nanhai-g279-v7-runner-staging-observation-v4',
                    'status': 'REMOTE_STATE_UNKNOWN_RECONCILE_READ_ONLY',
                    'outer_ssh_rc': None, 'remote_rc': None,
                    'error': type(error).__name__+': '+str(error),
                    'runner_executed': False, 'graph_executed': False}
    try:
        exclusive_json(RELEASE_DIR, 'TERMINAL.json', terminal)
    except BaseException as error:
        return {'status': 'REMOTE_STATE_UNKNOWN_NO_TERMINAL_RECEIPT',
                'outer_ssh_rc': terminal.get('outer_ssh_rc'),
                'remote_rc': terminal.get('remote_rc'),
                'error': type(error).__name__+': '+str(error),
                'runner_executed': False, 'graph_executed': False}
    return terminal


def actual_transport(argv: list[str], program: str) -> subprocess.CompletedProcess:
    """The sole released SSH transport: literal argv, one process, bounded wait."""
    if argv != SSH_ARGV:
        raise ValueError('SSH argv drift')
    return subprocess.run(argv, input=program.encode(), capture_output=True,
                          timeout=60, check=False)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--static-check', action='store_true')
    parser.add_argument('--stage', action='store_true')
    args = parser.parse_args()
    if args.static_check == args.stage:
        parser.error('choose one mode')
    if args.stage:
        result = stage_once(actual_transport)
        print(json.dumps(result, sort_keys=True))
        return 0 if result.get('status') == 'STAGED_HASH_VERIFIED_NOT_EXECUTED' else 3
    binding=authority()
    data=source_bytes()
    print(json.dumps({'status':'STATIC_CANDIDATE_ONLY','source_sha256':digest(data),'source_bytes':len(data),
                      'source_mode':oct(SOURCE_MODE),
                      'destination':binding['destination'],'destination_mode':oct(DEST_MODE),
                      'env_config_sha256':binding['config_sha256'],
                      'ssh_executed':False,'runner_executed':False,'graph_executed':False},sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
