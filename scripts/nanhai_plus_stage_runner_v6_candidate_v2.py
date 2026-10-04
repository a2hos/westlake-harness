#!/usr/bin/env python3
"""G279 v6 runner staging v2 candidate. CLI can inspect, never stage or execute."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'scripts/nanhai_plus_native_graph_v6.py'
SOURCE_SHA = 'c7b536a91adb22e2a6fbcebee07ed6f79e9d15b19d7a2e73b9a71b3f93c3a60f'
SOURCE_BYTES = 32654
SOURCE_MODE = 0o644
PROJECT = '/data/source/.nanhai-plus-opaleye-native'
DEST_NAME = 'nanhai_plus_native_graph_v6.py'
DEST_MODE = 0o444
ENV_CONFIG_SHA = '5ce3a58541ef1711890aad8348c3a31a03203f584fa50f1f5c0cb4fd88b49718'
SSH_ARGV = ['/usr/bin/ssh', '-o', 'BatchMode=yes', 'gz02', '/usr/bin/python3.12 -']
REMOTE_SCHEMA = 'nanhai-g279-v6-runner-staging-remote-v2'
RELEASE_DIR = ROOT / 'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g279-native-graph-source-choice-v1/runner-v6-staging-release-v2'


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


def remote_program(data: bytes, *, project: str = PROJECT) -> str:
    """Build a fixed stdin Python program; project override is fixture-only."""
    if data != source_bytes():
        raise ValueError('payload differs from admitted local runner')
    if not project.startswith('/') or any(part in ('', '.', '..') for part in project.split('/')[1:]):
        raise ValueError('noncanonical project path')
    values = {'project': project, 'name': DEST_NAME, 'sha256': SOURCE_SHA,
              'bytes': SOURCE_BYTES, 'mode': DEST_MODE,
              'payload_b64': base64.b64encode(data).decode('ascii')}
    preface = 'import base64,hashlib,json,os,stat,sys\nP='+repr(values)+'\n'
    return preface + r'''
def tuple_id(st):
 return (st.st_dev,st.st_ino,st.st_uid,stat.S_IMODE(st.st_mode))
def open_chain(parts):
 fds=[os.open('/',os.O_RDONLY|os.O_DIRECTORY)]
 try:
  for part in parts:
   fds.append(os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fds[-1]))
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
def expected_row(row):
 return row['sha256']==P['sha256'] and row['bytes']==P['bytes'] and row['mode']==P['mode'] and row['uid']==os.getuid() and row['stable'] is True
def conditional_unlink(directory,name,created_id,parts,parents):
 # Never remove another inode or a pathname after its parent chain drifted.
 check_chain(parts,parents)
 current=os.stat(name,dir_fd=directory,follow_symlinks=False)
 if (current.st_dev,current.st_ino)!=created_id:raise ValueError('cleanup target replaced; reconcile read-only')
 os.unlink(name,dir_fd=directory);os.fsync(directory)
def main():
 parts=P['project'].split('/')[1:]+['control']
 fds=open_chain(parts)
 temp=None;temp_id=None;created_id=None
 try:
  directory=fds[-1];parents=chain_ids(fds)
  if os.fstat(fds[-2]).st_uid!=os.getuid() or os.fstat(directory).st_uid!=os.getuid():raise ValueError('project/control ownership mismatch')
  check_chain(parts,parents)
  payload=base64.b64decode(P['payload_b64'],validate=True)
  if len(payload)!=P['bytes'] or hashlib.sha256(payload).hexdigest()!=P['sha256']:raise ValueError('payload mismatch')
  try:fd=os.open(P['name'],os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory)
  except FileNotFoundError:fd=None
  if fd is not None:
   try:row=identity(fd)
   finally:os.close(fd)
   check_chain(parts,parents)
   if not expected_row(row):raise ValueError('existing destination differs or UID mismatch; no overwrite')
   return {'status':'ALREADY_PRESENT_VERIFIED','created':False,'row':row}
  temp=P['name']+'.partial-'+str(os.getpid())
  fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
  temp_stat=os.fstat(fd);temp_id=(temp_stat.st_dev,temp_stat.st_ino)
  try:
   with os.fdopen(fd,'wb') as stream:
    stream.write(payload);stream.flush();os.fchmod(stream.fileno(),P['mode']);os.fsync(stream.fileno())
   check_chain(parts,parents)
   os.link(temp,P['name'],src_dir_fd=directory,dst_dir_fd=directory,follow_symlinks=False)
   created_id=temp_id
   os.fsync(directory)
   check_chain(parts,parents)
   fd=os.open(P['name'],os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory)
   try:row=identity(fd)
   finally:os.close(fd)
   check_chain(parts,parents)
   if (row['dev'],row['ino'])!=created_id or not expected_row(row):
    conditional_unlink(directory,P['name'],created_id,parts,parents)
    created_id=None
    raise ValueError('created runner readback mismatch; own inode removed')
   return {'status':'CREATED_READBACK_VERIFIED','created':True,'row':row}
  except BaseException:
   if created_id is not None:
    conditional_unlink(directory,P['name'],created_id,parts,parents)
   raise
  finally:
   if temp_id is not None:
    conditional_unlink(directory,temp,temp_id,parts,parents)
 finally:
  for fd in reversed(fds):os.close(fd)
try:
 result=main();result.update({'schema':'nanhai-g279-v6-runner-staging-remote-v2','remote_rc':0,'project':P['project'],'path':P['project']+'/control/'+P['name'],'runner_executed':False,'graph_executed':False,'state_uncertain':False})
except BaseException as error:
 result={'schema':'nanhai-g279-v6-runner-staging-remote-v2','status':'FAIL_CLOSED_RECONCILE_READ_ONLY','remote_rc':23,'error':type(error).__name__+': '+str(error),'runner_executed':False,'graph_executed':False,'state_uncertain':True}
print(json.dumps(result,sort_keys=True))
sys.exit(result['remote_rc'])
'''


def authority() -> dict:
    """Read current project authority; inherited NANHAI_* values are ignored."""
    from nanhai_plus_env import load_environment
    document = ROOT / 'local_env.md'
    bindings, audit = load_environment(document)
    if audit['config_sha256'] != ENV_CONFIG_SHA or bindings['NANHAI_GZ02_BUILD_HOST'] != 'gz02' or \
       bindings['NANHAI_GZ02_NATIVE_PROJECT_ROOT'] != PROJECT or \
       bindings['NANHAI_GZ02_SOONG_UI'] != PROJECT + '/out/soong-ui-v1/soong_ui' or \
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
    result = {'schema': 'nanhai-g279-v6-runner-staging-observation-v2',
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
        if completed.returncode == 0 and remote.get('schema') == REMOTE_SCHEMA and remote.get('remote_rc') == 0 and \
           remote.get('runner_executed') is False and remote.get('graph_executed') is False and remote.get('state_uncertain') is False and \
           remote.get('path') == expected['path'] and remote.get('status') in ('CREATED_READBACK_VERIFIED','ALREADY_PRESENT_VERIFIED') and \
           isinstance(row,dict) and all(row.get(k)==expected[k] for k in ('sha256','bytes','mode')) and \
           row.get('uid') is not None and row.get('stable') is True:
            result['status'] = 'STAGED_HASH_VERIFIED_NOT_EXECUTED'
        elif remote.get('schema') == REMOTE_SCHEMA and remote.get('remote_rc') == 23:
            result['status'] = 'REMOTE_FAILED_RECONCILE_READ_ONLY'
    except (ValueError, TypeError, AttributeError) as error:
        result['parse_error'] = type(error).__name__ + ': ' + str(error)
    return result


def stage_once(transport: Callable) -> dict:
    """Dormant one-shot protocol; current CLI cannot call it.

    UNKNOWN is durable before transport. Any ambiguous result blocks retries and
    requires read-only reconciliation; neither receipt is rewritten.
    """
    try:
        binding = authority()
        data = source_bytes()
        program = remote_program(data)
        expected = {'path': binding['destination'], 'sha256': SOURCE_SHA,
                    'bytes': SOURCE_BYTES, 'mode': DEST_MODE}
        unknown = {'schema': 'nanhai-g279-v6-runner-staging-unknown-v2',
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
        terminal = {'schema': 'nanhai-g279-v6-runner-staging-observation-v2',
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--static-check', action='store_true')
    parser.add_argument('--stage', action='store_true')
    args = parser.parse_args()
    if args.static_check == args.stage:
        parser.error('choose one mode')
    if args.stage:
        print(json.dumps({'status':'NO_GO_STAGING_UNRELEASED','ssh_executed':False,'runner_executed':False,'graph_executed':False}),file=sys.stderr)
        return 3
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
