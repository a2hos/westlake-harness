#!/usr/bin/env python3
"""G279 v6 runner staging candidate. CLI can inspect, never stage or execute."""
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
REMOTE_SCHEMA = 'nanhai-g279-v6-runner-staging-remote-v1'


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
    """Build stdin Python program. Project override exists only for local fixtures."""
    if data != source_bytes():
        raise ValueError('payload differs from admitted local runner')
    if not project.startswith('/') or any(part in ('', '.', '..') for part in project.split('/')[1:]):
        raise ValueError('noncanonical project path')
    values = {'project': project, 'name': DEST_NAME, 'sha256': SOURCE_SHA,
              'bytes': SOURCE_BYTES, 'mode': DEST_MODE,
              'payload_b64': base64.b64encode(data).decode('ascii')}
    preface = 'import base64,hashlib,json,os,stat,sys\nP='+repr(values)+'\n'
    return preface + r'''
def sha_fd(fd):
 h=hashlib.sha256();os.lseek(fd,0,os.SEEK_SET)
 while True:
  block=os.read(fd,1048576)
  if not block:break
  h.update(block)
 return h.hexdigest()
def regular_identity(fd):
 before=os.fstat(fd)
 if not stat.S_ISREG(before.st_mode):raise ValueError('non-regular runner')
 got=sha_fd(fd);after=os.fstat(fd)
 stable=(before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns,before.st_mode)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns,after.st_mode)
 return {'sha256':got,'bytes':before.st_size,'mode':stat.S_IMODE(before.st_mode),'stable':stable}
def main():
 parts=P['project'].split('/')[1:]
 fds=[os.open('/',os.O_RDONLY|os.O_DIRECTORY)]
 created=False;temp=None
 try:
  for part in parts:
   fds.append(os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fds[-1]))
  fds.append(os.open('control',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fds[-1]))
  directory=fds[-1]
  project_stat=os.fstat(fds[-2]);control_stat=os.fstat(directory)
  if project_stat.st_uid!=os.getuid() or control_stat.st_uid!=os.getuid():raise ValueError('project/control ownership mismatch')
  payload=base64.b64decode(P['payload_b64'],validate=True)
  if len(payload)!=P['bytes'] or hashlib.sha256(payload).hexdigest()!=P['sha256']:raise ValueError('payload mismatch')
  try:
   fd=os.open(P['name'],os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory)
  except FileNotFoundError:fd=None
  if fd is not None:
   try:row=regular_identity(fd)
   finally:os.close(fd)
   if row!={'sha256':P['sha256'],'bytes':P['bytes'],'mode':P['mode'],'stable':True}:raise ValueError('existing destination differs; no overwrite')
   return {'status':'ALREADY_PRESENT_VERIFIED','created':False,'row':row}
  temp=P['name']+'.partial-'+str(os.getpid())
  fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
  try:
   with os.fdopen(fd,'wb') as stream:
    stream.write(payload);stream.flush();os.fchmod(stream.fileno(),P['mode']);os.fsync(stream.fileno())
   os.link(temp,P['name'],src_dir_fd=directory,dst_dir_fd=directory,follow_symlinks=False)
   created=True;os.fsync(directory)
  except BaseException:
   if created:
    os.unlink(P['name'],dir_fd=directory);os.fsync(directory)
   raise
  finally:os.unlink(temp,dir_fd=directory)
  fd=os.open(P['name'],os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory)
  try:row=regular_identity(fd)
  finally:os.close(fd)
  if row!={'sha256':P['sha256'],'bytes':P['bytes'],'mode':P['mode'],'stable':True}:
   os.unlink(P['name'],dir_fd=directory);os.fsync(directory)
   raise ValueError('created runner readback mismatch')
  return {'status':'CREATED_READBACK_VERIFIED','created':True,'row':row}
 finally:
  for fd in reversed(fds):os.close(fd)
try:
 result=main();result.update({'schema':'nanhai-g279-v6-runner-staging-remote-v1','remote_rc':0,'project':P['project'],'path':P['project']+'/control/'+P['name'],'runner_executed':False,'graph_executed':False})
except BaseException as error:
 result={'schema':'nanhai-g279-v6-runner-staging-remote-v1','status':'FAIL_CLOSED','remote_rc':23,'error':type(error).__name__+': '+str(error),'runner_executed':False,'graph_executed':False}
print(json.dumps(result,sort_keys=True))
sys.exit(result['remote_rc'])
'''


def inspect_with_transport(transport: Callable) -> dict:
    """Dormant transport path; caller must independently release it."""
    try:
        data = source_bytes()
        program = remote_program(data)
        completed = transport(SSH_ARGV.copy(), program)
        result = {'schema': 'nanhai-g279-v6-runner-staging-observation-v1',
                  'ssh_outer_argv': SSH_ARGV, 'outer_ssh_rc': completed.returncode,
                  'remote_rc': None, 'stdout_sha256': digest(completed.stdout),
                  'stderr_sha256': digest(completed.stderr),
                  'remote_program_sha256': digest(program.encode()),
                  'expected': {'path': PROJECT+'/control/'+DEST_NAME,
                               'sha256': SOURCE_SHA, 'bytes': SOURCE_BYTES, 'mode': DEST_MODE},
                  'runner_executed': False, 'graph_executed': False,
                  'status': 'FAIL_CLOSED'}
        remote = json.loads(completed.stdout)
        result['remote_rc'] = remote.get('remote_rc')
        result['remote'] = remote
        row = remote.get('row')
        if completed.returncode == 0 and remote.get('schema') == REMOTE_SCHEMA and remote.get('remote_rc') == 0 and \
           remote.get('runner_executed') is False and remote.get('graph_executed') is False and \
           remote.get('path') == result['expected']['path'] and remote.get('status') in ('CREATED_READBACK_VERIFIED','ALREADY_PRESENT_VERIFIED') and \
           row == {'sha256': SOURCE_SHA, 'bytes': SOURCE_BYTES, 'mode': DEST_MODE, 'stable': True}:
            result['status'] = 'STAGED_HASH_VERIFIED_NOT_EXECUTED'
        return result
    except BaseException as error:
        return {'schema': 'nanhai-g279-v6-runner-staging-observation-v1',
                'status': 'FAIL_CLOSED', 'outer_ssh_rc': None, 'remote_rc': None,
                'error': type(error).__name__+': '+str(error),
                'runner_executed': False, 'graph_executed': False}


def actual_transport(argv: list[str], program: str) -> subprocess.CompletedProcess:
    """Dormant; current CLI cannot call this."""
    return subprocess.run(argv, input=program.encode(), capture_output=True, timeout=30, check=False)


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
    data=source_bytes()
    print(json.dumps({'status':'STATIC_CANDIDATE_ONLY','source_sha256':digest(data),'source_bytes':len(data),
                      'source_mode':oct(SOURCE_MODE),
                      'destination':PROJECT+'/control/'+DEST_NAME,'destination_mode':oct(DEST_MODE),
                      'ssh_executed':False,'runner_executed':False,'graph_executed':False},sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
