#!/usr/bin/env python3
"""Prepared-only, one-shot correction of two exact gz02 project directory modes."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
ENV_SHA = '5ce3a58541ef1711890aad8348c3a31a03203f584fa50f1f5c0cb4fd88b49718'
PROJECT = '/data/source/.nanhai-plus-opaleye-native'
PROJECT_ID = (64785, 29884417, 1000, 1000)
CONTROL_ID = (64785, 29884418, 1000, 1000)
LEASE = 'g279-native-graph-v7-stage-v4.lease'
FINAL = 'nanhai_plus_native_graph_v7.py'
SSH = ['/usr/bin/ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
       '-o', 'HostKeyAlgorithms=ssh-ed25519', '-o', 'ConnectTimeout=10',
       'gz02', '/usr/bin/python3.12 -']
RELEASE = ROOT / 'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g279-native-graph-source-choice-v1/g279-mode-correction-candidate-v1/release'

def utc() -> str:
    return datetime.now(timezone.utc).isoformat()

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def authority() -> dict:
    from nanhai_plus_env import load_environment
    bindings, audit = load_environment(ROOT / 'local_env.md')
    if audit['config_sha256'] != ENV_SHA or bindings['NANHAI_GZ02_BUILD_HOST'] != 'gz02' or \
       bindings['NANHAI_GZ02_NATIVE_PROJECT_ROOT'] != PROJECT or \
       bindings['NANHAI_CONTAINER_POLICY'] != 'forbidden':
        raise ValueError('current environment binding drift')
    return {'config_sha256': audit['config_sha256'],
            'document_sha256': sha((ROOT / 'local_env.md').read_bytes()),
            'host': bindings['NANHAI_GZ02_BUILD_HOST'], 'project': PROJECT}

def exclusive_json(directory: Path, name: str, body: dict) -> None:
    if name not in ('UNKNOWN.json', 'TERMINAL.json') or not directory.is_dir() or directory.is_symlink():
        raise ValueError('release directory/name invalid')
    fd_dir = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                     dir_fd=fd_dir)
        with os.fdopen(fd, 'wb') as out:
            out.write((json.dumps(body, sort_keys=True, indent=2) + '\n').encode())
            out.flush(); os.fsync(out.fileno())
        os.fsync(fd_dir)
    finally:
        os.close(fd_dir)

def remote_program(nonce: str, *, project: str = PROJECT,
                   project_id: tuple = PROJECT_ID, control_id: tuple = CONTROL_ID) -> str:
    """Fixture may replace exact path/inodes; production does not accept CLI overrides."""
    if len(nonce) != 32 or any(x not in '0123456789abcdef' for x in nonce):
        raise ValueError('nonce invalid')
    if not project.startswith('/') or any(x in ('', '.', '..') for x in project.split('/')[1:]):
        raise ValueError('project path invalid')
    p = {'project': project, 'project_id': project_id, 'control_id': control_id,
         'lease': LEASE, 'final': FINAL, 'nonce': nonce}
    return 'import json,os,stat,sys\nP='+repr(p)+'\n' + r'''
def ident(st):return (st.st_dev,st.st_ino,st.st_uid,st.st_gid)
def mode(st):return stat.S_IMODE(st.st_mode)
def chain(parts):
 fds=[os.open('/',os.O_RDONLY|os.O_DIRECTORY)]
 try:
  for part in parts:fds.append(os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fds[-1]))
  return fds
 except BaseException:
  for fd in reversed(fds):os.close(fd)
  raise
def named_match(parts,expected):
 fds=chain(parts)
 try:
  current=[(ident(os.fstat(fd)),mode(os.fstat(fd))) for fd in fds]
  if current!=expected:raise ValueError('named parent chain changed')
 finally:
  for fd in reversed(fds):os.close(fd)
def no_acl(fd):
 names=os.listxattr(fd)
 if 'system.posix_acl_access' in names or 'system.posix_acl_default' in names:
  raise ValueError('ACL present')
def main():
 parts=P['project'].split('/')[1:]+['control']
 fds=chain(parts)
 try:
  project,control=fds[-2],fds[-1]
  before=[(ident(os.fstat(fd)),mode(os.fstat(fd))) for fd in fds]
  ps,cs=os.fstat(project),os.fstat(control)
  if os.getuid()!=1000 or ident(ps)!=tuple(P['project_id']) or ident(cs)!=tuple(P['control_id']):
   raise ValueError('owner/inode identity drift')
  if mode(ps)!=0o775 or mode(cs)!=0o775:raise ValueError('expected 0775 mode drift')
  for fd in fds:
   st=os.fstat(fd)
   if not stat.S_ISDIR(st.st_mode) or mode(st)&0o022 and fd not in (project,control):
    raise ValueError('parent type/group-write drift')
   no_acl(fd)
  for name in (P['lease'],P['final']):
   try:os.stat(name,dir_fd=control,follow_symlinks=False)
   except FileNotFoundError:pass
   else:raise ValueError('stage lease/final already exists: '+name)
  named_match(parts,before)
  # Both mode changes are via held O_NOFOLLOW directory fds. On failure,
  # leave any partial state in place; no automatic rollback or cleanup.
  os.fchmod(control,0o755);os.fsync(control)
  os.fchmod(project,0o755);os.fsync(project)
  expected_after=before.copy()
  expected_after[-2]=(before[-2][0],0o755)
  expected_after[-1]=(before[-1][0],0o755)
  named_match(parts,expected_after)
  after_project,after_control=os.fstat(project),os.fstat(control)
  if ident(after_project)!=tuple(P['project_id']) or ident(after_control)!=tuple(P['control_id']) or \
     mode(after_project)!=0o755 or mode(after_control)!=0o755:
   raise ValueError('post-change fd identity/mode drift')
  no_acl(project);no_acl(control)
  for name in (P['lease'],P['final']):
   try:os.stat(name,dir_fd=control,follow_symlinks=False)
   except FileNotFoundError:pass
   else:raise ValueError('stage name appeared during correction')
  return {'status':'EXACT_TWO_MODES_CORRECTED_READBACK','nonce':P['nonce'],
          'project':P['project'],'project_id':P['project_id'],'control_id':P['control_id'],
          'before_mode':'0775','after_mode':'0755','mutation_count':2}
 finally:
  for fd in reversed(fds):os.close(fd)
try:
 r=main();r.update({'schema':'nanhai-g279-mode-correction-remote-v1','remote_rc':0,'state_uncertain':False})
except BaseException as error:
 r={'schema':'nanhai-g279-mode-correction-remote-v1','status':'FAIL_CLOSED_READ_ONLY_RECONCILE',
    'remote_rc':23,'state_uncertain':True,'error':type(error).__name__+': '+str(error)}
print(json.dumps(r,sort_keys=True));sys.exit(r['remote_rc'])
'''

def observe(completed: subprocess.CompletedProcess, nonce: str, program: str) -> dict:
    row = {'schema': 'nanhai-g279-mode-correction-observation-v1',
           'outer_ssh_rc': completed.returncode, 'stdout_sha256': sha(completed.stdout),
           'stderr_sha256': sha(completed.stderr), 'program_sha256': sha(program.encode()),
           'status': 'REMOTE_STATE_UNKNOWN_READ_ONLY_RECONCILE'}
    try:
        remote = json.loads(completed.stdout)
        row['remote'] = remote
        if completed.returncode == 0 and remote.get('schema') == 'nanhai-g279-mode-correction-remote-v1' and \
           remote.get('status') == 'EXACT_TWO_MODES_CORRECTED_READBACK' and \
           remote.get('remote_rc') == 0 and remote.get('state_uncertain') is False and \
           remote.get('nonce') == nonce and remote.get('project') == PROJECT and \
           tuple(remote.get('project_id', ())) == PROJECT_ID and \
           tuple(remote.get('control_id', ())) == CONTROL_ID and \
           remote.get('before_mode') == '0775' and remote.get('after_mode') == '0755' and \
           remote.get('mutation_count') == 2:
            row['status'] = 'TWO_MODES_CORRECTED_READBACK_NOT_STAGED'
        elif remote.get('remote_rc') == 23:
            row['status'] = 'REMOTE_FAILED_READ_ONLY_RECONCILE'
    except (ValueError, TypeError, AttributeError) as e:
        row['parse_error'] = type(e).__name__ + ': ' + str(e)
    return row

def stage_once(transport) -> dict:
    try:
        auth = authority()
        nonce = secrets.token_hex(16)
        program = remote_program(nonce)
        unknown = {'schema': 'nanhai-g279-mode-correction-unknown-v1',
                   'status': 'REMOTE_STATE_UNKNOWN_READ_ONLY_RECONCILE',
                   'authority': auth, 'nonce': nonce, 'ssh_argv': SSH,
                   'remote_program_sha256': sha(program.encode()),
                   'project_id': PROJECT_ID, 'control_id': CONTROL_ID,
                   'expected_before_mode': '0775', 'expected_after_mode': '0755'}
        exclusive_json(RELEASE, 'UNKNOWN.json', unknown)
    except BaseException as e:
        return {'status': 'FAIL_CLOSED_BEFORE_SSH', 'outer_ssh_rc': None,
                'error': type(e).__name__ + ': ' + str(e)}
    try:
        completed = transport(SSH.copy(), program)
        terminal = observe(completed, nonce, program)
    except BaseException as e:
        terminal = {'schema': 'nanhai-g279-mode-correction-observation-v1',
                    'status': 'REMOTE_STATE_UNKNOWN_READ_ONLY_RECONCILE',
                    'outer_ssh_rc': None, 'error': type(e).__name__ + ': ' + str(e)}
    try:
        exclusive_json(RELEASE, 'TERMINAL.json', terminal)
    except BaseException as e:
        return {'status': 'REMOTE_STATE_UNKNOWN_NO_TERMINAL_RECEIPT',
                'error': type(e).__name__ + ': ' + str(e)}
    return terminal

def actual_transport(argv: list[str], program: str) -> subprocess.CompletedProcess:
    if argv != SSH:
        raise ValueError('SSH argv drift')
    return subprocess.run(argv, input=program.encode(), capture_output=True, timeout=60, check=False)

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--static-check', action='store_true')
    parser.add_argument('--correct', action='store_true')
    args = parser.parse_args()
    if args.static_check == args.correct:
        parser.error('choose one mode')
    if args.static_check:
        print(json.dumps({'status': 'STATIC_CANDIDATE_ONLY', 'authority': authority(),
                          'project_id': PROJECT_ID, 'control_id': CONTROL_ID,
                          'ssh_executed': False, 'chmod_executed': False}, sort_keys=True))
        return 0
    result = stage_once(actual_transport)
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get('status') == 'TWO_MODES_CORRECTED_READBACK_NOT_STAGED' else 3

if __name__ == '__main__':
    raise SystemExit(main())
