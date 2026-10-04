#!/usr/bin/env python3
"""Single-use, read-only gz02 SSH identity probe. No graph or device action."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
RECEIPTS = HERE / 'receipts'
HOST = '1.95.90.207'
PORT = '58222'
ALIAS = '[1.95.90.207]:58222'
HOST_FP = 'SHA256:RuAqHWgFJEIEcb4hC+WXULCRfV3uCsayP4Iw4aJvwzg'
PROXY = '/usr/bin/nc -X 5 -x 127.0.0.1:7897 %h %p'
REMOTE = '/usr/bin/id -u'
SSH_SHA = '17542914a3fb55e7efeb35a90d594a21c84bf6a4cfe1fc8ddff5606dc2658fc3'
NC_SHA = '5735aaf2f80ffa7f28a8026f1fae6cffd6673d578c5618e302d8b591ad5c12c5'
NONCE = 'f2f727d359e411de1bf931506ea006b1'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('nonregular input: ' + str(path))
        chunks = []
        while True:
            block = os.read(fd, 1048576)
            if not block:
                break
            chunks.append(block)
        after = os.fstat(fd)
        for field in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_uid'):
            if getattr(before, field) != getattr(after, field):
                raise ValueError('input drift: ' + str(path))
        return b''.join(chunks)
    finally:
        os.close(fd)


def create_exclusive(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError('short receipt write')
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def json_bytes(obj):
    return (json.dumps(obj, sort_keys=True, separators=(',', ':')) + '\n').encode()


def host_pin(known):
    if known.is_symlink() or known.resolve(strict=True) != known:
        raise ValueError('known_hosts redirect')
    lines = [line.split() for line in read_regular(known).decode().splitlines() if line.startswith(ALIAS + ' ')]
    keys = [line[2] for line in lines if len(line) >= 3 and line[1] == 'ssh-ed25519']
    if len(keys) != 1:
        raise ValueError('host pin missing or ambiguous')
    key = base64.b64decode(keys[0], validate=True)
    actual = 'SHA256:' + base64.b64encode(hashlib.sha256(key).digest()).decode().rstrip('=')
    if actual != HOST_FP:
        raise ValueError('host pin mismatch')
    return actual


def ssh_argv(known):
    opts = ['-F', '/dev/null', '-vv', '-T',
            '-o', 'User=AlexYang', '-o', 'HostName=' + HOST, '-o', 'Port=' + PORT,
            '-o', 'ProxyCommand=' + PROXY, '-o', 'ProxyJump=none',
            '-o', 'BatchMode=yes', '-o', 'NumberOfPasswordPrompts=0',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'HostKeyAlgorithms=ssh-ed25519',
            '-o', 'ConnectTimeout=8', '-o', 'ConnectionAttempts=1',
            '-o', 'UserKnownHostsFile=' + str(known), '-o', 'GlobalKnownHostsFile=/dev/null',
            '-o', 'HostKeyAlias=' + ALIAS, '-o', 'CheckHostIP=no',
            '-o', 'CanonicalizeHostname=no', '-o', 'UpdateHostKeys=no',
            '-o', 'ControlMaster=no', '-o', 'ControlPath=none', '-o', 'ControlPersist=no',
            '-o', 'ClearAllForwardings=yes', '-o', 'PermitLocalCommand=no',
            '-o', 'RequestTTY=no', '-o', 'ForwardAgent=no', '-o', 'ExitOnForwardFailure=yes']
    return ['/usr/bin/ssh', *opts, 'gz02', REMOTE]


def validate_effective(cfg, known):
    values = dict(line.split(' ', 1) for line in cfg.splitlines() if ' ' in line)
    wants = {'user': 'AlexYang', 'hostname': HOST, 'port': PORT,
             'proxycommand': PROXY, 'proxyjump': 'none', 'batchmode': 'yes',
             'stricthostkeychecking': 'true', 'hostkeyalgorithms': 'ssh-ed25519',
             'hostkeyalias': ALIAS, 'userknownhostsfile': str(known),
             'globalknownhostsfile': '/dev/null', 'checkhostip': 'no',
             'canonicalizehostname': 'false', 'updatehostkeys': 'false',
             'controlmaster': 'false', 'controlpath': 'none', 'controlpersist': 'no',
             'clearallforwardings': 'yes', 'permitlocalcommand': 'no',
             'requesttty': 'false', 'forwardagent': 'no'}
    if any(values.get(k, 'none' if k in ('proxyjump', 'controlpath') else None) != v
           for k, v in wants.items()):
        raise ValueError('effective SSH route drift')


def validate_terminal(rc, stdout, stderr):
    debug = stderr.decode(errors='replace')
    if rc != 0 or not re.fullmatch(rb'[0-9]+\n', stdout):
        raise ValueError('remote uid result missing')
    if 'Remote protocol version 2.0' not in debug:
        raise ValueError('SSH banner not observed')
    if 'Server host key: ssh-ed25519 ' + HOST_FP not in debug:
        raise ValueError('SSH host key not observed')
    if 'Authenticated to ' + HOST not in debug:
        raise ValueError('SSH authentication not observed')


def local_preflight():
    if sha(read_regular(Path('/usr/bin/ssh'))) != SSH_SHA or sha(read_regular(Path('/usr/bin/nc'))) != NC_SHA:
        raise ValueError('SSH or nc binary drift')
    known = Path.home() / '.ssh/known_hosts'
    host_pin(known)
    argv = ssh_argv(known)
    cfg = subprocess.run(['/usr/bin/ssh', '-G', *argv[1:-2], 'gz02'],
                         capture_output=True, text=True, timeout=5, check=True)
    validate_effective(cfg.stdout, known)
    # Local listener only. A SOCKS TCP success is never accepted as SSH proof.
    with socket.create_connection(('127.0.0.1', 7897), timeout=1):
        pass
    return argv


def execute():
    if sys.argv[1:] != ['--run']:
        raise ValueError('explicit --run required')
    candidate_raw = read_regular(HERE / 'CANDIDATE.json')
    candidate = json.loads(candidate_raw)
    controller_sha = sha(read_regular(Path(__file__)))
    if candidate['controller_sha256'] != controller_sha or candidate['nonce'] != NONCE or candidate['status'] != 'STATIC_CANDIDATE_NO_EXECUTION_RELEASE':
        raise ValueError('candidate drift')
    release_raw = read_regular(HERE / 'ROOT-RELEASE.json')
    release = json.loads(release_raw)
    peer = HERE / 'peer-review-v1/REVIEW.json'
    if release != {'schema': 'g279-proxy-readonly-handshake-release-v4',
                   'decision': 'ISSUE_EXACT_GZ02_READONLY_HANDSHAKE_ONCE',
                   'candidate_sha256': sha(candidate_raw), 'controller_sha256': controller_sha,
                   'peer_review_sha256': sha(read_regular(peer)),
                   'nonce': NONCE, 'remote_command': REMOTE,
                   'host_fingerprint': HOST_FP, 'graph': False, 'target': False,
                   'device': False, 'container': False, 'namespace': False}:
        raise ValueError('root release absent or drifted')
    argv = local_preflight()
    if any(RECEIPTS.iterdir()):
        raise ValueError('receipt directory consumed; no replay')
    start = {'schema': 'g279-proxy-readonly-handshake-start-v4', 'nonce': NONCE,
             'candidate_sha256': sha(candidate_raw), 'controller_sha256': controller_sha,
             'release_sha256': sha(release_raw), 'argv': argv, 'replay_allowed': False}
    create_exclusive(RECEIPTS / 'START.json', json_bytes(start))
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    try:
        out, err = process.communicate(timeout=25)
        rc = process.returncode
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        out, err = process.communicate()
        rc = 124
    create_exclusive(RECEIPTS / 'stdout.raw', out)
    create_exclusive(RECEIPTS / 'stderr.raw', err)
    try:
        validate_terminal(rc, out, err)
        outcome = 'AUTHENTICATED_READONLY_UID_OBSERVED'
    except ValueError:
        outcome = 'NO_AUTHENTICATED_REMOTE_RESULT_NO_REPLAY'
    terminal = {'schema': 'g279-proxy-readonly-handshake-terminal-v4', 'nonce': NONCE,
                'start_sha256': sha(read_regular(RECEIPTS / 'START.json')),
                'ssh_rc': rc, 'stdout_sha256': sha(out), 'stderr_sha256': sha(err),
                'outcome_candidate': outcome, 'replay_allowed': False}
    create_exclusive(RECEIPTS / 'TERMINAL.json', json_bytes(terminal))
    return terminal


if __name__ == '__main__':
    print(json.dumps(execute(), sort_keys=True))
