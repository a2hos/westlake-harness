#!/usr/bin/env python3
"""One-shot read-only AlexPC audit; inert until exact independent/root release exists."""
import base64
import hashlib
import json
import os
import pathlib
import resource
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
KNOWN = pathlib.Path('/Users/alexyang/.ssh/known_hosts')
FINGERPRINT = 'OrNmPM32xAI6J3RzMRnIYPIfmzqxZhP/rV0InmnlkKs'
SSH = ['/usr/bin/ssh', '-F', '/dev/null', '-T', '-p', '22',
       '-o', 'User=alexyang', '-o', 'HostName=192.168.8.22',
       '-o', 'HostKeyAlias=alexpc.local', '-o', f'UserKnownHostsFile={KNOWN}',
       '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'HostKeyAlgorithms=ssh-ed25519',
       '-o', 'StrictHostKeyChecking=yes', '-o', 'BatchMode=yes',
       '-o', 'ConnectTimeout=7', '-o', 'ConnectionAttempts=1',
       '-o', 'ProxyJump=none', '-o', 'ProxyCommand=none',
       '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
       '-o', 'UpdateHostKeys=no', '-o', 'CheckHostIP=no',
       '-o', 'ClearAllForwardings=yes', '-o', 'RequestTTY=no',
       'alexyang@192.168.8.22', 'LC_ALL=C /usr/bin/python3 -B -']


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pinned_key():
    p = subprocess.run(['/usr/bin/ssh-keygen', '-F', 'alexpc.local', '-f', str(KNOWN)],
                       capture_output=True, text=True, timeout=3)
    lines = [x for x in p.stdout.splitlines() if x and not x.startswith('#')]
    if p.returncode != 0 or len(lines) != 1:
        return False
    parts = lines[0].split()
    if len(parts) < 3 or parts[1] != 'ssh-ed25519':
        return False
    digest = hashlib.sha256(base64.b64decode(parts[2])).digest()
    return base64.b64encode(digest).decode().rstrip('=') == FINGERPRINT


def gate(candidate, release):
    assert candidate['schema'] == 'g279-alexpc-four-gate-candidate-v1'
    assert candidate['remote_sha256'] == sha(HERE / 'remote_audit.py')
    assert candidate['runner_sha256'] == sha(HERE / 'run_once.py')
    assert candidate['ssh_argv'] == SSH
    assert release['decision'] == 'GO_SINGLE_READONLY_ALEXPC_AUDIT'
    assert release['candidate_sha256'] == sha(HERE / 'CANDIDATE.json')
    assert release['peer_review_sha256'] == sha(HERE / 'peer-review-v1/REVIEW.json')
    assert isinstance(release['nonce'], str) and len(release['nonce']) >= 32
    assert pinned_key()


def main():
    if len(sys.argv) != 1:
        raise SystemExit('NO_GO_ARGS')
    candidate = json.loads((HERE / 'CANDIDATE.json').read_text())
    release = json.loads((HERE / 'ROOT-RELEASE.json').read_text())
    gate(candidate, release)
    actual = HERE / 'actual-v1'
    actual.mkdir(exist_ok=True)
    start = actual / 'START.json'
    with start.open('x') as f:
        json.dump({'nonce': release['nonce'], 'candidate_sha256': sha(HERE / 'CANDIDATE.json'),
                   'release_sha256': sha(HERE / 'ROOT-RELEASE.json'),
                   'remote_sha256': sha(HERE / 'remote_audit.py'),
                   'argv': SSH, 'start_epoch': time.time()}, f, sort_keys=True)
        f.write('\n')
    code = (HERE / 'remote_audit.py').read_bytes()
    t0 = time.monotonic()
    with (actual / 'stdout.raw').open('xb') as stdout, (actual / 'stderr.raw').open('xb') as stderr:
        def bounded_child():
            resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
        p = subprocess.Popen(SSH, stdin=subprocess.PIPE, stdout=stdout, stderr=stderr,
                             preexec_fn=bounded_child, start_new_session=True)
        try:
            p.communicate(input=code, timeout=20)
            rc = p.returncode
            timed_out = False
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, 9)
            p.wait()
            rc = p.returncode
            timed_out = True
    out = (actual / 'stdout.raw').read_bytes()
    err = (actual / 'stderr.raw').read_bytes()
    parsed = None
    if rc == 0 and not timed_out and len(out) < 1024 * 1024:
        try:
            parsed = json.loads(out)
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    accepted = (isinstance(parsed, dict) and parsed.get('schema') == 'g279-alexpc-four-gate-remote-v1'
                and parsed.get('source_root') == candidate['source_root']
                and parsed.get('host', {}).get('hostname') == 'alexyLinux'
                and parsed.get('gates') == {'identity': True, 'r4': True, 'toolchain': True, 'capacity': True}
                and parsed.get('all_four') is True)
    terminal = {'schema': 'g279-alexpc-four-gate-terminal-v1', 'rc': rc,
                'timed_out': timed_out, 'duration_s': round(time.monotonic() - t0, 3),
                'stdout_sha256': sha(actual / 'stdout.raw'), 'stderr_sha256': sha(actual / 'stderr.raw'),
                'stdout_bytes': len(out), 'stderr_bytes': len(err),
                'candidate_sha256': sha(HERE / 'CANDIDATE.json'),
                'release_sha256': sha(HERE / 'ROOT-RELEASE.json'),
                'start_sha256': sha(start), 'gates': parsed.get('gates') if isinstance(parsed, dict) else None,
                'decision': 'GO_READONLY_HOST_CANDIDATE_ONLY' if accepted else 'NO_GO_HOST_UNKNOWN_OR_INCOMPLETE'}
    with (actual / 'TERMINAL.json').open('x') as f:
        json.dump(terminal, f, indent=2, sort_keys=True)
        f.write('\n')
    print(json.dumps({'terminal_sha256': sha(actual / 'TERMINAL.json'), 'decision': terminal['decision']}))
    return 0 if terminal['decision'].startswith('GO_') else 2


if __name__ == '__main__':
    sys.exit(main())
