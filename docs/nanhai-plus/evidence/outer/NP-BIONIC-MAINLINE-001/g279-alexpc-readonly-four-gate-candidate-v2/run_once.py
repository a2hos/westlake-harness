#!/usr/bin/env python3
"""One-shot AlexPC read-only audit; no SSH until exact peer/root release."""
import base64
import hashlib
import json
import os
import pathlib
import re
import resource
import selectors
import signal
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
SSH_EXPECTED = {'hostname': '192.168.8.22', 'user': 'alexyang', 'port': '22',
                'hostkeyalias': 'alexpc.local', 'stricthostkeychecking': 'true',
                'batchmode': 'yes', 'controlmaster': 'false',
                'clearallforwardings': 'yes', 'requesttty': 'false',
                'forwardagent': 'no', 'hostkeyalgorithms': 'ssh-ed25519',
                'userknownhostsfile': str(KNOWN), 'globalknownhostsfile': '/dev/null'}
STREAM_LIMITS = {'stdout': 65536, 'stderr': 16384}


def sha_bytes(value):
    return hashlib.sha256(value).hexdigest()


def sha(path):
    return sha_bytes(path.read_bytes())


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


def ssh_g():
    # -G evaluates configuration locally and opens no network connection.
    p = subprocess.run(SSH[:-2] + ['-G', SSH[-2]], capture_output=True, text=True, timeout=5)
    if p.returncode != 0:
        return False, {}
    values = {}
    for line in p.stdout.splitlines():
        parts = line.split(' ', 1)
        if len(parts) == 2:
            values[parts[0]] = parts[1]
    ok = all(values.get(k) == v for k, v in SSH_EXPECTED.items())
    ok = ok and values.get('proxyjump') in (None, 'none') and values.get('proxycommand') in (None, 'none')
    return ok, {k: values.get(k) for k in SSH_EXPECTED}


def valid_elf_x86_64(header):
    if not isinstance(header, str) or len(header) != 40 or not re.fullmatch('[0-9a-f]{40}', header):
        return False
    value = bytes.fromhex(header)
    return value[:5] == b'\x7fELF\x02' and value[18:20] == b'\x3e\x00'


def verify_report(value, candidate):
    """Recompute all four gates from facts; remote self-reported booleans are not authority."""
    try:
        if not isinstance(value, dict) or value['schema'] != 'g279-alexpc-four-gate-remote-v2':
            return False, {}
        host = value['host']
        identity = (host == {'hostname': 'alexyLinux', 'system': 'Linux', 'machine': 'x86_64',
                             'username': 'alexyang', 'uid': host['uid']} and
                    type(host['uid']) is int and host['uid'] > 0)
        heads = value['heads']
        r4 = (value['source_root'] == candidate['source_root'] and
              value['source_root_canonical'] is True and
              value['manifest_sha256'] == candidate['manifest_sha256'] and
              set(heads) == set(candidate['expected_heads']) and
              all(heads[n] == {'rc': 0, 'head': h} for n, h in candidate['expected_heads'].items()))
        tool = value['toolchain']
        clang = tool['clang_default_version_from_soong']
        toolchain = (isinstance(clang, str) and re.fullmatch(r'clang-r[0-9]+[a-z]?', clang) is not None and
                     tool['ninja_path'] == candidate['source_root'] + '/prebuilts/build-tools/linux-x86/bin/ninja' and
                     tool['clang_path'] == candidate['source_root'] + '/prebuilts/clang/host/linux-x86/' + clang + '/bin/clang' and
                     tool['soong_ui_path'] == candidate['source_root'] + '/build/soong/soong_ui.bash' and
                     valid_elf_x86_64(tool['ninja_header20_hex']) and
                     valid_elf_x86_64(tool['clang_header20_hex']) and
                     tool['ninja_elf_x86_64'] is True and tool['clang_elf_x86_64'] is True and
                     tool['soong_ui_present'] is True and
                     all(isinstance(tool[k], str) and re.fullmatch('[0-9a-f]{64}', tool[k])
                         for k in ('ninja_sha256', 'clang_sha256')) and
                     heads['prebuilts/build-tools']['head'] == candidate['expected_heads']['prebuilts/build-tools'] and
                     heads['prebuilts/clang/host/linux-x86']['head'] == candidate['expected_heads']['prebuilts/clang/host/linux-x86'])
        capacity = value['capacity']
        path_facts = capacity['private_paths']
        expected_path_names = {pathlib.Path(candidate['capacity']['project_base']).name, 'out', 'tmp'}
        private_safe = (set(path_facts) == expected_path_names and
                        all(type(f['exists']) is bool and type(f['is_symlink']) is bool and
                            f['is_symlink'] is False and
                            ((f['exists'] is False and f['is_dir'] is None and
                              f['owner_uid'] is None and f['writable'] is None) or
                             (f['exists'] is True and f['is_dir'] is True and
                              type(f['owner_uid']) is int and f['owner_uid'] == host['uid'] and
                              f['writable'] is True)) for f in path_facts.values()))
        capacity_ok = (capacity['parent'] == str(pathlib.Path(candidate['capacity']['project_base']).parent) and
                       type(capacity['free_bytes']) is int and
                       capacity['free_bytes'] >= candidate['capacity']['minimum_free_bytes'] and
                       capacity['parent_writable'] is True and
                       capacity['private_paths_safe'] is True and private_safe and
                       capacity['project_base_exists'] is path_facts[pathlib.Path(candidate['capacity']['project_base']).name]['exists'] and
                       capacity['out_exists'] is path_facts['out']['exists'] and
                       capacity['tmp_exists'] is path_facts['tmp']['exists'])
        recomputed = {'identity': bool(identity), 'r4': bool(r4),
                      'toolchain': bool(toolchain), 'capacity': bool(capacity_ok)}
        # A contradiction in either direction is a malformed report.
        exact = (set(value['gates']) == set(recomputed) and
                 all(value['gates'][name] is state for name, state in recomputed.items()) and
                 value['all_four'] is all(recomputed.values()))
        return exact and all(recomputed.values()), recomputed
    except (KeyError, TypeError, ValueError, AttributeError):
        return False, {}


def gate(candidate_bytes, release_bytes, code_bytes):
    candidate = json.loads(candidate_bytes)
    release = json.loads(release_bytes)
    if candidate['schema'] != 'g279-alexpc-four-gate-candidate-v2':
        raise ValueError('candidate schema')
    if candidate['remote_sha256'] != sha_bytes(code_bytes):
        raise ValueError('remote bytes drift')
    if candidate['runner_sha256'] != sha(HERE / 'run_once.py'):
        raise ValueError('runner drift')
    if candidate['ssh_argv'] != SSH:
        raise ValueError('SSH argv drift')
    if release['decision'] != 'GO_SINGLE_READONLY_ALEXPC_AUDIT':
        raise ValueError('release decision')
    if release['candidate_sha256'] != sha_bytes(candidate_bytes):
        raise ValueError('release candidate drift')
    if release['peer_review_sha256'] != sha(HERE / 'peer-review-v1/REVIEW.json'):
        raise ValueError('peer review drift')
    if not isinstance(release['nonce'], str) or len(release['nonce']) < 32:
        raise ValueError('nonce')
    if not pinned_key():
        raise ValueError('known host drift')
    g_ok, _ = ssh_g()
    if not g_ok:
        raise ValueError('fresh ssh -G drift')
    return candidate, release


def capture_bounded(code_bytes):
    def child_limit():
        resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
    p = subprocess.Popen(SSH, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         preexec_fn=child_limit, start_new_session=True)
    try:
        p.stdin.write(code_bytes)
        p.stdin.close()
    except BrokenPipeError:
        p.stdin.close()
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        rc = p.wait(timeout=2)
        p.stdout.close()
        p.stderr.close()
        return rc, 'stdin_broken_pipe', b'', b''
    buffers = {'stdout': bytearray(), 'stderr': bytearray()}
    selector = selectors.DefaultSelector()
    selector.register(p.stdout, selectors.EVENT_READ, 'stdout')
    selector.register(p.stderr, selectors.EVENT_READ, 'stderr')
    end = time.monotonic() + 20
    failure = None
    try:
        while selector.get_map():
            remaining = end - time.monotonic()
            if remaining <= 0:
                failure = 'timeout'
                break
            for key, _ in selector.select(remaining):
                stream = key.data
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffers[stream].extend(chunk)
                if len(buffers[stream]) > STREAM_LIMITS[stream]:
                    failure = stream + '_oversize'
                    break
            if failure:
                break
        if failure:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            rc = p.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            rc = p.wait(timeout=2)
            failure = failure or 'wait_timeout'
    finally:
        selector.close()
        p.stdout.close()
        p.stderr.close()
    return rc, failure, bytes(buffers['stdout']), bytes(buffers['stderr'])


def main():
    if len(sys.argv) != 1:
        raise SystemExit('NO_GO_ARGS')
    # Read once, bind the exact byte buffers to START and the SSH stdin.
    candidate_bytes = (HERE / 'CANDIDATE.json').read_bytes()
    release_bytes = (HERE / 'ROOT-RELEASE.json').read_bytes()
    code_bytes = (HERE / 'remote_audit.py').read_bytes()
    candidate, release = gate(candidate_bytes, release_bytes, code_bytes)
    actual = HERE / 'actual-v1'
    actual.mkdir(exist_ok=True)
    start = actual / 'START.json'
    start_record = {'nonce': release['nonce'], 'candidate_sha256': sha_bytes(candidate_bytes),
                    'release_sha256': sha_bytes(release_bytes), 'remote_sent_sha256': sha_bytes(code_bytes),
                    'runner_sha256': sha(HERE / 'run_once.py'), 'argv': SSH, 'start_epoch': time.time()}
    with start.open('x') as f:
        json.dump(start_record, f, sort_keys=True)
        f.write('\n')
    t0 = time.monotonic()
    rc, failure, stdout, stderr = capture_bounded(code_bytes)
    parsed = None
    if rc == 0 and failure is None:
        try:
            parsed = json.loads(stdout)
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    accepted, recomputed = verify_report(parsed, candidate)
    # Persist only allowlisted structured facts. Never persist raw stdout/stderr.
    if accepted:
        tool = parsed['toolchain']
        capacity = parsed['capacity']
        result = {'schema': 'g279-alexpc-four-gate-remote-v2',
                  'host': {k: parsed['host'][k] for k in ('hostname', 'system', 'machine', 'uid', 'username')},
                  'source_root': candidate['source_root'],
                  'source_root_canonical': True,
                  'manifest_sha256': parsed['manifest_sha256'],
                  'heads': {k: {'rc': 0, 'head': candidate['expected_heads'][k]}
                            for k in candidate['expected_heads']},
                  'toolchain': {k: tool[k] for k in ('clang_default_version_from_soong',
                              'ninja_path', 'clang_path', 'soong_ui_path', 'ninja_header20_hex',
                              'clang_header20_hex', 'ninja_sha256', 'clang_sha256',
                              'ninja_elf_x86_64', 'clang_elf_x86_64', 'soong_ui_present')},
                  'capacity': {'parent': capacity['parent'], 'free_bytes': capacity['free_bytes'],
                               'parent_writable': capacity['parent_writable'],
                               'private_paths_safe': capacity['private_paths_safe'],
                               'private_paths': {name: {key: facts[key] for key in
                                                  ('exists', 'is_symlink', 'is_dir', 'owner_uid', 'writable')}
                                                 for name, facts in capacity['private_paths'].items()},
                               'project_base_exists': capacity['project_base_exists'],
                               'out_exists': capacity['out_exists'], 'tmp_exists': capacity['tmp_exists']},
                  'gates': recomputed, 'all_four': True}
        # Only exact expected fields from a fully accepted report are persisted.
        with (actual / 'RESULT.json').open('x') as f:
            json.dump(result, f, indent=2, sort_keys=True)
            f.write('\n')
    terminal = {'schema': 'g279-alexpc-four-gate-terminal-v2', 'rc': rc, 'failure': failure,
                'duration_s': round(time.monotonic() - t0, 3),
                'stdout_sha256': sha_bytes(stdout), 'stderr_sha256': sha_bytes(stderr),
                'stdout_bytes': len(stdout), 'stderr_bytes': len(stderr),
                'candidate_sha256': sha_bytes(candidate_bytes), 'release_sha256': sha_bytes(release_bytes),
                'remote_sent_sha256': sha_bytes(code_bytes), 'start_sha256': sha(start),
                'result_sha256': sha(actual / 'RESULT.json') if (actual / 'RESULT.json').exists() else None,
                'recomputed_gates': recomputed,
                'decision': 'GO_READONLY_HOST_CANDIDATE_ONLY' if rc == 0 and failure is None and accepted
                            else 'NO_GO_HOST_UNKNOWN_OR_INCOMPLETE'}
    with (actual / 'TERMINAL.json').open('x') as f:
        json.dump(terminal, f, indent=2, sort_keys=True)
        f.write('\n')
    print(json.dumps({'terminal_sha256': sha(actual / 'TERMINAL.json'), 'decision': terminal['decision']}))
    return 0 if terminal['decision'].startswith('GO_') else 2


if __name__ == '__main__':
    sys.exit(main())
