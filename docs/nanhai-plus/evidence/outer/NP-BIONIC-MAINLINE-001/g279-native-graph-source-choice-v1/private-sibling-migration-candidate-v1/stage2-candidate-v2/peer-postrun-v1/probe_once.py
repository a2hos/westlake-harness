#!/usr/bin/env python3
"""Send one read-only Stage2 evidence probe to gz02 and freeze its raw reply."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
V2 = HERE.parent
PACKET = V2 / 'PACKET.json'
PROBE = HERE / 'remote_readonly_probe.py'
SSH = ['/usr/bin/ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
       '-o', 'HostKeyAlgorithms=ssh-ed25519', '-o', 'ConnectTimeout=10',
       '-o', 'UserKnownHostsFile=/Users/alexyang/.ssh/known_hosts',
       'gz02', '/usr/bin/python3.12 -']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_once(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(fd, data[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    packet_data = PACKET.read_bytes()
    packet = json.loads(packet_data)
    if sha(packet_data) != 'f760bf560d2eb3f7aaf8076c24ea866337e3211df7dd1b2bf59d1832737613d7' or \
       packet['nonce'] != '6f324a6cb4e1a5fe8ec594334c61d079':
        raise ValueError('packet drift')
    source = PROBE.read_bytes()
    program = ('PACKET = ' + repr(packet) + '\n').encode() + source
    write_once(HERE / 'probe-command.json', (json.dumps({
        'schema': 'g279-stage2-independent-probe-command-v1',
        'ssh_argv': SSH, 'packet_file_sha256': sha(packet_data),
        'probe_source_sha256': sha(source), 'program_sha256': sha(program),
        'remote_write': False, 'graph': False, 'device': False,
        'container': False, 'namespace': False}, sort_keys=True, indent=2) + '\n').encode())
    try:
        run = subprocess.run(SSH, input=program, capture_output=True, timeout=180)
        rc, stdout, stderr = run.returncode, run.stdout, run.stderr
    except subprocess.TimeoutExpired as e:
        rc, stdout, stderr = 124, e.stdout or b'', e.stderr or b''
    write_once(HERE / 'remote.stdout.raw', stdout)
    write_once(HERE / 'remote.stderr.raw', stderr)
    report = {'schema': 'g279-stage2-independent-probe-terminal-v1',
              'ssh_rc': rc, 'stdout_sha256': sha(stdout), 'stderr_sha256': sha(stderr),
              'stdout_bytes': len(stdout), 'stderr_bytes': len(stderr),
              'remote_status': None}
    if rc == 0:
        try:
            report['remote_status'] = json.loads(stdout)['status']
        except (ValueError, KeyError):
            pass
    write_once(HERE / 'probe-terminal.json', (json.dumps(report, sort_keys=True, indent=2) + '\n').encode())
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
