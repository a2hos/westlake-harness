#!/usr/bin/env python3
"""One independent read-only gz02 Stage3 probe; freeze raw response locally."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
STAGE3 = HERE.parent
STAGE2 = STAGE3.parent / 'stage2-candidate-v2'
PROBE = HERE / 'remote_readonly_probe.py'
SSH = ['/usr/bin/ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
       '-o', 'HostKeyAlgorithms=ssh-ed25519', '-o', 'ConnectTimeout=10',
       '-o', 'UserKnownHostsFile=/Users/alexyang/.ssh/known_hosts',
       'gz02', '/usr/bin/python3.12 -']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(name, data):
    fd = os.open(HERE / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(fd, data[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    p3_raw, p2_raw = (STAGE3 / 'PACKET.json').read_bytes(), (STAGE2 / 'PACKET.json').read_bytes()
    if sha(p3_raw) != '362394aa2bf7b20a0952af6297a1e11e047bdfa41e1388668ff5f3357a5d803b' or \
       sha(p2_raw) != 'f760bf560d2eb3f7aaf8076c24ea866337e3211df7dd1b2bf59d1832737613d7':
        raise ValueError('packet identity drift')
    p3, p2 = json.loads(p3_raw), json.loads(p2_raw)
    body = PROBE.read_bytes()
    program = ('PACKET = ' + repr(p3) + '\nSTAGE2_PACKET = ' + repr(p2) + '\n').encode() + body
    command = {'schema':'g279-stage3-v11-independent-probe-command-v1',
               'ssh_argv':SSH,'stage3_packet_sha256':sha(p3_raw),
               'stage2_packet_sha256':sha(p2_raw),'probe_source_sha256':sha(body),
               'program_sha256':sha(program),'remote_write':False,
               'graph':False,'device':False,'container':False,'namespace':False}
    save('probe-command.json',(json.dumps(command,sort_keys=True,indent=2)+'\n').encode())
    try:
        result = subprocess.run(SSH, input=program, capture_output=True, timeout=180)
        rc, stdout, stderr = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as e:
        rc, stdout, stderr = 124, e.stdout or b'', e.stderr or b''
    save('remote.stdout.raw',stdout)
    save('remote.stderr.raw',stderr)
    terminal = {'schema':'g279-stage3-v11-independent-probe-terminal-v1',
                'ssh_rc':rc,'stdout_bytes':len(stdout),'stderr_bytes':len(stderr),
                'stdout_sha256':sha(stdout),'stderr_sha256':sha(stderr),'remote_status':None}
    if rc == 0:
        try:
            terminal['remote_status'] = json.loads(stdout)['status']
        except (ValueError, KeyError):
            pass
    save('probe-terminal.json',(json.dumps(terminal,sort_keys=True,indent=2)+'\n').encode())
    print(json.dumps(terminal,sort_keys=True))


if __name__ == '__main__':
    main()
