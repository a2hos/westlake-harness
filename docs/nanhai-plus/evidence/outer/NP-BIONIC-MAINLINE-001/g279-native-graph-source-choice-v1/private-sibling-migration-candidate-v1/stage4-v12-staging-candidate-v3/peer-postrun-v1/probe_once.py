#!/usr/bin/env python3
"""Run one pinned read-only SSH probe and freeze its raw response locally."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
STAGE4 = HERE.parent
SSH = ['/usr/bin/ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
       '-o', 'HostKeyAlgorithms=ssh-ed25519', '-o', 'ConnectTimeout=10',
       '-o', 'UserKnownHostsFile=/Users/alexyang/.ssh/known_hosts',
       'gz02', '/usr/bin/python3.12 -']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(name, data):
    fd = os.open(HERE / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
    try:
        at = 0
        while at < len(data):
            at += os.write(fd, data[at:])
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    packet_raw = (STAGE4 / 'PACKET.json').read_bytes()
    if sha(packet_raw) != '91e8786ece772a89b317785a12b6c20492414f082837eb94c8d5a2cd99e97385':
        raise ValueError('packet file drift')
    packet = json.loads(packet_raw)
    body = (HERE / 'remote_readonly_probe.py').read_bytes()
    program = ('PACKET = ' + repr(packet) + '\n').encode() + body
    command = {'schema':'g279-stage4-v12-independent-probe-command-v1',
               'ssh_argv':SSH,'packet_file_sha256':sha(packet_raw),
               'probe_source_sha256':sha(body),'program_sha256':sha(program),
               'remote_write':False,'graph':False,'target':False,'device':False,
               'container':False,'namespace':False}
    save('probe-command.json',(json.dumps(command,indent=2,sort_keys=True)+'\n').encode())
    try:
        r = subprocess.run(SSH,input=program,capture_output=True,timeout=180)
        rc, stdout, stderr = r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired as e:
        rc, stdout, stderr = 124, e.stdout or b'', e.stderr or b''
    save('remote.stdout.raw',stdout)
    save('remote.stderr.raw',stderr)
    terminal = {'schema':'g279-stage4-v12-independent-probe-terminal-v1',
                'ssh_rc':rc,'stdout_bytes':len(stdout),'stderr_bytes':len(stderr),
                'stdout_sha256':sha(stdout),'stderr_sha256':sha(stderr),
                'remote_status':None}
    if rc == 0:
        try:
            terminal['remote_status'] = json.loads(stdout)['status']
        except (ValueError,KeyError):
            pass
    save('probe-terminal.json',(json.dumps(terminal,indent=2,sort_keys=True)+'\n').encode())
    print(json.dumps(terminal,sort_keys=True))


if __name__ == '__main__':
    main()
