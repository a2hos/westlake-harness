#!/usr/bin/env python3
"""Bounded local Unix-controller identity/read-only selection audit. No names or secrets emitted."""
import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import urllib.parse
import yaml

SOURCE = Path.home() / 'Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml'
EXPECTED_SOURCE_SHA = '6d11128415287b191dff62c1d28095e01b4d559ef57847c78f188077b9c411a1'
SOCKET = Path('/tmp/verge/verge-mihomo.sock')
HERE = Path(__file__).resolve().parent
SOL_LOCAL = 0
LOCAL_PEERPID = 2


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def process_identity():
    p = subprocess.run(['pgrep', '-x', 'verge-mihomo'], capture_output=True, text=True, timeout=3, check=True)
    ids = p.stdout.split()
    if len(ids) != 1 or not ids[0].isdigit():
        raise ValueError('process_count')
    pid = int(ids[0])
    q = subprocess.run(['ps', '-p', str(pid), '-o', 'uid=,command='], capture_output=True, text=True, timeout=3, check=True)
    row = q.stdout.strip()
    match = re.match(r'^([0-9]+)\s+(.*)$', row)
    if not match:
        raise ValueError('ps_shape')
    uid = int(match.group(1))
    cmd = match.group(2)
    d = re.search(r' -d (.*?) -f ', cmd)
    f = re.search(r' -f (.*?) -ext-ctl-unix ', cmd)
    u = re.search(r' -ext-ctl-unix (\S+)', cmd)
    return pid, uid, bool(d and f and u and d.group(1) == str(SOURCE.parent)
                          and f.group(1) == str(SOURCE) and u.group(1) == str(SOCKET))


class IdentityUnixHTTP(http.client.HTTPConnection):
    def __init__(self, path, expected_pid):
        super().__init__('localhost', timeout=3)
        self.path = str(path)
        self.expected_pid = expected_pid
        self.peer_pid = None

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            sock.connect(self.path)
            self.peer_pid = struct.unpack('i', sock.getsockopt(SOL_LOCAL, LOCAL_PEERPID, 4))[0]
            if self.peer_pid != self.expected_pid:
                raise ValueError('unix_peer_pid_mismatch')
            self.sock = sock
        except BaseException:
            sock.close()
            raise


def selected_now(name, secret, pid):
    conn = IdentityUnixHTTP(SOCKET, pid)
    try:
        path = '/proxies/' + urllib.parse.quote(name, safe='')
        conn.request('GET', path, headers={'Authorization': 'Bearer ' + secret,
                                           'Accept': 'application/json'})
        response = conn.getresponse()
        body = response.read(1048577)
        if response.status != 200 or len(body) > 1048576:
            raise ValueError('controller_response')
        data = json.loads(body)
        if not isinstance(data, dict) or not isinstance(data.get('now'), str):
            raise ValueError('controller_shape')
        return data['now'], conn.peer_pid
    finally:
        conn.close()


def main():
    if (HERE / 'OBSERVATION.json').exists():
        raise ValueError('one_shot_receipt_exists')
    before = sha(SOURCE)
    if before != EXPECTED_SOURCE_SHA:
        raise ValueError('source_drift')
    source = yaml.safe_load(SOURCE.read_bytes())
    if source.get('external-controller-unix') != str(SOCKET):
        raise ValueError('socket_config_drift')
    secret = source.get('secret')
    if not isinstance(secret, str) or not secret:
        raise ValueError('controller_auth_missing')
    proxies = source.get('proxies') or []
    groups = source.get('proxy-groups') or []
    proxy_names = {x.get('name') for x in proxies}
    group_names = {x.get('name') for x in groups}
    if None in proxy_names or None in group_names or proxy_names & group_names:
        raise ValueError('ambiguous_names')
    start_pid, start_uid, cmd_match = process_identity()
    st = SOCKET.lstat()
    if not stat.S_ISSOCK(st.st_mode) or st.st_uid != start_uid or not cmd_match:
        raise ValueError('socket_process_identity')
    seen = set()
    name = 'PROXY'
    peer_pids = []
    while name in group_names:
        if name in seen or len(seen) > 8:
            raise ValueError('selection_cycle')
        seen.add(name)
        name, peer = selected_now(name, secret, start_pid)
        peer_pids.append(peer)
    if name not in proxy_names or name in ('DIRECT', 'REJECT', 'GLOBAL'):
        raise ValueError('not_current_non_direct_leaf')
    end_pid, end_uid, end_match = process_identity()
    after = sha(SOURCE)
    if (start_pid, start_uid) != (end_pid, end_uid) or not end_match or after != before:
        raise ValueError('identity_changed')
    out = {'schema': 'g279-native-controller-identity-readonly-v1',
           'at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'source_sha256': before, 'source_sha_after_equal': True,
           'mihomo_pid': start_pid, 'mihomo_uid': start_uid,
           'process_exact_d_f_ext_ctl_unix': True,
           'socket_path': str(SOCKET), 'socket_uid': st.st_uid,
           'socket_mode': oct(stat.S_IMODE(st.st_mode)),
           'local_peerpid_matches_process_each_request': all(x == start_pid for x in peer_pids),
           'controller_http_200_bearer_auth': True,
           'selection_group_hops': len(seen),
           'current_leaf_in_exact_source_proxies': True,
           'current_leaf_non_direct': True,
           'node_name_or_credential_recorded': False,
           'network_or_gz02_or_device_or_container': False,
           'scope': 'One local read-only Unix controller observation; future current selection can change.'}
    path = HERE / 'OBSERVATION.json'
    with path.open('x') as f:
        json.dump(out, f, sort_keys=True, indent=2)
        f.write('\n')
    print(json.dumps({'receipt_sha256': sha(path), 'selection_group_hops': len(seen),
                      'peer_pid_matched': out['local_peerpid_matches_process_each_request']}))


if __name__ == '__main__':
    main()
