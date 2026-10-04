#!/usr/bin/env python3
"""Credential-free, network-free fixtures for socks_boundary.py."""
import hashlib
import importlib.util
import json
from pathlib import Path

here = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('socks_boundary', here / 'socks_boundary.py')
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


def frame(rep=0, atyp=1):
    address = {1: b'\x7f\x00\x00\x01',
               3: b'\x03abc',
               4: b'\x00' * 16}[atyp]
    return bytes([5, rep, 0, atyp]) + address + b'\x12\x34'


good = [(frame(0, a), 'PROXY_REPORTED_CONNECT_GRANTED_ONLY') for a in (1, 3, 4)]
good += [(frame(r), 'PROXY_REPORTED_' + oracle.REP_LABELS[r]) for r in range(1, 9)]
good += [(frame(9), 'PROXY_REPORTED_UNKNOWN_FAILURE')]
bad = [b'', frame()[:-1], frame() + b'x', b'\x04' + frame()[1:],
       frame()[:2] + b'\x01' + frame()[3:], frame()[:3] + b'\x09' + frame()[4:],
       frame(atyp=3)[:4] + b'\x00' + frame(atyp=3)[5:],
       frame(atyp=3)[:4] + b'\x04' + frame(atyp=3)[5:]]
assert oracle.request_frame().hex() == '05010001015f5acfe36e'
for raw, status in good:
    got = oracle.parse_connect_reply(raw)
    assert got['status'] == status
    assert got['remote_tcp_proven'] is False and got['gz02_identity_proven'] is False
    assert not any(k.startswith('bound_') and k != 'bound_address_type' for k in got)
for raw in bad:
    try:
        oracle.parse_connect_reply(raw)
    except ValueError:
        pass
    else:
        raise AssertionError('malformed_frame_accepted')
print(json.dumps({'schema': 'g279-socks-connect-offline-fixtures-v1',
                  'decision': 'PASS_OFFLINE_PARSER_ONLY',
                  'valid_cases': len(good), 'invalid_cases': len(bad),
                  'request_sha256': hashlib.sha256(oracle.request_frame()).hexdigest(),
                  'network_connections': 0, 'proxy_launches': 0, 'ssh_commands': 0,
                  'device_commands': 0, 'remote_tcp_proven': False,
                  'gz02_identity_proven': False}, sort_keys=True))
