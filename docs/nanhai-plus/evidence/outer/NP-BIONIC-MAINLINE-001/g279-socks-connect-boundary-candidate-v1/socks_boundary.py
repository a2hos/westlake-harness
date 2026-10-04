#!/usr/bin/env python3
"""Offline SOCKS5 CONNECT frame oracle for a future private-instance pilot.

This module deliberately has no socket, subprocess, proxy, SSH, or device entry.
It does not establish that the upstream node or gz02 was reached.
"""

import ipaddress
import struct

TARGET_IP = ipaddress.IPv4Address('1.95.90.207')
TARGET_PORT = 58222
MAX_REPLY = 262  # VER REP RSV ATYP LEN(1) name(255) PORT(2)
REP_LABELS = {
    1: 'GENERAL_FAILURE',
    2: 'RULESET_DENIED',
    3: 'NETWORK_UNREACHABLE',
    4: 'HOST_UNREACHABLE',
    5: 'CONNECTION_REFUSED',
    6: 'TTL_EXPIRED',
    7: 'COMMAND_UNSUPPORTED',
    8: 'ADDRESS_UNSUPPORTED',
}


def request_frame():
    """Literal gz02 CONNECT bytes; caller must bind to a separately released scope."""
    return b'\x05\x01\x00\x01' + TARGET_IP.packed + struct.pack('!H', TARGET_PORT)


def parse_connect_reply(raw):
    """Classify one *complete* SOCKS5 reply without exporting BND endpoint bytes.

    A success reply is only the proxy's assertion that CONNECT was granted. It
    is not an SSH banner, a remote TCP receipt, or authenticated gz02 identity.
    """
    if not isinstance(raw, bytes) or not 6 <= len(raw) <= MAX_REPLY:
        raise ValueError('reply_type_or_length')
    ver, rep, rsv, atyp = raw[:4]
    if ver != 5 or rsv != 0:
        raise ValueError('reply_header')
    if atyp == 1:
        expected = 10
    elif atyp == 4:
        expected = 22
    elif atyp == 3:
        name_len = raw[4]
        if name_len == 0:
            raise ValueError('empty_domain')
        expected = 7 + name_len
    else:
        raise ValueError('address_type')
    if len(raw) != expected:
        raise ValueError('incomplete_or_trailing_reply')
    # REP is protocol status, not an independently verified upstream cause.
    if rep == 0:
        status = 'PROXY_REPORTED_CONNECT_GRANTED_ONLY'
    elif rep in REP_LABELS:
        status = 'PROXY_REPORTED_' + REP_LABELS[rep]
    else:
        status = 'PROXY_REPORTED_UNKNOWN_FAILURE'
    return {'schema': 'g279-socks-connect-boundary-v1',
            'status': status, 'rep': rep, 'reply_length': len(raw),
            'bound_address_type': {1: 'IPv4', 3: 'DOMAIN', 4: 'IPv6'}[atyp],
            'remote_tcp_proven': False, 'gz02_identity_proven': False}
