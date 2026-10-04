#!/usr/bin/env python3
"""Offline SOCKS5 stage receipt contract pilot; never opens a socket."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).parent
BASE = HERE.parent.parent / "g279-native-graph-source-choice-v1/graph-v13-proxy-readonly-handshake-candidate-v4"

def classify(method_reply, connect_reply, server_prefix):
    if method_reply is None:
        return "SOCKS_METHOD_UNKNOWN"
    if len(method_reply) != 2 or method_reply[0] != 5:
        return "SOCKS_METHOD_INVALID"
    if method_reply[1] != 0:
        return "SOCKS_METHOD_DENIED"
    if connect_reply is None:
        return "SOCKS_CONNECT_UNKNOWN"
    if len(connect_reply) < 4 or connect_reply[0] != 5 or connect_reply[2] != 0:
        return "SOCKS_CONNECT_INVALID"
    atyp = connect_reply[3]
    size = {1: 4, 4: 16}.get(atyp)
    if atyp == 3:
        if len(connect_reply) < 5:
            return "SOCKS_CONNECT_INVALID"
        size = 1 + connect_reply[4]
    if size is None or len(connect_reply) != 4 + size + 2:
        return "SOCKS_CONNECT_INVALID"
    if connect_reply[1] != 0:
        return "SOCKS_CONNECT_REJECTED"
    if server_prefix is None:
        return "SOCKS_CONNECT_OK_SERVER_BANNER_UNKNOWN"
    if server_prefix.startswith(b"SSH-2.0-"):
        return "SSH_SERVER_BANNER_OBSERVED"
    return "SOCKS_CONNECT_OK_NON_SSH_PREFIX"

good = bytes.fromhex("050000017f0000010016")
rejected = bytes.fromhex("050500017f0000010016")
fixtures = [
    ("no_stage_bytes", None, None, None, "SOCKS_METHOD_UNKNOWN"),
    ("method_denied", bytes.fromhex("05ff"), None, None, "SOCKS_METHOD_DENIED"),
    ("connect_denied", bytes.fromhex("0500"), rejected, None, "SOCKS_CONNECT_REJECTED"),
    ("connect_ok_no_banner", bytes.fromhex("0500"), good, None, "SOCKS_CONNECT_OK_SERVER_BANNER_UNKNOWN"),
    ("server_banner", bytes.fromhex("0500"), good, b"SSH-2.0-test\r\n", "SSH_SERVER_BANNER_OBSERVED"),
    ("truncated_connect", bytes.fromhex("0500"), bytes.fromhex("05000001"), None, "SOCKS_CONNECT_INVALID"),
]
results = []
for name, method, reply, prefix, expected in fixtures:
    observed = classify(method, reply, prefix)
    results.append({"name": name, "expected": expected, "observed": observed, "pass": observed == expected})

stderr = (BASE / "receipts/stderr.raw").read_bytes()
terminal = json.loads((BASE / "receipts/TERMINAL.json").read_text())
assert hashlib.sha256(stderr).hexdigest() == terminal["stderr_sha256"]
historical = classify(None, None, None)
assert terminal["ssh_rc"] == 255 and historical == "SOCKS_METHOD_UNKNOWN"
out = {
    "schema": "evo45-offline-stage-receipt-pilot-v1",
    "fixtures": results,
    "all_fixture_pass": all(x["pass"] for x in results),
    "v4_stderr_sha256": terminal["stderr_sha256"],
    "v4_ssh_rc": terminal["ssh_rc"],
    "v4_proxy_stage_classification_from_existing_receipt": historical,
    "v4_note": "OpenSSH debug text does not record SOCKS5 method or CONNECT reply; client local-version line is not a server banner.",
    "device_commands": 0,
    "ssh_commands": 0,
    "network_commands": 0,
    "container_commands": 0,
    "authoritative_count_delta": 0,
}
with (HERE / "PILOT.json").open("x") as output:
    json.dump(out, output, ensure_ascii=False, indent=2, sort_keys=True)
    output.write("\n")
print(json.dumps(out, sort_keys=True))
