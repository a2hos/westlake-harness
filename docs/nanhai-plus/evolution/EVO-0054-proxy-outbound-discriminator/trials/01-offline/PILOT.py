"""Offline information boundary check; no network, proxy or runner calls."""

def classify(rule, outbound, ssh_banner):
    if not rule:
        return "NO_RULE_EVIDENCE"
    if outbound is None:
        return "LOCAL_RULE_ONLY"
    if outbound == "NO_ATTEMPT":
        return "NODE_OUTBOUND_NOT_ATTEMPTED"
    if outbound == "CONNECT_FAILED":
        return "NODE_OUTBOUND_CONNECT_FAILED"
    if outbound == "CONNECT_OK" and not ssh_banner:
        return "NODE_CONNECT_ONLY_NO_SSH_BANNER"
    if outbound == "CONNECT_OK" and ssh_banner:
        return "SSH_BANNER_OBSERVED_HOSTKEY_UNKNOWN"
    raise ValueError("invalid outbound witness")

assert classify(True, None, False) == "LOCAL_RULE_ONLY"  # actual v6
assert classify(True, "NO_ATTEMPT", False) == "NODE_OUTBOUND_NOT_ATTEMPTED"
assert classify(True, "CONNECT_FAILED", False) == "NODE_OUTBOUND_CONNECT_FAILED"
assert classify(True, "CONNECT_OK", False) == "NODE_CONNECT_ONLY_NO_SSH_BANNER"
assert classify(True, "CONNECT_OK", True) == "SSH_BANNER_OBSERVED_HOSTKEY_UNKNOWN"
assert classify(False, None, False) == "NO_RULE_EVIDENCE"
assert all("HOSTKEY" not in classify(True, x, False) for x in (None, "NO_ATTEMPT", "CONNECT_FAILED", "CONNECT_OK"))
print("PASS_OFFLINE_BOUNDARY actual_v6=LOCAL_RULE_ONLY discriminating_synthetic_cases=4 network_calls=0")
