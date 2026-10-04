#!/usr/bin/env python3
"""Offline, narrow pre-freeze controller-snapshot contract pilot."""
import ast
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).parent
BASE = HERE.parent.parent
RUNNER = BASE / "g279-private-mihomo-v2a-syntax-candidate-v1/runner.py"
EXPECTED_RUNNER = "3b342f21ed3c3ebcd1bae47a5c749685a9012a0dc99bf9d35d95647d6a024cf0"
assert hashlib.sha256(RUNNER.read_bytes()).hexdigest() == EXPECTED_RUNNER

tree = ast.parse(RUNNER.read_text())
execute = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "execute")
calls = []
for node in ast.walk(execute):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        calls.append({"name": node.func.id, "line": node.lineno})
calls.sort(key=lambda x: x["line"])
write_line = min(x["line"] for x in calls if x["name"] == "write_once")
identity_reads = [x for x in calls if x["name"] in {"stable_read", "active_process", "current_leaf"}]
late_reads = [x for x in identity_reads if x["line"] > max(x["line"] for x in calls if x["name"] == "private_dir") and x["line"] < write_line]

def boundary_gate(before, late):
    keys = ("source_sha256", "process_pid", "process_uid", "socket_dev", "socket_ino", "peer_pid", "peer_uid", "selected_leaf_digest")
    return all(before.get(key) is not None and before.get(key) == late.get(key) for key in keys)

baseline = {"source_sha256": "a" * 64, "process_pid": 101, "process_uid": 0, "socket_dev": 1, "socket_ino": 9001, "peer_pid": 101, "peer_uid": 0, "selected_leaf_digest": "b" * 64}
cases = []
for name, mutation, expected in [
    ("stable", {}, True),
    ("selection_changes", {"selected_leaf_digest": "c" * 64}, False),
    ("source_changes", {"source_sha256": "d" * 64}, False),
    ("socket_replaced", {"socket_ino": 9002}, False),
    ("peer_changes", {"peer_pid": 102}, False),
    ("missing_readback", {"selected_leaf_digest": None}, False),
]:
    late = dict(baseline, **mutation)
    actual = boundary_gate(baseline, late)
    cases.append({"name": name, "expected": expected, "actual": actual, "pass": expected == actual})

result = {
    "schema": "evo46-offline-boundary-precheck-pilot-v1",
    "runner_sha256": EXPECTED_RUNNER,
    "v2a_identity_read_calls": identity_reads,
    "v2a_private_write_line": write_line,
    "v2a_late_identity_read_calls": late_reads,
    "v2a_late_boundary_contract_met": bool(late_reads),
    "synthetic_fixtures": cases,
    "all_synthetic_fixtures_pass": all(x["pass"] for x in cases),
    "scope_limit": "AST check only detects named identity read calls in this exact runner and does not prove future semantic equivalence or real controller safety.",
    "network_commands": 0,
    "ssh_commands": 0,
    "device_commands": 0,
    "container_commands": 0,
    "authoritative_count_delta": 0,
}
with (HERE / "PILOT.json").open("x") as out:
    json.dump(result, out, ensure_ascii=False, indent=2, sort_keys=True)
    out.write("\n")
print(json.dumps(result, sort_keys=True))
