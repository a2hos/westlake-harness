#!/usr/bin/env python3
"""Offline receipt-joined dependency-cut allocation pilot; no dispatch."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).parent
BASE = HERE.parent.parent
SUMMARY = BASE.parent.parent.parent / "TASK-SUMMARY.json"

def read(rel):
    path = BASE / rel
    data = path.read_bytes()
    return json.loads(data), hashlib.sha256(data).hexdigest()

summary = json.loads(SUMMARY.read_text())
portfolio = summary["apk_portfolio"]
hide, hide_sha = read("g327-hideme-four-static-candidate-v1/ROOT-STATIC-ADMISSION.json")
no_go, no_go_sha = read("g279-private-mihomo-v2a-syntax-candidate-v2/ROOT-NO-GO.json")
syntax, syntax_sha = read("g279-private-mihomo-v2a-syntax-candidate-v3/ROOT-POSTRUN-ACCEPTANCE.json")
raw, raw_sha = read("blackbox-adguardvpn-official-intake-candidate-v1/ROOT-RAW-ADMISSION.json")
static, static_sha = read("g328-adguardvpn-four-static-candidate-v1/ROOT-STATIC-ADMISSION.json")
qualified, qualified_sha = read("g329-adguardvpn-blackbox-qualification-candidate-v1/ROOT-QUALIFICATION.json")

assert portfolio["downloaded_payloads"] == 102
assert portfolio["complete_static_inventories"] == 100
assert portfolio["cold_start_verified"] == 0
assert portfolio["qualified_blackbox_startups"] == 0
assert hide["static_after"] == 99 and static["static_after"] == 100
assert raw["raw_after"] == 102 and qualified["qualified_after"] == 17
assert no_go["release_issued"] is False
assert syntax["actual_syntax_rc"] == 0 and syntax["private_proxy_process_started"] is False
assert syntax["gz02_connected"] is False

cohort = {
    "root_raw_delta": raw["raw_after"] - raw["raw_before"],
    "four_phase_static_delta": (hide["static_after"] - hide["static_before"]) + (static["static_after"] - static["static_before"]),
    "qualified_blackbox_input_delta": qualified["qualified_after"] - qualified["qualified_before"],
    "verified_cold_start_delta": sum(x.get("cold_start_delta", x.get("startup_delta", 0)) for x in (hide, raw, static, qualified, syntax, no_go)),
}
assert cohort == {"root_raw_delta": 1, "four_phase_static_delta": 2, "qualified_blackbox_input_delta": 1, "verified_cold_start_delta": 0}

decision = {
    "schema": "evo47-dependency-cut-offline-pilot-v1",
    "summary_sha256": hashlib.sha256(SUMMARY.read_bytes()).hexdigest(),
    "input_sha256": {"hide_static": hide_sha, "v2a_v2_no_go": no_go_sha, "v2a_v3_syntax": syntax_sha, "adguard_raw": raw_sha, "adguard_static": static_sha, "adguard_qualification": qualified_sha},
    "portfolio": {"raw": 102, "four_phase_static": 100, "qualified_blackbox_inputs": 17, "verified_cold_starts": 0},
    "cohort_observed_delta": cohort,
    "shared_gate_readback": {"private_syntax_rc0": True, "private_listener_observed": False, "gz02_ssh_observed": False, "native_graph_observed": False},
    "candidate_allocation_trial": "Temporarily assign one otherwise incremental-APK-intake agent to a bounded v2b local listener/route readback packet; keep an independent intake lane. This is a recommendation only, no dispatch.",
    "why_next_gate": "Exact syntax is accepted, but no private process/listener/remote path exists; another raw/static input cannot itself establish the missing shared host gate.",
    "trial_success_receipt": "Peer/root accepted v2b local listener identity and route behavior, with exact process and no global proxy mutation; still not a startup.",
    "trial_falsifier": "Fresh state shows an already accepted independent route/graph, or v2b packet cannot pass offline controls; then recompute cut instead of spending another cycle on this route.",
    "fanout_note": "100 static inputs are a potential downstream backlog, not 100 proven launches; this pilot does not assign a numeric expected startup gain.",
    "no_dispatch": True,
    "device_commands": 0,
    "container_commands": 0,
    "network_commands": 0,
    "count_delta": 0,
}
with (HERE / "PILOT.json").open("x") as out:
    json.dump(decision, out, ensure_ascii=False, indent=2, sort_keys=True)
    out.write("\n")
print(json.dumps({"cohort": cohort, "verified_cold_starts": 0, "private_listener_observed": False, "no_dispatch": True}, sort_keys=True))
