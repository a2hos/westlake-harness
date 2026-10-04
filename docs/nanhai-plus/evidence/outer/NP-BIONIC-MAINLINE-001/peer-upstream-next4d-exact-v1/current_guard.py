#!/usr/bin/env python3
"""Freeze current 95/338 control identity and selected-artifact anti-join."""
import hashlib
import json
import os
from pathlib import Path
import sys

root = Path(os.environ["NANHAI_PROJECT_ROOT"])
here = Path(__file__).resolve().parent
base = here.parent
read = lambda p: json.loads(p.read_text())
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
sel = read(here / "SELECTION.json")
registry = base / "upstream-apk-registry-v1/REGISTRY.json"
audit = base / "peer-upstream-artifact-gap-audit-v1/RESULT.json"
checkpoint = root / "docs/nanhai-plus/checkpoints/20261004-raw135-static135-blackbox28-upstream95-evo61/CHECKPOINT.json"
cp = read(checkpoint)
accepted_old = read(audit)["accepted_exact_upstream"]
root_receipts = [read(p) for p in base.rglob("ROOT-RAW-ADMISSION.json") if here not in p.parents]
accepted_sha = {x.get("apk_sha256") for x in root_receipts if x.get("decision", "").startswith("ACCEPT")}
old_sha = {x.get("sha256") for x in accepted_old}
selected_sha = {x["expected_sha256"] for x in sel["rows"]}
checks = {
    "registry_frozen": sha(registry) == sel["registry_sha256"],
    "old_audit_frozen": sha(audit) == sel["audit_result_sha256"],
    "current_checkpoint_frozen": sha(checkpoint) == sel["current_checkpoint_sha256"],
    "current_checkpoint_95_of_338": cp["upstream_exact_raw_accepted"] == 95 and cp["upstream_registry_artifacts"] == 338,
    "four_distinct_packages_and_artifacts": len({x["package"] for x in sel["rows"]}) == len({x["artifact_id"] for x in sel["rows"]}) == 4,
    "not_in_older_accepted_79": not (selected_sha & old_sha),
    "not_in_individual_root_raw_receipts": not (selected_sha & accepted_sha),
}
out = {"schema": "peer-upstream-next4d-current-guard-v1", "checks": checks, "all_pass": all(checks.values()), "checkpoint_sha256": sha(checkpoint), "registry_sha256": sha(registry), "selected_sha256": sorted(selected_sha), "individual_root_raw_receipts_inspected": len(root_receipts), "limits": "Older gap audit freezes the original 79; current checkpoint freezes 95/338. Individual root receipts are an additional anti-join, not a full reconstruction of all 95 admissions.", "device_commands": 0, "container_commands": 0}
print(json.dumps(out, sort_keys=True, indent=2))
sys.exit(0 if out["all_pass"] else 2)
