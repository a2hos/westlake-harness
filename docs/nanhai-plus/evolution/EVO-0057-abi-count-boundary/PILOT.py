#!/usr/bin/env python3
"""Offline replay of the ARM64 portfolio count boundary; no APK or device access."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
BASE = ROOT / "docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001"
CAP = BASE / "g343-capcut-four-static-v1/phases/elf/ELF-CLASSIFICATION.json"
FOSS = BASE / "peer-apk-portfolio-fossify-clock-static-v1/ELF-RESULT.json"


def read(path):
    blob = path.read_bytes()
    return json.loads(blob), hashlib.sha256(blob).hexdigest()


cap, cap_sha = read(CAP)
foss, foss_sha = read(FOSS)
misplaced = cap["arm64_path_misplaced_arm32_elf"]
assert len(misplaced) == 1
assert all(x["name"].startswith("lib/arm64-v8a/") and x["class"] == 1 and x["machine"] == 40 for x in misplaced)
assert all(x["name"].startswith("lib/arm64-v8a/") and x["class"] == 2 and x["machine"] == 183 for x in cap["true_arm64_elf"])
assert all(x["name"].startswith("lib/armeabi-v7a/") and x["class"] == 1 and x["machine"] == 40 for x in cap["other_arm32_elf"])
assert len(cap["true_arm64_elf"]) + len(misplaced) + len(cap["other_arm32_elf"]) == cap["archive_so_count"]
assert foss["arm64_elf_entries"] == foss["abi_matches_machine"] == 1
out = {
    "schema": "evo57-offline-abi-count-pilot-v1",
    "source_sha256": {"capcut_classification": cap_sha, "fossify_elf_result": foss_sha},
    "capcut": {
        "arm64_path_entries": len(cap["true_arm64_elf"]) + len(misplaced),
        "verified_arm64_elf": len(cap["true_arm64_elf"]),
        "misplaced_arm32_in_arm64_path": len(misplaced),
        "misplaced_member": misplaced[0]["name"],
        "correctly_placed_arm32": len(cap["other_arm32_elf"]),
        "path_only_overcount": len(misplaced),
    },
    "fossify_clock_negative_control": {"arm64_path_entries": 1, "verified_arm64_elf": 1, "mismatch": 0},
    "claim_boundary": "Static ABI inventory only; no install, load, startup or package-wide failure inference",
    "device_calls": 0,
    "container_calls": 0,
    "network_calls": 0,
    "production_edits": 0,
}
print(json.dumps(out, sort_keys=True, indent=2))
