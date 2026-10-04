#!/usr/bin/env python3
"""Read-only scanner readiness, deliberately not a provider scan."""
import hashlib
import json
import os
from pathlib import Path
import sys

root = Path(os.environ["NANHAI_PROJECT_ROOT"])
runtime = Path(os.environ["NANHAI_RUNTIME_ROOT"])
out = Path(os.environ["NANHAI_OUT_ROOT"])
checkpoint = root / "docs/nanhai-plus/checkpoints/20261004-raw135-static135-blackbox28-upstream95-evo61/CHECKPOINT.json"
cli = root / "harness/westlake_gap/cli.py"
scanner = root / "harness/westlake_gap/scanner.py"
nativeprov = root / "harness/westlake_gap/nativeprov.py"
sample = root / "docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/peer-upstream-next4c-exact-v1/io.pcontacts.app"
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
read = lambda p: json.loads(p.read_text())
cp = read(checkpoint)
c = cli.read_text()
s = scanner.read_text()
static = read(sample / "STATIC.json")
raw = read(sample / "RAW.json")
historical = []
for p in sorted((runtime / "source/benchmark").glob("*/runtime-lock.json")):
    x = read(p)
    historical.append({"relative_path": str(p.relative_to(root)), "sha256": sha(p), "target_abi": x.get("target_abi"), "boot_classpath_count": len(x.get("boot_classpath", [])), "bridge_elf_count": len(x.get("bridge_libraries", [])), "system_elf_count": len(x.get("system_libraries", [])), "first_bcp_path": x.get("boot_classpath", [{}])[0].get("path"), "runtime_lock_id": x.get("runtime_lock_id")})
target_files = {name: [str(p.relative_to(root)) for p in out.rglob(name) if p.is_file()] for name in ("core-oj.jar", "libart.so", "libc.so", "runtime-lock.json")}
checks = {
    "frozen_135_inventory_control": cp["full_host_static_accepted"] == cp["raw_accepted"] == 135 and cp["semantic_dex_entries"] == 546 and cp["true_arm64_elf_entries"] == 2103,
    "runtime_scan_requires_index": 'scan.add_argument("--runtime", required=True' in c and 'runtime = read_json(args.runtime)' in c and 'RuntimeResolver(runtime)' in s,
    "snapshot_requires_ordered_bcp": 'snapshot-runtime requires --jar or --classpath-file' in c and '"boot_classpath": [record["sha256"] for record in artifact_records]' in s,
    "snapshot_content_locks_native_providers": '"bridge_libraries": [record["sha256"] for record in elf_records]' in s and '"system_libraries": [record["sha256"] for record in system_records]' in s,
    "missing_system_index_is_blind": '"native_import_coverage", "O-BLIND"' in s,
    "accepted_static_sample": static["four_phase_rc0"] and raw["actual_sha256"] == static["apk_sha256"] and all(v["rc"] == 0 for v in static["phases"].values()),
    "no_current_r4_target_outputs_in_registered_out": all(not v for v in target_files.values()),
    "no_graph_or_runtime_run": cp["graph_result_observed"] is False and cp["cold_start_verified"] == 0,
    "historical_locks_lack_system_elf_index": bool(historical) and all(x["system_elf_count"] == 0 for x in historical),
}
result = {"schema": "peer-scanner-runtime-readiness-135-v1", "decision": "INVENTORY_READY_RUNTIME_RESOLUTION_BLIND" if all(checks.values()) else "CHECK_FAILED", "checks": checks, "all_checks_pass": all(checks.values()), "inputs": {"checkpoint": {"path": str(checkpoint.relative_to(root)), "sha256": sha(checkpoint)}, "cli_sha256": sha(cli), "scanner_sha256": sha(scanner), "nativeprov_sha256": sha(nativeprov), "sample_raw_sha256": sha(sample / "RAW.json"), "sample_static_sha256": sha(sample / "STATIC.json")}, "inventory": {"accepted_apks": 135, "semantic_dex": 546, "true_arm64_elf": 2103}, "historical_runtime_locks": historical, "current_out_target_files": target_files, "can_now": ["existing exact APK ZIP/manifest/DEX/packaged ARM64 ELF inventory with per-APK input SHA guard", "package-local declared symbols, DT_NEEDED, JNI names, and ABI exposure as static candidates"], "blind_or_unknown": ["full scan/benchmark missing-class, missing-method, missing-field findings against target R4 boot classpath", "JNI binding/provider resolution against actual Bionic bridge ELFs", "native imports resolved against deployed R4 Bionic/system ELF exports; missing system index is O-BLIND", "dynamic loading, runtime reachability, install, lifecycle and cold start"], "minimum_next": "On a verified native R4/Bionic build host, freeze ordered boot-classpath JAR SHA-256 values plus same-build ARM64 bridge and system ELF SHA-256 values; generate snapshot-runtime with target ABI arm64-v8a, retain full index and runtime_lock_id, independently verify source/build/target provenance, then pilot scan one frozen APK before 135-way benchmark.", "device_commands": 0, "container_commands": 0, "bridge_commands": 0, "runtime_scans_executed": 0}
print(json.dumps(result, sort_keys=True, indent=2))
sys.exit(0 if result["all_checks_pass"] else 2)
