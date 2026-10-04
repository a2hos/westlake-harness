#!/usr/bin/env python3
"""Independent read-only verification of the G343 host static receipts."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import zipfile

ROOT = Path(os.environ["NANHAI_PROJECT_ROOT"])
BASE = ROOT / "docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001"
C = BASE / "g343-capcut-four-static-v1"
RAW = BASE / "g316-capcut-official-raw-candidate-v2/root-raw-admission-v1/ROOT-RAW-ADMISSION.json"
BLACKBOX = BASE / "g317-capcut-blackbox-qualification-candidate-v1/root-qualification-v1/ROOT-QUALIFICATION.json"
APK = Path(os.environ["NANHAI_STAGING_ROOT"]) / "g316-capcut-official-v1/CapCut.apk"
HERE = Path(__file__).parent

def sha(p):
    h = hashlib.sha256()
    with p.open("rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()

def j(p):
    return json.loads(p.read_text())

def main():
    if sys.argv[1:] != ["--execute"] or (HERE / "REVIEW.json").exists():
        return 2
    checks = {}
    def ck(name, ok):
        checks[name] = bool(ok)

    raw, blackbox, start, result, handoff = map(j, (RAW, BLACKBOX, C / "START.json", C / "RESULT.json", C / "HANDOFF.json"))
    apk_sha = sha(APK)
    ck("apk_exact_bytes", APK.stat().st_size == 319992455 and apk_sha == "f2d5cf017bc4bf5a2d3e500a1a8c13cf0c83e3fa1bc707c6603e91af9b77612a")
    ck("raw_admission", raw["apk_sha256"] == apk_sha and raw["decision"] == "ACCEPT_EXACT_CAPCUT_13_6_0_HOST_RAW_ONLY_WITH_ARM64_PATH_EXCEPTION" and sha(RAW) == start["raw_admission_sha256"] == handoff["raw_admission_sha256"])
    ck("blackbox_qualification", blackbox["apk_sha256"] == apk_sha and blackbox["decision"] == "ACCEPT_EXACT_PACKAGE_BLACKBOX_TEST_QUALIFICATION_ONLY" and blackbox["root_raw_admission_sha256"] == sha(RAW))
    ck("frozen_sources", sha(C / "run.py") == start["runner_sha256"] and sha(C / "scan_phase.py") == start["phase_script_sha256"] and sha(ROOT / "harness/westlake_gap/scanner.py") == start["scanner_sha256"] == handoff["scanner_sha256"])
    readelf = ROOT / ".nanhai-plus-runtime/bionic-oh7-aosp16/inputs-view/harness-native-hosttool-v1/bin/readelf"
    ck("readelf_frozen", readelf.is_symlink() and sha(readelf) == start["readelf_sha256"])
    ck("start_result_handoff", sha(C / "START.json") == handoff["start_sha256"] and sha(C / "RESULT.json") == handoff["result_sha256"] and result["rc"] == 0 and result["all_four_phases_rc0"] and result["nonce"] == start["nonce"])

    command_checks, phase_checks = {}, {}
    expected_input = {"apk": apk_sha, "raw_admission": sha(RAW), "scanner": sha(ROOT / "harness/westlake_gap/scanner.py")}
    venv_python = ROOT / ".nanhai-plus-runtime/bionic-oh7-aosp16/venvs/harness-python-v1/bin/python3"
    for phase in ("zip", "metadata", "dex", "elf"):
        row = j(C / f"{phase}-COMMAND.json")
        p = j(C / "phases" / phase / "RESULT.json")
        command_checks[phase] = (row == result["rows"][("zip", "metadata", "dex", "elf").index(phase)] and row["rc"] == 0 and not row["timed_out"] and row["argv"] == [str(venv_python), "-I", "-B", str(C / "scan_phase.py"), phase] and sha(C / f"{phase}-stdout.raw") == row["stdout_sha256"] and sha(C / f"{phase}-stderr.raw") == row["stderr_sha256"] and sha(C / f"{phase}-COMMAND.json") == handoff["phases"][phase]["command_sha256"])
        phase_checks[phase] = (p["rc"] == 0 and p["input_guard_equal"] is True and p["input_sha256_before"] == p["input_sha256_after"] == expected_input and sha(C / "phases" / phase / "RESULT.json") == handoff["phases"][phase]["phase_result_sha256"])
    ck("phase_commands", all(command_checks.values()))
    ck("phase_input_guards", all(phase_checks.values()))

    dex = j(C / "phases/dex/DEX-INVENTORY.json")["dex_entries"]
    classification = j(C / "phases/elf/ELF-CLASSIFICATION.json")
    records = j(C / "phases/elf/ELF-INVENTORY.json")
    expected_classes = {name: {x["name"]: x for x in classification[name]} for name in ("true_arm64_elf", "arm64_path_misplaced_arm32_elf", "other_arm32_elf", "other_elf", "non_elf_so")}
    observed = {name: {} for name in expected_classes}
    dex_match = []
    with zipfile.ZipFile(APK) as z:
        names = z.namelist()
        crc_first_bad = z.testzip()
        for entry in dex:
            data = z.read(entry["name"])
            dex_match.append(len(data) == entry["bytes"] and hashlib.sha256(data).hexdigest() == entry["sha256"] and data[:4] == b"dex\n")
        for name in names:
            if not (name.startswith("lib/") and name.endswith(".so")):
                continue
            data = z.read(name)
            if data[:4] != b"\x7fELF":
                kind = "non_elf_so"
                row = {"name": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "kind": "non_elf", "magic": data[:8].hex()}
            else:
                endian = data[5]
                machine = struct.unpack("<H" if endian == 1 else ">H", data[18:20])[0]
                bits = data[4]
                row = {"name": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "kind": "elf", "class": bits, "endian": endian, "machine": machine}
                abi = name.split("/")[1]
                if bits == 2 and machine == 183 and abi == "arm64-v8a": kind = "true_arm64_elf"
                elif bits == 1 and machine == 40 and abi == "arm64-v8a": kind = "arm64_path_misplaced_arm32_elf"
                elif bits == 1 and machine == 40: kind = "other_arm32_elf"
                else: kind = "other_elf"
            observed[kind][name] = row
    ck("zip_complete_crc_names", len(names) == len(set(names)) == handoff["zip_entries"] == 27633 and crc_first_bad is None and names.count("AndroidManifest.xml") == 1)
    ck("dex_24_content", len(dex) == 24 and all(dex_match) and len({e["name"] for e in dex}) == 24)
    ck("elf_full_292_classification", classification["archive_so_count"] == 292 and observed == expected_classes and {k: len(v) for k, v in observed.items()} == {"true_arm64_elf": 146, "arm64_path_misplaced_arm32_elf": 1, "other_arm32_elf": 145, "other_elf": 0, "non_elf_so": 0})
    misplaced = observed["arm64_path_misplaced_arm32_elf"].get("lib/arm64-v8a/libcvt.so", {})
    ck("misplaced_libcvt_exact", misplaced.get("sha256") == "336c9807054a2f88703509b6f27edd9d7c82acdbc7f2a50d6b0e2d5c79697153" and misplaced.get("class") == 1 and misplaced.get("machine") == 40)
    ck("readelf_records_146", len(records) == 146 and {r.get("archive_entry") for r in records} == set(observed["true_arm64_elf"]) and all(r.get("readelf_ok") is True and r.get("abi_matches_machine") is True for r in records))
    ck("inventory_hashes", sha(C / "phases/dex/DEX-INVENTORY.json") == handoff["inventory_sha256"]["dex"] and sha(C / "phases/elf/ELF-CLASSIFICATION.json") == handoff["inventory_sha256"]["classification"] and sha(C / "phases/elf/ELF-INVENTORY.json") == handoff["inventory_sha256"]["elf"])
    manifest = j(C / "phases/metadata/MANIFEST.json")
    ck("manifest_identity", manifest.get("package") == "com.lemon.lvoverseas" and manifest.get("version_name") == "13.6.0" and str(manifest.get("version_code")) == "13601600" and str(manifest.get("target_sdk")) == "34" and manifest.get("sha256") == apk_sha)

    passed = all(checks.values())
    review = {"schema": "peer-g343-capcut-static-review-v1", "at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "decision": "ACCEPT_G343_HOST_STATIC_ONLY_WITH_MISPLACED_ARM32_RISK" if passed else "NO_GO", "checks": checks, "phase_command_checks": command_checks, "phase_receipt_checks": phase_checks, "observed_counts": {"zip_entries": len(names), "dex_entries": len(dex), "elf": {k: len(v) for k, v in observed.items()}}, "apk_sha256": apk_sha, "apk_bytes": APK.stat().st_size, "candidate_handoff_sha256": sha(C / "HANDOFF.json"), "raw_admission_sha256": sha(RAW), "blackbox_qualification_sha256": sha(BLACKBOX), "actual_review_command": {"argv": [sys.executable, str(Path(__file__)), "--execute"], "interpreter": sys.executable, "python_version": sys.version, "wrapper": "python3 scripts/nanhai_plus_env.py --run"}, "original_phase_interpreter": str(venv_python), "limits": ["Host ZIP/metadata/DEX/ELF only; does not prove install, loader acceptance, Bionic compatibility, Activity lifecycle, UI, or cold start", "lib/arm64-v8a/libcvt.so is ELF32 EM_ARM and must remain a distinct runtime risk", "Existing raw and blackbox root admissions are cited, not reissued; authoritative counts unchanged by this peer review"], "device_commands": 0, "container_commands": 0, "ssh_commands": 0, "authoritative_count_changed": False}
    (HERE / "REVIEW.json").write_text(json.dumps(review, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"decision": review["decision"], "checks": checks, "counts": review["observed_counts"]}, sort_keys=True))
    return 0 if passed else 2

if __name__ == "__main__":
    sys.exit(main())
