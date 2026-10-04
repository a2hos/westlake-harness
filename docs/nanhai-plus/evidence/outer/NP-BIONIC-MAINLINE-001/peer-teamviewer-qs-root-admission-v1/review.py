#!/usr/bin/env python3
"""Root review of official QuickSupport raw, static and blackbox input evidence."""
import hashlib
import json
import os
from pathlib import Path
import zipfile

root = Path(os.environ["NANHAI_PROJECT_ROOT"])
base = root / "docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001"
raw_dir = base / "peer-teamviewer-qs-official-raw-v1"
static_dir = base / "peer-teamviewer-qs-four-static-v1"
qualification_dir = base / "peer-teamviewer-qs-qualification-v1"
out = Path(__file__).resolve().parent
apk = Path(os.environ["NANHAI_STAGING_ROOT"]) / "peer-teamviewer-qs-official-raw-v1/teamviewer-qs-official.apk"

def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def load(path):
    return json.loads(path.read_text())

raw, verify = load(raw_dir / "RESULT.json"), load(raw_dir / "VERIFY.json")
static, qualification = load(static_dir / "RESULT.json"), load(qualification_dir / "QUALIFICATION.json")
eula = load(qualification_dir / "EULA-SCOPE.json")
assert apk.is_file() and sha(apk) == raw["apk_sha256"] == verify["apk_sha256"] == static["apk_sha256"]
assert apk.stat().st_size == raw["apk_bytes"] == verify["apk_bytes"] == static["apk_bytes"]
assert raw["candidate_pass"] and verify["candidate_pass"] and qualification["candidate_pass"]
assert raw["publisher_page_links_exact_apk"] and raw["publisher_apk_url"] == qualification["publisher_apk_url"]
assert raw["get"]["rc"] == verify["aapt2"]["rc"] == verify["apksigner"]["rc"] == 0
assert verify["package_version"] == ["com.teamviewer.quicksupport.market", "1582264", "15.82.264"]
assert verify["raw_result_sha256"] == sha(raw_dir / "RESULT.json")
assert qualification["play_exact_package_seen"] and qualification["play_publisher_seen"] and qualification["play_50m_seen"]
assert qualification["publisher_exact_apk_href"] and eula["mobile_application_scope_seen"] and eula["source_code_clause_seen"]
assert all(x["rc"] == 0 and x["input_guard_equal"] and x["input_sha256_before"] == x["input_sha256_after"] for x in static["phases"].values())
assert set(static["phases"]) == {"zip", "metadata", "dex", "elf"}
assert static["all_four_phases_rc0"]
with zipfile.ZipFile(apk) as zf:
    names = zf.namelist()
    assert zf.testzip() is None and len(names) == len(set(names)) == 707
    assert sum(name == "AndroidManifest.xml" for name in names) == 1
    assert sum(name.endswith(".dex") for name in names) == 1
    assert sum(name.startswith("lib/arm64-v8a/") and name.endswith(".so") for name in names) == 10
assert static["phases"]["dex"]["semantic_dex_entries"] == 1
assert static["phases"]["elf"]["elf_counts"]["true_arm64_elf"] == static["phases"]["elf"]["readelf_ok"] == 10
assert all(x["container_commands"] == x["device_commands"] == 0 for x in (raw, static, qualification))

result = {"schema": "nanhai-root-teamviewer-qs-admission-v1", "package": verify["package_version"][0],
          "version_code": verify["package_version"][1], "version_name": verify["package_version"][2],
          "apk_sha256": sha(apk), "apk_bytes": apk.stat().st_size,
          "signer_cert_sha256": verify["signer_cert_sha256"][0],
          "raw_receipt_sha256": sha(raw_dir / "RESULT.json"), "verify_receipt_sha256": sha(raw_dir / "VERIFY.json"),
          "static_receipt_sha256": sha(static_dir / "RESULT.json"),
          "qualification_receipt_sha256": sha(qualification_dir / "QUALIFICATION.json"),
          "publisher_url": raw["publisher_page"], "apk_url": raw["publisher_apk_url"],
          "play_url": qualification["play_url"], "raw_delta": 1, "full_static_delta": 1,
          "blackbox_test_input_delta": 1, "semantic_dex_delta": 1, "true_arm64_elf_delta": 10,
          "cold_start_delta": 0, "device_commands": 0, "container_commands": 0,
          "decision": "ACCEPT_OFFICIAL_RAW_FOUR_PHASE_HOST_STATIC_AND_BOUNDED_BLACKBOX_TEST_INPUT_ONLY",
          "limits": "No installed Activity/Bionic runtime proof; Play installs refer to the package, not this exact APK version; source-code absence is not globally proved."}
out.mkdir(exist_ok=True)
(out / "ROOT-ADMISSION.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
print(json.dumps({k: result[k] for k in ("raw_delta", "full_static_delta", "blackbox_test_input_delta", "cold_start_delta")}))
