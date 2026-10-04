#!/usr/bin/env python3
"""Read-only, deterministic peer review of the Snapchat candidate receipts."""
import hashlib
import json
import os
import pathlib
import re
import struct
import subprocess
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
HERE = pathlib.Path(__file__).resolve().parent
RAW = ROOT / "peer-snapchat-official-raw-v1"
STATIC = ROOT / "peer-snapchat-four-static-v2"
QUAL = ROOT / "peer-snapchat-blackbox-qualification-v1"
PRE = ROOT / "peer-mainstream-blackbox-prescreen-v1/PRESCREEN.json"
REG = ROOT / "upstream-apk-registry-v1/REGISTRY.json"
APK = pathlib.Path(os.environ["NANHAI_STAGING_ROOT"]) / "peer-snapchat-official-raw-v1/Snapchat.apk"

def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def js(path):
    return json.loads(path.read_text())

checks = {}
def check(name, good):
    checks[name] = bool(good)

raw = js(RAW / "HANDOFF.json")
verify = js(RAW / "VERIFY.json")
stat = js(STATIC / "FULL-STATIC-HANDOFF.json")
res = js(STATIC / "RESULT.json")
qual = js(QUAL / "QUALIFICATION.json")
final = js(QUAL / "FINAL-HANDOFF.json")
registry = js(REG)
apksha = sha(APK)
check("apk_bytes_sha", APK.stat().st_size == 218350579 and apksha == "77c0ff8a35c513601928a6aed77fbb315b9202f494ac09a2591087f0e909e59b")
check("apk_sha_across_receipts", all(x["apk_sha256"] == apksha for x in (raw, verify, stat, res, qual)))
check("raw_handoff_file_hashes", all((RAW / n).stat().st_size == v["bytes"] and sha(RAW / n) == v["sha256"] for n, v in raw["files"].items()))
check("handoff_chain", sha(PRE) == stat["prescreen_sha256"] == qual["prescreen_sha256"] == final["prescreen_sha256"] and sha(RAW / "HANDOFF.json") == stat["raw_handoff_sha256"] == qual["raw_handoff_sha256"] == final["raw_handoff_sha256"] and sha(STATIC / "FULL-STATIC-HANDOFF.json") == final["complete_static_v2_handoff_sha256"] and sha(QUAL / "QUALIFICATION.json") == final["qualification_candidate_sha256"])
check("static_artifact_hashes", all(sha(STATIC / n) == stat[k] for n, k in (("scan.py", "scan_script_sha256"), ("RESULT.json", "scan_result_sha256"), ("DEX-INVENTORY.json", "root_inventory_sha256"), ("ELF-CLASSIFICATION.json", "elf_classification_sha256"), ("ELF-INVENTORY.json", "elf_inventory_sha256"), ("embedded-dex-v1/RESULT.json", "embedded_result_sha256"), ("embedded-dex-v1/DEX-INVENTORY.json", "embedded_inventory_sha256"))))
support = (RAW / "support-page.raw").read_text(errors="replace")
headers = (RAW / "publisher-get-headers.raw").read_text(errors="replace").lower()
check("publisher_chain", 'href="https://www.snapchat.com/additionaldownloads/"' in support and "location: /additionaldownloads" in headers and "location: https://storage.googleapis.com/snapchat-web/download/android-apks_universal.apk" in headers and "content-length: 218350579" in headers and "application/vnd.android.package-archive" in headers)

tool_results = {}
for name in ("aapt2", "apksigner"):
    argv = verify[name]["argv"]
    check(name + "_tool_exists", pathlib.Path(argv[0]).is_file())
    p = subprocess.run(argv, capture_output=True)
    tool_results[name] = {"rc": p.returncode, "stdout_sha256": hashlib.sha256(p.stdout).hexdigest(), "stderr_sha256": hashlib.sha256(p.stderr).hexdigest()}
    check(name + "_replay", p.returncode == 0 and tool_results[name]["stdout_sha256"] == verify[name]["stdout_sha256"] and tool_results[name]["stderr_sha256"] == verify[name]["stderr_sha256"])
    if name == "aapt2":
        badging = p.stdout.decode(errors="replace")
        check("package_version", bool(re.search(r"package: name='com\.snapchat\.android' versionCode='316472' versionName='14\.25\.0\.43'", badging)))
    else:
        signer = p.stdout.decode(errors="replace").lower()
        check("signer_cert", "c7e9caf66dbe343daea2b3d9e756f7b1d913de310797cf3617ce32974617cf48" in signer.replace(":", ""))

zf = js(STATIC / "ZIP-FACTS.json")
cls = js(STATIC / "ELF-CLASSIFICATION.json")
embedded = js(STATIC / "embedded-dex-v1/RESULT.json")
with zipfile.ZipFile(APK) as z:
    names = z.namelist()
    check("zip_integrity", z.testzip() is None and len(names) == 11745 and len(set(names)) == len(names))
    roots = sorted(n for n in names if re.fullmatch(r"classes(?:[0-9]+)?\.dex", n))
    dexall = sorted(n for n in names if n.endswith(".dex"))
    sos = sorted(n for n in names if n.startswith("lib/") and n.endswith(".so"))
    asset_sos = sorted(n for n in names if not n.startswith("lib/") and n.endswith(".so"))
    check("zip_manifest_dex_so", names.count("AndroidManifest.xml") == 1 and len(roots) == 10 and len(dexall) == 11 and len(sos) == 60 and len(asset_sos) == 3 and sorted(zf["root_dex_names"]) == roots and sorted(zf["all_dex_names"]) == dexall and sorted(zf["so_names"]) == sos and zf["entries"] == len(names))
    check("dex_magic", all(z.read(n)[:4] == b"dex\n" for n in dexall))
    asset = z.read("assets/secondary-dex/native_specs_crypto_lib.dex")
    check("embedded_dex", len(asset) == embedded["asset_bytes"] and hashlib.sha256(asset).hexdigest() == embedded["asset_sha256"] and embedded["rc"] == 0 and embedded["total_semantic_dex_entries"] == 11)
    actual = {"true_arm64_elf": [], "other_arm32_elf": [], "arm64_path_arm32_elf": [], "non_elf_so": [], "other_elf": []}
    rows_ok = True
    for category, rows in cls.items():
        if not isinstance(rows, list):
            continue
        for row in rows:
            n = row["name"]
            b = z.read(n)
            elf = len(b) >= 20 and b[:4] == b"\x7fELF"
            ec = b[4] if elf else None
            machine = struct.unpack("<H", b[18:20])[0] if elf and b[5] == 1 else None
            rows_ok &= len(b) == row["bytes"] and hashlib.sha256(b).hexdigest() == row["sha256"] and ec == row.get("elf_class") and machine == row.get("machine")
            if not elf: actual["non_elf_so"].append(n)
            elif n.startswith("lib/arm64-v8a/") and ec == 2 and machine == 183: actual["true_arm64_elf"].append(n)
            elif n.startswith("lib/arm64-v8a/") and ec == 1 and machine == 40: actual["arm64_path_arm32_elf"].append(n)
            elif ec == 1 and machine == 40: actual["other_arm32_elf"].append(n)
            else: actual["other_elf"].append(n)
    check("elf_rows_sha_headers", rows_ok)
    check("elf_full_classification", all(sorted(actual[k]) == sorted(r["name"] for r in cls[k]) for k in actual) and sum(len(v) for v in actual.values()) == len(sos) and len(actual["true_arm64_elf"]) == len(actual["other_arm32_elf"]) == 30)

check("four_phase_rc_guards", set(res["phases"]) == {"zip", "metadata", "dex", "elf"} and all(p["rc"] == 0 and p["input_guard_equal"] and p["input_sha256_before"] == p["input_sha256_after"] for p in res["phases"].values()) and stat["private_tmp_empty_after"] and stat["semantic_root_dex"] == 10 and stat["semantic_embedded_dex"] == 1 and stat["semantic_total_dex"] == 11)
up = next(x for x in registry["artifacts"] if x["id"] == "a-11ed4add5570205856b8")
regrec = next(x for x in registry["records"] if x["id"] == "r-9690b1b1d1083c1406e2")
oldcert = regrec["fields"]["certificate_sha256"]["value"]
check("upstream_distinct_variant", up["package"] == "com.snapchat.android" and up["sha256"] == "a37383d12c69982786fd8a45ba4271bb16ada2ebc2f7d051e2830a2cb103d178" and up["split_counts"] == [18] and up["versions"] == ["14.25.0.43"] and up["sha256"] != apksha and oldcert != verify["signer_cert_sha256"][0])
play = (QUAL / "play.raw").read_text(errors="replace")
check("play_same_package_market", "com.snapchat.android" in play and "Snap Inc." in play and ("1,000,000,000+" in play or "1B+" in play) and sha(QUAL / "play.raw") == qual["play_page_sha256"])
check("bounded_source_snapshot", sha(QUAL / "publisher_repos.raw") == qual["publisher_repositories_page_sha256"] and qual["source_scope"].startswith("Bounded "))
check("count_device_boundary", not any(x.get("authoritative_count_changed", False) for x in (stat, final, embedded)) and not qual["qualification_count_changed"] and not qual["raw_count_changed"] and not qual["static_count_changed"] and not stat["startup_proven"] and qual["device_commands"] == 0 and qual["container_commands"] == 0)

raw_names = ["apk_bytes_sha", "apk_sha_across_receipts", "raw_handoff_file_hashes", "publisher_chain", "aapt2_replay", "apksigner_replay", "package_version", "signer_cert", "upstream_distinct_variant"]
static_names = ["handoff_chain", "static_artifact_hashes", "zip_integrity", "zip_manifest_dex_so", "dex_magic", "embedded_dex", "elf_rows_sha_headers", "elf_full_classification", "four_phase_rc_guards"]
black_names = ["play_same_package_market", "bounded_source_snapshot", "count_device_boundary"]
out = {
    "schema": "peer-snapchat-independent-review-v1",
    "apk_sha256": apksha,
    "package": "com.snapchat.android",
    "version_name": "14.25.0.43",
    "version_code": 316472,
    "signer_cert_sha256": verify["signer_cert_sha256"][0],
    "upstream_xapk": {"artifact_id": up["id"], "sha256": up["sha256"], "split_count": 18, "registered_certificate_sha256": oldcert, "identity": "separate supplemental variant"},
    "tool_replay": tool_results,
    "checks": checks,
    "decisions": {
        "raw": "GO_OFFICIAL_UNIVERSAL_SUPPLEMENTAL_VARIANT" if all(checks[k] for k in raw_names) else "NO_GO",
        "static": "GO_COMPLETE_HOST_STATIC" if all(checks[k] for k in static_names) else "NO_GO",
        "blackbox": "GO_BOUNDED_TEST_QUALIFICATION_ONLY" if all(checks[k] for k in black_names) else "NO_GO",
    },
    "limits": ["No independent publisher certificate pin; publisher direct GET chain and APK signature verification are observed.", "Historical registered 18-split XAPK has a different SHA and recorded certificate fingerprint; no variant/signature equivalence is inferred.", "The GitHub publisher repository snapshot is a bounded source check, not proof that no source exists anywhere.", "Host static and package-wide Play market data do not prove installation, Bionic compatibility, cold start, rendering, or version-specific installs."],
}
print(json.dumps(out, indent=2, sort_keys=True))
sys.exit(0 if all(checks.values()) else 1)
