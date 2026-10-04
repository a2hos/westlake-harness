#!/usr/bin/env python3
"""Freeze the pre-batch-105 root-accepted package set; fail closed on drift."""

import hashlib
import json
from pathlib import Path

BASE = Path("docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001")
V1 = BASE / "g339-cross-apk-exposure-cohort-v1/RESULT.json"
NEW_PACKAGES = {"InfinityLoop1309.NewPipeEnhanced", "io.heckel.ntfy", "org.lichess.mobileV2"}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(relative):
    path = BASE / relative
    return json.loads(path.read_text()), {"path": str(path), "sha256": digest(path)}


def add(rows, package, evidence, expected_apk=None):
    if package in rows:
        raise ValueError(f"duplicate root acceptance: {package}")
    rows[package] = {"package": package, "root_receipt": evidence,
                     "expected_apk_sha256": expected_apk}


def main():
    rows = {}
    p = "harness-stock-inventory-batch2-v1/"
    accepted, receipt = read(p + "root-review-v1/REVIEW.json")
    result, result_receipt = read(p + "RESULT.json")
    assert accepted["status"].startswith("ACCEPT_SEVEN")
    assert accepted["result_sha256"] == result_receipt["sha256"]
    for row in result["rows"]:
        if row["package"] != accepted["incomplete_package"] and row.get("rc") == 0:
            add(rows, row["package"], receipt, row["apk_sha256"])

    p = "harness-native-inventory-recovery-v1/"
    accepted, receipt = read(p + "root-review-v1/REVIEW.json")
    assert accepted["status"].startswith("ACCEPT_THREE")
    for package in ("com.kunzisoft.keepass.libre", "net.thunderbird.android", "org.fossify.gallery"):
        result, detail = read(p + package + "/RESULT.json")
        assert result["rc"] == 0
        add(rows, package, receipt, result["apk_sha256"])
        rows[package]["supporting_result"] = detail
        native_elf = BASE / p / package / "ELF-INVENTORY.json"
        rows[package]["native_elf_ref"] = {"path": str(native_elf), "sha256": digest(native_elf)}

    for batch in (3, 4):
        p = f"harness-stock-inventory-batch{batch}-v1/root-run-v1/ROOT-ACCEPTANCE.json"
        accepted, receipt = read(p)
        for item in accepted["packages"]:
            add(rows, item["package"], receipt, item["apk_sha256"])

    for batch in range(5, 12):
        p = f"harness-stock-inventory-batch{batch}-v1/root-review-v1/ROOT-ACCEPTANCE.json"
        accepted, receipt = read(p)
        for item in accepted["accepted"]:
            add(rows, item["package"], receipt, item.get("apk_sha256"))
            if "MANIFEST.json" in item.get("refs", {}):
                rows[item["package"]]["root_manifest_ref"] = item["refs"]["MANIFEST.json"]

    accepted, receipt = read("harness-stock-inventory-batch12-v2/root-review-v1/ROOT-ACCEPTANCE.json")
    for item in accepted["accepted_rows"]:
        add(rows, item["package"], receipt)
        rows[item["package"]]["root_result_ref"] = item["result"]

    for prefix in ("harness-stock-inventory-batch12-v3-candidate", "harness-stock-inventory-a3-v1", "harness-stock-inventory-a4-v2"):
        accepted, receipt = read(prefix + "/root-review-v1/ROOT-ACCEPTANCE.json")
        for package in accepted["accepted_packages"]:
            add(rows, package, receipt)
        if prefix.endswith("batch12-v3-candidate"):
            for package in accepted["accepted_packages"]:
                rows[package]["split_aggregate_ref"] = accepted["aggregate"]
        else:
            for package in accepted["accepted_packages"]:
                rows[package]["root_result_ref"] = accepted["result"]

    for prefix, key in (("harness-vivaldi-inventory-candidate-v3", "accepted_package"),
                        ("harness-protonmeet-inventory-candidate-v1", "package")):
        accepted, receipt = read(prefix + "/root-review-v1/ROOT-ACCEPTANCE.json")
        package = accepted[key]
        add(rows, package, receipt)
        rows[package]["root_result_ref"] = accepted["result"]

    # The 29 direct one-package root receipts in the pre-105 snapshot. New agents
    # can add receipts to this directory; only packages in V1's frozen input set
    # can be considered here, and the three later admitted packages are excluded.
    v1 = json.loads(V1.read_text())
    frozen_candidates = {item["package"] for item in v1["inputs"]}
    for path in sorted(BASE.rglob("ROOT-STATIC-ADMISSION.json")):
        accepted = json.loads(path.read_text())
        package = accepted.get("package")
        if package not in frozen_candidates or package in NEW_PACKAGES:
            continue
        add(rows, package, {"path": str(path), "sha256": digest(path)},
            accepted.get("apk_sha256") or accepted.get("raw_sha256"))

    for prefix in ("g281-zoom-static-v1", "g285-elementx-static-v1", "g289-tiktoklite-static-v3"):
        manifest, _ = read(prefix + "/phases/metadata/MANIFEST.json")
        root_paths = sorted((BASE / prefix).glob("ROOT-*.json"))
        root_paths = [p for p in root_paths if any(word in p.name for word in ("ACCEPT", "ADMISSION", "REVIEW"))]
        if not root_paths:
            raise ValueError("missing root static receipt for " + prefix)
        path = root_paths[0]
        root = json.loads(path.read_text())
        add(rows, manifest["package"], {"path": str(path), "sha256": digest(path)},
            root.get("apk_sha256") or root.get("original_apk_sha256"))

    for prefix, key in (("apk-stock-intake-a2", "payloads"),
                        ("apk-stock-intake-a3-candidate-v1", "accepted_packages"),
                        ("apk-stock-intake-a4-candidate-v1", "accepted_packages")):
        raw, raw_receipt = read(prefix + "/root-intake-v1/ROOT-ACCEPTANCE.json")
        for item in raw[key]:
            package = item.get("package") or item.get("registry_package_label")
            if package in rows and not rows[package]["expected_apk_sha256"]:
                rows[package]["expected_apk_sha256"] = item["sha256"]
                rows[package]["root_raw_receipt"] = raw_receipt

    for prefix, package, field in (
            ("blackbox-vivaldi-intake-candidate-v1", "com.vivaldi.browser", "payload_sha256"),
            ("blackbox-protonmeet-intake-candidate-v1", "proton.android.meet", "payload")):
        raw, raw_receipt = read(prefix + "/root-intake-v1/ROOT-ACCEPTANCE.json")
        value = raw[field] if field == "payload_sha256" else raw[field]["sha256"]
        rows[package]["expected_apk_sha256"] = value
        rows[package]["root_raw_receipt"] = raw_receipt

    if len(rows) != 105:
        raise ValueError(f"pre-batch accepted identity count {len(rows)}, expected 105")
    candidates = {item["package"]: item for item in v1["inputs"]}
    if set(rows) - set(candidates) != {"com.junkfood.seal", "org.briarproject.briar.android"}:
        raise ValueError("pre-batch missing identities changed")
    if set(candidates) - set(rows) != {"wrong.package"}:
        raise ValueError("negative synthetic control changed")
    for package, row in rows.items():
        if package in candidates:
            item = candidates[package]
            row["apk_sha256"] = item["apk_sha256"]
            row["inputs"] = {k: item[k] for k in
                             ("manifest", "manifest_sha256", "dex", "dex_sha256", "elf", "elf_sha256")}
            if row["expected_apk_sha256"] and row["expected_apk_sha256"] != row["apk_sha256"]:
                raise ValueError("APK identity mismatch: " + package)
            ref = row.get("root_manifest_ref")
            if ref and (ref["path"] != str(BASE / item["manifest"]) or ref["sha256"] != item["manifest_sha256"]):
                raise ValueError("root manifest binding mismatch: " + package)
        else:
            row["layout"] = "batch12-v3-split-native-members"
    print(json.dumps({"schema": "g339-pre-batch105-root-identity-lock-v2",
                      "v1_snapshot_sha256": digest(V1),
                      "pre105_checkpoint": {"path": "docs/nanhai-plus/checkpoints/20261004-raw107-static105-blackbox20-g279-v7-nogo/CHECKPOINT.json",
                                            "sha256": "1ddae14db50ed5338f202e53b8eb634d130a9a7669eb91d5a8d7bf374b1edf0f"},
                      "scope": "105 root-accepted complete host-static package identities before PipePipe/ntfy/Lichess",
                      "excluded_new_packages": sorted(NEW_PACKAGES),
                      "negative_control_excluded": "wrong.package",
                      "count": 105,
                      "identities": [rows[k] for k in sorted(rows)]}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
