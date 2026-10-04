#!/usr/bin/env python3
"""Fail-closed ARM64 DT_NEEDED cohort over one frozen root-admitted APK set."""

import argparse
import collections
import hashlib
import json
from pathlib import Path

BASE = Path("docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001")


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def checked(ref):
    path = Path(ref["path"])
    if not path.is_file() or sha(path) != ref["sha256"]:
        raise ValueError("receipt or input SHA mismatch: " + str(path))
    return json.loads(path.read_text())


def source(base, relative, expected):
    path = base / relative
    if not path.is_file() or sha(path) != expected:
        raise ValueError("frozen input SHA mismatch: " + str(path))
    return json.loads(path.read_text())


def needed_from_elf(rows):
    if not isinstance(rows, list):
        raise ValueError("ELF inventory must be a list")
    names = set()
    for row in rows:
        if row["abi"] == "arm64-v8a":
            if not row.get("abi_matches_machine") or not row.get("readelf_ok"):
                raise ValueError("ARM64 ELF machine/readelf gate failed")
            names.update(name for name in row["needed"] if isinstance(name, str))
    return sorted(names)


def split_record_paths():
    split_root = BASE / "harness-stock-inventory-batch12-v3-candidate"
    mapping = {}
    for path in sorted((split_root / "member-trials").glob("*/ELF-RECORD.json")):
        key = sha(path)
        if key in mapping:
            raise ValueError("duplicate split ELF record digest")
        mapping[key] = path
    return split_root, mapping


def analyze(lock_path):
    lock_bytes = lock_path.read_bytes()
    lock = json.loads(lock_bytes)
    checkpoint = checked(lock["pre105_checkpoint"])
    if checkpoint["full_host_static_accepted"] != 105 or lock["count"] != 105:
        raise ValueError("pre-batch-105 checkpoint/count mismatch")
    identities = lock["identities"]
    if len(identities) != 105 or len({x["package"] for x in identities}) != 105:
        raise ValueError("root-accepted identity cardinality mismatch")
    if ({x["package"] for x in identities} &
            (set(lock["excluded_new_packages"]) | {lock["negative_control_excluded"]})):
        raise ValueError("post-baseline or negative-control package in lock")
    split_root, split_records = split_record_paths()
    exposures = {}
    sources = []
    for row in identities:
        root = checked(row["root_receipt"])
        if "ACCEPT" not in str(root.get("decision", root.get("status", ""))):
            raise ValueError("root receipt does not accept: " + row["package"])
        if row.get("root_raw_receipt"):
            checked(row["root_raw_receipt"])
        if row.get("supporting_result"):
            checked(row["supporting_result"])
        if row.get("root_result_ref"):
            checked(row["root_result_ref"])
        manifest_ref = row.get("root_manifest_ref")
        if manifest_ref:
            checked(manifest_ref)
        package = row["package"]
        expected_apk = row.get("expected_apk_sha256")
        if row.get("layout") == "batch12-v3-split-native-members":
            aggregate = checked(row["split_aggregate_ref"])
            facts = [fact for fact in aggregate["facts"] if fact["package"] == package]
            if len(facts) != 1:
                raise ValueError("split aggregate identity mismatch: " + package)
            fact = facts[0]
            prefix = split_root / "java-trials/tuplefix-v2" / package
            manifest_path = prefix / "MANIFEST.json"
            dex_path = prefix / "DEX-INVENTORY.json"
            if sha(manifest_path) != fact["manifest_sha256"] or sha(dex_path) != fact["dex_inventory_sha256"]:
                raise ValueError("split Java SHA mismatch: " + package)
            manifest = json.loads(manifest_path.read_text())
            json.loads(dex_path.read_text())
            elf = []
            for member in fact["native_member_receipts"]:
                path = split_records.get(member["record_sha256"])
                if path is None:
                    raise ValueError("split ELF record missing: " + package)
                elf.append(json.loads(path.read_text()))
            if len(elf) != fact["elf_entries"]:
                raise ValueError("split ELF cardinality mismatch: " + package)
            if fact["apk_sha256"] != expected_apk:
                raise ValueError("split accepted APK identity mismatch: " + package)
            input_digests = [fact["manifest_sha256"], fact["dex_inventory_sha256"]]
            input_digests += sorted(member["record_sha256"] for member in fact["native_member_receipts"])
        else:
            refs = row["inputs"]
            manifest = source(BASE, refs["manifest"], refs["manifest_sha256"])
            source(BASE, refs["dex"], refs["dex_sha256"])
            elf = source(BASE, refs["elf"], refs["elf_sha256"])
            if row.get("native_elf_ref"):
                elf = checked(row["native_elf_ref"])
            if manifest_ref and (manifest_ref["path"] != str(BASE / refs["manifest"]) or
                                 manifest_ref["sha256"] != refs["manifest_sha256"]):
                raise ValueError("root manifest ref mismatch: " + package)
            input_digests = [refs["manifest_sha256"], refs["dex_sha256"], refs["elf_sha256"]]
            if row.get("native_elf_ref"):
                input_digests.append(row["native_elf_ref"]["sha256"])
        if manifest["package"] != package or manifest["sha256"] != row.get("apk_sha256", expected_apk):
            raise ValueError("manifest package/APK identity mismatch: " + package)
        if expected_apk and manifest["sha256"] != expected_apk:
            raise ValueError("root APK identity mismatch: " + package)
        if not expected_apk and not manifest_ref:
            raise ValueError("no root APK SHA or root manifest binding: " + package)
        try:
            exposures[package] = needed_from_elf(elf)
        except ValueError as exc:
            raise ValueError(package + ": " + str(exc)) from exc
        sources.append({"package": package, "apk_sha256": manifest["sha256"],
                        "root_receipt_sha256": row["root_receipt"]["sha256"],
                        "input_sha256": input_digests})
    clusters = collections.defaultdict(list)
    for package, names in exposures.items():
        for name in names:
            clusters[name].append(package)
    ranking = [{"needed_soname": name, "package_count": len(packages),
                "packages": sorted(packages)}
               for name, packages in sorted(clusters.items(),
                                            key=lambda item: (-len(item[1]), item[0]))
               if len(packages) >= 3]
    return {"schema": "g339-pre-batch105-locked-arm64-needed-cohort-v2",
            "status": "HOST_STATIC_EXPOSURE_ONLY",
            "scope": "105 frozen root-accepted APK identities; no provider subtraction, execution-order proof, device, or cold start",
            "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
            "checkpoint_sha256": lock["pre105_checkpoint"]["sha256"],
            "accepted_packages_checked": len(exposures),
            "excluded_post_snapshot": lock["excluded_new_packages"],
            "negative_control_excluded": lock["negative_control_excluded"],
            "source_bindings": sources,
            "cohorts": ranking[:20]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("lock", type=Path)
    args = parser.parse_args()
    print(json.dumps(analyze(args.lock), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
