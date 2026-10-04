#!/usr/bin/env python3
"""Read-only distinct-package ARM64 DT_NEEDED audit of accepted static inputs."""
import collections
import hashlib
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[6]
BASE = ROOT / "docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001"
LOCK = BASE / "g339-cross-apk-exposure-cohort-v2/LOCK.json"
EXTRA = {
    "com.lemon.lvoverseas": "g343-capcut-four-static-v1/phases/elf/ELF-INVENTORY.json",
    "InfinityLoop1309.NewPipeEnhanced": "peer-apk-portfolio-pipepipe-static-v2/ELF-INVENTORY.json",
    "io.heckel.ntfy": "peer-apk-portfolio-ntfy-static-v1/ELF-INVENTORY.json",
    "org.lichess.mobileV2": "peer-apk-portfolio-lichess-static-v1/ELF-INVENTORY.json",
    "com.anydesk.anydeskandroid": "peer-blackbox-anydesk-static-v1/ELF-INVENTORY.json",
    "org.fossify.clock": "peer-apk-portfolio-fossify-clock-static-v1/ELF-INVENTORY.json",
    "com.whatsapp": "raw112-static111-whatsapp-four-static-v1/phases/elf/ELF-INVENTORY.json",
    "com.aimp.player": "peer-apk-portfolio-aimp-static-v1/ELF-INVENTORY.json",
    "com.snapchat.android": "peer-snapchat-four-static-v1/ELF-INVENTORY.json",
}
COMPARE = ("libc.so", "libdl.so", "libm.so", "liblog.so", "libz.so", "libEGL.so",
           "libGLESv2.so", "libmediandk.so", "libOpenSLES.so")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    lock = json.loads(LOCK.read_text())
    assert len(lock["identities"]) == 105
    records = {}
    verified = 0
    for identity in lock["identities"]:
        package = identity["package"]
        if "native_elf_ref" in identity:
            ref = identity["native_elf_ref"]
            path = ROOT / ref["path"]
            expected = ref["sha256"]
        elif "inputs" in identity:
            ref = identity["inputs"]
            path = BASE / ref["elf"]
            expected = ref["elf_sha256"]
        else:
            continue  # Two split packages are reconstructed from accepted member receipts.
        assert sha(path) == expected, (package, path)
        records[package] = json.loads(path.read_text())
        verified += 1
    for package, relative in EXTRA.items():
        assert package not in records
        records[package] = json.loads((BASE / relative).read_text())
    split_base = BASE / "harness-stock-inventory-batch12-v3-candidate"
    aggregate = json.loads((split_base / "AGGREGATE.json").read_text())
    by_sha = {sha(path): path for path in (split_base / "member-trials").glob("*/ELF-RECORD.json")}
    assert len(aggregate["facts"]) == 2
    for fact in aggregate["facts"]:
        package = fact["package"]
        assert package not in records
        records[package] = [json.loads(by_sha[row["record_sha256"]].read_text())
                            for row in fact["native_member_receipts"]]
    assert len(records) == 114

    arm64 = {package: [row for row in rows if row.get("machine") == "AArch64"
                       and row.get("abi") == "arm64-v8a"] for package, rows in records.items()}
    comparison = {}
    for needed in COMPARE:
        matched = [(package, row) for package, rows in arm64.items() for row in rows
                   if needed in row.get("needed", [])]
        packages = sorted({package for package, _ in matched})
        providers_in_same_apk = sorted(package for package in packages if any(
            row.get("name", "").rsplit("/", 1)[-1] == needed for row in arm64[package]))
        comparison[needed] = {
            "distinct_packages": len(packages),
            "elf_dt_needed_edges": len(matched),
            "distinct_elf_sha256": len({row["sha256"] for _, row in matched}),
            "same_apk_arm64_provider_packages": providers_in_same_apk,
            "packages": packages,
            "per_package_elf_edges": dict(sorted(collections.Counter(package for package, _ in matched).items())),
        }
    result = {
        "schema": "peer-cross-apk-distinct-arm64-needed-v1",
        "g339_lock_sha256": sha(LOCK),
        "g339_lock_packages": 105,
        "g339_individual_elf_input_sha256_verified": verified,
        "g339_split_member_packages": 2,
        "later_root_admitted_packages": len(EXTRA),
        "distinct_packages": len(records),
        "distinct_arm64_elf_inventory_entries": sum(map(len, arm64.values())),
        "counting_rule": "One package identity; only inventory records with machine=AArch64 and abi=arm64-v8a. Each DT_NEEDED edge counted once per ELF. Same APK providers tested by ARM64 basename. No loader execution inferred.",
        "comparison": comparison,
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
