#!/usr/bin/env python3
"""Bounded, receipt-pinned cross-APK reference-frequency pilot.

This ranks declarations, not missing implementations or cold-start blockers.
"""
import argparse
import collections
import hashlib
import json
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_pinned(root, item):
    path = root / item["path"]
    if not path.is_file() or digest(path) != item["sha256"]:
        raise ValueError(f"missing or changed input: {item['path']}")
    return json.loads(path.read_text())


def aggregate(root, manifest):
    if manifest.get("schema") != "cross-apk-reference-input-v1":
        raise ValueError("wrong manifest schema")
    rows = manifest["packages"]
    if len(rows) != 78 or len({r["package"] for r in rows}) != 78:
        raise ValueError("expected exactly 78 unique accepted packages")
    methods = collections.defaultdict(set)
    symbols = collections.defaultdict(set)
    needed = collections.defaultdict(set)
    counts = {"packages": 0, "dex_entries": 0, "arm64_elf_entries": 0}
    for row in rows:
        pkg = row["package"]
        receipt = load_pinned(root, row["receipt"])
        if not any(token in str(receipt.get("status", receipt.get("decision", ""))).upper()
                   for token in ("ACCEPT", "COMPLETE")):
            raise ValueError(f"receipt does not accept: {pkg}")
        dex = load_pinned(root, row["dex"])
        elf = ([load_pinned(root, item) for item in row["elf_records"]]
               if "elf_records" in row else load_pinned(root, row["elf"]))
        if not isinstance(dex.get("method_refs"), list) or not isinstance(elf, list):
            raise ValueError(f"bad inventory schema: {pkg}")
        counts["packages"] += 1
        counts["dex_entries"] += len(dex["dex_entries"])
        for ref in dex["method_refs"]:
            key = ref.get("key")
            if not (isinstance(key, list) and len(key) == 3 and isinstance(key[0], str)
                    and key[0].startswith(("L", "["))):
                raise ValueError(f"bad method key: {pkg}")
            methods[tuple(key)].add(pkg)
        for lib in elf:
            if lib.get("machine") != "AArch64" or lib.get("abi") != "arm64-v8a":
                continue
            if lib.get("readelf_ok") is not True:
                raise ValueError(f"unverified arm64 ELF: {pkg}")
            counts["arm64_elf_entries"] += 1
            for sym in lib.get("undefined_symbols", []):
                symbols[sym].add(pkg)
            for name in lib.get("needed", []):
                needed[name].add(pkg)

    def ranked(mapping, limit=30):
        return [{"reference": list(key) if isinstance(key, tuple) else key,
                 "unique_packages": len(pkgs), "packages": sorted(pkgs)}
                for key, pkgs in sorted(mapping.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:limit]]

    return {"schema": "cross-apk-reference-output-v1", "target": "OH 7.0.0.39 + AOSP 16.0.0_r4 + arm64 + App Bionic",
            "scope": "78 root-accepted complete host-static APK inventories only",
            "counts": counts, "distinct_platform_method_references": len(methods),
            "distinct_arm64_undefined_symbols": len(symbols),
            "top_platform_methods": ranked(methods), "top_arm64_native_imports": ranked(symbols),
            "top_arm64_needed_libraries": ranked(needed),
            "interpretation": {"declaration_frequency": "observed", "code_reachability": "UNKNOWN",
                               "provider_implementation": "UNKNOWN", "runtime_gap": "UNKNOWN",
                               "cold_start_blocker": "UNKNOWN"}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, required=True)
    ap.add_argument("--manifest", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    manifest = json.loads(args.manifest.read_text())
    result = aggregate(args.root, manifest)
    result["input_manifest_sha256"] = digest(args.manifest)
    args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
