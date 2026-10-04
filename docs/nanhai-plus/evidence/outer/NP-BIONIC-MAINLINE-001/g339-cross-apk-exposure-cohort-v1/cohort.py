#!/usr/bin/env python3
"""Read-only cross-APK exposure cohort from existing host static inventories.

This deliberately does not infer provider absence, execution order, or cold starts.
"""

import argparse
import collections
import hashlib
import json
from pathlib import Path

SYNTHETIC = {"example", "example.synthetic", "independent.synthetic", "other"}


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def files_for(dex_path):
    directory = dex_path.parent
    elf = directory / "ELF-INVENTORY.json"
    manifest = directory / "MANIFEST.json"
    if not elf.exists():
        elf = directory.parent / "elf" / "ELF-INVENTORY.json"
        manifest = directory.parent / "metadata" / "MANIFEST.json"
    return elf, manifest


def values(requests, field):
    for row in requests:
        if isinstance(row, dict):
            value = row.get(field)
            if isinstance(value, str) and value.strip():
                yield value.strip()


def collect(root):
    records = {}
    conflicted = set()
    rejected = collections.Counter()
    for dex_path in sorted(root.rglob("DEX-INVENTORY.json")):
        elf_path, manifest_path = files_for(dex_path)
        if not elf_path.is_file() or not manifest_path.is_file():
            rejected["incomplete_triplet"] += 1
            continue
        try:
            manifest = json.loads(manifest_path.read_text())
            package, artifact = manifest.get("package"), manifest.get("sha256")
            if not isinstance(package, str) or not isinstance(artifact, str) or len(artifact) != 64:
                rejected["invalid_identity"] += 1
                continue
            if package in SYNTHETIC:
                rejected["synthetic_fixture"] += 1
                continue
            dex = json.loads(dex_path.read_text())
            elf = json.loads(elf_path.read_text())
            if not isinstance(dex, dict) or not isinstance(elf, list):
                rejected["invalid_inventory"] += 1
                continue
            services = sorted(set(values(dex.get("service_requests", []), "service")))
            libraries = sorted(set(values(dex.get("load_libraries", []), "value")))
            needed = sorted({name for row in elf if isinstance(row, dict)
                             and row.get("abi") == "arm64-v8a"
                             for name in row.get("needed", []) if isinstance(name, str)})
            key = (package, artifact)
            if key in conflicted:
                rejected["conflicting_duplicate_skipped"] += 1
                continue
            item = {"package": package, "apk_sha256": artifact,
                    "manifest_sha256": sha256(manifest_path),
                    "dex_sha256": sha256(dex_path), "elf_sha256": sha256(elf_path),
                    "manifest": str(manifest_path.relative_to(root)),
                    "dex": str(dex_path.relative_to(root)),
                    "elf": str(elf_path.relative_to(root)),
                    "service_requests": services, "load_libraries": libraries,
                    "arm64_needed": needed}
            previous = records.get(key)
            if previous:
                if any(previous[field] != item[field] for field in
                       ("service_requests", "load_libraries", "arm64_needed")):
                    del records[key]
                    conflicted.add(key)
                    rejected["conflicting_duplicate_identity"] += 1
                    continue
                rejected["duplicate_same_identity"] += 1
                continue
            records[key] = item
        except (OSError, ValueError, TypeError, KeyError):
            rejected["unreadable_or_invalid_triplet"] += 1
            continue
    package_ids = [package for package, _ in records]
    if len(package_ids) != len(set(package_ids)):
        raise ValueError("multiple APK identities for one package; choose an exact artifact first")
    return sorted(records.values(), key=lambda row: row["package"]), dict(sorted(rejected.items()))


def clusters(records, field, min_packages):
    members = collections.defaultdict(list)
    for row in records:
        for value in row[field]:
            members[value].append(row["package"])
    return [{"surface": key, "package_count": len(packages), "packages": sorted(packages)}
            for key, packages in sorted(members.items(),
                                        key=lambda pair: (-len(pair[1]), pair[0]))
            if len(packages) >= min_packages]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence_root", type=Path)
    parser.add_argument("--min-packages", type=int, default=3)
    parser.add_argument("--top", type=int, default=20)
    args = parser.parse_args()
    if not args.evidence_root.is_dir() or args.min_packages < 2 or args.top < 1:
        parser.error("provide an evidence directory, min-packages >= 2, and top >= 1")
    records, rejected = collect(args.evidence_root)
    result = {"schema": "nanhai-cross-apk-exposure-cohort-v1",
              "scope": "host static inventory candidate only; no provider subtraction, reachability, runtime, or root admission inference",
              "evidence_root": str(args.evidence_root),
              "input_packages": len(records), "rejected_or_deduplicated": rejected,
              "inputs": [{key: row[key] for key in
                          ("package", "apk_sha256", "manifest", "manifest_sha256",
                           "dex", "dex_sha256", "elf", "elf_sha256")}
                         for row in records],
              "cohorts": {field: clusters(records, field, args.min_packages)[:args.top]
                          for field in ("service_requests", "load_libraries", "arm64_needed")}}
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
