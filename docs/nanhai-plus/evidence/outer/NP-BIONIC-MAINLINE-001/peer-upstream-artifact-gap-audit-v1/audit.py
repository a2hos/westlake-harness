#!/usr/bin/env python3
"""Exact registry-artifact gap audit over frozen root-receipt inputs."""
import hashlib
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
BASE = HERE.parent
PROJECT = BASE.parents[4]

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def read(rel, expected):
    path = PROJECT / rel
    assert path.is_file() and sha(path) == expected, rel
    return json.loads(path.read_text())

inputs = json.loads((HERE / "INPUTS.json").read_text())
registry = read(inputs["registry"]["path"], inputs["registry"]["sha256"])
artifacts = registry["artifacts"]
bysha = {a["sha256"]: a for a in artifacts}
assert len(bysha) == len(artifacts) == 338

accepted = {}
for item in inputs["upstream_root_receipts"]:
    x = read(item["path"], item["sha256"])
    if item["kind"] == "stock_batch":
        rows = x.get("payloads", x.get("accepted_packages", x.get("packages", [])))
    else:
        rows = [x]
    for row in rows:
        digest = row.get("sha256", row.get("apk_sha256", row.get("registered_artifact_sha256")))
        assert digest in bysha, (item["path"], digest)
        a = bysha[digest]
        assert row.get("package", row.get("registry_package_label", a["package"])) == a["package"]
        assert digest not in accepted, digest
        accepted[digest] = {"id": a["id"], "package": a["package"], "sha256": digest, "root_receipt": item["path"], "root_receipt_sha256": item["sha256"]}
assert len(accepted) == 79

missing = []
accepted_packages = {row["package"] for row in accepted.values()}
for a in artifacts:
    if a["sha256"] in accepted:
        continue
    url = a["source_urls"]
    known_arm64 = "arm64-v8a" in a["abis"]
    priority = ("P0_REGISTERED_FDROID_URL_ARM64_DECLARED" if url and known_arm64
                else "P1_ARM64_DECLARED_SOURCE_URL_ABSENT" if known_arm64
                else "P2_REGISTERED_FDROID_URL_ABI_UNDECLARED" if url
                else "P3_SOURCE_URL_AND_ABI_UNDECLARED")
    missing.append({
        "id": a["id"], "package": a["package"], "sha256": a["sha256"],
        "versions": a["versions"], "version_codes": a["version_codes"],
        "source_urls_registered_not_revalidated": url,
        "abis_registered": a["abis"], "split_counts_registered": a["split_counts"],
        "priority": priority,
        "same_package_different_variant_already_raw_accepted": a["package"] in accepted_packages,
    })
missing.sort(key=lambda r: (r["priority"], r["package"], r["id"]))

raw_rows = []
for item in inputs["other_raw_root_receipts"]:
    x = read(item["path"], item["sha256"])
    assert str(x.get("decision", x.get("status", ""))).startswith(("ACCEPT", "ROOT_ACCEPT")), item["path"]
    if item["kind"] == "root_raw":
        rows = x.get("accepted", x.get("packages", []))
        if x.get("payload"): rows = [dict(x["payload"], package=x.get("package", x["payload"].get("package")))]
        if x.get("package") and not x.get("payload"): rows = [x]
    elif item["kind"] == "single_payload":
        rows = [dict(x.get("payload", x.get("body", {})), package=x.get("package", item.get("package")), sha256=x.get("payload_sha256", x.get("payload", x.get("body", {})).get("sha256")))]
    elif item["kind"] == "payloads":
        rows = x["payloads"]
    else:
        raise AssertionError(item)
    for row in rows:
        package = row.get("package", row.get("proposed_package_label"))
        digest = row.get("apk_sha256", row.get("sha256"))
        assert package and digest and len(digest) == 64, (item["path"], row)
        raw_rows.append({"package_label": package, "sha256": digest, "root_receipt": item["path"], "package_semantics_verified_by_receipt": x.get("package_semantics_verified", x.get("manifest_package_version_verified", None))})

all_rows = list(accepted.values()) + raw_rows
unique_hashes = {x["sha256"] for x in all_rows}
labels = {x.get("package", x.get("package_label")) for x in all_rows}
out = {
    "schema": "peer-upstream-artifact-gap-audit-v1",
    "registry_sha256": inputs["registry"]["sha256"],
    "upstream_commit": registry["upstream_commit"],
    "counts": {
        "registry_artifacts": len(artifacts), "registry_packages": len({a["package"] for a in artifacts}),
        "accepted_exact_upstream_artifacts": len(accepted),
        "accepted_exact_upstream_packages": len(accepted_packages),
        "missing_exact_upstream_artifacts": len(missing),
        "missing_artifact_packages": len({a["package"] for a in missing}),
        "missing_new_packages_relative_to_79": len({a["package"] for a in missing} - accepted_packages),
        "missing_new_packages_relative_to_114_raw_receipt_labels": len({a["package"] for a in missing} - labels),
        "missing_packages_already_present_among_114_raw_receipt_labels": len({a["package"] for a in missing} & labels),
        "missing_other_variants_of_accepted_package": sum(x["same_package_different_variant_already_raw_accepted"] for x in missing),
        "missing_registered_fdroid_urls": sum(bool(x["source_urls_registered_not_revalidated"]) for x in missing),
        "missing_declared_arm64": sum("arm64-v8a" in x["abis_registered"] for x in missing),
        "missing_declared_arm64_with_registered_url": sum(x["priority"] == "P0_REGISTERED_FDROID_URL_ARM64_DECLARED" for x in missing),
        "root_accepted_raw_distinct_artifact_sha_from_frozen_receipts": len(unique_hashes),
        "root_accepted_raw_distinct_package_labels_from_frozen_receipts": len(labels),
        "root_accepted_raw_rows_from_frozen_receipts": len(all_rows),
    },
    "accepted_exact_upstream": sorted(accepted.values(), key=lambda x: (x["package"], x["id"])),
    "missing_exact_upstream": missing,
    "other_raw_receipt_rows": sorted(raw_rows, key=lambda x: (x["package_label"], x["sha256"])),
    "limits": [
        "Registry artifact ID and SHA are the difference key; package/variant sameness never substitutes an exact artifact.",
        "Registered F-Droid URLs are historical exact-version leads, not independently verified live GET or SHA matches in this audit.",
        "ABI declarations are registry metadata, not independent ELF proof for missing bytes.",
        "Distinct package labels come from root receipts; Signal and WhatsApp raw intake explicitly leave package/manifest semantics unverified, so 114 labels are not 114 verified unique startup apps.",
        "Raw bytes and host static do not prove installation, Bionic compatibility, or truly cold startup.",
    ],
}
assert len(unique_hashes) == len(all_rows) == 114
assert len(missing) == 259
print(json.dumps(out, indent=2, sort_keys=True))
