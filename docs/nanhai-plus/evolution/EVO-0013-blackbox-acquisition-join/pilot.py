#!/usr/bin/env python3
"""Read-only, frozen ten-candidate acquisition join. Output is diagnostic only."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
BASE = ROOT / "docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001"
INPUTS = {
    "queue": ("blackbox-source-priority-v2/PRIORITY-QUEUE.json", "012a3022ad1663bca422a6d43a77fe157bfaa62e06e37a21192ba9d55fa522a3"),
    "v8": ("apk-stock-intake-v8/root-intake-v1/ROOT-ACCEPTANCE.json", "bb528044a1366a58d7b8842634f1c9792c37822acb5c68f33d4a06acfc196396"),
    "v9": ("apk-stock-intake-v9/root-intake-v1/ROOT-ACCEPTANCE.json", "69ad17b8b32dd808f889feb87df3af09913729aa04cd0ca4f1a54c310af72a79"),
    "whatsapp": ("mainstream-whatsapp-official-supplement-v1/root-intake-v1/ROOT-ACCEPTANCE.json", "3843de1d242c69f26c3c5f3122be1e73d52b1e0ccff05dfc52e39eb14e195da6"),
    "batch10": ("harness-stock-inventory-batch10-v1/root-review-v1/ROOT-ACCEPTANCE.json", "3a2cbe1acfaeea37c77c6e699a6221792f8d1244d10eed3383d987fcd201f35f"),
    "batch11": ("harness-stock-inventory-batch11-v1/root-review-v1/ROOT-ACCEPTANCE.json", "58960e2ba553b94990a615d4134f78220be46866384d2b159a91bfa55fd35548"),
}


def load():
    docs = {}
    for name, (relative, expected) in INPUTS.items():
        raw = (BASE / relative).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError(f"{name}: frozen receipt changed")
        docs[name] = json.loads(raw)
    return docs


def join(docs, inject_false_same_package=False):
    queue = docs["queue"]["tier_B_candidates"]
    raw = [(r["registry_package_label"], None, r["sha256"], "upstream_raw")
           for n in ("v8", "v9") for r in docs[n]["payloads"]]
    raw.append(("com.whatsapp", docs["whatsapp"].get("new_website_label"), docs["whatsapp"]["body"]["sha256"], "official_supplement"))
    if inject_false_same_package:
        raw.append(("com.discord", "different version", "0" * 64, "negative_fixture"))
    rows = []
    for c in queue:
        pkg = c["package"]
        history = c["historical_original_fields"]
        exact_sha = history["artifact_sha256"]
        same_pkg = [r for r in raw if r[0] == pkg]
        exact = [r for r in same_pkg if r[2] == exact_sha and (r[1] is None or r[1] == history.get("version_name"))]
        rows.append({"package": pkg, "historical_version": history.get("version_name"), "historical_artifact_sha256": exact_sha,
                     "exact_historical_payload_in_pilot_inputs": bool(exact), "same_package_other_raw_in_pilot_inputs": [r[3] for r in same_pkg if r not in exact],
                     "next_evidence": "verify complete split/version/signature and source" if exact else "acquire exact historical artifact or separately verify official new variant"})
    recent = [r["package"] for n in ("batch10", "batch11") for r in docs[n]["accepted"]]
    overlap = sorted(set(recent) & {r["package"] for r in rows})
    return {"candidate_count": len(rows), "recent_scanned_packages": len(recent), "recent_scanned_candidate_overlap": overlap,
            "exact_historical_payload_count_in_pilot_inputs": sum(r["exact_historical_payload_in_pilot_inputs"] for r in rows),
            "qualified_blackbox_delta": 0, "startup_delta": 0, "rows": rows}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--negative-same-package", action="store_true")
    args = ap.parse_args()
    try:
        out = join(load(), args.negative_same_package)
    except Exception as exc:
        print(json.dumps({"status": "FAIL_CLOSED", "error": str(exc)}))
        return 2
    if args.negative_same_package and out["exact_historical_payload_count_in_pilot_inputs"] != 0:
        print(json.dumps({"status": "FAIL_OPEN", **out}, indent=2))
        return 2
    print(json.dumps({"status": "PASS_DIAGNOSTIC", "negative_fixture": args.negative_same_package, **out}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
