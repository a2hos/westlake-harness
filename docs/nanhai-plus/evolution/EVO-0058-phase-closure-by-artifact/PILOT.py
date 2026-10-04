#!/usr/bin/env python3
"""Small read-only phase-closure pilot; never changes admissions."""
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]
EVIDENCE = ROOT / "docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001"
SAMPLES = [
    (
        "whatsapp",
        "com.whatsapp",
        "mainstream-whatsapp-official-supplement-v1/root-intake-v1/ROOT-ACCEPTANCE.json",
        "raw112-static111-whatsapp-four-static-v1/ROOT-STATIC-ADMISSION.json",
    ),
    (
        "aimp",
        "com.aimp.player",
        "peer-apk-portfolio-aimp-root-admission-v1/ROOT-RAW-ADMISSION.json",
        "peer-apk-portfolio-aimp-root-admission-v1/ROOT-STATIC-ADMISSION.json",
    ),
    (
        "snapchat-universal",
        "com.snapchat.android",
        "peer-snapchat-root-admission-v1/ROOT-RAW-ADMISSION.json",
        "peer-snapchat-root-admission-v1/ROOT-STATIC-ADMISSION.json",
    ),
]


def receipt(relative, expected_package):
    path = EVIDENCE / relative
    data = path.read_bytes()
    obj = json.loads(data)
    return {
        "path": str(path.relative_to(ROOT)),
        "receipt_sha256": hashlib.sha256(data).hexdigest(),
        "package": obj.get("package", expected_package),
        "apk_sha256": obj.get("apk_sha256", obj.get("body", {}).get("sha256")),
    }


def key(r):
    return (r["package"], r["apk_sha256"])


def main():
    gap = json.loads((EVIDENCE / "raw112-static111-whatsapp-four-static-v1/GAP-AUDIT.json").read_text())
    assert gap["unmatched_raw_identity"]["package"] == "com.whatsapp"
    assert gap["unmatched_raw_identity"]["apk_sha256"] == "c4260c7c569c19267fd33ee33b6241fadbee55e3bcfceb3ee151012801368dbb"
    pairs = [(name, receipt(raw, package), receipt(static, package)) for name, package, raw, static in SAMPLES]
    assert all(raw["package"] == package and static["package"] == package for (name, package, _, _), (_, raw, static) in zip(SAMPLES, pairs))
    assert all(key(raw) == key(static) for _, raw, static in pairs)
    raw_set = {key(raw) for _, raw, _ in pairs}
    current_static = {key(static) for _, _, static in pairs}
    prior_static = {key(static) for name, _, static in pairs if name != "whatsapp"}
    registered_snapchat_xapk = (
        "com.snapchat.android",
        "a37383d12c69982786fd8a45ba4271bb16ada2ebc2f7d051e2830a2cb103d178",
    )
    assert registered_snapchat_xapk not in raw_set
    assert registered_snapchat_xapk not in current_static
    result = {
        "schema": "evo58-offline-phase-closure-pilot-v1",
        "sample_count": len(pairs),
        "actual_receipts": [dict(name=name, raw=raw, static=static) for name, raw, static in pairs],
        "pre_whatsapp_static_missing": [list(x) for x in sorted(raw_set - prior_static)],
        "current_static_missing": [list(x) for x in sorted(raw_set - current_static)],
        "registered_snapchat_xapk_separate": list(registered_snapchat_xapk),
        "scope": "Three exact receipts only; prior view omits the later WhatsApp static receipt to replay the observed gap. No full-corpus coverage or runtime claim.",
    }
    assert result["pre_whatsapp_static_missing"] == [["com.whatsapp", "c4260c7c569c19267fd33ee33b6241fadbee55e3bcfceb3ee151012801368dbb"]]
    assert result["current_static_missing"] == []
    sys.stdout.write(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
