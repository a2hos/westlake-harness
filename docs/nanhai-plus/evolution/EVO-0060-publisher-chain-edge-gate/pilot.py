#!/usr/bin/env python3
"""Read-only publisher landing -> JS -> config -> CDN -> exact APK edge pilot."""
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(os.environ["NANHAI_PROJECT_ROOT"])
BASE = ROOT / "docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001"
QUAL = BASE / "peer-xender-qualification-v1"
RAW = BASE / "peer-xender-official-raw-v1"

def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    counterexample = sys.argv[1:] == ["--counterexample"]
    if sys.argv[1:] not in ([], ["--counterexample"]):
        return 2
    q = json.loads((QUAL / "QUALIFICATION.json").read_text())
    r = json.loads((RAW / "RESULT.json").read_text())
    v = json.loads((RAW / "VERIFY.json").read_text())
    landing = (QUAL / "landing.raw").read_text(errors="replace")
    js = (QUAL / "js.raw").read_text(errors="replace")
    config = json.loads((QUAL / "config.raw").read_text())
    apk = Path(os.environ["NANHAI_STAGING_ROOT"]) / "peer-xender-official-raw-v1/xender-official.apk"
    android = [x for x in config["apps"] if x.get("os") == "android" and x.get("pn") == q["package"]]
    if counterexample and len(android) == 1:
        android[0] = dict(android[0], download_url="https://example.invalid/other.apk")
    checks = {
        "frozen_landing_sha": sha(QUAL / "landing.raw") == q["publisher_landing_sha256"],
        "frozen_js_sha": sha(QUAL / "js.raw") == q["publisher_js_sha256"],
        "frozen_config_sha": sha(QUAL / "config.raw") == q["publisher_config_sha256"],
        "landing_declares_exact_js": q["publisher_js"].split("/")[-1] in landing,
        "js_declares_exact_api_base": q["publisher_config_api"].split("?")[0] in js,
        "one_android_package": len(android) == 1,
        "android_config_matches_get_url": len(android) == 1 and android[0]["download_url"] == r["get"]["argv"][-1] == q["publisher_apk_url"],
        "android_config_matches_apk_package_version": len(android) == 1 and android[0]["pn"] == v["package_version"][0] == q["package"] and android[0]["version"] == v["package_version"][1] == str(q["version_code"]),
        "get_rc_and_receipt_sha": r["get"]["rc"] == 0 and sha(RAW / "apk-get-headers.raw") == q["publisher_get_headers_sha256"],
        "apk_exact_sha": sha(apk) == r["apk_sha256"] == v["apk_sha256"] == q["apk_sha256"],
    }
    failed = [k for k, value in checks.items() if not value]
    out = {"schema": "evo60-publisher-chain-edge-pilot-v1", "case": "synthetic_config_url_mismatch" if counterexample else "frozen_positive", "decision": "GO" if not failed else "NO_GO", "checks": checks, "failed_edges": failed, "input_sha256": {"qualification": sha(QUAL / "QUALIFICATION.json"), "raw_result": sha(RAW / "RESULT.json"), "raw_verify": sha(RAW / "VERIFY.json"), "landing": sha(QUAL / "landing.raw"), "js": sha(QUAL / "js.raw"), "config": sha(QUAL / "config.raw"), "apk": sha(apk)}, "network_commands": 0, "device_commands": 0, "container_commands": 0, "production_changed": False}
    print(json.dumps(out, sort_keys=True, indent=2))
    return 0 if not failed else 2

if __name__ == "__main__":
    sys.exit(main())
