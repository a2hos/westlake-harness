"""Receipt-only APK identity join before root's substantive admission review."""
import hashlib
import json
from pathlib import Path

BASE = Path(__file__).resolve().parents[2] / "evidence/outer/NP-BIONIC-MAINLINE-001"

def read(path):
    return json.loads(path.read_text())

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def pair(raw_path, static_path, kind):
    raw, static = read(raw_path), read(static_path)
    if kind == "fdroid":
        rp, rh = raw["package_expected"], raw["actual_sha256"]
        bound = static["raw_sha256"] == sha(raw_path)
        phase = static["four_phase_rc0"]
    else:
        verify_path = raw_path.parent / "VERIFY.json"
        verify = read(verify_path)
        rp, rh = verify["package_version"][0], verify["apk_sha256"]
        bound = verify["raw_result_sha256"] == sha(raw_path)
        phase = static["all_four_phases_rc0"]
    sp = static["package"] if kind == "fdroid" else static["phases"]["metadata"]["package"]
    sh = static["apk_sha256"]
    return {"raw_package": rp, "static_package": sp, "raw_apk_sha256": rh,
            "static_apk_sha256": sh, "raw_receipt_bound": bound,
            "four_phase_rc0": phase, "identity_match": rp == sp and rh == sh and bound and phase}

def main():
    rows = {}
    for package in ["com.dozingcatsoftware.cardswithcats", "com.exner.tools.meditationtimer",
                    "com.ltrademark.hourly", "org.nsh07.pomodoro"]:
        d = BASE / "peer-upstream-next4e-exact-v1" / package
        rows[package] = pair(d / "RAW.json", d / "STATIC.json", "fdroid")
    for label in ["remote", "host"]:
        raw = BASE / f"peer-teamviewer-{label}-official-raw-v1/RESULT.json"
        static = BASE / f"peer-teamviewer-{label}-four-static-v1/RESULT.json"
        rows[f"teamviewer-{label}"] = pair(raw, static, "teamviewer")
    remote_raw = BASE / "peer-teamviewer-remote-official-raw-v1/RESULT.json"
    host_static = BASE / "peer-teamviewer-host-four-static-v1/RESULT.json"
    swapped = pair(remote_raw, host_static, "teamviewer")
    result = {"schema": "evo64-peer-root-identity-join-pilot-v1", "positive": rows,
              "negative_swapped_teamviewer_remote_raw_host_static": swapped,
              "expected": "six_identity_matches_and_one_swap_rejected",
              "observed": "six_identity_matches_and_one_swap_rejected" if all(x["identity_match"] for x in rows.values()) and not swapped["identity_match"] else "FAIL"}
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result["observed"] == result["expected"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
