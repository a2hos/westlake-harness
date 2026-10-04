"""Offline admission sentinel for one frozen HelloWorld startup-reach result."""
import hashlib
import json
from pathlib import Path

from westlake_gap.contracts import manifest_facts

ROOT = Path(__file__).resolve().parents[4]
BASE = ROOT / "docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/hello-baseline-upstream-reach-v1"
APK = ROOT / ".nanhai-plus-runtime/bionic-oh7-aosp16/staging/hello-baseline-upstream-reach-v1/HelloWorld-original.apk"
REACH = ROOT / "harness/westlake_gap/reach.py"

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def classify(run, output, expected_apk, actual_apk, current_source, facts):
    if run["rc"] != 0 or run["input_apk_sha256"] != expected_apk or actual_apk != expected_apk:
        return "INVALID_INPUT_OR_COMMAND"
    if run["output_sha256"] != sha(output):
        return "INVALID_OUTPUT_BINDING"
    if run["scanner_reach_sha256"] != current_source:
        return "STALE_SCANNER_VERSION"
    package = facts["package"]
    def expand(name):
        return package + name if name.startswith(".") else (package + "." + name if "." not in name else name)
    expected = {expand(x) for x in facts["main_activities"]}
    observed = set(json.loads(output.read_text())["summary"]["entry_points"]["1"])
    if expected and not expected.issubset(observed):
        return "SUSPECT_STATIC_FALSE_NEGATIVE"
    return "VALID_STATIC_REACH_ONLY"

def main():
    facts = manifest_facts(APK)
    actual = sha(APK)
    current = sha(REACH)
    before = json.loads((BASE / "RUN-before-fix.json").read_text())
    after = json.loads((BASE / "RUN.json").read_text())
    expected = "2d122a7973ffd68c799700aaaaaa0593e5deec30bac83e22a9dc1bf9f64319fd"
    cases = {
        "before_frozen": classify(before, BASE / "STARTUP-REACH-before-fix.json", expected, actual, current, facts),
        "after_frozen": classify(after, BASE / "STARTUP-REACH.json", expected, actual, current, facts),
        "before_claiming_current_scanner": classify({**before, "scanner_reach_sha256": current}, BASE / "STARTUP-REACH-before-fix.json", expected, actual, current, facts),
        "mutated_input_hash": classify(after, BASE / "STARTUP-REACH.json", "0" * 64, actual, current, facts),
    }
    result = {"schema": "evo63-offline-static-admission-pilot-v1", "apk_sha256": actual,
              "manifest_package": facts["package"], "manifest_application": facts["application_class"],
              "manifest_main_activities": facts["main_activities"], "reach_source_sha256": current,
              "cases": cases, "expected": {"before_frozen": "STALE_SCANNER_VERSION",
                "before_claiming_current_scanner": "SUSPECT_STATIC_FALSE_NEGATIVE",
                "after_frozen": "VALID_STATIC_REACH_ONLY", "mutated_input_hash": "INVALID_INPUT_OR_COMMAND"}}
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if cases == result["expected"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
