#!/usr/bin/env python3
"""Independent manifest/entry-point review of the second static reach pilot."""
import hashlib
import json
import os
from pathlib import Path
from datetime import datetime, timezone

from westlake_gap.contracts import manifest_facts

root = Path(os.environ["NANHAI_PROJECT_ROOT"])
here = Path(__file__).resolve().parent
apk = Path(os.environ["NANHAI_STAGING_ROOT"]) / "peer-upstream-next4d-exact-v1/com.justdeax.composeStopwatch/original.apk"

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

run = json.loads((here / "RUN.json").read_text())
scan = json.loads((here / "STARTUP-REACH.json").read_text())
facts = manifest_facts(apk)
assert run["rc"] == 0 and run["apk_sha256"] == sha(apk)
assert run["output_sha256"] == sha(here / "STARTUP-REACH.json")
assert run["reach_source_sha256"] == sha(root / "harness/westlake_gap/reach.py")
assert facts["package"] == "com.justdeax.composeStopwatch"
assert facts["main_activities"] == scan["summary"]["entry_points"]["1"] == ["com.justdeax.composeStopwatch.AppActivity"]
assert scan["summary"]["entry_points"]["0"] and scan["summary"]["methods_by_stage"]["first activity"] > 0
assert scan["summary"]["runtime_index_used"] is False and run["runtime_index_used"] is False
assert run["cold_start_delta"] == run["device_commands"] == run["container_commands"] == 0

review = {"schema": "nanhai-second-apk-static-reach-root-review-v1", "at_utc": datetime.now(timezone.utc).isoformat(),
          "decision": "ACCEPT_SECOND_REAL_APK_STATIC_ENTRYPOINT_PILOT_ONLY",
          "apk_sha256": sha(apk), "run_sha256": sha(here / "RUN.json"),
          "output_sha256": sha(here / "STARTUP-REACH.json"),
          "manifest_package": facts["package"], "manifest_launcher": facts["main_activities"],
          "detected_launcher": scan["summary"]["entry_points"]["1"],
          "process_start_methods": scan["summary"]["methods_by_stage"]["process start"],
          "first_activity_methods": scan["summary"]["methods_by_stage"]["first activity"],
          "runtime_index_present": False, "cold_start_delta": 0,
          "limits": "The second real APK avoids a launcher false negative but does not test the no-launcher case or target-runtime behavior; EVO63 remains a pilot."}
(here / "ROOT-REVIEW.json").write_text(json.dumps(review, sort_keys=True, indent=2) + "\n")
print(json.dumps({"decision": review["decision"], "launcher": review["detected_launcher"], "cold_start_delta": 0}))
