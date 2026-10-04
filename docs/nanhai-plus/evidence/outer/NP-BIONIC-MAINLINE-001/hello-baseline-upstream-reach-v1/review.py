#!/usr/bin/env python3
"""Root review of the HelloWorld relative-component scanner regression."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
from datetime import datetime, timezone

root = Path(os.environ["NANHAI_PROJECT_ROOT"])
here = Path(__file__).resolve().parent
before = json.loads((here / "STARTUP-REACH-before-fix.json").read_text())
after = json.loads((here / "STARTUP-REACH.json").read_text())
run = json.loads((here / "RUN.json").read_text())

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

assert run["rc"] == 0 and run["input_apk_sha256"] == "2d122a7973ffd68c799700aaaaaa0593e5deec30bac83e22a9dc1bf9f64319fd"
assert run["output_sha256"] == sha(here / "STARTUP-REACH.json")
assert before["summary"]["entry_points"] == {"0": [], "1": [], "2": [], "3": []}
assert before["summary"]["methods_by_stage"]["not reached statically"] == 58
assert after["summary"]["entry_points"]["0"] == ["com.example.helloworld.HelloWorldApplication"]
assert after["summary"]["entry_points"]["1"] == ["com.example.helloworld.MainActivity"]
assert after["summary"]["methods_by_stage"]["process start"] > 0
assert after["summary"]["methods_by_stage"]["first activity"] > 0
assert after["platform_stage"]["Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I"] == 0
assert after["summary"]["runtime_index_used"] is False
assert run["target_runtime_index"] is None and not run["runtime_gap_claim"] and not run["cold_start_claim"]
class_refs = sorted(key for key in after["platform_stage"] if key.endswith("->C:"))
assert class_refs == ["Landroid/widget/Button;->C:", "Landroid/widget/LinearLayout;->C:",
                     "Landroid/widget/TextView;->C:", "Ljava/lang/StringBuilder;->C:"]

python = Path(os.environ["NANHAI_RUNTIME_ROOT"]) / "venvs/harness-python-v1/bin/python3"
env = os.environ.copy()
env["PATH"] = "/opt/homebrew/opt/openjdk@17/bin:/usr/local/bin:/usr/bin:/bin"
env["WESTLAKE_D8"] = "/Users/alexyang/Library/Android/sdk/build-tools/36.1.0/d8"
env["PYTHONPATH"] = "harness:tests"
argv = [str(python), "-B", "-m", "unittest", "discover", "-s", "tests", "-p", "test_reach.py"]
test = subprocess.run(argv, cwd=root, env=env, capture_output=True, timeout=60)
(here / "test.stdout.raw").write_bytes(test.stdout)
(here / "test.stderr.raw").write_bytes(test.stderr)
assert test.returncode == 0 and b"Ran 5 tests" in test.stderr and b"OK" in test.stderr

receipt = {"schema": "nanhai-hello-upstream-reach-root-review-v1", "at_utc": datetime.now(timezone.utc).isoformat(),
           "decision": "ACCEPT_STATIC_ENTRYPOINT_BUGFIX_ONLY", "apk_sha256": run["input_apk_sha256"],
           "before_output_sha256": sha(here / "STARTUP-REACH-before-fix.json"),
           "after_output_sha256": sha(here / "STARTUP-REACH.json"),
           "reach_source_sha256": sha(root / "harness/westlake_gap/reach.py"),
           "test_source_sha256": sha(root / "tests/test_reach.py"), "test_argv": argv, "test_rc": test.returncode,
           "test_stdout_sha256": sha(here / "test.stdout.raw"), "test_stderr_sha256": sha(here / "test.stderr.raw"),
           "process_start_methods": after["summary"]["methods_by_stage"]["process start"],
           "first_activity_methods": after["summary"]["methods_by_stage"]["first activity"],
           "platform_stage_entries": len(after["platform_stage"]),
           "synthetic_class_reference_entries": class_refs,
           "method_shaped_platform_candidate_count": len(after["platform_stage"]) - len(class_refs),
           "runtime_index_present": False, "cold_start_delta": 0, "device_commands": 0, "container_commands": 0,
           "limits": "Static candidate call graph; four C: entries are intentional class-reference nodes, not methods. No R4 Bionic runtime resolution, install or Activity execution."}
(here / "ROOT-REVIEW.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
print(json.dumps({"test_rc": test.returncode, "platform_stage_entries": len(after["platform_stage"]), "decision": receipt["decision"]}))
