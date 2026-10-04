#!/usr/bin/env python3
"""Second real-APK static reach pilot after the relative-component fix."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
from datetime import datetime, timezone

root = Path(os.environ["NANHAI_PROJECT_ROOT"])
here = Path(__file__).resolve().parent
apk = Path(os.environ["NANHAI_STAGING_ROOT"]) / "peer-upstream-next4d-exact-v1/com.justdeax.composeStopwatch/original.apk"
admission = root / "docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/peer-upstream-next4d-exact-v1/root-admission-v1/ROOT-ADMISSION.json"
python = Path(os.environ["NANHAI_RUNTIME_ROOT"]) / "venvs/harness-python-v1/bin/python3"
expected = "dbf937ebbe7c0b3d24c07fa0ede7cb53ea117f7071db3b61f1c96b7d257cda55"

def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

assert apk.is_file() and sha(apk) == expected
assert any(row["package"] == "com.justdeax.composeStopwatch" and row["apk_sha256"] == expected
           for row in json.loads(admission.read_text())["rows"])
env = os.environ.copy()
env["PYTHONPATH"] = str(root / "harness")
argv = [str(python), "-B", "-m", "westlake_gap.cli", "startup-reach", str(apk),
        "--out", str(here / "STARTUP-REACH.json")]
with (here / "stdout.raw").open("wb") as stdout, (here / "stderr.raw").open("wb") as stderr:
    done = subprocess.run(argv, cwd=root, env=env, stdout=stdout, stderr=stderr, timeout=120)
receipt = {"schema": "nanhai-second-apk-static-reach-v1", "at_utc": datetime.now(timezone.utc).isoformat(),
           "apk_sha256": sha(apk), "admission_sha256": sha(admission),
           "reach_source_sha256": sha(root / "harness/westlake_gap/reach.py"),
           "cli_source_sha256": sha(root / "harness/westlake_gap/cli.py"),
           "argv": argv, "rc": done.returncode, "stdout_sha256": sha(here / "stdout.raw"),
           "stderr_sha256": sha(here / "stderr.raw"),
           "output_sha256": sha(here / "STARTUP-REACH.json") if (here / "STARTUP-REACH.json").is_file() else None,
           "runtime_index_used": False, "cold_start_delta": 0, "device_commands": 0, "container_commands": 0}
(here / "RUN.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
print(json.dumps({"rc": done.returncode, "apk_sha256": expected, "output_sha256": receipt["output_sha256"]}))
raise SystemExit(done.returncode)
