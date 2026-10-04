#!/usr/bin/env python3
"""Run upstream startup-reach on the exact historical HelloWorld APK, without a runtime index."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from datetime import datetime, timezone

root = Path(os.environ["NANHAI_PROJECT_ROOT"])
here = Path(__file__).resolve().parent
source = root / ".nanhai-plus-runtime/musl-oh7-pilot/staging/host-hello/2d122a7973ffd68c799700aaaaaa0593e5deec30bac83e22a9dc1bf9f64319fd.apk"
source_receipt = root / "docs/nanhai-plus/versions/musl-oh7-aosp16.lock.json"
stage = Path(os.environ["NANHAI_STAGING_ROOT"]) / "hello-baseline-upstream-reach-v1"
apk = stage / "HelloWorld-original.apk"
python = Path(os.environ["NANHAI_RUNTIME_ROOT"]) / "venvs/harness-python-v1/bin/python3"
expected = "2d122a7973ffd68c799700aaaaaa0593e5deec30bac83e22a9dc1bf9f64319fd"

def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def write(path, obj):
    path.write_text(json.dumps(obj, sort_keys=True, indent=2) + "\n")

assert source.is_file() and sha(source) == expected
assert expected in source_receipt.read_text()
assert python.is_file()
stage.mkdir(parents=True, exist_ok=True)
if apk.exists():
    assert sha(apk) == expected
else:
    shutil.copyfile(source, apk)
assert sha(apk) == expected
env = os.environ.copy()
env["PYTHONPATH"] = str(root / "harness")
argv = [str(python), "-B", "-m", "westlake_gap.cli", "startup-reach", str(apk), "--out", str(here / "STARTUP-REACH.json")]
with (here / "stdout.raw").open("wb") as stdout, (here / "stderr.raw").open("wb") as stderr:
    done = subprocess.run(argv, cwd=root, env=env, stdout=stdout, stderr=stderr, timeout=120)
receipt = {"schema": "nanhai-hello-upstream-startup-reach-v1", "at_utc": datetime.now(timezone.utc).isoformat(),
           "input_apk_sha256": sha(apk), "historical_input_source_sha256": sha(source),
           "historical_source_receipt_sha256": sha(source_receipt),
           "scanner_cli_sha256": sha(root / "harness/westlake_gap/cli.py"),
           "scanner_reach_sha256": sha(root / "harness/westlake_gap/reach.py"),
           "argv": argv, "rc": done.returncode, "stdout_sha256": sha(here / "stdout.raw"),
           "stderr_sha256": sha(here / "stderr.raw"),
           "output_sha256": sha(here / "STARTUP-REACH.json") if (here / "STARTUP-REACH.json").is_file() else None,
           "target_runtime_index": None, "runtime_gap_claim": False, "cold_start_claim": False,
           "container_commands": 0, "device_commands": 0}
write(here / "RUN.json", receipt)
print(json.dumps({"rc": done.returncode, "apk_sha256": expected, "output_sha256": receipt["output_sha256"]}))
sys.exit(done.returncode)
