#!/usr/bin/env python3
"""Pin exact package, version, SDK, signer and source identity for the official APK."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(os.environ["NANHAI_PROJECT_ROOT"])
HERE = Path(__file__).parent
APK = Path(os.environ["NANHAI_STAGING_ROOT"]) / "peer-imo-official-raw-v1/imo-official.apk"
TOOLS = Path.home() / "Library/Android/sdk/build-tools/36.1.0"

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def run(name, argv):
    p = subprocess.run([str(v) for v in argv], capture_output=True, timeout=120, check=False)
    (HERE / (name + ".stdout.raw")).write_bytes(p.stdout)
    (HERE / (name + ".stderr.raw")).write_bytes(p.stderr)
    return {"argv": [str(v) for v in argv], "rc": p.returncode, "stdout_sha256": sha(HERE / (name + ".stdout.raw")), "stderr_sha256": sha(HERE / (name + ".stderr.raw"))}

def main():
    if sys.argv[1:] != ["--execute"] or (HERE / "VERIFY.json").exists(): return 2
    raw = json.loads((HERE / "RESULT.json").read_text())
    assert raw["candidate_pass"] and sha(APK) == raw["apk_sha256"] and APK.stat().st_size == raw["apk_bytes"]
    aapt = run("aapt2", [TOOLS / "aapt2", "dump", "badging", APK])
    signer = run("apksigner", [TOOLS / "apksigner", "verify", "--verbose", "--print-certs", APK])
    txt = (HERE / "aapt2.stdout.raw").read_text(errors="replace")
    sig = (HERE / "apksigner.stdout.raw").read_text(errors="replace")
    m = re.search(r"^package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'", txt, re.M)
    target = re.search(r"^targetSdkVersion:'([^']+)'", txt, re.M)
    certs = re.findall(r"Signer #\d+ certificate SHA-256 digest: ([0-9a-fA-F]+)", sig)
    result = {"schema": "peer-imo-official-verify-v1", "apk_sha256": sha(APK), "apk_bytes": APK.stat().st_size, "package_version": m.groups() if m else None, "target_sdk": target.group(1) if target else None, "signer_cert_sha256": certs, "aapt2": aapt, "apksigner": signer, "raw_result_sha256": sha(HERE / "RESULT.json"), "root_count_changed": False, "startup_proven": False}
    result["candidate_pass"] = aapt["rc"] == signer["rc"] == 0 and m is not None and m.group(1) == "com.imo.android.imoim" and bool(certs)
    (HERE / "VERIFY.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["candidate_pass"] else 2

if __name__ == "__main__": sys.exit(main())
