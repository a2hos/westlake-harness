#!/usr/bin/env python3
"""Pin ntfy package, version, signer, SDK, and true ARM64 ELF."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

ROOT = Path(os.environ["NANHAI_PROJECT_ROOT"])
HERE = Path(__file__).parent
APK = Path(os.environ["NANHAI_STAGING_ROOT"]) / "peer-apk-portfolio-fossify-clock-v1/fossify-clock-1.6.0.apk"
TOOLS = Path.home() / "Library/Android/sdk/build-tools/36.1.0"

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def command(name, args):
    result = subprocess.run(args, capture_output=True, timeout=120, check=False)
    (HERE / (name + ".stdout.raw")).write_bytes(result.stdout)
    (HERE / (name + ".stderr.raw")).write_bytes(result.stderr)
    return {"argv": [str(x) for x in args], "rc": result.returncode,
            "stdout_sha256": sha(HERE / (name + ".stdout.raw")),
            "stderr_sha256": sha(HERE / (name + ".stderr.raw"))}

def main():
    if sys.argv[1:] != ["--execute"] or (HERE / "VERIFY.json").exists():
        return 2
    acquire = json.loads((HERE / "RESULT.json").read_text())
    assert acquire["sha_matches_upstream"] and sha(APK) == acquire["expected_sha256"]
    aapt = command("aapt2", [TOOLS / "aapt2", "dump", "badging", APK])
    signer = command("apksigner", [TOOLS / "apksigner", "verify", "--verbose", "--print-certs", APK])
    badging = (HERE / "aapt2.stdout.raw").read_text(errors="replace")
    certs = (HERE / "apksigner.stdout.raw").read_text(errors="replace")
    package = re.search(r"^package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'", badging, re.M)
    sdk = re.search(r"^sdkVersion:'([^']+)'", badging, re.M)
    target = re.search(r"^targetSdkVersion:'([^']+)'", badging, re.M)
    fingerprints = re.findall(r"Signer #\d+ certificate SHA-256 digest: ([0-9a-fA-F]+)", certs)
    native = []
    with zipfile.ZipFile(APK) as archive:
        for name in archive.namelist():
            if name.startswith("lib/arm64-v8a/") and name.endswith(".so"):
                data = archive.read(name)
                native.append({"name": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                               "true_elf64_aarch64": len(data) >= 20 and data[:4] == b"\x7fELF" and data[4] == 2 and data[5] == 1 and int.from_bytes(data[18:20], "little") == 183})
    result = {"schema": "peer-apk-portfolio-fossify-clock-verify-v1", "apk_sha256": sha(APK),
              "package": package.groups() if package else None, "min_sdk": sdk.group(1) if sdk else None,
              "target_sdk": target.group(1) if target else None, "signer_cert_sha256": fingerprints,
              "aapt2": aapt, "apksigner": signer, "arm64_native": native,
              "host_only": True, "raw_count_changed": False, "startup_proven": False}
    result["candidate_pass"] = (aapt["rc"] == 0 and signer["rc"] == 0 and
                               result["package"] == ("org.fossify.clock", "10", "1.6.0") and
                               bool(fingerprints) and all(x["true_elf64_aarch64"] for x in native))
    with (HERE / "VERIFY.json").open("x") as output:
        json.dump(result, output, sort_keys=True, indent=2)
        output.write("\n")
    print(json.dumps({k:v for k,v in result.items() if k != "arm64_native"}, sort_keys=True))
    return 0 if result["candidate_pass"] else 2

if __name__ == "__main__":
    sys.exit(main())
