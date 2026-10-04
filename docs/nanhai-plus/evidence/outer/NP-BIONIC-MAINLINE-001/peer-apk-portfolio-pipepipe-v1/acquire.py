#!/usr/bin/env python3
"""Acquire only the upstream-registered PipePipe APK on the native host."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT = Path(os.environ["NANHAI_PROJECT_ROOT"])
HERE = Path(__file__).parent
REGISTRY = ROOT / "docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/upstream-apk-registry-v1/REGISTRY.json"
PACKAGE = "InfinityLoop1309.NewPipeEnhanced"

def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()

def write(name, data):
    with (HERE / name).open("x") as stream:
        json.dump(data, stream, sort_keys=True, indent=2)
        stream.write("\n")

def run(argv, name):
    with (HERE / (name + ".stdout.raw")).open("xb") as out, (HERE / (name + ".stderr.raw")).open("xb") as err:
        process = subprocess.run(argv, stdout=out, stderr=err, timeout=210, check=False)
    return {"argv": argv, "rc": process.returncode,
            "stdout_sha256": sha(HERE / (name + ".stdout.raw")),
            "stderr_sha256": sha(HERE / (name + ".stderr.raw"))}

def main():
    if sys.argv[1:] != ["--execute"] or (HERE / "RESULT.json").exists():
        return 2
    registry = json.loads(REGISTRY.read_text())
    artifact = next(x for x in registry["artifacts"] if x["package"] == PACKAGE)
    assert artifact["versions"] == ["5.3.1"] and artifact["version_codes"] == ["110804"]
    assert len(artifact["source_urls"]) == 1
    staging = Path(os.environ["NANHAI_STAGING_ROOT"]) / "peer-apk-portfolio-pipepipe-v1"
    staging.mkdir(mode=0o700, parents=True, exist_ok=False)
    part = staging / "PipePipe-5.3.1.apk.part"
    apk = staging / "PipePipe-5.3.1.apk"
    curl = os.environ["NANHAI_CURL"]
    command = run([curl, "--fail", "--location", "--retry", "0", "--connect-timeout", "15",
                   "--max-time", "180", "--output", str(part),
                   "--dump-header", str(HERE / "GET.headers.raw"), artifact["source_urls"][0]], "GET")
    result = {"schema": "peer-apk-portfolio-pipepipe-v1", "at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "registry_sha256": sha(REGISTRY), "artifact_id": artifact["id"], "package_expected": PACKAGE,
              "version_expected": "5.3.1", "version_code_expected": "110804", "source_url": artifact["source_urls"][0],
              "expected_sha256": artifact["sha256"], "download": command,
              "raw_count_changed": False, "static_count_changed": False, "startup_proven": False,
              "device_commands": 0, "container_commands": 0}
    if command["rc"] == 0 and part.is_file():
        result["bytes"] = part.stat().st_size
        result["actual_sha256"] = sha(part)
        result["sha_matches_upstream"] = result["actual_sha256"] == artifact["sha256"]
        if result["sha_matches_upstream"]:
            with zipfile.ZipFile(part) as archive:
                bad = archive.testzip()
                names = archive.namelist()
                result["zip_first_bad"] = bad
                result["zip_duplicate_names"] = len(names) - len(set(names))
                result["root_dex"] = len([n for n in names if n.startswith("classes") and n.endswith(".dex") and "/" not in n])
                result["native_abi_names"] = sorted(set(n.split("/")[1] for n in names if n.startswith("lib/") and n.endswith(".so") and len(n.split("/")) >= 3))
            part.rename(apk)
            result["apk_path"] = str(apk.relative_to(ROOT))
    write("RESULT.json", result)
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("sha_matches_upstream") and result.get("zip_first_bad") is None else 2

if __name__ == "__main__":
    sys.exit(main())
