#!/usr/bin/env python3
"""Bounded native-host official AnyDesk APK acquisition."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT = Path(os.environ["NANHAI_PROJECT_ROOT"])
HERE = Path(__file__).parent
URL = "https://download.anydesk.com/anydesk.apk"
LIMIT = 62914560

def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()

def write(name, value):
    with (HERE / name).open("x") as output:
        json.dump(value, output, sort_keys=True, indent=2)
        output.write("\n")

def main():
    if sys.argv[1:] != ["--execute"] or (HERE / "RAW.json").exists():
        return 2
    pre = json.loads((HERE / "PRESCREEN.json").read_text())
    assert pre["proceed_to_bounded_acquisition"] and pre["head_content_length"] < LIMIT
    staging = Path(os.environ["NANHAI_STAGING_ROOT"]) / "peer-blackbox-anydesk-v1"
    staging.mkdir(mode=0o700, parents=True, exist_ok=False)
    part, apk = staging / "AnyDesk.apk.part", staging / "AnyDesk.apk"
    curl = os.environ["NANHAI_CURL"]
    argv = [curl, "--fail", "--location", "--retry", "0", "--connect-timeout", "15",
            "--max-time", "180", "--max-filesize", str(LIMIT), "--output", str(part), URL]
    with (HERE / "GET.stdout.raw").open("xb") as out, (HERE / "GET.stderr.raw").open("xb") as err:
        command = subprocess.run(argv, stdout=out, stderr=err, timeout=195, check=False)
    result = {"schema": "peer-blackbox-anydesk-raw-v1", "official_url": URL, "prescreen_sha256": sha(HERE / "PRESCREEN.json"),
              "argv": argv, "download_rc": command.returncode,
              "stdout_sha256": sha(HERE / "GET.stdout.raw"), "stderr_sha256": sha(HERE / "GET.stderr.raw"),
              "download_limit_bytes": LIMIT, "counts_changed": False, "startup_proven": False,
              "device_commands": 0, "container_commands": 0}
    if command.returncode == 0 and part.is_file():
        result["bytes"] = part.stat().st_size
        result["apk_sha256"] = sha(part)
        with zipfile.ZipFile(part) as archive:
            names = archive.namelist()
            result["zip_crc_bad"] = archive.testzip()
            result["zip_duplicate_names"] = len(names) - len(set(names))
            result["manifest_count"] = names.count("AndroidManifest.xml")
            result["native_abis"] = sorted({n.split("/")[1] for n in names if n.startswith("lib/") and n.endswith(".so")})
            result["root_dex"] = sum(n.startswith("classes") and n.endswith(".dex") and "/" not in n for n in names)
        if result["bytes"] <= LIMIT and result["zip_crc_bad"] is None and result["zip_duplicate_names"] == 0 and result["manifest_count"] == 1:
            part.rename(apk)
            result["apk_path"] = str(apk.relative_to(ROOT))
    write("RAW.json", result)
    print(json.dumps({k:v for k,v in result.items() if k != "argv"}, sort_keys=True))
    return 0 if "apk_path" in result else 2

if __name__ == "__main__":
    sys.exit(main())
