#!/usr/bin/env python3
"""One bounded publisher-link acquisition of Snapchat's non-GMS APK."""
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
STAGING = Path(os.environ["NANHAI_STAGING_ROOT"]) / "peer-snapchat-official-raw-v1"
SUPPORT = "https://help.snapchat.com/hc/en-us/articles/7012377684756-What-devices-does-Snapchat-support"
PUBLISHER_LINK = "https://www.snapchat.com/additionaldownloads/"

def sha(p):
    h = hashlib.sha256()
    with p.open("rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()

def run(name, argv, timeout):
    with (HERE / (name + ".stdout.raw")).open("xb") as out, (HERE / (name + ".stderr.raw")).open("xb") as err:
        p = subprocess.run(argv, stdout=out, stderr=err, timeout=timeout, check=False)
    return {"argv": argv, "rc": p.returncode, "stdout_sha256": sha(HERE / (name + ".stdout.raw")), "stderr_sha256": sha(HERE / (name + ".stderr.raw"))}

def main():
    if sys.argv[1:] != ["--execute"] or (HERE / "RESULT.json").exists():
        return 2
    STAGING.mkdir(mode=0o700, parents=True, exist_ok=False)
    curl = os.environ["NANHAI_CURL"]
    support = run("support", [curl, "--fail", "--location", "--retry", "0", "--connect-timeout", "15", "--max-time", "30", "--output", str(HERE / "support-page.raw"), "--dump-header", str(HERE / "support-headers.raw"), SUPPORT], 45)
    head = run("head", [curl, "--fail", "--location", "--head", "--retry", "0", "--connect-timeout", "15", "--max-time", "30", "--dump-header", str(HERE / "publisher-head-headers.raw"), PUBLISHER_LINK], 45)
    part = STAGING / "Snapchat.apk.part"
    get = run("get", [curl, "--fail", "--location", "--retry", "0", "--connect-timeout", "15", "--max-time", "240", "--output", str(part), "--dump-header", str(HERE / "publisher-get-headers.raw"), PUBLISHER_LINK], 260)
    result = {"schema": "peer-snapchat-official-raw-v1", "at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "publisher_support": SUPPORT, "publisher_link": PUBLISHER_LINK, "support": support, "head": head, "get": get, "root_count_changed": False, "device_commands": 0, "container_commands": 0, "startup_proven": False}
    if part.is_file():
        result["payload_bytes"] = part.stat().st_size
        result["payload_sha256"] = sha(part)
        try:
            with zipfile.ZipFile(part) as z:
                names = z.namelist()
                result["zip_entries"] = len(names)
                result["zip_first_bad"] = z.testzip()
                result["zip_duplicate_names"] = len(names) - len(set(names))
                result["manifest_entries"] = names.count("AndroidManifest.xml")
                result["root_dex"] = sum(n.startswith("classes") and n.endswith(".dex") and "/" not in n for n in names)
                result["abis"] = sorted({n.split("/")[1] for n in names if n.startswith("lib/") and n.endswith(".so") and len(n.split("/")) > 2})
        except Exception as e:
            result["zip_error"] = repr(e)
    headers = (HERE / "publisher-get-headers.raw").read_text(errors="replace")
    result["official_chain_has_snapchat_domain"] = "location: https://storage.googleapis.com/snapchat-web/download/android-apks_universal.apk" in headers.lower()
    result["apk_mime_seen"] = "content-type: application/vnd.android.package-archive" in headers.lower()
    result["candidate_pass"] = (support["rc"] == 0 and head["rc"] == 0 and get["rc"] == 0 and result.get("official_chain_has_snapchat_domain") and result.get("apk_mime_seen") and result.get("payload_bytes", 0) > 0 and result.get("zip_first_bad", "failed") is None and result.get("zip_duplicate_names") == 0 and result.get("manifest_entries") == 1 and result.get("root_dex", 0) > 0)
    if result["candidate_pass"]:
        apk = STAGING / "Snapchat.apk"
        part.rename(apk)
        result["apk_path"] = str(apk.relative_to(ROOT))
    (HERE / "RESULT.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k not in ("support", "head", "get")}, sort_keys=True))
    return 0 if result["candidate_pass"] else 2

if __name__ == "__main__":
    sys.exit(main())
