#!/usr/bin/env python3
"""Explicit one-shot GitHub Element X APK GET; never runs on import."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
import zipfile

HERE = Path(__file__).resolve().parent
API = "https://api.github.com/repos/element-hq/element-x-android/releases/tags/v26.09.1"
URL = "https://github.com/element-hq/element-x-android/releases/download/v26.09.1/app-fdroid-arm64-v8a-release-signed.apk"
ASSET_ID = 539529327
SHA = "ceb076564298cd0aef4688ad79058b55638d196b9beb5ac47ab421d757335bf3"
SIZE = 117664325
RECORD_ID = "r-52d5e188c88dfba15c98"
REGISTRY_SHA = "289dcdb499d5ff37e58a8e7d4fbd3d30e3fe9f77d4e7e8ba7139c927c890c1eb"
TOOL_SHA = {
    "aapt2": "3c5920804724dfe9a43e0dbf1f5b5dcbf08c4a2e829bebdaa04d38bfe7d7ada4",
    "apksigner": "9469c60e5e40fc5c44a2f2338509cb6600cdf065e9b50f9fa3ca6c5be5bae6a9",
    "java": "cd158e1a5328ff42b687b7c2f5c61c7c3be3cfee7f18226ee903169e97336158",
    "curl": "b636262803922ee1dd0fbf614818473ffa53c811e44fd3278c2270d3af4759d3",
}

def utc():
    return datetime.now(timezone.utc).isoformat()

def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def command(name, argv, timeout, env=None):
    start = utc(); tick = time.monotonic()
    try:
        p = subprocess.run(argv, cwd=HERE, env=env, capture_output=True, timeout=timeout)
        rc, out, err, timed = p.returncode, p.stdout, p.stderr, False
    except subprocess.TimeoutExpired as e:
        rc, out, err, timed = None, e.stdout or b"", e.stderr or b"", True
    (HERE / (name + ".stdout.raw")).write_bytes(out)
    (HERE / (name + ".stderr.raw")).write_bytes(err)
    return {"name": name, "argv": argv, "started_utc": start, "ended_utc": utc(),
            "elapsed_seconds": round(time.monotonic()-tick, 3), "rc": rc,
            "timed_out": timed, "stdout_bytes": len(out), "stderr_bytes": len(err),
            "stdout_sha256": hashlib.sha256(out).hexdigest(),
            "stderr_sha256": hashlib.sha256(err).hexdigest()}

def main():
    if sys.argv[1:] != ["--execute"]:
        raise SystemExit("PREPARED_ONLY: explicit --execute required; no request made")
    source = Path(os.environ["NANHAI_SOURCE_POOL_ROOT"])
    evidence = Path(os.environ["NANHAI_EVIDENCE_ROOT"])
    staging = Path(os.environ["NANHAI_STAGING_ROOT"]) / "g284-elementx-github-raw-candidate-v1"
    staging.mkdir(parents=True, exist_ok=False)
    part = staging / "elementx-v26.09.1-arm64.apk.part"
    apk = staging / "elementx-v26.09.1-arm64.apk"
    regpath = evidence / "outer/NP-BIONIC-MAINLINE-001/upstream-apk-registry-v1/REGISTRY.json"
    assert sha(regpath) == REGISTRY_SHA
    reg = json.loads(regpath.read_text())
    row = next(x for x in reg["records"] if x["id"] == RECORD_ID)
    assert row["fields"]["artifact_sha256"]["value"] == SHA
    assert row["fields"]["bytes"]["value"] == SIZE
    assert row["fields"]["version_name"]["value"] == "26.09.1"
    assert row["fields"]["version_code"]["value"] == 202609012
    assert row["fields"]["source_url"]["value"] == "https://f-droid.org/repo/io.element.android.x_202609012.apk"
    aapt = source / "AOSP-16.0.0_r4/prebuilts/sdk-r4/tools/darwin/bin/aapt2"
    signer = source / "AOSP-16.0.0_r4/prebuilts/sdk-r4/tools/darwin/lib/apksigner.jar"
    java = Path("/Applications/DevEco-Studio.app/Contents/jbr/Contents/Home/bin/java")
    curl = os.environ["NANHAI_CURL"]
    tools = {str(p): sha(p) for p in (aapt, signer, java)}
    assert tools == {str(aapt): TOOL_SHA["aapt2"], str(signer): TOOL_SHA["apksigner"], str(java): TOOL_SHA["java"]}
    assert sha(Path(curl)) == TOOL_SHA["curl"]
    receipt = {"schema": "g284-elementx-github-raw-candidate-v1", "generation": "NEW_AFTER_G282_FDROID_TIMEOUT",
               "started_utc": utc(), "status": "IN_PROGRESS", "registry_path": str(regpath),
               "registry_sha256": sha(regpath), "registry_record_id": RECORD_ID,
               "expected_artifact_sha256": SHA, "expected_artifact_bytes": SIZE,
               "official_api": API, "official_stable_url": URL, "official_asset_id": ASSET_ID,
               "staging_apk": str(apk), "tools_before": tools, "curl_sha256_before": TOOL_SHA["curl"], "commands": [],
               "candidate_only": True, "raw_accepted": False, "canonical_delta": 0,
               "device_commands": 0, "container_commands": 0,
               "prior_failed_staging_reused": False}
    def save(status):
        receipt["status"] = status; receipt["ended_utc"] = utc()
        (HERE / "RESULT.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
    preflight = [curl, "-q", "--fail", "--silent", "--show-error", "--max-time", "20", API]
    rec = command("api", preflight, 25); receipt["commands"].append(rec)
    if rec["rc"] != 0 or rec["timed_out"]:
        save("STOP_API_ERROR"); return
    release = json.loads((HERE / "api.stdout.raw").read_bytes())
    assets = [a for a in release.get("assets", []) if a.get("id") == ASSET_ID]
    asset = assets[0] if len(assets) == 1 else {}
    receipt["api_asset"] = {k: asset.get(k) for k in ("id", "name", "size", "digest", "browser_download_url")}
    if release.get("tag_name") != "v26.09.1" or receipt["api_asset"] != {
        "id": ASSET_ID, "name": "app-fdroid-arm64-v8a-release-signed.apk", "size": SIZE,
        "digest": "sha256:" + SHA, "browser_download_url": URL}:
        save("STOP_API_ASSET_IDENTITY_DRIFT"); return
    get = [curl, "-q", "--fail", "--location", "--proto", "=https", "--proto-redir", "=https",
           "--retry", "0", "--connect-timeout", "20", "--max-time", "300",
           "--silent", "--show-error", "--output", str(part), "--write-out",
           "http=%{http_code} tls=%{ssl_verify_result} bytes=%{size_download} redirects=%{num_redirects}", URL]
    rec = command("download", get, 310); receipt["commands"].append(rec)
    receipt["transfer"] = (HERE / "download.stdout.raw").read_text(errors="replace")
    if part.exists():
        receipt["part_bytes"] = part.stat().st_size
        receipt["part_sha256"] = sha(part)
    if rec["rc"] != 0 or rec["timed_out"] or not receipt["transfer"].startswith("http=200 tls=0 "):
        save("STOP_FIRST_DOWNLOAD_ERROR"); return
    if receipt.get("part_bytes") != SIZE or receipt.get("part_sha256") != SHA:
        save("STOP_PAYLOAD_IDENTITY_MISMATCH"); return
    part.rename(apk)
    with zipfile.ZipFile(apk) as z:
        names = z.namelist()
        receipt["zip"] = {"entries": len(names), "bad_entry": z.testzip(),
                          "manifest_count": names.count("AndroidManifest.xml"),
                          "lib_abis": sorted({m.group(1) for n in names if
                                              (m := re.match(r"lib/([^/]+)/[^/]+\.so$", n))})}
    if receipt["zip"]["bad_entry"] or receipt["zip"]["manifest_count"] != 1:
        save("STOP_ZIP_INVALID"); return
    env = os.environ.copy()
    for k in ("JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH",
              "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH"):
        env.pop(k, None)
    env.update({"LC_ALL": "C", "TZ": "UTC", "TMPDIR": str(HERE)})
    for name, argv in [
        ("badging", [str(aapt), "dump", "badging", str(apk)]),
        ("signature", [str(java), "-XX:-UsePerfData", "-Xmx512m", "-Djava.awt.headless=true",
                       "-Djava.io.tmpdir=" + str(HERE), "-jar", str(signer), "verify",
                       "--verbose", "--print-certs", str(apk)])]:
        rec = command(name, argv, 120, env); receipt["commands"].append(rec)
        if rec["rc"] != 0 or rec["timed_out"]:
            save("STOP_" + name.upper() + "_ERROR"); return
    badging = (HERE / "badging.stdout.raw").read_text(errors="replace")
    signature = (HERE / "signature.stdout.raw").read_text(errors="replace")
    receipt["package_line"] = next((x for x in badging.splitlines() if x.startswith("package: ")), None)
    receipt["native_code_line"] = next((x for x in badging.splitlines() if x.startswith("native-code: ")), None)
    receipt["signature_lines"] = [x for x in signature.splitlines() if x.startswith(("Verified using", "Number of signers:", "Signer #"))]
    receipt["tools_after"] = {str(p): sha(p) for p in (aapt, signer, java)}
    receipt["curl_sha256_after"] = sha(Path(curl))
    receipt["apk_sha256_after"] = sha(apk)
    good = ("name='io.element.android.x'" in (receipt["package_line"] or "")
            and "versionCode='202609012'" in (receipt["package_line"] or "")
            and "versionName='26.09.1'" in (receipt["package_line"] or "")
            and receipt["zip"]["lib_abis"] == ["arm64-v8a"]
            and "arm64-v8a" in (receipt["native_code_line"] or "")
            and "Number of signers: 1" in signature
            and "Verified using v2 scheme (APK Signature Scheme v2): true" in signature
            and receipt["tools_after"] == tools and receipt["curl_sha256_after"] == TOOL_SHA["curl"]
            and receipt["apk_sha256_after"] == SHA)
    save("RAW_CANDIDATE_STATIC_PASS" if good else "RAW_CANDIDATE_STATIC_MISMATCH")

if __name__ == "__main__":
    main()
