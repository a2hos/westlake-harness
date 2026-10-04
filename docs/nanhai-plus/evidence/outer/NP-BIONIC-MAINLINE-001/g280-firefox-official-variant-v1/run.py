#!/usr/bin/env python3
"""Bounded, host-only verification of an existing official Firefox APK."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[5]
APK = PROJECT / ".nanhai-plus-runtime/bionic-oh7-aosp16/staging/mainstream-stock-intake-v2/org.mozilla.firefox/body.raw"
STAGING = APK.parent
POOL = Path(os.environ["NANHAI_SOURCE_POOL_ROOT"])
AAPT = POOL / "AOSP-16.0.0_r4/prebuilts/sdk-r4/tools/darwin/bin/aapt2"
SIGNER = POOL / "AOSP-16.0.0_r4/prebuilts/sdk-r4/tools/darwin/lib/apksigner.jar"
JAVA = Path("/Applications/DevEco-Studio.app/Contents/jbr/Contents/Home/bin/java")
EXPECTED = "d9c16c7406ec275896bb7734cb652c812092531e917a9db7287175dec26e251c"
TOOL_SHA = {
    "aapt2": "3c5920804724dfe9a43e0dbf1f5b5dcbf08c4a2e829bebdaa04d38bfe7d7ada4",
    "apksigner.jar": "9469c60e5e40fc5c44a2f2338509cb6600cdf065e9b50f9fa3ca6c5be5bae6a9",
    "java": "cd158e1a5328ff42b687b7c2f5c61c7c3be3cfee7f18226ee903169e97336158",
}


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def task(name, argv, limit):
    t0 = time.monotonic()
    env = dict(os.environ, TMPDIR=str(HERE), TMP=str(HERE), TEMP=str(HERE))
    try:
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=limit, env=env)
        rc, stdout, stderr, timeout = p.returncode, p.stdout, p.stderr, False
    except subprocess.TimeoutExpired as e:
        rc, stdout, stderr, timeout = 124, e.stdout or b"", e.stderr or b"", True
    elapsed = time.monotonic() - t0
    (HERE / (name + ".stdout.raw")).write_bytes(stdout)
    (HERE / (name + ".stderr.raw")).write_bytes(stderr)
    row = {"name": name, "argv": argv, "rc": rc, "timeout": timeout, "limit_seconds": limit, "elapsed_seconds": elapsed, "stdout_sha256": sha(HERE / (name + ".stdout.raw")), "stderr_sha256": sha(HERE / (name + ".stderr.raw")), "stdout_bytes": len(stdout), "stderr_bytes": len(stderr)}
    (HERE / (name + ".COMMAND.json")).write_text(json.dumps(row, indent=2) + "\n")
    return row


def main():
    assert os.environ["NANHAI_INPUTS_ROOT"]
    assert APK.is_file() and APK.stat().st_size == 133273833
    assert sha(APK) == EXPECTED
    for name, path in (("aapt2", AAPT), ("apksigner.jar", SIGNER), ("java", JAVA)):
        assert path.is_file() and sha(path) == TOOL_SHA[name]
    pre = {"apk": str(APK), "sha256": EXPECTED, "bytes": APK.stat().st_size, "tools": {k: {"path": str(p), "sha256": TOOL_SHA[k]} for k, p in (("aapt2", AAPT), ("apksigner.jar", SIGNER), ("java", JAVA))}, "script_sha256": sha(Path(__file__)), "verify_zip_sha256": sha(HERE / "verify_zip.py")}
    (HERE / "INPUTS.json").write_text(json.dumps(pre, indent=2) + "\n")
    rows = []
    rows.append(task("zip", [sys.executable, "-B", str(HERE / "verify_zip.py"), str(APK), str(HERE / "ZIP-FACTS.json"), EXPECTED], 300))
    rows.append(task("badging", [str(AAPT), "dump", "badging", str(APK)], 180))
    rows.append(task("signature", [str(JAVA), "-XX:-UsePerfData", "-Xmx512m", "-Djava.awt.headless=true", "-Djava.io.tmpdir=" + str(HERE), "-jar", str(SIGNER), "verify", "--verbose", "--print-certs", str(APK)], 180))
    assert sha(APK) == EXPECTED
    for name, path in (("aapt2", AAPT), ("apksigner.jar", SIGNER), ("java", JAVA)):
        assert sha(path) == TOOL_SHA[name]
    badging = (HERE / "badging.stdout.raw").read_text(errors="replace")
    sig = (HERE / "signature.stdout.raw").read_text(errors="replace")
    package = re.search(r"^package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'", badging, re.M)
    native = re.findall(r"^native-code: (.+)$", badging, re.M)
    sig_cert = re.findall(r"^Signer #\d+ certificate SHA-256 digest: ([0-9a-fA-F]+)$", sig, re.M)
    verified = {k: bool(re.search(r"^Verified using " + re.escape(k) + r" scheme \(APK Signature Scheme v\d\): true$", sig, re.M)) for k in ("v1", "v2", "v3", "v3.1", "v4")}
    zipfacts = json.loads((HERE / "ZIP-FACTS.json").read_text()) if (HERE / "ZIP-FACTS.json").exists() else None
    req = json.loads((STAGING / "REQUEST.json").read_text())
    rec = json.loads((STAGING / "RECEIPT.json").read_text())
    metrics = rec.get("metrics", {})
    provenance = {"request_path": str(STAGING / "REQUEST.json"), "request_sha256": sha(STAGING / "REQUEST.json"), "receipt_path": str(STAGING / "RECEIPT.json"), "receipt_sha256": sha(STAGING / "RECEIPT.json"), "headers_sha256": sha(STAGING / "headers.raw"), "requested_source_url": next((x for x in req.get("argv", []) if x.startswith("https://")), None), "effective_url": metrics.get("url_effective") or metrics.get("url"), "http_code": metrics.get("http_code"), "ssl_verify_result": metrics.get("ssl_verify_result"), "download_bytes": metrics.get("size_download"), "historic_expected_sha256": req.get("expected_sha256"), "historic_expected_mismatch_preserved": req.get("expected_sha256") != EXPECTED}
    result = {"schema": "g280-firefox-official-variant-static-preflight-v1", "at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "status": "CANDIDATE_ONLY_NO_CANONICAL_ADMISSION", "body_sha256": EXPECTED, "body_bytes": APK.stat().st_size, "commands": rows, "zip_preflight": zipfacts, "package": package.group(1) if package else None, "version_code": package.group(2) if package else None, "version_name": package.group(3) if package else None, "native_code_badging": native, "signer_certificate_sha256": sig_cert, "verified_schemes_parsed": verified, "provenance": provenance, "all_commands_rc0": all(r["rc"] == 0 for r in rows), "source_postguard_equal": True, "canonical_count_delta": 0, "device_commands": 0, "container_commands": 0, "limitations": ["Current original is a distinct variant from the historical registry SHA; do not rewrite old failure", "Published publisher-signing certificate comparison remains separate", "This is not a full harness DEX/ELF static inventory, installability, blackbox qualification, or cold startup"]}
    (HERE / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"all_commands_rc0": result["all_commands_rc0"], "package": result["package"], "version_name": result["version_name"], "version_code": result["version_code"], "zip_entries": zipfacts["zip_entries"] if zipfacts else None, "abi_counts": zipfacts["abi_counts"] if zipfacts else None, "certificate_count": len(sig_cert)}, sort_keys=True))
    return 0 if result["all_commands_rc0"] and zipfacts and zipfacts["preflight_pass"] and package and sig_cert else 2


if __name__ == "__main__":
    raise SystemExit(main())
