#!/usr/bin/env python3
"""G284 v2: one explicit official APK GET with crash-visible, no-replay receipts."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
import zipfile

HERE = Path(__file__).resolve().parent
API = "https://api.github.com/repos/element-hq/element-x-android/releases/tags/v26.09.1"
URL = "https://github.com/element-hq/element-x-android/releases/download/v26.09.1/app-fdroid-arm64-v8a-release-signed.apk"
ASSET_ID = 539529327
RECORD_ID = "r-52d5e188c88dfba15c98"
REGISTRY_SHA = "289dcdb499d5ff37e58a8e7d4fbd3d30e3fe9f77d4e7e8ba7139c927c890c1eb"
APK_SHA = "ceb076564298cd0aef4688ad79058b55638d196b9beb5ac47ab421d757335bf3"
APK_SIZE = 117664325
TOOLS = {
    "curl": "b636262803922ee1dd0fbf614818473ffa53c811e44fd3278c2270d3af4759d3",
    "aapt2": "3c5920804724dfe9a43e0dbf1f5b5dcbf08c4a2e829bebdaa04d38bfe7d7ada4",
    "apksigner": "9469c60e5e40fc5c44a2f2338509cb6600cdf065e9b50f9fa3ca6c5be5bae6a9",
    "java": "cd158e1a5328ff42b687b7c2f5c61c7c3be3cfee7f18226ee903169e97336158",
}

class GateError(RuntimeError):
    pass

def need(ok, message):
    if not ok:
        raise GateError(message)

def utc():
    return datetime.now(timezone.utc).isoformat()

def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def durable_exclusive_json(path, obj):
    """Create a durable receipt once; a previous generation state is never replaced."""
    data = (json.dumps(obj, ensure_ascii=False, indent=2) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
    except BaseException:
        raise
    dfd = os.open(Path(path).parent, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)

def durable_final(path, obj):
    """Publish terminal RESULT atomically without replacing a prior RESULT."""
    path = Path(path)
    tmp = path.with_name(path.name + ".pending." + str(os.getpid()))
    durable_exclusive_json(tmp, obj)
    try:
        os.link(tmp, path)  # EEXIST means another terminal receipt already won.
        dfd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        tmp.unlink(missing_ok=True)

def run_command(name, argv, timeout, child_env):
    began = utc(); tick = time.monotonic()
    try:
        p = subprocess.run(argv, cwd=HERE, env=child_env, capture_output=True, timeout=timeout)
        rc, out, err, timed = p.returncode, p.stdout, p.stderr, False
    except subprocess.TimeoutExpired as e:
        rc, out, err, timed = None, e.stdout or b"", e.stderr or b"", True
    # No headers or signed redirect URLs are requested or persisted.
    (HERE / (name + ".stdout.raw")).write_bytes(out)
    (HERE / (name + ".stderr.raw")).write_bytes(err)
    return {"name": name, "argv": argv, "began_utc": began, "ended_utc": utc(),
            "elapsed_seconds": round(time.monotonic() - tick, 3), "rc": rc,
            "timed_out": timed, "stdout_bytes": len(out), "stderr_bytes": len(err),
            "stdout_sha256": hashlib.sha256(out).hexdigest(),
            "stderr_sha256": hashlib.sha256(err).hexdigest()}

def authoritative_bindings():
    project = HERE.parents[5]  # .../opaleye/docs/nanhai-plus/evidence/outer/NP.../g284-v2
    loader_path = project / "scripts/nanhai_plus_env.py"
    need(loader_path.is_file(), "environment loader missing at project root")
    spec = importlib.util.spec_from_file_location("nanhai_plus_env", loader_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    bindings, audit = module.load_environment(project / "local_env.md")
    need(bindings["NANHAI_PROJECT_ROOT"] == str(project), "project root binding drift")
    need(bindings["NANHAI_EVIDENCE_ROOT"] == str(HERE.parents[2]), "evidence root binding drift")
    for key, value in bindings.items():
        need(os.environ.get(key) == value, "inherited environment drift: " + key)
    need(bindings.get("NANHAI_CONTAINER_POLICY") == "forbidden", "container policy drift")
    need(bindings.get("NANHAI_TARGET_ID") == "oh7.0.0.39-aosp16r4-arm64-bionic", "target drift")
    return bindings, audit

def execute(result):
    bindings, audit = authoritative_bindings()
    result["environment"] = {"document": audit["document"],
                             "config_sha256": audit["config_sha256"],
                             "links_checked": audit["links_checked"]}
    regpath = Path(bindings["NANHAI_EVIDENCE_ROOT"]) / "outer/NP-BIONIC-MAINLINE-001/upstream-apk-registry-v1/REGISTRY.json"
    need(sha(regpath) == REGISTRY_SHA, "registry file SHA drift")
    reg = json.loads(regpath.read_text())
    rows = [r for r in reg["records"] if r["id"] == RECORD_ID]
    need(len(rows) == 1, "registry record identity drift")
    row = rows[0]; fields = row["fields"]
    for key, expected in {"artifact_sha256": APK_SHA, "bytes": APK_SIZE,
                          "version_name": "26.09.1", "version_code": 202609012,
                          "source_url": "https://f-droid.org/repo/io.element.android.x_202609012.apk"}.items():
        need(fields[key]["value"] == expected, "registry field drift: " + key)
    need(row["package"] == "io.element.android.x", "registry package drift")
    source = Path(bindings["NANHAI_SOURCE_POOL_ROOT"])
    tools = {"curl": Path(bindings["NANHAI_CURL"]),
             "aapt2": source / "AOSP-16.0.0_r4/prebuilts/sdk-r4/tools/darwin/bin/aapt2",
             "apksigner": source / "AOSP-16.0.0_r4/prebuilts/sdk-r4/tools/darwin/lib/apksigner.jar",
             "java": Path("/Applications/DevEco-Studio.app/Contents/jbr/Contents/Home/bin/java")}
    for name, path in tools.items():
        need(sha(path) == TOOLS[name], "tool SHA drift: " + name)
    result["registry"] = {"path": str(regpath), "sha256": REGISTRY_SHA,
                          "record_id": RECORD_ID, "artifact_sha256": APK_SHA,
                          "artifact_bytes": APK_SIZE}
    result["tools_before"] = {name: TOOLS[name] for name in tools}
    child_env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC", "TMPDIR": str(HERE)}
    # This project uses the inherited network route, but never passes NANHAI or auth secrets.
    for key in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "all_proxy", "no_proxy"):
        if key in os.environ:
            child_env[key] = os.environ[key]
    staging = Path(bindings["NANHAI_STAGING_ROOT"]) / "g284-elementx-github-raw-candidate-v2"
    need(not staging.exists(), "one-shot staging already exists; remote state unknown")
    staging.mkdir(parents=True, exist_ok=False)
    part = staging / "elementx-v26.09.1-arm64.apk.part"
    apk = staging / "elementx-v26.09.1-arm64.apk"
    result["staging"] = str(staging)
    curl = str(tools["curl"])
    api_cmd = [curl, "-q", "--fail", "--silent", "--show-error", "--max-time", "20", API]
    rec = run_command("api", api_cmd, 25, child_env); result["commands"].append(rec)
    need(rec["rc"] == 0 and not rec["timed_out"], "API request failed")
    release = json.loads((HERE / "api.stdout.raw").read_bytes())
    assets = [a for a in release.get("assets", []) if a.get("id") == ASSET_ID]
    need(release.get("tag_name") == "v26.09.1" and len(assets) == 1, "release identity drift")
    asset = assets[0]
    expected = {"id": ASSET_ID, "name": "app-fdroid-arm64-v8a-release-signed.apk",
                "size": APK_SIZE, "digest": "sha256:" + APK_SHA,
                "browser_download_url": URL}
    for key, value in expected.items():
        need(asset.get(key) == value, "release asset drift: " + key)
    result["api_asset"] = expected
    get_cmd = [curl, "-q", "--fail", "--location", "--proto", "=https", "--proto-redir", "=https",
               "--retry", "0", "--connect-timeout", "20", "--max-time", "300",
               "--silent", "--show-error", "--output", str(part), "--write-out",
               "http=%{http_code} tls=%{ssl_verify_result} bytes=%{size_download} redirects=%{num_redirects}", URL]
    rec = run_command("download", get_cmd, 310, child_env); result["commands"].append(rec)
    result["transfer"] = (HERE / "download.stdout.raw").read_text(errors="replace")
    if part.exists():
        result["part_bytes"] = part.stat().st_size
        result["part_sha256"] = sha(part)
    need(rec["rc"] == 0 and not rec["timed_out"], "first APK GET failed")
    need(result["transfer"].startswith("http=200 tls=0 "), "HTTP or TLS result mismatch")
    need(result.get("part_bytes") == APK_SIZE and result.get("part_sha256") == APK_SHA,
         "APK bytes or SHA mismatch")
    part.rename(apk)
    with zipfile.ZipFile(apk) as z:
        names = z.namelist()
        result["zip"] = {"entries": len(names), "bad_entry": z.testzip(),
                         "manifest_count": names.count("AndroidManifest.xml"),
                         "lib_abis": sorted({m.group(1) for n in names if
                                             (m := re.match(r"lib/([^/]+)/[^/]+\.so$", n))})}
    need(result["zip"]["bad_entry"] is None and result["zip"]["manifest_count"] == 1,
         "ZIP CRC or manifest invalid")
    for name, argv in [
        ("badging", [str(tools["aapt2"]), "dump", "badging", str(apk)]),
        ("signature", [str(tools["java"]), "-XX:-UsePerfData", "-Xmx512m", "-Djava.awt.headless=true",
                       "-Djava.io.tmpdir=" + str(HERE), "-jar", str(tools["apksigner"]),
                       "verify", "--verbose", "--print-certs", str(apk)])]:
        rec = run_command(name, argv, 120, child_env); result["commands"].append(rec)
        need(rec["rc"] == 0 and not rec["timed_out"], name + " tool failed")
    badging = (HERE / "badging.stdout.raw").read_text(errors="replace")
    signature = (HERE / "signature.stdout.raw").read_text(errors="replace")
    result["package_line"] = next((x for x in badging.splitlines() if x.startswith("package: ")), None)
    result["native_code_line"] = next((x for x in badging.splitlines() if x.startswith("native-code: ")), None)
    result["signature_lines"] = [x for x in signature.splitlines() if x.startswith(("Verified using", "Number of signers:", "Signer #"))]
    need("name='io.element.android.x'" in (result["package_line"] or "")
         and "versionCode='202609012'" in (result["package_line"] or "")
         and "versionName='26.09.1'" in (result["package_line"] or ""), "manifest identity mismatch")
    need(result["zip"]["lib_abis"] == ["arm64-v8a"]
         and "arm64-v8a" in (result["native_code_line"] or ""), "ABI mismatch")
    need("Number of signers: 1" in signature
         and "Verified using v2 scheme (APK Signature Scheme v2): true" in signature,
         "APK signature mismatch")
    result["tools_after"] = {name: sha(path) for name, path in tools.items()}
    need(result["tools_after"] == result["tools_before"], "tool postguard drift")
    result["apk_sha256_after"] = sha(apk)
    need(result["apk_sha256_after"] == APK_SHA, "APK postguard drift")

def main():
    if sys.argv[1:] != ["--execute"]:
        raise SystemExit("PREPARED_ONLY: explicit --execute required")
    start = {"schema": "g284-elementx-github-raw-v2-start", "at_utc": utc(),
             "status": "REMOTE_STATE_UNKNOWN_IN_PROGRESS", "generation": "g284-elementx-github-raw-candidate-v2",
             "script_sha256": sha(__file__), "url": URL, "asset_id": ASSET_ID,
             "expected_artifact_sha256": APK_SHA, "expected_artifact_bytes": APK_SIZE,
             "meaning": "If RESULT.json is absent, inspect this execution; never blindly replay."}
    durable_exclusive_json(HERE / "START.json", start)
    result = {"schema": "g284-elementx-github-raw-v2-result", "start_sha256": sha(HERE / "START.json"),
              "generation": start["generation"], "commands": [], "candidate_only": True,
              "raw_accepted": False, "canonical_delta": 0, "device_commands": 0,
              "container_commands": 0, "prior_failed_part_reused": False}
    old_term = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(GateError("SIGTERM interrupted")))
    try:
        execute(result)
        result["status"] = "RAW_CANDIDATE_STATIC_PASS"
    except BaseException as e:
        result["status"] = "TERMINAL_FAILED"
        result["error_type"] = type(e).__name__
        result["error"] = str(e)[:500]
    finally:
        signal.signal(signal.SIGTERM, old_term)
        result["ended_utc"] = utc()
        durable_final(HERE / "RESULT.json", result)
    print(json.dumps({"status": result["status"], "result": str(HERE / "RESULT.json")}))

if __name__ == "__main__":
    main()
