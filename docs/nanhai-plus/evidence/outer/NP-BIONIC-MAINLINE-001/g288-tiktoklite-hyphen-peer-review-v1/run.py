#!/usr/bin/env python3
"""One-shot TikTok Lite official APK intake candidate. Never auto-retry or switch variants."""
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
PAGE = "https://www.tiktok.com/download"
APK = "https://sf16-va.tiktokcdn.com/obj/eden-va2/lapshyasbrvarpa_kpvykuh_jnb/ljhwZthlaukjlkulzlp/US/Lite/TikTok-Lite_360961.apk"
OTHER_LITE = "https://sf16-va.tiktokcdn.com/obj/eden-va2/lapshyasbrvarpa_kpvykuh_jnb/ljhwZthlaukjlkulzlp/US/Lite/TikTok_Lite_360961.apk"
APK_BYTES = 48413684
PAGE_MAX = 600000
PACKAGE = "com.zhiliaoapp.musically.go"
ENV_SHA = "5ce3a58541ef1711890aad8348c3a31a03203f584fa50f1f5c0cb4fd88b49718"
TOOLS_SHA = {
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

def exclusive_json(path, obj):
    data = (json.dumps(obj, ensure_ascii=False, indent=2) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    dfd = os.open(Path(path).parent, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)

def final_json(path, obj):
    path = Path(path)
    pending = path.with_name(path.name + ".pending." + str(os.getpid()))
    exclusive_json(pending, obj)
    try:
        os.link(pending, path)  # never replace an earlier terminal receipt
        dfd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        pending.unlink(missing_ok=True)

def command(name, argv, timeout, env):
    began, tick = utc(), time.monotonic()
    try:
        p = subprocess.run(argv, cwd=HERE, env=env, capture_output=True, timeout=timeout)
        rc, out, err, timed = p.returncode, p.stdout, p.stderr, False
    except subprocess.TimeoutExpired as e:
        rc, out, err, timed = None, e.stdout or b"", e.stderr or b"", True
    (HERE / (name + ".stdout.raw")).write_bytes(out)
    (HERE / (name + ".stderr.raw")).write_bytes(err)
    return {"name": name, "argv": argv, "began_utc": began, "ended_utc": utc(),
            "seconds": round(time.monotonic() - tick, 3), "rc": rc, "timed_out": timed,
            "stdout_bytes": len(out), "stdout_sha256": hashlib.sha256(out).hexdigest(),
            "stderr_bytes": len(err), "stderr_sha256": hashlib.sha256(err).hexdigest()}

def bindings_and_tools(result):
    project = HERE.parents[5]
    loader = project / "scripts/nanhai_plus_env.py"
    need(loader.is_file(), "environment loader missing")
    spec = importlib.util.spec_from_file_location("nanhai_plus_env", loader)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    bindings, audit = module.load_environment(project / "local_env.md")
    need(audit["config_sha256"] == ENV_SHA, "frozen local_env config drift")
    need(bindings["NANHAI_PROJECT_ROOT"] == str(project), "project binding drift")
    need(bindings["NANHAI_EVIDENCE_ROOT"] == str(HERE.parents[2]), "evidence binding drift")
    need(bindings["NANHAI_CONTAINER_POLICY"] == "forbidden", "container policy drift")
    for key, value in bindings.items():
        need(os.environ.get(key) == value, "inherited environment drift: " + key)
    source = Path(bindings["NANHAI_SOURCE_POOL_ROOT"])
    tools = {"curl": Path(bindings["NANHAI_CURL"]),
             "aapt2": source / "AOSP-16.0.0_r4/prebuilts/sdk-r4/tools/darwin/bin/aapt2",
             "apksigner": source / "AOSP-16.0.0_r4/prebuilts/sdk-r4/tools/darwin/lib/apksigner.jar",
             "java": Path("/Applications/DevEco-Studio.app/Contents/jbr/Contents/Home/bin/java")}
    for name, path in tools.items():
        need(sha(path) == TOOLS_SHA[name], "tool SHA drift: " + name)
    result["environment"] = {"config_sha256": audit["config_sha256"],
                             "document": audit["document"], "links_checked": audit["links_checked"]}
    result["tools_before"] = dict(TOOLS_SHA)
    return bindings, tools

def parse_transfer(name):
    s = (HERE / (name + ".stdout.raw")).read_text(errors="replace")
    fields = dict(re.findall(r"(http|tls|bytes|redirects)=([^\s]+)", s))
    need(set(fields) == {"http", "tls", "bytes", "redirects"}, name + " transfer fields invalid")
    return fields

def official_apk_urls(raw):
    html = raw.decode("utf-8", errors="replace").replace("\\u002F", "/").replace("\\/", "/")
    return set(re.findall(r"https://[^\s\"'<>]+?\.apk", html))

def official_lite_card(raw):
    html = raw.decode("utf-8", errors="strict")
    marker = '"download_page_apk":{"apps":['
    need(1 <= html.count(marker) <= 3, "official app card missing or multiplicity drift")
    decoder = json.JSONDecoder()
    cards = [decoder.raw_decode(chunk)[0] for chunk in html.split(marker)[1:]]
    need(all(card == cards[0] for card in cards), "official app card copies disagree")
    card = cards[0]
    need(isinstance(card, dict) and card.get("type") == "lite", "first app card is not Lite")
    need(card.get("link") == APK and card.get("version") == "36.9.61",
         "official Lite card URL/version drift")
    return {"type": card["type"], "link": card["link"], "version": card["version"],
            "size_label": card.get("size"), "title": card.get("content", {}).get("appTitle")}

def head_identity(raw):
    headers = raw.decode("latin1")
    lengths = re.findall(r"(?im)^content-length:\s*(\d+)\s*$", headers)
    types = re.findall(r"(?im)^content-type:\s*([^\r\n]+)", headers)
    need(len(lengths) == 1 and len(types) == 1, "CDN HEAD header multiplicity drift")
    return int(lengths[0]), types[0].strip().lower()

def execute(result):
    bindings, tools = bindings_and_tools(result)
    stage = Path(bindings["NANHAI_STAGING_ROOT"]) / "g288-tiktoklite-hyphen-official-raw-candidate-v1"
    need(not stage.exists(), "one-shot staging already exists; state unknown")
    stage.mkdir(parents=True, exist_ok=False)
    result["staging"] = str(stage)
    page_body = HERE / "page.body.raw"
    head_body = HERE / "head.headers.raw"
    part = stage / "tiktok-lite-hyphen-360961.apk.part"
    apk = stage / "tiktok-lite-hyphen-360961.apk"
    child_env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC", "TMPDIR": str(stage)}
    for key in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "all_proxy", "no_proxy"):
        if key in os.environ:
            child_env[key] = os.environ[key]
    curl = str(tools["curl"])
    base = [curl, "-q", "--fail", "--silent", "--show-error", "--proto", "=https", "--proto-redir", "=https",
            "--retry", "0", "--connect-timeout", "15"]
    page_cmd = base + ["--max-time", "25", "--max-filesize", str(PAGE_MAX),
                       "--output", str(page_body), "--write-out",
                       "http=%{http_code} tls=%{ssl_verify_result} bytes=%{size_download} redirects=%{num_redirects}", PAGE]
    rec = command("page", page_cmd, 30, child_env); result["commands"].append(rec)
    need(rec["rc"] == 0 and not rec["timed_out"], "official page request failed")
    transfer = parse_transfer("page"); result["page_transfer"] = transfer
    need(transfer["http"] == "200" and transfer["tls"] == "0" and transfer["redirects"] == "0",
         "official page HTTP/TLS/redirect failed")
    need(page_body.is_file() and page_body.stat().st_size <= PAGE_MAX, "official page byte cap")
    result["page"] = {"bytes": page_body.stat().st_size, "sha256": sha(page_body)}
    urls = official_apk_urls(page_body.read_bytes())
    need(APK in urls, "exact official APK URL absent from live page")
    result["official_lite_card"] = official_lite_card(page_body.read_bytes())
    result["official_page_exact_apk_link"] = APK
    result["other_lite_variant_present"] = OTHER_LITE in urls
    head_cmd = base + ["--head", "--max-time", "20", "--dump-header", str(head_body),
                       "--output", "/dev/null", "--write-out",
                       "http=%{http_code} tls=%{ssl_verify_result} bytes=%{size_download} redirects=%{num_redirects}", APK]
    rec = command("head", head_cmd, 25, child_env); result["commands"].append(rec)
    need(rec["rc"] == 0 and not rec["timed_out"], "official CDN HEAD failed")
    transfer = parse_transfer("head"); result["head_transfer"] = transfer
    need(transfer["http"] == "200" and transfer["tls"] == "0" and transfer["redirects"] == "0",
         "CDN HEAD HTTP/TLS/redirect mismatch")
    head_length, head_type = head_identity(head_body.read_bytes())
    need(head_length == APK_BYTES, "CDN HEAD content length drift")
    need(head_type == "application/vnd.android.package-archive", "CDN HEAD content type drift")
    result["head"] = {"bytes": head_body.stat().st_size, "sha256": sha(head_body),
                      "content_length": head_length, "content_type": head_type}
    # The only APK GET in this generation. No resume and no alternative URL.
    get_cmd = base + ["--max-time", "180", "--max-filesize", str(APK_BYTES),
                      "--output", str(part), "--write-out",
                      "http=%{http_code} tls=%{ssl_verify_result} bytes=%{size_download} redirects=%{num_redirects}", APK]
    rec = command("download", get_cmd, 190, child_env); result["commands"].append(rec)
    if part.exists():
        result["part"] = {"bytes": part.stat().st_size, "sha256": sha(part)}
    need(rec["rc"] == 0 and not rec["timed_out"], "first APK GET failed; no retry")
    transfer = parse_transfer("download"); result["download_transfer"] = transfer
    need(transfer["http"] == "200" and transfer["tls"] == "0" and transfer["redirects"] == "0",
         "APK HTTP/TLS/redirect mismatch")
    need(part.stat().st_size == APK_BYTES and int(transfer["bytes"]) == APK_BYTES,
         "APK byte count mismatch")
    part.rename(apk)
    result["apk"] = {"path": str(apk), "bytes": apk.stat().st_size,
                     "sha256": sha(apk), "publisher_sha256_available": False,
                     "sha256_role": "observed received bytes only; no publisher digest comparison"}
    with zipfile.ZipFile(apk) as z:
        names = z.namelist()
        result["zip"] = {"entries": len(names), "bad_entry": z.testzip(),
                         "manifest_count": names.count("AndroidManifest.xml"),
                         "lib_abis": sorted({m.group(1) for n in names if
                                             (m := re.match(r"lib/([^/]+)/[^/]+\.so$", n))})}
    need(result["zip"]["bad_entry"] is None and result["zip"]["manifest_count"] == 1,
         "ZIP CRC/manifest failed")
    for name, argv in [
        ("badging", [str(tools["aapt2"]), "dump", "badging", str(apk)]),
        ("signature", [str(tools["java"]), "-XX:-UsePerfData", "-Xmx512m", "-Djava.awt.headless=true",
                       "-Djava.io.tmpdir=" + str(stage), "-jar", str(tools["apksigner"]),
                       "verify", "--verbose", "--print-certs", str(apk)])]:
        rec = command(name, argv, 120, child_env); result["commands"].append(rec)
        need(rec["rc"] == 0 and not rec["timed_out"], name + " tool failed")
    badging = (HERE / "badging.stdout.raw").read_text(errors="replace")
    signature = (HERE / "signature.stdout.raw").read_text(errors="replace")
    pick = lambda prefix: next((x for x in badging.splitlines() if x.startswith(prefix)), None)
    result["manifest"] = {"package": pick("package: "), "min_sdk": pick("minSdkVersion:"),
                          "target_sdk": pick("targetSdkVersion:"), "native_code": pick("native-code: ")}
    result["signature"] = {"lines": [x for x in signature.splitlines() if
                                  x.startswith(("Verified using", "Number of signers:", "Signer #"))]}
    need("name='" + PACKAGE + "'" in (result["manifest"]["package"] or ""), "package mismatch")
    need(all(result["manifest"][k] for k in ("package", "min_sdk", "target_sdk")),
         "missing manifest version or SDK fields")
    need(re.search(r"versionCode='\d+'", result["manifest"]["package"]), "missing versionCode")
    need(re.search(r"versionName='[^']+'", result["manifest"]["package"]), "missing versionName")
    result["manifest_identity"] = {
        "package": PACKAGE,
        "version_code": re.search(r"versionCode='(\d+)'", result["manifest"]["package"]).group(1),
        "version_name": re.search(r"versionName='([^']+)'", result["manifest"]["package"]).group(1),
        "min_sdk": re.search(r"'([^']+)'", result["manifest"]["min_sdk"]).group(1),
        "target_sdk": re.search(r"'([^']+)'", result["manifest"]["target_sdk"]).group(1)}
    need(result["zip"]["lib_abis"] in ([], ["arm64-v8a"]), "non-arm64 native library")
    need("Number of signers: 1" in signature and
         ("Verified using v2 scheme (APK Signature Scheme v2): true" in signature or
          "Verified using v3 scheme (APK Signature Scheme v3): true" in signature),
         "APK signature scheme/signer failed")
    cert = re.search(r"(?im)^Signer #1 certificate SHA-256 digest:\s*([0-9a-f]{64})\s*$", signature)
    need(cert is not None, "signer certificate SHA-256 absent")
    result["signature"]["certificate_sha256"] = cert.group(1).lower()
    result["signature"]["publisher_certificate_anchor"] = None
    result["signature"]["meaning"] = "valid APK signature and observed cert; publisher attribution pending independent anchor"
    result["tools_after"] = {name: sha(path) for name, path in tools.items()}
    need(result["tools_after"] == result["tools_before"], "tool postguard drift")
    result["apk_sha256_after"] = sha(apk)
    need(result["apk_sha256_after"] == result["apk"]["sha256"], "APK postguard drift")

def main():
    if sys.argv[1:] != ["--execute"]:
        raise SystemExit("PREPARED_ONLY: explicit --execute required")
    start = {"schema": "g288-tiktoklite-hyphen-raw-v1-start", "at_utc": utc(),
             "status": "REMOTE_STATE_UNKNOWN_IN_PROGRESS", "generation": HERE.name,
             "script_sha256": sha(__file__), "page": PAGE, "exact_apk_url": APK,
             "expected_head_and_received_bytes": APK_BYTES,
             "meaning": "If RESULT is absent, inspect state; never blindly replay."}
    exclusive_json(HERE / "START.json", start)
    result = {"schema": "g288-tiktoklite-hyphen-raw-v1-result", "start_sha256": sha(HERE / "START.json"),
              "generation": HERE.name, "commands": [], "candidate_only": True,
              "raw_accepted": False, "blackbox_qualified": False, "overseas_mainstream_qualified": False,
              "source_availability_review": "PENDING_SEPARATE_REVIEW", "canonical_delta": 0,
              "device_commands": 0, "container_commands": 0, "publisher_artifact_digest": None,
              "alternative_lite_variant_used": False}
    old_term = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(GateError("SIGTERM interrupted")))
    try:
        execute(result)
        result["status"] = "OFFICIAL_CHANNEL_RAW_CANDIDATE_STATIC_PASS"
    except BaseException as e:
        result["status"] = "TERMINAL_FAILED"
        result["error_type"] = type(e).__name__
        result["error"] = str(e)[:500]
    finally:
        signal.signal(signal.SIGTERM, old_term)
        result["ended_utc"] = utc()
        final_json(HERE / "RESULT.json", result)
    print(json.dumps({"status": result["status"], "result": str(HERE / "RESULT.json")}))

if __name__ == "__main__":
    main()
