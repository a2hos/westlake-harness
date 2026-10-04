#!/usr/bin/env python3
"""Independent, offline review of two publisher APK candidates."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

root = Path(os.environ["NANHAI_PROJECT_ROOT"])
base = root / "docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001"
here = Path(__file__).resolve().parent
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
read = lambda p: json.loads(p.read_text())
expected = {
    "remote": ("com.teamviewer.teamviewer.market.mobile", "1582270", "15.82.270", "2428b81eb78e93ebacb0dde64fc1a5f382e2446db8521b8481b0d74ee4cdc935", "TeamViewer.apk", "100M+"),
    "host": ("com.teamviewer.host.market", "1582263", "15.82.263", "0372259d3a49ff007e62ca5f56f0145b8afedb2d7ff79224034e1025c3dc27bb", "TeamViewerHost.apk", "5M+"),
}
eula = base / "peer-teamviewer-qs-qualification-v1/EULA-SCOPE.json"
eula_data = read(eula)
assert sha(eula) == "5da5a8a4d601400f102de2d34f461ad14155eb5e25dfaa4fd2247ed364ef9e77"
rows = []
for kind, (package, code, version, digest, filename, scale) in expected.items():
    raw_dir = base / f"peer-teamviewer-{kind}-official-raw-v1"
    static_dir = base / f"peer-teamviewer-{kind}-four-static-v1"
    qual_dir = base / f"peer-teamviewer-{kind}-qualification-v1"
    raw, verify, static, qual = (read(raw_dir / "RESULT.json"), read(raw_dir / "VERIFY.json"), read(static_dir / "RESULT.json"), read(qual_dir / "QUALIFICATION.json"))
    apk = root / raw["apk_path"]
    page = (raw_dir / "publisher-page.raw").read_text(errors="replace")
    play = (qual_dir / "play.html").read_text(errors="replace")
    url = "https://download.teamviewer.com/download/" + filename
    get_headers = (raw_dir / "apk-get-headers.raw").read_text(errors="replace")
    with zipfile.ZipFile(apk) as z:
        names = z.namelist()
        bad = z.testzip()
        root_dex = [n for n in names if re.fullmatch(r"classes(?:[0-9]+)?\.dex", n)]
        all_dex = [n for n in names if n.endswith(".dex")]
        arm64 = [n for n in names if n.startswith("lib/arm64-v8a/") and n.endswith(".so")]
    tool_checks = {}
    tool_outputs = {}
    for tool in ("aapt2", "apksigner"):
        argv = verify[tool]["argv"]
        assert Path(argv[0]).is_file() and Path(argv[-1]) == apk
        proc = subprocess.run(argv, capture_output=True, timeout=90)
        for stream, data in (("stdout", proc.stdout), ("stderr", proc.stderr)):
            target = here / f"{kind}-{tool}.{stream}.v2.raw"
            if target.exists():
                assert target.read_bytes() == data
            else:
                with target.open("xb") as f:
                    f.write(data)
            tool_outputs[f"{tool}_{stream}_sha256"] = sha(target)
        tool_checks[tool + "_rc0"] = proc.returncode == 0
        if tool == "aapt2":
            badging = proc.stdout.decode(errors="replace")
            tool_checks["manifest_package_version"] = f"name='{package}' versionCode='{code}' versionName='{version}'" in badging
        else:
            signer = re.findall(r"Signer #1 certificate SHA-256 digest: ([0-9a-fA-F]{64})", proc.stdout.decode(errors="replace"))
            tool_checks["signature_cert"] = len(signer) == 1 and signer[0].lower() == verify["signer_cert_sha256"][0]
    checks = {
        "raw_and_apk_identity": sha(apk) == digest == raw["apk_sha256"] == verify["apk_sha256"] == static["apk_sha256"] and apk.stat().st_size == raw["apk_bytes"] == verify["apk_bytes"] == static["apk_bytes"],
        "publisher_product_exact_link": f'data-product="TeamViewer {"full client" if kind == "remote" else "Host"}"><a class="cmp-button" href="{url}"' in page,
        "publisher_get_receipts": raw["page"]["rc"] == raw["get"]["rc"] == raw["head"]["rc"] == 0 and raw["publisher_apk_url"] == qual["publisher_apk_url"] == url,
        "publisher_cdn_redirect": "location: https://dl.teamviewer.com/mobile/" + filename in get_headers,
        "get_final_200_expected_mime_or_octet": raw["apk_mime_seen"] and "HTTP/2 200" in get_headers and ("content-type: application/vnd.android.package-archive" in get_headers or "content-type: application/octet-stream" in get_headers),
        "zip_integrity": bad is None and len(names) == len(set(names)) and names.count("AndroidManifest.xml") == 1,
        "dex_complete": len(root_dex) == len(all_dex) == raw["root_dex_entries"] == static["phases"]["dex"]["semantic_dex_entries"],
        "arm64_true_elf": len(arm64) == raw["arm64_so_entries"] == static["phases"]["elf"]["elf_counts"]["true_arm64_elf"] == static["phases"]["elf"]["abi_matches_machine"] and static["phases"]["elf"]["elf_counts"]["arm64_path_arm32_elf"] == static["phases"]["elf"]["elf_counts"]["non_elf_so"] == 0,
        "four_phase_guard": static["all_four_phases_rc0"] and set(static["phases"]) == {"zip","metadata","dex","elf"} and all(v["rc"] == 0 and v["input_guard_equal"] and v["input_sha256_before"] == v["input_sha256_after"] and v["input_sha256_after"]["apk"] == digest for v in static["phases"].values()),
        "play_exact_package": f"id={package}&amp;hl=en_US" in play and qual["play_exact_package_seen"],
        "play_same_publisher": "TeamViewer Germany GmbH" in play and qual["play_publisher_seen"],
        "play_package_scale": f'>{scale}</div><div class="g1rdde">Downloads' in play and qual["play_100m_seen" if kind == "remote" else "play_5m_seen"],
        "bounded_source_scope": eula_data["mobile_application_scope_seen"] and eula_data["source_code_clause_seen"],
        **tool_checks,
    }
    rows.append({"kind":kind,"package":package,"version_code":code,"version_name":version,"apk_sha256":digest,"apk_bytes":apk.stat().st_size,"signer_cert_sha256":verify["signer_cert_sha256"][0],"source_url":url,"play_downloads_package_wide":scale,"root_dex":len(root_dex),"embedded_dex":len(all_dex)-len(root_dex),"true_arm64_elf":len(arm64),"checks":checks,"all_checks_pass":all(checks.values()),"tool_outputs":tool_outputs,"candidate_receipts":{label:{"sha256":sha(path),"bytes":path.stat().st_size} for label,path in (("raw",raw_dir/"RESULT.json"),("verify",raw_dir/"VERIFY.json"),("static",static_dir/"RESULT.json"),("qualification",qual_dir/"QUALIFICATION.json"),("publisher_page",raw_dir/"publisher-page.raw"),("play",qual_dir/"play.html"))}})

existing = []
for p in base.rglob("ROOT-RAW-ADMISSION.json"):
    if here in p.parents:
        continue
    x = read(p)
    if x.get("package") in {r["package"] for r in rows}:
        existing.append(str(p.relative_to(root)))
out = {"schema":"peer-teamviewer-remote-host-independent-review-v1","rows":rows,"eula_scope_sha256":sha(eula),"existing_root_raw_receipts":existing,"all_checks_pass":all(r["all_checks_pass"] for r in rows) and not existing,"decisions":{"remote":{"raw":"GO","static":"GO","blackbox_qualification":"GO_BOUNDED_100M_PACKAGE_WIDE"},"host":{"raw":"GO","static":"GO","blackbox_qualification":"GO_BOUNDED_5M_PACKAGE_WIDE"}},"limits":["Play downloads are package-wide, not exact APK version downloads; Host's 5M+ is weaker than Remote's 100M+ and is independently judged sufficient market reach without a numeric project threshold.","Publisher link plus APK signature support original acquisition, but no external publisher certificate pin is claimed.","EULA supports proprietary client scope, not global absence of source for every bundled component.","No install, Bionic runtime, Activity, display, or cold start is proved."],"device_commands":0,"container_commands":0,"bridge_commands":0,"authoritative_counts_changed":False}
print(json.dumps(out,sort_keys=True,indent=2))
sys.exit(0 if out["all_checks_pass"] else 2)
