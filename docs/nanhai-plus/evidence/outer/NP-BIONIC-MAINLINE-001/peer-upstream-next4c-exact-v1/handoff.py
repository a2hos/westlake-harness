#!/usr/bin/env python3
"""Deterministic cross-check and candidate handoff for four selected exact APKs."""
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import zipfile

HERE = Path(__file__).resolve().parent
AUDIT = HERE.parent / "peer-upstream-artifact-gap-audit-v1/RESULT.json"
PACKAGES = ("com.afkanerd.deku", "de.circle_dev.flux_news", "io.pcontacts.app", "de.marmaro.krt.ffupdater")

def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def js(path):
    return json.loads(path.read_text())

assert sha(AUDIT) == "77c0fffc751389d41575a3278201b4b46c5a420db3c6c32e72ad6bc4a3ead8a1"
audit = js(AUDIT)
assert sha(HERE / "SELECTION.json") == "dd3eba59555e6cd71b3c112ab3952e2f350c5089673deea2d83a7c70ef5e373a"
selection = js(HERE / "SELECTION.json")
rows = []
for package in PACKAGES:
    p = HERE / package
    a = next(x for x in audit["missing_exact_upstream"] if x["package"] == package and x["priority"] == "P2_REGISTERED_FDROID_URL_ABI_UNDECLARED")
    selected = next(x for x in selection["rows"] if x["package"] == package)
    assert selected["artifact_id"] == a["id"] and selected["expected_sha256"] == a["sha256"] and selected["source_url"] == a["source_urls_registered_not_revalidated"][0]
    raw = js(p / "RAW.json")
    static = js(p / "STATIC.json")
    apk = Path(os.environ["NANHAI_STAGING_ROOT"]) / "peer-upstream-next4c-exact-v1" / package / "original.apk"
    temp = Path(os.environ["NANHAI_TMP_ROOT"]) / "peer-upstream-next4c-exact-v1" / package
    files = {n: {"sha256": sha(p/n), "bytes": (p/n).stat().st_size} for n in ("RAW.json", "STATIC.json", "GET.headers.raw", "GET.stdout.raw", "GET.stderr.raw", "aapt2.stdout.raw", "aapt2.stderr.raw", "apksigner.stdout.raw", "apksigner.stderr.raw", "ZIP-RESULT.json", "METADATA-RESULT.json", "DEX-RESULT.json", "ELF-RESULT.json", "MANIFEST.json", "DEX-INVENTORY.json", "ELF-INVENTORY.json")}
    headers = (p / "GET.headers.raw").read_text(errors="replace").lower()
    signer_text = (p / "apksigner.stdout.raw").read_text(errors="replace")
    signer = re.findall(r"Signer #1 certificate SHA-256 digest: ([0-9a-fA-F]{64})", signer_text)
    with zipfile.ZipFile(apk) as z:
        all_dex = [n for n in z.namelist() if n.endswith(".dex")]
        root_dex = [n for n in all_dex if re.fullmatch(r"classes(?:[0-9]+)?\.dex", n)]
    check = {
        "exact_apk_sha": sha(apk) == a["sha256"] == raw["actual_sha256"] == static["apk_sha256"],
        "artifact_id": a["id"] == raw["artifact_id"] == static["artifact_id"],
        "get_http_200_apk_mime": "http/2 200" in headers and "content-type: application/vnd.android.package-archive" in headers,
        "raw_validation": raw["decision"] == "GO_EXACT_REGISTERED_RAW_CANDIDATE" and raw["get"]["rc"] == raw["aapt2"]["rc"] == raw["apksigner"]["rc"] == 0 and raw["zip_first_bad"] is None and raw["zip_duplicate_names"] == 0 and raw["manifest_count"] == 1 and raw["package_version_match"] and raw["arm64_abi_compatible"] and (raw["arm64_so_count"] > 0 or raw["native_abis"] == []),
        "tool_stdout_stderr_hashes": all(raw[t][stream+"_sha256"] == files[t+"."+stream+".raw"]["sha256"] for t in ("GET", "aapt2", "apksigner") if t in raw for stream in ("stdout", "stderr")) and all(raw[t.lower()][stream+"_sha256"] == files[t+"."+stream+".raw"]["sha256"] for t in ("aapt2", "apksigner") for stream in ("stdout", "stderr")),
        "four_phase_rc_guards": static["decision"] == "GO_COMPLETE_HOST_STATIC_CANDIDATE" and static["four_phase_rc0"] and set(static["phases"]) == {"zip", "metadata", "dex", "elf"} and all(v["rc"] == 0 and v["input_guard_equal"] for v in static["phases"].values()),
        "dex_scope_complete": len(all_dex) == len(root_dex) == raw["root_dex_count"] == static["phases"]["dex"]["dex_entries"],
        "private_tmp_empty": temp.is_dir() and not any(temp.iterdir()),
        "signer_found": len(signer) == 1,
    }
    rows.append({"package": package, "artifact_id": a["id"], "apk_sha256": a["sha256"], "apk_bytes": apk.stat().st_size, "source_url": a["source_urls_registered_not_revalidated"][0], "version_name": a["versions"][0], "version_code": a["version_codes"][0], "signer_cert_sha256": signer[0].lower() if signer else None, "root_dex": raw["root_dex_count"], "all_dex": len(all_dex), "embedded_dex": len(all_dex)-len(root_dex), "semantic_dex": static["phases"]["dex"]["dex_entries"], "arm64_lib_so": raw["arm64_so_count"], "true_arm64_elf": static["phases"]["elf"]["arm64_elf_entries"], "readelf_ok": static["phases"]["elf"]["readelf_ok"], "raw_decision": raw["decision"], "static_decision": static["decision"], "checks": check, "files": files})

out = {"schema": "peer-upstream-next4c-exact-four-handoff-v1", "input_audit_sha256": sha(AUDIT), "selection_sha256": sha(HERE / "SELECTION.json"), "raw_candidates": 4, "complete_host_static_candidates": 4, "root_admissions": 0, "cold_starts": 0, "device_commands": 0, "container_commands": 0, "rows": rows, "all_checks_pass": all(all(r["checks"].values()) for r in rows), "limits": ["F-Droid GET and exact registry SHA are observed; no independent F-Droid publisher signing-key pin is asserted.", "Four-phase static inventory is native host evidence, not install, Bionic runtime, Activity, display, network service, or cold-start proof.", "Raw and static are peer candidates only; authoritative counts remain unchanged until root admission."]}
print(json.dumps(out, sort_keys=True, indent=2))
sys.exit(0 if out["all_checks_pass"] else 2)
