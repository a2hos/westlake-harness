#!/usr/bin/env python3
"""Read-only first-cold-start information ladder over frozen root receipts."""
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(os.environ["NANHAI_PROJECT_ROOT"])
HERE = Path(__file__).resolve().parent

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def read(ref):
    path = ROOT / ref["path"]
    assert path.is_file() and sha(path) == ref["sha256"], ref
    return json.loads(path.read_text())

def main():
    negative = sys.argv[1:] == ["--counterexample"]
    if sys.argv[1:] not in ([], ["--counterexample"]):
        return 2
    assert sha(HERE / "INPUTS.json") == "74cfff80960108ce0e1824c4e0cc8e09cd4ae06e85230b8904833e84ac040efd"
    inputs = json.loads((HERE / "INPUTS.json").read_text())
    rows = []
    for item in inputs["rows"]:
        raw_root, static_root, raw, static = (read(item[k]) for k in ("raw_root", "static_root", "raw", "static"))
        package = item["package"]
        digest = raw_root["apk_sha256"]
        assert package == raw_root["package"] == static_root["package"]
        assert digest == static_root["apk_sha256"] == raw["apk_sha256"] == static["apk_sha256"] if "apk_sha256" in raw else digest == static_root["apk_sha256"] == raw["actual_sha256"] == static["apk_sha256"]
        assert str(raw_root["decision"]).startswith("ACCEPT") and str(static_root["decision"]).startswith("ACCEPT")
        if package == "com.tencent.ig":
            elf = read(item["elf"])
            dex = read(item["dex"])
            arm64 = elf["elf_counts"]["true_arm64_elf"]
            dex_count = dex["semantic_dex_entries"]
            bytes_count = raw["apk_bytes"]
        else:
            arm64 = static["phases"]["elf"]["arm64_elf_entries"]
            dex_count = static["phases"]["dex"]["dex_entries"]
            bytes_count = raw["bytes"]
            assert static["four_phase_rc0"] and raw["decision"] == "GO_EXACT_REGISTERED_RAW_CANDIDATE"
        if negative and package == "com.stoutner.privacybrowser.standard":
            arm64 = 1
        rows.append({"package": package, "apk_sha256": digest, "apk_bytes": bytes_count, "packaged_true_arm64_elf": arm64, "semantic_dex": dex_count, "root_limited_raw_and_static": True})
    bypkg = {r["package"]: r for r in rows}
    first = bypkg["com.stoutner.privacybrowser.standard"]
    second = bypkg["io.pcontacts.app"]
    third = bypkg["org.fairscan.app"]
    hold = bypkg["com.tencent.ig"]
    checks = {
        "zero_packaged_native_sentinel": first["packaged_true_arm64_elf"] == 0 and first["semantic_dex"] == 1,
        "one_native_next_step": second["packaged_true_arm64_elf"] == 1 and second["semantic_dex"] == 1,
        "complexity_gradient": first["packaged_true_arm64_elf"] < second["packaged_true_arm64_elf"] < third["packaged_true_arm64_elf"] < hold["packaged_true_arm64_elf"],
        "heavy_blackbox_deferred": hold["apk_bytes"] > 10 * third["apk_bytes"] and hold["packaged_true_arm64_elf"] >= 40,
    }
    failed = [k for k,v in checks.items() if not v]
    out = {"schema":"evo61-coldstart-information-ladder-pilot-v1","case":"negative_mutated_zero_native_count" if negative else "frozen_positive","decision":"GO_CANDIDATE_ORDER_ONLY" if not failed else "NO_GO_ORDER_PREMISE","checks":checks,"failed":failed,"suggested_after_helloworld":[first["package"],second["package"],third["package"]],"defer_from_first_three":hold["package"],"rows":rows,"input_manifest_sha256":sha(HERE / "INPUTS.json"),"runtime_observations":0,"cold_start_delta":0,"device_commands":0,"container_commands":0,"production_changed":False}
    print(json.dumps(out,sort_keys=True,indent=2))
    return 0 if not failed else 2

if __name__ == "__main__":
    sys.exit(main())
