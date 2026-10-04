#!/usr/bin/env python3
"""Independent root admission for four exact upstream, host-static candidates."""
import hashlib
import json
import os
from pathlib import Path
import zipfile

root = Path(os.environ["NANHAI_PROJECT_ROOT"])
peer = Path(__file__).resolve().parent.parent
out = Path(__file__).resolve().parent
registry_path = peer.parent / "upstream-apk-registry-v1/REGISTRY.json"
checkpoint_path = root / "docs/nanhai-plus/checkpoints/20261004-raw135-static135-blackbox28-upstream95-evo61/CHECKPOINT.json"

def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def load(path):
    return json.loads(path.read_text())

selection = load(peer / "SELECTION.json")
handoff = load(peer / "HANDOFF.json")
guard = load(peer / "CURRENT-GUARD.json")
checkpoint = load(checkpoint_path)
registry = load(registry_path)
assert checkpoint["upstream_exact_raw_accepted"] == 95
assert checkpoint["raw_accepted"] == checkpoint["full_host_static_accepted"] == 135
assert sha(checkpoint_path) == selection["current_checkpoint_sha256"] == guard["checkpoint_sha256"]
assert sha(registry_path) == selection["registry_sha256"] == guard["registry_sha256"]
assert guard["all_pass"] and handoff["all_checks_pass"]
assert sha(peer / "HANDOFF.json") == sha(peer / "REPLAY.json")
assert len(selection["rows"]) == len(handoff["rows"]) == 4
assert len({r["package"] for r in selection["rows"]}) == 4
assert len({r["artifact_id"] for r in selection["rows"]}) == 4
artifacts = {x["id"]: x for x in registry["artifacts"]}

rows = []
for selected in selection["rows"]:
    package = selected["package"]
    artifact = artifacts[selected["artifact_id"]]
    candidate = next(x for x in handoff["rows"] if x["package"] == package)
    raw_path = peer / package / "RAW.json"
    static_path = peer / package / "STATIC.json"
    raw, static = load(raw_path), load(static_path)
    apk = Path(os.environ["NANHAI_STAGING_ROOT"]) / peer.name / package / "original.apk"
    assert apk.is_file() and sha(apk) == selected["expected_sha256"] == artifact["sha256"]
    assert selected["source_url"] in artifact["source_urls"]
    assert selected["version_code"] in artifact["version_codes"]
    assert selected["version_name"] in artifact["versions"]
    assert selected["expected_sha256"] == candidate["apk_sha256"] == raw["actual_sha256"] == static["apk_sha256"]
    assert sha(raw_path) == candidate["files"]["RAW.json"]["sha256"] == static["raw_sha256"]
    assert sha(static_path) == candidate["files"]["STATIC.json"]["sha256"]
    assert raw["package_version_match"] and raw["sha_matches_registry"]
    assert raw["aapt2"]["rc"] == raw["apksigner"]["rc"] == raw["get"]["rc"] == 0
    assert raw["decision"] == "GO_EXACT_REGISTERED_RAW_CANDIDATE"
    assert static["decision"] == "GO_COMPLETE_HOST_STATIC_CANDIDATE" and static["four_phase_rc0"]
    assert all(x["rc"] == 0 and x["input_guard_equal"] and x["apk_sha_before"] == x["apk_sha_after"] == selected["expected_sha256"] for x in static["phases"].values())
    assert set(static["phases"]) == {"zip", "metadata", "dex", "elf"}
    assert all(candidate["checks"].values())
    with zipfile.ZipFile(apk) as zf:
        names = zf.namelist()
        assert len(names) == len(set(names)) and zf.testzip() is None
        assert sum(name == "AndroidManifest.xml" for name in names) == 1
        dex_count = sum(name.endswith(".dex") for name in names)
        arm64_count = sum(name.startswith("lib/arm64-v8a/") and name.endswith(".so") for name in names)
        assert dex_count == candidate["semantic_dex"]
        assert arm64_count == candidate["true_arm64_elf"] == candidate["readelf_ok"]
    rows.append({"package": package, "artifact_id": artifact["id"], "apk_sha256": sha(apk), "apk_bytes": apk.stat().st_size,
                 "source_url": selected["source_url"], "version_name": selected["version_name"], "version_code": selected["version_code"],
                 "candidate_raw_sha256": sha(raw_path), "candidate_static_sha256": sha(static_path),
                 "semantic_dex_delta": dex_count, "true_arm64_elf_delta": arm64_count,
                 "decision": "ACCEPT_EXACT_RAW_AND_FOUR_PHASE_HOST_STATIC_ONLY"})

result = {"schema": "nanhai-root-next4d-exact-admission-v1", "base_checkpoint_sha256": sha(checkpoint_path),
          "registry_sha256": sha(registry_path), "handoff_sha256": sha(peer / "HANDOFF.json"),
          "guard_sha256": sha(peer / "CURRENT-GUARD.json"), "rows": rows,
          "raw_delta": len(rows), "full_static_delta": len(rows),
          "semantic_dex_delta": sum(x["semantic_dex_delta"] for x in rows),
          "true_arm64_elf_delta": sum(x["true_arm64_elf_delta"] for x in rows),
          "cold_start_delta": 0, "device_commands": 0, "container_commands": 0,
          "scope": "Exact registered original APK and four-phase native-host static only; no Bionic runtime or Activity proof"}
out.mkdir(exist_ok=True)
(out / "ROOT-ADMISSION.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
print(json.dumps({k: result[k] for k in ("raw_delta", "full_static_delta", "semantic_dex_delta", "true_arm64_elf_delta", "cold_start_delta")}))
