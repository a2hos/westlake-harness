#!/usr/bin/env python3
"""One-at-a-time exact registered next-four-c APK intake and host scan."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import traceback
import zipfile

ROOT = Path(os.environ["NANHAI_PROJECT_ROOT"])
HERE = Path(__file__).resolve().parent
AUDIT = HERE.parent / "peer-upstream-artifact-gap-audit-v1"
REGISTRY = HERE.parent / "upstream-apk-registry-v1/REGISTRY.json"
AUDIT_EXPECTED = "77c0fffc751389d41575a3278201b4b46c5a420db3c6c32e72ad6bc4a3ead8a1"
INPUTS_EXPECTED = "9d776d88c7d54db7c030ceecc7a7e451f79d009bd6ed18fa9888588c616aebc4"
SELECTION_EXPECTED = "5e30132e37a4fb2a52c678c33fda752ce475a9ff63f01b02e0fdc62063b1d46f"
REFERENCE_VERIFY = HERE.parent / "peer-snapchat-official-raw-v1/VERIFY.json"
PACKAGES = ("com.best.deskclock", "com.justdeax.composeStopwatch", "com.k.todo", "app.siftrecipes")

def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def write(path, obj):
    with path.open("x") as f:
        json.dump(obj, f, sort_keys=True, indent=2, ensure_ascii=False)
        f.write("\n")

def encode(value):
    if isinstance(value, (set, frozenset)):
        return sorted((encode(x) for x in value), key=str)
    if isinstance(value, dict):
        return {str(k): encode(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [encode(x) for x in value]
    if hasattr(value, "__dict__"):
        return encode(vars(value))
    return value

def capture(argv, prefix, cwd=None, env=None, timeout=300):
    stdout = prefix.with_suffix(".stdout.raw")
    stderr = prefix.with_suffix(".stderr.raw")
    with stdout.open("xb") as out, stderr.open("xb") as err:
        p = subprocess.run(argv, stdout=out, stderr=err, cwd=cwd, env=env, timeout=timeout)
    return {"argv": [str(a) for a in argv], "rc": p.returncode, "stdout_sha256": sha(stdout), "stderr_sha256": sha(stderr), "stdout_bytes": stdout.stat().st_size, "stderr_bytes": stderr.stat().st_size}

def main():
    if len(sys.argv) != 2 or sys.argv[1] not in PACKAGES:
        print("usage: intake.py <one exact selected package>", file=sys.stderr)
        return 2
    package = sys.argv[1]
    venv = Path(os.environ["NANHAI_RUNTIME_ROOT"]) / "venvs/harness-python-v1/bin/python3"
    if Path(sys.prefix).resolve() != venv.parent.parent.resolve():
        assert venv.is_file()
        os.execv(str(venv), [str(venv), "-B", str(Path(__file__).resolve()), package])
    assert sha(AUDIT / "RESULT.json") == AUDIT_EXPECTED
    assert sha(AUDIT / "INPUTS.json") == INPUTS_EXPECTED
    assert sha(HERE / "SELECTION.json") == SELECTION_EXPECTED
    audit = json.loads((AUDIT / "RESULT.json").read_text())
    inputs = json.loads((AUDIT / "INPUTS.json").read_text())
    selection = json.loads((HERE / "SELECTION.json").read_text())
    assert sha(REGISTRY) == inputs["registry"]["sha256"] == audit["registry_sha256"]
    row = next(x for x in audit["missing_exact_upstream"] if x["package"] == package and x["priority"] == "P2_REGISTERED_FDROID_URL_ABI_UNDECLARED")
    artifact = next(x for x in json.loads(REGISTRY.read_text())["artifacts"] if x["id"] == row["id"])
    assert artifact["sha256"] == row["sha256"] and artifact["source_urls"] == row["source_urls_registered_not_revalidated"] and len(artifact["source_urls"]) == 1
    selected = next(x for x in selection["rows"] if x["package"] == package)
    assert selected == {"artifact_id": artifact["id"], "package": package, "expected_sha256": artifact["sha256"], "version_name": artifact["versions"][0], "version_code": artifact["version_codes"][0], "source_url": artifact["source_urls"][0]}
    out = HERE / package
    stage = Path(os.environ["NANHAI_STAGING_ROOT"]) / "peer-upstream-next4d-exact-v1" / package
    temp = Path(os.environ["NANHAI_TMP_ROOT"]) / "peer-upstream-next4d-exact-v1" / package
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    stage.mkdir(mode=0o700, parents=True, exist_ok=False)
    temp.mkdir(mode=0o700, parents=True, exist_ok=False)
    part = stage / "original.apk.part"
    apk = stage / "original.apk"
    raw = {"schema": "peer-upstream-next4d-exact-raw-v1", "artifact_id": row["id"], "package_expected": package, "version_expected": artifact["versions"], "version_code_expected": artifact["version_codes"], "source_url_registered": artifact["source_urls"][0], "expected_sha256": artifact["sha256"], "registry_sha256": sha(REGISTRY), "audit_result_sha256": sha(AUDIT / "RESULT.json"), "input_sha256": sha(AUDIT / "INPUTS.json"), "selection_sha256": sha(HERE / "SELECTION.json"), "device_commands": 0, "container_commands": 0, "startup_proven": False, "authoritative_count_changed": False}
    started = time.monotonic()
    argv = [os.environ["NANHAI_CURL"], "--fail", "--location", "--retry", "0", "--connect-timeout", "15", "--max-time", "300", "--output", str(part), "--dump-header", str(out / "GET.headers.raw"), artifact["source_urls"][0]]
    try:
        raw["get"] = capture(argv, out / "GET", timeout=330)
        raw["get_elapsed_seconds"] = round(time.monotonic() - started, 3)
        if raw["get"]["rc"] != 0 or not part.is_file():
            raw["decision"] = "NO_GO_GET_FAILED"
            write(out / "RAW.json", raw)
            return 2
        raw["bytes"] = part.stat().st_size
        raw["actual_sha256"] = sha(part)
        raw["sha_matches_registry"] = raw["actual_sha256"] == artifact["sha256"]
        if not raw["sha_matches_registry"]:
            raw["decision"] = "NO_GO_SHA_MISMATCH_STOP_THIS_ARTIFACT"
            write(out / "RAW.json", raw)
            return 2
        part.rename(apk)
        with zipfile.ZipFile(apk) as z:
            names = z.namelist()
            raw["zip_entries"] = len(names)
            raw["zip_first_bad"] = z.testzip()
            raw["zip_duplicate_names"] = len(names) - len(set(names))
            raw["manifest_count"] = names.count("AndroidManifest.xml")
            raw["root_dex_count"] = len([n for n in names if re.fullmatch(r"classes(?:[0-9]+)?\.dex", n)])
            raw["native_abis"] = sorted({n.split("/")[1] for n in names if n.startswith("lib/") and n.endswith(".so") and len(n.split("/")) >= 3})
            raw["arm64_so_count"] = len([n for n in names if n.startswith("lib/arm64-v8a/") and n.endswith(".so")])
            raw["arm64_abi_compatible"] = not raw["native_abis"] or "arm64-v8a" in raw["native_abis"]
        verify = json.loads(REFERENCE_VERIFY.read_text())
        aapt2 = Path(verify["aapt2"]["argv"][0])
        apksigner = Path(verify["apksigner"]["argv"][0])
        assert aapt2.is_file() and apksigner.is_file()
        raw["aapt2_tool_sha256"] = sha(aapt2)
        raw["apksigner_tool_sha256"] = sha(apksigner)
        raw["aapt2"] = capture([aapt2, "dump", "badging", apk], out / "aapt2", timeout=120)
        raw["apksigner"] = capture([apksigner, "verify", "--verbose", "--print-certs", apk], out / "apksigner", timeout=120)
        badging = (out / "aapt2.stdout.raw").read_text(errors="replace")
        raw["package_version_match"] = bool(re.search(r"package: name='" + re.escape(package) + r"' versionCode='" + re.escape(str(artifact["version_codes"][0])) + r"' versionName='" + re.escape(artifact["versions"][0]) + r"'", badging))
        raw["decision"] = "GO_EXACT_REGISTERED_RAW_CANDIDATE" if raw["zip_first_bad"] is None and raw["zip_duplicate_names"] == 0 and raw["manifest_count"] == 1 and raw["arm64_abi_compatible"] and raw["aapt2"]["rc"] == raw["apksigner"]["rc"] == 0 and raw["package_version_match"] else "NO_GO_RAW_VALIDATION"
        write(out / "RAW.json", raw)
        if not raw["decision"].startswith("GO_"):
            return 2
        sys.path.insert(0, str(ROOT / "harness"))
        from westlake_gap import scanner
        readelf = Path(os.environ["NANHAI_INPUTS_ROOT"]) / "harness-native-hosttool-v1/bin/readelf"
        assert readelf.exists()
        os.environ["PATH"] = str(readelf.parent) + os.pathsep + os.environ.get("PATH", "")
        os.environ["TMPDIR"] = str(temp)
        phases = {}
        for phase in ("zip", "metadata", "dex", "elf"):
            tick = time.monotonic()
            item = {"phase": phase, "apk_sha_before": sha(apk), "scanner_sha256": sha(ROOT / "harness/westlake_gap/scanner.py"), "readelf_sha256": sha(readelf), "device_commands": 0, "container_commands": 0}
            try:
                if phase == "zip":
                    with zipfile.ZipFile(apk) as z:
                        n = z.namelist()
                        item.update(entries=len(n), duplicate_names=len(n)-len(set(n)), crc_first_bad=z.testzip(), manifest_count=n.count("AndroidManifest.xml"), root_dex_count=len([v for v in n if re.fullmatch(r"classes(?:[0-9]+)?\.dex", v)]), arm64_so_count=len([v for v in n if v.startswith("lib/arm64-v8a/") and v.endswith(".so")]))
                    assert item["duplicate_names"] == 0 and item["crc_first_bad"] is None and item["manifest_count"] == 1
                elif phase == "metadata":
                    value = scanner.apk_metadata(apk)
                    write(out / "MANIFEST.json", encode(value))
                    item.update(package=value.get("package"), version_name=value.get("version_name"), version_code=str(value.get("version_code")), target_sdk=str(value.get("target_sdk")), manifest_available=value.get("manifest_available"))
                    assert item["package"] == package and item["version_name"] == artifact["versions"][0] and item["version_code"] == str(artifact["version_codes"][0])
                elif phase == "dex":
                    value = scanner.inventory_dex(apk)
                    write(out / "DEX-INVENTORY.json", encode(value))
                    item["dex_entries"] = len(value.dex_entries)
                    item["dex_names"] = [v["name"] for v in value.dex_entries]
                    assert item["dex_entries"] == raw["root_dex_count"]
                else:
                    with zipfile.ZipFile(apk) as z:
                        records = [scanner.read_elf(data=z.read(n), label=n, abi="arm64-v8a") for n in z.namelist() if n.startswith("lib/arm64-v8a/") and n.endswith(".so")]
                    write(out / "ELF-INVENTORY.json", encode(records))
                    item["arm64_elf_entries"] = len(records)
                    item["readelf_ok"] = sum(v.get("readelf_ok") is True for v in records)
                    item["abi_matches_machine"] = sum(v.get("abi_matches_machine") is True for v in records)
                    assert item["arm64_elf_entries"] == item["readelf_ok"] == item["abi_matches_machine"] == raw["arm64_so_count"]
                item["rc"] = 0
            except BaseException as e:
                item.update(rc=2, error=repr(e), traceback=traceback.format_exc())
            item["elapsed_seconds"] = round(time.monotonic()-tick, 3)
            item["apk_sha_after"] = sha(apk)
            item["input_guard_equal"] = item["apk_sha_before"] == item["apk_sha_after"] == artifact["sha256"]
            phases[phase] = item
            write(out / (phase.upper() + "-RESULT.json"), item)
            if item["rc"] != 0 or not item["input_guard_equal"]:
                break
        static = {"schema": "peer-upstream-next4d-exact-four-static-v1", "artifact_id": artifact["id"], "package": package, "apk_sha256": artifact["sha256"], "raw_sha256": sha(out / "RAW.json"), "phases": phases, "four_phase_rc0": len(phases) == 4 and all(v["rc"] == 0 and v["input_guard_equal"] for v in phases.values()), "startup_proven": False, "authoritative_count_changed": False, "device_commands": 0, "container_commands": 0}
        static["decision"] = "GO_COMPLETE_HOST_STATIC_CANDIDATE" if static["four_phase_rc0"] else "NO_GO_STATIC"
        write(out / "STATIC.json", static)
        print(json.dumps({"package": package, "raw_decision": raw["decision"], "static_decision": static["decision"], "phase_rc": {k:v["rc"] for k,v in phases.items()}}, sort_keys=True))
        return 0 if static["four_phase_rc0"] else 2
    except BaseException as e:
        raw.update(decision="NO_GO_EXCEPTION", error=repr(e), traceback=traceback.format_exc())
        if not (out / "RAW.json").exists():
            write(out / "RAW.json", raw)
        print(repr(e), file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
