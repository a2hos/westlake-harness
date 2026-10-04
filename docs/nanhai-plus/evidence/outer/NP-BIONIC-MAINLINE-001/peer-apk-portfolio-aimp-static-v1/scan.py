#!/usr/bin/env python3
"""Four native-host static phases for publisher-hashed AIMP stable APK."""
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import traceback
import zipfile

ROOT = Path(os.environ["NANHAI_PROJECT_ROOT"])
VENV = Path(os.environ['NANHAI_RUNTIME_ROOT']) / 'venvs/harness-python-v1'
VENV_RECEIPT = ROOT / 'docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/harness-python-runtime-v1/INSTALLED-VENV-MANIFEST.json'
if Path(json.loads(VENV_RECEIPT.read_text())['venv']) != VENV:
    raise ValueError('registered scanner Python environment differs from project runtime')
if Path(sys.prefix) != VENV:
    interpreter = VENV / 'bin/python3'
    if not interpreter.is_file():
        raise ValueError('registered scanner Python interpreter missing')
    os.execv(str(interpreter), [str(interpreter), '-B', *sys.argv])
HERE = Path(__file__).parent
APK = Path(os.environ["NANHAI_STAGING_ROOT"]) / "peer-apk-portfolio-aimp-official-v2/aimp_4.31.1747.apk"
EXPECTED = "2d70fb1cb519104826d825d2060289ad77fbd75b5b68c00ff93631ffafa06a46"

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

def main():
    if sys.argv[1:] != ["--execute"] or (HERE / "STATIC.json").exists():
        return 2
    raw = HERE.parent / "peer-apk-portfolio-aimp-official-v2"
    if sha(APK) != EXPECTED or not json.loads((raw / "VERIFY-V2.json").read_text())["candidate_pass"]:
        return 2
    sys.path.insert(0, str(ROOT / "harness"))
    from westlake_gap import scanner
    phases = {}
    readelf_path = ROOT / ".nanhai-plus-runtime/bionic-oh7-aosp16/inputs-view/harness-native-hosttool-v1/bin/readelf"
    if not readelf_path.is_symlink() or not readelf_path.exists():
        return 2
    os.environ["PATH"] = str(readelf_path.parent) + os.pathsep + os.environ.get("PATH", "")
    for phase in ("zip", "metadata", "dex", "elf"):
        started = time.monotonic()
        row = {"phase": phase, "apk_sha_before": sha(APK), "scanner_sha256": sha(ROOT / "harness/westlake_gap/scanner.py"),
               "readelf_sha256": sha(readelf_path), "network_commands": 0, "device_commands": 0, "container_commands": 0}
        try:
            if phase == "zip":
                with zipfile.ZipFile(APK) as z:
                    names = z.namelist()
                    row["entries"] = len(names)
                    row["duplicate_names"] = len(names) - len(set(names))
                    row["crc_bad"] = z.testzip()
                    row["manifest_count"] = names.count("AndroidManifest.xml")
                    row["root_dex"] = len([n for n in names if n.startswith("classes") and n.endswith(".dex") and "/" not in n])
                    row["so_count"] = len([n for n in names if n.startswith("lib/") and n.endswith(".so")])
                assert row["duplicate_names"] == 0 and row["crc_bad"] is None and row["manifest_count"] == 1
            elif phase == "metadata":
                value = scanner.apk_metadata(APK)
                write(HERE / "MANIFEST.json", encode(value))
                row.update(package=value.get("package"), version_name=value.get("version_name"),
                           version_code=str(value.get("version_code")), target_sdk=str(value.get("target_sdk")),
                           manifest_available=value.get("manifest_available"))
                assert row["package"] == "com.aimp.player" and row["version_name"] == "v4.31.1747 (10.09.2026)" and row["version_code"] == "1747"
            elif phase == "dex":
                value = scanner.inventory_dex(APK)
                write(HERE / "DEX-INVENTORY.json", encode(value))
                row["dex_entries"] = len(value.dex_entries)
                row["dex_names"] = [e["name"] for e in value.dex_entries]
                assert row["dex_entries"] >= 1
            else:
                records = []
                with zipfile.ZipFile(APK) as z:
                    for name in z.namelist():
                        if name.startswith("lib/arm64-v8a/") and name.endswith(".so"):
                            records.append(scanner.read_elf(data=z.read(name), label=name, abi="arm64-v8a"))
                write(HERE / "ELF-INVENTORY.json", encode(records))
                row["arm64_elf_entries"] = len(records)
                row["readelf_ok"] = sum(x.get("readelf_ok") is True for x in records)
                row["abi_matches_machine"] = sum(x.get("abi_matches_machine") is True for x in records)
                assert row["arm64_elf_entries"] == row["readelf_ok"] == row["abi_matches_machine"]
            row["rc"] = 0
        except BaseException as error:
            row.update(rc=2, error=repr(error), traceback=traceback.format_exc())
        row.update(apk_sha_after=sha(APK), elapsed_seconds=time.monotonic() - started)
        row["source_guard_equal"] = row["apk_sha_before"] == row["apk_sha_after"] == EXPECTED
        phases[phase] = row
        write(HERE / (phase.upper() + "-RESULT.json"), row)
        if row["rc"] != 0 or not row["source_guard_equal"]:
            break
    result = {"schema": "peer-apk-portfolio-aimp-static-v1", "package": "com.aimp.player",
              "apk_sha256": EXPECTED, "phases": phases, "four_phase_rc0": len(phases) == 4 and all(x["rc"] == 0 for x in phases.values()),
              "root_count_changed": False, "startup_proven": False, "device_commands": 0, "container_commands": 0}
    write(HERE / "STATIC.json", result)
    print(json.dumps({"four_phase_rc0": result["four_phase_rc0"], "phase_counts": {p: {k: v for k, v in x.items() if k in ("rc", "entries", "dex_entries", "arm64_elf_entries", "readelf_ok", "abi_matches_machine", "target_sdk", "elapsed_seconds")} for p, x in phases.items()}}, sort_keys=True))
    return 0 if result["four_phase_rc0"] else 2

if __name__ == "__main__":
    sys.exit(main())
