#!/usr/bin/env python3
"""Four native-host static phases for the exact official imo APK."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import time
import traceback
import zipfile

ROOT = Path(os.environ["NANHAI_PROJECT_ROOT"])
HERE = Path(__file__).parent
RAW = HERE.parent / "peer-pubgm-official-raw-v1"
APK = Path(os.environ["NANHAI_STAGING_ROOT"]) / "peer-pubgm-official-raw-v1/pubgm-official.apk"
SCANNER = ROOT / "harness/westlake_gap/scanner.py"
READELF = ROOT / ".nanhai-plus-runtime/bionic-oh7-aosp16/inputs-view/harness-native-hosttool-v1/bin/readelf"
EXPECTED = "9024ea4f6bf6cc3de55bbaee34a31cde8be661d5a8f2941ded99baebdeceda7c"
BYTES = 1274351207

def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()

def write(path, obj):
    with path.open("x") as f:
        json.dump(obj, f, sort_keys=True, indent=2, ensure_ascii=False)
        f.write("\n")

def encode(obj):
    if isinstance(obj, (set, frozenset)): return sorted((encode(x) for x in obj), key=str)
    if isinstance(obj, dict): return {str(k): encode(v) for k, v in obj.items()}
    if isinstance(obj, (tuple, list)): return [encode(x) for x in obj]
    if hasattr(obj, "__dict__"): return encode(vars(obj))
    return obj

def input_guard():
    values = {"apk": sha(APK), "raw_result": sha(RAW / "RESULT.json"), "raw_verify": sha(RAW / "VERIFY.json"), "scanner": sha(SCANNER), "readelf": sha(READELF)}
    assert APK.stat().st_size == BYTES and values["apk"] == EXPECTED
    assert json.loads((RAW / "VERIFY.json").read_text())["candidate_pass"]
    assert READELF.is_symlink() and READELF.exists()
    return values

def main():
    if sys.argv[1:] != ["--execute"] or (HERE / "RESULT.json").exists(): return 2
    private_tmp = Path(os.environ["NANHAI_TMP_ROOT"]) / "peer-pubgm-four-static-v1"
    private_tmp.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.environ["TMPDIR"] = str(private_tmp)
    os.environ["PATH"] = str(READELF.parent) + os.pathsep + os.environ.get("PATH", "")
    sys.path.insert(0, str(ROOT / "harness"))
    from westlake_gap import scanner
    phases = {}
    for phase in ("zip", "metadata", "dex", "elf"):
        started = time.monotonic()
        row = {"phase": phase, "rc": 2, "at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "argv": [sys.executable, str(Path(__file__)), "--execute"], "interpreter": sys.executable, "tmpdir": os.environ["TMPDIR"], "device_commands": 0, "container_commands": 0}
        before = None
        try:
            before = input_guard()
            row["input_sha256_before"] = before
            if phase == "zip":
                with zipfile.ZipFile(APK) as z:
                    names = z.namelist()
                    facts = {"entries": len(names), "duplicate_names": len(names) - len(set(names)), "crc_first_bad": z.testzip(), "manifest_count": names.count("AndroidManifest.xml"), "root_dex_names": [n for n in names if n.startswith("classes") and n.endswith(".dex") and "/" not in n], "all_dex_names": [n for n in names if n.endswith(".dex")], "so_names": [n for n in names if n.startswith("lib/") and n.endswith(".so")]}
                write(HERE / "ZIP-FACTS.json", facts)
                row["entries"] = facts["entries"]
                assert facts["duplicate_names"] == 0 and facts["crc_first_bad"] is None and facts["manifest_count"] == 1
            elif phase == "metadata":
                meta = scanner.apk_metadata(APK)
                write(HERE / "MANIFEST.json", encode(meta))
                row.update(package=meta.get("package"), version_name=meta.get("version_name"), version_code=str(meta.get("version_code")), target_sdk=str(meta.get("target_sdk")))
                assert meta.get("manifest_available") is True and row["package"] == "com.tencent.ig" and row["version_name"] == "4.6.0" and row["version_code"] == "21518" and meta.get("sha256") == EXPECTED
            elif phase == "dex":
                inv = scanner.inventory_dex(APK)
                write(HERE / "DEX-INVENTORY.json", encode(inv))
                row["semantic_dex_entries"] = len(inv.dex_entries)
                assert len(inv.dex_entries) > 0
            else:
                classes = {k: [] for k in ("true_arm64_elf", "arm64_path_arm32_elf", "other_arm32_elf", "other_elf", "non_elf_so")}
                records = []
                with zipfile.ZipFile(APK) as z:
                    for name in [n for n in z.namelist() if n.startswith("lib/") and n.endswith(".so")]:
                        data = z.read(name)
                        item = {"name": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                        abi = name.split("/")[1]
                        if not data.startswith(b"\x7fELF"):
                            key = "non_elf_so"
                            item["magic"] = data[:8].hex()
                        else:
                            assert len(data) >= 20 and data[5] in (1, 2)
                            bits, endian = data[4], data[5]
                            machine = struct.unpack("<H" if endian == 1 else ">H", data[18:20])[0]
                            item.update(elf_class=bits, endian=endian, machine=machine)
                            if bits == 2 and machine == 183 and abi == "arm64-v8a":
                                key = "true_arm64_elf"
                                record = scanner.read_elf(data=data, label=name, abi=abi)
                                record["archive_entry"] = name
                                records.append(record)
                            elif bits == 1 and machine == 40 and abi == "arm64-v8a": key = "arm64_path_arm32_elf"
                            elif bits == 1 and machine == 40: key = "other_arm32_elf"
                            else: key = "other_elf"
                        classes[key].append(item)
                write(HERE / "ELF-CLASSIFICATION.json", classes)
                write(HERE / "ELF-INVENTORY.json", encode(records))
                row["elf_counts"] = {k: len(v) for k, v in classes.items()}
                row["readelf_ok"] = sum(r.get("readelf_ok") is True for r in records)
                row["abi_matches_machine"] = sum(r.get("abi_matches_machine") is True for r in records)
                assert row["elf_counts"]["true_arm64_elf"] == row["readelf_ok"] == row["abi_matches_machine"]
            row["rc"] = 0
        except BaseException as e:
            row["error"] = repr(e)
            row["traceback"] = traceback.format_exc()
        try:
            after = input_guard()
            row["input_sha256_after"] = after
            row["input_guard_equal"] = before == after
            if before != after: row["rc"] = 2
        except BaseException as e:
            row["post_guard_error"] = repr(e)
            row["rc"] = 2
        row["elapsed_seconds"] = round(time.monotonic() - started, 3)
        phases[phase] = row
        write(HERE / (phase.upper() + "-RESULT.json"), row)
        print(json.dumps({"phase": phase, "rc": row["rc"], "elapsed_seconds": row["elapsed_seconds"]}), flush=True)
        if row["rc"] != 0: break
    result = {"schema": "peer-pubgm-four-static-v1", "apk_sha256": EXPECTED, "apk_bytes": BYTES, "phases": phases, "all_four_phases_rc0": len(phases) == 4 and all(x["rc"] == 0 and x["input_guard_equal"] for x in phases.values()), "authoritative_count_changed": False, "blackbox_qualified": False, "startup_proven": False, "device_commands": 0, "container_commands": 0}
    write(HERE / "RESULT.json", result)
    return 0 if result["all_four_phases_rc0"] else 2

if __name__ == "__main__": sys.exit(main())
