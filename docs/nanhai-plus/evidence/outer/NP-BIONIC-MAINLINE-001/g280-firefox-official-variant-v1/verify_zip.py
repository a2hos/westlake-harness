#!/usr/bin/env python3
"""Read-only ZIP and native-ABI preflight for one pinned APK."""
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import zipfile


def main():
    apk = Path(sys.argv[1])
    out = Path(sys.argv[2])
    expected = sys.argv[3]
    body_hash = hashlib.sha256(apk.read_bytes()).hexdigest()
    assert body_hash == expected
    result = {
        "body_sha256": body_hash,
        "body_bytes": apk.stat().st_size,
        "zip_entries": 0,
        "unique_names": False,
        "crc_first_failure": None,
        "manifest_names": [],
        "root_dex": [],
        "native_members": [],
        "abi_counts": {},
        "invalid_native_members": [],
    }
    with zipfile.ZipFile(apk) as z:
        infos = z.infolist()
        result["zip_entries"] = len(infos)
        names = [i.filename for i in infos]
        result["unique_names"] = len(set(names)) == len(names)
        result["crc_first_failure"] = z.testzip()
        for info in infos:
            name = info.filename
            if name == "AndroidManifest.xml":
                result["manifest_names"].append(name)
            if name.startswith("classes") and name.endswith(".dex") and "/" not in name:
                with z.open(info) as f:
                    magic = f.read(8).hex()
                result["root_dex"].append({"name": name, "bytes": info.file_size, "magic_hex": magic})
            parts = name.split("/")
            if len(parts) == 3 and parts[0] == "lib" and parts[2].endswith(".so"):
                abi = parts[1]
                with z.open(info) as f:
                    head = f.read(20)
                valid = len(head) >= 20 and head[:4] == b"\x7fELF" and head[5] in (1, 2)
                machine = struct.unpack("<H" if head[5] == 1 else ">H", head[18:20])[0] if valid else None
                cls = head[4] if valid else None
                expected_pair = {"arm64-v8a": (2, 183), "armeabi-v7a": (1, 40), "x86_64": (2, 62), "x86": (1, 3)}.get(abi)
                valid = valid and expected_pair == (cls, machine)
                row = {"name": name, "abi": abi, "bytes": info.file_size, "elf_class": cls, "machine": machine, "abi_matches_elf": valid}
                result["native_members"].append(row)
                result["abi_counts"][abi] = result["abi_counts"].get(abi, 0) + 1
                if not valid:
                    result["invalid_native_members"].append(name)
    result["preflight_pass"] = bool(result["unique_names"] and result["crc_first_failure"] is None and len(result["manifest_names"]) == 1 and not result["invalid_native_members"])
    out.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps({k: result[k] for k in ("body_sha256", "body_bytes", "zip_entries", "unique_names", "crc_first_failure", "manifest_names", "abi_counts", "preflight_pass")}, sort_keys=True))
    return 0 if result["preflight_pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
