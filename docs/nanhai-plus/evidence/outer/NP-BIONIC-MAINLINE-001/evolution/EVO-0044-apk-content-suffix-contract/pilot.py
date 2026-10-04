#!/usr/bin/env python3
"""Host-only falsifier for Signal APK content versus scanner suffix dispatch."""
import hashlib
import json
import os
from pathlib import Path
import sys
import time

root = Path(os.environ["NANHAI_PROJECT_ROOT"])
here = Path(__file__).parent
raw = root / ".nanhai-plus-runtime/bionic-oh7-aosp16/staging/mainstream-stock-intake-v2/org.thoughtcrime.securesms/body.raw"
scanner_source = root / "harness/westlake_gap/scanner.py"
expected = {
    "apk": "9fca2a1cd46ad805bd12d7bcc3930cc9388bffd5a1d01b0422c6149f1b702122",
    "scanner": "5ac937a7dcc425544dd4051368bfab6a3cdc1808024a505c20dfb09f2e187e3a",
}

def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()

assert sha(raw) == expected["apk"]
assert sha(scanner_source) == expected["scanner"]
alias = here / "signal-content-identity.apk"
if alias.is_symlink():
    assert alias.resolve() == raw.resolve()
else:
    assert not alias.exists()
    alias.symlink_to(raw)
assert sha(alias) == expected["apk"]
sys.path.insert(0, str(root / "harness"))
from westlake_gap import scanner

started = time.monotonic_ns()
control = scanner.apk_metadata(raw)
treatment = scanner.apk_metadata(alias)
ended = time.monotonic_ns()
result = {
    "schema": "evo44-apk-suffix-pilot-v1",
    "source_sha256": expected,
    "raw_path": str(raw.relative_to(root)),
    "alias_path": str(alias.relative_to(root)),
    "alias_is_symlink": alias.is_symlink(),
    "same_content_sha256": sha(alias) == sha(raw) == expected["apk"],
    "control": {k: control.get(k) for k in ("filename", "package", "version_name", "version_code", "target_sdk", "manifest_available", "manifest_error")},
    "treatment": {k: treatment.get(k) for k in ("filename", "package", "version_name", "version_code", "target_sdk", "manifest_available", "manifest_error")},
    "elapsed_seconds": (ended - started) / 1e9,
    "content_identity_preserved": control["sha256"] == treatment["sha256"] == expected["apk"] and control["bytes"] == treatment["bytes"],
    "device_commands": 0,
    "network_commands": 0,
    "container_commands": 0,
    "authoritative_count_delta": 0,
}
with (here / "PILOT.json").open("x") as output:
    json.dump(result, output, ensure_ascii=False, indent=2, sort_keys=True)
    output.write("\n")
print(json.dumps(result, ensure_ascii=False, sort_keys=True))
