#!/usr/bin/env python3
"""Local-only fixtures for the prepared G287 runner; never invokes execute()."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "run.py"
SOURCE = SCRIPT.read_text()
spec = importlib.util.spec_from_file_location("g287_candidate", SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

def check(ok, name):
    if not ok:
        raise RuntimeError(name)
    return name

def main():
    cases = []
    tree = ast.parse(SOURCE)
    cases.append(check(bool(tree), "AST_PARSE"))
    expected = m.APK.encode().replace(b"/", b"\\u002F")
    urls = m.official_apk_urls(b'{"apk":"' + expected + b'"}')
    cases.append(check(m.APK in urls, "ESCAPED_OFFICIAL_URL_ACCEPTED"))
    urls = m.official_apk_urls(m.OTHER_LITE.encode())
    cases.append(check(m.APK not in urls, "ALTERNATE_LITE_CANNOT_SATISFY_EXACT_URL"))
    cases.append(check(m.head_identity(b"HTTP/2 200\r\ncontent-length: 35983713\r\ncontent-type: application/vnd.android.package-archive\r\n")
                       == (m.APK_BYTES, "application/vnd.android.package-archive"), "HEAD_IDENTITY_PARSE"))
    try:
        m.head_identity(b"HTTP/2 200\r\ncontent-length: 35983713\r\ncontent-length: 48413684\r\ncontent-type: application/vnd.android.package-archive\r\n")
        raise RuntimeError("DUPLICATE_HEAD_NOT_REJECTED")
    except m.GateError:
        cases.append("DUPLICATE_HEAD_REJECTED")
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "START.json"
        m.exclusive_json(p, {"state": "UNKNOWN"})
        first = p.read_bytes()
        try:
            m.exclusive_json(p, {"state": "REPLAY"})
            raise RuntimeError("REPLAY_NOT_REJECTED")
        except FileExistsError:
            cases.append("START_EXCLUSIVE_REPLAY_REJECTED")
        check(p.read_bytes() == first, "START_PRESERVED")
        q = Path(td) / "RESULT.json"
        m.final_json(q, {"status": "TERMINAL_FAILED"})
        first = q.read_bytes()
        try:
            m.final_json(q, {"status": "OVERWRITE"})
            raise RuntimeError("RESULT_OVERWRITE_NOT_REJECTED")
        except FileExistsError:
            cases.append("RESULT_ATOMIC_NO_REPLACE")
        check(q.read_bytes() == first, "RESULT_PRESERVED")
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and
             isinstance(n.func, ast.Name) and n.func.id == "command"]
    cases.append(check(len(calls) == 4, "FOUR_BOUNDED_COMMAND_SITES"))
    cases.append(check("--max-filesize" in SOURCE and "PAGE_MAX" in SOURCE and "APK_BYTES" in SOURCE,
                       "PAGE_AND_APK_BYTE_CAPS_STATIC"))
    cases.append(check('"--retry", "0"' in SOURCE, "NO_CURL_RETRY_STATIC"))
    cases.append(check("--execute" in SOURCE and "PREPARED_ONLY" in SOURCE, "EXPLICIT_EXECUTION_GUARD"))
    cases.append(check("publisher_artifact_digest\": None" in SOURCE and
                       "alternative_lite_variant_used\": False" in SOURCE, "NO_INVENTED_DIGEST_OR_VARIANT_FALLBACK"))
    result = {"schema": "g287-tiktoklite-local-fixture-v1", "status": "PASS",
              "script_sha256": hashlib.sha256(SCRIPT.read_bytes()).hexdigest(), "cases": cases,
              "network_requests": 0, "apk_get": 0, "device_commands": 0, "container_commands": 0}
    (HERE / "FIXTURE.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))

if __name__ == "__main__":
    main()
