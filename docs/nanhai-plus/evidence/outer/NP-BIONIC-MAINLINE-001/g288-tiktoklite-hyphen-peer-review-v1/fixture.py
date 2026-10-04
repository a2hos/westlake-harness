#!/usr/bin/env python3
"""Local-only checks for the frozen G288 intake candidate."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
script = HERE / "run.py"
ast.parse(script.read_text())
spec = importlib.util.spec_from_file_location("g288_run", script)
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)
page = (HERE / "page.body.raw").read_bytes()
head = (HERE / "head.headers.raw").read_bytes()
card = run.official_lite_card(page)
assert card["link"] == run.APK and card["version"] == "36.9.61"
assert run.APK in run.official_apk_urls(page)
assert run.OTHER_LITE in run.official_apk_urls(page)
assert run.head_identity(head) == (run.APK_BYTES, "application/vnd.android.package-archive")
try:
    run.official_lite_card(page.replace(b"TikTok-Lite_360961.apk", b"TikTok_Lite_360961.apk"))
except run.GateError:
    pass
else:
    raise AssertionError("alternate Lite variant was accepted as official card")
probe = subprocess.run([sys.executable, str(script)], capture_output=True, text=True)
assert probe.returncode != 0 and "PREPARED_ONLY" in probe.stderr
assert not (HERE / "START.json").exists() and not (HERE / "RESULT.json").exists()
source = script.read_text()
assert source.count('get_cmd = base +') == 1
assert 'result["zip"]["lib_abis"] in ([], ["arm64-v8a"])' in source
assert 'need("name=\'" + PACKAGE' in source
assert 'need(cert is not None' in source
assert 'z.testzip()' in source
observation = json.loads((HERE / "HTTP-OBSERVATION.json").read_text())
assert [row["rc"] for row in observation["requests"]] == [0, 0]
assert observation["apk_get_count"] == 0
assert observation["requests"][0]["body_or_headers_sha256"] == hashlib.sha256(page).hexdigest()
assert observation["requests"][1]["body_or_headers_sha256"] == hashlib.sha256(head).hexdigest()
result = {"schema": "g288-local-fixture-v1", "status": "PASS",
          "runner_sha256": hashlib.sha256(script.read_bytes()).hexdigest(),
          "page_sha256": hashlib.sha256(page).hexdigest(),
          "head_sha256": hashlib.sha256(head).hexdigest(), "card": card,
          "cases": ["AST", "OFFICIAL_CARD", "BOTH_VARIANTS_DISTINCT", "HEAD_EXACT",
                    "ALTERNATE_REJECTED", "NO_ARG_CLOSED", "ONE_APK_GET_SITE",
                    "ZIP_ABI_PACKAGE_CERT_GATES", "OBSERVATION_HASHES"],
          "apk_get_count": 0, "device_count": 0, "container_count": 0}
(HERE / "FIXTURE.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result))
