#!/usr/bin/env python3
"""Local-only receipt and authoritative-binding fixtures; no APK/API network."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import ast

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("elementx_v3", HERE / "run.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
cases = []
source = (HERE / "run.py").read_text()
ast.parse(source)
if source.count('"--max-filesize"') != 2 or module.API_MAX_BYTES != 1048576 or module.APK_SIZE != 117664325:
    raise RuntimeError("API/APK byte caps missing")
if '"--output", str(api_body)' not in source or 'api_body.read_bytes()' not in source:
    raise RuntimeError("API body is not streamed to bounded file")
cases.append("API_AND_APK_EXACT_BYTE_CAPS_STATIC")

with tempfile.TemporaryDirectory(prefix="g284-v3-fixture-") as td:
    root = Path(td)
    start = root / "START.json"
    result = root / "RESULT.json"
    module.durable_exclusive_json(start, {"status": "REMOTE_STATE_UNKNOWN_IN_PROGRESS"})
    try:
        module.durable_exclusive_json(start, {"status": "REPLAY"})
    except FileExistsError:
        cases.append("START_EXCLUSIVE_NO_REPLAY")
    else:
        raise RuntimeError("second START unexpectedly succeeded")
    first = start.read_bytes()
    module.durable_final(result, {"status": "TERMINAL_FAILED", "reason": "fixture"})
    try:
        module.durable_final(result, {"status": "OVERWRITE"})
    except FileExistsError:
        cases.append("RESULT_ATOMIC_NO_REPLACE")
    else:
        raise RuntimeError("second RESULT unexpectedly succeeded")
    if start.read_bytes() != first or json.loads(result.read_text())["status"] != "TERMINAL_FAILED":
        raise RuntimeError("fixture receipt changed")
    cases.append("START_AND_RESULT_DURABLE_CONTENT")

with tempfile.TemporaryDirectory(prefix="g284-v3-top-fixture-") as td:
    old_here, old_execute, old_argv = module.HERE, module.execute, sys.argv
    try:
        module.HERE = Path(td)
        module.execute = lambda _: (_ for _ in ()).throw(module.GateError("fixture pre-network failure"))
        sys.argv = [str(HERE / "run.py"), "--execute"]
        module.main()
        terminal = json.loads((Path(td) / "RESULT.json").read_text())
        if terminal["status"] != "TERMINAL_FAILED" or not (Path(td) / "START.json").is_file():
            raise RuntimeError("top-level failure did not close receipts")
        try:
            module.main()
        except FileExistsError:
            cases.append("TOP_LEVEL_EXCEPTION_TERMINAL_AND_REPLAY_REJECTED")
        else:
            raise RuntimeError("top-level replay unexpectedly succeeded")
    finally:
        module.HERE, module.execute, sys.argv = old_here, old_execute, old_argv

with tempfile.TemporaryDirectory(prefix="g284-v3-timeout-fixture-") as td:
    old_here, old_run = module.HERE, module.subprocess.run
    try:
        module.HERE = Path(td)
        def fake_timeout(*args, **kwargs):
            raise module.subprocess.TimeoutExpired(args[0], kwargs["timeout"], b"", b"timeout fixture")
        module.subprocess.run = fake_timeout
        rec = module.run_command("timeout", ["/usr/bin/true"], 1, {})
        if rec["rc"] is not None or not rec["timed_out"] or rec["stderr_bytes"] == 0:
            raise RuntimeError("timeout was not captured")
        cases.append("SUBPROCESS_TIMEOUT_CAPTURED_FOR_TERMINAL_GATE")
    finally:
        module.HERE, module.subprocess.run = old_here, old_run

bindings, audit = module.authoritative_bindings()
cases.append("CURRENT_LOCAL_ENV_BINDING_PASS")
old_env_sha = module.ENV_CONFIG_SHA
module.ENV_CONFIG_SHA = "0" * 64
try:
    module.authoritative_bindings()
except module.GateError:
    cases.append("FROZEN_ENV_CONFIG_SHA_REJECTED")
else:
    raise RuntimeError("changed config SHA accepted")
finally:
    module.ENV_CONFIG_SHA = old_env_sha
original = os.environ["NANHAI_STAGING_ROOT"]
os.environ["NANHAI_STAGING_ROOT"] = original + "-stale"
try:
    module.authoritative_bindings()
except module.GateError:
    cases.append("STALE_ENV_BINDING_REJECTED")
else:
    raise RuntimeError("stale environment accepted")
finally:
    os.environ["NANHAI_STAGING_ROOT"] = original

receipt = {"schema": "g284-elementx-github-raw-v3-local-fixture",
           "cases": cases, "environment_config_sha256": audit["config_sha256"],
           "script_sha256": hashlib.sha256((HERE / "run.py").read_bytes()).hexdigest(),
           "network_requests": 0, "apk_get": 0, "device": 0, "container": 0}
(HERE / "FIXTURE.json").write_text(json.dumps(receipt, indent=2) + "\n")
print(json.dumps(receipt))
