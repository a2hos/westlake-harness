#!/usr/bin/env python3
"""Local signature/entrypoint adversarial fixtures; never invoke graph."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
RUNNER = HERE / 'nanhai_plus_native_graph_v12.py'
spec = importlib.util.spec_from_file_location('g279_v12', RUNNER)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def put(path: Path, data: bytes):
    if path.exists():
        path.chmod(0o600)
    path.write_bytes(data)
    path.chmod(0o444)


def denied(fn):
    try:
        fn()
    except (ValueError, OSError):
        return
    raise AssertionError('unsigned or tampered owner ACK accepted')


with tempfile.TemporaryDirectory(prefix='g279-v12-fixture-') as tmp:
    root = Path(tmp).resolve(strict=True)
    key = root / 'owner-fixture-key'
    generate = subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], capture_output=True)
    assert generate.returncode == 0, generate.stderr
    pub = key.with_suffix('.pub').read_text().split()
    mod.OWNER_PUBLIC_KEY = ' '.join(pub[:2])
    control = root / 'control'
    control.mkdir()
    ack = control / 'g279-native-graph-v12-owner-ack.json'
    sig = control / 'g279-native-graph-v12-owner-ack.json.sig'
    content = b'{"goal_id":"goal_01","runner":"v12","nonce":"fixture"}\n'
    put(ack, content)
    signing = subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(key), '-n', mod.OWNER_NAMESPACE],
                             input=content, capture_output=True)
    assert signing.returncode == 0, signing.stderr
    put(sig, signing.stdout)
    result = mod.verify_owner_signature(control)
    assert result['verification_rc'] == 0
    put(ack, content + b' ')
    denied(lambda: mod.verify_owner_signature(control))
    put(ack, content)
    wrong_namespace = subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(key), '-n', 'wrong-namespace'],
                                     input=content, capture_output=True)
    assert wrong_namespace.returncode == 0
    put(sig, wrong_namespace.stdout)
    denied(lambda: mod.verify_owner_signature(control))
    put(sig, signing.stdout)
    mod.OWNER_PUBLIC_KEY = 'ssh-ed25519 ' + 'A' * len(pub[1])
    denied(lambda: mod.verify_owner_signature(control))
    sig.unlink()
    denied(lambda: mod.verify_owner_signature(control))

source = RUNNER.read_text()
assert "NO_GO_V12_UNRELEASED" not in source
assert "return reviewed_execution_candidate(release)" in source
assert "verify_owner_signature(PROJECT_ROOT / 'control')" in source
print(json.dumps({'status':'PASS','fixtures': ['signed_ack', 'tampered_ack_denied', 'wrong_namespace_denied', 'wrong_key_denied', 'missing_signature_denied', 'graph_not_invoked']}))
