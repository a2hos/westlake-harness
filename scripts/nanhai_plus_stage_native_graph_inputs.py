#!/usr/bin/env python3
"""Stage hash-bound G279 graph inputs on gz02; never execute the graph."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

from nanhai_plus_env import load_environment


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g279-native-graph-source-choice-v1"
RECEIPT = EVIDENCE / "input-staging-v1/STAGING.json"
CONFIG_SHA = "5ce3a58541ef1711890aad8348c3a31a03203f584fa50f1f5c0cb4fd88b49718"
INPUT_SHA = {
    "generate_manifest_heads.py": "dafbc416c2b036ea8816591f408b24a8a99974827302968041474d54ef550634",
    "MANIFEST-HEADS.tsv": "fe22e645511647b6b34dd83f5c0573ef1f8d45eaf380ac08b12c5120d1e13356",
}
REQUIRED = (
    "NANHAI_SOURCE_POOL_ROOT",
    "NANHAI_GZ02_BUILD_HOST",
    "NANHAI_GZ02_AOSP_SOURCE_ROOT",
    "NANHAI_GZ02_SOONG_WORKTREE",
    "NANHAI_GZ02_NATIVE_PROJECT_ROOT",
    "NANHAI_GZ02_SOONG_UI",
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


REMOTE_PROGRAM = r"""
import base64, hashlib, json, os, pathlib, sys
packet = json.load(sys.stdin)
project = pathlib.Path(packet['project'])
control = project / 'control'
if not project.is_dir() or project.is_symlink() or not control.is_dir() or control.is_symlink():
    raise SystemExit('project control identity mismatch')
if project.resolve() != project or control.resolve() != control:
    raise SystemExit('project control resolution mismatch')
if [item['name'] for item in packet['files']] != ['generate_manifest_heads.py', 'MANIFEST-HEADS.tsv', 'g279-native-graph-env.json']:
    raise SystemExit('staging set/order mismatch')
out = []
directory = os.open(control, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
created_names = []
try:
    for item in packet['files']:
        name = item['name']
        data = base64.b64decode(item['content'], validate=True)
        expected = item['sha256']
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError('transport hash mismatch')
        created = False
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444, dir_fd=directory)
            created = True
            created_names.append(name)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
                os.fchmod(stream.fileno(), 0o444)
        except FileExistsError:
            pass
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        with os.fdopen(fd, 'rb') as stream:
            actual = hashlib.sha256(stream.read()).hexdigest()
            mode = os.fstat(stream.fileno()).st_mode & 0o777
        if actual != expected or mode & 0o222:
            raise ValueError('destination identity mismatch: ' + name)
        out.append({'name': name, 'created': created, 'sha256': expected, 'bytes': len(data), 'mode': oct(mode)})
except BaseException:
    for name in reversed(created_names):
        os.unlink(name, dir_fd=directory)
    raise
finally:
    os.close(directory)
print(json.dumps({'project': str(project), 'files': out}, sort_keys=True))
"""


def main() -> int:
    if RECEIPT.exists():
        raise SystemExit("immutable staging receipt already exists; inspect it before retry")
    RECEIPT.parent.mkdir(parents=True, exist_ok=True)
    lock_fd = os.open(RECEIPT.parent / "STAGING.lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(lock_fd)
        raise SystemExit("another staging process owns the atomic lock")
    if RECEIPT.exists():
        os.close(lock_fd)
        raise SystemExit("immutable staging receipt appeared under lock")
    receipt = {"schema": "nanhai-g279-input-staging-v1", "at": datetime.now(timezone.utc).isoformat(),
               "container_execution": False, "graph_executed": False, "device_executed": False,
               "remote_rc": None, "remote": None, "status": "FAILED_PRE_STAGING"}
    exit_code = 2
    try:
        expected, audit = load_environment(ROOT / "local_env.md")
        if audit["config_sha256"] != CONFIG_SHA:
            raise ValueError("frozen local_env config changed")
        for key in REQUIRED:
            if os.environ.get(key) != expected[key]:
                raise ValueError("NANHAI binding mismatch: " + key)
        if os.environ.get("NANHAI_ENV_CONFIG_SHA256") != CONFIG_SHA:
            raise ValueError("wrapper config SHA mismatch")
        if expected["NANHAI_GZ02_BUILD_HOST"] != "gz02":
            raise ValueError("unexpected host identity")
        env_bytes = (ROOT / "local_env.md").read_bytes()
        receipt["host"] = expected["NANHAI_GZ02_BUILD_HOST"]
        receipt["env_config_sha256"] = CONFIG_SHA
        receipt["local_env_file_sha256"] = digest(env_bytes)
        binding = {"schema": "nanhai-g279-native-graph-env-v1",
                   "env_config_sha256": CONFIG_SHA, "local_env_file_sha256": digest(env_bytes),
                   "paths": {key: expected[key] for key in REQUIRED if key != "NANHAI_GZ02_BUILD_HOST"}}
        files = {
            "generate_manifest_heads.py": (EVIDENCE / "generate_manifest_heads.py").read_bytes(),
            "MANIFEST-HEADS.tsv": (EVIDENCE / "MANIFEST-HEADS.tsv").read_bytes(),
            "g279-native-graph-env.json": (json.dumps(binding, sort_keys=True, indent=2) + "\n").encode(),
        }
        for name, expected_sha in INPUT_SHA.items():
            if digest(files[name]) != expected_sha:
                raise ValueError("admitted input drift: " + name)
        receipt["binding_sha256"] = digest(files["g279-native-graph-env.json"])
        packet = {"project": expected["NANHAI_GZ02_NATIVE_PROJECT_ROOT"],
                  "files": [{"name": name, "sha256": digest(data), "content": base64.b64encode(data).decode()}
                            for name, data in files.items()]}
        argv = ["ssh", "-o", "BatchMode=yes", expected["NANHAI_GZ02_BUILD_HOST"],
                shlex.join(["python3", "-c", REMOTE_PROGRAM])]
        receipt["status"] = "REMOTE_STATE_UNKNOWN"
        run = subprocess.run(argv, input=json.dumps(packet).encode(), capture_output=True, timeout=90)
        receipt["remote_rc"] = run.returncode
        receipt["stderr"] = run.stderr.decode(errors="replace")[:2000]
        if run.returncode != 0:
            raise RuntimeError("remote staging command failed")
        remote = json.loads(run.stdout)
        if remote.get("project") != packet["project"] or len(remote.get("files", [])) != 3:
            raise ValueError("remote receipt identity mismatch")
        for item, expected_item in zip(remote["files"], packet["files"], strict=True):
            if item["name"] != expected_item["name"] or item["sha256"] != expected_item["sha256"]:
                raise ValueError("remote staged file identity mismatch")
        receipt["remote"] = remote
        receipt["status"] = "STAGED_HASH_VERIFIED"
        exit_code = 0
    except BaseException as error:
        receipt["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        temporary = RECEIPT.with_name(RECEIPT.name + ".tmp." + str(os.getpid()))
        try:
            with temporary.open("x") as stream:
                stream.write(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.link(temporary, RECEIPT)
        finally:
            temporary.unlink(missing_ok=True)
            os.close(lock_fd)
    print(json.dumps({"receipt": str(RECEIPT), "status": receipt["status"],
                      "remote_rc": receipt["remote_rc"],
                      "binding_sha256": receipt.get("binding_sha256")}, ensure_ascii=False))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
