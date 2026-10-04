#!/usr/bin/env python3
"""Original inner owner reads the new native source binding, without executing it."""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(os.environ["NANHAI_PROJECT_ROOT"])
HERE = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    request = json.loads((HERE / "REQUEST.json").read_text())
    assert request["goal_id"] == "goal_01"
    assert request["claim"] == "NP-MUSL16-ART-024"
    assert request["session"] == "oracle-kimi:local:nanhai-plus#inner"
    assert request["container_policy_revision"] == 1
    assert request["container_execution"] is False
    assert os.environ["NANHAI_CONTAINER_POLICY"] == "forbidden"
    assert os.environ["NANHAI_BUILD_EXECUTION_MODE"] == "host-native"
    assert os.environ["NANHAI_ENV_CONFIG_SHA256"] == request["environment_sha256"]
    assert os.environ["NANHAI_GZ02_AOSP_SOURCE_ROOT"] == "/opt/19.SourceCode/AOSP-16.0.0_r4/android-source"
    assert sha(Path(os.environ["NANHAI_SOURCE_POOL_ROOT"]) / "SOURCES.json") == request["shared_source_index_sha256"]
    consumed = {}
    for relative, expected in request["refs"].items():
        assert sha(ROOT / relative) == expected, relative
        consumed[relative] = expected
    state = json.loads((ROOT / "docs/nanhai-plus/OUTER-STATE.json").read_text())
    claim = next(row for row in state["claims"] if row.get("claim_id") == request["claim"])
    assert claim["goal_id"] == request["goal_id"]
    assert claim["native_session"] == request["session"]
    assert claim["status"] == "ready" and claim["release_state"] == "completed_reviewed"
    assert claim["release_sequence"] == 276
    assert state["container_policy"]["status"] == "forbidden"
    receipt = ROOT / request["owner_receipt"]
    assert not receipt.exists()
    receipt.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "schema": "nanhai-g279-original-owner-source-ack-v1",
        "at": datetime.now(timezone.utc).isoformat(),
        "goal_id": request["goal_id"], "claim": request["claim"],
        "session": request["session"], "nonce": request["nonce"],
        "environment_sha256": request["environment_sha256"],
        "shared_source_index_sha256": request["shared_source_index_sha256"],
        "remote_source_index_sha256": request["remote_source_index_sha256"],
        "consumed": consumed, "container_execution_allowed": False,
        "graph_executed": False, "target_compilation_executed": False,
        "device_commands": 0,
    }
    receipt.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"rc": 0, "ack": str(receipt.relative_to(ROOT)), "sha256": sha(receipt)}))


if __name__ == "__main__":
    main()
