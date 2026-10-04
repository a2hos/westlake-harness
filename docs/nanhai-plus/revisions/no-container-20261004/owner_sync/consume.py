#!/usr/bin/env python3
"""Bounded original-owner acknowledgment of the no-container revision."""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(os.environ["NANHAI_PROJECT_ROOT"])
HERE = Path(__file__).resolve().parent
REQUEST = HERE / "POLICY-REQUEST.json"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    request = json.loads(REQUEST.read_text())
    assert request["goal_id"] == "goal_01"
    assert request["claim"] == "NP-MUSL16-ART-024"
    assert request["container_policy_revision"] == 1
    assert os.environ["NANHAI_CONTAINER_POLICY"] == "forbidden"
    assert os.environ["NANHAI_BUILD_EXECUTION_MODE"] == "host-native"
    assert "NANHAI_DOCKER" not in os.environ and "NANHAI_HOST_IMAGE" not in os.environ
    assert os.environ["NANHAI_ENV_CONFIG_SHA256"] == request["environment_sha256"]
    consumed = {}
    for relative, expected in request["refs"].items():
        path = ROOT / relative
        assert sha(path) == expected, relative
        consumed[relative] = expected
    state = json.loads((ROOT / "docs/nanhai-plus/OUTER-STATE.json").read_text())
    claim = next(x for x in state["claims"] if x.get("claim_id") == request["claim"])
    assert claim["goal_id"] == request["goal_id"]
    assert claim["native_session"] == request["session"]
    assert claim["status"] == "ready" and claim["release_state"] == "completed_reviewed"
    assert claim["release_sequence"] == 276
    assert state["container_policy"]["status"] == "forbidden"
    assert state["container_policy"]["revision"] == 1
    output = ROOT / request["owner_receipt"]
    assert not output.exists()
    output.parent.mkdir(parents=True, exist_ok=True)
    ack = {
        "schema": "nanhai-no-container-original-owner-ack-v1",
        "at": datetime.now(timezone.utc).isoformat(),
        "goal_id": request["goal_id"],
        "claim": request["claim"],
        "session": request["session"],
        "nonce": request["nonce"],
        "container_policy_revision": 1,
        "environment_sha256": request["environment_sha256"],
        "consumed": consumed,
        "container_execution_allowed": False,
        "old_container_packets_replay_allowed": False,
        "new_host_graph_executed": False,
        "device_commands": 0,
    }
    output.write_text(json.dumps(ack, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"rc": 0, "ack": str(output.relative_to(ROOT)), "sha256": sha(output)}))


if __name__ == "__main__":
    main()
