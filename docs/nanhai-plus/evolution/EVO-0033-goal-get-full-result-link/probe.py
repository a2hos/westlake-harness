#!/usr/bin/env python3
"""Offline pilot: reject a truncated Goal_get preview; validate a full-result join.

This does not call Herdr or fabricate live goal evidence. The positive is synthetic.
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
EXCERPT = ROOT / "docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g279-native-graph-source-choice-v1/g279-v13-a30-live-goal-peer-review-v1/LEDGER-EXCERPT.jsonl"
EVENT_ID = "tool_HrgpsqZJvNHMiXBIenp36Tku"
SESSION = "oracle-kimi:local:nanhai-plus#inner"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def joined(event, raw, expected_digest):
    """Require exact tool event plus separately retained full JSON bytes."""
    if event.get("tool_name") != "goal_get" or event.get("tool_call_id") != EVENT_ID:
        return False
    if event.get("session_id") != SESSION or event.get("success") is not True:
        return False
    if not raw or digest(raw) != expected_digest:
        return False
    try:
        value = json.loads(raw)
    except (ValueError, TypeError):
        return False
    required = {"goal_id", "status", "created_at_ms", "token_budget", "tokens_used"}
    return required <= set(value) and value["goal_id"] == "goal_01" and \
        value["token_budget"] == 20000000000 and \
        type(value["tokens_used"]) is int and 0 <= value["tokens_used"] < 20000000000


def main():
    rows = [json.loads(line) for line in EXCERPT.read_text().splitlines()]
    event = next(row["record"]["event"] for row in rows if row["record"]["event"].get("record_kind") == "notification" and row["record"]["event"].get("kind") == "tool_completed" and row["record"]["event"].get("tool_call_id") == EVENT_ID)
    preview = event["output_preview"].encode()
    assert not joined(event, preview, digest(preview))
    assert not joined(event, b"", digest(b""))

    # Synthetic only: proves join and invalidation mechanics, not live metadata.
    synthetic = json.dumps({"goal_id": "goal_01", "status": "blocked", "created_at_ms": 1790677296212,
                            "token_budget": 20000000000, "tokens_used": 255945577}, sort_keys=True).encode()
    assert joined(event, synthetic, digest(synthetic))
    assert not joined(event, synthetic + b" ", digest(synthetic))
    assert not joined({**event, "tool_call_id": "other"}, synthetic, digest(synthetic))
    assert not joined({**event, "session_id": "other"}, synthetic, digest(synthetic))
    print(json.dumps({"schema": "evo33-goal-get-full-result-link-offline-pilot-v1",
                      "actual_preview_bytes": len(preview), "actual_preview_rejected": True,
                      "actual_full_result_available": False, "synthetic_full_join_passed": True,
                      "mutated_digest_event_and_session_rejected": True,
                      "real_goal_continuity_passed": False,
                      "source_excerpt_sha256": digest(EXCERPT.read_bytes())}, sort_keys=True))


if __name__ == "__main__":
    main()
