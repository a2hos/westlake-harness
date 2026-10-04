#!/usr/bin/env python3
"""Read-only, three-hop freshness pilot. Never publishes or mutates inputs."""
import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path

FIELDS = {
    "accepted_raw_apk_artifact_identities": "downloaded_payloads",
    "complete_host_static_inventories": "complete_static_inventories",
    "qualified_blackbox_test_packages": "qualified_blackbox_packages",
    "stock_apk_cold_starts_verified": "cold_start_verified",
    "overseas_mainstream_blackbox_cold_starts_verified": "qualified_blackbox_startups",
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def check(summary, outer, board):
    canonical = summary["apk_portfolio"]
    chain = [outer.get("progress", {}), board.get("progress", {})]
    mismatches = []
    for public_key, source_key in FIELDS.items():
        expected = canonical[source_key]
        for hop, progress in zip(("outer", "board"), chain):
            if progress.get(public_key) != expected:
                mismatches.append({"hop": hop, "field": public_key,
                                   "expected": expected, "actual": progress.get(public_key)})
    if board.get("source") != "OUTER-STATE.json public projection (path-safe)":
        mismatches.append({"hop": "board", "field": "source", "expected": "public projection"})
    if board.get("progress", {}).get("snapshot_at_utc") != outer.get("progress", {}).get("snapshot_at_utc"):
        mismatches.append({"hop": "board", "field": "snapshot_at_utc", "expected": outer.get("progress", {}).get("snapshot_at_utc"),
                           "actual": board.get("progress", {}).get("snapshot_at_utc")})
    if board.get("checked_at") != outer.get("checked_at"):
        mismatches.append({"hop": "board", "field": "checked_at", "expected": outer.get("checked_at"),
                           "actual": board.get("checked_at")})
    try:
        if datetime.fromisoformat(outer["checked_at"]) < datetime.fromisoformat(summary["checked_at"]):
            mismatches.append({"hop": "outer", "field": "checked_at", "expected": "not earlier than summary",
                               "actual": outer["checked_at"]})
    except (KeyError, ValueError):
        mismatches.append({"hop": "outer", "field": "checked_at", "expected": "valid source timestamps"})
    return mismatches


def main():
    a = argparse.ArgumentParser()
    a.add_argument("summary", type=Path)
    a.add_argument("outer", type=Path)
    a.add_argument("board", type=Path)
    a.add_argument("--counterexample", action="store_true")
    args = a.parse_args()
    summary, outer, board = [json.loads(p.read_text()) for p in (args.summary, args.outer, args.board)]
    if args.counterexample:
        board["progress"] = dict(board["progress"])
        board["progress"].update(accepted_raw_apk_artifact_identities=111,
                                 complete_host_static_inventories=109,
                                 qualified_blackbox_test_packages=21,
                                 snapshot_at_utc="2026-10-04T00:00:00+00:00")
    problems = check(summary, outer, board)
    print(json.dumps({"status": "GO" if not problems else "NO_GO", "counterexample": args.counterexample,
                      "input_sha256": {name: sha(path) for name, path in zip(("summary", "outer", "board"),
                                                                        (args.summary, args.outer, args.board))},
                      "mismatches": problems}, ensure_ascii=False, sort_keys=True))
    raise SystemExit(0 if not problems else 2)


if __name__ == "__main__":
    main()
