#!/usr/bin/env python3
"""Offline pilot: compare literal preflight field reads with candidate/release JSON."""
import ast
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "evidence/outer/NP-BIONIC-MAINLINE-001/g279-native-graph-source-choice-v1"


def literal_reads(controller: Path, variable: str) -> set[str]:
    tree = ast.parse(controller.read_bytes(), filename=str(controller))
    preflight = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "preflight")
    keys = set()
    for node in ast.walk(preflight):
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id == variable and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
            keys.add(node.slice.value)
    return keys


def check(version: int) -> dict:
    folder = BASE / f"graph-v13-proxy-readonly-state-candidate-v{version}"
    candidate_path = folder / "CANDIDATE.json"
    controller_path = folder / "controller.py"
    candidate = json.loads(candidate_path.read_bytes())
    release_path = folder / "ROOT-EXACT-READONLY-STATE-RELEASE.json"
    release = json.loads(release_path.read_bytes()) if release_path.exists() else None
    needed_candidate = literal_reads(controller_path, "candidate")
    needed_release = literal_reads(controller_path, "release")
    return {
        "version": version,
        "candidate_sha256": hashlib.sha256(candidate_path.read_bytes()).hexdigest(),
        "controller_sha256": hashlib.sha256(controller_path.read_bytes()).hexdigest(),
        "candidate_required": sorted(needed_candidate),
        "candidate_missing": sorted(needed_candidate - candidate.keys()),
        "release_present": release is not None,
        "release_required": sorted(needed_release),
        "release_missing": sorted(needed_release - release.keys()) if release is not None else None,
    }


if __name__ == "__main__":
    rows = [check(2), check(3)]
    assert rows[0]["candidate_missing"] == ["timeout_root_acceptance_sha256"]
    assert rows[0]["release_missing"] == []
    assert rows[1]["candidate_missing"] == []
    assert rows[1]["release_present"] is False
    print(json.dumps({"schema": "evo39-preflight-field-contract-pilot-v1", "rows": rows}, sort_keys=True, separators=(",", ":")))
