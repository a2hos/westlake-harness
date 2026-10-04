#!/usr/bin/env python3
"""Create a project-owned symlink view of admitted AOSP R4 roots on Linux."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tempfile


def checked_relative(value: str) -> Path:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts or str(path) != value:
        raise ValueError(f"unsafe source root: {value!r}")
    return Path(*path.parts)


def git_head(path: Path) -> str:
    return subprocess.check_output(
        ["git", "-C", str(path), "rev-parse", "HEAD"], text=True
    ).strip()


def create_view(audit: Path, source: Path, soong: Path, destination: Path) -> dict:
    record = json.loads(audit.read_text())
    if record.get("schema") != "nanhai.gz02.host_native_source_readonly_audit.v1":
        raise ValueError("unexpected source audit schema")
    if not source.is_dir() or not soong.is_dir() or destination.exists():
        raise ValueError("source/worktree missing or destination already exists")
    source_real = source.resolve(strict=True)
    expected_soong = next(
        row["head"] for row in record["stock_roots"] if row["root"] == "build/soong"
    )
    if git_head(soong) != expected_soong:
        raise ValueError("patched Soong worktree base changed")
    roots = record["stock_roots"] + record["additional_inputs"]
    if len(roots) != 46 or len({row["root"] for row in roots}) != 46:
        raise ValueError("expected exactly 46 unique admitted roots")
    for row in roots:
        relative = checked_relative(row["root"])
        target = source / relative
        if not target.is_dir() or git_head(target) != row["head"]:
            raise ValueError(f"source identity changed: {relative}")
        if not target.resolve(strict=True).is_relative_to(source_real):
            raise ValueError(f"source escapes checkout: {relative}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix="source-view-", dir=destination.parent))
    try:
        for row in roots:
            relative = checked_relative(row["root"])
            link = temporary / relative
            link.parent.mkdir(parents=True, exist_ok=True)
            target = soong if row["root"] == "build/soong" else source / relative
            os.symlink(target, link, target_is_directory=True)
        os.replace(temporary, destination)
    except BaseException:
        shutil.rmtree(temporary)
        raise
    return {
        "status": "source_view_created",
        "admitted_roots": len(roots),
        "source": str(source),
        "patched_soong": str(soong),
        "destination": str(destination),
        "claim": "symlink view only; no graph/build/device acceptance",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("audit", type=Path)
    parser.add_argument("source", type=Path)
    parser.add_argument("soong", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    print(json.dumps(create_view(args.audit, args.source, args.soong, args.destination), indent=2))


if __name__ == "__main__":
    main()
