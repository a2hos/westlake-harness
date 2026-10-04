#!/usr/bin/env python3
"""Load the active environment from the one marked block in local_env.md.

No host paths live in this script. Documentation is the configuration source;
shell exports and child environments are derived rather than separately edited.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys


START = "<!-- NANHAI_ENV_BEGIN -->"
END = "<!-- NANHAI_ENV_END -->"
NAME = re.compile(r"NANHAI_[A-Z][A-Z0-9_]*\Z")


class EnvironmentError(ValueError):
    pass


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EnvironmentError(f"Duplicate environment field: {key}")
        result[key] = value
    return result


def load_environment(document=None):
    """Return (exports, audit); validate before exposing any active bindings."""
    document = Path(document) if document else Path(__file__).resolve().parents[1] / "local_env.md"
    document = document.resolve(strict=True)
    content = document.read_text()
    if content.count(START) != 1 or content.count(END) != 1:
        raise EnvironmentError("Expected exactly one environment block in local_env.md")
    section = content.split(START, 1)[1].split(END, 1)[0].strip()
    match = re.fullmatch(r"```json\s*\n(.*?)\n```", section, re.S)
    if not match:
        raise EnvironmentError("Environment block must contain exactly one JSON code fence")
    config = json.loads(match.group(1), object_pairs_hook=unique_object)
    if not isinstance(config, dict) or type(config.get("schema")) is not int or config["schema"] != 1:
        raise EnvironmentError("Unsupported environment schema")
    if set(config) - {"schema", "paths", "values", "links"}:
        raise EnvironmentError("Unknown environment configuration field")
    paths, values = config.get("paths"), config.get("values", {})
    if not isinstance(paths, dict) or not paths or not isinstance(values, dict):
        raise EnvironmentError("paths must be a non-empty object; values must be an object")
    if paths.keys() & values.keys():
        raise EnvironmentError("Variable defined in both paths and values")
    bindings = {**paths, **values}
    for key, value in bindings.items():
        if not NAME.fullmatch(key) or key in {"NANHAI_ENV_FILE", "NANHAI_ENV_CONFIG_SHA256"}:
            raise EnvironmentError(f"Invalid or reserved variable: {key}")
        if not isinstance(value, str) or not value or any(c in value for c in "\0\r\n"):
            raise EnvironmentError(f"Invalid value for {key}")
    path_audit = {}
    for key, value in paths.items():
        path = Path(value)
        if not path.is_absolute():
            raise EnvironmentError(f"{key} must be an absolute path in local_env.md")
        if not path.exists():
            raise EnvironmentError(f"{key} is missing: {value}")
        path_audit[key] = {"path": value, "resolved": str(path.resolve()), "symlink": path.is_symlink()}
    links = config.get("links", [])
    if not isinstance(links, list):
        raise EnvironmentError("links must be a list")
    for link in links:
        if not isinstance(link, dict) or set(link) != {"link", "target"}:
            raise EnvironmentError("Each link must name a link and target variable")
        if link["link"] not in paths or link["target"] not in paths:
            raise EnvironmentError("Link refers to an undefined path variable")
        alias, target = Path(paths[link["link"]]), Path(paths[link["target"]])
        if not alias.is_symlink() or alias.resolve() != target.resolve():
            raise EnvironmentError(f"Source pool alias mismatch: {link['link']}")
    digest = hashlib.sha256(json.dumps(config, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    bindings.update(NANHAI_ENV_FILE=str(document), NANHAI_ENV_CONFIG_SHA256=digest)
    return bindings, {"document": str(document), "config_sha256": digest, "paths": path_audit,
                      "path_count": len(paths), "value_count": len(values), "links_checked": len(links)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", type=Path, help="Another worktree's local_env.md")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="Validate configured paths and source aliases")
    mode.add_argument("--shell", action="store_true", help="Emit quoted exports for bash or zsh")
    mode.add_argument("--json", action="store_true", help="Emit the active variable mapping")
    mode.add_argument("--run", nargs=argparse.REMAINDER, help="Run argv directly with authoritative bindings")
    args = parser.parse_args(argv)
    try:
        bindings, audit = load_environment(args.file)
        if args.check:
            print(json.dumps({"status": "paths_verified", **audit}, ensure_ascii=False, indent=2))
        elif args.shell:
            for key, value in bindings.items():
                print(f"export {key}={shlex.quote(value)}")
        elif args.json:
            print(json.dumps(bindings, ensure_ascii=False, indent=2))
        else:
            if not args.run:
                raise EnvironmentError("--run requires a command")
            if bindings.get("NANHAI_CONTAINER_POLICY") == "forbidden":
                command = Path(args.run[0]).name.lower()
                if command in {"docker", "podman", "nerdctl", "buildah", "runc", "crun", "nsjail", "proot"}:
                    raise EnvironmentError(f"Container or namespace launcher forbidden by current project policy: {command}")
                if "run" in args.run and any("stock-bionic-target-graph-" in item and
                                             item.endswith("/executor.py") for item in args.run):
                    raise EnvironmentError("Historical container graph executor is revoked by current project policy")
            environment = os.environ.copy()
            # The selected document wins over stale bindings inherited from a shell.
            for key in list(environment):
                if key.startswith("NANHAI_"):
                    del environment[key]
            environment.update(bindings)
            return subprocess.run(args.run, env=environment).returncode
        return 0
    except (EnvironmentError, OSError, json.JSONDecodeError) as error:
        print(f"nanhai environment: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
