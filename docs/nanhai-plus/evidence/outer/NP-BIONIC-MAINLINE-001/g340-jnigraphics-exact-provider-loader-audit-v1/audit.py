#!/usr/bin/env python3
"""Read-only exact R4 libjnigraphics source/product/local-artifact audit."""

import hashlib
import json
import os
from pathlib import Path
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(*argv):
    result = subprocess.run(argv, text=True, capture_output=True, check=False)
    return {"argv": list(argv), "rc": result.returncode,
            "stdout": result.stdout.strip(), "stderr": result.stderr.strip()}


def main():
    source_pool = Path(os.environ["NANHAI_SOURCE_POOL_ROOT"])
    workspace = Path(os.environ["NANHAI_R4_WORKSPACE_ROOT"])
    out = Path(os.environ["NANHAI_OUT_ROOT"])
    source_index = source_pool / "SOURCES.json"
    indexed = json.loads(source_index.read_text())
    repository = workspace / "android-source/frameworks-base-r4-45034f0"
    relative = "AOSP-16.0.0_r4/android-source/frameworks-base-r4-45034f0"
    matches = [repo for entry in indexed["entries"] for repo in entry.get("repositories", [])
               if repo.get("path") == relative]
    if len(matches) != 1:
        raise ValueError("exact R4 frameworks/base registry entry not unique")
    entry = matches[0]
    paths = ["native/graphics/jni/Android.bp", "native/graphics/jni/bitmap.cpp",
             "native/graphics/jni/imagedecoder.cpp", "native/graphics/jni/libjnigraphics.map.txt"]
    files = [{"relative": name, "sha256": digest(repository / name)} for name in paths]
    head = run("git", "-C", str(repository), "rev-parse", "HEAD")
    dirty = run("git", "-C", str(repository), "status", "--porcelain", "--", *paths)
    if head["rc"] != 0 or head["stdout"] != entry["head"] or dirty["rc"] != 0 or dirty["stdout"]:
        raise ValueError("exact R4 source head or file cleanliness mismatch")
    blueprint = (repository / paths[0]).read_text()
    if 'name: "libjnigraphics"' not in blueprint or '"libhwui"' not in blueprint:
        raise ValueError("expected module source contract absent")
    target_plan = Path("docs/nanhai-plus/tool-records/flutter-libjnigraphics-n1/targets/oh7.0.0.39-aosp16r4-arm64-bionic/plan.json")
    plan = json.loads(target_plan.read_text())
    if plan["decision"] != "replace":
        raise ValueError("current Bionic tool disposition changed")
    product_inputs = workspace / "product-config/r4-selected"
    product_files = sorted(path for path in product_inputs.rglob("*") if path.is_file() and path.suffix in {".mk", ".bp"})
    product_mentions = [str(path.relative_to(product_inputs)) for path in product_files
                        if "libjnigraphics" in path.read_text(errors="replace")]
    bionic_root = out.parent
    artifact_paths = sorted(str(path.relative_to(bionic_root)) for path in bionic_root.rglob("libjnigraphics.so")
                            if path.is_file())
    result = {"schema": "g340-jnigraphics-exact-provider-loader-audit-v1",
              "target": "OH7.0.0.39 / android-16.0.0_r4 / ARM64 / App single Bionic",
              "scope": "local host read-only source/product/output index; no remote product or device",
              "source_index_sha256": digest(source_index),
              "registered_repository": {"relative": relative, "head": entry["head"],
                                        "kind": entry.get("kind"), "build_accepted": entry.get("build_accepted")},
              "git_head_rc": head["rc"], "git_head": head["stdout"],
              "source_files_clean": dirty["stdout"] == "", "source_files": files,
              "soong_definition_observed": True,
              "soong_module_name": "libjnigraphics",
              "soong_android_shared_dependencies": ["libhwui", "liblog", "libandroid"],
              "local_product_config_mk_bp_files_scanned": len(product_files),
              "product_config_explicit_name_mentions": product_mentions,
              "bionic_project_local_same_name_so_count": len(artifact_paths),
              "bionic_project_local_same_name_so_paths": artifact_paths,
              "bionic_tool_plan": {"path": str(target_plan), "sha256": digest(target_plan),
                                    "decision": plan["decision"], "state": plan["state"],
                                    "build_ready": plan["build"]["ready"],
                                    "source_build_accepted": plan["source_build_accepted"]},
              "provider_artifact_verified": False,
              "soname_abi_exports_verified": False,
              "loader_search_order_verified": False,
              "decision": "NO_GO_PROVIDER_AND_LOADER_UNPROVEN",
              "device_commands": 0, "remote_commands": 0, "container_commands": 0}
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
