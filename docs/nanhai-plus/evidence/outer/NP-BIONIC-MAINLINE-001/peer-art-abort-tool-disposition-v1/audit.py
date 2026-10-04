"""Bounded read-only evidence audit for the one undetermined Bionic tool."""
import datetime
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[6]
OUT = Path(__file__).resolve().parent
CAT = ROOT / "docs/nanhai-plus/BIONIC-TOOLS.json"
PLAN = ROOT / "docs/nanhai-plus/tool-records/art-abort-bridge/targets/oh7.0.0.39-aosp16r4-arm64-bionic/plan.json"
SRC = Path("/opt/19.SourceCode/WestLake-Harness-eafec9451a91/source/bms/src/adapter/framework/appspawn-x/src/art_abort_message_bridge.cpp")
ART = Path("/opt/19.SourceCode/AOSP-16.0.0_r4/art")
APP = SRC.parent.parent

def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def search(name, root):
    argv = ["rg", "-n", "-g", "*.cc", "-g", "*.cpp", "-g", "*.h", "-g", "*.bp", "-g", "*.gn", "westlake_art_copy_fault_message_for_abort_logging|GetFaultMessageForAbortLogging|libwestlake_art_abort_bridge", str(root)]
    p = subprocess.run(argv, capture_output=True, text=True)
    (OUT / f"{name}.stdout.raw").write_text(p.stdout)
    (OUT / f"{name}.stderr.raw").write_text(p.stderr)
    return {"argv": argv, "rc": p.returncode, "stdout_sha256": sha(OUT / f"{name}.stdout.raw"), "stderr_sha256": sha(OUT / f"{name}.stderr.raw")}

catalog = json.loads(CAT.read_text())
plan = json.loads(PLAN.read_text())
assert catalog["audited"] == 89 and catalog["undetermined"] == 1
assert [r["id"] for r in catalog["rows"] if r["decision"] == "undetermined"] == ["art-abort-bridge"]
assert plan["decision"] == "undetermined" and not plan["accepted"]
result = {
    "schema": "peer-art-abort-tool-readonly-audit-v1",
    "at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "catalog_sha256": sha(CAT), "plan_sha256": sha(PLAN),
    "historical_source_sha256": sha(SRC),
    "r4_art_runtime_common_sha256": sha(ART / "runtime/runtime_common.cc"),
    "r4_art_runtime_h_sha256": sha(ART / "runtime/runtime.h"),
    "bounded_search": {"historical_appspawn": search("historical-appspawn", APP), "r4_art": search("r4-art", ART)},
    "catalog_undetermined": 1, "catalog_whole_tool_accepted": catalog["whole_tool_accepted"],
    "target_plan_state": plan["state"],
}
(OUT / "OBSERVATION.json").write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
