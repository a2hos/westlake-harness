#!/usr/bin/env python3
"""Read-only, receipt-bound disposition trial for frozen batch12-v2."""
import hashlib
import json
import pathlib
import zipfile

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[3]
BATCH = ROOT / "docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/harness-stock-inventory-batch12-v2"
RUN = BATCH / "runtime-result/packages"


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def disposition(fact, result, failed_elf_check=False, prefix=None):
    if fact.get("timed_out") is True and fact.get("process_rc") == -9:
        return "TIMEOUT_PARTIAL_ONLY"
    if (fact.get("process_rc") == 2 and not fact.get("timed_out")
            and failed_elf_check and prefix is not None and prefix != b"\x7fELF"):
        return "SO_SUFFIX_NON_ELF_UNRESOLVED"
    if (fact.get("process_rc") == 0 and not fact.get("timed_out")
            and fact.get("complete_static_inventory_candidate") is True
            and result.get("rc") == 0):
        return "COMPLETE_CANDIDATE_RECEIPT_ONLY"
    return "UNRESOLVED"


def main():
    inputs = json.loads((BATCH / "INPUTS.json").read_text())
    rows = []
    for item in inputs["apks"]:
        name = item["registry_package_label"]
        folder = RUN / name
        fact = json.loads((folder / "FIELD-FACTS.json").read_text())
        result_path = folder / "RESULT.json"
        result = json.loads(result_path.read_text()) if result_path.exists() else {}
        checks_path = folder / "CHECKS.json"
        checks = json.loads(checks_path.read_text()) if checks_path.exists() else []
        failed = [x["id"].split(":", 1)[1] for x in checks
                  if x["id"].startswith("elf_header:") and x["pass"] is False]
        prefix = None
        if len(failed) == 1:
            apk = ROOT / item["path"]
            assert apk.stat().st_size == item["bytes"] and digest(apk) == item["sha256"]
            with zipfile.ZipFile(apk) as archive:
                assert archive.namelist().count(failed[0]) == 1
                with archive.open(failed[0]) as member:
                    prefix = member.read(4)
        label = disposition(fact, result, bool(failed), prefix)
        rows.append({"package": name, "class": label, "rc": fact["process_rc"],
                     "timed_out": fact["timed_out"], "failed_elf_entry": failed,
                     "member_prefix_hex": prefix.hex() if prefix is not None else None})
    # Negative: a suffix alone cannot pass without a failed check and verified non-ELF bytes.
    seal = next(x for x in rows if x["package"] == "com.junkfood.seal")
    sf = json.loads((RUN / "com.junkfood.seal/FIELD-FACTS.json").read_text())
    negatives = {
        "suffix_without_failed_check": disposition(sf, {}, False, bytes.fromhex(seal["member_prefix_hex"])),
        "suffix_with_elf_magic": disposition(sf, {}, True, b"\x7fELF"),
        "timeout_without_kill_rc": disposition({"timed_out": True, "process_rc": 0}, {}),
        "partial_rc0_without_complete_flag": disposition({"timed_out": False, "process_rc": 0}, {"rc": 0}),
    }
    assert [x["class"] for x in rows].count("COMPLETE_CANDIDATE_RECEIPT_ONLY") == 2
    assert [x["class"] for x in rows].count("SO_SUFFIX_NON_ELF_UNRESOLVED") == 1
    assert [x["class"] for x in rows].count("TIMEOUT_PARTIAL_ONLY") == 1
    assert set(negatives.values()) == {"UNRESOLVED"}
    print(json.dumps({"rows": rows, "negatives": negatives}, indent=2))


if __name__ == "__main__":
    main()
