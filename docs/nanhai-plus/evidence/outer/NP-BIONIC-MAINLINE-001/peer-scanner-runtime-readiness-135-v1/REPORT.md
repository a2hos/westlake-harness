# Scanner readiness for the frozen 135-APK host-static inventory

**Decision: inventory ready; target-runtime resolution blind.** The frozen checkpoint (`acf2e9821c2c864ee6e6d9d54cfb8ccf461980aa531378f9ac201fe6c9fa974f`) records 135 accepted four-phase host-static APKs, 546 semantic DEX entries, and 2,103 true ARM64 packaged ELF entries. It also records no observed R4 graph result and zero cold starts. One root-admitted PContacts raw/static receipt pair was independently cross-checked as a sample, not as a re-audit of all 135 packages.

| Can use now | Must remain blind or unknown |
| --- | --- |
| Exact APK SHA-guarded ZIP/manifest/DEX and packaged ARM64 ELF inventory; local declared symbols, `DT_NEEDED`, JNI names and ABI exposure as static candidates. | `scan`/`benchmark` missing class, method and field conclusions against the intended R4 boot classpath; JNI provider/binding or native import resolution against the actual Bionic/system ELF set; dynamic loading, reachability, installation and cold start. |

The CLI's `scan` requires a full runtime JSON (`--runtime`), and `scan_apk` constructs `RuntimeResolver(runtime)`. `snapshot-runtime` first requires **ordered** BCP JAR paths; `build_runtime_index` derives its `runtime_lock_id` from ordered BCP SHA-256 values, bridge ELF SHA-256 values, system ELF SHA-256 values, and target ABI. A `runtime-summary` lacks the class definitions needed for member resolution. The scanner explicitly emits `O-BLIND` for native-import coverage when the runtime system-library index is absent. Supplying an empty or historical runtime would therefore produce misleading target findings.

Read-only checks found none of `core-oj.jar`, `libart.so`, `libc.so`, or `runtime-lock.json` under the registered `NANHAI_OUT_ROOT`. The five historical benchmark runtime locks inspected all lack system ELFs; their BCP paths refer to historical Bridge/WestLake roots or relative names, and one targets ARMv7. Their mere `runtime_lock_id` values do not establish this project's R4/Bionic content provenance. Source identity and static graph drafts likewise do not establish built provider content.

The minimal next step is to obtain a verified native R4/Bionic build result and freeze the same-build ordered BCP JARs plus ARM64 bridge and system ELF SHA-256 values, including ABI and build/source provenance. Generate `snapshot-runtime` into project-independent output, preserve the **full index** and runtime lock, independently review it, then pilot `scan` on one frozen APK before any 135-way `benchmark`. Until then, keep provider comparisons `blind/unknown`; no static exposure is a startup wall.

Replay command from project root:

```sh
python3 -B scripts/nanhai_plus_env.py --run python3 -B docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/peer-scanner-runtime-readiness-135-v1/check.py > docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/peer-scanner-runtime-readiness-135-v1/RESULT-v2.json
```

Replay rc 0; `RESULT-v2.json` SHA-256 `93def4173c103d5ef4fadc04c4a8c56b6735f8b618a4d3e8fdf5a3498c7c98d0`. The first exploratory `RESULT.json` was retained (rc 2): its historical-lock guard wrongly assumed every old BCP path began with `${WESTLAKE_RUNTIME_ROOT}`. Inspection showed `${BRIDGE_ARM64}` and relative paths too; v2 checks the actual common disqualifier, absent system ELF indexes. This evidence queried no device or container and changed no canonical state, source tree, Bridge, or runtime output.
