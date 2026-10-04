# WestLake Task Handoff — Proton Meet complete static inventory candidate

## Boundary
- Boundary: Package/Resource and Device/Tooling, host static APK evidence only.
- Android behavior: Scan all ZIP members and CRC, classify native members by verified bytes, and run the original pinned harness metadata, ELF and DEX scanners.
- OpenHarmony mapping: OH7.0.0.39 / AOSP16 r4 / ARM64 App Bionic is the target; no OH runtime or device command was issued.
- Fix layer: Isolated candidate evidence only; no shared scanner, accepted raw receipt, authority count, Bridge or G275 control change.

## Evidence target
- What this proves: Exact root-accepted Proton Meet APK has a 2,716-member complete ZIP CRC scan, one root manifest, 16 root DEX, and 45 real ELF entries across three ABIs: 15 ARM64, 15 armeabi-v7a and 15 x86_64. No ZIP-in-SO or unclassified native entry was observed. The original harness scanners returned package, DEX and ELF records that match independent ZIP member SHA/bytes.
- What this does not prove: Independent/root static admission, full gap compatibility, qualifying overseas mainstream blackbox status, installation, cold launch, device pass, or any Bionic tool completion.

## Environment
- Host: macOS through `scripts/nanhai_plus_env.py`, pinned `harness-python-v1` venv, 21 source SHA pins and qualified OH SDK readelf alias.
- Device: None; exclusions and HOLD retained.
- Tool path: Exact venv/readelf paths and hashes in `INPUTS.json`; each child command, timeout, rc and stream hashes in `phases/*/COMMAND.json`.
- Artifact path: `NANHAI_EVIDENCE_ROOT/outer/NP-BIONIC-MAINLINE-001/harness-protonmeet-inventory-candidate-v1`.
- App: `proton.android.meet`, 1.2.2 / code 131, raw SHA `981fd735cef19a87890b7c17c10a506600f519b59a4dcc20fd2144b198b3b7a9`.

## Status
- Label: `build_pass=false`; `stub=false`; `real_impl=not_assessed`; `device_verified=false`.
- Why: Host static candidate only. The outer authority stays at 72 accepted static rows pending independent and root review.

## Observed wall
- Classification: none
- Fact: One outer attempt returned rc0 in 79.42 seconds, with ZIP/metadata/ELF/DEX children rc0 in 1.89/0.55/50.53/23.84 seconds. No scanner error or device wall was observed.
- Evidence: `RESULT.json`, `phases/*/{COMMAND,RESULT}.json`, raw stdout/stderr, `ZIP-FACTS.json`, `MANIFEST.json`, `ELF-INVENTORY.json`, `DEX-INVENTORY.json` and source guard receipts.
- First failing command: None.
- Exit/status: Outer rc0, four child rc0, 9/9 aggregate checks true; per-child process-group watchdog 120/180/600/600 seconds, outer budget 1,350 seconds, no retries.

## Hypotheses
- Candidate: Full runtime compatibility may still depend on Android services and native symbols not exercised by this host static inventory.
- Cheapest falsifier: Use the accepted row to plan exact, cold runtime experiments after architecture and device gates.
- Blocking: no

## Proven
- The exact accepted raw SHA/bytes and root acceptance receipt are pinned. Full source/APK/venv/readelf guards match before and after.
- ZIP has 2,716 unique entries and all pass CRC; exactly one root Manifest. All 16 root DEX headers have valid DEX magic/declared size and independent SHA/bytes matching original scanner records.
- All 45 `lib/*/*.so` entries have real ELF magic/class/machine for their named ABI; the original scanner returns matching member SHA/bytes and `readelf_ok=true`, `abi_matches_machine=true`, no scan errors. Of those, 15 are ARM64. Zero ZIP-in-SO and zero unknown `.so` content.
- Original metadata scanner reports `proton.android.meet` / `1.2.2` and exact accepted payload SHA/bytes. `RESULT.json` marks no startup, blackbox qualification, device command or authoritative count mutation.

## Not proven
- Root acceptance of the static row, complete Android API gap resolution, split-set install closure, overseas mainstream qualification, launch or device behavior.
- Static references and native imports are candidates; they do not establish an active runtime call path.

## Failed
- None in this candidate. A Python compile preflight produced local bytecode cache files, which were removed from this candidate directory before READY sealing; no input or execution receipt was altered.

## Next evidence
- Command: Independent peer rehash exact raw APK, root raw acceptance, the four terminal command/stream receipts, all ZIP members and the 16 DEX/45 ELF SHA identities against `RESULT.json`; then root may admit exactly one static row.
- Expected output: One package, 16 DEX, 45 true ELF including 15 ARM64, zero ZIP-in-SO, all guards equal, no runtime or device count delta.
- If it fails: Keep this as candidate and preserve authoritative static count 72.

## Shim/stub/bypass inventory
- Item: None in runtime. Isolated host scanner orchestrator only.
- Owner: This static lane prepares candidate; outer root owns admission.
- Why it exists: The 262 MB original APK contains 45 multi-ABI ELF and 16 DEX entries, so stage budgets and complete member checks are required.
- Removal condition: Retire candidate orchestrator only after review; retain immutable receipts.
- Test coverage: Four terminal phases, 9 aggregate checks, exact source/raw/venv/tool guards, full CRC and per-member SHA/bytes cross-check.
- App-specific or common: Input is one Proton Meet APK; classification approach is generic but not promoted.

## Memory/skill/CI/review updates
- Memory: No write.
- Skill: Applied `westlake-engineering-discipline` evidence separation.
- CI: No shared CI change.
- Review checklist: Verify root raw acceptance SHA, all four child rc0 and no timeout, 2,716/2,716 CRC, 16 DEX and 45 true ELF SHA identity, 15 ARM64, no ZIP-in-SO, source guard equality, no authority/device/blackbox claim.
