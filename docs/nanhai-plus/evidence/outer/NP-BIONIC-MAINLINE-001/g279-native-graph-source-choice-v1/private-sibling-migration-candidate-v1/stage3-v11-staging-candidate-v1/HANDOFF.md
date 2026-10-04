# WestLake Task Handoff — G279 v11 runner staging candidate

## Boundary
- Boundary: Tooling and Security, one exact host script staging operation only.
- Android behavior: none invoked; no Soong graph or target compilation.
- OpenHarmony mapping: none invoked.
- Fix layer: gz02 sibling project-control staging.

## Evidence target
- What this proves: local candidate pins accepted Stage1/2 directories and 14 exact input files, plus v11 runner SHA/45330 bytes/mode0444, and its isolated writer fixtures pass.
- What this does not prove: actual gz02 staging, new runner remote readback, active config switch, EVO19, owner ACK, graph or device result.

## Environment
- Host: local macOS fixture host; intended remote gz02 Linux x86_64 UID1000.
- Device: none; device HOLD remains.
- Tool path: `launcher.py` and `remote_body.py` in this candidate directory.
- Artifact path: `PACKET.json`, `FIXTURE.json`, and later one-shot START/TERMINAL only after independent release.
- App: none.

## Status
- Label: real_impl.
- Why: one-shot staging code and local fixtures exist; `--execute` has no independent release and was not run.

## Observed wall
- Classification: not_reached
- Fact: gz02 v11 staging was not invoked by this author.
- Evidence: fixture reports SSH 0 and remote writes 0; receipts directory absent.
- First failing command: none; no remote command was issued.
- Exit/status: local fixture rc0; remote staging not_reached.

## Hypotheses
- Candidate: no runtime cause asserted; first uncertainty is the fresh remote root/control/14-file identity at independent release time.
- Cheapest falsifier: peer review exact packet/program SHA and perform fresh gz02 read-only preflight.
- Blocking: no

## Proven
- Packet reconstructs exact accepted Stage1/2 evidence and local v11 static SHA `8b6484017d3679f4b14cde7c91e25a76f05289882fc390d3511180611714ffbe`.
- Temporary-tree fixture stages exact mode0444 file with readback and receipt, denies same-byte inode replacement before lease, and preserves lease/quarantine after injected partial failure.
- Unreleased `--execute` is denied before local START or SSH. The active local env remains the old root.

## Not proven
- Remote staged v11 inode/SHA/mode and peer postrun acceptance, future local config switch, native full-R4-TOP graph, target or device behavior.

## Failed
- No actual staging command failed; no actual staging command was issued.

## Next evidence
- Command: `python3 fixtures.py` from this directory, then independent review of `launcher.py`, `remote_body.py`, `PACKET.json` and fresh gz02 preflight.
- Expected output: local PASS and a separate `GO_V11_STAGING_ONCE` exact-SHA independent release if the remote preconditions remain intact.
- If it fails: keep the nonce unreleased and diagnose the changed identity; do not replay Stage1/2 or run graph.

## Shim/stub/bypass inventory
- Item: none introduced.
- Owner: G279 staging candidate author.
- Why it exists: no shim, stub or bypass is part of exact script staging.
- Removal condition: none.
- Test coverage: local writer success, staged-file substitution, quarantine and release denial; no Linux ACL or graph proof.
- App-specific or common: project control only.

## Memory/skill/CI/review updates
- Memory: no update requested or written.
- Skill: WestLake handoff contract used with host-only/not_reached values.
- CI: none changed; local fixture and py_compile only.
- Review checklist: verify stage1/2 source receipts, 14 exact file dev/inode/mode/size/SHA, sibling root/control/old/source-view identity, local old config, v11 runner SHA/bytes, host key, O_EXCL START/lease/receipt, quarantine/no-replay, and no graph path. Release staging separately from config switch and graph.

The sibling source-view is for host Soong UI/diagnostics. The eventual G279 stock graph TOP is the complete R4 checkout `/opt/19.SourceCode/AOSP-16.0.0_r4/android-source`.
