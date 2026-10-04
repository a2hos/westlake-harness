# WestLake Task Handoff — G279 stage 3 binding-switch candidate

## Boundary
- Boundary: Tooling and Security, local config binding proposal and owner-intent provenance only.
- Android behavior: none executed or changed.
- OpenHarmony mapping: none executed or changed.
- Fix layer: local control packet; no runtime or graph code in this package.

## Evidence target
- What this proves: exact old/proposed local env SHA, three-value diff, proposed remote binding relation, stage-2 local terminal consistency and independent stage-2 postrun acceptance were checked without writing.
- What this does not prove: new runner readiness, original-owner graph ACK, active local switch, graph or device result.

## Environment
- Host: local macOS read-only checker; stage-2 terminal refers to gz02.
- Device: none; device HOLD remains.
- Tool path: `stage3-binding-switch-candidate-v1/readonly_check.py` only.
- Artifact path: `stage3-binding-switch-candidate-v1/STAGE3-PACKET.json`, `OWNER-GRAPH-REQUEST-TEMPLATE.json`, `SWITCH-PLAN.md`, `CHECK.json`.
- App: none.

## Status
- Label: real_impl.
- Why: a read-only packet checker exists and passed; the switch executor, new graph runner and owner request remain absent.

## Observed wall
- Classification: not_reached
- Fact: the local binding switch and graph were not invoked by this packet.
- Evidence: checker output `CONSISTENT_WAIT_EXTERNAL_GATES` with local binding changed false and remote commands zero.
- First failing command: none; no switch or graph command issued.
- Exit/status: read-only checker rc 0; switch and graph not_reached.

## Hypotheses
- Candidate: no runtime cause asserted; new exact runner and original owner intent are pending independent evidence.
- Cheapest falsifier: inspect the new runner/owner packet before considering a switch.
- Blocking: no

## Proven
- `readonly_check.py` returned rc 0 and found exactly three proposed machine-readable value changes.
- The proposed future config SHA is `a4e742576589390209188cddf8d3278c294d9e87e8e9c4733e15eee0a951ddba`; the new remote binding SHA is `9157f7d3e719c2fe1d2186bb79095500572049c4b7a3bc8d3befbdb98d47ae2f`.
- The old active config remains `5ce3a58541ef1711890aad8348c3a31a03203f584fa50f1f5c0cb4fd88b49718`. The G279 stock graph TOP remains the full R4 checkout; the 46-link view is for host Soong UI and partial diagnostics.
- Independent stage-2 postrun REVIEW SHA `78d51ad3d3ae1c181cfc3619e428b793ad09b2d3d0ac897e2a415cc9668fb7ca` accepts staged bytes and confirms the active binding stayed old.

## Not proven
- Original-session owner graph-only ACK, new runner/gate exact identity, local switch, native graph, target or device behavior.

## Failed
- No command failed in this stage-3 read-only preparation. The old v7 graph-intent template is path-bound to the old root and cannot serve the future config.

## Next evidence
- Command: `python3 stage3-binding-switch-candidate-v1/readonly_check.py` and independent review of the future new runner/owner request when formed.
- Expected output: `CONSISTENT_WAIT_EXTERNAL_GATES` until a separately frozen new runner and original-session ACK exist.
- If it fails: retain active old binding and diagnose the exact SHA/field mismatch; do not switch or replay receipts.

## Shim/stub/bypass inventory
- Item: none introduced.
- Owner: G279 migration packet author.
- Why it exists: no shim, stub or bypass is used by this read-only packet.
- Removal condition: none.
- Test coverage: read-only checker verifies local byte/digest and terminal relationships; no remote or graph test claim.
- App-specific or common: host control only.

## Memory/skill/CI/review updates
- Memory: no update requested or written.
- Skill: WestLake handoff contract fields filled with host-only/not_reached values.
- CI: none changed; local checker and gate only.
- Review checklist: compare packet and template SHA, stage-2 independent postrun, new full-R4-TOP runner SHA/readback, original-session JSONL ACK provenance, and separate trust-bound graph release before any local switch or graph.
