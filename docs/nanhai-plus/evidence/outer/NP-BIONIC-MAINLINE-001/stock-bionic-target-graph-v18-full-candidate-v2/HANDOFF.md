# G274/v18 full executor candidate v2

This is a fresh, single-use **candidate**, not an execution release. It extends the accepted G273 graph executor while retaining its offline image, private volume/container lifecycle, 600-second stock command bound, output archive oracles, and owned-resource cleanup. The original 29 source roots and complete SDK guard remain active. The G274 input contributes nine exact `android-16.0.0_r4` read-only source roots (38 total), four additional exact-identity overlaps, and 13 original links; 12 resolve to qualified targets and one original `frameworks/native` link remains dangling. The frozen G273 files are untouched.

`executor.py check-candidate` performs metadata and predecessor checks without Docker. `executor.py run` accepts no arbitrary command. Before creating Docker resources and after cleanup/export, it rehashes the old complete source/SDK set and all 85,499 new source entries, then requires byte-identical pre/post guard results. The stock Linux container must show exactly nine new read-only binds and the qualified link table bind. A mismatch is terminal, not graph success. Stock shell bytes remain the G273 accepted bytes.

The v2 output oracles derive an exact allowlist from the old 29-root manifest, the 18,023 private materialization entries, and the nine SHA-bound G274 JSONL manifests. Four exact overlaps are counted once; 85,495 new stock paths are admitted. The release-map, product finder, and Blueprint finder checks use this common allowlist and reject every unlisted path. Each oracle invocation rehashes the bound manifest identities; no process-global allowlist cache or directory-prefix wildcard is admitted. An isolated second-call manifest-drift test and a synthetic graph with one qualified and one unlisted Blueprint path verify the boundary. The v1 candidate is preserved unchanged.

The one-shot `run` path requires a root-sealed G274 packet in this directory, the original active `NP-MUSL16-ART-024` claim, a new original `nanhai-plus/octos-inner` owner ACK covering the candidate, G273 terminal review and every bound project input, and matching nonce/generation/release 274. No such packet or ACK is included here. The candidate remains blocked from execution until independent review, root review, fresh original-owner ACK and root seal. It must not be launched based only on this handoff, static checks, or the G274 source admission.

No Docker, graph, target compile, device or APK command was run to prepare this candidate. Prior G273 result is rc2 at the Soong 240/240 undefined-module wall; ARM64 target compilation remains zero. Large source/build payloads stay outside this project input view.

## Boundary
- Boundary: Bionic host source-graph input, read-only AOSP16 R4 source view; no App runtime or OH client ABI claim.
- Android behavior: Preserve exact stock Soong module definitions and original symlink payloads.
- OpenHarmony mapping: OH7.0.0.39 target is recorded but not run by this candidate.
- Fix layer: Source-view and one-shot host executor orchestration.

## Evidence target
- What this proves: Candidate wiring, exact source/SDK static guards, and refusal before fresh owner release.
- What this does not prove: Graph success, ARM64 target compilation, APK cold start, or device verification.

## Environment
- Host: Project host with `local_env.md` loaded through `scripts/nanhai_plus_env.py`.
- Device: None accessed; device HOLD and whitelist remain in force.
- Tool path: This directory's `executor.py`, accepted G273 executor, and v18 extension.
- Artifact path: This directory's `PACKET-CANDIDATE.json`, `READY.json`, `STATIC-CHECK.json`, and `oracle_policy.py`.
- App: HelloWorld is downstream and was not launched.

## Status
- Label: build_pass=false; stub=false; real_impl=false; device_verified=false.
- Why: Only metadata and read-only source guards ran; no stock graph or target compile ran.

## Observed wall
- Classification: not_reached
- Fact: G274 run path requires independent review, fresh original-owner ACK and root seal; these are not present in this candidate.
- Evidence: `PACKET-CANDIDATE.json` has null release fields; `STATIC-CHECK.json` records zero Docker commands.
- First failing command: None; G274 graph execution intentionally not attempted.
- Exit/status: Static check rc0; graph status not reached.

## Hypotheses
- Candidate: Additional Soong undefined modules may remain after nine R4 roots are mounted.
- Cheapest falsifier: Freshly sealed G274 one-shot stock graph result and exact first diagnostic.
- Blocking: no

## Proven
- Metadata validation, complete old and new source/SDK read-only guard, and nine added stock bind arguments passed static checks.

## Not proven
- Linux mount inspection, materialized stock graph, ARM64 build, App startup and device behavior.

## Failed
- No implementation command failed; initial handoff gate failed due absent sections and was corrected before candidate freeze.

## Next evidence
- Command: After independent/root review, original-owner ACK and seal, run the single-use `executor.py run` through the authorized owner path.
- Expected output: Fresh `runtime-result/RESULT.json` with pre/post source and SDK guards, mount inspection, exact first wall or graph pass, and owned-resource cleanup.
- If it fails: Keep rc/log/archive receipts immutable; do not replay the package; prepare a new candidate from the observed first wall.

## Shim/stub/bypass inventory
- Item: None added.
- Owner: Outer coordinator.
- Why it exists: Not applicable.
- Removal condition: Not applicable.
- Test coverage: Static guard and negative writable-bind test; no runtime coverage.
- App-specific or common: Common host build input view.

## Memory/skill/CI/review updates
- Memory: No memory export requested or performed.
- Skill: WestLake engineering discipline gate applied.
- CI: No CI promotion; static local check only.
- Review checklist: Independent peer must inspect the full executor and release gates before root seal.
