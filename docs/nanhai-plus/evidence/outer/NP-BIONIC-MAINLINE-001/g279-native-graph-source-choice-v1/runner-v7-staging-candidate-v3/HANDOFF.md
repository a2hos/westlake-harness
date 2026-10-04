# WestLake Task Handoff

## Boundary
- Boundary: Device/Tooling, local project authority to gz02 project control input.
- Android behavior: None exercised; v7 runner bytes are a graph control input.
- OpenHarmony mapping: None exercised.
- Fix layer: Host staging protocol only.

## Evidence target
- What this proves: v7 exact SHA/size/mode is locally pinned; one-shot UNKNOWN precedes transport; local fixtures demonstrate no automatic pathname cleanup after partial write or concurrent replacement.
- What this does not prove: Real gz02 staging, original owner graph authorization, EVO19 v7 preflight, Soong graph, target compile, APK or device result.

## Environment
- Host: Local macOS fixture; intended remote gz02 not contacted.
- Device: None.
- Tool path: `scripts/nanhai_plus_stage_runner_v7_candidate_v3.py`.
- Artifact path: `runner-v7-staging-candidate-v3/STATIC-CANDIDATE.json`.
- App: None.

## Status
- Label: stub
- Why: `--stage` remains rc3; injected local fixtures cannot mutate gz02.

## Observed wall
- Classification: observed
- Fact: v2 peer found stat-then-unlink race; v7 graph peer found same-writer JSON cannot authenticate original owner.
- Evidence: `runner-v6-staging-candidate-v2/peer-review-v1/REVIEW.json` and `runner-v7-graph-candidate-v1/peer-review-v1/REVIEW.json`.
- First failing command: `python3 -B scripts/nanhai_plus_stage_runner_v7_candidate_v3.py --stage`.
- Exit/status: rc3, `NO_GO_STAGING_UNRELEASED`.

## Hypotheses
- Candidate: Direct O_EXCL final creation plus UNKNOWN/read-only reconciliation removes the v2 cleanup race at the cost of leaving a partial file after failure.
- Cheapest falsifier: Independent static review and local injected partial-write/replacement fixtures, then separate bounded remote read-only inspection before any actual stage.
- Blocking: no

## Proven
- Ten local fixtures passed; injected partial write and concurrent replacement preserve the path for read-only reconciliation.
- Current `local_env.md` binding and exact v7 runner SHA/size/mode pass static check; stage CLI rc3.

## Not proven
- Actual remote owner/path state; no SSH or staging performed.
- Original owner graph ACK provenance; separate plan explains the required independent session witness and authorization boundary.

## Failed
- No remote action failed. Local `--stage` denial is intentional.

## Next evidence
- Command: Different peer reviews candidate script/fixture and `OWNER-GRAPH-ACK-PROVENANCE.md`; only after graph release chain is independently resolved, consider a separately authorized one-shot stage.
- Expected output: Exact reviewed SHA and no automatic path cleanup; status remains staging-only.
- If it fails: Keep UNKNOWN and reconcile remote destination read-only; do not blindly retry or execute runner.

## Shim/stub/bypass inventory
- Item: `--stage` hard-close.
- Owner: Nanhai Plus outer control.
- Why it exists: Prevent unreviewed remote mutation.
- Removal condition: Separate independent peer GO and one-shot release authorization for exact v7 bytes.
- Test coverage: rc3 CLI and ten local fixtures.
- App-specific or common: Common host control.

## Memory/skill/CI/review updates
- Memory: No update requested.
- Skill: Followed WestLake evidence separation.
- CI: Local fixture only.
- Review checklist: Verify no generated remote `unlink`, exact v7 bytes, env authority, UNKNOWN before transport, one-shot retry block, and owner provenance not inferred from remote JSON.
