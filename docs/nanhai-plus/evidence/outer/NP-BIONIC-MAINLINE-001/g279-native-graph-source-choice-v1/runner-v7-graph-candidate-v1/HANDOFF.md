# WestLake Task Handoff

## Boundary
- Boundary: Device/Tooling and Bionic native graph generation on gz02.
- Android behavior: Generate AOSP16 R4 ARM64 Bionic libc/libm/libdl/linker Soong graph only.
- OpenHarmony mapping: None in this graph step.
- Fix layer: Project-owned native host runner, separate from App and device behavior.

## Evidence target
- What this proves: Static candidate has a reachable graph-only `--run` after exact EVO19 receipt, outer release and original-owner ACK validation; v7 OUT/TMP/control paths are distinct from v6.
- What this does not prove: Release files exist, original owner signed them, Linux child cleanup/seccomp inheritance has runtime proof, graph succeeds, target compiles, APK starts, or device passes.

## Environment
- Host: Local macOS static fixtures; intended graph host gz02 is untouched.
- Device: None.
- Tool path: `scripts/nanhai_plus_native_graph_v7.py`.
- Artifact path: `runner-v7-graph-candidate-v1/STATIC-CANDIDATE.json`.
- App: None.

## Status
- Label: stub
- Why: The current environment lacks v7 staged runner, EVO19 receipt, outer release and original-owner graph ACK. No real graph path was executed.

## Observed wall
- Classification: observed
- Fact: Local `--run` fails the native host release gate with rc3 before graph dispatch.
- Evidence: Captured `run_denial.stdout` and `run_denial.stderr` in this candidate directory.
- First failing command: `python3 -B scripts/nanhai_plus_native_graph_v7.py --run`.
- Exit/status: rc3, `NO_GO_GRAPH_RELEASE_GATE`.

## Hypotheses
- Candidate: Exact staged v7 runner plus separately reviewed EVO19, outer release and original-owner ACK could permit one graph-only attempt.
- Cheapest falsifier: Independent static peer review of this SHA and synthetic gate fixtures, then read-only remote identity and separate owner ACK.
- Blocking: no

## Proven
- Static check rc0; local host `--run` rc3 before graph.
- Local synthetic fixtures prove exact three-document binding and reject missing owner ACK, failed EVO19 SSH rc, changed runner bytes and target compile authorization.
- Graph argv retains `--soong-only --skip-ninja --skip-soong-tests`; target compiler trace observation prevents graph acceptance.

## Not proven
- Actual external authorization provenance of release/owner documents; JSON fields alone cannot authenticate a signer.
- Remote v7 staging, execution-adjacent byte handoff, actual seccomp inheritance, complete descendant cleanup, Soong graph artifact, recursive subninja generated-action closure.

## Failed
- No real graph attempt. Local `--run` denial is intentional; no remote failure was observed.

## Next evidence
- Command: Independently review v7 source SHA and release packet contract, then obtain distinct outer release and original-owner graph ACK for this exact runner; read back remote v7 runner and all EVO19 inputs before one graph-only attempt.
- Expected output: Matching immutable receipts and explicit graph-only authorization; actual graph output remains a separate later result.
- If it fails: Keep graph NO_GO, retain exact failed receipt, and reconcile read-only before any retry.

## Shim/stub/bypass inventory
- Item: None added. The no-namespace seccomp guard is a preexisting host tool candidate.
- Owner: Nanhai Plus outer control and independent guard reviewer.
- Why it exists: Deny namespace/mount/chroot during native graph invocation.
- Removal condition: Not applicable; runtime behavior still needs evidence.
- Test coverage: Prior host-tool smoke only; v7 did not execute it.
- App-specific or common: Common host build control.

## Memory/skill/CI/review updates
- Memory: No update requested.
- Skill: Followed WestLake evidence separation.
- CI: Local fixture only; no graph CI run.
- Review checklist: Verify exact runner SHA and mode, outer/owner provenance, EVO19 readback, new OUT/TMP/control isolation, no generated Ninja execution, and Linux cleanup/guard behavior before release.
