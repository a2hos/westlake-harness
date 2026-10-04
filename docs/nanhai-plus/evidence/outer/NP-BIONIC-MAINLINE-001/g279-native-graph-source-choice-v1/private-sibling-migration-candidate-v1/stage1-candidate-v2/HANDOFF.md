# G279 sibling stage 1 candidate v2

V2 supersedes the v1 launcher candidate for any later review. V1 source and static receipt remain historical. No release file exists, and no remote write was executed.

## Boundary
- Boundary: Tooling and Security on gz02 native host; create only the new sibling and its stage-1 files.
- Android behavior: No Android app, Soong graph, or target action is invoked.
- OpenHarmony mapping: No OH process, service, image, or device is invoked.
- Fix layer: Project host migration control; old root and source baselines remain unchanged.

## Evidence target
- What this proves: Local code compiles; frozen-plan static check and seven local fixtures pass, including durable START before SSH and same-nonce replay rejection.
- What this does not prove: New root on gz02, remote copy execution, graph generation, target compilation, or device behavior.

## Environment
- Host: Local macOS fixture process; future fixed gz02 SSH route has pinned ed25519 fingerprint `SHA256:RuAqHWgFJEIEcb4hC+WXULCRfV3uCsayP4Iw4aJvwzg`.
- Device: No device access in stage 1.
- Tool path: `scripts/nanhai_plus_g279_sibling_stage1_candidate_v2.py` sends `scripts/nanhai_plus_g279_sibling_stage1_remote_v1.py` through `/usr/bin/ssh` to `/usr/bin/python3.12` only after exact independent release.
- Artifact path: `docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g279-native-graph-source-choice-v1/private-sibling-migration-candidate-v1/stage1-candidate-v2/`.
- App: No APK or app command in this stage.

## Status
- Label: real_impl for the local candidate code only.
- Why: The remote write path is implemented and exercised on temporary local trees; gz02 execution is still held for independent review.

## Observed wall
- Classification: not_reached
- Fact: No gz02 write command has been issued from this candidate.
- Evidence: Static check reports `remote_writes: 0`; local fixtures report `remote_writes: 0`.
- First failing command: The future SSH write command has not been issued.
- Exit/status: Local static check rc0, fixtures rc0; remote execution not reached.

## Hypotheses
- Candidate: The exact UID1000 0755 root/out/tmp and 0700 control/staging sequence can isolate the sibling without changing the old root.
- Cheapest falsifier: Independent code review followed by one fresh read-only gz02 owner, mode, ACL, new-root-absence and host-key preflight.
- Blocking: no

## Proven
- V2 `--execute` writes O_EXCL `nonce.START.json`, fsyncs file and receipt directory, and records nonce, packet, launcher, remote-body and review SHA, both roots and `UNKNOWN_UNTIL_RECONCILED` before SSH.
- A pre-existing START or TERMINAL for the same nonce refuses replay. A local process interruption fixture leaves START and no terminal, then rejects a second attempt.
- The remote body checks the nine old file SHA/size/mode pins before creating the sibling. It uses O_NOFOLLOW directory walking, O_EXCL lease and file creation, readback, and an O_EXCL remote receipt. Partial failure attempts a QUARANTINE marker and never removes the old root.
- A malformed remote rc0 response remains `UNKNOWN_QUARANTINE` and has a local O_EXCL TERMINAL; no success is inferred solely from SSH rc0.

## Not proven
- Actual gz02 directory ownership, ACL and traversal of the proposed sibling, and the old file identities at execution time.
- Whether stage-1 remote receipt can be obtained and independently reconciled after a future one-shot run.
- Stage 2 path binding, owner graph ACK, Soong graph, target artifacts and device operation.

## Failed
- No stage-1 fixture failed in this v2 run. The prior old-root v4 stage preflight remains separately recorded as 0775 mode NO_GO; it was not retried.

## Next evidence
- Command: Independent review of the exact v2 launcher, v1 remote body and v2 fixtures SHAs; then a fresh read-only gz02 preflight before any separately released `--execute` with a fixed 32-hex nonce.
- Expected output: New root absent; fixed host key, UID1000, parent 0755 with no POSIX ACL, old file pins intact, and a signed-off exact-SHA release JSON before the first START.
- If it fails: Keep remote write held; do not retry a nonce with START. Reconcile any uncertain new root, lease, QUARANTINE and receipt read-only.

## Shim/stub/bypass inventory
- Item: No Android shim, stub, permission bypass, container or namespace tool is introduced by stage 1.
- Owner: G279 host migration owner.
- Why it exists: The candidate copies host control and tool bytes to an isolated sibling for later path-binding work.
- Removal condition: Stage 1 remains as immutable evidence after migration; no runtime shim is created.
- Test coverage: Python compile, static check, local temporary-tree copy/replay/abort/quarantine fixtures and local START/terminal interruption fixtures.
- App-specific or common: Project host-control operation, with no app-specific behavior.

## Memory/skill/CI/review updates
- Memory: No memory update requested or made.
- Skill: Followed WestLake evidence separation; this handoff is checked by `westlake_gate.py`.
- CI: Local Python compile, static check and fixtures only; no remote CI claim.
- Review checklist: Verify the three script SHAs, packet SHA for the fixed nonce, host key and UID checks, exact nine source pins, directory modes, O_EXCL START before SSH, no retry, remote O_EXCL receipt, unknown-state handling, and no old-root/local_env/source writes. Require a separate release JSON; this packet itself grants no remote execution.

The future reviewed command shape is `python3 scripts/nanhai_plus_g279_sibling_stage1_candidate_v2.py --execute --nonce <reviewed-32-hex-nonce> --review-file <independent-release.json>`. Stage 2 must generate new path-bound local environment, runner, stager and gate identities; this packet does not authorize graph work.
