# WestLake Task Handoff — G279 sibling stage 2 v2 candidate

## Boundary
- Boundary: Tooling and Security, host-side project source-view migration only.
- Android behavior: none; Android code and runtime were not invoked.
- OpenHarmony mapping: none; no OpenHarmony process or device operation.
- Fix layer: project-owned gz02 migration control script and local fixtures.

## Evidence target
- What this proves: local v2 code passes exact packet reconstruction, stage-1 identity substitution denial, a temporary-tree 46-link writer path, partial-failure quarantine, and unreleased execution denial.
- What this does not prove: gz02 stage-2 execution, source tree byte cleanliness, binding switch, Soong graph, ARM64 target build, or device behavior.

## Environment
- Host: local macOS fixture host; proposed remote host is pinned gz02 UID 1000.
- Device: none, device HOLD maintained.
- Tool path: `scripts/nanhai_plus_g279_sibling_stage2_candidate_v2.py`, `scripts/nanhai_plus_g279_sibling_stage2_remote_v2.py`, `scripts/nanhai_plus_g279_sibling_stage2_fixtures_v2.py`.
- Artifact path: `docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g279-native-graph-source-choice-v1/private-sibling-migration-candidate-v1/stage2-candidate-v2/`.
- App: none; no APK or app run.

## Status
- Label: real_impl.
- Why: the local-only candidate and fixture implementation exists and passes local checks; the remote writer remains unreleased and unexecuted.

## Observed wall
- Classification: not_reached
- Fact: no stage-2 remote command was issued in this candidate turn.
- Evidence: `FIXTURE.json` reports network 0 and remote writes 0; local START and terminal receipts are absent.
- First failing command: none; no remote execution command was issued.
- Exit/status: not_reached for remote execution; local fixture rc 0.

## Hypotheses
- Candidate: no runtime cause proposed; the next uncertainty is fresh gz02 identity and source readback at release time.
- Cheapest falsifier: independent read-only review of the exact v2 packet and fresh host/source preflight.
- Blocking: no

## Proven
- New v2 packet pins accepted stage-1 root dev/inode 64785/47185921, control 64785/47185922, old root 64785/29884417, plus nine exact staged file identities before its O_EXCL lease.
- The positive fixture constructs all 46 links, including a separate patched-Soong alias, and reaches `STAGED_READBACK_ONLY` with a final receipt in an isolated local tree.
- A same-byte new-inode staged file is rejected before the lease. A forced eighth-link failure preserves seven links and creates lease/quarantine without a terminal receipt or automatic deletion.

## Not proven
- Fresh gz02 inode, ACL, source HEAD and link result at actual execution time.
- Original-owner graph ACK, active local binding switch, native Soong graph, target compile and device result.

## Failed
- Stage-2 v1 independent peer review returned `NO_GO_STAGE2_REMOTE_WRITE_V1` for unpinned staged inode identities, absent positive writer fixture, and rc 1 handoff contract gate. Its nonce and files remain historical evidence.

## Next evidence
- Command: `python3 scripts/nanhai_plus_g279_sibling_stage2_fixtures_v2.py`; then independent exact-SHA packet/code review and fresh gz02 read-only preflight.
- Expected output: local fixture `PASS` with remote writes 0, followed by a separate independent review decision for one v2 nonce.
- If it fails: keep v2 unreleased; preserve the failed receipt and create another generation after diagnosis.

## Shim/stub/bypass inventory
- Item: none introduced.
- Owner: G279 migration candidate author.
- Why it exists: no shim, stub or bypass is part of this stage.
- Removal condition: none for this packet.
- Test coverage: local fixture covers 46-link success, replacement-inode denial, partial quarantine and no-review refusal; no remote test claim.
- App-specific or common: host control only; no app-specific behavior.

## Memory/skill/CI/review updates
- Memory: no memory update requested or written.
- Skill: this handoff follows the WestLake gate template with explicit host-only and not-reached values.
- CI: no CI run or CI change; local `py_compile` and fixture only.
- Review checklist: compare packet, launcher, remote body, stage-1 terminal/peer probe, nine inode/SHA rows, 46 source mappings, future env bytes, and one-shot START/quarantine logic. Require a new independent GO decision before any SSH write.

The frozen v2 nonce is `6f324a6cb4e1a5fe8ec594334c61d079`; canonical packet SHA is `e8581d9366477911cb9da05ccff6d60e32beaa3cddc6bc60c7a556a758fea371`. The active `local_env.md` and OUTER-STATE remain unchanged. Stage 2 does not authorize their change; that requires accepted remote postrun evidence and a witnessed original-owner graph ACK for the new generation.
