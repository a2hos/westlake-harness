# WestLake Task Handoff — G279 v12 runner Stage4 staging candidate v2

## Boundary
- Boundary: Device/Tooling and Security; one exact native-host script staging operation only.
- Android behavior: none invoked; no Soong graph, Bionic target compilation or APK launch.
- OpenHarmony mapping: none invoked.
- Fix layer: gz02 private sibling project-control staging; no container or namespace sandbox.

## Evidence target
- What this proves: frozen v2 candidate pins the accepted Stage1/2/3 directory and 17 exact file identities, the 15-entry control inventory, and v12 runner candidate SHA `b3277b024ba258cc00c7fea1d9275672108970886c78b0c221f60aec16600a3b` / 47,610 bytes / intended mode 0444. Local writer fixtures test the packet.
- What this does not prove: current remote input state, actual v12 staging/readback, EVO19, owner ACK, graph, target build, App or device result.

## Environment
- Host: local macOS fixture host; intended remote gz02 Linux x86_64 UID/EUID 1000.
- Device: none; project device HOLD and allowlist unchanged.
- Tool path: v2 `launcher.py`, `remote_body.py`, and `fixtures.py` in this directory; SSH is not run by this candidate generation.
- Artifact path: v2 `PACKET.json` and `FIXTURE.json`; one-shot START/TERMINAL would be separate later receipts only after independent review, fresh preflight and root release.
- App: none.

## Status
- Label: real_impl.
- Why: native-host staging code and local fixtures exist, while `--execute` remains unreleased and has not been run.

## Observed wall
- Classification: not_reached
- Fact: v2 gz02 staging has not been attempted; v1 independent review returned NO_GO_THIS_PACKET solely because its HANDOFF.md failed the mechanical gate (rc 1).
- Evidence: v1 peer `REVIEW.json` SHA `67be580a1182fee341473fd0a62cc3489e2fe104b324f86cbd562050fbdd45df`; v2 fixture reports SSH 0 and remote writes 0.
- First failing command: v1 `westlake_gate.py HANDOFF.md`, rc 1, as recorded by the independent peer; no v2 remote command exists.
- Exit/status: v2 local fixture rc 0; remote staging not_reached.

## Hypotheses
- Candidate: the accepted Stage3 bytes and directory identities may still match on gz02 when a fresh read-only preflight is performed; this is unverified.
- Cheapest falsifier: independently re-read all 17 pinned files, directory identities and the exact 15-entry control inventory immediately before any one-shot staging release.
- Blocking: no

## Proven
- This v2 packet has a new nonce `98436646ab71ba46dcc5cfe3d4d12e45` and preserves exact v12 source SHA/bytes and accepted v11 runner/lease/receipt identities. No v1 nonce or packet is replayed.
- Temporary-tree fixtures cover exact packet reconstruction, release denial before START/SSH, successful mode 0444 local staging, same-byte inode replacement denial, and partial-write quarantine without deletion/replay.
- Remote writer code has no graph, target, device, container or namespace invocation; this is static/local evidence, not remote execution proof.

## Not proven
- Fresh gz02 identities and preflight, v12 staged file inode/SHA/mode, independent postrun acceptance, formal v12 EVO19 gate, original owner signed ACK, native graph, ARM64 Bionic target or HelloWorld runtime.

## Failed
- v1 handoff mechanical gate rc 1 is retained as an immutable NO_GO peer review. No v2 staging command has failed because none has run.

## Next evidence
- Command: run `python3 fixtures.py` and the WestLake handoff gate on this v2 document, then independent exact-SHA review and a fresh read-only gz02 preflight.
- Expected output: local fixture PASS and handoff gate PASS; only a later separate peer/root one-shot release could permit v12 staging.
- If it fails: keep v2 nonce unreleased, preserve the error receipt, identify the changed document or remote identity, and do not replay v1 or run graph.

## Shim/stub/bypass inventory
- Item: none introduced.
- Owner: G279 Stage4 candidate author.
- Why it exists: no shim, stub or bypass is part of staging exact runner bytes.
- Removal condition: none.
- Test coverage: local writer/release/quarantine fixtures; no remote Linux, graph or App proof.
- App-specific or common: project control only.

## Memory/skill/CI/review updates
- Memory: no update requested or written.
- Skill: `westlake-engineering-discipline` handoff contract applied to host-only, not_reached evidence.
- CI: none changed; local fixture, syntax compilation and `westlake_gate.py` are the checks for this packet.
- Review checklist: verify new nonce, active local_env SHA, 17 exact remote input identities including frozen v11 runner/lease/receipt, 15-entry control inventory, Stage3 peer/root acceptance, v12 runner SHA/bytes/mode, host key/UID, O_EXCL START/lease/receipt, quarantine/no-replay, no forbidden execution, and absence of Stage4 SSH, remote writes and graph results.

The full stock R4 checkout remains the future graph TOP. This source-view is only a declared read-only input/diagnostic view; this staging candidate never runs Soong.
