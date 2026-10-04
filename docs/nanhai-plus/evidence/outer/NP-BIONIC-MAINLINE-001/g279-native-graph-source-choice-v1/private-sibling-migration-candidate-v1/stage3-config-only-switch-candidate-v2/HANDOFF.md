# WestLake Task Handoff — G279 Stage3 v2 CONFIG-ONLY binding candidate

## Boundary
- Boundary: project control tooling and local binding, three exact env values only.
- Android behavior: none invoked; full R4 graph TOP is reserved for a later gate.
- OpenHarmony mapping: none invoked.
- Fix layer: local `local_env.md` atomic binding only after independent release.

## Evidence target
- What this proves: exact three-key old/new config comparison, fsynced O_EXCL one-shot local switch mechanics and read-only reconciliation pass isolated fixtures.
- What this does not prove: an authoritative binding switch, active-env EVO19, original-owner ACK, graph, target, App or device behavior.

## Environment
- Host: local macOS fixture host; authoritative project root in `PACKET.json`.
- Device: none; device HOLD remains.
- Tool path: `switch.py` and `reconcile.py` in this candidate directory.
- Artifact path: frozen `PACKET.json`, `FIXTURE.json`; future START/TERMINAL only after release.
- App: none.

## Status
- Label: real_impl.
- Why: one-shot switch and read-only reconciliation code exist and pass isolated fixtures; authoritative `--execute` was not run.

## Observed wall
- Classification: not_reached
- Fact: exact v11 staging was executed separately; Stage3 v2 local switch remains unreleased and unexecuted.
- Evidence: fixture reports authoritative env edits 0, remote commands 0, graph 0, device 0 and container 0.
- First failing command: none for authoritative switch; it was not attempted.
- Exit/status: local fixture rc0; authoritative switch not_reached.

## Hypotheses
- Candidate: fresh active env or v11 postrun/root acceptance may drift before release.
- Cheapest falsifier: read the exact receipt SHA and current old env raw/config SHA before independent switch review.
- Blocking: no

## Proven
- The frozen packet reconstructs the old/new raw and machine config SHAs and exactly three changed keys.
- Temporary-tree fixtures cover exact atomic switch, old-byte backup, terminal, nonce replay denial, injected post-replace failure/quarantine, drift denial before START, unreleased execution denial, and read-only reconciliation.
- No graph, device, container, namespace or remote command is in the local switch executor.

## Not proven
- Authoritative local binding change, active-env EVO19, frozen outer release, original-owner graph-only ACK, graph, target or device result.

## Failed
- No authoritative switch command failed; no authoritative switch command was issued.

## Next evidence
- Command: independent review of `SWITCH-PLAN.md`, `switch.py`, `reconcile.py`, `PACKET.json`, `FIXTURE.json` and v11 accepted postrun; then `python3 fixtures.py` as a local repeat.
- Expected output: fixture PASS and, only if evidence remains exact, separate `GO_CONFIG_ONLY_LOCAL_SWITCH_ONCE` review binding all listed SHAs.
- If it fails: do not issue release or execute; diagnose identity drift and make a new generation.

## Shim/stub/bypass inventory
- Item: none introduced.
- Owner: G279 Stage3 candidate author.
- Why it exists: no shim, stub or bypass is part of the config switch.
- Removal condition: none.
- Test coverage: isolated temp-tree switch and reconciliation only; no actual local binding operation.
- App-specific or common: project control only.

## Memory/skill/CI/review updates
- Memory: no update requested or written.
- Skill: WestLake handoff contract used with control-only/not_reached values.
- CI: none changed; local fixture, `py_compile` and handoff gate only.
- Review checklist: see `SWITCH-PLAN.md`; exact v11 peer/root postrun SHA and three-key diff are mandatory. The owner ACK and graph remain later, separate gates.
