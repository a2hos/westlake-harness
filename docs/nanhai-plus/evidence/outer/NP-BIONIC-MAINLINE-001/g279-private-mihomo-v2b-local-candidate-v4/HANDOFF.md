# G279 private native Mihomo v2b v4 code candidate

## Boundary
- Boundary: host Device/Tooling route evidence only.
- Android behavior: no Android app behavior exercised.
- OpenHarmony mapping: none exercised.
- Fix layer: private native host runner's `MATCH,REJECT` evidence projection.

## Evidence target
- What this proves: offline mock's complete whitelisted line survives a TERMINAL-shaped JSON round trip, and an independent reader can recompute both `raw_line_sha256` and canonical `route_event_sha256`; forged, duplicate, out-of-range, and sensitive extra fields are rejected.
- What this does not prove: a real private Mihomo instance, real-node route, gz02 `/32` PROXY, SSH, Soong graph, HelloWorld, or device.

## Environment
- Host: local macOS project host; Python byte-only fixture.
- Device: none; device HOLD preserved.
- Tool path: `python3 -B fixtures.py`; no Mihomo invocation in this generation.
- Artifact path: this independent v4 directory; v3 inputs remain frozen.
- App: none.

## Status
- Label: real_impl candidate, not released or runtime verified.
- Why: `runner.py` now exports the complete raw line only after `re.fullmatch` of the fixed ASCII whitelist; `peer-review-v1/REVIEW.json` and `root-release-v1/ROOT-RELEASE.json` are absent, so the one-shot runner cannot pass its release gate.

## Observed wall
- Classification: observed
- Fact: v3 peer review reported that the real TERMINAL would omit the timestamp and thus could not independently recompute raw-line SHA after private log deletion.
- Evidence: `../g279-private-mihomo-v2b-local-candidate-v3/peer-review-v1/REVIEW.json`, decision `NO_GO_V2B_REAL_EXECUTION_V3`.
- First failing command: none in v4; this was a static review finding.
- Exit/status: v3 peer NO_GO; v4 offline fixture rc 0 only.

## Hypotheses
- Candidate: exact complete Mihomo line format used in the v3 mock will also hold for a later real-node run.
- Cheapest falsifier: independent static review of frozen v4, then separately authorized one-shot real local test if released.
- Blocking: no

## Proven
- The exported `raw_line` byte sequence round-trips through TERMINAL-shaped JSON and hashes to `raw_line_sha256`; its complete canonical event hashes to `route_event_sha256`.
- The accepted line includes only timestamp, info level, fixed loopback source, bounded port, fixed TEST-NET-3 target, Match and REJECT. Any appended node name, password or unrelated suffix fails closed.
- Offline fixtures pass without starting Mihomo, a socket, device, container, or real network operation.

## Not proven
- Independent peer acceptance, root release, real TERMINAL, private node behavior and route selection in a live process.

## Failed
- v3's retained normalized fields omitted the raw timestamp; its real raw hash was not independently recomputable after cleanup.

## Next evidence
- Command: independently review `runner.py`, `fixtures.py`, `FIXTURE.json`, and their hashes in `CANDIDATE.json`; no `--execute` invocation in this handoff.
- Expected output: peer decision on v4's strict whitelist, data minimization, and terminal recomputation.
- If it fails: keep v4 unreleased; make a fresh immutable generation with the smallest correction.

## Shim/stub/bypass inventory
- Item: none added.
- Owner: G279 outer coordinator.
- Why it exists: not applicable.
- Removal condition: not applicable.
- Test coverage: offline fixtures cover the evidence projection.
- App-specific or common: host tooling only.

## Memory/skill/CI/review updates
- Memory: no update requested.
- Skill: WestLake evidence discipline applied; no change proposed.
- CI: offline fixture is reproducible, but not added to project CI by this candidate.
- Review checklist: verify strict fullmatch before export, byte-for-byte raw hash recomputation, canonical event hash recomputation, and absent release/START/TERMINAL.
