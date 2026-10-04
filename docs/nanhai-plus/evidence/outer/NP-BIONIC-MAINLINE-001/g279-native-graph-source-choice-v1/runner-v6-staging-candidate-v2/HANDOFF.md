# WestLake Task Handoff

## Boundary
- Boundary: Device/Tooling, native host to project-owned gz02 control input.
- Android behavior: None exercised; runner is a build control script.
- OpenHarmony mapping: None exercised.
- Fix layer: Host staging control only.

## Evidence target
- What this proves: Local candidate checks authoritative environment, durable pre-SSH UNKNOWN one-shot receipt, remote UID/path/inode-safe staging logic, and conservative failure states in fixtures.
- What this does not prove: Actual SSH staging, graph execution, target build, APK, or device behavior.

## Environment
- Host: Local macOS fixture; intended remote host gz02 remains untouched.
- Device: None.
- Tool path: `scripts/nanhai_plus_stage_runner_v6_candidate_v2.py`.
- Artifact path: `runner-v6-staging-candidate-v2/STATIC-CANDIDATE.json`.
- App: None.

## Status
- Label: stub
- Why: CLI `--stage` is deliberately hard-closed with rc3; only static/local fixture paths ran.

## Observed wall
- Classification: observed
- Fact: v6 graph runner `--run` is hard-closed rc3; staging that exact byte sequence would not enable graph execution.
- Evidence: v6 runner source and v2 static candidate receipt.
- First failing command: `python3 -B scripts/nanhai_plus_stage_runner_v6_candidate_v2.py --stage`.
- Exit/status: rc3, `NO_GO_STAGING_UNRELEASED`.

## Hypotheses
- Candidate: A newly reviewed executable graph runner can reuse the v2 staging protocol after its exact SHA/path/mode pins change.
- Cheapest falsifier: Static review of the new runner entrypoint and safety gates before any remote command.
- Blocking: no

## Proven
- Ten local fixtures pass, including UNKNOWN-before-transport, no retry, timeout, terminal receipt failure, parent symlink rejection, and concurrent replacement preservation.
- Static check rc0 and stage denial rc3.

## Not proven
- Remote project owner and path stability on gz02 at staging time; no staging was performed.
- Execution-adjacent runner identity or graph safety.

## Failed
- Initial v2 fixture import lacked scripts path; fixture was corrected and passed. No remote action was involved.

## Next evidence
- Command: First create and independently review a new graph runner with executable `--run` and exact SHA; then adapt and review this one-shot staging packet.
- Expected output: New immutable runner identity and peer GO for staging; only then consider one authorized remote stage.
- If it fails: Keep UNKNOWN/read-only reconciliation semantics and do not retry blindly.

## Shim/stub/bypass inventory
- Item: `--stage` hard-close.
- Owner: Nanhai Plus outer control.
- Why it exists: Prevent unreviewed remote mutation.
- Removal condition: New executable runner SHA, independent staging review, release receipt, and owner authorization.
- Test coverage: CLI rc3 plus local fixtures.
- App-specific or common: Common host-control pattern.

## Memory/skill/CI/review updates
- Memory: No memory update requested.
- Skill: Followed WestLake evidence separation; no skill change.
- CI: No CI change; local fixture evidence only.
- Review checklist: Verify immutable UNKNOWN before transport, one-shot behavior, UID/path/inode-safe cleanup, and exact source SHA before release.
