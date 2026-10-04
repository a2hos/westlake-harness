# Six APK input admission

## Boundary
- Boundary: Package/Resource and Device/Tooling; no ART/JNI, Binder, Surface, Input, Permission, or appspawn-x implementation changed.
- Android behavior: Original APK input identity and four-phase host inventory are required before attempting Activity launch.
- OpenHarmony mapping: OH7.0.0.39 / AOSP16 r4 / ARM64 single-Bionic target remains unbuilt and unlaunched.
- Fix layer: Input evidence and outer control state only.

## Evidence target
- What this proves: Four exact upstream registry APKs and two TeamViewer official APKs have root-admitted raw bytes and complete host static inventories; the two TeamViewer packages have bounded overseas-mainstream blackbox test-input qualification.
- What this does not prove: APK install, target Bionic compatibility, Activity/display/input behavior, cold start, or 146 distinct apps.

## Environment
- Host: macOS native process; no container or namespace.
- Device: none; device HOLD preserved.
- Tool path: project harness scanner and installed aapt2/apksigner, as recorded in candidate receipts.
- Artifact path: root-six-apk-admission-v1/ROOT-ADMISSION.json and referenced immutable receipts.
- App: four F-Droid registered apps, TeamViewer Remote, TeamViewer Host.

## Status
- Label: build_pass
- Why: Label applies only to native-host static scanner commands; no target build or device verification occurred.

## Observed wall
- Classification: resource_gap
- Fact: No fresh authenticated native Linux R4 host and same-build R4/OH39 Bionic runtime index are bound to this outer loop; graph/target/install gates remain unavailable.
- Evidence: 20261004-hello-reach-static-evo63-host-nogo checkpoint and its host/runtime reviews.
- First failing command: gz02 TCP and alexpc DNS/LAN entry probes in prior host observation; no new target command this round.
- Exit/status: prior probes timed out; this round host-static candidate checks and root rehash passed.

## Hypotheses
- Candidate: A fresh authenticated native Linux route would permit the next H1-H4 read-only gate.
- Cheapest falsifier: current route identity and one-use read-only H1-H4 receipt.
- Blocking: no

## Proven
- Six raw identities and complete static inventories admitted; 4 exact upstream registry artifacts, 2 qualified blackbox inputs, 7 semantic DEX and 28 true ARM64 ELF added.
- EVO64 receipt identity pilot matched six raw/static pairs and rejected one deliberate swap.

## Not proven
- Distinct 200 app identities, target build, install, launch, display, interaction, runtime API closure.

## Failed
- No new target command; none recorded this round.

## Next evidence
- Command: recover authenticated native Linux entry, then run a fresh one-use read-only H1-H4; separately bind same-build R4/OH39 Bionic runtime before platform-gap claims.
- Expected output: signed native-host identity and graph inputs, followed by target artifacts and truly-cold device receipt in later gates.
- If it fails: retain exact command/return code and classify the observed substage without reusing old nonce.

## Shim/stub/bypass inventory
- Item: none added.
- Owner: outer coordinator.
- Why it exists: not applicable.
- Removal condition: not applicable.
- Test coverage: not applicable.
- App-specific or common: not applicable.

## Memory/skill/CI/review updates
- Memory: no memory write requested.
- Skill: WestLake evidence tiers applied; EVO64 remains limited pilot.
- CI: no CI change.
- Review checklist: root-admission receipt, peer cross-review, original APK rehash, registry anti-join, static-only count boundaries.
