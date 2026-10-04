# G299 overseas blackbox original APK intake candidate

## Boundary
- Boundary: host-only APK acquisition and identity/static precheck for the AOSP16 ARM64/Bionic portfolio.
- Android behavior: two original APK archives and their manifests/signatures were inspected; no install or launch.
- OpenHarmony mapping: none exercised.
- Fix layer: portfolio input only; no adapter or runtime change.

## Evidence target
- What this proves: two distinct official-site APK downloads, exact local SHA/size, package/version, APK signature verification, full ZIP CRC, manifest/Dex presence and real ARM64 ELF members.
- What this does not prove: publisher-to-certificate cryptographic binding, independent raw admission, blackbox qualification, host four-phase inventory, installation, device behavior or cold start.

## Environment
- Host: local macOS; `python3 scripts/nanhai_plus_env.py --run` loads the project staging root.
- Device: none; device HOLD preserved.
- Tool path: Android SDK build-tools 36.0.0 `aapt2` 2.20-13193326 and `apksigner` 0.9, Python standard-library `zipfile` scanner `scan.py`.
- Artifact path: `$NANHAI_STAGING_ROOT/g299-blackbox-next-intake-v1/` contains the two APKs, GET headers and raw tool outputs. Candidate receipt is `CANDIDATE.json`; binary APKs remain outside Git.
- App: NordVPN `com.nordvpn.android`, Surfshark `com.surfshark.vpnclient.android`.

## Status
- Label: stub.
- Why: host raw/static candidate, no accepted portfolio count or runtime evidence.

## Observed wall
- Classification: none
- Fact: both official HTTPS GETs returned HTTP 200 with the expected final content lengths, then `aapt2`, `apksigner`, full ZIP CRC and ARM64 ELF checks passed.
- Evidence: `CANDIDATE.json` SHA `0a97aa3e61a12fa380af0da2deca97997e574d448b0e1748e6259f2088d1e626` and raw outputs in project staging.
- First failing command: initial `scan.py` rc 1 because its package regex also matched `compileSdkVersionCodename`; corrected to whitespace-bound keys, second scan rc 0. No APK or source bytes changed.
- Exit/status: final `HOST_RAW_STATIC_CANDIDATE_ONLY`.

## Hypotheses
- Candidate: either APK may need a publisher signing-certificate reference before stronger package qualification.
- Cheapest falsifier: obtain an official signer fingerprint or an independently signed distribution checksum and compare to the recorded certificate digest and raw SHA.
- Blocking: no

## Proven
- [NordVPN official Android page](https://nordvpn.com/download/android/) links its website APK channel; the link resolves to `https://downloads.nordcdn.com/apps/android/generic/nordvpn-sideload/latest/v2/NordVPN.apk`, and the actual GET ended at `downloads77-android.nordcdn.com` with HTTP 200, 109,609,596 bytes. [Google Play](https://play.google.com/store/apps/details?id=com.nordvpn.android) lists the same package under Nord Security with 100M+ downloads; that is package-level market evidence, not proof about these exact bytes.
- NordVPN manifest: `com.nordvpn.android`, `9.14.1+sideload`, versionCode `1002121`; SHA-256 `820ec9e0f930504893aa46d4fbe84edc5a2a7c6617809a284bb2b3163ec7ae4e`. APK v3 signature verifies; certificate SHA-256 `bc64ae0725af656b3b10b684cd1df4c9d6b7f81bc5dc32df3a3b2ce94ce61466`, DN `O=Tefincom`. Full ZIP CRC passes: 3,517 entries, 3 DEX, 20 ARM64 ELF.
- [Surfshark official Android page](https://surfshark.com/download/android) links `https://downloads.surfshark.com/android/Surfshark.apk`; actual GET HTTP 200, 156,032,892 bytes. [Google Play](https://play.google.com/store/apps/details?id=com.surfshark.vpnclient.android) lists the same package under Surfshark B.V. with 10M+ downloads; this is package-level market evidence.
- Surfshark manifest: `com.surfshark.vpnclient.android`, `3.35.0`, versionCode `310048760`; SHA-256 `bba60c65cca0791a2f053b3e146e5e806da5089272c45614901a8e17c93866a7`. APK v1/v2 signatures verify; certificate SHA-256 `4a0dc39f29beeeed408f8c33acbb3b18c14eac24a76208aa566e5cab8f3e3726`, certificate DN fields `Unknown`. Full ZIP CRC passes: 3,971 entries, 4 DEX, 37 ARM64 ELF.
- All 57 ARM64 `.so` members have ELF64 class and AArch64 machine 183. Both are standalone APK ZIP archives containing `AndroidManifest.xml` and `classes.dex`, and both declare `arm64-v8a` in `aapt2` badging.
- No existing NordVPN or Surfshark package hit was found in the preexisting `TASK-SUMMARY.json` or `apk-next-acquisition-queue-v1/COVERAGE.json`; those controls report 83 accepted raw APK payloads before this candidate.

## Not proven
- Official publication of these exact signing certificate fingerprints; website TLS and APK signature verification do not independently establish the publisher-to-cert relationship.
- That both are installable or launchable on current OH7/Bionic, or that VPN service semantics are implemented.
- Any change to accepted 83, qualified blackbox 5, or cold starts 0/200.

## Failed
- None in the final artifact checks. The first parser attempt was a local scanner bug and was corrected before `CANDIDATE.json` was written.

## Next evidence
- Command: independent reviewer replays hashes, badging, signature, CRC and ABI checks; root admits exact raw artifact identities only if provenance and nonduplicate controls pass. Host four-phase inventory and blackbox qualification are separate subsequent gates.
- Expected output: two bounded original-APK candidate decisions; no cold-start credit.
- If it fails: retain raw downloads and tool outputs as unaccepted candidates; do not mutate canonical counts.

## Shim/stub/bypass inventory
- Item: none in adapter/App; scanner is an input evidence tool.
- Owner: G299 portfolio intake.
- Why it exists: make source, APK identity and architecture checks repeatable.
- Removal condition: not applicable.
- Test coverage: actual two APKs, full ZIP CRC and 57 native ELF headers.
- App-specific or common: common raw APK intake scanner with exact inputs for these two packages.

## Memory/skill/CI/review updates
- Memory: none.
- Skill: host/raw evidence stays separate from device and cold-start acceptance.
- CI: `scan.py` rc 0 under the project environment loader; handoff gate applies.
- Review checklist: recheck official link path and effective URL, package/version, cert digest, ZIP CRC, ELF64/AArch64, nonduplicate status and zero count delta.

No container, graph or device operation was used. Original goal/session/claim/budget and device HOLD remain unchanged.
