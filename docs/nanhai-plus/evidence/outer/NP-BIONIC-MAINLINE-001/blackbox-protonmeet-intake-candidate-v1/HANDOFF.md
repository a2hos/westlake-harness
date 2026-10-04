# WestLake Task Handoff — Proton Meet official APK raw candidate

## Boundary
- Boundary: Package/Resource and Device/Tooling; host acquisition and APK identity only.
- Android behavior: One publisher-direct APK transfer, ZIP CRC, aapt2 package/version/ABI and apksigner certificate validation.
- OpenHarmony mapping: OH7.0.0.39 / AOSP16 r4 / ARM64 Bionic remains the target. This task performs no OH operation.
- Fix layer: Isolated candidate receipts and payload in the project's runtime staging directory; no shared source, authoritative count, device or Bridge change.

## Evidence target
- What this proves: The single fixed GET returned 262,604,360 bytes from Proton's official Meet APK URL, with the same ETag as the preceding HEAD. The resulting APK SHA is `981fd735cef19a87890b7c17c10a506600f519b59a4dcc20fd2144b198b3b7a9`; all 2,716 ZIP entries pass CRC, and the valid APK signer certificate SHA-256 equals the fingerprint published on [Proton's Meet download page](https://proton.me/meet/download).
- What this does not prove: Independent/root acceptance, full split closure, overseas mainstream or blackbox qualification, installation, cold start, runtime compatibility, or any Bionic tool completion.

## Environment
- Host: macOS using `scripts/nanhai_plus_env.py`; exact `/usr/bin/curl`, AOSP16 r4 aapt2/apksigner and DevEco Java hashes pinned before and after.
- Device: None; current device exclusions and HOLD remain in force.
- Tool path: `run.py` records exact argv, rc, elapsed time and raw stdout/stderr hashes in `RESULT.json` and sibling raw files.
- Artifact path: `NANHAI_EVIDENCE_ROOT/outer/NP-BIONIC-MAINLINE-001/blackbox-protonmeet-intake-candidate-v1`; 262 MB payload remains in `NANHAI_RUNTIME_ROOT/staging/blackbox-protonmeet-intake-candidate-v1`.
- App: Proton Meet, `proton.android.meet`, 1.2.2 / code 131.

## Status
- Label: `build_pass=false`; `stub=false`; `real_impl=not_assessed`; `device_verified=false`.
- Why: This is one original APK raw candidate requiring independent review; authoritative accepted count stays 76.

## Observed wall
- Classification: none
- Fact: One bounded GET returned rc0 in 28.71 seconds; aapt2 and apksigner returned rc0. No error or device wall was observed.
- Evidence: `RESULT.json`, `download.stdout.raw`, `badging.stdout.raw`, `signature.stdout.raw`, `NANHAI_RUNTIME_ROOT/staging/blackbox-protonmeet-intake-candidate-v1/{head,get}.headers.raw` and the exact payload.
- First failing command: None.
- Exit/status: Actual outer rc0; no retries, redirects or alternate mirrors. All source/tool hash guards equal before and after.

## Hypotheses
- Candidate: Proton Meet may not meet the project's overseas mainstream criterion, even though this official raw APK is valid.
- Cheapest falsifier: Apply the predefined market/usage and source-availability qualification rubric separately, with dated independent evidence.
- Blocking: no

## Proven
- Publisher page names `https://proton.me/download/MeetAndroid/ProtonMeet-Android.apk` and provides certificate SHA-256 `DCC9439EC1A6C6A8D0203F3423EE42BCC8B970628E53CB73A0393F398DD5B853`; local page bytes and HEAD headers are hashed in `RESULT.json`.
- HEAD and GET both report HTTP 200, exact 262,604,360-byte content and ETag `"c28f722ea2a8f2f0547e84fe3aa59007-51"`. The GET used one `If-Match`, 300,000,000-byte limit and 180-second curl timeout.
- The 2,716 unique ZIP members pass CRC; one root Manifest; aapt2 reports package `proton.android.meet`, version `1.2.2`, code `131`, and native ABIs arm64-v8a, armeabi-v7a, x86_64.
- apksigner verifies v2/v3 schemes and one certificate; its SHA-256 matches the publisher's posted fingerprint. Pin checks for curl, prior official scout, aapt2, apksigner and Java remained equal.

## Not proven
- Full split-set closure from one APK, overseas mainstream status, complete source availability or resulting blackbox qualification, static inventory, install, startup or device behavior.
- One current official download does not replace any historical upstream registry version or provide a stable future payload hash for the rolling URL.

## Failed
- No command failed in this candidate. Zoom's official download page was inspected first but exposed no frozen APK target in the retrieved HTML; no Zoom APK GET was attempted.

## Next evidence
- Command: Independent peer rehash the exact payload, page/HEAD/GET receipts, ZIP CRC, aapt2 and apksigner raw streams against `RESULT.json`; then root may accept exactly one raw original candidate.
- Expected output: Same package/version/bytes/SHA and official certificate match, with zero blackbox/startup/tool count delta.
- If it fails: Retain this candidate as failed or incomplete and keep authoritative count 76.

## Shim/stub/bypass inventory
- Item: None.
- Owner: This intake lane owns candidate evidence; outer root owns admission.
- Why it exists: Original official APK bytes are required for later static and cold-start attempts.
- Removal condition: Candidate may be closed after independent/root decision; immutable receipts remain.
- Test coverage: Exact HEAD/GET lock, full ZIP CRC, aapt2 and apksigner, tool/source pre/post hashes.
- App-specific or common: Proton Meet exact official URL and posted signer fingerprint; workflow generic but not promoted.

## Memory/skill/CI/review updates
- Memory: No write.
- Skill: Applied `westlake-engineering-discipline` host/device evidence separation.
- CI: No shared CI change.
- Review checklist: Verify no accepted package duplicate, official link and fingerprint, same HEAD/GET ETag, single GET, complete ZIP CRC, raw tool output hashes, no source/Bridge/device mutation, no blackbox qualification or count claim.
