# BIGO LIVE official APK: independent candidate handoff

Decision: **GO for independent peer review as one new raw/static and overseas mainstream blackbox test-input candidate only.** The candidate package `sg.bigo.live` had no exact-package hit among prior root qualification receipts in the bounded search. Root authoritative deltas remain zero. No device, container, BridgeAOSPV16, installation, or cold start was attempted.

## Exact original package and source

- Publisher page: <https://www.bigo.tv/id/blog/bigo-live-apk>, whose download button links directly to <https://static-web.bigolive.tv/as/bigo-static/apk/bigolive-bigotv.apk>. The page describes it as BIGO's official APK. Prescreen: `../peer-bigo-prescreen-v1/PRESCREEN.json` SHA-256 `5f210dad4b00174365321f8b7f39668dbeb5d3ec3e6ccbf705e78b7336c440f3`.
- Staged original: `.nanhai-plus-runtime/bionic-oh7-aosp16/staging/peer-bigo-official-raw-v1/bigo-official.apk`, 156,619,073 bytes, SHA-256 `30c97668ef095f6372f3a2353b8d65fa9050cf49ad5ba070d7579dcbd16a12a1`.
- `aapt2 dump badging` rc 0: package `sg.bigo.live`, versionCode `4137`, versionName `6.53.1`, target SDK 36. `apksigner verify --verbose --print-certs` rc 0; signer certificate SHA-256 `5c333105423f4d1b074a8deb7e5a2c6e9b485cf47fd6fd5309778e8dc3629401`. No external certificate pin is asserted.
- Acquisition `../peer-bigo-official-raw-v1/RESULT.json` SHA-256 `7b0e5aff3fbc6d93e4a230385e72ac6bc246dc43cf93345679dbebb8a4d67dc8`; verification `VERIFY.json` SHA-256 `447f1eaf6fad05a225428277ebb915cc71c1bcc886d787636feb03b95bdd9aca`. Raw GET/HEAD headers and tool stdout/stderr are retained there.

## Four native-host phases

Command: `python3 scripts/nanhai_plus_env.py --run .nanhai-plus-runtime/bionic-oh7-aosp16/venvs/harness-python-v1/bin/python3 docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/peer-bigo-four-static-v1/scan.py --execute`; rc 0. Every phase records the exact APK, raw receipts, scanner and readelf hashes before and after with equality true. Temporary files use project-private `NANHAI_TMP_ROOT/peer-bigo-four-static-v1`.

| Phase | rc | Result |
| --- | ---: | --- |
| ZIP | 0 | 13,568 entries; no duplicate names; CRC clean; one manifest; 47 root/total DEX; 195 `.so` paths |
| Metadata | 0 | Exact package, version and SHA matched |
| DEX | 0 | Original scanner semantic inventory covers all 47 DEX |
| ELF | 0 | 97 true ARM64 ELF with `readelf_ok=true` and machine match; 98 ARM32 ELF in `armeabi-v7a`; 0 ARM32 misplaced under `arm64-v8a`; 0 non-ELF `.so` |

`RESULT.json` SHA-256 `bec5ae1e55fb6ab4841c7e9344352d35b00e1e417c456aa9ccb70815cd707179`; scanner script SHA-256 `1146d395bf5f810b9111fe130ba9ac5ffb569cc130df83825279c920c0d03593`. One nested ZIP, `assets/audioroot_ludo.zip`, has 28 entries, clean CRC, and no DEX/SO/nested package entries. `NESTED-ARCHIVE.json` SHA-256 `366d091211d4dfef8be602afd31b10d0597dbab05eb16a69954f24e4f2c7ba71`.

## Qualification limit

`../peer-bigo-qualification-v1/QUALIFICATION.json` SHA-256 `5be34a00ad163ec5afd99842d0435dc924865ac3dba4f241b19541736eb0e26a`. Google Play independently lists exact package `sg.bigo.live` under BIGO TECHNOLOGY PTE. LTD. with **500M+ package-wide downloads**. That and the official source support an overseas mainstream test-input candidate. Bounded source visibility is recorded without claiming global absence of public source. The Play variant is not asserted byte-equivalent to the publisher APK. Peer/root must admit raw/static and qualification separately; static does not prove cold start, Activity lifecycle, UI or Bionic compatibility.
