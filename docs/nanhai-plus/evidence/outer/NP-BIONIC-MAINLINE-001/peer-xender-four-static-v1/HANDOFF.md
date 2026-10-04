# Xender official APK: independent candidate handoff

Decision: **GO for independent peer review as a second distinct raw/static and overseas mainstream blackbox test-input candidate.** The package `cn.xender` has no exact-package hit in the prior root qualification receipts searched. Root authoritative deltas remain zero. No device, container, BridgeAOSPV16, installation, or cold start was attempted.

## Publisher channel and exact original

- Official landing <https://www.xender.com/> loads `js/index.22e6c96706269929b192.js`, which names `https://js.xdd-w-00tj3nsj.com/h5_upd_url` as its download configuration endpoint. A GET to that endpoint with `?app=xd&platform=` returns an Android row: package `cn.xender`, versionCode `1000310`, Play URL for `cn.xender`, and direct APK URL <https://w48975123.mochain.net/upd/202609/Xender_V19.0.0.prime_GP.apk>. This is an official-page-to-config-to-CDN chain; the CDN domain differs from the landing domain. Raw landing, JS and JSON configuration bytes are retained in `../peer-xender-qualification-v1/`.
- Staged original: `.nanhai-plus-runtime/bionic-oh7-aosp16/staging/peer-xender-official-raw-v1/xender-official.apk`, 31,703,348 bytes, SHA-256 `e205201d0593e5c370d3b1b659e98289eb8370b02a6c11f953120fd4381cb962`.
- `aapt2 dump badging` rc 0: package `cn.xender`, versionCode `1000310`, versionName `19.0.0.prime`, target SDK 36. Package and versionCode match the publisher configuration. `apksigner verify --verbose --print-certs` rc 0; signer certificate SHA-256 `2dc51edb11905e74e712c123b42ce8ad6f623687d912eb051f14116646ef9ab3`. No independent publisher certificate pin is asserted.
- Prescreen `../peer-xender-prescreen-v1/PRESCREEN.json` SHA-256 `942df42549ab70d8b34d303d499c38487b8303d1b68c291dd368691c5d3c39c5`; acquisition `../peer-xender-official-raw-v1/RESULT.json` SHA-256 `c094583d6e2dc8e60abdbdc555f15eedd661d854c2c1b511e6676f03544b9bb5`; verification `VERIFY.json` SHA-256 `fcd50c54e9144b8efc49dc8a685806125a0567246b24ee5650bec7acc630dbff`.

## Four native-host phases

Command: `python3 scripts/nanhai_plus_env.py --run .nanhai-plus-runtime/bionic-oh7-aosp16/venvs/harness-python-v1/bin/python3 docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/peer-xender-four-static-v1/scan.py --execute`; rc 0. Every phase records exact APK, raw receipts, scanner and readelf hashes before and after with equality true. Temporary files use project-private `NANHAI_TMP_ROOT/peer-xender-four-static-v1`.

| Phase | rc | Result |
| --- | ---: | --- |
| ZIP | 0 | 5,380 entries; no duplicate names; CRC clean; one manifest; 6 root/total DEX; 26 `.so` paths; no nested APK/ZIP/JAR-like entries |
| Metadata | 0 | Exact package, version and SHA matched |
| DEX | 0 | Original scanner semantic inventory covers all 6 DEX |
| ELF | 0 | 10 true ARM64 ELF with `readelf_ok=true` and machine match; 10 ARM32 ELF; 6 x86/x86_64 ELF; 0 ARM32 misplaced under `arm64-v8a`; 0 non-ELF `.so` |

`RESULT.json` SHA-256 `3bf9c96f35a126f37e163d1eaf42c0fc11c9a2bbca7525aeb4105ddb60bfecc2`; scan script SHA-256 `80fa9666636beefb97a5bd45c520b21a137e3f7e5f6aa3299653f485e6e43fdf`.

## Qualification and prescreen limit

`../peer-xender-qualification-v1/QUALIFICATION.json` SHA-256 `9115ec6bdcbe64ae232d9d95f629bbb21901a0259a342b1620b3fe8c00259753`. Google Play independently lists exact package `cn.xender` with **500M+ package-wide downloads**; the publisher describes worldwide use. Bounded source visibility is recorded without claiming global absence of public source. The Play-delivered variant is not asserted byte-equivalent to this official-channel APK.

Tango's official landing currently resolves its download CTA through an AppsFlyer link, without a locked direct APK. Likee's official default APK was obtained but is ARM32-only: `video.like` 3.84.3 / 4942, 89,963,816 bytes, SHA-256 `532b96a64d5d2ea68f6c4b87597ea00094a577e329d729307f2e0cbc5fe93b16`; `../peer-likee-official-raw-v1/NO-GO.json` SHA-256 `a38c26a74e6369f46be263731944ac8a9270e58962e05b06a24cd53c02d7e2b9`. It was not sent through four-stage ARM64 static or counted.

Peer/root must admit raw/static and blackbox qualification separately; static does not prove cold start, Activity lifecycle, UI or Bionic compatibility.
