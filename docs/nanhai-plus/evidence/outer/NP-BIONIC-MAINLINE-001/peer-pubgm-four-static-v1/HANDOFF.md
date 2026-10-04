# PUBG MOBILE global: independent review handoff

Candidate only. Root admission and blackbox qualification remain pending independent review. No installation, launch, device result, or Bionic compatibility is claimed.

## Original publisher input

- Publisher page: <https://www.pubgmobile.com/en-US/home.shtml>. The captured page links the exact APK URL <https://f.gbcass.com/PUBGMOBILE_Global_4.6.0_uawebsite_livik01_5678FCFA.apk>.
- Original downloaded APK: `.nanhai-plus-runtime/bionic-oh7-aosp16/staging/peer-pubgm-official-raw-v1/pubgm-official.apk`; 1,274,351,207 bytes; SHA-256 `9024ea4f6bf6cc3de55bbaee34a31cde8be661d5a8f2941ded99baebdeceda7c`.
- `aapt2 dump badging` rc 0: `com.tencent.ig`, versionCode `21518`, versionName `4.6.0`, target SDK 35. `apksigner verify --verbose --print-certs` rc 0: signer certificate SHA-256 `e075e99e8540bee44a6bb3fc97d8b0b0fe16f863599490e708b7729a21fa70fa`.
- Google Play <https://play.google.com/store/apps/details?id=com.tencent.ig&hl=en_US> is the same package, publisher Level Infinite, 1B+ package-wide downloads. Play does not prove this exact APK/version is identical to a Play-delivered variant.

## Native host static phases

Execution: `python3 scripts/nanhai_plus_env.py --run .nanhai-plus-runtime/bionic-oh7-aosp16/venvs/harness-python-v1/bin/python3 docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/peer-pubgm-four-static-v1/scan.py --execute` (rc 0). The exact venv interpreter and argv for each phase are recorded in `RESULT.json`; each phase has rc 0 and equal SHA-256 input guards before/after. TMP is project-private. There were zero container and zero device commands.

| Phase | Result |
| --- | --- |
| ZIP | rc 0; 1,904 entries, zero duplicate names, CRC clean, one manifest; no nested APK/ZIP/JAR/APKS/XAPK entries. |
| Metadata | rc 0; package/version/target SDK match original `aapt2` result. |
| DEX | rc 0; three root DEX entries and three semantically scanned DEX entries. |
| ELF | rc 0; 40 true ARM64 ELFs in ARM64 paths, all 40 `readelf` successes and machine matches; 41 ARM32 ELFs in ARM32 paths; zero ARM32 ELFs misplaced in ARM64 paths; zero non-ELF `.so`. |

## Reviewable receipts

- Prescreen: `../peer-pubgm-prescreen-v1/PRESCREEN.json` SHA-256 `2b1b6821cc114493adbb996ba2a031c2324526ccec240e4d41b8561a69fb5dec`.
- Original acquisition: `../peer-pubgm-official-raw-v1/RESULT.json` SHA-256 `b6f86dcda81394197a22b59b58c35134cf9a19e1c89081a3bed2389f823bb87c`; `acquire.py` SHA-256 `d6d754872201abcea490a79bf691f35d7df4c87197df6b226b839d404fcbfa44`.
- Identity/signature: `../peer-pubgm-official-raw-v1/VERIFY.json` SHA-256 `491e7a06975ad03762b95ead84611eabdab952c086241e132b7baa67d0e01eb8`; `verify.py` SHA-256 `d06c58f3453210ffee03239fb9ec9c3988ea46cd235b970a899535f54a0512d0`.
- Four static phases: `RESULT.json` SHA-256 `a905bae5c4f3d5a5397547b0d2d4fcb8e1c013192d5344ab12d38fa19a863bd4`; `scan.py` SHA-256 `218238d4da721eb4a4cfc2950d47942a37a1ed7e33990968e3202c69d3e99658`. Phase facts and inventories are adjacent.
- Overseas blackbox qualification: `../peer-pubgm-qualification-v1/QUALIFICATION.json` SHA-256 `0f02a19b6e55fd18fd588282c2ff8a8092998ba2bcb2862f37c6b27f70345b7a`, with captured publisher and Play HTML. The source check is bounded and does not assert global source absence.

This handoff changes no authoritative counts or control files. Independent peer should verify publisher HTML exact href, APK bytes and signature, ZIP/DEX/ELF inventory, same-package Play listing and bounded blackbox qualification before root admission.
