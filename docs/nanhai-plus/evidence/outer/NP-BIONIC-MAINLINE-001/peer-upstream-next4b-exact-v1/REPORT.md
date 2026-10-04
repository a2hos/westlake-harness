# Four further registered upstream APK candidates

`SELECTION.json` freezes four missing artifact IDs, exact SHA-256 values, versions, and registered F-Droid URLs from the prior 338-artifact gap audit. Each native-host GET wrote only to its own project staging directory. No signature or static check ran until the complete downloaded APK matched its registered SHA. All four matched; the original APK bytes remain in `NANHAI_STAGING_ROOT/peer-upstream-next4b-exact-v1/<package>/original.apk`.

| Package / artifact | Exact registered SHA-256 | Bytes | Raw candidate | Four-phase static candidate | DEX | True ARM64 ELF |
| --- | --- | ---: | --- | --- | ---: | ---: |
| JTX Board `a-5dd27d26c6d932f68d0c` | `92fbd67fd935b52bba9e04003e9d6dc8235bb5c66e48dcf77af41c0e660b0c9e` | 8,930,747 | GO | GO | 3 | 1 |
| Privacy Browser `a-30e87ec07c416de4d09c` | `209e0670cb44a959dd628737eaa5b8df05bfb605e4706de49ea2b72684cf72e3` | 17,083,571 | GO | GO | 1 | 0 |
| FairScan `a-17e6d7b1ef1274c7e49d` | `35300568c6f5882b42256f0e662b2790494c3be764b05f00bee82371d49dd798` | 45,938,803 | GO | GO | 1 | 11 |
| Lemuroid `a-f1a367c3a73d18209179` | `f83912a5c276f3616833fcf1b44a8e40c61d5a20f76db3f4297d6c1f63805c42` | 11,970,354 | GO | GO | 2 | 2 |

All four GETs returned rc 0 with final HTTP 200 and APK MIME. ZIP CRC and duplicate-name checks passed, each APK had one manifest, aapt2 matched the exact registered package/version/code, and apksigner verification returned rc 0 with certificate output preserved. The four native-host phases (`zip`, `metadata`, `dex`, `elf`) each returned rc 0 with equal before/after APK SHA guards. Independent ZIP enumeration found no embedded DEX: all 7 DEX were semantically inventoried. ARM64 `readelf_ok` and machine matches cover all 14 ARM64 `lib/` `.so` entries. Privacy Browser has no native `lib/` `.so` at all, so its empty ARM64 ELF inventory is expected. All four private TMP directories were empty after.

`HANDOFF.json` independently rereads the staged APKs and hashes all per-package `RAW.json`, `STATIC.json`, GET, tool, phase, manifest, DEX, and ELF receipts. Handoff and replay returned rc 0, `cmp` rc 0, SHA-256 `1fad8f3ac77f9b9fa3255535639382fcec7f9d4cbf709ad16080e9785d441bfa`. Each `intake.py` invocation also returned rc 0.

These are original-APK and complete host-static **candidates for independent review**, not root admissions. F-Droid-distributed APK signatures verify, but an external publisher signing-key pin is not claimed. Static evidence does not prove install, Bionic compatibility, Activity lifecycle, display, or cold startup. No total ledger, RESUME, OUTER-STATE, device, container, or Bridge was changed.
