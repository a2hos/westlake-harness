# Four further exact upstream APK candidates

`SELECTION.json` freezes four still-missing `(artifact ID, SHA-256, version, URL)` rows from the prior exact gap audit. Each APK was downloaded by a native-host GET to its own project staging directory. The per-package `RAW.json` was written only after comparing the complete received SHA with the registry; a mismatch would have stopped that APK before signature or static work. All four matched.

| Package / artifact | Exact registered SHA-256 | Bytes | ZIP + signature + manifest | Four static phases | Semantic DEX | True ARM64 ELF |
| --- | --- | ---: | --- | --- | ---: | ---: |
| mpv `a-1f62491a80584c7b95f1` | `5cba2237b20ba34b79eaccfbd39bdb5b09d2a9a774bdccee09ca450eac4edd34` | 123,244,634 | GO candidate | GO candidate | 1 | 10 |
| StreetComplete `a-f753949ae8c1346a0933` | `9845b2e86f6e92440d7a1ed4742b861ef46d866e3f141e666fc7e41dcdd443ec` | 96,482,236 | GO candidate | GO candidate | 4 | 2 |
| Home Assistant Minimal `a-1abef3c4f37c226f12d5` | `f3ecfcba33d2d7936e7f6d5adde6cdd35b50d19d0af36b1d5b5ed11c9e53a601` | 57,401,014 | GO candidate | GO candidate | 9 | 3 |
| Jami `a-2fc4eef2d8add4e33054` | `459c8826b1f8dba48fbf8869ba11b6d1438e592f8ff6dd541a06577efa25cee2` | 100,428,373 | GO candidate | GO candidate | 1 | 4 |

All four GETs returned rc 0 with final HTTP 200 and APK MIME. ZIP CRC and duplicate-name checks passed, each APK had one manifest, `aapt2` verified the exact registered package/version/code, and `apksigner verify --verbose --print-certs` returned rc 0 with preserved certificate output. Each ZIP contains ARM64 libraries even though the registry ABI field was empty. The four native-host phases (`zip`, `metadata`, `dex`, `elf`) each returned rc 0 with equal before/after APK SHA guards. `readelf_ok` and ARM64-machine matches cover all 19 ARM64 `lib/` `.so` entries. Independent ZIP enumeration found no embedded DEX: all 15 DEX are roots and semantically inventoried. Private per-package TMP directories were empty after.

`HANDOFF.json` hashes all per-package raw and static receipts and independently rereads the staged APKs. Its run and replay each returned rc 0; `cmp` rc 0; both SHA-256 `1abce7f33a4ad33149e712c4b8943cc1eef2b9c8fc716d9fa079e683e3a94900`. All four `intake.py` invocations returned rc 0. The complete GET headers, tool stdout/stderr, four phase results, manifest, DEX inventory, and ELF inventory are preserved in each package subdirectory.

These are original-APK and complete host-static **candidates for independent review**, with no root admission or authoritative count change. The F-Droid distribution APK signatures are verified cryptographically, but no external publisher certificate pin is claimed. Static evidence does not prove install, Bionic compatibility, Activity lifecycle, display, or truly cold startup. No device, container, or Bridge was used.
