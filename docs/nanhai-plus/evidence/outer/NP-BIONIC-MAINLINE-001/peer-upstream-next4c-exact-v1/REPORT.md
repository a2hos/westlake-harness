# Four more exact upstream APK candidates

`SELECTION.json` freezes four distinct missing package/artifact IDs, exact registry SHA-256 values, versions, and F-Droid URLs from the prior 338-artifact gap audit. Each native-host GET used a separate project staging directory. The per-package script stops at a failed GET or SHA mismatch and does no signature/static work for that item; no fallback artifact or second URL is substituted. All four selected GETs matched the registry SHA on the first attempt, so no replacement was needed.

| Package / artifact | Exact registered SHA-256 | Bytes | Raw candidate | Four-phase static candidate | DEX | True ARM64 ELF |
| --- | --- | ---: | --- | --- | ---: | ---: |
| Deku `a-b7a27f1ce8b533da7ded` | `10a862955c6559ac056d4809b3879efcf7a9af4c10208b282fa987d7d8f82f8c` | 12,737,269 | GO | GO | 1 | 4 |
| Flux News `a-e7af1d469505fe299eb8` | `168cb7b2d24e585db82c40b188f024257cc20e5be32693a5eb38252b72483f0b` | 35,641,857 | GO | GO | 1 | 5 |
| PContacts `a-ae528ecc6d492fd87d3c` | `58e2227f80e37c79d2ffb9c588538b233aa4276096ed39b814bd34989d9d8a4c` | 4,443,581 | GO | GO | 1 | 1 |
| FFUpdater `a-424824476cc44afbee5c` | `b1a854c248ca3336afd112f8f620c5c8c44c02dd6aac5784199f9931c2377ce6` | 4,957,402 | GO | GO | 2 | 1 |

All four GETs returned rc 0 with final HTTP 200 and APK MIME. ZIP CRC and duplicate-name checks passed, each APK had one manifest, aapt2 matched the exact package/version/code, and apksigner verification returned rc 0 with certificate output preserved. All four native-host phases (`zip`, `metadata`, `dex`, `elf`) returned rc 0 with equal before/after APK SHA guards. Independent ZIP enumeration found no embedded DEX: all five DEX were semantically inventoried. ARM64 `readelf_ok` and machine matches cover all 11 ARM64 `lib/` `.so` entries. Per-package private TMP directories were empty after.

`HANDOFF.json` independently rereads the staged APKs and hashes every raw, GET, tool, static phase, manifest, DEX, and ELF receipt. Handoff and replay returned rc 0, `cmp` rc 0, SHA-256 `dbe061883c13a993475949c5f6fb23d2aba07bd0c79695184ea66a8edd7c4bcb`. Each of the four `intake.py` invocations returned rc 0. Original APKs remain under `NANHAI_STAGING_ROOT/peer-upstream-next4c-exact-v1/<package>/original.apk`.

These are original-APK and complete host-static **candidates for independent review**, not root admissions. F-Droid-distributed APK signatures verify, but an external publisher signing-key pin is not claimed. Static evidence does not prove install, Bionic compatibility, Activity lifecycle, display, or cold startup. No authoritative ledger, RESUME, OUTER-STATE, device, container, or Bridge was changed.
