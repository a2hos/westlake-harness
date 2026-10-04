# Four P0 exact upstream APK candidates

The four inputs are the P0 rows of the frozen [artifact gap audit](../peer-upstream-artifact-gap-audit-v1/RESULT.json), backed by its pinned registry and `INPUTS.json`. Each GET used the registered F-Droid exact-version URL and a private native-host staging directory. No subsequent check ran until that APK's SHA-256 matched its registered artifact. All four downloads matched; each original APK remains in `NANHAI_STAGING_ROOT/peer-p0-upstream-exact-v1/<package>/original.apk`.

| Package / artifact | Exact APK SHA-256 | Bytes | Raw | Four-phase static | DEX | True ARM64 ELF |
| --- | --- | ---: | --- | --- | ---: | ---: |
| FluffyChat `a-c6a54846db20d9b2d99d` | `edcdf6171c09ab39ed76447c1ee11c66503d922dfe4f36f2dd429f2f9c652481` | 185,599,421 | GO candidate | GO candidate | 2 | 9 |
| Nextcloud `a-93343ea6fbf4c80b8f20` | `2d08059c9a0a94ef4316e5c8491e3c6aee99a87b58bb796163c44e08deb1615c` | 96,757,432 | GO candidate | GO candidate | 7 | 6 |
| OsmAnd `a-b443b6a5d594b48d6000` | `0239f0b09e1bf7e22a468b881a0a744c1a19ca72b8daf068ac3ac1b5b240e4b6` | 157,841,461 | GO candidate | GO candidate | 5 | 6 |
| Fennec F-Droid `a-1ebdf60c95b146c9966d` | `27f2951376ca1085e0933066c902fdfe4d260916d381e233475c5fd6964f5745` | 127,634,542 | GO candidate | GO candidate | 3 | 15 |

Per-package `RAW.json` records GET rc 0, final HTTP 200 APK MIME, exact SHA, ZIP CRC and duplicate-name results, one manifest, aapt2 rc 0 with exact package/version, and apksigner rc 0 with certificate output preserved. Per-package `STATIC.json` records four native-host phase rc values (`zip`, `metadata`, `dex`, `elf`), matching before/after APK SHA guards, semantic DEX inventory, and ARM64 `readelf` results. All four private TMP directories were empty after. An independent ZIP enumeration in `HANDOFF-v2.json` finds no embedded DEX in these APKs: 17 total root/semantic DEX and 36 true ARM64 ELF across the batch.

The immutable `HANDOFF.json` was the first cross-check. `HANDOFF-v2.json` adds the independent all-DEX ZIP enumeration and supersedes it for review without altering the first receipt. The v2 handoff and replay each returned rc 0, `cmp` rc 0, SHA-256 `40b3f66274597abb1fb272ae752d61e4b28b45857e09e8b682dd65e752a50a4f`. Its per-file hashes cover every raw and static receipt. All four `intake.py` invocations returned rc 0.

These are **separate original-APK and complete host-static candidates**, not root admissions. F-Droid distribution signing verifies as an APK signature, but this work does not pin the F-Droid publishing certificate externally. No installation, Bionic loader, Activity lifecycle, display, service behavior, or truly cold startup is proven. No authoritative count or control document changed, and no device, container, or Bridge action occurred.
