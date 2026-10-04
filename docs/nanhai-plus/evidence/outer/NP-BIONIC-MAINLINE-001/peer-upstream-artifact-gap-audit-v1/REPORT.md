# Upstream APK artifact gap audit (frozen root receipts)

This read-only audit fixes the upstream registry and 47 root raw-admission receipts by file SHA in `INPUTS.json`. `audit.py` uses `(artifact ID, SHA-256)` identity: an accepted package with a different APK, XAPK, split set, or version never closes a missing artifact row. `RESULT.json` lists all 79 accepted exact upstream artifacts and all 259 missing ones with complete IDs and SHA-256 values.

| Measure | Result |
| --- | ---: |
| Registry artifacts / package strings | 338 / 329 |
| Root-accepted exact upstream artifact SHA / package strings | 79 / 79 |
| Missing exact upstream artifacts | 259 |
| Package strings among missing artifacts | 251 |
| Missing package strings absent from all accepted raw receipts | 244 |
| Missing artifacts with registered F-Droid exact-version URL | 211 |
| Missing artifacts with declared ARM64 ABI | 14 |
| Missing artifacts with both declared ARM64 and URL | 4 |
| All root-accepted raw artifact SHA / distinct receipt package labels | 114 / 114 |

The 79 accepted upstream artifacts comprise 73 exact SHA matches in 11 `apk-stock-intake` root admissions and six individual root admissions: Element X, Vector, PipePipe, ntfy, Lichess, and Fossify Clock. All 79 SHA values are unique and match one registry artifact each. The 259 missing rows include a second VLC variant, `a-2ecf8dddb3fe14ca9663` SHA-256 `c493c167de52724dbdd727fd6e20ec43d89200a847fb7b7d88da850faf336bcd`; the accepted VLC variant does not cover it. Other publisher universal APKs (for example Snapchat) likewise do not replace any registered XAPK by package name.

The 114 raw SHA values and 114 distinct package **labels** are a receipt-covered count, not 114 proven cold-start apps. Among the 35 non-registry-matched raw receipts, Signal explicitly says `package_semantics_verified=false`, and WhatsApp says `manifest_package_version_verified=false`; this audit does not silently turn their proposed labels into verified manifests. Other receipts were not uniformly re-parsed here. Truly cold starts remain outside this evidence layer.

The first acquisition tier is four missing artifacts with an exact registered F-Droid repository URL and ARM64 in registry metadata. `SOURCE-HEAD.json` records `curl --head --location` rc 0, HTTP 200, APK MIME, zero body bytes for each URL. The F-Droid package pages presently list the matching version/code and ARM64: [FluffyChat](https://f-droid.org/en/packages/chat.fluffy.fluffychat/), [Nextcloud](https://f-droid.org/packages/com.nextcloud.client/), [OsmAnd](https://f-droid.org/en/packages/net.osmand.plus/), [Fennec F-Droid](https://f-droid.org/packages/org.mozilla.fennec_fdroid/). These are F-Droid-built/signed distribution artifacts; HEAD and listing do not establish that the APK bytes match the registry SHA. A bounded GET, SHA verification, ZIP/signature check, and independent root admission would be the next evidence step.

| Priority | Artifact | Registered SHA-256 | Registered exact URL |
| --- | --- | --- | --- |
| P0 | `a-c6a54846db20d9b2d99d` FluffyChat 2.9.5 | `edcdf6171c09ab39ed76447c1ee11c66503d922dfe4f36f2dd429f2f9c652481` | `https://f-droid.org/repo/chat.fluffy.fluffychat_3566.apk` |
| P0 | `a-93343ea6fbf4c80b8f20` Nextcloud 35.0.0 | `2d08059c9a0a94ef4316e5c8491e3c6aee99a87b58bb796163c44e08deb1615c` | `https://f-droid.org/repo/com.nextcloud.client_350000090.apk` |
| P0 | `a-b443b6a5d594b48d6000` OsmAnd 5.4.4 | `0239f0b09e1bf7e22a468b881a0a744c1a19ca72b8daf068ac3ac1b5b240e4b6` | `https://f-droid.org/repo/net.osmand.plus_540403.apk` |
| P0 | `a-1ebdf60c95b146c9966d` Fennec 156.0.0 | `27f2951376ca1085e0933066c902fdfe4d260916d381e233475c5fd6964f5745` | `https://f-droid.org/repo/org.mozilla.fennec_fdroid_1560020.apk` |

Ten other missing rows declare ARM64 but have no registered source URL; they need publisher or exact upstream acquisition provenance before an APK GET can satisfy their artifact IDs. Another 207 rows have a registered F-Droid URL but no ABI declaration; ZIP/ELF inspection is needed after exact SHA verification. Thirty-eight rows lack both URL and ABI declaration. Registry source URLs are leads, not current successful downloads or publisher-owned release proof.

Reproduction from project root:

```sh
python3 -B scripts/nanhai_plus_env.py --run python3 -B docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/peer-upstream-artifact-gap-audit-v1/audit.py > docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/peer-upstream-artifact-gap-audit-v1/RESULT.json
```

The audit and replay both returned rc 0, `cmp` rc 0, and JSON SHA-256 `77c0fffc751389d41575a3278201b4b46c5a420db3c6c32e72ad6bc4a3ead8a1`. HEAD probe rc 0; all four HTTP statuses were 200. No APK body, device, container, or Bridge was accessed; no canonical control artifact or original receipt was changed.
