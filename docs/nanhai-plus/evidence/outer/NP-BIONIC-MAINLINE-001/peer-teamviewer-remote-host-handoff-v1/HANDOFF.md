# Two TeamViewer Android packages: independent review handoff

Two different package IDs are candidate overseas-mainstream blackbox **test inputs**, subject to non-author independent review and root admission. No cold start, device, Bionic compatibility, or canonical count is claimed.

The [publisher Android page](https://www.teamviewer.com/en/download/portal/android/) lists each product with its version, [Google Play](https://play.google.com/store/apps/details?id=com.teamviewer.teamviewer.market.mobile&hl=en_US) link, and direct APK link. Captured HTML confirms both APK and Play links for the corresponding product blocks. These are publisher downloads, not third-party mirror payloads.

| Product | Exact package and version | Publisher APK | Original APK SHA-256; bytes | Play reach |
| --- | --- | --- | --- | --- |
| TeamViewer full client | `com.teamviewer.teamviewer.market.mobile` `15.82.270` (`1582270`) | [TeamViewer.apk](https://download.teamviewer.com/download/TeamViewer.apk) | `2428b81eb78e93ebacb0dde64fc1a5f382e2446db8521b8481b0d74ee4cdc935`; 245,891,200 | 100M+ package-wide |
| TeamViewer Host | `com.teamviewer.host.market` `15.82.263` (`1582263`) | [TeamViewerHost.apk](https://download.teamviewer.com/download/TeamViewerHost.apk) | `0372259d3a49ff007e62ca5f56f0145b8afedb2d7ff79224034e1025c3dc27bb`; 68,939,457 | [5M+ package-wide](https://play.google.com/store/apps/details?id=com.teamviewer.host.market&hl=en_US) |

Both original APKs passed ZIP CRC/duplicate-name/manifest/ARM64 presence checks; `aapt2 dump badging` and `apksigner verify --verbose --print-certs` each returned rc 0. Both carry signer certificate SHA-256 `a7d99ff485f0c55fd4f1f9cc35cb08a1b74eb995fc3f0524318ff662f8d3cd26`. Signature validity plus the direct publisher link support the acquisition chain; there is no independently published certificate digest pin in this candidate.

The four native-host phases ZIP, metadata, DEX and ELF all returned rc 0 for each APK with equal per-phase input SHA-256 guards. The exact interpreter/argv is recorded in each `RESULT.json`: `python3 scripts/nanhai_plus_env.py --run .nanhai-plus-runtime/bionic-oh7-aosp16/venvs/harness-python-v1/bin/python3 <candidate scan.py> --execute`. Temporary directories are project-private. No container, namespace, chroot, device or Bridge command ran.

| Product | ZIP | DEX | True ARM64 ELF | Other ELF | Wrong ARM32 under ARM64 / non-ELF SO |
| --- | ---: | ---: | ---: | --- | ---: |
| Full client | 1,541 | 2 | 9 (9 `readelf`/machine matches) | 9 ARM32, 18 x86/x86_64 | 0 / 0 |
| Host | 874 | 1 | 11 (11 `readelf`/machine matches) | 11 ARM32, 16 x86/x86_64 | 0 / 0 |

Reviewable receipt hashes:

| Product | Acquisition `RESULT.json` | Identity `VERIFY.json` | Four-phase `RESULT.json` | Qualification `QUALIFICATION.json` |
| --- | --- | --- | --- | --- |
| Full client | `1990f995e3142e56643406ea291c6490afbf451537258dba9f8385bf948ffc8c` | `cac694785578394cf46344ec1c7dd4b27819ce08564368eee05a37ce7b6243be` | `9c56c7269453ded9f6b08694ea02ffbf419d0ae14e93a269f9e745dce3d91a7d` | `e82aa1f8e5f528ec6955ef78ddf1779c61fdcd69e18561503be87c8c91ae5532` |
| Host | `a37a77b47869dee73b5ec0061efb9caa27a62dda465e99256b11808ad139c40c` | `6de584beb126f7fa5a51c5cdee534aac79e5333ca29c4662e1c94c0a37b096d7` | `3eb709e3e90d1990e1a2985ff8e468b442a1bcfe9bfaf946e957816661bb20f6` | `d4ea4d6448b25d6c8ea0c08c86959c7a65f81b73fcffd98fc04c12bf595cdc23` |

The source boundary is the TeamViewer [EULA](https://www.teamviewer.com/en/legal/eula/) covering mobile apps and excluding source-code rights from the license grant; its prior same-publisher read is `../peer-teamviewer-qs-qualification-v1/EULA-SCOPE.json` SHA-256 `5da5a8a4d601400f102de2d34f461ad14155eb5e25dfaa4fd2247ed364ef9e77`. This does not prove global absence of third-party component source. Host's 5M+ Play scale is weaker than the full client's 100M+ and should receive an explicit independent mainstream decision.

`CANDIDATES.json` SHA-256 `90d95c7360ddcb022ed26217e7ac5a5642205ea75af44b3ff40f68b3ccfe9785` binds both package IDs, original hashes, receipt hashes and a bounded root-receipt dedup search (rc 1, zero matches at capture time). Each product's raw outputs and scripts reside in its own `peer-teamviewer-{remote,host}-{official-raw,four-static,qualification}-v1` directory. Preserve separate package admission decisions; neither should inherit QuickSupport's or the other's status.
