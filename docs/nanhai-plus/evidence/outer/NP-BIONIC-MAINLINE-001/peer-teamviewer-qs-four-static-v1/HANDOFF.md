# TeamViewer QuickSupport official APK: independent review handoff

This is one candidate for overseas mainstream blackbox test-input qualification. It is not root-admitted and has no installation, launch, device, or Bionic compatibility result.

## Publisher chain and exact input

The [TeamViewer Android download page](https://www.teamviewer.com/en/download/portal/android/) lists QuickSupport `15.82.264` and directly links [TeamViewerQS.apk](https://download.teamviewer.com/download/TeamViewerQS.apk). Captured page and GET headers are in `../peer-teamviewer-qs-official-raw-v1/`. The GET command returned rc 0 and yielded the unmodified 52,434,999-byte APK at `.nanhai-plus-runtime/bionic-oh7-aosp16/staging/peer-teamviewer-qs-official-raw-v1/teamviewer-qs-official.apk`, SHA-256 `2cbd20da44138342e61cde01b655b51246599555c6146d2cba7d864a102e9b5d`.

`aapt2 dump badging` rc 0 identifies `com.teamviewer.quicksupport.market`, versionCode `1582264`, versionName `15.82.264`, target SDK 36. `apksigner verify --verbose --print-certs` rc 0 reports signer certificate SHA-256 `a7d99ff485f0c55fd4f1f9cc35cb08a1b74eb995fc3f0524318ff662f8d3cd26`. This proves APK signature validity but does not independently pin the certificate to a separately published TeamViewer digest; the publisher page's direct link establishes the acquisition chain.

The [same-package Play listing](https://play.google.com/store/apps/details?id=com.teamviewer.quicksupport.market&hl=en_US) names TeamViewer and shows 50M+ package-wide downloads. It does not show 50M+ for this exact version or prove identity with the Play-delivered variant. [TeamViewer's EULA](https://www.teamviewer.com/en/legal/eula/) covers mobile applications and excludes source-code rights from its license grant; this supports bounded proprietary-client treatment, not global absence of component source.

## Native-host four-phase static

Command (outer rc 0): `python3 scripts/nanhai_plus_env.py --run .nanhai-plus-runtime/bionic-oh7-aosp16/venvs/harness-python-v1/bin/python3 docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/peer-teamviewer-qs-four-static-v1/scan.py --execute`. The exact interpreter, argv, private TMP path, and input SHA-256 before and after each phase are in `RESULT.json`. All four phases had rc 0 and unchanged input guards. No container, namespace, chroot, or device command was used.

| Phase | Bounded result |
| --- | --- |
| ZIP | 707 entries, CRC clean, zero duplicate names, one manifest, one root DEX, 34 `.so`. |
| Metadata | Exact package and version above; rc 0. |
| DEX | One semantic DEX entry; rc 0. |
| ELF | 10 true ARM64 ELFs, all `readelf` successes and ABI/machine matches; 10 ARM32 ELFs in `armeabi-v7a`, seven x86 and seven x86_64 ELFs; zero ARM32 in ARM64 paths and zero non-ELF `.so`; rc 0. |

## Receipt seal for peer review

- Acquisition `../peer-teamviewer-qs-official-raw-v1/RESULT.json` SHA-256 `0e68123ce7c05e3b14ba8228e7c248023d5e6b7076123c523ec33409a5b2bb23`; `acquire.py` SHA-256 `91f0de89ce107350017357d6c2642ca5720a77119272c37b973622a70f097749`.
- Identity/signature `../peer-teamviewer-qs-official-raw-v1/VERIFY.json` SHA-256 `03810441cf8a4ce46de011e0e7523dc2f250bfba688fe153b9f1d1559d42ccb1`; `verify.py` SHA-256 `d37d58dc66a62053e1616a5e2cfb57e5c094b031ac32cddf954c99115c9e5841`.
- Four static phases `RESULT.json` SHA-256 `f00ff18261af8239a0aa4b5aa7c1bb07c0aea25e96eab1c94d3bfcecba590222`; `scan.py` SHA-256 `f5a3869174bfa898e87cdc4f38dc3af4fac72eb2872e39ab577a1c371c0d21d8`. Phase outputs and inventory JSON are adjacent.
- Qualification `../peer-teamviewer-qs-qualification-v1/QUALIFICATION.json` SHA-256 `2ca9e180acd95ff4437f6342eb5747b3d19487412551636705fdd0711101c119`; `qualify.py` SHA-256 `39f95617a9b56cac7c6f504ca792d5a99e6f006f8c17af0a3d14f5cd2900fc50`; captured Play HTML SHA-256 `6d3bbe989fe37c3de3627ddf17828c78771ef01aca4dfba9513a7db2ab8574db`.
- Bounded EULA read `../peer-teamviewer-qs-qualification-v1/EULA-SCOPE.json` SHA-256 `5da5a8a4d601400f102de2d34f461ad14155eb5e25dfaa4fd2247ed364ef9e77`; raw EULA HTML SHA-256 `3198a7deed815ca51a521961efd3a574e4e6d1eb0647ccedbaad1cb433f2f2ec`.

Peer should independently verify the exact publisher href, APK hash/size, package/signature, four phase guards and inventory, same-package Play reach, and limited source classification. This candidate changes no authoritative ledger, recovery, or BridgeAOSPV16 file.
