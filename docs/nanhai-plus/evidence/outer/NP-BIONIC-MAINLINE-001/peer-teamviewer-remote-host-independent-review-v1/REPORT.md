# Independent TeamViewer Remote and Host candidate review

**Decision: both packages are independently reviewable original-APK, four-phase host-static, and bounded overseas-mainstream blackbox test-input candidates.** They remain separate packages and are **not** root admissions or cold-start results.

| Layer | TeamViewer Remote | TeamViewer Host |
| --- | --- | --- |
| Original APK | GO: `com.teamviewer.teamviewer.market.mobile`, `15.82.270` / `1582270`, SHA-256 `2428b81eb78e93ebacb0dde64fc1a5f382e2446db8521b8481b0d74ee4cdc935`, 245,891,200 bytes | GO: `com.teamviewer.host.market`, `15.82.263` / `1582263`, SHA-256 `0372259d3a49ff007e62ca5f56f0145b8afedb2d7ff79224034e1025c3dc27bb`, 68,939,457 bytes |
| Host static | GO: ZIP/metadata/DEX/ELF rc 0, 2 DEX and 9 true ARM64 ELF | GO: ZIP/metadata/DEX/ELF rc 0, 1 DEX and 11 true ARM64 ELF |
| Blackbox input qualification | GO bounded: same-package Google Play listing shows 100M+ package-wide downloads | **Separate GO bounded:** same-package Google Play listing shows 5M+ package-wide downloads. This is materially weaker scale than Remote, yet sufficient evidence of substantial overseas use under the project rule, which specifies no numeric minimum. |

The captured [publisher Android page](https://www.teamviewer.com/en/download/portal/android/) binds the named product blocks to `TeamViewer.apk` and `TeamViewerHost.apk` on `download.teamviewer.com`. Each GET receipt shows the matching redirect to `dl.teamviewer.com/mobile/<same filename>` and final HTTP 200. Host's final response uses `application/octet-stream`; Remote uses `application/vnd.android.package-archive`. The first exploratory review rejected Host solely on the narrower MIME assumption (rc 2) and is retained. The final review accepts those two explicit types only after independently verifying the actual APK bytes, ZIP/manifest, package/version with aapt2, and signature with apksigner. Both signatures verify and have the same signer certificate SHA-256 `a7d99ff485f0c55fd4f1f9cc35cb08a1b74eb995fc3f0524318ff662f8d3cd26`; no external publisher certificate pin is asserted.

Independent checks rehashed the staged APKs and candidate receipts, re-enumerated ZIP members/CRC, ran aapt2 and apksigner anew, checked all four phase return codes and equal input SHA guards, compared root versus all DEX entries (embedded DEX 0), and confirmed no ARM32 ELF or non-ELF `.so` under either ARM64 path. The Play snapshots contain the exact package IDs, TeamViewer Germany GmbH, and the quoted download bands. These bands apply to each **package overall**, not the downloaded exact version. The previously captured TeamViewer EULA scope receipt supports proprietary mobile-client treatment, without proving global absence of every third-party component's source. A bounded root-receipt search found neither package previously admitted; QuickSupport is a different package.

Replay, from project root:

```sh
python3 -B scripts/nanhai_plus_env.py --run python3 -B docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/peer-teamviewer-remote-host-independent-review-v1/review.py > docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/peer-teamviewer-remote-host-independent-review-v1/REVIEW-v3-REPLAY.json
```

Final review and replay both returned rc 0; `cmp` rc 0. Their common SHA-256 is `da8b85e1a10f78e391349b9582bb768e3fafe7965744dfb2b7a847a0a61092ff`. Review script SHA-256 is `f635d790b98e5aacd90a851d37a0c4f74823a4eba53b55ba6dcba13ab9f0777d`. The structured receipt records per-layer checks, candidate receipt hashes, and separately captured independent tool output. No device, container, Bridge, or authoritative count was touched. Static inspection and market qualification do not establish install, Bionic execution, Activity lifecycle, display, or truly cold start.
