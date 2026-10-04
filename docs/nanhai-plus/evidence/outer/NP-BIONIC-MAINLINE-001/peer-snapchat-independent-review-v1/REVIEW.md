# Snapchat official universal APK — independent peer review

Decision for the exact 218,350,579-byte APK, SHA-256 `77c0ff8a35c513601928a6aed77fbb315b9202f494ac09a2591087f0e909e59b`:

| Layer | Decision | Scope |
| --- | --- | --- |
| Raw | `GO_OFFICIAL_UNIVERSAL_SUPPLEMENTAL_VARIANT` | Publisher support page links `additionaldownloads`; recorded GET redirects to publisher Google Storage APK. Local bytes, package/version, and APK signature verify. |
| Static | `GO_COMPLETE_HOST_STATIC` | Four candidate phases have rc 0 and equal input guards. Independent ZIP/decompression and ELF headers confirm 10 root DEX + 1 embedded DEX, 30 true ARM64 and 30 ARM32 `lib/` ELF, no non-ELF `lib/` `.so`. |
| Blackbox | `GO_BOUNDED_TEST_QUALIFICATION_ONLY` | Play lists package `com.snapchat.android`, Snap Inc., 1B+ package-wide downloads; bounded publisher repository snapshot found SDKs/samples, not a full buildable Android client. |

The APK is `com.snapchat.android` version `14.25.0.43`, code `316472`, signed by certificate SHA-256 `c7e9caf66dbe343daea2b3d9e756f7b1d913de310797cf3617ce32974617cf48`. The upstream registry's same-version artifact `a-11ed4add5570205856b8` is an 18-split XAPK with SHA-256 `a37383d12c69982786fd8a45ba4271bb16ada2ebc2f7d051e2830a2cb103d178` and a different recorded certificate SHA-256 `2f1caafca1ed30d0b4e38863eefabea0e815711fa4cf79b822519a8259d95a58`. This universal APK is a **separate supplemental variant**; no hash, signature, split completeness, or installation equivalence with the XAPK is inferred.

The ZIP also contains three `.so` files under `assets/com/snap/hexagon/skel/`. They are outside the 60 `lib/` ABI entries and the 30+30 ELF count. The independent check verified all 60 classified `lib/` entry sizes, hashes, ELF classes, and machine fields against decompressed APK bytes. It replayed `aapt2 dump badging` and `apksigner verify --verbose --print-certs`; both returned rc 0 with output hashes identical to the raw receipt. It verified raw handoff file hashes, the cross-layer handoff chain, Play snapshot hash, all four static rc/input guards, and the embedded DEX SHA. The root and embedded semantic scanner inventories were checked by their immutable hashes and rc receipts, not independently recomputed with a second scanner implementation.

Reproduction command, from project root:

```sh
python3 -B scripts/nanhai_plus_env.py --run python3 -B docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/peer-snapchat-independent-review-v1/review.py > docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/peer-snapchat-independent-review-v1/REVIEW.json
```

Initial final run rc 0; repeated run rc 0; `cmp` rc 0. Both JSON outputs have SHA-256 `002a15547ea44b6dc3bfd7c06acc221447b4df341e9463e8e5f4c9eb06326369`. The review script and outputs are confined to this peer directory; the APK and source receipts were read only.

Limits: no independent publisher certificate pin; repository inspection is bounded and cannot prove source absence globally. Play downloads are package-wide, not tied to this exact version. These host-static results do not prove install, Bionic compatibility, Activity lifecycle, cold start, rendering, or network service behavior. No authoritative count, device, container, or Bridge action was taken.

Publisher and market source pages: [Snapchat support](https://help.snapchat.com/hc/en-us/articles/7012377684756-What-devices-does-Snapchat-support), [Google Play](https://play.google.com/store/apps/details?id=com.snapchat.android&hl=en_US), [Snapchat GitHub repositories](https://github.com/orgs/Snapchat/repositories).
