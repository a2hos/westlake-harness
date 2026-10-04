# Four more exact upstream APK candidates

Current baseline checkpoint: upstream exact 99/338 (SHA `1fe0e1edc9f702557286a5ecdfbe7257648245fc97f23c24216eb5e68d4d628f`). `CURRENT-GUARD.json` rc 0 verifies registry and old gap-audit hashes, distinct identities, and an anti-join against the prior 79 plus individual root raw receipts. It does not independently reconstruct all 99 accepted artifacts.

Selection SHA `8b53ba0b1ed02b3da9f00a8e79cb4ccd92dcebc1b3490551bf307ed5eb9d176c`. APKs remain at `NANHAI_STAGING_ROOT/peer-upstream-next4e-exact-v1/<package>/original.apk`; private TMP and evidence are project-local.

| Package / artifact | Exact SHA-256 | Bytes | Signer cert SHA-256 | DEX | True ARM64 ELF | RAW / static |
| --- | --- | ---: | --- | ---: | ---: | --- |
| `com.dozingcatsoftware.cardswithcats` / `a-a2e99d4259611eef7917` | `19b6693e7d7fa19a0cfe63602df309e9a455d42a33670f715e082452bab3741e` | 64,348,929 | `dcb1787180dfdcdc8349998f4fe154ae119a403100da406006009c9855f99ea0` | 1 | 5 | GO / GO |
| `com.exner.tools.meditationtimer` / `a-46ebfb10ee53c6ae9855` | `50a463f1b486dd9136841445b7a5e03c4e6dc5b3b72cb9ae15d445b52ad90b21` | 4,078,553 | `3f15745561afae58a2f73ff97a517303eba059b7c608aac576fab7465df27843` | 1 | 2 | GO / GO |
| `com.ltrademark.hourly` / `a-39391b9d99f88e067474` | `01397bdb5462c276b4d9294cab2bd32b1ae24653f94df5d0f08812bc836a2219` | 2,156,209 | `d761b654c5f7a7e0cf7c9930d70946b8fcd00513bc60c719ed0e3fddbc7f9ab4` | 1 | 0 | GO / GO |
| `org.nsh07.pomodoro` / `a-6584a3fcde422ef3679b` | `08079f1e0795bc85047a487df30f27d0feadd2bb2a024b374a124fa183109671` | 5,763,085 | `07bef30581baee8f45ec93e47ee68ef20874e50ef5709c78b2ee67ac86be4c3d` | 1 | 1 | GO / GO |

Each invocation of `python3 -B scripts/nanhai_plus_env.py --run python3 -B docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/peer-upstream-next4e-exact-v1/intake.py <package>` returned rc 0; per-package stdout and stderr remain. GET from the one registered URL, aapt2 package/version check, and apksigner verification each returned rc 0. Every byte SHA matched the registered artifact before any signature or static scan. ZIP CRC, duplicate-name, single-manifest, and ABI checks passed. All four native-host phases (`zip`, `metadata`, `dex`, `elf`) returned rc 0 with equal before/after APK SHA. Independent handoff found no embedded DEX; all packaged ARM64 `.so` files were true ELF with successful matching-machine readelf.

`handoff.py` to `HANDOFF.json` rc 0; replay to `REPLAY.json` rc 0; byte `cmp` rc 0. Both handoff SHA-256 values: `f230f179735227585b742e2110673eb3c6773681c3b699e4ecf9682d86d3f574`. Current guard SHA-256: `8aa6b1b2880aa36da358124bd86692e94be54d17436e990af1a906ebb21fe858`. All handoff checks true.

These are exact original-APK and complete host-static **candidates for independent review**, not root admissions or startup evidence. F-Droid-distributed signatures verify; no external publisher signing-key pin is claimed. No authoritative ledger, RESUME, OUTER-STATE, device, container, or Bridge changed.
