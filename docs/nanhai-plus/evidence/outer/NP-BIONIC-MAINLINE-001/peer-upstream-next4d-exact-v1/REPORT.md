# Four more exact upstream APK candidates

Current baseline: checkpoint `upstream_exact_raw_accepted=95/338` (SHA `acf2e9821c2c864ee6e6d9d54cfb8ccf461980aa531378f9ac201fe6c9fa974f`). `CURRENT-GUARD.json` rc 0 confirms frozen registry and original gap audit, four distinct IDs/packages, and no selected SHA in older 79 accepted records or 50 individual root raw receipts. This anti-join does not itself reconstruct all 95 admissions.

Selection SHA `5e30132e37a4fb2a52c678c33fda752ce475a9ff63f01b02e0fdc62063b1d46f`. Original APKs stay under `NANHAI_STAGING_ROOT/peer-upstream-next4d-exact-v1/<package>/original.apk`; each package has private `NANHAI_TMP_ROOT` and a project-local evidence directory.

| Package / artifact | Exact SHA-256 | Bytes | Signer cert SHA-256 | DEX | True ARM64 ELF | RAW / static |
| --- | --- | ---: | --- | ---: | ---: | --- |
| `com.best.deskclock` / `a-d7daa96aea3c791870be` | `64d6152ff3a5c84ee45ca96b3c0003e058965371f6a6c5060e56a54300e69a01` | 7,181,862 | `91aec64808918f21cfec27339cc5bd3f529759fc79ac32ba4379531595bd375c` | 1 | 0 | GO / GO |
| `com.justdeax.composeStopwatch` / `a-e35b50eef5173077f344` | `dbf937ebbe7c0b3d24c07fa0ede7cb53ea117f7071db3b61f1c96b7d257cda55` | 1,451,410 | `6b2ab59a567e5e05d5a3d56366bd5ae0d12a11ee2e1046d54d149bfa5343d2e0` | 1 | 2 | GO / GO |
| `com.k.todo` / `a-59cc2e162d53c8fa98e1` | `77e8d32476d9db8870e5705975dead6143115127feef616db96e6637de8aec01` | 30,222,956 | `6c423a8bc5f36e69b17dcb01345e31fa4ee0168ffc63099ff1a6f3a6ddc02b6b` | 2 | 4 | GO / GO |
| `app.siftrecipes` / `a-75624e2e4a82f10589b8` | `fdc68ce83806767d43b057aaa5db12c8eead58093623f09f37fec9928507244e` | 78,674,715 | `05fab0d4078ea7d473298f4bb47646c7196057ea17809e2941930487c889f9c5` | 3 | 46 | GO / GO |

Each package command was `python3 -B scripts/nanhai_plus_env.py --run python3 -B docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/peer-upstream-next4d-exact-v1/intake.py <package>`; all four returned rc 0. Per-package command stdout/stderr are preserved. Each fresh registered-URL GET, aapt2 manifest/package/version check, and apksigner verify returned rc 0; GET bytes matched the registry SHA exactly before further validation. ZIP CRC, duplicate-name, single-manifest, and ABI checks passed. Four native-host phases (`zip`, `metadata`, `dex`, `elf`) each returned rc 0 with equal before/after APK SHA. Independent handoff found all DEX at ZIP root (embedded DEX 0) and all packaged ARM64 `.so` files were true matching ELF/readelf successes.

Handoff command `python3 -B scripts/nanhai_plus_env.py --run python3 -B .../peer-upstream-next4d-exact-v1/handoff.py > HANDOFF.json` rc 0; identical replay to `REPLAY.json` rc 0; `cmp HANDOFF.json REPLAY.json` rc 0. Handoff SHA `4cbe92d965affe5d3840087f99bbcc272c24bb035b955e665cc141cd2cdece5a`, replay SHA `4cbe92d965affe5d3840087f99bbcc272c24bb035b955e665cc141cd2cdece5a`. Guard SHA `2ccef361c219a0f1726340c1b407396e5f2314779e54543c448afa6e34c61893`.

These are original-APK and complete host-static **candidates for independent review**, not root admissions. F-Droid-distributed APK signatures verify; no independent publisher signing-key pin is claimed. Static evidence proves no install, Bionic compatibility, Activity lifecycle, display, or cold startup. No authoritative ledger, RESUME, OUTER-STATE, device, container, or Bridge was changed.
