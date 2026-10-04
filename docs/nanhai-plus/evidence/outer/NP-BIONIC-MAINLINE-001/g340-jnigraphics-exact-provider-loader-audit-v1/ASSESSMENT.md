# G340 exact R4 `libjnigraphics` provider/loader audit

Decision: **NO_GO for a provider or loader verdict.** The G339 frozen 105-APK cohort shows 34 ARM64 packages with `DT_NEEDED: libjnigraphics.so`. This is a declared dependency, not evidence that any of the 34 reaches it during cold start.

What is proven locally:

- The shared source index registers a complete, pinned, read-only `frameworks/base` checkout for `android-16.0.0_r4` at `45034f0663f960d9ee5fb0a101a4732b71f6e2f4`. `git` reports the four provider source files clean. `native/graphics/jni/Android.bp` defines `cc_library_shared` named `libjnigraphics` with Android-side `bitmap.cpp`, `imagedecoder.cpp`, a version script, and dependencies including `libhwui`, `liblog`, and `libandroid`. The source map declares AndroidBitmap and AImageDecoder entry points. This proves a source/build definition, not a completed target binary.
- The current Bionic disposition for legacy `flutter-libjnigraphics-n1` is **replace** with this R4 framework implementation; its target plan remains `not_run`, `build.ready=false`, `source_build_accepted=false`. The legacy Musl facade is historical and cannot be treated as this target's provider.
- The local `product-config/r4-selected` directory currently contains 24 `.mk`/`.bp` files and none explicitly mentions `libjnigraphics`. The source index calls this selection partial and notes an additional local config whose admission was unresolved; the scan does not promote that file. Absence of a mention says nothing conclusive about transitive Soong selection or final product packaging.
- An exact-name read-only scan of the project's independent Bionic OUT/staging tree found **zero** `libjnigraphics.so` files. Current graph/build receipts do not establish an ARM64 target build. No local target artifact is available for `readelf`.

What is not proven: target `.so` existence on the native Linux build host or product image; its ELF machine/ABI, `DT_SONAME`, exported-version set and `DT_NEEDED` closure; final install path; duplicate same-name libraries; linker configuration/search order in the App's single-Bionic process; runtime `dlopen` choice; first-screen reachability; or any of the 34 APKs' cold starts. No device, SSH, proxy, container, or namespace operation was used.

**One minimum next probe, gated on the authenticated exact-R4 native Linux product build:** ask the original build owner for the produced `libjnigraphics.so` and its product-install manifest from the same Soong generation, then run `llvm-readelf -h -d -Ws` on that exact file and enumerate all installed files of the same basename in that product generation. Record the file SHA-256, ELF `AArch64` machine, `DT_SONAME`, AndroidBitmap/AImageDecoder exports, `DT_NEEDED`, source/toolchain/product generation, and all candidate install paths. If no same-generation artifact exists, retain NO_GO and route the R4 module/dependency build as the next task. A valid artifact would retire only the **missing-local-provider** hypothesis; loader selection still requires the actual App linker config and later runtime mapping under the existing device HOLD gate. This probe can change which provider work is prioritized, but cannot by itself promote or demote 34 APK startup outcomes.

The reproducible host-only command is:

```sh
python3 -B scripts/nanhai_plus_env.py --run python3 -B docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g340-jnigraphics-exact-provider-loader-audit-v1/audit.py > docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g340-jnigraphics-exact-provider-loader-audit-v1/RESULT.json
```

It returned rc=0 twice with byte-identical `RESULT.json` and `REPLAY.json`. `RESULT.json` records the source hashes and exact negative local output finding. The status inside the result is `NO_GO_PROVIDER_AND_LOADER_UNPROVEN`.
