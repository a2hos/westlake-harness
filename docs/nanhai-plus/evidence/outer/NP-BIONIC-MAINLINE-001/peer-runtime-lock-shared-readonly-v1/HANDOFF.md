# Shared-source runtime lock audit: NO_GO

**Decision:** The currently registered `/opt/19.SourceCode` inputs do not establish an OH7.0.0.39 + AOSP `android-16.0.0_r4` ARM64/Bionic same-build runtime lock. This is a read-only, bounded local audit, not a claim that no such output exists on any remote host. No output from old Bridge, Musl, AOSP14, or ARM32 lines is admitted.

## Exact source and output boundaries

The shared [source rules](/opt/19.SourceCode/AGENTS.md), [README](/opt/19.SourceCode/README.md), and `SOURCES.json` (SHA-256 `7d87ea12cb46a1193e60be427906f1725c02ccbeef91097d8d25d59882006636`) register AOSP `16.0.0_r4` as a partial selected source collection, not a complete local product build. Its ART source HEAD is `1690c6912a7972c9e62c39b48c706de9b8b18b4a`, matching the index. The OH `7.0.0.39` entry is a source mount alias with 520/520 manifest path/HEAD verification, not a whole-file or build acceptance. The local R4 root bounded `find -maxdepth 5` found no `libart.so`, `core-oj.jar`, or `runtime-lock.json` (rc 0; scope recorded in `SUPPLEMENT.json`). The project Bionic OUT tree has no `libart.so`, `libc.so`, `core-oj.jar`, or `runtime-lock.json` marker in the recorded read-only check.

`alexpc-aosp16/out/target/product/generic_arm64` does contain ARM64 `libart.so` and `libc.so`, `core-oj.jar`, `core-libart.jar`, and `framework.jar`. `RESULT.json` records their bytes, SHA-256 and file type. Its fingerprint is `Android/aosp_arm64/generic_arm64:Baklava/BP4A.251205.006/eng.alexya:eng/test-keys`. The shared README and index classify `alexpc-aosp16` as another existing checkout whose **exact R4 version was not verified**. Its `.repo/manifest.xml`, ART `.git`, and Bionic `.git` are absent in this bounded local view. A generic AOSP16 build fingerprint and valid ARM64 ELF types cannot prove R4 source commit, OH7 target integration, build configuration or a same-build BCP/ART/Bionic relationship. These tempting bytes are excluded from this target runtime lock.

The `OpenHarmony-7.0.0.39-dayu600-7885-Release` legacy entry is existing OH product images/build outputs; its build provenance and applicability to this AOSP16 Bionic target are not admitted. `WestLake-ART-Build-9acbaec8c3bd/worktrees/oh39-r4-musl` is explicitly historical Musl work and likewise excluded. Earlier benchmark `runtime-lock.json` files under the project source have zero system ELF entries and include Bridge-path or ARM32 contexts; they cannot substitute for a fresh target lock (see `../peer-scanner-runtime-readiness-135-v1/RESULT-v2.json`).

## Minimum missing set

1. A native ARM64/Bionic target build with exact `android-16.0.0_r4` and OH7.0.0.39 source manifest/commit and target configuration provenance.
2. Its **ordered** boot classpath manifest with SHA-256 of every actual target JAR.
3. Same-build ARM64 ART, Bionic, bridge and system ELF output bytes with SHA-256 and explicit source/build linkage.
4. Independently verified runtime index and `runtime_lock_id` binding those exact bytes. Only then can a frozen APK pilot use runtime resolution; the current static inventories do not prove runtime compatibility or launch.

## Reproduce and review

Run `python3 scripts/nanhai_plus_env.py --run python3 docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/peer-runtime-lock-shared-readonly-v1/audit.py --execute` only in a new output directory or after reviewing its one-shot guard. The recorded execution returned rc 0 and wrote `RESULT.json` SHA-256 `d933ad9a056b886b0cd1337db9b0c58b110db4bfa861cb6a57483f144869b0e2`; script SHA-256 `636232215f0b70d4fe9f921a4606ffe8653ae598350c83a086605b1642297a13`. `SUPPLEMENT.json` SHA-256 `dc5b61e9e1c023a1047d0197477d485171a65764f7d0951ca96f8c288a911ae4` records the index's two legacy classifications and exact bounded `find` argv/rc. Audit wrote only this peer evidence directory and ran no container, namespace, chroot, device, or Bridge command. No canonical or shared input was changed.
