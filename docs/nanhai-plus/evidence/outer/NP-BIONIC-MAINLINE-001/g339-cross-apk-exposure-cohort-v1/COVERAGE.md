# G339 static exposure cohort coverage

The read-only pilot joins a `MANIFEST.json`, `DEX-INVENTORY.json`, and `ELF-INVENTORY.json` only when all three are co-located in a package directory or the standard `phases/{metadata,dex,elf}` layout. It deduplicates by `(package, APK SHA-256)`, excludes four explicitly named synthetic fixtures, and rejects conflicting duplicate exposures. Its 104 candidate package identities are **not** a re-admission of the project's 105 root-accepted complete static inventories.

Two specifically identified accepted packages are omitted by this layout rule:

- `com.junkfood.seal`, APK SHA-256 `7070a3d4f079046912b4b8dde4edc8d1ef6eade3c9c98b02bfcaba3669c11d98`.
- `org.briarproject.briar.android`, APK SHA-256 `9025888a4a5f5268e1ccbcd840bd07e51e9eaf1d7bbf305ca262b8afc662e372`.

Both have root static acceptance in `harness-stock-inventory-batch12-v3-candidate/root-review-v1/ROOT-ACCEPTANCE.json` (SHA-256 `cf41494ecedadecf5bdede379f70c7e19ffa8d795bf2d7424f0e043111b59469`). Their DEX files are under `java-trials/tuplefix-v2/<package>/`, while native ELF facts are individual `member-trials/*/ELF-RECORD.json` files joined by `AGGREGATE.json` (SHA-256 `5a1c8e42814ce5a6bc3790aa553d7ed0e540b1767edf8fcbb252f617a8cd3406`); there is no co-located ELF inventory for either package.

Because two accepted packages are omitted while the first pilot snapshot differed from the accepted total by only one, at least one pilot identity may be outside the accepted set or represented differently. During a replay, another agent wrote `peer-apk-portfolio-pipepipe-static-v2/MANIFEST.json` and corresponding inventories; the live directory scan then returned 105 candidates, including `InfinityLoop1309.NewPipeEnhanced`. That new candidate has not been checked against root admission in this pilot, and its addition explains the byte difference between `RESULT.json` and `REPLAY.json`. The exact accepted-set difference is **not yet reconciled**. Do not change the authoritative 105 or use either snapshot for progress accounting. A next version should consume an explicit root-admission identity manifest and handle batch12-v3's split member records before claiming portfolio-wide coverage.

The largest non-base native demand worth a targeted provider/loader probe is `libjnigraphics.so`, declared as `DT_NEEDED` by 32 pilot packages. This is an exposure count. It does not show that the AOSP16/Bionic provider is absent, that the library is loaded on the first-screen path, or that fixing it would start any APK. Upstream reports a same-soname shadowing case, but its runtime and namespace assumptions must not be copied into this container-free single-Bionic target.
