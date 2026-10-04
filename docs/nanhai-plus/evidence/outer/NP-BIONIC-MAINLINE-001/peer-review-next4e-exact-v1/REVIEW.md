# Independent review: next4e exact upstream four APKs

**Decision: GO for four exact original APK and complete native-host static candidates, within the limits below.** This reviewer did not author `peer-upstream-next4e-exact-v1`. No root admission, authoritative count, installation, runtime or cold-start claim follows from this review.

I read the author's `SELECTION.json` SHA-256 `8b53ba0b1ed02b3da9f00a8e79cb4ccd92dcebc1b3490551bf307ed5eb9d176c`, `HANDOFF.json` SHA-256 `f230f179735227585b742e2110673eb3c6773681c3b699e4ecf9682d86d3f574`, `CURRENT-GUARD.json` SHA-256 `8aa6b1b2880aa36da358124bd86692e94be54d17436e990af1a906ebb21fe858`, and the upstream registry. Independently, I rehashed every staged original APK, checked each artifact ID/package/version/SHA/source URL against `REGISTRY.json`, ran `aapt2 dump badging` and `apksigner verify --verbose --print-certs` again, tested every ZIP member's CRC, checked duplicate names and manifest count, enumerated all DEX paths and all `.so` ELF headers, and checked each author's four phase rc and input guards. Captured GET headers and command-output hashes were also cross-checked. The independent review command `python3 scripts/nanhai_plus_env.py --run python3 docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/peer-review-next4e-exact-v1/review.py --execute` returned rc 0. It used ordinary native host processes, no container/namespace/chroot, device or Bridge.

| Package | Exact APK SHA-256 | Bytes | DEX | True ARM64 ELF | Review |
| --- | --- | ---: | ---: | ---: | --- |
| `com.dozingcatsoftware.cardswithcats` | `19b6693e7d7fa19a0cfe63602df309e9a455d42a33670f715e082452bab3741e` | 64,348,929 | 1 | 5 | all checks pass |
| `com.exner.tools.meditationtimer` | `50a463f1b486dd9136841445b7a5e03c4e6dc5b3b72cb9ae15d445b52ad90b21` | 4,078,553 | 1 | 2 | all checks pass |
| `com.ltrademark.hourly` | `01397bdb5462c276b4d9294cab2bd32b1ae24653f94df5d0f08812bc836a2219` | 2,156,209 | 1 | 0 | all checks pass; no packaged native `.so` |
| `org.nsh07.pomodoro` | `08079f1e0795bc85047a487df30f27d0feadd2bb2a024b374a124fa183109671` | 5,763,085 | 1 | 1 | all checks pass |

The zero-ELF Hourly package is a Java-only static inventory and is not evidence of ARM64 runtime execution. F-Droid distribution URLs and registered payload hashes match, and APK signature verification succeeds; this review does not independently bind each signer to a publisher key. The author's dedup guard is bounded to the older accepted audit and individual root receipts, rather than a reconstructed complete accepted set. Root should repeat an authoritative current anti-join before admission. None of the four is an overseas-mainstream blackbox qualification candidate on this evidence.

Machine receipts: `RESULT.json` SHA-256 `a8506edd559c2458267b3276d898b2f9e357a49d5c74249e69b045bac0ed55e7`; `review.py` SHA-256 `103eea12cdbffdf08d9df6a5c6476e06c95a112a7c44a514aefbe8d4788409c0`; `RECEIPT-INTEGRITY.json` SHA-256 `235dbb10b8e1c9c0b28b3853d74940b13c3717f4aaff461053549c65e7716ee4`. Re-run the script only in a fresh review output directory after checking its one-shot guard; its raw aapt2/apksigner stdout and stderr are in package subdirectories.
