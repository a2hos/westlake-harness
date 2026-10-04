# G339 v2: frozen 105 APK native dependency cohort

This is a host-only pilot derived from the [upstream WestLake method](https://github.com/A2OH/westlake-harness): aggregate a declared APK surface across a corpus before selecting a common conformance probe. It uses the current project's OH7.0.0.39 / AOSP16 r4 / ARM64 / single-Bionic target. It does not copy upstream namespace/container assumptions or claim a provider is absent.

`build_lock.py` fixes the pre-batch105 checkpoint (`1ddae14d…`), 105 exact root-accepted package identities, root receipt hashes, APK SHA-256, and static input hashes. It excludes `wrong.package` as a negative synthetic control. The three later root-accepted PipePipe, ntfy, and Lichess packages belong to the next cohort and are explicitly out of this frozen snapshot. The previous dynamic directory scan included `wrong.package` and missed two accepted packages because Seal and Briar store native records separately; `analyze_lock.py` joins their `AGGREGATE.json` member references by SHA-256 and verifies the DEX/manifest hashes.

Commands, both rc=0:

```sh
python3 -B scripts/nanhai_plus_env.py --run python3 -B docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g339-cross-apk-exposure-cohort-v2/build_lock.py > docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g339-cross-apk-exposure-cohort-v2/LOCK.json
python3 -B scripts/nanhai_plus_env.py --run python3 -B docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g339-cross-apk-exposure-cohort-v2/analyze_lock.py docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g339-cross-apk-exposure-cohort-v2/LOCK.json > docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g339-cross-apk-exposure-cohort-v2/RESULT.json
```

Each command was repeated with byte-identical output (`LOCK-REPLAY.json`, `REPLAY.json`). A mutated lock containing `wrong.package` was rejected rc=1. The locked result has 105 identity/input SHA-verified packages and finds 34 whose ARM64 ELF records declare `DT_NEEDED: libjnigraphics.so`. This is an **exposure cluster**, not a current Bionic provider verdict, first-screen reachability result, repaired issue, device pass, or startup. Its actionable next step is one exact-provider/loader-order probe on the current Bionic build, then a real cold-start backtest when the HelloWorld base and device HOLD gates permit it.
