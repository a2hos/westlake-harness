# EVO60: publisher download-chain edge gate

Problem: a publisher landing page, its JavaScript, an API response, and the final APK CDN may use different hosts. A valid APK signature and package do not by themselves show that the recorded GET URL was actually selected by the publisher page. Xender's current candidate supplies all four frozen layers, so it is a small offline test of this provenance boundary. This direction differs from EVO59's summary/board freshness gate.

Inputs: Xender `peer-xender-qualification-v1/{QUALIFICATION.json,landing.raw,js.raw,config.raw}`, `peer-xender-official-raw-v1/{RESULT.json,VERIFY.json,apk-get-headers.raw}`, and the staged original APK. `pilot.py` reads all inputs only through the project path or `NANHAI_STAGING_ROOT`, checks each frozen SHA, then checks landing → exact JS filename → exact API base → one Android config package/version → config download URL = actual GET URL → exact APK SHA. It makes no network request.

Actual commands from project root:

```sh
python3 -B scripts/nanhai_plus_env.py --run python3 -B docs/nanhai-plus/evolution/EVO-0060-publisher-chain-edge-gate/pilot.py > docs/nanhai-plus/evolution/EVO-0060-publisher-chain-edge-gate/POSITIVE.json
python3 -B scripts/nanhai_plus_env.py --run python3 -B docs/nanhai-plus/evolution/EVO-0060-publisher-chain-edge-gate/pilot.py --counterexample > docs/nanhai-plus/evolution/EVO-0060-publisher-chain-edge-gate/COUNTEREXAMPLE.json
```

Result: frozen positive rc 0, `GO`, zero failed edges. An in-memory counterexample changes only the parsed Android config CDN URL to `https://example.invalid/other.apk`; it returns rc 2, `NO_GO`, with exactly `android_config_matches_get_url` failed. Positive JSON SHA-256 `4580d55d61f03748e67c02b7de570cce09a58e9aa4d7528656523cb66b7ee31e`; counterexample SHA-256 `39cf07459d584aef0668268486d3d6fd940c16ee3430d2635a3a6fc4a09aac20`; pilot script SHA-256 `7ee817756e8cb7d1be2abe14fe5888f0abb519b90f989f8b66981ed685f74062`.

One proposed improvement: require this byte-pinned **edge check** before accepting a multi-host publisher download chain as provenance evidence. It catches a case where each component exists and the APK verifies, but the CDN URL in the saved publisher config differs from the actual GET target. It does not prove domain ownership, a publisher certificate pin, or that the current live site still serves those bytes.

Promotion gate: independent peer review of this Xender pilot, then one second publisher with a different page/API/CDN structure and a negative same-package wrong-CDN case; require exact raw headers and APK hash in both. Until then this stays a read-only pilot, not a canonical verifier or count update. If the gate rejects a valid publisher flow because URLs are dynamically signed, retain the full frozen chain for manual review and narrow the edge rule to that observed API contract.

No total ledger, original 89-tool denominator, device, container, Bridge, or production script was changed. Static/raw evidence remains separate from startup evidence.
