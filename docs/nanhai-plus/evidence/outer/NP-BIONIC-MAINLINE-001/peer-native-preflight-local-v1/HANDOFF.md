# Native R4 H1–H4 offline preflight packet candidate

Decision: **GO for local static/fixture review only; NO_GO for SSH, host preflight or graph execution.** `preflight_packet.py` defaults to `DRY_RUN_ONLY`. Its only nondefault input is a local synthetic JSON fixture; `--execute` is hard-rejected with rc 4. The code has no SSH, network, subprocess, container, namespace, device or Bridge call path. `test_offline.py` only invokes this local Python tool. No existing v13 packet or nonce was replayed.

The v13 graph runner SHA-256 `36cbba5abfd1d99adf47e360c5c5b532887a466763929d5e22cd6b05eddb6a99` already guards gz02 source, control files, graph-only argv, release signature and process trace, but is fixed to gz02/old staged paths and an execution-adjacent old release. It does **not** provide a new host-key-pinned SSH entry, new one-use nonce, or before-graph R4 Clang/sysroot candidate door. This addition is only an offline H1–H4 receipt-shape validator; it neither modifies nor duplicates that runner's graph execution.

The four gates stop at the first failure: H1 checks project-scope/one-use authorization fields, nonce format and known-old denial, Linux x86_64 identity and matching host-key pin; H2 checks exact R4 manifest, 1011/2 project closure, clean heads, full Bionic checkout and Soong patch pin; H3 checks candidate host tools, `clang-r563880c`, resource/sysroot hashes and a required *post-graph* generated-action readback; H4 checks project-private OUT/TMP, read-only source, direct forbidden launcher names, container/namespace observations and the future process-trace obligation. No container or namespace substitute is used.

These checks validate **asserted fixture fields**, not real signatures, host keys, filesystem SHA, remote source state or process traces. A positive fixture means `STATIC_FIXTURE_PASS_NOT_REMOTE_AUTHORIZATION`; its synthetic hashes and freshness assertion cannot authorize SSH. A real packet still needs a new signed project-scoped release, a fresh nonce checked against the actual one-use ledger, an independently pinned host key, authenticated read-only Linux readback, and source/tool/file verification before any graph-only release. The static packet schema deliberately emits no runnable SSH argv. After graph, generated compiler/sysroot action identity must be read back before target compilation.

Local validation command:

```text
python3 docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/peer-native-preflight-local-v1/test_offline.py
```

Actual rc 0. `TEST-RESULTS.json` retains each exact subprocess argv, rc, fixture input SHA-256, raw stdout/stderr SHA-256 and first-failure gate; raw outputs and fixtures are adjacent. Fifteen cases passed: default dry-run rc 0; positive synthetic fixture rc 0; old nonce, mismatched/unpinned host key, missing one-use authorization, incomplete R4 source, missing sysroot or post-graph obligation, observed container or namespace, `unshare` launcher, overlapping/traversal OUT path all rc 2 at the expected first gate; explicit `--execute` rc 4. All 15 have remote calls 0.

Source inputs: prior root-limited `peer-hello-native-closure-packet-v1/PACKET.md` SHA-256 `566d92b868ed280d787dfe40a1054cd4ae204854646d4f9b2631ce7bbcb769d4` and the v13 runner named above. No canonical control, source, registry, count, inner agent, device or Bridge file was changed.
