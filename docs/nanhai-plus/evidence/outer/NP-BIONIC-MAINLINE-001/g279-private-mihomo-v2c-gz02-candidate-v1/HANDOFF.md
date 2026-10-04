# G279 v2c private gz02 route candidate — code only

This candidate advances the accepted v2b v4 **bounded local TEST-NET-3 REJECT fact** to a separately gated, one-shot private Mihomo `/32 → PROXY` and host-key-pinned, read-only gz02 SSH identity probe. It is **not released or executed**. No Mihomo instance, real SSH connection, device, container, graph, HK01 hop, or global proxy change was made for this candidate.

`runner.py` pins the v2a and v2b acceptance receipts, their terminal hashes, local `/usr/bin/ssh` and `/usr/bin/nc` hashes, one unambiguous ED25519 known_hosts entry, and a separate v2c private root. A future run would require an independent peer `GO_V2C_V1_CODE_ONLY` receipt and a root-issued exact release binding the candidate and peer hashes. Both are absent. The release is one shot; `START.json`/`TERMINAL.json` presence blocks replay.

The proposed runtime sequence rechecks the selected node and source immediately before a 0600 private config write, proves the local negative REJECT in the new isolated instance, then uses `ssh -F /dev/null` with a fixed loopback SOCKS `ProxyCommand` and strict host-key verification to execute only `LC_ALL=C /usr/bin/id -u` on gz02. It requires rc 0, the pinned server key fingerprint, public-key authentication, and a strict full-line Mihomo `IPCIDR(1.95.90.207/32) using PROXY[...]` route record. Raw logs, selected node name, source credentials, and full SSH debug text remain private and are not exported. The local negative record is separately normalized by the v2b exact-line parser.

The top-level `main` catches `Exception` only, then calls `sys.exit(main(...))` outside the handler. This avoids the observed v2b `BaseException`/`SystemExit(0)` rc2 defect. The instance scope still catches `BaseException` solely to stop and account for its own process group before returning a bounded failure.

Offline fixture validation is recorded in `FIXTURE.json`. The `ssh -G` check expands the fixed local configuration only; it does not open a connection. The positive log pattern is an intentionally strict candidate oracle; the exact current Mihomo binary's real gz02 route line has **not** been observed and must be independently reviewed before release. A mismatch must fail closed and cannot be interpreted as route success.

No v2b private credential, process, nonce, or port is replayed. A future v2c run owns its private config/log lifecycle and cleanup gate; failure to prove process stop retains the private directory for controlled review and denies success.
