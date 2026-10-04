# Native Linux host entry recheck — current NO_GO

The project still has no reachable, authenticated native Linux x86_64 build host. This recheck used only the registered aliases `gz02` and `alexpc`, with no credentials printed and no remote SSH command.

At **2026-10-04 22:26:35 UTC** (local receipt timestamp):

- `ssh -G gz02` returned rc 0 and resolved the effective endpoint to `1.95.90.207:58222`; no `ProxyCommand` or `ProxyJump` is active. Literal address resolution returned rc 0. A bounded TCP connect timed out after 3.003 s (probe rc 2), before an SSH banner or host-key exchange.
- `ssh -G alexpc` returned rc 0 and resolved `alexpc.local:22`; no proxy is active. DNS was bounded at 5 s and returned rc 124 (`timeout`), so TCP was not attempted.
- Local `ssh-keygen -F` lookups returned the saved known-host entries, but those are historical local pins; neither endpoint reached a fresh server-key exchange.

Exact top-level command:

```sh
python3 -B scripts/nanhai_plus_env.py --run python3 -B docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/peer-native-linux-host-entry-20261005-v2/probe.py > docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/peer-native-linux-host-entry-20261005-v2/OBSERVATION.json
```

The diagnostic returned rc 0; this does not mean host readiness. `OBSERVATION.json` records each argv, rc, elapsed time, effective non-secret SSH fields, local config hashes, and the zero remote-command boundary. This run performed zero SSH sessions, remote commands, graph/build commands, device commands, container/namespace commands, Bridge accesses, network changes, and old-nonce replays.

Prior independent failure receipt remains [peer-native-linux-host-entry-20261004-v1/REPORT.md](../peer-native-linux-host-entry-20261004-v1/REPORT.md): gz02 had the same TCP timeout and alexpc the same DNS blocker. The shortest next command, after restoring a project-owned route and independently confirming current host-key pins, is a **new** strict read-only packet:

```sh
ssh -o BatchMode=yes -o StrictHostKeyChecking=yes gz02 'uname -a; id -u; test -r /opt/19.SourceCode/AOSP-16.0.0_r4/android-source/.repo/manifest.xml && echo manifest-readable'
```

Do not run that packet until the route and current pin are independently confirmed; its expected scope is identity/input readability only, not graph execution or APK startup.
