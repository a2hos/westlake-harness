# Current project native Linux host entry: local NO_GO

At **2026-10-04 22:05 UTC**, neither of the two project host leads reached an SSH handshake. `local_env.md` registers `gz02`; `alexpc` is a prior project backup lead and an SSH alias. The effective SSH configuration points to `gz02` at `1.95.90.207:58222` and `alexpc.local:22`. No proxy jump or proxy command is active for these aliases. The local `known_hosts` contains fingerprints for both, but this read-only lookup is **not** fresh server-key verification or independent owner pin attestation.

| Lead | Bounded observation | First blocker |
| --- | --- | --- |
| `gz02` | `ssh -G gz02` rc 0 at 22:05:26 UTC; literal-IP `getaddrinfo` rc 0; TCP connect to `1.95.90.207:58222` timed out after 3.003 s (probe rc 2). `ssh-keygen -F '[1.95.90.207]:58222' -f ~/.ssh/known_hosts -l` rc 0. | TCP route/connectivity, before SSH banner or host-key comparison. |
| `alexpc` | `ssh -G alexpc` rc 0 at 22:05:29 UTC; `alexpc.local` `getaddrinfo` hit the 5 s bound (rc 124); TCP not attempted. `ssh-keygen -F alexpc.local -f ~/.ssh/known_hosts -l` rc 0. | Local hostname resolution, before TCP or SSH. |

The top-level native command was:

```sh
python3 -B scripts/nanhai_plus_env.py --run python3 -B docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/peer-native-linux-host-entry-20261004-v1/probe.py > docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/peer-native-linux-host-entry-20261004-v1/OBSERVATION-v2.json
```

It returned rc 0 as a **completed diagnostic**, not a successful host entry. `OBSERVATION-v2.json` SHA-256: `0e2444a22c17f685bfee4454bd2ecab76e27605305c56d65d0a59ce4f58c377e`; script SHA-256: `eb9ade6c3fd6ba41ef1ee4ecb1bf56523e0bc660c01e360ffd7157981dab98a5`. Its timestamped per-step results and fingerprints are the detailed receipt. The initial observation (`OBSERVATION.json`) remains as history; v2 added command times without changing the probe boundary.

**Next gate:** restore a project-owned reachable native Linux x86_64 route. For `gz02`, independently confirm current server host-key fingerprint against the owner pin before strict `BatchMode=yes`, `StrictHostKeyChecking=yes` SSH; for `alexpc`, resolve the registered name and confirm its current project ownership and pin. Only then run a new read-only remote identity/source/toolchain/OUT-capacity packet. No SSH, remote command, graph, old nonce, device, container, namespace, Bridge, or canonical-file mutation occurred here. A saved key or historical host receipt does not establish current host identity or R4 readiness.
