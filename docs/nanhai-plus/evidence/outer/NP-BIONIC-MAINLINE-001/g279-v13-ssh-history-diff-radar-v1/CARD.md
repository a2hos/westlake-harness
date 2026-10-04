# G279 v13 gz02 route history difference card

Read-only historical comparison, 2026-10-04. No SSH, device, container, proxy change, node switch, credential read or Bridge access by this review.

## Result

The statement **“gz02 was always unavailable” is contradicted** by prior project receipts. The strongest bounded earlier proof is v13 S1 runner readback: `g279-v13-runner-stage-prep-v2/READBACK-START.json` binds the exact native SSH argv and nonce `c6f89075372a4a8d9441e6b80b88c631`; `READBACK-TERMINAL.json` reports SSH rc0, empty stderr and nonempty stdout; `READBACK-stdout.raw` contains a remote 28-entry control inventory with the staged v13 runner. Independent peer and `ROOT-STAGE-ACCEPTANCE.json` at 2026-10-04T15:18:29.844Z accept the exact staged bytes/readback. This is remote readback at that time, **not** a current connectivity claim or graph run.

The subsequent v13 EVO19 gate root receipt at 2026-10-04T15:28:27.178Z accepts a second 11-input readback, reports outer SSH rc0 and remote rc0. Its evidence is weaker for transport: raw stdout/stderr and START/TERMINAL were not separately retained, and its peer reconstructed stdout from rows. It still corroborates the earlier S1 remote result within its stated scope.

## Route/time comparison

| Time UTC | Path and exact receipt | Host/port/key choice | Observed result |
| --- | --- | --- | --- |
| 15:18 | S1 native `ssh gz02`, `READBACK-START/TERMINAL`, raw stdout/stderr, root acceptance | Pinned S1 helper checked local `ssh -G`: user `AlexYang`, host `1.95.90.207`, port `58222`, `proxycommand=none`, `proxyjump=none`. SSH argv used BatchMode, strict checking, ED25519 algorithm, user known_hosts. | SSH rc0, empty stderr, remote inventory; no graph. |
| 15:28 | EVO19 v13 `EVO19-GATE.json`, peer/root postrun | Same S1 helper SHA `9fa1f13d07a2d2586c97a818d9fee4714bb815e44382ba5194c7a72f66a12e1f` and known_hosts SHA `519aab445016e0a5fc983a1210037535908dab7711c13c9075f16e868f24b53b`; direct `gz02` alias, same exact host/port/no proxy check. | Reported SSH rc0, remote rc0, 11 rows; no graph. |
| 17:16 | v13 proxy read-only v3 `state-START/TERMINAL`, local SOCKS review | Explicit `-F /dev/null`, user/host/port, `ProxyCommand=/usr/bin/nc -x 127.0.0.1:7897 -X 5`, `HostKeyAlias=[1.95.90.207]:58222`, strict ED25519 user known_hosts. Global Verge Mihomo selected **DIRECT** for exact destination, local service log reported dial timeout. | SSH rc255, `Connection closed by UNKNOWN port 65535`; remote banner/key/auth not observed. |
| 20:09 | private v2c v6 `START/TERMINAL`, peer/root postrun | Private Mihomo rule emitted exact local line `IPCIDR(1.95.90.207/32) using PROXY[g279-v2c-selected]`; global Verge process stayed separate. Same destination/port, private selected node differs from earlier direct/no-proxy and global DIRECT paths. | Child SSH rc255, 1462 stderr bytes, reported pre-banner closed marker; private line proves rule selection only, not node outbound socket or remote TCP. |

The S1 SSH helper source (`g279-v12-signed-control-stage-launcher-v2/launcher.py:272-295`) performs the direct/no-proxy `ssh -G` and ED25519 known-host row/fingerprint checks before constructing argv. The v3 explicit proxy argv is retained in its START receipt; its local SOCKS review binds the DIRECT timeout log for the exact endpoint. The v6 exact `/32` line SHA is `e66213a4700e8e026a779909d0311ab6f8f5b1d2749938eb584ef7150f5afdde`; `peer-postrun-v6/REVIEW.json` and root postrun accept only local rule selection and bounded failure. v6 cleaned the private process/log directory, so no preserved node-outbound TCP trace is available to upgrade that result. It did **not** observe host key/auth/UID, and its 1462-byte SSH marker was not preserved as independently replayable raw stderr after cleanup.

The later failure therefore has at least a changed **route architecture** (earlier native direct, then global SOCKS→DIRECT timeout, then private `/32`→PROXY) and a changed time window. The records do not isolate whether endpoint reachability, egress routing, selected proxy node, or SSH server behavior changed. They do not show a port or pinned host-key change: all cited packets target `1.95.90.207:58222` with strict ED25519 intent. A configured/pinned host key is not a successfully observed remote host key in the rc255 sessions.

## Minimal next evidence

First freeze this historical comparison and obtain **one current local-only fact** that distinguishes private PROXY rule selection from actual selected-node outbound dial (e.g. a bounded sanitized Mihomo connection/log/API observation tied to exact endpoint, time, private instance and node alias), without credentials or new SSH. If no such retained/current fact exists, keep remote state UNKNOWN. Any later handshake must be a separately reviewed new one-shot nonce with the same pinned destination/host key, raw START/stdout/stderr/terminal retained and independent postrun; no v3/v6 replay or graph release follows from this card.
