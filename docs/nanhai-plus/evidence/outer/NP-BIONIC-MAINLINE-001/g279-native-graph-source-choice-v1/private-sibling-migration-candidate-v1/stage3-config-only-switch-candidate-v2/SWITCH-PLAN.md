# G279 Stage3 v2 — CONFIG-ONLY local binding switch candidate

This is a new generation after the Stage3 v1 PREP-only plan. Stage3 v1 remains historical. Stage2 sibling and 46-link source-view are accepted. The exact v11 runner staging one-shot has returned `STAGED_READBACK_ONLY`; its independent postrun and root acceptance must be frozen before this switch is released. This candidate has made **no** authoritative `local_env.md` edit.

## Dependency order

1. Accept independent v11 staged-runner readback and root postrun acceptance, matching the one-shot nonce, terminal, peer review, exact runner SHA and mode 0444. Preserve the Stage1/2 old/new root evidence.
2. Independently review this exact CONFIG-ONLY packet, script, proposed file and fixtures. An independent reviewer may issue `GO_CONFIG_ONLY_LOCAL_SWITCH_ONCE` with `packet_sha256`, `switch_script_sha256`, `future_file_sha256`, `v11_staging_terminal_sha256`, `v11_staging_peer_postrun_sha256`, `v11_staging_root_postrun_sha256`, and a named `independent_reviewer`.
3. Only after that release, run one `python3 switch.py --execute --review-file <exact-review>` locally. The script refuses the nonce if START or TERMINAL already exists. It creates fsynced O_EXCL START, an old-byte backup and a same-directory temporary file, replaces atomically, fsyncs the directory, runs the real env parser/check, reads back exact new bytes, and creates fsynced O_EXCL TERMINAL. No graph, target, device, container, namespace or remote command is in this executor.
4. Reconcile read-only with `python3 reconcile.py`, then independently admit only CONFIG-ONLY binding. Run fresh active-env EVO19 gate/spec; freeze the outer release; request the original `nanhai-plus/octos-inner` owner GRAPH-ONLY ACK of the exact new config, full R4 TOP and reviewed runner generation. Only a later independent graph release may authorize graph. Device remains held.

The prior Stage3 v1 order made the owner ACK precede an EVO19 gate that itself needs the new active env. The CONFIG-ONLY switch resolves that dependency without treating the switch as graph authorization. The stock graph TOP remains `/opt/19.SourceCode/AOSP-16.0.0_r4/android-source`; `source-view` is only for host UI and diagnosis.

## Exact change and identities

`PACKET.json` pins old raw file SHA `497517ad575ed18a58b9bb58a3e07306d05a1ddf3b7c3a3be1a3850a9f73cee3`, old machine config SHA `5ce3a58541ef1711890aad8348c3a31a03203f584fa50f1f5c0cb4fd88b49718`, proposed raw SHA `5fefb4ca26c218683df175452495b86a19b53e69168727adccd7eb365b22d35c`, and proposed config SHA `a4e742576589390209188cddf8d3278c294d9e87e8e9c4733e15eee0a951ddba`. Only these three keys differ:

| Key | Old | Proposed |
| --- | --- | --- |
| `NANHAI_GZ02_NATIVE_PROJECT_ROOT` | `/data/source/.nanhai-plus-opaleye-native` | `/data/source/.nanhai-plus-opaleye-native-v7` |
| `NANHAI_GZ02_NATIVE_SOURCE_VIEW` | `/data/source/.nanhai-plus-opaleye-native/source-view` | `/data/source/.nanhai-plus-opaleye-native-v7/source-view` |
| `NANHAI_GZ02_SOONG_UI` | `/data/source/.nanhai-plus-opaleye-native/out/soong-ui-v1/soong_ui` | `/data/source/.nanhai-plus-opaleye-native-v7/out/soong-ui-v1/soong_ui` |

The full R4 source root remains unchanged. The packet also binds the accepted Stage2 root SHA, v11 staging packet SHA, and exact v11 runner SHA `8b6484017d3679f4b14cde7c91e25a76f05289882fc390d3511180611714ffbe`.

## Uncertain-state and rollback rule

`START.json` says `UNKNOWN_UNTIL_RECONCILED`; it is written before the active file can change. A failure after START creates `QUARANTINE.json` if possible and never auto-rolls back or replays the nonce. The backup is an O_EXCL, fsynced exact copy of the old file. Run `python3 reconcile.py` after interruption to compare the active file with both pinned raw SHAs and inspect START, TERMINAL, QUARANTINE and backup. If active is new without a valid terminal, or any evidence conflicts, freeze all downstream gates. A rollback, if needed, must be a **separate** independently reviewed one-shot generation that restores the exact backup with a new nonce and post-readback; no manual in-place edit and no reuse of this nonce.

## Independent review checklist

- Confirm current `local_env.md` still matches the old raw/config SHA and the proposed file matches the new raw/config SHA; compare all keys, not only the three names.
- Confirm v11 staging peer review and root postrun acceptance match the terminal SHA, nonce, exact 0444 runner SHA, and old/new sibling identity; inspect the fresh remote postrun separately. Do not infer graph authority from staging.
- Review `switch.py`, `reconcile.py`, frozen `PACKET.json`, `FIXTURE.json`, exact SHA manifest and this order. Verify O_NOFOLLOW, O_EXCL START before mutation, backup, same-directory replace, fsync, no replay, and read-only reconciliation.
- Release only `GO_CONFIG_ONLY_LOCAL_SWITCH_ONCE` if all exact SHA predicates match. Keep the owner ACK request closed until active-env EVO19 and outer release are frozen.
