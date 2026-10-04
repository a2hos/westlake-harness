# G279 sibling stage 1 candidate

Decision: **static candidate only; remote execution NO_GO until independent exact-SHA release**. Boundary is gz02 native host filesystem migration. This packet does not change `local_env.md`, the old root, source repositories, graph runner, owner gate, target output, devices, containers, or namespaces.

The launcher is `scripts/nanhai_plus_g279_sibling_stage1_candidate_v1.py`; the remote stdin body is `scripts/nanhai_plus_g279_sibling_stage1_remote_v1.py`. Default `--static-check` verifies the frozen migration plan, current old-root machine-readable environment digest, SSH route and pinned ed25519 host key, then prints a packet digest without contacting gz02. `--execute` requires a fixed 32-character nonce and a separately produced review JSON with `decision=ACCEPT_STAGE1_REMOTE_WRITE_ONCE`, exact launcher/body/packet SHA, proposed new root, and named independent reviewer. No release file is part of this candidate.

The remote body checks gz02/UID1000, `/data/source` UID1000 mode 0755 and no POSIX ACL, no symlink in the traversed path, new sibling absence, and all nine pinned old files before creating anything. It creates a real UID1000 root/out/tmp at 0755 and control/staging at 0700, plus an O_EXCL lease. It copies seven exact control seeds to 0444 and exact Soong UI/guard ELF bytes to 0555 under out, using O_NOFOLLOW and SHA/size/mode checks. It reopens and checks all nine old sources, reads back each new file, and writes O_EXCL `control/STAGE1-RECEIPT.json`. It does not copy the old path-bound environment JSON or old OUT/TMP/staging trees. It does not run either ELF.

Before root creation, any failed check aborts with no new root. Once created, any failure preserves the root and old tree, attempts O_EXCL `QUARANTINE.json`, and returns rc23. An SSH timeout or uncertain result is recorded locally as `UNKNOWN_QUARANTINE`; **never retry or delete automatically**. Reconcile the exact new root inode, lease, copied paths and receipt read-only before any later action. Rollback at this phase means keeping the authoritative old binding and old root untouched while quarantining the sibling; no config switch has occurred.

One reviewed command shape, after a release JSON exists, is:

```text
python3 scripts/nanhai_plus_g279_sibling_stage1_candidate_v1.py --execute --nonce <reviewed-32-hex-nonce> --review-file <independent-release.json>
```

Independent review must inspect the exact three script SHAs and packet SHA; confirm the nine source SHA/size/mode pins and destination names, no unlisted writes or generated actions, remote host key/UID/ACL checks, first failure and quarantine paths, receipt durability, and local UNKNOWN handling. Confirm sibling absence with fresh read-only gz02 preflight immediately before any separately released run. Stage 2 must regenerate `local_env.md` path bindings, path-bound JSON, runner, stager and gate in a new generation; this stage 1 packet does not authorize graph execution or replace original-owner graph ACK.

Local verification: Python compile rc0; `--static-check` rc0 with 9 files; five temporary-directory fixtures rc0 (success readback, replay reject, precreate source drift, partial quarantine, unsafe parent reject). No gz02 write, graph, target, device, container or namespace command ran.
