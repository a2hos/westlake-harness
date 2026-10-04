# G279 v7 runner staging v4 candidate

The new `scripts/nanhai_plus_stage_runner_v7_candidate_v4.py --stage` branch is executable code, but was **not invoked** in this preparation. The fixed release directory is absent until separately prepared. Only `--static-check` and local fixtures were run. Another peer must review the exact script SHA before a single staging-only release.

Before release, verify current `local_env.md` config SHA and exact project path, source runner SHA/41,813 bytes/mode 0644, gz02 project/control UID and modes, and that neither the fixed v4 lease nor final v7 runner path already exists. Create the fixed local release directory empty; invoke once under the project environment wrapper. `UNKNOWN.json` must exist before the sole SSH transport. Keep `TERMINAL.json` and the outer exit code. If any outcome is unknown, inspect the two remote files and parent path **read-only**; do not delete or retry.

A successful staging receipt is still only copied runner bytes. Independently read back remote final SHA/size/mode/UID and lease nonce/SHA, then decide source admission. Do not execute the staged runner, Soong graph, target compilation, container, namespace, device or Bridge from this packet. The owner graph ACK plan in v3 remains unexecuted and the same-UID JSON provenance problem remains open.
