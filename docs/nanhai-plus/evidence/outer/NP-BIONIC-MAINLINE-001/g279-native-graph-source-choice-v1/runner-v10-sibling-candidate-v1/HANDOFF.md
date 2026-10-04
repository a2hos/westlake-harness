# G279 native graph v10 candidate handoff

Boundary: host-only native Linux Soong graph candidate for AOSP16 R4 ARM64 Bionic. No container or namespace isolation, remote command, graph, target compilation, APK, or device action occurred in this packet.

The candidate binds the private gz02 sibling `/data/source/.nanhai-plus-opaleye-native-v7` and stage-2 binding/config hashes. The graph working directory remains the complete, separately guarded R4 source alias `/opt/19.SourceCode/AOSP-16.0.0_r4/android-source`; the 46-link sibling source view remains a diagnostic migration artifact. The candidate validates the stage-1 receipt, stage-2 lease/receipt, binding, and directory identities observed in the independent postrun probe. Hostname comparison accepts actual `GZ02` case-insensitively.

Run locally: `python3 -B docs/nanhai-plus/evidence/outer/NP-BIONIC-MAINLINE-001/g279-native-graph-source-choice-v1/runner-v10-sibling-candidate-v1/static_fixtures.py`. Nineteen local checks pass, including stage-2 receipt mutations, preservation of descendant cleanup and namespace trace code, full-R4 graph cwd, `--static-check` rc0, and `--run` rc3. This is static/local evidence only.

Release blockers: stage exact v10 runner bytes under the sibling control and independently read back; update and review EVO19 identity gate for v10 and the active new environment; obtain a fresh graph-only ACK from the original `octos-inner` session with independent provenance; review a separate one-shot release/dispatch packet; verify inherited seccomp and child cleanup on Linux. The `--run` entry remains deliberately closed. Historical metadata ACK and stage-2 terminal do not authorize graph execution.

See `STATIC-CANDIDATE.json` for exact hashes and the closed scope.
