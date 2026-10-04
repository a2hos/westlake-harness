# G274/v18 container-to-native migration design (read-only)

**Decision: `NO_GO_NO_LOCAL_EXECUTABLE_NATIVE_PATH`.** This review translates the old G274/v18 input gates into a no-container native-host sequence. It does not execute a graph, compile a target, open SSH, touch a device, access BridgeAOSPV16, or replay a nonce.

The historical receipts establish three different facts:

1. **G274 input closure only.** The candidate freezes nine exact source roots and an SDK guard, but records `graph_executed=false`, `target_compiled=false`, and root status `ROOT_ADMIT_G274_V18_INPUT_ONLY_NOT_EXECUTION`. Its peer review says a v18 materializer and independent review are still required.
2. **G278 host-tool closure only.** On the historical GZ02 run, `ssh_batchmode_rc=0` and `build_rc=0` produced a Linux x86_64 patched `soong_ui` host tool from a 46-link source view. The receipt explicitly limits the claim: UI-level sandbox switches only; generated Ninja actions may still embed `nsjail`; no Soong binary execution, graph, target compile, or device result.
3. **v18 extension remains unreleased.** The independent v18 review is `PASS_STATIC_EXTENSION_ONLY_DO_NOT_DISPATCH_OR_EXECUTE`; `STATIC-CHECK.json` says `STATIC_CANDIDATE_ONLY_NOT_RELEASED` and `root_seal=false`. The v18 materialization records 38 read-only roots (29 old plus 9 new), but this is a content manifest, not a current Linux mount or build result.

The native replacement therefore needs this order:

1. Preserve the G274 nine-root and v18 38-root allowlist as a read-only manifest under `NANHAI_SOURCE_POOL_ROOT`; do not copy unregistered source or SDK payloads.
2. On a freshly authenticated Linux x86_64 host, resolve each pool-relative root, verify repository HEAD/tree/blob and all symlink targets, then create an isolated project source view. Fail closed on missing roots, changed hashes, unresolved links, or a non-clean source tree.
3. Apply only the reviewed two `build/soong/ui/build/sandbox_linux.go` switches in the project worktree. Build the host `soong_ui` microfactory binary; retain full argv, toolchain hashes, ELF identity, and `execve` trace.
4. Inspect generated Ninja/actions for `nsjail`, Docker/Podman/OCI, namespace, chroot, or equivalent executor paths. A successful UI host-tool build is insufficient if generated actions still request them.
5. Freeze independent OUT/TMP/staging paths and capacity, then run one graph-only preflight with a fresh owner ACK/release packet. Target compilation, Bionic runtime lock, APK scanning, and device work remain later gates.

The smallest falsifier is `native_source_view_and_host_tool_falsifier`: one fresh receipt must prove every v18 root resolves to its registered exact source entry, patched host `soong_ui` build returns rc 0, `execve` contains no forbidden executor, and generated actions contain no forbidden executor. Any missing root/hash/tree, unresolved symlink, non-Linux host, forbidden generated action, absent fresh host identity, or absent owner ACK yields NO_GO and stops before graph dispatch.

The current local machine cannot satisfy that falsifier: `NANHAI_BIONIC_BUILD_READY=false`; the G278 host receipt is historical, while the current GZ02 route is unavailable. No fresh owner ACK or v18 root seal exists, and generated-action safety was never established. The assessment command returned rc 2 on its first wording/allowlist assumptions (retained only as history), then rc 0 with all eight corrected guards true and decision NO_GO. Final result SHA-256: see `RESULT-v2.json`.
