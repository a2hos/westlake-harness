# G274 stock-path view: read-only scout

Scope is the original G273/v17b Soong frontier (18 diagnostics, 12 undefined module names), with OH7.0.0.39 / AOSP16 R4 / ARM64 / App-Bionic unchanged. This is **a virtual source-view check only**. It does not mount a Linux stock tree, run Docker or Soong, build an ARM64 target, contact a device, or start an APK. The old G273 result is terminal and must not be replayed.

`scout.py` ran with `python3 scripts/nanhai_plus_env.py --run python3 -B .../g274-stock-view-scout-v1/scout.py` and returned rc 0. Its complete machine-readable receipt is `SCOUT.json`. It uses the nine-source `CANDIDATE.json` plus all nine frozen per-file manifests and compares them to G273/v17b `SOURCE-MANIFEST.json`. No authoritative count/control or shared source was edited by this scout.

The first local scout trial returned rc 1 at `frameworks/base/data/fonts/fonts.mk`: it rejected every path overlap. Inspection found four exact same-content overlaps, so the scout now requires matching SHA-256, mode and byte length and still rejects a different-byte overlap. The successful rc 0 receipt is from the revised script; the rc 1 trial is not graph or source failure.

## Exact view delta

Add nine read-only stock roots to a **new** G274 candidate source volume, preserving original tree paths: `packages/apps/DocumentsUI`, `system/netd`, `device/google/cuttlefish`, `system/bpf`, `packages/modules/common`, `frameworks/base`, `hardware/interfaces`, `frameworks/native`, and `system/libvintf`. Bind their nine version-pinned shared-pool source directories as read-only stock roots, following the v17b whole-root pattern. These hold 85,499 tracked entries, 1,875,247,905 logical bytes and 2,394 `*.bp` files. The prior G273 source view has no identical-root conflict.

Four exact file paths already selected for the old source volume sit under new whole roots: three `frameworks/base/data/*/*.mk` files and `hardware/interfaces/configstore/1.1/default/surfaceflinger.mk`. Their SHA-256, mode and byte length match the new R4 manifests exactly. A new packet should bind these four equivalences explicitly, retain the old receipts and verify that no different bytes are hidden under the new root mounts. Do not silently omit the old selected records or reclassify them as graph completion.

## Original symlinks

The 13 symlinks reported unresolved inside isolated checkouts have their exact original payload and hash in `SCOUT.json`. In the virtual stock layout, **12 targets have qualified exact paths**: eleven point to three already admitted `build/soong/scripts` files and one to the new full `frameworks/native` root. Their stock target paths, mode and SHA are in `SCOUT.json`. The remaining original `frameworks/native/include/private/binder` points at `frameworks/native/libs/binder/include/private/binder`, absent even from the full R4 `frameworks/native` checkout. Keep its original symlink and record it as dangling; do not invent a target or delete the link. This is a source-view caveat, not by itself an observed Soong error.

## Transitive risk and next gate

The two current graphics `-ndk_static` missing names are literal `cc_defaults` in `hardware/interfaces/graphics/Android.bp`. Their Linux dependencies include `android.hardware.graphics.common-V7-ndk`, `android.hardware.graphics.composer3-V4-ndk`, and `android.hardware.drm.common-V1-ndk`. The corresponding `aidl_interface` Blueprint provider files are present in the new `hardware/interfaces` tree (exact file hashes in `SCOUT.json`); generated variants, imports, Soong namespace visibility and transitive dependencies remain unverified. The 2,394 new Blueprint files can expose additional owners once Soong evaluates the new view. A lexical name scan is a prioritization aid, not a graph acceptance.

The minimum next step is a new G274/v18 **candidate** derived from frozen v17b inputs, adding nine guarded read-only roots and explicit four-path overlap and 13-link audits. Rehash all inputs before/after consumption; independently review the materialization and Linux mount identity/RO flags. Only then seek the original owner’s fresh ACK and root seal for one new graph attempt. Stop at its first actual wall and use that stdout to choose the next source owner. No current receipt releases that graph.
