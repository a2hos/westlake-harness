#!/usr/bin/env bash
# Build only the Linux host soong_ui from the isolated, patched source view.
set -euo pipefail

: "${TOP:?project source view required}"
: "${OUT_DIR:?project output directory required}"
: "${TMPDIR:?project temp directory required}"
: "${NANHAI_SOONG_WORKTREE:?patched Soong worktree required}"
: "${NANHAI_NATIVE_PROJECT_ROOT:?project output root required}"

test "$(uname -s)" = Linux
test "$(uname -m)" = x86_64
test "$(readlink -f "$TOP/build/soong")" = "$(readlink -f "$NANHAI_SOONG_WORKTREE")"
project_root=$(readlink -f "$NANHAI_NATIVE_PROJECT_ROOT")
case "$(readlink -m "$OUT_DIR")" in "$project_root"/*) ;; *) exit 2 ;; esac
case "$(readlink -m "$TMPDIR")" in "$project_root"/*) ;; *) exit 2 ;; esac

mkdir -p "$OUT_DIR" "$TMPDIR"
export TOP OUT_DIR TMPDIR
source "$TOP/build/soong/scripts/microfactory.bash"
soong_build_go soong_ui android/soong/cmd/soong_ui
test -s "$OUT_DIR/soong_ui"
