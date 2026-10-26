#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"

CC="${CC:-clang}"
ISH_BIN="${ISH_BIN:-$PROJECT_DIR/build-arm64-linux/ish}"
ROOTFS="${ROOTFS:-$PROJECT_DIR/debian-arm64-fakefs}"
TIMEOUT_S="${TIMEOUT_S:-120}"
HOST_TMP="$(mktemp -d)"
trap 'rm -rf "$HOST_TMP"' EXIT

command -v "$CC" >/dev/null || { echo "missing C compiler: $CC" >&2; exit 1; }
test -x "$ISH_BIN" || { echo "missing ish binary: $ISH_BIN" >&2; exit 1; }
test -d "$ROOTFS" || { echo "missing rootfs: $ROOTFS" >&2; exit 1; }

# --no-relax keeps the ADRP+ADD pair the single-step check depends on.
"$CC" --target=aarch64-linux-gnu -ffreestanding -fno-stack-protector -fno-pic \
    -static -nostdlib -O1 -fuse-ld=lld -Wl,--no-dynamic-linker -Wl,--no-relax \
    "$SCRIPT_DIR/ptrace-socket-regress.c" -o "$HOST_TMP/ptrace-socket-regress"

tar -C "$HOST_TMP" -cf - ptrace-socket-regress |
    timeout "$TIMEOUT_S" "$ISH_BIN" -f "$ROOTFS" /bin/tar -xf - -C /tmp
timeout "$TIMEOUT_S" "$ISH_BIN" -f "$ROOTFS" /tmp/ptrace-socket-regress | tee "$HOST_TMP/out"
grep -qx 'RESULT: PASS' "$HOST_TMP/out"
