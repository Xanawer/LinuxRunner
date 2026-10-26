#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
CC="${CC:-clang}"
ISH_BIN="${ISH_BIN:-$PROJECT_DIR/build-arm64-linux/ish}"
ROOTFS="${ROOTFS:-$PROJECT_DIR/debian-arm64-fakefs}"
TIMEOUT_S="${TIMEOUT_S:-40}"
HOST_TMP="$(mktemp -d)"
trap 'rm -rf "$HOST_TMP"' EXIT
# Cross-compiled and freestanding, so any host with clang and lld can build it.
"$CC" --target=aarch64-linux-gnu -ffreestanding -fno-stack-protector -fno-pic \
    -static -nostdlib -O1 -fuse-ld=lld -Wl,--no-dynamic-linker \
    "$SCRIPT_DIR/sigreturn-vdso.c" -o "$HOST_TMP/sigreturn-vdso"
tar -C "$HOST_TMP" -cf - sigreturn-vdso |
    timeout -k 5 "$TIMEOUT_S" "$ISH_BIN" -f "$ROOTFS" /bin/tar -xf - -C /tmp
timeout -k 5 "$TIMEOUT_S" "$ISH_BIN" -f "$ROOTFS" /tmp/sigreturn-vdso | grep -qx sigreturn-vdso-ok
echo sigreturn-vdso-gate-ok
