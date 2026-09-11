#!/usr/bin/env bash
# build_raptor7_aire.sh — Build the RAPTOR-7 AIRE demo binary
#
# Produces:
#   raptor7_aire_debug    — unstripped (symbol reference)
#   raptor7_aire          — stripped  (load this in Ghidra)
#   RAPTOR7_FUNCTION_MAP.txt — address → real function name

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Rebuild outside the preserved corpus. Never executes the target.
OUT_DIR="${AIRE_TEST_OUTPUT_DIR:-$ROOT_DIR/build/test-corpus}"
mkdir -p "$OUT_DIR"

SRC="$ROOT_DIR/tests/source/raptor7_aire.c"
OUT_DEBUG="$OUT_DIR/raptor7_aire_debug"
OUT_STRIPPED="$OUT_DIR/raptor7_aire"
MAP_FILE="$OUT_DIR/RAPTOR7_FUNCTION_MAP.txt"

# ── Locate OpenSSL ────────────────────────────────────────────────────────
OPENSSL_CFLAGS=""
OPENSSL_LIBS="-lcrypto -lssl"
HAVE_OPENSSL_FLAG="-DHAVE_OPENSSL"

if pkg-config --cflags openssl 2>/dev/null | grep -q include; then
    OPENSSL_CFLAGS="$(pkg-config --cflags openssl)"
    OPENSSL_LIBS="$(pkg-config --libs openssl)"
    echo "[+] OpenSSL via pkg-config"
elif [ -f /usr/include/openssl/evp.h ]; then
    echo "[+] OpenSSL headers at /usr/include/openssl — direct link"
else
    echo "[!] OpenSSL not found — Test 1 and Test 8 crypto paths disabled"
    OPENSSL_CFLAGS=""
    OPENSSL_LIBS=""
    HAVE_OPENSSL_FLAG=""
fi

# ── Compile ───────────────────────────────────────────────────────────────
echo "[+] Compiling $SRC ..."
gcc -O0 -fno-inline -g \
    -Wall -Wextra -Wno-unused-parameter \
    $HAVE_OPENSSL_FLAG \
    $OPENSSL_CFLAGS \
    -o "$OUT_DEBUG" \
    "$SRC" \
    $OPENSSL_LIBS \
    -lm

echo "[+] Build succeeded: $OUT_DEBUG"

# ── Function map (before strip) ───────────────────────────────────────────
echo "[+] Generating $MAP_FILE ..."
{
    echo "# RAPTOR-7 AIRE Demo — Function Map"
    echo "# Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "#"
    echo "# ADDRESS              REAL NAME"
    nm -n --defined-only "$OUT_DEBUG" \
        | grep " T " \
        | awk '{printf "0x%s  %s\n", $1, $3}' \
        | sort
} > "$MAP_FILE"
echo "[+] $MAP_FILE written"

# ── Strip ─────────────────────────────────────────────────────────────────
cp "$OUT_DEBUG" "$OUT_STRIPPED"
strip --strip-all "$OUT_STRIPPED"
echo "[+] Stripped binary: $OUT_STRIPPED"

# ── Summary ───────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo " RAPTOR-7 AIRE Demo Binary"
echo "═══════════════════════════════════════════════════════════════════"
echo " Load in Ghidra : $OUT_STRIPPED"
echo " Symbol map     : $MAP_FILE"
echo ""
echo " AIRE test targets (navigate by address in Ghidra):"
grep -E "(encrypt_mission|heartbeat|parse_telemetry|dispatch_drone|init_c2|validate_video|validate_telemetry|establish_c2|process_auth)" \
    "$MAP_FILE" | grep -v "^#" || true
echo ""
echo " Crackme answer : run $OUT_DEBUG RAPTOR_7_ONLINE"
echo "═══════════════════════════════════════════════════════════════════"
