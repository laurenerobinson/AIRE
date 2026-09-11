#!/usr/bin/env bash
# build_aire_test.sh — Build the AIRE test binary for all 8 test cases
#
# Produces:
#   aire_test_debug    — unstripped, with symbols (use for address mapping)
#   aire_test_stripped — stripped version to load in Ghidra
#   FUNCTION_MAP.txt   — symbol → address table for the stripped binary

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Rebuild outside the preserved corpus. Never executes the target.
OUT_DIR="${AIRE_TEST_OUTPUT_DIR:-$ROOT_DIR/build/test-corpus}"
mkdir -p "$OUT_DIR"

SRC="$ROOT_DIR/tests/source/aire_test.c"
OUT_DEBUG="$OUT_DIR/aire_test_debug"
OUT_STRIPPED="$OUT_DIR/aire_test_stripped"
MAP_FILE="$OUT_DIR/FUNCTION_MAP.txt"

# ── Locate OpenSSL headers / libs ─────────────────────────────────────────
OPENSSL_CFLAGS=""
OPENSSL_LIBS="-lcrypto -lssl"

# Try pkg-config first, fall back to direct include
if pkg-config --cflags openssl 2>/dev/null | grep -q include; then
    OPENSSL_CFLAGS="$(pkg-config --cflags openssl)"
    OPENSSL_LIBS="$(pkg-config --libs openssl)"
    echo "[+] OpenSSL via pkg-config: $OPENSSL_CFLAGS"
elif [ -f /usr/include/openssl/evp.h ]; then
    echo "[+] OpenSSL headers found at /usr/include/openssl — using direct link"
else
    echo "[!] WARNING: OpenSSL headers not found — Test 1 will be compiled without OpenSSL"
    OPENSSL_CFLAGS=""
    OPENSSL_LIBS=""
fi

HAVE_OPENSSL_FLAG=""
if [ -n "$OPENSSL_LIBS" ]; then
    HAVE_OPENSSL_FLAG="-DHAVE_OPENSSL"
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

# ── Generate FUNCTION_MAP before stripping ────────────────────────────────
echo "[+] Generating $MAP_FILE ..."
{
    echo "# AIRE Test Binary — Function Map"
    echo "# Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "# Format: ADDRESS  FUNCTION_NAME"
    echo "#"
    nm -n --defined-only "$OUT_DEBUG" \
        | grep " T " \
        | awk '{printf "0x%s  %s\n", $1, $3}' \
        | sort
} > "$MAP_FILE"

echo "[+] $MAP_FILE written ($(wc -l < "$MAP_FILE") entries)"

# ── Strip for Ghidra ──────────────────────────────────────────────────────
cp "$OUT_DEBUG" "$OUT_STRIPPED"
strip --strip-all "$OUT_STRIPPED"
echo "[+] Stripped binary: $OUT_STRIPPED"

# ── Summary ───────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════"
echo " AIRE Test Binary — ready for Ghidra"
echo "═══════════════════════════════════════════════════════════"
echo " Load in Ghidra: $OUT_STRIPPED"
echo " Symbol map:     $MAP_FILE"
echo ""
echo " Test functions and what AIRE should name them:"
echo ""
echo "  aes256_cbc_encrypt_buffer   (Test 1) — AES-256-CBC encrypt"
echo "    Signals: EVP_EncryptInit_ex, EVP_EncryptUpdate, EVP_EncryptFinal_ex"
echo "    Expect:  high confidence crypto name"
echo ""
echo "  stub_noop_function          (Test 2) — trivial stub"
echo "    Signals: 3 insns, no callees, no strings"
echo "    Expect:  INSUFFICIENT_EVIDENCE message in AIRE panel"
echo ""
echo "  parse_tlv_record            (Test 3) — large TLV parser"
echo "    Signals: >3200 decompile chars → smart-trim fires"
echo "    Expect:  name like parse_tlv_record / decode_binary_record"
echo ""
echo "  dispatch_protocol_message   (Test 4) — 14-way dispatcher"
echo "    Signals: branchRatio > 3.0, many handler callees"
echo "    Expect:  name like dispatch_proto_msg / handle_message_type"
echo ""
echo "  init_tcp_client_connection  (Test 5) — TCP setup"
echo "    Signals: socket/connect/setsockopt, SO_REUSEADDR, TCP_NODELAY"
echo "    Expect:  something more specific than generic 'setup_socket'"
echo ""
echo "  parse_tls_record_header     (Test 6a) — TLS header parser"
echo "  validate_tls_record_length  (Test 6b) — TLS length validator"
echo "    Signals: same TLS vocabulary → near-duplicate suggestions"
echo "    Expect:  dedup / diversity filter fires"
echo ""
echo "  (Test 7: set AIRE_OLLAMA_MODEL=nonexistent-model in Ghidra env)"
echo "    Expect:  stable fallback message, no fabricated names"
echo ""
echo "  perform_session_key_exchange (Test 8) — full evidence"
echo "    Signals: named callees (aes256, dispatch, parse_tlv, crc32),"
echo "             string refs, crypto + network flags, multiple blocks"
echo "    Expect:  high confidence, detailed breakdown in AIRE detail panel"
echo "═══════════════════════════════════════════════════════════"
