/*
 * crackmedemo — AIRE Ghidra Plugin Demo Target
 *
 * Purpose: demonstrate how much the AIRE AI-powered renaming plugin
 * accelerates reverse engineering. Compiled with -s (stripped), every
 * function below becomes an anonymous FUN_XXXXXXXX in Ghidra.
 * AIRE analyses decompiled output, call graphs, referenced strings, and
 * heuristic flags to suggest the meaningful names you see in this source.
 *
 * ── Challenge: three-stage validation gate ─────────────────────────
 *   Stage 1  length_gate        — must be exactly 12 chars
 *   Stage 2  xor_stream_decode  — rolling-XOR decode + strcmp
 *   Stage 3a hash_stage         — DJB2 of last 4 chars == EXPECTED_HASH
 *   Stage 3b bitrot_canary      — rotr32 accumulator == CANARY_SENTINEL
 *
 * ── Decoys (always fail, waste analyst time) ───────────────────────
 *   decoy_admin_check   — plausible admin string, intentionally rejected
 *   decoy_b64_check     — base64 of the real password, also rejected
 *   decoy_env_check     — checks $UNLOCK_KEY env var, never set in a
 *                          normal run
 *
 * Correct password: "R3v3rse_L337"
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/*  Constants / encoded data                                           */
/* ------------------------------------------------------------------ */

#define PW_LEN          12
#define XOR_SEED        0x37u
#define XOR_STEP        0x0Du
#define HASH_MAGIC      5381u

/*
 * DJB2 of the last 4 chars of "R3v3rse_L337" → "L337"
 * Precomputed: 0x7C83235E
 */
#define EXPECTED_HASH   0x7C83235Eu

/*
 * Bitrot canary for "R3v3rse_L337":
 *   acc = XOR of rotr32(byte[i], i%8) for i in 0..11
 * Precomputed: 0x5200000A
 */
#define CANARY_SENTINEL 0x5200000Au

/*
 * XOR stream-encoded "R3v3rse_L337".
 * key[i] = (XOR_SEED + i * XOR_STEP) & 0xFF
 *
 * Python to verify:
 *   pw="R3v3rse_L337"
 *   [hex(ord(c)^((0x37+i*0x0D)&0xFF)) for i,c in enumerate(pw)]
 */
static const uint8_t kEncodedPw[PW_LEN] = {
    0x65, 0x77, 0x27, 0x6D, 0x19, 0x0B, 0xE0, 0xCD,
    0xD3, 0x9F, 0x8A, 0xF1
};

/*
 * Decoy A: plausible admin credential — never the real password.
 * Referenced by decoy_admin_check so "strings" finds something tempting.
 */
static const char kDecoyAdmin[] = "adm!n_legacy";

/*
 * Decoy B: base64("R3v3rse_L337") — looks important, checked literally.
 * An analyst who decodes it and tries the decoded string here still fails.
 */
static const char kDecoyB64[]   = "UjN2M3JzZV9MMzM3";

/* ------------------------------------------------------------------ */
/*  Utility: DJB2 hash over n bytes                                   */
/* ------------------------------------------------------------------ */
static uint32_t djb2_hash(const char *s, size_t n)
{
    uint32_t h = HASH_MAGIC;
    size_t i;
    for (i = 0; i < n; i++)
        h = ((h << 5) + h) ^ (uint8_t)s[i];
    return h;
}

/* ------------------------------------------------------------------ */
/*  Utility: 32-bit right-rotation                                    */
/* ------------------------------------------------------------------ */
static uint32_t rotr32(uint32_t v, unsigned r)
{
    r &= 31u;
    return (v >> r) | (v << (32u - r));
}

/* ------------------------------------------------------------------ */
/*  Stage 1 — length gate                                             */
/* ------------------------------------------------------------------ */

/*
 * length_gate — returns 1 iff input is exactly PW_LEN bytes.
 * Stripped: looks like a strlen + compare against a constant.
 * AIRE signal: strlen call, compare against literal 12 → "length_gate"
 *              or "check_input_length".
 */
static int length_gate(const char *s)
{
    return (strlen(s) == PW_LEN);
}

/* ------------------------------------------------------------------ */
/*  Stage 2 — XOR stream decode                                       */
/* ------------------------------------------------------------------ */

/*
 * xor_stream_decode — writes the decoded password into dst[PW_LEN+1].
 * Stripped: a loop indexing a byte array, XOR-ing with an affine
 * function of the loop counter, storing into a stack buffer.
 * AIRE signal: byte-array reference, XOR, loop index arithmetic →
 *              "xor_stream_decode" or "decode_rolling_xor".
 */
static void xor_stream_decode(char *dst)
{
    int i;
    for (i = 0; i < PW_LEN; i++) {
        uint8_t key = (uint8_t)((XOR_SEED + (unsigned)i * XOR_STEP) & 0xFFu);
        dst[i] = (char)(kEncodedPw[i] ^ key);
    }
    dst[PW_LEN] = '\0';
}

/* ------------------------------------------------------------------ */
/*  Stage 3a — suffix hash check                                      */
/* ------------------------------------------------------------------ */

/*
 * hash_stage — hashes the last 4 bytes of candidate and compares to
 * EXPECTED_HASH. A patch that only fixes the strcmp in Stage 2 still
 * fails here if the suffix hash doesn't match.
 * AIRE signal: djb2_hash call, compare against magic constant, suffix
 *              pointer arithmetic → "hash_stage_check" or
 *              "validate_suffix_hash".
 */
static int hash_stage(const char *candidate)
{
    uint32_t h = djb2_hash(candidate + PW_LEN - 4, 4);
    return (h == EXPECTED_HASH);
}

/* ------------------------------------------------------------------ */
/*  Stage 3b — bitrot canary                                          */
/* ------------------------------------------------------------------ */

/*
 * bitrot_canary — accumulates XOR of right-rotated byte values, checks
 * against a precomputed sentinel. Foils a patch that zeros the strcmp
 * result without understanding the full validation flow.
 * AIRE signal: rotr32 call, XOR accumulator loop, compare against
 *              0x5200000A → "bitrot_canary" or "integrity_canary_check".
 */
static int bitrot_canary(const char *candidate)
{
    uint32_t acc = 0;
    int i;
    for (i = 0; i < PW_LEN; i++)
        acc ^= rotr32((uint32_t)(uint8_t)candidate[i], (unsigned)i % 8u);
    return (acc == CANARY_SENTINEL);
}

/* ------------------------------------------------------------------ */
/*  Decoy paths                                                        */
/* ------------------------------------------------------------------ */

/*
 * decoy_admin_check — compares against kDecoyAdmin; intentionally returns
 * 0 even on match so the decoy never grants access.
 * AIRE signal: strcmp + readable string reference "adm!n_legacy" →
 *              "decoy_admin_check" or "legacy_admin_credential_check".
 */
static int decoy_admin_check(const char *s)
{
    (void)strcmp(s, kDecoyAdmin);   /* evaluate but discard */
    return 0;
}

/*
 * decoy_b64_check — compares against kDecoyB64; same intentional discard.
 * AIRE signal: strcmp + base64-looking string → "decoy_b64_check" or
 *              "base64_credential_decoy".
 */
static int decoy_b64_check(const char *s)
{
    (void)strcmp(s, kDecoyB64);
    return 0;
}

/*
 * decoy_env_check — reads UNLOCK_KEY env var; NULL in a normal run so
 * always 0. Looks like a privileged bypass; wastes analyst time.
 * AIRE signal: getenv call, strcmp → "decoy_env_unlock_check" or
 *              "check_env_bypass_key".
 */
static int decoy_env_check(const char *s)
{
    const char *env = getenv("UNLOCK_KEY");
    if (!env) return 0;
    (void)strcmp(s, env);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Core validation orchestrator                                      */
/* ------------------------------------------------------------------ */

/*
 * validate_password — orchestrates all three real stages and three
 * decoy branches. The decoys are called first to pollute control-flow
 * graphs and mislead single-function analysis.
 * AIRE signal: calls to length_gate, xor_stream_decode, hash_stage,
 *              bitrot_canary, and three decoy helpers; conditional chain
 *              → "validate_password" or "orchestrate_auth_stages".
 */
static int validate_password(const char *input)
{
    char decoded[PW_LEN + 1];

    /* Decoy calls — always return 0, but force analyst to trace them. */
    decoy_admin_check(input);
    decoy_b64_check(input);
    decoy_env_check(input);

    /* Stage 1: length gate. */
    if (!length_gate(input))
        return 0;

    /* Stage 2: XOR stream decode and exact match. */
    xor_stream_decode(decoded);
    if (strcmp(input, decoded) != 0)
        return 0;

    /* Stage 3a: suffix hash must match. */
    if (!hash_stage(input))
        return 0;

    /* Stage 3b: bitrot integrity canary. */
    if (!bitrot_canary(input))
        return 0;

    return 1;
}

/* ------------------------------------------------------------------ */
/*  ASCII banner (obfuscated to avoid plain strings(1) read-out)      */
/* ------------------------------------------------------------------ */

/*
 * print_banner — emits a startup banner via a character-shifted byte
 * array so "strings" finds nothing useful.
 * AIRE signal: byte-array loop, putchar/fputc calls → "print_banner"
 *              or "display_encoded_banner".
 */
static void print_banner(void)
{
    /*
     * Each byte is (real_char + 1). Decodes to the box-art header.
     * Real content (before shift):
     *   ===========================
     *    AIRE crackme demo  v1.0
     *   ===========================
     */
    static const unsigned char enc_banner[] = {
        /* "===========================" + newline (+1 shift) */
        0x3E,0x3E,0x3E,0x3E,0x3E,0x3E,0x3E,0x3E,0x3E,0x3E,
        0x3E,0x3E,0x3E,0x3E,0x3E,0x3E,0x3E,0x3E,0x3E,0x3E,
        0x3E,0x3E,0x3E,0x3E,0x3E,0x3E,0x3E,0x0B,
        /* " AIRE crackme demo  v1.0" + newline */
        0x21,0x42,0x4A,0x53,0x46,0x21,0x64,0x73,0x62,0x64,
        0x6C,0x6E,0x66,0x21,0x65,0x66,0x6E,0x70,0x21,0x21,
        0x77,0x32,0x2F,0x31,0x0B,
        /* "===========================" + newline */
        0x3E,0x3E,0x3E,0x3E,0x3E,0x3E,0x3E,0x3E,0x3E,0x3E,
        0x3E,0x3E,0x3E,0x3E,0x3E,0x3E,0x3E,0x3E,0x3E,0x3E,
        0x3E,0x3E,0x3E,0x3E,0x3E,0x3E,0x3E,0x0B,
        0x00
    };
    const unsigned char *p;
    for (p = enc_banner; *p; p++)
        putchar((int)(*p - 1));
    putchar('\n');
}

/* ------------------------------------------------------------------ */
/*  Entry point                                                        */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    char buf[256];
    const char *input;

    print_banner();

    if (argc > 1) {
        input = argv[1];
    } else {
        printf("Password: ");
        fflush(stdout);
        if (!fgets(buf, sizeof(buf), stdin))
            return 1;
        buf[strcspn(buf, "\n")] = '\0';
        input = buf;
    }

    if (validate_password(input)) {
        puts("[+] Access granted. Flag: AIRE{r3v3rs3_sm4rt3r_n0t_h4rd3r}");
        return 0;
    }

    puts("[-] Wrong password. Keep reversing.");
    return 1;
}
