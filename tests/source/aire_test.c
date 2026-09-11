/*
 * aire_test.c — AIRE Ghidra Extension Test Binary
 *
 * Covers all 8 AIRE test cases:
 *   Test 1 — Strong crypto evidence: AES-256-CBC encrypt (named callees + strings)
 *   Test 2 — Trivial stub: INSUFFICIENT_EVIDENCE path (no callees, no strings)
 *   Test 3 — Large TLV parser: smart-trim trigger (>3200 chars decompile)
 *   Test 4 — Protocol dispatcher: high branch ratio (14-way switch)
 *   Test 5 — TCP setup: ambiguous network evidence (potential generic name)
 *   Test 6a/6b — Two similar TLS parsers: deduplication / diversity test
 *   Test 7 — (no code needed: user sets bad AIRE_OLLAMA_MODEL)
 *   Test 8 — Full-evidence function: confidence breakdown detail
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif

/* ──────────────────────────────────────────────────────────────────────────
 * Shared types / helpers
 * ────────────────────────────────────────────────────────────────────────── */

#define MAX_RECORD_FIELDS  32
#define MAX_FIELD_LEN      256
#define TLV_MAX_DEPTH      8
#define PROTO_MAX_PAYLOAD  4096

typedef enum {
    MSG_HANDSHAKE      = 0x01,
    MSG_DATA           = 0x02,
    MSG_KEEPALIVE      = 0x03,
    MSG_ACK            = 0x04,
    MSG_NACK           = 0x05,
    MSG_RESET          = 0x06,
    MSG_QUERY          = 0x07,
    MSG_RESPONSE       = 0x08,
    MSG_SUBSCRIBE      = 0x09,
    MSG_UNSUBSCRIBE    = 0x0A,
    MSG_PUBLISH        = 0x0B,
    MSG_ROUTE          = 0x0C,
    MSG_ERROR          = 0x0D,
    MSG_UNKNOWN        = 0xFF
} msg_type_t;

typedef struct {
    uint8_t  type;
    uint16_t length;
    uint8_t  payload[PROTO_MAX_PAYLOAD];
    uint32_t checksum;
    uint8_t  flags;
    uint16_t session_id;
} proto_msg_t;

typedef struct {
    uint8_t  tag;
    uint16_t length;
    uint8_t *value;
    int      depth;
} tlv_field_t;

typedef struct {
    tlv_field_t fields[MAX_RECORD_FIELDS];
    int         field_count;
    uint32_t    record_id;
    uint8_t     version;
    uint16_t    flags;
    char        source_addr[64];
} tlv_record_t;

typedef struct {
    int      fd;
    uint32_t remote_ip;
    uint16_t remote_port;
    uint16_t local_port;
    int      is_connected;
    int      timeout_ms;
    char     interface_name[16];
} tcp_conn_t;

/* Simple logging helpers so the binary has real string references */
static void log_error(const char *msg) {
    fprintf(stderr, "[AIRE_TEST] ERROR: %s\n", msg);
}
static void log_debug(const char *msg) {
    fprintf(stderr, "[AIRE_TEST] DEBUG: %s\n", msg);
}
static uint32_t crc32_simple(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }
    return ~crc;
}

/* ──────────────────────────────────────────────────────────────────────────
 * TEST 1 — AES-256-CBC encrypt
 *   Signals: callees EVP_EncryptInit_ex, EVP_EncryptUpdate, EVP_EncryptFinal_ex,
 *            usesCryptoLike=true, string refs "AES-256-CBC", "encrypt failed"
 *   Expected: high-confidence name like aes256_cbc_encrypt / encrypt_buffer_aes
 * ────────────────────────────────────────────────────────────────────────── */
int aes256_cbc_encrypt_buffer(
        const uint8_t *plaintext, int plaintext_len,
        const uint8_t *key,       /* 32 bytes */
        const uint8_t *iv,        /* 16 bytes */
        uint8_t       *ciphertext /* caller-allocated, plaintext_len + 16 */ )
{
#ifdef HAVE_OPENSSL
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        log_error("EVP_CIPHER_CTX_new failed");
        return -1;
    }

    int out_len1 = 0, out_len2 = 0;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        log_error("EVP_EncryptInit_ex failed for AES-256-CBC");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &out_len1, plaintext, plaintext_len)) {
        log_error("EVP_EncryptUpdate failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + out_len1, &out_len2)) {
        log_error("EVP_EncryptFinal_ex failed — padding error");
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return out_len1 + out_len2;
#else
    (void)plaintext; (void)plaintext_len;
    (void)key; (void)iv; (void)ciphertext;
    log_error("OpenSSL not compiled in — AES-256-CBC unavailable");
    return -1;
#endif
}

/* ──────────────────────────────────────────────────────────────────────────
 * TEST 2 — Trivial stub (INSUFFICIENT_EVIDENCE path)
 *   Signals: 3 instructions, no callees, no strings, 1 basic block
 *   Expected: model returns INSUFFICIENT_EVIDENCE
 * ────────────────────────────────────────────────────────────────────────── */
int stub_noop_function(void)
{
    return 0;
}

/* ──────────────────────────────────────────────────────────────────────────
 * TEST 3 — Large TLV record parser (smart-trim trigger)
 *   Signals: many nested loops, branches, string refs ("invalid tag",
 *            "record too large", "depth limit exceeded", etc.)
 *   Expected: decompile >3200 chars → smart-trim fires; name like
 *             parse_tlv_record / decode_binary_record
 * ────────────────────────────────────────────────────────────────────────── */
static int validate_tlv_tag(uint8_t tag) {
    /* Tags 0x00 and 0xFF are reserved in our protocol */
    if (tag == 0x00 || tag == 0xFF) return 0;
    return 1;
}

static int validate_tlv_length(uint16_t len, size_t remaining) {
    if (len == 0)              return 0;  /* zero-length fields not allowed */
    if (len > remaining)       return 0;  /* would overflow buffer */
    if (len > MAX_FIELD_LEN)   return 0;  /* single field too large */
    return 1;
}

int parse_tlv_record(const uint8_t *buf, size_t buf_len, tlv_record_t *out)
{
    if (!buf || !out || buf_len < 8) {
        log_error("parse_tlv_record: null or too-short buffer");
        return -1;
    }

    memset(out, 0, sizeof(*out));

    /* Header: 4-byte record_id, 1-byte version, 1-byte flags(hi), 1-byte flags(lo), 1-byte field_count */
    size_t pos = 0;
    out->record_id  = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16)
                    | ((uint32_t)buf[2] <<  8) |  (uint32_t)buf[3];
    pos += 4;
    out->version    = buf[pos++];
    out->flags      = ((uint16_t)buf[pos] << 8) | buf[pos + 1];
    pos += 2;
    int expected_fields = buf[pos++];

    if (out->version != 1 && out->version != 2) {
        log_error("parse_tlv_record: unsupported version");
        return -1;
    }
    if (expected_fields > MAX_RECORD_FIELDS) {
        log_error("parse_tlv_record: record too large — field count exceeds limit");
        return -1;
    }

    int depth_stack[TLV_MAX_DEPTH];
    int depth_remaining[TLV_MAX_DEPTH];
    int depth = 0;
    depth_stack[0]     = 0;
    depth_remaining[0] = (int)(buf_len - pos);

    int field_idx = 0;
    int iterations = 0;
    const int MAX_ITER = 1024;

    while (pos < buf_len && field_idx < MAX_RECORD_FIELDS && iterations++ < MAX_ITER) {

        if (pos + 3 > buf_len) {
            log_error("parse_tlv_record: truncated TLV header");
            break;
        }

        uint8_t  tag = buf[pos];
        uint16_t len = ((uint16_t)buf[pos + 1] << 8) | buf[pos + 2];
        pos += 3;

        if (!validate_tlv_tag(tag)) {
            log_error("parse_tlv_record: invalid tag byte — skipping record");
            return -1;
        }

        size_t remaining = buf_len - pos;
        if (!validate_tlv_length(len, remaining)) {
            log_error("parse_tlv_record: invalid length field");
            return -1;
        }

        /* Tag 0xFE = nested container; push depth */
        if (tag == 0xFE) {
            if (depth + 1 >= TLV_MAX_DEPTH) {
                log_error("parse_tlv_record: depth limit exceeded in nested TLV");
                return -1;
            }
            depth++;
            depth_stack[depth]     = field_idx;
            depth_remaining[depth] = len;
            continue;
        }

        /* Tag 0xFD = end of container; pop depth */
        if (tag == 0xFD) {
            if (depth == 0) {
                log_error("parse_tlv_record: unexpected container-end tag at root");
                return -1;
            }
            depth--;
            continue;
        }

        tlv_field_t *f = &out->fields[field_idx];
        f->tag    = tag;
        f->length = len;
        f->depth  = depth;
        f->value  = (uint8_t *)(buf + pos);
        pos += len;

        /* Special tag handling */
        if (tag == 0x01 && len <= 63) {
            /* Source address field */
            memcpy(out->source_addr, f->value, len);
            out->source_addr[len] = '\0';
        } else if (tag == 0x02 && len == 1) {
            /* Override version from field */
            if (f->value[0] != out->version) {
                log_debug("parse_tlv_record: version mismatch between header and field 0x02");
            }
        } else if (tag == 0x10) {
            /* CRC field — verify if present */
            if (len == 4) {
                uint32_t claimed = ((uint32_t)f->value[0] << 24)
                                 | ((uint32_t)f->value[1] << 16)
                                 | ((uint32_t)f->value[2] <<  8)
                                 |  (uint32_t)f->value[3];
                uint32_t actual = crc32_simple(buf, pos - len - 3);
                if (claimed != actual) {
                    log_error("parse_tlv_record: CRC mismatch — record corrupt");
                    return -1;
                }
            }
        } else if (tag == 0x20) {
            /* Flags override */
            if (len == 2) {
                out->flags = ((uint16_t)f->value[0] << 8) | f->value[1];
            }
        } else if (tag == 0x30 || tag == 0x31 || tag == 0x32) {
            /* Extended attribute family — validate content is printable ASCII */
            for (int ci = 0; ci < len; ci++) {
                if (f->value[ci] < 0x20 || f->value[ci] > 0x7E) {
                    log_error("parse_tlv_record: non-printable byte in extended attribute");
                    return -1;
                }
            }
        }

        if (depth_remaining[depth] > 0) {
            depth_remaining[depth] -= (len + 3);
            if (depth_remaining[depth] < 0) {
                log_error("parse_tlv_record: container length overflow");
                return -1;
            }
        }

        field_idx++;
    }

    if (field_idx != expected_fields) {
        log_debug("parse_tlv_record: actual field count differs from header");
    }

    out->field_count = field_idx;
    return 0;
}

/* ──────────────────────────────────────────────────────────────────────────
 * TEST 4 — Protocol message dispatcher (high branch ratio)
 *   Signals: 14-way switch → branchRatio > 3.0, strings per msg type
 *   Expected: name like dispatch_protocol_message / handle_proto_msg
 * ────────────────────────────────────────────────────────────────────────── */

static int handle_handshake(proto_msg_t *m) {
    log_debug("handling handshake message");
    return m->length > 0 ? 0 : -1;
}
static int handle_data(proto_msg_t *m) {
    if (m->length == 0) { log_error("empty data message"); return -1; }
    return 0;
}
static int handle_keepalive(proto_msg_t *m) {
    (void)m; return 0;
}
static int handle_ack(proto_msg_t *m) {
    (void)m; return 0;
}
static int handle_nack(proto_msg_t *m) {
    log_debug("NACK received — retransmit requested");
    return 0;
}
static int handle_reset(proto_msg_t *m) {
    log_error("session reset by remote");
    (void)m; return 1; /* signal caller to close */
}
static int handle_query(proto_msg_t *m) {
    if (m->length < 4) { log_error("query too short"); return -1; }
    return 0;
}
static int handle_response(proto_msg_t *m) {
    if (m->flags & 0x80) { log_error("response error flag set"); return -1; }
    return 0;
}
static int handle_subscribe(proto_msg_t *m) {
    log_debug("subscribe request received");
    (void)m; return 0;
}
static int handle_unsubscribe(proto_msg_t *m) {
    log_debug("unsubscribe request received");
    (void)m; return 0;
}
static int handle_publish(proto_msg_t *m) {
    if (m->length > PROTO_MAX_PAYLOAD) { log_error("publish payload too large"); return -1; }
    return 0;
}
static int handle_route(proto_msg_t *m) {
    if (m->session_id == 0) { log_error("route message missing session_id"); return -1; }
    return 0;
}
static int handle_error_msg(proto_msg_t *m) {
    log_error("protocol error message received from remote");
    (void)m; return -1;
}

int dispatch_protocol_message(proto_msg_t *msg)
{
    if (!msg) {
        log_error("dispatch_protocol_message: null message pointer");
        return -1;
    }

    /* Validate checksum before dispatch */
    uint32_t expected_csum = crc32_simple(msg->payload, msg->length);
    if (msg->checksum != 0 && msg->checksum != expected_csum) {
        log_error("dispatch_protocol_message: checksum mismatch — dropping message");
        return -1;
    }

    switch ((msg_type_t)msg->type) {
        case MSG_HANDSHAKE:   return handle_handshake(msg);
        case MSG_DATA:        return handle_data(msg);
        case MSG_KEEPALIVE:   return handle_keepalive(msg);
        case MSG_ACK:         return handle_ack(msg);
        case MSG_NACK:        return handle_nack(msg);
        case MSG_RESET:       return handle_reset(msg);
        case MSG_QUERY:       return handle_query(msg);
        case MSG_RESPONSE:    return handle_response(msg);
        case MSG_SUBSCRIBE:   return handle_subscribe(msg);
        case MSG_UNSUBSCRIBE: return handle_unsubscribe(msg);
        case MSG_PUBLISH:     return handle_publish(msg);
        case MSG_ROUTE:       return handle_route(msg);
        case MSG_ERROR:       return handle_error_msg(msg);
        case MSG_UNKNOWN:
        default:
            log_error("dispatch_protocol_message: unknown message type — dropping");
            return -1;
    }
}

/* ──────────────────────────────────────────────────────────────────────────
 * TEST 5 — TCP socket setup (ambiguous network evidence)
 *   Signals: socket(), connect(), setsockopt(), strings "connection failed",
 *            "SO_REUSEADDR", "TCP_NODELAY" — usesNetworkIOLike=true
 *   Risk: model might suggest generic name like "setup_socket"
 *   Expected: something more specific like init_tcp_connection / open_tcp_client
 * ────────────────────────────────────────────────────────────────────────── */
int init_tcp_client_connection(tcp_conn_t *conn)
{
    if (!conn) {
        log_error("init_tcp_client_connection: null conn pointer");
        return -1;
    }

    conn->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (conn->fd < 0) {
        log_error("init_tcp_client_connection: socket() failed");
        return -1;
    }

    /* Set SO_REUSEADDR to allow quick rebind */
    int opt = 1;
    if (setsockopt(conn->fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        log_error("init_tcp_client_connection: setsockopt SO_REUSEADDR failed");
    }

    /* Disable Nagle for low-latency messaging */
#ifdef TCP_NODELAY
    if (setsockopt(conn->fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) < 0) {
        log_error("init_tcp_client_connection: setsockopt TCP_NODELAY failed");
    }
#endif

    /* Set send/recv timeout */
    if (conn->timeout_ms > 0) {
        struct timeval tv = {
            .tv_sec  = conn->timeout_ms / 1000,
            .tv_usec = (conn->timeout_ms % 1000) * 1000
        };
        setsockopt(conn->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(conn->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(conn->remote_port);
    addr.sin_addr.s_addr = htonl(conn->remote_ip);

    if (connect(conn->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_error("init_tcp_client_connection: connect() failed — connection refused or timed out");
        close(conn->fd);
        conn->fd = -1;
        return -1;
    }

    conn->is_connected = 1;
    log_debug("init_tcp_client_connection: TCP connection established");
    return 0;
}

/* ──────────────────────────────────────────────────────────────────────────
 * TEST 6a — TLS record header parser (first of similar pair)
 *   Both 6a and 6b parse TLS-like record headers; they should produce
 *   near-duplicate suggestions → deduplication / diversity filter fires
 * ────────────────────────────────────────────────────────────────────────── */

typedef struct {
    uint8_t  content_type;   /* 0x14=ChangeCipherSpec, 0x15=Alert, 0x16=Handshake, 0x17=AppData */
    uint8_t  version_major;
    uint8_t  version_minor;
    uint16_t length;
    uint8_t *fragment;
} tls_record_t;

int parse_tls_record_header(const uint8_t *buf, size_t buf_len, tls_record_t *out)
{
    if (!buf || !out || buf_len < 5) {
        log_error("parse_tls_record_header: buffer too short for TLS record header");
        return -1;
    }

    out->content_type  = buf[0];
    out->version_major = buf[1];
    out->version_minor = buf[2];
    out->length        = ((uint16_t)buf[3] << 8) | buf[4];

    /* Validate content type */
    switch (out->content_type) {
        case 0x14: /* ChangeCipherSpec */
        case 0x15: /* Alert */
        case 0x16: /* Handshake */
        case 0x17: /* ApplicationData */
            break;
        default:
            log_error("parse_tls_record_header: unknown TLS content type");
            return -1;
    }

    /* Validate TLS version: only 1.0 (3,1) 1.1 (3,2) 1.2 (3,3) accepted */
    if (out->version_major != 3 || out->version_minor < 1 || out->version_minor > 3) {
        log_error("parse_tls_record_header: unsupported TLS version");
        return -1;
    }

    if (out->length > 16384) {  /* TLS max fragment length */
        log_error("parse_tls_record_header: TLS record length exceeds 2^14 limit");
        return -1;
    }

    if (buf_len < (size_t)(5 + out->length)) {
        log_error("parse_tls_record_header: buffer does not contain full TLS record");
        return -1;
    }

    out->fragment = (uint8_t *)(buf + 5);
    return 0;
}

/* ──────────────────────────────────────────────────────────────────────────
 * TEST 6b — TLS record validator (second of similar pair, intentionally close)
 *   Slightly different structure, same domain vocabulary
 *   → model likely returns near-duplicate suggestions for 6a and 6b
 * ────────────────────────────────────────────────────────────────────────── */
int validate_tls_record_length(const uint8_t *buf, size_t buf_len, uint16_t *out_length)
{
    if (!buf || !out_length || buf_len < 5) {
        log_error("validate_tls_record_length: insufficient buffer for TLS header");
        return -1;
    }

    uint8_t  ctype   = buf[0];
    uint8_t  vmajor  = buf[1];
    uint8_t  vminor  = buf[2];
    uint16_t length  = ((uint16_t)buf[3] << 8) | buf[4];

    if (ctype < 0x14 || ctype > 0x17) {
        log_error("validate_tls_record_length: invalid TLS content type byte");
        return -1;
    }
    if (vmajor != 3) {
        log_error("validate_tls_record_length: TLS major version must be 3");
        return -1;
    }
    if (vminor == 0) {
        log_error("validate_tls_record_length: TLS 1.0 (3,0) SSLv3 not supported");
        return -1;
    }
    if (length == 0) {
        log_error("validate_tls_record_length: zero-length TLS record fragment");
        return -1;
    }
    if (length > 16384) {
        log_error("validate_tls_record_length: TLS fragment exceeds maximum record size");
        return -1;
    }
    if ((size_t)(5 + length) > buf_len) {
        log_error("validate_tls_record_length: TLS record truncated in buffer");
        return -1;
    }

    *out_length = length;
    return 0;
}

/* ──────────────────────────────────────────────────────────────────────────
 * TEST 8 — Full-evidence function (confidence breakdown showcase)
 *   Named callees (aes256_cbc_encrypt_buffer, dispatch_protocol_message,
 *                  parse_tlv_record, crc32_simple)
 *   String refs: "session key exchange", "key derivation", "master secret"
 *   Callers: main()
 *   Multiple basic blocks, loops, branches
 *   Expected: high confidence, detailed breakdown in AIRE detail panel
 * ────────────────────────────────────────────────────────────────────────── */
int perform_session_key_exchange(
        tcp_conn_t  *conn,
        uint8_t     *master_secret,    /* 48 bytes out */
        const uint8_t *peer_public_key, /* 32 bytes in  */
        size_t        peer_key_len)
{
    if (!conn || !master_secret || !peer_public_key || peer_key_len < 32) {
        log_error("perform_session_key_exchange: invalid arguments");
        return -1;
    }
    if (!conn->is_connected) {
        log_error("perform_session_key_exchange: connection not established");
        return -1;
    }

    log_debug("perform_session_key_exchange: beginning key derivation");

    /* Derive master secret using a mix of the peer key and a local nonce.
     * This is a simplified stand-in — real code would use ECDH or similar. */
    uint8_t local_nonce[32];
#ifdef HAVE_OPENSSL
    if (RAND_bytes(local_nonce, sizeof(local_nonce)) != 1) {
        log_error("perform_session_key_exchange: RAND_bytes failed — key derivation aborted");
        return -1;
    }
#else
    for (int i = 0; i < 32; i++) local_nonce[i] = (uint8_t)(i ^ 0xA5);
#endif

    /* XOR peer key with nonce into first 32 bytes of master secret */
    for (int i = 0; i < 32; i++) {
        master_secret[i] = peer_public_key[i] ^ local_nonce[i];
    }
    /* Zero-pad remaining 16 bytes */
    memset(master_secret + 32, 0, 16);

    /* Verify the derived key looks reasonable — must not be all-zero */
    uint32_t key_csum = crc32_simple(master_secret, 48);
    if (key_csum == 0) {
        log_error("perform_session_key_exchange: derived key is degenerate (all-zero)");
        return -1;
    }

    /* Send the local nonce to the peer so they can derive the same secret */
    uint8_t send_buf[36];
    send_buf[0] = 0x01;  /* nonce frame type */
    send_buf[1] = 0x00;
    send_buf[2] = 0x20;  /* length = 32 */
    memcpy(send_buf + 3, local_nonce, 32);
    send_buf[35] = (uint8_t)(key_csum & 0xFF);

    ssize_t sent = write(conn->fd, send_buf, sizeof(send_buf));
    if (sent != (ssize_t)sizeof(send_buf)) {
        log_error("perform_session_key_exchange: failed to send nonce frame");
        return -1;
    }

    /* Encrypt a test message with the derived key to verify both ends agree */
    uint8_t test_plain[] = "master secret verification";
    uint8_t test_cipher[48];
    uint8_t iv[16];
    memset(iv, 0x5A, sizeof(iv));

    int enc_len = aes256_cbc_encrypt_buffer(
            test_plain, (int)sizeof(test_plain) - 1,
            master_secret, iv, test_cipher);

    if (enc_len < 0) {
        log_error("perform_session_key_exchange: session key self-test encrypt failed");
        return -1;
    }

    /* Wrap into proto message and dispatch */
    proto_msg_t verify_msg;
    memset(&verify_msg, 0, sizeof(verify_msg));
    verify_msg.type       = MSG_DATA;
    verify_msg.session_id = conn->remote_port;
    verify_msg.length     = (uint16_t)enc_len;
    memcpy(verify_msg.payload, test_cipher, (size_t)enc_len);
    verify_msg.checksum   = crc32_simple(verify_msg.payload, enc_len);

    if (dispatch_protocol_message(&verify_msg) < 0) {
        log_error("perform_session_key_exchange: verification message dispatch failed");
        return -1;
    }

    log_debug("perform_session_key_exchange: session key exchange complete");
    return 0;
}

/* ──────────────────────────────────────────────────────────────────────────
 * main — exercise each function so nothing gets optimised away
 * ────────────────────────────────────────────────────────────────────────── */
int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    printf("AIRE Test Binary\n");
    printf("Functions present for all 8 test cases.\n");

    /* Test 1 — AES encrypt */
#ifdef HAVE_OPENSSL
    uint8_t key[32], iv[16], plain[16], cipher[32];
    memset(key, 0x42, sizeof(key));
    memset(iv,  0x00, sizeof(iv));
    memset(plain, 0xAB, sizeof(plain));
    int enc = aes256_cbc_encrypt_buffer(plain, sizeof(plain), key, iv, cipher);
    printf("Test 1 (AES encrypt): enc_len=%d\n", enc);
#else
    printf("Test 1 (AES encrypt): OpenSSL not compiled in\n");
#endif

    /* Test 2 — stub */
    int stub_ret = stub_noop_function();
    printf("Test 2 (stub): ret=%d\n", stub_ret);

    /* Test 3 — TLV parser with minimal valid record */
    uint8_t tlv_buf[32] = { 0,0,0,1, 1, 0,0, 2,   /* header */
                             0x30, 0,3, 'a','b','c', /* field 1 */
                             0x31, 0,3, 'x','y','z'  /* field 2 */
                           };
    tlv_record_t rec;
    int pr = parse_tlv_record(tlv_buf, sizeof(tlv_buf), &rec);
    printf("Test 3 (TLV parser): ret=%d fields=%d\n", pr, rec.field_count);

    /* Test 4 — dispatcher */
    proto_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = MSG_KEEPALIVE;
    int dr = dispatch_protocol_message(&msg);
    printf("Test 4 (dispatcher): ret=%d\n", dr);

    /* Test 5 — TCP setup (won't actually connect in test) */
    tcp_conn_t conn;
    memset(&conn, 0, sizeof(conn));
    conn.remote_ip   = 0x7F000001; /* 127.0.0.1 */
    conn.remote_port = 9999;
    conn.timeout_ms  = 100;
    int tr = init_tcp_client_connection(&conn);
    printf("Test 5 (TCP setup): ret=%d (expected -1 if no listener)\n", tr);
    if (conn.fd >= 0) close(conn.fd);

    /* Test 6a/6b — TLS parsers */
    uint8_t tls_buf[10] = { 0x16, 3, 3, 0,3, 0,0,0 };
    tls_record_t tlsr;
    int t6a = parse_tls_record_header(tls_buf, sizeof(tls_buf), &tlsr);
    printf("Test 6a (TLS header parser): ret=%d\n", t6a);
    uint16_t tls_len = 0;
    int t6b = validate_tls_record_length(tls_buf, sizeof(tls_buf), &tls_len);
    printf("Test 6b (TLS length validator): ret=%d len=%u\n", t6b, tls_len);

    /* Test 7 — no code, user sets AIRE_OLLAMA_MODEL to a bad value */
    printf("Test 7 (bad model): set AIRE_OLLAMA_MODEL=nonexistent-model in Ghidra env\n");

    /* Test 8 — full-evidence session key exchange (needs real connection) */
    printf("Test 8 (session key exchange): load binary in Ghidra, point at perform_session_key_exchange\n");

    return 0;
}
