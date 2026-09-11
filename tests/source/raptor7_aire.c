/*
 * raptor7_aire.c — RAPTOR-7 Tactical Control Interface
 *
 * CTF-style crackme extended with full drone subsystem simulation.
 * Designed for AIRE Ghidra extension demonstration — all 8 test cases
 * are present as realistic drone control subsystem functions.
 *
 *  Test 1  — encrypt_mission_payload()    AES-256-CBC + named EVP callees
 *  Test 2  — drone_heartbeat_alive()      trivial stub → INSUFFICIENT_EVIDENCE
 *  Test 3  — parse_telemetry_packet()     large TLV parser → smart-trim
 *  Test 4  — dispatch_drone_command()     14-way command switch → high branchRatio
 *  Test 5  — init_c2_uplink()             TCP/socket setup → network evidence
 *  Test 6a — validate_video_frame()       \  similar frame validators
 *  Test 6b — validate_telemetry_frame()   /  → dedup / diversity filter
 *  Test 7  — (no code) set bad AIRE_OLLAMA_MODEL in Ghidra env
 *  Test 8  — establish_c2_session()       full-evidence key exchange
 *
 * Build:
 *   gcc -O0 -fno-inline -g -DHAVE_OPENSSL -o raptor7_aire_debug raptor7_aire.c \
 *       -lcrypto -lssl -lm
 *   strip --strip-all -o raptor7_aire raptor7_aire_debug
 *
 * Auth crackme: password is XOR-encoded (key 0x4F).
 * Strip binary before presenting; recover with Ghidra + AIRE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <math.h>

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 * ANSI colour / banner helpers
 * ═══════════════════════════════════════════════════════════════════════════ */
#define RESET   "\033[0m"
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define CYAN    "\033[1;36m"
#define BOLD    "\033[1m"
#define DIM     "\033[2m"

/* ═══════════════════════════════════════════════════════════════════════════
 * Auth constants  (original raptor7 crackme — unchanged)
 * ═══════════════════════════════════════════════════════════════════════════ */
#define PASS_LEN     15
#define XOR_KEY      0x4F
#define MAX_ATTEMPTS  3

/*
 * XOR-encoded "RAPTOR_7_ONLINE" ^ 0x4F.
 * Positions 4 and 9 decode to 0x00, so `strings` cannot recover this.
 */
static const unsigned char encoded_pass[PASS_LEN] = {
    0x1D, 0x0E, 0x1F, 0x1B, 0x00,
    0x1D, 0x10, 0x78, 0x10, 0x00,
    0x01, 0x03, 0x06, 0x01, 0x0A
};

/* Decoy credential table — `strings` will find these first */
__attribute__((used)) static const char cred_table_a[] = "operator_admin";
__attribute__((used)) static const char cred_table_b[] = "R4PT0R_access";

/* ═══════════════════════════════════════════════════════════════════════════
 * Shared drone types
 * ═══════════════════════════════════════════════════════════════════════════ */

#define MAX_WAYPOINTS      16
#define MAX_TLV_FIELDS     32
#define TLV_MAX_DEPTH       8
#define MAX_FRAME_PAYLOAD 512
#define C2_MAX_PAYLOAD    1024

/* Drone command opcodes — used by the dispatcher */
typedef enum {
    CMD_ARM            = 0x01,
    CMD_DISARM         = 0x02,
    CMD_TAKEOFF        = 0x03,
    CMD_LAND           = 0x04,
    CMD_RTH            = 0x05,   /* Return to Home */
    CMD_WAYPOINT       = 0x06,
    CMD_HOVER          = 0x07,
    CMD_SET_ALT        = 0x08,
    CMD_SET_SPEED      = 0x09,
    CMD_CAMERA_ON      = 0x0A,
    CMD_CAMERA_OFF     = 0x0B,
    CMD_PAYLOAD_DROP   = 0x0C,
    CMD_EMERGENCY_STOP = 0x0D,
    CMD_UNKNOWN        = 0xFF
} drone_cmd_t;

/* C2 command packet */
typedef struct {
    uint8_t  opcode;
    uint16_t length;
    uint8_t  payload[C2_MAX_PAYLOAD];
    uint32_t checksum;
    uint8_t  flags;
    uint16_t session_id;
} c2_packet_t;

/* GPS telemetry TLV record */
typedef struct {
    uint8_t  tag;
    uint16_t length;
    uint8_t *value;
    int      depth;
} tlv_field_t;

typedef struct {
    tlv_field_t fields[MAX_TLV_FIELDS];
    int         field_count;
    uint32_t    sequence;
    uint8_t     version;
    uint16_t    status_flags;
    double      latitude;
    double      longitude;
    float       altitude_m;
    float       heading_deg;
    float       speed_ms;
    char        drone_id[32];
} telemetry_record_t;

/* C2 uplink connection */
typedef struct {
    int      fd;
    uint32_t server_ip;
    uint16_t server_port;
    int      is_connected;
    int      timeout_ms;
    uint8_t  session_key[32];
    uint16_t session_id;
} c2_link_t;

/* Generic frame header (video and telemetry share the same 5-byte preamble) */
typedef struct {
    uint8_t  frame_type;   /* 0x01=video 0x02=telemetry 0x03=control */
    uint8_t  version;
    uint16_t payload_len;
    uint32_t sequence;
    uint32_t checksum;
    uint8_t  flags;
    uint8_t *payload;
} drone_frame_t;

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

static void log_warn(const char *msg) {
    fprintf(stderr, "[RAPTOR-7] WARN: %s\n", msg);
}
static void log_info(const char *msg) {
    fprintf(stderr, "[RAPTOR-7] INFO: %s\n", msg);
}

static uint32_t crc32_compute(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (0xEDB88320u & -(crc & 1));
    }
    return ~crc;
}

static void msleep(unsigned int ms) { usleep(ms * 1000u); }

static void slow_line(const char *text, unsigned int delay_ms) {
    fputs(text, stdout);
    fflush(stdout);
    if (delay_ms) msleep(delay_ms);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ── ORIGINAL RAPTOR-7 AUTH (crackme core — unchanged) ───────────────────
 * ═══════════════════════════════════════════════════════════════════════════ */

__attribute__((noinline))
static int check_operator_level(const char *buf) {
    return (strcmp(buf, cred_table_a) == 0) ? 1 : 0;
}

__attribute__((noinline))
static int validate_legacy_token(const char *buf) {
    return (strcmp(buf, cred_table_b) == 0) ? 1 : 0;
}

/*
 * process_auth() — real XOR credential validation.
 * Decodes at runtime; uses memcmp to handle embedded null bytes at
 * positions 4 and 9.  Decoy checks run first to bury the real comparison.
 */
static int process_auth(const char *input)
{
    unsigned char decoded[PASS_LEN];
    size_t i;
    int score;

    if (strlen(input) != PASS_LEN) return 0;

    for (i = 0; i < PASS_LEN; i++)
        decoded[i] = (unsigned char)(encoded_pass[i] ^ XOR_KEY);

    score  = check_operator_level(input) << 1;
    score |= validate_legacy_token(input);

    return ((memcmp(input, decoded, PASS_LEN) == 0) && (score == 0)) ? 1 : 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ── TEST 1: encrypt_mission_payload() ────────────────────────────────────
 *    AES-256-CBC encryption of mission data before uplink transmission.
 *    AIRE signals: named callees EVP_EncryptInit_ex / EVP_EncryptUpdate /
 *    EVP_EncryptFinal_ex, string refs "AES-256-CBC", usesCryptoLike=true
 *    Expected AIRE name: encrypt_mission_payload / aes256_cbc_encrypt
 * ═══════════════════════════════════════════════════════════════════════════ */
int encrypt_mission_payload(
        const uint8_t *plaintext, int plaintext_len,
        const uint8_t *key,       /* 32 bytes — derived session key */
        const uint8_t *iv,        /* 16 bytes — random per-message */
        uint8_t       *ciphertext /* caller allocates plaintext_len + 16 */)
{
#ifdef HAVE_OPENSSL
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        log_warn("encrypt_mission_payload: EVP_CIPHER_CTX_new failed");
        return -1;
    }

    int out_len1 = 0, out_len2 = 0;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        log_warn("encrypt_mission_payload: EVP_EncryptInit_ex failed — AES-256-CBC init error");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &out_len1, plaintext, plaintext_len)) {
        log_warn("encrypt_mission_payload: EVP_EncryptUpdate failed — payload encryption error");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + out_len1, &out_len2)) {
        log_warn("encrypt_mission_payload: EVP_EncryptFinal_ex failed — finalization error");
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    log_info("encrypt_mission_payload: AES-256-CBC encryption complete");
    return out_len1 + out_len2;
#else
    (void)plaintext; (void)plaintext_len;
    (void)key; (void)iv; (void)ciphertext;
    log_warn("encrypt_mission_payload: OpenSSL not available — AES-256-CBC disabled");
    return -1;
#endif
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ── TEST 2: drone_heartbeat_alive() ──────────────────────────────────────
 *    Minimal heartbeat stub — drone signals it is still operational.
 *    AIRE signals: 3 instructions, no callees, no strings, 1 basic block
 *    Expected AIRE output: INSUFFICIENT_EVIDENCE
 * ═══════════════════════════════════════════════════════════════════════════ */
int drone_heartbeat_alive(void)
{
    return 1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ── TEST 3: parse_telemetry_packet() ─────────────────────────────────────
 *    Parses GPS/IMU telemetry TLV frames from the drone's sensor bus.
 *    Large function body → decompile exceeds 3200 chars → smart-trim fires.
 *    AIRE signals: nested loops, many branches, string refs "telemetry",
 *    "invalid tag", "sequence mismatch", "altitude out of range", etc.
 *    Expected AIRE name: parse_telemetry_packet / decode_gps_telemetry
 * ═══════════════════════════════════════════════════════════════════════════ */

static int tlv_tag_is_valid(uint8_t tag) {
    return (tag != 0x00 && tag != 0xFF);
}

static int tlv_length_fits(uint16_t len, size_t remaining) {
    return (len > 0 && (size_t)len <= remaining && len <= 256);
}

int parse_telemetry_packet(const uint8_t *buf, size_t buf_len, telemetry_record_t *out)
{
    if (!buf || !out || buf_len < 12) {
        log_warn("parse_telemetry_packet: null pointer or buffer too short");
        return -1;
    }
    memset(out, 0, sizeof(*out));

    /* ── Fixed header ── */
    size_t pos = 0;
    out->sequence     = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16)
                      | ((uint32_t)buf[2] <<  8)  |  (uint32_t)buf[3];
    pos += 4;
    out->version      = buf[pos++];
    out->status_flags = ((uint16_t)buf[pos] << 8) | buf[pos + 1];
    pos += 2;
    int expected_fields = buf[pos++];

    if (out->version != 1 && out->version != 2) {
        log_warn("parse_telemetry_packet: unsupported telemetry version");
        return -1;
    }
    if (expected_fields > MAX_TLV_FIELDS) {
        log_warn("parse_telemetry_packet: field count exceeds maximum — packet too large");
        return -1;
    }

    /* ── Depth tracking for nested containers ── */
    int depth_remaining[TLV_MAX_DEPTH];
    int depth = 0;
    depth_remaining[0] = (int)(buf_len - pos);

    int field_idx = 0;
    int iter      = 0;
    const int ITER_LIMIT = 512;

    while (pos < buf_len && field_idx < MAX_TLV_FIELDS && iter++ < ITER_LIMIT) {

        if (pos + 3 > buf_len) {
            log_warn("parse_telemetry_packet: truncated TLV header in stream");
            break;
        }

        uint8_t  tag = buf[pos];
        uint16_t len = ((uint16_t)buf[pos + 1] << 8) | buf[pos + 2];
        pos += 3;

        if (!tlv_tag_is_valid(tag)) {
            log_warn("parse_telemetry_packet: invalid tag byte — dropping packet");
            return -1;
        }
        if (!tlv_length_fits(len, buf_len - pos)) {
            log_warn("parse_telemetry_packet: TLV length overflow — corrupt telemetry");
            return -1;
        }

        /* Container push */
        if (tag == 0xFE) {
            if (depth + 1 >= TLV_MAX_DEPTH) {
                log_warn("parse_telemetry_packet: nesting depth limit exceeded");
                return -1;
            }
            depth++;
            depth_remaining[depth] = len;
            continue;
        }
        /* Container pop */
        if (tag == 0xFD) {
            if (depth == 0) {
                log_warn("parse_telemetry_packet: unexpected container-end at root depth");
                return -1;
            }
            depth--;
            continue;
        }

        /* ── Tag decode ── */
        const uint8_t *v = buf + pos;
        pos += len;

        switch (tag) {

            case 0x01: /* Drone ID */
                if (len <= 31) {
                    memcpy(out->drone_id, v, len);
                    out->drone_id[len] = '\0';
                } else {
                    log_warn("parse_telemetry_packet: drone_id field too long — truncating");
                    memcpy(out->drone_id, v, 31);
                    out->drone_id[31] = '\0';
                }
                break;

            case 0x02: /* Latitude — 8-byte IEEE 754 double */
                if (len == 8) {
                    memcpy(&out->latitude, v, 8);
                    if (out->latitude < -90.0 || out->latitude > 90.0) {
                        log_warn("parse_telemetry_packet: latitude out of range [-90,90]");
                        return -1;
                    }
                }
                break;

            case 0x03: /* Longitude — 8-byte IEEE 754 double */
                if (len == 8) {
                    memcpy(&out->longitude, v, 8);
                    if (out->longitude < -180.0 || out->longitude > 180.0) {
                        log_warn("parse_telemetry_packet: longitude out of range [-180,180]");
                        return -1;
                    }
                }
                break;

            case 0x04: /* Altitude — 4-byte float, metres MSL */
                if (len == 4) {
                    memcpy(&out->altitude_m, v, 4);
                    if (out->altitude_m < -500.0f || out->altitude_m > 12000.0f) {
                        log_warn("parse_telemetry_packet: altitude out of operational range");
                        return -1;
                    }
                }
                break;

            case 0x05: /* Heading — 4-byte float, degrees */
                if (len == 4) {
                    memcpy(&out->heading_deg, v, 4);
                    if (out->heading_deg < 0.0f || out->heading_deg > 360.0f) {
                        log_warn("parse_telemetry_packet: heading out of range [0,360]");
                        return -1;
                    }
                }
                break;

            case 0x06: /* Groundspeed — 4-byte float, m/s */
                if (len == 4) {
                    memcpy(&out->speed_ms, v, 4);
                    if (out->speed_ms < 0.0f || out->speed_ms > 200.0f) {
                        log_warn("parse_telemetry_packet: speed exceeds maximum airspeed limit");
                        return -1;
                    }
                }
                break;

            case 0x10: /* Packet CRC — verify inline */
                if (len == 4) {
                    uint32_t claimed = ((uint32_t)v[0] << 24) | ((uint32_t)v[1] << 16)
                                     | ((uint32_t)v[2] <<  8) |  (uint32_t)v[3];
                    uint32_t actual = crc32_compute(buf, pos - len - 3);
                    if (claimed != actual) {
                        log_warn("parse_telemetry_packet: CRC mismatch — telemetry corrupt");
                        return -1;
                    }
                }
                break;

            case 0x20: /* Status flags override */
                if (len == 2)
                    out->status_flags = ((uint16_t)v[0] << 8) | v[1];
                break;

            default:
                /* Unknown tag — log and skip */
                if (tag >= 0x80) {
                    log_warn("parse_telemetry_packet: unrecognised extended tag — skipping");
                }
                break;
        }

        /* Track remaining bytes inside current container */
        if (depth > 0) {
            depth_remaining[depth] -= (len + 3);
            if (depth_remaining[depth] < 0) {
                log_warn("parse_telemetry_packet: container byte count overrun");
                return -1;
            }
        }

        out->fields[field_idx].tag    = tag;
        out->fields[field_idx].length = len;
        out->fields[field_idx].value  = (uint8_t *)(buf + pos - len);
        out->fields[field_idx].depth  = depth;
        field_idx++;
    }

    out->field_count = field_idx;
    log_info("parse_telemetry_packet: telemetry record decoded successfully");
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ── TEST 4: dispatch_drone_command() ─────────────────────────────────────
 *    Routes incoming C2 command packets to the appropriate handler.
 *    AIRE signals: 14-case switch → branchRatio > 3.0, named handler callees,
 *    string refs per command type "ARM", "DISARM", "WAYPOINT", "RTH", etc.
 *    Expected AIRE name: dispatch_drone_command / handle_c2_command
 * ═══════════════════════════════════════════════════════════════════════════ */

static int cmd_arm(c2_packet_t *p) {
    log_info("dispatch: arming drone motors");
    return p->length == 0 ? 0 : -1;
}
static int cmd_disarm(c2_packet_t *p) {
    log_info("dispatch: disarming drone motors");
    return p->length == 0 ? 0 : -1;
}
static int cmd_takeoff(c2_packet_t *p) {
    if (p->length < 2) { log_warn("dispatch: takeoff missing altitude parameter"); return -1; }
    return 0;
}
static int cmd_land(c2_packet_t *p) {
    (void)p;
    log_info("dispatch: initiating landing sequence");
    return 0;
}
static int cmd_rth(c2_packet_t *p) {
    (void)p;
    log_info("dispatch: return-to-home engaged");
    return 0;
}
static int cmd_waypoint(c2_packet_t *p) {
    if (p->length < 16) { log_warn("dispatch: waypoint payload too short — need lat/lon/alt"); return -1; }
    return 0;
}
static int cmd_hover(c2_packet_t *p) {
    (void)p;
    log_info("dispatch: holding position — hover mode active");
    return 0;
}
static int cmd_set_altitude(c2_packet_t *p) {
    if (p->length < 4) { log_warn("dispatch: set_altitude missing float parameter"); return -1; }
    return 0;
}
static int cmd_set_speed(c2_packet_t *p) {
    if (p->length < 4) { log_warn("dispatch: set_speed missing float parameter"); return -1; }
    return 0;
}
static int cmd_camera_on(c2_packet_t *p) {
    (void)p;
    log_info("dispatch: payload camera activated");
    return 0;
}
static int cmd_camera_off(c2_packet_t *p) {
    (void)p;
    log_info("dispatch: payload camera deactivated");
    return 0;
}
static int cmd_payload_drop(c2_packet_t *p) {
    if (!(p->flags & 0x01)) {
        log_warn("dispatch: payload_drop requires arming flag — rejected");
        return -1;
    }
    log_info("dispatch: payload release mechanism triggered");
    return 0;
}
static int cmd_emergency_stop(c2_packet_t *p) {
    (void)p;
    log_warn("dispatch: EMERGENCY STOP — all motors cut");
    return 1; /* signal caller to halt all subsystems */
}

int dispatch_drone_command(c2_packet_t *pkt)
{
    if (!pkt) {
        log_warn("dispatch_drone_command: null packet pointer");
        return -1;
    }

    /* Verify packet integrity before dispatch */
    uint32_t expected = crc32_compute(pkt->payload, pkt->length);
    if (pkt->checksum != 0 && pkt->checksum != expected) {
        log_warn("dispatch_drone_command: checksum mismatch — command packet rejected");
        return -1;
    }

    switch ((drone_cmd_t)pkt->opcode) {
        case CMD_ARM:            return cmd_arm(pkt);
        case CMD_DISARM:         return cmd_disarm(pkt);
        case CMD_TAKEOFF:        return cmd_takeoff(pkt);
        case CMD_LAND:           return cmd_land(pkt);
        case CMD_RTH:            return cmd_rth(pkt);
        case CMD_WAYPOINT:       return cmd_waypoint(pkt);
        case CMD_HOVER:          return cmd_hover(pkt);
        case CMD_SET_ALT:        return cmd_set_altitude(pkt);
        case CMD_SET_SPEED:      return cmd_set_speed(pkt);
        case CMD_CAMERA_ON:      return cmd_camera_on(pkt);
        case CMD_CAMERA_OFF:     return cmd_camera_off(pkt);
        case CMD_PAYLOAD_DROP:   return cmd_payload_drop(pkt);
        case CMD_EMERGENCY_STOP: return cmd_emergency_stop(pkt);
        case CMD_UNKNOWN:
        default:
            log_warn("dispatch_drone_command: unknown opcode — command dropped");
            return -1;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ── TEST 5: init_c2_uplink() ─────────────────────────────────────────────
 *    Establishes TCP connection to the ground station C2 server.
 *    AIRE signals: socket/connect/setsockopt, SO_REUSEADDR, TCP_NODELAY,
 *    "uplink", "ground station", usesNetworkIOLike=true
 *    Risk: model may suggest something generic like "setup_socket"
 *    Expected AIRE name: init_c2_uplink / connect_ground_station
 * ═══════════════════════════════════════════════════════════════════════════ */
int init_c2_uplink(c2_link_t *link)
{
    if (!link) {
        log_warn("init_c2_uplink: null link pointer");
        return -1;
    }

    link->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (link->fd < 0) {
        log_warn("init_c2_uplink: socket() failed — cannot open C2 uplink");
        return -1;
    }

    int opt = 1;
    if (setsockopt(link->fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        log_warn("init_c2_uplink: setsockopt SO_REUSEADDR failed");

#ifdef TCP_NODELAY
    if (setsockopt(link->fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) < 0)
        log_warn("init_c2_uplink: setsockopt TCP_NODELAY failed — latency may increase");
#endif

    if (link->timeout_ms > 0) {
        struct timeval tv = {
            .tv_sec  = link->timeout_ms / 1000,
            .tv_usec = (link->timeout_ms % 1000) * 1000
        };
        setsockopt(link->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(link->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(link->server_port);
    addr.sin_addr.s_addr = htonl(link->server_ip);

    if (connect(link->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_warn("init_c2_uplink: connect() failed — ground station unreachable");
        close(link->fd);
        link->fd = -1;
        return -1;
    }

    link->is_connected = 1;
    log_info("init_c2_uplink: C2 uplink to ground station established");
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ── TEST 6a: validate_video_frame() ──────────────────────────────────────
 *    Validates a video stream frame header from the payload camera.
 *    AIRE signals: frame type check, version check, length bounds,
 *    string "video frame", "camera payload", sequence tracking
 * ── TEST 6b: validate_telemetry_frame() ──────────────────────────────────
 *    Validates a telemetry downlink frame from the sensor bus.
 *    AIRE signals: same structural vocabulary as 6a — near-duplicate
 *    suggestions expected → dedup / semantic diversity filter fires
 * ═══════════════════════════════════════════════════════════════════════════ */
int validate_video_frame(const uint8_t *buf, size_t buf_len, drone_frame_t *out)
{
    if (!buf || !out || buf_len < 12) {
        log_warn("validate_video_frame: buffer too short for frame header");
        return -1;
    }

    out->frame_type  = buf[0];
    out->version     = buf[1];
    out->payload_len = ((uint16_t)buf[2] << 8) | buf[3];
    out->sequence    = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16)
                     | ((uint32_t)buf[6] << 8)  |  (uint32_t)buf[7];
    out->checksum    = ((uint32_t)buf[8] << 24) | ((uint32_t)buf[9] << 16)
                     | ((uint32_t)buf[10] << 8) |  (uint32_t)buf[11];
    out->flags       = buf_len > 12 ? buf[12] : 0;

    if (out->frame_type != 0x01) {
        log_warn("validate_video_frame: frame type is not video — wrong handler");
        return -1;
    }
    if (out->version != 1 && out->version != 2) {
        log_warn("validate_video_frame: unsupported camera stream version");
        return -1;
    }
    if (out->payload_len == 0) {
        log_warn("validate_video_frame: zero-length video frame payload");
        return -1;
    }
    if (out->payload_len > MAX_FRAME_PAYLOAD) {
        log_warn("validate_video_frame: video frame exceeds maximum payload size");
        return -1;
    }
    if (buf_len < (size_t)(13 + out->payload_len)) {
        log_warn("validate_video_frame: video frame truncated — incomplete camera data");
        return -1;
    }

    uint32_t actual = crc32_compute(buf, 8);
    if (out->checksum != 0 && out->checksum != actual) {
        log_warn("validate_video_frame: video frame checksum mismatch — corruption detected");
        return -1;
    }

    out->payload = (uint8_t *)(buf + 13);
    log_info("validate_video_frame: camera payload frame validated");
    return 0;
}

int validate_telemetry_frame(const uint8_t *buf, size_t buf_len, drone_frame_t *out)
{
    if (!buf || !out || buf_len < 12) {
        log_warn("validate_telemetry_frame: buffer too short for frame header");
        return -1;
    }

    out->frame_type  = buf[0];
    out->version     = buf[1];
    out->payload_len = ((uint16_t)buf[2] << 8) | buf[3];
    out->sequence    = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16)
                     | ((uint32_t)buf[6] << 8)  |  (uint32_t)buf[7];
    out->checksum    = ((uint32_t)buf[8] << 24) | ((uint32_t)buf[9] << 16)
                     | ((uint32_t)buf[10] << 8) |  (uint32_t)buf[11];
    out->flags       = buf_len > 12 ? buf[12] : 0;

    if (out->frame_type != 0x02) {
        log_warn("validate_telemetry_frame: frame type is not telemetry — wrong handler");
        return -1;
    }
    if (out->version != 1 && out->version != 2) {
        log_warn("validate_telemetry_frame: unsupported telemetry stream version");
        return -1;
    }
    if (out->payload_len == 0) {
        log_warn("validate_telemetry_frame: zero-length telemetry payload");
        return -1;
    }
    if (out->payload_len > MAX_FRAME_PAYLOAD) {
        log_warn("validate_telemetry_frame: telemetry frame exceeds maximum payload size");
        return -1;
    }
    if (buf_len < (size_t)(13 + out->payload_len)) {
        log_warn("validate_telemetry_frame: telemetry frame truncated — sensor data incomplete");
        return -1;
    }

    uint32_t actual = crc32_compute(buf, 8);
    if (out->checksum != 0 && out->checksum != actual) {
        log_warn("validate_telemetry_frame: telemetry checksum mismatch — data corrupt");
        return -1;
    }

    out->payload = (uint8_t *)(buf + 13);
    log_info("validate_telemetry_frame: telemetry downlink frame validated");
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ── TEST 8: establish_c2_session() ───────────────────────────────────────
 *    Full-evidence function: derives a session key and authenticates the
 *    drone to the ground station over the encrypted C2 uplink.
 *    AIRE signals:
 *      Named callees — encrypt_mission_payload, dispatch_drone_command,
 *                      parse_telemetry_packet, crc32_compute
 *      Strings — "session key", "key derivation", "handshake", "C2 session"
 *      Flags   — usesCryptoLike + usesNetworkIOLike
 *      Structure — multiple basic blocks, loops, branches
 *    Expected AIRE name: establish_c2_session (high confidence, full breakdown)
 * ═══════════════════════════════════════════════════════════════════════════ */
int establish_c2_session(
        c2_link_t     *link,
        const uint8_t *operator_token, /* 32 bytes — from process_auth */
        size_t         token_len)
{
    if (!link || !operator_token || token_len < 32) {
        log_warn("establish_c2_session: invalid arguments");
        return -1;
    }
    if (!link->is_connected) {
        log_warn("establish_c2_session: C2 uplink not connected — call init_c2_uplink first");
        return -1;
    }

    log_info("establish_c2_session: beginning C2 session key derivation");

    /* ── Step 1: generate local nonce ── */
    uint8_t local_nonce[32];
#ifdef HAVE_OPENSSL
    if (RAND_bytes(local_nonce, sizeof(local_nonce)) != 1) {
        log_warn("establish_c2_session: RAND_bytes failed — key derivation aborted");
        return -1;
    }
#else
    for (int i = 0; i < 32; i++) local_nonce[i] = (uint8_t)(i ^ 0xA5 ^ operator_token[i % token_len]);
#endif

    /* ── Step 2: derive session key = operator_token XOR nonce ── */
    for (int i = 0; i < 32; i++)
        link->session_key[i] = operator_token[i] ^ local_nonce[i];

    /* Sanity — key must not be all-zero */
    uint32_t key_crc = crc32_compute(link->session_key, 32);
    if (key_crc == 0) {
        log_warn("establish_c2_session: derived session key is degenerate — aborting handshake");
        return -1;
    }

    /* ── Step 3: encrypt the handshake hello with derived key ── */
    uint8_t hello[]    = "RAPTOR-7 C2 handshake";
    uint8_t iv[16];
    uint8_t hello_enc[48];
    memset(iv, 0x3C, sizeof(iv));

    int enc_len = encrypt_mission_payload(
            hello, (int)strlen((char *)hello),
            link->session_key, iv, hello_enc);

    if (enc_len < 0) {
        log_warn("establish_c2_session: handshake encryption failed");
        return -1;
    }

    /* ── Step 4: wrap in a C2 packet and dispatch ── */
    c2_packet_t hello_pkt;
    memset(&hello_pkt, 0, sizeof(hello_pkt));
    hello_pkt.opcode     = CMD_ARM;          /* ARM as handshake opener */
    hello_pkt.session_id = link->server_port;
    hello_pkt.length     = (uint16_t)enc_len;
    memcpy(hello_pkt.payload, hello_enc, (size_t)enc_len);
    hello_pkt.checksum   = crc32_compute(hello_pkt.payload, enc_len);
    hello_pkt.flags      = 0x01;             /* arming flag set */

    int disp = dispatch_drone_command(&hello_pkt);
    if (disp < 0) {
        log_warn("establish_c2_session: handshake command dispatch failed");
        return -1;
    }

    /* ── Step 5: send nonce to ground station for key agreement ── */
    uint8_t nonce_frame[36];
    nonce_frame[0] = 0x01;   /* nonce frame type */
    nonce_frame[1] = 0x00;
    nonce_frame[2] = 0x20;   /* 32-byte payload */
    memcpy(nonce_frame + 3, local_nonce, 32);
    nonce_frame[35] = (uint8_t)(key_crc & 0xFF);

    ssize_t sent = write(link->fd, nonce_frame, sizeof(nonce_frame));
    if (sent != (ssize_t)sizeof(nonce_frame)) {
        log_warn("establish_c2_session: failed to transmit nonce frame to ground station");
        return -1;
    }

    /* ── Step 6: receive and validate ground station acknowledgement ── */
    uint8_t ack_buf[64];
    ssize_t recv_len = read(link->fd, ack_buf, sizeof(ack_buf));
    if (recv_len < 5) {
        log_warn("establish_c2_session: ACK from ground station too short or missing");
        return -1;
    }

    /* Parse the ACK as a telemetry packet to verify the channel is live */
    telemetry_record_t ack_record;
    if (parse_telemetry_packet(ack_buf, (size_t)recv_len, &ack_record) < 0) {
        log_warn("establish_c2_session: ACK telemetry parse failed — session not established");
        return -1;
    }

    link->session_id = (uint16_t)(key_crc & 0xFFFF);
    log_info("establish_c2_session: C2 session established — uplink secure");
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ── POST-AUTH: drone state, mission decrypt, telemetry, command shell ─────
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ── Drone state machine ── */
typedef enum {
    STATE_STANDBY   = 0,
    STATE_ARMED     = 1,
    STATE_AIRBORNE  = 2,
    STATE_RETURNING = 3,
    STATE_EMERGENCY = 4
} drone_state_t;

static drone_state_t g_state    = STATE_STANDBY;
static float         g_alt      = 0.0f;
static float         g_lat      = 34.0522f;
static float         g_lon      = -118.2437f;
static float         g_speed    = 0.0f;
static float         g_heading  = 0.0f;
static int           g_battery  = 94;
static unsigned int  g_tick     = 0;

static const char *g_state_label[] = {
    "STANDBY  ", "ARMED    ", "AIRBORNE ", "RETURNING", "EMERGENCY"
};

/* ── Encrypted mission briefing (AES-256-CBC, key derived from password) ── */
#define MISSION_ENC_LEN 272

static const uint8_t mission_iv[16] = {
    0x52, 0x41, 0x50, 0x54, 0x4F, 0x52, 0x37, 0x5F,
    0x4B, 0x45, 0x59, 0x5F, 0x49, 0x56, 0x30, 0x31
};

static const uint8_t mission_enc[MISSION_ENC_LEN] = {
    0x7F, 0x04, 0x40, 0x8C, 0xEB, 0xED, 0xA1, 0xB2,
    0x5F, 0x9C, 0xFA, 0xFF, 0x03, 0xC1, 0x95, 0xC1,
    0x9B, 0x22, 0x2D, 0x71, 0xCC, 0x16, 0x3A, 0x3C,
    0x16, 0xC3, 0x43, 0x16, 0xF1, 0xFC, 0x62, 0xDD,
    0x3E, 0xF6, 0x0D, 0xE0, 0x2F, 0x6C, 0x74, 0x0F,
    0xDF, 0x9F, 0xCA, 0x97, 0x6D, 0xAF, 0x9F, 0xD6,
    0x1F, 0x10, 0x0F, 0x35, 0x63, 0x5C, 0xCB, 0x38,
    0x46, 0x58, 0x9A, 0x48, 0x41, 0xD7, 0x4A, 0x7A,
    0x39, 0x44, 0x89, 0x88, 0x18, 0x23, 0x4E, 0x1F,
    0x4F, 0xF1, 0xCA, 0xDB, 0xAB, 0x34, 0xF3, 0x1A,
    0x01, 0xF6, 0xFC, 0x23, 0x73, 0xE4, 0x3B, 0x9C,
    0x13, 0x1D, 0xC5, 0xB4, 0xA8, 0xB4, 0x6F, 0x2C,
    0xA7, 0xF5, 0x99, 0x51, 0x13, 0xFA, 0xA5, 0x7A,
    0x09, 0xAA, 0x93, 0x14, 0x83, 0x86, 0x0C, 0xB9,
    0x94, 0xFB, 0xBC, 0xD0, 0x73, 0x14, 0x09, 0x78,
    0x5A, 0x8F, 0x62, 0xF1, 0x6B, 0x04, 0x07, 0x3D,
    0xE4, 0x5C, 0xB4, 0x80, 0xF4, 0xE4, 0xD8, 0x10,
    0x53, 0x12, 0x35, 0x69, 0x86, 0x64, 0x17, 0xEE,
    0x52, 0xCD, 0xE4, 0x15, 0x59, 0x70, 0xED, 0xBE,
    0xF2, 0x0C, 0xB9, 0x09, 0xB3, 0x86, 0x37, 0xD0,
    0xA5, 0xAA, 0xFE, 0x8C, 0xBA, 0x91, 0x39, 0xE1,
    0xEF, 0x76, 0x0A, 0xC3, 0x75, 0x8D, 0x4F, 0x90,
    0x27, 0xAD, 0x9A, 0xA2, 0x24, 0x40, 0x6B, 0x27,
    0xFF, 0x3C, 0xD7, 0x9C, 0xEF, 0xB7, 0xF0, 0xA5,
    0x38, 0x70, 0xB4, 0x41, 0xA2, 0x30, 0x4D, 0x29,
    0x09, 0xE5, 0xCF, 0x4F, 0x27, 0xCD, 0xBF, 0xA1,
    0x82, 0x7E, 0xD4, 0x19, 0x69, 0xE8, 0x0C, 0x6D,
    0xB7, 0x4F, 0xF2, 0x53, 0xBF, 0x6A, 0xA7, 0xE6,
    0xCA, 0x63, 0x29, 0x79, 0x9A, 0x3A, 0x9B, 0xEC,
    0x3D, 0x5E, 0x2D, 0x94, 0xE2, 0x19, 0xF7, 0x24,
    0x3E, 0x65, 0x7C, 0xA9, 0xFD, 0x4F, 0x61, 0x24,
    0xBD, 0x3E, 0xE3, 0x0F, 0x65, 0xC0, 0xB2, 0xF8,
    0x2B, 0x91, 0xCF, 0x0D, 0xCF, 0x75, 0xF9, 0x24,
    0xBC, 0x00, 0x8F, 0x77, 0xF9, 0xE6, 0x40, 0xA7,
};

/* key[i] = password[i % plen] ^ (i * 0x17 & 0xFF) — same as Python precompute */
static void derive_mission_key(const char *pass, uint8_t key[32]) {
    size_t plen = strlen(pass);
    for (int i = 0; i < 32; i++)
        key[i] = (uint8_t)((unsigned char)pass[i % plen] ^ ((uint8_t)(i * 0x17)));
}

static void reveal_mission(const char *pass) {
#ifdef HAVE_OPENSSL
    uint8_t key[32];
    derive_mission_key(pass, key);

    uint8_t plain[MISSION_ENC_LEN];
    int out1 = 0, out2 = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { log_warn("reveal_mission: EVP_CIPHER_CTX_new failed"); return; }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, mission_iv) ||
        1 != EVP_DecryptUpdate(ctx, plain, &out1, mission_enc, MISSION_ENC_LEN) ||
        1 != EVP_DecryptFinal_ex(ctx, plain + out1, &out2)) {
        EVP_CIPHER_CTX_free(ctx);
        log_warn("reveal_mission: decryption failed");
        return;
    }
    EVP_CIPHER_CTX_free(ctx);
    int plain_len = out1 + out2;

    slow_line(YELLOW "\n  ╔══════════════════════════════════════════╗\n" RESET, 60);
    slow_line(YELLOW   "  ║   CLASSIFIED  //  MISSION BRIEFING      ║\n" RESET, 60);
    slow_line(YELLOW   "  ╚══════════════════════════════════════════╝\n\n" RESET, 300);

    for (int i = 0; i < plain_len; i++) {
        putchar(plain[i]);
        fflush(stdout);
        msleep(plain[i] == '\n' ? 120 : 14);
    }
    printf("\n");
    fflush(stdout);
    msleep(600);
#else
    (void)pass;
    slow_line(YELLOW "  [MISSION] OpenSSL required to decrypt mission briefing.\n" RESET, 0);
#endif
}

/* ── Telemetry simulation helpers ── */
static void simulate_tick(void) {
    g_tick++;
    if (g_state == STATE_AIRBORNE || g_state == STATE_RETURNING) {
        g_lat    += 0.0001f * sinf((float)g_tick * 0.4f);
        g_lon    += 0.0001f * cosf((float)g_tick * 0.4f);
        g_heading = fmodf(g_heading + 2.5f, 360.0f);
        g_speed   = 12.0f + 3.0f * sinf((float)g_tick * 0.7f);
        if (g_tick % 30 == 0 && g_battery > 0) g_battery--;
    }
}

#define TELEM_LINES 7

static void print_telem_block(void) {
    printf(CYAN "  ── LIVE TELEMETRY ──────────────────────────\n" RESET);
    printf("  STATE    : %s\033[K\n",               g_state_label[g_state]);
    printf("  POSITION : %.4fN  %.4fW\033[K\n",     g_lat, fabsf(g_lon));
    printf("  ALTITUDE : %.1f m\033[K\n",            g_alt);
    printf("  HEADING  : %.1f deg    SPEED: %.1f m/s\033[K\n", g_heading, g_speed);
    printf("  BATTERY  : %d%%\033[K\n",              g_battery);
    printf(CYAN "  ─────────────────────────────────────────────\n" RESET);
    fflush(stdout);
}

static void live_telem(int ticks) {
    print_telem_block();
    for (int i = 1; i < ticks; i++) {
        msleep(800);
        simulate_tick();
        printf("\033[%dA", TELEM_LINES);
        print_telem_block();
    }
    printf("\n");
}

/* ── Command shell ── */
static void shell_help(void) {
    slow_line(BOLD "\n  RAPTOR-7 COMMAND REFERENCE\n" RESET, 0);
    slow_line("  ─────────────────────────────────────────────\n", 0);
    slow_line("  ARM                  Arm motors (from STANDBY)\n",  0);
    slow_line("  DISARM               Disarm (when ARMED)\n",        0);
    slow_line("  TAKEOFF [alt_m]      Ascend to altitude (default 50m)\n", 0);
    slow_line("  LAND                 Land and disarm\n",             0);
    slow_line("  RTH                  Return to home\n",              0);
    slow_line("  HOVER                Hold current position\n",       0);
    slow_line("  WAYPOINT <lat> <lon> <alt>   Fly to waypoint\n",    0);
    slow_line("  CAMERA ON|OFF        Toggle payload camera\n",       0);
    slow_line("  PAYLOAD DROP         Release payload (armed flag required)\n", 0);
    slow_line("  EMERGENCY            Emergency motor cut\n",         0);
    slow_line("  STATUS               Live telemetry (5 ticks)\n",   0);
    slow_line("  MISSION              Re-display mission briefing\n", 0);
    slow_line("  HELP                 This reference\n",              0);
    slow_line("  EXIT                 Terminate uplink\n\n",          0);
}

static int shell_exec(char *line, const char *pass) {
    /* tokenize in-place */
    char *tok[8];
    int   ntok = 0;
    char *p    = line;
    while (*p && ntok < 8) {
        while (*p == ' ') p++;
        if (!*p) break;
        tok[ntok++] = p;
        while (*p && *p != ' ') p++;
        if (*p) *p++ = '\0';
    }
    if (ntok == 0) return 0;

    /* uppercase command token */
    for (char *c = tok[0]; *c; c++) *c = (char)toupper((unsigned char)*c);

    /* EXIT / QUIT */
    if (strcmp(tok[0], "EXIT") == 0 || strcmp(tok[0], "QUIT") == 0) {
        slow_line(DIM "\n  [RAPTOR-7] Uplink terminated. Goodbye.\n\n" RESET, 300);
        return -1;
    }

    /* HELP */
    if (strcmp(tok[0], "HELP") == 0) { shell_help(); return 0; }

    /* MISSION */
    if (strcmp(tok[0], "MISSION") == 0) { reveal_mission(pass); return 0; }

    /* STATUS */
    if (strcmp(tok[0], "STATUS") == 0) { live_telem(5); return 0; }

    /* ARM */
    if (strcmp(tok[0], "ARM") == 0) {
        if (g_state != STATE_STANDBY) {
            slow_line(RED "  [!!] INTERLOCK — ALREADY ARMED OR AIRBORNE\n\n" RESET, 0);
            return 0;
        }
        c2_packet_t pkt; memset(&pkt, 0, sizeof(pkt));
        pkt.opcode = CMD_ARM;
        dispatch_drone_command(&pkt);
        g_state = STATE_ARMED;
        slow_line(GREEN "  [✓] MOTORS ARMED — READY FOR TAKEOFF\n\n" RESET, 300);
        return 0;
    }

    /* DISARM */
    if (strcmp(tok[0], "DISARM") == 0) {
        if (g_state != STATE_ARMED) {
            slow_line(RED "  [!!] INTERLOCK — MUST BE ARMED AND ON GROUND\n\n" RESET, 0);
            return 0;
        }
        c2_packet_t pkt; memset(&pkt, 0, sizeof(pkt));
        pkt.opcode = CMD_DISARM;
        dispatch_drone_command(&pkt);
        g_state = STATE_STANDBY;
        slow_line(YELLOW "  [✓] MOTORS DISARMED\n\n" RESET, 300);
        return 0;
    }

    /* TAKEOFF [alt] */
    if (strcmp(tok[0], "TAKEOFF") == 0) {
        if (g_state != STATE_ARMED) {
            slow_line(RED "  [!!] INTERLOCK — ARM FIRST\n\n" RESET, 0);
            return 0;
        }
        float target = (ntok >= 2) ? strtof(tok[1], NULL) : 50.0f;
        if (target <= 0.0f || target > 500.0f) target = 50.0f;
        c2_packet_t pkt; memset(&pkt, 0, sizeof(pkt));
        pkt.opcode = CMD_TAKEOFF;
        pkt.length = 2;
        dispatch_drone_command(&pkt);
        g_alt    = target;
        g_speed  = 8.0f;
        g_state  = STATE_AIRBORNE;
        printf(GREEN "  [✓] ASCENDING TO %.0f m\n\n" RESET, target);
        fflush(stdout);
        live_telem(4);
        return 0;
    }

    /* LAND */
    if (strcmp(tok[0], "LAND") == 0) {
        if (g_state != STATE_AIRBORNE && g_state != STATE_RETURNING) {
            slow_line(RED "  [!!] NOT AIRBORNE\n\n" RESET, 0);
            return 0;
        }
        c2_packet_t pkt; memset(&pkt, 0, sizeof(pkt));
        pkt.opcode = CMD_LAND;
        dispatch_drone_command(&pkt);
        g_alt   = 0.0f;
        g_speed = 0.0f;
        g_state = STATE_STANDBY;
        slow_line(GREEN "  [✓] LANDING SEQUENCE COMPLETE — MOTORS DISARMED\n\n" RESET, 400);
        return 0;
    }

    /* RTH */
    if (strcmp(tok[0], "RTH") == 0) {
        if (g_state != STATE_AIRBORNE) {
            slow_line(RED "  [!!] NOT AIRBORNE\n\n" RESET, 0);
            return 0;
        }
        c2_packet_t pkt; memset(&pkt, 0, sizeof(pkt));
        pkt.opcode = CMD_RTH;
        dispatch_drone_command(&pkt);
        g_state = STATE_RETURNING;
        slow_line(YELLOW "  [✓] RETURN-TO-HOME ENGAGED\n\n" RESET, 300);
        live_telem(4);
        return 0;
    }

    /* HOVER */
    if (strcmp(tok[0], "HOVER") == 0) {
        if (g_state != STATE_AIRBORNE) {
            slow_line(RED "  [!!] NOT AIRBORNE\n\n" RESET, 0);
            return 0;
        }
        c2_packet_t pkt; memset(&pkt, 0, sizeof(pkt));
        pkt.opcode = CMD_HOVER;
        dispatch_drone_command(&pkt);
        g_speed = 0.0f;
        slow_line(GREEN "  [✓] HOLDING POSITION — HOVER MODE ACTIVE\n\n" RESET, 300);
        return 0;
    }

    /* WAYPOINT <lat> <lon> <alt> */
    if (strcmp(tok[0], "WAYPOINT") == 0) {
        if (g_state != STATE_AIRBORNE) {
            slow_line(RED "  [!!] NOT AIRBORNE\n\n" RESET, 0);
            return 0;
        }
        if (ntok < 4) {
            slow_line(RED "  [!!] USAGE: WAYPOINT <lat> <lon> <alt>\n\n" RESET, 0);
            return 0;
        }
        float wlat = strtof(tok[1], NULL);
        float wlon = strtof(tok[2], NULL);
        float walt = strtof(tok[3], NULL);
        c2_packet_t pkt; memset(&pkt, 0, sizeof(pkt));
        pkt.opcode = CMD_WAYPOINT;
        pkt.length = 16;
        dispatch_drone_command(&pkt);
        g_lat    = wlat;
        g_lon    = wlon;
        g_alt    = walt;
        g_speed  = 14.0f;
        g_heading = fmodf(g_heading + 45.0f, 360.0f);
        printf(GREEN "  [✓] WAYPOINT LOCKED: %.4fN  %.4fW  %.0f m\n\n" RESET, wlat, fabsf(wlon), walt);
        fflush(stdout);
        live_telem(5);
        return 0;
    }

    /* CAMERA ON | OFF */
    if (strcmp(tok[0], "CAMERA") == 0 && ntok >= 2) {
        for (char *c = tok[1]; *c; c++) *c = (char)toupper((unsigned char)*c);
        c2_packet_t pkt; memset(&pkt, 0, sizeof(pkt));
        if (strcmp(tok[1], "ON") == 0) {
            pkt.opcode = CMD_CAMERA_ON;
            dispatch_drone_command(&pkt);
            slow_line(GREEN "  [✓] PAYLOAD CAMERA ACTIVE\n\n" RESET, 300);
        } else {
            pkt.opcode = CMD_CAMERA_OFF;
            dispatch_drone_command(&pkt);
            slow_line(YELLOW "  [✓] PAYLOAD CAMERA DEACTIVATED\n\n" RESET, 300);
        }
        return 0;
    }

    /* PAYLOAD DROP */
    if (strcmp(tok[0], "PAYLOAD") == 0 && ntok >= 2) {
        for (char *c = tok[1]; *c; c++) *c = (char)toupper((unsigned char)*c);
        if (strcmp(tok[1], "DROP") == 0) {
            if (g_state != STATE_AIRBORNE) {
                slow_line(RED "  [!!] NOT AIRBORNE\n\n" RESET, 0);
                return 0;
            }
            c2_packet_t pkt; memset(&pkt, 0, sizeof(pkt));
            pkt.opcode = CMD_PAYLOAD_DROP;
            pkt.flags  = 0x01;
            dispatch_drone_command(&pkt);
            slow_line(GREEN "  [✓] PAYLOAD RELEASED\n\n" RESET, 400);
            return 0;
        }
    }

    /* EMERGENCY */
    if (strcmp(tok[0], "EMERGENCY") == 0) {
        c2_packet_t pkt; memset(&pkt, 0, sizeof(pkt));
        pkt.opcode = CMD_EMERGENCY_STOP;
        dispatch_drone_command(&pkt);
        g_state = STATE_EMERGENCY;
        g_speed = 0.0f;
        slow_line(RED BOLD "\n  [!!] EMERGENCY STOP — ALL MOTORS CUT\n\n" RESET, 500);
        return 0;
    }

    /* Unknown */
    printf(DIM "  Unknown command: %s  (type HELP for reference)\n\n" RESET, tok[0]);
    fflush(stdout);
    return 0;
}

static void run_command_shell(const char *pass) {
    reveal_mission(pass);
    shell_help();

    char line[256];
    while (1) {
        printf(CYAN "  RAPTOR-7" RESET " [" BOLD "%s" RESET "]> ", g_state_label[g_state]);
        fflush(stdout);
        if (!fgets(line, (int)sizeof(line), stdin)) break;
        line[strcspn(line, "\n")] = '\0';
        if (shell_exec(line, pass) < 0) break;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ── BANNER / UI (original raptor7 presentation — unchanged) ─────────────
 * ═══════════════════════════════════════════════════════════════════════════ */
static void print_header(void) {
    slow_line("\n", 0);
    slow_line(CYAN "╔══════════════════════════════════════════════╗\n", 80);
    slow_line(     "║         RAPTOR-7 UNMANNED SYSTEM             ║\n", 80);
    slow_line(     "║         TACTICAL CONTROL INTERFACE           ║\n", 80);
    slow_line(     "║         FIRMWARE v2.3.1 // CLASSIFIED        ║\n", 80);
    slow_line(     "╚══════════════════════════════════════════════╝\n" RESET "\n", 400);
}

static void print_status(void) {
    slow_line(BOLD "  SYSTEM STATUS  : " RESET "STANDBY\n",           750);
    slow_line(BOLD "  UPLINK         : " RESET DIM "OFFLINE\n" RESET, 750);
    slow_line(BOLD "  GPS LOCK       : " RESET GREEN "ACQUIRED\n" RESET, 750);
    slow_line(BOLD "  BATTERY        : " RESET "94%\n\n",              750);
}

static void print_auth_header(void) {
    slow_line(BOLD "  AUTHENTICATION REQUIRED\n", 0);
    slow_line(     "  " CYAN "──────────────────────────────" RESET "\n", 200);
}

static void print_success(void) {
    slow_line(GREEN "  [✓] IDENTITY CONFIRMED — WELCOME, OPERATOR\n", 600);
    slow_line(      "  [✓] LOADING MISSION PROFILE...\n\n" RESET,     1800);
    slow_line(BOLD  "  > RAPTOR-7 ONLINE\n"       RESET, 900);
    slow_line(BOLD  "  > UPLINK ESTABLISHED\n"    RESET, 900);
    slow_line(BOLD  "  > PAYLOAD: READY\n"        RESET, 900);
    slow_line(BOLD  "  > AWAITING COMMAND INPUT\n" RESET "\n", 0);
}

static void print_denied(int remaining) {
    slow_line(RED "  [!!] ACCESS DENIED — INCIDENT LOGGED\n", 400);
    if (remaining > 0) {
        char buf[64];
        snprintf(buf, sizeof(buf),
                 RED "  [!!] %d ATTEMPT%s REMAINING\n" RESET "\n",
                 remaining, remaining == 1 ? "" : "S");
        slow_line(buf, 400);
    } else {
        slow_line(RESET, 0);
    }
}

static void print_locked(void) {
    slow_line(RED BOLD "\n  [!!] TERMINAL LOCKED\n\n" RESET, 0);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * main — crackme entry point + subsystem exercise
 * ═══════════════════════════════════════════════════════════════════════════ */
int main(int argc, char *argv[])
{
    int  remaining = MAX_ATTEMPTS;
    char input[256];

    print_header();
    print_status();
    print_auth_header();

    /* ── Argument mode ── */
    if (argc > 1) {
        strncpy(input, argv[1], 255);
        input[255] = '\0';

        printf("  OPERATOR ID : %s\n\n", input);
        fflush(stdout);
        msleep(900);

        if (process_auth(input)) {
            print_success();

            /* subsystem self-test (keeps AIRE test functions exercised) */
            log_info("main: subsystem self-test starting");
            drone_heartbeat_alive();
            c2_packet_t pkt;
            memset(&pkt, 0, sizeof(pkt));
            pkt.opcode = CMD_HOVER;
            dispatch_drone_command(&pkt);
            uint8_t telem_buf[16] = { 0,0,0,1, 1, 0,0, 2,
                                      0x05, 0,4, 0,0,0,0, 0 };
            telemetry_record_t rec;
            parse_telemetry_packet(telem_buf, sizeof(telem_buf), &rec);
            log_info("main: subsystem self-test complete");

            run_command_shell(input);
            return 0;
        }

        remaining--;
        print_denied(remaining);
        msleep(600);
        print_locked();
        return 1;
    }

    /* ── Interactive mode ── */
    while (remaining > 0) {
        printf("  OPERATOR ID : ");
        fflush(stdout);

        if (!fgets(input, (int)sizeof(input), stdin)) break;
        input[strcspn(input, "\n")] = '\0';

        printf("\n");
        fflush(stdout);
        msleep(900);

        if (process_auth(input)) {
            print_success();
            run_command_shell(input);
            return 0;
        }

        remaining--;
        print_denied(remaining);
        msleep(600);

        if (remaining > 0)
            print_auth_header();
    }

    print_locked();
    return 1;
}
