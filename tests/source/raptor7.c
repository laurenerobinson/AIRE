/*
 * raptor7.c — RAPTOR-7 Tactical Control Interface
 *
 * CTF-style crackme for university reverse engineering demo.
 * Password is XOR-encoded (key 0x4F); no plaintext stored.
 * Strip binary before distributing: strip raptor7
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── ANSI color helpers ─────────────────────────────────────── */
#define RESET    "\033[0m"
#define RED      "\033[1;31m"
#define GREEN    "\033[1;32m"
#define YELLOW   "\033[1;33m"
#define CYAN     "\033[1;36m"
#define BOLD     "\033[1m"
#define DIM      "\033[2m"

/* ── Auth constants ─────────────────────────────────────────── */
#define PASS_LEN     15
#define XOR_KEY      0x4F
#define MAX_ATTEMPTS 3

/*
 * XOR-encoded "RAPTOR_7_ONLINE" ^ 0x4F.
 * Positions 4 and 9 decode to 0x00 ('O' ^ 0x4F), so this array
 * cannot be recovered by `strings` — it contains embedded nulls.
 */
static const unsigned char encoded_pass[PASS_LEN] = {
    0x1D, 0x0E, 0x1F, 0x1B, 0x00,   /* R  A  P  T  O  */
    0x1D, 0x10, 0x78, 0x10, 0x00,   /* R  _  7  _  O  */
    0x01, 0x03, 0x06, 0x01, 0x0A    /* N  L  I  N  E  */
};

/*
 * Decoy credential tables — kept in .rodata so `strings` picks them up.
 * A reverser will find these first and chase the wrong trail.
 */
__attribute__((used)) static const char cred_table_a[] = "operator_admin";
__attribute__((used)) static const char cred_table_b[] = "R4PT0R_access";

/* ── Decoy A — "operator_admin" — always fails ──────────────── */
__attribute__((noinline))
static int check_operator_level(const char *buf)
{
    return (strcmp(buf, cred_table_a) == 0) ? 1 : 0;
}

/* ── Decoy B — "R4PT0R_access" — always fails ──────────────── */
__attribute__((noinline))
static int validate_legacy_token(const char *buf)
{
    return (strcmp(buf, cred_table_b) == 0) ? 1 : 0;
}

/*
 * process_auth() — real credential validation.
 *
 * Decodes the stored bytes with XOR at runtime, then compares
 * via memcmp (not strcmp) to handle the embedded null bytes at
 * positions 4 and 9 of the decoded password.
 *
 * The decoy checks run first and their scores feed into a fake
 * combined result to bury the real comparison in noise for the
 * static analyst.
 */
static int process_auth(const char *input)
{
    unsigned char decoded[PASS_LEN];
    size_t i;
    int score;

    if (strlen(input) != PASS_LEN)
        return 0;

    for (i = 0; i < PASS_LEN; i++)
        decoded[i] = (unsigned char)(encoded_pass[i] ^ XOR_KEY);

    /* Decoy pre-checks — both fail for the real password */
    score  = check_operator_level(input) << 1;
    score |= validate_legacy_token(input);

    /* Real comparison — memcmp handles the embedded null bytes */
    return ((memcmp(input, decoded, PASS_LEN) == 0) && (score == 0)) ? 1 : 0;
}

/* ── UI helpers ─────────────────────────────────────────────── */
static void msleep(unsigned int ms)
{
    usleep(ms * 1000u);
}

static void slow_line(const char *text, unsigned int delay_ms)
{
    fputs(text, stdout);
    fflush(stdout);
    if (delay_ms)
        msleep(delay_ms);
}

static void print_header(void)
{
    slow_line("\n", 0);
    slow_line(CYAN "╔══════════════════════════════════════════════╗\n", 80);
    slow_line(     "║         RAPTOR-7 UNMANNED SYSTEM             ║\n", 80);
    slow_line(     "║         TACTICAL CONTROL INTERFACE           ║\n", 80);
    slow_line(     "║         FIRMWARE v2.3.1 // CLASSIFIED        ║\n", 80);
    slow_line(     "╚══════════════════════════════════════════════╝\n"
              RESET "\n", 400);
}

static void print_status(void)
{
    slow_line(BOLD "  SYSTEM STATUS  : " RESET "STANDBY\n",          750);
    slow_line(BOLD "  UPLINK         : " RESET DIM "OFFLINE\n" RESET, 750);
    slow_line(BOLD "  GPS LOCK       : " RESET GREEN "ACQUIRED\n"
              RESET,                                                    750);
    slow_line(BOLD "  BATTERY        : " RESET "94%\n\n",             750);
}

static void print_auth_header(void)
{
    slow_line(BOLD "  AUTHENTICATION REQUIRED\n", 0);
    slow_line(     "  " CYAN "──────────────────────────────" RESET "\n", 200);
}

static void print_success(void)
{
    slow_line(GREEN "  [✓] IDENTITY CONFIRMED — WELCOME, OPERATOR\n", 600);
    slow_line(      "  [✓] LOADING MISSION PROFILE...\n\n" RESET,     1800);
    slow_line(BOLD  "  > RAPTOR-7 ONLINE\n"      RESET, 900);
    slow_line(BOLD  "  > UPLINK ESTABLISHED\n"   RESET, 900);
    slow_line(BOLD  "  > PAYLOAD: READY\n"       RESET, 900);
    slow_line(BOLD  "  > AWAITING COMMAND INPUT\n" RESET "\n", 0);
}

static void print_denied(int remaining)
{
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

static void print_locked(void)
{
    slow_line(RED BOLD "\n  [!!] TERMINAL LOCKED\n\n" RESET, 0);
}

/* ── Entry point ────────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    int  remaining = MAX_ATTEMPTS;
    char input[256];

    print_header();
    print_status();
    print_auth_header();

    /* ── Argument mode: treat argv[1] as the first attempt ── */
    if (argc > 1) {
        strncpy(input, argv[1], 255);
        input[255] = '\0';

        printf("  OPERATOR ID : %s\n\n", input);
        fflush(stdout);
        msleep(900);

        if (process_auth(input)) {
            print_success();
            return 0;
        }

        remaining--;
        print_denied(remaining);
        msleep(600);
        print_locked();
        return 1;
    }

    /* ── Interactive mode: up to MAX_ATTEMPTS tries ─────────── */
    while (remaining > 0) {
        printf("  OPERATOR ID : ");
        fflush(stdout);

        if (!fgets(input, (int)sizeof(input), stdin))
            break;
        input[strcspn(input, "\n")] = '\0';

        printf("\n");
        fflush(stdout);
        msleep(900);

        if (process_auth(input)) {
            print_success();
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
