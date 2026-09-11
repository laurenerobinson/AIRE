#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/*
 * Encoded password: "R3v3rse_Me!" XOR 0x5A, byte by byte.
 * No plaintext password is stored in this binary.
 */
static const unsigned char enc_buf[] = {
    0x08, 0x69, 0x2C, 0x69, 0x28, 0x29, 0x3F, 0x05, 0x17, 0x3F, 0x7B
};
#define ENC_LEN  11
#define XOR_KEY  0x5A

/*
 * Decoy path A — legacy credential check.
 * Always fails against the real password; present to mislead analysis.
 */
static int check_legacy(const char *s)
{
    static const char legacy[] = "adm1n_legacy";
    return (strcmp(s, legacy) == 0);
}

/*
 * Decoy path B — backup credential check.
 * Same: always fails against the real password.
 */
static int check_backup(const char *s)
{
    static const char backup[] = "B4ckup_P4ss";
    return (strcmp(s, backup) == 0);
}

/*
 * process_input — decodes the XOR-obfuscated password at runtime
 * and compares it to the caller-supplied string.
 * Returns 1 on match, 0 otherwise.
 */
static int process_input(const char *input)
{
    char decoded[ENC_LEN + 1];
    int i;

    /* Decoy checks first — misleads a casual analyst into chasing these. */
    if (check_legacy(input))  return 1;
    if (check_backup(input))  return 1;

    /* Length gate: avoids the decode work for obviously wrong inputs
     * and prevents partial-match side-channel issues. */
    if (strlen(input) != ENC_LEN)
        return 0;

    /* Decode: each byte was XOR'd with XOR_KEY at "compile time". */
    for (i = 0; i < ENC_LEN; i++)
        decoded[i] = (char)(enc_buf[i] ^ XOR_KEY);
    decoded[ENC_LEN] = '\0';

    return (strcmp(input, decoded) == 0);
}

int main(int argc, char *argv[])
{
    char buf[256];
    const char *input;

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

    if (process_input(input)) {
        puts("Access granted!");
        return 0;
    }

    puts("Wrong password.");
    return 1;
}
