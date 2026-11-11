/* A.I.R.E. M9 security fixture: SHA-256 of predefined sample data via Windows
 * CNG. Static-analysis fixture only; hashing is performed by bcrypt.dll. */
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>

#define NOINLINE __attribute__((noinline))
#define DIGEST_LEN 32

static const char *SAMPLE_RECORDS[] = {
    "record-1: alpha", "record-2: bravo", "record-3: charlie", "record-4: delta",
};

/* Input processing: join the predefined records with '\n' separators. */
NOINLINE ULONG prepare_sample_input(UCHAR *buffer, ULONG capacity) {
    ULONG used = 0;
    for (size_t i = 0; i < sizeof(SAMPLE_RECORDS) / sizeof(SAMPLE_RECORDS[0]); i++) {
        size_t length = strlen(SAMPLE_RECORDS[i]);
        if (used + length + 1 > capacity) break;
        memcpy(buffer + used, SAMPLE_RECORDS[i], length);
        used += (ULONG)length;
        buffer[used++] = '\n';
    }
    return used;
}

/* Digest: BCryptCreateHash -> BCryptHashData (chunked) -> BCryptFinishHash. */
NOINLINE NTSTATUS sha256_digest(const UCHAR *data, ULONG length, UCHAR digest[DIGEST_LEN]) {
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return status;
    status = BCryptCreateHash(algorithm, &hash, NULL, 0, NULL, 0, 0);
    for (ULONG offset = 0; BCRYPT_SUCCESS(status) && offset < length; offset += 16) {
        ULONG chunk = length - offset < 16 ? length - offset : 16;
        status = BCryptHashData(hash, (PUCHAR)data + offset, chunk, 0);
    }
    if (BCRYPT_SUCCESS(status)) status = BCryptFinishHash(hash, digest, DIGEST_LEN, 0);
    if (hash) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return status;
}

NOINLINE void print_digest(const UCHAR digest[DIGEST_LEN]) {
    printf("SHA-256: ");
    for (int i = 0; i < DIGEST_LEN; i++) printf("%02x", digest[i]);
    printf("\n");
}

int main(void) {
    UCHAR input[256], digest[DIGEST_LEN];
    ULONG length = prepare_sample_input(input, sizeof(input));
    if (!BCRYPT_SUCCESS(sha256_digest(input, length, digest))) {
        printf("SHA-256 failed\n");
        return 1;
    }
    print_digest(digest);
    return 0;
}
