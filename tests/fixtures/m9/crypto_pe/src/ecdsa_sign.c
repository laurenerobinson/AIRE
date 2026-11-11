/* A.I.R.E. M9 security fixture: ECDSA P-256 sign/verify via Windows CNG.
 * Static-analysis fixture only. Signing, verification and key handling are
 * separate functions; all cryptography is performed by bcrypt.dll. */
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>

#define NOINLINE __attribute__((noinline))
#define DIGEST_LEN 32
#define SIGNATURE_LEN 64
#define PUBLIC_BLOB_LEN (sizeof(BCRYPT_ECCKEY_BLOB) + 64)

static const char MESSAGE[] = "A.I.R.E. M9 message to be signed with ECDSA P-256";

/* Key handling: generate and finalize an ephemeral P-256 key pair. */
NOINLINE NTSTATUS generate_signing_key(BCRYPT_ALG_HANDLE *algorithm, BCRYPT_KEY_HANDLE *key) {
    NTSTATUS status = BCryptOpenAlgorithmProvider(algorithm, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return status;
    status = BCryptGenerateKeyPair(*algorithm, key, 256, 0);
    if (!BCRYPT_SUCCESS(status)) return status;
    return BCryptFinalizeKeyPair(*key, 0);
}

/* Key handling: export only the public half, as a verifier would receive it. */
NOINLINE NTSTATUS export_public_key(BCRYPT_KEY_HANDLE key, UCHAR *blob, ULONG capacity, ULONG *length) {
    return BCryptExportKey(key, NULL, BCRYPT_ECCPUBLIC_BLOB, blob, capacity, length, 0);
}

/* Key handling: import the public key for verification. */
NOINLINE NTSTATUS import_verification_key(BCRYPT_ALG_HANDLE algorithm, const UCHAR *blob, ULONG length,
                                                 BCRYPT_KEY_HANDLE *key) {
    return BCryptImportKeyPair(algorithm, NULL, BCRYPT_ECCPUBLIC_BLOB, key, (PUCHAR)blob, length, 0);
}

/* Message digest (SHA-256) that ECDSA signs. Uses the classic CNG hash
 * sequence (the one-shot BCryptHash API is absent from MinGW headers). */
NOINLINE NTSTATUS hash_message(const char *message, UCHAR digest[DIGEST_LEN]) {
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return status;
    status = BCryptCreateHash(algorithm, &hash, NULL, 0, NULL, 0, 0);
    if (BCRYPT_SUCCESS(status)) status = BCryptHashData(hash, (PUCHAR)message, (ULONG)strlen(message), 0);
    if (BCRYPT_SUCCESS(status)) status = BCryptFinishHash(hash, digest, DIGEST_LEN, 0);
    if (hash) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return status;
}

/* Signing: requires the private key. */
NOINLINE NTSTATUS sign_digest(BCRYPT_KEY_HANDLE key, UCHAR digest[DIGEST_LEN],
                                     UCHAR signature[SIGNATURE_LEN], ULONG *length) {
    return BCryptSignHash(key, NULL, digest, DIGEST_LEN, signature, SIGNATURE_LEN, length, 0);
}

/* Verification: uses only the imported public key. */
NOINLINE BOOL verify_signature(BCRYPT_KEY_HANDLE public_key, UCHAR digest[DIGEST_LEN],
                                      UCHAR *signature, ULONG length) {
    return BCRYPT_SUCCESS(BCryptVerifySignature(public_key, NULL, digest, DIGEST_LEN, signature, length, 0));
}

int main(void) {
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE private_key = NULL, public_key = NULL;
    UCHAR digest[DIGEST_LEN], signature[SIGNATURE_LEN], blob[PUBLIC_BLOB_LEN];
    ULONG signature_len = 0, blob_len = 0;
    int result = 1;
    if (!BCRYPT_SUCCESS(generate_signing_key(&algorithm, &private_key)) ||
        !BCRYPT_SUCCESS(export_public_key(private_key, blob, sizeof(blob), &blob_len)) ||
        !BCRYPT_SUCCESS(import_verification_key(algorithm, blob, blob_len, &public_key))) {
        printf("ECDSA key handling failed\n");
        goto done;
    }
    if (!BCRYPT_SUCCESS(hash_message(MESSAGE, digest)) ||
        !BCRYPT_SUCCESS(sign_digest(private_key, digest, signature, &signature_len))) {
        printf("ECDSA signing failed\n");
        goto done;
    }
    printf("signature valid: %s\n", verify_signature(public_key, digest, signature, signature_len) ? "yes" : "no");
    signature[0] ^= 0x01; /* tamper: verification must now fail */
    printf("tampered signature valid: %s\n",
           verify_signature(public_key, digest, signature, signature_len) ? "yes" : "no");
    result = 0;
done:
    if (public_key) BCryptDestroyKey(public_key);
    if (private_key) BCryptDestroyKey(private_key);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    return result;
}
