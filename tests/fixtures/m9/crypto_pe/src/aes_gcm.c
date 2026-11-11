/* A.I.R.E. M9 security fixture: AES-256-GCM encrypt/decrypt via Windows CNG.
 * Static-analysis fixture only. The key/nonce are fixed, PUBLIC test values:
 * never reuse this pattern for real secrets. No algorithm is implemented here;
 * all cryptography is performed by bcrypt.dll (BCryptEncrypt/BCryptDecrypt). */
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>

#define NOINLINE __attribute__((noinline))
#define TAG_LEN 16

static const UCHAR DEMO_KEY[32] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
static const UCHAR DEMO_NONCE[12] = {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};
static const char DEMO_AAD[] = "aire-m9-associated-data";
static const char PLAINTEXT[] = "A.I.R.E. M9 AES-256-GCM sample message";

NOINLINE void print_hex(const char *label, const UCHAR *data, ULONG length) {
    printf("%s: ", label);
    for (ULONG i = 0; i < length; i++) printf("%02x", data[i]);
    printf("\n");
}

/* Key handling: open the AES provider, select GCM chaining, import the key. */
NOINLINE NTSTATUS create_aes_gcm_key(BCRYPT_ALG_HANDLE *algorithm, BCRYPT_KEY_HANDLE *key) {
    NTSTATUS status = BCryptOpenAlgorithmProvider(algorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return status;
    status = BCryptSetProperty(*algorithm, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                               sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) return status;
    return BCryptGenerateSymmetricKey(*algorithm, key, NULL, 0, (PUCHAR)DEMO_KEY, sizeof(DEMO_KEY), 0);
}

NOINLINE void init_auth_info(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO *info, UCHAR *tag) {
    BCRYPT_INIT_AUTH_MODE_INFO(*info);
    info->pbNonce = (PUCHAR)DEMO_NONCE;
    info->cbNonce = sizeof(DEMO_NONCE);
    info->pbAuthData = (PUCHAR)DEMO_AAD;
    info->cbAuthData = (ULONG)strlen(DEMO_AAD);
    info->pbTag = tag;
    info->cbTag = TAG_LEN;
}

/* Encryption: AES-256-GCM, producing ciphertext and a 16-byte tag. */
NOINLINE NTSTATUS aes_gcm_encrypt(BCRYPT_KEY_HANDLE key, const UCHAR *plain, ULONG plain_len,
                                         UCHAR *cipher, UCHAR *tag, ULONG *written) {
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    init_auth_info(&info, tag);
    return BCryptEncrypt(key, (PUCHAR)plain, plain_len, &info, NULL, 0, cipher, plain_len, written, 0);
}

/* Decryption: verifies the tag; failure returns STATUS_AUTH_TAG_MISMATCH. */
NOINLINE NTSTATUS aes_gcm_decrypt(BCRYPT_KEY_HANDLE key, const UCHAR *cipher, ULONG cipher_len,
                                         UCHAR *tag, UCHAR *plain, ULONG *written) {
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    init_auth_info(&info, tag);
    return BCryptDecrypt(key, (PUCHAR)cipher, cipher_len, &info, NULL, 0, plain, cipher_len, written, 0);
}

NOINLINE void destroy_aes_key(BCRYPT_ALG_HANDLE algorithm, BCRYPT_KEY_HANDLE key) {
    if (key) BCryptDestroyKey(key);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
}

int main(void) {
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    UCHAR cipher[sizeof(PLAINTEXT)], recovered[sizeof(PLAINTEXT) + 1], tag[TAG_LEN];
    ULONG length = (ULONG)strlen(PLAINTEXT), written = 0;
    int result = 1;
    if (!BCRYPT_SUCCESS(create_aes_gcm_key(&algorithm, &key))) {
        printf("AES-GCM key setup failed\n");
        goto done;
    }
    if (!BCRYPT_SUCCESS(aes_gcm_encrypt(key, (const UCHAR *)PLAINTEXT, length, cipher, tag, &written))) {
        printf("AES-GCM encryption failed\n");
        goto done;
    }
    print_hex("ciphertext", cipher, written);
    print_hex("tag", tag, TAG_LEN);
    if (!BCRYPT_SUCCESS(aes_gcm_decrypt(key, cipher, written, tag, recovered, &written))) {
        printf("AES-GCM authentication failed\n");
        goto done;
    }
    recovered[written] = 0;
    printf("decrypted: %s\n", (char *)recovered);
    result = memcmp(recovered, PLAINTEXT, length) != 0;
done:
    destroy_aes_key(algorithm, key);
    return result;
}
