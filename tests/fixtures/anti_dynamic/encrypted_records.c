#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Reversible XOR stream obfuscation, deliberately not secure cryptography. */
static const unsigned char ciphertext_0[] = {
    0xf5, 0xaf, 0x49, 0x0a, 0x2a, 0xb5, 0x59, 0x14, 0x60, 0xdf, 0xbd, 0x0a,
    0x06, 0x6e, 0x50, 0xd9, 0x33, 0x80, 0xf9, 0x62, 0x3b, 0x08
};

static const unsigned char ciphertext_1[] = {
    0x9f, 0xb5, 0x13, 0x45, 0xf5, 0x40, 0x16, 0x42, 0x73, 0xd8, 0xbe, 0x1b,
    0x8f, 0xe8, 0x92, 0x96, 0x94, 0x7a, 0x5b, 0xf1, 0x8e, 0x5e, 0x56, 0x6a
};

static const unsigned char ciphertext_2[] = {
    0xa3, 0xa1, 0xc0, 0x0d, 0x29, 0x90, 0x58, 0xf6, 0x56, 0xe2, 0x69, 0x26,
    0x05, 0x53, 0x62, 0x65, 0x91, 0x37, 0xcc, 0xe4, 0xbb, 0xe4, 0xa4, 0x2d, 0xb2, 0xb6
};

struct encrypted_record {
    const unsigned char *bytes;
    size_t length;
    uint32_t key;
};

static const struct encrypted_record records[] = {
    {ciphertext_0, sizeof(ciphertext_0), UINT32_C(0x7139a42d)},
    {ciphertext_1, sizeof(ciphertext_1), UINT32_C(0x7139a42e)},
    {ciphertext_2, sizeof(ciphertext_2), UINT32_C(0x7139a42f)}
};

static void usage(const char *name)
{
    printf("usage: %s [--observe|--help]\n", name);
    puts("Decrypt records briefly, compute a digest, then re-encrypt and wipe.");
    puts("--observe prints the plaintext during its live interval.");
}

static int parse_options(int argc, char **argv, int *observe)
{
    *observe = 0;
    if (argc == 1) {
        return 0;
    }
    if (argc != 2) {
        return -1;
    }
    if (strcmp(argv[1], "--help") == 0) {
        usage(argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "--observe") == 0) {
        *observe = 1;
        return 0;
    }
    return -1;
}

static uint32_t next_key(uint32_t state)
{
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
}

static void crypt_record(unsigned char *bytes, size_t length, uint32_t key)
{
    size_t index;

    for (index = 0; index < length; ++index) {
        key = next_key(key);
        bytes[index] ^= (unsigned char)key;
    }
}

static void wipe_record(void *memory, size_t length)
{
    volatile unsigned char *cursor = memory;

    while (length != 0) {
        *cursor++ = 0;
        --length;
    }
}

static uint32_t checksum(const unsigned char *bytes, size_t length)
{
    uint32_t result = UINT32_C(2166136261);
    size_t index;

    for (index = 0; index < length; ++index) {
        result ^= bytes[index];
        result *= UINT32_C(16777619);
    }
    return result;
}

static int printable_record(const unsigned char *bytes, size_t length)
{
    size_t index;
    int has_separator = 0;

    for (index = 0; index < length; ++index) {
        if (bytes[index] < 32 || bytes[index] > 126) {
            return 0;
        }
        if (bytes[index] == '=') {
            has_separator = 1;
        }
    }
    return has_separator;
}

static int process_record(size_t index, int observe, uint32_t *digest)
{
    const struct encrypted_record *record = &records[index];
    unsigned char *scratch = malloc(record->length + 1);
    int result = 0;

    if (scratch == NULL) {
        perror("malloc");
        return 1;
    }
    memcpy(scratch, record->bytes, record->length);
    scratch[record->length] = '\0';
    crypt_record(scratch, record->length, record->key);
    if (!printable_record(scratch, record->length)) {
        fputs("decrypted record failed validation\n", stderr);
        result = 1;
        goto cleanup;
    }
    *digest ^= checksum(scratch, record->length);
    printf("probe=encrypted-record index=%zu length=%zu\n",
           index, record->length);
    if (observe) {
        printf("plaintext=%s\n", (char *)scratch);
    }

    /* Break here to inspect the plaintext before its lifetime ends. */
    crypt_record(scratch, record->length, record->key);
    if (memcmp(scratch, record->bytes, record->length) != 0) {
        fputs("re-encryption failed\n", stderr);
        result = 1;
    }

cleanup:
    wipe_record(scratch, record->length + 1);
    free(scratch);
    return result;
}

static int run_records(int observe)
{
    uint32_t digest = 0;
    size_t index;
    size_t count = sizeof(records) / sizeof(records[0]);

    for (index = 0; index < count; ++index) {
        if (process_record(index, observe, &digest) != 0) {
            return 1;
        }
    }
    printf("payload=encrypted-records digest=%08lx records=%zu\n",
           (unsigned long)digest, count);
    return 0;
}

int main(int argc, char **argv)
{
    int observe;
    int parsed = parse_options(argc, argv, &observe);

    if (parsed > 0) {
        return 0;
    }
    if (parsed < 0) {
        usage(argv[0]);
        return 2;
    }
    return run_records(observe);
}
