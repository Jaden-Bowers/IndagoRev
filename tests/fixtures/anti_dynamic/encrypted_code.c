#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* Linux x86-64 SysV: ENDBR64; mov eax,edi; imul eax,eax,7; add eax,3; ret. */
static const unsigned char encrypted_code[] = {
    0x54, 0xb7, 0xd7, 0x20, 0x62, 0x04, 0x66, 0xde, 0x28, 0xc3, 0x91, 0x61, 0xb0
};

static void usage(const char *name)
{
    printf("usage: %s [--observe|--help]\n", name);
    puts("Decode a small arithmetic function, execute it, re-encode and erase.");
    puts("--observe prints the decoded code checksum before execution.");
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

#if defined(__x86_64__)
static void crypt_code(unsigned char *memory)
{
    unsigned char key = 0xa7;
    size_t index;

    for (index = 0; index < sizeof(encrypted_code); ++index) {
        memory[index] ^= key;
        key = (unsigned char)(key + 17);
    }
}

static uint32_t checksum(const unsigned char *memory)
{
    uint32_t hash = UINT32_C(2166136261);
    size_t index;

    for (index = 0; index < sizeof(encrypted_code); ++index) {
        hash ^= memory[index];
        hash *= UINT32_C(16777619);
    }
    return hash;
}

static int protection_error(const char *operation)
{
    int saved = errno;

    perror(operation);
    if (saved == EPERM || saved == EACCES || saved == ENOSYS) {
        return 77;
    }
    return 1;
}

static int wipe_and_release(unsigned char *memory, size_t length)
{
    volatile unsigned char *cursor;
    size_t index;
    int result = 0;

    /* Remove execute permission before writing, even on the cleanup path. */
    if (mprotect(memory, length, PROT_READ | PROT_WRITE) != 0) {
        perror("mprotect cleanup");
        result = 1;
    } else {
        cursor = memory;
        for (index = 0; index < length; ++index) {
            cursor[index] = 0;
        }
    }
    if (munmap(memory, length) != 0) {
        perror("munmap");
        result = 1;
    }
    return result;
}

static int execute_code(unsigned char *memory)
{
    typedef int (*arithmetic_function)(int);
    arithmetic_function function;
    void *address = memory;
    static const int inputs[] = {0, 1, 7, 42};
    size_t index;

    /* Linux x86-64 uses equally sized code and data pointers. */
    _Static_assert(sizeof(function) == sizeof(address), "pointer size");
    memcpy(&function, &address, sizeof(function));
    for (index = 0; index < sizeof(inputs) / sizeof(inputs[0]); ++index) {
        int actual = function(inputs[index]);
        int expected = inputs[index] * 7 + 3;
        printf("probe=decoded-code input=%d result=%d expected=%d\n",
               inputs[index], actual, expected);
        if (actual != expected) {
            fputs("decoded function failed arithmetic check\n", stderr);
            return 1;
        }
    }
    return 0;
}

static int run_code(int observe)
{
    long page_size = sysconf(_SC_PAGESIZE);
    unsigned char *memory;
    int result;

    if (page_size <= 0 || (size_t)page_size < sizeof(encrypted_code)) {
        fputs("invalid page size\n", stderr);
        return 1;
    }
    memory = mmap(NULL, (size_t)page_size, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) {
        return protection_error("mmap");
    }
    memcpy(memory, encrypted_code, sizeof(encrypted_code));
    crypt_code(memory);
    if (checksum(memory) != UINT32_C(0x64761977)) {
        fputs("decoded code failed integrity check\n", stderr);
        result = 1;
        goto cleanup;
    }
    if (observe) {
        printf("decoded-checksum=%08lx\n", (unsigned long)checksum(memory));
    }
    __builtin___clear_cache((char *)memory, (char *)memory + sizeof(encrypted_code));
    if (mprotect(memory, (size_t)page_size, PROT_READ | PROT_EXEC) != 0) {
        result = protection_error("mprotect executable");
        goto cleanup;
    }
    result = execute_code(memory);
    if (mprotect(memory, (size_t)page_size, PROT_READ | PROT_WRITE) != 0) {
        result = protection_error("mprotect writable");
        goto cleanup;
    }
    crypt_code(memory);
    if (memcmp(memory, encrypted_code, sizeof(encrypted_code)) != 0) {
        fputs("code re-encryption failed\n", stderr);
        result = 1;
    }

cleanup:
    if (wipe_and_release(memory, (size_t)page_size) != 0) {
        result = 1;
    }
    if (result == 0) {
        puts("payload=encrypted-code checks=4 erased=1");
    }
    return result;
}
#endif

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
#if defined(__x86_64__)
    return run_code(observe);
#else
    (void)encrypted_code;
    puts("reason=requires-linux-x86-64-sysv");
    return 77;
#endif
}
