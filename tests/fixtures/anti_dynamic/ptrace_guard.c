#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* Keep tracing state out of the parent so the fixture is easy to rerun. */
enum child_result {
    CHILD_EXPECTED = 20,
    CHILD_DENIED = 21,
    CHILD_ALTERED = 22,
    CHILD_ERROR = 23
};

struct observation {
    int expected;
    int unavailable;
    int altered;
};

static void usage(const char *name)
{
    printf("usage: %s [--observe|--help]\n", name);
    puts("Probe PTRACE_TRACEME in a disposable child, then hash a record.");
    puts("--observe permits the payload after an altered ptrace result.");
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

static void child_probe(void)
{
    long first;
    long second;
    int first_error;
    int second_error;

    errno = 0;
    first = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    first_error = errno;
    if (first == -1) {
        if (first_error == EPERM || first_error == EACCES ||
            first_error == ENOSYS) {
            _exit(CHILD_DENIED);
        }
        _exit(CHILD_ERROR);
    }

    /* A blanket interceptor that returns zero twice changes this branch. */
    errno = 0;
    second = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    second_error = errno;
    if (second == -1 && second_error == EPERM) {
        _exit(CHILD_EXPECTED);
    }
    if (second == 0) {
        _exit(CHILD_ALTERED);
    }
    _exit(CHILD_ERROR);
}

static int collect_probe(struct observation *result)
{
    pid_t child;
    pid_t waited;
    int status;

    memset(result, 0, sizeof(*result));
    child = fork();
    if (child == -1) {
        perror("fork");
        return -1;
    }
    if (child == 0) {
        child_probe();
    }

    /* The child raises no signals and exits without a ptrace stop. */
    do {
        waited = waitpid(child, &status, 0);
    } while (waited == -1 && errno == EINTR);
    if (waited == -1) {
        perror("waitpid");
        return -1;
    }
    if (!WIFEXITED(status)) {
        fprintf(stderr, "probe did not exit normally: status=%d\n", status);
        return -1;
    }

    switch (WEXITSTATUS(status)) {
    case CHILD_EXPECTED:
        result->expected = 1;
        return 0;
    case CHILD_DENIED:
        result->unavailable = 1;
        return 0;
    case CHILD_ALTERED:
        result->altered = 1;
        return 0;
    default:
        fputs("unexpected ptrace probe failure\n", stderr);
        return -1;
    }
}

static uint32_t hash_record(const unsigned char *record, size_t length)
{
    uint32_t hash = UINT32_C(2166136261);
    size_t index;

    for (index = 0; index < length; ++index) {
        hash ^= record[index];
        hash *= UINT32_C(16777619);
    }
    return hash;
}

static void run_payload(void)
{
    static const unsigned char record[] = "indago:ptrace:fixture";
    uint32_t digest = hash_record(record, sizeof(record) - 1);

    printf("payload=ptrace digest=%08lx\n", (unsigned long)digest);
}

static void print_observation(const struct observation *result)
{
    printf("probe=ptrace expected=%d unavailable=%d altered=%d\n",
           result->expected, result->unavailable, result->altered);
    if (result->unavailable) {
        puts("reason=tracing-denied-or-unavailable");
    }
    if (result->altered) {
        puts("reason=second-traceme-unexpectedly-succeeded");
    }
}

int main(int argc, char **argv)
{
    struct observation result;
    int observe;
    int parsed = parse_options(argc, argv, &observe);

    if (parsed > 0) {
        return 0;
    }
    if (parsed < 0) {
        usage(argv[0]);
        return 2;
    }
    if (collect_probe(&result) != 0) {
        return 1;
    }
    print_observation(&result);
    if (result.unavailable) {
        return 77;
    }
    if (result.altered && !observe) {
        return 10;
    }
    run_payload();
    return 0;
}
