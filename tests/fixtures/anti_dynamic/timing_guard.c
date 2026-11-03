#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SAMPLE_COUNT 3
#define WORK_ROUNDS 200000u

struct options {
    int observe;
    uint64_t limit_ns;
};

struct measurement {
    uint64_t elapsed_ns;
    uint32_t digest;
};

static void usage(const char *name)
{
    printf("usage: %s [--observe] [--limit-ms N] [--help]\n", name);
    puts("Measure three bounded volatile loops using CLOCK_MONOTONIC.");
    puts("The default per-sample limit is 250 ms; N ranges from 0 to 60000.");
    puts("A zero limit provides a reproducible detection-path exercise.");
}

static int parse_limit(const char *text, uint64_t *nanoseconds)
{
    unsigned long value;
    char *end;
    const char *cursor;

    if (*text == '\0') {
        return -1;
    }
    for (cursor = text; *cursor != '\0'; ++cursor) {
        if (*cursor < '0' || *cursor > '9') {
            return -1;
        }
    }
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || *end != '\0' || value > 60000) {
        return -1;
    }
    *nanoseconds = (uint64_t)value * UINT64_C(1000000);
    return 0;
}

static int parse_options(int argc, char **argv, struct options *options)
{
    int index;
    int limit_seen = 0;

    options->observe = 0;
    options->limit_ns = UINT64_C(250000000);
    for (index = 1; index < argc; ++index) {
        if (strcmp(argv[index], "--help") == 0 && argc == 2) {
            usage(argv[0]);
            return 1;
        }
        if (strcmp(argv[index], "--observe") == 0 && !options->observe) {
            options->observe = 1;
        } else if (strcmp(argv[index], "--limit-ms") == 0 && !limit_seen) {
            if (++index == argc ||
                parse_limit(argv[index], &options->limit_ns) != 0) {
                return -1;
            }
            limit_seen = 1;
        } else {
            return -1;
        }
    }
    return 0;
}

static uint32_t bounded_work(uint32_t seed)
{
    volatile uint32_t state = seed;
    uint32_t index;

    /* Volatile stores preserve work even if built outside this CMake project. */
    for (index = 0; index < WORK_ROUNDS; ++index) {
        uint32_t value = state;
        value ^= value << 13;
        value ^= value >> 17;
        value ^= value << 5;
        state = value + index;
    }
    return state;
}

static int elapsed_time(const struct timespec *start,
                        const struct timespec *finish, uint64_t *elapsed)
{
    int64_t seconds = (int64_t)finish->tv_sec - (int64_t)start->tv_sec;
    int64_t nanos = (int64_t)finish->tv_nsec - (int64_t)start->tv_nsec;

    if (seconds < 0 || (seconds == 0 && nanos < 0)) {
        return -1;
    }
    if (nanos < 0) {
        --seconds;
        nanos += INT64_C(1000000000);
    }
    *elapsed = (uint64_t)seconds * UINT64_C(1000000000) + (uint64_t)nanos;
    return 0;
}

static int measure(unsigned sample, struct measurement *result)
{
    struct timespec start;
    struct timespec finish;

    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        perror("clock_gettime start");
        return -1;
    }
    result->digest = bounded_work(UINT32_C(0x7249ac13) + sample);
    if (clock_gettime(CLOCK_MONOTONIC, &finish) != 0) {
        perror("clock_gettime finish");
        return -1;
    }
    if (elapsed_time(&start, &finish, &result->elapsed_ns) != 0) {
        fputs("monotonic clock moved backwards\n", stderr);
        return -1;
    }
    return 0;
}

static int run_samples(const struct options *options)
{
    uint32_t combined = 0;
    uint64_t maximum = 0;
    unsigned slow = 0;
    unsigned sample;

    for (sample = 0; sample < SAMPLE_COUNT; ++sample) {
        struct measurement result;
        if (measure(sample, &result) != 0) {
            return 1;
        }
        printf("probe=timing sample=%u elapsed_ns=%" PRIu64 " limit_ns=%" PRIu64 "\n",
               sample, result.elapsed_ns, options->limit_ns);
        if (result.elapsed_ns > maximum) {
            maximum = result.elapsed_ns;
        }
        if (result.elapsed_ns > options->limit_ns) {
            ++slow;
        }
        combined ^= result.digest;
    }
    printf("timing-summary slow=%u max_ns=%" PRIu64 "\n", slow, maximum);
    if (slow != 0 && !options->observe) {
        puts("reason=timing-threshold-exceeded");
        return 10;
    }
    printf("payload=timing digest=%08" PRIx32 "\n", combined);
    return 0;
}

int main(int argc, char **argv)
{
    struct options options;
    int parsed = parse_options(argc, argv, &options);

    if (parsed > 0) {
        return 0;
    }
    if (parsed < 0) {
        usage(argv[0]);
        return 2;
    }
    return run_samples(&options);
}
