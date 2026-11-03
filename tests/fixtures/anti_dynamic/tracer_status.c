#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Linux exposes the current tracer in each task's status record. */
struct status_record {
    long tracer;
    long process;
    unsigned fields;
};

static void usage(const char *name)
{
    printf("usage: %s [--observe|--help]\n", name);
    puts("Read TracerPid before and after a small record transformation.");
    puts("--observe continues when either snapshot contains a tracer.");
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

static int parse_number(const char *text, long *value)
{
    char *end;
    long parsed;

    errno = 0;
    parsed = strtol(text, &end, 10);
    if (errno != 0 || end == text || parsed < 0 || parsed > INT_MAX) {
        return -1;
    }
    while (*end != '\0' && isspace((unsigned char)*end)) {
        ++end;
    }
    if (*end != '\0') {
        return -1;
    }
    *value = parsed;
    return 0;
}

static int consume_line(const char *line, struct status_record *record)
{
    if (strncmp(line, "TracerPid:", 10) == 0) {
        if ((record->fields & 1u) != 0 ||
            parse_number(line + 10, &record->tracer) != 0) {
            return -1;
        }
        record->fields |= 1u;
    } else if (strncmp(line, "Pid:", 4) == 0) {
        if ((record->fields & 2u) != 0 ||
            parse_number(line + 4, &record->process) != 0) {
            return -1;
        }
        record->fields |= 2u;
    }
    return 0;
}

static int read_status(struct status_record *record)
{
    FILE *stream;
    char *line = NULL;
    size_t capacity = 0;
    int result = 0;

    memset(record, 0, sizeof(*record));
    stream = fopen("/proc/self/status", "r");
    if (stream == NULL) {
        perror("/proc/self/status");
        return 77;
    }
    while (getline(&line, &capacity, stream) >= 0) {
        if (consume_line(line, record) != 0) {
            result = 1;
            break;
        }
    }
    if (ferror(stream)) {
        result = 1;
    }
    free(line);
    if (fclose(stream) != 0) {
        result = 1;
    }
    if (record->fields != 3u || record->process != (long)getpid()) {
        result = 1;
    }
    if (result != 0) {
        fputs("malformed or incomplete process status\n", stderr);
    }
    return result;
}

static uint32_t rotate_left(uint32_t value)
{
    return (value << 5) | (value >> 27);
}

static uint32_t transform_records(void)
{
    static const uint32_t records[] = {
        17, 31, 43, 59, 71, 89, 101, 127
    };
    uint32_t state = UINT32_C(0x12345678);
    size_t index;

    for (index = 0; index < sizeof(records) / sizeof(records[0]); ++index) {
        state = rotate_left(state ^ records[index]);
        state += (uint32_t)index * UINT32_C(0x9e3779b9);
    }
    return state;
}

static int report_snapshot(const char *label, struct status_record *record)
{
    int result = read_status(record);

    if (result != 0) {
        return result;
    }
    printf("probe=tracer-status phase=%s pid=%ld tracer=%ld\n",
           label, record->process, record->tracer);
    return 0;
}

int main(int argc, char **argv)
{
    struct status_record before;
    struct status_record after;
    uint32_t digest;
    int observe;
    int result;
    int parsed = parse_options(argc, argv, &observe);

    if (parsed > 0) {
        return 0;
    }
    if (parsed < 0) {
        usage(argv[0]);
        return 2;
    }
    result = report_snapshot("before", &before);
    if (result != 0) {
        return result;
    }
    if (before.tracer != 0 && !observe) {
        puts("reason=tracer-present-before-payload");
        return 10;
    }

    digest = transform_records();
    result = report_snapshot("after", &after);
    if (result != 0) {
        return result;
    }
    if (after.tracer != 0 && !observe) {
        puts("reason=tracer-present-after-payload");
        return 10;
    }
    printf("payload=tracer-status digest=%08lx\n", (unsigned long)digest);
    return 0;
}
