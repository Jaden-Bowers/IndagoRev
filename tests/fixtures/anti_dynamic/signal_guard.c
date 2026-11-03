#define _POSIX_C_SOURCE 200809L
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* A debugger may stop on, suppress, or forward these process-local signals. */
static volatile sig_atomic_t trap_count;
static volatile sig_atomic_t user_count;
static volatile sig_atomic_t delivery_order;

struct signal_scope {
    struct sigaction old_trap;
    struct sigaction old_user;
    sigset_t old_mask;
    int trap_installed;
    int user_installed;
    int mask_saved;
};

static void usage(const char *name)
{
    printf("usage: %s [--observe|--help]\n", name);
    puts("Check delivery of SIGUSR1, SIGTRAP, SIGUSR1, SIGTRAP.");
    puts("--observe continues if a debugger suppresses a signal.");
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

static void receive_signal(int number)
{
    /* Only sig_atomic_t accesses here: no stdio or allocation in the handler. */
    if (number == SIGTRAP) {
        if (trap_count < 9) {
            trap_count = trap_count + 1;
        }
        delivery_order = (delivery_order % 1000) * 10 + 2;
    } else if (number == SIGUSR1) {
        if (user_count < 9) {
            user_count = user_count + 1;
        }
        delivery_order = (delivery_order % 1000) * 10 + 1;
    }
}

static int restore_scope(struct signal_scope *scope)
{
    int result = 0;

    if (scope->mask_saved &&
        sigprocmask(SIG_SETMASK, &scope->old_mask, NULL) != 0) {
        perror("restore signal mask");
        result = -1;
    }
    if (scope->user_installed &&
        sigaction(SIGUSR1, &scope->old_user, NULL) != 0) {
        perror("restore SIGUSR1");
        result = -1;
    }
    if (scope->trap_installed &&
        sigaction(SIGTRAP, &scope->old_trap, NULL) != 0) {
        perror("restore SIGTRAP");
        result = -1;
    }
    return result;
}

static int install_scope(struct signal_scope *scope)
{
    struct sigaction action;
    sigset_t unblocked;

    memset(scope, 0, sizeof(*scope));
    memset(&action, 0, sizeof(action));
    action.sa_handler = receive_signal;
    if (sigemptyset(&action.sa_mask) != 0 ||
        sigaddset(&action.sa_mask, SIGTRAP) != 0 ||
        sigaddset(&action.sa_mask, SIGUSR1) != 0) {
        perror("handler mask");
        return -1;
    }
    if (sigaction(SIGTRAP, &action, &scope->old_trap) != 0) {
        perror("sigaction SIGTRAP");
        return -1;
    }
    scope->trap_installed = 1;
    if (sigaction(SIGUSR1, &action, &scope->old_user) != 0) {
        perror("sigaction SIGUSR1");
        return -1;
    }
    scope->user_installed = 1;
    if (sigemptyset(&unblocked) != 0 ||
        sigaddset(&unblocked, SIGTRAP) != 0 ||
        sigaddset(&unblocked, SIGUSR1) != 0) {
        perror("probe mask");
        return -1;
    }
    if (sigprocmask(SIG_UNBLOCK, &unblocked, &scope->old_mask) != 0) {
        perror("sigprocmask");
        return -1;
    }
    scope->mask_saved = 1;
    return 0;
}

static int deliver_sequence(void)
{
    static const int sequence[] = {SIGUSR1, SIGTRAP, SIGUSR1, SIGTRAP};
    size_t index;

    for (index = 0; index < sizeof(sequence) / sizeof(sequence[0]); ++index) {
        if (raise(sequence[index]) != 0) {
            fputs("raise failed\n", stderr);
            return -1;
        }
    }
    return 0;
}

static void run_payload(void)
{
    uint32_t state = UINT32_C(0x10203040);
    unsigned index;

    for (index = 0; index < 16; ++index) {
        state = (state ^ (index + 1)) * UINT32_C(33);
    }
    printf("payload=signal digest=%08lx\n", (unsigned long)state);
}

int main(int argc, char **argv)
{
    struct signal_scope scope;
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
    if (install_scope(&scope) != 0) {
        (void)restore_scope(&scope);
        return 1;
    }
    result = deliver_sequence();
    if (restore_scope(&scope) != 0 || result != 0) {
        return 1;
    }
    printf("probe=signals trap=%d user=%d order=%d\n",
           (int)trap_count, (int)user_count, (int)delivery_order);
    if (trap_count != 2 || user_count != 2 || delivery_order != 1212) {
        puts("reason=signal-delivery-changed");
        if (!observe) {
            return 10;
        }
    }
    run_payload();
    return 0;
}
