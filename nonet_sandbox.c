/*
 * nonet_sandbox.c — C sandbox helper for the `nonet` decorator.
 *
 * Exports:
 *   int install_sandbox_filter(const int *extra_blocked, int extra_count)
 *
 * The built-in blacklist blocks the most dangerous syscall families.
 * The caller (Python mitigations) can supply additional syscall numbers
 * in *extra_blocked* to extend the deny list without recompiling this file.
 *
 * Build:
 *   gcc -O2 -shared -fPIC -o nonet_sandbox.so nonet_sandbox.c -lseccomp
 */

#include <errno.h>
#include <seccomp.h>
#include <sys/prctl.h>
#include <stdio.h>
#include <string.h>

/* Built-in deny list — always blocked regardless of extra_blocked. */
static const int BUILTIN_BLOCKED[] = {
    /* ── networking ─────────────────────────────────────────────────── */
    SCMP_SYS(socket),
    SCMP_SYS(socketpair),
    SCMP_SYS(connect),
    SCMP_SYS(bind),
    SCMP_SYS(listen),
    SCMP_SYS(accept),
    SCMP_SYS(accept4),
    SCMP_SYS(sendto),
    SCMP_SYS(sendmsg),
    SCMP_SYS(sendmmsg),
    SCMP_SYS(recvfrom),
    SCMP_SYS(recvmsg),
    SCMP_SYS(recvmmsg),
    SCMP_SYS(setsockopt),
    SCMP_SYS(getsockopt),
    SCMP_SYS(getpeername),
    SCMP_SYS(getsockname),
    SCMP_SYS(shutdown),

    /* ── process creation & exec ─────────────────────────────────────── */
    SCMP_SYS(fork),
    SCMP_SYS(vfork),
    SCMP_SYS(execve),
    SCMP_SYS(execveat),

    /* ── privilege escalation ────────────────────────────────────────── */
    SCMP_SYS(ptrace),
    SCMP_SYS(bpf),
    SCMP_SYS(perf_event_open),
    SCMP_SYS(keyctl),
    SCMP_SYS(add_key),
    SCMP_SYS(request_key),
};

#define ARRAY_LEN(a) ((int)(sizeof(a) / sizeof((a)[0])))

static int block_one(scmp_filter_ctx ctx, int syscall_nr)
{
    int rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), syscall_nr, 0);
    if (rc < 0) {
        fprintf(stderr, "[nonet/C] seccomp_rule_add(%d) failed: %s\n",
                syscall_nr, strerror(-rc));
    }
    return rc;
}

/*
 * install_sandbox_filter
 *   extra_blocked : array of additional syscall numbers to deny
 *   extra_count   : length of extra_blocked (0 is fine)
 *
 * Returns 0 on success, -1 on failure.
 */
int install_sandbox_filter(const int *extra_blocked, int extra_count)
{
    /* Step 1: no-new-privs */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        fprintf(stderr, "[nonet/C] prctl(PR_SET_NO_NEW_PRIVS) failed: %s\n",
                strerror(errno));
        return -1;
    }

    /* Step 2: build filter — allow everything not in either deny list */
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) {
        fprintf(stderr, "[nonet/C] seccomp_init failed\n");
        return -1;
    }

    for (int i = 0; i < ARRAY_LEN(BUILTIN_BLOCKED); i++) {
        if (block_one(ctx, BUILTIN_BLOCKED[i]) < 0) {
            seccomp_release(ctx);
            return -1;
        }
    }

    for (int i = 0; i < extra_count; i++) {
        if (block_one(ctx, extra_blocked[i]) < 0) {
            seccomp_release(ctx);
            return -1;
        }
    }

    if (seccomp_load(ctx) != 0) {
        fprintf(stderr, "[nonet/C] seccomp_load failed: %s\n",
                strerror(errno));
        seccomp_release(ctx);
        return -1;
    }

    seccomp_release(ctx);
    fprintf(stderr,
            "[nonet/C] sandbox installed — "
            "%d built-in + %d extra syscalls blocked\n",
            ARRAY_LEN(BUILTIN_BLOCKED), extra_count);
    return 0;
}
