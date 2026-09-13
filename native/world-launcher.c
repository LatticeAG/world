// world-launcher — certified wasm-process-v1 launch boundary (spec §3.3).
//
// This helper is the ONLY path that may start a guest. It:
//   1. creates the §6.8 control socketpair (SOCK_SEQPACKET),
//   2. enters user/pid/mount/net namespaces and sets no_new_privs,
//   3. installs the pinned seccomp-bpf baseline (raw BPF; no libseccomp),
//   4. execs the certified wasm runtime on the pinned module bytes.
//
// Anything failing before exec exits 2; the broker treats that as
// ENFORCER_UNAVAILABLE and never marks the crossing dispatched.
//
// Usage: world-launcher <module.wasm> <runtime>
//   stdout: "chan=<fd>" — the parent endpoint of the control socketpair.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/bpf_common.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#ifndef SECCOMP_RET_ERRNO
#define SECCOMP_RET_ERRNO 0x00050000U
#endif
#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW 0x7fff0000U
#endif
#ifndef AUDIT_ARCH_AARCH64
#define AUDIT_ARCH_AARCH64 0xC00000B7U
#endif
#ifndef AUDIT_ARCH_X86_64
#define AUDIT_ARCH_X86_64 0xC000003EU
#endif

#define ALLOW(nr) \
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, (nr), 0, 1), \
    BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)

static int install_baseline(void) {
    static struct sock_filter filter[] = {
        // arch check: wrong-arch syscall numbers never pass.
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, arch)),
#if defined(__aarch64__)
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
#else
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, AUDIT_ARCH_X86_64, 1, 0),
#endif
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)),
#ifdef SYS_read
        ALLOW(SYS_read),
#endif
#ifdef SYS_write
        ALLOW(SYS_write),
#endif
#ifdef SYS_close
        ALLOW(SYS_close),
#endif
#ifdef SYS_mmap
        ALLOW(SYS_mmap),
#endif
#ifdef SYS_munmap
        ALLOW(SYS_munmap),
#endif
#ifdef SYS_mprotect
        ALLOW(SYS_mprotect),
#endif
#ifdef SYS_futex
        ALLOW(SYS_futex),
#endif
#ifdef SYS_clock_gettime
        ALLOW(SYS_clock_gettime),
#endif
#ifdef SYS_exit_group
        ALLOW(SYS_exit_group),
#endif
#ifdef SYS_recvmsg
        ALLOW(SYS_recvmsg),
#endif
#ifdef SYS_sendmsg
        ALLOW(SYS_sendmsg),
#endif
#ifdef SYS_writev
        ALLOW(SYS_writev),
#endif
#ifdef SYS_readv
        ALLOW(SYS_readv),
#endif
#ifdef SYS_brk
        ALLOW(SYS_brk),
#endif
#ifdef SYS_rt_sigreturn
        ALLOW(SYS_rt_sigreturn),
#endif
#ifdef SYS_getrandom
        ALLOW(SYS_getrandom),
#endif
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: world-launcher <module.wasm> <runtime>\n");
        return 2;
    }
    const char *module = argv[1];
    const char *runtime = argv[2];

    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) != 0) {
        fprintf(stderr, "socketpair: %s\n", strerror(errno));
        return 2;
    }

    if (unshare(CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET) != 0) {
        fprintf(stderr, "unshare: %s\n", strerror(errno));
        return 2;
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        fprintf(stderr, "no_new_privs: %s\n", strerror(errno));
        return 2;
    }
    if (install_baseline() != 0) {
        fprintf(stderr, "seccomp: %s\n", strerror(errno));
        return 2;
    }

    // pair[0] = parent endpoint (reported on stdout), pair[1] = guest import fd 3.
    printf("chan=%d\n", pair[0]);
    fflush(stdout);
    if (dup2(pair[1], 3) < 0) return 2;
    execl(runtime, runtime, module, NULL);
    fprintf(stderr, "exec: %s\n", strerror(errno));
    return 2;
}
