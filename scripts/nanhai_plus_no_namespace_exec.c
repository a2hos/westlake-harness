/* Native Linux x86_64 syscall guard for an ordinary, unprivileged build process.
 * It creates no container, namespace, chroot, mount or network namespace.
 * Build and probe independently before using it with Soong.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#if !defined(__x86_64__)
#error "This guard is reviewed only for Linux x86_64"
#endif
#if defined(__ILP32__)
#error "x32 ABI is not admitted"
#endif

#define DENIED (SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA))
#define UNAVAILABLE (SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA))
#define DENY_SYSCALL(number) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (number), 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, DENIED)

/* clone(2) puts flags in argument zero on x86_64. */
#define NEW_NAMESPACE_FLAGS (CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | \
                             CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | \
                             CLONE_NEWNET | CLONE_NEWTIME)

static int install_filter(void) {
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x40000000U, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        DENY_SYSCALL(__NR_unshare),
        DENY_SYSCALL(__NR_setns),
        DENY_SYSCALL(__NR_chroot),
        DENY_SYSCALL(__NR_pivot_root),
        DENY_SYSCALL(__NR_mount),
        DENY_SYSCALL(__NR_umount2),
#ifdef __NR_open_tree
        DENY_SYSCALL(__NR_open_tree),
#endif
#ifdef __NR_move_mount
        DENY_SYSCALL(__NR_move_mount),
#endif
#ifdef __NR_fsopen
        DENY_SYSCALL(__NR_fsopen),
#endif
#ifdef __NR_fsconfig
        DENY_SYSCALL(__NR_fsconfig),
#endif
#ifdef __NR_fsmount
        DENY_SYSCALL(__NR_fsmount),
#endif
#ifdef __NR_fspick
        DENY_SYSCALL(__NR_fspick),
#endif
#ifdef __NR_mount_setattr
        DENY_SYSCALL(__NR_mount_setattr),
#endif
#ifdef __NR_clone3
        /* clone3 flags are behind a pointer, which seccomp BPF cannot inspect. */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone3, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, UNAVAILABLE),
#endif
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 4),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, NEW_NAMESPACE_FLAGS, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, DENIED),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(instructions) / sizeof(instructions[0])),
        .filter = instructions,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("PR_SET_NO_NEW_PRIVS");
        return -1;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0) {
        perror("PR_SET_SECCOMP");
        return -1;
    }
    return 0;
}

static int probe(void) {
    /* Every fallback is inert or invalid if the filter were absent. */
    errno = 0;
    if (syscall(__NR_unshare, 0) != -1 || errno != EPERM) return 11;
    errno = 0;
    if (syscall(__NR_chroot, (const char *)-1) != -1 || errno != EPERM) return 12;
    errno = 0;
    if (syscall(__NR_mount, (const char *)-1, (const char *)-1,
                (const char *)-1, 0, NULL) != -1 || errno != EPERM) return 13;
#ifdef __NR_clone3
    errno = 0;
    if (syscall(__NR_clone3, NULL, 0) != -1 || errno != ENOSYS) return 14;
#endif
    errno = 0;
    if (syscall(__NR_clone, CLONE_NEWUSER | CLONE_THREAD, NULL,
                NULL, NULL, 0) != -1 || errno != EPERM) return 15;
    puts("namespace syscalls denied; no namespace created");
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fputs("usage: no-namespace-exec --probe | program [args...]\n", stderr);
        return 64;
    }
    if (install_filter() != 0) return 70;
    if (argc == 2 && strcmp(argv[1], "--probe") == 0) {
        return probe();
    }
    execvp(argv[1], &argv[1]);
    perror("execvp");
    return 71;
}
