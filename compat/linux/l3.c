/*
 * L3 (docs/compat.md): dynamic Linux ELF64 executable (`ET_DYN` with `PT_INTERP` =
 * `/lib64/ld-linux-x86-64.so.2`, `DT_NEEDED` = `libl3.so`, `PT_TLS`, `PT_GNU_RELRO`).
 *
 * Checks:
 *   dyn      PT_INTERP dynamic linker loaded libl3.so, bound PLT/GOT, ran DT_INIT_ARRAY, PT_TLS
 *   relro    writing to libl3.so's PT_GNU_RELRO page triggers SIGSEGV (hardware mprotect RO)
 *   proc     /proc/self/{exe,cmdline,maps,status,fd}, /proc/version, other PID -> ENOENT
 *   dev      /dev/{null,zero,urandom,full}, /dev/sda -> ENOENT
 *   syscalls uname, pipe2 + poll, statx, prctl(PR_SET_NAME / PR_GET_NAME)
 *   prefix   (when given a file path arg) write/read/unlink in prefix + escape refused
 */

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;
typedef int i32;

extern int l3_add(int a, int b);
extern int l3_mul(int a, int b);
extern int l3_ctor_ran(void);
extern void *l3_relro_ptr(void);

static __thread int l3_tls_var = 77;

static i64 sys6(i64 n, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f)
{
    i64 r;
    register i64 r10 __asm__("r10") = d;
    register i64 r8 __asm__("r8") = e;
    register i64 r9 __asm__("r9") = f;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return r;
}

enum {
    SYS_read = 0, SYS_write = 1, SYS_open = 2, SYS_close = 3, SYS_poll = 7,
    SYS_rt_sigaction = 13, SYS_uname = 63, SYS_unlink = 87, SYS_readlink = 89,
    SYS_prctl = 157, SYS_getdents64 = 217, SYS_exit_group = 231, SYS_openat = 257,
    SYS_pipe2 = 293, SYS_statx = 332,
};
enum { ENOENT = 2, EACCES = 13, ENOSPC = 28 };
enum { O_RDONLY = 0, O_WRONLY = 1, O_CREAT = 0x40, O_TRUNC = 0x200, O_DIRECTORY = 0x10000 };
enum { SIGSEGV = 11, SA_SIGINFO = 4, SA_RESTORER = 0x04000000 };
enum { AT_FDCWD = -100, POLLIN = 1, PR_SET_NAME = 15, PR_GET_NAME = 16 };

static u64 slen(const char *s)
{
    u64 n = 0;
    while (s[n])
        n++;
    return n;
}
static void out(const char *s) { sys6(SYS_write, 1, (i64)s, (i64)slen(s), 0, 0, 0); }

static int has_sub(const char *hay, u64 hlen, const char *needle)
{
    u64 nlen = slen(needle);
    if (nlen == 0 || nlen > hlen)
        return 0;
    for (u64 i = 0; i <= hlen - nlen; i++) {
        u64 k = 0;
        while (k < nlen && hay[i + k] == needle[k])
            k++;
        if (k == nlen)
            return 1;
    }
    return 0;
}

static int streq(const char *a, const char *b)
{
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

static char *utoa(u64 v, char *end)
{
    *--end = 0;
    do {
        *--end = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    return end;
}

static int failed;
static void check(const char *what, int ok, const char *detail)
{
    out("L3: ");
    out(what);
    out(ok ? " ok" : " FAILED");
    if (detail) {
        out(": ");
        out(detail);
    }
    out("\n");
    if (!ok)
        failed++;
}

static __attribute__((noreturn)) void exit_group(int code)
{
    for (;;)
        sys6(SYS_exit_group, code, 0, 0, 0, 0, 0);
}

/* ---- RELRO write fault test ---- */
struct k_sigaction { void *handler; u64 flags; void *restorer; u64 mask; };
static volatile int relro_faulted;

void l3_restorer(void);
__asm__(".globl l3_restorer\nl3_restorer:\n  mov $15, %eax\n  syscall\n  hlt\n");

void l3_write_probe(void *p);
extern char l3_probe_fault[], l3_probe_after[];
__asm__(".globl l3_write_probe, l3_probe_fault, l3_probe_after\n"
        "l3_write_probe:\n"
        "l3_probe_fault:\n"
        "  movq $0, (%rdi)\n"
        "l3_probe_after:\n"
        "  ret\n");

static void on_segv(int sig, void *info, void *uc)
{
    (void)info;
    u64 *gregs = (u64 *)((char *)uc + 40);
    if (sig == SIGSEGV && gregs[16] == (u64)l3_probe_fault) {
        relro_faulted = 1;
        gregs[16] = (u64)l3_probe_after;
    }
}

static void test_dyn(void)
{
    int sum = l3_add(19, 23);
    int prod = l3_mul(6, 7);
    int ctor = l3_ctor_ran();
    int tls0 = l3_tls_var;
    l3_tls_var = 99;
    int ok = (sum == 42 && prod == 42 && ctor == 1 && tls0 == 77 && l3_tls_var == 99);
    check("dyn", ok, "PT_INTERP ld-linux + libl3.so + DT_INIT_ARRAY + PT_TLS");
}

static void test_relro(void)
{
    struct k_sigaction sa = { (void *)on_segv, SA_SIGINFO | SA_RESTORER, (void *)l3_restorer, 0 };
    int ok = sys6(SYS_rt_sigaction, SIGSEGV, (i64)&sa, 0, 8, 0, 0) == 0;
    void *rp = l3_relro_ptr();
    l3_write_probe(rp);
    check("relro", ok && relro_faulted == 1, "PT_GNU_RELRO write faulted with SIGSEGV");
}

static void test_proc(void)
{
    static char buf[4096];
    int ok = 1;
    i64 n = sys6(SYS_readlink, (i64)"/proc/self/exe", (i64)buf, sizeof(buf) - 1, 0, 0, 0);
    ok = ok && n > 0;

    i64 fd = sys6(SYS_openat, AT_FDCWD, (i64)"/proc/self/maps", O_RDONLY, 0, 0, 0);
    i64 mlen = fd >= 0 ? sys6(SYS_read, fd, (i64)buf, sizeof(buf) - 1, 0, 0, 0) : -1;
    if (fd >= 0) sys6(SYS_close, fd, 0, 0, 0, 0, 0);
    ok = ok && mlen > 0 && has_sub(buf, (u64)mlen, "libl3.so") && has_sub(buf, (u64)mlen, "ld-linux");

    fd = sys6(SYS_openat, AT_FDCWD, (i64)"/proc/self/status", O_RDONLY, 0, 0, 0);
    i64 sl = fd >= 0 ? sys6(SYS_read, fd, (i64)buf, sizeof(buf) - 1, 0, 0, 0) : -1;
    if (fd >= 0) sys6(SYS_close, fd, 0, 0, 0, 0, 0);
    ok = ok && sl > 0 && has_sub(buf, (u64)sl, "Pid:") && has_sub(buf, (u64)sl, "Threads:");

    fd = sys6(SYS_openat, AT_FDCWD, (i64)"/proc/version", O_RDONLY, 0, 0, 0);
    i64 vl = fd >= 0 ? sys6(SYS_read, fd, (i64)buf, sizeof(buf) - 1, 0, 0, 0) : -1;
    if (fd >= 0) sys6(SYS_close, fd, 0, 0, 0, 0, 0);
    ok = ok && vl > 0 && has_sub(buf, (u64)vl, "Linux version");

    /* /proc/self/fd directory listing */
    fd = sys6(SYS_openat, AT_FDCWD, (i64)"/proc/self/fd", O_RDONLY | O_DIRECTORY, 0, 0, 0);
    i64 dl = fd >= 0 ? sys6(SYS_getdents64, fd, (i64)buf, sizeof(buf), 0, 0, 0) : -1;
    if (fd >= 0) sys6(SYS_close, fd, 0, 0, 0, 0, 0);
    ok = ok && dl > 0;

    /* Capability-scoped isolation: another PID must not be visible. */
    i64 other = sys6(SYS_openat, AT_FDCWD, (i64)"/proc/1/status", O_RDONLY, 0, 0, 0);
    ok = ok && other == -ENOENT;
    check("proc", ok, "/proc/self/{exe,maps,status,fd}, /proc/version, /proc/1 -> ENOENT");
}

static void test_dev(void)
{
    char buf[32];
    int ok = 1;
    i64 fd = sys6(SYS_openat, AT_FDCWD, (i64)"/dev/null", O_WRONLY, 0, 0, 0);
    ok = ok && fd >= 0 && sys6(SYS_write, fd, (i64)"discard", 7, 0, 0, 0) == 7;
    if (fd >= 0) sys6(SYS_close, fd, 0, 0, 0, 0, 0);

    fd = sys6(SYS_openat, AT_FDCWD, (i64)"/dev/zero", O_RDONLY, 0, 0, 0);
    for (int i = 0; i < 16; i++) buf[i] = 0x55;
    ok = ok && fd >= 0 && sys6(SYS_read, fd, (i64)buf, 16, 0, 0, 0) == 16;
    for (int i = 0; i < 16; i++)
        if (buf[i] != 0) ok = 0;
    if (fd >= 0) sys6(SYS_close, fd, 0, 0, 0, 0, 0);

    fd = sys6(SYS_openat, AT_FDCWD, (i64)"/dev/urandom", O_RDONLY, 0, 0, 0);
    ok = ok && fd >= 0 && sys6(SYS_read, fd, (i64)buf, 32, 0, 0, 0) == 32;
    int nonzero = 0;
    for (int i = 0; i < 32; i++) nonzero |= (buf[i] != 0);
    ok = ok && nonzero;
    if (fd >= 0) sys6(SYS_close, fd, 0, 0, 0, 0, 0);

    fd = sys6(SYS_openat, AT_FDCWD, (i64)"/dev/full", O_WRONLY, 0, 0, 0);
    ok = ok && fd >= 0 && sys6(SYS_write, fd, (i64)"x", 1, 0, 0, 0) == -ENOSPC;
    if (fd >= 0) sys6(SYS_close, fd, 0, 0, 0, 0, 0);

    /* Hardware device nodes must not exist. */
    ok = ok && sys6(SYS_openat, AT_FDCWD, (i64)"/dev/sda", O_RDONLY, 0, 0, 0) == -ENOENT;
    check("dev", ok, "/dev/{null,zero,urandom,full}, /dev/sda -> ENOENT");
}

static void test_syscalls(void)
{
    int ok = 1;
    char uts[390];
    ok = ok && sys6(SYS_uname, (i64)uts, 0, 0, 0, 0, 0) == 0 && streq(uts, "Linux") && streq(uts + 260, "x86_64");

    /* pipe2 + poll + read/write */
    i32 pfds[2] = { -1, -1 };
    ok = ok && sys6(SYS_pipe2, (i64)pfds, 0, 0, 0, 0, 0) == 0;
    if (pfds[0] >= 0 && pfds[1] >= 0) {
        ok = ok && sys6(SYS_write, pfds[1], (i64)"d-cmpl", 6, 0, 0, 0) == 6;
        struct { i32 fd; short events; short revents; } pfd = { pfds[0], POLLIN, 0 };
        ok = ok && sys6(SYS_poll, (i64)&pfd, 1, 0, 0, 0, 0) == 1 && (pfd.revents & POLLIN);
        char rb[16] = { 0 };
        ok = ok && sys6(SYS_read, pfds[0], (i64)rb, 6, 0, 0, 0) == 6 && streq(rb, "d-cmpl");
        sys6(SYS_close, pfds[0], 0, 0, 0, 0, 0);
        sys6(SYS_close, pfds[1], 0, 0, 0, 0, 0);
    }

    /* statx */
    char stx[256];
    ok = ok && sys6(SYS_statx, AT_FDCWD, (i64)"/proc/version", 0, 0x7ff, (i64)stx, 0) == 0;

    /* prctl(PR_SET_NAME / PR_GET_NAME) */
    char comm[16] = { 0 };
    ok = ok && sys6(SYS_prctl, PR_SET_NAME, (i64)"l3-dyn", 0, 0, 0, 0) == 0;
    ok = ok && sys6(SYS_prctl, PR_GET_NAME, (i64)comm, 0, 0, 0, 0) == 0 && streq(comm, "l3-dyn");
    check("syscalls", ok, "uname, pipe2+poll, statx, prctl");
}

static void test_prefix(const char *path)
{
    if (!path) {
        check("prefix", 1, "skipped (no path given)");
        return;
    }
    int ok = 1;
    i64 fd = sys6(SYS_openat, AT_FDCWD, (i64)path, O_WRONLY | O_CREAT | O_TRUNC, 0644, 0, 0);
    ok = ok && fd >= 0 && sys6(SYS_write, fd, (i64)"l3 prefix payload\n", 18, 0, 0, 0) == 18;
    if (fd >= 0) sys6(SYS_close, fd, 0, 0, 0, 0, 0);

    char rb[32] = { 0 };
    fd = sys6(SYS_openat, AT_FDCWD, (i64)path, O_RDONLY, 0, 0, 0);
    ok = ok && fd >= 0 && sys6(SYS_read, fd, (i64)rb, 18, 0, 0, 0) == 18 && streq(rb, "l3 prefix payload\n");
    if (fd >= 0) sys6(SYS_close, fd, 0, 0, 0, 0, 0);

    ok = ok && sys6(SYS_unlink, (i64)path, 0, 0, 0, 0, 0) == 0;
    /* Escape outside prefix/namespace must fail. */
    i64 esc = sys6(SYS_openat, AT_FDCWD, (i64)"/boot/README.TXT", O_RDONLY, 0, 0, 0);
    ok = ok && (esc == -EACCES || esc == -ENOENT);
    check("prefix", ok, "prefix read/write/unlink ok, escape refused");
}

void _start(void);
__attribute__((noreturn, used)) void l3_main(u64 *sp);
__asm__(".globl _start\n"
        "_start:\n"
        "  xor %ebp, %ebp\n"
        "  mov %rsp, %rdi\n"
        "  and $-16, %rsp\n"
        "  call l3_main\n"
        "  hlt\n");

void l3_main(u64 *sp)
{
    u64 argc = sp[0];
    char **argv = (char **)(sp + 1);
    out("Hello from Linux (L3): dynamic ELF + ld-linux.so + /proc + /dev on D-CMPL\n");
    test_dyn();
    test_relro();
    test_proc();
    test_dev();
    test_syscalls();
    test_prefix(argc > 1 ? argv[1] : 0);
    out("L3: ");
    char nb[24];
    out(utoa((u64)failed, nb + sizeof(nb)));
    out(" checks failed\n");
    exit_group(failed);
}
