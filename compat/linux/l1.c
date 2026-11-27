/*
 * L1 (docs/compat.md): a static Linux Hello World, freestanding (no libc; it does what musl's
 * startup does: set_tid_address, TLS through arch_prctl(ARCH_SET_FS), then raw syscalls).
 * Built by build.ps1 with clang for x86_64-linux (ET_EXEC at 0x400000); it is an ordinary Linux
 * binary and runs unchanged on Linux. On D-OS it runs under D-CMPL's Linux server
 * (`dcmpl linux l1 [mode]`), which builds the initial stack and serves every syscall.
 *
 * Checks the Linux process contract: argc/argv/envp/auxv on the initial stack (AT_PAGESZ,
 * AT_RANDOM, AT_ENTRY), set_tid_address returns the tid, %fs:0 reads the TLS block after
 * arch_prctl, and ARCH_GET_FS gives it back. Exit code 0 = all good, else the failed check.
 *
 * Modes (argv[1]): none = print hello; "enosys" = an unsupported syscall must return -ENOSYS;
 * "fault" = write to NULL; "bench <n>" = n getpid round trips, cycles per call printed.
 */

typedef unsigned long u64;
typedef long i64;

static i64 sys3(i64 n, i64 a, i64 b, i64 c)
{
    i64 r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return r;
}

enum { SYS_write = 1, SYS_getpid = 39, SYS_ptrace = 101, SYS_arch_prctl = 158, SYS_set_tid_address = 218,
       SYS_exit_group = 231 };
enum { ARCH_SET_FS = 0x1002, ARCH_GET_FS = 0x1003, ENOSYS = 38 };
enum { AT_NULL = 0, AT_PAGESZ = 6, AT_ENTRY = 9, AT_RANDOM = 25 };

static u64 slen(const char *s)
{
    u64 n = 0;
    while (s[n])
        n++;
    return n;
}

static void out(const char *s) { sys3(SYS_write, 1, (i64)s, (i64)slen(s)); }

static __attribute__((noreturn)) void exit_group(int code)
{
    for (;;)
        sys3(SYS_exit_group, code, 0, 0);
}

static int streq(const char *a, const char *b)
{
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

static u64 parse(const char *s)
{
    u64 v = 0;
    while (s && *s >= '0' && *s <= '9')
        v = v * 10 + (u64)(*s++ - '0');
    return v;
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

static inline u64 rdtsc(void)
{
    unsigned lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((u64)hi << 32) | lo;
}

/* musl-style thread control block: %fs:0 points at itself. */
static struct tcb { struct tcb *self; u64 canary; } tcb;
static int tid_slot;

void _start(void);
__attribute__((noreturn, used)) void l1_main(u64 *sp);

__asm__(".globl _start\n"
        "_start:\n"
        "  xor %ebp, %ebp\n"
        "  mov %rsp, %rdi\n"          /* argc, argv, envp, auxv */
        "  and $-16, %rsp\n"
        "  call l1_main\n"
        "  hlt\n");

void l1_main(u64 *sp)
{
    u64 argc = sp[0];
    char **argv = (char **)(sp + 1);
    char **envp = argv + argc + 1;
    char **e = envp;
    while (*e)
        e++;
    u64 *auxv = (u64 *)(e + 1);
    u64 pagesz = 0, entry = 0, random = 0;
    for (u64 *a = auxv; a[0] != AT_NULL; a += 2) {
        if (a[0] == AT_PAGESZ)
            pagesz = a[1];
        else if (a[0] == AT_ENTRY)
            entry = a[1];
        else if (a[0] == AT_RANDOM)
            random = a[1];
    }
    if (argc < 1 || !argv[0] || pagesz != 4096 || entry != (u64)&_start || !random)
        exit_group(10);

    if (sys3(SYS_set_tid_address, (i64)&tid_slot, 0, 0) <= 0)
        exit_group(11);
    tcb.self = &tcb;
    tcb.canary = *(u64 *)random;
    if (sys3(SYS_arch_prctl, ARCH_SET_FS, (i64)&tcb, 0) != 0)
        exit_group(12);
    u64 fs0, back = 0;
    __asm__ volatile("mov %%fs:0, %0" : "=r"(fs0));
    if (fs0 != (u64)&tcb || sys3(SYS_arch_prctl, ARCH_GET_FS, (i64)&back, 0) != 0 || back != (u64)&tcb)
        exit_group(13);

    const char *mode = argc > 1 ? argv[1] : "";
    if (streq(mode, "")) {
        out("Hello, world from Linux (L1)\n");
        out("L1: argv/auxv on the stack, TLS at FS, set_tid_address served\n");
        exit_group(0);
    }
    if (streq(mode, "enosys")) {
        i64 r = sys3(SYS_ptrace, 0, 0, 0);
        out(r == -ENOSYS ? "L1: ptrace -> ENOSYS, handled cleanly\n" : "L1: ptrace did not fail with ENOSYS\n");
        exit_group(r == -ENOSYS ? 0 : 14);
    }
    if (streq(mode, "fault")) {
        out("L1: writing to address 0\n");
        *(volatile int *)0 = 1;
        exit_group(15);
    }
    if (streq(mode, "bench")) {
        u64 n = parse(argc > 2 ? argv[2] : "1000");
        i64 pid = sys3(SYS_getpid, 0, 0, 0);
        u64 t0 = rdtsc();
        for (u64 i = 0; i < n; i++)
            if (sys3(SYS_getpid, 0, 0, 0) != pid)
                exit_group(16);
        u64 per = n ? (rdtsc() - t0) / n : 0;
        char num[24];
        out("BENCH compat: forwarded Linux syscall round trip (getpid, L1 -> Linux server): ");
        out(utoa(per, num + sizeof(num)));
        out(" cycles\n");
        exit_group(0);
    }
    out("L1: unknown mode\n");
    exit_group(17);
}
