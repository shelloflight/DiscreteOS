/*
 * L2 (docs/compat.md): a static Linux program with threads, memory, files and signals, built by
 * build.ps1 with clang for x86_64-linux (freestanding, raw system calls, as a C library's
 * internals make them). It is an ordinary Linux binary and runs unchanged on Linux. On D-OS it
 * runs under D-CMPL's Linux server: `dcmpl linux l2 [dir]`, or `run l2 [dir]` in the shell.
 *
 * Each check prints one line; the exit code is the number of failed checks (0 = all good).
 *   memory   mmap (anonymous, a PROT_NONE reservation made writable with mprotect), munmap, brk
 *   threads  4 threads made with clone(CLONE_VM | CLONE_THREAD | CLONE_SETTLS | ...) on their own
 *            mmap'd stacks, each with its own TLS block at %fs; a futex-based lock around a
 *            shared counter; the parent waits on each child's tid (CLONE_CHILD_CLEARTID + wake)
 *   futex    a wait that times out (ETIMEDOUT after >= 20 ms), a wake with nobody waiting
 *   signals  a SIGSEGV handler (SA_SIGINFO) that skips the faulting instruction, SIGUSR1 raised
 *            with tgkill while blocked (stays pending) and delivered when unblocked
 *   files    (only with a directory argument) write, read back, fstat, lseek, getdents64,
 *            rename, unlink, and the file gone afterwards
 *   time     clock_gettime (monotonic advances, realtime after 2000), nanosleep
 *   enosys   fork() fails cleanly with -ENOSYS
 */

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;
typedef int i32;

static i64 sys6(i64 n, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f)
{
    i64 r;
    register i64 r10 __asm__("r10") = d;
    register i64 r8 __asm__("r8") = e;
    register i64 r9 __asm__("r9") = f;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return r;
}
#define sys0(n) sys6(n, 0, 0, 0, 0, 0, 0)
#define sys1(n, a) sys6(n, (i64)(a), 0, 0, 0, 0, 0)
#define sys2(n, a, b) sys6(n, (i64)(a), (i64)(b), 0, 0, 0, 0)
#define sys3(n, a, b, c) sys6(n, (i64)(a), (i64)(b), (i64)(c), 0, 0, 0)
#define sys4(n, a, b, c, d) sys6(n, (i64)(a), (i64)(b), (i64)(c), (i64)(d), 0, 0)

enum {
    SYS_read = 0, SYS_write = 1, SYS_open = 2, SYS_close = 3, SYS_fstat = 5, SYS_lseek = 8, SYS_mmap = 9,
    SYS_mprotect = 10, SYS_munmap = 11, SYS_brk = 12, SYS_rt_sigaction = 13, SYS_rt_sigprocmask = 14,
    SYS_nanosleep = 35, SYS_getpid = 39, SYS_clone = 56, SYS_fork = 57, SYS_exit = 60, SYS_rename = 82,
    SYS_unlink = 87, SYS_arch_prctl = 158, SYS_gettid = 186, SYS_futex = 202, SYS_getdents64 = 217,
    SYS_set_tid_address = 218, SYS_clock_gettime = 228, SYS_exit_group = 231, SYS_tgkill = 234,
};
enum { EAGAIN = 11, ENOENT = 2, ENOSYS = 38, ETIMEDOUT = 110 };
enum { PROT_NONE = 0, PROT_READ = 1, PROT_WRITE = 2, MAP_PRIVATE = 2, MAP_ANONYMOUS = 0x20 };
enum { O_RDONLY = 0, O_WRONLY = 1, O_CREAT = 0x40, O_TRUNC = 0x200, O_DIRECTORY = 0x10000 };
enum { FUTEX_WAIT = 0, FUTEX_WAKE = 1, FUTEX_PRIVATE = 128 };
enum { SIGSEGV = 11, SIGUSR1 = 10, SA_SIGINFO = 4, SA_RESTORER = 0x04000000, SIG_BLOCK = 0, SIG_UNBLOCK = 1 };
#define CLONE_FLAGS (0x100 | 0x200 | 0x400 | 0x800 | 0x10000 | 0x40000 | 0x80000 | 0x100000 | 0x200000)

/* What the compiler may call for struct and array copies (no C library here). */
void *memset(void *d, int c, u64 n)
{
    unsigned char *p = d;
    while (n--)
        *p++ = (unsigned char)c;
    return d;
}
void *memcpy(void *d, const void *s, u64 n)
{
    unsigned char *p = d;
    const unsigned char *q = s;
    while (n--)
        *p++ = *q++;
    return d;
}

static u64 slen(const char *s)
{
    u64 n = 0;
    while (s[n])
        n++;
    return n;
}
static void out(const char *s) { sys3(SYS_write, 1, s, slen(s)); }
static char *utoa(u64 v, char *end)
{
    *--end = 0;
    do {
        *--end = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    return end;
}
static void out_num(u64 v)
{
    char b[24];
    out(utoa(v, b + sizeof(b)));
}
static int streq(const char *a, const char *b)
{
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}
static void scopy(char *d, const char *s)
{
    while ((*d++ = *s++))
        ;
}
static void scat(char *d, const char *s) { scopy(d + slen(d), s); }

static int failed;
static void check(const char *what, int ok, const char *detail)
{
    out("L2: ");
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
        sys1(SYS_exit_group, code);
}

static void *mmap_anon(u64 len, int prot)
{
    return (void *)sys6(SYS_mmap, 0, (i64)len, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}
static int bad_ptr(void *p) { return (u64)p > (u64)-4096; }

static u64 now_ns(int clock)
{
    i64 ts[2];
    if (sys2(SYS_clock_gettime, clock, ts) != 0)
        return 0;
    return (u64)ts[0] * 1000000000ul + (u64)ts[1];
}

/* ---- memory -------------------------------------------------------------------------------- */
static void test_memory(void)
{
    int ok = 1;
    unsigned char *m = mmap_anon(1 << 20, PROT_READ | PROT_WRITE);
    if (bad_ptr(m)) {
        ok = 0;
    } else {
        for (u64 i = 0; i < (1 << 20); i += 4096)
            if (m[i] != 0)
                ok = 0;
        for (u64 i = 0; i < (1 << 20); i++)
            m[i] = (unsigned char)i;
        for (u64 i = 0; i < (1 << 20); i += 997)
            if (m[i] != (unsigned char)i)
                ok = 0;
        ok = ok && sys2(SYS_munmap, m, 1 << 20) == 0;
    }
    /* A reservation, then the middle made writable (how thread stacks get guard pages). */
    unsigned char *r = mmap_anon(64 * 1024, PROT_NONE);
    ok = ok && !bad_ptr(r) && sys3(SYS_mprotect, r + 4096, 56 * 1024, PROT_READ | PROT_WRITE) == 0;
    if (ok) {
        r[4096] = 1;
        r[60 * 1024 - 1] = 2;
        ok = r[4096] == 1 && r[60 * 1024 - 1] == 2;
    }
    u64 b0 = (u64)sys1(SYS_brk, 0);
    u64 b1 = (u64)sys1(SYS_brk, b0 + 300000);
    if (b1 == b0 + 300000) {
        volatile char *p = (char *)b0;
        p[0] = 7;
        p[299999] = 9;
        ok = ok && p[0] == 7 && p[299999] == 9 && (u64)sys1(SYS_brk, b0 + 4096) == b0 + 4096;
    } else {
        ok = 0;
    }
    check("memory", ok, "mmap, PROT_NONE + mprotect, munmap, brk");
}

/* ---- threads: clone, TLS, futex lock -------------------------------------------------------- */
struct tcb { struct tcb *self; int id; int pad; };
static struct tcb tcbs[5];
static volatile i32 lock_word;
static volatile i64 counter;
static i32 child_tids[4];
static volatile i32 tls_ok[4];

static void lock(void)
{
    while (__sync_val_compare_and_swap(&lock_word, 0, 1) != 0) {
        __sync_lock_test_and_set(&lock_word, 2);
        sys4(SYS_futex, &lock_word, FUTEX_WAIT | FUTEX_PRIVATE, 2, 0);
        if (__sync_val_compare_and_swap(&lock_word, 0, 2) == 0)
            return;
    }
}
static void unlock(void)
{
    if (__sync_lock_test_and_set(&lock_word, 0) == 2)
        sys4(SYS_futex, &lock_word, FUTEX_WAKE | FUTEX_PRIVATE, 1, 0);
}

static int worker(void *arg)
{
    int id = (int)(u64)arg;
    struct tcb *t;
    __asm__ volatile("mov %%fs:0, %0" : "=r"(t));
    tls_ok[id] = t == &tcbs[id + 1] && t->id == id + 1 && sys0(SYS_gettid) == child_tids[id];
    for (int i = 0; i < 1000; i++) {
        lock();
        counter++;
        unlock();
    }
    return 0;
}

/* clone(flags, stack, ptid, ctid, tls) with fn/arg on the child's stack; the child calls
 * fn(arg) and exits its thread with the result. Returns the child's tid (or -errno). */
i64 l2_clone(u64 flags, void *stack, i32 *ptid, i32 *ctid, void *tls, int (*fn)(void *), void *arg);
__asm__(".globl l2_clone\n"
        "l2_clone:\n"
        "  and $-16, %rsi\n"
        "  sub $16, %rsi\n"
        "  mov %r9, (%rsi)\n"        /* fn */
        "  mov 8(%rsp), %rax\n"      /* arg */
        "  mov %rax, 8(%rsi)\n"
        "  mov %rcx, %r10\n"         /* ctid */
        "  mov $56, %eax\n"
        "  syscall\n"
        "  test %rax, %rax\n"
        "  jnz 1f\n"
        "  xor %ebp, %ebp\n"
        "  pop %rax\n"
        "  pop %rdi\n"
        "  call *%rax\n"
        "  mov %eax, %edi\n"
        "  mov $60, %eax\n"
        "  syscall\n"
        "  hlt\n"
        "1: ret\n");

static void test_threads(void)
{
    int ok = 1;
    for (int i = 0; i < 4; i++) {
        tcbs[i + 1].self = &tcbs[i + 1];
        tcbs[i + 1].id = i + 1;
        char *stack = mmap_anon(64 * 1024, PROT_READ | PROT_WRITE);
        if (bad_ptr(stack)) {
            ok = 0;
            continue;
        }
        i64 tid = l2_clone(CLONE_FLAGS, stack + 64 * 1024, &child_tids[i], &child_tids[i], &tcbs[i + 1], worker, (void *)(u64)i);
        if (tid <= 0)
            ok = 0;
    }
    /* Wait for each child: the kernel (here: the Linux server) clears its tid and wakes us. */
    u64 t0 = now_ns(1);
    for (int i = 0; i < 4; i++) {
        i32 v;
        while ((v = __atomic_load_n(&child_tids[i], __ATOMIC_ACQUIRE)) != 0) {
            i64 ts[2] = { 1, 0 };
            sys4(SYS_futex, &child_tids[i], FUTEX_WAIT, v, ts);
            if (now_ns(1) - t0 > 30000000000ul) {
                ok = 0;
                break;
            }
        }
    }
    int tls = tls_ok[0] && tls_ok[1] && tls_ok[2] && tls_ok[3];
    char d[64] = "counter ";
    char n[24];
    scat(d, utoa((u64)counter, n + sizeof(n)));
    scat(d, tls ? ", TLS per thread" : ", TLS WRONG");
    check("threads", ok && counter == 4000 && tls, d);
}

/* ---- futex timeout -------------------------------------------------------------------------- */
static void test_futex(void)
{
    i32 word = 5;
    i64 ts[2] = { 0, 20000000 };
    u64 t0 = now_ns(1);
    i64 r = sys4(SYS_futex, &word, FUTEX_WAIT | FUTEX_PRIVATE, 5, ts);
    u64 dt = now_ns(1) - t0;
    i64 r2 = sys4(SYS_futex, &word, FUTEX_WAIT | FUTEX_PRIVATE, 6, ts);  /* value differs */
    i64 w = sys4(SYS_futex, &word, FUTEX_WAKE | FUTEX_PRIVATE, 1, 0);
    check("futex", r == -ETIMEDOUT && dt >= 20000000 && r2 == -EAGAIN && w == 0, "timeout, EAGAIN, empty wake");
}

/* ---- signals -------------------------------------------------------------------------------- */
struct k_sigaction { void *handler; u64 flags; void *restorer; u64 mask; };
static volatile int segv_seen, usr1_seen;
static volatile u64 segv_addr;

void l2_restorer(void);
__asm__(".globl l2_restorer\nl2_restorer:\n  mov $15, %eax\n  syscall\n  hlt\n");

/* A store to address 8 whose length the handler knows (it resumes after it). */
void l2_probe(void);
extern char l2_probe_fault[], l2_probe_after[];
__asm__(".globl l2_probe, l2_probe_fault, l2_probe_after\n"
        "l2_probe:\n"
        "l2_probe_fault:\n"
        "  movl $1, 8\n"
        "l2_probe_after:\n"
        "  ret\n");

static void on_segv(int sig, void *info, void *uc)
{
    u64 *gregs = (u64 *)((char *)uc + 40);   /* uc_mcontext */
    if (sig == SIGSEGV && gregs[16] == (u64)l2_probe_fault) {
        segv_seen++;
        segv_addr = *(u64 *)((char *)info + 16);
        gregs[16] = (u64)l2_probe_after;     /* skip the store */
    }
}
static void on_usr1(int sig, void *info, void *uc)
{
    (void)info;
    (void)uc;
    if (sig == SIGUSR1)
        usr1_seen++;
}

static void test_signals(void)
{
    struct k_sigaction a = { (void *)on_segv, SA_SIGINFO | SA_RESTORER, (void *)l2_restorer, 0 };
    int ok = sys4(SYS_rt_sigaction, SIGSEGV, &a, 0, 8) == 0;
    l2_probe();
    ok = ok && segv_seen == 1 && segv_addr == 8;
    struct k_sigaction b = { (void *)on_usr1, SA_SIGINFO | SA_RESTORER, (void *)l2_restorer, 0 };
    ok = ok && sys4(SYS_rt_sigaction, SIGUSR1, &b, 0, 8) == 0;
    u64 set = 1ul << (SIGUSR1 - 1);
    sys4(SYS_rt_sigprocmask, SIG_BLOCK, &set, 0, 8);
    sys3(SYS_tgkill, sys0(SYS_getpid), sys0(SYS_gettid), SIGUSR1);
    int pending_while_blocked = usr1_seen == 0;
    sys4(SYS_rt_sigprocmask, SIG_UNBLOCK, &set, 0, 8);
    ok = ok && pending_while_blocked && usr1_seen == 1;
    check("signals", ok, "SIGSEGV handled and skipped, SIGUSR1 held while blocked");
}

/* ---- files ---------------------------------------------------------------------------------- */
struct dirent64 { u64 ino; i64 off; unsigned short reclen; unsigned char type; char name[]; };

static void test_files(const char *dir)
{
    if (!dir) {
        check("files", 1, "skipped (no directory given)");
        return;
    }
    char path[256], path2[256];
    scopy(path, dir);
    scat(path, "/l2-test.txt");
    scopy(path2, dir);
    scat(path2, "/l2-renamed.txt");
    int ok = 1;
    i64 fd = sys3(SYS_open, path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        check("files", 0, "open for writing failed");
        return;
    }
    char line[64];
    for (int i = 0; i < 100; i++) {
        char n[24];
        scopy(line, "line ");
        scat(line, utoa((u64)i, n + sizeof(n)));
        scat(line, " of the L2 file test\n");
        if (sys3(SYS_write, fd, line, slen(line)) != (i64)slen(line))
            ok = 0;
    }
    sys1(SYS_close, fd);
    fd = sys3(SYS_open, path, O_RDONLY, 0);
    u64 st[18];
    ok = ok && fd >= 0 && sys2(SYS_fstat, fd, st) == 0 && st[6] > 2000;   /* st_size */
    static char buf[8192];
    i64 n = fd >= 0 ? sys3(SYS_read, fd, buf, sizeof(buf)) : -1;
    int lines = 0;
    for (i64 i = 0; i < n; i++)
        lines += buf[i] == '\n';
    ok = ok && sys3(SYS_lseek, fd, 5, 0) == 5 && sys3(SYS_read, fd, buf, 1) == 1 && buf[0] == '0';
    sys1(SYS_close, fd);
    /* The directory lists it. */
    i64 dfd = sys3(SYS_open, dir, O_RDONLY | O_DIRECTORY, 0);
    int listed = 0;
    if (dfd >= 0) {
        i64 got;
        while ((got = sys3(SYS_getdents64, dfd, buf, sizeof(buf))) > 0)
            for (i64 off = 0; off < got;) {
                struct dirent64 *e = (struct dirent64 *)(buf + off);
                listed += streq(e->name, "l2-test.txt");
                off += e->reclen;
            }
        sys1(SYS_close, dfd);
    }
    ok = ok && listed == 1 && sys2(SYS_rename, path, path2) == 0 && sys1(SYS_unlink, path2) == 0;
    ok = ok && sys3(SYS_open, path2, O_RDONLY, 0) == -ENOENT;
    char d[64] = "";
    char nb[24];
    scat(d, utoa((u64)lines, nb + sizeof(nb)));
    scat(d, " lines read back, listed, renamed, removed");
    check("files", ok && lines == 100, d);
}

/* ---- time, unsupported calls ---------------------------------------------------------------- */
static void test_time(void)
{
    u64 a = now_ns(1);
    i64 ts[2] = { 0, 5000000 };
    int slept = sys2(SYS_nanosleep, ts, 0) == 0;
    u64 b = now_ns(1);
    u64 rt = now_ns(0);
    check("time", slept && b - a >= 5000000 && rt > 946684800ul * 1000000000ul, "monotonic, nanosleep, realtime after 2000");
}

static void test_enosys(void)
{
    i64 r = sys0(SYS_fork);
    check("enosys", r == -ENOSYS, "fork -> ENOSYS");
}

void _start(void);
__attribute__((noreturn, used)) void l2_main(u64 *sp);
__asm__(".globl _start\n"
        "_start:\n"
        "  xor %ebp, %ebp\n"
        "  mov %rsp, %rdi\n"
        "  and $-16, %rsp\n"
        "  call l2_main\n"
        "  hlt\n");

static i32 main_tid;

void l2_main(u64 *sp)
{
    u64 argc = sp[0];
    char **argv = (char **)(sp + 1);
    sys1(SYS_set_tid_address, &main_tid);
    tcbs[0].self = &tcbs[0];
    sys2(SYS_arch_prctl, 0x1002, &tcbs[0]);
    out("Hello from Linux (L2): threads, memory, files and signals on D-CMPL\n");
    const char *dir = argc > 1 ? argv[1] : 0;
    test_memory();
    test_threads();
    test_futex();
    test_signals();
    test_files(dir);
    test_time();
    test_enosys();
    out("L2: ");
    out_num((u64)failed);
    out(" checks failed\n");
    exit_group(failed);
}
