/*
 * utest: ring-3 test program for the syscall ABI (started by init: "run utest <mode>").
 *
 *   all              every ABI check below, fault isolation, kill, threads, FPU, benchmark, a short fuzz
 *   fuzz <n>         syscall fuzzer: <n> random syscalls spread over short-lived child processes
 *   smap / smep      ask a test kernel to touch / execute user memory without permission (must panic)
 *   bench            only the benchmarks (the profile test runs them with histograms on)
 *   compat           the D-CMPL proofs (compat.c: W1, L1, start exception, PE fuzzing)
 *   cet              only the CET shadow-stack checks (cet.c; the Bochs test, which is slow)
 * Child modes (spawned by the modes above): crash <kind>, exit <code>, spin, block, threads,
 * fpu <seed>, quota, fuzzchild <seed> <n>, the IPC ones ("p10 ...", ipc.c) and "cet ..." (cet.c).
 *
 * Output lines start with "utest:"; failures print "FAIL" (the test harness looks for it).
 */

#include "utest.h"

unsigned failures;
dos_handle_t self_proc, self_vmar, log_h;

uint64_t parse_u(const char *s)
{
    uint64_t v = 0;
    while (*s >= '0' && *s <= '9')
        v = v * 10 + (uint64_t)(*s++ - '0');
    return v;
}

const char *word(const char *s, int n)   /* n-th space-separated word */
{
    while (n--) {
        while (*s && *s != ' ')
            s++;
        while (*s == ' ')
            s++;
    }
    return s;
}

/* Memory: a fresh RW mapping of `len` bytes (a VMO mapped anywhere in the root VMAR). */
void *map_new(uint64_t len, dos_handle_t *vmo_out)
{
    int64_t v = dos_vmo_create(len);
    if (v < 0)
        return 0;
    int64_t a = dos_vmar_map(self_vmar, DOS_ANY, (dos_handle_t)v, 0, len, DOS_RIGHT_READ | DOS_RIGHT_WRITE);
    if (a < 0) {
        dos_handle_close((dos_handle_t)v);
        return 0;
    }
    if (vmo_out)
        *vmo_out = (dos_handle_t)v;
    else
        dos_handle_close((dos_handle_t)v);   /* the mapping keeps the VMO alive */
    return (void *)(uintptr_t)a;
}

/* ---- spawning copies of this program ------------------------------------------------------ */

dos_handle_t my_image(void)
{
    char buf[32];
    for (uint32_t i = 0; i < dos_start->nhandles; i++)
        if (dos_start->handles[i].tag == DOS_TAG_PROGRAM &&
            dos_object_name(dos_start->handles[i].handle, buf, sizeof(buf)) == 8 && strncmp(buf, "utest.dx", 8) == 0)
            return dos_start->handles[i].handle;
    return DOS_HANDLE_INVALID;
}

/* Spawn "utest <args>" with the log (unless quiet) and the given limits. Returns the process handle. */
int64_t spawn_self(const char *args, const struct dos_limits *limits, int with_log)
{
    struct dos_spawn_handle hs[2];
    uint32_t nh = 0;
    if (with_log) {
        int64_t l = dos_handle_duplicate(log_h, DOS_RIGHTS_SAME);
        if (l > 0)
            hs[nh++] = (struct dos_spawn_handle){ (dos_handle_t)l, DOS_RIGHTS_SAME, DOS_TAG_LOG, 0 };
    }
    struct dos_spawn s = {
        .parent = self_proc, .image = my_image(),
        .name = (uint64_t)(uintptr_t)"utest.child", .name_len = 11,
        .args = (uint64_t)(uintptr_t)args, .args_len = strlen(args),
        .handles = (uint64_t)(uintptr_t)hs, .nhandles = nh,
        .limits = (uint64_t)(uintptr_t)limits,
    };
    return dos_spawn(&s);
}

int64_t wait_exit(int64_t proc, uint64_t timeout_ns)
{
    if (proc < 0)
        return proc;
    int64_t r = dos_object_wait((dos_handle_t)proc, DOS_TERMINATED, timeout_ns);
    int64_t code = r < 0 ? r : dos_process_exit_code((dos_handle_t)proc);
    dos_handle_close((dos_handle_t)proc);
    return code;
}

/* ---- ABI checks ------------------------------------------------------------------------------ */

static void test_basics(void)
{
    EXPECT(dos_abi_version(), DOS_ABI_VERSION);
    struct dos_info info;
    EXPECT(dos_object_info(self_proc, &info), 0);
    CHECK(info.type == DOS_OBJ_PROCESS && (info.rights & DOS_RIGHT_MANAGE));
    EXPECT(dos_object_info(self_vmar, &info), 0);
    CHECK(info.type == DOS_OBJ_VMAR);
    EXPECT(dos_object_info(dos_startup_handle(DOS_TAG_THREAD_SELF), &info), 0);
    CHECK(info.type == DOS_OBJ_THREAD);
    EXPECT(dos_object_info(log_h, &info), 0);
    CHECK(info.type == DOS_OBJ_LOG && info.rights == (DOS_RIGHT_DUPLICATE | DOS_RIGHT_TRANSFER | DOS_RIGHT_WRITE));
    EXPECT(DOS_SC(DOS_SYS_COUNT, 0, 0, 0, 0, 0, 0), DOS_ERR_NOT_SUPPORTED);
    EXPECT(DOS_SC(0x7FFFFFFF, 0, 0, 0, 0, 0, 0), DOS_ERR_NOT_SUPPORTED);
    EXPECT(DOS_SC(UINT64_MAX, 1, 2, 3, 4, 5, 6), DOS_ERR_NOT_SUPPORTED);
    CHECK(dos_clock_ns() > 0);
    dos_printf("utest: abi: version, startup handles, unknown syscalls\n");
}

static void test_handles(void)
{
    EXPECT(dos_handle_close(0), DOS_ERR_BAD_HANDLE);
    EXPECT(dos_handle_close(0x12345678), DOS_ERR_BAD_HANDLE);
    int64_t e = dos_event_create();
    CHECK(e > 0);
    dos_handle_t ev = (dos_handle_t)e;
    /* Rights only shrink. */
    int64_t w = dos_handle_duplicate(ev, DOS_RIGHT_WAIT);
    CHECK(w > 0 && w != e);
    EXPECT(dos_event_signal((dos_handle_t)w, 0, DOS_SIGNALED), DOS_ERR_ACCESS_DENIED);
    EXPECT(dos_handle_duplicate((dos_handle_t)w, DOS_RIGHT_WAIT | DOS_RIGHT_SIGNAL), DOS_ERR_ACCESS_DENIED);
    EXPECT(dos_handle_duplicate((dos_handle_t)w, DOS_RIGHT_WAIT), DOS_ERR_ACCESS_DENIED);   /* no DUPLICATE */
    EXPECT(dos_event_signal(ev, 0, 1u << 5), DOS_ERR_INVALID_ARGS);
    EXPECT(dos_event_signal(ev, 0, DOS_SIGNALED), 0);
    EXPECT(dos_object_wait((dos_handle_t)w, DOS_SIGNALED, 0), DOS_SIGNALED);
    /* Wrong types. */
    EXPECT(dos_vmo_size(ev), DOS_ERR_WRONG_TYPE);
    EXPECT(dos_event_signal(self_vmar, 0, DOS_SIGNALED), DOS_ERR_WRONG_TYPE);
    /* Closed handles stay invalid. */
    EXPECT(dos_handle_close((dos_handle_t)w), 0);
    EXPECT(dos_handle_close((dos_handle_t)w), DOS_ERR_BAD_HANDLE);
    EXPECT(dos_object_wait((dos_handle_t)w, DOS_SIGNALED, 0), DOS_ERR_BAD_HANDLE);
    int64_t r = dos_handle_replace(ev, DOS_RIGHT_WAIT | DOS_RIGHT_SIGNAL);
    CHECK(r > 0);
    EXPECT(dos_handle_close(ev), DOS_ERR_BAD_HANDLE);
    EXPECT(dos_handle_close((dos_handle_t)r), 0);
    /* Timers and timeouts. */
    int64_t t = dos_timer_create();
    CHECK(t > 0);
    EXPECT(dos_object_wait((dos_handle_t)t, DOS_SIGNALED, 1000000), DOS_ERR_TIMED_OUT);
    EXPECT(dos_timer_set((dos_handle_t)t, 2000000), 0);
    uint64_t t0 = dos_clock_ns();
    EXPECT(dos_object_wait((dos_handle_t)t, DOS_SIGNALED, DOS_WAIT_FOREVER), DOS_SIGNALED);
    CHECK(dos_clock_ns() - t0 >= 1500000);
    EXPECT(dos_handle_close((dos_handle_t)t), 0);
    dos_printf("utest: handles: rights only shrink, wrong types, closed handles, events, timers\n");
}

static void test_pointers(void)
{
    char buf[64];
    struct dos_info info;
    EXPECT(dos_log_write(log_h, (void *)KERNEL_ADDR, 16), DOS_ERR_BAD_ADDRESS);
    EXPECT(dos_log_write(log_h, (void *)0, 16), DOS_ERR_BAD_ADDRESS);
    EXPECT(dos_log_write(log_h, (void *)UNMAPPED, 16), DOS_ERR_BAD_ADDRESS);
    EXPECT(dos_log_write(log_h, (void *)(NONCANON - 8), 16), DOS_ERR_BAD_ADDRESS);
    EXPECT(dos_log_write(log_h, (void *)(uintptr_t)buf, UINT64_MAX - 100), DOS_ERR_INVALID_ARGS);
    EXPECT(dos_object_info(self_proc, (struct dos_info *)KERNEL_ADDR), DOS_ERR_BAD_ADDRESS);
    EXPECT(dos_object_info(self_proc, (struct dos_info *)UNMAPPED), DOS_ERR_BAD_ADDRESS);
    EXPECT(dos_object_info(self_proc, (struct dos_info *)(uintptr_t)&main), DOS_ERR_BAD_ADDRESS);  /* read-only code */
    EXPECT(dos_object_info(self_proc, &info), 0);
    int64_t v = dos_vmo_create(8192);
    CHECK(v > 0);
    EXPECT(dos_vmo_write((dos_handle_t)v, 0, (void *)KERNEL_ADDR, 64), DOS_ERR_BAD_ADDRESS);
    EXPECT(dos_vmo_read((dos_handle_t)v, 0, (void *)KERNEL_ADDR, 64), DOS_ERR_BAD_ADDRESS);
    EXPECT(dos_vmo_read((dos_handle_t)v, 0, (void *)(uintptr_t)&main, 64), DOS_ERR_BAD_ADDRESS);
    /* A range that starts in mapped memory and runs into unmapped memory fails as a whole. */
    dos_handle_t one;
    char *page = map_new(4096, &one);
    CHECK(page != 0);
    EXPECT(dos_vmo_read((dos_handle_t)v, 0, page + 4000, 200), DOS_ERR_BAD_ADDRESS);
    EXPECT(dos_vmo_read((dos_handle_t)v, 0, page + 4000, 96), 0);
    EXPECT(dos_vmar_allocate(self_vmar, DOS_ANY, 4096, DOS_RIGHTS_SAME, (uint64_t *)KERNEL_ADDR), DOS_ERR_BAD_ADDRESS);
    struct dos_spawn *bad = (struct dos_spawn *)KERNEL_ADDR;
    EXPECT(dos_spawn(bad), DOS_ERR_BAD_ADDRESS);
    EXPECT(dos_object_name(self_proc, (char *)KERNEL_ADDR, 8), DOS_ERR_BAD_ADDRESS);
    EXPECT(dos_object_name(self_proc, buf, sizeof(buf)), 5);    /* "utest" (named by init) */
    dos_handle_close((dos_handle_t)v);
    dos_handle_close(one);
    dos_printf("utest: pointers: kernel, NULL, unmapped, non-canonical, read-only and overflowing ranges rejected\n");
}

static void test_memory(void)
{
    dos_handle_t vmo;
    uint64_t len = 64 * 1024;
    uint8_t *a = map_new(len, &vmo);
    CHECK(a != 0);
    if (!a)
        return;
    for (uint64_t i = 0; i < len; i += 4096)
        a[i] = (uint8_t)(i >> 12);
    uint8_t b = 0;
    EXPECT(dos_vmo_read(vmo, 5 * 4096, &b, 1), 0);
    CHECK(b == 5);
    uint8_t c = 0xAB;
    EXPECT(dos_vmo_write(vmo, 7 * 4096 + 1, &c, 1), 0);
    CHECK(a[7 * 4096 + 1] == 0xAB);
    /* A second mapping of the same VMO shares its pages, at another (random) address. */
    int64_t a2 = dos_vmar_map(self_vmar, DOS_ANY, vmo, 0, len, DOS_RIGHT_READ);
    CHECK(a2 > 0 && (uint8_t *)(uintptr_t)a2 != a);
    if (a2 > 0)
        CHECK(((uint8_t *)(uintptr_t)a2)[7 * 4096 + 1] == 0xAB);
    EXPECT(dos_vmar_map(self_vmar, DOS_ANY, vmo, 0, len, DOS_RIGHT_READ | DOS_RIGHT_EXECUTE), DOS_ERR_ACCESS_DENIED);
    EXPECT(dos_vmar_map(self_vmar, DOS_ANY, vmo, 0, len, DOS_RIGHT_WRITE | DOS_RIGHT_EXECUTE), DOS_ERR_ACCESS_DENIED);
    EXPECT(dos_vmar_map(self_vmar, DOS_ANY, vmo, 0, len + 4096, DOS_RIGHT_READ), DOS_ERR_OUT_OF_RANGE);
    EXPECT(dos_vmar_map(self_vmar, (uint64_t)(uintptr_t)a - 0x200000, vmo, 0, 4096, DOS_RIGHT_READ), DOS_ERR_NO_SPACE);
    /* A read-only VMO handle cannot be mapped writable. */
    int64_t ro = dos_handle_duplicate(vmo, DOS_RIGHT_READ | DOS_RIGHT_MAP);
    EXPECT(dos_vmar_map(self_vmar, DOS_ANY, (dos_handle_t)ro, 0, 4096, DOS_RIGHT_READ | DOS_RIGHT_WRITE), DOS_ERR_ACCESS_DENIED);
    dos_handle_close((dos_handle_t)ro);
    EXPECT(dos_vmar_unmap(self_vmar, (uint64_t)a2, len), 1);
    EXPECT(dos_vmar_unmap(self_vmar, (uint64_t)(uintptr_t)a, len), 1);
    /* Sub-regions and vmar_destroy. */
    uint64_t base = 0;
    int64_t sub = dos_vmar_allocate(self_vmar, DOS_ANY, 1u << 20, DOS_RIGHT_MAP | DOS_RIGHT_READ, &base);
    CHECK(sub > 0 && base >= 0x200000);
    EXPECT(dos_vmar_map((dos_handle_t)sub, 0, vmo, 0, 4096, DOS_RIGHT_READ | DOS_RIGHT_WRITE), DOS_ERR_ACCESS_DENIED);
    EXPECT(dos_vmar_map((dos_handle_t)sub, 0, vmo, 0, 4096, DOS_RIGHT_READ), (int64_t)base);
    EXPECT(dos_vmar_destroy(self_vmar), DOS_ERR_INVALID_ARGS);
    EXPECT(dos_vmar_destroy((dos_handle_t)sub), 0);
    EXPECT(dos_vmar_destroy((dos_handle_t)sub), DOS_ERR_BAD_STATE);
    EXPECT(dos_vmar_map((dos_handle_t)sub, 0, vmo, 0, 4096, DOS_RIGHT_READ), DOS_ERR_BAD_STATE);
    uint64_t base2 = 0;
    int64_t sub2 = dos_vmar_allocate(self_vmar, base - 0x200000, 1u << 20, DOS_RIGHT_MAP | DOS_RIGHT_READ, &base2);
    CHECK(sub2 > 0 && base2 == base);
    EXPECT(dos_vmar_destroy((dos_handle_t)sub2), 0);
    dos_handle_close((dos_handle_t)sub2);
    dos_handle_close((dos_handle_t)sub);
    dos_handle_close(vmo);
    /* Demand paging: sparse 256 KiB VMO faulted from ring 3 and via kernel user_copy. */
    int64_t lv = dos_vmo_create(64u * 4096);
    CHECK(lv > 0);
    int64_t lmap = dos_vmar_map(self_vmar, DOS_ANY, (dos_handle_t)lv, 0, 64u * 4096, DOS_RIGHT_READ | DOS_RIGHT_WRITE);
    CHECK(lmap > 0);
    volatile uint8_t *lp = (volatile uint8_t *)(uintptr_t)lmap;
    CHECK(lp[0] == 0 && lp[63u * 4096] == 0); /* demand-paged zero reads */
    lp[17u * 4096 + 9] = 0x5A;
    CHECK(lp[17u * 4096 + 9] == 0x5A);
    /* Kernel user_copy into an untouched demand-paged page (page 40). */
    static const char tag[] = "demand-copy";
    EXPECT(dos_vmo_write((dos_handle_t)lv, 128, tag, sizeof(tag)), 0);
    EXPECT(dos_vmo_read((dos_handle_t)lv, 128, (void *)(uintptr_t)(lmap + 40u * 4096), sizeof(tag)), 0);
    CHECK(memcmp((const void *)(uintptr_t)(lmap + 40u * 4096), tag, sizeof(tag)) == 0);
    EXPECT(dos_vmar_unmap(self_vmar, (uint64_t)lmap, 64u * 4096), 1);
    dos_handle_close((dos_handle_t)lv);
    /* Quota: a child limited to 1 MiB cannot get more. */
    struct dos_limits small = { 1u << 20, 64, 4 };
    EXPECT(wait_exit(spawn_self("quota", &small, 1), DOS_WAIT_FOREVER), 0);
    struct dos_quota q;
    EXPECT(dos_process_quota(self_proc, &q), 0);
    CHECK(q.used.memory > 0 && q.used.handles > 0 && q.used.threads == 1);
    dos_printf("utest: memory: VMO mapping, shared pages, W^X, no EXECUTE, ASLR placement, sub-regions, quotas\n");
}

/* ---- threads ---------------------------------------------------------------------------------- */

static volatile uint64_t counter;
static int64_t start_ev;

static void worker(uint64_t arg)
{
    dos_object_wait((dos_handle_t)start_ev, DOS_SIGNALED, DOS_WAIT_FOREVER);
    for (int i = 0; i < 10000; i++)
        __atomic_fetch_add(&counter, 1, __ATOMIC_RELAXED);
    dos_thread_exit((int32_t)(100 + arg));
}

static void late_worker(uint64_t code)
{
    int64_t t = dos_timer_create();
    dos_timer_set((dos_handle_t)t, 20000000);
    dos_object_wait((dos_handle_t)t, DOS_SIGNALED, DOS_WAIT_FOREVER);
    dos_thread_exit((int32_t)code);
}

static void test_threads(void)
{
    enum { N = 6 };
    start_ev = dos_event_create();
    int64_t th[N];
    for (int i = 0; i < N; i++) {
        uint8_t *stack = map_new(64 * 1024, 0);
        th[i] = dos_thread_create(self_proc, worker, stack + 64 * 1024, (uint64_t)i);
        CHECK(th[i] > 0);
    }
    struct dos_quota q;
    dos_process_quota(self_proc, &q);
    CHECK(q.used.threads == N + 1);
    dos_event_signal((dos_handle_t)start_ev, 0, DOS_SIGNALED);
    for (int i = 0; i < N; i++) {
        EXPECT(dos_object_wait((dos_handle_t)th[i], DOS_TERMINATED, DOS_WAIT_FOREVER), DOS_TERMINATED);
        EXPECT(dos_thread_exit_code((dos_handle_t)th[i]), 100 + i);
        dos_handle_close((dos_handle_t)th[i]);
    }
    CHECK(counter == N * 10000);
    EXPECT(dos_thread_create(self_proc, worker, (void *)KERNEL_ADDR, 0), DOS_ERR_INVALID_ARGS);
    EXPECT(wait_exit(spawn_self("threads", 0, 1), DOS_WAIT_FOREVER), 7);
    dos_printf("utest: threads: %d threads on all CPUs, exit codes, last thread ends the process\n", N);
}

/* ---- fault isolation, kill --------------------------------------------------------------------- */

static const char *const crashes[] = {
    "null", "kread", "kwrite", "textwrite", "stackexec", "dataexec", "noncanon",
    "ud2", "priv", "ioport", "div0", "int3", "int80", "stackoverflow",
};

static void test_faults(void)
{
    unsigned n = sizeof(crashes) / sizeof(crashes[0]);
    for (unsigned i = 0; i < n; i++) {
        char args[32] = "crash ";
        memcpy(args + 6, crashes[i], strlen(crashes[i]) + 1);
        int64_t code = wait_exit(spawn_self(args, 0, 0), DOS_WAIT_FOREVER);
        if (code != DOS_EXIT_FAULT) {
            dos_printf("utest: FAIL crash %s: exit code %ld, want FAULT\n", crashes[i], code);
            failures++;
        }
    }
    dos_printf("utest: fault isolation: %u kinds of faults each killed only the faulting process\n", n);

    /* Kill: a spinning child, a child blocked in a wait, a child with spinning threads. */
    const char *victims[] = { "spin", "block", "spinthreads" };
    for (unsigned i = 0; i < 3; i++) {
        int64_t p = spawn_self(victims[i], 0, 0);
        CHECK(p > 0);
        int64_t t = dos_timer_create();
        dos_timer_set((dos_handle_t)t, 20000000);
        dos_object_wait((dos_handle_t)t, DOS_SIGNALED, DOS_WAIT_FOREVER);
        dos_handle_close((dos_handle_t)t);
        EXPECT(dos_process_kill((dos_handle_t)p), 0);
        int64_t code = wait_exit(p, 2000000000ull);
        if (code != DOS_EXIT_KILLED) {
            dos_printf("utest: FAIL kill %s: exit code %ld (%s), want KILLED\n", victims[i], code, dos_status(code));
            failures++;
        }
    }
    EXPECT(wait_exit(spawn_self("exit 42", 0, 0), DOS_WAIT_FOREVER), 42);
    dos_printf("utest: kill: spinning, blocked and multi-threaded processes stop at once\n");
}

static void test_spawn(void)
{
    /* Not an executable. */
    int64_t junk = dos_vmo_create(4096);
    char text[64] = "\x7f" "ELF this is not really an executable";
    dos_vmo_write((dos_handle_t)junk, 0, text, sizeof(text));
    struct dos_spawn s = { .parent = self_proc, .image = (dos_handle_t)junk, .name = (uint64_t)(uintptr_t)"junk", .name_len = 4 };
    /* Code signing (ABI v4): an image nobody signed or allowed is refused before it is parsed. */
    EXPECT(dos_spawn(&s), DOS_ERR_NOT_SIGNED);
    EXPECT(dos_vmo_verify((dos_handle_t)junk, (dos_handle_t)junk), DOS_ERR_INVALID_ARGS);   /* no .dsig there */
    EXPECT(dos_vmo_allow_unsigned((dos_handle_t)junk, log_h), DOS_ERR_WRONG_TYPE);          /* not the VMEX resource */
    EXPECT(dos_spawn(&s), DOS_ERR_NOT_SIGNED);
    dos_handle_t vmex = dos_startup_handle(DOS_TAG_VMEX);
    if (vmex) {
        /* The VMEX authority may let unsigned code run: sealed (no more writes), then parsed. */
        EXPECT(dos_vmo_allow_unsigned((dos_handle_t)junk, vmex), 0);
        EXPECT(dos_vmo_write((dos_handle_t)junk, 0, text, 4), DOS_ERR_ACCESS_DENIED);
        EXPECT(dos_spawn(&s), DOS_ERR_INVALID_ARGS);
        dos_printf("utest: code signing: unsigned images refused (NOT_SIGNED); VMEX holders may allow them (sealed)\n");
    } else {
        dos_printf("utest: code signing: unsigned images refused (NOT_SIGNED); no VMEX here\n");
    }
    /* Handles must carry TRANSFER; nothing is consumed when validation fails. */
    int64_t ev = dos_event_create();
    int64_t no_xfer = dos_handle_duplicate((dos_handle_t)ev, DOS_RIGHT_WAIT | DOS_RIGHT_DUPLICATE);
    struct dos_spawn_handle hs[1] = { { (dos_handle_t)no_xfer, DOS_RIGHTS_SAME, DOS_TAG_USER, 0 } };
    s.image = my_image();
    s.handles = (uint64_t)(uintptr_t)hs;
    s.nhandles = 1;
    EXPECT(dos_spawn(&s), DOS_ERR_ACCESS_DENIED);
    EXPECT(dos_handle_close((dos_handle_t)no_xfer), 0);
    /* A handle moved into a child is gone here. */
    hs[0].handle = (dos_handle_t)ev;
    s.args = (uint64_t)(uintptr_t)"exit 3";
    s.args_len = 6;
    int64_t p = dos_spawn(&s);
    CHECK(p > 0);
    EXPECT(dos_handle_close((dos_handle_t)ev), DOS_ERR_BAD_HANDLE);
    EXPECT(wait_exit(p, DOS_WAIT_FOREVER), 3);
    /* No MANAGE on the parent: no spawn. */
    int64_t weak = dos_handle_duplicate(self_proc, DOS_RIGHT_WAIT);
    s.parent = (dos_handle_t)weak;
    s.nhandles = 0;
    EXPECT(dos_spawn(&s), DOS_ERR_ACCESS_DENIED);
    dos_handle_close((dos_handle_t)weak);
    dos_handle_close((dos_handle_t)junk);
    dos_printf("utest: spawn: ELF checked, handles moved (TRANSFER needed), parent needs MANAGE\n");
}

/* ---- FPU -------------------------------------------------------------------------------------- */

static double fpu_work(uint64_t seed)
{
    double x = (double)(seed % 1000) / 7.0, acc = 0;
    for (int i = 1; i < 200000; i++) {
        acc += x / (double)i;
        x = x * 1.0000001 + 0.5;
        if ((i & 1023) == 0)
            dos_yield();
    }
    return acc;
}

static void test_fpu(void)
{
    int64_t p[3];
    for (int i = 0; i < 3; i++) {
        char args[16] = "fpu 1";
        args[4] = (char)('1' + i);
        p[i] = spawn_self(args, 0, 1);
    }
    double mine = fpu_work(7);
    for (int i = 0; i < 3; i++)
        EXPECT(wait_exit(p[i], DOS_WAIT_FOREVER), 0);
    CHECK(mine == fpu_work(7));
    dos_printf("utest: fpu: SSE state kept per thread across switches\n");
}

/* ---- benchmark --------------------------------------------------------------------------------- */

static void bench(void)
{
    enum { N = 20000 };
    for (int i = 0; i < 1000; i++)
        dos_abi_version();
    uint64_t t0 = rdtsc();
    for (int i = 0; i < N; i++)
        dos_abi_version();
    uint64_t null_sc = (rdtsc() - t0) / N;
    int64_t ev = dos_event_create();
    t0 = rdtsc();
    for (int i = 0; i < N; i++) {
        dos_event_signal((dos_handle_t)ev, 0, DOS_SIGNALED);
        dos_object_wait((dos_handle_t)ev, DOS_SIGNALED, 0);
        dos_event_signal((dos_handle_t)ev, DOS_SIGNALED, 0);
    }
    uint64_t evc = (rdtsc() - t0) / N;
    t0 = rdtsc();
    for (int i = 0; i < N; i++)
        dos_handle_close((dos_handle_t)dos_handle_duplicate((dos_handle_t)ev, DOS_RIGHTS_SAME));
    uint64_t dup = (rdtsc() - t0) / N;
    dos_handle_close((dos_handle_t)ev);
    t0 = rdtsc();
    for (int i = 0; i < 200; i++) {
        int64_t v = dos_vmo_create(4096);
        int64_t a = dos_vmar_map(self_vmar, DOS_ANY, (dos_handle_t)v, 0, 4096, DOS_RIGHT_READ | DOS_RIGHT_WRITE);
        *(volatile char *)(uintptr_t)a = 1;
        dos_vmar_unmap(self_vmar, (uint64_t)a, 4096);
        dos_handle_close((dos_handle_t)v);
    }
    uint64_t map = (rdtsc() - t0) / 200;
    dos_printf("BENCH user: null syscall round trip: %lu cycles\n", null_sc);
    dos_printf("BENCH user: event signal+wait+clear (3 syscalls): %lu cycles\n", evc);
    dos_printf("BENCH user: handle duplicate+close (2 syscalls): %lu cycles\n", dup);
    dos_printf("BENCH user: 1-page VMO create+map+touch+unmap+close: %lu cycles\n", map);
}

/* ---- fuzzer ---------------------------------------------------------------------------------- */

static uint64_t rng;
static uint64_t rnd(void)
{
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;
    return rng;
}

static uint8_t fuzz_buf[8192] __attribute__((aligned(64)));

static uint64_t fuzz_arg(dos_handle_t *pool, unsigned npool)
{
    switch (rnd() % 12) {
    case 0: case 1: case 2: return pool[rnd() % npool];                   /* a live handle */
    case 3: return rnd() % 64;                                            /* small number */
    case 4: return (uint64_t)(uintptr_t)fuzz_buf + rnd() % sizeof(fuzz_buf);   /* valid pointer */
    case 5: return KERNEL_ADDR + (rnd() % 0x100000);                      /* kernel pointer */
    case 6: return 0x7FFFFFFF0000ull - (rnd() % 0x2000);                  /* around USER_TOP */
    case 7: return rnd() & 0x00007FFFFFFFF000ull;                         /* random user address */
    case 8: return (uint64_t)-1 - rnd() % 4;                              /* ~0 */
    case 9: return 4096ull << (rnd() % 20);                               /* sizes */
    case 10: return rnd() % 0x400;                                        /* rights-like bits */
    default: return rnd();
    }
}

static int fuzz_child(uint64_t seed, uint64_t n)
{
    rng = seed | 1;
    dos_handle_t pool[64];
    unsigned npool = 0;
    for (uint32_t i = 0; i < dos_start->nhandles && npool < 8; i++)
        pool[npool++] = dos_start->handles[i].handle;
    pool[npool++] = (dos_handle_t)dos_event_create();
    pool[npool++] = (dos_handle_t)dos_timer_create();
    pool[npool++] = (dos_handle_t)dos_vmo_create(16384);
    for (uint64_t i = 0; i < n; i++) {
        uint64_t nr = rnd() % (DOS_SYS_COUNT + 2);
        if (nr == DOS_SYS_PROCESS_EXIT || nr == DOS_SYS_THREAD_EXIT)
            continue;
        if ((nr == DOS_SYS_THREAD_CREATE || nr == DOS_SYS_THREAD_SET_EXCEPTION_HANDLER) && rnd() % 32)
            continue;                         /* a random thread entry / handler kills the process: rarely */
        if (nr == DOS_SYS_PROCESS_EXCEPTION_CHANNEL)
            continue;                         /* its own supervisor would stop it at its first fault, for ever */
        uint64_t a[6];
        for (int k = 0; k < 6; k++)
            a[k] = fuzz_arg(pool, npool);
        if (nr == DOS_SYS_OBJECT_WAIT)
            a[2] = rnd() % 100000;            /* never block for long */
        if (nr == DOS_SYS_CHANNEL_READ || nr == DOS_SYS_CHANNEL_CALL || nr == DOS_SYS_PORT_ENTER)
            a[3] = rnd() % 100000;
        if (nr == DOS_SYS_PROCESS_KILL && a[0] == pool[0])
            continue;                         /* not itself (the parent counts kills anyway) */
        if (nr == DOS_SYS_PROCESS_WRITE_MEMORY && a[0] == pool[0])
            continue;                         /* not into its own stack (it could loop for ever) */
        int64_t r = DOS_SC(nr, a[0], a[1], a[2], a[3], a[4], a[5]);
        int creates = nr == DOS_SYS_EVENT_CREATE || nr == DOS_SYS_TIMER_CREATE || nr == DOS_SYS_VMO_CREATE ||
                      nr == DOS_SYS_HANDLE_DUPLICATE || nr == DOS_SYS_HANDLE_REPLACE || nr == DOS_SYS_VMAR_ALLOCATE ||
                      nr == DOS_SYS_PROCESS_CREATE || nr == DOS_SYS_SPAWN || nr == DOS_SYS_CHANNEL_CREATE ||
                      nr == DOS_SYS_PORT_CREATE || nr == DOS_SYS_VMO_MAKE_EXECUTABLE;
        if (creates && r > 0 && r <= 0xFFFFFFFF) {
            if (npool < 64)
                pool[npool++] = (dos_handle_t)r;
            else
                pool[8 + rnd() % 56] = (dos_handle_t)r;
        }
    }
    return 0;
}

static void fuzz(uint64_t total)
{
    uint64_t per = 2000, done = 0, procs = 0, codes[3] = { 0, 0, 0 };
    struct dos_limits lim = { 16u << 20, 256, 8 };
    uint64_t seed = rdtsc();
    while (done < total) {
        char args[64] = "fuzzchild ";
        char *p = args + 10;
        uint64_t s = seed + procs * 0x9E3779B97F4A7C15ull, tmp = s;
        char digits[24];
        int nd = 0;
        do {
            digits[nd++] = (char)('0' + tmp % 10);
            tmp /= 10;
        } while (tmp);
        while (nd)
            *p++ = digits[--nd];
        memcpy(p, " 2000", 6);
        int64_t code = wait_exit(spawn_self(args, &lim, 0), 30000000000ull);
        if (code == 0)
            codes[0]++;
        else if (code == DOS_EXIT_KILLED)
            codes[1]++;
        else if (code == DOS_EXIT_FAULT)
            codes[2]++;
        else {
            dos_printf("utest: FAIL fuzz child (seed %lu) ended with %ld (%s)\n", s, code, dos_status(code));
            failures++;
        }
        done += per;
        procs++;
    }
    struct dos_quota q;
    dos_process_quota(self_proc, &q);
    CHECK(q.used.threads == 1);
    dos_printf("utest: fuzz: %lu random syscalls in %lu processes (%lu finished, %lu killed, %lu faulted), kernel OK\n",
               done, procs, codes[0], codes[1], codes[2]);
}

/* ---- child modes ------------------------------------------------------------------------------- */

static void spin_thread(uint64_t arg)
{
    (void)arg;
    for (;;)
        __asm__ volatile("pause");
}

__attribute__((noinline)) static int recurse(int n)
{
    volatile char pad[256];
    pad[0] = (char)n;
    if (n < 0)
        return 0;                         /* never: keeps the compiler from proving infinite recursion */
    return recurse(n + 1) + pad[0];
}

/* 0: what the "null" crash dereferences. Volatile and global, so neither the compiler nor the
 * static analyzer treats the deliberate NULL access as a mistake. */
static volatile uintptr_t null_addr = 0;

static int crash(const char *kind)
{
    volatile uint64_t *p;
    if (!strcmp(kind, "null")) {
        p = (volatile uint64_t *)null_addr;     /* a NULL access on purpose (fault isolation test) */
        return (int)*p;
    }
    if (!strcmp(kind, "kread")) {
        p = (volatile uint64_t *)KERNEL_ADDR;
        return (int)*p;
    }
    if (!strcmp(kind, "kwrite")) {
        *(volatile uint64_t *)0xFFFF800000100000ull = 1;
        return 0;
    }
    if (!strcmp(kind, "textwrite")) {
        *(volatile uint8_t *)(uintptr_t)&crash = 0xC3;
        return 0;
    }
    if (!strcmp(kind, "stackexec")) {
        volatile uint8_t code[16] = { 0xC3 };
        ((void (*)(void))(uintptr_t)code)();
        return 0;
    }
    if (!strcmp(kind, "dataexec")) {
        uint8_t *m = map_new(4096, 0);
        m[0] = 0xC3;
        ((void (*)(void))(uintptr_t)m)();
        return 0;
    }
    if (!strcmp(kind, "noncanon")) {
        p = (volatile uint64_t *)NONCANON;
        return (int)*p;
    }
    if (!strcmp(kind, "ud2"))
        __asm__ volatile("ud2");
    if (!strcmp(kind, "priv"))
        __asm__ volatile("cli; hlt");
    if (!strcmp(kind, "ioport"))
        __asm__ volatile("outb %%al, $0x80" : : "a"(0));
    if (!strcmp(kind, "div0")) {
        uint32_t x = 1, zero = 0;          /* a real DIV: C's 1/z may compile to a compare */
        __asm__ volatile("xor %%edx, %%edx; divl %1" : "+a"(x) : "r"(zero) : "rdx");
        return (int)x;
    }
    if (!strcmp(kind, "int3"))
        __asm__ volatile("int3");
    if (!strcmp(kind, "int80"))
        __asm__ volatile("int $0x80");
    if (!strcmp(kind, "stackoverflow"))
        return recurse(0);
    return 1;
}

static int child(const char *a)
{
    if (!strncmp(a, "crash ", 6))
        return crash(word(a, 1)) + 1000;      /* returning at all is a failure */
    if (!strncmp(a, "exit ", 5))
        return (int)parse_u(word(a, 1));
    if (!strcmp(a, "spin"))
        spin_thread(0);
    if (!strcmp(a, "block")) {
        int64_t ev = dos_event_create();
        dos_object_wait((dos_handle_t)ev, DOS_SIGNALED, DOS_WAIT_FOREVER);
        return 1;                             /* woken: only by being killed (never returns) */
    }
    if (!strcmp(a, "spinthreads")) {
        for (int i = 0; i < 3; i++) {
            uint8_t *stack = map_new(16384, 0);
            dos_thread_create(self_proc, spin_thread, stack + 16384, 0);
        }
        spin_thread(0);
    }
    if (!strcmp(a, "threads")) {
        /* The main thread exits first; the process lives on until its last thread ends. */
        uint8_t *stack = map_new(16384, 0);
        dos_thread_create(self_proc, late_worker, stack + 16384, 7);
        dos_thread_exit(5);
    }
    if (!strncmp(a, "fpu ", 4))
        return fpu_work(parse_u(word(a, 1))) == fpu_work(parse_u(word(a, 1))) ? 0 : 1;
    if (!strcmp(a, "quota")) {
        EXPECT(dos_vmo_create(2u << 20), DOS_ERR_NO_RESOURCES);
        int64_t v = dos_vmo_create(64 * 1024);
        CHECK(v > 0);
        int n = 0;
        while (dos_event_create() > 0)
            n++;
        CHECK(n > 0 && n < 64);
        return failures ? 1 : 0;
    }
    if (!strncmp(a, "fuzzchild ", 10))
        return fuzz_child(parse_u(word(a, 1)), parse_u(word(a, 2)));
    if (!strncmp(a, "ipcchild ", 9))
        return ipc_fuzz_child(parse_u(word(a, 1)), parse_u(word(a, 2)));
    if (!strncmp(a, "p10 ", 4))
        return ipc_child(a + 4);
    if (!strncmp(a, "cet ", 4))
        return cet_child(a + 4);
    return 99;
}

int main(void)
{
    self_proc = dos_startup_handle(DOS_TAG_PROC_SELF);
    self_vmar = dos_startup_handle(DOS_TAG_VMAR_ROOT);
    log_h = dos_startup_handle(DOS_TAG_LOG);
    const char *a = dos_args();

    if (!strcmp(a, "smap")) {
        volatile uint64_t secret = 0x5EC12E7;
        dos_printf("utest: asking the kernel to read user memory without STAC (must fault: SMAP)\n");
        DOS_SC(DOS_SYS_KTEST_SMAP, (uintptr_t)&secret, 0, 0, 0, 0, 0);
        dos_printf("utest: FAIL: the kernel read user memory and survived\n");
        return 1;
    }
    if (!strcmp(a, "smep")) {
        dos_printf("utest: asking the kernel to execute user code (must fault: SMEP)\n");
        DOS_SC(DOS_SYS_KTEST_SMEP, (uintptr_t)&spin_thread, 0, 0, 0, 0, 0);
        dos_printf("utest: FAIL: the kernel executed user code and survived\n");
        return 1;
    }
    if (!strncmp(a, "fuzz ", 5)) {
        fuzz(parse_u(word(a, 1)));
        ipc_fuzz(parse_u(word(a, 1)) / 4);
        dos_printf("utest: %s\n", failures ? "FAILED" : "PASSED");
        return failures ? 1 : 0;
    }
    if (!strcmp(a, "bench")) {
        bench();
        bench_ipc();
        dos_printf("utest: bench %s\n", failures ? "FAILED" : "done");
        return failures ? 1 : 0;
    }
    if (!strcmp(a, "attest"))
        return attest_print();
    if (!strcmp(a, "compat")) {
        test_compat();
        return failures ? 1 : 0;
    }
    if (!strcmp(a, "cet")) {
        test_shstk();
        dos_printf("utest: %s (%u failures)\n", failures ? "FAILED" : "PASSED", failures);
        return failures ? 1 : 0;
    }
    if (strcmp(a, "all"))
        return child(a);

    dos_printf("utest: ring-3 ABI tests (process koid via startup handles, ABI v%d)\n", DOS_ABI_VERSION);
    test_basics();
    test_handles();
    test_pointers();
    test_memory();
    test_threads();
    test_spawn();
    test_faults();
    test_fpu();
    test_channels();
    test_ipc_processes();
    test_ports();
    test_exceptions();
    test_supervisor();
    test_bases();
    test_sealing();
    test_avx();
    test_shstk();
    test_attest();
    bench();
    bench_ipc();
    fuzz(20000);
    ipc_fuzz(4000);
    dos_printf("utest: %s (%u failures)\n", failures ? "FAILED" : "PASSED", failures);
    return failures ? 1 : 0;
}
