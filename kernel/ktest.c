/*
 * In-kernel tests. Only compiled into test images (build.ps1 test); see ktest.h.
 *   KTEST_SELFTEST  - runtime library checks (formatting, string routines)
 *   KTEST_PANIC     - KASSERT must panic with location
 *   KTEST_STACKPROT - a stack buffer overflow must be caught by the stack protector
 *   KTEST_PAGEFAULT - an unmapped access must give a decoded #PF report
 *   KTEST_DOUBLEFAULT - a kernel stack overflow must be reported via the #DF IST stack
 *   KTEST_CET       - with CET shadow stacks on (Bochs), an overwritten return address must end
 *                     in #CP, not at the planted address
 *   KTEST_NX        - executing kernel data must fault (NX)
 *   KTEST_WX        - writing kernel code must fault (W^X)
 *   KTEST_KASLR     - the image runs relocated at its random base; the region bases are in their
 *                     windows and used (build.ps1 boots it three times: the layouts must differ)
 *   KTEST_ROINIT    - writing ro-after-init data (the KASLR layout) must fault
 *   KTEST_BOUNDS    - an out-of-bounds array index must trap (-fsanitize=array-bounds, release flags)
 *   KTEST_NULLDEREF - NULL must be unmapped
 *   KTEST_STACKGUARD - a kernel stack overflow must hit the guard page
 *   KTEST_DOUBLEFREE, KTEST_UAF, KTEST_HEAPGUARD - heap hardening must catch misuse
 *   KTEST_RUSTPANIC - a failed kassert! in Rust must be a kernel panic with Rust location
 *   KTEST_DEADLOCK  - re-taking a held spinlock must panic (self-deadlock), not hang
 *   KTEST_LOCKORDER - taking locks against their rank order must panic (lockdep)
 *   KTEST_SCHED     - scheduler: ping-pong, 100 threads, sleep accuracy, priorities, round robin
 *   KTEST_THREADGUARD - a thread's stack overflow must hit its guard page (named in the report)
 *   KTEST_MUTEXDEADLOCK - re-locking a mutex you own must panic, not hang
 *   KTEST_ATOMICSLEEP - blocking while holding a spinlock must panic
 *   KTEST_BENCH     - benchmark harness (allocation, locks, clock, log, Rust, scheduler, SMP)
 *   KTEST_SMP       - multi-core: CPUs online, pinning, cross-CPU locks and wake-ups, TLB shootdown,
 *                     load balancing, migration, per-CPU timers, churn
 *   KTEST_LOCKUP    - a CPU stuck with interrupts off must be caught by the watchdog (NMI backtrace)
 *   KTEST_SOFTLOCKUP - a CPU not switching while work waits must get a soft-lockup warning
 *   KTEST_SOAK      - randomized stress in rounds, with leak checks after each (build.ps1 soak)
 *   KTEST_UBSANTRAP - in a UBSan build, a signed overflow must be caught and named
 *   KTEST_KASANOOB, KTEST_KASANUAF - in a KASAN build, a write past a slab allocation and a read
 *                     of a freed one must be caught and named (kind, size, offset, function)
 *   KTEST_PROFILE   - the sampling profiler finds a known busy function; latency histograms
 *   KTEST_COMPAT    - D-CMPL proofs in ring 3 (init runs "utest compat": W1, L1, PE fuzzing)
 *   KTEST_LIBD      - the user runtime in ring 3 (init runs "ltest": handles, heap, threads,
 *                     mutexes, channels, stack guard pages; ltest runs ctest for the C API)
 *   KTEST_DRIVERS   - user-space drivers (init runs "devmgr test": device ABI, virtio-blk I/O,
 *                     crash + restart, DMA blocked by the IOMMU, interrupts, virtio-input keys)
 *   KTEST_READONLY  - the default storage setup is read-only (init runs "storage readonly": every
 *                     driver refuses a raw write, fstest finds every volume readable, nothing writable)
 *   KTEST_STORAGE   - storage (init runs "storage test": storaged with its test hooks, the AHCI
 *                     and NVMe drivers, then fstest: GPT, FAT32, DFS, snapshots, power cuts,
 *                     corruption detection, namespace isolation)
 *   KTEST_SERVICES  - the service manager (init runs "services test": manifests embedded and
 *                     signed on disk, refusals, exact grants, quotas, restarts with backoff, storaged
 *                     and devmgr killed and restarted with I/O working again, clean shutdown)
 *   KTEST_TIME      - the wall-clock time across a reboot (init "time test"; the host boots twice)
 *   KTEST_SHELL     - the terminal and the shell with writable disks (init "shell test"); the host
 *                     types a session on the keyboard and reads it back on serial
 *   KTEST_OBJECTS   - kernel objects, handles, rights, quotas (Rust), and out-of-memory paths
 *                     proven by fault injection (C threads/heap and the whole object layer)
 * KTEST_SELFTEST also covers locks, the clock, timers, the kernel log, threads and blocking
 * primitives, and the Rust selftest. The single-CPU behaviour tests (selftest, sched, bench) pin
 * themselves to CPU 0 so their ordering expectations hold on any number of CPUs.
 */
#ifdef KTEST

#include <stddef.h>
#include <stdint.h>
#include "ktest.h"
#include "printf.h"
#include "panic.h"
#include "rust.h"
#include "string.h"
#include "compiler.h"
#include "klog.h"

const BootInfo *ktest_bootinfo;

/* Test-only syscalls (kernel/rust/src/user/syscall.rs): the kernel touches user memory without
 * STAC (SMAP must fault) or calls into a user page (SMEP must fault). Both end in a panic. */
void ktest_user_smap(uint64_t user_ptr);
void ktest_user_smep(uint64_t user_ptr);
void ktest_user_smap(uint64_t user_ptr)
{
    kprintf("KTEST smap: kernel reading user address %#llx without STAC\n", (unsigned long long)user_ptr);
    volatile uint64_t v = *(volatile uint64_t *)(uintptr_t)user_ptr;
    kprintf("KTEST smap: FAILED (read %#llx)\n", (unsigned long long)v);
}

void ktest_user_smep(uint64_t user_ptr)
{
    kprintf("KTEST smep: kernel calling user code at %#llx\n", (unsigned long long)user_ptr);
    ((void (*)(void))(uintptr_t)user_ptr)();
    kprintf("KTEST smep: FAILED (user code ran in ring 0)\n");
}

/* What init runs in this test image ("" = just start; see user/init/src/lib.rs). */
const char *ktest_init_args(void)
{
#if defined(KTEST_USER) || defined(KTEST_SPEC)
    return "run utest all";
#elif defined(KTEST_PROFILE)
    return "run utest bench";
#elif defined(KTEST_COMPAT)
    return "run utest compat";
#elif defined(KTEST_LIBD)
    return "run ltest";
#elif defined(KTEST_DRIVERS)
    return "devmgr test";
#elif defined(KTEST_READONLY)
    return "storage readonly";
#elif defined(KTEST_STORAGE)
    return "storage test";
#elif defined(KTEST_SERVICES)
    /* A kernel address in the log: the log service's readers must only ever see it filtered. */
    klog_info("KTEST services: kernel text at %p (readers of the log see [kaddr])", (void *)ktest_init_args);
    return "services test";
#elif defined(KTEST_TIME)
    return "time test";
#elif defined(KTEST_SHELL)
    return "shell test";
#elif defined(KTEST_FUZZ)
    return "run utest fuzz 200000";
#elif defined(KTEST_ATTEST) || defined(KTEST_ATTESTTPM)
    return "run utest attest";
#elif defined(KTEST_HWBENCH)
    return "bench";
#elif defined(KTEST_POWEROFF)
    return "power off";
#elif defined(KTEST_REBOOT)
    return "power reboot";
#elif defined(KTEST_SMAP)
    return "run utest smap";
#elif defined(KTEST_SMEP)
    return "run utest smep";
#else
    return "";
#endif
}

#if defined(KTEST_SELFTEST)

#include "apic.h"
#include "cpu.h"
#include "klog.h"
#include "ktime.h"
#include "mm.h"
#include "rust.h"
#include "spinlock.h"
#include "thread.h"
#include "wait.h"

static int failures;

static void expect_fmt(const char *expect, int expect_ret, const char *got, int ret, int line)
{
    if (strcmp(expect, got) != 0 || ret != expect_ret) {
        kprintf("  FAIL line %d: expected \"%s\" (%d), got \"%s\" (%d)\n", line, expect, expect_ret, got, ret);
        failures++;
    }
}

#define CHECK_FMT(expect, ...)                                               \
    do {                                                                     \
        char b_[64];                                                         \
        int r_ = ksnprintf(b_, sizeof(b_), __VA_ARGS__);                     \
        expect_fmt(expect, (int)strlen(expect), b_, r_, __LINE__);           \
    } while (0)

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            kprintf("  FAIL line %d: %s\n", __LINE__, #cond);                \
            failures++;                                                      \
        }                                                                    \
    } while (0)

static void test_format(void)
{
    CHECK_FMT("-42", "%d", -42);
    CHECK_FMT("4294967295", "%u", 4294967295u);
    CHECK_FMT("-9223372036854775808", "%lld", (long long)INT64_MIN);
    CHECK_FMT("18446744073709551615", "%llu", (unsigned long long)UINT64_MAX);
    CHECK_FMT("deadbeef", "%x", 0xdeadbeefu);
    CHECK_FMT("DEADBEEF", "%X", 0xdeadbeefu);
    CHECK_FMT("0x1f", "%#x", 0x1f);
    CHECK_FMT("0", "%#x", 0);
    CHECK_FMT("000000ff", "%08x", 0xff);
    CHECK_FMT("-0042", "%05d", -42);
    CHECK_FMT("  -42", "%5d", -42);
    CHECK_FMT("-42  |", "%-5d|", -42);
    CHECK_FMT("+7", "%+d", 7);
    CHECK_FMT(" 7", "% d", 7);
    CHECK_FMT("00042", "%.5d", 42);
    CHECK_FMT("", "%.0d", 0);
    CHECK_FMT("   ab", "%5s", "ab");
    CHECK_FMT("abc", "%.3s", "abcdef");
    CHECK_FMT("  abc", "%*.*s", 5, 3, "abcdef");
    CHECK_FMT("(null)", "%s", (const char *)NULL);
    CHECK_FMT("x", "%c", 'x');
    CHECK_FMT("100%", "%d%%", 100);
    CHECK_FMT("0x0000000000001234", "%p", (void *)0x1234);
    CHECK_FMT("123", "%zu", (size_t)123);
    CHECK_FMT("-1", "%hhd", 255);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat"
    CHECK_FMT("%q", "%q");                /* unknown conversions are printed literally */
#pragma clang diagnostic pop

    /* Truncation: output is cut, NUL-terminated, and the full length is still reported. */
    char small[5];
    int r = ksnprintf(small, sizeof(small), "hello world");
    expect_fmt("hell", 11, small, r, __LINE__);
    r = ksnprintf(NULL, 0, "%d", 12345);
    CHECK(r == 5);
}

/* cpu_random64: never the RDRAND erratum values (0, ~0), no repeats in a short run */
static void test_random(void)
{
    uint64_t seen[16];
    for (int i = 0; i < 16; i++) {
        seen[i] = cpu_random64();
        CHECK(seen[i] != 0 && seen[i] != ~0ull);
        for (int j = 0; j < i; j++)
            CHECK(seen[i] != seen[j]);
    }
    CHECK(!cpu.rdrand_broken);           /* QEMU's RDRAND (or none) passes the boot self-check */
}

static void test_string(void)
{
    char a[16];
    memset(a, 'x', sizeof(a));
    CHECK(a[0] == 'x' && a[15] == 'x');

    char m[] = "abcdefgh";
    memmove(m + 2, m, 5);                 /* overlap, dst above src */
    CHECK(memcmp(m, "ababcdeh", 8) == 0);
    char n[] = "abcdefgh";
    memmove(n, n + 2, 5);                 /* overlap, dst below src */
    CHECK(memcmp(n, "cdefgfgh", 8) == 0);

    CHECK(memcmp("abc", "abd", 3) < 0);
    CHECK(memcmp("abd", "abc", 3) > 0);
    CHECK(strlen("") == 0 && strlen("discrete") == 8);
    CHECK(strnlen("discrete", 4) == 4);
    CHECK(strcmp("a", "a") == 0 && strcmp("a", "b") < 0);
}

static void test_memory(void)
{
    /* PMM: allocations are distinct, aligned, and freeing restores the count. */
    uint64_t before = pmm_free_frames();
    uint64_t f1 = pmm_alloc(), f2 = pmm_alloc();
    CHECK(f1 && f2 && f1 != f2 && !(f1 & 0xFFF) && !(f2 & 0xFFF));
    CHECK(f1 >= 0x100000 && f2 >= 0x100000);          /* low memory is never handed out */
    pmm_free(f1);
    pmm_free(f2);
    CHECK(pmm_free_frames() == before);

    /* VMM: kernel image is mapped at the expected physical address; NULL and the identity map are gone. */
    extern char __kernel_start[];
    CHECK(vmm_translate((uint64_t)(uintptr_t)__kernel_start) == KERNEL_PHYS(__kernel_start));
    CHECK(vmm_translate(0) == VMM_NOT_MAPPED);
    CHECK(vmm_translate(0x100000) == VMM_NOT_MAPPED);
    {   /* the direct map covers free memory (not the kernel image: a fixed address would move into it) */
        uint64_t f = pmm_alloc();
        CHECK(f && vmm_translate(PHYSMAP_BASE + f) == f);
        pmm_free(f);
    }

    /* Heap: zeroed, aligned, distinct; sizes across every class and large allocations. */
    static const size_t sizes[] = { 1, 15, 16, 17, 100, 255, 256, 600, 1000, 1024, 1025, 4096, 6000, 20000 };
    void *ptrs[ARRAY_SIZE(sizes)];
    for (size_t i = 0; i < ARRAY_SIZE(sizes); i++) {
        uint8_t *p = kmalloc(sizes[i]);
        ptrs[i] = p;
        CHECK(p != NULL && ((uintptr_t)p & 15) == 0);
        if (!p)
            continue;
        int zero = 1;
        for (size_t k = 0; k < sizes[i]; k++)
            zero &= p[k] == 0;
        CHECK(zero);
        memset(p, (int)i, sizes[i]);
    }
    for (size_t i = 0; i < ARRAY_SIZE(sizes); i++)
        for (size_t j = i + 1; j < ARRAY_SIZE(sizes); j++)
            CHECK(ptrs[i] != ptrs[j]);
    for (size_t i = 0; i < ARRAY_SIZE(sizes); i++)
        if (ptrs[i])
            CHECK(((uint8_t *)ptrs[i])[sizes[i] - 1] == (uint8_t)i);
    for (size_t i = 0; i < ARRAY_SIZE(sizes); i++)
        kfree(ptrs[i]);
    CHECK(kmalloc(0) == NULL);

    /* Freed small objects are reused (LIFO) and come back zeroed. */
    uint8_t *a = kmalloc(32);
    memset(a, 0x55, 32);
    kfree(a);
    uint8_t *b = kmalloc(32);
    CHECK(a == b && b[0] == 0 && b[31] == 0);
    kfree(b);

    /* Many allocations in one class span several slab pages. */
    void *many[300];
    for (int i = 0; i < 300; i++)
        CHECK((many[i] = kmalloc(16)) != NULL);
    for (int i = 0; i < 300; i++)
        kfree(many[i]);
}

static uint64_t read_rflags(void)
{
    uint64_t f;
    __asm__ volatile("pushfq; popq %0" : "=r"(f));
    return f;
}

static void test_locks(void)
{
    static spinlock_t a = SPINLOCK_INIT("ktest.a", LOCK_RANK_TEST);
    static spinlock_t b = SPINLOCK_INIT("ktest.b", LOCK_RANK_LEAF);

    spin_lock(&a);
    CHECK(spin_held_by_me(&a) && spin_held_count() == 1);
    CHECK(!spin_trylock(&a));                  /* held: trylock fails instead of deadlocking */
    spin_lock(&b);                             /* increasing rank: allowed */
    CHECK(spin_held_count() == 2);
    spin_unlock(&b);
    spin_unlock(&a);
    CHECK(!spin_held_by_me(&a) && spin_held_count() == 0);

    /* IRQ-safe variant: interrupts off while held, previous state restored afterwards. */
    CHECK(read_rflags() & (1u << 9));
    uint64_t f = spin_lock_irqsave(&a);
    CHECK(!(read_rflags() & (1u << 9)));
    spin_unlock_irqrestore(&a, f);
    CHECK(read_rflags() & (1u << 9));

    CHECK(spin_trylock(&a));
    spin_unlock(&a);
}

static void test_time(void)
{
    uint64_t t0 = time_ns();
    CHECK(t0 > 0);
    CHECK(time_ns() >= t0);
    tsc_delay_us(2000);
    uint64_t dt = time_ns() - t0;
    CHECK(dt >= 2 * NS_PER_MS && dt < 100 * NS_PER_MS);
    CHECK(time_cycles_to_ns(tsc_hz) > NS_PER_S - NS_PER_MS && time_cycles_to_ns(tsc_hz) < NS_PER_S + NS_PER_MS);
}

static volatile int oneshot_hits, periodic_hits, selfcancel_hits;
static volatile uint64_t oneshot_at;

static void on_oneshot(struct ktimer *t, void *ctx)
{
    (void)t;
    CHECK(ctx == (void *)&oneshot_hits);
    oneshot_at = time_ns();
    oneshot_hits++;
}

static void on_periodic(struct ktimer *t, void *ctx)
{
    (void)t;
    (void)ctx;
    periodic_hits++;
}

static void on_selfcancel(struct ktimer *t, void *ctx)
{
    (void)ctx;
    if (++selfcancel_hits == 3)
        timer_cancel(t);                       /* periodic timer stops itself from its callback */
}

static void wait_ms(uint64_t ms) { thread_sleep_ns(ms * NS_PER_MS); }

static void test_timers(void)
{
    static struct ktimer one, per, self, never;

    uint64_t start = time_ns();
    timer_start_oneshot(&one, 3 * NS_PER_MS, on_oneshot, (void *)&oneshot_hits);
    timer_start_periodic(&per, 1 * NS_PER_MS, on_periodic, NULL);
    timer_start_periodic(&self, 1 * NS_PER_MS, on_selfcancel, NULL);
    timer_start_oneshot(&never, 50 * NS_PER_MS, on_oneshot, NULL);
    CHECK(timer_cancel(&never));               /* cancelled before it fired */
    CHECK(!timer_cancel(&never));

    wait_ms(15);
    CHECK(oneshot_hits == 1);                  /* once, and not early */
    CHECK(oneshot_at - start >= 3 * NS_PER_MS);
    CHECK(periodic_hits >= 5);                 /* 1 ms period over 15 ms; host timer jitter under emulation */
    CHECK(timer_cancel(&per));
    CHECK(selfcancel_hits == 3);
    CHECK(!self.pending);

    int hits = periodic_hits;
    wait_ms(5);
    CHECK(periodic_hits == hits);              /* cancelled: no more calls */
    CHECK(!one.pending && !timer_cancel(&one));
}

static void test_klog(void)
{
    /* C API: a leveled record lands in the ring with its level and text. */
    uint64_t seq = 0;
    struct klog_entry e;
    while (klog_read(&seq, &e))                /* skip to the end */
        ;
    klog_warn("selftest record %d", 42);
    CHECK(klog_read(&seq, &e));
    CHECK(e.level == KLOG_WARN && e.len == 18 && memcmp(e.text, "selftest record 42", 18) == 0);
    CHECK(!klog_read(&seq, &e));

    /* kprintf output is captured line by line. */
    kprintf("selftest captured line\n");
    CHECK(klog_read(&seq, &e));
    CHECK(e.level == KLOG_INFO && e.len == 22 && memcmp(e.text, "selftest captured line", 22) == 0);
}

/* ---- threads and blocking primitives ---- */

static struct kmutex counter_mx = KMUTEX_INIT("ktest.counter");
static volatile uint64_t counter;

static int adder(void *arg)
{
    uintptr_t n = (uintptr_t)arg;
    for (uintptr_t i = 0; i < n; i++) {
        kmutex_lock(&counter_mx);
        uint64_t v = counter;
        if ((i & 7) == 0)
            thread_yield();                    /* others run (and block on the mutex) mid-update */
        counter = v + 1;
        kmutex_unlock(&counter_mx);
    }
    return (int)n;
}

static int set_flag(void *arg)
{
    *(volatile int *)arg = 1;
    return 7;
}

static struct ksem ping = KSEM_INIT("ktest.ping", 0), pong = KSEM_INIT("ktest.pong", 0);

static int ponger(void *arg)
{
    for (uintptr_t i = 0; i < (uintptr_t)arg; i++) {
        ksem_down(&ping);
        ksem_up(&pong);
    }
    return 0;
}

static struct kevent gate = KEVENT_INIT("ktest.gate", 0);
static volatile int passed_gate;

static int gate_waiter(void *arg)
{
    (void)arg;
    kevent_wait(&gate, WAIT_FOREVER);
    __atomic_add_fetch(&passed_gate, 1, __ATOMIC_RELAXED);
    return 0;
}

static bool has(const char *s, const char *sub)
{
    size_t n = strlen(sub);
    for (; *s; s++)
        if (strlen(s) >= n && memcmp(s, sub, n) == 0)
            return true;
    return false;
}

/* BootInfo validation: the real BootInfo passes; each kind of bad hand-over is refused
 * with its own reason. Runs on copies: placed (as far as the checks know) at 0x4000, map at 0x4400. */
static void test_bootinfo(void)
{
    if (!ktest_bootinfo) {
        CHECK(!"no BootInfo");
        return;
    }
    int refused = 0;
    static BootInfo b;
    static MemoryMapEntry m[BOOTINFO_MMAP_MAX];
    const MemoryMapEntry *real = (const MemoryMapEntry *)(uintptr_t)ktest_bootinfo->mmap_addr;
    uint64_t usable = 0;
    for (uint32_t i = 0; i < ktest_bootinfo->mmap_count; i++)
        if (real[i].type == MMAP_USABLE && real[i].base >= 0x100000)
            usable = real[i].base;
#define RESET() do { b = *ktest_bootinfo; b.mmap_addr = 0x4400; memcpy(m, real, sizeof(m)); } while (0)
#define REFUSED(what, mutate)                                                                  \
    do {                                                                                       \
        RESET();                                                                               \
        mutate;                                                                                \
        refused++;                                                                             \
        const char *e_ = bootinfo_check(&b, 0x4000, m);                                        \
        if (!e_ || !has(e_, what)) {                                                            \
            kprintf("  FAIL line %d: expected '%s', got '%s'\n", __LINE__, what, e_ ? e_ : "accepted"); \
            failures++;                                                                        \
        }                                                                                      \
    } while (0)
    RESET();
    CHECK(bootinfo_check(&b, 0x4000, m) == NULL);
    const char *e2 = bootinfo_check(&b, 0x90000, m);
    CHECK(e2 && has(e2, "pointer outside conventional memory"));
    refused++;
    REFUSED("bad BootInfo magic", b.magic ^= 1);
    REFUSED("unsupported BootInfo version", b.version = 2);
    REFUSED("unknown firmware type", b.firmware = 7);
    REFUSED("reserved BootInfo flags", b.flags = 0x80);
    REFUSED("kernel measured but not verified", b.flags = BOOT_KERNEL_MEASURED);
    REFUSED("TPM measurement from a BIOS boot", (b.firmware = BOOT_FW_BIOS, b.efi_system_table = 0, b.fb_type = 0, b.fb_base = b.fb_size = 0, b.fb_width = b.fb_height = b.fb_pitch = 0, b.flags = BOOT_KERNEL_VERIFIED | BOOT_KERNEL_MEASURED));
    REFUSED("kernel signature record is not a .dsig", (b.flags = BOOT_KERNEL_VERIFIED, b.kernel_dsig[0] = (uint8_t)'X'));
    REFUSED("kernel signature record is not for a kernel", (b.flags = BOOT_KERNEL_VERIFIED, b.kernel_dsig[8] = 2));
    REFUSED("for an image of another size", (b.flags = BOOT_KERNEL_VERIFIED, b.kernel_dsig[32] ^= 1));
    REFUSED("UEFI system table from a BIOS boot", (b.firmware = BOOT_FW_BIOS, b.efi_system_table = 0x1000, b.fb_type = 0));
    REFUSED("entry count out of range", b.mmap_count = BOOTINFO_MMAP_MAX + 1);
    REFUSED("memory map outside conventional memory", b.mmap_addr = 0x80000 - 8);
    REFUSED("memory map overlaps BootInfo", b.mmap_addr = 0x4010);
    REFUSED("kernel loaded at wrong address", b.kernel_phys += 0x1000);
    REFUSED("not running where the loader says", b.kernel_virt += 0x200000);
    REFUSED("KASLR fields invalid", b.kaslr_sources = 0);
    REFUSED("KASLR fields invalid", b.kaslr_sources = 0x100);
    REFUSED("KASLR fields invalid", b.reserved0 = 1);
    REFUSED("kernel size does not match", b.kernel_size = 4096);
    REFUSED("empty entry", m[0].length = 0);
    REFUSED("wraps around", (m[0].base = ~0ull - 10, m[0].length = 100));
    REFUSED("kernel is not inside a usable memory region", for (uint32_t i = 0; i < b.mmap_count; i++) if (m[i].type == MMAP_USABLE) m[i].type = MMAP_RESERVED);
    REFUSED("RSDP address out of range", b.rsdp = 0x100000000ull);
    /* framebuffer (as a UEFI boot) */
#define FB() (b.firmware = BOOT_FW_UEFI, b.fb_type = BOOT_FB_RGB32, b.fb_base = 0xFD000000ull, b.fb_width = 800, \
              b.fb_height = 600, b.fb_pitch = 3200, b.fb_size = 3200 * 600, b.fb_red_shift = 16, b.fb_green_shift = 8, \
              b.fb_blue_shift = 0)
    RESET();
    FB();
    CHECK(bootinfo_check(&b, 0x4000, m) == NULL);
    REFUSED("fields set without a framebuffer", (FB(), b.fb_type = 0));
    REFUSED("unknown framebuffer type", (FB(), b.fb_type = 9));
    REFUSED("framebuffer from a BIOS boot", (FB(), b.firmware = BOOT_FW_BIOS, b.efi_system_table = 0));
    REFUSED("framebuffer size out of range", (FB(), b.fb_width = 0));
    REFUSED("framebuffer pitch out of range", (FB(), b.fb_pitch = 3196));
    REFUSED("smaller than its pitch", (FB(), b.fb_size = 4096));
    REFUSED("framebuffer address out of range", (FB(), b.fb_base = ~0ull - 4096));
    REFUSED("channel layout invalid", (FB(), b.fb_green_shift = 16));
    REFUSED("framebuffer overlaps usable RAM", (FB(), b.fb_base = usable));
#undef FB
#undef REFUSED
#undef RESET
    kprintf("  bootinfo: the real BootInfo passes; %d kinds of bad hand-over refused\n", refused);
}

static void test_threads(void)
{
    uint32_t base = thread_count();

    /* create + join, exit codes, mutual exclusion across yields */
    struct thread *t[4];
    counter = 0;
    for (int i = 0; i < 4; i++)
        CHECK((t[i] = thread_create("ktest.adder", adder, (void *)200, THREAD_PRIO_NORMAL)) != NULL);
    int sum = 0;
    for (int i = 0; i < 4; i++)
        sum += thread_join(t[i]);
    CHECK(sum == 800 && counter == 800);
    CHECK(thread_count() == base);

    /* priorities: a higher-priority thread runs before thread_create returns, a lower one only
     * once we block */
    volatile int hi = 0, lo = 0;
    struct thread *h = thread_create("ktest.high", set_flag, (void *)&hi, THREAD_PRIO_HIGH);
    CHECK(hi == 1);
    struct thread *l = thread_create("ktest.low", set_flag, (void *)&lo, THREAD_PRIO_LOW);
    CHECK(lo == 0);
    CHECK(thread_join(l) == 7 && lo == 1);
    CHECK(thread_join(h) == 7);

    /* semaphore ping-pong */
    struct thread *p = thread_create("ktest.pong", ponger, (void *)100, THREAD_PRIO_NORMAL);
    for (int i = 0; i < 100; i++) {
        ksem_up(&ping);
        ksem_down(&pong);
    }
    thread_join(p);
    CHECK(ping.count == 0 && pong.count == 0);

    /* a manual-reset event releases every waiter and stays signaled */
    struct thread *g[3];
    for (int i = 0; i < 3; i++)
        g[i] = thread_create("ktest.gate", gate_waiter, NULL, THREAD_PRIO_NORMAL);
    thread_sleep_ns(NS_PER_MS);
    CHECK(passed_gate == 0);
    kevent_signal(&gate);
    for (int i = 0; i < 3; i++)
        thread_join(g[i]);
    CHECK(passed_gate == 3);
    CHECK(kevent_wait(&gate, 0));
    kevent_reset(&gate);
    CHECK(!kevent_wait(&gate, 0));

    /* timeouts and sleeping */
    struct ksem empty = KSEM_INIT("ktest.empty", 0);
    uint64_t t0 = time_ns();
    CHECK(!ksem_down_timeout(&empty, 3 * NS_PER_MS));
    uint64_t dt = time_ns() - t0;
    CHECK(dt >= 3 * NS_PER_MS && dt < 50 * NS_PER_MS);
    CHECK(!ksem_down_timeout(&empty, 0));
    ksem_up(&empty);
    CHECK(ksem_down_timeout(&empty, 0));
    t0 = time_ns();
    thread_sleep_ns(2 * NS_PER_MS);
    dt = time_ns() - t0;
    CHECK(dt >= 2 * NS_PER_MS && dt < 50 * NS_PER_MS);

    /* detached threads are freed by the reaper */
    for (int i = 0; i < 5; i++)
        thread_detach(thread_create("ktest.detached", set_flag, (void *)&lo, THREAD_PRIO_NORMAL));
    thread_sleep_ns(2 * NS_PER_MS);
    CHECK(thread_count() == base);

    /* every stack has an unmapped guard page below it; a joined thread's stack is unmapped */
    struct thread *s = thread_create("ktest.stack", set_flag, (void *)&lo, THREAD_PRIO_LOW);
    uint64_t top = s->kstack_top;
    CHECK(vmm_translate(s->kstack_guard) == VMM_NOT_MAPPED);
    CHECK(vmm_translate(s->kstack_guard + PAGE_SIZE) != VMM_NOT_MAPPED);
    CHECK(vmm_translate(top - 8) != VMM_NOT_MAPPED);
    thread_join(s);
    CHECK(vmm_translate(top - 8) == VMM_NOT_MAPPED);

    /* mutex trylock / ownership */
    struct kmutex m = KMUTEX_INIT("ktest.m");
    CHECK(kmutex_trylock(&m) && kmutex_held_by_me(&m));
    CHECK(!kmutex_trylock(&m));
    kmutex_unlock(&m);
    CHECK(!kmutex_held_by_me(&m));
}

void ktest_run(void)
{
    kprintf("KTEST selftest: running\n");
    thread_set_affinity(THREAD_CPU(0));          /* ordering checks below assume one CPU */
    test_bootinfo();
    test_format();
    test_string();
    test_random();
    test_memory();
    test_locks();
    test_time();
    test_timers();
    test_klog();
    test_threads();
    failures += (int)rust_selftest();
    thread_set_affinity(THREAD_AFFINITY_ALL);
    if (failures)
        kprintf("KTEST selftest: FAILED (%d)\n", failures);
    else
        kprintf("KTEST selftest: PASSED\n");
}

#elif defined(KTEST_PANIC)

void ktest_run(void)
{
    kprintf("KTEST panic: triggering KASSERT\n");
    volatile int one = 1;
    KASSERT(one == 2);
    kprintf("KTEST panic: FAILED (KASSERT returned)\n");
}

#elif defined(KTEST_STACKPROT)

static NOINLINE void overflow(volatile char *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        p[i] = 'A';
}

static NOINLINE void victim(void)
{
    char buf[16];
    overflow(buf, 64);  /* writes past buf: canary + return address */
}

void ktest_run(void)
{
    kprintf("KTEST stackprot: overflowing a stack buffer\n");
    victim();
    kprintf("KTEST stackprot: FAILED (overflow not detected)\n");
}

#elif defined(KTEST_PAGEFAULT)

void ktest_run(void)
{
    kprintf("KTEST pagefault: reading an unmapped address\n");
    volatile uint64_t *p = (volatile uint64_t *)0x6000000000ull;   /* 384 GiB: never mapped */
    (void)*p;
    kprintf("KTEST pagefault: FAILED (no fault)\n");
}

#elif defined(KTEST_DOUBLEFAULT)

/* Kernel stack overflow: the #PF can't push its frame on the dead stack -> #DF, which must
 * still be reported thanks to its IST stack. */
void ktest_run(void)
{
    kprintf("KTEST doublefault: switching to an unmapped stack\n");
    __asm__ volatile("movq %0, %%rsp\n\tpushq %%rax" : : "r"(0x6000000000ull) : "memory");
    kprintf("KTEST doublefault: FAILED (no fault)\n");
}

#elif defined(KTEST_CET)

#include "cet.h"

static void cet_landing(void)
{
    kprintf("KTEST cet: FAILED (the overwritten return address was used)\n");
    for (;;)
        __asm__ volatile("cli; hlt");
}

/* The CALL puts the return address on both stacks; the stub overwrites the normal stack's copy,
 * as a stack buffer overflow would, and returns: the shadow stack disagrees, so #CP. */
void ktest_run(void)
{
    if (!cet_ss) {
        kprintf("KTEST cet: FAILED (shadow stacks are off on this CPU)\n");
        return;
    }
    kprintf("KTEST cet: shadow stacks on; overwriting a return address\n");
    __asm__ volatile("call 1f\n\t"
                     "jmp 2f\n"
                     "1:\n\t"
                     "movq %0, (%%rsp)\n\t"
                     "ret\n"
                     "2:\n"
                     : : "r"(cet_landing) : "memory");
    kprintf("KTEST cet: FAILED (no fault)\n");
}

#elif defined(KTEST_NX)

#include "cpu.h"

/* Kernel data is mapped RW+NX: executing it (here: a planted RET in .bss) must fault. */
static uint8_t planted_code[64];

void ktest_run(void)
{
    if (!cpu.nx) {
        kprintf("KTEST nx: SKIPPED (CPU has no NX)\n");
        return;
    }
    kprintf("KTEST nx: executing code planted in kernel data\n");
    planted_code[0] = 0xC3;   /* ret */
    void (*fn)(void) = (void (*)(void))(uintptr_t)planted_code;
    fn();
    kprintf("KTEST nx: FAILED (executed non-executable data)\n");
}

#elif defined(KTEST_KASLR)

#include "ksyms.h"
#include "mm.h"
#include "thread.h"

/* Pointers stored in data: right only if the loader applied the image's relocations. Read through
 * volatile so the compiler cannot fold them into RIP-relative addresses. */
static const char *const volatile reloc_probe = __kernel_start;
static void (*const volatile fn_probe)(void) = ktest_run;
static volatile uint64_t thread_local_addr;

static int stack_probe(void *arg)
{
    (void)arg;
    volatile int local = 1;
    thread_local_addr = (uint64_t)(uintptr_t)&local;
    return local;
}

static bool in_window(uint64_t base, uint64_t size, uint64_t lo, uint64_t hi, uint64_t align)
{
    return base >= lo && base + size <= hi && base % align == 0;
}

void ktest_run(void)
{
    int fails = 0;
#define KCHECK(c) do { if (!(c)) { kprintf("  FAIL line %d: %s\n", __LINE__, #c); fails++; } } while (0)
    const struct kernel_layout *l = &kernel_layout;
    uint64_t vb = kernel_vbase();
    kprintf("KTEST kaslr: layout image %#llx direct map %#llx heap %#llx stacks %#llx\n",
            (unsigned long long)vb, (unsigned long long)l->physmap, (unsigned long long)l->heap,
            (unsigned long long)l->kstack);
    /* image: where the loader said, in its window, relocated */
    KCHECK(vb >= KIMAGE_WINDOW && vb < KIMAGE_WINDOW_END && vb % LARGE_PAGE_SIZE == 0);
    KCHECK(ktest_bootinfo && ktest_bootinfo->kernel_virt == (uint64_t)(uintptr_t)__kernel_start);
    KCHECK(reloc_probe == __kernel_start);
    KCHECK(fn_probe == ktest_run);
    uint64_t off = 1;
    const char *name = ksym_lookup((uint64_t)(uintptr_t)kaslr_init, &off);
    KCHECK(name && strcmp(name, "kaslr_init") == 0 && off == 0);
    /* regions: inside their windows, aligned, and actually used */
    KCHECK(in_window(l->physmap, l->physmap_size, PHYSMAP_WINDOW, PHYSMAP_WINDOW_END, 1ull << 30));
    KCHECK(in_window(l->heap, HEAP_SIZE, HEAP_WINDOW, HEAP_WINDOW_END, 1ull << 30));
    KCHECK(in_window(l->kstack, KSTACK_REGION, KSTACK_WINDOW, KSTACK_WINDOW_END, 1ull << 30));
    KCHECK(l->image_bits >= 17 && l->physmap_bits >= 10 && l->heap_bits >= 10 && l->kstack_bits >= 10);
    uint64_t frame = pmm_alloc();
    KCHECK(frame && (uint64_t)(uintptr_t)phys_to_virt(frame) == l->physmap + frame && vmm_translate(l->physmap + frame) == frame);
    if (frame)
        pmm_free(frame);
    void *big = kmalloc(64 * 1024);
    KCHECK(big && (uint64_t)(uintptr_t)big >= l->heap && (uint64_t)(uintptr_t)big < l->heap + HEAP_SIZE);
    kfree(big);
    struct thread *t = thread_create("ktest.kaslr", stack_probe, NULL, THREAD_PRIO_NORMAL);
    KCHECK(t && thread_join(t) == 1);
    KCHECK(thread_local_addr >= l->kstack && thread_local_addr < l->kstack + KSTACK_REGION);
    /* the loader's seed is gone once used */
    int seed_left = 0;
    for (unsigned i = 0; ktest_bootinfo && i < sizeof(ktest_bootinfo->seed); i++)
        seed_left |= ktest_bootinfo->seed[i];
    KCHECK(seed_left == 0);
#undef KCHECK
    if (fails)
        kprintf("KTEST kaslr: FAILED (%d)\n", fails);
    else
        kprintf("KTEST kaslr: PASSED (image moved by %#llx)\n", (unsigned long long)kaslr_offset());
}

#elif defined(KTEST_ROINIT)

#include "mm.h"

/* The KASLR layout (and the stack canary) are read-only once the VMM runs: writing them faults. */
void ktest_run(void)
{
    kprintf("KTEST roinit: writing the KASLR layout after boot\n");
    volatile uint64_t *p = &kernel_layout.heap;
    *p = 0;
    kprintf("KTEST roinit: FAILED (ro-after-init data was writable)\n");
}

#elif defined(KTEST_BOUNDS)

/* Release flags include -fsanitize=array-bounds in trap mode: an out-of-range index into a
 * fixed-size array is a #UD, named in the report, instead of a silent read past the array. */
static int bounds_table[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

static NOINLINE int bounds_read(unsigned i) { return bounds_table[i]; }

void ktest_run(void)
{
    volatile unsigned idx = 8;
    kprintf("KTEST bounds: reading element 8 of an 8-element array\n");
    int v = bounds_read(idx);
    kprintf("KTEST bounds: FAILED (read %d past the end)\n", v);
}

#elif defined(KTEST_WX)

/* Kernel code is mapped read-only: patching it must fault. */
void ktest_run(void)
{
    kprintf("KTEST wx: writing into kernel code\n");
    volatile uint8_t *code = (volatile uint8_t *)(uintptr_t)&ktest_run;
    *code = 0x90;
    kprintf("KTEST wx: FAILED (kernel code was writable)\n");
}

#elif defined(KTEST_NULLDEREF)

void ktest_run(void)
{
    kprintf("KTEST nullderef: dereferencing NULL\n");
    volatile uint64_t *volatile p = NULL;
    (void)*p;
    kprintf("KTEST nullderef: FAILED (NULL page is mapped)\n");
}

#elif defined(KTEST_STACKGUARD)

static volatile int never = -1;

static NOINLINE int recurse(int depth)
{
    volatile char frame[512];
    frame[0] = (char)depth;
    if (depth == never)
        return 0;
    return recurse(depth + 1) + frame[0];
}

/* Unbounded recursion must run into the boot stack's guard page and be reported (via #DF/IST). */
void ktest_run(void)
{
    kprintf("KTEST stackguard: recursing until the stack overflows\n");
    recurse(0);
    kprintf("KTEST stackguard: FAILED (no fault)\n");
}

#elif defined(KTEST_DOUBLEFREE)

#include "mm.h"

void ktest_run(void)
{
    kprintf("KTEST doublefree: freeing a heap object twice\n");
    void *p = kmalloc(48);
    kfree(p);
    kfree(p);
    kprintf("KTEST doublefree: FAILED (not detected)\n");
}

#elif defined(KTEST_UAF)

#include "mm.h"

void ktest_run(void)
{
    kprintf("KTEST uaf: writing to a freed heap object\n");
    volatile uint8_t *p = kmalloc(64);
    kfree((void *)p);
    p[20] = 'X';                     /* use after free */
    void *q = kmalloc(64);           /* reuses the slot: poison check must notice */
    kprintf("KTEST uaf: FAILED (not detected, got %p)\n", q);
}

#elif defined(KTEST_HEAPGUARD)

#include "mm.h"

void ktest_run(void)
{
    kprintf("KTEST heapguard: writing one byte past a large allocation\n");
    volatile uint8_t *p = kmalloc(6000);
    p[6000] = 'X';
    kprintf("KTEST heapguard: FAILED (overflow not detected)\n");
}

#elif defined(KTEST_RUSTPANIC)

#include "rust.h"

void ktest_run(void)
{
    rust_ktest_panic();
    kprintf("KTEST rustpanic: FAILED (Rust panic returned)\n");
}

#elif defined(KTEST_DEADLOCK)

#include "spinlock.h"

void ktest_run(void)
{
    static spinlock_t a = SPINLOCK_INIT("ktest.a", LOCK_RANK_TEST);
    kprintf("KTEST deadlock: taking spinlock 'ktest.a' twice\n");
    spin_lock(&a);
    spin_lock(&a);
    kprintf("KTEST deadlock: FAILED (second acquire returned)\n");
}

#elif defined(KTEST_LOCKORDER)

#include "spinlock.h"

void ktest_run(void)
{
    static spinlock_t low = SPINLOCK_INIT("ktest.low", LOCK_RANK_TEST);
    static spinlock_t high = SPINLOCK_INIT("ktest.high", LOCK_RANK_LEAF);
    kprintf("KTEST lockorder: taking 'ktest.high' then 'ktest.low'\n");
    spin_lock(&high);
    spin_lock(&low);
    kprintf("KTEST lockorder: FAILED (order violation not detected)\n");
}

#elif defined(KTEST_SCHED)

#include "cpu.h"
#include "ktime.h"
#include "percpu.h"
#include "thread.h"
#include "wait.h"

static int failures;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            kprintf("  FAIL line %d: %s\n", __LINE__, #cond);                \
            failures++;                                                      \
        }                                                                    \
    } while (0)

/* --- ping-pong between two threads through semaphores --- */
static struct ksem ping = KSEM_INIT("sched.ping", 0), pong = KSEM_INIT("sched.pong", 0);

static int ponger(void *arg)
{
    for (uintptr_t i = 0; i < (uintptr_t)arg; i++) {
        ksem_down(&ping);
        ksem_up(&pong);
    }
    return 0;
}

static void test_pingpong(void)
{
    const uintptr_t rounds = 5000;
    struct thread *p = thread_create("sched.pong", ponger, (void *)rounds, THREAD_PRIO_NORMAL);
    uint64_t t0 = time_ns();
    for (uintptr_t i = 0; i < rounds; i++) {
        ksem_up(&ping);
        ksem_down(&pong);
    }
    uint64_t dt = time_ns() - t0;
    CHECK(thread_join(p) == 0);
    kprintf("  ping-pong: %llu round trips, %llu ns each\n", (unsigned long long)rounds,
            (unsigned long long)(dt / rounds));
}

/* --- many threads sleeping and sharing a mutex --- */
static struct kmutex many_mx = KMUTEX_INIT("sched.many");
static uint64_t many_counter;

static int many_main(void *arg)
{
    uintptr_t id = (uintptr_t)arg;
    for (int i = 0; i < 10; i++) {
        thread_sleep_ns((id % 4 + 1) * 250 * NS_PER_US);
        kmutex_lock(&many_mx);
        many_counter++;
        kmutex_unlock(&many_mx);
    }
    return (int)id;
}

static int many_quick(void *arg)
{
    (void)arg;
    return 3;
}

static void test_many(void)
{
    enum { N = 100 };
    static struct thread *t[N];
    uint32_t base = thread_count();
    for (uintptr_t i = 0; i < N; i++)
        CHECK((t[i] = thread_create("sched.many", many_main, (void *)i, THREAD_PRIO_NORMAL)) != NULL);
    CHECK(thread_count() == base + N);
    long sum = 0;
    for (int i = 0; i < N; i++)
        sum += thread_join(t[i]);
    CHECK(sum == N * (N - 1) / 2 && many_counter == N * 10);
    CHECK(thread_count() == base);
    kprintf("  many threads: %d threads x 10 sleep+lock rounds OK\n", N);

    /* Regression: create+join in a loop must not grow any thread's stack (each round trip resumes
     * the idle thread with a reschedule pending). */
    for (int i = 0; i < 1000; i++)
        CHECK(thread_join(thread_create("sched.churn", many_quick, NULL, THREAD_PRIO_NORMAL)) == 3);
    CHECK(thread_count() == base);
    kprintf("  churn: 1000 x create+join OK\n");
}

/* --- sleep accuracy, alone and with CPU-bound threads competing --- */
static volatile int stop_busy;

static int busy_main(void *arg)
{
    (void)arg;
    while (!stop_busy)
        cpu_pause();                           /* never blocks or yields: must be preempted */
    return 0;
}

/* Sleep lateness = timer delivery (under emulation: dominated by the host's timer granularity) +
 * wake-to-run latency (the scheduler's part: from the timer waking the thread until it runs). */
static uint64_t sleep_accuracy(const char *what, unsigned prio)
{
    struct thread *me = thread_current();
    unsigned saved = me->prio;
    me->prio = (uint8_t)prio;                  /* we are running, so not queued: safe to change */
    uint64_t max_late = 0, total_late = 0, max_w2r = 0, total_w2r = 0;
    const int n = 40;
    for (int i = 0; i < n; i++) {
        uint64_t want = (uint64_t)(i % 8 + 1) * 250 * NS_PER_US;   /* 0.25 .. 2 ms */
        uint64_t t0 = time_ns();
        thread_sleep_ns(want);
        uint64_t now = time_ns();
        uint64_t got = now - t0, w2r = now - me->woken_ns;
        CHECK(got >= want);
        uint64_t late = got - want;
        total_late += late;
        total_w2r += w2r;
        if (late > max_late)
            max_late = late;
        if (w2r > max_w2r)
            max_w2r = w2r;
    }
    me->prio = (uint8_t)saved;
    kprintf("  sleep (%s): %d sleeps, late mean %llu us max %llu us; wake-to-run mean %llu us max %llu us\n",
            what, n, (unsigned long long)(total_late / n / NS_PER_US), (unsigned long long)(max_late / NS_PER_US),
            (unsigned long long)(total_w2r / n / NS_PER_US), (unsigned long long)(max_w2r / NS_PER_US));
    CHECK(max_late < 10 * NS_PER_MS);          /* bounded even with host timer jitter */
    return max_w2r;
}

static void test_sleep(void)
{
    CHECK(sleep_accuracy("idle system", THREAD_PRIO_NORMAL) < 500 * NS_PER_US);

    stop_busy = 0;
    struct thread *b1 = thread_create("sched.busy", busy_main, NULL, THREAD_PRIO_NORMAL);
    struct thread *b2 = thread_create("sched.busy", busy_main, NULL, THREAD_PRIO_NORMAL);
    /* A higher-priority sleeper preempts CPU-bound threads as soon as its timer fires: its
     * wake-to-run latency stays far below the 5 ms slice the busy threads would otherwise get. */
    CHECK(sleep_accuracy("2 busy threads, sleeper HIGH", THREAD_PRIO_HIGH) < 500 * NS_PER_US);
    stop_busy = 1;
    thread_join(b1);
    thread_join(b2);
}

/* --- priority order and round robin --- */
static struct kevent start_gate = KEVENT_INIT("sched.gate", 0);
static volatile int finish_seq;

struct spin_job {
    uint64_t spin_ns;
    int      finished_as;
    int      preempted;      /* times this thread saw a gap of > 1 ms in its own execution */
};

static int spin_main(void *arg)
{
    struct spin_job *j = arg;
    kevent_wait(&start_gate, WAIT_FOREVER);
    uint64_t start = time_ns(), last = start;
    while (time_ns() - start < j->spin_ns) {
        uint64_t now = time_ns();
        if (now - last > NS_PER_MS)
            j->preempted++;
        last = now;
    }
    j->finished_as = __atomic_add_fetch(&finish_seq, 1, __ATOMIC_RELAXED);
    return 0;
}

static void test_priority(void)
{
    /* LOW, NORMAL, HIGH released together: they finish in priority order. */
    static struct spin_job jobs[3];
    static const unsigned prios[3] = { THREAD_PRIO_LOW, THREAD_PRIO_NORMAL, THREAD_PRIO_HIGH };
    struct thread *t[3];
    finish_seq = 0;
    kevent_reset(&start_gate);
    for (int i = 0; i < 3; i++) {
        jobs[i] = (struct spin_job){ .spin_ns = 10 * NS_PER_MS };
        t[i] = thread_create("sched.prio", spin_main, &jobs[i], prios[i]);
    }
    thread_sleep_ns(NS_PER_MS);                /* all three are now blocked on the gate */
    kevent_signal(&start_gate);
    for (int i = 0; i < 3; i++)
        thread_join(t[i]);
    CHECK(jobs[2].finished_as == 1 && jobs[1].finished_as == 2 && jobs[0].finished_as == 3);
    kprintf("  priority: finished HIGH=%d NORMAL=%d LOW=%d\n", jobs[2].finished_as, jobs[1].finished_as,
            jobs[0].finished_as);

    /* Two equal-priority CPU-bound threads share the CPU in 5 ms slices. */
    static struct spin_job rr[2];
    kevent_reset(&start_gate);
    for (int i = 0; i < 2; i++) {
        rr[i] = (struct spin_job){ .spin_ns = 40 * NS_PER_MS };
        t[i] = thread_create("sched.rr", spin_main, &rr[i], THREAD_PRIO_NORMAL);
    }
    thread_sleep_ns(NS_PER_MS);
    kevent_signal(&start_gate);
    thread_join(t[0]);
    thread_join(t[1]);
    CHECK(rr[0].preempted >= 2 && rr[1].preempted >= 2);
    kprintf("  round robin: 2 threads x 40 ms, preempted %d and %d times\n", rr[0].preempted, rr[1].preempted);
}

void ktest_run(void)
{
    kprintf("KTEST sched: running\n");
    thread_set_affinity(THREAD_CPU(0));          /* single-CPU semantics (priority order, slices) */
    test_pingpong();
    test_many();
    test_sleep();
    test_priority();
    thread_set_affinity(THREAD_AFFINITY_ALL);
    uint64_t sw = 0, pre = 0, irq = 0;
    for (uint32_t c = 0; c < cpu_slots; c++) {
        if (cpus[c]) {
            sw += cpus[c]->switches;
            pre += cpus[c]->preemptions;
            irq += cpus[c]->irqs;
        }
    }
    kprintf("  stats: %llu context switches, %llu preemptions, %llu interrupts\n",
            (unsigned long long)sw, (unsigned long long)pre, (unsigned long long)irq);
    if (failures)
        kprintf("KTEST sched: FAILED (%d)\n", failures);
    else
        kprintf("KTEST sched: PASSED\n");
}

#elif defined(KTEST_THREADGUARD)

#include "thread.h"

static volatile int never = -1;

static NOINLINE int recurse(int depth)
{
    volatile char frame[512];
    frame[0] = (char)depth;
    if (depth == never)
        return 0;
    return recurse(depth + 1) + frame[0];
}

static int overflow_main(void *arg)
{
    (void)arg;
    return recurse(0);
}

/* A thread's unbounded recursion must hit the guard page below its own stack. */
void ktest_run(void)
{
    kprintf("KTEST threadguard: overflowing the stack of thread 'ktest.recurse'\n");
    thread_join(thread_create("ktest.recurse", overflow_main, NULL, THREAD_PRIO_NORMAL));
    kprintf("KTEST threadguard: FAILED (no fault)\n");
}

#elif defined(KTEST_MUTEXDEADLOCK)

#include "wait.h"

void ktest_run(void)
{
    static struct kmutex m = KMUTEX_INIT("ktest.m");
    kprintf("KTEST mutexdeadlock: locking mutex 'ktest.m' twice\n");
    kmutex_lock(&m);
    kmutex_lock(&m);
    kprintf("KTEST mutexdeadlock: FAILED (second lock returned)\n");
}

#elif defined(KTEST_ATOMICSLEEP)

#include "spinlock.h"
#include "thread.h"

void ktest_run(void)
{
    static spinlock_t a = SPINLOCK_INIT("ktest.a", LOCK_RANK_TEST);
    kprintf("KTEST atomicsleep: sleeping while holding spinlock 'ktest.a'\n");
    spin_lock(&a);
    thread_sleep_ns(NS_PER_MS);
    kprintf("KTEST atomicsleep: FAILED (slept with a spinlock held)\n");
}

#elif defined(KTEST_BENCH) || defined(KTEST_HWBENCH)

#include "bench.h"
#include "console.h"
#include "smp.h"
#include "cpu.h"
#include "klog.h"
#include "ktime.h"
#include "mm.h"
#include "rust.h"
#include "spec.h"
#include "spinlock.h"
#include "thread.h"
#include "wait.h"

static void b_kmalloc32(void *ctx) { (void)ctx; kfree(kmalloc(32)); }

/* The parts of a switch between two processes (a cross-process call makes two): what each costs
 * on this CPU, to see where a call's time goes. */
static uint8_t b_fpu_area[16384] __attribute__((aligned(64)));
static void b_ibpb(void *ctx) { (void)ctx; spec_ibpb(); }
static void b_cr3(void *ctx)
{
    (void)ctx;
    uint64_t v;
    __asm__ volatile("mov %%cr3, %0\n\tmov %0, %%cr3" : "=r"(v) : : "memory");   /* drops every non-global TLB entry */
}
static void b_fpu(void *ctx) { (void)ctx; fpu_save(b_fpu_area); fpu_restore(b_fpu_area); }
static void b_kmalloc8k(void *ctx) { (void)ctx; kfree(kmalloc(8192)); }
static void b_pmm(void *ctx) { (void)ctx; pmm_free(pmm_alloc()); }
static void b_time(void *ctx) { *(volatile uint64_t *)ctx = time_ns(); }

static spinlock_t bench_lk = SPINLOCK_INIT("bench", LOCK_RANK_TEST);
static void b_spin(void *ctx) { (void)ctx; spin_lock(&bench_lk); spin_unlock(&bench_lk); }
static void b_spin_irq(void *ctx) { (void)ctx; spin_unlock_irqrestore(&bench_lk, spin_lock_irqsave(&bench_lk)); }

/* Scheduler: a partner thread at the same priority yields back, or answers through semaphores. */
static volatile int partner_stop;
static struct ksem b_ping = KSEM_INIT("bench.ping", 0), b_pong = KSEM_INIT("bench.pong", 0);
static struct kmutex b_mx = KMUTEX_INIT("bench.mx");

static int yielder(void *arg) { (void)arg; while (!partner_stop) thread_yield(); return 0; }
static int ponger(void *arg)
{
    (void)arg;
    for (;;) {
        ksem_down(&b_ping);
        if (partner_stop)
            return 0;
        ksem_up(&b_pong);
    }
}
static int nothing(void *arg) { (void)arg; return 0; }

static void b_yield(void *ctx) { (void)ctx; thread_yield(); }
static void b_pingpong(void *ctx) { (void)ctx; ksem_up(&b_ping); ksem_down(&b_pong); }
static void b_create_join(void *ctx) { (void)ctx; thread_join(thread_create("bench.t", nothing, NULL, THREAD_PRIO_NORMAL)); }
static void b_mutex(void *ctx) { (void)ctx; kmutex_lock(&b_mx); kmutex_unlock(&b_mx); }

/* SMP: partners pinned to CPU 1 while the benchmark runs on CPU 0. */
static int remote_ponger(void *arg) { return ponger(arg); }
static uint64_t tlb_va;
static void b_shootdown(void *ctx)
{
    (void)ctx;
    uint64_t pa = pmm_alloc();
    vmm_map_page(tlb_va, pa, VMM_W);
    *(volatile uint64_t *)tlb_va = 1;           /* this CPU caches the translation */
    vmm_unmap_free(tlb_va, 1);                  /* unmap + flush on every CPU + free */
}

static void ms_line(const char *what, uint64_t cycles)
{
    uint64_t us = time_cycles_to_ns(cycles) / NS_PER_US;
    kprintf("BENCH %s: %llu.%03llu ms\n", what, (unsigned long long)(us / 1000), (unsigned long long)(us % 1000));
}

void ktest_run(void)
{
    volatile uint64_t sink;
#ifdef KTEST_HWBENCH
    kprintf("KTEST bench: running (hardware benchmark image: lock-order checking off)\n");
#else
    kprintf("KTEST bench: running (test build: lock-order checking adds to lock costs)\n");
#endif
    thread_set_affinity(THREAD_CPU(0));          /* partners share CPU 0 unless pinned elsewhere */
    if (ktest_bootinfo)
        ms_line("boot stage 1 -> kernel entry", kernel_entry_tsc - ktest_bootinfo->tsc_stage1);
    ms_line("kernel entry -> tests", rdtsc() - kernel_entry_tsc);
    bench_run("kmalloc+kfree 32 B", b_kmalloc32, NULL, 20000);
    bench_run("kmalloc+kfree 8 KiB (guard-paged)", b_kmalloc8k, NULL, 2000);
    bench_run("pmm_alloc+pmm_free", b_pmm, NULL, 20000);
    bench_run("spin_lock+unlock", b_spin, NULL, 20000);
    bench_run("spin_lock_irqsave+restore", b_spin_irq, NULL, 20000);
    bench_run("time_ns", b_time, (void *)&sink, 20000);
    bench_run("rust Box alloc+free 32 B", rust_bench_box, NULL, 20000);
    bench_run("rust SpinLock lock+unlock", rust_bench_spinlock, NULL, 20000);
#ifndef KTEST_HWBENCH   /* 20 000 records would overwrite the log the results screen is made from */
    bench_run("klog record (capture)", rust_bench_klog, NULL, 20000);
#endif

    bench_run("kmutex lock+unlock (uncontended)", b_mutex, NULL, 20000);
    /* A process switch: CR3 (with the TLB refills after it), the user FPU state, and IBPB where
     * the mitigation is on. Each cross-process call does two switches. */
    bench_run("switch part: CR3 reload (non-global TLB flush)", b_cr3, NULL, 20000);
    if (cpu.fpu_size <= sizeof(b_fpu_area)) {
        char what[96];
        ksnprintf(what, sizeof(what), "switch part: FPU state save+restore (%u bytes)", cpu.fpu_size);
        bench_run(what, b_fpu, NULL, 20000);
    }
    if (spec.mitig & MIT_IBPB)
        bench_run("switch part: IBPB (between processes)", b_ibpb, NULL, 20000);
    else
        kprintf("BENCH switch part: IBPB (between processes): off on this CPU\n");
    partner_stop = 0;
    struct thread *y = thread_create("bench.yield", yielder, NULL, THREAD_PRIO_NORMAL);
    bench_run("thread_yield round trip (2 context switches)", b_yield, NULL, 20000);
    partner_stop = 1;
    thread_join(y);
    partner_stop = 0;
    struct thread *p = thread_create("bench.pong", ponger, NULL, THREAD_PRIO_NORMAL);
    bench_run("semaphore ping-pong round trip (2 block+wake)", b_pingpong, NULL, 20000);
    partner_stop = 1;
    ksem_up(&b_ping);
    thread_join(p);
    bench_run("thread_create+join (16 KiB stack)", b_create_join, NULL, 2000);
    bench_run("rust spawn+join (closure)", rust_bench_spawn, NULL, 2000);
    rust_bench_objects_init();
    bench_run("handle lookup + rights check", rust_bench_handle_lookup, NULL, 20000);
    bench_run("handle duplicate+close", rust_bench_handle_dup_close, NULL, 20000);
    bench_run("event signal+wait+clear (no block)", rust_bench_event_signal_wait, NULL, 20000);
    bench_run("vmo create+close (1 page)", rust_bench_vmo_create_close, NULL, 20000);

    if (smp_cpus() >= 2) {
        partner_stop = 0;
        p = thread_create_on("bench.rpong", remote_ponger, NULL, THREAD_PRIO_NORMAL, THREAD_CPU(1));
        bench_run("cross-CPU semaphore ping-pong (CPU 0 <-> 1)", b_pingpong, NULL, 20000);
        partner_stop = 1;
        ksem_up(&b_ping);
        thread_join(p);
        tlb_va = HEAP_BASE + HEAP_SIZE - 16 * PAGE_SIZE;    /* never reached by the heap */
        char what[96];
        ksnprintf(what, sizeof(what), "map+unmap 1 page with TLB shootdown (%u CPUs)", smp_cpus());
        bench_run(what, b_shootdown, NULL, 2000);
    }
    thread_set_affinity(THREAD_AFFINITY_ALL);
    kprintf("KTEST bench: DONE\n");
}

#ifdef KTEST_HWBENCH
/* The results screen (docs/benchmarks.md): after init has run the user and storage benchmarks,
 * the screen is cleared and every "BENCH " line from the kernel log (kernel and user space alike)
 * is shown on one page with the machine's identity, ready to be photographed. Serial gets the
 * same text. The machine then idles: switch it off with the power button. */
static bool starts(const struct klog_entry *e, const char *p)
{
    size_t n = strlen(p);
    return e->len >= n && memcmp(e->text, p, n) == 0;
}

static void show(const struct klog_entry *e, size_t skip)
{
    kprintf("  %.*s\n", (int)(e->len - skip), e->text + skip);
}

void ktest_after_init(int code)
{
    static const char *const head[] = { "D-KRNL ", "Summary: ", "TSC: ", "Boot: ", "D-KRNL: ready" };
    uint64_t calls = 0, moved = 0;
    channel_call_stats(&calls, &moved);
    kprintf("BENCH user: channel calls that involved another CPU: %llu of %llu\n", (unsigned long long)moved, (unsigned long long)calls);
    struct klog_entry e;
    uint64_t seq = 0;
    unsigned n = 0;
    console_clear();
    kprintf("D-OS hardware benchmark results (best batch per test; cycles are TSC cycles)\n");
    for (size_t h = 0; h < sizeof(head) / sizeof(head[0]); h++) {
        for (seq = 0; klog_read(&seq, &e);)
            if (starts(&e, head[h]))
                show(&e, 0);
    }
    kprintf("Results:\n");
    for (seq = 0; klog_read(&seq, &e);) {
        if (starts(&e, "BENCH ") && !starts(&e, "BENCH boot stage") && !starts(&e, "BENCH kernel entry")) {
            show(&e, 6);
            n++;
        }
    }
    kprintf("%u results, %llu log records lost; init exited with code %d. Done: switch off with the power button.\n",
            n, (unsigned long long)klog_dropped(), code);
    kprintf("KTEST hwbench: %s\n", code == 0 && n >= 20 && !klog_dropped() ? "DONE" : "INCOMPLETE");
}
#endif

#elif defined(KTEST_SMP)

#include "cpu.h"
#include "ktime.h"
#include "mm.h"
#include "percpu.h"
#include "smp.h"
#include "spinlock.h"
#include "thread.h"
#include "wait.h"

static int failures;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            kprintf("  FAIL line %d: %s\n", __LINE__, #cond);                \
            failures++;                                                      \
        }                                                                    \
    } while (0)

static uint32_t ncpu;

/* --- every CPU runs a thread pinned to it --- */
static int where_main(void *arg)
{
    (void)arg;
    return (int)thread_cpu();
}

static void test_pinning(void)
{
    for (uint32_t c = 0; c < ncpu; c++) {
        struct thread *t = thread_create_on("smp.where", where_main, NULL, THREAD_PRIO_NORMAL, THREAD_CPU(c));
        CHECK(t && thread_join(t) == (int)c);
    }
    /* Migrating the current thread */
    for (uint32_t c = ncpu; c-- > 0;) {
        CHECK(thread_set_affinity(THREAD_CPU(c)));
        CHECK(thread_cpu() == c);
    }
    CHECK(!thread_set_affinity(0));
    thread_set_affinity(THREAD_AFFINITY_ALL);
    kprintf("  pinning: a thread ran on each of %u CPUs; kmain migrated across all of them\n", ncpu);
}

/* --- shared counters: spinlock, mutex and atomics from every CPU at once --- */
static spinlock_t cnt_lk = SPINLOCK_INIT("smp.cnt", LOCK_RANK_TEST);
static struct kmutex cnt_mx = KMUTEX_INIT("smp.cnt");
static volatile uint64_t spin_count, mutex_count;
static uint64_t atomic_count;
static struct kevent go = KEVENT_INIT("smp.go", 0);

static int counter_main(void *arg)
{
    uintptr_t n = (uintptr_t)arg;
    kevent_wait(&go, WAIT_FOREVER);
    for (uintptr_t i = 0; i < n; i++) {
        uint64_t f = spin_lock_irqsave(&cnt_lk);
        spin_count++;
        spin_unlock_irqrestore(&cnt_lk, f);
        __atomic_add_fetch(&atomic_count, 1, __ATOMIC_RELAXED);
        if ((i & 7) == 0) {
            kmutex_lock(&cnt_mx);
            mutex_count++;
            kmutex_unlock(&cnt_mx);
        }
    }
    return 0;
}

static void test_counters(void)
{
    const uintptr_t n = 50000;
    struct thread *t[MAX_CPUS];
    kevent_reset(&go);
    for (uint32_t c = 0; c < ncpu; c++)
        t[c] = thread_create_on("smp.count", counter_main, (void *)n, THREAD_PRIO_NORMAL, THREAD_CPU(c));
    uint64_t t0 = time_ns();
    kevent_signal(&go);
    for (uint32_t c = 0; c < ncpu; c++)
        thread_join(t[c]);
    uint64_t dt = time_ns() - t0;
    CHECK(spin_count == n * ncpu && atomic_count == n * ncpu && mutex_count == (n / 8) * ncpu);
    kprintf("  counters: %u CPUs x %llu spinlock/atomic + %llu mutex increments, exact (%llu ms)\n", ncpu,
            (unsigned long long)n, (unsigned long long)(n / 8), (unsigned long long)(dt / NS_PER_MS));
}

/* --- cross-CPU ping-pong: every round trip is two IPI wake-ups --- */
static struct ksem ping = KSEM_INIT("smp.ping", 0), pong = KSEM_INIT("smp.pong", 0);

static int ponger(void *arg)
{
    for (uintptr_t i = 0; i < (uintptr_t)arg; i++) {
        ksem_down(&ping);
        ksem_up(&pong);
    }
    return 0;
}

static void test_pingpong(void)
{
    const uintptr_t rounds = 10000;
    thread_set_affinity(THREAD_CPU(0));
    struct thread *p = thread_create_on("smp.pong", ponger, (void *)rounds, THREAD_PRIO_NORMAL, THREAD_CPU(ncpu - 1));
    uint64_t t0 = time_ns();
    for (uintptr_t i = 0; i < rounds; i++) {
        ksem_up(&ping);
        ksem_down(&pong);
    }
    uint64_t dt = time_ns() - t0;
    CHECK(thread_join(p) == 0);
    thread_set_affinity(THREAD_AFFINITY_ALL);
    kprintf("  cross-CPU ping-pong: CPU 0 <-> CPU %u, %llu round trips, %llu ns each\n", ncpu - 1,
            (unsigned long long)rounds, (unsigned long long)(dt / rounds));
}

/* --- TLB shootdown: remapping a page must be seen by every CPU at once ---
 * Each round maps the test address to the other of two frames, holding the round number. Workers
 * on the other CPUs read it every round, so their TLBs hold the old translation; without a
 * shootdown they would read the previous round's frame. */
#define TLB_ROUNDS 300
static uint64_t tlb_va;
static volatile uint32_t tlb_round, tlb_acks, tlb_bad;

static int tlb_reader(void *arg)
{
    (void)arg;
    for (uint32_t r = 1; r <= TLB_ROUNDS; r++) {
        while (__atomic_load_n(&tlb_round, __ATOMIC_ACQUIRE) < r)
            cpu_pause();
        if (*(volatile uint64_t *)tlb_va != r)
            __atomic_add_fetch(&tlb_bad, 1, __ATOMIC_RELAXED);
        __atomic_add_fetch(&tlb_acks, 1, __ATOMIC_RELEASE);
    }
    return 0;
}

/* Lazy variant: readers block between rounds, so their CPUs are idle (lazy) during the remap and are
 * skipped by the shootdown; they must flush on wake-up before reading. */
static struct ksem lazy_go[MAX_CPUS];

static int tlb_sleepy_reader(void *arg)
{
    uint32_t c = (uint32_t)(uintptr_t)arg;
    for (uint32_t r = 1; r <= TLB_ROUNDS; r++) {
        ksem_down(&lazy_go[c]);
        if (*(volatile uint64_t *)tlb_va != r)
            __atomic_add_fetch(&tlb_bad, 1, __ATOMIC_RELAXED);
        __atomic_add_fetch(&tlb_acks, 1, __ATOMIC_RELEASE);
    }
    return 0;
}

static void tlb_rounds(uint64_t frame[2], bool sleepy)
{
    for (uint32_t r = 1; r <= TLB_ROUNDS; r++) {
        if (r > 1)
            vmm_unmap_page(tlb_va);                         /* flushes every CPU before returning */
        *(volatile uint64_t *)phys_to_virt(frame[r & 1]) = r;
        vmm_map_page(tlb_va, frame[r & 1], VMM_W);
        __atomic_store_n(&tlb_acks, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&tlb_round, r, __ATOMIC_RELEASE);
        if (sleepy)
            for (uint32_t c = 1; c < ncpu; c++)
                ksem_up(&lazy_go[c]);
        while (__atomic_load_n(&tlb_acks, __ATOMIC_ACQUIRE) < ncpu - 1)
            cpu_pause();
        if (sleepy)
            thread_sleep_ns(200 * NS_PER_US);              /* let the readers' CPUs go idle again */
    }
}

static void test_tlb(void)
{
    thread_set_affinity(THREAD_CPU(0));
    tlb_va = HEAP_BASE + HEAP_SIZE - 64 * PAGE_SIZE;        /* never reached by the heap */
    uint64_t frame[2] = { pmm_alloc_zeroed(), pmm_alloc_zeroed() };
    struct thread *t[MAX_CPUS];
    uint64_t before = smp_shootdowns();
    for (uint32_t c = 1; c < ncpu; c++)
        t[c] = thread_create_on("smp.tlb", tlb_reader, NULL, THREAD_PRIO_NORMAL, THREAD_CPU(c));
    tlb_rounds(frame, false);
    for (uint32_t c = 1; c < ncpu; c++)
        thread_join(t[c]);
    vmm_unmap_page(tlb_va);
    uint32_t busy_bad = tlb_bad;
    uint64_t busy_shootdowns = smp_shootdowns() - before;

    /* Idle CPUs: skipped (no IPI) and flushed when they wake. */
    uint64_t skips0 = smp_lazy_skips();
    __atomic_store_n(&tlb_round, 0, __ATOMIC_RELAXED);
    for (uint32_t c = 1; c < ncpu; c++) {
        ksem_init(&lazy_go[c], "smp.lazy", 0);
        t[c] = thread_create_on("smp.lazy", tlb_sleepy_reader, (void *)(uintptr_t)c, THREAD_PRIO_NORMAL, THREAD_CPU(c));
    }
    thread_sleep_ns(NS_PER_MS);
    tlb_rounds(frame, true);
    for (uint32_t c = 1; c < ncpu; c++)
        thread_join(t[c]);
    vmm_unmap_page(tlb_va);
    uint64_t skips = smp_lazy_skips() - skips0;
    pmm_free(frame[0]);
    pmm_free(frame[1]);
    thread_set_affinity(THREAD_AFFINITY_ALL);
    CHECK(busy_bad == 0 && tlb_bad == 0);
    CHECK(busy_shootdowns >= TLB_ROUNDS - 1);
    CHECK(skips > 0);
    kprintf("  TLB shootdown: %d remaps seen at once by %u other CPUs, %u stale reads\n", TLB_ROUNDS, ncpu - 1, busy_bad);
    kprintf("  lazy TLB: %d remaps with the readers' CPUs idle: %llu IPIs skipped, %u stale reads\n", TLB_ROUNDS,
            (unsigned long long)skips, tlb_bad - busy_bad);
}

/* --- load balancing: CPU-bound threads spread over the CPUs --- */
struct busy_job {
    uint64_t iterations;
    uint64_t cpus_seen;
    uint64_t sink;
} __attribute__((aligned(64)));                 /* one cache line each: no false sharing between CPUs */

/* Fixed CPU work (no waiting, no shared memory): the wall time of N jobs shows how much really ran
 * in parallel. Not inlined: every measurement must run the same machine code (inlined copies with
 * different code layout differed by up to 3.5x on a Zen 5 core). */
static NOINLINE void busy_work(struct busy_job *j)
{
    const uint64_t n = j->iterations;
    uint64_t x = n, seen = 0;
    for (uint64_t i = 0; i < n; i++) {
        x = x * 6364136223846793005ull + 1442695040888963407ull;
        if (!(i & 4095))
            seen |= THREAD_CPU(thread_cpu());
    }
    j->cpus_seen = seen;
    j->sink = x;
}

static int busy_main(void *arg)
{
    struct busy_job *j = arg;
    kevent_wait(&go, WAIT_FOREVER);
    busy_work(j);
    return 0;
}

static void test_balance(void)
{
    enum { N = 8 };
    static struct busy_job jobs[N];
    struct thread *t[N];

    /* Calibrate one job to ~20 ms on one CPU. */
    struct busy_job one = { .iterations = 1u << 16 };
    uint64_t single;
    for (;;) {
        uint64_t s0 = time_ns();
        busy_work(&one);
        single = time_ns() - s0;
        if (single >= 20 * NS_PER_MS || one.iterations >= (1ull << 40))
            break;
        one.iterations *= 2;
    }

    /* One pinned job per CPU: wall time should stay close to one job's time. */
    kevent_reset(&go);
    for (uint32_t c = 0; c < ncpu && c < N; c++) {
        jobs[c] = (struct busy_job){ .iterations = one.iterations };
        t[c] = thread_create_on("smp.busy1", busy_main, &jobs[c], THREAD_PRIO_NORMAL, THREAD_CPU(c));
    }
    thread_sleep_ns(NS_PER_MS);
    uint64_t p0 = time_ns();
    kevent_signal(&go);
    for (uint32_t c = 0; c < ncpu && c < N; c++)
        thread_join(t[c]);
    uint64_t pinned = time_ns() - p0;
    CHECK(pinned < single * ncpu * 3 / 4);         /* serialized CPUs would take ncpu x as long */
    kprintf("  parallel: one job per CPU on %u CPUs took %llu ms (one job alone: %llu ms)\n", ncpu,
            (unsigned long long)(pinned / NS_PER_MS), (unsigned long long)(single / NS_PER_MS));

    kevent_reset(&go);
    for (int i = 0; i < N; i++) {
        jobs[i] = (struct busy_job){ .iterations = one.iterations };
        t[i] = thread_create("smp.busy", busy_main, &jobs[i], THREAD_PRIO_NORMAL);
    }
    thread_sleep_ns(NS_PER_MS);
    uint64_t t0 = time_ns();
    kevent_signal(&go);
    uint64_t used = 0;
    for (int i = 0; i < N; i++) {
        thread_join(t[i]);
        used |= jobs[i].cpus_seen;
    }
    uint64_t dt = time_ns() - t0;
    uint32_t n_used = (uint32_t)__builtin_popcountll(used);
    uint64_t speedup10 = dt ? N * single * 10 / dt : 0;     /* tenths */
    CHECK(n_used == ncpu);
    kprintf("  balance: %d CPU-bound jobs ran on %u of %u CPUs: %llu ms wall vs %llu ms serial, speedup %llu.%llux\n",
            N, n_used, ncpu, (unsigned long long)(dt / NS_PER_MS), (unsigned long long)(N * single / NS_PER_MS),
            (unsigned long long)(speedup10 / 10), (unsigned long long)(speedup10 % 10));
}

/* --- timers fire on the CPU that armed them, on time --- */
static int sleeper_main(void *arg)
{
    (void)arg;
    uint64_t worst = 0;
    for (int i = 0; i < 20; i++) {
        uint64_t want = (uint64_t)(i % 4 + 1) * 500 * NS_PER_US;
        uint64_t t0 = time_ns();
        thread_sleep_ns(want);
        uint64_t got = time_ns() - t0;
        if (got < want)
            return -1;
        if (got - want > worst)
            worst = got - want;
    }
    return (int)(worst / NS_PER_US);
}

static void test_timers(void)
{
    struct thread *t[MAX_CPUS];
    for (uint32_t c = 0; c < ncpu; c++)
        t[c] = thread_create_on("smp.sleep", sleeper_main, NULL, THREAD_PRIO_HIGH, THREAD_CPU(c));
    int worst = 0;
    for (uint32_t c = 0; c < ncpu; c++) {
        int w = thread_join(t[c]);
        CHECK(w >= 0 && w < 10000);
        if (w > worst)
            worst = w;
    }
    kprintf("  per-CPU timers: 20 sleeps on each CPU, worst lateness %d us\n", worst);
}

/* --- churn: every CPU creates and joins threads that land anywhere --- */
static int quick(void *arg) { return (int)(uintptr_t)arg; }

static int churn_main(void *arg)
{
    (void)arg;
    thread_set_affinity(THREAD_AFFINITY_ALL);            /* children may go to any CPU */
    for (int i = 0; i < 250; i++) {
        struct thread *t = thread_create("smp.child", quick, (void *)(uintptr_t)i, THREAD_PRIO_NORMAL);
        if (!t || thread_join(t) != i)
            return -1;
        void *p = kmalloc((size_t)(i % 5) * 1500 + 16);  /* small and guard-paged large objects */
        if (!p)
            return -1;
        kfree(p);
    }
    return 0;
}

static void test_churn(void)
{
    uint32_t base = thread_count();
    uint64_t free0 = pmm_free_frames();
    struct thread *t[MAX_CPUS];
    for (uint32_t c = 0; c < ncpu; c++)
        t[c] = thread_create_on("smp.churn", churn_main, NULL, THREAD_PRIO_NORMAL, THREAD_CPU(c));
    for (uint32_t c = 0; c < ncpu; c++)
        CHECK(thread_join(t[c]) == 0);
    thread_sleep_ns(10 * NS_PER_MS);                      /* let the reaper settle */
    CHECK(thread_count() == base);
    int64_t lost = (int64_t)free0 - (int64_t)pmm_free_frames();
    CHECK(lost < 64);                                      /* slab pages may stay cached */
    kprintf("  churn: %u CPUs x 250 create+join+alloc, thread count back to %u, %lld frames held\n", ncpu, base,
            (long long)lost);
}

/* --- address-space wrap-around: the stack and heap regions are reused from the start once their
 * end is reached, skipping what is still in use (long uptimes must never exhaust them) --- */
static int wrap_child(void *arg)
{
    void *p = kmalloc(6000);                               /* large: heap region */
    if (!p)
        return -1;
    ((volatile char *)p)[5999] = 1;
    kfree(p);
    return (int)(uintptr_t)arg;
}

static void test_wrap(void)
{
    uint32_t base = thread_count();
    void *keep = kmalloc(6000);                            /* stays allocated across the wrap */
    vm_test_near_end();
    uint64_t lowest_stack = UINT64_MAX, lowest_heap = UINT64_MAX;
    bool ok = keep != NULL;
    for (int i = 0; i < 64 && ok; i++) {
        struct thread *t = thread_create("smp.wrap", wrap_child, (void *)(uintptr_t)i, THREAD_PRIO_NORMAL);
        void *p = kmalloc(9000);
        ok = t && p;
        if (t) {
            if (t->kstack_guard < lowest_stack)
                lowest_stack = t->kstack_guard;
            ok = thread_join(t) == i && ok;
        }
        if (p && (uint64_t)(uintptr_t)p < lowest_heap)
            lowest_heap = (uint64_t)(uintptr_t)p;
        kfree(p);
    }
    ((volatile char *)keep)[0] = 2;
    kfree(keep);
    thread_sleep_ns(5 * NS_PER_MS);
    CHECK(ok);
    CHECK(lowest_stack < KSTACK_BASE + KSTACK_REGION / 2);   /* wrapped back to the start */
    CHECK(lowest_heap < HEAP_BASE + HEAP_SIZE / 2);
    CHECK(thread_count() == base);
    kprintf("  wrap-around: 64 threads and allocations across the end of the stack and heap regions OK\n");
}

void ktest_run(void)
{
    kprintf("KTEST smp: running\n");
    ncpu = smp_cpus();
    CHECK(ncpu >= 2);
    for (uint32_t c = 0; c < ncpu; c++)
        CHECK(cpus[c] && cpus[c]->online && cpus[c]->cpu_id == c);
    if (ncpu >= 2) {
        test_pinning();
        test_counters();
        test_pingpong();
        test_tlb();
        test_balance();
        test_timers();
        test_churn();
        test_wrap();
    }
    uint64_t ipis = 0, steals = 0, flushes = 0;
    for (uint32_t c = 0; c < ncpu; c++) {
        ipis += cpus[c]->ipis;
        steals += cpus[c]->steals;
        flushes += cpus[c]->tlb_flushes;
    }
    kprintf("  stats: %llu IPIs, %llu steals, %llu TLB shootdowns (%llu remote flushes)\n",
            (unsigned long long)ipis, (unsigned long long)steals, (unsigned long long)smp_shootdowns(),
            (unsigned long long)flushes);
    if (failures)
        kprintf("KTEST smp: FAILED (%d)\n", failures);
    else
        kprintf("KTEST smp: PASSED\n");
}

#elif defined(KTEST_LOCKUP)

#include "cpu.h"
#include "smp.h"
#include "thread.h"

static int stuck_main(void *arg)
{
    (void)arg;
    kprintf("KTEST lockup: CPU %u spins with interrupts off\n", thread_cpu());
    cpu_cli();
    for (;;)
        cpu_pause();
}

void ktest_run(void)
{
    if (smp_cpus() < 2) {
        kprintf("KTEST lockup: FAILED (needs 2 CPUs)\n");
        return;
    }
    thread_detach(thread_create_on("ktest.stuck", stuck_main, NULL, THREAD_PRIO_NORMAL, THREAD_CPU(1)));
    thread_sleep_ns(20 * NS_PER_S);
    kprintf("KTEST lockup: FAILED (watchdog did not fire)\n");
}

#elif defined(KTEST_SOFTLOCKUP)

#include "cpu.h"
#include "smp.h"
#include "spinlock.h"
#include "thread.h"

static spinlock_t hog_lk = SPINLOCK_INIT("ktest.hog", LOCK_RANK_TEST);
static volatile int other_ran;

static int hog_main(void *arg)
{
    (void)arg;
    spin_lock(&hog_lk);                          /* preemption off, interrupts on */
    uint64_t start = time_ns();
    while (time_ns() - start < 7 * NS_PER_S)
        cpu_pause();
    spin_unlock(&hog_lk);
    return 0;
}

static int other_main(void *arg)
{
    (void)arg;
    other_ran = 1;
    return 0;
}

void ktest_run(void)
{
    if (smp_cpus() < 2) {
        kprintf("KTEST softlockup: FAILED (needs 2 CPUs)\n");
        return;
    }
    kprintf("KTEST softlockup: CPU 1 holds a spinlock for 7 s while another thread waits there\n");
    struct thread *h = thread_create_on("ktest.hog", hog_main, NULL, THREAD_PRIO_NORMAL, THREAD_CPU(1));
    thread_sleep_ns(10 * NS_PER_MS);
    struct thread *o = thread_create_on("ktest.waiter", other_main, NULL, THREAD_PRIO_NORMAL, THREAD_CPU(1));
    thread_join(h);
    thread_join(o);
    kprintf("KTEST softlockup: DONE (waiter ran: %s)\n", other_ran ? "yes" : "no");
}

#elif defined(KTEST_SOAK)

/*
 * Soak: rounds of randomized concurrent work on every CPU (threads with random priorities and
 * affinities doing allocations, mutex/semaphore/event traffic, sleeps, yields, migrations and
 * nested thread creation). After each round everything must be accounted for: shared counters
 * exact, thread count back to its baseline, no lost memory beyond cached slab pages.
 * Runs until stopped; build.ps1 soak watches the "SOAK round" lines.
 */
#include "cpu.h"
#include "mm.h"
#include "percpu.h"
#include "rust.h"
#include "smp.h"
#include "thread.h"
#include "wait.h"

#define ROUND_NS     (2 * NS_PER_S)
#define WORKERS      12

static uint64_t seed;
static struct kmutex soak_mx = KMUTEX_INIT("soak.mx");
static struct ksem soak_sem = KSEM_INIT("soak.sem", 4);
static struct kevent soak_ev = KEVENT_INIT("soak.ev", 1);
static uint64_t mx_count, expect_count;
static volatile uint64_t round_end;

static uint64_t rnd(uint64_t *s)                   /* xorshift64* */
{
    *s ^= *s >> 12;
    *s ^= *s << 25;
    *s ^= *s >> 27;
    return *s * 0x2545F4914F6CDD1Dull;
}

static int child_main(void *arg)
{
    uint64_t s = (uint64_t)(uintptr_t)arg | 1;
    void *p = kmalloc(rnd(&s) % 3000 + 1);
    if (rnd(&s) & 1)
        thread_yield();
    kfree(p);
    return 7;
}

static int worker_main(void *arg)
{
    uint64_t s = (uint64_t)(uintptr_t)arg;
    uint64_t ops = 0, mine = 0;
    void *held[8] = { 0 };
    while (time_ns() < round_end) {
        switch (rnd(&s) % 11) {
        case 0: case 1: {                          /* allocation churn, sizes up to 3 large pages */
            unsigned k = (unsigned)(rnd(&s) % 8);
            kfree(held[k]);
            held[k] = kmalloc(rnd(&s) % 12000 + 1);
            if (!held[k])
                return -1;
            break;
        }
        case 2: case 3:
            kmutex_lock(&soak_mx);
            mx_count++;
            mine++;
            kmutex_unlock(&soak_mx);
            break;
        case 4:
            if (ksem_down_timeout(&soak_sem, NS_PER_MS))
                ksem_up(&soak_sem);
            break;
        case 5:
            if (rnd(&s) & 1)
                kevent_signal(&soak_ev);
            else
                kevent_wait(&soak_ev, 200 * NS_PER_US);
            break;
        case 6:
            thread_sleep_ns(rnd(&s) % (500 * NS_PER_US));
            break;
        case 7:
            thread_yield();
            break;
        case 8: {                                  /* migrate somewhere random (or anywhere) */
            uint64_t m = rnd(&s) & smp_online_mask();
            thread_set_affinity(m ? m : THREAD_AFFINITY_ALL);
            break;
        }
        case 9: {
            struct thread *c = thread_create("soak.child", child_main, (void *)(uintptr_t)rnd(&s), THREAD_PRIO_NORMAL);
            if (!c || thread_join(c) != 7)
                return -1;
            break;
        }
        case 10:                                   /* kernel objects: random handle traffic */
            if (!rust_soak_objects(rnd(&s)))
                return -1;
            break;
        }
        ops++;
    }
    for (unsigned k = 0; k < 8; k++)
        kfree(held[k]);
    __atomic_add_fetch(&expect_count, mine, __ATOMIC_RELAXED);
    return (int)(ops > 0x7FFFFFFF ? 0x7FFFFFFF : ops);
}

void ktest_run(void)
{
    seed = cpu_random64() | 1;
    kprintf("KTEST soak: %u CPUs, %d workers per round, seed %#llx\n", smp_cpus(), WORKERS, (unsigned long long)seed);
    uint32_t base_threads = thread_count();
    uint64_t base_free = 0;
    uint64_t base_objects = rust_objects_live();
    for (uint32_t round = 1;; round++) {
        round_end = time_ns() + ROUND_NS;
        struct thread *w[WORKERS];
        for (int i = 0; i < WORKERS; i++) {
            unsigned prio = THREAD_PRIO_NORMAL - 2 + (unsigned)(rnd(&seed) % 5);
            uint64_t aff = (i % 3 == 0) ? THREAD_AFFINITY_ALL : (rnd(&seed) & smp_online_mask());
            w[i] = thread_create_on("soak.worker", worker_main, (void *)(uintptr_t)(rnd(&seed) | 1), prio,
                                    aff ? aff : THREAD_AFFINITY_ALL);
            if (!w[i]) {
                kprintf("SOAK FAIL: round %u: out of memory creating workers\n", round);
                return;
            }
        }
        uint64_t ops = 0;
        int bad = 0;
        for (int i = 0; i < WORKERS; i++) {
            int r = thread_join(w[i]);
            if (r < 0)
                bad++;
            else
                ops += (uint64_t)r;
        }
        thread_sleep_ns(20 * NS_PER_MS);           /* reaper */
        uint32_t threads = thread_count();
        uint64_t free = pmm_free_frames();
        if (round == 2)
            base_free = free;                       /* after warm-up: slab caches populated */
        uint64_t objects = rust_objects_live();
        if (bad || mx_count != expect_count || threads != base_threads ||
            (base_free && free + 256 < base_free) || objects != base_objects) {
            kprintf("SOAK FAIL: round %u: %d failed workers, counter %llu/%llu, threads %u/%u, free %llu (base %llu), objects %llu/%llu\n",
                    round, bad, (unsigned long long)mx_count, (unsigned long long)expect_count, threads,
                    base_threads, (unsigned long long)free, (unsigned long long)base_free,
                    (unsigned long long)objects, (unsigned long long)base_objects);
            return;
        }
        uint64_t steals = 0;
        for (uint32_t c = 0; c < cpu_slots; c++)
            if (cpus[c])
                steals += cpus[c]->steals;
        kprintf("SOAK round %u OK: %llu ops, %u threads, %llu free frames, %llu shootdowns (+%llu lazy), %llu steals\n",
                round, (unsigned long long)ops, threads, (unsigned long long)free, (unsigned long long)smp_shootdowns(),
                (unsigned long long)smp_lazy_skips(), (unsigned long long)steals);
    }
}

#elif defined(KTEST_OBJECTS)

#include "fault.h"
#include "mm.h"
#include "rust.h"
#include "thread.h"

static int fi_thread(void *arg)
{
    (void)arg;
    return 5;
}

/* Fail the 1st, 2nd, ... allocation of thread creation and of a guard-paged large kmalloc until
 * both succeed: each failure must be reported as NULL, without a panic and without a leak. */
static int fault_inject_threads(void)
{
    int failures = 0;
    thread_sleep_ns(20 * NS_PER_MS);               /* reaper: heap accounting must be quiet */
    unsigned n;
    for (n = 1; n < 1000; n++) {
        uint64_t heap0 = heap_live_allocs();
        uint32_t threads0 = thread_count();
        fault_inject_arm(FAULT_KMALLOC | FAULT_PMM, n);
        struct thread *t = thread_create("ktest.fi", fi_thread, NULL, THREAD_PRIO_NORMAL);
        void *big = kmalloc(3 * PAGE_SIZE);
        bool fired = fault_inject_disarm();
        if (fired == (t && big)) {
            kprintf("  FAIL fault %u: fired=%d but thread=%p big=%p\n", n, fired, (void *)t, big);
            failures++;
        }
        if (t && thread_join(t) != 5) {
            kprintf("  FAIL fault %u: wrong exit code\n", n);
            failures++;
        }
        kfree(big);
        if (heap_live_allocs() != heap0 || thread_count() != threads0) {
            kprintf("  FAIL fault %u: leak: heap %llu -> %llu, threads %u -> %u\n", n,
                    (unsigned long long)heap0, (unsigned long long)heap_live_allocs(), threads0, thread_count());
            return failures + 1;
        }
        if (!fired)
            break;
    }
    kprintf("  out of memory (C): thread_create + large kmalloc: %u failure points, all clean\n", n - 1);
    return failures;
}

void ktest_run(void)
{
    kprintf("KTEST objects: kernel objects, handles, rights, quotas, out-of-memory paths\n");
    int failures = fault_inject_threads();
    failures += (int)rust_objects_test();
    if (failures)
        kprintf("KTEST objects (all): FAILED (%d)\n", failures);
}

#elif defined(KTEST_KASANOOB) || defined(KTEST_KASANUAF)

#include "mm.h"

/* Built with KASAN: the bad access below must stop the kernel with a named report. Not inlined,
 * so the report names this function. */
NOINLINE void ktest_kasan(volatile uint8_t *p);
void ktest_kasan(volatile uint8_t *p)
{
#if defined(KTEST_KASANOOB)
    p[20] = 1;                                /* one byte past a 20-byte allocation (slot of 32) */
#else
    volatile uint64_t v = ((volatile uint64_t *)p)[1];   /* a freed object */
    (void)v;
#endif
}

void ktest_run(void)
{
#ifndef KTEST_KASAN
    kprintf("KTEST kasan: FAILED (not a KASAN build)\n");
#endif
    uint8_t *p = kmalloc(20);
#if defined(KTEST_KASANUAF)
    kfree(p);
    kprintf("KTEST kasan: reading a freed object\n");
#else
    kprintf("KTEST kasan: writing past the end of a 20-byte allocation\n");
#endif
    ktest_kasan(p);
    kprintf("KTEST kasan: FAILED (bad access not caught)\n");
}

#elif defined(KTEST_PROFILE)

#include "ktime.h"
#include "profile.h"
#include "thread.h"

/* A known busy function: the profiler must find it on top. */
NOINLINE int ktest_prof_spin(void *arg);
int ktest_prof_spin(void *arg)
{
    uint64_t until = time_ns() + (uint64_t)(uintptr_t)arg;
    volatile uint64_t x = 0;
    while (time_ns() < until)
        for (int i = 0; i < 1000; i++)
            x += (uint64_t)i;
    return (int)(x & 1);
}

/* Part 1 (kernel): sample while two threads spin in ktest_prof_spin. Part 2: keep the histograms
 * on while init runs the user benchmarks (syscalls), print them when it exits. */
void ktest_run(void)
{
    kprintf("KTEST profile: sampling all CPUs at 1000 Hz while 2 threads spin for 300 ms\n");
    profile_start(1000);
    struct thread *a = thread_create("ktest.spin", ktest_prof_spin, (void *)(uintptr_t)(300 * NS_PER_MS), THREAD_PRIO_NORMAL);
    struct thread *b = thread_create("ktest.spin", ktest_prof_spin, (void *)(uintptr_t)(300 * NS_PER_MS), THREAD_PRIO_NORMAL);
    thread_join(a);
    thread_join(b);
    profile_stop();
    const char *top = profile_print(5);
    lat_print_all();
    bool ok = top && strcmp(top, "ktest_prof_spin") == 0;
    kprintf("KTEST profile (kernel): %s\n", ok ? "OK" : "FAILED");
    profile_start(1000);                      /* histograms for the user part */
}

void ktest_after_init(int code)
{
    profile_stop();
    kprintf("KTEST profile: latency while init ran the user benchmarks\n");
    lat_print_all();
    bool ok = code == 0 && lat_syscall.count > 0 && lat_wakeup.count > 0;
    kprintf("KTEST profile: %s\n", ok ? "PASSED" : "FAILED");
}

#elif defined(KTEST_UBSANTRAP)

/* Built with UBSan (trap mode): a signed overflow must stop the kernel with a named #UD report. */
void ktest_run(void)
{
#ifndef KTEST_UBSAN
    kprintf("KTEST ubsantrap: FAILED (not a UBSan build)\n");
#endif
    volatile int big = 0x7FFFFFFF, one = 1;
    kprintf("KTEST ubsantrap: overflowing a signed int\n");
    int r = big + one;
    kprintf("KTEST ubsantrap: FAILED (overflow not caught, got %d)\n", r);
}

#elif defined(KTEST_DRIVERS)

#include "mm.h"

/* devmgr test makes virtio-blk DMA a sector to physical 0x100000 (the kernel image), which the
 * IOMMU must block: the kernel hashes that memory before init runs and checks it afterwards. */
#define DMA_TARGET 0x100000ull
static uint64_t dma_target_hash;

static uint64_t hash_target(void)
{
    const uint8_t *p = (const uint8_t *)(uintptr_t)(kernel_vbase() + DMA_TARGET);   /* the image, not in the direct map */
    uint64_t h = 0xCBF29CE484222325ull;            /* FNV-1a over the 4 KiB the test aims at */
    for (int i = 0; i < 4096; i++)
        h = (h ^ p[i]) * 0x100000001B3ull;
    return h;
}

void ktest_run(void) { dma_target_hash = hash_target(); }

void ktest_after_init(int code)
{
    bool same = hash_target() == dma_target_hash;
    kprintf("KTEST drivers: kernel memory at %#llx %s after the DMA test\n", DMA_TARGET,
            same ? "unchanged" : "OVERWRITTEN");
    kprintf("KTEST drivers: %s\n", same && code == 0 ? "PASSED" : "FAILED");
}

#elif defined(KTEST_USER) || defined(KTEST_SMAP) || defined(KTEST_SMEP) || defined(KTEST_COMPAT) || defined(KTEST_LIBD) || defined(KTEST_STORAGE) || defined(KTEST_READONLY) || defined(KTEST_ATTEST) || defined(KTEST_ATTESTTPM) || defined(KTEST_POWEROFF) || defined(KTEST_REBOOT) || defined(KTEST_SERVICES) || \
    defined(KTEST_TIME) || defined(KTEST_SHELL)

/* Ring-3 tests: init runs utest (ktest_init_args); nothing to do in the kernel first. */
void ktest_run(void) {}

#elif defined(KTEST_SPEC)

#include "percpu.h"
#include "spec.h"

/* Transient-execution mitigations, every one forced on (spec.c: KPTI, VERW, RSB filling; IBPB
 * where the CPU has it), then the whole ring-3 suite on top (init runs "utest all").
 *  - The user page tables are walked: only the entry pages may be mapped, with the right
 *    permissions; kernel code, data, heap, direct map and stacks must be absent.
 *  - Every interrupt from ring 3 records the CR3 it found (isr.asm): it must be the running
 *    process's user tables, never the kernel's (an exit path that did not switch). */
static uint64_t spec_user_ok, spec_user_bad;

void ktest_spec_user_entry(void)
{
    struct percpu *pc = percpu();
    if (pc->entry_cr3 && pc->entry_cr3 == pc->user_cr3)
        __atomic_fetch_add(&spec_user_ok, 1, __ATOMIC_RELAXED);
    else
        __atomic_fetch_add(&spec_user_bad, 1, __ATOMIC_RELAXED);
}

void ktest_run(void)
{
    char why[160];
    bool ok = kpti_selfcheck(why, sizeof(why));
    kprintf("KTEST spec: user page tables: %s%s\n", ok ? "" : "FAILED: ", why);
    bool clamp = array_index_nospec(3, 4) == 3 && array_index_nospec(4, 4) == 0 && array_index_nospec(~0ull, 4) == 0;
    kprintf("KTEST spec: array_index_nospec %s\n", clamp ? "OK" : "FAILED");
    bool all = true;
    for (uint32_t c = 0; c < cpu_slots; c++)
        if (cpus[c] && (cpus[c]->mitig & (MIT_KPTI | MIT_VERW | MIT_RSB)) != (MIT_KPTI | MIT_VERW | MIT_RSB))
            all = false;
    kprintf("KTEST spec: KPTI, VERW and RSB filling on every CPU: %s\n", all ? "yes" : "FAILED");
}

void ktest_after_init(int code)
{
    uint64_t ok = __atomic_load_n(&spec_user_ok, __ATOMIC_RELAXED), bad = __atomic_load_n(&spec_user_bad, __ATOMIC_RELAXED);
    kprintf("KTEST spec: %llu interrupts from ring 3 found the user page tables loaded, %llu did not\n",
            (unsigned long long)ok, (unsigned long long)bad);
    kprintf("KTEST spec: %s\n", code == 0 && ok > 0 && bad == 0 ? "PASSED" : "FAILED");
}

#elif defined(KTEST_FUZZ)

/* ELF parser fuzzing in the kernel (Rust), then init runs the syscall fuzzer in ring 3. */
void ktest_run(void)
{
    uint32_t failures = rust_elf_fuzz();
    kprintf("KTEST fuzz: ELF parser %s\n", failures ? "FAILED" : "OK");
    failures = rust_acpi_fuzz();
    kprintf("KTEST fuzz: ACPI parsers %s\n", failures ? "FAILED" : "OK");
    rust_objects_snapshot();
}

/* After the syscall and IPC fuzzers (init has exited): nothing they created may be left. */
void ktest_after_init(int code)
{
    uint32_t leaked = rust_objects_leaked();
    kprintf("KTEST fuzz: objects after user space ended: %s (%llu channel ends collected from cycles)\n",
            leaked ? "LEAKED (FAILED)" : "none leaked", (unsigned long long)rust_channels_collected());
    kprintf("KTEST fuzz: %s\n", code == 0 && !leaked ? "PASSED" : "FAILED");
}

#else
#error "KTEST defined without a KTEST_<NAME> selector"
#endif

#if !defined(KTEST_PROFILE) && !defined(KTEST_DRIVERS) && !defined(KTEST_SPEC) && !defined(KTEST_FUZZ) && !defined(KTEST_HWBENCH)
void ktest_after_init(int code) { (void)code; }
#endif
#ifndef KTEST_SPEC
void ktest_spec_user_entry(void) {}
#endif

#endif /* KTEST */
