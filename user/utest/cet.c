/*
 * utest: CET shadow stacks in ring 3 (docs/hardening.md).
 *
 * utest is linked with `-z shstk`, so on a CPU with CET every thread of it runs with a shadow
 * stack made by the kernel. Checked: each thread has its own; deep call chains work; the shadow
 * stack cannot be written with ordinary stores; an overwritten return address stops the process
 * (#CP) instead of returning there; an exception handler may resume from inside a call (the
 * kernel restores the shadow-stack pointer with the registers); threads that end give theirs back.
 * Without CET the test says so and checks nothing else.
 */

#include "utest.h"

/* RDSSPQ RAX: the shadow-stack pointer, or RAX unchanged (0) when shadow stacks are off (the
 * encoding is a NOP then). Spelled as bytes: no assembler feature flag needed. */
static inline uint64_t rdssp(void)
{
    uint64_t v = 0;
    __asm__ volatile(".byte 0xf3, 0x48, 0x0f, 0x1e, 0xc8" : "+a"(v));
    return v;
}

__attribute__((noinline)) static uint64_t depth(uint64_t n)
{
    if (n == 0)
        return rdssp();
    uint64_t r = depth(n - 1);
    __asm__ volatile("" : "+r"(r));       /* not a tail call: every level returns through RET */
    return r;
}

/* ---- child modes (each must die with FAULT) ---------------------------------------------------- */

__attribute__((noinline)) static void landing(void)
{
    dos_printf("utest: FAIL: a RET went to an overwritten return address\n");
    dos_process_exit(1);
}

/* Overwrite this function's own return address, then return: the shadow stack disagrees (#CP). */
__attribute__((noinline)) static void smash(void)
{
    volatile uint64_t *ra = (volatile uint64_t *)__builtin_frame_address(0) + 1;
    *ra = (uint64_t)(uintptr_t)&landing;
}

int cet_child(const char *a)
{
    if (!rdssp())
        return 2;                             /* no shadow stack: nothing to show */
    if (!strcmp(a, "ret")) {
        smash();
        return 1;
    }
    if (!strcmp(a, "write")) {
        *(volatile uint64_t *)(uintptr_t)rdssp() = (uint64_t)(uintptr_t)&landing;   /* read-only */
        return 1;
    }
    return 99;
}

/* ---- threads ------------------------------------------------------------------------------------- */

static volatile uint64_t thread_ssp;

static void ssp_thread(uint64_t arg)
{
    thread_ssp = depth(arg);
    dos_thread_exit(0);
}

static uint64_t run_thread(uint64_t n)
{
    uint8_t *stack = map_new(64 * 1024, 0);
    if (!stack)
        return 0;
    thread_ssp = 0;
    int64_t t = dos_thread_create(self_proc, ssp_thread, stack + 64 * 1024, n);
    if (t <= 0)
        return 0;
    dos_object_wait((dos_handle_t)t, DOS_TERMINATED, DOS_WAIT_FOREVER);
    dos_handle_close((dos_handle_t)t);
    dos_vmar_unmap(self_vmar, (uint64_t)(uintptr_t)stack, 64 * 1024);
    return thread_ssp;
}

/* ---- exception handler resuming from inside a call ---------------------------------------------- */

static uint8_t cet_hstack[16384] __attribute__((aligned(16)));
static volatile uint32_t cet_hits;

__attribute__((noinline)) static void resume_from_call(struct dos_exception_record *r)
{
    r->regs.rip += 2;                         /* past the ud2 */
    dos_exception_return(r);                  /* SSP here: one return address deeper than at the fault */
}

static void cet_handler(struct dos_exception_record *r)
{
    cet_hits++;
    resume_from_call(r);
}

__attribute__((noinline)) static uint64_t fault_and_return(void)
{
    __asm__ volatile("ud2" ::: "memory");
    return rdssp();
}

void test_shstk(void)
{
    uint64_t ssp = rdssp();
    if (!ssp) {
        dos_printf("utest: shadow stacks: off (this CPU has no CET); nothing to check\n");
        return;
    }
    CHECK((ssp & 7) == 0);

    /* A deep chain (more than a page of return addresses) comes back to the same SSP. */
    uint64_t deep = depth(2000);
    CHECK(deep < ssp && ssp - deep >= 2000 * 8);
    CHECK(rdssp() == ssp);

    /* Every thread has a shadow stack of its own; ending threads give theirs back. */
    uint64_t t1 = run_thread(10), t2 = 0;
    CHECK(t1 != 0 && (t1 > ssp + (1 << 20) || t1 + (1 << 20) < ssp));
    for (int i = 0; i < 64; i++)
        t2 = run_thread(100);
    CHECK(t2 != 0);

    /* A handler that returns from inside a call: the resumed code still returns correctly. */
    EXPECT(dos_thread_set_exception_handler(cet_handler, cet_hstack + sizeof(cet_hstack)), 0);
    uint64_t before = rdssp();
    uint64_t inside = fault_and_return();
    CHECK(cet_hits == 1 && inside == before - 8 && rdssp() == before);
    EXPECT(dos_thread_set_exception_handler(0, 0), 0);

    /* Attacks: both end the process, neither reaches `landing`. */
    EXPECT(wait_exit(spawn_self("cet ret", 0, 1), DOS_WAIT_FOREVER), DOS_EXIT_FAULT);
    EXPECT(wait_exit(spawn_self("cet write", 0, 1), DOS_WAIT_FOREVER), DOS_EXIT_FAULT);
    dos_printf("utest: shadow stacks: on in every thread (65 made and freed), 2000-deep calls, "
               "handler resumed from a call, overwritten return address and shadow-stack write stopped\n");
}
