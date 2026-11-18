/* panic() and the stack-protector runtime. */

#include <stdarg.h>
#include <stdint.h>
#include "panic.h"
#include "arch.h"
#include "printf.h"
#include "console.h"
#include "cpu.h"
#include "smp.h"
#include "spinlock.h"
#include "thread.h"
#include "mm.h"
#include "rust.h"
#include "version.h"

/* Stack canary. Set by entry.asm (RDRAND, TSC fallback) before any C code runs. Low byte is always 0
 * so string overflows (strcpy-style) cannot reproduce it. Read-only once the VMM is active. */
uintptr_t __stack_chk_guard RO_AFTER_INIT;

NORETURN void __stack_chk_fail(void);

void __stack_chk_fail(void)
{
    panic("stack smashing detected (stack canary overwritten)");
}

/* SMP: the first CPU to panic claims the report (panic_cpu); every other CPU is stopped with an NMI
 * before anything is printed, then locks are bypassed (in_panic) so the report always gets out. */
static uint32_t panic_cpu;          /* CPU number + 1 of the panicking CPU, 0 = none */
static volatile int in_panic;
static volatile int dumping;        /* crash dump in progress (a fault inside it ends the report) */

/* Crash dump over the console/serial: machine state after the report, lock-free (every other
 * CPU is stopped). Parsable sections between the two marker lines. */
static void crash_dump(void)
{
    dumping = 1;
    kprintf("--- crash dump (%s %s) ---\n", DKRNL_NAME, DKRNL_VERSION);
    /* KASLR: addresses here are at the randomized base; subtract the offset to symbolize kernel.elf. */
    kprintf("[kaslr]\nimage offset %#llx (link base %#llx)\n", (unsigned long long)kaslr_offset(),
            (unsigned long long)KERNEL_LINK_BASE);
    kprintf("[cpus]\n");
    sched_dump_cpus();
    kprintf("[threads]\n");
    sched_dump_threads(true);
    kprintf("[objects]\n");
    dkrnl_objects_print();
    kprintf("[memory]\n");
    kprintf("  %llu of %llu frames free\n", (unsigned long long)pmm_free_frames(),
            (unsigned long long)pmm_total_frames());
    kprintf("--- end of crash dump ---\n");
    dumping = 0;
}

bool panic_in_progress(void) { return in_panic != 0; }
bool panic_claimed(void) { return __atomic_load_n(&panic_cpu, __ATOMIC_ACQUIRE) != 0; }
bool panic_owner_is_me(void) { return __atomic_load_n(&panic_cpu, __ATOMIC_ACQUIRE) == this_cpu() + 1; }

void panic_begin(void)
{
    cpu_cli();
    uint32_t none = 0;
    if (!__atomic_compare_exchange_n(&panic_cpu, &none, this_cpu() + 1, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        if (dumping && panic_owner_is_me())
            kprintf("\n  (crash dump cut short: fault while dumping)\nSystem halted.\n");
        cpu_halt_forever();      /* fault while panicking, or another CPU is already reporting */
    }

    smp_stop_others();           /* nobody else runs (or prints) from here on */
    in_panic = 1;
    console_set_color(VGA_WHITE, VGA_RED);
    kprintf("\n*** KERNEL PANIC ***\n");
}

void panic_halt(void)
{
    sched_panic_info();          /* which thread was running, on which CPU */
    spin_dump_held();            /* test builds: which locks were held */
    smp_dump_target();           /* watchdog: the hung CPU's backtrace */
    crash_dump();
    kprintf("System halted.\n");
    cpu_halt_forever();
}

void panic_at(const char *file, int line, const char *fmt, ...)
{
    panic_begin();

    va_list ap;
    va_start(ap, fmt);
    kvprintf(fmt, ap);
    va_end(ap);

    kprintf("\n  at %s:%d\n", file, line);
    const uint64_t *frame = __builtin_frame_address(0);
    backtrace_print(frame[1], frame[0]);    /* starting at panic_at's caller */
    panic_halt();
}

void rust_panic(const char *file, size_t file_len, uint32_t line, const char *msg, size_t msg_len)
{
    panic_begin();
    kprintf("Rust panic: %.*s\n  at %.*s:%u\n", (int)msg_len, msg, (int)file_len, file, line);
    panic_halt();
}
