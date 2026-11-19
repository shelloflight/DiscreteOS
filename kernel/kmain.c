/*
 * D-KRNL main entry (C side).
 * Called from kernel/arch/x86_64/entry.asm in 64-bit long mode with RDI = BootInfo*,
 * after .bss is zeroed and the stack canary is set. Interrupts are off until init is complete.
 */

#include <stdint.h>
#include "acpi.h"
#include "power.h"
#include "apic.h"
#include "arch.h"
#include "bootinfo.h"
#include "cet.h"
#include "console.h"
#include "cpu.h"
#include "fbcon.h"
#include "kasan.h"
#include "kdb.h"
#include "klog.h"
#include "ktime.h"
#include "mm.h"
#include "string.h"
#include "thread.h"
#include "ktest.h"
#include "panic.h"
#include "percpu.h"
#include "printf.h"
#include "rust.h"
#include "smp.h"
#include "spec.h"
#include "version.h"

void kmain(BootInfo *bi_phys);   /* called from entry.asm */

static void print_memory_map(const BootInfo *bi)
{
    const MemoryMapEntry *mm = (const MemoryMapEntry *)(uintptr_t)bi->mmap_addr;
    uint64_t usable = 0;

    kprintf("Memory map (%u regions):\n", bi->mmap_count);
    for (uint32_t i = 0; i < bi->mmap_count; i++) {
        kprintf("  %016llx - %016llx  %s\n",
                (unsigned long long)mm[i].base,
                (unsigned long long)(mm[i].base + mm[i].length - 1),
                mmap_type_name(mm[i].type));
        if (mm[i].type == MMAP_USABLE)
            usable += mm[i].length;
    }
    kprintf("  %llu MiB usable\n", (unsigned long long)(usable >> 20));
}

static void print_us(const char *what, uint64_t cycles)
{
    uint64_t us = tsc_to_us(cycles);
    kprintf("%s%llu.%03llu ms\n", what, (unsigned long long)(us / 1000), (unsigned long long)(us % 1000));
}

static struct boot_timing boot_timing;      /* UEFI loader step times, if it left them */
static struct boot_wall boot_wall;          /* UEFI GetTime at boot, if the loader left it */

bool boot_time_record(struct boot_time_record *out)
{
    const struct boot_wall *w = &boot_wall;
    if (w->magic != BOOT_WALL_MAGIC || w->tsc > kernel_entry_tsc || w->year < 2000 || w->year > 2399 ||
        w->month < 1 || w->month > 12 || w->day < 1 || w->day > 31 || w->hour > 23 || w->minute > 59 ||
        w->second > 59 || w->nanosecond >= 1000000000u)
        return false;
    memset(out, 0, sizeof(*out));
    out->magic = BOOT_TIME_MAGIC;
    out->source = 1;
    out->year = w->year;
    out->month = w->month;
    out->day = w->day;
    out->hour = w->hour;
    out->minute = w->minute;
    out->second = w->second;
    out->nanosecond = w->nanosecond;
    out->time_zone = (w->time_zone >= -1440 && w->time_zone <= 1440) ? w->time_zone : 2047;
    out->mono_ns = -(int64_t)time_cycles_to_ns(kernel_entry_tsc - w->tsc);
    return true;
}

/* "Boot: loader steps: read kernel 120.4 ms, verify 4.1 ms, ..." (UEFI; the loader's own stamps),
 * wrapped so every line fits one kernel log record. */
static void print_loader_steps(void)
{
    if (boot_timing.count < 2)
        return;
    char line[120];
    size_t n = (size_t)ksnprintf(line, sizeof(line), "Boot: loader steps:");
    for (uint32_t i = 1; i <= boot_timing.count; i++) {
        char item[64];
        if (i < boot_timing.count) {
            uint64_t us = tsc_to_us(boot_timing.step[i].tsc - boot_timing.step[i - 1].tsc);
            ksnprintf(item, sizeof(item), " %s %llu.%01llu ms", boot_timing.step[i].name,
                      (unsigned long long)(us / 1000), (unsigned long long)(us % 1000 / 100));
        } else {
            uint64_t con = tsc_to_us(boot_timing.console_cycles);
            ksnprintf(item, sizeof(item), " (console output %llu.%01llu ms of it)",
                      (unsigned long long)(con / 1000), (unsigned long long)(con % 1000 / 100));
        }
        size_t k = strlen(item);
        if (n + k + 2 >= 100) {
            kprintf("%s\n", line);
            n = (size_t)ksnprintf(line, sizeof(line), "Boot: loader steps:");
        } else if (n > 19 && i < boot_timing.count) {   /* 19 = strlen("Boot: loader steps:") */
            line[n++] = ',';
        }
        memcpy(line + n, item, k + 1);
        n += k;
    }
    kprintf("%s\n", line);
}

/* Make sure the tickless timer really delivers a one-shot interrupt on time before declaring the
 * system ready. If TSC-deadline mode misbehaves (some hypervisors), fall back to LAPIC one-shot. */
static volatile uint64_t selfcheck_fired_ns;

static void selfcheck_cb(struct ktimer *t, void *ctx)
{
    (void)t;
    (void)ctx;
    selfcheck_fired_ns = time_ns();
}

static bool timer_try(void)
{
    static struct ktimer probe;
    const uint64_t delay = 2 * NS_PER_MS, limit = 50 * NS_PER_MS;
    selfcheck_fired_ns = 0;
    uint64_t start = time_ns();
    timer_start_oneshot(&probe, delay, selfcheck_cb, NULL);
    while (!selfcheck_fired_ns && time_ns() - start < delay + limit)
        cpu_pause();                         /* interrupts are on; no HLT in case nothing comes */
    timer_cancel(&probe);
    return selfcheck_fired_ns && selfcheck_fired_ns - start >= delay;
}

static void timer_selfcheck(void)
{
    if (timer_try())
        return;
    if (strcmp(timer_mode(), "TSC-deadline") == 0) {
        kprintf("APIC timer: TSC-deadline mode is not delivering interrupts on time; using LAPIC one-shot\n");
        timer_use_oneshot();
        if (timer_try())
            return;
    }
    panic("APIC timer is not delivering interrupts");
}
/* Kernel debugger console on the serial line (COM1). The keyboard belongs to user space
 * (the PS/2 and virtio-input drivers); kdb stays reachable over serial even when user
 * space is wedged, which is what a kernel debugger needs. */
static NORETURN void console_loop(void)
{
    char line[128];
    size_t n = 0;

    if (!serial_input_init()) {
        kprintf("kdb: no serial input; console idle\n");
        for (;;)
            thread_sleep_ns(UINT64_MAX / 2);
    }
    kprintf("kdb: serial console ready (try: help)\n");
    for (;;) {
        int c = serial_getc();
        if (c < 0) {
            serial_wait();              /* sleeps until the serial IRQ signals input */
            continue;
        }
        if (c == '\r')
            c = '\n';
        if (c == 0x7F)
            c = '\b';
        if (c == '\n') {
            line[n] = '\0';
            if (n)
                kprintf("\n");
            if (n && !kdb_command(line))
                kprintf("kdb: unknown command '%s' (try: help)\n", line);
            n = 0;
        } else if (c == '\b') {
            if (n) {
                n--;
                console_write("\b", 1);
            }
        } else if (c >= ' ' && c < 0x7F && n < sizeof(line) - 1) {
            line[n++] = (char)c;
            char ch = (char)c;
            console_write(&ch, 1);
        }
    }
}

/* The facts printed early in the boot scroll off a framebuffer console long before anyone can read
 * them (found on the first real-hardware boot): repeat them, briefly, right before user space
 * starts, so they stay on screen. Never addresses (KASLR). */
static void boot_summary(void)
{
    const struct kernel_layout *l = &kernel_layout;
    kprintf("Summary: %s, %u CPU%s online, %llu MiB RAM\n", cpu.brand[0] ? cpu.brand : cpu.vendor, smp_cpus(),
            smp_cpus() == 1 ? "" : "s", (unsigned long long)(pmm_total_frames() * PAGE_SIZE >> 20));
    kprintf("Summary: NX %s, SMEP %s, SMAP %s, UMIP %s; CET shadow stacks %s, IBT %s\n",
            cpu.nx ? "on" : "off", cpu.smep ? "on" : "off", cpu.smap ? "on" : "off", cpu.umip ? "on" : "off",
            cet_ss ? "on" : cpu.cet_ss ? "off" : "absent", cpu.cet_ibt ? "off" : "absent");
    kprintf("Summary: KASLR image %llu bits, direct map %llu, heap %llu, stacks %llu (sources %s%s%s%s)\n",
            (unsigned long long)l->image_bits, (unsigned long long)l->physmap_bits, (unsigned long long)l->heap_bits,
            (unsigned long long)l->kstack_bits, (l->sources & KASLR_SRC_RDSEED) ? "RDSEED " : "",
            (l->sources & KASLR_SRC_RDRAND) ? "RDRAND " : "", (l->sources & KASLR_SRC_EFI_RNG) ? "EFI-RNG " : "",
            (l->sources & KASLR_SRC_TSC) ? "TSC" : "");
    char m[128];
    kprintf("Summary: %s\n", spec_summary(m, sizeof(m)));
}

/* Validated copies: the bootloader's low-memory structures disappear with the identity map. */
static BootInfo       boot_info;
static MemoryMapEntry boot_mmap[BOOTINFO_MMAP_MAX];

extern char boot_stack_guard[];   /* entry.asm */

void kmain(BootInfo *bi_phys)
{
    console_init(bi_phys);

    console_set_color(VGA_LIGHT_CYAN, VGA_BLACK);
    kprintf("%s %s (%s)\n", DKRNL_NAME, DKRNL_VERSION, DKRNL_ARCH);
    console_set_color(VGA_LIGHT_GREY, VGA_BLACK);
    if (!serial_present())
        kprintf("warning: no serial port detected\n");

    const char *err = bootinfo_validate(bi_phys);
    if (err)
        panic("invalid boot information: %s", err);
    boot_info = *bi_phys;
    memcpy(boot_mmap, (const void *)(uintptr_t)bi_phys->mmap_addr, bi_phys->mmap_count * sizeof(MemoryMapEntry));
    boot_info.mmap_addr = (uint64_t)(uintptr_t)boot_mmap;
    if (boot_info.firmware == BOOT_FW_UEFI && ((uintptr_t)bi_phys & 0xFFF) == 0) {
        memcpy(&boot_timing, (const uint8_t *)bi_phys + BOOT_TIMING_OFFSET, sizeof(boot_timing));
        bool ok = boot_timing.magic == BOOT_TIMING_MAGIC && boot_timing.count >= 2 && boot_timing.count <= BOOT_TIMING_STEPS;
        for (uint32_t i = 0; ok && i < boot_timing.count; i++) {
            boot_timing.step[i].name[sizeof(boot_timing.step[i].name) - 1] = 0;
            ok = boot_timing.step[i].tsc >= boot_info.tsc_stage1 && boot_timing.step[i].tsc <= boot_info.tsc_loader_exit &&
                 (i == 0 || boot_timing.step[i].tsc >= boot_timing.step[i - 1].tsc);
        }
        if (!ok)
            boot_timing.count = 0;
        memcpy(&boot_wall, (const uint8_t *)bi_phys + BOOT_WALL_OFFSET, sizeof(boot_wall));
    }
    const BootInfo *bi = &boot_info;
    if (bi->rsdp)
        acpi_set_boot_rsdp((const void *)(uintptr_t)bi->rsdp);   /* copied: the identity map goes away */
    if (bi->firmware == BOOT_FW_UEFI)
        kprintf("BootInfo OK (v%u, UEFI, %u memory map entries, %s)\n", bi->version, bi->mmap_count,
                bi->fb_type ? "GOP framebuffer" : "no framebuffer");
    else
        kprintf("BootInfo OK (v%u, BIOS, boot drive %#x)\n", bi->version, bi->boot_drive);

    /* CPU: features + protections, own descriptor tables, exception handling */
    cpu_init();
    /* KASLR: the region bases, before anything uses them; then the loader's seed is wiped. */
    kaslr_init(bi);
    memset(boot_info.seed, 0, sizeof(boot_info.seed));
    memset(bi_phys->seed, 0, sizeof(bi_phys->seed));
    cpu_print_info();
    gdt_init();
    idt_init();
    kprintf("GDT/TSS/IDT loaded (IST stacks for #DF, NMI, #MC)\n");

    print_memory_map(bi);

    /* Memory management: own page tables (W^X, guard pages, no identity map), then the heap.
     * Nothing may print between vmm_activate() and vga_set_base(): the old VGA mapping is gone.
     * After a UEFI boot the screen is the framebuffer, mapped once the VMM and heap are up. */
    vmm_add_guard(boot_stack_guard, "kernel boot stack");
    pmm_init(bi);
    vmm_build(bi);
    void *vga = console_has_vga() ? vmm_map_phys(vga_phys_base(), VGA_TEXT_BYTES, VMM_W | VMM_UC) : NULL;
    vmm_activate();
    if (vga)
        vga_set_base(vga);
    pmm_print();
    vmm_print();
    kaslr_print();
    heap_init();
    heap_print();
    kpti_init();
    spec_print();
    kpti_print();
    if (bi->fb_type && console_attach_framebuffer(bi)) {
        char fbd[64];
        fbcon_describe(fbd, sizeof(fbd));
        kprintf("Console: framebuffer %s, write-combining %s\n", fbd, cpu.pat ? "on" : "OFF (no PAT)");
    }
    kasan_init();
    if (cpu.rdrand_broken)
        kprintf("warning: RDRAND failed its self-check (stuck or invalid values), disabled; "
                "heap secret and ASLR use a weak TSC-based seed\n");
    else if (!cpu.rdrand)
        kprintf("warning: no RDRAND; stack canary and heap secret use a weak TSC-based seed\n");

    /* Interrupt controllers and time */
    pic_disable();
    tsc_init();
    time_init();
    acpi_init();
    power_init();
    lapic_init();
    ioapic_init();
    timer_init();

    cpu_sti();
    timer_selfcheck();
    kprintf("Interrupts enabled, timer OK (tickless, %s)\n", timer_mode());
    kprintf("Time: monotonic clock (TSC, ns since kernel entry), timer callbacks at their exact deadline\n");

    /* Threads: from here on kmain is a thread like any other. With CET shadow stacks, every thread
     * is made with one and this CPU switches them on before the first switch (interrupts off until
     * then); kmain never returns, so the frames made before need none. */
    cet_init();
    cpu_cli();
    sched_init();
    if (cet_ss)
        cet_cpu_enable(&bsp_percpu, current_thread());
    cpu_sti();
    cet_print();
    sched_print();

    /* Every other CPU core: started now, scheduled from here on */
    smp_init(bi);

    /* Rust side: allocator, panic bridge, console, kernel log */
    dkrnl_init();
    dkrnl_security_init(bi->firmware, bi->flags, bi->kernel_dsig);
    klog_info("Kernel log: %u-record ring, %llu dropped", 512u, (unsigned long long)klog_dropped());

    print_us(bi->firmware == BOOT_FW_UEFI ? "Boot: UEFI loader entry -> kernel entry " : "Boot: stage 1 -> kernel entry ",
             kernel_entry_tsc - bi->tsc_stage1);
    print_loader_steps();

    ktest_set_bootinfo(bi);
    ktest_run();
    boot_summary();

    /* User space: init, the first ring-3 process and service manager (embedded; user/init) */
#ifdef KTEST
    const char *init_args = ktest_init_args();
#else
    const char *init_args = "";
#endif
    dkrnl_start_init(init_args, strlen(init_args));

    print_us("D-KRNL: ready, kernel init ", rdtsc() - kernel_entry_tsc);
    console_loop();
}
