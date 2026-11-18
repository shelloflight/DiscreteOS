/* CPU exception reporting: name, decoded error code, full register dump, and a frame-pointer backtrace. */

#include <stdint.h>
#include "arch.h"
#include "cpu.h"
#include "ksyms.h"
#include "mm.h"
#include "panic.h"
#include "printf.h"
#include "smp.h"
#include "thread.h"

static const char *const exception_names[32] = {
    "Divide error (#DE)",         "Debug (#DB)",                 "Non-maskable interrupt (NMI)",
    "Breakpoint (#BP)",           "Overflow (#OF)",              "Bound range exceeded (#BR)",
    "Invalid opcode (#UD)",       "Device not available (#NM)",  "Double fault (#DF)",
    "Coprocessor segment overrun","Invalid TSS (#TS)",           "Segment not present (#NP)",
    "Stack-segment fault (#SS)",  "General protection (#GP)",    "Page fault (#PF)",
    "Reserved (15)",              "x87 FP error (#MF)",          "Alignment check (#AC)",
    "Machine check (#MC)",        "SIMD FP exception (#XM)",     "Virtualization (#VE)",
    "Control protection (#CP)",   "Reserved (22)",               "Reserved (23)",
    "Reserved (24)",              "Reserved (25)",               "Reserved (26)",
    "Reserved (27)",              "Hypervisor injection (#HV)",  "VMM communication (#VC)",
    "Security exception (#SX)",   "Reserved (31)",
};

extern char __kernel_start[], __kernel_end[], __text_start[], __rodata_end[];
extern char __ro_after_init_start[], __ro_after_init_end[];

/* Valid frame pointers lie in the kernel image (boot stack) or in a mapped thread stack. */
#define BT_MAX_FRAMES 16

static bool in_range(uint64_t a, const void *lo, const void *hi)
{
    return a >= (uint64_t)(uintptr_t)lo && a < (uint64_t)(uintptr_t)hi;
}

/* Plain-language explanation of a faulting address, when we can tell. */
static void fault_hint(uint64_t addr, uint64_t err, bool page_fault)
{
    const char *guard = vmm_guard_name(addr);
    const char *thread_guard = thread_guard_name(addr);
    uint32_t ist_cpu = 0;
    const char *ist_guard = smp_guard_name(addr, &ist_cpu);
    if (addr < PAGE_SIZE)
        kprintf("  -> NULL pointer dereference\n");
    else if (guard)
        kprintf("  -> hit guard page: %s (stack overflow)\n", guard);
    else if (ist_guard)
        kprintf("  -> hit guard page: %s of CPU %u (stack overflow)\n", ist_guard, ist_cpu);
    else if (thread_guard)
        kprintf("  -> hit guard page: kernel stack of thread '%s' (stack overflow)\n", thread_guard);
    else if (addr >= KSTACK_BASE && addr < KSTACK_BASE + KSTACK_REGION && vmm_translate_nolock(addr) == VMM_NOT_MAPPED)
        kprintf("  -> unmapped kernel stack address: stack of an exited thread, or a stack gap\n");
    else if (addr >= HEAP_BASE && addr < HEAP_BASE + HEAP_SIZE && vmm_translate_nolock(addr) == VMM_NOT_MAPPED)
        kprintf("  -> unmapped kernel heap address: guard page (overflow) or freed allocation (use-after-free)\n");
    else if (page_fault && (err & 1) && !(err & 4) && addr >= USER_BASE && addr < USER_TOP && (err & 16))
        kprintf("  -> kernel tried to execute user memory (SMEP)\n");
    else if (page_fault && (err & 1) && !(err & 4) && addr >= USER_BASE && addr < USER_TOP)
        kprintf("  -> kernel accessed user memory outside user_copy (SMAP)\n");
    else if (page_fault && (err & 1) && (err & 16))
        kprintf("  -> execute from non-executable memory (NX / W^X)\n");
    else if (page_fault && (err & 1) && (err & 2) && in_range(addr, __text_start, __rodata_end))
        kprintf("  -> write to read-only kernel memory (W^X)\n");
    else if (page_fault && (err & 1) && (err & 2) && in_range(addr, __ro_after_init_start, __ro_after_init_end))
        kprintf("  -> write to read-only-after-init kernel data (KASLR layout, stack canary)\n");
    else if (addr < PHYSMAP_BASE)
        kprintf("  -> address in the lower (user) half: not mapped in this address space\n");
}

static bool frame_ok(uint64_t rbp)
{
    if ((rbp & 7) || vmm_guard_name(rbp))
        return false;
    if (in_range(rbp, __kernel_start, __kernel_end - 16))
        return true;
    return rbp >= KSTACK_BASE && rbp < KSTACK_BASE + KSTACK_REGION &&
           vmm_translate_nolock(rbp) != VMM_NOT_MAPPED && vmm_translate_nolock(rbp + 8) != VMM_NOT_MAPPED;
}

static void print_frame(int i, uint64_t addr)
{
    uint64_t off = 0;
    const char *name = ksym_lookup(i ? addr - 1 : addr, &off);   /* return address: the call is before it */
    if (name)
        kprintf("  #%-2d %016llx  %s+%#llx\n", i, (unsigned long long)addr, name, (unsigned long long)(i ? off + 1 : off));
    else
        kprintf("  #%-2d %016llx\n", i, (unsigned long long)addr);
}

void backtrace_print(uint64_t rip, uint64_t rbp)
{
    kprintf("Backtrace:\n");
    print_frame(0, rip);
    for (int i = 1; i < BT_MAX_FRAMES; i++) {
        if (!frame_ok(rbp))
            break;
        const uint64_t *frame = (const uint64_t *)(uintptr_t)rbp;
        uint64_t ret = frame[1];
        if (!ret)
            break;
        print_frame(i, ret);
        if (frame[0] <= rbp)          /* frames must move up the stack; stops loops */
            break;
        rbp = frame[0];
    }
}

/* UBSan in trap mode (test builds with -fsanitize-trap) compiles each failed check to
 * `ud1l disp(%eax), %eax` (67 0F B9 /r), with the check kind as the displacement. Names follow
 * clang's SanitizerHandler list. */
static const char *const ubsan_kinds[] = {
    "signed integer overflow (add)", "__builtin_unreachable reached", "CFI check failed",
    "division overflow / by zero", "dynamic type cache miss", "float cast overflow",
    "function type mismatch", "implicit conversion changed the value", "invalid builtin argument",
    "invalid ObjC cast", "load of an invalid value (bool/enum)", "missing return",
    "signed integer overflow (multiply)", "signed integer overflow (negate)", "nullability (argument)",
    "nullability (return)", "NULL passed as a nonnull argument", "NULL returned from returns_nonnull",
    "index out of bounds", "pointer arithmetic overflow", "shift out of bounds",
    "signed integer overflow (subtract)", "misaligned or NULL pointer use", "alignment assumption",
    "VLA bound not positive",
};

static void ubsan_hint(uint64_t rip)
{
    if (!in_range(rip, __text_start, __rodata_end - 5))
        return;
    const uint8_t *c = (const uint8_t *)(uintptr_t)rip;
    if (c[0] != 0x67 || c[1] != 0x0F || c[2] != 0xB9)
        return;
    unsigned kind = 0;
    if ((c[3] & 0xC0) == 0x40)
        kind = c[4];
    else if ((c[3] & 0xC0) != 0x00)
        return;
    kprintf("  -> UBSan: undefined behaviour: %s (check %u)\n",
            kind < sizeof(ubsan_kinds) / sizeof(ubsan_kinds[0]) ? ubsan_kinds[kind] : "unknown check", kind);
}

void exception_handler(struct interrupt_frame *f)
{
    if (f->vector == 2)
        smp_nmi(f);                   /* another CPU is panicking and stops this one: no return */
    panic_begin();

    kprintf("CPU exception: %s, vector %llu, error code %#llx (CPU %u)\n",
            exception_names[f->vector & 31], (unsigned long long)f->vector, (unsigned long long)f->error,
            this_cpu());

    if (f->vector == 14) {
        uint64_t e = f->error;
        kprintf("  CR2=%016llx  [%s, %s, %s%s%s%s]\n", (unsigned long long)read_cr2(),
                (e & 1) ? "protection violation (present)" : "not-present page",
                (e & 2) ? "write" : "read",
                (e & 4) ? "user" : "kernel",
                (e & 8) ? ", reserved bit set" : "",
                (e & 16) ? ", instruction fetch" : "",
                (e & 32) ? ", protection key" : "");
        fault_hint(read_cr2(), e, true);
    } else if (f->vector == 8) {
        /* A double fault usually follows a page fault that couldn't be delivered: CR2 still holds it. */
        kprintf("  CR2=%016llx  (last page-fault address)\n", (unsigned long long)read_cr2());
        fault_hint(read_cr2(), 0, false);
    } else if (f->vector == 6) {
        ubsan_hint(f->rip);
    }

    kprintf("  RIP=%016llx  CS=%04llx  RFLAGS=%016llx\n",
            (unsigned long long)f->rip, (unsigned long long)f->cs, (unsigned long long)f->rflags);
    kprintf("  RSP=%016llx  SS=%04llx  CR3=%016llx\n",
            (unsigned long long)f->rsp, (unsigned long long)f->ss, (unsigned long long)read_cr3());
    kprintf("  RAX=%016llx  RBX=%016llx  RCX=%016llx\n",
            (unsigned long long)f->rax, (unsigned long long)f->rbx, (unsigned long long)f->rcx);
    kprintf("  RDX=%016llx  RSI=%016llx  RDI=%016llx\n",
            (unsigned long long)f->rdx, (unsigned long long)f->rsi, (unsigned long long)f->rdi);
    kprintf("  RBP=%016llx  R8 =%016llx  R9 =%016llx\n",
            (unsigned long long)f->rbp, (unsigned long long)f->r8, (unsigned long long)f->r9);
    kprintf("  R10=%016llx  R11=%016llx  R12=%016llx\n",
            (unsigned long long)f->r10, (unsigned long long)f->r11, (unsigned long long)f->r12);
    kprintf("  R13=%016llx  R14=%016llx  R15=%016llx\n",
            (unsigned long long)f->r13, (unsigned long long)f->r14, (unsigned long long)f->r15);

    backtrace_print(f->rip, f->rbp);
    panic_halt();
}
