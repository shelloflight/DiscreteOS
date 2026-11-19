/*
 * User mode, CPU side: SYSCALL/SYSRET setup, FPU/SSE for user threads, SMAP patching, user
 * faults (kill the process, never the kernel) and the user-copy fault fixup.
 * The rest of user mode lives in Rust (kernel/rust/src/user/): syscalls, processes, the loader.
 */

#include <stdint.h>
#include "arch.h"
#include "cpu.h"
#include "mm.h"
#include "panic.h"
#include "percpu.h"
#include "printf.h"
#include "rust.h"
#include "spec.h"
#include "string.h"
#include "thread.h"
#include "user.h"

#define MSR_STAR   0xC0000081
#define MSR_LSTAR  0xC0000082
#define MSR_FMASK  0xC0000084
#define EFER_SCE   (1ull << 0)

/* Flags cleared on SYSCALL: TF, IF, DF, IOPL, NT, AC (the kernel starts with a clean state). */
#define SYSCALL_FMASK 0x47700ull

extern char syscall_entry[];
extern const char user_copy_fault[];
extern const uint64_t smap_sites[], smap_sites_end[], isr_smap_site[];

void user_cpu_init(void)
{
    cpu_init_xsave();                 /* XCR0 on every CPU (CR4.OSXSAVE is set by now) */
    spec_cpu_init();                  /* speculation mitigations (MSRs, percpu.mitig) */
    wrmsr(MSR_EFER, rdmsr(MSR_EFER) | EFER_SCE);
    /* STAR: SYSCALL loads CS = 0x08, SS = 0x10; SYSRET loads CS = base + 16 = 0x23 (user code)
     * and SS = base + 8 = 0x1B (user data), with base = 0x13 (GDT order in arch.h). The base
     * carries RPL 3 itself: AMD CPUs take SS from it as is, so with 0x10 the user's SS would be
     * 0x18 (RPL 0) and the next IRETQ to user mode would fault (found under WHPX; TCG forces 3). */
    wrmsr(MSR_STAR, ((uint64_t)(GDT_KDATA | 3) << 48) | ((uint64_t)GDT_KCODE << 32));
    wrmsr(MSR_LSTAR, (uint64_t)(uintptr_t)syscall_entry);
    wrmsr(MSR_FMASK, SYSCALL_FMASK);
}

/* Without SMAP, STAC/CLAC are invalid opcodes: overwrite them with a 3-byte NOP. Runs from
 * cpu_init, while the kernel still runs on the bootloader's writable mapping of itself. */
static void patch(uint64_t site)
{
    uint8_t *p = (uint8_t *)(uintptr_t)site;
    KASSERT(p[0] == 0x0F && p[1] == 0x01 && (p[2] == 0xCB || p[2] == 0xCA));
    p[0] = 0x0F;
    p[1] = 0x1F;
    p[2] = 0x00;                     /* nopl (%rax) */
}

void user_smap_patch(void)
{
    if (cpu.smap)
        return;
    for (const uint64_t *s = smap_sites; s < smap_sites_end; s++)
        patch(*s);
    patch(isr_smap_site[0]);
}

/* ---- fault fixup and user faults ------------------------------------------------------------ */

bool user_copy_fixup_try(struct interrupt_frame *f)
{
    if (f->vector != 14 || (f->cs & 3) || f->rip != (uint64_t)(uintptr_t)user_copy_fault)
        return false;
    if (read_cr2() >= USER_TOP)
        return false;                 /* a kernel address: the caller's check failed; a real bug */
    f->r8 = f->rcx;                   /* bytes left (syscall.asm: user_copy) */
    f->rcx = 0;                       /* the REP MOVSB resumes and stops at once */
    return true;
}

static const char *const vec_names[32] = {
    "Divide error (#DE)", "Debug (#DB)", "NMI", "Breakpoint (#BP)", "Overflow (#OF)",
    "Bound range exceeded (#BR)", "Invalid opcode (#UD)", "Device not available (#NM)",
    "Double fault (#DF)", "Coprocessor segment overrun", "Invalid TSS (#TS)", "Segment not present (#NP)",
    "Stack-segment fault (#SS)", "General protection (#GP)", "Page fault (#PF)", "Reserved (15)",
    "x87 FP error (#MF)", "Alignment check (#AC)", "Machine check (#MC)", "SIMD FP exception (#XM)",
    "Virtualization (#VE)", "Control protection (#CP)", "Reserved (22)", "Reserved (23)", "Reserved (24)",
    "Reserved (25)", "Reserved (26)", "Reserved (27)", "Hypervisor injection (#HV)",
    "VMM communication (#VC)", "Security exception (#SX)", "Reserved (31)",
};

static const char *pf_hint(uint64_t addr, uint64_t err)
{
    if (addr >= USER_TOP)
        return "access to kernel memory (supervisor pages)";
    if (addr < USER_BASE)
        return "NULL pointer dereference";
    if ((err & 1) && (err & 16))
        return "execute from non-executable memory (NX / W^X)";
    if ((err & 1) && (err & 2))
        return "write to read-only memory";
    if (!(err & 1))
        return "unmapped address (or a guard page)";
    return NULL;
}

#define USER_FAULT_REPORTS 64
static uint32_t fault_reports;

/* A fault in ring 3. The thread's exception handler or the process's supervisor may take it (and
 * resume the thread: return with interrupts off); otherwise report it, kill the process, end
 * this thread. */
void user_fault(struct interrupt_frame *f)
{
    uint64_t cr2 = read_cr2();        /* before anything can fault again */
    cpu_sti();
    if (dkrnl_user_exception(f, cr2)) {
        cpu_cli();                    /* the interrupt exit path runs with interrupts off */
        return;
    }
    struct thread *t = current_thread();
    const char *hint = NULL;
    if (f->vector == 14)
        hint = pf_hint(cr2, f->error);
    else if (f->vector == 13)
        hint = "privileged instruction, I/O port or non-canonical address";
    else if (f->vector == 6)
        hint = "invalid instruction";

    /* A program that faults in a loop (spawning crashing children) must not be able to flood
     * the console: full reports for the first USER_FAULT_REPORTS faults, then silence. */
    uint32_t nth = __atomic_fetch_add(&fault_reports, 1, __ATOMIC_RELAXED);
    if (nth >= USER_FAULT_REPORTS) {
        if (nth == USER_FAULT_REPORTS)
            kprintf("user fault: %u crash reports printed; further ones are suppressed\n", USER_FAULT_REPORTS);
        dkrnl_user_kill_current(DOS_EXIT_FAULT);
        uthread_exit(UTHREAD_EXIT_KILLED);
    }
    dkrnl_user_print_current();
    kprintf(" (thread '%s', tid %u, CPU %u): %s, error %#llx\n", t->name, t->tid, this_cpu(),
            vec_names[f->vector & 31], (unsigned long long)f->error);
    if (f->vector == 14)
        kprintf("  CR2=%016llx  [%s, %s]\n", (unsigned long long)cr2,
                (f->error & 1) ? "protection violation" : "not-present page",
                (f->error & 16) ? "instruction fetch" : (f->error & 2) ? "write" : "read");
    kprintf("  RIP=%016llx  RSP=%016llx  RFLAGS=%016llx\n", (unsigned long long)f->rip,
            (unsigned long long)f->rsp, (unsigned long long)f->rflags);
    kprintf("  RAX=%016llx  RBX=%016llx  RCX=%016llx  RDX=%016llx\n", (unsigned long long)f->rax,
            (unsigned long long)f->rbx, (unsigned long long)f->rcx, (unsigned long long)f->rdx);
    kprintf("  RSI=%016llx  RDI=%016llx  RBP=%016llx\n", (unsigned long long)f->rsi,
            (unsigned long long)f->rdi, (unsigned long long)f->rbp);
    if (hint)
        kprintf("  -> %s\n", hint);
    kprintf("  -> process killed (exit code FAULT); the kernel is unaffected\n");

    dkrnl_user_kill_current(DOS_EXIT_FAULT);
    uthread_exit(UTHREAD_EXIT_KILLED);
}

/* The IRETQ back to ring 3 faulted (isr.asm: GS was already the user's and has been taken back):
 * the user frame is bad. Kill the process rather than the kernel. */
extern const char isr_iret[];

void user_bad_iret_check(struct interrupt_frame *f)
{
    if ((f->cs & 3) || f->rip != (uint64_t)(uintptr_t)isr_iret || f->vector == 2 || f->vector == 8 || f->vector == 18)
        return;
    /* rip, cs, rflags, rsp, ss: copied first; under KPTI they are on this CPU's entry stack,
     * which the next entry from ring 3 reuses. */
    uint64_t target[5];
    memcpy(target, (const void *)(uintptr_t)f->rsp, sizeof(target));
    if (!(target[1] & 3) || !current_thread()->user)
        return;                       /* a return to kernel mode: a kernel bug, reported as such */
    cpu_sti();
    kprintf("user: return to ring 3 faulted (%s, error %#llx; CS %#llx SS %#llx RIP %#llx); killing the process\n",
            vec_names[f->vector & 31], (unsigned long long)f->error, (unsigned long long)target[1],
            (unsigned long long)target[4], (unsigned long long)target[0]);
    dkrnl_user_kill_current(DOS_EXIT_FAULT);
    uthread_exit(UTHREAD_EXIT_KILLED);
}

/* SYSRET refused a return address (syscall.asm): cannot happen through syscalls; fail closed. */
void user_bad_return(struct interrupt_frame *f)
{
    kprintf("user: refusing to return to RIP %#llx (not a user address); killing the process\n",
            (unsigned long long)f->rip);
    dkrnl_user_kill_current(DOS_EXIT_FAULT);
    uthread_exit(UTHREAD_EXIT_KILLED);
}

/* Interrupt exit to ring 3 (isr_dispatch, interrupts off): a killed thread ends here. */
void user_return_check(struct interrupt_frame *f)
{
    if (!(f->cs & 3))
        return;
    struct thread *t = current_thread();
    if (!__atomic_load_n(&t->kill, __ATOMIC_ACQUIRE))
        return;
    cpu_sti();
    uthread_exit(UTHREAD_EXIT_KILLED);
}
