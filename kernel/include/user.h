/* User mode, CPU side (kernel/arch/x86_64/user.c, syscall.asm). See docs/abi.md for the ABI. */
#ifndef DOS_USER_H
#define DOS_USER_H

#include <stdbool.h>
#include <stdint.h>
#include "arch.h"
#include "compiler.h"

/* Exit codes the kernel gives a process (ABI, docs/abi.md). */
#define DOS_EXIT_KILLED      ((int32_t)0x80000001)   /* process_kill */
#define DOS_EXIT_FAULT       ((int32_t)0x80000002)   /* a thread faulted (crash report on the console) */
#define UTHREAD_EXIT_KILLED  INT32_MIN               /* internal: the thread ends because its process died */

void user_cpu_init(void);         /* SYSCALL MSRs, on every CPU (gdt_init_cpu) */
void user_smap_patch(void);       /* boot CPU, cpu_init: NOP out STAC/CLAC without SMAP */
bool user_copy_fixup_try(struct interrupt_frame *f);   /* #PF inside user_copy: resume at the fixup */
/* Exception from ring 3: delivered to the thread's handler or the process's supervisor (returns,
 * interrupts off, to resume with the frame as they left it), else the process is killed. */
void user_fault(struct interrupt_frame *f);
NORETURN void user_bad_return(struct interrupt_frame *f);
void user_return_check(struct interrupt_frame *f);     /* interrupt exit: killed user thread? */
void user_bad_iret_check(struct interrupt_frame *f);   /* #GP etc. on the IRETQ to ring 3: kill the process */

/* Copy n bytes; returns the bytes NOT copied (0 = all). The user side must lie below USER_TOP. */
uint64_t user_copy(void *dst, const void *src, uint64_t n);

#endif
