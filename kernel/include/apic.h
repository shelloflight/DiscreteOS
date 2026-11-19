/* Local APIC (per-CPU interrupts, timer, IPIs) and I/O APIC (device interrupt routing).
 * The local APIC runs in x2APIC mode (MSR access) when the CPU has it, else xAPIC (MMIO). */
#ifndef DOS_APIC_H
#define DOS_APIC_H

#include <stdbool.h>
#include <stdint.h>

void     lapic_init(void);        /* boot CPU: map, enable, pick x2APIC/xAPIC */
void     lapic_init_ap(void);     /* AP: enable its own LAPIC in the same mode */
void     lapic_resume_bsp(void);  /* S3: restore BSP's LAPIC and timer mode */
void     lapic_eoi(void);
uint32_t lapic_id(void);
bool     lapic_x2apic(void);

/* IPIs. Interrupts are saved/disabled internally. */
void     lapic_send_ipi(uint32_t apic_id, uint8_t vector);
void     lapic_send_nmi(uint32_t apic_id);
void     lapic_send_init(uint32_t apic_id);
void     lapic_send_sipi(uint32_t apic_id, uint8_t page);

/* Tickless timer ("clock event"): calibrates the LAPIC timer against the TSC and picks TSC-deadline
 * mode when the CPU has it, else LAPIC one-shot. ktime.c drives it through timer_program(). */
#define TIMER_NONE UINT64_MAX
void        timer_init(void);
void        timer_init_ap(void);                   /* AP: same mode and calibration as the boot CPU */
void        timer_program(uint64_t deadline_ns);   /* this CPU; absolute time_ns(); TIMER_NONE disarms; IRQs off */
void        timer_use_oneshot(void);               /* fall back from TSC-deadline mode (boot CPU, before SMP) */
const char *timer_mode(void);
uint64_t    timer_irqs(void);                      /* timer interrupts so far, all CPUs (stats) */

void     ioapic_init(void);
/* Route ISA IRQ `irq` (honouring ACPI overrides) to `vector` on the boot CPU, or mask it again. */
bool     ioapic_route_isa_irq(uint8_t irq, uint8_t vector);
bool     ioapic_route_sci(uint8_t irq, uint8_t vector);   /* level/low unless the MADT overrides */
void     ioapic_mask_isa_irq(uint8_t irq);
void     ioapic_reroute(void);                            /* interrupt remapping just turned on */
void     ioapic_resume(void);                             /* S3: mask all pins, then restore routed pins */
uint32_t ioapic_ids(uint8_t *out, uint32_t max);         /* ids of the I/O APICs in use */
uint32_t ioapic_routed(uint8_t id, uint16_t *out, uint32_t max); /* routed pins: vector | level << 8 */
/* APIC id device interrupts (MSI, I/O APIC) are sent to: the boot CPU. */
uint32_t irq_target_apic(void);

#endif
