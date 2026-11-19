/* ACPI table discovery (RSDP -> RSDT/XSDT -> MADT). All tables are checksum- and bounds-validated. */
#ifndef DOS_ACPI_H
#define DOS_ACPI_H

#include <stdbool.h>
#include <stdint.h>

#define ACPI_MAX_IOAPIC 8
#define ACPI_MAX_ISO    24
#define ACPI_MAX_CPUS   64

struct acpi_ioapic {
    uint8_t  id;
    uint32_t addr;
    uint32_t gsi_base;
};

/* Interrupt source override: ISA IRQ -> global system interrupt (+ polarity/trigger flags) */
struct acpi_iso {
    uint8_t  irq;
    uint32_t gsi;
    uint16_t flags;
};

struct acpi_info {
    bool     present;          /* RSDP found and valid */
    bool     madt;             /* MADT found and parsed */
    uint8_t  revision;
    char     oem[7];
    uint64_t lapic_addr;
    uint32_t cpu_count;        /* enabled CPUs (MADT local APIC / x2APIC entries) */
    uint32_t cpu_apic[ACPI_MAX_CPUS];   /* their APIC IDs */
    uint32_t ioapic_count;
    struct acpi_ioapic ioapic[ACPI_MAX_IOAPIC];
    uint32_t iso_count;
    struct acpi_iso iso[ACPI_MAX_ISO];
};

extern struct acpi_info acpi;

void acpi_init(void);
/* RSDP handed over by the boot loader (BootInfo.rsdp, UEFI): copied, used instead of the BIOS-area scan. */
void acpi_set_boot_rsdp(const void *rsdp);

/* A table from the root table by signature, mapped read-only + NX, length-bounded and checksum-
 * verified (its contents are still untrusted: the caller bounds-checks every field). NULL and
 * *len = 0 if absent. Used by the device framework (MCFG, DMAR). */
const void *acpi_find_table(const char sig[4], uint32_t *len);
/* The n-th table (from 0) with this signature, in root-table order (SSDTs). */
const void *acpi_find_table_nth(const char sig[4], uint32_t n, uint32_t *len);

/* A table by physical address (the FADT's DSDT pointer), validated like acpi_find_table. */
const void *acpi_table_at(uint64_t phys, uint32_t *len);

/* Fuzzing (ktest fuzz): parse `len` bytes as a MADT into scratch state; 0 = every invariant held. */
int acpi_madt_check(const void *table, uint32_t len);

#endif
