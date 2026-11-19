/*
 * Power control: switch the machine off (ACPI S5) and reset it (docs/power.md).
 *
 *   power_init()      after acpi_init: reads the FADT and the DSDT's \_S5 package, prints one
 *                     "Power:" line with what was found
 *   power_off()       ACPI S5; returns only if the machine did not switch off
 *   power_reboot()    FADT reset register, then the 8042 keyboard controller, then port 0xCF9,
 *                     then a triple fault; does not return
 *
 * User space reaches these through the `system_power` syscall, which needs the POWER resource
 * (given to init only); the kernel debugger has `poweroff` and `reboot`.
 */
#ifndef DOS_POWER_H
#define DOS_POWER_H

#include <stdbool.h>
#include <stdint.h>

void power_init(void);
bool power_off_supported(void);
bool power_suspend_supported(void);
/* The AML interpreter evaluated \_S5 / \_S3: use these SLP_TYP values. */
void power_set_s5(uint8_t typ_a, uint8_t typ_b);
void power_set_s3(uint8_t typ_a, uint8_t typ_b);
/* Map `len` bytes (at most a page) of physical memory for AML operation regions: writable and
 * uncached, only outside usable RAM and inside the direct map, and not where the kernel already
 * mapped the page differently (read-only firmware tables); NULL otherwise (the access is refused). */
void *acpi_mmio_map(uint64_t pa, uint32_t len);
void power_off(void);
int  power_suspend(void);
void power_reboot(void) __attribute__((noreturn));

/* The \_S5 package in AML (`len` bytes): SLP_TYPa/b (0-7). 0 if found, -1 if not. Never reads
 * outside [aml, aml + len). Fuzzed by ktest fuzz (rust_acpi_fuzz). */
int power_parse_s5(const uint8_t *aml, uint32_t len, uint8_t *typ_a, uint8_t *typ_b);

#endif
