/*
 * Power control (see power.h, docs/power.md).
 *
 * Switching off needs two things from ACPI: where the PM1 control registers are (FADT) and which
 * SLP_TYP value means S5 on this chipset (the \_S5 package in the DSDT, written in AML). A full AML
 * interpreter is future work; \_S5 is a plain data package on practically every machine, so a
 * small scanner reads it: find the name, check it is a package, decode its first two integers.
 * Everything it reads is bounds-checked (the tables are firmware input), and it is fuzzed.
 *
 * Resetting uses the FADT reset register when the firmware declares one, then the classic
 * fallbacks. Neither path needs AML.
 */

#include "power.h"
#include "acpi.h"
#include "cpu.h"
#include "ktime.h"
#include "mm.h"
#include "printf.h"
#include "string.h"

/* ACPI Generic Address Structure */
struct __attribute__((packed)) gas {
    uint8_t  space;          /* 0 memory, 1 system I/O */
    uint8_t  bit_width;
    uint8_t  bit_offset;
    uint8_t  access_size;    /* 1 byte, 2 word, 3 dword, 4 qword (0: from bit_width) */
    uint64_t address;
};
_Static_assert(sizeof(struct gas) == 12, "GAS layout");

#define GAS_MEMORY 0
#define GAS_IO     1

/* FADT field offsets (ACPI 6.5, table 5.9) */
#define FADT_DSDT          40
#define FADT_SMI_CMD       48
#define FADT_ACPI_ENABLE   52
#define FADT_PM1A_CNT      64
#define FADT_PM1B_CNT      68
#define FADT_BOOT_ARCH     109
#define FADT_FLAGS         112
#define FADT_RESET_REG     116
#define FADT_RESET_VALUE   128
#define FADT_X_DSDT        140
#define FADT_X_PM1A_CNT    172
#define FADT_X_PM1B_CNT    184
#define FADT_SLEEP_CONTROL 244

#define FLAG_RESET_REG_SUP (1u << 10)
#define FLAG_HW_REDUCED    (1u << 20)
#define BOOT_ARCH_8042     (1u << 1)

#define SLP_EN      (1u << 13)   /* PM1 control */
#define SCI_EN      (1u << 0)
#define HWR_SLP_EN  (1u << 5)    /* sleep control register (hardware-reduced ACPI) */

static struct {
    bool     fadt;
    bool     s5;               /* \_S5 found */
    uint8_t  typ_a, typ_b;
    bool     hw_reduced;
    struct gas pm1a, pm1b;     /* control blocks (address 0 = absent) */
    struct gas sleep_ctl;      /* hardware-reduced ACPI */
    uint32_t smi_cmd;
    uint8_t  acpi_enable;
    bool     reset_reg;
    struct gas reset;
    uint8_t  reset_value;
    bool     i8042;
} pw;

static void out16(uint16_t port, uint16_t v) { __asm__ volatile("outw %0, %1" : : "a"(v), "Nd"(port)); }
static void out32(uint16_t port, uint32_t v) { __asm__ volatile("outl %0, %1" : : "a"(v), "Nd"(port)); }
static uint16_t in16(uint16_t port)
{
    uint16_t v;
    __asm__ volatile("inw %1, %0" : "=a"(v) : "Nd"(port));
    return v;
}

static uint32_t gas_bytes(const struct gas *g, uint32_t dflt)
{
    switch (g->access_size) {
    case 1: return 1;
    case 2: return 2;
    case 3: return 4;
    default: break;
    }
    if (g->bit_width == 8 || g->bit_width == 16 || g->bit_width == 32)
        return g->bit_width / 8u;
    return dflt;
}

/* Only I/O ports and memory below the direct map's reach; anything else is refused (false). */
static bool gas_write(const struct gas *g, uint32_t v, uint32_t dflt_bytes)
{
    uint32_t n = gas_bytes(g, dflt_bytes);
    if (g->space == GAS_IO && g->address && g->address <= 0xFFFF) {
        uint16_t port = (uint16_t)g->address;
        if (n == 1)
            outb(port, (uint8_t)v);
        else if (n == 2)
            out16(port, (uint16_t)v);
        else
            out32(port, v);
        return true;
    }
    if (g->space == GAS_MEMORY && g->address && g->address < PHYSMAP_SIZE - 8) {
        volatile uint8_t *p = vmm_map_phys(g->address, 8, VMM_W | VMM_UC);
        if (n == 1)
            *p = (uint8_t)v;
        else if (n == 2)
            *(volatile uint16_t *)p = (uint16_t)v;
        else
            *(volatile uint32_t *)p = v;
        return true;
    }
    return false;
}

static bool gas_read16(const struct gas *g, uint16_t *out)
{
    if (g->space == GAS_IO && g->address && g->address <= 0xFFFF) {
        *out = in16((uint16_t)g->address);
        return true;
    }
    if (g->space == GAS_MEMORY && g->address && g->address < PHYSMAP_SIZE - 8) {
        *out = *(volatile uint16_t *)vmm_map_phys(g->address, 8, VMM_W | VMM_UC);
        return true;
    }
    return false;
}

/* ---- \_S5 in AML -------------------------------------------------------------------------------- */

/* PkgLength at p (inside [p, end)): bytes it occupies, or 0 if malformed. */
static uint32_t pkg_length(const uint8_t *p, const uint8_t *end, uint32_t *value)
{
    if (p >= end)
        return 0;
    uint32_t extra = p[0] >> 6;
    if ((uint32_t)(end - p) < 1 + extra)
        return 0;
    if (!extra) {
        *value = p[0] & 0x3Fu;
        return 1;
    }
    uint32_t v = p[0] & 0x0Fu;
    for (uint32_t i = 0; i < extra; i++)
        v |= (uint32_t)p[1 + i] << (4 + 8 * i);
    *value = v;
    return 1 + extra;
}

/* One integer data object at *pp; advances *pp. */
static bool aml_integer(const uint8_t **pp, const uint8_t *end, uint64_t *out)
{
    const uint8_t *p = *pp;
    if (p >= end)
        return false;
    uint32_t n;
    switch (p[0]) {
    case 0x00: *out = 0; *pp = p + 1; return true;            /* ZeroOp */
    case 0x01: *out = 1; *pp = p + 1; return true;            /* OneOp */
    case 0xFF: *out = ~0ull; *pp = p + 1; return true;        /* OnesOp */
    case 0x0A: n = 1; break;                                  /* BytePrefix */
    case 0x0B: n = 2; break;                                  /* WordPrefix */
    case 0x0C: n = 4; break;                                  /* DWordPrefix */
    case 0x0E: n = 8; break;                                  /* QWordPrefix */
    default: return false;
    }
    if ((uint64_t)(end - p) < 1u + n)
        return false;
    uint64_t v = 0;
    for (uint32_t i = 0; i < n; i++)
        v |= (uint64_t)p[1 + i] << (8 * i);
    *out = v;
    *pp = p + 1 + n;
    return true;
}

int power_parse_s5(const uint8_t *aml, uint32_t len, uint8_t *typ_a, uint8_t *typ_b)
{
    if (!aml || len < 8)
        return -1;
    const uint8_t *end = aml + len;
    for (const uint8_t *p = aml + 1; p + 4 <= end; p++) {
        if (memcmp(p, "_S5_", 4) != 0)
            continue;
        /* NameOp, optionally a root prefix: 08 [5C] "_S5_" */
        bool named = p[-1] == 0x08 || (p[-1] == 0x5C && p - aml >= 2 && p[-2] == 0x08);
        if (!named)
            continue;
        const uint8_t *q = p + 4;
        if (q >= end || *q != 0x12)                     /* PackageOp */
            continue;
        q++;
        uint32_t plen = 0, used = pkg_length(q, end, &plen);
        if (!used || plen < used + 1 || plen > (uint32_t)(end - q))
            continue;
        const uint8_t *pend = q + plen;                 /* the package ends here */
        q += used;
        uint8_t count = *q++;
        if (count < 1)
            continue;
        uint64_t a = 0, b = 0;
        if (!aml_integer(&q, pend, &a))
            continue;
        if (count >= 2 && !aml_integer(&q, pend, &b))
            b = a;
        else if (count < 2)
            b = a;
        *typ_a = (uint8_t)(a & 7);
        *typ_b = (uint8_t)(b & 7);
        return 0;
    }
    return -1;
}

/* ---- set-up --------------------------------------------------------------------------------- */

static uint32_t rd32(const uint8_t *f, uint32_t off) { uint32_t v; memcpy(&v, f + off, 4); return v; }
static uint64_t rd64(const uint8_t *f, uint32_t off) { uint64_t v; memcpy(&v, f + off, 8); return v; }

static void legacy_io_gas(struct gas *g, uint32_t port)
{
    memset(g, 0, sizeof(*g));
    if (port && port <= 0xFFFF) {
        g->space = GAS_IO;
        g->bit_width = 16;
        g->address = port;
    }
}

void power_init(void)
{
    uint32_t len = 0;
    const uint8_t *f = acpi_find_table("FACP", &len);
    pw.i8042 = true;                                    /* no FADT: legacy PC */
    if (!f || len < 116) {
        kprintf("Power: no FADT; reset by the keyboard controller or port 0xCF9, no ACPI power-off\n");
        return;
    }
    pw.fadt = true;
    uint32_t flags = rd32(f, FADT_FLAGS);
    uint16_t arch = (uint16_t)(f[FADT_BOOT_ARCH] | f[FADT_BOOT_ARCH + 1] << 8);
    pw.i8042 = (arch & BOOT_ARCH_8042) != 0 || arch == 0;   /* 0: field unused (old FADTs) */
    pw.smi_cmd = rd32(f, FADT_SMI_CMD);
    pw.acpi_enable = f[FADT_ACPI_ENABLE];
    legacy_io_gas(&pw.pm1a, rd32(f, FADT_PM1A_CNT));
    legacy_io_gas(&pw.pm1b, rd32(f, FADT_PM1B_CNT));
    if (len >= FADT_X_PM1B_CNT + 12) {
        struct gas x;
        memcpy(&x, f + FADT_X_PM1A_CNT, sizeof(x));
        if (x.address)
            pw.pm1a = x;
        memcpy(&x, f + FADT_X_PM1B_CNT, sizeof(x));
        if (x.address)
            pw.pm1b = x;
    }
    if (len >= FADT_RESET_VALUE + 1 && (flags & FLAG_RESET_REG_SUP)) {
        memcpy(&pw.reset, f + FADT_RESET_REG, sizeof(pw.reset));
        pw.reset_value = f[FADT_RESET_VALUE];
        pw.reset_reg = pw.reset.address != 0;
    }
    if ((flags & FLAG_HW_REDUCED) && len >= FADT_SLEEP_CONTROL + 12) {
        pw.hw_reduced = true;
        memcpy(&pw.sleep_ctl, f + FADT_SLEEP_CONTROL, sizeof(pw.sleep_ctl));
    }

    uint64_t dsdt = len >= FADT_X_DSDT + 8 ? rd64(f, FADT_X_DSDT) : 0;
    if (!dsdt)
        dsdt = rd32(f, FADT_DSDT);
    uint32_t dlen = 0;
    const uint8_t *d = acpi_table_at(dsdt, &dlen);
    if (d && memcmp(d, "DSDT", 4) == 0 && dlen > 36)
        pw.s5 = power_parse_s5(d + 36, dlen - 36, &pw.typ_a, &pw.typ_b) == 0;

    char off[96], rst[64];
    if (!pw.s5)
        ksnprintf(off, sizeof(off), "no power-off (no \\_S5 data package in the DSDT)");
    else if (pw.hw_reduced)
        ksnprintf(off, sizeof(off), "power-off by ACPI S5 (SLP_TYP %u, sleep control register)", pw.typ_a);
    else if (!pw.pm1a.address)
        ksnprintf(off, sizeof(off), "no power-off (no PM1 control block)");
    else
        ksnprintf(off, sizeof(off), "power-off by ACPI S5 (SLP_TYP %u/%u, PM1a %s %#llx)", pw.typ_a, pw.typ_b,
                  pw.pm1a.space == GAS_IO ? "port" : "MMIO", (unsigned long long)pw.pm1a.address);
    if (pw.reset_reg)
        ksnprintf(rst, sizeof(rst), "reset register (%s %#llx = %#x)", pw.reset.space == GAS_IO ? "port" : "MMIO",
                  (unsigned long long)pw.reset.address, pw.reset_value);
    else
        ksnprintf(rst, sizeof(rst), "%s", pw.i8042 ? "keyboard controller, then port 0xCF9" : "port 0xCF9");
    kprintf("Power: %s; reset by %s\n", off, rst);
}

bool power_off_supported(void)
{
    return pw.s5 && (pw.hw_reduced ? pw.sleep_ctl.address != 0 : pw.pm1a.address != 0);
}

static void wait_ms(uint64_t ms)
{
    uint64_t end = time_ns() + ms * 1000000ull;
    while (time_ns() < end)
        __asm__ volatile("pause");
}

void power_off(void)
{
    if (!power_off_supported()) {
        kprintf("Power: ACPI power-off is not available on this machine\n");
        return;
    }
    kprintf("Power: switching off (ACPI S5)\n");
    if (pw.hw_reduced) {
        gas_write(&pw.sleep_ctl, (uint32_t)(pw.typ_a << 2) | HWR_SLP_EN, 1);
    } else {
        /* ACPI mode first (UEFI firmware hands over in it; old BIOSes may not). */
        uint16_t cnt = 0;
        if (gas_read16(&pw.pm1a, &cnt) && !(cnt & SCI_EN) && pw.smi_cmd && pw.smi_cmd <= 0xFFFF && pw.acpi_enable) {
            outb((uint16_t)pw.smi_cmd, pw.acpi_enable);
            for (int i = 0; i < 300 && gas_read16(&pw.pm1a, &cnt) && !(cnt & SCI_EN); i++)
                wait_ms(10);
        }
        uint64_t f;
        __asm__ volatile("pushfq; popq %0; cli" : "=r"(f) : : "memory");
        if (pw.pm1b.address)
            gas_write(&pw.pm1b, (uint32_t)pw.typ_b << 10 | SLP_EN, 2);
        gas_write(&pw.pm1a, (uint32_t)pw.typ_a << 10 | SLP_EN, 2);
        if (f & (1u << 9))
            cpu_sti();
    }
    wait_ms(2000);
    kprintf("Power: ACPI S5 did not switch off\n");
}

void power_reboot(void)
{
    kprintf("Power: resetting\n");
    if (pw.reset_reg) {
        gas_write(&pw.reset, pw.reset_value, 1);
        wait_ms(500);
    }
    if (pw.i8042) {
        for (int i = 0; i < 1000 && (inb(0x64) & 2); i++)
            io_wait();
        outb(0x64, 0xFE);                       /* pulse the reset line */
        wait_ms(500);
    }
    outb(0xCF9, 0x02);
    outb(0xCF9, 0x06);                          /* full reset */
    wait_ms(500);
    kprintf("Power: no reset method worked; triple fault\n");
    struct __attribute__((packed)) { uint16_t limit; uint64_t base; } idt = { 0, 0 };
    __asm__ volatile("lidt %0; int3" : : "m"(idt));
    cpu_halt_forever();
}
