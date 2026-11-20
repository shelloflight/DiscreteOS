/*
 * Power control (see power.h, docs/power.md).
 *
 * Switching off needs two things from ACPI: where the PM1 control registers are (FADT) and which
 * SLP_TYP value means S5 on this chipset (\_S5 in the DSDT, written in AML). At power_init a small
 * scanner reads \_S5 when it is a plain data package (practically every machine): find the name,
 * check it is a package, decode its first two integers; bounds-checked and fuzzed. Once the AML
 * interpreter has loaded the namespace (kernel/rust/src/dev/acpi.rs) it evaluates \_S5 properly
 * (a method too) and hands the result over with power_set_s5; before switching off it runs
 * \_TTS(5) and \_PTS(5).
 *
 * Resetting uses the FADT reset register when the firmware declares one, then the classic
 * fallbacks. Neither path needs AML.
 */

#include "power.h"
#include "rust.h"
#include "acpi.h"
#include "apic.h"
#include "arch.h"
#include "cet.h"
#include "cpu.h"
#include "cpupm.h"
#include "ktime.h"
#include "mm.h"
#include "percpu.h"
#include "printf.h"
#include "smp.h"
#include "string.h"
#include "thread.h"

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
#define FADT_FIRMWARE_CTRL 36
#define FADT_DSDT          40
#define FADT_SMI_CMD       48
#define FADT_ACPI_ENABLE   52
#define FADT_PM1A_EVT      56
#define FADT_PM1B_EVT      60
#define FADT_PM1A_CNT      64
#define FADT_PM1B_CNT      68
#define FADT_GPE0_BLK      80
#define FADT_GPE1_BLK      84
#define FADT_GPE0_LEN      92
#define FADT_GPE1_LEN      93
#define FADT_BOOT_ARCH     109
#define FADT_FLAGS         112
#define FADT_RESET_REG     116
#define FADT_RESET_VALUE   128
#define FADT_X_FIRMWARE_CTRL 132
#define FADT_X_DSDT        140
#define FADT_X_PM1A_EVT    148
#define FADT_X_PM1B_EVT    160
#define FADT_X_PM1A_CNT    172
#define FADT_X_PM1B_CNT    184
#define FADT_X_GPE0_BLK    220
#define FADT_X_GPE1_BLK    232
#define FADT_SLEEP_CONTROL 244

/* FACS field offsets (ACPI 6.5, table 5.15) */
#define FACS_WAKE_VEC      12
#define FACS_X_WAKE_VEC    24

#define FLAG_RESET_REG_SUP (1u << 10)
#define FLAG_HW_REDUCED    (1u << 20)
#define BOOT_ARCH_8042     (1u << 1)

#define WAK_STS     (1u << 15)   /* PM1 status (RW1C) */
#define PWRBTN_STS  (1u << 8)
#define PM1_ALL_STS 0xC731u      /* TMR, BM, GBL, PWRBTN, SLPBTN, RTC, PCIEXP_WAKE, WAK */
#define SLP_EN      (1u << 13)   /* PM1 control */
#define SLP_TYP_MASK (7u << 10)
#define SCI_EN      (1u << 0)
#define HWR_SLP_EN  (1u << 5)    /* sleep control register (hardware-reduced ACPI) */

extern int  s3_enter(uint64_t pm1a_addr, uint16_t pm1a_val,
                     uint64_t pm1b_addr, uint16_t pm1b_val, uint32_t mmio_mask);
extern char s3_wake_entry64[];

static struct {
    bool     fadt;
    bool     s5;               /* \_S5 found */
    uint8_t  typ_a, typ_b;
    bool     s3;               /* \_S3 found */
    uint8_t  s3_a, s3_b;
    uint8_t  s0_a, s0_b;       /* \_S0 (working state; 0 when absent) */
    uint64_t facs_pa;          /* physical address of FACS (0 = none/invalid) */
    bool     hw_reduced;
    struct gas pm1a_evt, pm1b_evt;
    struct gas pm1a, pm1b;     /* control blocks (address 0 = absent) */
    struct gas sleep_ctl;      /* hardware-reduced ACPI */
    struct gas gpe[2];         /* GPE0/GPE1 blocks: status bytes, then as many enable bytes */
    uint8_t  gpe_len[2];
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

/* The PM1 control value with SLP_TYP = typ and SLP_EN as asked; every other bit is kept as read.
 * SCI_EN above all: clearing it hands ACPI events to SMM, where firmware may take the press
 * that wakes the machine for a power-off request. */
static uint16_t pm1_cnt_value(const struct gas *g, uint8_t typ, bool en)
{
    uint16_t cnt = 0;
    (void)gas_read16(g, &cnt);
    cnt = (uint16_t)((cnt & ~(SLP_TYP_MASK | SLP_EN)) | ((uint32_t)(typ & 7) << 10));
    return en ? (uint16_t)(cnt | SLP_EN) : cnt;
}

/* Every GPE off and its status cleared before sleep, so no pending event wakes the machine at
 * once. No wake GPE is armed: the power button (a fixed-feature wake source) wakes it. The ACPI
 * thread re-enables the run-time GPEs after \_WAK. */
static void gpe_quiesce(void)
{
    for (int b = 0; b < 2; b++) {
        uint32_t half = pw.gpe_len[b] / 2u;
        if (!pw.gpe[b].address || !half)
            continue;
        struct gas g = pw.gpe[b];
        g.access_size = 1;
        g.bit_width = 8;
        for (uint32_t i = 0; i < half; i++) {
            g.address = pw.gpe[b].address + half + i;
            (void)gas_write(&g, 0, 1);              /* enable */
            g.address = pw.gpe[b].address + i;
            (void)gas_write(&g, 0xFF, 1);           /* status (write 1 to clear) */
        }
    }
}

static void pm1_clear_status(uint32_t bits)
{
    if (pw.pm1a_evt.address)
        (void)gas_write(&pw.pm1a_evt, bits, 2);
    if (pw.pm1b_evt.address)
        (void)gas_write(&pw.pm1b_evt, bits, 2);
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

static int power_parse_sx(const uint8_t *aml, uint32_t len, const char name[4], uint8_t *typ_a, uint8_t *typ_b)
{
    if (!aml || len < 8)
        return -1;
    const uint8_t *end = aml + len;
    for (const uint8_t *p = aml + 1; p + 4 <= end; p++) {
        if (memcmp(p, name, 4) != 0)
            continue;
        /* NameOp, optionally a root prefix: 08 [5C] "_Sx_" */
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

int power_parse_s5(const uint8_t *aml, uint32_t len, uint8_t *typ_a, uint8_t *typ_b)
{
    return power_parse_sx(aml, len, "_S5_", typ_a, typ_b);
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
    legacy_io_gas(&pw.pm1a_evt, rd32(f, FADT_PM1A_EVT));
    legacy_io_gas(&pw.pm1b_evt, rd32(f, FADT_PM1B_EVT));
    legacy_io_gas(&pw.pm1a, rd32(f, FADT_PM1A_CNT));
    legacy_io_gas(&pw.pm1b, rd32(f, FADT_PM1B_CNT));
    if (len >= FADT_X_PM1B_CNT + 12) {
        struct gas x;
        memcpy(&x, f + FADT_X_PM1A_EVT, sizeof(x));
        if (x.address)
            pw.pm1a_evt = x;
        memcpy(&x, f + FADT_X_PM1B_EVT, sizeof(x));
        if (x.address)
            pw.pm1b_evt = x;
        memcpy(&x, f + FADT_X_PM1A_CNT, sizeof(x));
        if (x.address)
            pw.pm1a = x;
        memcpy(&x, f + FADT_X_PM1B_CNT, sizeof(x));
        if (x.address)
            pw.pm1b = x;
    }
    if (len >= FADT_GPE1_LEN + 1) {
        legacy_io_gas(&pw.gpe[0], rd32(f, FADT_GPE0_BLK));
        legacy_io_gas(&pw.gpe[1], rd32(f, FADT_GPE1_BLK));
        pw.gpe_len[0] = f[FADT_GPE0_LEN];
        pw.gpe_len[1] = f[FADT_GPE1_LEN];
        if (len >= FADT_X_GPE1_BLK + 12) {
            struct gas x;
            memcpy(&x, f + FADT_X_GPE0_BLK, sizeof(x));
            if (x.address)
                pw.gpe[0] = x;
            memcpy(&x, f + FADT_X_GPE1_BLK, sizeof(x));
            if (x.address)
                pw.gpe[1] = x;
        }
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

    /* FACS: waking vector for S3 resume (not checksummed by ACPI; checked by signature + length). */
    uint64_t facs_pa = len >= FADT_X_FIRMWARE_CTRL + 8 ? rd64(f, FADT_X_FIRMWARE_CTRL) : 0;
    if (!facs_pa)
        facs_pa = rd32(f, FADT_FIRMWARE_CTRL);
    if (facs_pa && facs_pa < PHYSMAP_SIZE - 64) {
        const uint8_t *facs = vmm_map_phys(facs_pa, 64, 0);
        if (facs && memcmp(facs, "FACS", 4) == 0 && rd32(facs, 4) >= 64)
            pw.facs_pa = facs_pa;
    }

    uint64_t dsdt = len >= FADT_X_DSDT + 8 ? rd64(f, FADT_X_DSDT) : 0;
    if (!dsdt)
        dsdt = rd32(f, FADT_DSDT);
    uint32_t dlen = 0;
    const uint8_t *d = acpi_table_at(dsdt, &dlen);
    if (d && memcmp(d, "DSDT", 4) == 0 && dlen > 36) {
        pw.s5 = power_parse_s5(d + 36, dlen - 36, &pw.typ_a, &pw.typ_b) == 0;
        pw.s3 = power_parse_sx(d + 36, dlen - 36, "_S3_", &pw.s3_a, &pw.s3_b) == 0;
        (void)power_parse_sx(d + 36, dlen - 36, "_S0_", &pw.s0_a, &pw.s0_b);
    }

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

void power_set_s5(uint8_t typ_a, uint8_t typ_b)
{
    bool changed = !pw.s5 || pw.typ_a != (typ_a & 7) || pw.typ_b != (typ_b & 7);
    pw.typ_a = typ_a & 7;
    pw.typ_b = typ_b & 7;
    pw.s5 = true;
    if (changed)
        kprintf("Power: \\_S5 from AML: SLP_TYP %u/%u%s\n", pw.typ_a, pw.typ_b,
                power_off_supported() ? "; ACPI power-off available" : "");
}

void power_set_s3(uint8_t typ_a, uint8_t typ_b)
{
    bool changed = !pw.s3 || pw.s3_a != (typ_a & 7) || pw.s3_b != (typ_b & 7);
    pw.s3_a = typ_a & 7;
    pw.s3_b = typ_b & 7;
    pw.s3 = true;
    if (changed)
        kprintf("Power: \\_S3 from AML: SLP_TYP %u/%u%s\n", pw.s3_a, pw.s3_b,
                power_suspend_supported() ? "; ACPI S3 sleep available" : "");
}

void *acpi_mmio_map(uint64_t pa, uint32_t len)
{
    if (!pa || !len || len > PAGE_SIZE || pa >= PHYSMAP_SIZE - len || pmm_range_is_ram(pa, len))
        return NULL;
    return vmm_map_phys_exact(pa, len, VMM_W | VMM_UC);
}

bool power_off_supported(void)
{
    return pw.s5 && (pw.hw_reduced ? pw.sleep_ctl.address != 0 : pw.pm1a.address != 0);
}

bool power_suspend_supported(void)
{
    return pw.s3 && pw.facs_pa != 0 && !pw.hw_reduced && pw.pm1a.address != 0 && smp_low_ram_ok();
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
    dkrnl_acpi_prepare_sleep(5);                /* \_TTS(5), \_PTS(5) once the namespace is loaded */
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
            gas_write(&pw.pm1b, pm1_cnt_value(&pw.pm1b, pw.typ_b, true), 2);
        gas_write(&pw.pm1a, pm1_cnt_value(&pw.pm1a, pw.typ_a, true), 2);
        if (f & (1u << 9))
            cpu_sti();
    }
    wait_ms(2000);
    kprintf("Power: ACPI S5 did not switch off\n");
}

/* Called from s3_wake_entry64 on the saved stack, interrupts and shadow stacks still off: the
 * CPU state firmware reset that the wake path needs, the IDT first of all, so that a fault is
 * reported instead of triple-faulting back into the firmware's resume path. Shadow stacks go on
 * only after this (the GDT reload's far return would raise #CP with them on). Returns the
 * shadow-stack restore token for `ssp` (0 when shadow stacks are off). */
uint64_t s3_resume_cpu(uint64_t ssp);
uint64_t s3_resume_cpu(uint64_t ssp)
{
    cpu_init_pat();
    gdt_resume_cpu(&bsp_percpu);       /* GDT, TR, segment bases, XCR0, mitigations, SYSCALL */
    idt_load();
    return cet_ss ? cet_bsp_wake_token(ssp) : 0;
}

int power_suspend(void)
{
    if (!power_suspend_supported()) {
        kprintf("Power: ACPI S3 sleep is not available on this machine\n");
        return -1;
    }

    /* Firmware always resumes S3 on the BSP (CPU 0); migrate there before parking APs. */
    struct thread *cur = thread_current();
    uint64_t old_aff = cur->affinity;
    if (!thread_set_affinity(THREAD_CPU(0)))
        return -1;

    dkrnl_tpm_suspend();                        /* TPM2_Shutdown(STATE), for firmware's Startup(STATE) */
    dkrnl_acpi_prepare_sleep(3);

    /* Ensure ACPI mode is enabled before entering S3. */
    uint16_t cnt = 0;
    if (gas_read16(&pw.pm1a, &cnt) && !(cnt & SCI_EN) && pw.smi_cmd && pw.smi_cmd <= 0xFFFF && pw.acpi_enable) {
        outb((uint16_t)pw.smi_cmd, pw.acpi_enable);
        for (int i = 0; i < 300 && gas_read16(&pw.pm1a, &cnt) && !(cnt & SCI_EN); i++)
            wait_ms(10);
    }

    volatile uint8_t *facs = vmm_map_phys_rw(pw.facs_pa, 64);
    if (!facs) {
        thread_set_affinity(old_aff);
        return -1;
    }

    uint64_t pm1a_addr = pw.pm1a.address;
    uint64_t pm1b_addr = pw.pm1b.address;
    uint32_t mmio_mask = 0;
    if (pw.pm1a.space == GAS_MEMORY) {
        pm1a_addr = (uint64_t)(uintptr_t)vmm_map_phys(pw.pm1a.address, 8, VMM_W | VMM_UC);
        mmio_mask |= 1;
    } else if (pw.pm1a.space != GAS_IO || pw.pm1a.address > 0xFFFF) {
        thread_set_affinity(old_aff);
        return -1;
    }
    if (pm1b_addr) {
        if (pw.pm1b.space == GAS_MEMORY) {
            pm1b_addr = (uint64_t)(uintptr_t)vmm_map_phys(pw.pm1b.address, 8, VMM_W | VMM_UC);
            mmio_mask |= 2;
        } else if (pw.pm1b.space != GAS_IO || pw.pm1b.address > 0xFFFF) {
            pm1b_addr = 0;
        }
    }

    kprintf("Power: entering ACPI S3 (FACS %#llx, SLP_TYP %u/%u)\n",
            (unsigned long long)pw.facs_pa, pw.s3_a, pw.s3_b);

    if (!smp_suspend()) {
        smp_resume();
        thread_set_affinity(old_aff);
        return -1;
    }

    dkrnl_pci_suspend();

    uint32_t wake_vec = smp_setup_s3_trampoline((uint64_t)(uintptr_t)s3_wake_entry64);
    *(volatile uint32_t *)(facs + FACS_WAKE_VEC) = wake_vec;
    *(volatile uint64_t *)(facs + FACS_X_WAKE_VEC) = 0;
    __asm__ volatile("mfence" ::: "memory");

    cpu_cli();
    /* Nothing pending may wake the machine at once: GPEs off, fixed status (WAK_STS above all,
     * ACPI 6.5, 16.1.6) cleared before SLP_EN. */
    gpe_quiesce();
    pm1_clear_status(PM1_ALL_STS);
    time_suspend();
    uint16_t val_a = pm1_cnt_value(&pw.pm1a, pw.s3_a, true);
    uint16_t val_b = pm1b_addr ? pm1_cnt_value(&pw.pm1b, pw.s3_b, true) : 0;
    int r = s3_enter(pm1a_addr, val_a, pm1b_addr, val_b, mmio_mask);

    /* ---- BSP wake path (interrupts off; s3_resume_cpu reloaded GDT and IDT) ------------------ */
    *(volatile uint32_t *)(facs + FACS_WAKE_VEC) = 0;
    smp_clear_s3_trampoline();
    /* Back to S0 in PM1 control: firmware that reads SLP_TYP to tell a resume from a boot would
     * otherwise take the next reset for another S3 resume. And drop the power-button press that
     * woke the machine: once SCI is on again it would reach init as a shutdown request. */
    if (pm1b_addr)
        gas_write(&pw.pm1b, pm1_cnt_value(&pw.pm1b, pw.s0_b, false), 2);
    gas_write(&pw.pm1a, pm1_cnt_value(&pw.pm1a, pw.s0_a, false), 2);
    pm1_clear_status(PWRBTN_STS | WAK_STS);

    time_resume();
    pic_disable();
    lapic_resume_bsp();
    time_resume_cpu();

    dkrnl_pci_resume();
    dkrnl_iommu_resume();
    ioapic_resume();

    cpu_sti();
    smp_resume();
    cpupm_resume();
    dkrnl_acpi_wake(3);
    dkrnl_tpm_resume();

    thread_set_affinity(old_aff);
    if (r == 0)
        kprintf("Power: resumed from ACPI S3 (%u CPU(s) online)\n", smp_cpus());
    else
        kprintf("Power: ACPI S3 did not enter sleep\n");
    return r;
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
