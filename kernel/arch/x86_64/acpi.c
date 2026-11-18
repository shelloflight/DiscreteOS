/*
 * ACPI discovery: RSDP -> RSDT/XSDT -> MADT (interrupt controllers, CPUs, IRQ overrides).
 * Firmware tables are untrusted input: every table is mapped read-only + NX, length-bounded and
 * checksum-verified before use; MADT entries are bounds-checked individually.
 */

#include <stddef.h>
#include <stdint.h>
#include "acpi.h"
#include "compiler.h"
#include "printf.h"
#include "string.h"
#include "mm.h"

struct acpi_info acpi;

/* The root table's entries, kept for acpi_find_table() (device framework: MCFG, DMAR, IVRS). */
static const uint8_t *root_entries;
static size_t root_count, root_entry_size;

struct PACKED rsdp {
    char     signature[8];      /* "RSD PTR " */
    uint8_t  checksum;
    char     oem[6];
    uint8_t  revision;
    uint32_t rsdt;
    /* ACPI 2.0+ */
    uint32_t length;
    uint64_t xsdt;
    uint8_t  ext_checksum;
    uint8_t  reserved[3];
};

struct PACKED sdt_header {
    char     signature[4];
    uint32_t length;
    uint8_t  revision;
    uint8_t  checksum;
    char     oem[6];
    char     oem_table[8];
    uint32_t oem_revision;
    uint32_t creator_id;
    uint32_t creator_revision;
};

#define TABLE_MAX_LEN (1u << 20)   /* sanity bound for any single table */

static bool checksum_ok(const void *p, size_t len)
{
    uint8_t sum = 0;
    for (size_t i = 0; i < len; i++)
        sum = (uint8_t)(sum + ((const uint8_t *)p)[i]);
    return sum == 0;
}

static bool rsdp_valid(const struct rsdp *r, size_t max_len)
{
    if (memcmp(r->signature, "RSD PTR ", 8) != 0 || !checksum_ok(r, 20))
        return false;
    return r->revision < 2 || (r->length >= sizeof(*r) && r->length <= max_len && checksum_ok(r, r->length));
}

static const struct rsdp *rsdp_scan(uint64_t start, uint64_t len)
{
    const uint8_t *base = vmm_map_phys(start, len, 0);    /* read-only, NX */
    for (uint64_t off = 0; off + sizeof(struct rsdp) <= len; off += 16) {
        const struct rsdp *r = (const struct rsdp *)(base + off);
        if (rsdp_valid(r, 4096))
            return r;
    }
    return NULL;
}

/* UEFI: the loader passes the RSDP from the configuration table; kmain copies it here early. */
static struct rsdp boot_rsdp;
static bool boot_rsdp_given;

void acpi_set_boot_rsdp(const void *phys_identity)
{
    memcpy(&boot_rsdp, phys_identity, sizeof(boot_rsdp));
    boot_rsdp_given = true;
}

static const struct rsdp *rsdp_find(void)
{
    if (boot_rsdp_given) {
        if (rsdp_valid(&boot_rsdp, sizeof(boot_rsdp)))
            return &boot_rsdp;
        kprintf("ACPI: the RSDP from the boot loader is invalid; scanning the BIOS areas\n");
    }
    /* 1 KiB at the start of the EBDA (segment stored at 0x40E), then the BIOS area 0xE0000-0xFFFFF. */
    uint64_t ebda = (uint64_t)(*(const volatile uint16_t *)vmm_map_phys(0x40E, 2, 0)) << 4;
    if (ebda >= 0x80000 && ebda < 0xA0000) {
        const struct rsdp *r = rsdp_scan(ebda, 1024);
        if (r)
            return r;
    }
    return rsdp_scan(0xE0000, 0x20000);
}

/* Map and validate a table; returns NULL if it is unusable. */
static const struct sdt_header *table_get(uint64_t phys)
{
    if (!phys || phys >= PHYSMAP_SIZE - TABLE_MAX_LEN)
        return NULL;
    const struct sdt_header *h = vmm_map_phys(phys, sizeof(struct sdt_header), 0);   /* read-only, NX */
    if (h->length < sizeof(*h) || h->length > TABLE_MAX_LEN)
        return NULL;
    vmm_map_phys(phys, h->length, 0);
    if (!checksum_ok(h, h->length))
        return NULL;
    return h;
}

/* A CPU listed twice (local APIC + x2APIC entry) counts once; more than ACPI_MAX_CPUS are ignored. */
static void add_cpu(struct acpi_info *out, uint32_t apic_id)
{
    for (uint32_t i = 0; i < out->cpu_count; i++)
        if (out->cpu_apic[i] == apic_id)
            return;
    if (out->cpu_count < ACPI_MAX_CPUS)
        out->cpu_apic[out->cpu_count++] = apic_id;
}

/* MADT: `len` bytes at `t` (the header's length field is not trusted: `len` bounds every read).
 * Fills `out`; returns false if the table is too short to hold a MADT. Also the fuzzing entry
 * point (ktest fuzz: acpi_madt_check). */
static bool madt_parse_into(const uint8_t *base, uint32_t len_avail, struct acpi_info *out, bool quiet)
{
    const uint8_t *end = base + len_avail;
    if (len_avail < sizeof(struct sdt_header) + 8)
        return false;
    const uint8_t *p = base + sizeof(struct sdt_header) + 8;   /* + LAPIC address (u32) + flags (u32) */
    uint32_t lapic32;
    memcpy(&lapic32, base + sizeof(struct sdt_header), 4);
    out->lapic_addr = lapic32;

    while (end - p >= 2) {
        uint8_t type = p[0], len = p[1];
        if (len < 2 || len > end - p) {
            if (!quiet)
                kprintf("ACPI: malformed MADT entry (type %u, len %u), stopping\n", type, len);
            break;
        }
        switch (type) {
        case 0:                              /* processor local APIC */
            if (len >= 8) {
                uint32_t flags;
                memcpy(&flags, p + 4, 4);
                if (flags & 1)               /* enabled (online-capable = hot-plug, not present) */
                    add_cpu(out, p[3]);
            }
            break;
        case 9:                              /* processor local x2APIC */
            if (len >= 16) {
                uint32_t id, flags;
                memcpy(&id, p + 4, 4);
                memcpy(&flags, p + 8, 4);
                if (flags & 1)
                    add_cpu(out, id);
            }
            break;
        case 1:                              /* I/O APIC */
            if (len >= 12 && out->ioapic_count < ACPI_MAX_IOAPIC) {
                struct acpi_ioapic *io = &out->ioapic[out->ioapic_count++];
                io->id = p[2];
                memcpy(&io->addr, p + 4, 4);
                memcpy(&io->gsi_base, p + 8, 4);
            }
            break;
        case 2:                              /* interrupt source override */
            if (len >= 10 && p[2] == 0 && out->iso_count < ACPI_MAX_ISO) {
                struct acpi_iso *iso = &out->iso[out->iso_count++];
                iso->irq = p[3];
                memcpy(&iso->gsi, p + 4, 4);
                memcpy(&iso->flags, p + 8, 2);
            }
            break;
        case 5:                              /* 64-bit local APIC address override */
            if (len >= 12)
                memcpy(&out->lapic_addr, p + 4, 8);
            break;
        default:
            break;
        }
        p += len;
    }
    out->madt = true;
    return true;
}

static void madt_parse(const struct sdt_header *h)
{
    madt_parse_into((const uint8_t *)h, h->length, &acpi, false);
}

/* Fuzzing (ktest fuzz): parse `len` bytes as a MADT into a scratch result and check what the rest
 * of the kernel relies on. 0 = fine, otherwise which invariant broke. */
int acpi_madt_check(const void *table, uint32_t len)
{
    struct acpi_info r;
    memset(&r, 0, sizeof(r));
    madt_parse_into(table, len, &r, true);
    if (r.cpu_count > ACPI_MAX_CPUS)
        return 1;
    if (r.ioapic_count > ACPI_MAX_IOAPIC)
        return 2;
    if (r.iso_count > ACPI_MAX_ISO)
        return 3;
    for (uint32_t i = 0; i < r.cpu_count; i++)
        for (uint32_t j = i + 1; j < r.cpu_count; j++)
            if (r.cpu_apic[i] == r.cpu_apic[j])
                return 4;                    /* a CPU counted twice would be started twice */
    return 0;
}

void acpi_init(void)
{
    const struct rsdp *r = rsdp_find();
    if (!r) {
        kprintf("ACPI: not found (using legacy defaults)\n");
        return;
    }
    acpi.present = true;
    acpi.revision = r->revision;
    memcpy(acpi.oem, r->oem, 6);
    acpi.oem[6] = '\0';

    bool use_xsdt = r->revision >= 2 && r->xsdt;
    const struct sdt_header *root = table_get(use_xsdt ? r->xsdt : r->rsdt);
    if (!root || memcmp(root->signature, use_xsdt ? "XSDT" : "RSDT", 4) != 0) {
        kprintf("ACPI: root table invalid (using legacy defaults)\n");
        return;
    }

    size_t entry_size = use_xsdt ? 8 : 4;
    size_t count = (root->length - sizeof(*root)) / entry_size;
    const uint8_t *entries = (const uint8_t *)root + sizeof(*root);
    root_entries = entries;
    root_count = count;
    root_entry_size = entry_size;

    for (size_t i = 0; i < count; i++) {
        uint64_t addr = 0;
        memcpy(&addr, entries + i * entry_size, entry_size);
        const struct sdt_header *t = table_get(addr);
        if (t && memcmp(t->signature, "APIC", 4) == 0) {
            madt_parse(t);
            break;
        }
    }

    kprintf("ACPI: rev %u, OEM \"%s\", %s (RSDP %s); %u CPU(s), %u I/O APIC(s), %u IRQ override(s)\n",
            acpi.revision, acpi.oem, use_xsdt ? "XSDT" : "RSDT", r == &boot_rsdp ? "from UEFI" : "BIOS scan",
            acpi.cpu_count, acpi.ioapic_count, acpi.iso_count);
    if (!acpi.madt)
        kprintf("ACPI: no MADT (using legacy defaults)\n");
}

const void *acpi_table_at(uint64_t phys, uint32_t *len)
{
    const struct sdt_header *t = table_get(phys);
    *len = t ? t->length : 0;
    return t;
}

const void *acpi_find_table(const char sig[4], uint32_t *len)
{
    for (size_t i = 0; root_entries && i < root_count; i++) {
        uint64_t addr = 0;
        memcpy(&addr, root_entries + i * root_entry_size, root_entry_size);
        const struct sdt_header *t = table_get(addr);
        if (t && memcmp(t->signature, sig, 4) == 0) {
            *len = t->length;
            return t;
        }
    }
    *len = 0;
    return NULL;
}
