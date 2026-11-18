/*
 * Kernel console: every message goes to the serial log and to the screen. The screen is VGA text
 * mode after a BIOS boot and the GOP framebuffer (fbcon.c) after a UEFI boot; UEFI machines need
 * not have VGA at all, so VGA memory is never touched there.
 * One IRQ-safe lock serialises output so messages from different contexts never interleave.
 * During a panic the lock is bypassed (the panicking code may hold it); output is best effort.
 */

#include "console.h"
#include "fbcon.h"
#include "klog.h"
#include "panic.h"
#include "spinlock.h"

static spinlock_t console_lk = SPINLOCK_INIT("console", LOCK_RANK_CONSOLE);
static enum { SCREEN_NONE, SCREEN_VGA, SCREEN_FB } screen;

#define CONSOLE_LOCKED (1ull << 63)   /* marker in the returned flags: lock was really taken */

/* Runs before BootInfo is validated (a failed validation must still be reported), so only a
 * cautious look: VGA text only when this clearly is a BIOS boot. */
void console_init(const BootInfo *bi)
{
    serial_init();
    uintptr_t a = (uintptr_t)bi;
    if (a >= 0x500 && a + sizeof(*bi) <= 0x80000 && bi->magic == BOOTINFO_MAGIC && bi->firmware == BOOT_FW_BIOS) {
        vga_init();
        screen = SCREEN_VGA;
    }
}

bool console_has_vga(void) { return screen == SCREEN_VGA; }

bool console_attach_framebuffer(const BootInfo *bi)
{
    if (screen != SCREEN_NONE || !fbcon_init(bi))
        return false;
    /* Show the boot log so far: everything printed is in the kernel log ring. */
    uint64_t f = console_lock();
    static struct klog_entry e;
    uint64_t seq = 0;
    while (klog_read(&seq, &e)) {
        fbcon_write(e.text, e.len);
        fbcon_write("\n", 1);
    }
    screen = SCREEN_FB;
    console_unlock(f);
    return true;
}

uint64_t console_lock(void)
{
    if (panic_in_progress())
        return 0;
    return spin_lock_irqsave(&console_lk) | CONSOLE_LOCKED;
}

void console_unlock(uint64_t flags)
{
    if (flags & CONSOLE_LOCKED)
        spin_unlock_irqrestore(&console_lk, flags & ~CONSOLE_LOCKED);
}

void console_write_locked(const char *s, size_t n)
{
    serial_write(s, n);
    if (screen == SCREEN_VGA)
        vga_write(s, n);
    else if (screen == SCREEN_FB)
        fbcon_write(s, n);
}

void console_write(const char *s, size_t n)
{
    uint64_t f = console_lock();
    console_write_locked(s, n);
    console_unlock(f);
}

void console_clear(void)
{
    uint64_t f = console_lock();
    if (screen == SCREEN_VGA)
        vga_clear();
    else if (screen == SCREEN_FB)
        fbcon_clear();
    console_unlock(f);
}

void console_set_color(enum vga_color fg, enum vga_color bg)
{
    uint64_t f = console_lock();
    vga_set_color(fg, bg);
    fbcon_set_color(fg, bg);
    console_unlock(f);
}
