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
/* The screen was handed to user space (the terminal mapped the display device): only serial
 * from then on. A panic takes it back (`reclaimed`): the screen is cleared once, then the report. */
static bool released, reclaimed;
static struct console_display fbdesc;

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
        if (!(e.flags & KLOG_FLAG_CONTINUES))
            fbcon_write("\n", 1);
    }
    screen = SCREEN_FB;
    fbdesc = (struct console_display){
        .base = bi->fb_base, .size = bi->fb_size, .kind = CONSOLE_DISPLAY_RGB32,
        .width = bi->fb_width, .height = bi->fb_height, .pitch = bi->fb_pitch,
        .red_shift = bi->fb_red_shift, .green_shift = bi->fb_green_shift, .blue_shift = bi->fb_blue_shift,
    };
    console_unlock(f);
    return true;
}

bool console_display(struct console_display *out)
{
    if (screen == SCREEN_FB) {
        *out = fbdesc;
        return true;
    }
    if (screen == SCREEN_VGA) {
        *out = (struct console_display){ .base = vga_phys_base(), .size = 4096, .kind = CONSOLE_DISPLAY_VGA_TEXT,
                                         .width = 80, .height = 25, .pitch = 160 };
        return true;
    }
    return false;
}

void console_release_screen(void)
{
    uint64_t f = console_lock();
    released = true;
    console_unlock(f);
}

bool console_screen_released(void) { return released; }

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
    if (released) {
        if (!panic_in_progress())
            return;
        if (!reclaimed) {
            reclaimed = true;
            if (screen == SCREEN_VGA)
                vga_clear();
            else if (screen == SCREEN_FB)
                fbcon_clear();
        }
    }
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
    if (released && !reclaimed) {
        console_unlock(f);
        return;
    }
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
