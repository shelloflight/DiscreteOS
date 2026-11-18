/*
 * Framebuffer text console (kernel/drivers/fbcon.c): the kernel's screen when booted by UEFI (GOP
 * framebuffer, no VGA text mode). 8x16 glyphs (doubled on large screens), the 16 VGA colours,
 * jump scrolling from a shadow text buffer (the framebuffer is never read back).
 */
#ifndef DOS_FBCON_H
#define DOS_FBCON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "bootinfo.h"
#include "console.h"

extern const uint8_t font8x16[256 * 16];

/* Maps the framebuffer (write-combining) and clears it. Needs the VMM; false without a framebuffer. */
bool fbcon_init(const BootInfo *bi);
bool fbcon_active(void);
void fbcon_write(const char *s, size_t n);
void fbcon_set_color(enum vga_color fg, enum vga_color bg);
void fbcon_clear(void);                 /* blank the text area, cursor home */
/* "1280x800, 160x50 cells" for the boot log */
void fbcon_describe(char *buf, size_t len);

#endif
