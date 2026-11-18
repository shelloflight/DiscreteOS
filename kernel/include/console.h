/* Kernel console: fans output out to the VGA text screen and the COM1 serial port. */
#ifndef DOS_CONSOLE_H
#define DOS_CONSOLE_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include "bootinfo.h"

enum vga_color {
    VGA_BLACK, VGA_BLUE, VGA_GREEN, VGA_CYAN, VGA_RED, VGA_MAGENTA, VGA_BROWN, VGA_LIGHT_GREY,
    VGA_DARK_GREY, VGA_LIGHT_BLUE, VGA_LIGHT_GREEN, VGA_LIGHT_CYAN, VGA_LIGHT_RED,
    VGA_LIGHT_MAGENTA, VGA_YELLOW, VGA_WHITE,
};

/* drivers/vga.c */
void vga_init(void);
void vga_clear(void);
void vga_set_color(enum vga_color fg, enum vga_color bg);
void vga_write(const char *s, size_t n);
uint64_t vga_phys_base(void);
void vga_set_base(void *base);   /* re-point the text buffer after the VMM switch */
#define VGA_TEXT_BYTES (80 * 25 * 2)

/* drivers/serial.c */
bool serial_init(void);           /* false if no UART answered the loopback test */
bool serial_present(void);
void serial_write(const char *s, size_t n);
bool serial_input_init(void);     /* receive interrupts (IRQ 4) on; false without a UART */
int  serial_getc(void);           /* next received byte, or -1 */
void serial_wait(void);           /* block the calling thread until input may be available */

/* console.c */
void console_init(const BootInfo *bi);              /* serial, plus VGA text after a BIOS boot */
bool console_has_vga(void);
/* UEFI: switch the screen to the GOP framebuffer (needs the VMM); replays the boot log. */
bool console_attach_framebuffer(const BootInfo *bi);
void console_write(const char *s, size_t n);          /* takes the console lock */
void console_set_color(enum vga_color fg, enum vga_color bg);
void console_clear(void);                             /* blank the screen (not serial), cursor home */

/* Hold the console across several writes (one message stays together). Bypassed during a panic. */
uint64_t console_lock(void);
void     console_unlock(uint64_t flags);
void     console_write_locked(const char *s, size_t n);  /* caller holds console_lock() */

#endif
