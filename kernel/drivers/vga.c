/* VGA text mode (80x25, 0xB8000) driver: colours, scrolling, hardware cursor. */

#include <stdint.h>
#include "console.h"
#include "cpu.h"
#include "mm.h"

#define VGA_PHYS  0xB8000ull

/* Before the VMM is active the boot page tables identity-map low memory; afterwards kmain moves
 * this to the direct-map (uncached) mapping via vga_set_base(). */
static volatile uint16_t *vga_mem = (volatile uint16_t *)(uintptr_t)VGA_PHYS;
#define VGA_MEM vga_mem
#define VGA_COLS  80
#define VGA_ROWS  25
#define TAB_WIDTH 8

#define CRTC_INDEX 0x3D4
#define CRTC_DATA  0x3D5

static size_t  row, col;
static uint8_t attr = (VGA_BLACK << 4) | VGA_LIGHT_GREY;

static inline uint16_t cell(char c) { return (uint16_t)((uint16_t)attr << 8 | (uint8_t)c); }

static void update_cursor(void)
{
    uint16_t pos = (uint16_t)(row * VGA_COLS + col);
    outb(CRTC_INDEX, 0x0F);
    outb(CRTC_DATA, (uint8_t)(pos & 0xFF));
    outb(CRTC_INDEX, 0x0E);
    outb(CRTC_DATA, (uint8_t)(pos >> 8));
}

static void scroll(void)
{
    for (size_t i = 0; i < (VGA_ROWS - 1) * VGA_COLS; i++)
        VGA_MEM[i] = VGA_MEM[i + VGA_COLS];
    for (size_t i = (VGA_ROWS - 1) * VGA_COLS; i < VGA_ROWS * VGA_COLS; i++)
        VGA_MEM[i] = cell(' ');
    row = VGA_ROWS - 1;
}

static void newline(void)
{
    col = 0;
    if (++row >= VGA_ROWS)
        scroll();
}

static void put(char c)
{
    switch (c) {
    case '\n': newline(); return;
    case '\r': col = 0; return;
    case '\t':
        do {
            put(' ');
        } while (col % TAB_WIDTH);
        return;
    case '\b':
        if (col) {
            col--;
            VGA_MEM[row * VGA_COLS + col] = cell(' ');
        }
        return;
    default:
        VGA_MEM[row * VGA_COLS + col] = cell(c);
        if (++col >= VGA_COLS)
            newline();
    }
}

void vga_set_color(enum vga_color fg, enum vga_color bg)
{
    attr = (uint8_t)((bg & 0x0F) << 4 | (fg & 0x0F));
}

void vga_clear(void)
{
    for (size_t i = 0; i < VGA_ROWS * VGA_COLS; i++)
        VGA_MEM[i] = cell(' ');
    row = col = 0;
    update_cursor();
}

uint64_t vga_phys_base(void) { return VGA_PHYS; }

void vga_set_base(void *base) { vga_mem = (volatile uint16_t *)base; }

void vga_init(void)
{
    vga_set_color(VGA_LIGHT_GREY, VGA_BLACK);
    vga_clear();
}

void vga_write(const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++)
        put(s[i]);
    update_cursor();
}
