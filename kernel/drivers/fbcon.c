/*
 * Framebuffer text console (UEFI GOP framebuffer). See fbcon.h.
 *
 * The screen is drawn from a shadow text buffer (character + attribute per cell), so the
 * framebuffer is only ever written: reads of write-combining / device memory are very slow on
 * real hardware. Scrolling is a jump scroll: when the cursor falls off the bottom, the text moves
 * up by a third of the screen and the whole screen is redrawn from the shadow, so a redraw is paid
 * once per many lines instead of once per line (Fast). Large screens (>= 2560 pixels wide) get
 * doubled glyphs (Practical).
 *
 * Called under the console lock (or lock-free during a panic): no locks of its own.
 */

#include "fbcon.h"
#include "mm.h"
#include "printf.h"
#include "string.h"

#define GLYPH_W 8
#define GLYPH_H 16
#define TAB_WIDTH 8
#define MAX_CELLS (320 * 120)          /* shadow buffer: up to 2560x1920 at scale 1 */

static volatile uint32_t *fb;
static uint32_t width, height, pitch_px, scale, cols, rows;
static uint32_t row, col;
static uint8_t  attr = 0x07;
static uint32_t palette[16];
static uint16_t shadow[MAX_CELLS];      /* char | attr << 8 */
static bool     active;

/* The 16 VGA text colours (CGA palette). */
static const uint8_t vga_rgb[16][3] = {
    {0x00, 0x00, 0x00}, {0x00, 0x00, 0xAA}, {0x00, 0xAA, 0x00}, {0x00, 0xAA, 0xAA},
    {0xAA, 0x00, 0x00}, {0xAA, 0x00, 0xAA}, {0xAA, 0x55, 0x00}, {0xAA, 0xAA, 0xAA},
    {0x55, 0x55, 0x55}, {0x55, 0x55, 0xFF}, {0x55, 0xFF, 0x55}, {0x55, 0xFF, 0xFF},
    {0xFF, 0x55, 0x55}, {0xFF, 0x55, 0xFF}, {0xFF, 0xFF, 0x55}, {0xFF, 0xFF, 0xFF},
};

bool fbcon_active(void) { return active; }

static void draw_cell(uint32_t r, uint32_t c)
{
    uint16_t v = shadow[r * cols + c];
    const uint8_t *g = &font8x16[(v & 0xFF) * GLYPH_H];
    uint32_t fg = palette[(v >> 8) & 0x0F], bg = palette[(v >> 12) & 0x0F];
    volatile uint32_t *p = fb + (uint64_t)r * GLYPH_H * scale * pitch_px + (uint64_t)c * GLYPH_W * scale;
    for (uint32_t y = 0; y < GLYPH_H * scale; y++) {
        uint8_t bits = g[y / scale];
        volatile uint32_t *line = p + (uint64_t)y * pitch_px;
        for (uint32_t x = 0; x < GLYPH_W * scale; x++)
            line[x] = (bits & (0x80u >> (x / scale))) ? fg : bg;
    }
}

/* Clears the text area to the background of each blank cell's attribute (one colour per row run:
 * plain stores, much cheaper than drawing blank glyphs), then draws the non-blank cells. */
static void redraw(void)
{
    for (uint32_t r = 0; r < rows; r++) {
        for (uint32_t c = 0; c < cols; c++) {
            uint16_t v = shadow[r * cols + c];
            if ((v & 0xFF) != ' ' && (v & 0xFF) != 0) {
                draw_cell(r, c);
                continue;
            }
            uint32_t bg = palette[(v >> 12) & 0x0F];
            volatile uint32_t *p = fb + (uint64_t)r * GLYPH_H * scale * pitch_px + (uint64_t)c * GLYPH_W * scale;
            for (uint32_t y = 0; y < GLYPH_H * scale; y++)
                for (uint32_t x = 0; x < GLYPH_W * scale; x++)
                    p[(uint64_t)y * pitch_px + x] = bg;
        }
    }
}

static void scroll(void)
{
    uint32_t by = rows / 3 ? rows / 3 : 1;
    memmove(shadow, shadow + by * cols, (size_t)(rows - by) * cols * sizeof(shadow[0]));
    for (uint32_t i = (rows - by) * cols; i < rows * cols; i++)
        shadow[i] = (uint16_t)(' ' | attr << 8);
    row = rows - by;
    redraw();
}

static void newline(void)
{
    col = 0;
    if (++row >= rows)
        scroll();
}

static void put(char ch)
{
    switch (ch) {
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
            shadow[row * cols + col] = (uint16_t)(' ' | attr << 8);
            draw_cell(row, col);
        }
        return;
    default:
        shadow[row * cols + col] = (uint16_t)((uint8_t)ch | attr << 8);
        draw_cell(row, col);
        if (++col >= cols)
            newline();
    }
}

void fbcon_write(const char *s, size_t n)
{
    if (!active)
        return;
    for (size_t i = 0; i < n; i++)
        put(s[i]);
}

/* Blank text, cursor home, screen redrawn (a results screen starts on a clean page). */
void fbcon_clear(void)
{
    if (!active)
        return;
    for (uint32_t i = 0; i < cols * rows; i++)
        shadow[i] = (uint16_t)(' ' | attr << 8);
    row = col = 0;
    redraw();
}

void fbcon_set_color(enum vga_color fg, enum vga_color bg)
{
    attr = (uint8_t)((bg & 0x0F) << 4 | (fg & 0x0F));
}

void fbcon_describe(char *buf, size_t len)
{
    ksnprintf(buf, len, "%ux%u, %ux%u cells%s", width, height, cols, rows, scale > 1 ? " (2x glyphs)" : "");
}

bool fbcon_init(const BootInfo *bi)
{
    if (bi->fb_type != BOOT_FB_RGB32)
        return false;                       /* validated by bootinfo_validate */
    width = bi->fb_width;
    height = bi->fb_height;
    pitch_px = bi->fb_pitch / 4;
    scale = width >= 2560 && height >= 1440 ? 2 : 1;
    cols = width / (GLYPH_W * scale);
    rows = height / (GLYPH_H * scale);
    while ((uint64_t)cols * rows > MAX_CELLS)
        rows--;
    if (!cols || !rows)
        return false;
    for (int i = 0; i < 16; i++)
        palette[i] = (uint32_t)vga_rgb[i][0] << bi->fb_red_shift | (uint32_t)vga_rgb[i][1] << bi->fb_green_shift |
                     (uint32_t)vga_rgb[i][2] << bi->fb_blue_shift;
    fb = vmm_map_phys(bi->fb_base, bi->fb_size, VMM_W | VMM_WC);
    for (uint32_t i = 0; i < cols * rows; i++)
        shadow[i] = (uint16_t)(' ' | attr << 8);
    /* Whole screen black once (the area right of / below the text grid included). */
    for (uint32_t y = 0; y < height; y++)
        for (uint32_t x = 0; x < width; x++)
            fb[(uint64_t)y * pitch_px + x] = palette[0];
    row = col = 0;
    active = true;
    return true;
}
