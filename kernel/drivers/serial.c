/*
 * 16550 UART driver (COM1). Output is polled (logging, headless testing, panics); input comes by
 * interrupt (IRQ 4) into a ring the kernel debugger console reads (kmain.c console_loop).
 * All waits are bounded so a missing or broken UART can never hang the kernel.
 */

#include <stdbool.h>
#include <stdint.h>
#include "console.h"
#include "apic.h"
#include "arch.h"
#include "cpu.h"
#include "printf.h"
#include "wait.h"

#define COM1 0x3F8

enum {
    UART_DATA = 0, UART_IER = 1, UART_FCR = 2, UART_LCR = 3, UART_MCR = 4, UART_LSR = 5,
};

#define LSR_THR_EMPTY 0x20  /* can accept a byte */
#define LSR_TX_IDLE   0x40  /* everything sent */
#define SPIN_LIMIT    100000u

static bool present;

static bool wait_lsr(uint8_t mask)
{
    for (uint32_t i = 0; i < SPIN_LIMIT; i++)
        if (inb(COM1 + UART_LSR) & mask)
            return true;
    return false;
}

bool serial_init(void)
{
    /* Let anything the bootloader queued finish before reprogramming the UART. */
    wait_lsr(LSR_TX_IDLE);

    outb(COM1 + UART_IER, 0x00);   /* no interrupts (polled for now) */
    outb(COM1 + UART_LCR, 0x80);   /* DLAB on */
    outb(COM1 + UART_DATA, 0x01);  /* divisor 1 -> 115200 baud */
    outb(COM1 + UART_IER, 0x00);
    outb(COM1 + UART_LCR, 0x03);   /* 8N1, DLAB off */
    outb(COM1 + UART_FCR, 0xC7);   /* FIFO on, cleared, 14-byte threshold */

    /* Loopback self-test: don't trust a port that doesn't echo. */
    outb(COM1 + UART_MCR, 0x1E);
    outb(COM1 + UART_DATA, 0xAE);
    present = wait_lsr(0x01) && inb(COM1 + UART_DATA) == 0xAE;

    outb(COM1 + UART_MCR, 0x0F);   /* normal mode: DTR, RTS, OUT1, OUT2 */
    return present;
}

bool serial_present(void) { return present; }

static void tx(uint8_t b)
{
    if (wait_lsr(LSR_THR_EMPTY))
        outb(COM1 + UART_DATA, b);
}

void serial_write(const char *s, size_t n)
{
    if (!present)
        return;
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '\n')
            tx('\r');
        tx((uint8_t)s[i]);
    }
}

/* ---- input (kdb console) ------------------------------------------------------------------ */
#define COM1_IRQ    4
#define LSR_DATA    0x01

static volatile uint8_t rx_ring[256];
static volatile uint8_t rx_head, rx_tail;      /* head: written by the IRQ; tail: by the reader */
static struct kevent rx_ev = KEVENT_INIT("serial.rx", 1);

static void serial_irq(struct interrupt_frame *f)
{
    (void)f;
    bool got = false;
    for (int i = 0; i < 64 && (inb(COM1 + UART_LSR) & LSR_DATA); i++) {
        uint8_t c = inb(COM1 + UART_DATA);
        uint8_t next = (uint8_t)(rx_head + 1);
        if (next != rx_tail) {                  /* full: drop */
            rx_ring[rx_head] = c;
            rx_head = next;
            got = true;
        }
    }
    if (got)
        kevent_signal(&rx_ev);
}

bool serial_input_init(void)
{
    if (!present)
        return false;
    interrupt_register(VEC_IRQ_BASE + COM1_IRQ, serial_irq);
    if (!ioapic_route_isa_irq(COM1_IRQ, VEC_IRQ_BASE + COM1_IRQ))
        return false;
    while (inb(COM1 + UART_LSR) & LSR_DATA)    /* drop anything queued before boot */
        (void)inb(COM1 + UART_DATA);
    outb(COM1 + UART_IER, 0x01);               /* interrupt on received data */
    return true;
}

int serial_getc(void)
{
    if (rx_tail == rx_head)
        return -1;
    uint8_t c = rx_ring[rx_tail];
    rx_tail = (uint8_t)(rx_tail + 1);
    return c;
}

void serial_wait(void) { kevent_wait(&rx_ev, WAIT_FOREVER); }
