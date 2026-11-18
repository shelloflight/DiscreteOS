/*
 * Legacy 8259 PIC: remapped away from the exception vectors (to VEC_PIC_BASE) and fully masked.
 * D-OS uses the Local APIC + I/O APIC instead; remapping still matters because a masked PIC can
 * deliver spurious IRQ7/IRQ15, which must not land on a CPU exception vector.
 */

#include "arch.h"
#include "cpu.h"

#define PIC1_CMD  0x20
#define PIC1_DATA 0x21
#define PIC2_CMD  0xA0
#define PIC2_DATA 0xA1

void pic_disable(void)
{
    outb(PIC1_CMD, 0x11);  io_wait();            /* ICW1: init, expect ICW4 */
    outb(PIC2_CMD, 0x11);  io_wait();
    outb(PIC1_DATA, VEC_PIC_BASE);      io_wait(); /* ICW2: vector offsets */
    outb(PIC2_DATA, VEC_PIC_BASE + 8);  io_wait();
    outb(PIC1_DATA, 0x04); io_wait();            /* ICW3: slave on IRQ2 */
    outb(PIC2_DATA, 0x02); io_wait();
    outb(PIC1_DATA, 0x01); io_wait();            /* ICW4: 8086 mode */
    outb(PIC2_DATA, 0x01); io_wait();
    outb(PIC1_DATA, 0xFF);                       /* mask everything */
    outb(PIC2_DATA, 0xFF);
}
