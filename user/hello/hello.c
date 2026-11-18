/*
 * hello: the smallest D-OS program. The storage test uses it to prove code signing end to end: the build
 * signs it and puts it on the boot volume (\DOS\APPS\HELLO.DX + HELLO.DSIG); fstest reads it from
 * disk, has the kernel verify the signature (vmo_verify) and runs it.
 */

#include "dos.h"

int main(void)
{
    dos_printf("hello: a signed program loaded from disk is running\n");
    return 42;
}
