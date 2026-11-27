/*
 * L3 shared library (`libl3.so`): real x86-64 ELF64 shared object loaded by `ld-linux-x86-64.so.2`
 * via DT_NEEDED, testing DT_INIT_ARRAY constructors, PLT/GOT calls, and PT_GNU_RELRO.
 */

static int ctor_flag;

__attribute__((constructor))
static void libl3_init(void)
{
    ctor_flag = 1;
}

int l3_add(int a, int b)
{
    return a + b;
}

int l3_mul(int a, int b)
{
    return a * b;
}

int l3_ctor_ran(void)
{
    return ctor_flag;
}

/* Relocated function pointer placed into .data.rel.ro (PT_GNU_RELRO, aligned to 4 KiB so the
 * whole page is protected read-only by ld-linux-x86-64.so.2 after relocation). */
typedef int (*op_fn)(int, int);
__attribute__((section(".data.rel.ro"), aligned(4096)))
static op_fn const relro_ops[512] = { l3_add, l3_mul };

void *l3_relro_ptr(void)
{
    return (void *)&relro_ops[0];
}
