/* Compiler helpers shared by all kernel code. */
#ifndef DOS_COMPILER_H
#define DOS_COMPILER_H

#define NORETURN        __attribute__((noreturn))
#define NOINLINE        __attribute__((noinline))
#define UNUSED          __attribute__((unused))
#define PACKED          __attribute__((packed))
#define PRINTF_FMT(f,a) __attribute__((format(printf, f, a)))
#define LIKELY(x)       __builtin_expect(!!(x), 1)
#define UNLIKELY(x)     __builtin_expect(!!(x), 0)
#define ARRAY_SIZE(a)   (sizeof(a) / sizeof((a)[0]))
/* Written only before the VMM is active (boot CPU, early kmain); mapped read-only afterwards
 * (linker.ld, vmm.c), so a kernel write primitive cannot change it later. */
#define RO_AFTER_INIT   __attribute__((section(".data.ro_after_init")))

#endif
