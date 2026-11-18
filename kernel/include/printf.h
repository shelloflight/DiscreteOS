/*
 * Kernel formatted output.
 * Supported: %d %i %u %x %X %p %s %c %%, flags - 0 + space #, width/precision (incl. *),
 * length modifiers hh h l ll z t j. %p prints 0x + 16 hex digits.
 */
#ifndef DOS_PRINTF_H
#define DOS_PRINTF_H

#include <stdarg.h>
#include <stddef.h>
#include "compiler.h"

/* Output sink: receives chunks of formatted text. */
typedef void (*emit_fn)(void *ctx, const char *s, size_t n);

/* Core formatter. Returns the number of characters produced. */
int kvformat(emit_fn out, void *ctx, const char *fmt, va_list ap);

/* Bounded formatting into buf (always NUL-terminated when size > 0).
 * Returns the length the full output would have had (like C99 snprintf). */
int kvsnprintf(char *buf, size_t size, const char *fmt, va_list ap);
int ksnprintf(char *buf, size_t size, const char *fmt, ...) PRINTF_FMT(3, 4);

/* Print to the kernel console (VGA + serial). */
int kvprintf(const char *fmt, va_list ap);
int kprintf(const char *fmt, ...) PRINTF_FMT(1, 2);

#endif
