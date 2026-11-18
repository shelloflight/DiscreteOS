/* Freestanding memory/string routines (kernel/lib/string.c). The compiler may also emit calls to these. */
#ifndef DOS_STRING_H
#define DOS_STRING_H

#include <stddef.h>

void  *memset(void *dst, int c, size_t n);
void  *memcpy(void *restrict dst, const void *restrict src, size_t n);
void  *memmove(void *dst, const void *src, size_t n);
int    memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
size_t strnlen(const char *s, size_t max);
int    strcmp(const char *a, const char *b);

#endif
