/*
 * Freestanding memory/string routines.
 * memset/memcpy/memmove use `rep stosb/movsb`, which is fast on CPUs with ERMS (Ivy Bridge+ / Zen) and
 * cannot be "optimized" by the compiler back into a recursive call to itself.
 */

#include "string.h"
#include <stdint.h>

void *memset(void *dst, int c, size_t n)
{
    void *d = dst;
    __asm__ volatile("rep stosb" : "+D"(d), "+c"(n) : "a"(c) : "memory");
    return dst;
}

void *memcpy(void *restrict dst, const void *restrict src, size_t n)
{
    void *d = dst;
    __asm__ volatile("rep movsb" : "+D"(d), "+S"(src), "+c"(n) : : "memory");
    return dst;
}

void *memmove(void *dst, const void *src, size_t n)
{
    uintptr_t d = (uintptr_t)dst, s = (uintptr_t)src;

    if (d == s || n == 0)
        return dst;
    if (d < s || d >= s + n)
        return memcpy(dst, src, n);  /* no harmful overlap: forward copy */

    /* Overlap with dst above src: copy backwards. */
    void *dp = (char *)dst + n - 1;
    const void *sp = (const char *)src + n - 1;
    __asm__ volatile("std\n\trep movsb\n\tcld" : "+D"(dp), "+S"(sp), "+c"(n) : : "memory");
    return dst;
}

int memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *x = a, *y = b;
    for (size_t i = 0; i < n; i++)
        if (x[i] != y[i])
            return x[i] < y[i] ? -1 : 1;
    return 0;
}

size_t strlen(const char *s)
{
    size_t n = 0;
    while (s[n])
        n++;
    return n;
}

size_t strnlen(const char *s, size_t max)
{
    size_t n = 0;
    while (n < max && s[n])
        n++;
    return n;
}

int strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}
