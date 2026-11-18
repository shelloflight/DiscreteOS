/*
 * Minimal user runtime for the C test programs: process entry, startup handles, printf to
 * the debug log, and the few libc functions the compiler may call. C programs that need a heap,
 * threads or locks include libd.h (the libd runtime) as well.
 */

#include <stdarg.h>
#include "dos.h"

const struct dos_startup *dos_start;
static dos_handle_t log_handle;

void dos_entry(const struct dos_startup *s);

/* Entry point: RDI = startup block. A 16-byte aligned stack for C, no frame to return to. */
__asm__(".globl _start\n"
        "_start:\n"
        "  xor %ebp, %ebp\n"
        "  and $-16, %rsp\n"
        "  call dos_entry\n"
        "  ud2\n");

void dos_entry(const struct dos_startup *s)
{
    if (!s || s->magic != DOS_STARTUP_MAGIC || s->abi_version < DOS_ABI_VERSION)
        dos_process_exit(-1);
    dos_start = s;
    log_handle = dos_startup_handle(DOS_TAG_LOG);
    dos_process_exit(main());
}

dos_handle_t dos_startup_handle(uint32_t tag)
{
    for (uint32_t i = 0; i < dos_start->nhandles; i++)
        if (dos_start->handles[i].tag == tag)
            return dos_start->handles[i].handle;
    return DOS_HANDLE_INVALID;
}

const char *dos_args(void) { return (const char *)(uintptr_t)dos_start->args; }
void dos_set_log(dos_handle_t log) { log_handle = log; }

const char *dos_status(int64_t r)
{
    static const char *const names[] = { "OK", "NO_MEMORY", "INVALID_ARGS", "BAD_HANDLE", "WRONG_TYPE",
        "ACCESS_DENIED", "NO_RESOURCES", "OUT_OF_RANGE", "TIMED_OUT", "BAD_STATE", "NO_SPACE",
        "BAD_ADDRESS", "NOT_SUPPORTED", "SHOULD_WAIT", "BUFFER_TOO_SMALL", "PEER_CLOSED" };
    if (r > 0)
        return "OK (value)";
    if (-r < (int64_t)(sizeof(names) / sizeof(names[0])))
        return names[-r];
    return "?";
}

/* ---- printf ---------------------------------------------------------------------------------- */

struct out {
    char buf[256];
    size_t n;
};

static void flush(struct out *o)
{
    if (o->n && log_handle)
        dos_log_write(log_handle, o->buf, o->n);
    o->n = 0;
}

static void put(struct out *o, char c)
{
    if (o->n == sizeof(o->buf))
        flush(o);
    o->buf[o->n++] = c;
}

static void put_u(struct out *o, uint64_t v, unsigned base, int width, char pad)
{
    char tmp[24];
    int n = 0;
    do {
        unsigned d = (unsigned)(v % base);
        tmp[n++] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
        v /= base;
    } while (v);
    while (n < width--)
        put(o, pad);
    while (n)
        put(o, tmp[--n]);
}

void dos_printf(const char *fmt, ...)
{
    struct out o = { .n = 0 };
    va_list ap;
    va_start(ap, fmt);
    for (const char *p = fmt; *p; p++) {
        if (*p != '%') {
            put(&o, *p);
            continue;
        }
        p++;
        char pad = ' ';
        int width = 0, longs = 0;
        if (*p == '0') {
            pad = '0';
            p++;
        }
        while (*p >= '0' && *p <= '9')
            width = width * 10 + (*p++ - '0');
        while (*p == 'l') {
            longs++;
            p++;
        }
        switch (*p) {
        case 'd': {
            int64_t v = longs ? va_arg(ap, int64_t) : va_arg(ap, int);
            if (v < 0) {
                put(&o, '-');
                v = -v;
            }
            put_u(&o, (uint64_t)v, 10, width, pad);
            break;
        }
        case 'u':
            put_u(&o, longs ? va_arg(ap, uint64_t) : va_arg(ap, unsigned), 10, width, pad);
            break;
        case 'x':
            put_u(&o, longs ? va_arg(ap, uint64_t) : va_arg(ap, unsigned), 16, width, pad);
            break;
        case 'p':
            put(&o, '0');
            put(&o, 'x');
            put_u(&o, (uint64_t)(uintptr_t)va_arg(ap, void *), 16, 16, '0');
            break;
        case 's': {
            const char *s = va_arg(ap, const char *);
            for (s = s ? s : "(null)"; *s; s++)
                put(&o, *s);
            break;
        }
        case 'c':
            put(&o, (char)va_arg(ap, int));
            break;
        case '%':
            put(&o, '%');
            break;
        default:
            put(&o, '?');
            break;
        }
    }
    va_end(ap);
    flush(&o);
}

/* ---- libc pieces ------------------------------------------------------------------------------ */

size_t strlen(const char *s)
{
    size_t n = 0;
    while (s[n])
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

int strncmp(const char *a, const char *b, size_t n)
{
    for (; n; n--, a++, b++) {
        if (*a != *b || !*a)
            return (unsigned char)*a - (unsigned char)*b;
    }
    return 0;
}

void *memcpy(void *d, const void *s, size_t n)
{
    void *r = d;
    __asm__ volatile("rep movsb" : "+D"(d), "+S"(s), "+c"(n) : : "memory");
    return r;
}

void *memset(void *d, int c, size_t n)
{
    void *r = d;
    __asm__ volatile("rep stosb" : "+D"(d), "+c"(n) : "a"(c) : "memory");
    return r;
}

int memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *x = a, *y = b;
    for (; n; n--, x++, y++)
        if (*x != *y)
            return *x - *y;
    return 0;
}
