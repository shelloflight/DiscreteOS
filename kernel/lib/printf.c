/*
 * Kernel printf engine. One formatter (kvformat) drives every sink:
 * bounded buffers (ksnprintf) and the console (kprintf, buffered in chunks to cut per-char overhead).
 */

#include <stdbool.h>
#include <stdint.h>
#include "printf.h"
#include "string.h"
#include "console.h"
#include "klog.h"

typedef struct {
    emit_fn fn;
    void   *ctx;
    size_t  count;
} sink;

static void sink_write(sink *s, const char *p, size_t n)
{
    if (n) {
        s->fn(s->ctx, p, n);
        s->count += n;
    }
}

static void sink_pad(sink *s, char c, size_t n)
{
    char tmp[16];
    memset(tmp, c, sizeof(tmp));
    while (n) {
        size_t k = n < sizeof(tmp) ? n : sizeof(tmp);
        sink_write(s, tmp, k);
        n -= k;
    }
}

/* Writes digits of v right-aligned ending at `end`; returns pointer to first digit. */
static char *utoa_rev(uint64_t v, unsigned base, bool upper, char *end)
{
    const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    char *p = end;
    do {
        *--p = digits[v % base];
        v /= base;
    } while (v);
    return p;
}

enum len_mod { LEN_INT, LEN_CHAR, LEN_SHORT, LEN_LONG, LEN_LLONG, LEN_SIZE, LEN_PTRDIFF, LEN_INTMAX };

static int64_t fetch_signed(enum len_mod len, va_list *ap)
{
    switch (len) {
    case LEN_CHAR:    return (signed char)va_arg(*ap, int);
    case LEN_SHORT:   return (short)va_arg(*ap, int);
    case LEN_LONG:    return va_arg(*ap, long);
    case LEN_LLONG:   return va_arg(*ap, long long);
    case LEN_SIZE:    return (int64_t)va_arg(*ap, size_t);
    case LEN_PTRDIFF: return va_arg(*ap, ptrdiff_t);
    case LEN_INTMAX:  return va_arg(*ap, intmax_t);
    default:          return va_arg(*ap, int);
    }
}

static uint64_t fetch_unsigned(enum len_mod len, va_list *ap)
{
    switch (len) {
    case LEN_CHAR:    return (unsigned char)va_arg(*ap, unsigned int);
    case LEN_SHORT:   return (unsigned short)va_arg(*ap, unsigned int);
    case LEN_LONG:    return va_arg(*ap, unsigned long);
    case LEN_LLONG:   return va_arg(*ap, unsigned long long);
    case LEN_SIZE:    return va_arg(*ap, size_t);
    case LEN_PTRDIFF: return (uint64_t)va_arg(*ap, ptrdiff_t);
    case LEN_INTMAX:  return va_arg(*ap, uintmax_t);
    default:          return va_arg(*ap, unsigned int);
    }
}

int kvformat(emit_fn out, void *ctx, const char *fmt, va_list ap_in)
{
    sink s = { out, ctx, 0 };
    va_list ap;
    va_copy(ap, ap_in);

    while (*fmt) {
        const char *lit = fmt;
        while (*fmt && *fmt != '%')
            fmt++;
        sink_write(&s, lit, (size_t)(fmt - lit));
        if (!*fmt)
            break;
        fmt++; /* '%' */

        /* flags */
        bool left = false, zero = false, alt = false, plus = false, space = false;
        for (;; fmt++) {
            if (*fmt == '-') left = true;
            else if (*fmt == '0') zero = true;
            else if (*fmt == '#') alt = true;
            else if (*fmt == '+') plus = true;
            else if (*fmt == ' ') space = true;
            else break;
        }

        /* width */
        size_t width = 0;
        if (*fmt == '*') {
            int w = va_arg(ap, int);
            if (w < 0) { left = true; w = -w; }
            width = (size_t)w;
            fmt++;
        } else {
            while (*fmt >= '0' && *fmt <= '9')
                width = width * 10 + (size_t)(*fmt++ - '0');
        }

        /* precision */
        int prec = -1;
        if (*fmt == '.') {
            fmt++;
            prec = 0;
            if (*fmt == '*') {
                int p = va_arg(ap, int);
                prec = p < 0 ? -1 : p;
                fmt++;
            } else {
                while (*fmt >= '0' && *fmt <= '9')
                    prec = prec * 10 + (*fmt++ - '0');
            }
        }

        /* length */
        enum len_mod len = LEN_INT;
        switch (*fmt) {
        case 'h': fmt++; len = LEN_SHORT; if (*fmt == 'h') { fmt++; len = LEN_CHAR; } break;
        case 'l': fmt++; len = LEN_LONG;  if (*fmt == 'l') { fmt++; len = LEN_LLONG; } break;
        case 'z': fmt++; len = LEN_SIZE; break;
        case 't': fmt++; len = LEN_PTRDIFF; break;
        case 'j': fmt++; len = LEN_INTMAX; break;
        default: break;
        }

        char conv = *fmt;
        if (!conv)
            break;
        fmt++;

        char numbuf[24];
        char *end = numbuf + sizeof(numbuf);
        const char *body = NULL;
        size_t blen = 0;
        const char *prefix = "";
        size_t zeros = 0;          /* precision zeros for numbers */
        bool numeric = false;

        switch (conv) {
        case 'd':
        case 'i': {
            int64_t v = fetch_signed(len, &ap);
            uint64_t u = v < 0 ? (uint64_t)0 - (uint64_t)v : (uint64_t)v;
            prefix = v < 0 ? "-" : plus ? "+" : space ? " " : "";
            body = (prec == 0 && u == 0) ? end : utoa_rev(u, 10, false, end);
            numeric = true;
            break;
        }
        case 'u':
        case 'x':
        case 'X': {
            uint64_t u = fetch_unsigned(len, &ap);
            unsigned base = conv == 'u' ? 10 : 16;
            if (alt && base == 16 && u != 0)
                prefix = conv == 'X' ? "0X" : "0x";
            body = (prec == 0 && u == 0) ? end : utoa_rev(u, base, conv == 'X', end);
            numeric = true;
            break;
        }
        case 'p': {
            uint64_t u = (uint64_t)(uintptr_t)va_arg(ap, void *);
            prefix = "0x";
            body = utoa_rev(u, 16, false, end);
            if (prec < 16)
                prec = 16;
            numeric = true;
            break;
        }
        case 's': {
            const char *str = va_arg(ap, const char *);
            if (!str)
                str = "(null)";
            body = str;
            blen = prec >= 0 ? strnlen(str, (size_t)prec) : strlen(str);
            break;
        }
        case 'c':
            numbuf[0] = (char)va_arg(ap, int);
            body = numbuf;
            blen = 1;
            break;
        case '%':
            sink_write(&s, "%", 1);
            continue;
        default:
            /* Unknown conversion: print it literally so mistakes are visible. */
            sink_write(&s, "%", 1);
            sink_write(&s, &conv, 1);
            continue;
        }

        if (numeric) {
            blen = (size_t)(end - body);
            if (prec >= 0) {
                zero = false; /* C rule: precision overrides the 0 flag */
                if ((size_t)prec > blen)
                    zeros = (size_t)prec - blen;
            }
        } else {
            zero = false;
        }

        size_t plen = strlen(prefix);
        size_t total = plen + zeros + blen;
        size_t pad = width > total ? width - total : 0;

        if (!left && !zero)
            sink_pad(&s, ' ', pad);
        sink_write(&s, prefix, plen);
        if (!left && zero)
            sink_pad(&s, '0', pad);
        sink_pad(&s, '0', zeros);
        sink_write(&s, body, blen);
        if (left)
            sink_pad(&s, ' ', pad);
    }

    va_end(ap);
    return (int)s.count;
}

/* ---- bounded buffer sink ------------------------------------------------- */

typedef struct {
    char  *buf;
    size_t cap;   /* bytes available for characters (size - 1) */
    size_t len;
} sn_ctx;

static void sn_emit(void *ctx, const char *s, size_t n)
{
    sn_ctx *c = ctx;
    if (c->len < c->cap) {
        size_t room = c->cap - c->len;
        size_t k = n < room ? n : room;
        memcpy(c->buf + c->len, s, k);
        c->len += k;
    }
}

int kvsnprintf(char *buf, size_t size, const char *fmt, va_list ap)
{
    sn_ctx c = { buf, size ? size - 1 : 0, 0 };
    int n = kvformat(sn_emit, &c, fmt, ap);
    if (size)
        buf[c.len] = '\0';
    return n;
}

int ksnprintf(char *buf, size_t size, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = kvsnprintf(buf, size, fmt, ap);
    va_end(ap);
    return n;
}

/* ---- console sink (chunk-buffered) ----------------------------------------- */

typedef struct {
    char   buf[128];
    size_t len;
} con_ctx;

static void con_flush(con_ctx *c)
{
    console_write_locked(c->buf, c->len);
    klog_capture(c->buf, c->len);       /* console output also lands in the kernel log */
    c->len = 0;
}

static void con_emit(void *ctx, const char *s, size_t n)
{
    con_ctx *c = ctx;
    while (n) {
        size_t room = sizeof(c->buf) - c->len;
        size_t k = n < room ? n : room;
        memcpy(c->buf + c->len, s, k);
        c->len += k;
        s += k;
        n -= k;
        if (c->len == sizeof(c->buf))
            con_flush(c);
    }
}

int kvprintf(const char *fmt, va_list ap)
{
    con_ctx c;
    c.len = 0;
    uint64_t f = console_lock();          /* whole message stays together */
    int n = kvformat(con_emit, &c, fmt, ap);
    if (c.len)
        con_flush(&c);
    console_unlock(f);
    return n;
}

/* ---- leveled kernel log ---------------------------------------------------- */

void klog(int level, const char *fmt, ...)
{
    char buf[KLOG_MSG_MAX];
    va_list ap;
    va_start(ap, fmt);
    int n = kvsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    size_t len = (size_t)n < sizeof(buf) ? (size_t)n : sizeof(buf) - 1;
    klog_write(level, buf, len);
}

int kprintf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = kvprintf(fmt, ap);
    va_end(ap);
    return n;
}
