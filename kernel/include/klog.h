/*
 * Kernel log (implemented in Rust: kernel/rust/src/klog.rs).
 *
 * An in-memory ring of timestamped, leveled records. When full, the oldest records are overwritten;
 * readers notice through sequence numbers. Everything printed with kprintf() is captured too (as
 * KLOG_INFO, one record per line), so the ring holds the full boot log for a future `dmesg`.
 *
 *   klog(level, fmt, ...)   record + print "[  seconds.micros] level: message" on the console
 *                           (KLOG_DEBUG only reaches the console in test builds)
 *   klog_read(&seq, &e)     copy the first record with sequence >= seq; seq is advanced past it.
 *                           Returns false when there is nothing newer. Lock-protected; IRQ safe.
 */
#ifndef DOS_KLOG_H
#define DOS_KLOG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "compiler.h"

enum { KLOG_ERROR = 0, KLOG_WARN = 1, KLOG_INFO = 2, KLOG_DEBUG = 3 };

#define KLOG_MSG_MAX 120          /* bytes of text per record; longer messages are split */
#define KLOG_SOURCE_MAX 24

enum { KLOG_ORIGIN_KERNEL = 0, KLOG_ORIGIN_PROGRAM = 1 };
#define KLOG_FLAG_CONTINUES 1     /* no newline at the end: the process's next record continues it */

/* Shared with Rust (#[repr(C)] KlogEntry). */
struct klog_entry {
    uint64_t seq;
    uint64_t time_us;             /* monotonic, since kernel entry */
    uint8_t  level;
    uint8_t  len;
    uint8_t  origin;              /* KLOG_ORIGIN_* */
    uint8_t  flags;               /* KLOG_FLAG_* */
    uint32_t koid;                /* program records: the writing process */
    char     source[KLOG_SOURCE_MAX]; /* program records: its name, set by the kernel */
    char     text[KLOG_MSG_MAX];  /* not NUL-terminated */
    uint8_t  reserved[8];
};
_Static_assert(sizeof(struct klog_entry) == 176, "klog_entry layout is shared with Rust");

void klog(int level, const char *fmt, ...) PRINTF_FMT(2, 3);

/* Rust side */
void     klog_write(int level, const char *s, size_t n);
void     klog_capture(const char *s, size_t n);  /* raw console text; split into records at '\n' */
bool     klog_read(uint64_t *seq, struct klog_entry *out);
uint64_t klog_dropped(void);                     /* records lost to overwrites so far */

#define klog_error(...) klog(KLOG_ERROR, __VA_ARGS__)
#define klog_warn(...)  klog(KLOG_WARN, __VA_ARGS__)
#define klog_info(...)  klog(KLOG_INFO, __VA_ARGS__)
#define klog_debug(...) klog(KLOG_DEBUG, __VA_ARGS__)

#endif
