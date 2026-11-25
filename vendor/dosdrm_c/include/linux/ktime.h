#ifndef _LINUX_KTIME_H
#define _LINUX_KTIME_H

#include <linux/types.h>
#include <dosdrm/shim.h>

typedef s64 ktime_t;

static inline u64 ktime_get_ns(void) {
    return dosdrm_clock_ns();
}

static inline u64 ktime_get_mono_fast_ns(void) {
    return dosdrm_clock_ns();
}

#endif
