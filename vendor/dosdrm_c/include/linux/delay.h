#ifndef _LINUX_DELAY_H
#define _LINUX_DELAY_H

#include <linux/types.h>
#include <dosdrm/shim.h>

static inline void udelay(unsigned long us) {
    dosdrm_udelay((uint32_t)us);
}

static inline void mdelay(unsigned long ms) {
    dosdrm_udelay((uint32_t)(ms * 1000UL));
}

static inline void fsleep(unsigned long us) {
    dosdrm_udelay((uint32_t)us);
}

#endif
