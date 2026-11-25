#ifndef _LINUX_KERNEL_H
#define _LINUX_KERNEL_H

#include <linux/types.h>
#include <linux/bitops.h>

#define DIV_ROUND_UP(n, d)       (((n) + (d) - 1u) / (d))
#define DIV_ROUND_CLOSEST(x, d)  (((x) + ((d) / 2u)) / (d))
#define lower_32_bits(n)         ((u32)((n) & 0xFFFFFFFFULL))
#define upper_32_bits(n)         ((u32)(((n) >> 32) & 0xFFFFFFFFULL))
#define IS_ALIGNED(x, a)         (((u64)(x) & ((u64)(a) - 1ULL)) == 0ULL)

#define min_t(type, x, y)        (((type)(x)) < ((type)(y)) ? ((type)(x)) : ((type)(y)))
#define max_t(type, x, y)        (((type)(x)) > ((type)(y)) ? ((type)(x)) : ((type)(y)))
#define clamp_t(type, v, lo, hi) min_t(type, max_t(type, (v), (lo)), (hi))

#ifndef min
#define min(x, y) ((x) < (y) ? (x) : (y))
#endif
#ifndef max
#define max(x, y) ((x) > (y) ? (x) : (y))
#endif

static inline u64 div_u64(u64 dividend, u32 divisor) {
    return divisor ? (dividend / (u64)divisor) : 0ULL;
}

static inline u64 div64_u64(u64 dividend, u64 divisor) {
    return divisor ? (dividend / divisor) : 0ULL;
}

static inline u64 mul_u32_u32(u32 a, u32 b) {
    return (u64)a * (u64)b;
}

#endif
