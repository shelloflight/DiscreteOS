#ifndef _LINUX_BITOPS_H
#define _LINUX_BITOPS_H

#include <linux/types.h>

#define BIT(nr)         (1UL << (nr))
#define BIT_ULL(nr)     (1ULL << (nr))
#define GENMASK(h, l)   (((~0UL) - (1UL << (l)) + 1) & (~0UL >> (63 - (h))))
#define GENMASK_ULL(h, l) (((~0ULL) - (1ULL << (l)) + 1) & (~0ULL >> (63 - (h))))
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define ALIGN(x, a)     (((x) + ((a) - 1)) & ~((a) - 1))

#endif
