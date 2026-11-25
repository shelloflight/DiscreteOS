#ifndef _LINUX_TYPES_H
#define _LINUX_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int8_t __s8;
typedef int16_t __s16;
typedef int32_t __s32;
typedef int64_t __s64;

typedef uint16_t __le16;
typedef uint32_t __le32;
typedef uint64_t __le64;
typedef uint16_t __be16;
typedef uint32_t __be32;
typedef uint64_t __be64;

typedef uint64_t dma_addr_t;
typedef uint64_t phys_addr_t;
typedef uint64_t resource_size_t;
typedef int64_t ssize_t;
typedef uint32_t gfp_t;

#define GFP_KERNEL 0u
#define GFP_ATOMIC 1u
#define __iomem
#define __user
#define __must_check

#endif
