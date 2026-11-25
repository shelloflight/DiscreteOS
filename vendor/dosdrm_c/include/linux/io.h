#ifndef _LINUX_IO_H
#define _LINUX_IO_H

#include <linux/types.h>

static inline void mb(void) {
#if defined(__x86_64__) || defined(_M_X64)
    __asm__ volatile("mfence" ::: "memory");
#else
    __sync_synchronize();
#endif
}

static inline void rmb(void) {
#if defined(__x86_64__) || defined(_M_X64)
    __asm__ volatile("lfence" ::: "memory");
#else
    __sync_synchronize();
#endif
}

static inline void wmb(void) {
#if defined(__x86_64__) || defined(_M_X64)
    __asm__ volatile("sfence" ::: "memory");
#else
    __sync_synchronize();
#endif
}

#define dma_rmb() rmb()
#define dma_wmb() wmb()

static inline u32 readl(const volatile void __iomem *addr) {
    u32 v = *(const volatile u32 *)addr;
    rmb();
    return v;
}

static inline void writel(u32 val, volatile void __iomem *addr) {
    wmb();
    *(volatile u32 *)addr = val;
}

static inline u32 ioread32(const volatile void __iomem *addr) {
    return readl(addr);
}

static inline void iowrite32(u32 val, volatile void __iomem *addr) {
    writel(val, addr);
}

#endif
