/* utest: shared helpers of the ring-3 test program (utest.c: core ABI; ipc.c: IPC, ports,
 * exceptions, compatibility mechanisms). */
#ifndef UTEST_H
#define UTEST_H

#include "dos.h"

extern unsigned failures;
extern dos_handle_t self_proc, self_vmar, log_h;

#define CHECK(cond)                                                                        \
    do {                                                                                   \
        if (!(cond)) {                                                                     \
            dos_printf("utest: FAIL line %d: %s\n", __LINE__, #cond);                      \
            failures++;                                                                    \
        }                                                                                  \
    } while (0)

#define EXPECT(expr, want)                                                                 \
    do {                                                                                   \
        int64_t r_ = (expr);                                                               \
        if (r_ != (int64_t)(want)) {                                                       \
            dos_printf("utest: FAIL line %d: %s = %ld (%s), want %ld\n", __LINE__, #expr,   \
                       r_, dos_status(r_), (int64_t)(want));                               \
            failures++;                                                                    \
        }                                                                                  \
    } while (0)

#define KERNEL_ADDR 0xFFFFFFFF80100000ull
#define UNMAPPED    0x00007F0000000000ull
#define NONCANON    0x0000800000000000ull

static inline uint64_t rdtsc(void)
{
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

uint64_t     parse_u(const char *s);
const char  *word(const char *s, int n);
void        *map_new(uint64_t len, dos_handle_t *vmo_out);
dos_handle_t my_image(void);
int64_t      spawn_self(const char *args, const struct dos_limits *limits, int with_log);
int64_t      wait_exit(int64_t proc, uint64_t timeout_ns);

/* ipc.c */
void test_channels(void);
void test_ipc_processes(void);
void test_ports(void);
void test_exceptions(void);
void test_supervisor(void);
void test_bases(void);
void test_sealing(void);
void test_avx(void);
void bench_ipc(void);
int  ipc_child(const char *a);   /* child modes "p10 ..." */

/* attest.c */
void test_attest(void);
int  attest_print(void);

/* ipcfuzz.c */
void ipc_fuzz(uint64_t total);
int  ipc_fuzz_child(uint64_t seed, uint64_t n);

/* compat.c */
void test_compat(void);

/* cet.c */
void test_shstk(void);
int  cet_child(const char *a);   /* child modes "cet ..." */

#endif
