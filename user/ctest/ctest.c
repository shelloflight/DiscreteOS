/*
 * ctest: libd from C (user/include/libd.h). Run by ltest; exit 0 when every check passed.
 * Heap (malloc, calloc overflow, realloc keeps the data, free returns everything), threads with
 * return values and distinct ids, and a mutex under contention from four threads.
 */

#include "libd.h"

#define CHECK(c)                                                                \
    do {                                                                        \
        if (!(c)) {                                                             \
            dos_printf("ctest: FAIL: %s (line %d)\n", #c, __LINE__);            \
            return 1;                                                           \
        }                                                                       \
    } while (0)

static libd_mutex_t lock = LIBD_MUTEX_INIT;
static uint64_t counter;

static int64_t worker(void *arg)
{
    uint64_t n = (uint64_t)(uintptr_t)arg;
    for (uint64_t i = 0; i < n; i++) {
        libd_mutex_lock(&lock);
        counter++;
        libd_mutex_unlock(&lock);
    }
    return (int64_t)libd_thread_id();
}

static int test_heap(void)
{
    struct libd_heap_stats before, after;
    libd_heap_stats(&before);
    uint8_t *p[64];
    for (int i = 0; i < 64; i++) {
        size_t n = (size_t)(i * 97 + 1);
        p[i] = libd_malloc(n);
        CHECK(p[i] != NULL && ((uintptr_t)p[i] & 15) == 0);
        memset(p[i], i, n);
    }
    for (int i = 0; i < 64; i++) {
        size_t n = (size_t)(i * 97 + 1);
        p[i] = libd_realloc(p[i], n * 3);      /* grows across size classes and into own mappings */
        CHECK(p[i] != NULL);
        for (size_t j = 0; j < n; j++)
            CHECK(p[i][j] == (uint8_t)i);
    }
    for (int i = 0; i < 64; i++)
        libd_free(p[i]);
    uint8_t *z = libd_calloc(1000, 10);
    CHECK(z != NULL);
    for (int i = 0; i < 10000; i++)
        CHECK(z[i] == 0);
    libd_free(z);
    CHECK(libd_calloc((size_t)1 << 62, 8) == NULL);    /* n * size overflows: refused */
    CHECK(libd_malloc((size_t)-1) == NULL);
    libd_free(NULL);
    libd_heap_stats(&after);
    CHECK(after.bytes == before.bytes && after.blocks == before.blocks && after.large == before.large);
    dos_printf("ctest: heap: malloc/calloc/realloc/free, 16-byte aligned, overflow refused, nothing left over\n");
    return 0;
}

static int test_threads(void)
{
    enum { N = 4, ITERS = 50000 };
    libd_thread_t t[N];
    for (int i = 0; i < N; i++)
        CHECK(libd_thread_spawn(worker, (void *)(uintptr_t)ITERS, 0, &t[i]) == 0);
    int64_t ids[N];
    for (int i = 0; i < N; i++) {
        CHECK(libd_thread_join(t[i], &ids[i]) == 0);
        CHECK(ids[i] > 1);
        for (int j = 0; j < i; j++)
            CHECK(ids[j] != ids[i]);
    }
    CHECK(counter == (uint64_t)N * ITERS);
    CHECK(libd_thread_id() == 1);
    CHECK(libd_mutex_trylock(&lock) == 1);
    CHECK(libd_mutex_trylock(&lock) == 0);
    libd_mutex_unlock(&lock);
    libd_mutex_destroy(&lock);
    dos_printf("ctest: threads: %d threads, distinct ids, mutex count %llu exact\n", N, (unsigned long long)counter);
    return 0;
}

int main(void)
{
    if (libd_init(dos_start, "ctest") != 0) {
        dos_printf("ctest: FAIL: libd_init\n");
        return 1;
    }
    if (test_heap() || test_threads())
        return 1;
    dos_printf("ctest: PASSED\n");
    return 0;
}
