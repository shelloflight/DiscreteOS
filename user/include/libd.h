/*
 * libd for C programs: the D-OS user runtime (heap, threads, mutexes) shared with Rust programs.
 * Implemented in Rust (user/lib/libd, feature `capi`); build.ps1 links it into every C program
 * that includes this header. Raw syscalls stay in dos.h.
 *
 * Call libd_init first (main's first line). Every function is safe to call from any thread.
 * Errors are DOS_ERR_* status codes; out of memory is NULL or DOS_ERR_NO_MEMORY, never a crash.
 */
#ifndef LIBD_H
#define LIBD_H

#include "dos.h"

/* Set up the runtime; `name` (a string literal) prefixes error reports. 0 or a status. */
int64_t libd_init(const struct dos_startup *s, const char *name);

/* ---- heap ----------------------------------------------------------------------------------------
 * 16-byte aligned blocks; freed small blocks are overwritten before reuse. */
void *libd_malloc(size_t size);
void *libd_calloc(size_t n, size_t size);      /* NULL if n * size overflows */
void *libd_realloc(void *p, size_t size);      /* NULL on failure, the old block untouched */
void libd_free(void *p);

struct libd_heap_stats {
    uint64_t bytes;      /* in use (small blocks at their size class, large ones page-rounded) */
    uint64_t blocks;     /* blocks in use */
    uint64_t large;      /* of which in their own mapping (> 2 KiB) */
    uint64_t arenas;     /* 64 KiB arenas behind small blocks */
};
void libd_heap_stats(struct libd_heap_stats *out);

/* ---- threads -------------------------------------------------------------------------------------
 * Each thread has its own stack with an unmapped guard page below it (an overflow is a fault, not
 * silent corruption) and a thread control block at its FS base (FS:0 the block, FS:8 the id). */
typedef void *libd_thread_t;
/* Start entry(arg); stack in bytes (0: 64 KiB). 0 and *out set, or a status. */
int64_t libd_thread_spawn(int64_t (*entry)(void *arg), void *arg, size_t stack, libd_thread_t *out);
/* Wait for it (once); entry's return value into *result (if not NULL). 0, or the thread's exit
 * code if it ended without returning. */
int64_t libd_thread_join(libd_thread_t t, int64_t *result);
uint64_t libd_thread_id(void);                 /* 1 for the first thread, then 2, 3, ... */
void libd_sleep_ns(uint64_t ns);

/* ---- mutexes -------------------------------------------------------------------------------------
 * One atomic instruction when uncontended; waiters sleep on a kernel event. Not recursive. */
typedef struct { uint32_t state, event; } libd_mutex_t;
#define LIBD_MUTEX_INIT { 0, 0 }
void libd_mutex_lock(libd_mutex_t *m);
void libd_mutex_unlock(libd_mutex_t *m);
int libd_mutex_trylock(libd_mutex_t *m);       /* 1 taken, 0 held by someone */
void libd_mutex_destroy(libd_mutex_t *m);      /* when no longer used: releases its kernel event */

#endif
