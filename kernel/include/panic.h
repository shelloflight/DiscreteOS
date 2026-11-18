/* Fatal error handling. A panic prints the reason and location, then halts the CPU forever. */
#ifndef DOS_PANIC_H
#define DOS_PANIC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "compiler.h"

NORETURN void panic_at(const char *file, int line, const char *fmt, ...) PRINTF_FMT(3, 4);

#define panic(...) panic_at(__FILE__, __LINE__, __VA_ARGS__)

/* Always-on assertion: kernel invariants are checked in release builds too (fail closed). */
#define KASSERT(cond)                                                   \
    do {                                                                \
        if (UNLIKELY(!(cond)))                                          \
            panic_at(__FILE__, __LINE__, "KASSERT failed: %s", #cond);  \
    } while (0)

/* Building blocks for custom panic reports (e.g. CPU exceptions):
 * panic_begin() disables interrupts, guards against recursion and prints the banner;
 * panic_halt() prints the final line and stops. */
void panic_begin(void);
NORETURN void panic_halt(void);

/* True once a panic has started: locks and logging switch to lock-free best effort so the
 * report always gets out, even if the panicking code held the console lock. */
bool panic_in_progress(void);
bool panic_claimed(void);        /* a CPU has started a panic (it may not be printing yet) */
bool panic_owner_is_me(void);

/* Rust panic handler entry (kernel/rust/src/lib.rs): strings are not NUL-terminated. */
NORETURN void rust_panic(const char *file, size_t file_len, uint32_t line, const char *msg, size_t msg_len);

#endif
