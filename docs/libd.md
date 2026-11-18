# libd: the user runtime

`libd` is the library every ring-3 program is built on: the complete ABI, owned handles, a heap
that is safe for many threads, threads, locks and channels. Rust programs use the crate directly;
C programs use the same code through `user/include/libd.h`.

**Code:** `user/lib/libd/` (Rust, `no_std`, no dependencies), `user/include/libd.h` (C).
**Tests:** `ltest` and `ctest` (test case `libd`).

## Modules

| Module | What |
|---|---|
| `sys` | every syscall and structure of [abi.md](abi.md), mirroring `dos.h`; `Ok(value)` or `Err(status)` |
| `handle` | `Owned` (closed on drop; `dup`, `replace`, `wait`, `info`, `into_raw`), `Event`, `Timer`, `sleep` |
| `chan` | `Channel`: messages with data and owned handles; handles nobody takes close with the message |
| `sync` | `Mutex<T>`, `RawMutex`, `Once` |
| `thread` | `spawn`, `Builder`, `JoinHandle`, `current_id`, `reap` (feature `alloc`) |
| `heap` | the global allocator and its statistics (feature `alloc`) |
| `Port`, `Mapping`, `Dma` | async waits on many objects; VMOs mapped here; DMA pins |
| `fs`, `proto` | files as handles and namespaces ([storage.md](storage.md)); the driver protocol |
| `svc` | the service manager's protocol (`CONNECT`, `SYNC`, `SHUTDOWN`, `LOG_LEVEL`) and `endpoint(name)` ([services.md](services.md)) |
| `rec`, `term`, `tool` | typed records (what shell commands exchange; `Out` for a program's output); the terminal's session protocol; how the shell starts a tool or a foreign program (`TAG_IMAGE`, `TAG_TIME_BASE`) ([shell.md](shell.md)) |
| `log`, `time` | the log service's records and reader; wall-clock time (`Time`, ns since 2000-01-01 UTC) and the clock service's client; levels: `log_warn!`, `log_error!`, `log_debug!` |
| `capi` | the C binding (feature `capi`) |

A program declares its entry with `libd::entry!(_start, main)` and calls `libd::init` first.
Every Rust program is built on libd, D-CMPL included ([compat.md](compat.md)): its Windows
threads are libd threads (FS stays the thread control block; the foreign program uses GS).
`init` refuses a kernel whose ABI is older than the one libd was built for.

## Heap

- Blocks up to 2 KiB come from eight size classes carved out of 64 KiB arenas; larger blocks get
  their own mapping, unmapped on free.
- One lock, held for a few instructions; a waiter that spins too long yields.
- Freed small blocks are overwritten (`0xDD`) before reuse. `realloc` stays in place within a
  size class or page count.
- Out of memory is a null pointer (Rust: an allocation error), never a crash inside the heap.

## Threads

- Each thread gets a stack (default 64 KiB, `Builder::stack_size`) mapped inside a reserved
  region with an **unmapped guard page** on each side. An overflow faults in the guard page.
- The top of the stack holds the thread control block. The FS base points at it: FS:0 is the
  block itself, FS:8 the thread id (1 for the first thread). Threads created with the raw
  `thread_create` have no block.
- `join` returns the closure's value, or `Err(exit code)` if the thread ended through
  `thread_exit`. A dropped `JoinHandle` detaches the thread; ended detached threads are reclaimed
  on the next `spawn` or `reap`.
- All allocations are fallible: a failed spawn is an `Err`.
- The kernel cannot release a reserved region, so an ended thread's stack pages are unmapped and
  the empty region is kept for the next thread with that stack size. Address space stays bounded
  by the peak number of threads.

## Mutex

Futex-style: taking a free mutex is one compare-and-swap, releasing one with no waiters is one
swap, no syscall. A contended waiter spins briefly, then sleeps on a kernel event the mutex
creates on first contention; the releasing thread signals it. If the event cannot be created,
waiters yield instead. Not recursive.

## C binding

```c
#include "libd.h"

int main(void)
{
    libd_init(dos_start, "myprog");
    char *p = libd_malloc(100);
    libd_thread_t t;
    libd_thread_spawn(worker, p, 0, &t);
    libd_thread_join(t, NULL);
    libd_free(p);
    return 0;
}
```

`build.ps1` builds libd as a static library with feature `capi` and links it into every C program
that includes `libd.h`. C allocations carry a 16-byte size header (C's `free` has no size).

## Measured

QEMU TCG (indicative only): uncontended mutex lock+unlock 16 ns, 64-byte `Box` alloc+free 63 ns,
thread spawn+join with a 64 KiB stack 180 µs (mostly the eagerly committed stack).
