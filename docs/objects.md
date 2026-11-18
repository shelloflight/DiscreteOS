# Kernel objects, handles and rights

Everything a program can use is a **kernel object** reached through a **handle**. This is the
model the syscall ABI ([abi.md](abi.md)) is built on.

**Code:** `kernel/rust/src/object/` (one file per object type; `handle.rs`, `quota.rs`, `kref.rs`
for the machinery); devices in `object/device.rs` and `kernel/rust/src/dev/`.

## Model

- Objects are reference-counted and typed, with a kernel object id (koid) that is never reused.
- A handle is `(object, rights)` in one process's handle table. There are no global names, no
  `root`, no ambient authority.
- **Rights never grow.** Duplicating, replacing or granting a handle takes a subset of its rights
  (or `SAME`). Asking for more is `ACCESS_DENIED`.
- Every process has **quotas** (memory, handles, threads), charged up the whole ancestor chain, so a
  child can never use more than its parent was given. Defaults: 64 MiB, 4096 handles, 64 threads.
- The only authority without a handle: creating Events, Timers and VMOs inside one's own process,
  bounded by its quota.

## Object types

| Type | What | Signals |
|---|---|---|
| Process | handle table + root VMAR + quota account | `TERMINATED` |
| Thread | a thread in a process | `TERMINATED` |
| VMO | physical pages (committed eagerly, zeroed) | |
| VMAR | a range of an address space: mappings and child regions | |
| Event | one user-settable signal | `SIGNALED` |
| Timer | one-shot deadline | `SIGNALED` |
| Log | the right to print on the kernel console | |
| Channel | one endpoint of a message pipe (data + handles) | `READABLE` `WRITABLE` `PEER_CLOSED` |
| Port | shared-memory submission/completion rings + async waits | |
| Exception | a stopped thread's fault, held by its supervisor | |
| Resource | a kernel privilege: `VMEX` (make code executable), `POWER` | |
| Device | one PCI function or platform device, for a user-space driver | |
| Interrupt | one interrupt source of a device | `SIGNALED` |
| Pin | VMO pages mapped for DMA in a device's IOMMU domain | |

Executable memory only comes from the program loader or from `vmo_make_executable` (needs `VMEX`),
which **seals** the VMO first: no writable handle or mapping can exist or ever be made. W^X holds
across every alias.

## Rights

| Bit | Right | Needed for |
|---|---|---|
| 0 | DUPLICATE | `handle_duplicate` |
| 1 | TRANSFER | `handle_grant`, sending in a channel message, passing to `spawn` |
| 2 | READ | reading; mapping readable |
| 3 | WRITE | writing, setting timers, `log_write`; mapping writable |
| 4 | EXECUTE | mapping executable |
| 5 | MAP | mapping a VMO; changing a VMAR |
| 6 | SIGNAL | `event_signal` |
| 7 | WAIT | `object_wait` |
| 8 | INSPECT | quotas, exit codes, device info |
| 9 | MANAGE | kill; create processes/threads inside; exception channels; memory access; using a resource |

`SAME` (bit 31) means "the source handle's rights". Unknown bits are refused. Checks happen in a
fixed order: valid handle, type, rights, arguments, state, quota.

## Handle values

A handle value is a 32-bit `(slot, generation)` pair scrambled with a per-process random key. Values
look random, differ between processes, and a closed value stays invalid (the slot's generation is
bumped). `0` is never valid. Lookup is O(1).

## Lifetimes

- An object lives while any reference exists: handles, mappings, running threads.
- Killing a process stops every user thread (IPI or wake-up; none returns to user mode), closes its
  handle table, empties its address space, then sets `TERMINATED`.
- Threads hold their process, so page tables never disappear under a running thread.
- Closing a channel end drops its queued messages and sets `PEER_CLOSED` on the other end. Cycles of
  channel ends queued inside each other are found and broken when any process exits
  (`channel.rs`, `collect_cycles`); uncertainty always counts as "still referenced".
- Dropping the last handle to an unresolved Exception kills the faulting process.

## Locking

Handle tables and VMARs share one lock rank (they may allocate while held, are never nested, and
objects are never dropped under them). Ranks are checked in test builds (`lockorder`); a new lock
needs a rank that fits the existing order in `kernel/include/spinlock.h`.

## Adding an object type

1. A module in `object/` with the object, its default rights and its signals.
2. Register the type in `object/mod.rs`; charge quota through `Charge` (refunded on drop).
3. Out of memory returns `Status::NoMemory`; add the new allocations to the fault-injection
   scenario in `object/tests.rs`.
4. Syscalls in `user/syscall.rs`, the C binding in `user/include/dos.h`, the table in
   [abi.md](abi.md), and ring-3 tests in `user/utest`.

## Tests

`objects`: rights on every operation, handle reuse, quotas, kill, VMAR rules, an out-of-memory sweep
with fault injection over every allocation of a scenario (must return `NO_MEMORY` and leak nothing),
and multi-core handle-table stress. `soak` mixes random object traffic and checks the live object
count returns to baseline.

## Limitations

- VMO pages are committed eagerly (no demand paging yet).
- Unmapping shoots down the TLB only on CPUs that have the address space loaded.
- `handle_grant` and failed channel writes consume the handle; duplicate first to keep a copy.
