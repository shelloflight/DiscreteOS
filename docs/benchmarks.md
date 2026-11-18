# Benchmarks

D-OS measures before it optimizes. There are two ways to get numbers:

- `.\build.ps1 test -Case bench` runs the kernel benchmark harness in QEMU (use it to compare
  before/after a change on the same machine; QEMU's absolute numbers mean little);
- `.\build.ps1 bench` builds **`build\discrete-bench.img`**, a hardware benchmark image that boots
  on a real PC, runs everything, and ends on one results page to photograph.

**Code:** `kernel/lib/bench.c`, `kernel/include/bench.h` (kernel), `utest bench` and `fstest bench`
(user space and storage).

## Running the hardware image

1. Write `build\discrete-bench.img` to a USB stick like `discrete.img` ([hardware.md](hardware.md)).
2. Boot it (UEFI); it needs no input and takes 10-30 seconds.
3. Photograph the results page, which ends with `KTEST hwbench: DONE`. `INCOMPLETE` means a
   benchmark failed, fewer than 20 results were recorded, or the log overflowed.

Disks are only read (the `hwbench` test checks this). The image is the release kernel with the
benchmarks run before `init`; lock-order checking is off so lock costs match release builds.

## What is measured

| Group | Benchmarks |
|---|---|
| Kernel | slab and guard-paged allocation, page frames, Rust `Box`; spinlocks, mutex, Rust `SpinLock`; `time_ns`; yield and semaphore round trips (same CPU, cross-CPU); thread create/join; handle lookup/duplicate/close; events; VMO create; map/unmap with TLB shootdown on every CPU; the parts of a process switch (CR3 reload, FPU state, IBPB) |
| User (ring 3, real syscall path) | null syscall; event signal/wait/clear; handle duplicate/close; VMO create/map/touch/unmap; channel write/read; cross-process channel call (and how many calls since boot involved another CPU); channel throughput (64 KiB messages); port batch; forwarded syscall |
| Storage | sequential read throughput and random 4 KiB read latency on the largest file of each volume |

Kernel lines show the best batch of 64 (steady state) and the mean, in cycles and ns. `TSC: N MHz`
converts cycles to time.

## Comparing with other kernels

Compare on **the same PC**, booted into Linux, with equivalent tests:

| D-OS | Linux equivalent |
|---|---|
| `user: null syscall round trip` | `perf bench syscall basic`, lmbench `lat_syscall null` |
| `user: channel call round trip` | `perf bench sched pipe`, lmbench `lat_ctx -s 0 2` |
| `cross-CPU semaphore ping-pong` | `perf bench sched pipe` pinned to two CPUs |
| `user: channel throughput` | lmbench `bw_pipe` / `bw_unix` |
| `map+unmap 1 page with TLB shootdown` | `munmap` in a multi-threaded process |
| `fs: sequential read` | `fio --rw=read --bs=32k --direct=1 --ioengine=psync` |
| `fs: random 4 KiB reads` | `fio --rw=randread --bs=4k --direct=1 --ioengine=psync --iodepth=1` |

D-OS storage runs at queue depth 1 through a user-space driver and file service; compare with
`fio` at `iodepth=1`. Check both systems' active speculation mitigations. D-OS syscalls include
capability checks that Linux's `getpid` does not.

## Reference results

Ryzen 9 9900X (24 threads, TSC 4392 MHz), 32 GiB, NVMe; AutoIBRS, no KPTI.

| Kernel | ns | User (ring 3) | ns |
|---|---|---|---|
| kmalloc+kfree 32 B | 24.8 | null syscall | 34 |
| spin_lock+unlock | 7.8 | event signal+wait+clear | 188 |
| thread_yield round trip | 38.8 | handle duplicate+close | 138 |
| semaphore ping-pong | 75.1 | VMO create+map+touch+unmap+close | 703 |
| thread_create+join | 861 | channel write+read 64 B | 307 |
| handle lookup + rights check | 21.9 | channel call to another process | 3699 |
| cross-CPU semaphore ping-pong | 1094 | port batch, per op | 22 |
| map+unmap, shootdown on 24 CPUs | 586 | forwarded syscall | 4807 |

Channel throughput: 12.5 GB/s. Boot: about 85 ms for D-OS's own part (loader + kernel init).

Process switch parts on the 9900X (before the call handoff below): CR3 reload 90 ns, FPU state save
and restore (2432 bytes, AVX-512) 98 ns, IBPB 155 ns. A cross-process call makes two switches:
0.7 µs of its 3.7 µs. The rest is most likely the call crossing CPUs: an idle CPU took the woken
server before the caller had blocked (a cross-CPU wake-up costs about 1 µs here).

**Call handoff:** a thread woken by a synchronous call (or its reply) is queued on the waker's CPU
and reserved for it for 20 µs: no other CPU may take it in that time. The waker blocks within
nanoseconds and switches straight to it. `channel calls that involved another CPU` shows whether
calls stayed on one CPU.

Known slow spots, good places to contribute: file reads of 32 KiB and more are bound by one driver
request per 32 KiB (a channel message); larger requests need memory shared with the drivers.