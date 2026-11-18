# Architecture

D-OS is a **capability-based hybrid kernel** for x86-64. It is deliberately *not* UNIX-like in its
OS model, and deliberately *standard* where standards cost nothing (ELF, UEFI, ACPI, GPT, virtio).
Its closest relatives are Fuchsia, seL4 and Plan 9.

Every design decision is weighed against three goals: **Fast, Secure, Practical**. When they
conflict, the trade-off is written down (in the relevant doc and in the pull request), never made
silently.

## Components

| Name | What | State |
|---|---|---|
| **D-KRNL** | the kernel (C + Rust + NASM) | working, hardened, tested |
| **D-CMPL** | compatibility layer: Windows and Linux programs run unchanged | first proofs run |
| **D-AWMI** | window manager and graphics | not started |
| **D-PACK** | signed packages and system updates | not started |

## The model in one page

| Area | D-OS | Instead of (UNIX) |
|---|---|---|
| Access control | **Capabilities**: a program can use only the handles it was given. No `root`, no ambient authority | users, groups, `rwx` |
| Kernel resources | **Typed objects behind handles** with rights that can only shrink ([objects.md](objects.md)) | file descriptors, "everything is a file" |
| Starting programs | **`spawn()`** with an explicit handle set; nothing is inherited by accident | `fork()` + `exec()` |
| Visibility | **Per-app namespaces** built from granted directory handles | one global filesystem tree |
| Drivers | **User space** (`.ddrv`), isolated by the IOMMU, restartable | in-kernel drivers |
| IPC / syscalls | Channels, shared-memory rings (ports), fast synchronous call/reply, zero-copy VMOs | pipes, blocking syscalls |
| Code | **Signed**; W^X everywhere, including across aliases | writable, unsigned binaries |

## Boot to user space

```
firmware ─► loader (BIOS stage 1-3 or BOOTX64.EFI)
              verifies the kernel's signature, applies KASLR, builds BootInfo
          ─► D-KRNL: validates BootInfo, CPU/memory/interrupts, SMP, Rust subsystems,
              PCI + IOMMU, measured boot, then starts init in ring 3
          ─► init (service manager): reads the service manifests, starts storaged and devmgr
              with exactly the grants they list, links them, supervises and restarts them
          ─► devmgr: starts one user-space driver per device (virtio, AHCI, NVMe, xHCI, PS/2)
```

User programs and the system's service manifests are embedded in the kernel image today (there is no
installer yet); `init` gets a read-only VMO for each one ([services.md](services.md)).

## Source tree

| Path | Language | Contents |
|---|---|---|
| `boot/` | NASM, C | BIOS stages 1-3, UEFI loader, shared signature verifier and KASLR code ([boot.md](boot.md)) |
| `kernel/arch/x86_64/` | C, NASM | CPU setup, GDT/IDT, APIC, SMP, syscall entry, context switch, speculation mitigations, power |
| `kernel/mm/` | C | physical memory, page tables, heap, KASLR, KPTI |
| `kernel/sched/` | C | scheduler, per-CPU data, wait queues |
| `kernel/lib/` | C | printf, strings, spinlocks, KASAN, profiler, benchmarks, fault injection |
| `kernel/drivers/` | C | early console only: serial, VGA text, framebuffer |
| `kernel/rust/src/object/` | Rust | kernel objects, handles, rights, quotas, IPC ([objects.md](objects.md)) |
| `kernel/rust/src/user/` | Rust | syscalls, ELF loader, user threads, exceptions ([abi.md](abi.md)) |
| `kernel/rust/src/dev/` | Rust | PCI, IOMMU (VT-d, AMD-Vi), interrupt delivery for user-space drivers |
| `kernel/rust/src/security/` | Rust | verified/measured boot, TPM 2.0, attestation ([signing.md](signing.md)) |
| `kernel/kdb.c`, `kernel/ktest.c` | C | serial kernel debugger; in-kernel tests |
| `user/include/dos.h`, `user/lib/dos.c` | C | C binding of the ABI and a minimal runtime for C programs |
| `user/lib/libd/`, `user/include/libd.h` | Rust, C | `libd`: the user runtime (complete ABI, owned handles, heap, threads, locks, channels, files, driver protocol), also for C ([libd.md](libd.md)) |
| `user/lib/fs/`, `user/lib/crypto/` | Rust | `dosfs` (GPT, FAT32, DFS, BLAKE3); `doscrypt` (SHA-2, Ed25519, `.dsig`, attestation) |
| `user/init/`, `user/lib/dman/` | Rust | first process and service manager, its manifests; the manifest parser ([services.md](services.md)) |
| `user/devmgr/`, `user/storaged/` | Rust | device manager + drivers, storage service |
| `user/dcmpl/`, `compat/` | Rust, C | D-CMPL and its Windows/Linux proof programs ([compat.md](compat.md)) |
| `user/utest/`, `user/fstest/`, `user/ltest/`, `user/ctest/`, `user/hello/` | C, Rust | ring-3 test programs |
| `tools/dosimg/` | Rust | host tool: disk images, signing, fsck, attestation verifier |
| `build.ps1` | PowerShell | build, run, debug, test ([building.md](building.md)) |

## Languages

| Layer | Language | Why |
|---|---|---|
| Boot stages, entry stubs, ISRs, context switch | NASM | must be exact |
| Core kernel (arch, memory, scheduler, early drivers) | C (clang, freestanding) | small, tested; may move to Rust where it pays off |
| **New subsystems by default** (objects, syscalls, IPC, parsers, filesystems, drivers, services) | Rust (`no_std`) | memory safety where untrusted input arrives |
| C++ | not used | one systems language beside C is enough |

C and Rust meet at a plain C ABI (`extern "C"`, `#[repr(C)]`; declarations in
`kernel/include/rust.h` and `kernel/rust/src/ffi.rs`). `unsafe` Rust stays in small blocks, each
with a `// SAFETY:` comment (clippy enforces it in the kernel).

## Rules all code follows

- **Validate every boundary.** BootInfo, firmware tables, disk contents, syscall arguments, IPC
  messages and foreign binaries are hostile. Fail closed with a clear error, never undefined
  behaviour. Every parser of untrusted input has a fuzzer.
- **Out of memory is an error, never a panic** (`NO_MEMORY`); fault injection proves it.
- **W^X**: no page is ever writable and executable, through any mapping or alias.
- **Rights never grow.** A handle can be narrowed, never widened.
- **Hot paths stay short**: no allocation in interrupt handlers, the scheduler, or the syscall and
  IPC fast paths. Measure before and after a performance change (`.\build.ps1 test -Case bench`).
- **Reproducible builds**: no timestamps, absolute paths or build-time randomness in outputs. The
  full test run rebuilds the image elsewhere and requires identical bytes.
- **Clear errors**: every failure says what happened and, where possible, what to do.
- **ABI stability**: syscall numbers, status codes and rights bits are never reused or changed
  ([abi.md](abi.md#versioning)).

## Where new code goes

| You want to add | Put it in | Also |
|---|---|---|
| A device driver | a module in `user/devmgr/src/` implementing the driver protocol (`user/lib/libd/src/proto.rs`); block drivers implement `Disk` for `blkserve.rs` | a test in `devmgr test` or `storage` |
| A filesystem or on-disk parser | `user/lib/fs/` (host-testable, `no_std + alloc`) | unit tests and a fuzzer in `fuzz.rs` |
| A kernel object or syscall | `kernel/rust/src/object/` and `user/syscall.rs`; C binding in `dos.h` | bump the ABI version, update [abi.md](abi.md), add `utest` cases |
| A user program | `user/<name>/`: a Rust crate on libd with its own `_start` (see `user/ltest`), or `.c` files (include `libd.h` for the heap, threads and locks); `build.ps1` embeds it as `<name>.dx` | run it from `init` (`init run <name>`) in a test case |
| A service | a program as above, plus a manifest in `user/init/services/` naming exactly what it gets ([services.md](services.md)) | the `services` case; a test manifest in `user/init/services/test/` |
| Low-level arch code | `kernel/arch/x86_64/` | a KTEST variant if it can fail in an interesting way |

## Dependencies

No external crates or libraries: everything is in-tree, `no_std`, with `Cargo.lock` committed. A
new dependency needs a strong reason in its pull request, a license compatible with `GPL-3.0-or-later`, and must
not break reproducible builds.
