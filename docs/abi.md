# User ABI (version 9)

The interface between ring-3 programs and the kernel. It is handle-based from the first syscall:
no paths, no PIDs, no global names. A program can only use the handles it was started with and the
ones it creates or receives. The object model behind every call is in [objects.md](objects.md).

**Code:** `kernel/rust/src/user/` (syscalls, ELF loader, exceptions, user-memory access),
`kernel/arch/x86_64/syscall.asm` and `user.c` (entry/exit/faults). Bindings:
`user/include/dos.h` (C), `user/lib/libd/src/sys.rs` (Rust).

## Versioning

- `abi_version()` (syscall 0) returns **9**; the startup block carries it too. A program checks it
  is at least the version it was built for.
- **Syscall numbers are never reused or renumbered.** A removed call keeps answering
  `NOT_SUPPORTED`.
- Structures only grow at the end, guarded by a size or flags field. `flags` fields must be 0 until
  a flag is defined (anything else is `INVALID_ARGS`).
- Status codes and rights bits keep their values for ever.
- A new syscall or behaviour bumps the version: update `ABI_VERSION` (`user/loader.rs`),
  `DOS_ABI_VERSION` (`dos.h`) and this page.

| Version | Added |
|---|---|
| 1 | handles, VMOs, VMARs, processes, threads, events, timers, spawn |
| 2 | channels, ports, exceptions, FS/GS bases, executable VMOs, debugger access (32-50); start exception |
| 3 | devices for user-space drivers (51-59) |
| 4 | code signing (60-61); `spawn` runs only trusted images |
| 5 | remote attestation (62) |
| 6 | power control (63) |
| 7 | service manager decisions in the measurement log (64); MANIFEST and MEASURE startup handles; `vmo_verify` accepts manifest signatures |
| 8 | the log service (65-66): kernel log records name the writing process; KLOG and BOOT_TIME startup handles |
| 9 | the terminal and the shell (67-68): the `display` device and `display_info`; `process_handles` |

## Calling convention (x86-64)

| | |
|---|---|
| Instruction | `syscall` |
| Number | RAX |
| Arguments | RDI, RSI, RDX, R10, R8, R9 |
| Result | RAX: `>= 0` a value (handle, size, address, count, signals); `< 0` a status code |
| Clobbered | RCX, R11; everything else is preserved |

Handles are 32-bit (`0` is never valid). Timeouts are relative nanoseconds: `0` polls,
`UINT64_MAX` waits for ever. `ANY` (`UINT64_MAX`) as an offset lets the kernel choose an address.

## Status codes

| Code | Name | Meaning |
|---|---|---|
| 0 | OK | |
| -1 | NO_MEMORY | the kernel is out of memory (never a panic) |
| -2 | INVALID_ARGS | malformed argument (alignment, size, flags, W+X, ...) or invalid executable |
| -3 | BAD_HANDLE | not a live handle in this process |
| -4 | WRONG_TYPE | the object has another type |
| -5 | ACCESS_DENIED | the handle lacks a right, or more rights were asked for |
| -6 | NO_RESOURCES | a quota would be exceeded |
| -7 | OUT_OF_RANGE | offset/length outside the object |
| -8 | TIMED_OUT | a wait timed out |
| -9 | BAD_STATE | the process is dead, the thread still runs, ... |
| -10 | NO_SPACE | no room in the region, or the range overlaps a mapping |
| -11 | BAD_ADDRESS | a pointer argument is not valid user memory |
| -12 | NOT_SUPPORTED | unknown syscall |
| -13 | SHOULD_WAIT | nothing to do right now: retry or wait |
| -14 | BUFFER_TOO_SMALL | the sizes needed are written back |
| -15 | PEER_CLOSED | the other end of the channel is closed |
| -16 | BAD_SIGNATURE | a `.dsig` does not match the content or the D-OS key |
| -17 | NOT_SIGNED | `spawn` of an image that is neither signed nor allowed unsigned |

## Syscalls

`R` is the right the handle needs.

| # | Name | Arguments | Result | R |
|---|---|---|---|---|
| 0 | abi_version | | version | |
| 1 | log_write | log, ptr, len (<= 64 KiB) | len | WRITE |
| 2 | handle_close | h | 0 | |
| 3 | handle_duplicate | h, rights | new handle | DUPLICATE |
| 4 | handle_replace | h, rights | new handle (h is gone) | |
| 5 | handle_grant | h, rights, process | handle in that process (h is gone, even on error) | TRANSFER; MANAGE on process |
| 6 | object_info | h, `struct dos_info *` | 0 | |
| 7 | object_name | h, buf, len | name length | |
| 8 | object_wait | h, signal mask, timeout | signals seen | WAIT |
| 9 | event_create | | handle | |
| 10 | event_signal | h, clear, set (only `SIGNALED`) | 0 | SIGNAL |
| 11 | timer_create | | handle | |
| 12 | timer_set | h, delay ns | 0 | WRITE |
| 13 | timer_cancel | h | 1 if it was pending | WRITE |
| 14 | vmo_create | size (<= 1 GiB) | handle | |
| 15 | vmo_read | h, offset, buf, len | 0 | READ |
| 16 | vmo_write | h, offset, buf, len | 0 | WRITE |
| 17 | vmo_size | h | size | |
| 18 | vmar_map | vmar, offset or `ANY`, vmo, vmo offset, len, perms | address | MAP + perms on both |
| 19 | vmar_unmap | vmar, addr, len | mappings removed | MAP |
| 20 | vmar_allocate | vmar, offset or `ANY`, len, rights, `uint64_t *base` | region handle | MAP |
| 21 | process_create | parent, name, name len, `struct dos_limits *` or 0, `dos_handle_t *vmar` | process handle | MANAGE on parent |
| 22 | process_kill | process | 0 | MANAGE |
| 23 | process_exit | code | does not return | |
| 24 | process_quota | process, `struct dos_quota *` | 0 | INSPECT |
| 25 | process_exit_code | process | exit code (`BAD_STATE` while running) | INSPECT |
| 26 | thread_create | process, entry, stack top, arg | thread handle | MANAGE |
| 27 | thread_exit | code | does not return | |
| 28 | thread_exit_code | thread | exit code (`BAD_STATE` while running) | INSPECT |
| 29 | spawn | `struct dos_spawn *` | process handle | MANAGE on parent, READ on image, TRANSFER on each handle |
| 30 | clock_ns | | monotonic ns since boot | |
| 31 | yield | | 0 | |
| 32 | channel_create | `dos_handle_t out[2]` | 0 | |
| 33 | channel_write | ch, `struct dos_msg *` | 0 (handles moved, consumed even on error) | WRITE; TRANSFER on each handle |
| 34 | channel_read | ch, `struct dos_msg *`, ... | bytes | READ |
| 35 | channel_call | ch, write msg, read msg, timeout | bytes of the reply | READ WRITE |
| 36 | port_create | entries (power of 2, <= 4096), `dos_handle_t *vmo` | port handle + ring VMO | |
| 37 | port_enter | port, submit count, min completions, timeout | submissions taken | READ WRITE |
| 38 | object_wait_async | h, mask, port, key | 0 | WAIT; WRITE on port |
| 39 | port_cancel | port, h, key | waits cancelled | WRITE |
| 40 | process_exception_channel | process | channel handle | MANAGE |
| 41 | exception_get_regs | exception, `struct dos_regs *` | 0 | READ |
| 42 | exception_set_regs | exception, `const struct dos_regs *` | 0 (validated) | WRITE |
| 43 | exception_resume | exception, `RESUME` or `KILL`, code | 0 | MANAGE |
| 44 | thread_set_exception_handler | entry, stack top (0, 0 removes) | 0 | |
| 45 | exception_return | `const struct dos_exception_record *` | does not return | |
| 46 | thread_set_base | `FS` or `GS`, base | 0 | |
| 47 | thread_get_base | `FS` or `GS` | base | |
| 48 | vmo_make_executable | vmo, VMEX resource | new handle: EXECUTE, no WRITE | MANAGE on resource |
| 49 | process_read_memory | process, addr, buf, len (<= 64 KiB) | 0 | MANAGE |
| 50 | process_write_memory | process, addr, buf, len (<= 64 KiB) | 0 | MANAGE |
| 51 | device_info | device, `struct dos_device_info *` | 0 | INSPECT |
| 52 | device_config_read | device, offset, size (1/2/4) | value | READ |
| 53 | device_config_write | device, offset, size, value | 0 | WRITE |
| 54 | device_map_bar | device, bar | device VMO handle | MAP |
| 55 | device_io_read | device, bar, offset, size | value | READ |
| 56 | device_io_write | device, bar, offset, size, value | 0 | WRITE |
| 57 | device_interrupt | device, index, flags (0) | interrupt handle | MANAGE |
| 58 | interrupt_ack | interrupt | times fired so far | WRITE |
| 59 | device_dma_map | device, vmo, offset, len, flags, `uint64_t addrs[]` | pin handle | MANAGE; READ/WRITE on VMO |
| 60 | vmo_verify | vmo, dsig vmo | 0 (sealed; a program or driver is trusted to run, a manifest is only known genuine) | READ on both |
| 61 | vmo_allow_unsigned | vmo, VMEX resource | 0 (sealed, trusted as unsigned code) | READ; MANAGE on resource |
| 62 | attest | nonce (32 bytes), buf, cap | report length | |
| 63 | system_power | POWER resource, action (1 off, 2 reset) | does not return, or `NOT_SUPPORTED` | MANAGE on resource |
| 64 | measure | MEASURE resource, digest (32 bytes), text, len (<= 52, printable ASCII) | 0 (PCR 10 extended, logged as `svc <text>`) | MANAGE on resource |
| 65 | klog_read | KLOG resource, seq, buf, cap | records copied (`struct dos_klog_entry`, 176 bytes; at most 64), kernel addresses replaced by `[kaddr]` | MANAGE on resource |
| 66 | log_record | log, level (0 error .. 3 debug), text, len | len (`log_write` is level 2, info) | WRITE |
| 67 | display_info | device, `struct dos_display_info *` | 0 (`WRONG_TYPE` unless it is the display) | INSPECT |
| 68 | process_handles | process, `struct dos_handle_entry *`, cap | handles it holds (at most 256 entries copied: type, rights, koid, name; never handle values) | INSPECT |

Test kernels only: `0xF000` / `0xF001` make the kernel touch / execute a user address, to prove
SMAP and SMEP fire.

## spawn and the startup block

`spawn` creates a process, loads an ELF image from a VMO and starts its first thread. The image
must be **trusted** (verified with `vmo_verify`, embedded in the kernel, or allowed with
`vmo_allow_unsigned`), else `NOT_SIGNED` before anything else happens. Passed handles are checked
first; if that fails, nothing happened. After that they are moved, never left in two places.

Executables (`.dx`, ELF64):

| Rule | |
|---|---|
| Types | ET_DYN (static PIE at a random base, RELATIVE relocations only) or ET_EXEC |
| Segments | at most 16 PT_LOAD, in order, inside the file, never sharing a page, never W+X |
| Refused | PT_INTERP, PT_TLS, executable stack, DT_NEEDED, other relocation types, entry outside code, over 64 MiB |
| Stack | 256 KiB, guard pages on both sides, random address |

At the entry point, RDI points at `struct dos_startup`: magic `DOSS`, ABI version, the handle list
(`{handle, tag}` pairs, up to 256 passed by the spawner plus the process's own three), the argument
bytes (<= 4096), the image base and the stack.

Tags: `PROC_SELF` 1, `THREAD_SELF` 2, `VMAR_ROOT` 3, `LOG` 4, `PROGRAM` 5, `VMEX` 6, `DEVICE` 7,
`POWER` 8, `MEASURE` 9, `MANIFEST` 10, `KLOG` 11, `BOOT_TIME` 12, and `DOS_TAG_USER` (0x10000) and
up for the spawner's own. `init` gets its own handles, the log, one read-only VMO per embedded program
and per embedded service manifest (`*.dman`: data, never runnable), the VMEX, POWER, MEASURE and
KLOG resources, the boot-time record (UEFI only: the firmware's time at boot and the monotonic
time it corresponds to, `struct dos_boot_time`) and every device.
Tags user space agrees on: the service manager's control channel and endpoints
([services.md](services.md)), namespaces ([storage.md](storage.md)).

## Processes

A process ends on `process_exit`, when its last thread exits, when killed, or when a thread faults
with no handler. Exit codes the kernel sets: `DOS_EXIT_KILLED` (`0x80000001`), `DOS_EXIT_FAULT`
(`0x80000002`, with a crash report on the console, rate-limited). `TERMINATED` is set once
everything is released.

## User memory

- The user half is `0x200000` .. `0x00007FFFFFFF0000`.
- Every pointer argument is range-checked and copied once with fault-tolerant copies: a bad pointer
  is `BAD_ADDRESS`, never a crash. SMAP and SMEP are on.
- Each process gets random bases for its mappings, image and stack. Page tables count against its
  memory quota.

## CPU state

Each thread has its own XSAVE state (x87, SSE, AVX, AVX-512 where present) and its own FS/GS base.
`rdtsc` and `int3` are allowed; there is no direct I/O port access (drivers use `device_io_*`).

## Channels

A message is up to 64 KiB of data and up to 64 handles; at most 256 messages wait per direction.
Handles in a message are moved; all checks happen before anything moves. `channel_call` tags the
message with a transaction id (first 4 bytes, top bit set) and waits for the reply with the same
id; the server's reply switches straight to the caller.

## Ports

A port is a submission ring (64-byte entries) and a completion ring (16-byte entries) in a VMO the
creator maps. `port_enter` runs submitted entries (a whitelist of non-blocking syscalls) and waits
for `min_complete` completions. The kernel treats the shared header as hostile. `object_wait_async`
posts one completion `{key, signals}` when a signal in the mask is set.

## Exceptions

A user-mode fault goes, in order, to:

1. the thread's **handler** (`thread_set_exception_handler`): it runs on its own stack with an
   exception record and returns with `exception_return`. A fault inside the handler skips to 2;
2. the process's **supervisor** (holder of its exception channel): the thread blocks until the
   supervisor resumes (possibly with new registers) or kills it;
3. otherwise the process is killed with `DOS_EXIT_FAULT`.

Spawn flags:
- `DOS_SPAWN_START_EXCEPTION`: the first thread stops before its first instruction with a
  `START` exception, so a supervisor can set up memory and registers (used to build a Linux
  initial stack; also a debugger's "stop at start").
- `DOS_SPAWN_FORWARD`: every syscall becomes a `SYSCALL` exception for the supervisor (how D-CMPL
  runs Linux programs).

Register sets from user space are validated (user addresses only, user-settable flags only).

## Code signing, attestation, power

- `vmo_verify` checks a `.dsig` ([signing.md](signing.md)) against the kernel's key, seals the VMO,
  and requires every byte past the signed size to be zero. `vmo_allow_unsigned` lets a VMEX holder
  run unsigned code. Both decisions are measured into PCR 10.
- `attest` returns a signed report for the caller's nonce ([attestation.md](attestation.md));
  `DOS_ATTEST_MAX` bytes hold any report.
- `system_power` needs the POWER resource; nothing is flushed by the kernel ([power.md](power.md)).
- The kernel log: every `log_write`/`log_record` becomes records attributed by the kernel to the
  writing process (koid and name; a program cannot write under another's name). `klog_read`
  needs the KLOG resource (the log service only) and never returns a kernel address: hex runs in
  the kernel half are replaced by `[kaddr]` first (KASLR).
- `measure` needs the MEASURE resource (init only): the service manager records each manifest it
  accepts or refuses in PCR 10 ([services.md](services.md)).

## Devices (for user-space drivers)

The kernel finds devices at boot and gives them all to `init`, which passes them to the device
manager, which grants each to its driver.

- **Config space**: reads anywhere; writes only to the command register's decode and bus-master
  bits and the device-specific area outside the PM, MSI, PCIe and MSI-X capabilities.
- **MMIO**: `device_map_bar` returns an uncached device VMO; the MSI-X table pages are hidden (only
  the kernel programs interrupts). BARs overlapping RAM or another device are refused.
- **I/O ports**: only inside the device's own I/O BARs or platform windows.
- **Interrupts**: one Interrupt object per MSI-X/MSI entry or ISA line. Wait, `interrupt_ack`, then
  service the device; nothing is lost. Legacy INTx is not offered.
- **DMA**: `device_dma_map` pins VMO pages and returns device addresses. With an IOMMU, everything
  else the device tries to reach is blocked and counted; without one, the boot log says DMA is not
  confined. Sealed (code) VMOs can never be DMA targets.
- **The display** (ABI v9): a platform device named `display`, the screen the kernel console used
  (UEFI GOP framebuffer, or VGA text after a BIOS boot). BAR 0 is its memory, mapped
  write-combining; `display_info` gives its layout (`struct dos_display_info`: RGB32 or VGA text,
  width, height, pitch, colour shifts); VGA text has the CRT controller ports as I/O window 1.
  **Mapping BAR 0 takes the screen**: the kernel console writes to serial only from then on, until
  a panic takes the screen back. The graphics card's PCI BAR that holds the framebuffer can no
  longer be mapped by a driver. Init gives it to the terminal ([shell.md](shell.md)).

## Tests

`user` (`utest all`: handles, rights, invalid pointers, memory, threads, spawn, user faults, kill,
FPU state, IPC, ports, exceptions; `kasan-user` repeats it under KASAN), `fuzz` (ELF parser
mutations and random syscalls), `smap`, `smep`, `compat`, `drivers` (`drivers-amd` on AMD-Vi),
`keyboard`, `usbkbd` (`usbnokbd`: no keyboard; `usbhub`: behind two hubs; `usbplug`: hot-plug, a reconnecting device; `usbtwo`: two keyboards on one controller), `attest`, `poweroff`,
`services` (MANIFEST and MEASURE handles, `measure`, manifest signatures, `klog_read` filtering,
`log_record` levels), `time`, `time-uefi` (BOOT_TIME), `shell` (the display, `process_handles`).
