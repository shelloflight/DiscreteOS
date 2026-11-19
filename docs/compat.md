# D-CMPL: the compatibility layer

D-CMPL runs programs built for other operating systems (Windows first, Linux too) on D-OS without
changing them.

**Code:** `user/dcmpl/` (Rust on [libd](libd.md): `win/` the PE loader, `kernel32` and SEH,
`linux/` the Linux server, `path.rs` paths through the namespace, `out.rs` console output, the PE
parser and its fuzzer); `compat/win/` and `compat/linux/` (the test programs).

## Approach: reimplement the OS interface, never translate binaries

Foreign programs and their libraries are loaded unchanged and run natively on the CPU. D-CMPL
provides the interface *underneath* them, the one they expect from their own OS, built on D-OS
handles (the WINE/Proton model for Windows, Starnix/WSL1 for Linux). No emulator, no instruction
translation.

## Personalities

| | Windows | Linux |
|---|---|---|
| Stable interface | DLL exports (`kernel32`, ...) | the syscall interface |
| Executable | PE32+ | ELF64 |
| Where D-CMPL runs | **inside the process**: a PE loader plus D-CMPL's `kernel32` | **outside**: a Linux server process; each syscall is forwarded to it |
| Thread-local storage | TEB at GS (FS stays libd's) | TLS at FS (the program's own) |

## Running a program

In the shell, `run <file> [arguments]` reads the file, tells the personality from its header (`MZ`
is Windows, `\x7FELF` is Linux; anything else is refused) and starts D-CMPL with:

- the image (a VMO) and the arguments;
- **the current place** as the working directory, with the session's rights there, and no other
  place;
- an output channel (standard output and error, shown like a tool's text), the log, the wall clock;
- the VMEX resource, used only to make the program's code executable (sealed, never writable).

Nothing else of the session: no other volume, no endpoint, no service manager. The shell's manifest
grants D-CMPL's image and VMEX for this (`programs = ["dcmpl.dx"]`, `vmex = true`).

Directly: `dcmpl win <exe> [args]` or `dcmpl linux <elf> [args]` with an embedded program.

## Windows (W2: console programs with the static C runtime)

The PE loader is strict (bounds- and overflow-checked like the kernel's ELF parser; delay-load and
.NET images refused). It loads at the preferred base or relocates, binds imports to `kernel32`,
maps each section from its own VMO (code sealed and executable), reads the TLS directory and calls
the TLS callbacks, and runs the entry point on a stack of the image's SizeOfStackReserve.

- **kernel32**: 146 functions, everything MSVC's `/MT` runtime imports and the common rest: heap
  (libd's allocator), critical sections, threads (libd threads, each with its own TEB, TLS block,
  FLS data and callbacks), TLS/FLS slots, events, waits, command line, environment, files and
  directories through the namespace, the console, code pages (UTF-8 is the ANSI code page), time,
  VirtualAlloc/VirtualProtect. An import D-CMPL does not provide refuses the program at load,
  naming the DLL and function.
- **Paths**: `\` is `/`, a drive letter is dropped (`C:\data\a.txt` is `/data/a.txt`), relative
  paths start at the working directory; outside the namespace is `ERROR_ACCESS_DENIED`.
- **SEH**: each thread has an in-process exception handler (`thread_set_exception_handler`, its
  own stack). A fault or `RaiseException` is dispatched like Windows does it: the image's
  function table (`.pdata`) and unwind codes are walked (prologues, epilogues, chained entries,
  machine frames), language handlers run (`__try/__except`, `__finally`, C++ `try/catch` with
  destructors); the second pass (`RtlUnwindEx`) runs termination handlers and resumes at the
  target, through `STATUS_UNWIND_CONSOLIDATE` for C++ catch blocks. Every read of unwind data is
  checked against the image and every stack read against the thread's stack.
- **Unhandled**: the program's own top-level filter runs first; then D-CMPL logs the exception and
  lets the fault happen again without a handler, so the kernel reports it and ends the process
  like a native one. `__fastfail` ends it at once (`STATUS_STACK_BUFFER_OVERRUN`).
- **W^X**: VirtualProtect remaps a mapping's own VMO: data can be made read-only and back, code can
  never become writable and data never executable. VirtualAlloc gives read/write memory only.

Not provided yet: other DLLs (`LoadLibrary` fails, `GetProcAddress` finds nothing), the dynamic
runtime (`/MD`, W3), console input, named objects shared between processes, rethrowing from a C++
catch block that was entered from a hardware fault, vectored handlers.

## Linux (L2: static programs with threads)

The program runs in its own process, spawned with `FORWARD` (every syscall is a message to the
server) and `START_EXCEPTION` (the server builds argc/argv/envp/auxv before the first
instruction). The server is one loop over the exception channel; a syscall is answered at once,
or **parked** (the thread stays stopped) while it waits, with a deadline.

| Area | Served |
|---|---|
| Files | `open(at)`, `read`, `write`, `pread`/`pwrite`, `readv`/`writev`, `lseek`, `close`, `(f)stat`, `newfstatat`, `getdents64`, `dup`/`dup2`/`dup3`, `fcntl`, `access`, `getcwd`, `chdir`, `mkdir(at)`, `unlink(at)`, `rmdir`, `rename(at/2)`, `(f)truncate`, `fsync`; through the namespace (no symbolic links, pipes or devices; `ioctl` is `ENOTTY`, so `isatty` is false) |
| Memory | `mmap` (anonymous; private file copies; executable only from a file, sealed with VMEX; `PROT_WRITE|PROT_EXEC` refused), `munmap`, `brk`, `mprotect` (see below), `madvise` |
| Threads | `clone` with `CLONE_VM|CLONE_THREAD` (a thread created stopped, `thread_create_stopped`, started with the parent's registers, its stack and TLS), `set_tid_address`, child-tid clear and wake at exit, `exit` (that thread only, `EXIT_THREAD`), `exit_group`, `futex` (wait, wake, bitsets, requeue; timeouts), `sched_yield` |
| Signals | `rt_sigaction`, `rt_sigprocmask`, `sigaltstack`, `rt_sigreturn`, `kill`, `tkill`, `tgkill`; faults become SIGSEGV/SIGBUS/SIGFPE/SIGILL/SIGTRAP for a handler (the x86-64 `rt_sigframe`), default actions end the program |
| Time, ids | `clock_gettime`, `clock_getres`, `gettimeofday`, `time`, `nanosleep`, `clock_nanosleep`, `getpid`, `gettid`, `getuid` and friends (1000), `getrandom`, `getrlimit`/`prlimit64`, `sched_getaffinity` |

Everything else (`fork`, `execve`, sockets, pipes, `poll`, `uname`, ...) is answered `-ENOSYS` and
logged. Limits: `mprotect` can only make a `PROT_NONE` reservation usable (or unusable again);
elsewhere it accepts requests without `PROT_EXEC` without enforcing them (the ABI cannot change a
mapping's permissions) and refuses `PROT_EXEC`. A signal for another thread interrupts its wait or
is delivered at its next syscall. Signal frames carry no FPU state. Shared file mappings are
private copies.

## Kernel mechanisms it uses

All general-purpose (debuggers and native programs use them too); none weakens the capability
model. See [abi.md](abi.md#exceptions).

1. **Exception channels**: faults go to a supervisor, which resumes (optionally with new
   registers), kills the process, or ends only that thread (`EXIT_THREAD`).
2. **Syscall forwarding** (`DOS_SPAWN_FORWARD`): every syscall of the process becomes a message to
   its supervisor. Fixed at spawn; refused without a supervisor.
3. **In-process exception handlers** (SEH, C++ exceptions).
4. **Register access** to stopped threads, and per-thread FS/GS bases.
5. **Code creation under W^X**: holders of the VMEX resource can seal a VMO and make it executable.
6. **Fixed-address mappings** for images that prefer a base address.
7. **XSAVE** state per thread.
8. **Start exception** (`DOS_SPAWN_START_EXCEPTION`, and `thread_create_stopped` for new threads):
   the supervisor sets up memory and registers before the first instruction.
9. **`process_vmar`**: the supervisor maps memory into the program (Linux `mmap`, `brk`).

## Security

- D-CMPL is **not** the security boundary; the kernel is. A foreign program holds only the handles
  it was given. Raw Windows NT syscalls hit the D-OS ABI and fail; Linux programs cannot bypass
  forwarding.
- Foreign programs are sandboxed like native ones: `run` gives one directory and an output channel.
- A program read from a file is unsigned code: D-CMPL makes it executable with VMEX (Windows) or
  allows it with `vmo_allow_unsigned` (Linux); both decisions are measured into PCR 10.
- The Linux server runs per program, never as one system-wide server.
- No CET shadow stacks yet: `dcmpl` is built without them (Windows exception handling resumes a
  context by rewriting a return address), and FORWARD processes never get one. CET-aware unwinding
  (Windows `CETCOMPAT` images, glibc's `arch_prctl` shadow-stack calls) would lift this.

## Roadmap

| Milestone | Needs |
|---|---|
| W1 / L1: hello world, no runtime / static | **done** |
| W2: console programs with the static CRT (heap, threads, TLS, SEH, C++ exceptions, files) | **done** |
| L2: static programs with threads, `mmap`, files, signals, `futex` | **done** |
| W3 / L3: dynamic CRT / glibc via the program's own `ld-linux.so` | library loading, `/proc` and `/dev` views |
| W4 / L4: GUI programs | D-AWMI, GPU stack |

## Non-goals

- Kernel-mode anti-cheat or any foreign kernel driver. Remote attestation
  ([attestation.md](attestation.md)) is the intended path for vendors that need integrity proof.
- Instruction-set translation (ARM, 32-bit x86).
- Bit-exact behaviour of undocumented Windows internals.

## Tests

- `compat`: the start exception, `process_vmar`, `thread_create_stopped`; W1 and L1 (no runtime);
  W2 (`compat/win/w2.c` + `w2cxx.cpp`, MSVC `/MT`): heap, 4 threads under a critical section,
  `__declspec(thread)`, TLS and FLS slots with callbacks, command line, environment, SEH (access
  violation, `RaiseException`, divide by zero, `__finally`), C++ exceptions, time; an unhandled
  fault ends it like a native one; L2 (`compat/linux/l2.c`, clang static): mmap/brk, 4 `clone`
  threads with TLS and a futex lock, futex timeouts, a SIGSEGV handler that resumes, a blocked
  SIGUSR1 delivered when unblocked, time, `fork` refused; unsupported imports and syscalls fail
  cleanly; the PE parser is fuzzed.
- `shell`: `run` of W2 and L2 from the boot volume in `/data`: both write, read back, list, rename
  and delete files in the place they were given; a file that is not a program is refused.
