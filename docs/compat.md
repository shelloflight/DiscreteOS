# D-CMPL: the compatibility layer

D-CMPL runs programs built for other operating systems (Windows first, Linux too) on D-OS without
changing them.

**Code:** `user/dcmpl/` (Rust on [libd](libd.md): `win/` the multi-module PE/DLL loader, `kernel32`/`kernelbase`/`ntdll`/`ucrtbase`/`vcruntime` and multi-module SEH/C++ FH4, `linux/` the user-space ELF64 dynamic loader, syscall server, VMA-tracked `mprotect` and synthetic `/proc`/`/dev` views, `path.rs` namespace and per-app prefix resolution, `out.rs` console output, the PE parser and its fuzzer); `compat/win/` and `compat/linux/` (the test programs).

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

In the shell, `run [--prefix <dir>] <file> [arguments]` reads the file, tells the personality from
its header (`MZ` is Windows, `\x7FELF` is Linux; anything else is refused) and starts D-CMPL with:

- the image (a VMO) and the arguments;
- **the current place** as the working directory, with the session's rights there;
- an optional **per-app namespace prefix** (`--prefix <dir>`, with the session's rights there; `/`
  is refused), isolating the program's Windows drive root (`<prefix>/drive_c` or `<prefix>`) or
  Linux root (`/lib64`, `/usr`, app data) inside an explicit directory;
- the executable's parent directory read-only (`--app-dir`), so sibling `.dll` / `.so` files load
  without widening write authority;
- an output channel (standard output and error, shown like a tool's text), the log, the wall clock;
- the VMEX resource, used only to make the program's code executable (sealed, never writable).

Nothing else of the session: no other volume, no endpoint, no service manager. The shell's manifest
grants D-CMPL's image and VMEX for this (`programs = ["dcmpl.dx"]`, `vmex = true`).

Directly: `dcmpl [--prefix <dir>] [--app-dir <dir>] win <exe> [args]` or
`dcmpl [--prefix <dir>] [--app-dir <dir>] linux <elf> [args]` with an embedded program.

## Windows (W3: dynamic CRT `/MD` and PE DLLs)

The PE loader is strict (bounds- and overflow-checked like the kernel's ELF parser; delay-load and
.NET images refused). It loads the main executable and any imported or dynamically loaded PE32+
DLLs (`FILE_DLL`), relocating as needed, mapping each section from its own VMO (code sealed and
executable), binding imports by name or ordinal, resolving forwarded exports, initializing per-DLL
static TLS slots, running TLS callbacks and `DllMain` (`DLL_PROCESS_ATTACH` / `DLL_THREAD_ATTACH` /
`DLL_THREAD_DETACH` / `DLL_PROCESS_DETACH`), and running the entry point on a stack of the image's
`SizeOfStackReserve`.

- **DLL search order**: already-loaded module -> built-in shim -> explicit path -> executable
  directory (`--app-dir`) -> embedded program VMOs -> prefix (`<prefix>/drive_c/windows/system32`,
  `<prefix>/system32`, `<prefix>`) -> current directory -> `PATH`.
- **Built-in shims**:
  - `kernel32.dll`, `kernelbase.dll`, `ntdll.dll`: heap (libd's allocator), critical sections, SRW
    locks, `InitOnceExecuteOnce`, threads (libd threads, each with its own TEB, multi-module TLS
    array, FLS data and callbacks), TLS/FLS slots, events, waits, `LoadLibrary(A/W/ExA/ExW)`,
    `FreeLibrary`, `GetProcAddress` (name, ordinal, forwarders), `GetModuleHandle(A/W/ExA/ExW)`,
    `GetModuleFileName(A/W)`, command line, environment, files and directories through the
    namespace, the console, code pages (UTF-8 is the ANSI code page), time, `VirtualAlloc` /
    `VirtualProtect`.
  - `ucrtbase.dll`, `vcruntime140.dll`, `vcruntime140_1.dll` (and Windows API-set redirects
    `api-ms-win-crt-*` -> `ucrtbase.dll`, `api-ms-win-core-*` / `api-ms-win-security-*` ->
    `kernelbase.dll`): dynamic MSVC `/MD` C/C++ runtime including `_initterm`/`_initterm_e`,
    `_onexit` tables & `atexit`, `_beginthreadex`/`_endthreadex`, `FILE*` streams & formatted I/O
    (`__stdio_common_v{f,s,sn}printf[_s]`), narrow argv/env, memory/string/ctype/time/locale
    helpers, `__C_specific_handler`, `_CxxThrowException`, and MSVC FH4 `__CxxFrameHandler4`.
  - An unresolved DLL or export refuses the load, naming the DLL and function.
- **Paths**: `\` is `/`; when a prefix is granted, drive-letter and rooted paths (`C:\foo`, `\foo`)
  resolve inside `<prefix>/drive_c` (if present) or `<prefix>` unless they explicitly name another
  granted mount; relative paths start at the working directory; escaping the granted namespace
  returns `ERROR_ACCESS_DENIED`.
- **Multi-module SEH & C++ FH4**: each thread has an in-process exception handler
  (`thread_set_exception_handler`, its own stack). A fault, `RaiseException`, or
  `_CxxThrowException` resolves the owning module's `.pdata` across the executable and every loaded
  DLL, walks unwind codes (prologues, epilogues, chained entries, machine frames), invokes language
  handlers (`__try/__except`, `__finally`, C++ `try/catch` with destructors and FH4 RTTI matching),
  and resumes via `RtlUnwindEx` and `STATUS_UNWIND_CONSOLIDATE`. Every read of unwind data is
  checked against the owning module and every stack read against the thread's stack.
- **Unhandled**: the program's own top-level filter runs first; then D-CMPL logs the exception and
  lets the fault happen again without a handler, so the kernel reports it and ends the process
  like a native one. `__fastfail` ends it at once (`STATUS_STACK_BUFFER_OVERRUN`).
- **W^X**: `VirtualProtect` remaps a mapping's own VMO: data can be made read-only and back, code
  can never become writable and data never executable. `VirtualAlloc` gives read/write memory only.

Not provided yet: console input, named objects shared between processes, rethrowing from a C++
catch block that was entered from a hardware fault, vectored handlers, GUI (`user32`/`gdi32`).

## Linux (L3: dynamic ELF64 with `ld-linux.so`, `/proc`, `/dev`)

The program runs in its own process, spawned with `FORWARD` (every syscall is a message to the
server) and `START_EXCEPTION` (the server maps the image and sets up `argc`/`argv`/`envp`/`auxv`
before the first instruction). Both static (`ET_EXEC`/`ET_DYN`) and dynamically linked ELF64
binaries with `PT_INTERP` are loaded entirely in user space by D-CMPL (using a tiny static
bootstrap stub so the kernel's native ELF loader stays strict and untouched). When `PT_INTERP` is
present, D-CMPL loads the interpreter (such as `/lib64/ld-linux-x86-64.so.2`) from the granted
prefix, `--app-dir`, or embedded VMOs, populates `AT_PHDR`/`AT_PHENT`/`AT_PHNUM`/`AT_BASE`/
`AT_ENTRY`, and starts execution at the interpreter's entry point. The server is one loop over the
exception channel; a syscall is answered at once, or **parked** (the thread stays stopped) while it
waits, with a deadline.

| Area | Served |
|---|---|
| Files | `open(at)`, `read`, `write`, `pread`/`pwrite`, `readv`/`writev`, `lseek`, `close`, `(f)stat`, `newfstatat`, `statx`, `readlink(at)`, `getdents64`, `dup`/`dup2`/`dup3`, `fcntl`, `access`, `getcwd`, `chdir`, `mkdir(at)`, `unlink(at)`, `rmdir`, `rename(at/2)`, `(f)truncate`, `fsync`, `(f)statfs`, `pipe`/`pipe2` (in-process pipes), `poll`/`ppoll`; through the namespace and optional `--prefix` (`ioctl` is `ENOTTY`, so `isatty` is false) |
| Synthetic `/proc` & `/dev` | Capability-scoped `/proc/self/{exe,cmdline,environ,auxv,maps,status,stat,comm,fd,fd/<n>}`, `/proc/<pid>/*`, `/proc/{cpuinfo,meminfo,version,stat}` (other PIDs return `-ENOENT`); `/dev/{null,zero,urandom,random,full,stdin,stdout,stderr,fd}` (hardware device nodes return `-ENOENT`) |
| Memory | `mmap` (anonymous, `PROT_NONE` reservations, private file copies; executable only from a file, sealed with VMEX; `PROT_WRITE\|PROT_EXEC` refused), `munmap`, `brk`, VMA-tracked hardware-enforced `mprotect` (remaps VMOs in-place for `PT_GNU_RELRO` RW->RO while enforcing W^X), `madvise`, `membarrier` |
| Threads | `clone` with `CLONE_VM\|CLONE_THREAD` (a thread created stopped, `thread_create_stopped`, started with the parent's registers, its stack and TLS), `set_tid_address`, child-tid clear and wake at exit, `exit` (that thread only, `EXIT_THREAD`), `exit_group`, `futex` (wait, wake, bitsets, requeue; timeouts), `sched_yield` |
| Signals | `rt_sigaction`, `rt_sigprocmask`, `sigaltstack`, `rt_sigreturn`, `kill`, `tkill`, `tgkill`; faults become SIGSEGV/SIGBUS/SIGFPE/SIGILL/SIGTRAP for a handler (the x86-64 `rt_sigframe`), default actions end the program |
| Time, ids, info | `clock_gettime`, `clock_getres`, `gettimeofday`, `time`, `nanosleep`, `clock_nanosleep`, `getpid`, `gettid`, `getuid` and friends (1000), `getrandom`, `getrlimit`/`prlimit64`, `sched_getaffinity`, `uname`, `prctl`, `sysinfo`, `getrusage` |

Everything else (`fork`, `execve`, `ptrace`, sockets, ...) is answered `-ENOSYS` and logged.
Limits: `mprotect` enforces W^X and refuses `PROT_EXEC` on anonymous/writable memory; a signal for
another thread interrupts its wait or is delivered at its next syscall; signal frames carry no FPU
state; shared file mappings are private copies.

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

| Milestone | Status |
|---|---|
| W1 / L1: hello world, no runtime / static | **done** |
| W2: console programs with the static CRT (heap, threads, TLS, SEH, C++ exceptions, files) | **done** |
| L2: static programs with threads, `mmap`, files, signals, `futex` | **done** |
| W3 / L3: dynamic CRT (`/MD`, PE DLL loader) & dynamic Linux (`ld-linux.so`, `/proc`, `/dev`, `--prefix`) | **done** |
| W4 / L4: GUI programs (`user32`/`gdi32`, Wayland, Vulkan/DXVK/Zink) | needs D-AWMI + GPU stack |

## Non-goals

- Kernel-mode anti-cheat or any foreign kernel driver. Remote attestation
  ([attestation.md](attestation.md)) is the intended path for vendors that need integrity proof.
- Instruction-set translation (ARM, 32-bit x86).
- Bit-exact behaviour of undocumented Windows internals.

## Tests

- `compat`: the start exception, `process_vmar`, `thread_create_stopped`; W1 and L1 (no runtime,
  `ptrace -> ENOSYS`); W2 (`compat/win/w2.c` + `w2cxx.cpp`, MSVC `/MT`): heap, 4 threads under a
  critical section, `__declspec(thread)`, TLS and FLS slots with callbacks, command line,
  environment, SEH (access violation, `RaiseException`, divide by zero, `__finally`), C++
  exceptions, time; an unhandled fault ends it like a native one; W3 (`compat/win/w3.c` +
  `w3cxx.cpp` + `w3lib.c`, MSVC `/MD /EHsc` + `/MD /LD` DLL): static & dynamic (`LoadLibraryA`)
  DLL loading, `DllMain` attach/detach, name/ordinal/forwarded exports, per-DLL TLS across 4
  threads, `/MD` CRT, cross-DLL SEH, `/MD` C++ FH4 exceptions; L2 (`compat/linux/l2.c`, clang
  static): mmap/brk, 4 `clone` threads with TLS and a futex lock, futex timeouts, a SIGSEGV
  handler that resumes, a blocked SIGUSR1 delivered when unblocked, time, `fork` refused; L3
  (`compat/linux/l3.c` + `libl3.c` + `ld_dos.c`, clang `-fPIE`/`-shared` with `PT_INTERP`):
  user-space dynamic linker (`ld-linux-x86-64.so.2`), `DT_NEEDED` shared library with
  `DT_INIT_ARRAY` & `PT_GNU_RELRO` (verified read-only via `SIGSEGV`), `PT_TLS`, synthetic `/proc`
  and `/dev` (with cross-PID and hardware node isolation), `uname`/`pipe2`/`poll`/`statx`/`prctl`;
  unsupported imports and syscalls fail cleanly; the PE parser and export table parser are fuzzed
  across executables and DLLs.
- `shell`: `run` of W2 and L2 from the boot volume in `/data` (write, read back, list, rename,
  delete), plus `run --prefix <dir>` of W3 (`/MD` + sibling `W3LIB.DLL`) and L3 (loading
  `ld-linux-x86-64.so.2` and `libl3.so` from `<prefix>/lib64` and verifying prefix-scoped file I/O
  and escape refusal); a file that is not a program is refused.
