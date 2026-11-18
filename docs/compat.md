# D-CMPL: the compatibility layer

D-CMPL runs programs built for other operating systems (Windows first, Linux too) on D-OS without
changing them.

**Code:** `user/dcmpl/` (Rust, ring 3: PE loader, minimal `kernel32`, Linux server, PE fuzzer);
`compat/win/` and `compat/linux/` (the proof programs).

## Approach: reimplement the OS interface, never translate binaries

Foreign programs and their libraries are loaded unchanged and run natively on the CPU. D-CMPL
provides the interface *underneath* them, the one they expect from their own OS, built on D-OS
handles (the WINE/Proton model for Windows, Starnix/WSL1 for Linux). No emulator, no instruction
translation.

## Personalities

| | Windows | Linux |
|---|---|---|
| Stable interface | DLL exports (`ntdll`, `kernel32`, ...) | the syscall interface |
| Executable | PE32+ | ELF64 |
| Where D-CMPL runs | **inside the process**: a PE loader plus D-CMPL's own DLLs | **outside**: a Linux server process; each syscall is forwarded to it |
| Thread-local storage | TEB at GS | TLS at FS |

## Kernel mechanisms it uses

All general-purpose (debuggers and native programs use them too); none weakens the capability
model. See [abi.md](abi.md#exceptions).

1. **Exception channels**: faults go to a supervisor, which resumes (optionally with new
   registers) or kills.
2. **Syscall forwarding** (`DOS_SPAWN_FORWARD`): every syscall of the process becomes a message to
   its supervisor. Fixed at spawn; refused without a supervisor.
3. **In-process exception handlers** (for SEH, C++ exceptions).
4. **Register access** to stopped threads, and per-thread FS/GS bases.
5. **Code creation under W^X**: holders of the VMEX resource can seal a VMO and make it executable.
6. **Fixed-address mappings** for images that prefer a base address.
7. **XSAVE** state per thread.
8. **Start exception** (`DOS_SPAWN_START_EXCEPTION`): the supervisor sets up the initial stack
   before the first instruction.

## Security

- D-CMPL is **not** the security boundary; the kernel is. A foreign program holds only the handles
  it was given. Raw Windows NT syscalls hit the D-OS ABI and fail; Linux programs cannot bypass
  forwarding.
- Foreign programs are sandboxed like native ones: a per-app namespace and the capabilities in
  their manifest.
- The Linux server runs per app, never as one system-wide server.

## What works today

`dcmpl` modes:
- **`win <exe>`**: strict PE32+ parser (bounds- and overflow-checked like the kernel's ELF parser;
  TLS, delay-load and .NET images refused), loads at the preferred base or relocates, binds
  imports, maps sections with code sealed and executable, sets up stack and TEB, calls the entry.
  `kernel32`: `GetStdHandle`, `WriteFile`, `ExitProcess`. Any other import refuses the program,
  naming the DLL and function.
- **`linux <elf> [args]`**: spawns with `FORWARD` + `START_EXCEPTION`, builds argv/envp/auxv, and
  serves `write`, `exit`, `exit_group`, `arch_prctl`, `set_tid_address`, `getpid`, `gettid`. Other
  syscalls return `-ENOSYS` and are logged.
- **`pefuzz <n>`**: the PE parser fuzzer.

Proof programs: `compat/win/w1.c` (built with MSVC, no CRT, against import libraries made from
`.def` files) and `compat/linux/l1.c` (static Linux ELF built with clang). Both are ordinary
binaries for their own OS.

## Roadmap

| Milestone | Needs |
|---|---|
| W1 / L1: hello world, no CRT / static | **done** |
| W2: console program with the static CRT (heap, TLS, SEH, ~80 `kernel32` exports) | user runtime, in-process exceptions |
| L2: static programs with threads, `mmap`, files, signals | user runtime, file service |
| W3 / L3: dynamic CRT / glibc via the program's own `ld-linux.so` | files, library loading |
| W4 / L4: GUI programs | D-AWMI, GPU stack |

## Non-goals

- Kernel-mode anti-cheat or any foreign kernel driver. Remote attestation
  ([attestation.md](attestation.md)) is the intended path for vendors that need integrity proof.
- Instruction-set translation (ARM, 32-bit x86).
- Bit-exact behaviour of undocumented Windows internals.

## Tests

`compat`: the start exception; W1 and L1 run unchanged; an unsupported import and an unsupported
syscall fail cleanly; faults are reported; the PE parser is fuzzed.
