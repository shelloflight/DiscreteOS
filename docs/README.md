# D-OS documentation

Start with **architecture** and **building**, then read the page for the part of the system you
want to work on. Each page lists its source files, the rules that code must keep, and the tests
that cover it.

| Page | Covers |
|---|---|
| [architecture.md](architecture.md) | How the system fits together, the source tree, design rules, where new code goes |
| [building.md](building.md) | Toolchain, build/run/debug, the test suite, adding a test |
| [boot.md](boot.md) | BIOS and UEFI loaders, disk image, BootInfo, KASLR |
| [objects.md](objects.md) | Kernel objects, handles, rights, quotas, lifetimes |
| [abi.md](abi.md) | The user/kernel ABI: syscalls, status codes, startup block, ELF rules |
| [libd.md](libd.md) | The user runtime: heap, threads, locks, owned handles, channels; its C binding |
| [services.md](services.md) | init, the service manager: manifests, exact grants, supervision, shutdown |
| [shell.md](shell.md) | The terminal, the shell (typed records, places, jobs) and the tools with declared rights |
| [storage.md](storage.md) | Block drivers, `storaged`, files as handles, DFS and FAT32 |
| [compat.md](compat.md) | D-CMPL: running Windows and Linux programs unchanged |
| [signing.md](signing.md) | Verified boot, measured boot, code signing, `.dsig` format |
| [attestation.md](attestation.md) | Remote attestation reports |
| [hardening.md](hardening.md) | Compiler/linker hardening, speculation mitigations, fuzzing, static analysis |
| [power.md](power.md) | ACPI power-off and reset |
| [hardware.md](hardware.md) | Booting D-OS safely on a real PC |
| [benchmarks.md](benchmarks.md) | The hardware benchmark image and how to compare results |
