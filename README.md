# The Discrete Operating System (D-OS)

A fast, secure and practical operating system for x86-64, built from scratch: its own bootloaders,
a capability-based hybrid kernel in C and Rust, user-space drivers, and a compatibility layer that
runs Windows and Linux programs unchanged.

## What it is

D-OS is deliberately not UNIX-like. Programs hold **capabilities** (handles with rights that can
only shrink) instead of relying on users, groups and `root`. Drivers run in **user space**,
isolated by the IOMMU and restartable. All code is **signed** and the boot is **verified and
measured**. Where standards cost nothing, D-OS uses them: ELF, UEFI, ACPI, GPT, virtio.

| Component | Role | State |
|---|---|---|
| **D-KRNL** | the kernel | working, hardened, extensively tested |
| **D-CMPL** | compatibility layer for Windows and Linux programs | first programs run |
| **D-AWMI** | window manager and graphics | planned |
| **D-PACK** | signed packages and updates | planned |

## Where it stands

**D-KRNL 1.0.** The kernel is complete (stable SMP, a versioned ABI, every protection proven by a
test, fuzzers and sanitizers clean). It boots in QEMU and on real PCs (BIOS and UEFI) to user space. There is no
shell or GUI yet.

- Own BIOS and UEFI loaders with verified boot (Ed25519) and KASLR; one GPT image for both
- SMP kernel (x2APIC), W^X everywhere, SMEP/SMAP/UMIP, KPTI, retpolines and other speculation
  mitigations chosen per CPU
- Capability objects, quotas, ring-3 processes, IPC (channels, shared-memory rings, fast
  call/reply, zero-copy memory), a versioned ABI
- User-space drivers: PCI/PCIe, MSI-X, Intel VT-d and AMD-Vi IOMMUs, virtio, AHCI, NVMe, PS/2,
  USB keyboards (xHCI)
- Storage: GPT, FAT32, and DFS (copy-on-write B+tree with BLAKE3 checksums and snapshots); files
  are handles; per-app namespaces; disks are read-only by default
- A service manager: each service gets exactly the capabilities its signed manifest lists, and is
  restarted with backoff when it fails; core services for a structured system log, wall-clock time
  and keyboard input
- Measured boot with TPM 2.0, code signing for programs, remote attestation
- An MSVC-built Windows program and a static Linux program run unchanged
- 79 automated test cases: protections firing, fuzzers, sanitizers, static analysis, multi-core
  stress, reproducible builds

## Quick start

Windows x64 with LLVM, NASM, Rust (rustup), QEMU and the Visual Studio C++ tools
([full setup](docs/building.md)):

```powershell
.\build.ps1 run      # build and boot in QEMU
.\build.ps1 test     # run the full test suite
```

To try it on real hardware, see [docs/hardware.md](docs/hardware.md). D-OS never writes your
disks.

## Documentation

[`docs/`](docs/README.md) has a page per subsystem. Start with
[architecture](docs/architecture.md) and [building](docs/building.md).

## Contributing

Contributions are welcome, and the bar is deliberate. A pull request must:

- **make a real, positive difference**: a feature, a fix, a measurable speed-up, better hardware
  support, stronger security;
- **prove it works**: the full `.\build.ps1 test` suite passing on your machine, with the generated
  `build\test-report.md` attached, plus a test that covers the change.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening one. Merged changes are announced in the
`#changelog` channel of the [community Discord](https://discord.gg/discrete).

## Community

- Discord: [discord.gg/discrete](https://discord.gg/discrete)
- Bugs and proposals: GitHub issues
- Security vulnerabilities: privately, see [SECURITY.md](.github/SECURITY.md)

## License

D-OS is free software: you can redistribute it and/or modify it under the terms of the
GNU General Public License as published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version (`GPL-3.0-or-later`). See [LICENSE](LICENSE).

## Disclaimer

Claude has been, and will continue to be, used during D-OS development for repetitive boilerplate and 
the odd rigorous task that would otherwise take much longer.
Please read the channel in the community [Discord](https://discord.gg/discrete) about the Discrete Philosophy.