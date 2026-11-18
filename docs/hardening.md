# Hardening

Every protection below has a test that proves it **fires**. Keep it that way: a new protection
comes with a test that triggers it.

**Code:** `build.ps1` (`$cflags`, `$linkArgs`, `Test-StaticAnalysis`); `kernel/rust/.cargo/config.toml`;
`kernel/linker.ld`; `kernel/arch/x86_64/spec.c` (speculation policy); `kernel/mm/kpti.c`;
`isr.asm`, `syscall.asm`, `switch.asm`, `thunk.asm`; `kernel/rust/src/nospec.rs`, `spec.h`.
KASLR is in [boot.md](boot.md#kaslr).

## C kernel (clang)

| Flag | Effect | Test |
|---|---|---|
| `-fpie` + PIE link | runs at any base (KASLR) | `kaslr`, `kaslr-host` |
| `-fstack-protector-strong` | per-boot random canary, read-only after init | `stackprot` |
| `-ftrivial-auto-var-init=zero` | no stale stack data | by construction |
| `-fzero-call-used-regs=used-gpr` | registers cleared on return | by construction |
| `-fstack-clash-protection` (cc1) | large frames probe page by page | `stackguard`, `threadguard` |
| `-fno-delete-null-pointer-checks` | NULL checks are kept | `nullderef` |
| `-fsanitize=array-bounds` (trap), `-fstrict-flex-arrays=3` | out-of-range index traps | `bounds` |
| `-Wframe-larger-than=4096`, `-Werror` | build fails on big frames and any warning | build |
| UBSan (trap), KASAN (heap) | test builds | `ubsan*`, `kasan*` |

## Rust kernel

`relocation-model=pie`; `panic = "abort"` (a Rust panic is a kernel panic: `rustpanic`);
`overflow-checks = true`; frame pointers; `#![no_std]`, no external crates;
`unsafe_op_in_unsafe_fn = deny` and clippy `undocumented_unsafe_blocks`. Stack protector and CET
for Rust need unstable flags; revisit when they stabilize.

## Link

Static PIE with a packed RELR table; `-z text` (no relocation in code); `.rela.dyn` must be empty
(linker assertion); W^X segments (`wx`, `nx`); `.data.ro_after_init` read-only once the VMM runs
(`roinit`); `--build-id=none` for reproducible bytes.

## CET

Detected and reported, not enabled yet. IBT needs Rust built with `-Zcf-protection`; supervisor
shadow stacks need testing on a CET-capable CPU (QEMU TCG does not implement CET). Untested CET code
would only break boot on the machines that have it.

## Speculative-execution mitigations

The boot CPU's CPUID and `IA32_ARCH_CAPABILITIES` decide the policy; every CPU applies it. The
choice is printed at boot and in the `Summary:` lines.

| Issue | Mitigation | Test |
|---|---|---|
| Meltdown | **KPTI** on affected Intel CPUs: ring 3 runs on page tables that map only the entry code and per-CPU entry data | `spec`, `spec-intel` |
| Spectre v2 | eIBRS / AutoIBRS when available, else **retpolines** (patched to plain jumps at boot when not needed) | `spec`, `spec-intel` |
| RSB underflow | RSB filling on context switch (retpoline mode) | `spec` |
| Cross-process branch poisoning | **IBPB** when another process's thread runs | where the CPU has IBPB |
| MDS / TAA | `VERW` before returning to ring 3 on affected CPUs | `spec`, `spec-intel` |
| Spectre v1 | branch-free index clamping of syscall numbers and handle slots | `spec`, selftest |
| SWAPGS | `lfence` where entry paths join | `user`, `spec` |

Not covered yet: Intel BHI, SSBD, L1TF, SRBDS/GDS. KPTI runs without PCID (only old Intel CPUs need
it). Precompiled Rust `core`/`alloc` are not retpolined (irrelevant on CPUs with eIBRS/AutoIBRS).

## Fuzzing

Every parser of untrusted input has a fuzzer in the suite:

| Input | Fuzzer | Case |
|---|---|---|
| Syscalls | `utest fuzz` (random calls, handles, pointers) | `fuzz`, `kasan-fuzz` |
| IPC | `utest ipcfuzz` (hostile messages, lying port rings; checks no object leaks) | `fuzz`, `kasan-fuzz` |
| ELF | `rust_elf_fuzz` (kernel) | `fuzz` |
| PE | `dcmpl pefuzz` | `compat` |
| ACPI tables, `\_S5` | `rust_acpi_fuzz` (`dev/acpi_fuzz.rs`) | `fuzz`, `kasan-fuzz` |
| GPT, FAT32, DFS | `user/lib/fs/src/fuzz.rs` (host) | `storage-host` |

Host fuzzers take `DOS_FUZZ_SEED` (reproduce) and `DOS_FUZZ_SCALE` (longer campaigns). Kernel
fuzzers are seeded from the clock and name the parser and invariant that broke. They are random
mutation fuzzers without coverage feedback.

## Static analysis (`static` case)

- clang's analyzer (`core`, `unix`, `security`, `deadcode`, `nullability`) over every C translation
  unit, in the release and test configurations.
- clippy `-D warnings` over every Rust crate, including test code.

Both must stay at zero findings.
