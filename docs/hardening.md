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

**Supervisor shadow stacks** (`kernel/arch/x86_64/cet.c`) are on when the CPU has them: every kernel
thread has an 8 KiB shadow stack beside its kernel stack (a guard page between), every CPU one per
IST stack. CALL stores each return address there as well; a RET that finds a different one on the
normal stack raises #CP, a kernel panic. A stack buffer overflow can no longer redirect a return.

- Switched with the thread (`context_switch`: RSTORSSP / SAVEPREVSSP). An entry from ring 3 lands on
  the user thread's shadow stack (IA32_PL0_SSP, written when a user thread is switched in) and marks
  its token busy; SYSCALL does not switch, so its entry does (SETSSBSY). IRETQ back to ring 3 clears
  the token; SYSRET does not, so that path clears it (CLRSSBSY).
- Kernel code never rewrites a return address: the user-copy fault fixup resumes the copy with
  nothing left to copy instead of jumping elsewhere, so the kernel never needs to write its own
  shadow stacks (WRSS stays off).
- Off, and said so at boot, when KPTI is on (entries run on per-CPU stacks) or when Spectre v2 needs
  retpolines (their thunk rewrites its return address). CPUs with CET have eIBRS or AutoIBRS and
  need neither.
- Tests: QEMU's TCG has no CET, so `cet` and `cet-cp` run in Bochs (Tiger Lake model, one CPU): the
  release image boots to the shell with shadow stacks on, and an overwritten return address ends in
  #CP. Skipped when Bochs is not installed.

Not yet: user-mode shadow stacks (ring 3) and kernel IBT (needs Rust's `-Zcf-protection`, unstable).

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
