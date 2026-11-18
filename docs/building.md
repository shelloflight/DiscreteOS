# Building and testing

Everything goes through one script, `build.ps1`, on Windows x64.

## Toolchain

| Tool | Used for | Notes |
|---|---|---|
| PowerShell 7+ | `build.ps1` | 5.1 works, but 7 builds test variants in parallel |
| LLVM (clang, ld.lld, lld-link, llvm-objcopy, llvm-nm, llvm-readobj) | C kernel, loaders, user programs | found on `PATH` or in `C:\Program Files\LLVM\bin` |
| NASM | boot stages, entry stubs | on `PATH` |
| Rust via rustup | kernel Rust, user crates, `dosimg` | the exact version is pinned in `rust-toolchain.toml` and installed on demand |
| QEMU (with its edk2/OVMF firmware) | running and testing | `C:\Program Files\qemu` or `PATH`; `DOS_OVMF_DIR` overrides the firmware folder |
| Visual Studio or Build Tools, C++ x64 workload | the Windows compatibility proof program (`compat/win`) | found with `vswhere`; `DOS_MSVC_BIN` overrides |
| MinGW gcc (optional) | host check of the loaders' C crypto | skipped with a note if missing |
| 7-Zip (optional) | host check that a FAT32 volume written by D-OS reads correctly | skipped if missing |

Most of these install with `winget`: `LLVM.LLVM`, `NASM.NASM`, `SoftwareFreedomConservancy.QEMU`,
`Rustlang.Rustup`, `7zip.7zip`.

The first build creates a development signing key in `build\keys\` (never committed). Every
checkout trusts only its own key; `DOS_SIGNING_KEY` points at another key file.

## Commands

```powershell
.\build.ps1                 # build build\discrete.img (BIOS + UEFI, 64 MiB GPT image)
.\build.ps1 run             # build and boot in QEMU, serial on this console (-Uefi for UEFI, -Smp N)
.\build.ps1 debug           # boot paused with a GDB stub on localhost:1234
.\build.ps1 test            # the full test suite (see below)
.\build.ps1 test -Case boot,uefi   # selected cases only
.\build.ps1 soak -Minutes 60       # long randomized multi-core stress run
.\build.ps1 bench           # build\discrete-bench.img for real hardware (benchmarks.md)
.\build.ps1 clean
```

Outputs: `build\discrete.img`, `build\kernel.elf` (with symbols, for GDB), `build\kernel.map`,
`build\SHA256SUMS`, and per-case serial logs under `build\ktest\`.

### Kernel debugger

`kdb` runs on the serial port of every release boot. With `.\build.ps1 run`, type into the
console: `help`, `threads`, `cpus`, `objects`, `measure`, `mem`, `prof [ms]`, `lat`, `poweroff`,
`reboot`.

## The test suite

`.\build.ps1 test` runs every case and ends with `TEST PASSED (N cases)` or `TEST FAILED`.
It:

1. rebuilds the release image in a second directory and requires identical bytes (`repro`;
   skip with `-NoRepro`);
2. builds the kernel test variants (each case can select one with `-DKTEST_<NAME>`, UBSan or
   KASAN);
3. boots each case in QEMU and checks the serial log: required lines must appear, forbidden
   lines (`KERNEL PANIC`, `FAIL`, ...) must not;
4. runs the host cases: `cargo test` for `dosfs` and `doscrypt`, the loaders' KASLR code, and
   static analysis (clang analyzer over all C, clippy `-D warnings` over all Rust);
5. writes **`build\test-report.md`**: result per case, commit, tool versions. Attach it to your
   pull request.

The case list with a one-line description of each is at the top of `build.ps1`.
Main groups:

| Group | Cases |
|---|---|
| Boot | `boot`, `boot-amd`, `uefi`, `uefi-uniproc`, `uniproc`, `bios-badsig`, `uefi-badsig`, `manydevices` |
| Protections fire | `stackprot`, `nx`, `wx`, `nullderef`, `stackguard`, `heapguard`, `doublefree`, `uaf`, `bounds`, `roinit`, `smap`, `smep`, `spec`, `kaslr`, ... |
| Kernel | `selftest`, `sched`, `smp`, `smp-xapic`, `objects`, `lockup`, `softlockup`, `soak`, `bench` |
| Sanitizers | `ubsan`, `ubsan-smp`, `ubsantrap`, `kasan`, `kasan-user`, `kasan-fuzz`, `kasanoob`, `kasanuaf` |
| User space | `user`, `libd`, `fuzz`, `compat`, `drivers`, `drivers-amd`, `keyboard`, `usbkbd`, `storage`, `readonly`, `attest`, `poweroff`, `reboot` |
| Host | `storage-host`, `crypto-host`, `kaslr-host`, `static` |

## Adding a test

**A kernel test.** Add a case to `$TestCases` in `build.ps1`:

```powershell
mycase = @{ Define = 'MYCASE'; Expect = @('KTEST mycase: PASSED'); Forbid = @('KERNEL PANIC', 'FAIL'); Timeout = 30 }
```

then add `#elif defined(KTEST_MYCASE)` with a `ktest_run()` in `kernel/ktest.c` (or a Rust test
reached from `kernel/rust/src/ktest.rs`) that prints the expected line. Other keys: `Smp`, `Cpu`
(QEMU CPU model), `Uefi`, `Devices`, `Ubsan`, `Kasan`, `Keys`/`Serial` (typed input),
`MustExit` (QEMU must end, e.g. power-off). They are documented above `$TestCases`.

**A user-space test.** Most ring-3 tests live in `user/utest` (C), `user/fstest` or `user/ltest` (Rust) and
run inside an existing case (`user`, `libd`, `storage`, `compat`). Add a function there, print a clear
`FAIL: ...` line on failure, and it is covered.

**A host test.** Libraries that do not need the kernel (`user/lib/fs`, `user/lib/crypto`) use
ordinary `cargo test`. Parsers of untrusted data also get a fuzzer (`user/lib/fs/src/fuzz.rs`).

A good test fails without your change and passes with it. A protection test must prove the
protection *fires* (the fault, refusal or panic happens), not only that nothing breaks.
