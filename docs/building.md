# Building and testing

Everything goes through one cross-platform Rust host tool, **`dbuild`** (`tools/dbuild`), using thin
bootstrap wrappers on Windows (`.\dbuild.ps1`) and Linux (`./dbuild.sh`).

## Toolchain

| Tool | Used for | Notes |
|---|---|---|
| Rust via rustup | `dbuild`, kernel Rust, user workspace | exact version pinned in `rust-toolchain.toml` and installed on demand (`x86_64-unknown-none`) |
| LLVM (`clang`, `ld.lld`, `lld-link`, `llvm-objcopy`, `llvm-nm`, `llvm-readobj`, `llvm-dlltool`) | C kernel, loaders, user programs, Linux/Windows compat | on `PATH` (or `C:\Program Files\LLVM\bin` on Windows) |
| NASM | boot stages, entry stubs | on `PATH` |
| QEMU (with edk2/OVMF firmware) | running and testing | on `PATH` (or `C:\Program Files\qemu` on Windows); `DOS_OVMF_DIR` overrides the firmware folder |
| Visual Studio / Build Tools C++ x64 + Windows 10/11 SDK *(Windows; optional on Linux)* | D-CMPL W2 (MSVC static CRT test) and MSVC W1 | auto-detected on Windows (`vswhere` + `Windows Kits\10`); `DOS_MSVC_BIN` / `DOS_WINSDK` override. Without them (e.g. Linux), W1 builds with Clang + `lld-link` + `llvm-dlltool` and W2 is skipped cleanly |
| Host C compiler (`gcc` / `cc` / `clang`, optional) | host checks of the loaders' C crypto and KASLR | system `cc`/`gcc` on Linux; MinGW `gcc` on Windows |
| 7-Zip (`7z`, optional) | host check that a FAT32 volume written by D-OS reads cleanly | skipped if missing |
| Bochs (optional) | CET shadow-stack and strict-MSR test cases | skipped if missing |

- **Windows (`winget`):** `LLVM.LLVM`, `NASM.NASM`, `SoftwareFreedomConservancy.QEMU`, `Rustlang.Rustup`, `7zip.7zip`, `Bochs.Bochs`, plus Visual Studio Build Tools (Desktop C++ workload + Windows SDK).
- **Linux (Debian/Ubuntu example):** `clang lld llvm nasm qemu-system-x86 ovmf p7zip-full bochs` plus `rustup`.

The first build creates a development signing key in `build/keys/` (never committed). Every checkout
trusts only its own key; `DOS_SIGNING_KEY` points at another key file.

## Commands

Use `.\dbuild.ps1` on Windows or `./dbuild.sh` on Linux:

```sh
./dbuild.sh                           # build build/discrete.img (BIOS + UEFI, 64 MiB GPT image)
./dbuild.sh run                       # build and boot in QEMU, serial on this console (--uefi, --smp N, --iommu amd, --audio hda|virtio|usb|none, --net virtio|e1000e|none, --gpu std|virtio|virtio-vga|none; a virtio tablet is the pointer for `gui`)
./dbuild.sh debug                     # boot paused with a GDB stub on localhost:1234
./dbuild.sh test                      # run the full test suite (repro + QEMU/Bochs + host + static)
./dbuild.sh test --case boot,uefi     # selected cases only
./dbuild.sh soak --minutes 60         # long randomized multi-core stress run
./dbuild.sh bench                     # build/discrete-bench.img for real hardware (benchmarks.md)
./dbuild.sh img <cmd> [args...]       # disk image, signing, verification, and attestation utilities
./dbuild.sh commit                    # interactive stage, commit message, DCO sign-off (-s), and push
./dbuild.sh clean                     # remove build/
```

Outputs: `build/discrete.img`, `build/kernel.elf` (with symbols, for GDB), `build/kernel.map`,
`build/SHA256SUMS`, and per-case serial logs under `build/ktest/`.

### Kernel debugger

`kdb` runs on the serial port of every release boot. With `dbuild run`, type into the console:
`help`, `threads`, `cpus`, `objects`, `measure`, `mem`, `prof [ms]`, `lat`, `poweroff`, `reboot`.

## The test suite

`dbuild test` runs every case and ends with `TEST PASSED (N cases)` or `TEST FAILED`. It:

1. rebuilds the release image cleanly in `build/repro` and requires identical bytes (`repro`; skip
   with `--no-repro`);
2. builds the shared userland, compatibility binaries, and bootloaders once, then builds all
   `KTEST_*` kernel variants in parallel;
3. boots each case in QEMU (or Bochs for CET/strict-MSR) and checks the serial log: required lines
   must appear, forbidden lines (`KERNEL PANIC`, `FAIL`, ...) must not;
4. runs the host cases: `cargo test` for `dosfs`, `dosaudio`, `dosnet`, `doscrypt`, `dman`, and
   `aml`, the loaders' KASLR and C crypto checks, and static analysis (`clang --analyze` over all C,
   `clippy -D warnings` over all Rust crates);
5. writes **`build/test-report.md`**: result per case, commit, tool versions. Attach it to your
   pull request.

Main test groups (see `tools/dbuild/src/test.rs` for the full list):

| Group | Cases |
|---|---|
| Boot | `boot`, `boot-amd`, `uefi`, `uefi-uniproc`, `uniproc`, `bios-badsig`, `uefi-badsig`, `manydevices` |
| Protections fire | `stackprot`, `cet`, `cet-cp`, `cet-user`, `nx`, `wx`, `nullderef`, `stackguard`, `heapguard`, `doublefree`, `uaf`, `bounds`, `roinit`, `smap`, `smep`, `spec`, `spec-intel`, `kaslr`, ... |
| Kernel | `selftest`, `sched`, `cpupm`, `cpupm-bochs`, `smp`, `smp-xapic`, `objects`, `lockup`, `softlockup`, `soak`, `bench`, `profile` |
| Sanitizers | `ubsan`, `ubsan-smp`, `ubsantrap`, `kasan`, `kasan-user`, `kasan-fuzz`, `kasanoob`, `kasanuaf` |
| User space | `user`, `libd`, `fuzz`, `compat`, `drivers`, `drivers-amd`, `keyboard`, `usbkbd`, `usbnokbd`, `usbhub`, `usbplug`, `usbtwo`, `usbrepeat`, `usbhold`, `usbstorage`, `usbstorage2`, `storage`, `readonly`, `services`, `shell`, `audio-hda`, `audio-virtio`, `audio-usb`, `audio-sec`, `net-virtio`, `net-e1000e`, `net-shell`, `gpu-virtio`, `gpu-virtio-amd`, `gpu-gop`, `gpu-shell`, `awmi-virtio`, `awmi-gop`, `time`, `time-uefi`, `attest`, `attest-tpm`, `powerbutton`, `poweroff`, `poweroff-uefi`, `reboot`, `hwbench`, `kdb` |
| Host | `storage-host`, `audio-host`, `net-host`, `gpu-host`, `awmi-host`, `crypto-host`, `manifest-host`, `aml-host`, `kaslr-host`, `static` |

## Adding a test

**A kernel test.** Add a `TestCase` entry in `all_test_cases()` in `tools/dbuild/src/test.rs`:

```rust
TestCase::boot("mycase")
    .def("MYCASE")
    .timeout(30)
    .expect(&["KTEST mycase: PASSED"])
    .forbid(&["KERNEL PANIC", "FAIL"]),
```

then add `#elif defined(KTEST_MYCASE)` with a `ktest_run()` in `kernel/ktest.c` (or a Rust test
reached from `kernel/rust/src/ktest.rs`) that prints the expected line.

**A user-space test.** Most ring-3 tests live in `user/utest` (C), `user/fstest` or `user/ltest`
(Rust) and run inside an existing case (`user`, `libd`, `storage`, `compat`). Add a function there,
print a clear `FAIL: ...` line on failure, and it is covered.

**A host test.** Libraries that do not need the kernel (`user/lib/audio`, `user/lib/fs`,
`user/lib/crypto`, `user/lib/dman`, `kernel/aml`) use ordinary `cargo test`. Parsers of untrusted
data also get a fuzzer.

A good test fails without your change and passes with it. A protection test must prove the
protection *fires* (the fault, refusal or panic happens), not only that nothing breaks.
