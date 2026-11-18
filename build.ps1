<#
.SYNOPSIS
    D-OS build script.

.DESCRIPTION
    build  - assemble/compile/link everything and produce build\discrete.img (default)
    run    - build, then boot the image in QEMU (serial on this console); -Uefi boots it with UEFI firmware
    debug  - build, then boot QEMU paused with a GDB stub on localhost:1234
    test   - run the boot test suite headless (release image + kernel test variants);
             writes build\test-report.md (attach it to pull requests)
    bench  - build build\discrete-bench.img: the hardware benchmark image (docs/benchmarks.md). Write it
             to a USB stick like discrete.img; it boots, runs every benchmark (disks read only) and
             ends on one results screen to photograph
    soak   - long randomized multi-core stress run (KTEST_SOAK) for -Minutes; fails on any panic,
             failed round or stall
    clean  - delete the build directory

    QEMU (q35 + intel-iommu, or amd-iommu with -Iommu amd) runs with -Smp CPUs (default 4). Test cases may
    override the CPU count, CPU model and IOMMU.

    Test cases (see $TestCases below):
      boot         release image boots cleanly with all protections on; devmgr binds every driver
      uefi         the same image boots through UEFI (OVMF): the UEFI loader, GOP framebuffer console, ACPI
                   from UEFI, then the full boot with all devices
      uefi-uniproc UEFI boot on a single CPU
      uefi-selftest in-kernel tests (incl. BootInfo validation) after a UEFI boot
      keyboard     keys typed via the QEMU monitor reach the user-space PS/2 driver (ps2.ddrv)
      usbkbd       a USB keyboard on an xHCI controller (xhci.ddrv): controller bring-up, port
                   enumeration (a tablet is probed and skipped), HID boot reports become typed keys
      usbnokbd     xHCI with only a tablet and a mouse: each probed and reported once, no
                   re-probing; keys still reach the PS/2 driver
      usbplug      hot-plug: a tablet reconnecting three times is reported once then left alone; a
                   keyboard plugged into a hub later is found and types
      usbhub       a keyboard two hubs down (hub on a root port, hub on its port 1): hubs
                   configured and their ports probed, keys typed arrive
      drivers      user-space drivers (devmgr test): device ABI, virtio-blk I/O, crash + restart,
                   DMA blocked by the IOMMU, MSI-X interrupts, virtio-input keys
      drivers-amd  the same on an AMD-Vi IOMMU (amd-iommu): IVRS, device table, command buffer,
                   DMA fault reported through the event log
      boot-amd     the release image boots with AMD-Vi: every driver binds, DMA confined
      storage      storage (init "storage test"): AHCI + NVMe drivers, storaged, GPT, FAT32 and DFS
                   volumes made on the host, snapshots, power cuts, corruption detection, namespace
                   isolation (fstest); then on the host: 7-Zip reads the file D-OS wrote to FAT32,
                   dosimg fsck finds the DFS system volume clean
      readonly     the default storage setup never writes a disk (docs/hardware.md): every block
                   driver refuses a raw write, every volume reads but cannot be written; afterwards
                   every disk image is byte-identical to before (also checked after boot and uefi)
      manydevices  the release image with 64 extra PCIe root ports (70 devices, more than the
                   old 64-handle spawn limit; a real PC had 50): init and devmgr still start
      services     the service manager (init "services test"): manifests embedded and on disk
                   (signed accepted; unsigned, tampered, unknown key, ungranted endpoint refused),
                   exact grants and quotas, restart with backoff and giving up, storaged and devmgr
                   killed with I/O working again, shutdown in reverse order, power-off
      storage-host dosfs unit tests on the host (cargo test): BLAKE3 vectors, GPT, FAT32, DFS,
                   power-cut sweep over every sector of a workload
      manifest-host the service manifest parser on the host: schema tests and a mutation fuzzer
      time         the wall-clock time across a reboot (clock service from the CMOS RTC, file times
                   on DFS and FAT32; the host boots the same disks twice); time-uefi: the same with
                   the UEFI boot-time record
      selftest     in-kernel runtime library tests pass
      panic        KASSERT failure produces a kernel panic with location
      stackprot    stack buffer overflow is caught by the stack protector
      pagefault    unmapped access gives a decoded #PF report with backtrace
      doublefault  kernel stack overflow is reported via the #DF IST stack
      nx           executing kernel data faults (NX)
      wx           writing kernel code faults (W^X)
      nullderef    NULL is unmapped
      stackguard   kernel stack overflow hits its guard page (reported via #DF IST)
      doublefree   heap double free is detected
      uaf          heap use-after-free is detected
      heapguard    overflowing a large heap allocation hits its guard page
      rustpanic    a failed kassert! in Rust is a kernel panic with message and Rust source location
      deadlock     re-taking a held spinlock is detected (self-deadlock), not a silent hang
      lockorder    taking locks against their rank order is caught by lock-order checking (test builds)
      sched        scheduler: semaphore ping-pong, 100 threads, sleep accuracy, priority order, round robin
      threadguard  a thread's stack overflow hits the guard page below its stack (named in the report)
      mutexdeadlock re-locking a mutex the thread already owns is detected, not a silent hang
      atomicsleep  blocking while holding a spinlock is detected
      bench        benchmark harness runs (allocation, locks, clock, log, Rust, context switch, threads, SMP)
      poweroff     init switches the machine off through system_power (the POWER resource; ACPI S5
                   from the DSDT's \_S5); a process without the resource is refused; QEMU must stop
      reboot       the same for a reset (FADT reset register); QEMU must leave on reset
      poweroff-uefi the power-off on UEFI firmware (OVMF's tables)
      hwbench      the hardware benchmark image (bench target) in QEMU: kernel, user and storage
                   benchmarks, then the results screen; disks unchanged afterwards
      smp          multi-core: pinning, cross-CPU locks/wake-ups, TLB shootdown, balancing, per-CPU timers
      smp-xapic    the same on xAPIC (MMIO) instead of x2APIC
      uniproc      release image on a single CPU
      lockup       a CPU stuck with interrupts off is caught by the watchdog, with its NMI backtrace
      softlockup   a CPU that stops switching while work waits gets a soft-lockup warning
      soak         a few rounds of the randomized soak test (the soak target runs it for longer)
      compat       D-CMPL proofs: W1 (MSVC-built PE) and L1 (static Linux ELF) run unchanged; an
                   unsupported import / syscall fails cleanly; faults are reported; PE parser fuzzed
      objects      kernel objects: rights enforcement, handle reuse after close, quotas, process kill,
                   out-of-memory paths proven by fault injection, multi-core handle-table stress
      ubsan        selftest built with UBSan (trap mode): the C kernel runs free of undefined behaviour
      ubsan-smp    the multi-core test built with UBSan
      ubsantrap    a signed overflow in a UBSan build is caught and named in the #UD report
      kaslr        the kernel runs relocated at a random base, region bases randomized; booted three
                   times (BIOS, BIOS, UEFI): every layout must differ
      kaslr-host   the loaders' KASLR code on the host: relocation, refused tables, base choice; its
                   RELR decoding of kernel.bin equals llvm-readobj's
      roinit       writing ro-after-init data (the KASLR layout) faults
      bounds       an out-of-bounds array index traps (-fsanitize=array-bounds in release flags)

    Before the cases (full runs only), the release image is rebuilt in a second directory and
    must be byte-identical (reproducible build check). Skip with -NoRepro.

    The Rust toolchain comes from cargo on PATH, else the devbox at $env:DOS_RUST_BOX, else
    ..\Devbox\boxes\rust next to this repo. The version is pinned in rust-toolchain.toml.

.EXAMPLE
    .\build.ps1 run
    .\build.ps1 test
    .\build.ps1 test -Case stackprot
    .\build.ps1 soak -Minutes 60
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('build', 'run', 'debug', 'test', 'soak', 'clean', 'bench')]
    [string]$Target = 'build',

    # test: run only these cases (default: all)
    [string[]]$Case,

    # test: max seconds per case before it counts as a failure
    [int]$TestTimeout = 15,

    # test: skip the reproducible-build check
    [switch]$NoRepro,

    # run/debug/soak: number of CPUs
    [int]$Smp = 4,

    # soak: how long to run
    [int]$Minutes = 10,

    # build: output directory and kernel test variant (used by test's parallel variant builds)
    [string]$OutDir,
    [string]$KernelTest,
    [switch]$Ubsan,
    [switch]$Kasan,
    [switch]$Quiet,

    # run/debug: boot with UEFI firmware (OVMF) instead of the BIOS
    [switch]$Uefi,

    # run/debug: the emulated IOMMU (intel = VT-d, amd = AMD-Vi)
    [ValidateSet('intel', 'amd')]
    [string]$Iommu = 'intel'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root  = $PSScriptRoot
$Build = Join-Path $Root 'build'

# ---------------------------------------------------------------------------
# Boot disk layout (in 512-byte sectors), made by `dosimg boot` (docs/boot.md): GPT; partition 1
# is the BIOS boot partition at LBA 2048 holding stage 2 and the kernel; partition 2 the EFI
# System Partition with the UEFI loader and the kernel. Passed to stage 1/2 as NASM defines.
# ---------------------------------------------------------------------------
$SectorSize     = 512
$Stage2Lba      = 2048
$Stage2Sectors  = 32              # reserved area for stage 2 (16 KiB)
$Stage3Lba      = $Stage2Lba + $Stage2Sectors   # stage 3: the BIOS path's signature verifier (32 KiB)
$Stage3Sectors  = 64
$KsigLba        = $Stage3Lba + $Stage3Sectors   # the kernel's .dsig (one sector used of 8)
$KernelLba      = $KsigLba + 8                  # keep in sync with tools/dosimg (make_boot)

# ---------------------------------------------------------------------------
# Test suite. Each case boots an image and checks the serial log.
#   Define : kernel test selector (-DKTEST -DKTEST_<Define>); $null = release image
#   Expect : strings that must all appear (the case ends as soon as they do)
#   Forbid : strings that must never appear
#   MustExit : after the Expect strings, QEMU itself must end within 5 s (a power-off or reset
#              really happened: -no-reboot makes a reset end QEMU, and -no-shutdown is dropped)
#   Keys   : optional QEMU 'sendkey' names typed once KeysAfter appears on serial ('!cmd': a monitor
#            command such as device_add/device_del; '~ms': a pause)
#   Serial : optional lines typed into COM1 (kdb) once SerialAfter appears
#   Devices: attach the user-space driver devices (virtio-blk with the test disk, virtio keyboard)
#   Smp, Cpu, Timeout : optional CPU count (default 4), QEMU CPU model (default max), seconds
#   Ubsan  : build the C kernel with UBSan in trap mode (no runtime: a failed check is a #UD)
#   Kasan  : build the C kernel with KASAN-style heap checks (every load/store checked against the
#            slab shadow, kernel/lib/kasan.c)
#   Uefi   : boot with UEFI firmware (OVMF) instead of the BIOS (the same image)
#   Iommu  : 'amd' for an AMD-Vi IOMMU (amd-iommu) instead of Intel VT-d
# ---------------------------------------------------------------------------
# Many PCI devices (manydevices): $Count PCIe root ports on q35's root bus, 8 functions per slot from
# slot 8 up. Each is a PCI function the kernel hands to init as a device.
function Get-ManyDeviceArgs([int]$Count) {
    $a = @()
    for ($i = 0; $i -lt $Count; $i++) {
        $slot = [int](8 + [Math]::Floor($i / 8)); $fn = $i % 8
        $mf = if ($fn -eq 0) { ',multifunction=on' } else { '' }
        $a += @('-device', ('pcie-root-port,id=rp{0},bus=pcie.0,chassis={1},slot={1},addr=0x{2:x}.{3}{4}' -f $i, ($i + 1), $slot, $fn, $mf))
    }
    return ,$a
}

# Lines typed on the keyboard as QEMU key names: each line ends with Enter and a pause (the command
# runs). '@name' is a key by its QEMU name (tab, up, ctrl-c), with no Enter after it.
function ConvertTo-QemuKeys([string[]]$Lines, [int]$PauseMs = 900) {
    $named = @{ ' ' = 'spc'; '/' = 'slash'; '.' = 'dot'; '-' = 'minus'; '|' = 'shift-backslash'; '>' = 'shift-dot'; '<' = 'shift-comma'
                '=' = 'equal'; '_' = 'shift-minus'; ':' = 'shift-semicolon'; '"' = 'shift-apostrophe'; '*' = 'shift-8' }
    $keys = @()
    foreach ($l in $Lines) {
        if ($l.StartsWith('@')) { $keys += $l.Substring(1); continue }
        $tab = $l.EndsWith('<tab>')            # 'go /sy<tab>': Tab completes, then Enter
        if ($tab) { $l = $l.Substring(0, $l.Length - 5) }
        foreach ($c in $l.ToCharArray()) {
            $s = [string]$c
            if ($named.ContainsKey($s)) { $keys += $named[$s] }
            elseif ($s -cmatch '[A-Z]') { $keys += "shift-$($s.ToLowerInvariant())" }
            else { $keys += $s }
        }
        if ($tab) { $keys += @('tab', '~400') }
        $keys += @('ret', "~$PauseMs")
    }
    return ,$keys
}

$KernelStages = @('D-KRNL 1.', 'BootInfo OK',
                'GDT/TSS/IDT loaded', 'PMM:', 'VMM: kernel W^X', 'NULL page unmapped', 'KASLR: image 17 bits, direct map', 'Heap:', 'Speculation: Meltdown ', 'Speculation: MDS/TAA ',
                'APIC timer:', 'Interrupts enabled, timer OK', 'Scheduler: preemptive', 'SMP: ', 'Rust: dkrnl', 'Objects: handles',
                'PCI: ECAM at', 'IOMMU: DMA remapping on for every device', 'Devices: ', 'Verified boot: kernel signature valid (Ed25519', 'Measured boot: PCR 8 = kernel', 'Summary: ', 'Summary: KASLR image 17 bits', 'Summary: KPTI ',
                'User: init started in ring 3', 'init: running in ring 3')
$BootStages = @('D-OS: stage1 OK', 'D-OS: stage2 OK', 'D-OS: entering long mode', 'D-OS: stage3: kernel signature valid (Ed25519', 'D-OS: stage3: kernel relocated (KASLR, 17 bits', 'BootInfo OK (v5, BIOS') + $KernelStages
$UefiStages = @('D-OS: UEFI loader', 'D-OS: kernel signature valid (Ed25519', 'D-OS: kernel ', 'loaded at 0x100000', 'D-OS: kernel relocated (KASLR, 17 bits', 'D-OS: GOP framebuffer', 'D-OS: ACPI 2.0 RSDP', 'D-OS: exiting boot services',
                'BootInfo OK (v5, UEFI', 'Console: framebuffer', 'write-combining on', '(RSDP from UEFI)') + $KernelStages
$Halted = 'System halted.'
$TestCases = [ordered]@{
    boot        = @{ Define = $null;         Devices = $true; Expect = $BootStages + @('SMP: 4 CPUs online (x2APIC)', 'D-KRNL: ready', 'init: started devmgr', 'devmgr: ps2.ddrv ready', 'devmgr: virtio-blk.ddrv ready', 'devmgr: virtio-input.ddrv ready', 'devmgr: ahci.ddrv ready', 'devmgr: nvme.ddrv ready', 'devmgr: disks are read-only', 'storaged: volume ''system'': DFS', 'MiB free, generation 2, 0 snapshot(s), read-only', 'init: 4 volume(s)', 'devmgr: running'); Forbid = @('KERNEL PANIC', 'FAIL', 'OFF (unsupported)', 'did not start', 'warning', 'exited with code', 'NOT confined'); Post = 'Test-DisksUnchanged' }
    'boot-amd'  = @{ Define = $null;         Devices = $true; Iommu = 'amd'; Expect = @('IOMMU: AMD-Vi, 1 unit(s)', 'IOMMU: DMA remapping on for every device', '(the IOMMU itself: kept by the kernel)', 'D-KRNL: ready', 'devmgr: ps2.ddrv ready', 'devmgr: virtio-blk.ddrv ready', 'devmgr: virtio-input.ddrv ready', 'devmgr: ahci.ddrv ready', 'devmgr: nvme.ddrv ready', 'devmgr: disks are read-only', 'storaged: volume ''system'': DFS', 'init: 4 volume(s)', 'devmgr: running'); Forbid = @('KERNEL PANIC', 'FAIL', 'did not start', 'warning', 'exited with code', 'NOT confined', 'unusable', 'blocked DMA'); Post = 'Test-DisksUnchanged' }
    uefi        = @{ Define = $null;         Devices = $true; Uefi = $true; Timeout = 90; Expect = $UefiStages + @('SMP: 4 CPUs online (x2APIC)', 'D-KRNL: ready', 'init: started devmgr', 'devmgr: ps2.ddrv ready', 'devmgr: virtio-blk.ddrv ready', 'devmgr: virtio-input.ddrv ready', 'devmgr: ahci.ddrv ready', 'devmgr: nvme.ddrv ready', 'devmgr: disks are read-only', 'storaged: volume ''system'': DFS', 'init: 4 volume(s)', 'devmgr: running', 'terminal: ready: framebuffer', 'shell: ready'); Forbid = @('KERNEL PANIC', 'FAIL', 'OFF (unsupported)', 'did not start', 'warning', 'exited with code', 'NOT confined', 'NOT confined', 'stage1'); Post = 'Test-DisksUnchanged' }
    'uefi-uniproc' = @{ Define = $null;       Uefi = $true; Smp = 1; Timeout = 60; Expect = $UefiStages + @('SMP: 1 CPU', 'D-KRNL: ready'); Forbid = @('KERNEL PANIC', 'FAIL') }
    'uefi-selftest' = @{ Define = 'SELFTEST';  Uefi = $true; Timeout = 60; Expect = $UefiStages + @('KTEST selftest: PASSED', 'KTEST rust selftest: PASSED', 'D-KRNL: ready'); Forbid = @('KERNEL PANIC', 'FAIL') }
    keyboard    = @{ Define = $null;         Expect = @('ps2: keyboard ready', 'terminal: line from ps2: Disc OS');  Forbid = @('KERNEL PANIC')
                     Keys = @('shift-d', 'i', 's', 'c', 'spc', 'shift-o', 'shift-s', 'ret'); KeysAfter = 'devmgr: ps2.ddrv ready' }
    # USB: a qemu-xhci controller with a tablet (not a keyboard: probed and left unused) and a
    # keyboard on its USB 2 ports; keys typed go to the USB keyboard (the input device created last).
    usbkbd      = @{ Define = $null;         Qemu = @('-device', 'qemu-xhci,id=xhci', '-device', 'usb-tablet,bus=xhci.0', '-device', 'usb-kbd,bus=xhci.0')
                     Expect = @('xhci: controller ready on pci-', 'HID device 0627:0001 (left unused)', ': keyboard ready on port ', 'DMA confined by the IOMMU', 'devmgr: xhci.ddrv ready', 'terminal: line from xhci: Usb Kbd')
                     Forbid = @('KERNEL PANIC', 'exited with code', 'blocked DMA', 'FAIL'); Timeout = 60
                     Keys = @('shift-u', 's', 'b', 'spc', 'shift-k', 'b', 'd', 'ret'); KeysAfter = 'devmgr: xhci.ddrv ready' }
    # USB without a keyboard: a tablet and a mouse are probed and reported once each, then left
    # alone (a probe's own port reset must not trigger another probe); typing still works on PS/2.
    usbnokbd    = @{ Define = $null;         Qemu = @('-device', 'qemu-xhci,id=xhci', '-device', 'usb-tablet,bus=xhci.0', '-device', 'usb-mouse,bus=xhci.0')
                     Expect = @('xhci: controller ready on pci-', ': HID device 0627:0001 (left unused)', ': mouse 0627:0001 (left unused)', 'devmgr: xhci.ddrv ready', 'terminal: line from ps2: Disc OS')
                     Forbid = @('KERNEL PANIC', 'exited with code', 'blocked DMA', 'FAIL', 'keyboard ready on port'); Timeout = 60
                     Keys = @('shift-d', 'i', 's', 'c', 'spc', 'shift-o', 'shift-s', 'ret'); KeysAfter = 'devmgr: xhci.ddrv ready'
                     Post = 'Test-UsbProbedOnce' }
    # USB hot-plug: a tablet unplugged and plugged back three times is reported once, then left
    # alone (third identical probe); a keyboard plugged into a hub later is found and types.
    usbplug     = @{ Define = $null;         Qemu = @('-device', 'qemu-xhci,id=xhci', '-device', 'usb-hub,bus=xhci.0,port=1', '-device', 'usb-tablet,bus=xhci.0,port=2,id=tab')
                     Expect = @('xhci: controller ready on pci-', ': HID device 0627:0001 (left unused)', 'device keeps reconnecting; left alone until unplugged', '.4 (USB HID boot protocol', 'terminal: line from xhci: Plug')
                     Forbid = @('KERNEL PANIC', 'exited with code', 'blocked DMA', 'FAIL', 'not set up', 'stopped answering'); Timeout = 60
                     Keys = @('!device_del tab', '~400', '!device_add usb-tablet,bus=xhci.0,port=2,id=tab', '~600', '!device_del tab', '~400', '!device_add usb-tablet,bus=xhci.0,port=2,id=tab', '~600',
                              '!device_del tab', '~400', '!device_add usb-tablet,bus=xhci.0,port=2,id=tab', '~600', '!device_add usb-kbd,bus=xhci.0,port=1.4,id=kbd', '~2500',
                              'shift-p', 'l', 'u', 'g', 'ret'); KeysAfter = 'devmgr: xhci.ddrv ready'
                     Post = 'Test-UsbPlugOnce' }
    # Two keyboards on one controller: one on a root port, one behind a hub (QEMU types on the one
    # created last). Both are served: a first boot keyboard (on a PC often a receiver or a lighting
    # controller) must not keep the real one from being probed.
    usbtwo      = @{ Define = $null;         Qemu = @('-device', 'qemu-xhci,id=xhci', '-device', 'usb-kbd,bus=xhci.0,port=1', '-device', 'usb-hub,bus=xhci.0,port=2', '-device', 'usb-kbd,bus=xhci.0,port=2.1')
                     Expect = @('xhci: controller ready on pci-', ': keyboard ready on port 5 (', ': keyboard ready on port 6.1 (', 'devmgr: xhci.ddrv ready', 'terminal: line from xhci: Two')
                     Forbid = @('KERNEL PANIC', 'exited with code', 'blocked DMA', 'FAIL', 'not set up'); Timeout = 60
                     Keys = @('shift-t', 'w', 'o', 'ret'); KeysAfter = ': keyboard ready on port 6.1 (' }
    # USB hubs: a hub on a root port, a second hub on its port 1 with the keyboard on port 3, and a
    # tablet on the first hub's port 2. Both hubs are configured, the keyboard found two tiers down.
    usbhub      = @{ Define = $null;         Qemu = @('-device', 'qemu-xhci,id=xhci', '-device', 'usb-hub,bus=xhci.0,port=1', '-device', 'usb-hub,bus=xhci.0,port=1.1',
                                                        '-device', 'usb-tablet,bus=xhci.0,port=1.2', '-device', 'usb-kbd,bus=xhci.0,port=1.1.3')
                     Expect = @('xhci: controller ready on pci-', ': hub 0409:55aa, 8 ports', '.1: hub 0409:55aa, 8 ports', '.2: HID device 0627:0001 (left unused)', '.1.3 (USB HID boot protocol', 'devmgr: xhci.ddrv ready', 'terminal: line from xhci: Usb Hub')
                     Forbid = @('KERNEL PANIC', 'exited with code', 'blocked DMA', 'FAIL', 'not set up', 'stopped answering'); Timeout = 60
                     Keys = @('shift-u', 's', 'b', 'spc', 'shift-h', 'u', 'b', 'ret'); KeysAfter = ': keyboard ready on port ' }
    selftest    = @{ Define = 'SELFTEST';    Expect = @('  measured boot: Ed25519 vectors', 'KTEST selftest: PASSED', 'KTEST rust selftest: PASSED', 'D-KRNL: ready');  Forbid = @('KERNEL PANIC', 'FAIL') }
    panic       = @{ Define = 'PANIC';       Expect = @('KERNEL PANIC', 'KASSERT failed: one == 2', 'ktest.c:', $Halted); Forbid = @('FAILED') }
    stackprot   = @{ Define = 'STACKPROT';   Expect = @('KERNEL PANIC', 'stack smashing detected', $Halted);              Forbid = @('FAILED') }
    pagefault   = @{ Define = 'PAGEFAULT';   Expect = @('Page fault (#PF)', 'CR2=0000006000000000', 'not-present page, read, kernel', 'Backtrace', $Halted); Forbid = @('FAILED') }
    doublefault = @{ Define = 'DOUBLEFAULT'; Expect = @('Double fault (#DF)', $Halted);                                    Forbid = @('FAILED') }
    nx          = @{ Define = 'NX';          Expect = @('Page fault (#PF)', 'instruction fetch', 'execute from non-executable memory', $Halted); Forbid = @('FAILED', 'SKIPPED') }
    wx          = @{ Define = 'WX';          Expect = @('Page fault (#PF)', 'protection violation (present), write, kernel', 'write to read-only kernel memory', $Halted); Forbid = @('FAILED') }
    nullderef   = @{ Define = 'NULLDEREF';   Expect = @('Page fault (#PF)', 'CR2=0000000000000000', 'NULL pointer dereference', $Halted); Forbid = @('FAILED') }
    stackguard  = @{ Define = 'STACKGUARD';  Expect = @('Double fault (#DF)', 'hit guard page: kernel boot stack', $Halted); Forbid = @('FAILED') }
    doublefree  = @{ Define = 'DOUBLEFREE';  Expect = @('KERNEL PANIC', 'heap: double free', $Halted);                Forbid = @('FAILED') }
    uaf         = @{ Define = 'UAF';         Expect = @('KERNEL PANIC', 'heap: use-after-free detected', $Halted);    Forbid = @('FAILED') }
    heapguard   = @{ Define = 'HEAPGUARD';   Expect = @('Page fault (#PF)', 'unmapped kernel heap address', $Halted); Forbid = @('FAILED') }
    rustpanic   = @{ Define = 'RUSTPANIC';   Expect = @('KERNEL PANIC', 'Rust panic: KASSERT failed: one == 2', 'kernel/rust/src/ktest.rs:', $Halted); Forbid = @('FAILED') }
    deadlock    = @{ Define = 'DEADLOCK';    Expect = @('KERNEL PANIC', "spinlock self-deadlock: 'ktest.a' is already held", 'Held locks', $Halted); Forbid = @('FAILED') }
    lockorder   = @{ Define = 'LOCKORDER';   Expect = @('KERNEL PANIC', "lock order violation: acquiring 'ktest.low' (rank 5) while holding 'ktest.high'", $Halted); Forbid = @('FAILED') }
    sched       = @{ Define = 'SCHED';       Expect = @('KTEST sched: PASSED');                                       Forbid = @('KERNEL PANIC', 'FAIL') }
    threadguard = @{ Define = 'THREADGUARD'; Expect = @('Double fault (#DF)', "hit guard page: kernel stack of thread 'ktest.recurse'", "in thread 'ktest.recurse'", $Halted); Forbid = @('FAILED') }
    mutexdeadlock = @{ Define = 'MUTEXDEADLOCK'; Expect = @('KERNEL PANIC', "mutex 'ktest.m' deadlock: already held by thread 'kmain'", $Halted); Forbid = @('FAILED') }
    atomicsleep = @{ Define = 'ATOMICSLEEP'; Expect = @('KERNEL PANIC', "thread 'kmain' blocked while holding a spinlock", 'ktest.a (rank 5)', $Halted); Forbid = @('FAILED') }
    bench       = @{ Define = 'BENCH';       Expect = @('BENCH kmalloc+kfree 32 B', 'BENCH rust Box alloc+free', 'BENCH thread_yield round trip', 'BENCH rust spawn+join', 'BENCH cross-CPU semaphore ping-pong', 'BENCH map+unmap 1 page with TLB shootdown', 'KTEST bench: DONE');  Forbid = @('KERNEL PANIC', 'FAIL') }
    smp         = @{ Define = 'SMP';         Expect = @('SMP: 4 CPUs online (x2APIC)', 'TLB shootdown: 300 remaps', 'KTEST smp: PASSED');  Forbid = @('KERNEL PANIC', 'FAIL'); Timeout = 30 }
    'smp-xapic' = @{ Define = 'SMP';         Expect = @('SMP: 4 CPUs online (xAPIC)', 'KTEST smp: PASSED');  Forbid = @('KERNEL PANIC', 'FAIL'); Cpu = 'max,-x2apic'; Timeout = 30 }
    uniproc     = @{ Define = $null;         Expect = $BootStages + @('SMP: 1 CPU', 'D-KRNL: ready');  Forbid = @('KERNEL PANIC', 'FAIL'); Smp = 1 }
    lockup      = @{ Define = 'LOCKUP';      Expect = @('watchdog: CPU 1 is not responding', 'KERNEL PANIC', 'watchdog: hard lockup on CPU 1', "NMI backtrace of CPU 1 (thread 'ktest.stuck'), interrupts off", $Halted); Forbid = @('FAILED'); Timeout = 40 }
    softlockup  = @{ Define = 'SOFTLOCKUP';  Expect = @("watchdog: soft lockup on CPU 1: thread 'ktest.hog'", 'Backtrace', 'KTEST softlockup: DONE (waiter ran: yes)'); Forbid = @('KERNEL PANIC', 'FAILED'); Timeout = 40 }
    soak        = @{ Define = 'SOAK';        Expect = @('SOAK round 3 OK');  Forbid = @('KERNEL PANIC', 'FAIL'); Timeout = 40 }
    ubsan       = @{ Define = 'SELFTEST';    Ubsan = $true; Expect = @('KTEST selftest: PASSED', 'D-KRNL: ready');  Forbid = @('KERNEL PANIC', 'FAIL', 'UBSan') }
    'ubsan-smp' = @{ Define = 'SMP';         Ubsan = $true; Expect = @('KTEST smp: PASSED');  Forbid = @('KERNEL PANIC', 'FAIL', 'UBSan'); Timeout = 40 }
    ubsantrap   = @{ Define = 'UBSANTRAP';   Ubsan = $true; Expect = @('Invalid opcode (#UD)', 'UBSan: undefined behaviour: signed integer overflow (add)', 'Backtrace', $Halted); Forbid = @('FAILED') }
    profile     = @{ Define = 'PROFILE';     Expect = @('PROFILE: top ktest_prof_spin', 'KTEST profile (kernel): OK', 'LATENCY wakeup: ', 'LATENCY irq: ', 'BENCH user: channel call round trip', 'LATENCY syscall: ', 'KTEST profile: PASSED'); Forbid = @('KERNEL PANIC', 'FAIL'); Timeout = 120 }
    kasan       = @{ Define = 'SELFTEST';    Kasan = $true; Expect = @('KASAN: heap shadow on', 'KTEST selftest: PASSED', 'KTEST rust selftest: PASSED', 'D-KRNL: ready'); Forbid = @('KERNEL PANIC', 'FAIL', 'KASAN: slab'); Timeout = 40 }
    'kasan-user' = @{ Define = 'USER';       Kasan = $true; Expect = @('KASAN: heap shadow on', 'utest: PASSED', 'init: utest all exited with code 0'); Forbid = @('KERNEL PANIC', 'FAIL', 'KASAN: slab'); Timeout = 240 }
    kasanoob    = @{ Define = 'KASANOOB';    Kasan = $true; Expect = @('KERNEL PANIC', 'KASAN: slab-out-of-bounds write of size 1', '0 bytes past the end of a 20-byte allocation', 'ktest_kasan', $Halted); Forbid = @('FAILED') }
    kasanuaf    = @{ Define = 'KASANUAF';    Kasan = $true; Expect = @('KERNEL PANIC', 'KASAN: use-after-free read of size 8', 'ktest_kasan', $Halted); Forbid = @('FAILED') }
    # The user runtime (libd): init runs ltest (owned handles, heap on 4 CPUs, threads with guarded
    # stacks, mutexes, channels, a stack overflow caught in the guard page) and ltest runs ctest (the C API).
    libd        = @{ Define = 'LIBD';        Expect = @('ltest: abi: kernel v', 'ltest: handles: 100 owned handles closed', 'ltest: heap: 4 threads', 'ltest: threads: 16 threads',
                                                        'ltest: mutex: 4 threads x 100000 increments exact (400000)', '(no kernel event: yielding)', 'ltest: once: one run from 8 threads; detached: 8 threads ran and were reclaimed',
                                                        'ltest: channels: call to a server thread', 'ltest: stack guard: overflow faulted at', 'ctest: heap:', 'ctest: threads: 4 threads, distinct ids, mutex count 200000 exact', 'ctest: PASSED',
                                                        'ltest: C API: ctest passed', 'BENCH libd: thread spawn+join', 'BENCH libd: mutex lock+unlock', 'BENCH libd: Box alloc+free 64 B', 'ltest: PASSED', 'init: ltest exited with code 0')
                     Forbid = @('KERNEL PANIC', 'FAIL', 'PANIC'); Timeout = 120 }
    user        = @{ Define = 'USER';        Expect = @('utest: abi:', 'utest: code signing: unsigned images refused', 'utest: pointers:', 'utest: fault isolation: 14 kinds', 'utest: kill:', 'utest: fpu:', 'utest: channels:', 'utest: ipc:', 'utest: ports:', 'utest: exceptions:', 'utest: supervisor:', 'utest: bases:', 'utest: sealing:', 'utest: avx:', 'BENCH user: null syscall', 'BENCH user: channel call round trip', 'BENCH user: forwarded syscall', 'utest: fuzz:', 'utest: ipc fuzz:', 'utest: PASSED', 'init: utest all exited with code 0'); Forbid = @('KERNEL PANIC', 'FAIL'); Timeout = 120 }
    # Transient-execution mitigations (docs/hardening.md). spec: KPTI, VERW and RSB filling forced on
    # (whatever the host CPU), the shadow page tables walked, and the whole ring-3 suite run on top;
    # every interrupt from ring 3 must find the user page tables loaded. spec-intel: an Intel model
    # without ARCH_CAPABILITIES, so the kernel itself must decide it is Meltdown-affected.
    spec        = @{ Define = 'SPEC';        Expect = @('Speculation: Meltdown ', 'KPTI: user page tables map', 'KTEST spec: user page tables: ', 'all entry pages', 'KTEST spec: array_index_nospec OK',
                                                        'KTEST spec: KPTI, VERW and RSB filling on every CPU: yes', 'utest: fault isolation: 14 kinds', 'utest: PASSED', 'init: utest all exited with code 0', 'KTEST spec: PASSED'); Forbid = @('KERNEL PANIC', 'FAIL'); Timeout = 180 }
    'spec-intel' = @{ Define = 'USER';       Cpu = 'Skylake-Client'; Expect = @('(GenuineIntel)', 'Speculation: Meltdown affected, KPTI on', 'Spectre v2 retpolines + RSB filling', 'KPTI: user page tables map', 'Summary: KPTI on', 'utest: PASSED', 'init: utest all exited with code 0'); Forbid = @('KERNEL PANIC', 'FAIL'); Timeout = 180 }
    fuzz        = @{ Define = 'FUZZ';        Expect = @('elf fuzz:', 'KTEST fuzz: ELF parser OK', 'acpi fuzz:', 'KTEST fuzz: ACPI parsers OK', 'utest: fuzz: 200000 random syscalls', 'utest: ipc fuzz: 50000 operations', 'utest: PASSED', 'init: utest fuzz 200000 exited with code 0', 'KTEST fuzz: objects after user space ended: none leaked', 'KTEST fuzz: PASSED'); Forbid = @('KERNEL PANIC', 'FAIL'); Timeout = 180 }
    # The fuzzers again with KASAN: a parser reading one byte past a table (or a message) is reported.
    'kasan-fuzz' = @{ Define = 'FUZZ';       Kasan = $true; Expect = @('KASAN: heap shadow on', 'KTEST fuzz: ELF parser OK', 'KTEST fuzz: ACPI parsers OK', 'utest: ipc fuzz:', 'KTEST fuzz: PASSED'); Forbid = @('KERNEL PANIC', 'FAIL', 'KASAN: slab'); Timeout = 300 }
    # Remote attestation (docs/attestation.md): utest asks the kernel for a report with a fresh nonce and
    # prints it; the host then plays the remote verifier (dosimg attest-verify) against this build's
    # kernel .dsig and key: the report must verify, and tampered, replayed or foreign ones must not.
    attest      = @{ Define = 'ATTEST';      Expect = @('Attestation: key ', 'utest: attest report: ', 'init: utest attest exited with code 0'); Forbid = @('KERNEL PANIC', 'FAIL'); Post = 'Test-AttestReport' }
    smap        = @{ Define = 'SMAP';        Expect = @('KTEST smap: kernel reading user address', 'Page fault (#PF)', 'protection violation (present), read, kernel', 'kernel accessed user memory outside user_copy (SMAP)', $Halted); Forbid = @('KTEST smap: FAILED') }
    smep        = @{ Define = 'SMEP';        Expect = @('KTEST smep: kernel calling user code', 'Page fault (#PF)', 'instruction fetch', 'kernel tried to execute user memory (SMEP)', $Halted); Forbid = @('KTEST smep: FAILED') }
    kdb         = @{ Define = $null;         Expect = @('kdb: threads', 'TID  NAME', 'reaper', 'kdb: cpus', 'CPU  ONLINE', 'PCR  8', 'kdb: measure: '); Forbid = @('KERNEL PANIC')
                     Serial = @('threads', 'cpus', 'measure'); SerialAfter = 'kdb: serial console ready' }
    compat      = @{ Define = 'COMPAT';      Expect = @('utest: compat: start exception', 'Hello, world from Windows (W1)', 'W1: TEB at GS, PEB image base matches, kernel32 bound', 'BENCH compat: PE load of w1.exe', 'unsupported import USER32.dll!MessageBoxA', "user fault: process 'w1fault.exe'", 'Hello, world from Linux (L1)', 'L1: argv/auxv on the stack, TLS at FS, set_tid_address served', 'unsupported Linux syscall 63 (uname) -> ENOSYS', 'L1: uname -> ENOSYS, handled cleanly', 'l1: SIGSEGV', 'BENCH compat: forwarded Linux syscall round trip', 'dcmpl: pe fuzz:', 'utest: compat: PASSED', 'init: utest compat exited with code 0'); Forbid = @('KERNEL PANIC', 'FAIL', 'PANIC'); Timeout = 120 }
    drivers     = @{ Define = 'DRIVERS';     Devices = $true
                     Expect = @('IOMMU: DMA remapping on', 'devmgr: test: device ABI: config writes filtered, MSI-X table hidden', 'virtio-blk: 2048 sectors', 'DMA confined by the IOMMU',
                                'devmgr: test: virtio-blk: 2048 sectors', 'write + read back OK', 'devmgr: test: interrupt delivery: virtio-blk', "user fault: process 'virtio-blk.ddrv'", 'devmgr: restarting virtio-blk.ddrv',
                                'devmgr: test: virtio-blk.ddrv crashed and was restarted; I/O works again', 'IOMMU: blocked DMA write by 00:02.0 at 0x100000',
                                'devmgr: test: DMA outside the driver''s pins blocked by the IOMMU', 'devmgr: test: virtio-blk recovered after the DMA test',
                                "devmgr: test: keyboard: 'virtio' typed on virtio-input", 'devmgr: test: interrupt delivery: virtio-input', 'devmgr: test PASSED', 'init: devmgr exited with code 0', 'KTEST drivers: kernel memory at 0x100000 unchanged', 'KTEST drivers: PASSED')
                     Forbid = @('KERNEL PANIC', 'FAIL', 'PANIC'); Timeout = 90
                     Keys = @('v', 'i', 'r', 't', 'i', 'o', 'ret'); KeysAfter = 'devmgr: test: waiting for keys' }
    # AMD-Vi: the IOMMU is PCI function 00:02.0 (kept by the kernel), so virtio-blk is 00:03.0. QEMU
    # logs IO page faults without the address (its event encoder drops bits 64-127): the kernel's
    # memory check proves the block instead.
    'drivers-amd' = @{ Define = 'DRIVERS';   Devices = $true; Iommu = 'amd'
                     Expect = @('IOMMU: AMD-Vi, 1 unit(s)', 'IOMMU: DMA remapping on', 'devmgr: test: device ABI: config writes filtered, MSI-X table hidden', 'DMA confined by the IOMMU',
                                'devmgr: test: virtio-blk: 2048 sectors', 'write + read back OK', 'devmgr: test: interrupt delivery: virtio-blk',
                                'devmgr: test: virtio-blk.ddrv crashed and was restarted; I/O works again', 'IOMMU: blocked DMA access by 00:03.0 at ',
                                'devmgr: test: DMA outside the driver''s pins blocked by the IOMMU', 'devmgr: test: virtio-blk recovered after the DMA test',
                                "devmgr: test: keyboard: 'virtio' typed on virtio-input", 'devmgr: test PASSED', 'init: devmgr exited with code 0', 'KTEST drivers: kernel memory at 0x100000 unchanged', 'KTEST drivers: PASSED')
                     Forbid = @('KERNEL PANIC', 'FAIL', 'PANIC', 'unusable'); Timeout = 90
                     Keys = @('v', 'i', 'r', 't', 'i', 'o', 'ret'); KeysAfter = 'devmgr: test: waiting for keys' }
    storage     = @{ Define = 'STORAGE';     Devices = $true; Timeout = 300; Post = 'Test-StorageImages'
                     Expect = @('ahci: port 1:', 'nvme: NVMe', 'storaged: volume ''boot'': FAT32', 'storaged: volume ''system'': DFS', 'storaged: volume ''data'': DFS',
                                'partition 2 (''Basic data partition''): NTFS, not supported (left alone)',
                                'init: 4 volume(s)', 'fstest: fat32:', 'fstest: dfs:', 'BENCH storage: DFS write 1 MiB', 'fstest: snapshots:', 'fstest: child:',
                                'fstest: code signing: hello.dx from the boot volume', 'fstest: namespace isolation:', 'fstest: rename: DFS and FAT32', 'fstest: rename: power cut at 6 points', 'fstest: power cut:', 'fstest: corruption:', 'fstest: PASSED', 'init: fstest exited with code 0')
                     Forbid = @('KERNEL PANIC', 'FAIL', 'PANIC') }
    # The service manager (init "services test"): manifests embedded and on disk (signed, unsigned,
    # tampered), refusals named, exact grants and quotas (ltest inside the services), restart with
    # backoff and giving up, storaged then devmgr killed with I/O working again, then shutdown in
    # reverse start order and power-off.
    services    = @{ Define = 'SERVICES';    Devices = $true; Timeout = 120; MustExit = $true
                     Expect = @('init: service storaged accepted', 'init: service devmgr accepted', "unknown key 'grants.kernel-memory'",
                                'init: manifest svc-badcap.dman refused: it asks for endpoint nosuch.secrets, which no service provides',
                                'init: manifest esp:/DOS/SERVICES/TAMPERED.DMAN refused: signature check failed', 'init: manifest esp:/DOS/SERVICES/UNSIGNED.DMAN refused: not signed',
                                'init: service hello accepted (esp:/DOS/SERVICES/HELLO.DMAN)', 'hello: a signed program loaded from disk is running', 'ltest: svc-grants: exactly the granted handles', 'ltest: svc-quota: limits from the manifest',
                                'init: restarting svc-crash in 50 ms (restart 1 of 2)', 'init: restarting svc-crash in 100 ms (restart 2 of 2)', 'init: svc-crash keeps failing: given up after 2 restart(s)',
                                'init: test: storaged killed and restarted', 'devmgr: storage service reconnected', 'init: test: devmgr killed and restarted',
                                'log: running:', 'clock: ', 'terminal: ready', 'shell: ready', 'storaged: file times from the clock service',
                                'svc-log: ', 'no kernel address (', 'levels applied (warn kept, info dropped)',
                                'init: stopping devmgr', 'devmgr: shutdown:', 'init: stopping storaged', 'storaged: shutdown:', 'init: shutdown: every service stopped', 'init: test: PASSED', 'Power: switching off')
                     Forbid = @('KERNEL PANIC', 'test FAIL', 'svc FAIL', 'PANIC', 'could not measure', 'sync failed', 'did not confirm', 'did not stop in time'); Post = 'Test-ServicesOrder' }
    # The wall-clock time across a reboot (init "time test"): the clock service (CMOS RTC under
    # BIOS, the UEFI boot-time record under UEFI), file times on DFS and FAT32. The first boot
    # records the time; the host then boots the same disks again (Test-TimeReboot).
    time        = @{ Define = 'TIME';        Devices = $true; Timeout = 120; MustExit = $true; Post = 'Test-TimeReboot'
                     Expect = @('(from the CMOS real-time clock)', 'svc-time: wall-clock time ', 'svc-time: first boot: the time is recorded on DFS (/data) and FAT32 (/boot)', 'init: time test: first boot done', 'Power: switching off')
                     Forbid = @('KERNEL PANIC', 'svc FAIL', 'PANIC', 'test FAIL', 'FAILED') }
    'time-uefi' = @{ Define = 'TIME';        Devices = $true; Uefi = $true; Timeout = 180; MustExit = $true; Post = 'Test-TimeRebootUefi'
                     Expect = @('(from UEFI GetTime at boot)', 'svc-time: first boot: the time is recorded', 'init: time test: first boot done', 'Power: switching off')
                     Forbid = @('KERNEL PANIC', 'svc FAIL', 'PANIC', 'test FAIL', 'FAILED') }
    # The terminal and the shell (init "shell test": writable disks, the terminal mirrored to serial):
    # a session typed on the keyboard. Places, file tools with declared rights, filters over records,
    # a path outside the namespace refused, completion, the services, the log, then power off.
    shell       = @{ Define = 'SHELL';       Devices = $true; Timeout = 180; MustExit = $true; KeysAfter = 'shell: ready'
                     Keys = (ConvertTo-QemuKeys @('places', 'go data', 'make notes', 'copy /boot/README.TXT notes', 'list notes | where size > 10 | pick name size',
                                                 'show notes/README.TXT', 'move notes/README.TXT notes/readme.txt', 'copy notes/readme.txt /nowhere/x.txt', 'lst',
                                                 'help copy', 'tasks | where kind = service | where state = running | count', 'log | where source = shell | take 1',
                                                 'objects | where type = channel | count', 'delete notes/readme.txt notes', 'go /sy<tab>', 'time', 'power off'))
                     Expect = @('terminal: display 80x25 VGA text', 'shell: ready: 4 place(s): /boot (read-write), /data (read-write), /esp (read-write), /system (read-write); 6 tool(s)',
                                'terminal| / > places', 'terminal|  place', 'terminal| data > make notes', 'terminal| v made /data/notes', 'terminal| v copied /data/notes/README.TXT (58 B)',
                                'terminal|  README.TXT', 'terminal| D-OS boot volume (FAT32). Written by dosimg on the host.', 'terminal| v moved /data/notes/README.TXT to /data/notes/readme.txt',
                                "terminal| x copy: /nowhere/x.txt is not in this session's namespace", "terminal| x unknown command 'lst' - did you mean 'list'?",
                                'terminal|   usage: copy <from> <to>', 'terminal|  count', 'shell: ready: 4 place(s)', 'terminal| v deleted /data/notes/readme.txt', 'terminal| v deleted /data/notes',
                                'terminal| system > time', ' UTC', 'init: shell asked to switch off', 'init: shutdown: every service stopped', 'Power: switching off')
                     Forbid = @('KERNEL PANIC', 'PANIC', 'user fault', 'crashed', 'cannot start') }
    poweroff    = @{ Define = 'POWEROFF';    Expect = @('Power: power-off by ACPI S5', 'init: power: the VMEX resource is refused (-5)', 'Power: switch-off requested by process init', 'Power: switching off (ACPI S5)'); Forbid = @('KERNEL PANIC', 'FAIL', 'did not switch off', 'system_power returned', 'exited with code'); Timeout = 30; MustExit = $true }
    'poweroff-uefi' = @{ Define = 'POWEROFF'; Uefi = $true; Expect = @('Power: power-off by ACPI S5', 'Power: switching off (ACPI S5)'); Forbid = @('KERNEL PANIC', 'FAIL', 'did not switch off', 'system_power returned', 'exited with code'); Timeout = 60; MustExit = $true }
    reboot      = @{ Define = 'REBOOT';      Expect = @('reset by reset register', 'init: power: the VMEX resource is refused (-5)', 'Power: reset requested by process init', 'Power: resetting'); Forbid = @('KERNEL PANIC', 'FAIL', 'no reset method worked', 'system_power returned', 'exited with code'); Timeout = 30; MustExit = $true }
    hwbench     = @{ Define = 'HWBENCH';     Devices = $true; Uefi = $true; Timeout = 240; Post = 'Test-DisksUnchanged'
                     Expect = @('lock-order checking off', 'BENCH kmalloc+kfree 32 B', 'BENCH thread_yield round trip', 'KTEST bench: DONE', 'BENCH user: null syscall round trip',
                                'BENCH user: channel call round trip', 'BENCH fs: /esp: sequential read of /DOS/KERNEL.BIN', 'BENCH fs: /esp: random 4 KiB reads', 'fstest: bench: 4 volume(s) measured',
                                'D-OS hardware benchmark results', 'Results:', 'KTEST hwbench: DONE')
                     Forbid = @('KERNEL PANIC', 'FAIL', 'PANIC', 'INCOMPLETE') }
    readonly    = @{ Define = 'READONLY';    Devices = $true; Timeout = 120; Post = 'Test-DisksUnchanged'
                     Expect = @('devmgr: disks are read-only', 'storaged: running (read-only', 'storaged: read-only check: ahci:pci-00:1f.2:0: the driver refused a raw write',
                                'storaged: read-only check: ahci:pci-00:1f.2:1: the driver refused a raw write', 'storaged: read-only check: nvme:pci-00:04.0:0: the driver refused a raw write',
                                'storaged: read-only check: virtio-blk:pci-00:02.0:0: the driver refused a raw write', 'init: 4 volume(s)',
                                'fstest: readonly: /boot:', 'fstest: readonly: /system:', 'fstest: readonly: /data:', 'fstest: readonly: /esp:', 'fstest: readonly PASSED', 'init: fstest readonly exited with code 0')
                     Forbid = @('KERNEL PANIC', 'FAIL', 'PANIC') }
    manydevices = @{ Define = $null;         Qemu = (Get-ManyDeviceArgs 64); Timeout = 30
                     Expect = @('PCI 00:0f.7', 'PCI 00:1f.2', '69 functions', 'Devices: 72 for user-space drivers', 'User: init started in ring 3', 'init: started devmgr with 70 devices', 'devmgr: 70 devices, 2 with a driver', 'init: 1 volume(s)', 'devmgr: running')
                     Forbid = @('KERNEL PANIC', 'cannot start init', 'left out', 'FAIL', 'not used: the limit') }
    'storage-host' = @{ Host = 'Test-DosfsHost' }
    'crypto-host' = @{ Host = 'Test-CryptoHost' }
    'manifest-host' = @{ Host = 'Test-ManifestHost' }
    'uefi-badsig' = @{ Define = $null;       Uefi = $true; Tamper = $true; Timeout = 60; Expect = @('D-OS: UEFI loader', 'D-OS: kernel signature check failed: content does not match the signature', 'refusing to boot an unverified kernel'); Forbid = @('D-KRNL 1.', 'kernel signature valid') }
    'bios-badsig' = @{ Define = $null;       Tamper = $true; Expect = @('D-OS: stage2 OK', 'D-OS: stage3: kernel signature check failed: content does not match the signature', 'refusing to boot an unverified kernel'); Forbid = @('D-KRNL 1.', 'kernel signature valid') }
    kaslr       = @{ Define = 'KASLR';       Expect = @('D-OS: stage3: kernel relocated (KASLR', 'KTEST kaslr: layout image 0xffffff', 'KTEST kaslr: PASSED', 'D-KRNL: ready'); Forbid = @('KERNEL PANIC', 'FAIL'); Post = 'Test-KaslrReboots' }
    'kaslr-host' = @{ Host = 'Test-KaslrHost' }
    # Static analysis: clang's analyzer over every C file (kernel in its release and
    # two test configurations, loaders, user programs) and clippy with -D warnings over every Rust crate.
    # Clean = no finding at all.
    static      = @{ Host = 'Test-StaticAnalysis' }
    roinit      = @{ Define = 'ROINIT';      Expect = @('Page fault (#PF)', 'protection violation (present), write, kernel', 'write to read-only-after-init kernel data', $Halted); Forbid = @('FAILED') }
    bounds      = @{ Define = 'BOUNDS';      Expect = @('Invalid opcode (#UD)', 'UBSan: undefined behaviour: index out of bounds', 'bounds_read', $Halted); Forbid = @('FAILED') }
    objects     = @{ Define = 'OBJECTS';    Expect = @('out of memory (C): thread_create', 'rights: enforced', 'cycles: unreachable channel cycles collected', 'quotas: handles, memory, threads', 'each failed cleanly with no leak', 'KTEST objects: PASSED'); Forbid = @('KERNEL PANIC', 'FAIL'); Timeout = 60 }
}

# ---------------------------------------------------------------------------
# Tool discovery
# ---------------------------------------------------------------------------
function Find-Tool([string]$Name, [string[]]$Fallbacks) {
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($dir in $Fallbacks) {
        $p = Join-Path $dir "$Name.exe"
        if (Test-Path $p) { return $p }
    }
    throw "Required tool '$Name' not found. See docs/building.md for setup."
}

$LlvmDirs = @("$env:ProgramFiles\LLVM\bin")
$QemuDirs = @("$env:ProgramFiles\qemu")

function Invoke-Native([string]$Exe, [string[]]$ArgList) {
    Write-Verbose "$Exe $($ArgList -join ' ')"
    # stderr is merged as plain text (cargo reports progress there; PS 5.1 would treat it as errors),
    # and never leaks into function return values.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $Exe @ArgList 2>&1 | ForEach-Object { "$_" } | Out-Host }
    finally { $ErrorActionPreference = $prev }
    if ($LASTEXITCODE -ne 0) {
        throw "$(Split-Path $Exe -Leaf) failed with exit code $LASTEXITCODE"
    }
}

function Get-PaddedBytes([string]$Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    $padded = [Math]::Ceiling($bytes.Length / $SectorSize) * $SectorSize
    if ($padded -eq $bytes.Length) { return ,$bytes }
    $out = New-Object byte[] $padded
    [Array]::Copy($bytes, $out, $bytes.Length)
    return ,$out
}

function Get-RelPath([string]$Path) { $Path.Substring($Root.Length + 1) }

# ---------------------------------------------------------------------------
# Rust toolchain: cargo on PATH, else a devbox (portable, nothing installed system-wide).
# The toolchain version itself is pinned by rust-toolchain.toml (rustup installs it on demand).
# ---------------------------------------------------------------------------
$script:Cargo = $null
function Initialize-Rust {
    if ($script:Cargo) { return $script:Cargo }
    $cmd = Get-Command cargo -ErrorAction SilentlyContinue
    if (-not $cmd) {
        $boxes = @($env:DOS_RUST_BOX, (Join-Path (Split-Path $Root -Parent) 'Devbox\boxes\rust')) | Where-Object { $_ }
        $box = $boxes | Where-Object { Test-Path (Join-Path $_ 'cargo\bin\cargo.exe') } | Select-Object -First 1
        if (-not $box) {
            throw "Rust toolchain not found. Create a devbox: D:\Dev\Devbox\devbox.cmd new rust (or set DOS_RUST_BOX)."
        }
        $env:RUSTUP_HOME = Join-Path $box 'rustup'
        $env:CARGO_HOME  = Join-Path $box 'cargo'
        $env:PATH = "$(Join-Path $box 'cargo\bin');$(Join-Path $box 'mingw64\bin');$env:PATH"
        $cmd = Get-Command cargo
    }
    $script:Cargo = $cmd.Source
    return $script:Cargo
}

# Builds kernel/rust (staticlib) into $OutDir\rust and returns the library path.
# Test variants get --cfg ktest --cfg ktest_<case> (Rust twin of -DKTEST -DKTEST_<CASE>).
function Invoke-RustBuild([string]$OutDir, [string]$KernelTest, [switch]$Quiet) {
    $cargo = Initialize-Rust
    $crate = Join-Path $Root 'kernel\rust'
    $targetDir = Join-Path $OutDir 'rust'
    $rustc = @(
        # Reproducibility: no absolute paths; panic locations read kernel/rust/src/...
        "--remap-path-prefix=$crate\=kernel/rust/",
        "--remap-path-prefix=$Root\=",
        '--remap-path-prefix=src\=kernel/rust/src/',
        '--remap-path-prefix=src/=kernel/rust/src/'
    )
    if ($KernelTest) { $rustc += @('--cfg', 'ktest', '--cfg', "ktest_$($KernelTest.ToLowerInvariant())") }
    $cargoArgs = @('rustc', '--release', '--locked', '--target-dir', $targetDir)
    if ($Quiet) { $cargoArgs += '--quiet' }
    Push-Location $crate      # rust-toolchain.toml and .cargo/config.toml are found from here
    try {
        Invoke-Native $cargo ($cargoArgs + @('--') + $rustc)
    } finally { Pop-Location }
    $lib = Join-Path $targetDir 'x86_64-unknown-none\release\libdkrnl.a'
    if (-not (Test-Path $lib)) { throw "cargo did not produce $lib" }
    return $lib
}

# ---------------------------------------------------------------------------
# Build
#   OutDir      : output directory (release: build\)
#   KernelTest  : optional ktest selector -> -DKTEST -DKTEST_<name>
# Returns the image path.
# ---------------------------------------------------------------------------
function Invoke-Build([string]$OutDir = $Build, [string]$KernelTest = $null, [switch]$Quiet, [switch]$Ubsan, [switch]$Kasan) {
    $nasm    = Find-Tool 'nasm'
    $clang   = Find-Tool 'clang' $LlvmDirs
    $lld     = Find-Tool 'ld.lld' $LlvmDirs
    $objcopy = Find-Tool 'llvm-objcopy' $LlvmDirs

    $objDir = Join-Path $OutDir 'obj'
    New-Item -ItemType Directory -Force $objDir | Out-Null
    $image = Join-Path $OutDir 'discrete.img'
    function Log([string]$m) { if (-not $Quiet) { Write-Host $m } }

    # --- Kernel ------------------------------------------------------------
    $cflags = @(
        '--target=x86_64-elf', '-std=c17', '-O2', '-g',
        '-ffreestanding', '-fno-builtin', '-nostdinc', '-isystem', (Get-ClangResourceInclude $clang),
        '-fpie', '-fno-omit-frame-pointer',   # position-independent: KASLR (docs/boot.md)
        '-mno-red-zone', '-mno-mmx', '-mno-sse', '-mno-sse2', '-mno-80387',
        # Hardening (docs/hardening.md)
        '-fstack-protector-strong', '-mstack-protector-guard=global',
        '-ftrivial-auto-var-init=zero', '-fzero-call-used-regs=used-gpr', '-fno-common',
        '-Xclang', '-fstack-clash-protection',  # big frames probe page by page: no jumping a guard page (the driver flag is Linux-only)
        '-fno-delete-null-pointer-checks',      # a NULL check is never optimized away
        '-fstrict-flex-arrays=3', '-fsanitize=array-bounds', '-fsanitize-trap=array-bounds',   # fixed-size arrays bounds-checked (trap)
        '-Wframe-larger-than=4096',             # kernel stacks are 16 KiB
        '-mretpoline-external-thunk',           # Spectre v2: indirect branches via thunk.asm (patched out on eIBRS/AutoIBRS)
        # Reproducibility: no absolute build paths in debug info or __FILE__
        "-ffile-prefix-map=$Root\=",
        '-Wall', '-Wextra', '-Werror', '-Wshadow', '-Wstrict-prototypes', '-Wmissing-prototypes', '-Wvla',
        '-I', (Join-Path $Root 'kernel\include')
    )
    if ($KernelTest) { $cflags += @('-DKTEST', "-DKTEST_$KernelTest") }
    # UBSan, trap mode: no runtime library; every failed check is a `ud1` the #UD handler decodes.
    # `function` is left out: it puts type data in front of every function.
    if ($Ubsan) { $cflags += @('-fsanitize=undefined', '-fsanitize-trap=undefined', '-fno-sanitize=function', '-DKTEST_UBSAN') }
    # KASAN: outline checks (a call per load/store) against the heap shadow; no globals or stack
    # instrumentation. The heap, the string routines and the checker itself stay uninstrumented.
    $kasanFlags = @()
    if ($Kasan) {
        $cflags += '-DKTEST_KASAN'
        $kasanFlags = @('-fsanitize=kernel-address', '-mllvm', '-asan-instrumentation-with-call-threshold=0',
                        '-mllvm', '-asan-globals=0', '-mllvm', '-asan-stack=0', '-mllvm', '-asan-use-after-return=never')
    }
    $kasanSkip = @('heap.c', 'string.c', 'kasan.c')

    $objects = @()
    $kernelSrc = Join-Path $Root 'kernel'
    $objName = { param($f, $ext) ((Get-RelPath $f.FullName) -replace '[\\/]', '_') + $ext }

    Get-ChildItem $kernelSrc -Recurse -Filter *.asm | Sort-Object FullName | ForEach-Object {
        $obj = Join-Path $objDir (& $objName $_ '.o')
        Log "  NASM  $(Get-RelPath $_.FullName)"
        Invoke-Native $nasm @('-f', 'elf64', '-g', '-F', 'dwarf', '-o', $obj, $_.FullName)
        $objects += $obj
    }

    # --- Verified boot: the public key this build trusts (docs/signing.md) ---------------
    $key = Get-SigningKey
    $trustC = Join-Path $objDir 'trust.c'
    Write-TrustC $trustC $key
    $trustObj = Join-Path $objDir 'trust.o'
    Invoke-Native $clang ($cflags + @('-c', '-o', $trustObj, $trustC))
    $objects += $trustObj

    Get-ChildItem $kernelSrc -Recurse -Filter *.c | Sort-Object FullName | ForEach-Object {
        $obj = Join-Path $objDir (& $objName $_ '.o')
        Log "  CC    $(Get-RelPath $_.FullName)"
        $extra = if ($Kasan -and $_.Name -notin $kasanSkip) { $kasanFlags } else { @() }
        Invoke-Native $clang ($cflags + $extra + @('-c', '-o', $obj, $_.FullName))
        $objects += $obj
    }

    Log '  CARGO kernel\rust (dkrnl)'
    $rustLib = Invoke-RustBuild -OutDir $OutDir -KernelTest $KernelTest -Quiet:$Quiet

    # --- User programs (ring 3), embedded in the kernel image (no filesystem yet) ---------
    $programs = Invoke-UserBuild -OutDir $OutDir -Clang $clang -Lld $lld -Log ${function:Log}
    # Service manifests (docs/services.md) ride along: the system ones in every image, the service
    # manager's test ones only in its test image. The kernel hands them to init as MANIFEST VMOs.
    $manDir = Join-Path $Root 'user\init\services'
    $manifests = @(Get-ChildItem $manDir -Filter *.dman -File | Sort-Object Name)
    # Tool manifests (docs/shell.md): the shell's commands and the rights each parameter gets.
    $manifests += @(Get-ChildItem (Join-Path $Root 'user\tools\manifests') -Filter *.dman -File | Sort-Object Name)
    $testMan = @{ 'SERVICES' = 'test'; 'TIME' = 'time' }[$KernelTest]
    if ($testMan) { $manifests += @(Get-ChildItem (Join-Path $manDir $testMan) -Filter *.dman -File | Sort-Object Name) }
    $programs = @($programs) + @($manifests | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Path = $_.FullName } })
    $progAsm = Join-Path $objDir 'programs.asm'
    $progObj = Join-Path $objDir 'programs.o'
    Write-ProgramsAsm $progAsm $programs
    Invoke-Native $nasm @('-f', 'elf64', '-o', $progObj, $progAsm)
    $objects += $progObj

    # --- Link twice: the second link carries the kernel symbol table (symbolized backtraces).
    # The table sits after .rodata, so .text (and every function address) is the same in both.
    $kernelElf = Join-Path $OutDir 'kernel.elf'
    $kernelBin = Join-Path $OutDir 'kernel.bin'
    $ksymsBin = Join-Path $objDir 'ksyms.bin'
    $ksymsAsm = Join-Path $objDir 'ksyms.asm'
    $ksymsObj = Join-Path $objDir 'ksyms.o'
    $nm = Find-Tool 'llvm-nm' $LlvmDirs
    # Static PIE: the loader relocates the image (KASLR) from its packed RELR table; -z text
    # refuses any relocation in code.
    $linkArgs = @('-T', (Join-Path $Root 'kernel\linker.ld'), '-nostdlib', '-pie', '--no-dynamic-linker',
        '-z', 'pack-relative-relocs', '-z', 'text', '-z', 'noexecstack', '--build-id=none',
        '-z', 'max-page-size=0x1000', '--gc-sections', '-Map', (Join-Path $OutDir 'kernel.map'), '-o', $kernelElf)
    [IO.File]::WriteAllBytes($ksymsBin, (New-KsymsBlob @()))
    [IO.File]::WriteAllText($ksymsAsm, "section .ksyms progbits alloc noexec nowrite align=8`nincbin `"$($ksymsBin -replace '\\', '/')`"`n")
    Invoke-Native $nasm @('-f', 'elf64', '-o', $ksymsObj, $ksymsAsm)
    Log '  LD    kernel.elf (pass 1)'
    Invoke-Native $lld ($linkArgs + $objects + @($ksymsObj, $rustLib))
    $blob = New-KsymsBlob (Get-KernelSymbols $nm $kernelElf)
    [IO.File]::WriteAllBytes($ksymsBin, $blob)
    Invoke-Native $nasm @('-f', 'elf64', '-o', $ksymsObj, $ksymsAsm)
    Log '  LD    kernel.elf (pass 2, with symbol table)'
    Invoke-Native $lld ($linkArgs + $objects + @($ksymsObj, $rustLib))
    $check = New-KsymsBlob (Get-KernelSymbols $nm $kernelElf)
    if ([Convert]::ToBase64String($check) -ne [Convert]::ToBase64String($blob)) {
        throw 'kernel symbol table: function addresses moved between the two links'
    }
    Invoke-Native $objcopy @('-O', 'binary', $kernelElf, $kernelBin)
    $kernelSig = Join-Path $OutDir 'kernel.dsig'
    Log '  SIGN  kernel.bin (Ed25519)'
    Invoke-Native (Get-Dosimg) @('sign', $key.Seed, 'kernel', 'KERNEL.BIN', $kernelBin, $kernelSig)

    $kernelBytes   = Get-PaddedBytes $kernelBin
    $kernelSectors = $kernelBytes.Length / $SectorSize

    # --- Bootloader ----------------------------------------------------------
    $layoutDefs = @(
        '-i', ((Join-Path $Root 'boot') + '\'),
        "-DSTAGE2_LBA=$Stage2Lba", "-DSTAGE2_SECTORS=$Stage2Sectors",
        "-DSTAGE3_LBA=$Stage3Lba", "-DSTAGE3_SECTORS=$Stage3Sectors", "-DKSIG_LBA=$KsigLba",
        "-DKERNEL_LBA=$KernelLba", "-DKERNEL_SECTORS=$kernelSectors"
    )
    $stage1Bin = Join-Path $OutDir 'stage1.bin'
    Log '  NASM  boot\stage1.asm'
    Invoke-Native $nasm (@('-f', 'bin', '-o', $stage1Bin) + $layoutDefs + @((Join-Path $Root 'boot\stage1.asm')))

    $stage1Bytes = [IO.File]::ReadAllBytes($stage1Bin)
    if ($stage1Bytes.Length -ne $SectorSize) { throw "stage1.bin must be exactly 512 bytes (got $($stage1Bytes.Length))" }

    $stage2Bin = Join-Path $OutDir 'stage2.bin'
    Log '  NASM  boot\stage2.asm'
    Invoke-Native $nasm (@('-f', 'bin', '-o', $stage2Bin) + $layoutDefs + @((Join-Path $Root 'boot\stage2.asm')))
    $stage2Bytes = Get-PaddedBytes $stage2Bin
    if ($stage2Bytes.Length -gt $Stage2Sectors * $SectorSize) {
        throw "stage2.bin is $($stage2Bytes.Length) bytes; reserved area is $($Stage2Sectors * $SectorSize)"
    }

    # --- UEFI loader --------------------------------------------------------------
    $stage3Bin = Invoke-Stage3Build -OutDir $OutDir -Clang $clang -Lld $lld -Objcopy $objcopy -TrustC $trustC -Log ${function:Log}
    $efi = Invoke-UefiBuild -OutDir $OutDir -Clang $clang -Nasm $nasm -TrustC $trustC -Log ${function:Log}

    # --- A signed program on the boot volume (the code-signing test loads it from disk) -----
    $hello = (@($programs) | Where-Object Name -eq 'hello.dx' | Select-Object -First 1).Path
    $helloSig = Join-Path $OutDir 'hello.dsig'
    Invoke-Native (Get-Dosimg) @('sign', $key.Seed, 'program', 'hello.dx', $hello, $helloSig)
    $extraFiles = @("DOS/APPS/HELLO.DX=$hello", "DOS/APPS/HELLO.DSIG=$helloSig")
    if ($KernelTest -eq 'SERVICES') {
        # Manifests on the boot volume for the service manager's test: one signed, one unsigned, one
        # whose content changed after it was signed.
        $svcDir = Join-Path $OutDir 'services'
        New-Item -ItemType Directory -Force $svcDir | Out-Null
        $src = Join-Path $Root 'user\init\services\disk\hello.dman'
        $sig = Join-Path $svcDir 'HELLO.DSIG'
        Invoke-Native (Get-Dosimg) @('sign', $key.Seed, 'manifest', 'hello.dman', $src, $sig)
        $unsigned = Join-Path $svcDir 'UNSIGNED.DMAN'
        [IO.File]::WriteAllText($unsigned, ([IO.File]::ReadAllText($src) -replace 'name = "hello"', 'name = "unsigned"'))
        $tampered = Join-Path $svcDir 'TAMPERED.DMAN'
        [IO.File]::WriteAllText($tampered, ([IO.File]::ReadAllText($src) -replace 'name = "hello"', 'name = "tampered"'))
        $tsig = Join-Path $svcDir 'TAMPERED.DSIG'
        Invoke-Native (Get-Dosimg) @('sign', $key.Seed, 'manifest', 'tampered.dman', $tampered, $tsig)
        [IO.File]::AppendAllText($tampered, "# changed after it was signed`n")
        $extraFiles += @("DOS/SERVICES/HELLO.DMAN=$src", "DOS/SERVICES/HELLO.DSIG=$sig", "DOS/SERVICES/UNSIGNED.DMAN=$unsigned",
                         "DOS/SERVICES/TAMPERED.DMAN=$tampered", "DOS/SERVICES/TAMPERED.DSIG=$tsig")
    }

    # --- Disk image (BIOS + UEFI, GPT) ----------------------------------------------
    Log '  IMAGE discrete.img (dosimg boot)'
    $dosimg = Get-Dosimg
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { $made = & $dosimg boot $image $stage1Bin $stage2Bin $stage3Bin $kernelBin $kernelSig $efi @extraFiles 2>&1 | ForEach-Object { "$_" } }
    finally { $ErrorActionPreference = $prev }
    if ($LASTEXITCODE -ne 0) { throw "dosimg boot failed: $made" }
    $size = (Get-Item $image).Length

    # --- Hashes of shipped artifacts (reproducible-build check / integrity) -------
    $sums = foreach ($f in @($image, $stage1Bin, $stage2Bin, $stage3Bin, $kernelBin, $kernelSig, $efi)) {
        '{0}  {1}' -f (Get-FileHash -Algorithm SHA256 $f).Hash.ToLowerInvariant(), (Split-Path $f -Leaf)
    }
    [IO.File]::WriteAllText((Join-Path $OutDir 'SHA256SUMS'), (($sums -join "`n") + "`n"))

    Log ("Built {0} ({1} MiB, BIOS + UEFI; kernel {2} sectors @ LBA {3}, UEFI loader {4} KiB)" -f (Get-RelPath $image), ($size / 1MB), $kernelSectors, $KernelLba, [Math]::Ceiling((Get-Item $efi).Length / 1KB))
    Log "  sha256 $($sums[0])"
    return $image
}

# ---------------------------------------------------------------------------
# Signing key (docs/signing.md): a 32-byte Ed25519 seed. $env:DOS_SIGNING_KEY names a key file (a
# release key kept off this machine's build tree); otherwise build\keys\dev-signing.seed, created
# from the OS's CSPRNG on first use and never committed. Every build in this tree uses the same key,
# so the reproducible-build check compares like with like.
# ---------------------------------------------------------------------------
$script:SigningKey = $null
function Get-SigningKey {
    if ($script:SigningKey) { return $script:SigningKey }
    $seed = $env:DOS_SIGNING_KEY
    if (-not $seed) {
        $dir = Join-Path $Build 'keys'
        New-Item -ItemType Directory -Force $dir | Out-Null
        $seed = Join-Path $dir 'dev-signing.seed'
        if (-not (Test-Path $seed)) {
            $b = [byte[]]::new(32)
            [Security.Cryptography.RandomNumberGenerator]::Fill($b)
            $tmp = "$seed.$PID.tmp"
            [IO.File]::WriteAllBytes($tmp, $b)
            try { [IO.File]::Move($tmp, $seed) } catch { Remove-Item $tmp -ErrorAction SilentlyContinue }   # another build won
            Write-Host "  KEY   new development signing key: $(Get-RelPath $seed) (not committed; set DOS_SIGNING_KEY for a release key)"
        }
    }
    if ((Get-Item $seed).Length -ne 32) { throw "signing key $seed must be 32 bytes" }
    $pub = (& (Get-Dosimg) pubkey $seed | Select-Object -Last 1).Trim()
    if ($LASTEXITCODE -ne 0 -or $pub -notmatch '^[0-9a-f]{64}$') { throw "dosimg pubkey failed for $seed" }
    $script:SigningKey = [pscustomobject]@{ Seed = $seed; Public = $pub }
    return $script:SigningKey
}

# The public key compiled into the loaders and the kernel.
function Write-TrustC([string]$Path, $Key) {
    $bytes = for ($i = 0; $i -lt 64; $i += 2) { '0x' + $Key.Public.Substring($i, 2) }
    $text = "/* generated by build.ps1: the D-OS signing key this build trusts (Ed25519 public key) */`n" +
            "#include <stdint.h>`n" +
            "const uint8_t dos_trusted_key[32] = { $($bytes -join ', ') };`n"
    [IO.File]::WriteAllText($Path, $text)
}

# BIOS stage 3 (boot\stage3): the C signature verifier stage 2 calls before the kernel. A flat
# binary at 0x20000 (stage3.ld), built from stage3.c + boot\common\dcrypto.c + trust.c.
function Invoke-Stage3Build([string]$OutDir, [string]$Clang, [string]$Lld, [string]$Objcopy, [string]$TrustC, [scriptblock]$Log) {
    $obj = Join-Path $OutDir 'obj'
    $flags = @('--target=x86_64-elf', '-std=c17', '-Os', '-g0', '-ffreestanding', '-fno-builtin', '-nostdinc',
        '-isystem', (Get-ClangResourceInclude $Clang), '-fno-pic', '-fno-pie', '-mcmodel=small', '-mno-red-zone',
        '-mgeneral-regs-only', '-fno-stack-protector', '-fno-asynchronous-unwind-tables', "-ffile-prefix-map=$Root\=",
        '-Wall', '-Wextra', '-Werror', '-I', (Join-Path $Root 'boot\common'))
    $objs = @()
    foreach ($src in @((Join-Path $Root 'boot\stage3\stage3.c'), (Join-Path $Root 'boot\common\dcrypto.c'), (Join-Path $Root 'boot\common\kaslr.c'), $TrustC)) {
        $o = Join-Path $obj ("stage3_" + [IO.Path]::GetFileNameWithoutExtension($src) + '.o')
        & $Log "  CC    $(if ($src.StartsWith($Root)) { Get-RelPath $src } else { Split-Path $src -Leaf }) [stage 3]"
        Invoke-Native $Clang ($flags + @('-c', '-o', $o, $src))
        $objs += $o
    }
    $elf = Join-Path $OutDir 'stage3.elf'
    $bin = Join-Path $OutDir 'stage3.bin'
    Invoke-Native $Lld (@('-T', (Join-Path $Root 'boot\stage3\stage3.ld'), '-nostdlib', '-static', '--build-id=none',
        '-z', 'max-page-size=0x1000', '-o', $elf) + $objs)
    Invoke-Native $Objcopy @('-O', 'binary', $elf, $bin)
    return $bin
}

# ---------------------------------------------------------------------------
# UEFI loader: boot\uefi\loader.c + handoff.asm -> $OutDir\BOOTX64.EFI (PE32+ EFI application),
# clang for x86_64-windows (the UEFI calling convention) and lld-link. /Brepro: reproducible bytes.
# ---------------------------------------------------------------------------
function Invoke-UefiBuild([string]$OutDir, [string]$Clang, [string]$Nasm, [string]$TrustC, [scriptblock]$Log) {
    $lldLink = Find-Tool 'lld-link' $LlvmDirs
    $src = Join-Path $Root 'boot\uefi'
    $obj = Join-Path $OutDir 'obj'
    $handoffObj = Join-Path $obj 'uefi_handoff.o'
    $efi = Join-Path $OutDir 'BOOTX64.EFI'
    $flags = @('--target=x86_64-unknown-windows', '-std=c17', '-O2', '-g0', '-ffreestanding', '-fno-builtin',
        '-nostdinc', '-isystem', (Get-ClangResourceInclude $Clang), '-fno-stack-protector', '-fshort-wchar', '-mno-red-zone',
        '-mgeneral-regs-only', "-ffile-prefix-map=$Root\=", '-Wall', '-Wextra', '-Werror', '-Wshadow')
    $objs = @()
    foreach ($c in @((Join-Path $src 'loader.c'), (Join-Path $Root 'boot\common\dcrypto.c'), (Join-Path $Root 'boot\common\kaslr.c'), $TrustC)) {
        $o = Join-Path $obj ('uefi_' + [IO.Path]::GetFileNameWithoutExtension($c) + '.o')
        & $Log "  CC    $(if ($c.StartsWith($Root)) { Get-RelPath $c } else { Split-Path $c -Leaf }) [UEFI]"
        Invoke-Native $Clang ($flags + @('-c', '-o', $o, $c))
        $objs += $o
    }
    & $Log '  NASM  boot\uefi\handoff.asm'
    Invoke-Native $Nasm @('-f', 'win64', '-o', $handoffObj, (Join-Path $src 'handoff.asm'))
    & $Log '  LINK  BOOTX64.EFI'
    Invoke-Native $lldLink (@('/nologo', '/subsystem:efi_application', '/entry:efi_main', '/nodefaultlib', '/Brepro',
        '/dynamicbase', '/nxcompat', '/debug:none', "/out:$efi", $handoffObj) + $objs)
    return $efi
}

# ---------------------------------------------------------------------------
# User programs: user\<name>\*.c + user\lib\*.c -> $OutDir\user\<name>.dx (static PIE ELF64).
# Freestanding C against the ABI header (user\include\dos.h); stripped and without build ids
# or paths, so the embedded bytes are reproducible. A C program that includes libd.h is also
# linked with libd (the Rust runtime built as a static library with its C API, once per build).
# ---------------------------------------------------------------------------
function Invoke-UserBuild([string]$OutDir, [string]$Clang, [string]$Lld, [scriptblock]$Log) {
    $userSrc = Join-Path $Root 'user'
    $outUser = Join-Path $OutDir 'user'
    New-Item -ItemType Directory -Force $outUser | Out-Null
    $ucflags = @(
        '--target=x86_64-unknown-elf', '-std=c17', '-O2', '-g0',
        '-ffreestanding', '-nostdinc', '-isystem', (Get-ClangResourceInclude $Clang),
        '-fpie', '-fno-plt', '-fno-stack-protector', '-fno-asynchronous-unwind-tables', '-fno-unwind-tables',
        '-fno-common', "-ffile-prefix-map=$Root\=",
        '-Wall', '-Wextra', '-Werror', '-Wshadow', '-Wno-unused-parameter',
        '-I', (Join-Path $userSrc 'include')
    )
    $lib = @(Get-ChildItem (Join-Path $userSrc 'lib') -Filter *.c | Sort-Object Name)
    $progs = @(Get-ChildItem $userSrc -Directory | Where-Object { $_.Name -notin @('include', 'lib') } | Sort-Object Name)
    $out = @()
    $libdC = $null
    foreach ($p in $progs) {
        if (Test-Path (Join-Path $p.FullName 'Cargo.toml')) {
            $out += Invoke-RustUserBuild -Crate $p -OutDir $OutDir -Lld $Lld -Log $Log
            continue
        }
        $objs = @()
        $libs = @()
        $csrc = @(Get-ChildItem $p.FullName -Filter *.c | Sort-Object Name)
        if (@($csrc | Where-Object { (Get-Content $_.FullName -Raw) -match '#include\s+"libd\.h"' }).Count) {
            if (-not $libdC) { $libdC = Invoke-LibdCBuild -OutDir $OutDir -Log $Log }
            $libs += $libdC
        }
        foreach ($src in ($csrc + $lib)) {
            $o = Join-Path $outUser ("$($p.Name)_$($src.BaseName).o")
            & $Log "  CC    $(Get-RelPath $src.FullName) [user]"
            Invoke-Native $Clang ($ucflags + @('-c', '-o', $o, $src.FullName))
            $objs += $o
        }
        $dx = Join-Path $outUser "$($p.Name).dx"
        & $Log "  LD    user\$($p.Name).dx"
        Invoke-Native $Lld (@('-pie', '--no-dynamic-linker', '-nostdlib', '-e', '_start', '--build-id=none', '-s',
            '-z', 'noexecstack', '-z', 'relro', '-z', 'now', '-z', 'separate-loadable-segments',
            '-z', 'max-page-size=4096', '-o', $dx) + $objs + $(if ($libs.Count) { @('--gc-sections') + $libs } else { @() }))
        $out += [pscustomobject]@{ Name = "$($p.Name).dx"; Path = $dx }
    }
    return @($out) + @(Invoke-CompatBuild -OutDir $OutDir -Clang $Clang -Lld $Lld -Log $Log)
}

# libd for C programs: user\lib\libd built as a static library with feature `capi` (the libd_*
# functions of user\include\libd.h). Returns the library path.
function Invoke-LibdCBuild([string]$OutDir, [scriptblock]$Log) {
    $cargo = Initialize-Rust
    $crate = Join-Path $Root 'user\lib\libd'
    $targetDir = Join-Path $OutDir 'user\rust-libd-c'
    $rustc = @("--remap-path-prefix=$crate\=user/lib/libd/", "--remap-path-prefix=$Root\=",
               '--remap-path-prefix=src\=user/lib/libd/src/', '--remap-path-prefix=src/=user/lib/libd/src/')
    & $Log '  CARGO user\lib\libd [C API]'
    Push-Location $crate      # rust-toolchain.toml and .cargo/config.toml are found from here
    try {
        Invoke-Native $cargo (@('rustc', '--release', '--locked', '--quiet', '--features', 'capi', '--crate-type', 'staticlib',
            '--target-dir', $targetDir, '--') + $rustc)
    } finally { Pop-Location }
    $a = Join-Path $targetDir 'x86_64-unknown-none\release\liblibd.a'
    if (-not (Test-Path $a)) { throw "cargo did not produce $a" }
    return $a
}

# A Rust user program: user\<name>\ (no_std staticlib with its own _start) -> $OutDir\user\<name>.dx,
# linked like the C programs (static PIE, RELATIVE relocations only). Paths are remapped so the
# bytes do not depend on the checkout or the output directory.
function Invoke-RustUserBuild($Crate, [string]$OutDir, [string]$Lld, [scriptblock]$Log) {
    $cargo = Initialize-Rust
    $name = $Crate.Name
    $targetDir = Join-Path $OutDir "user\rust-$name"
    $rustc = @(
        "--remap-path-prefix=$($Crate.FullName)\=user/$name/",
        "--remap-path-prefix=$Root\=",
        "--remap-path-prefix=src\=user/$name/src/",
        "--remap-path-prefix=src/=user/$name/src/"
    )
    & $Log "  CARGO user\$name"
    Push-Location $Crate.FullName      # rust-toolchain.toml and .cargo/config.toml are found from here
    try {
        Invoke-Native $cargo (@('rustc', '--release', '--locked', '--quiet', '--target-dir', $targetDir, '--') + $rustc)
    } finally { Pop-Location }
    $a = Join-Path $targetDir "x86_64-unknown-none\release\lib$name.a"
    if (-not (Test-Path $a)) { throw "cargo did not produce $a" }
    $ldflags = @('-pie', '--no-dynamic-linker', '-nostdlib', '--build-id=none', '-s', '--gc-sections',
        '-z', 'noexecstack', '-z', 'relro', '-z', 'now', '-z', 'separate-loadable-segments', '-z', 'max-page-size=4096')
    $toml = Get-Content (Join-Path $Crate.FullName 'Cargo.toml') -Raw
    $out = @()
    if ($toml -match '(?m)^dx\s*=\s*\[([^\]]*)\]') {
        # Several programs in one crate ([package.metadata.dos] dx = ["list", "show"]): the library
        # linked once per program with its own entry (dx_list, dx_show) -> <name>.dx; no <crate>.dx.
        foreach ($d in @([regex]::Matches($Matches[1], '"([a-z0-9-]+)"') | ForEach-Object { $_.Groups[1].Value })) {
            $dx = Join-Path $OutDir "user\$d.dx"
            & $Log "  LD    user\$d.dx"
            Invoke-Native $Lld ($ldflags + @('-e', "dx_$($d -replace '-', '_')", '-o', $dx, $a))
            $out += [pscustomobject]@{ Name = "$d.dx"; Path = $dx }
        }
        return $out
    }
    $dx = Join-Path $OutDir "user\$name.dx"
    & $Log "  LD    user\$name.dx"
    Invoke-Native $Lld ($ldflags + @('-e', '_start', '-o', $dx, $a))
    $out = @([pscustomobject]@{ Name = "$name.dx"; Path = $dx })
    # User-space drivers in the same crate ([package.metadata.dos] ddrv = ["a", "b-c"]): the same
    # library linked once more per driver with its own entry (ddrv_a, ddrv_b_c) -> <name>.ddrv.
    if ($toml -match '(?m)^ddrv\s*=\s*\[([^\]]*)\]') {
        foreach ($d in @([regex]::Matches($Matches[1], '"([a-z0-9-]+)"') | ForEach-Object { $_.Groups[1].Value })) {
            $ddrv = Join-Path $OutDir "user\$d.ddrv"
            & $Log "  LD    user\$d.ddrv"
            Invoke-Native $Lld ($ldflags + @('-e', "ddrv_$($d -replace '-', '_')", '-o', $ddrv, $a))
            $out += [pscustomobject]@{ Name = "$d.ddrv"; Path = $ddrv }
        }
    }
    return $out
}

# MSVC (cl, link, lib) for the Windows proof programs: $env:DOS_MSVC_BIN, else the newest VC tools of
# the newest Visual Studio with the x64 compiler (vswhere). No developer prompt or Windows SDK is
# needed: the programs include no headers, and import libraries are made from compat\win\*.def.
$script:MsvcBin = $null
function Find-Msvc {
    if ($script:MsvcBin) { return $script:MsvcBin }
    $dir = $env:DOS_MSVC_BIN
    if (-not $dir) {
        $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
        if (-not (Test-Path $vswhere)) { throw 'MSVC not found (no vswhere.exe): install Visual Studio with the C++ x64 tools, or set DOS_MSVC_BIN.' }
        $vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if (-not $vs) { throw 'MSVC not found: no Visual Studio with the C++ x64 tools (or set DOS_MSVC_BIN).' }
        $tools = Get-ChildItem (Join-Path $vs 'VC\Tools\MSVC') -Directory | Sort-Object { [version]$_.Name } | Select-Object -Last 1
        $dir = Join-Path $tools.FullName 'bin\Hostx64\x64'
    }
    foreach ($t in 'cl.exe', 'link.exe', 'lib.exe') {
        if (-not (Test-Path (Join-Path $dir $t))) { throw "MSVC: $t not found in $dir" }
    }
    $script:MsvcBin = $dir
    return $dir
}

# D-CMPL proof programs, embedded next to the .dx programs as unchanged foreign binaries:
#   W1: compat\win\w1.c built with MSVC without a CRT -> w1.exe; variants w1fault.exe (writes to
#       NULL) and w1bad.exe (also imports USER32.dll!MessageBoxA). /Brepro: reproducible bytes.
#   L1: compat\linux\l1.c built with clang for x86_64-linux, a static ET_EXEC at 0x400000 -> l1.
function Invoke-CompatBuild([string]$OutDir, [string]$Clang, [string]$Lld, [scriptblock]$Log) {
    $src = Join-Path $Root 'compat'
    $out = Join-Path $OutDir 'compat'
    New-Item -ItemType Directory -Force $out | Out-Null
    $msvc = Find-Msvc
    $cl = Join-Path $msvc 'cl.exe'; $link = Join-Path $msvc 'link.exe'; $libexe = Join-Path $msvc 'lib.exe'
    foreach ($def in @(Get-ChildItem (Join-Path $src 'win') -Filter *.def | Sort-Object Name)) {
        Invoke-Native $libexe @('/nologo', '/Brepro', '/machine:x64', "/def:$($def.FullName)", "/out:$(Join-Path $out "$($def.BaseName).lib")")
    }
    $w1 = Join-Path $src 'win\w1.c'
    $progs = @()
    foreach ($v in @(@{ Name = 'w1'; Defs = @(); Libs = @('kernel32.lib') },
                     @{ Name = 'w1fault'; Defs = @('/DW1_FAULT'); Libs = @('kernel32.lib') },
                     @{ Name = 'w1bad'; Defs = @('/DW1_BAD'); Libs = @('kernel32.lib', 'user32.lib') })) {
        $obj = Join-Path $out "$($v.Name).obj"
        $exe = Join-Path $out "$($v.Name).exe"
        & $Log "  CL    compat\win\w1.c -> $($v.Name).exe [MSVC]"
        Invoke-Native $cl (@('/nologo', '/c', '/O1', '/GS-', '/Zl', '/W4', '/WX', '/Brepro') + $v.Defs + @("/Fo$obj", $w1))
        Invoke-Native $link (@('/nologo', '/NODEFAULTLIB', '/ENTRY:w1_main', '/SUBSYSTEM:CONSOLE', '/MACHINE:X64', '/Brepro',
            '/DYNAMICBASE', '/HIGHENTROPYVA', '/NXCOMPAT', '/MANIFEST:NO', "/LIBPATH:$out", "/OUT:$exe", $obj) + $v.Libs)
        $progs += [pscustomobject]@{ Name = "$($v.Name).exe"; Path = $exe }
    }
    $l1o = Join-Path $out 'l1.o'
    $l1 = Join-Path $out 'l1'
    & $Log '  CC    compat\linux\l1.c -> l1 [x86_64-linux]'
    Invoke-Native $Clang @('--target=x86_64-linux-gnu', '-std=c17', '-O2', '-g0', '-ffreestanding', '-fno-builtin', '-nostdinc',
        '-fno-pic', '-fno-pie', '-fno-stack-protector', '-fno-asynchronous-unwind-tables', "-ffile-prefix-map=$Root\=",
        '-Wall', '-Wextra', '-Werror', '-c', '-o', $l1o, (Join-Path $src 'linux\l1.c'))
    Invoke-Native $Lld @('-static', '-nostdlib', '-e', '_start', '--build-id=none', '-s', '-z', 'noexecstack',
        '-z', 'separate-loadable-segments', '-z', 'max-page-size=4096', '--image-base=0x400000', '-o', $l1, $l1o)
    $progs += [pscustomobject]@{ Name = 'l1'; Path = $l1 }
    return $progs
}

function Write-ProgramsAsm([string]$Path, $Programs) {
    $sb = [Text.StringBuilder]::new()
    [void]$sb.AppendLine('; generated by build.ps1: user programs embedded in the kernel image')
    # The table holds pointers (relocated at load: KASLR): .data.rel.ro, read-only once mapped.
    [void]$sb.AppendLine('section .data.rel.ro progbits alloc noexec write align=16')
    [void]$sb.AppendLine('global user_program_table, user_program_count')
    [void]$sb.AppendLine('align 8')
    [void]$sb.AppendLine("user_program_count: dq $(@($Programs).Count)")
    [void]$sb.AppendLine('user_program_table:')
    $i = 0
    foreach ($p in $Programs) { [void]$sb.AppendLine("    dq name$i, data$i, end$i - data$i"); $i++ }
    $i = 0
    foreach ($p in $Programs) {
        [void]$sb.AppendLine("name$($i): db `"$($p.Name)`", 0")
        [void]$sb.AppendLine('align 16')
        [void]$sb.AppendLine("data$($i): incbin `"$($p.Path -replace '\\', '/')`"")
        [void]$sb.AppendLine("end$($i):")
        $i++
    }
    [IO.File]::WriteAllText($Path, $sb.ToString())
}

# Kernel symbol table for symbolized backtraces: text symbols sorted by address.
#   header: 'KSYM', count, string-table offset; entries: (offset from __text_start, name offset)
function Get-KernelSymbols([string]$Nm, [string]$Elf) {
    $lines = & $Nm '--defined-only' '--numeric-sort' '--demangle' $Elf
    if ($LASTEXITCODE -ne 0) { throw 'llvm-nm failed' }
    $textStart = $null
    $syms = [Collections.Generic.List[object]]::new()
    foreach ($l in $lines) {
        if ($l -notmatch '^([0-9a-f]{16}) ([tTwW]) (.+)$') { continue }
        $addr = [Convert]::ToUInt64($Matches[1], 16)
        $name = $Matches[3] -replace '::h[0-9a-f]{16}$', ''
        if ($name -eq '__text_start') { $textStart = $addr; continue }
        if ($name -match '^(__|\.L)') { continue }
        $syms.Add([pscustomobject]@{ Addr = $addr; Name = $name })
    }
    if ($null -eq $textStart) { throw 'kernel symbol table: __text_start not found' }
    $out = [Collections.Generic.List[object]]::new()
    $last = [UInt64]::MaxValue
    foreach ($s in $syms) {
        if ($s.Addr -lt $textStart -or $s.Addr -eq $last) { continue }
        $out.Add([pscustomobject]@{ Off = [uint32]($s.Addr - $textStart); Name = $s.Name })
        $last = $s.Addr
    }
    return ,$out
}

function New-KsymsBlob($Syms) {
    $syms = @($Syms)
    $ms = [IO.MemoryStream]::new()
    $w = [IO.BinaryWriter]::new($ms)
    $strtab = [IO.MemoryStream]::new()
    $names = foreach ($s in $syms) {
        $off = [uint32]$strtab.Length
        $b = [Text.Encoding]::UTF8.GetBytes($s.Name + [char]0)
        $strtab.Write($b, 0, $b.Length)
        $off
    }
    $w.Write([uint32]0x4D59534B)                       # 'KSYM'
    $w.Write([uint32]$syms.Count)
    $w.Write([uint32](12 + 8 * $syms.Count))           # string table offset
    $nameOffs = @($names)
    for ($i = 0; $i -lt $syms.Count; $i++) { $w.Write([uint32]$syms[$i].Off); $w.Write([uint32]$nameOffs[$i]) }
    $w.Write($strtab.ToArray())
    $w.Flush()
    return ,$ms.ToArray()
}

# Clang's own freestanding headers (stdint.h, stdarg.h, ...) - nothing from a host C library.
function Get-ClangResourceInclude([string]$clang) {
    $dir = (& $clang -print-resource-dir).Trim()
    return (Join-Path $dir 'include')
}

# ---------------------------------------------------------------------------
# QEMU
# ---------------------------------------------------------------------------
function Get-QemuArgs([string]$image, [int]$Cpus = $Smp, [string]$CpuModel = 'max', [switch]$Devices, [string]$DiskDir = $Build, [switch]$Uefi,
                      [string]$IommuKind = 'intel') {
    # -cpu max: expose modern CPU features (NX, SMEP, SMAP, UMIP, RDRAND, x2APIC) under emulation.
    # q35: PCIe with ECAM (ACPI MCFG); intel-iommu: VT-d DMA remapping (ACPI DMAR), or amd-iommu:
    # AMD-Vi (ACPI IVRS; the IOMMU is also a PCI function). No NIC yet.
    # dma-remap=on: QEMU translates emulated devices' DMA through the AMD-Vi tables (else passthrough).
    $dev = if ($IommuKind -eq 'amd') { 'amd-iommu,dma-remap=on' } else { 'intel-iommu' }
    $a = @('-machine', 'q35', '-device', $dev, '-nic', 'none',
           '-drive', "format=raw,file=$image,index=0,media=disk",
           '-cpu', $CpuModel, '-smp', "$Cpus", '-m', '256M', '-no-reboot', '-no-shutdown')
    if ($Uefi) {
        # UEFI firmware: QEMU's edk2 (OVMF) build, code read-only, a fresh variable store per run.
        $fw = Get-Ovmf
        New-Item -ItemType Directory -Force $DiskDir | Out-Null
        $vars = Join-Path $DiskDir 'ovmf-vars.fd'
        Copy-Item $fw.Vars $vars -Force
        $a += @('-drive', "if=pflash,format=raw,unit=0,readonly=on,file=$($fw.Code)", '-drive', "if=pflash,format=raw,unit=1,file=$vars")
    }
    if ($Devices) {
        # Devices for the user-space drivers: virtio-blk on a test disk, a virtio keyboard. Modern
        # virtio only, DMA through the IOMMU (iommu_platform).
        $disk = Get-TestDisk
        $a += @('-drive', "if=none,id=disk2,format=raw,file=$disk",
                '-device', 'virtio-blk-pci,drive=disk2,disable-legacy=on,iommu_platform=on',
                '-device', 'virtio-keyboard-pci,disable-legacy=on,iommu_platform=on')
        # Storage: a SATA disk on the q35 AHCI controller (port 1; the boot disk is port 0) and an
        # NVMe disk, both made by dosimg (GPT; FAT32 "boot" + DFS "system"; DFS "data").
        $disks = Get-StorageDisks $DiskDir
        $a += @('-drive', "if=none,id=sata1,format=raw,file=$($disks.Sata)", '-device', 'ide-hd,drive=sata1,bus=ide.1',
                '-drive', "if=none,id=nvm0,format=raw,file=$($disks.Nvme)", '-device', 'nvme,serial=DOS0,drive=nvm0')
    }
    return $a
}

# OVMF (edk2 for x86-64) as shipped with QEMU: share\edk2-x86_64-code.fd, and the variable store
# template edk2-i386-vars.fd (the same format for both). $env:DOS_OVMF_DIR overrides the folder.
function Get-Ovmf {
    $qemu = Find-Tool 'qemu-system-x86_64' $QemuDirs
    $dirs = @($env:DOS_OVMF_DIR, (Join-Path (Split-Path $qemu -Parent) 'share')) | Where-Object { $_ }
    foreach ($d in $dirs) {
        $code = Join-Path $d 'edk2-x86_64-code.fd'
        $vars = @('edk2-x86_64-vars.fd', 'edk2-i386-vars.fd') | ForEach-Object { Join-Path $d $_ } | Where-Object { Test-Path $_ } | Select-Object -First 1
        if ((Test-Path $code) -and $vars) { return [pscustomobject]@{ Code = $code; Vars = $vars } }
    }
    throw 'UEFI firmware (OVMF: edk2-x86_64-code.fd + edk2-i386-vars.fd) not found next to QEMU; set DOS_OVMF_DIR.'
}

# The virtio-blk test disk (1 MiB): byte j of sector s is (s * 13 + j) mod 256 (devmgr test checks it).
function Get-TestDisk {
    $path = Join-Path $Build 'disk2.img'
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Force $Build | Out-Null
        $d = [byte[]]::new(1MB)
        for ($sec = 0; $sec -lt 2048; $sec++) {
            $b = ($sec * 13) % 256
            for ($j = 0; $j -lt 512; $j++) { $d[$sec * 512 + $j] = [byte](($b + $j) % 256) }
        }
        [IO.File]::WriteAllBytes($path, $d)
    }
    return $path
}

# dosimg (tools/dosimg), the host image tool, built with the host toolchain.
$script:Dosimg = $null
function Get-Dosimg {
    if ($script:Dosimg) { return $script:Dosimg }
    $cargo = Initialize-Rust
    $target = Join-Path $Build 'host'
    Push-Location (Join-Path $Root 'tools\dosimg')
    try { Invoke-Native $cargo @('build', '--release', '--locked', '--quiet', '--target-dir', $target) } finally { Pop-Location }
    $script:Dosimg = Join-Path $target 'release\dosimg.exe'
    return $script:Dosimg
}

# The storage test disks in $Dir (created if missing): $Build keeps them across `run`s; each test
# case gets fresh copies of the pristine images (build\disks\base).
function Get-StorageDisks([string]$Dir) {
    $tool = Get-Dosimg
    $base = Join-Path $Build 'disks\base2'   # bump when tools/dosimg changes the test disks
    New-Item -ItemType Directory -Force $base, $Dir | Out-Null
    $out = @{}
    foreach ($k in @('sata', 'nvme')) {
        $b = Join-Path $base "$k.img"
        if (-not (Test-Path $b)) { Invoke-Native $tool @($k, $b) }
        $d = Join-Path $Dir "$k.img"
        if (-not (Test-Path $d)) { Copy-Item $b $d }
        $out[$k] = $d
    }
    return [pscustomobject]@{ Sata = $out.sata; Nvme = $out.nvme }
}

# storage: what D-OS left on the disks, checked on the host. 7-Zip (an independent FAT reader)
# must find the long-named file fstest wrote; the DFS "system" volume must pass dosimg fsck.
# Read-only storage (docs/hardware.md): after a boot without writable disks, every disk the
# machine had must be byte-identical to before: the boot image (its build hash), the SATA and
# NVMe disks (their pristine copies), the virtio-blk test disk (its generated pattern).
# attest: the remote verifier's side. The report and nonce come from the guest's log; the reference
# values (this build's kernel .dsig, the D-OS public key) from the build. Then the attacks: a replay
# (another nonce), a changed byte, a report checked against another kernel.
function Test-AttestReport([string]$DiskDir, [string]$Image, [string]$Log) {
    $dir = Split-Path $Image -Parent
    $nonce = ''
    $hex = [Text.StringBuilder]::new()
    foreach ($line in ($Log -split "`n")) {
        if ($line -match 'utest: attest nonce ([0-9a-f]{64})') { $nonce = $Matches[1] }
        elseif ($line -match 'utest: attest data ([0-9a-f]+)') { [void]$hex.Append($Matches[1]) }
    }
    if (-not $nonce -or $hex.Length -lt 2) { Write-Host '  attest: no report in the log'; return $false }
    $h = $hex.ToString()
    $bytes = [byte[]]::new($h.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($h.Substring(2 * $i, 2), 16) }
    $report = Join-Path $dir 'attest-report.bin'
    [IO.File]::WriteAllBytes($report, $bytes)
    $dsig = Join-Path $dir 'kernel.dsig'
    $key = (Get-SigningKey).Public
    $dosimg = Get-Dosimg
    $verify = {
        param($r, $n, $d)
        $out = & $dosimg attest-verify $r $n $d $key 2>&1 | Out-String
        return @($LASTEXITCODE, $out.Trim())
    }
    $ok = $true
    $v = & $verify $report $nonce $dsig
    Write-Host "  host: $($v[1])"
    if ($v[0] -ne 0 -or $v[1] -notmatch 'attest: VALID') { $ok = $false }
    # Attacks, each must be refused for its own reason.
    $other = ($nonce.Substring(0, 63)) + $(if ($nonce[63] -eq '0') { '1' } else { '0' })
    $tampered = Join-Path $dir 'attest-tampered.bin'
    $t = [byte[]]$bytes.Clone(); $t[200] = $t[200] -bxor 1; [IO.File]::WriteAllBytes($tampered, $t)
    $foreign = Join-Path $dir 'attest-other-kernel.dsig'
    $fd = [IO.File]::ReadAllBytes($dsig); $fd[100] = $fd[100] -bxor 1; [IO.File]::WriteAllBytes($foreign, $fd)
    foreach ($case in @(@('replayed for another nonce', $report, $other, $dsig, 'Nonce'),
                        @('one byte changed', $tampered, $nonce, $dsig, 'Signature'),
                        @('checked against another kernel', $report, $nonce, $foreign, 'UnknownKernel'))) {
        $v = & $verify $case[1] $case[2] $case[3]
        $refused = $v[0] -ne 0 -and $v[1] -match "REFUSED: $($case[4])"
        Write-Host "  host: attest, $($case[0]): $(if ($refused) { "refused ($($case[4]))" } else { "NOT REFUSED: $($v[1])" })"
        if (-not $refused) { $ok = $false }
    }
    return $ok
}

# xHCI without a keyboard: the devices are probed once (one line each, then nothing more while
# keys are typed elsewhere).
function Test-UsbProbedOnce([string]$DiskDir, [string]$Image, [string]$Log) {
    $n = ([regex]::Matches($Log, 'left unused')).Count
    Write-Host "  xhci: $n 'left unused' line(s) (expected 2: tablet, mouse)"
    return $n -eq 2
}

# time: the second boot of the same disks must find the records and a later time; both boots'
# clocks must agree with the host's (UTC) within 15 minutes.
function Test-TimeBoots([string]$DiskDir, [string]$Image, [string]$Log, [bool]$Uefi) {
    $log2 = Join-Path (Split-Path $Image -Parent) ("serial-time-second" + $(if ($Uefi) { "-uefi" } else { "" }) + ".log")
    $expect = @('svc-time: second boot: PASSED', 'init: time test: second boot PASSED', 'Power: switching off')
    $r = Invoke-QemuCapture $Image $log2 $expect @('KERNEL PANIC', 'svc FAIL', 'PANIC', 'FAILED') 180 -Devices -DiskDir $DiskDir -Uefi:$Uefi -MustExit
    $ok = @($expect | Where-Object { -not $r.Log.Contains($_) }).Count -eq 0
    $line = ($r.Log -split "`n" | Where-Object { $_ -match 'svc-time: second boot' } | Select-Object -First 1)
    Write-Host "  time: second boot: $(if ($ok) { $line.Trim() } else { 'FAILED' })"
    if (-not $ok) { Write-Host ($r.Log -split "`n" | Select-Object -Last 15 | Out-String) }
    $now = [DateTime]::UtcNow
    foreach ($l in @($Log, $r.Log)) {
        if ($l -match 'clock: (\d{4})-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d) UTC') {
            $t = [DateTime]::new([int]$Matches[1], [int]$Matches[2], [int]$Matches[3], [int]$Matches[4], [int]$Matches[5], [int]$Matches[6], [DateTimeKind]::Utc)
            $off = [Math]::Abs(($now - $t).TotalMinutes)
            Write-Host ("  time: D-OS said {0:u}, the host {1:u} ({2:N1} min apart)" -f $t, $now, $off)
            if ($off -gt 15) { $ok = $false }
        } else { Write-Host '  time: no clock line'; $ok = $false }
    }
    return $ok
}
function Test-TimeReboot([string]$DiskDir, [string]$Image, [string]$Log) { Test-TimeBoots $DiskDir $Image $Log $false }
function Test-TimeRebootUefi([string]$DiskDir, [string]$Image, [string]$Log) { Test-TimeBoots $DiskDir $Image $Log $true }

# Service manager: the volumes are made durable while the drivers still run, then each service stops
# after the services depending on it (console, then devmgr, then storaged), then the power goes.
function Test-ServicesOrder([string]$DiskDir, [string]$Image, [string]$Log) {
    $at = { param($s) $Log.IndexOf($s) }
    $seq = @('init: syncing storaged', 'storaged: sync: 4 volume(s) durable', 'init: stopping shell', 'init: stopping terminal', 'init: stopping devmgr', 'devmgr: shutdown:', 'init: stopping storaged', 'storaged: shutdown: 4 volume(s) durable', 'init: shutdown: every service stopped', 'Power: switch-off requested by process init')
    $pos = @($seq | ForEach-Object { & $at $_ })
    $ok = ($pos -notcontains -1)
    for ($i = 1; $i -lt $pos.Count; $i++) { if ($pos[$i] -lt $pos[$i - 1]) { $ok = $false } }
    Write-Host "  services: shutdown order $(if ($ok) { 'volumes made durable, then shell, terminal, devmgr, storaged (each after what depends on it), then power-off' } else { 'WRONG: ' + ($pos -join ', ') })"
    return $ok
}

# USB hot-plug: the reconnecting tablet is reported once and left alone once.
function Test-UsbPlugOnce([string]$DiskDir, [string]$Image, [string]$Log) {
    $n = ([regex]::Matches($Log, 'left unused')).Count
    $g = ([regex]::Matches($Log, 'keeps reconnecting')).Count
    Write-Host "  xhci: $n 'left unused', $g 'keeps reconnecting' line(s) (expected 1, 1)"
    return $n -eq 1 -and $g -eq 1
}

function Test-DisksUnchanged([string]$DiskDir, [string]$Image) {
    $same = { param($a, $b) (Get-FileHash -Algorithm SHA256 $a).Hash -eq (Get-FileHash -Algorithm SHA256 $b).Hash }
    $ok = $true
    $sums = Join-Path (Split-Path $Image -Parent) 'SHA256SUMS'
    $want = (Get-Content $sums | Where-Object { $_ -match ' discrete\.img$' } | Select-Object -First 1) -replace ' .*$', ''
    $got = (Get-FileHash -Algorithm SHA256 $Image).Hash.ToLowerInvariant()
    $results = @("boot image $(if ($want -eq $got) { 'unchanged' } else { 'CHANGED' })")
    $ok = $ok -and $want -eq $got
    foreach ($k in @('sata', 'nvme')) {
        $d = Join-Path $DiskDir "$k.img"
        $u = (Test-Path $d) -and (& $same $d (Join-Path $Build "disks\base2\$k.img"))
        $results += "$k $(if ($u) { 'unchanged' } else { 'CHANGED' })"
        $ok = $ok -and $u
    }
    $ref = Join-Path $DiskDir 'disk2.expected'
    $d = [byte[]]::new(1MB)
    for ($sec = 0; $sec -lt 2048; $sec++) { $b = ($sec * 13) % 256; for ($j = 0; $j -lt 512; $j++) { $d[$sec * 512 + $j] = [byte](($b + $j) % 256) } }
    [IO.File]::WriteAllBytes($ref, $d)
    $u = & $same (Get-TestDisk) $ref
    Remove-Item $ref
    $results += "virtio-blk $(if ($u) { 'unchanged' } else { 'CHANGED' })"
    $ok = $ok -and $u
    Write-Host "  host: disks after a read-only boot: $($results -join ', ')"
    return $ok
}

function Test-StorageImages([string]$DiskDir) {
    $tool = Get-Dosimg
    $sata = Join-Path $DiskDir 'sata.img'
    $fat = Join-Path $DiskDir 'boot.fat'
    $ok = $true
    Invoke-Native $tool @('extract', $sata, '1', $fat)
    $sevenZip = @("$env:ProgramFiles\7-Zip\7z.exe", "${env:ProgramFiles(x86)}\7-Zip\7z.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($sevenZip) {
        $list = & $sevenZip l $fat 2>&1 | Out-String
        $text = & $sevenZip e -so $fat 'Written by D-OS.txt' 2>$null | Out-String
        $seen = $list.Contains('Written by D-OS.txt') -and $text.Contains('Hello from D-OS: FAT32 write works.')
        Write-Host "  host: 7-Zip reads 'Written by D-OS.txt' from the FAT32 volume: $(if ($seen) { 'yes' } else { 'NO' })"
        $ok = $ok -and $seen
    } else {
        Write-Host '  host: 7-Zip not installed: FAT32 interoperability check skipped'
    }
    $fsck = & $tool fsck $sata 2 2>&1 | Out-String
    Write-Host "  host: $($fsck.Trim())"
    return ($ok -and $LASTEXITCODE -eq 0)
}

# Verified boot tests: a copy of the image whose kernel has one flipped byte, in both places it
# lives (the BIOS boot partition and \DOS\KERNEL.BIN on the ESP). Both loaders must refuse it.
function New-TamperedImage([string]$Image) {
    $dir = Join-Path $Build 'tampered'
    New-Item -ItemType Directory -Force $dir | Out-Null
    $copy = Join-Path $dir 'discrete.img'
    Copy-Item $Image $copy -Force
    Invoke-Native (Get-Dosimg) @('patch', $copy, '2', 'DOS/KERNEL.BIN', '8192', '01')
    $fs = [IO.File]::Open($copy, 'Open', 'ReadWrite')
    try {
        $fs.Position = $KernelLba * $SectorSize + 8192
        $b = $fs.ReadByte()
        $fs.Position = $KernelLba * $SectorSize + 8192
        $fs.WriteByte([byte]($b -bxor 1))
    } finally { $fs.Dispose() }
    return $copy
}

# crypto-host: the signing crypto on the host. doscrypt's unit tests (FIPS 180 / RFC 8032 / RFC 6979
# vectors, constants recomputed from the primes, constant-time Ed25519 scalar multiplication, TPM
# quotes); the loaders' C verifier (vectors, built with MinGW gcc); cross-checks: .dsig files made
# by the Rust signer verified by the C verifier (and a tampered copy refused), SHA-256/512 against
# .NET's implementation, ECDSA P-256 signatures made by .NET verified by doscrypt (and altered
# ones refused).
function New-P256Vectors([string]$path) {
    $lines = [Collections.Generic.List[string]]::new()
    $hash = [Security.Cryptography.HashAlgorithmName]::SHA256
    for ($i = 0; $i -lt 48; $i++) {
        $e = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
        $q = $e.ExportParameters($false).Q
        $m = [byte[]]::new($i * 7); [Security.Cryptography.RandomNumberGenerator]::Fill($m)
        $sig = $e.SignData($m, $hash)   # IEEE P1363: r || s
        $mh = if ($m.Length) { [Convert]::ToHexString($m) } else { '-' }
        $key = "$([Convert]::ToHexString($q.X)) $([Convert]::ToHexString($q.Y))"
        $lines.Add("$key $mh $([Convert]::ToHexString($sig)) 1")
        $bad = [byte[]]$sig.Clone(); $bad[$i % 64] = $bad[$i % 64] -bxor (1 -shl ($i % 8))
        $lines.Add("$key $mh $([Convert]::ToHexString($bad)) 0")
        $e.Dispose()
    }
    [IO.File]::WriteAllLines($path, $lines)
}

function Test-CryptoHost {
    $cargo = Initialize-Rust
    $ok = $true
    $vectors = Join-Path $Build 'host\p256-dotnet.txt'
    New-Item -ItemType Directory -Force (Split-Path $vectors -Parent) | Out-Null
    New-P256Vectors $vectors
    Push-Location (Join-Path $Root 'user\lib\crypto')
    $env:DOSCRYPT_P256_VECTORS = $vectors
    try {
        $out = & $cargo test --release --locked --quiet --target-dir (Join-Path $Build 'host') 2>&1 | Out-String
        $ok = $ok -and $LASTEXITCODE -eq 0
    } finally { Pop-Location; Remove-Item Env:\DOSCRYPT_P256_VECTORS -ErrorAction SilentlyContinue }
    Write-Host ($out.Trim() -split "`n" | Where-Object { $_ -match 'test result|FAILED|panicked' } | Out-String).Trim()
    $gcc = (Get-Command gcc -ErrorAction SilentlyContinue).Source
    if (-not $gcc) { $gcc = @($env:CARGO_HOME, '') | ForEach-Object { if ($_) { Join-Path (Split-Path $_ -Parent) 'mingw64\bin\gcc.exe' } } | Where-Object { Test-Path $_ } | Select-Object -First 1 }
    if (-not $gcc) { Write-Host '  host: no gcc (MinGW): C verifier checks skipped'; return $ok }
    $dir = Join-Path $Build 'host\ctest'
    New-Item -ItemType Directory -Force $dir | Out-Null
    $exe = Join-Path $dir 'test_dcrypto.exe'
    $common = Join-Path $Root 'boot\common'
    Invoke-Native $gcc @('-O2', '-std=c11', '-Wall', '-Wextra', '-Werror', '-o', $exe, (Join-Path $common 'test_dcrypto.c'), (Join-Path $common 'dcrypto.c'))
    $prevPath = $env:PATH
    $env:PATH = "$(Split-Path $gcc -Parent);$env:PATH"      # MinGW runtime DLLs
    try {
        $r = & $exe 2>&1 | Out-String; Write-Host "  host: $($r.Trim())"; $ok = $ok -and $LASTEXITCODE -eq 0
        $tool = Get-Dosimg
        $seed = Join-Path $dir 'test.seed'
        $b = [byte[]]::new(32); [Security.Cryptography.RandomNumberGenerator]::Fill($b); [IO.File]::WriteAllBytes($seed, $b)
        $pub = (& $tool pubkey $seed | Select-Object -Last 1).Trim()
        $agree = 0
        foreach ($size in @(0, 1, 127, 128, 129, 4096, 100003)) {
            $f = Join-Path $dir "data$size.bin"
            $d = [byte[]]::new($size); [Security.Cryptography.RandomNumberGenerator]::Fill($d); [IO.File]::WriteAllBytes($f, $d)
            & $tool sign $seed program "data$size" $f "$f.dsig" | Out-Null
            & $exe $pub $f "$f.dsig" ok | Out-Null; $good = $LASTEXITCODE -eq 0
            $sha512 = (& $tool sha512 $f | Select-Object -Last 1).Trim()
            $sha256 = (& $tool sha256 $f | Select-Object -Last 1).Trim()
            $same = $sha512 -eq (Get-FileHash -Algorithm SHA512 $f).Hash.ToLowerInvariant() -and $sha256 -eq (Get-FileHash -Algorithm SHA256 $f).Hash.ToLowerInvariant()
            $bad = $true
            if ($size -gt 0) {
                $d[$size - 1] = $d[$size - 1] -bxor 0x80; [IO.File]::WriteAllBytes($f, $d)
                & $exe $pub $f "$f.dsig" bad | Out-Null; $bad = $LASTEXITCODE -eq 0
            }
            if ($good -and $bad -and $same) { $agree++ } else { Write-Host "  host: cross-check FAILED for $size bytes (verify $good, tamper refused $bad, SHA-2 = .NET $same)" -ForegroundColor Red }
        }
        Write-Host "  host: $agree/7 sizes: Rust signer -> C verifier valid, tampered copy refused; SHA-256/512 equal to .NET's"
        $ok = $ok -and $agree -eq 7
    } finally { $env:PATH = $prevPath }
    return $ok
}

# static: clang --analyze on all C, clippy -D warnings on all Rust. The analyzer's Annex K check
# (security.insecureAPI.DeprecatedOrUnsafeBufferHandling: "use memcpy_s") is off: no freestanding
# code has those functions, and every length is checked where it comes from.
function Test-StaticAnalysis {
    $clang = Find-Tool 'clang' $LlvmDirs
    $inc = Get-ClangResourceInclude $clang
    $an = @('--analyze', '-Xanalyzer', '-analyzer-output=text',
            '-Xanalyzer', '-analyzer-checker=core,unix,security,deadcode,nullability',
            '-Xanalyzer', '-analyzer-disable-checker=security.insecureAPI.DeprecatedOrUnsafeBufferHandling', '-o', 'NUL')
    $kernel = @('--target=x86_64-elf', '-std=c17', '-ffreestanding', '-fno-builtin', '-nostdinc', '-isystem', $inc,
                '-mno-red-zone', '-mno-sse', '-mno-mmx', '-mno-80387', '-I', (Join-Path $Root 'kernel\include'))
    $sets = [Collections.Generic.List[object]]::new()
    $kfiles = @(Get-ChildItem (Join-Path $Root 'kernel') -Recurse -Filter *.c | Sort-Object FullName | ForEach-Object FullName)
    $sets.Add([pscustomobject]@{ Name = 'kernel (release)'; Flags = $kernel; Files = $kfiles })
    foreach ($t in @('SELFTEST', 'SPEC', 'FUZZ')) {
        $sets.Add([pscustomobject]@{ Name = "kernel (KTEST_$t)"; Flags = ($kernel + @('-DKTEST', "-DKTEST_$t")); Files = $kfiles })
    }
    $common = Join-Path $Root 'boot\common'
    $sets.Add([pscustomobject]@{ Name = 'stage 3'; Files = @((Join-Path $Root 'boot\stage3\stage3.c'), (Join-Path $common 'dcrypto.c'), (Join-Path $common 'kaslr.c'))
        Flags = @('--target=x86_64-elf', '-std=c17', '-ffreestanding', '-fno-builtin', '-nostdinc', '-isystem', $inc, '-mgeneral-regs-only', '-I', $common) })
    $sets.Add([pscustomobject]@{ Name = 'UEFI loader'; Files = @((Join-Path $Root 'boot\uefi\loader.c'))
        Flags = @('--target=x86_64-unknown-windows', '-std=c17', '-ffreestanding', '-fno-builtin', '-nostdinc', '-isystem', $inc, '-fshort-wchar', '-mgeneral-regs-only') })
    $userSrc = Join-Path $Root 'user'
    $ufiles = @(Get-ChildItem $userSrc -Recurse -Filter *.c | Where-Object { $_.FullName -notmatch '[\\/]target[\\/]' } | Sort-Object FullName | ForEach-Object FullName)
    $sets.Add([pscustomobject]@{ Name = 'user C'; Files = $ufiles
        Flags = @('--target=x86_64-unknown-elf', '-std=c17', '-ffreestanding', '-nostdinc', '-isystem', $inc, '-I', (Join-Path $userSrc 'include')) })
    $findings = 0; $files = 0
    foreach ($set in $sets) {
        $n = 0
        foreach ($f in $set.Files) {
            $out = & $clang ($set.Flags + $an + @($f)) 2>&1 | Out-String
            if ($LASTEXITCODE -ne 0) { Write-Host "  static: clang failed on $(Get-RelPath $f):`n$out"; return $false }
            $w = @($out -split "`n" | Where-Object { $_ -match ': warning: ' })
            if ($w.Count) { $w | ForEach-Object { Write-Host "  $($_.Trim())" } }
            $n += $w.Count; $files++
        }
        Write-Host "  static: clang analyzer, $($set.Name): $(@($set.Files).Count) files, $n findings"
        $findings += $n
    }
    $cargo = Initialize-Rust
    $crates = @('kernel\rust', 'user\lib\crypto', 'user\lib\fs', 'user\lib\libd', 'user\lib\dman', 'user\init', 'user\log', 'user\clock', 'user\terminal', 'user\shell', 'user\tools','user\devmgr', 'user\storaged', 'user\fstest', 'user\ltest', 'user\dcmpl', 'tools\dosimg')
    foreach ($c in $crates) {
        Push-Location (Join-Path $Root $c)
        try {
            $allTargets = [string[]]@()      # (an if-expression would unwrap a one-element array)
            if ((Test-Path 'src\main.rs') -or ($c -like 'user\lib\*')) { $allTargets = [string[]]@('--all-targets') }
            if ($c -eq 'user\lib\libd') { $allTargets += @('--features', 'capi') }   # the C API too
            $out = & $cargo clippy --release --locked --quiet @allTargets --target-dir (Join-Path $Build 'clippy') -- -D warnings 2>&1 | Out-String
            $code = $LASTEXITCODE
        } finally { Pop-Location }
        $errs = @($out -split "`n" | Where-Object { $_ -match '^error' })
        Write-Host "  static: clippy -D warnings, $($c): $(if ($code -eq 0) { 'clean' } else { "$($errs.Count) findings" })"
        if ($code -ne 0) { Write-Host $out.Trim(); $findings += [Math]::Max(1, $errs.Count) }
    }
    Write-Host "  static: $files C files analyzed, $($crates.Count) Rust crates linted: $findings findings"
    return $findings -eq 0
}

# storage-host: the dosfs unit tests, on the host.
# KASLR across boots: the kaslr case's image booted twice more (BIOS, UEFI). Each boot prints its
# layout (test builds only); all three must differ in every region.
function Test-KaslrReboots([string]$DiskDir, [string]$Image, [string]$FirstLog) {
    $layouts = @()
    $re = 'KTEST kaslr: layout image (0x[0-9a-f]+) direct map (0x[0-9a-f]+) heap (0x[0-9a-f]+) stacks (0x[0-9a-f]+)'
    if ($FirstLog -match $re) { $layouts += ,@($Matches[1], $Matches[2], $Matches[3], $Matches[4]) }
    foreach ($uefi in @($false, $true)) {
        $log = Join-Path (Split-Path $Image -Parent) "serial-kaslr-$(if ($uefi) { 'uefi' } else { 'bios2' }).log"
        $expect = @('KTEST kaslr: PASSED', 'D-KRNL: ready')
        $r = Invoke-QemuCapture $Image $log $expect @('KERNEL PANIC', 'FAIL') 90 -Uefi:$uefi
        if ($r.Log -match $re) { $layouts += ,@($Matches[1], $Matches[2], $Matches[3], $Matches[4]) }
        $passed = @($expect | Where-Object { -not $r.Log.Contains($_) }).Count -eq 0
        Write-Host "  $(if ($uefi) { 'UEFI' } else { 'BIOS' }) reboot: $(if ($passed) { 'KTEST kaslr: PASSED' } else { 'FAILED' })"
        if (-not $passed) { return $false }
    }
    if ($layouts.Count -ne 3) { Write-Host "  kaslr: expected 3 layouts, got $($layouts.Count)"; return $false }
    $names = @('image', 'direct map', 'heap', 'stacks')
    $ok = $true
    for ($k = 0; $k -lt 4; $k++) {
        $vals = @($layouts | ForEach-Object { $_[$k] })
        $distinct = @($vals | Sort-Object -Unique).Count
        Write-Host "  kaslr: $($names[$k]): $($vals -join ', ') ($distinct distinct)"
        if ($distinct -ne 3) { $ok = $false }
    }
    return $ok
}

# The loaders' KASLR code (boot\common\kaslr.c) on the host: synthetic tables, then its decoding of
# the real kernel's RELR table must list exactly the addresses llvm-readobj lists for kernel.elf.
function Test-KaslrHost {
    $gcc = (Get-Command gcc -ErrorAction SilentlyContinue).Source
    if (-not $gcc) { Initialize-Rust | Out-Null; $gcc = @($env:CARGO_HOME, '') | ForEach-Object { if ($_) { Join-Path (Split-Path $_ -Parent) 'mingw64\bin\gcc.exe' } } | Where-Object { Test-Path $_ } | Select-Object -First 1 }
    if (-not $gcc) { Write-Host '  host: no gcc (MinGW)'; return $false }
    $elf = Join-Path $Build 'kernel.elf'
    $bin = Join-Path $Build 'kernel.bin'
    if (-not (Test-Path $elf) -or -not (Test-Path $bin)) { Invoke-Build -Quiet | Out-Null }
    $dir = Join-Path $Build 'host\ctest'
    New-Item -ItemType Directory -Force $dir | Out-Null
    $exe = Join-Path $dir 'test_kaslr.exe'
    $common = Join-Path $Root 'boot\common'
    Invoke-Native $gcc @('-O2', '-std=c11', '-Wall', '-Wextra', '-Werror', '-o', $exe, (Join-Path $common 'test_kaslr.c'),
        (Join-Path $common 'kaslr.c'), (Join-Path $common 'dcrypto.c'))
    $prevPath = $env:PATH
    $env:PATH = "$(Split-Path $gcc -Parent);$env:PATH"      # MinGW runtime DLLs
    try {
        $r = & $exe 2>&1 | Out-String; Write-Host "  host: $($r.Trim())"; $ok = $LASTEXITCODE -eq 0
        $ours = @(& $exe list $bin) | ForEach-Object { $_.Trim().ToLowerInvariant() }
        $okList = $LASTEXITCODE -eq 0
    } finally { $env:PATH = $prevPath }
    $readobj = Find-Tool 'llvm-readobj' $LlvmDirs
    $theirs = @(& $readobj -r $elf | Where-Object { $_ -match '^\s+0x([0-9A-F]{16}) R_X86_64_RELATIVE' } | ForEach-Object { ([regex]::Match($_, '0x([0-9A-F]{16})')).Groups[1].Value.ToLowerInvariant() })
    $same = $okList -and $ours.Count -gt 0 -and (($ours | Sort-Object) -join ',') -eq (($theirs | Sort-Object) -join ',')
    Write-Host "  host: kernel.bin RELR: $($ours.Count) relocations decoded, llvm-readobj lists $($theirs.Count): $(if ($same) { 'identical' } else { 'DIFFERENT' })"
    return $ok -and $same
}

# manifest-host: the service manifest parser on the host: schema tests and the mutation fuzzer.
function Test-ManifestHost {
    $cargo = Initialize-Rust
    Push-Location (Join-Path $Root 'user\lib\dman')
    try {
        $out = & $cargo test --release --locked --quiet --target-dir (Join-Path $Build 'host') -- --nocapture 2>&1 | Out-String
        $code = $LASTEXITCODE
    } finally { Pop-Location }
    Write-Host ($out.Trim() -split "`n" | Where-Object { $_ -match 'test result|FAILED|panicked|dman fuzz' } | Out-String).Trim()
    return $code -eq 0
}

function Test-DosfsHost {
    $cargo = Initialize-Rust
    Push-Location (Join-Path $Root 'user\lib\fs')
    try {
        $out = & $cargo test --release --locked --quiet --target-dir (Join-Path $Build 'host') 2>&1 | Out-String
        $code = $LASTEXITCODE
    } finally { Pop-Location }
    Write-Host $out.Trim()
    return $code -eq 0
}

function Get-FreeTcpPort {
    $l = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $l.Start(); $port = $l.LocalEndpoint.Port; $l.Stop()
    return $port
}

# Types keys into the guest through the QEMU monitor (TCP); '!cmd' sends a monitor command, '~ms' waits.
function Send-QemuKeys([int]$Port, [string[]]$Keys) {
    $client = $null
    for ($i = 0; $i -lt 20 -and -not $client; $i++) {
        try { $client = [Net.Sockets.TcpClient]::new('127.0.0.1', $Port) } catch { Start-Sleep -Milliseconds 100 }
    }
    if (-not $client) { throw "Cannot connect to QEMU monitor on port $Port" }
    try {
        $w = [IO.StreamWriter]::new($client.GetStream())
        $w.AutoFlush = $true
        foreach ($k in $Keys) {
            if ($k.StartsWith('!')) { $w.Write("$($k.Substring(1))`n") }            # a monitor command
            elseif ($k.StartsWith('~')) { Start-Sleep -Milliseconds ([int]$k.Substring(1)) }   # a pause (ms)
            else { $w.Write("sendkey $k`n") }
            Start-Sleep -Milliseconds 60
        }
    } finally { $client.Dispose() }
}

# Types lines into the guest's COM1 (TCP chardev), each ended by CR like a terminal.
function Send-SerialLines([int]$Port, [string[]]$Lines) {
    $client = $null
    for ($i = 0; $i -lt 20 -and -not $client; $i++) {
        try { $client = [Net.Sockets.TcpClient]::new('127.0.0.1', $Port) } catch { Start-Sleep -Milliseconds 100 }
    }
    if (-not $client) { throw "Cannot connect to the QEMU serial port $Port" }
    try {
        $w = [IO.StreamWriter]::new($client.GetStream())
        $w.AutoFlush = $true
        foreach ($l in $Lines) { $w.Write("$l`r"); Start-Sleep -Milliseconds 400 }
        Start-Sleep -Milliseconds 300
    } finally { $client.Dispose() }
}

function Read-Shared([string]$Path) {
    if (-not (Test-Path $Path)) { return '' }
    $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
    try { return (New-Object IO.StreamReader($fs)).ReadToEnd() } finally { $fs.Dispose() }
}

# Boots $image headless; returns the serial log. Stops as soon as all $Expect strings
# (or any $Forbid string) appear, or after $Timeout seconds.
function Invoke-QemuCapture([string]$image, [string]$log, [string[]]$Expect, [string[]]$Forbid, [int]$Timeout,
                            [string[]]$Keys = @(), [string]$KeysAfter = '', [int]$Cpus = 4, [string]$CpuModel = 'max',
                            [switch]$Devices, [string[]]$Serial = @(), [string]$SerialAfter = '', [string]$DiskDir = $Build, [switch]$Uefi,
                            [string[]]$Extra = @(), [switch]$MustExit, [string]$IommuKind = 'intel') {
    $qemu = Find-Tool 'qemu-system-x86_64' $QemuDirs
    if (Test-Path $log) { Remove-Item $log }
    $qargs = (Get-QemuArgs $image $Cpus $CpuModel -Devices:$Devices -DiskDir $DiskDir -Uefi:$Uefi -IommuKind $IommuKind) + $Extra + @('-display', 'none')
    if ($MustExit) { $qargs = @($qargs | Where-Object { $_ -ne '-no-shutdown' }) }
    $serPort = 0
    if (@($Serial).Count) {
        # Serial input (kdb): COM1 on a TCP socket, its output still logged to the file.
        $serPort = Get-FreeTcpPort
        $qargs += @('-chardev', "socket,id=ser0,host=127.0.0.1,port=$serPort,server=on,wait=off,logfile=$log", '-serial', 'chardev:ser0')
    } else {
        $qargs += @('-serial', "file:$log")
    }
    $serialSent = $false
    $monPort = 0
    if (@($Keys).Count) {
        $monPort = Get-FreeTcpPort
        $qargs += @('-monitor', "tcp:127.0.0.1:$($monPort),server,nowait")
    }
    $keysSent = $false
    $bad = $false
    $quoted = $qargs | ForEach-Object { if ($_ -match '\s') { "`"$_`"" } else { $_ } }
    $proc = Start-Process -FilePath $qemu -ArgumentList $quoted -PassThru -NoNewWindow
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        while (-not $proc.HasExited -and $sw.Elapsed.TotalSeconds -lt $Timeout) {
            Start-Sleep -Milliseconds 100
            $out = Read-Shared $log
            if ($monPort -and -not $keysSent -and $out.Contains($KeysAfter)) {
                Send-QemuKeys $monPort $Keys
                $keysSent = $true
                continue
            }
            if ($serPort -and -not $serialSent -and $out.Contains($SerialAfter)) {
                Send-SerialLines $serPort $Serial
                $serialSent = $true
                continue
            }
            $done =@($Expect | Where-Object { -not $out.Contains($_) }).Count -eq 0
            $bad  = @($Forbid | Where-Object { $out.Contains($_) }).Count -gt 0
            if ($done -or $bad) { Start-Sleep -Milliseconds 200; break }  # let trailing output land
        }
        if ($MustExit -and -not $bad) {
            $until = $sw.Elapsed.TotalSeconds + 5
            while (-not $proc.HasExited -and $sw.Elapsed.TotalSeconds -lt $until) { Start-Sleep -Milliseconds 100 }
        }
    } finally {
        $exited = $proc.HasExited
        if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
        $proc.WaitForExit()
    }
    return [pscustomobject]@{ Log = (Read-Shared $log); Seconds = $sw.Elapsed.TotalSeconds; Exited = $exited }
}

# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------
function Invoke-Clean {
    if (Test-Path $Build) { Remove-Item -Recurse -Force $Build }
    Write-Host 'Cleaned.'
}

function Invoke-Run {
    $image = Invoke-Build
    $qemu = Find-Tool 'qemu-system-x86_64' $QemuDirs
    & $qemu @((Get-QemuArgs $image -Devices -Uefi:$Uefi -IommuKind $Iommu) + @('-serial', 'stdio'))
}

function Invoke-Debug {
    $image = Invoke-Build
    $qemu = Find-Tool 'qemu-system-x86_64' $QemuDirs
    Write-Host 'QEMU paused; GDB stub on localhost:1234 (target remote :1234). Symbols: build\kernel.elf'
    & $qemu @((Get-QemuArgs $image -Uefi:$Uefi -IommuKind $Iommu) + @('-serial', 'stdio', '-s', '-S', '-d', 'int,cpu_reset', '-D', (Join-Path $Build 'qemu.log')))
}

function Invoke-Test {
    # -Case a,b also arrives as one string when run via `pwsh -File`: split it.
    $names = if ($Case) { @($Case | ForEach-Object { $_ -split ',' } | Where-Object { $_ }) } else { @($TestCases.Keys) }
    foreach ($n in $names) { if (-not $TestCases.Contains($n)) { throw "Unknown test case '$n'. Known: $($TestCases.Keys -join ', ')" } }
    Get-SigningKey | Out-Null       # before the parallel variant builds: one key for all of them

    $results = @()
    $releaseImage = $null
    $images = @{}          # Define -> image: variants shared by several cases are built once

    # Reproducible build: the release image rebuilt in another directory must be byte-identical.
    if (-not $Case -and -not $NoRepro) {
        $releaseImage = Invoke-Build
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $copy = Invoke-Build -OutDir (Join-Path $Build 'repro') -Quiet
        $h1 = (Get-FileHash -Algorithm SHA256 $releaseImage).Hash
        $h2 = (Get-FileHash -Algorithm SHA256 $copy).Hash
        $same = $h1 -eq $h2
        Write-Host ("--- [repro] {0} vs {1}: {2} ---" -f $h1.Substring(0, 16), $h2.Substring(0, 16), $(if ($same) { 'identical' } else { 'DIFFERENT' }))
        $results += [pscustomobject]@{ Case = 'repro'; Result = $(if ($same) { 'PASS' } else { 'FAIL' }); Seconds = [Math]::Round($sw.Elapsed.TotalSeconds, 1) }
    }
    # Test variants (Define + UBSan) are independent builds. On PowerShell 7+ they are built in
    # parallel, each in its own pwsh process and output directory; the boots below stay
    # sequential (several cases measure time and would be disturbed by a loaded host).
    $variants = [ordered]@{}
    foreach ($n in $names) {
        $tc = $TestCases[$n]
        if (-not $tc.Contains('Define') -or -not $tc.Define) { continue }
        $u = $tc.Contains('Ubsan') -and $tc.Ubsan
        $k = $tc.Contains('Kasan') -and $tc.Kasan
        $key = "$($tc.Define)|$u|$k"
        if (-not $variants.Contains($key)) {
            $variants[$key] = [pscustomobject]@{ Define = $tc.Define; Ubsan = $u; Kasan = $k; OutDir = (Join-Path $Build "ktest\$n") }
        }
    }
    if ($PSVersionTable.PSVersion.Major -ge 7 -and $variants.Count -gt 1) {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $throttle = [Math]::Max(2, [Environment]::ProcessorCount / 2)
        Initialize-Rust | Out-Null      # environment (devbox paths) is inherited by the children
        $script = $PSCommandPath
        $errors = @($variants.Values | ForEach-Object -ThrottleLimit $throttle -Parallel {
            $a = @('-NoProfile', '-File', $using:script, 'build', '-OutDir', $_.OutDir, '-KernelTest', $_.Define, '-Quiet')
            if ($_.Ubsan) { $a += '-Ubsan' }
            if ($_.Kasan) { $a += '-Kasan' }
            $out = & (Get-Process -Id $PID).Path @a 2>&1 | Out-String
            if ($LASTEXITCODE -ne 0) { "--- build of $($_.Define) (ubsan: $($_.Ubsan), kasan: $($_.Kasan)) failed:`n$out" }
        })
        if ($errors.Count) { $errors | ForEach-Object { Write-Host $_ -ForegroundColor Red }; throw 'Test variant build failed.' }
        foreach ($k in $variants.Keys) { $images[$k] = Join-Path $variants[$k].OutDir 'discrete.img' }
        Write-Host ("--- built {0} test variants in parallel ({1:N1}s, {2} at a time) ---" -f $variants.Count, $sw.Elapsed.TotalSeconds, $throttle)
    }

    foreach ($n in $names) {
        $tc = $TestCases[$n]
        if ($tc.Contains('Host')) {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            Write-Host "--- [$n] host ---"
            $ok = & $tc.Host
            $results += [pscustomobject]@{ Case = $n; Result = $(if ($ok) { 'PASS' } else { 'FAIL' }); Seconds = [Math]::Round($sw.Elapsed.TotalSeconds, 1) }
            continue
        }
        if ($tc.Define) {
            $outDir = Join-Path $Build "ktest\$n"
            $ubsan = $tc.Contains('Ubsan') -and $tc.Ubsan
            $kasan = $tc.Contains('Kasan') -and $tc.Kasan
            $key = "$($tc.Define)|$ubsan|$kasan"
            if ($images.Contains($key)) {
                New-Item -ItemType Directory -Force $outDir | Out-Null
                $image = $images[$key]
            } else {
                $image = Invoke-Build -OutDir $outDir -KernelTest $tc.Define -Quiet -Ubsan:$ubsan -Kasan:$kasan
                $images[$key] = $image
            }
        } else {
            $outDir = $Build
            if (-not $releaseImage) { $releaseImage = Invoke-Build }   # build the release image once
            $image = $releaseImage
        }

        if ($tc.Contains('Tamper') -and $tc.Tamper) { $image = New-TamperedImage $image }
        $keys = [string[]]@()
        if ($tc.Contains('Keys')) { $keys = [string[]]$tc.Keys }
        $after = if ($tc.Contains('KeysAfter')) { $tc.KeysAfter } else { '' }
        $cpus  = if ($tc.Contains('Smp')) { $tc.Smp } else { 4 }
        $model = if ($tc.Contains('Cpu')) { $tc.Cpu } else { 'max' }
        $limit = if ($tc.Contains('Timeout')) { [Math]::Max($tc.Timeout, $TestTimeout) } else { $TestTimeout }
        $devs  = $tc.Contains('Devices') -and $tc.Devices
        $uefi  = $tc.Contains('Uefi') -and $tc.Uefi
        $ser   = if ($tc.Contains('Serial')) { [string[]]$tc.Serial } else { [string[]]@() }
        $serAfter = if ($tc.Contains('SerialAfter')) { $tc.SerialAfter } else { '' }
        $extra = if ($tc.Contains('Qemu')) { [string[]]$tc.Qemu } else { [string[]]@() }
        $mustExit = $tc.Contains('MustExit') -and $tc.MustExit
        $iommuKind = if ($tc.Contains('Iommu')) { $tc.Iommu } else { 'intel' }
        $diskDir = Join-Path $Build "disks\$n"
        if ($devs -and (Test-Path $diskDir)) { Remove-Item -Recurse -Force $diskDir }   # fresh disks every run
        $r = Invoke-QemuCapture $image (Join-Path $outDir "serial-$n.log") $tc.Expect $tc.Forbid $limit $keys $after $cpus $model `
            -Devices:$devs -Serial $ser -SerialAfter $serAfter -DiskDir $diskDir -Uefi:$uefi -Extra $extra -MustExit:$mustExit -IommuKind $iommuKind
        $missing = @($tc.Expect | Where-Object { -not $r.Log.Contains($_) })
        $found   = @($tc.Forbid | Where-Object { $r.Log.Contains($_) })
        $ok = ($missing.Count -eq 0) -and ($found.Count -eq 0)
        if ($mustExit -and -not $r.Exited) { $missing += 'QEMU did not end (no power-off / reset happened)'; $ok = $false }

        Write-Host ("--- [{0}] serial ({1:N1}s) ---" -f $n, $r.Seconds)
        Write-Host $r.Log.TrimEnd()
        if ($ok -and $tc.Contains('Post')) {
            $post = & $tc.Post $diskDir $image $r.Log
            if (-not $post) { Write-Host '  host check FAILED' -ForegroundColor Red }
            $ok = $ok -and $post
        }
        if (-not $ok) {
            if ($missing.Count) { Write-Host "  missing:   $($missing -join ' | ')" -ForegroundColor Red }
            if ($found.Count)   { Write-Host "  forbidden: $($found -join ' | ')" -ForegroundColor Red }
        }
        $results += [pscustomobject]@{ Case = $n; Result = $(if ($ok) { 'PASS' } else { 'FAIL' }); Seconds = [Math]::Round($r.Seconds, 1) }
    }

    Write-Host ''
    foreach ($r in $results) {
        Write-Host ("  {0,-13} {1}  ({2}s)" -f $r.Case, $r.Result, $r.Seconds) -ForegroundColor $(if ($r.Result -eq 'PASS') { 'Green' } else { 'Red' })
    }
    $failed = @($results | Where-Object Result -eq 'FAIL')
    $verdict = if ($failed.Count) { "TEST FAILED ($($failed.Count) of $($results.Count))" } else { "TEST PASSED ($($results.Count) cases)" }
    Write-TestReport $results $verdict -Partial:([bool]$Case)
    if ($failed.Count) {
        Write-Host $verdict -ForegroundColor Red
        exit 1
    }
    Write-Host $verdict -ForegroundColor Green
}

# build\test-report.md: what was tested, on what, and the result. Contributors attach it to a pull
# request as proof that the change passes the suite (CONTRIBUTING.md). Never fails the run.
function Write-TestReport($Results, [string]$Verdict, [switch]$Partial) {
    function First-Line([scriptblock]$b) { try { ((& $b) 2>&1 | Out-String).Trim() -split "`r?`n" | Select-Object -First 1 } catch { 'unknown' } }
    $commit = First-Line { git -C $Root rev-parse --short=12 HEAD }
    $dirty  = First-Line { git -C $Root status --porcelain --untracked-files=no }
    $tree = if ($dirty -and $dirty -ne 'unknown') {
        $diff = (git -C $Root diff HEAD 2>$null | Out-String)
        $h = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($diff))).Replace('-', '').Substring(0, 16).ToLower()
        "$commit + uncommitted changes (diff sha256 $h)"
    } else { "$commit (clean)" }
    $tools = @(
        "clang: $(First-Line { & (Find-Tool 'clang' $LlvmDirs) --version })",
        "nasm: $(First-Line { & (Find-Tool 'nasm') -v })",
        "qemu: $(First-Line { & (Find-Tool 'qemu-system-x86_64' $QemuDirs) --version })",
        "rustc: $(First-Line { Push-Location (Join-Path $Root 'kernel\rust'); try { & (Join-Path (Split-Path (Initialize-Rust) -Parent) 'rustc') --version } finally { Pop-Location } })"
    )
    $cpu = First-Line { (Get-CimInstance Win32_Processor | Select-Object -First 1).Name }
    $os  = First-Line { (Get-CimInstance Win32_OperatingSystem).Caption }
    $lines = @(
        '# D-OS test report', '',
        "- Result: **$Verdict**$(if ($Partial) { ' (partial run: selected cases only)' } else { ' (full suite)' })",
        "- Tree: $tree",
        "- Date (UTC): $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm'))",
        "- Host: $os, $cpu",
        "- Tools: $($tools -join '; ')",
        '', '| Case | Result | Seconds |', '|---|---|---|'
    ) + @($Results | ForEach-Object { "| $($_.Case) | $($_.Result) | $($_.Seconds) |" })
    $path = Join-Path $Build 'test-report.md'
    try {
        New-Item -ItemType Directory -Force $Build | Out-Null
        [IO.File]::WriteAllText($path, ($lines -join "`n") + "`n")
        Write-Host "Test report: $(Get-RelPath $path)"
    } catch { Write-Host "Test report not written: $_" -ForegroundColor Yellow }
}

# Soak: boots the KTEST_SOAK variant and watches it for $Minutes. Every round prints "SOAK round N OK";
# the run fails on a panic, a failed round, or no progress for 60 s.
function Invoke-Soak {
    $outDir = Join-Path $Build 'soak'          # not ktest\soak: a test run may rebuild that meanwhile
    $image = Invoke-Build -OutDir $outDir -KernelTest 'SOAK' -Quiet
    $log = Join-Path $outDir 'serial-soak-long.log'
    if (Test-Path $log) { Remove-Item $log }
    $qemu = Find-Tool 'qemu-system-x86_64' $QemuDirs
    $qargs = (Get-QemuArgs $image $Smp) + @('-display', 'none', '-serial', "file:$log")
    $proc = Start-Process -FilePath $qemu -ArgumentList $qargs -PassThru -NoNewWindow
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $lastRound = 0; $lastProgress = 0.0; $failure = $null
    Write-Host "Soak: $Smp CPUs for $Minutes min (log: $(Get-RelPath $log))"
    try {
        while ($sw.Elapsed.TotalMinutes -lt $Minutes) {
            Start-Sleep -Seconds 2
            $out = Read-Shared $log
            if ($proc.HasExited) { $failure = 'QEMU exited'; break }
            if ($out.Contains('KERNEL PANIC') -or $out.Contains('SOAK FAIL')) { $failure = 'panic or failed round'; break }
            $m = [regex]::Matches($out, 'SOAK round (\d+) OK')
            if ($m.Count) {
                $round = [int]$m[$m.Count - 1].Groups[1].Value
                if ($round -ne $lastRound) {
                    $lastRound = $round; $lastProgress = $sw.Elapsed.TotalSeconds
                    if ($round % 30 -eq 0) { Write-Host ("  {0:N1} min: round {1}" -f $sw.Elapsed.TotalMinutes, $round) }
                }
            }
            if ($sw.Elapsed.TotalSeconds - [Math]::Max($lastProgress, 20) -gt 60) { $failure = 'no progress for 60 s (hang?)'; break }
        }
    } finally {
        if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
        $proc.WaitForExit()
    }
    $out = Read-Shared $log
    $tail = ($out -split "`n" | Select-Object -Last 25) -join "`n"
    if ($failure -or $lastRound -lt 1) {
        Write-Host $tail
        Write-Host "SOAK FAILED after $([Math]::Round($sw.Elapsed.TotalMinutes, 1)) min, round $($lastRound): $failure" -ForegroundColor Red
        exit 1
    }
    Write-Host ($out -split "`n" | Where-Object { $_ -match 'SOAK round' } | Select-Object -Last 1)
    Write-Host "SOAK PASSED: $lastRound rounds in $([Math]::Round($sw.Elapsed.TotalMinutes, 1)) min on $Smp CPUs" -ForegroundColor Green
}

switch ($Target) {
    'build' {
        $o = if ($OutDir) { [IO.Path]::GetFullPath($OutDir) } else { $Build }
        Invoke-Build -OutDir $o -KernelTest $KernelTest -Ubsan:$Ubsan -Kasan:$Kasan -Quiet:$Quiet | Out-Null
    }
    'run'   { Invoke-Run }
    'debug' { Invoke-Debug }
    'test'  { Invoke-Test }
    'soak'  { Invoke-Soak }
    'clean' { Invoke-Clean }
    'bench' {
        $o = Join-Path $Build 'bench'
        $img = Invoke-Build -OutDir $o -KernelTest 'HWBENCH' -Quiet:$Quiet
        $dst = Join-Path $Build 'discrete-bench.img'
        Copy-Item -LiteralPath $img -Destination $dst -Force
        Write-Host "Hardware benchmark image: $dst (write it to a USB stick like discrete.img; disks are only read)"
    }
}
