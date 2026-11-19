# Power control

D-KRNL can switch the machine off (ACPI S5), suspend to RAM and resume (ACPI S3), and reset it,
puts idle CPUs into the deepest idle state worth it, and lets CPUs choose their own speed
(CPPC/HWP) where the hardware can.

Power-off and S3 sleep need nothing from AML on most machines; when the AML namespace is loaded
([acpi.md](acpi.md)) it supplies `\_S5`/`\_S3` (also as methods) and `\_TTS`/`\_PTS`/`\_WAK` run
around transitions.

**Code:** `kernel/arch/x86_64/power.c`, `kernel/arch/x86_64/s3.asm`, `kernel/include/power.h`;
syscall `system_power` ([abi.md](abi.md)). Idle states and performance: `kernel/arch/x86_64/cpupm.c`,
`kernel/include/cpupm.h`, `kernel/rust/src/dev/cpupm.rs`, `kernel/aml/src/processor.rs`.

## At boot

`power_init` reads the **FADT** (PM1a/PM1b control blocks, SMI command port, reset register, 8042
flag, hardware-reduced sleep register) and finds the `\_S5` package in the **DSDT** with a small
scanner (`power_parse_s5`) that decodes SLP_TYPa/b. It prints, for example:

```
Power: power-off by ACPI S5 (SLP_TYP 0/0, PM1a port 0x604); reset by reset register (port 0xcf9 = 0xf)
```

If `\_S5` is a method rather than a data package, the scanner finds nothing; the AML interpreter
evaluates it a moment later and hands the values over (`power_set_s5`, printed as
`Power: \_S5 from AML: ...` when they differ). Without `\_S5` or a PM1 control block, power-off is
reported as unavailable; reset still works.

## Switching off

`power_off` runs `\_TTS(5)` and `\_PTS(5)` on the ACPI thread (when the namespace is loaded and the
caller may block), enables ACPI mode if needed, writes `SLP_TYP | SLP_EN` to PM1b then PM1a (or the
hardware-reduced sleep register), and if the machine is still running 2 s later, says so and returns
(`NOT_SUPPORTED` to user space).

## Suspending and resuming (ACPI S3)

`power_suspend` (via `system_power(..., DOS_POWER_SUSPEND)` or `power sleep` in the shell):

1. User space (`init`) syncs every volume provider (`svc::SYNC`) and asks `devmgr` (`svc::SUSPEND`)
   to quiesce PCI bus mastering and stop every user-space driver before entering S3.
2. The kernel pins the caller to the BSP (CPU 0), runs `\_TTS(3)` and `\_PTS(3)` on the ACPI thread,
   parks all APs in `cli; hlt` (draining their run queues and stopping the watchdog), and saves PCI
   configuration headers (`dkrnl_pci_suspend`).
3. A real-mode waking trampoline is installed in low RAM and its address written to the FADT's FACS
   32-bit waking vector; `WAK_STS` is cleared, `time_suspend` snapshots the monotonic clock, and
   `s3_enter` saves BSP GPRs, control registers, EFER, segment bases, and CET SSP, flushes caches
   (`wbinvd`), and writes `SLP_TYP | SLP_EN` to PM1b/PM1a.
4. On wake, firmware jumps to the real-mode trampoline, which re-enters long mode on the BSP and
   restores CPU state (PAT, GDT/TSS/IDT, SYSCALL, CET, monotonic TSC, LAPIC), PCI config space,
   VT-d/AMD-Vi IOMMU DMA and interrupt remapping, and IOAPIC routes.
5. Interrupts are re-enabled, APs are restarted via INIT-SIPI-SIPI through `ap_resume_entry64`
   (restoring per-CPU GDT/TSS/IDT/CET/XSAVE/speculation state and timers), CPPC/HWP is re-applied,
   ACPI `\_PIC(1)`, `\_WAK(3)`, `\_TTS(0)` and SCI sources are restored, and `TPM2_Startup(STATE)`
   is issued if a TPM is present.
6. `init` asks `devmgr` (`svc::RESUME`) to restart every driver and re-attach disks transparently.

## Resetting

`power_reboot` tries, in order: the FADT reset register, the 8042 reset line, port 0xCF9, and
finally a triple fault. It never returns.

## Who may do it

- User space: `system_power(power, action)` with the **POWER resource**, which the kernel gives to
  init only.
- kdb: `poweroff`, `reboot`.
- The machine's power button: the kernel signals init's power-button event, and init shuts down
  cleanly before asking ([acpi.md](acpi.md)).

The kernel flushes nothing; storage services must sync before asking.

## Idle states

An idle CPU (nothing ready to run) waits in the deepest state whose target residency (twice its exit
latency) fits the time it expects to stay idle: until its next timer (the kernel is tickless, so
that is known), but no longer than twice its recent average idle period (interrupts and IPIs are
not predictable; the recent past is the guess).

- **At boot**, from CPUID: MWAIT C1 on bare metal when the CPU can end MWAIT on an interrupt with
  interrupts off; HLT otherwise. Under a hypervisor the CPU polls for 30 us first, then HLT (waking
  a halted virtual CPU costs tens of microseconds).
- **MWAIT** watches the cache line of the CPU's `need_resched`: a CPU that queues work for it
  just stores there, no IPI. It is entered with interrupts off, so the time is measured before the
  interrupt handler runs.
- **From the firmware**: the first present processor's `_CST` (every CPU of a machine has the same
  one), once the AML namespace is loaded. Its C1 gives the MWAIT hint; deeper states are entered by
  MWAIT hint or by reading an I/O port. They are used only on bare metal with an APIC timer that
  keeps running in them (ARAT) and an invariant TSC. A C3 entered by I/O port needs caches kept
  coherent with bus masters: only on AMD family 17h and later (as Linux assumes); elsewhere skipped.

What a Zen 5 desktop's tables lead to (the values are its firmware's):

```
ACPI: 24 processor(s); \_SB_.PLTF.C000: _CST 3 state(s), _CPC revision 3, registers in MSR, _PSS 2 state(s), control in MSR
Idle: C1 MWAIT 0 (1 us), C2 I/O 0x414 (18 us), C3 I/O 0x415 (350 us) from _CST
```

kdb's `power` prints how often each CPU entered each state and for how long.

## CPU performance

The kernel lets the CPU pick its own speed where it can, and asks for the fastest one otherwise:

1. **ACPI CPPC** (`_CPC`), when its registers are MSR fields ("functional fixed hardware"), I/O
   ports or constants (AMD Zen's CPPC MSRs, Intel's HWP MSRs): CPPC is enabled, and every CPU may
   run between its lowest non-linear and its highest performance, with no desired performance
   (autonomous) and an energy-performance preference (EPP) of 0x80, balanced.
2. **Intel HWP** without `_CPC`: the same through IA32_HWP_REQUEST.
3. **P-states** (`_PSS`/`_PCT`): the fastest one. There is no load-driven governor.

Each CPU writes its own registers (a kernel thread pinned to it). Every MSR is accessed through
`msr_read_safe`/`msr_write_safe`: a #GP (an MSR that CPU does not have) makes the access fail and
the feature stay as the firmware set it. AMD's CPPC MSRs are used only when `_CPC` describes them
(the firmware may have CPPC disabled). `cpupm_set_policy` switches every CPU to performance (EPP 0,
at least nominal), balanced or power saving (EPP 0xFF, no boost); nothing calls it yet.

```
Performance: ACPI CPPC (_CPC), autonomous, balanced (EPP 0x80); highest <h>, nominal <n>, lowest <l> (600-4400 MHz); 24 CPU(s)
```

## Tests

`poweroff` (VMEX resource refused; with POWER, QEMU must actually exit), `poweroff-uefi`, `reboot`,
`powerbutton`, `s3` (QEMU q35 with S3 enabled: `power sleep` in the shell, `system_wakeup`, full
4-CPU + VT-d + PCI + driver resume, post-wake keyboard and disk read, then `power off`), and the
`\_S5` scanner fuzzed in `fuzz`.

`cpupm`: a firmware description with an I/O-port C2 (port 0x80) and CPPC is installed (deep states
forced on under QEMU); every CPU sleeps and wakes 200 times and enters the C2; `cpupm-bochs` does
the same in Bochs, which faults on unknown MSRs like a CPU (QEMU ignores them): boot idle is MWAIT,
missing MSRs are refused without a panic, CPPC and HWP are refused cleanly. `aml-host` reads
`_CST`, `_CPC` and `_PSS` from built byte code, malformed objects, and the build machine's tables.

## Limitations

- S3 requires a 32-bit FACS waking vector and usable low RAM below 1 MiB (hardware-reduced ACPI /
  S0ix modern standby is not implemented).
- Idle and performance use the first present processor's objects for every CPU; `_LPI`, `_CSD`
  and `_PSD` (dependency domains) are not used.
- `_CPC` registers in system memory or PCC (platform communication channel) are not reached.
- Intel firmware that loads its processor SSDTs through `_PDC`/`_OSC` (dynamic tables) shows no
  `_CST`: C1 by MWAIT and HWP still work.
