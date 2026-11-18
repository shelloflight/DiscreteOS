# Booting D-OS on a real PC

D-OS boots to its kernel and services and shows the boot log. There is no shell yet. This page
explains how to try it on your own machine safely and what to report.

## Safety: D-OS never writes your disks

A normal boot is read-only for every disk, enforced in three independent places:

1. **Block drivers** refuse every write and flush before it reaches the controller.
2. **The device manager** starts drivers writable only in test modes, and logs
   `devmgr: disks are read-only`.
3. **The storage service** mounts every volume read-only and hands out read rights only.

D-OS mounts FAT32 and DFS partitions it finds (including a Windows EFI partition) but only reads
them. The `readonly`, `boot` and `uefi` tests check that every disk image is byte-identical after a
boot. Nothing is saved anywhere, so reports are photos of the screen.

## 1. Make a USB stick

```powershell
.\build.ps1          # build\discrete.img (BIOS + UEFI)
```

> **Writing the image erases the whole USB stick.** Double-check you picked the stick, not an
> internal drive.

With [Rufus](https://rufus.ie): select the stick, *Disk or ISO image* → `build\discrete.img`,
START, and choose *DD image* mode if asked. To reuse the stick later, delete its partitions in Disk
Management and create a new one.

## 2. Firmware settings

- **Secure Boot: off.** The D-OS loader is not signed for UEFI Secure Boot (it verifies the kernel
  itself). Turn it back on afterwards.
- **Fast Boot: off**, so the firmware looks at USB devices.
- Pick the stick once from the firmware's boot menu (often F8, F11 or F12), choosing the
  **UEFI:** entry.

## 3. What you should see

| Line | Meaning |
|---|---|
| `D-OS: kernel signature valid`, `kernel relocated (KASLR, ...)` | verified boot and KASLR work on this firmware |
| `CPU: ...`, `Protections: WP on, NX on, SMEP on, SMAP on, UMIP on` | CPU and protections detected |
| `Speculation: ...` | mitigations chosen for this CPU ([hardening.md](hardening.md)) |
| `SMP: N CPUs online` | every hardware thread started |
| `IOMMU: ...` | Intel VT-d or AMD-Vi driven: `DMA remapping on for every device`; the AMD-Vi unit's own PCI function is listed as kept by the kernel |
| `TPM: ...` | whether the firmware TPM was found and answered |
| `devmgr: disks are read-only`, `storaged: volume '...': ... read-only` | safety mode active |
| `Summary: ...` (just before `User: init started`) | the key early lines repeated, since they scroll off screen |

Large screens get doubled glyphs. If the log scrolls too fast, film it.

## 4. Not supported yet

- **USB**: only keyboards plugged straight into a root port of an xHCI controller (boot protocol,
  US layout, no key repeat). Keyboards behind a hub (some boards wire every port through an internal
  hub), mice and USB storage are not supported yet; some boards also emulate PS/2 for USB keyboards.
- **Network, sound, GPU acceleration.**
- The kernel debugger needs a serial port.

Switch off with the power button; nothing needs saving.

## 5. If something goes wrong

- Black screen: photograph it, try the other USB entry if there are two, check Secure Boot is off.
- `KERNEL PANIC` or a fault report: photograph the whole report (it has a backtrace and a `[kaslr]`
  offset for symbolizing).
- It stops: the last line on screen says where.

## Reporting

Open an issue with photos of the boot log, the board model and firmware version, and the CPU.

## Hardware known to boot

| Machine | Result |
|---|---|
| Gigabyte B650 AORUS ELITE AX, Ryzen 9 9900X, RX 9070, 32 GiB, NVMe; UEFI | boots to user space; verified + measured boot (firmware TPM via TCG2); NVMe read; EFI partition mounted read-only. Kernel TPM use needs AML (not yet) |
