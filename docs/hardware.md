# Booting D-OS on a real PC

D-OS boots to its kernel and services, then a shell (`log` there shows the whole boot log). This page
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
.\dbuild.ps1          # build/discrete.img (BIOS + UEFI; ./dbuild.sh on Linux)
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
| `CET: supervisor shadow stacks on ...` | CET shadow stacks in use; `off: ...` says why not ([hardening.md](hardening.md#cet)) |
| `SMP: N CPUs online` | every hardware thread started |
| `Idle: C1 MWAIT ...` (then the `_CST` states), `Performance: ...` | idle states and CPU speed control in use; kdb's `power` shows each CPU's idle-state counts ([power.md](power.md)) |
| `IOMMU: ...` | Intel VT-d or AMD-Vi driven: `DMA remapping on for every device`; the AMD-Vi unit's own PCI function is listed as kept by the kernel; firmware-reserved ranges (RMRR, IVMD) show as `... identity mapped for <device>` or `... refused: <why>`; `interrupt remapping on (...)`, or `off (<why>)` (then a device could forge interrupts) |
| `TPM: ...` | whether the firmware TPM was found and answered |
| `devmgr: disks are read-only`, `storaged: volume '...': ... read-only` | safety mode active |
| `Summary: ...` (just before `User: init started`) | the key early lines repeated, since they scroll off screen |

Large screens get doubled glyphs. If the log scrolls too fast, film it.

## 4. Not supported yet

- **USB** (xHCI, any port, behind USB 2 and USB 3 hubs): keyboards (boot protocol, US layout, key
  repeat, Caps Lock LED; up to four at once, as receivers and lighting controllers often offer a
  keyboard interface too), mice (up to two; their input reaches the device manager's input
  endpoint, nothing uses it yet), USB sticks and disks (bulk-only mass storage, 512-byte
  sectors, read-only like every disk), and USB Audio Class 1.0/2.0 devices via xHCI isochronous
  transfers (`usbaudio.ddrv`). The driver prints one line per device it finds
  (xhci 10:00.0: port 8.2: mouse ready on port 8.2 ...), with the controller's PCI address and the
  port path through any hubs. A device that keeps disconnecting and reconnecting on its own is
  left alone after three tries, until it is unplugged. Not supported: tablets and other absolute
  pointers, USB video, UAS-only disks, 4K-sector disks.
- **Audio** ([audio.md](audio.md)): Intel HD Audio (`hda.ddrv`, dynamic codec/widget/pin graph
  discovery, jack sense, HDMI/DP ELD), USB Audio (`usbaudio.ddrv`), and VirtIO Sound
  (`virtio-snd.ddrv`), routed through `audio.dsvc` with automatic output switching and the shell's
  `audio` command.
- **Several keyboards**: the first keyboard that types is in use. A keyboard plugged in while
  another is in use is held: nothing it types arrives until it is accepted with
  **Ctrl+Alt+Insert** on a keyboard already in use (so a USB device posing as a keyboard cannot
  type commands on its own).
- **Network, GPU acceleration.**
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
| Gigabyte B650 AORUS ELITE AX, Ryzen 9 9900X, RX 9070, 32 GiB, NVMe; UEFI | boots to user space; verified + measured boot (firmware TPM via TCG2); NVMe read; EFI partition mounted read-only. The kernel drives the firmware TPM through CRB with the ACPI start method (`_DSM`): `TPM 2.0 (CRB, ACPI start, manufacturer 'AMD')`, the loader's measurement replayed. USB: keyboards, a mouse, the boot stick as a disk at SuperSpeed (port 5), USB 2 and USB 3 hubs (0bda:5411, 0bda:0411) |
