# Graphics and GPU Drivers

D-OS runs every GPU driver as an unprivileged, isolated user-space process (`.ddrv`) confined inside
a per-device IOMMU domain (Intel VT-d or AMD-Vi), coordinated by `gpu.dsvc` alongside the UEFI GOP
framebuffer baseline. Framebuffer VMOs are pinned directly into the GPU's IOMMU domain as
read-only DMA targets (`DMA_DEVICE_READ`, zero copy) or blitted into write-combining (WC) BAR
apertures without readback.

**Code:** `user/lib/gpu` (`dosgpu`: `no_std`, `#![forbid(unsafe_code)]` EDID 1.4 / CTA-861 / DisplayID 2.0
parser with FreeSync/HDR10 metadata, VirtIO-GPU 2D/3D VirGL protocol & validator, AMD RDNA PCI IDs /
IP Discovery / DCN 4.0.1 & 3.x register tables / DP AUX & link training / tear-free buffer-age vsync
flipping / HW cursor / OSSSYS IH ring / DSC PPS & mode-setting / PM4 & SDMA 2D copy validators, Intel
Xe/i915 PCI IDs / GMD_ID / Display Pipes / MI Blitter, NVIDIA Open-GSP PCI IDs / `PMC_BOOT` / GSP-RM
RPC framing, 8-bit & 10-bit dirty-rect WC pixel blitters), `user/devmgr/src/{gpu_drv,virtio_gpu,amdgpu,xe,nvgpu}.rs`,
`user/gpu` (`gpu.dsvc`), `user/lib/libd/src/gpu.rs`, `user/init/services/gpu.dman`.
**Tests:** `gpu-host`, `gpu-virtio`, `gpu-virtio-amd`, `gpu-gop`, `gpu-shell`.
The compositor and window manager built on `gpu.display` is D-AWMI ([awmi.md](awmi.md)).

## Architecture

| Component | Role |
|---|---|
| GOP framebuffer baseline (`gpu.dsvc`) | Uses `platform:display` (`DISPLAY_RGB32`, write-combining BAR 0) as a zero-setup linear framebuffer backend; maps BAR 0 lazily on first `OP_PRESENT` so the terminal remains undisturbed on normal boots, and forwards the GOP framebuffer physical base/geometry (via `device_bar_addr`) to PCI GPU drivers for live scanout verification. |
| `virtio-gpu.ddrv` | Modern VirtIO 1.x GPU (PCI `1AF4:1050`): `controlq` + `cursorq` with MSI-X interrupts, zero-copy IOMMU-pinned framebuffer VMOs, EDID parsing (`VIRTIO_GPU_F_EDID`), dynamic modesetting, damage-rectangle flush, 64x64 hardware cursor, and VirGL 3D context/command submission (`VIRTIO_GPU_F_VIRGL`) with strict CS validation. |
| `amdgpu.ddrv` | AMD RDNA / AMDGPU (PCI `1002:*` class `03.*`): targets RDNA 4 (Navi 48 / RX 9070 / RX 9070 XT, DCN 4.0.1 / MMHUB 4.1 / OSSSYS 7.0 / SDMA 7.0), RDNA 3 (DCN 3.2), RDNA 2 dGPU (DCN 3.0), and Ryzen iGPU (DCN 3.1.5). Maps BAR 5 RMMIO (UC), BAR 2 Doorbell, and bounded WC windows of BAR 0 VRAM (O(1) kernel device VMO up to 64 GiB Resizable BAR). Performs a strictly read-only startup probe (checksum-verified IP Discovery, MMHUB MC-to-VRAM aperture translation, active DCN pipes, OTG timings & measured refresh rate, and DP AUX read-only DPCD + multi-block EDID 1.4/CTA-861/DisplayID 2.0). When the active pipe matches the UEFI GOP framebuffer, allocates 2–3 off-GOP VRAM scanout buffers (respecting `MEM_RESERVED_INFO` and top-of-VRAM firmware reserve), passes a 3-frame page-flip self-check (else reverts to GOP), and provides tear-free buffer-age vsync page flipping, 64x64/256x256 HUBP/DPP hardware cursor, OSSSYS IH ring vblank/flip IRQs (with predicted-vblank timer fallback), guarded mode-setting (DCCG/OTG/DP link training/DSC 1.2a PPS with automatic revert), FreeSync VRR, 10-bit HDR10, per-pipe multi-monitor outputs, crash recovery, GOP hand-back on session stop/shutdown, and strict PM4/SDMA validation. |
| `xe.ddrv` | Intel Xe / i915 (PCI `8086:*` class `03.*`): targets Gen9/Gen11/Gen12 (Xe-LP), Arc Alchemist (Xe-HPG), and Arc Battlemage / Lunar Lake (Xe2). Maps BAR 0 `GTTMMADR` (UC) and bounded 32 MiB WC BAR 2 aperture; decodes `GMD_ID`, probes active Display Pipes A-D (`TRANS_CONF`, `PIPE_SRCSZ`, `PLANE_SURF_1`), supports atomic `PLANE_SURF` page flips, and validates MI/XY Blitter command streams on IOMMU-pinned rings. |
| `nvgpu.ddrv` | NVIDIA Open-GSP (PCI `10DE:*` class `03.*`): targets Turing, Ampere, Ada Lovelace, and Blackwell GPUs via the open GSP-RM architecture. Maps BAR 0 MMIO (UC) and bounded 32 MiB WC BAR 1 VRAM; decodes `NV_PMC_BOOT_0`/`BOOT_42` and local VRAM size, probes GSP Falcon status, pins Open-GSP RPC DMA queues, and validates Open-GSP RPC message framing & checksums. |
| `gpu.dsvc` | Exposes capability-separated `gpu.query`, `gpu.display`, and `gpu.render` endpoints, manages the GOP baseline and PCI GPU backends from `devmgr.gpu`, and transparently reconnects adapters across driver restarts. |

## Kernel Support for Modern GPUs

- **O(1) Large Device VMOs:** Device BAR VMOs store their physical base and MSI-X hidden page ranges
  directly rather than per-page frame arrays, supporting Resizable BAR VRAM apertures up to 64 GiB
  with zero frame-vector heap allocation. Drivers map bounded windows via `Mapping::of_range`.
- **Write-Combining VRAM BARs:** Prefetchable memory BARs of 16 MiB or larger on PCI display
  controllers (`class 03`) are mapped Write-Combining (`VMM_WC`); register and doorbell BARs remain
  Uncached (`VMM_UC`).
- **Display BAR Ownership:** PCI display controllers (`class 03`) may map their own VRAM BAR even
  when the UEFI boot GOP framebuffer lies inside it (switching the kernel console to serial); all
  non-display PCI devices remain strictly blocked from overlapping `platform:display`.

## Capability Model

Services declare GPU permissions in their signed `.dman` manifest under `[grants]`:

```toml
[grants]
gpu = ["query"]                     # read-only adapter, mode, EDID, VRAM, and IOMMU status
gpu = ["display"]                   # modesetting, framebuffer VMO attach, present, page flip, cursor
gpu = ["render"]                    # GPU context creation and validated command submission
```

- **No ambient authority:** processes without `grants.gpu` receive zero GPU endpoint handles.
- **Role separation:** `gpu.query` refuses display/render operations with `ERR_ACCESS_DENIED`;
  `gpu.render` cannot alter display scanout; `gpu.display` cannot submit render command buffers.
- **Command-stream validation:** all VirGL 3D, AMD PM4/SDMA, Intel MI/Blitter, and NVIDIA Open-GSP
  RPC command buffers are validated in pure `#![forbid(unsafe_code)]` Rust (`dosgpu`) before any
  hardware submission.

## Shell Command

The shell holds `gpu = ["query"]` (read-only) and `awmi = ["admin"]` and provides:

- `gpu` (`display` alias) — list detected adapters with driver, PCI ID, active resolution, VRAM
  size, feature flags (`iommu`, `wc`, `edid`, `cursor`, `flip`, `async`, `native`, `vrr`, `hdr`,
  `dsc`, `virgl3d`, `gsp`), and frame count.
- `gpu modes [id]` — list supported display modes and refresh rates (up to 540+ Hz) for an adapter.
- `gpu display [id]` — read-only live display probe: DCN generation, active pipe(s), OTG timings,
  measured refresh rate, DPCD link state (lanes/rate/UHBR/DSC), MC/VRAM/GOP scanout match, and EDID
  modes.
- `gpu flip-test [id] [ms]` — runs an alternating-pattern hardware page-flip test (default 5 s) via
  `awmi.admin` (so the shell never holds `gpu.display`) and automatically reverts to the firmware
  framebuffer, reporting frames presented, missed/late flips, and measured refresh rate.

## Trade-offs

- Native AMD display takeover requires an exact GOP-to-DCN framebuffer match and a passing 3-frame
  flip self-check; if either fails (or `display = firmware` is set in `BOOT.CFG`), the driver stays
  read-only and the compositor uses the firmware GOP framebuffer so the screen never goes dark.
- Native DCN scanout writes damaged rectangles over PCIe WC VRAM from RAM backbuffers using
  buffer-age tracking (avoiding full-frame copies and VRAM readback), while keeping the GOP
  framebuffer untouched for instant hand-back on session stop, shutdown, or driver crash.
- Mode switching with link retraining or DSC is opt-in and guarded by full register save/restore with
  automatic revert if OTG frame progression stalls.

## Tests

- `gpu-host`: `dosgpu` unit tests (EDID 1.4 / CTA-861 / DisplayID 2.0 / FreeSync / HDR10, 8/10-bit
  dirty-rect WC blitting & buffer-age tracking, VirtIO-GPU 2D/3D VirGL, AMD RDNA / RX 9070 / IP
  Discovery / simulated DCN 4.0.1 & 3.x register files, DP AUX & link training, flip self-check,
  auto-revert & crash recovery, HW cursor, OSSSYS IH ring, DSC 1.2a PPS, VRR/HDR10, PM4/SDMA 2D
  composition, Intel Xe / MI, NVIDIA Open-GSP RPC) plus 15,000+ fuzz rounds over untrusted parsers,
  command validators, and arbitrary DCN register responses.
- `gpu-virtio` / `gpu-virtio-amd`: offline QEMU tests under Intel VT-d and AMD-Vi verifying
  IOMMU-confined `virtio-gpu.ddrv`, EDID, zero-copy framebuffer attach & multi-rect damage scanout,
  hardware cursor, dynamic mode switching (`800x600` <-> `1024x768`), capability role separation
  (including read-only `OP_GET_DISPLAY_INFO` allowed and `OP_FLIP_TEST`/`OP_RELEASE_DISPLAY` refused
  on `gpu.query`), VirGL CS validation, and live driver crash-and-restart recovery.
- `gpu-gop`: UEFI QEMU test verifying the GOP framebuffer baseline, role separation, and WC scanout.
- `gpu-shell`: QEMU shell test verifying `gpu`, `gpu modes`, and `gpu display` output on `virtio-gpu-pci`.
