# Graphics and GPU Drivers

D-OS runs every GPU driver as an unprivileged, isolated user-space process (`.ddrv`) confined inside
a per-device IOMMU domain (Intel VT-d or AMD-Vi), coordinated by `gpu.dsvc` alongside the UEFI GOP
framebuffer baseline. Framebuffer VMOs are pinned directly into the GPU's IOMMU domain as
read-only DMA targets (`DMA_DEVICE_READ`, zero copy) or blitted into write-combining (WC) BAR
apertures without readback.

**Code:** `user/lib/gpu` (`dosgpu`: `no_std`, `#![forbid(unsafe_code)]` EDID 1.4 parser, VirtIO-GPU
2D/3D VirGL protocol & validator, AMD RDNA PCI IDs / IP Discovery / DCN / PM4 / SDMA, Intel Xe/i915
PCI IDs / GMD_ID / Display Pipes / MI Blitter, NVIDIA Open-GSP PCI IDs / `PMC_BOOT` / GSP-RM RPC
framing, dirty-rect WC pixel blitter), `user/devmgr/src/{gpu_drv,virtio_gpu,amdgpu,xe,nvgpu}.rs`,
`user/gpu` (`gpu.dsvc`), `user/lib/libd/src/gpu.rs`, `user/init/services/gpu.dman`.
**Tests:** `gpu-host`, `gpu-virtio`, `gpu-virtio-amd`, `gpu-gop`, `gpu-shell`.

## Architecture

| Component | Role |
|---|---|
| GOP framebuffer baseline (`gpu.dsvc`) | Uses `platform:display` (`DISPLAY_RGB32`, write-combining BAR 0) as a zero-setup linear framebuffer backend; maps BAR 0 lazily on first `OP_PRESENT` so the terminal remains undisturbed on normal boots. |
| `virtio-gpu.ddrv` | Modern VirtIO 1.x GPU (PCI `1AF4:1050`): `controlq` + `cursorq` with MSI-X interrupts, zero-copy IOMMU-pinned framebuffer VMOs, EDID parsing (`VIRTIO_GPU_F_EDID`), dynamic modesetting, damage-rectangle flush, 64x64 hardware cursor, and VirGL 3D context/command submission (`VIRTIO_GPU_F_VIRGL`) with strict CS validation. |
| `amdgpu.ddrv` | AMD RDNA / AMDGPU (PCI `1002:*` class `03.*`): targets RDNA 4 (Navi 48 / RX 9070 / RX 9070 XT, GFX12 / DCN 4.0.1 / SDMA 7.0), RDNA 3 (Navi 31/32/33), and RDNA 2 (Navi 21/22/23/24 & Ryzen desktop iGPUs). Maps BAR 5 RMMIO (UC), BAR 2 Doorbell, and a bounded 32 MiB WC window of BAR 0 VRAM (O(1) kernel device VMO supporting up to 64 GiB Resizable BAR); reads VRAM size and parses the checksum-verified AMD IP Discovery table via indirect MMIO VRAM access; supports WC VRAM scanout, live DCN HUBP0 atomic page flips, and strict PM4 Type-3 / SDMA command-stream validation on IOMMU-pinned rings. |
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

The shell holds `gpu = ["query"]` (read-only) and provides:

- `gpu` (`display` alias) — list detected adapters with driver, PCI ID, active resolution, VRAM
  size, feature flags (`iommu`, `wc`, `edid`, `cursor`, `flip`, `virgl3d`, `gsp`), and frame count.
- `gpu modes [id]` — list supported display modes and refresh rates for an adapter.

## Tests

- `gpu-host`: `dosgpu` unit tests (EDID 1.4, dirty-rect WC blitting, VirtIO-GPU 2D/3D VirGL, AMD
  RDNA / RX 9070 / IP Discovery / PM4 / SDMA, Intel Xe / MI, NVIDIA Open-GSP RPC) plus 13,000 fuzz
  rounds over untrusted parsers and command validators.
- `gpu-virtio` / `gpu-virtio-amd`: offline QEMU tests under Intel VT-d and AMD-Vi verifying
  IOMMU-confined `virtio-gpu.ddrv`, EDID, zero-copy framebuffer attach & damage-rect scanout,
  hardware cursor, dynamic mode switching (`800x600` <-> `1024x768`), capability role separation,
  VirGL CS validation, and live driver crash-and-restart recovery.
- `gpu-gop`: UEFI QEMU test verifying the GOP framebuffer baseline, role separation, and WC scanout.
- `gpu-shell`: QEMU shell test verifying `gpu` and `gpu modes` output on `virtio-gpu-pci`.
