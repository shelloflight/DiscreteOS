# Audio

D-OS provides zero-setup, capability-gated, IOMMU-confined audio across Intel HD Audio, USB Audio
Class 1.0/2.0, and VirtIO Sound. All audio drivers run as isolated unprivileged user-space processes
(`.ddrv`) whose DMA buffers are pinned inside per-device IOMMU domains; PCM data flows through
zero-copy shared-memory `IoRing` VMOs (`app` ↔ `audio.dsvc` ↔ audio drivers).

**Code:** `user/lib/audio` (`dosaudio`: `no_std`, zero-alloc, zero-unsafe PCM converter, resampler,
mixer, routing policy, dynamic HDA widget graph solver, ELD parser, UAC 1.0/2.0 parser),
`user/audio` (`audio.dsvc`), `user/devmgr/src/{hda,virtio_snd,usbaudio}.rs`,
`user/devmgr/src/xhci/isoc.rs`, `user/lib/libd/src/audio.rs`, `user/init/services/audio.dman`.
**Tests:** `audio-host`, `audio-hda`, `audio-virtio`, `audio-usb`, `audio-sec`.

## Architecture

| Component | Role |
|---|---|
| `hda.ddrv` | Intel HD Audio (PCI `04.03.*`): CORB/RIRB (with ICW/IRR fallback), dynamic codec/AFG/widget/pin graph discovery (no board tables), unsolicited jack detection + `GET_PIN_SENSE`, HDMI/DP ELD parsing (`GET_DIP_SIZE`/`GET_ELD_DATA`), 4-period BDL DMA streams, and an LPIB stall watchdog. |
| `usbaudio.ddrv` + `xhci.ddrv` | Isolated USB Audio Class 1.0 & 2.0 driver spawned by `devmgr` when `xhci.ddrv` discovers an Audio Class device (`bInterfaceClass = 0x01`). `xhci.ddrv` executes control transfers and xHCI isochronous TRBs (`T_ISOCH`, `CErr = 0`) over a dedicated USB-bus channel (`TAG_USB_BUS`) and shared `IoRing`. |
| `virtio-snd.ddrv` | VirtIO 1.2 Sound (PCI `1AF4:1059`): `controlq`, `eventq`, `txq`, `rxq`, supporting shared MSI-X vectors when a device exposes fewer vectors than queues. |
| `audio.dsvc` | Mixer, format (`U8`, `S16_LE`, `S24_LE`, `S32_LE`, `F32_LE`), channel, and sample-rate conversion (`8 kHz–192 kHz`), automatic output switching, per-device volume/mute, driver crash/restart recovery, and capability/microphone enforcement. |

## Capability model & microphone indicator

Services declare audio permissions in their signed `.dman` manifest under `[grants]`:

```toml
[grants]
audio = ["playback"]             # playback only (capture is refused with ERR_ACCESS_DENIED)
audio = ["playback", "capture"]  # explicit microphone capture grant
audio = ["playback", "control"]  # playback + device routing, volume, and mic policy control
```

- **No ambient authority:** a process without `grants.audio` receives no audio endpoint handles from
  `init`.
- **Playback vs. capture separation:** `audio.dsvc` exposes separate `audio.playback`,
  `audio.capture`, and `audio.control` endpoints. Attempting `OP_OPEN_CAPTURE` over a playback
  channel is refused with `ERR_ACCESS_DENIED`.
- **Visible active microphone indicator:** whenever any capture stream is active, `audio.dsvc`
  signals `terminal.indicator` (`term::INDICATOR`), displaying a red `[MIC LIVE]` badge in the
  top-right corner of the screen and logging `terminal: indicator: MIC LIVE`. Closing the stream,
  revoking microphone access (`audio mic off`), or disconnecting the client immediately clears the
  badge.

## Automatic output switching

Unless a manual output is selected (`audio out <id>`), `audio.dsvc` automatically routes active
streams to the highest-priority online playback endpoint without interrupting clients:

1. **Headphones** (jack plugged in)
2. **USB Audio / USB headset** (attached)
3. **HDMI / DisplayPort** (plugged in, preferring ELD-valid sinks)
4. **Line-out / internal speakers / virtual output**

When an audio driver crashes, `devmgr` quiesces its PCI command register and restarts the driver;
`audio.dsvc` keeps client streams open and automatically reattaches and resumes playback as soon as
the restarted driver announces its endpoints.

## Shell commands

The shell provides the `audio` built-in (`sound` alias):

- `audio` — list audio devices, kinds, active/plugged states, and volumes
- `audio vol <0-100%> [id]` — set per-device volume (defaults to active output)
- `audio mute [on|off]` — toggle, mute, or unmute active output (saves current volume before muting)
- `audio unmute` — unmute active output and restore the volume saved before muting
- `audio out <id|auto>` — select a specific output device or return to automatic switching
- `audio tone [freq] [duration]` — play a test sine tone (default 440 Hz, 500 ms; accepts units such as `500Hz`, `1.5kHz`, `1000ms`, `2s`)
- `audio mic <on|off>` — allow or revoke microphone capture globally

## Tests

- `audio-host`: unit tests and 8,000-round fuzzers for `dosaudio` (PCM format conversion,
  resampling, saturating mixer, dynamic HDA widget graph discovery, HDMI/DP ELD parser, UAC 1.0/2.0
  descriptor parser, output switching priority).
- `audio-hda`, `audio-virtio`, `audio-usb`: QEMU `-audiodev wav` playback tests verifying RIFF/WAVE
  PCM headers, RMS/peak amplitude, and exact dominant frequency (Goertzel DFT) for all three
  drivers under Intel VT-d.
- `audio-sec`: proves ungranted app refusal, playback-only capture refusal, explicit microphone
  capture with live `[MIC LIVE]` indicator and revocation, per-device volume, automatic USB
  hot-plug/unplug output switching, and mid-stream HDA driver crash/restart recovery with WAV
  spectral verification.
