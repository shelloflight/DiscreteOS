# D-AWMI: compositor and window manager

D-AWMI (`awmi.dsvc`) is D-OS's compositor and window manager. It is idle at boot: no screen, no
input, a few pages of memory. The shell's `gui` starts a **session**: the compositor takes the
display from the terminal and the keyboard and pointer from the device manager, draws the desktop,
the windows with their server-side decorations and the dock, and gives everything back when the
session ends.

**Code:** `user/lib/awmi` (`dosawmi`: `no_std`, `#![forbid(unsafe_code)]` geometry and bounded damage
tracking, alpha compositing, rounded/hairline drawing, built-in 8x16 font, theme, window manager,
dock, wire codecs), `user/awmi` (`awmi.dsvc`, `awmi-demo.dsvc`), `user/lib/libd/src/awmi.rs`
(client protocol), `user/init/services/awmi.dman`, `awmi-demo.dman`.
**Tests:** `awmi-host`, `awmi-virtio`, `awmi-gop`.

## Session lifecycle

1. **Outputs** from `gpu.display`: the firmware framebuffer when there is one (it is the screen the
   terminal draws on, so ending the session hands it straight back), otherwise every online PCI GPU
   (`virtio-gpu`, `amdgpu`, `xe`, `nvgpu`). Each output gets one offscreen backbuffer VMO, attached
   once and kept across sessions: zero-copy IOMMU scanout on PCI GPUs, write-combining blits on the
   firmware framebuffer. Several outputs form one desktop, left to right.
2. **Screen and input:** `terminal.display` `DISPLAY_RELEASE` (the terminal keeps its scrollback but
   stops drawing) and `devmgr.input` `INPUT_GRAB` (keys and pointer events go to the compositor
   only: nothing typed reaches the shell).
3. **Frames:** client commits, input and dock changes add damage; a refresh-paced timer composites
   only the damaged rectangles (desktop, windows bottom to top, snap preview, dock, software cursor)
   and presents just those. Bursts coalesce into one frame per refresh. A single output with
   `CAP_HW_CURSOR` uses the 64x64 hardware cursor; otherwise the cursor is drawn in software.
4. **End:** `Super+Esc` (`Ctrl+Alt+Esc` inside a VM, where the host takes `Super`) or
   `OP_SESSION_STOP`: every window closes (`EVT_SESSION` 0), the grab is released, the terminal
   redraws. If the compositor exits or crashes, the device manager and the terminal see its channels
   close and take input and screen back on their own.

A GPU driver restart makes a present fail; the outputs are attached again at the next frame.

## Window management

Floating by default, with snapping: drag a title bar to move (an edge or corner of an output shows a
snap preview: halves, quarters, maximize), drag an edge or corner to resize, title bar buttons to
minimize, maximize/restore and close. Click to focus. Four workspaces. The dock is a floating
island at the bottom of the primary output: running windows (click: focus, or minimize the focused
one), workspaces `1`-`4`, network, audio, `MIC LIVE` (green) and security alert (red) indicators,
and the UTC clock.

| Keys | Action |
|---|---|
| `Super+Left` / `Super+Right` | snap to the left / right half |
| `Super+Up` / `Super+Down` | maximize / restore |
| `Super+Shift+Arrows` | snap to a quarter |
| `Super+1`..`4` / `Super+Shift+1`..`4` | switch workspace / move the focused window there |
| `Alt+Tab` | next window |
| `Super+Q` | ask the focused window to close (`EVT_CLOSE`) |
| `Super+Esc`, `Ctrl+Alt+Esc` | end the session |

Keyboards report `Super` (PS/2 `E0 5B`/`E0 5C`, USB HID GUI modifiers, Linux `KEY_LEFTMETA`/
`KEY_RIGHTMETA`) and `F1`-`F12`; with `Alt` or `Super` held, characters carry their modifier bits.
Pointers: USB HID mice (relative), `virtio-input` relative mice and absolute tablets
(`proto::POINTER_ABS`, `[0, 32767]` mapped onto the whole desktop).

## Isolation and trust

| Rule | How |
|---|---|
| A program draws only its own windows | its pixels are a VMO it created; the compositor maps a read-only duplicate and never writes it |
| A program cannot see other windows | no handle to another program's VMO, no way to name another program's window (ids are checked against the creating channel: `ERR_ACCESS_DENIED`), no readback outside test mode |
| Input goes where the user is | keys to the focused window only, pointer events to the window under the pointer only, in window-local coordinates |
| The title bar cannot lie | the service manager attaches each client's verified service name and trust tier to its channel (`provides.identify`); the trust dot and name come from there, the program sets only the title after them |
| Indicators cannot be forged | `MIC LIVE` comes from the audio service (open capture streams, `audio.control`), the alert from `awmi.indicator` holders only |

Trust tiers: **system** (group `system`), **native** (other services), **sandbox** (anything that may
run foreign code: `vmex` or the D-CMPL program). Sandboxed windows get an amber dot and an amber
hairline border.

## Capability model

```toml
[grants]
awmi = ["window"]      # create and draw its own windows; input for them while focused
awmi = ["query"]       # the compositor's status (OP_STATUS)
awmi = ["admin"]       # start and stop the session (the shell's `gui`), plus status
awmi = ["indicator"]   # set the dock's security alert
```

`awmi.dsvc` itself holds `gpu = ["display"]`, `audio = ["control"]` (microphone and mute state),
`net = ["status"]` (read-only link state), `devmgr.input`, `terminal.display` and `clock.time`.

## Client protocol (`libd::awmi`)

Requests are calls on the client's channel; events arrive on the same channel (txid 0).

| Op | Endpoint | Meaning |
|---|---|---|
| `OP_CREATE` (900) | window | `a` = client size; `b` = flags; payload = title. Reply: window id, configured size. Refused (`ERR_BAD_STATE`) outside a session; at most 16 windows per client |
| `OP_ATTACH` (901) | window | one VMO handle: the window's pixels (XRGB8888/ARGB8888, `pitch >= width * 4`, at most 64 MiB) |
| `OP_COMMIT` (902) | window | show the buffer; payload = up to 16 damage rectangles (window-local); `EVT_FRAME_DONE` follows |
| `OP_SET_TITLE` (903), `OP_DESTROY` (904) | window | the program's own windows only |
| `OP_SESSION_START` (930), `OP_SESSION_STOP` (931) | admin | `a` bit 0: open the demo windows |
| `OP_STATUS` (932) | query, admin | session, outputs, mode, windows, workspace, indicators, frames, input counters |
| `OP_INDICATOR` (933) | indicator | `IND_SECURITY_ALERT` |
| `OP_TEST_*` (940-944) | admin, test mode only | inject keys and pointer events, read back a backbuffer pixel, list windows, add a virtual output |

Events: `EVT_CONFIGURE` (size and state after a snap, resize, maximize, minimize, focus change),
`EVT_KEY`, `EVT_POINTER`, `EVT_FOCUS`, `EVT_CLOSE`, `EVT_FRAME_DONE`, `EVT_SESSION`.
`libd::awmi::Window` creates a window with its own buffer, `resize`s it on `EVT_CONFIGURE` and
`commit`s damage.

`awmi-demo.dsvc` is an ordinary `awmi.window` client: in a session started with the demo (`gui`) it
opens an About window (shortcuts) and a Canvas (draw with the pointer, the last key, focus).

## Trade-offs

- Compositing is on the CPU into RAM backbuffers (never reading write-combining memory back),
  damage-tracked so idle desktops cost nothing; GPU-shader compositing comes later.
- The UI font is the built-in 8x16 bitmap font; anti-aliased vector text, the native toolkit,
  theming and accessibility follow with the UI foundation.
- On a PCI GPU the terminal's firmware framebuffer is not the scanout, so the session prefers the
  firmware framebuffer when there is one; a GOP-less machine (BIOS boot) uses its PCI GPUs.

## Tests

- `awmi-host`: `dosawmi` unit tests (damage coalescing, multi-monitor clipping, snapping, workspaces,
  focus and ownership isolation, dock layout and rendering, codecs) plus 12,000 fuzz rounds over
  untrusted wire data, damage rectangles and the window manager with compositing.
- `awmi-virtio` (BIOS, `virtio-gpu-pci` with hardware cursor, HDA capture, virtio tablet) and
  `awmi-gop` (UEFI firmware framebuffer, software cursor): an ungranted service gets no endpoint;
  window-only clients are refused admin, status, indicator, test and other clients' windows; two
  clients' windows read back in their own colours; click-to-focus routes each key to the focused
  window only; identity and trust tier come from the service manager despite a forged title;
  `Super+Left/Up/Down` snap, maximize and restore; `Super+2` hides workspace 1; a window dragged
  onto a second (virtual) output draws there; the alert indicator and (`awmi-virtio`) `MIC LIVE`
  during a real capture stream; `Super+Q` closes; keys and pointer events typed by the host reach
  the compositor during the grab (`leak` never reaches the shell); after the session the terminal
  gets the keyboard back (`gui status`).
