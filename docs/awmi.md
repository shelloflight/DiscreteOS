# D-AWMI: compositor and window manager

D-AWMI (`awmi.dsvc`) is D-OS's compositor and window manager. A **session** takes the display
from the terminal and the keyboard and pointer from the device manager. The compositor then draws
the desktop, the windows with their server-side decorations, the dock and the launcher, and gives
everything back when the session ends.

A normal boot goes straight to a **desktop** session: the service manager starts the compositor
with `autostart`, and the session begins as soon as a display is there. If there is no display
within 20 s, the text console stays. The terminal window (`console.dsvc`) shows the same shell
session as the text console. A line `desktop = off` in `esp:/DOS/BOOT.CFG` boots to the text
console instead; the shell's `gui` starts the desktop from there. Fonts, the toolkit, themes, the
launcher and accessibility are described in [ui.md](ui.md).

**Code:** `user/lib/awmi` (`dosawmi`: `no_std`, `#![forbid(unsafe_code)]` geometry and bounded damage
tracking, alpha compositing, rounded/hairline drawing, built-in 8x16 font, theme, window manager,
dock, launcher, themes, wire codecs), `user/awmi` (`awmi.dsvc`, `awmi-demo.dsvc`, `console.dsvc`),
`user/lib/libd/src/awmi.rs` (client protocol), `user/init/services/awmi.dman`, `awmi-demo.dman`,
`console.dman`.
**Tests:** `awmi-host`, `awmi-virtio`, `awmi-gop`, `desktop-virtio`, `desktop-gop`.

## Session lifecycle

1. **Outputs** from `gpu.display`: verified native PCI outputs (`CAP_NATIVE_GOP_MATCH`, e.g. AMD
   DCN after passing its GOP-match and 3-frame flip self-check) are preferred over the firmware
   framebuffer for tear-free high-refresh scanout; `display = firmware` in `esp:/DOS/BOOT.CFG`
   (passing `firmware-display` to `awmi`) forces the firmware framebuffer instead. Without a
   verified native PCI output, the firmware framebuffer is used when present, otherwise every online
   PCI GPU (`virtio-gpu`, `amdgpu`, `xe`, `nvgpu`). Each output gets one offscreen backbuffer VMO,
   attached once and kept across sessions: zero-copy IOMMU scanout on PCI GPUs, write-combining
   blits on the firmware framebuffer or native VRAM scanout buffers. Several outputs form one
   desktop, left to right.
2. **Screen and input:** `terminal.display` `DISPLAY_RELEASE` (the terminal keeps its scrollback but
   stops drawing) and `devmgr.input` `INPUT_GRAB` (keys and pointer events go to the compositor
   only: nothing typed reaches the shell).
3. **Frames:** client commits, input, dock changes and animations add damage. Outputs supporting
   `CAP_ASYNC_FLIP` use event-driven vsync pacing (`OP_PRESENT_MULTI` -> unsolicited
   `EVT_FLIP_DONE` from the driver's vblank/flip interrupt, tying `EVT_FRAME_DONE` to real vertical
   blank with zero idle CPU and stepping down cleanly on late frames); synchronous outputs use a
   refresh-paced timer (supporting up to 540+ Hz). Bursts coalesce into one frame per refresh. A
   single output with `CAP_HW_CURSOR` uses the hardware cursor and pushes pointer moves immediately
   without recompositing; otherwise the cursor is drawn in software.
4. **End:** `Super+Esc` (`Ctrl+Alt+Esc` inside a VM, where the host takes `Super`) or
   `OP_SESSION_STOP`: every window closes (`EVT_SESSION` 0), native outputs call
   `OP_RELEASE_DISPLAY` to restore the firmware GOP framebuffer, the grab is released, and the
   terminal redraws. If the compositor exits or crashes, the device manager and the terminal see its
   channels close and take input and screen back on their own.

A GPU driver restart makes a present fail; the outputs are attached again at the next frame.

## Window management

Floating by default, with snapping: drag a title bar to move (an edge or corner of an output shows a
snap preview: halves, quarters, maximize), drag an edge or corner to resize, title bar buttons to
minimize, maximize/restore and close. Click to focus. Four workspaces. The dock is a floating
island at the bottom of the primary output: the windows of the current workspace (each workspace
has its own; click: focus, or minimize the focused one), workspaces `1`-`4`, network, audio,
`MIC LIVE` (green) and security alert (red) indicators, and the UTC clock.

| Keys | Action |
|---|---|
| `Super+Left` / `Super+Right` | snap to the left / right half |
| `Super+Up` / `Super+Down` | maximize / restore |
| `Super+Shift+Arrows` | snap to a quarter |
| `Super+1`..`4` / `Super+Shift+1`..`4` | switch workspace / move the focused window there |
| `Alt+Tab` | next window |
| `Super+Q` | ask the focused window to close (`EVT_CLOSE`) |
| `Super` (tap), `Alt+F1` | open or close the launcher ([ui.md](ui.md#launcher)) |
| `Super+Esc`, `Ctrl+Alt+Esc` | end the session |

`Super` itself is never delivered to windows: a tap opens the launcher, and with another key it
is a shortcut.

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
awmi = ["admin"]       # start and stop the session (the shell's `gui`), settings, plus status
awmi = ["indicator"]   # set the dock's security alert
```

`awmi.dsvc` itself holds `gpu = ["display"]`, `audio = ["control"]` (microphone and mute state),
`net = ["status"]` (read-only link state), `devmgr.input`, `terminal.display`, `clock.time`, and
read-only `sys:/` (fonts and themes).

## Client protocol (`libd::awmi`)

Requests are calls on the client's channel; events arrive on the same channel (txid 0).

| Op | Endpoint | Meaning |
|---|---|---|
| `OP_CREATE` (900) | window | `a` = client size; `b` = flags; payload = title. Reply: window id, configured size. Refused (`ERR_BAD_STATE`) outside a session; at most 16 windows per client |
| `OP_ATTACH` (901) | window | one VMO handle: the window's pixels (XRGB8888/ARGB8888, `pitch >= width * 4`, at most 64 MiB). A buffer attached to replace another (a resize) is shown from its first commit; until then the old one stays on screen and its pending frame is still answered |
| `OP_COMMIT` (902) | window | show the buffer; payload = up to 16 damage rectangles (window-local); `EVT_FRAME_DONE` follows |
| `OP_SET_TITLE` (903), `OP_DESTROY` (904) | window | the program's own windows only |
| `OP_FONTS` (905) | window | one read-only VMO handle: the font pack; `a` = its size |
| `OP_APP_REGISTER` (906) | window | a launcher entry: `a` = entry 0-3, payload = label (32 bytes) |
| `OP_SESSION_START` (930), `OP_SESSION_STOP` (931) | admin | `a`: `SESSION_DEMO` (1) opens the demo windows, `SESSION_DESKTOP` (2) the terminal window |
| `OP_STATUS` (932) | query, admin | session, outputs, mode, windows, workspace, indicators, frames, input counters, settings, launcher, fonts, entries |
| `OP_INDICATOR` (933) | indicator | `IND_SECURITY_ALERT` |
| `OP_SETTINGS` (934) | admin | `a` = settings (theme, text size << 8, reduce motion << 24), `b` = which (`SET_*`) |
| `OP_FLIP_TEST` (935) | admin | `a` = adapter id (0 = first), `b` = duration ms; releases terminal, runs `gpu::flip_test`, restores terminal |
| `OP_TEST_*` (940-945) | admin, test mode only | inject keys and pointer events, read back a backbuffer pixel, list windows, add a virtual output, hash a frame |

Events: `EVT_CONFIGURE` (size and state after a snap, resize, maximize, minimize, focus change),
`EVT_KEY`, `EVT_POINTER`, `EVT_FOCUS`, `EVT_CLOSE`, `EVT_FRAME_DONE`, `EVT_SESSION` (`a` bit 0
active, bit 1 demo, bit 2 desktop), `EVT_LAUNCH` (`a` = the entry opened), `EVT_SETTINGS` (`a` =
settings, payload = the theme's colours).
`libd::awmi::Window` creates a window with its own buffer, `resize`s it on `EVT_CONFIGURE` and
`commit`s damage.

Window programs that ship with the desktop, all ordinary `awmi.window` clients:

- `console.dsvc`: the terminal window. It needs `terminal.view` as well: the terminal lays the
  session out for the window's grid in a VMO the console maps read-only, says which rows changed,
  and takes the keys typed in the window. It opens on a desktop session and from the launcher.
- `awmi-demo.dsvc`: the toolkit's example apps, Widgets (a tour of the controls, all local to its
  window, with a theme preview that re-themes only that window) and About D-OS (the
  shortcuts), from the launcher or `gui demo`.

## Trade-offs

- Compositing is on the CPU into RAM backbuffers (never reading write-combining memory back),
  damage-tracked so idle desktops cost nothing; GPU-shader compositing comes later.
- The chrome is drawn with the shipped vector fonts; without them (a damaged system volume) the
  built-in 8x16 bitmap font keeps the desktop usable.
- The window chrome and the launcher are drawn by the compositor, never by clients, so a program
  cannot draw a fake title bar or launcher entry for another program.
- The firmware framebuffer (UEFI GOP) has no vertical-blank signal or page flipping, so a copy
  to it can tear while something moves (dragging a window, the launcher opening). To keep that
  rare, the launcher's dim is drawn once and only its panel animates. Tear-free output needs a
  native display driver that flips buffers at vertical blank.
- On a verified native AMD display (`CAP_NATIVE_GOP_MATCH`), the compositor flips dedicated VRAM
  scanout buffers at vertical blank and restores the untouched GOP scanout on session end; on
  unverified PCI GPUs or when `display = firmware` is configured in `BOOT.CFG`, the session falls
  back to the firmware framebuffer when present (or PCI GPUs on GOP-less BIOS boots).

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
  gets the keyboard back (`gui status`). They also check the shared font pack (read-only, refused
  to non-window endpoints), launcher registration and the Super-tap launcher, and the settings
  (admin only, sent to window programs, visible in the frame).
- `desktop-virtio` (BIOS, `virtio-gpu-pci`) and `desktop-gop` (UEFI framebuffer) boot the release
  image as shipped: the desktop starts by itself and the terminal window attaches. A command
  typed into it reaches the shell, and `gui text 125` changes the settings. Super and `widgets`
  open an app from the launcher. Ctrl+Alt+Esc returns to the text console, where `power off`
  switches off. Every other release-image test boots a copy with `desktop = off`.
