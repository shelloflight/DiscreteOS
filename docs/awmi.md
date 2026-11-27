# D-AWMI: compositor and window manager

D-AWMI (`awmi.dsvc`) is D-OS's compositor and window manager. A **session** takes the display
from the terminal and the keyboard and pointer from the device manager. The compositor then draws
the desktop, the windows with their server-side decorations, the dock and the launcher, and gives
everything back when the session ends.

A normal boot goes straight to a **desktop** session: the service manager starts the compositor
with `autostart`, and the session begins as soon as a display is there. If there is no display
within 20 s, the text console stays. The terminal window (`terminal.dapp`, launched by `appmgr`
with `autostart = true`) shows the same shell session as the text console. If a user identity has
an enrolled passphrase — or `lock = on` is set in `esp:/DOS/BOOT.CFG` — the session starts behind
the compositor-drawn login/lock screen ([identity.md](identity.md)). A line `desktop = off` in
`esp:/DOS/BOOT.CFG` boots to the text console instead; the shell's `gui` starts the desktop from
there. Fonts, the toolkit, themes, the launcher and accessibility are described in [ui.md](ui.md).

**Code:** `user/lib/awmi` (`dosawmi`: `no_std`, `#![forbid(unsafe_code)]` geometry and bounded damage
tracking, alpha compositing, rounded/hairline drawing, built-in 8x16 font, theme, window manager,
dock, launcher, lock screen, permission prompt, wire codecs), `user/awmi` (`awmi.dsvc`,
`awmi-demo.dsvc`, `console.dx` bundled in `terminal.dapp`), `user/lib/libd/src/awmi.rs` (client
protocol), `user/init/services/awmi.dman`, `awmi-demo.dman`.
**Tests:** `awmi-host`, `awmi-virtio`, `awmi-gop`, `desktop-virtio`, `desktop-gop`, `identity-tpm`, `apps-virtio`.

## Session lifecycle

1. **Outputs** from `gpu.display`: native Atomic KMS PCI outputs (`CAP_NATIVE_KMS`, plus any
   additional page-flipping outputs on that same GPU) are preferred over the firmware framebuffer
   for tear-free high-refresh scanout; `display = firmware` in `esp:/DOS/BOOT.CFG` (passing
   `firmware-display` to `awmi`) forces the firmware framebuffer instead. If a native KMS PCI GPU
   comes online after a session already started on GOP, `gpu.dsvc` emits `EVT_ADAPTERS_CHANGED` and
   the compositor seamlessly upgrades outputs on the next frame. Without `CAP_NATIVE_KMS`, the
   firmware framebuffer is used when present, otherwise every online PCI GPU (`virtio-gpu`,
   `amdgpu`, `xe`, `nvgpu`). Each output imports one offscreen backbuffer VMO into GEM
   (`OP_GEM_IMPORT` + `OP_KMS_CREATE_FB`), kept across sessions, with an automatic per-output scale
   (100% / 125% / 150% by width, overridable via `OP_SET_DISPLAY`). Several outputs form one
   desktop, left to right.
2. **Screen and input:** `terminal.display` `DISPLAY_RELEASE` (the terminal keeps its scrollback but
   stops drawing) and `devmgr.input` `INPUT_GRAB` (keys and pointer events go to the compositor
   only: nothing typed reaches the shell).
3. **Frames:** client commits, input, dock changes and animations add damage. Outputs supporting
   `CAP_ASYNC_FLIP` use event-driven vsync pacing (`OP_KMS_ATOMIC_COMMIT` -> unsolicited
   `EVT_VBLANK` from the driver's vblank interrupt, tying `EVT_FRAME_DONE` to real vertical blank
   with zero idle CPU and stepping down cleanly on late frames); synchronous outputs use a
   refresh-paced timer (supporting up to 540+ Hz). Bursts coalesce into one frame per refresh. The
   compositor selects context-aware minimal cursors (`Default`, `Pointer`, `Text`, `Move`, and
   4-axis resize arrows `ResizeEW`/`NS`/`NWSE`/`NESW`) based on what is under the pointer; a single
   output with `CAP_HW_CURSOR` commits the active shape, hotspot, and coordinates to the Atomic KMS
   cursor plane without recompositing, while all other outputs render the cursor into the damaged
   backbuffer.
4. **End:** `Super+Esc` (`Ctrl+Alt+Esc` inside a VM, where the host takes `Super`) or
   `OP_SESSION_STOP`: every window closes (`EVT_SESSION` 0), outputs issue `ATOMIC_RESET_BOOT` on
   `gpu.display` to restore boot scanout state, the grab is released, and the terminal redraws. If
   the compositor exits or crashes, the device manager and the terminal see its channels close and
   take input and screen back on their own.

A GPU driver restart makes a present fail; the outputs are attached again at the next frame.

## Window management

Floating by default, with snapping: drag a title bar to move (an edge or corner of an output shows a
snap preview: halves, quarters, maximize), drag an edge or corner to resize, title bar buttons to
minimize, maximize/restore and close. Click to focus. Four workspaces. The dock is a floating island at the bottom of the primary output: pinned quick-launch apps on the
left (up to 8 entries with a running dot; left-clicking focuses/restores an open window or sends
`EVT_LAUNCH` when closed, and right-clicking a pinned dock pill unpins it; right-clicking an app row
in the launcher toggles pinning), followed by the windows of the current workspace (each workspace
has its own; click: focus, or minimize the focused one), workspaces `1`-`4`, network, audio,
`MIC LIVE` (green) and security alert (red) indicators, and the UTC clock.

Desktop, display, and taskbar settings (theme, text scale, reduce motion, per-output UI scale,
confirmed display mode, VRR, HDR10, and customized taskbar pins) are persisted on installed disks in
`/home/.dos/settings.toml` (`dosid::DesktopSettings`) and restored on subsequent boots. Confirmed
display modes are only written after explicit user confirmation (`DISPLAY_CONFIRM_MODE`), preventing
an incompatible mode from persisting across reboots.

| Keys | Action |
|---|---|
| `Super+Left` / `Super+Right` | snap to the left / right half |
| `Super+Up` / `Super+Down` | maximize / restore |
| `Super+Shift+Arrows` | snap to a quarter |
| `Super+1`..`4` / `Super+Shift+1`..`4` | switch workspace / move the focused window there |
| `Alt+Tab` | next window |
| `Super+Q` | ask the focused window to close (`EVT_CLOSE`) |
| `Super+L` | engage the unforgeable compositor lock screen ([identity.md](identity.md)) |
| `Super` (tap), `Alt+F1` | open or close the launcher ([ui.md](ui.md#launcher)) |
| `Super+Esc`, `Ctrl+Alt+Esc` | end the session (disabled while locked) |

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
| The title bar cannot lie | the service manager attaches each client's verified service or app name and trust tier to its channel (`provides.identify`); the compositor always enforces `FLAG_DECORATED` so apps cannot hide chrome or draw fake title bars or lock screens |
| Lock & permission overlays cannot be forged | the lock/login screen (`identity.session`) and permission prompt (`awmi.launcher`) are drawn exclusively by the compositor above every window and capture all input; apps never receive keys or pointer events while locked or prompted |
| Indicators cannot be forged | `MIC LIVE` comes from the audio service (open capture streams, `audio.control`), the alert from `awmi.indicator` holders only |

Trust tiers: **system** (group `system`), **native** (other services), **sandbox** (anything that may
run foreign code: `vmex` or the D-CMPL program). Sandboxed windows get an amber dot and an amber
hairline border.

## Capability model

```toml
[grants]
awmi = ["window"]      # create and draw its own windows; input for them while focused
awmi = ["query"]       # the compositor's status (OP_STATUS)
awmi = ["admin"]       # start and stop the session, settings, display mode/scale, lock control, plus status
awmi = ["indicator"]   # set the dock's security alert
awmi = ["launcher"]    # register up to 16 .dapp launcher/dock entries and trigger permission prompts (appmgr only)
```

`awmi.dsvc` itself holds `gpu = ["display"]`, `audio = ["control"]` (microphone and mute state),
`net = ["status"]` (read-only link state), `identity = ["session"]` (exclusively for lock/login
authentication), `devmgr.input`, `terminal.display`, `clock.time`, and `namespace = ["*"]` (read-only
`/sys` for fonts/themes and writable `/home/.dos/settings.toml` on installed systems).

## Client protocol (`libd::awmi`)

Requests are calls on the client's channel; events arrive on the same channel (txid 0).

| Op | Endpoint | Meaning |
|---|---|---|
| `OP_CREATE` (900) | window | `a` = client size; `b` = flags; payload = title. Reply: window id, configured size. Refused (`ERR_BAD_STATE`) outside a session; at most 16 windows per client |
| `OP_ATTACH` (901) | window | one VMO handle: the window's pixels (XRGB8888/ARGB8888, `pitch >= width * 4`, at most 64 MiB). A buffer attached to replace another (a resize) is shown from its first commit; until then the old one stays on screen and its pending frame is still answered |
| `OP_COMMIT` (902) | window | show the buffer; payload = up to 16 damage rectangles (window-local); `EVT_FRAME_DONE` follows |
| `OP_SET_TITLE` (903), `OP_DESTROY` (904) | window | the program's own windows only |
| `OP_FONTS` (905) | window | one read-only VMO handle: the font pack; `a` = its size |
| `OP_APP_REGISTER` (906) | window, launcher | a launcher entry: `a` = entry 0-3 (window) or 0-15 (launcher), `b` = `APP_FLAG_PINNED` (1) to pin in dock, payload = label (32 bytes) |
| `OP_SESSION_START` (930), `OP_SESSION_STOP` (931) | admin | `a`: `SESSION_DEMO` (1) opens the demo windows, `SESSION_DESKTOP` (2) starts the desktop session |
| `OP_STATUS` (932) | query, admin | session, locked state, outputs, mode, windows, workspace, indicators, frames, input counters, settings, launcher, fonts, entries |
| `OP_INDICATOR` (933) | indicator | `IND_SECURITY_ALERT` |
| `OP_SETTINGS` (934) | admin | `a` = settings (theme, text size << 8, reduce motion << 24), `b` = which (`SET_*`) |
| `OP_SET_DISPLAY` (936) | admin | `a` = adapter id \| subop (`DISPLAY_SET_MODE`/`VRR`/`HDR`/`SCALE`/`CONFIRM_MODE`) << 32; Atomic KMS `TEST_ONLY` + modeset, 12s confirm/revert, VRR, HDR10, and per-output scale |
| `OP_LOCK` (937) | admin | engage the unforgeable lock/login screen (`a` = reason 1..4, `b` = mode 1..2) |
| `OP_SET_LOCK_POLICY` (938) | admin | update idle timeout seconds and lock-on-sleep policy |
| `OP_PERM_PROMPT` (939) | launcher | display compositor-drawn permission prompt (`a` = request id, `b` = permission mask, payload = `<app>\0<title>`); answered with `EVT_PERM_RESULT` (929) |
| `OP_TEST_*` (940-946) | admin, test mode only | inject keys and pointer events, read back a backbuffer pixel, list windows, add a virtual output, hash a frame, expire idle timer (`OP_TEST_IDLE_EXPIRE`, 946) |

Events: `EVT_CONFIGURE` (size and state after a snap, resize, maximize, minimize, focus change),
`EVT_KEY`, `EVT_POINTER`, `EVT_FOCUS`, `EVT_CLOSE`, `EVT_FRAME_DONE`, `EVT_SESSION` (`a` bit 0
active, bit 1 demo, bit 2 desktop), `EVT_LAUNCH` (`a` = the entry opened), `EVT_SETTINGS` (`a` =
settings, payload = the theme's colours), `EVT_PERM_RESULT` (929, `awmi.launcher`: user choice for
`OP_PERM_PROMPT`).
`libd::awmi::Window` creates a window with its own buffer, `resize`s it on `EVT_CONFIGURE` and
`commit`s damage.

Window programs that ship with the desktop, all ordinary `awmi.window` clients:

- Core `.dapp` native apps (`terminal.dapp`, `files.dapp`, `editor.dapp`, `settings.dapp`,
  `sysmon.dapp`): managed and launched by `appmgr.dsvc` ([apps.md](apps.md)). `terminal.dapp`
  bundles `console.dx` and connects to `terminal.view`, opening automatically on a desktop session.
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
- On native Atomic KMS PCI outputs (`CAP_NATIVE_KMS`), the compositor flips GEM-backed framebuffers
  at vertical blank and resets boot scanout on session end; when `CAP_NATIVE_KMS` is absent or
  `display = firmware` is configured in `BOOT.CFG`, the session uses the firmware framebuffer when
  present (or PCI GPUs on GOP-less BIOS boots).

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
