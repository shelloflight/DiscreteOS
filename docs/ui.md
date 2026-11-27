# UI foundation: fonts, toolkit, themes, accessibility

The parts every graphical program shares: the typefaces and the text engine, the native toolkit,
the themes and the accessibility settings. They are drawn by the compositor (window chrome, dock,
launcher; [awmi.md](awmi.md)) and by window programs (the terminal window, the example apps).

**Code:** `user/lib/font` (`dosfont`: font parser, rasterizer, layout, subsetter), `user/lib/ui`
(`dosui`: the toolkit, the font pack, the text adapter), `user/lib/awmi/src/theme.rs` (themes),
`launcher.rs` (launcher, settings), `text.rs` (the compositor's text interface), `user/awmi/src/`
`app.rs` (running a toolkit app in a window), `console.rs`, `demo.rs`, `user/init/fonts/`,
`user/init/themes/`.
**Tests:** `ui-host`, `awmi-host`, `awmi-virtio`, `awmi-gop`, `desktop-virtio`, `desktop-gop`.

All three libraries are `no_std`, `#![forbid(unsafe_code)]`, have no dependencies outside the tree
and use integer arithmetic only (ring-3 code is soft-float).

## Typefaces

| Face | File (`sys:/fonts`) | Used for |
|---|---|---|
| Inter Regular, Medium, SemiBold 4.1 | `inter-regular.ttf`, `inter-medium.ttf`, `inter-semibold.ttf` | interface text, labels, headings |
| Iosevka Term Nerd Font Mono 34.8 (Nerd Fonts 3.5.1) | `iosevka-term-nf-mono.ttf` | the terminal, code, icons |

The Term/Mono variant keeps every glyph, icons included, exactly one cell wide, which a terminal
grid needs. Icons are therefore drawn at twice the text size (`TextStyle::Icon`) to match the
interface. The Iosevka file is a subset (14 MB to 2.2 MB): Latin, Greek, Cyrillic, punctuation,
box drawing, block elements, arrows, maths, and the Nerd Font icon sets minus brand logos. It was
made with `dbuild font-subset <in.ttf> <out.ttf>`. The licences (SIL OFL 1.1 for both faces;
the icon sets' own licences) are next to the files, in `OFL-Inter.txt`, `OFL-Iosevka.txt` and
`NOTICE-NerdFonts-icons.txt`.

The compositor reads the faces once from the signed system volume (`namespace = ["/sys=sys:r"]`).
It packs them into one VMO (`DFNT` header, then the faces) and gives window programs a read-only
duplicate (`OP_FONTS`). A program parses the pack in place and never copies or writes it. Without
fonts, the compositor falls back to its built-in 8x16 bitmap font.

## Text engine (`dosfont`)

- **Parser:** TrueType `glyf` outlines (CFF `OTTO` fonts are refused). It reads `cmap` formats
  4 and 12, `hmtx`, `OS/2` heights, kerning from `GPOS` pair adjustments (formats 1 and 2,
  extension lookups) or `kern` format 0, and composite glyphs (depth 6, 64 components). Every
  offset is bounds-checked, and the parser is fuzzed on the host.
- **Rasterizer:** exact-area coverage accumulation (per-cell cover and area, 1/256 px), the same
  method FreeType's smooth renderer uses. A light gamma curve is applied for dark backgrounds.
  Glyphs are positioned at quarter-pixel steps. Below 28 px the x-height snaps to whole pixels
  (vertical-only hinting), which keeps small text sharp without a bytecode interpreter.
- **Cache:** 4096 glyph bitmaps, at most 3 MiB, least-recently-used.
- **Layout:** advances plus kerning, measuring, caret positions, hit testing, word wrap, and an
  ellipsis when text is cut. Characters missing from a face fall back to the other face
  (Inter ↔ Iosevka).

## Toolkit (`dosui`)

Declarative: a program describes its whole interface as a tree of `Node`s from its state. Events
produce messages, the program updates its state and describes the tree again, and the runtime
(`Ui`) works out what changed.

```rust
column([
    heading("Widgets"),
    checkbox("Notifications", self.notify).on_toggle(Msg::Notify),
    slider(self.level, 0, 100).on_slide(Msg::Level),
    input(self.name.clone()).placeholder("Type your name").on_change(Msg::Name),
    row([button("Reset").danger().on_press(Msg::Reset), spacer(), button("Save").primary().on_press(Msg::Save)]),
])
.padding(16)
.gap(12)
```

- **Widgets:** column, row, panel, scroll, spacer, divider, text (caption, heading, label, mono;
  tones; wrapping), button (primary, secondary, danger), checkbox, toggle, slider, text input
  (including `.secret()` masked input for passphrases), multiline monospace `textarea` (line
  numbers, cursor navigation, scrolling), list item (single-click `on_select` plus 450 ms
  double-click / Enter `on_activate`), progress bar. Sizes are `Auto`, `Px` or `Fill`.
- **Shapes:** rounded rectangles, borders, focus rings and circles are anti-aliased by exact
  coverage: the signed distance from each pixel centre to the edge, in 1/256 px, integer only.
  Straight edges stay pixel-crisp; the fill and a 1 px border get separate coverage.
- **Rendering:** every node has a signature (a hash of what it draws), so only nodes whose
  signature or place changed are repainted. Window runners (`user/apps/src/common.rs`,
  `user/awmi/src/app.rs`, `user/awmi/src/console.rs`) render into a private shadow backbuffer and
  copy only finished damaged rectangles into the shared compositor buffer before committing,
  preventing mid-paint hover flicker at high refresh rates. Hover and press transitions take 110 ms
  using alpha-only fades over transparent surfaces.
- **Running in a window:** `awmi::app::UiWindow` connects an `App` (`title`, `size`, `view`,
  `update`) to a D-AWMI window. It handles configure, focus, keys, pointer, frame pacing (one
  frame in flight) and settings changes.

## Themes

Two built-in themes, both also shipped as TOML in `sys:/themes` (`dark-slate.toml`,
`high-contrast.toml`) with every colour token and two metrics (`focus_ring`, `radius`). A theme
file that does not parse, or lacks a token, is refused and the built-in copy is used.

| Token (examples) | Dark Slate | High Contrast |
|---|---|---|
| `accent` (Discrete Blue) | `#566087` | `#485070` |
| `accent_ring` (focus rings, accent text) | `#838EB9` | `#C9D0EA` |
| `desktop_bg` | `#0E1016` | `#000000` |
| `text_primary` / `text_muted` | `#E5E7F0` / `#888EA4` | `#FFFFFF` / `#D0D4E0` |

Discrete Blue `#566087` fills accent surfaces (the focused workspace, primary buttons, the
selection). Text on it is white (6.1:1). Its tints (`accent_ring` `#838EB9`, `accent_strong`
`#A7B0D2`) are used where the accent must be read on a dark background. The host tests check WCAG
contrast for every text/background pair of both themes: 4.5:1 for text, 3:1 for focus rings and
trust dots.

## Launcher

Tap **Super** (press and release with no other key in between), or press **Alt+F1** inside a VM,
to open a centred search box. Typing filters the entries, Up/Down move the selection, Enter opens
it, Escape or another Super tap closes the launcher. While it is open it takes every key, and the
pointer only reaches the launcher. Super+Esc and Ctrl+Alt+Esc still leave the desktop.

- **Programs' entries:** a window program registers up to 4 entries (`OP_APP_REGISTER`), while
  `appmgr` (`awmi.launcher`) registers up to 16 verified `.dapp` entries (24 in all). Each entry is
  shown with the program's verified name, not a name the program chose. Opening one sends that
  program `EVT_LAUNCH`.
- **Files and directories:** opening the launcher builds a bounded, per-identity in-RAM index of
  the active user's `/home` (plus `/data` for Operators and `/sys`, up to 256 entries). Typing
  ranks basename prefix matches before substring/path matches; selecting a directory opens it in
  `files.dapp` and selecting a file opens it in `editor.dapp` inside that app's granted namespace.
- **Settings:** switch theme, larger text, smaller text, reduce motion, lock screen, leave the desktop.
- **Power controls:** the launcher footer includes a **Power** button that expands inline **Off**,
  **Reboot**, **Lock**, and **Rest** (sleep) controls (also searchable by typing `off`, `reboot`,
  `lock`, or `rest`/`sleep`), backed by `awmi`'s narrow `manager = ["power"]` grant.

## Accessibility

Keyboard and visual: every control can be reached with Tab and Shift+Tab and operated with Enter,
Space and arrows, and shows a visible focus ring. The window manager is fully keyboard-driven
([awmi.md](awmi.md)). The settings, kept by the compositor and sent to every window program
(`EVT_SETTINGS`, with the theme itself), are:

| Setting | Values | From |
|---|---|---|
| Theme | Dark Slate, High Contrast | launcher, `gui theme dark|contrast`, `OP_SETTINGS` |
| Text size | 100, 125, 150, 175, 200 % | launcher, `gui text <percent>`, `gpu scale <percent|auto> [id]`; per-output defaults: 125 % from 2560 px wide, 150 % from 3840 px, overridable per output |
| Reduce motion | on, off | launcher, `gui motion on|off` |

The text size scales the chrome as well (title bar, buttons and dock follow the line height), and
snapped windows are laid out again. With reduce motion on, the launcher, snap preview and hover
transitions appear immediately. `OP_SETTINGS` needs `awmi.admin`.

## Trade-offs

- **No hinting bytecode:** x-height snapping and quarter-pixel positioning give most of the
  sharpness for little code and no interpreter attack surface. Very small text is a little softer
  than with full TrueType hinting.
- **No subpixel (LCD) anti-aliasing:** grayscale only. It works on any panel layout, at any
  rotation, and on scaled outputs.
- **TrueType outlines only:** both shipped faces are TrueType. CFF fonts would need a second
  outline parser.
- **No screen reader, magnifier or accessibility tree yet:** this release covers keyboard and
  visual accessibility only.
- **The font pack is shared, not copied:** about 3 MiB mapped read-only once per window program
  instead of a parse per process. A program cannot change what another program reads.
