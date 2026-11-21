# The terminal, the shell and the tools

What a person at the machine uses: the **terminal** owns the screen and the keyboard, the
**shell** runs one session on it, and **tools** are small programs the shell starts with exactly
the paths typed. Commands pass **typed records** to each other, not byte streams.

**Code:** `user/terminal/` (screen, line editor), `user/shell/` (`lib.rs`: the session, paths,
tools and jobs; `cmds.rs`: built-in commands; `filter.rs`; `show.rs`: tables and values;
`parse.rs`), `user/tools/` (the tools; manifests in `user/tools/manifests/`),
`user/lib/libd/src/{rec,term,tool}.rs` (the protocols), `user/lib/dman/src/tool.rs` (tool
manifests). **Test:** `shell`.

```
data ▸ list notes | where size > 1M | sort modified | take 3
 name        kind  size     modified
 report.txt  file  1.2 MiB  2026-11-17 18:02
data ▸ copy report.txt /backup
✗ copy: /backup/report.txt is not in this session's namespace
  granted: /boot (read), /data (read), /esp (read), /system (read)
```

## Who holds what

| Process | Holds | Does not hold |
|---|---|---|
| `terminal` | the `display` device, `devmgr.input` | any file, endpoint or right of the session (offers `terminal.indicator` to `audio.dsvc` for the `[MIC LIVE]` badge, `terminal.display` to the compositor, which stops and restarts its drawing for a graphical session, and `terminal.view` to the terminal window) |
| `shell` | its manifest: every volume (`namespace = ["*"]`, with the rights the volume has: read-only on a normal boot), `log.read`, `clock.time`, `audio.playback`, `audio.control`, `net.client`, `net.icmp`, `net.control`, `gpu.query`, `awmi.admin`, `awmi.query`, a manager channel (`services`, `power`), the tools | the screen, the keyboard, the microphone, display modesetting, any window's pixels |
| a tool | an output channel, one node per path argument with the rights its manifest declares, the log | the namespace, endpoints, anything else of the shell |

The terminal and the shell are separate so that neither gets the other's authority: a bug in the
line editor cannot reach a file, and the shell cannot draw outside the terminal's protocol.

## The terminal

- **Screen**: the kernel offers its console screen as a platform device named `display` (ABI v9,
  [abi.md](abi.md)): the GOP framebuffer (8x16 glyphs, doubled from 2560x1440) or VGA text with
  its cursor ports. Mapping it takes the screen from the kernel; kernel lines then go to serial
  and the log service only, and a panic takes the screen back. Only changed cells are drawn.
- **Keys** (`proto::INPUT_KEY`, `proto::key`): characters plus named keys (arrows, Home/End,
  PgUp/PgDn, Insert/Delete, F1-F12) with Shift/Ctrl/Alt/Super, from PS/2, USB and virtio keyboards
  (characters typed with Alt or Super held also carry those modifier bits). A keyboard
  plugged in while another is in use types nothing until accepted with Ctrl+Alt+Insert on the
  keyboard in use ([hardware.md](hardware.md)).
- **Editing**: insert anywhere, Backspace/Delete, Left/Right, Home/End (Ctrl+A/E), history
  (Up/Down, 100 lines), Tab (the shell completes commands and paths), Escape clears, Ctrl+C
  cancels the line or stops the running command, Ctrl+L clears. PgUp/PgDn scroll back through
  2000 lines. A line typed (and Enter pressed) while a command still runs is submitted when the
  next prompt comes.
- **Keyboard notices**: until the first key arrives, the shell shows (dimmed, at most 40 lines)
  what the log says about keyboards (the keyboard drivers, lines that mention a keyboard) and every
  warning or error. A keyboard that is found but never types can be diagnosed from a photo of the
  screen; the first key ends it.
- Every typed line is logged (`terminal: line from ps2: ...`). With the argument `mirror`, or
  without a display, every line shown is logged too (`terminal| ...`): a session can be followed
  on serial.
- **Text:** output is kept as lines of Unicode characters and wrapped when drawn, so it reflows
  whenever the grid changes size (the shell is sent the new `SIZE`). The framebuffer and VGA text
  show characters through code page 437; the terminal window shows them all.
- **The terminal window:** while the desktop holds the screen, the terminal lays the session out
  for the terminal window's grid instead (`terminal.view`: `VIEW_ATTACH` returns a read-only VMO
  of cells, `VIEW_DAMAGE` says which rows changed, `VIEW_KEY` carries the keys typed in the
  window, `VIEW_RESIZE`, `VIEW_DETACH`). It is the same session: history, scrollback and the
  running command carry over in both directions ([awmi.md](awmi.md)).

Session protocol (`libd::term`, endpoint `terminal.session`): `WRITE` text with style bytes
(`STYLE attr`, `PLAIN`), `READ` (show a prompt, edit a line) answered by `LINE` (or cancelled),
`INTERRUPT`, `COMPLETE`/`COMPLETIONS`, `SIZE`, `CLEAR`.

## The shell

- **Names**: plain words, with the familiar names as aliases (`list`/`ls`/`dir`, `show`/`cat`,
  `copy`/`cp`, `move`/`mv`, `delete`/`rm`, `make`/`mkdir`, `create`/`touch`, `tasks`/`ps`,
  `end`/`kill`, `time`/`date`, `go`/`cd`, `net`/`ip`). An unknown command suggests the closest
  name. `help` lists everything; `help <command>` shows its usage and, for a tool, the rights each
  parameter gives.
- **Places**: there is no global root. `/` is the list of the session's places (`/data`,
  `/system`, ...); `places` shows them with their rights and sizes. The prompt is the current place
  (`data/notes ▸`). Relative names resolve in the current place; absolute paths go exactly there;
  `..` never leaves the namespace.
- **Records**: every command produces records with typed fields (text, integer, size, time, path,
  bool). Filters work on them: `where <field> <op> <value>` (`=`, `!=`, `<`, `>`, `<=`, `>=`,
  `contains`; sizes like `1M`, times like `2026-11-18 09:00`), `sort <field> [desc]`, `take <n>`,
  `pick <field>...`, `count`. At the end of the line records become a table; results of the file
  tools show as `✓ copied /data/b.txt (58 B)`.
- **Jobs**: `start <command>` runs it in the background; `jobs`, `wait <n>` (shows its output),
  `end <n>`. Ctrl+C ends the command in front.
- **Built-ins** (they use the session's own grants): `go`, `places`, `tasks` (services through the
  manager, and jobs), `objects [job | service]` (handles held, through `process_handles`),
  `end`/`restart` (services through the manager), `log [source]`, `time`, `audio` (devices,
  volume, mute/unmute, routing, test tone, mic policy; [audio.md](audio.md)), `net [check]` (`ip`,
  link and IPv4 status; `check`: which step to the internet fails), `ping <host> [count]` (DNS +
  ICMP echo, with a TCP reachability check when no reply comes), `tls <host> [port]` (TLS 1.3
  handshake & certificate verification against `/sys/certs/roots.der`;
  [networking.md](networking.md)), `gpu [modes [id]]` (`display`, GPU adapters, modes, EDID, VRAM,
  and IOMMU status; [graphics.md](graphics.md)), `gui [demo | status | theme dark|contrast |
  text 100-200 | motion on|off]` (`awmi`: start the desktop, with the example apps too for `demo`,
  back with `Super+Esc` or `Ctrl+Alt+Esc`; `status`: the compositor's state; `theme`, `text`,
  `motion`: the accessibility settings; [awmi.md](awmi.md), [ui.md](ui.md)), `power off | restart | sleep` (the manager stops every service
  cleanly first), `clear`, `run <tool> [arguments]`.
- **Foreign programs**: `run <file> [arguments]` with a file that is not a tool starts a Windows
  (PE) or Linux (ELF) program under D-CMPL, told apart by its header. It gets the current place
  (with the session's rights there) as its working directory, an output channel and the wall
  clock, and nothing else ([compat.md](compat.md#running-a-program)). Its output shows like a
  tool's text.

## Tools and declared rights

A tool is a program with a tool manifest, embedded in the kernel image and measured into PCR 10
like a service manifest (`svc tool <name>`):

```toml
kind = "tool"
name = "copy"
image = "copy.dx"
aliases = ["cp"]
description = "copy a file"

[parameters]           # in order; the last one may be "many"
from = "path:read"
to = "path:write,create"

[about]                # one line per parameter, for `help copy`
from = "the file to copy"
to = "the new file, or a directory to copy it into (the name stays)"
```

Parameter kinds: `path`, `text`, `number`; flags `read`, `write` (includes read), `create`,
`optional`, `many`. For each path the shell gives the tool (`libd::tool`):

| Declared | The tool gets |
|---|---|
| `path:read` | the file or directory itself, read-only |
| `path:write` | the directory it is in (read-write) and its name |
| `path:write,create` | the same; if it is an existing directory (or ends in `/`), that directory and the first path's name |

An optional path left out is the current place. A path outside the namespace, or write access to
a read-only place, is refused by the shell before the tool starts. The tools: `list`, `show`,
`copy`, `move` (a rename in one directory, atomic on DFS; between directories files are copied,
then the original deleted), `delete` (files and empty directories), `make`, `create` (`touch`,
creates empty files without truncating existing ones).

Trade-offs: a written path hands the tool its whole directory (storaged's rights are per node, so
a tool may touch the neighbours of a file it creates); tools get the log for their crash reports.

## Tests

`shell` (init `shell test`: writable disks, the terminal mirrored): a session typed on the
keyboard through the QEMU monitor and checked on serial: places, `make`, `copy` into a directory,
`list | where | pick`, `show`, `move`, a path outside the namespace refused, a misspelled command,
`help`, `tasks | where | count`, `log | where | take`, `objects`, `delete`, Tab completion,
`time`, then `power off` (every service stops in order, then the power). `manifest-host` covers
tool manifests (schema, refusals, a mutation fuzzer); `keyboard`, `usb*` see typed lines reach
the terminal; `uefi` sees the terminal take the framebuffer.

## Limitations

- One session, one terminal; no second terminal or remote session yet.
- Tools are only producers: a stage after `|` must be a filter.
- Copying directories and moving a directory to another directory are not supported yet.
- Typed lines go to the system log in clear text.
- Scripted input over the serial line is not supported (the kernel debugger owns COM1 input); the
  serial line carries the mirrored output.
