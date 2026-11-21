# Services and the service manager

`init` is the service manager. It starts every service from a **manifest** that says exactly what
the service gets, supervises it, and stops everything in order at shutdown. A service holds the
handles its manifest grants and nothing else: there is no ambient authority to fall back on.

**Code:** `user/init` (`src/mgr.rs`: the manager; `src/lib.rs`: init's modes and the test run);
`user/lib/dman` (the manifest parser, host-tested); `user/lib/libd/src/svc.rs` (the protocol);
manifests in `user/init/services`.

## Manifests (`.dman`)

A strict TOML subset: `key = value`, one-level `[tables]`, `#` comments, strings, non-negative
integers, booleans and arrays. Unknown keys and tables, wrong types and out-of-range values refuse
the **whole** manifest, and the error names the line and the key.

```toml
name = "devmgr"             # a-z 0-9 -, at most 24
image = "devmgr.dx"         # an embedded program
args = ""
group = "system"            # system: started at boot; test: only by the test run
after = ["storaged"]        # started once these run (or have finished)
log-level = "info"          # error | warn | info (default) | debug: lower records are not kept

[provides]
endpoints = ["disks"]       # others connect to "<name>.disks"
volumes = false             # announces volumes (the storage service)
identify = false            # clients' verified name and trust tier come with each CONNECT (the compositor)

[grants]
log = true
devices = ["pci", "platform:ps2"]   # "all", "pci", "pci:CC[SS[PP]]", "platform:<name>"
programs = ["*.ddrv"]       # program images, by name or "*.dx" / "*.dsvc" / "*.ddrv"
connect = ["storaged.disks"]
audio = ["playback"]        # optional audio capabilities: "playback", "capture", "control"
net = ["client"]            # optional network capabilities: "client", "icmp", "control", "status"
gpu = ["query"]             # optional GPU capabilities: "query", "display", "render"
awmi = ["window"]           # optional compositor capabilities: "window", "admin", "query", "indicator"
namespace = ["/system=system:r"]   # /<path>=<volume>:r | rw | rwa; or ["*"] / ["*:r"]: every volume
manager = ["services", "power"]     # a channel to the manager: list/stop/restart services; power
tools = false               # the tool manifests and their programs (the shell; docs/shell.md)
vmex = false
power = false
kernel-log = false          # the kernel log reader (the log service)
boot-time = false           # the firmware's time at boot (the clock service)

[quota]
memory = "96M"              # bytes, or K / M / G; 64K .. 1G (default 32M)
handles = 2048              # 16 .. 4096 (default 512)
threads = 48                # 1 .. 256 (default 16)

[restart]
policy = "always"           # always | on-failure (default) | never
limit = 3                   # restarts before giving up (default 3)
backoff = 100               # ms before the first restart, doubled each time, at most 10 s
```

### Where manifests come from

| Source | Trusted because |
|---|---|
| Embedded in the kernel image (`clock.dman`, `storaged.dman`, `devmgr.dman`) | the loader verified the kernel's signature; only the minimal bootstrap chain is embedded in `kernel.bin` |
| `sys:/services/*.dman`, `sys:/tools/*.dman`, `sys:/bin/*` on the immutable `sys` volume | each file has a `.dsig` next to it, Ed25519-verified by the kernel (`vmo_verify`) before loading |
| `DOS/SERVICES/<NAME>.DMAN` on the boot volume (`esp`) | a `<NAME>.DSIG` next to it: a `.dsig` of kind manifest (5) for this name, by the D-OS key, checked by the kernel (`vmo_verify`) |

Anything else is refused: no `.dsig`, a signature that does not match, a `.dsig` of another kind or
for another name. `dbuild img sign <seed> manifest <name>.dman <file> <out.dsig>` signs one.

### Boot to the desktop

On a normal boot the service manager starts the compositor with the argument `autostart`, so the
machine comes up on the desktop ([awmi.md](awmi.md)). In the optional `DOS/BOOT.CFG` on the boot
volume, `desktop = off` (or `no`, `false`, `0`) keeps the text console instead, and
`display = firmware` (or `gop`) passes `firmware-display` to the compositor so it stays on the
UEFI GOP framebuffer instead of switching to a native PCI display driver. The file is not signed
because it can only restrict the desktop or native display takeover: it grants nothing.

### Checks across manifests

Two services with one name, an image that is not an embedded program, an `after` naming no service,
or a `connect` to an endpoint no accepted service provides: refused. A refusal takes the services
needing it along.

Every decision is **measured into PCR 10** (`measure`, ABI v7): `svc accept <name>`, `svc tool
<name>` or `svc refuse <source>` with the manifest's SHA-256, so an attestation report shows what the system
was configured to grant ([attestation.md](attestation.md)).

## What a service gets

| Grant | Handles |
|---|---|
| always | its process, thread and root VMAR; a control channel to the manager (tag `TAG_CONTROL`) |
| `log` | the debug log |
| `devices` | each device the selectors match (tag `DEVICE`) |
| `programs` | each embedded program the names match (tag `PROGRAM`) |
| `connect` | one channel per endpoint (`TAG_ENDPOINT + i`, names in the `TAG_ENDPOINT_NAMES` VMO; `libd::svc::endpoint`) |
| `audio` | audio endpoints (`audio.playback`, `audio.capture`, `audio.control`); microphone capture requires explicit `capture` ([audio.md](audio.md)) |
| `net` | network endpoints (`net.client`, `net.icmp`, `net.control`, read-only `net.status`); no grant means no network access ([networking.md](networking.md)) |
| `gpu` | GPU endpoints (`gpu.query`, `gpu.display`, `gpu.render`); separates read-only inspection, display scanout, and command submission ([graphics.md](graphics.md)) |
| `awmi` | compositor endpoints (`awmi.window`, `awmi.admin`, `awmi.query`, `awmi.indicator`) ([awmi.md](awmi.md)) |
| `namespace` | each volume's root, narrowed to the rights granted, at its path ([storage.md](storage.md)); `*`: every volume at `/<volume>`, with at most the rights the volume has |
| `manager` | a channel to the manager (`tool::TAG_MANAGER`): `MGR_LIST`, `MGR_STOP`, `MGR_RESTART`, `MGR_OBJECTS` with `services`; `MGR_POWER` with `power` (a clean shutdown, then the power) |
| `tools` | every accepted tool manifest (`tool::TAG_TOOL_MANIFEST`, read-only) and each tool's program |
| `vmex`, `power` | the VMEX / POWER resource |
| `kernel-log` | the KLOG resource (`klog_read`); the manager also sends it every service's `log-level` |
| `boot-time` | the boot-time record (UEFI only) |

`[quota]` becomes the process's quota. Only init holds MEASURE and the manifests.

## Supervision

- Services start in dependency order: their `after` services run (or have finished), the services
  they connect to run, and the volumes are known if they need a namespace.
- When a service ends, its policy decides; a restart waits `backoff` ms, doubling each time. After
  `limit` restarts it is given up, with a log line saying so.
- **Endpoints**: a client's channel is made when it starts; the provider gets the other end over its
  control channel (`CONNECT`). When a provider restarts, every running client gets a new channel
  (`CONNECT "<service>.<endpoint>"`) and the provider the other end. The storage service announces
  its volumes again after a restart; namespaces handed out before then point at the old instance.

## Protocol (control channel, `libd::svc`)

| Op | Direction | Meaning |
|---|---|---|
| `CONNECT` (300) | manager -> service | carries a channel; payload: the endpoint (`disks` to a provider, `storaged.disks` to a client). To a provider with `provides.identify`: `<endpoint>\0<client service name>`, `b` = the client's trust tier (1 system, 2 native, 3 sandbox: `vmex` or D-CMPL) |
| `SHUTDOWN` (301) | manager -> service | make everything durable, exit 0 |
| `SYNC` (302) | manager -> volume provider, call | make every volume durable; reply when done |
| `LOG_LEVEL` (303) | manager -> kernel-log holder | a service's level: `a` = level, payload = its name |
| `SUSPEND` (304) | manager -> device manager, call | quiesce PCI devices and stop every driver before ACPI S3 sleep |
| `RESUME` (305) | manager -> device manager, call | restart every driver after ACPI S3 wake and wait until ready |
| `VOLUME`, `VOLUMES_DONE` | storage service -> manager | a mounted volume (carries its root); the boot-time set is complete |

## Shutdown and sleep

A shutdown starts when a holder of `manager = ["power"]` sends `MGR_POWER` (`POWER_OFF` or
`POWER_REBOOT`, e.g. the shell's `power off`), or when the machine's power button is pressed (init
waits on the kernel's power-button event, startup tag `POWER_BUTTON`; [acpi.md](acpi.md)).

1. Every volume provider is asked to `SYNC`, while the drivers under it still run.
2. Each service stops after every running service that depends on it (`after` or `connect`),
   the last started first among those free to stop (`SHUTDOWN`, 5 s, then it is ended).
3. Then `system_power`.

For ACPI S3 sleep (`MGR_POWER` with `POWER_SUSPEND`, e.g. `power sleep`), init sends `SYNC` to
every volume provider, sends `SUSPEND` to `devmgr` to quiesce and stop drivers, calls
`system_power(..., POWER_SUSPEND)`, and sends `RESUME` to `devmgr` upon wake.

## The system today

| Service | Gets | Provides |
|---|---|---|
| `log` | log, kernel log | `log.read` |
| `clock` | log, the `rtc` device, boot time | `clock.time` |
| `storaged` | log, `clock.time` (file times) | `storaged.disks`, volumes |
| `devmgr` | log, every PCI device and `ps2`, the `*.ddrv` drivers, `storaged.disks` | `devmgr.input`, `devmgr.audio`, `devmgr.net`, `devmgr.gpu` |
| `audio` | log, `devmgr.audio`, `terminal.indicator` | `audio.playback`, `audio.capture`, `audio.control` |
| `net` | log, `devmgr.net`, `clock.time` | `net.client`, `net.icmp`, `net.control`, `net.status` |
| `gpu` | log, the `display` device, `devmgr.gpu` | `gpu.query`, `gpu.display`, `gpu.render` |
| `terminal` | log, the `display` device, `devmgr.input` | `terminal.session`, `terminal.indicator`, `terminal.display`, `terminal.view` |
| `awmi` | log, `gpu.display`, `audio.control`, `net.status`, `devmgr.input`, `terminal.display`, `clock.time`, `sys:/` read-only (fonts, themes) | `awmi.window`, `awmi.admin`, `awmi.query`, `awmi.indicator` (identified clients) |
| `console` | log, `awmi.window`, `terminal.view` | |
| `awmi-demo` | log, `awmi.window` | |
| `shell` | log, `terminal.session`, `log.read`, `clock.time`, `audio.*`, `net.*`, `gpu.query`, `awmi.admin`, `awmi.query`, every volume, the manager (services, power), the tools | |

### The log service

Every record of the kernel log (kernel lines, and each program's output, named by the kernel after
the process that wrote it) goes into one stream with its own sequence numbers. A program's records
below its service's `log-level` are not kept; other processes (drivers, programs run by hand) keep
info and above. Programs write levels with `libd::log_warn!` and friends (`println` is info).
Readers call `libd::log::read` on `log.read`: records from a sequence number, how many were lost
before them, optionally waiting for the next. Records, not text lines: each has a time, a level, an
origin and a source. Kernel addresses never reach the service (the kernel filters them). It reads
the kernel ring every 50 ms: the kernel cannot wake a reader from where it logs (interrupts).

### The clock service

Wall-clock time, UTC, as `libd::time::Time`: nanoseconds since 2000-01-01 00:00:00 UTC (0 =
unknown). Source: the UEFI boot-time record, else the CMOS RTC, read once at start; afterwards that
reading plus the monotonic clock (no drift correction yet). `TIME_BASE` on `clock.time` answers
(wall-clock time, the monotonic time it was): a client adds the time elapsed since, no call per
reading (`libd::time::query`, `set_base`, `now`). The storage service stamps file times with
it.

### Keyboard and pointer input

The device manager sends every key from a keyboard in use to each client of `devmgr.input`
(`proto::INPUT_KEY`: a character or a named key with modifiers, and the driver's name). The
terminal turns them into edited lines for the shell ([shell.md](shell.md)). A keyboard plugged in
while another is in use is held until accepted with Ctrl+Alt+Insert on one in use
(`user/devmgr/src/trust.rs`, [hardware.md](hardware.md)). Mice and tablets send
`proto::INPUT_POINTER` (relative movement, or absolute `[0, 32767]` with `proto::POINTER_ABS`;
wheel, buttons). One client at a time may take all input with `proto::INPUT_GRAB` (`a` = 1; the
compositor during a graphical session, [awmi.md](awmi.md)): keys and pointer events then go to it
only, until it sends `a` = 0 or its channel closes.

### Tool manifests

Manifests with `kind = "tool"` describe the shell's tools, not services ([shell.md](shell.md)).
They are embedded like service manifests, parsed strictly (`dman::tool`), refused if their image is
not an embedded program or a name or alias is taken, and measured (`svc tool <name>`). A service
with `grants.tools` gets them all.

## Tests

- `services` (init `services test`): two bad embedded manifests refused (an unknown key, named; an
  endpoint nobody provides); a signed manifest from the boot volume accepted and run, an unsigned
  and a tampered one refused; `ltest svc-grants` finds exactly its grants (the log, its control
  channel, PCI class 01 devices only, `/system` read-only: create refused); `ltest svc-quota` has
  the manifest's quota and is refused memory beyond it; `svc-crash` restarted twice with backoff,
  then given up; storaged killed (devmgr linked again, I/O works), devmgr killed (disks handed over
  again, I/O works); `ltest svc-log` reads the whole log back (kernel and storaged records, in
  order, no kernel address: the one the kernel planted arrives as `[kaddr]`; its own info and
  debug lines dropped by its `warn` level); shutdown order checked on the host; power-off.
- `time`, `time-uefi` (init `time test`): the clock from the CMOS RTC (BIOS) or UEFI GetTime;
  `ltest svc-time` records the time in a file on DFS and on FAT32, the host boots the same disks
  again, and the second boot finds a later time and both files' modification times kept; both
  boots' clocks agree with the host's.
- `manifest-host`: the parser's schema tests and a mutation fuzzer (100 000 manifests, every
  truncation of every seed; nothing panics, whatever is accepted satisfies the schema).

## Limitations

- Manifests on disk are read from the boot volume only, once, at boot.
- The log service polls the kernel ring (50 ms); records are kept in memory only (2048).
- The clock is read once per boot; there is no time zone, no network time and no way to set it.
- The CMOS RTC device gives the clock service the whole CMOS (ports 0x70-0x71), not just the clock.
- A client of the storage service started before a restart keeps its old namespace (no re-grant).
