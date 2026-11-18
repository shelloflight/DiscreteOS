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

[provides]
endpoints = ["disks"]       # others connect to "<name>.disks"
volumes = false             # announces volumes (the storage service)

[grants]
log = true
devices = ["all"]           # "all", "pci:CC", "pci:CCSS", "pci:CCSSPP", "platform:<name>"
programs = ["*.ddrv"]       # program images, by name or "*.dx" / "*.ddrv"
connect = ["storaged.disks"]
namespace = ["/system=system:r"]   # /<path>=<volume>:r | rw | rwa
vmex = false
power = false

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
| Embedded in the kernel image (`user/init/services/*.dman`) | the loader verified the kernel's signature; the kernel hands them to init as MANIFEST VMOs (never runnable) |
| `DOS/SERVICES/<NAME>.DMAN` on the boot volume (`esp`) | a `<NAME>.DSIG` next to it: a `.dsig` of kind manifest (5) for this name, by the D-OS key, checked by the kernel (`vmo_verify`) |

Anything else is refused: no `.dsig`, a signature that does not match, a `.dsig` of another kind or
for another name. `dosimg sign <seed> manifest <name>.dman <file> <out.dsig>` signs one.

### Checks across manifests

Two services with one name, an image that is not an embedded program, an `after` naming no service,
or a `connect` to an endpoint no accepted service provides: refused. A refusal takes the services
needing it along.

Every decision is **measured into PCR 10** (`measure`, ABI v7): `svc accept <name>` or
`svc refuse <source>` with the manifest's SHA-256, so an attestation report shows what the system
was configured to grant ([attestation.md](attestation.md)).

## What a service gets

| Grant | Handles |
|---|---|
| always | its process, thread and root VMAR; a control channel to the manager (tag `TAG_CONTROL`) |
| `log` | the debug log |
| `devices` | each device the selectors match (tag `DEVICE`) |
| `programs` | each embedded program the names match (tag `PROGRAM`) |
| `connect` | one channel per endpoint (`TAG_ENDPOINT + i`, names in the `TAG_ENDPOINT_NAMES` VMO; `libd::svc::endpoint`) |
| `namespace` | each volume's root, narrowed to the rights granted, at its path ([storage.md](storage.md)) |
| `vmex`, `power` | the VMEX / POWER resource |

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
| `CONNECT` (300) | manager -> service | carries a channel; payload: the endpoint (`disks` to a provider, `storaged.disks` to a client) |
| `SHUTDOWN` (301) | manager -> service | make everything durable, exit 0 |
| `SYNC` (302) | manager -> volume provider, call | make every volume durable; reply when done |
| `VOLUME`, `VOLUMES_DONE` | storage service -> manager | a mounted volume (carries its root); the boot-time set is complete |

## Shutdown

1. Every volume provider is asked to `SYNC`, while the drivers under it still run.
2. Services stop in the reverse order of their starts (`SHUTDOWN`, 5 s, then they are ended).
3. Then `system_power`.

## The system today

| Service | Gets | Provides |
|---|---|---|
| `storaged` | log | endpoint `disks`, volumes |
| `devmgr` | log, every device, the `*.ddrv` drivers, `storaged.disks` | |

## Tests

- `services` (init `services test`): two bad embedded manifests refused (an unknown key, named; an
  endpoint nobody provides); a signed manifest from the boot volume accepted and run, an unsigned
  and a tampered one refused; `ltest svc-grants` finds exactly its grants (the log, its control
  channel, PCI class 01 devices only, `/system` read-only: create refused); `ltest svc-quota` has
  the manifest's quota and is refused memory beyond it; `svc-crash` restarted twice with backoff,
  then given up; storaged killed (devmgr linked again, I/O works), devmgr killed (disks handed over
  again, I/O works); shutdown order checked on the host; power-off.
- `manifest-host`: the parser's schema tests and a mutation fuzzer (100 000 manifests, every
  truncation of every seed; nothing panics, whatever is accepted satisfies the schema).

## Limitations

- Manifests on disk are read from the boot volume only, once, at boot.
- No per-service log levels or log service yet; output goes to the shared debug log.
- A client of the storage service started before a restart keeps its old namespace (no re-grant).
