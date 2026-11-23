# Application model (`.dapp`) and core native apps

Native desktop applications in D-OS are packaged as signed **`.dapp` bundles**, launched and
confined by the application manager (`appmgr.dsvc`), and granted explicit, plain-language,
**revocable permissions** scoped per user identity. `appmgr.dsvc` intentionally holds **no `vmex`**
capability: it can only execute binaries whose Ed25519 signature the kernel verifies directly.

**Code:** `user/lib/app` (`dosapp`: `no_std`, `#![forbid(unsafe_code)]`, `.dapp` v1 bundle codec,
`DRES` resource pack codec, manifest parser, permission ledger), `user/appmgr/` (`appmgr.dsvc`),
`user/init/services/appmgr.dman`, `user/lib/libd/src/appmgr.rs`,
`user/lib/awmi/src/perm.rs` (compositor permission prompt), `user/apps/` (`files`, `editor`,
`settings`, `sysmon`, manifests in `user/apps/manifests/`), `user/awmi/src/console.rs` (`terminal.dapp`).
**Tests:** `app-host`, `apps-virtio`.

## `.dapp` v1 bundle format

A `.dapp` file is a deterministic, byte-for-byte reproducible archive signed with Ed25519
(`doscrypt::dsig::KIND_APP`, kind 6):

| Region | Layout |
|---|---|
| Header (32 B) | Magic `DAPP`, version `1`, flags `0`, `entry_count` (`1..=64`), `toc_size` (`entry_count * 96`), `payload_size` (offset of trailing `.dsig`), 8 zero bytes |
| TOC (`entry_count * 96` B) | Strictly sorted ascending by entry name: `kind` (`u32`), `flags` (`u32`), `offset` (`u64`), `size` (`u64`), `sha256` (32 B), `name` (40 B NUL-padded ASCII path; no `..` or leading/trailing `/`) |
| Payloads | Packed sequentially on 8-byte boundaries with verified zero padding: exactly one `manifest.dman` (`ENTRY_MANIFEST`), one `<binary>.dx` (`ENTRY_BINARY`), one `<binary>.dx.dsig` (`ENTRY_BINARY_SIG`, 256-byte `KIND_PROGRAM`), and zero or more `res/...` (`ENTRY_RESOURCE`) |
| Trailer (256 B) | `.dsig` of kind `KIND_APP` (6) covering bytes `0..payload_size` |

### Dual verification

When `appmgr.dsvc` inspects or launches a bundle from `/sys/apps/*.dapp`:

1. The outer bundle payload and trailing `.dsig` are verified by the kernel (`sys::vmo_verify`,
   kind `KIND_APP` — verifies integrity without marking the archive executable).
2. Every TOC entry's SHA-256 hash, sorting order, alignment, and zero padding are checked.
3. The embedded `manifest.dman` is parsed with strict fail-closed validation (`dosapp::manifest`).
4. Before `sys::spawn`, the inner binary VMO and its embedded `.dsig` are verified by the kernel
   (`sys::vmo_verify`, kind `KIND_PROGRAM`). Tampered, padded, or unsigned bundles and binaries are
   refused unconditionally.
5. Static resources (`ENTRY_RESOURCE`) are packed into a read-only `DRES` VMO passed to the child
   under `libd::appmgr::TAG_APP_RESOURCES`.

## Application manifests & revocable permissions

Every `.dapp` declares its permissions explicitly in three lists inside `manifest.dman`:

```toml
kind = "app"
name = "editor"
title = "Text Editor"
version = "0.1.0"
binary = "editor.dx"
pinned = true

[permissions]
required = ["window", "files:read"]
optional = []
prompt = ["files:write"]

[quota]
memory = "64M"
handles = 256
threads = 16
```

| Permission | Capability / Handles granted | Identity cap required |
|---|---|---|
| `window` | `awmi.window` (identified by verified app name) | *(always allowed)* |
| `files:read` | Per-identity `/home` (and `/data` for Operator), read-only | `FILES_READ` |
| `files:write` | Per-identity `/home` (and `/data` for Operator), read-write | `FILES_WRITE` |
| `terminal` | `terminal.view` (shared with system terminal session) | *(always allowed)* |
| `display:query` | `gpu.query`, `awmi.query` | `DISPLAY_QUERY` |
| `display:admin` | `awmi.admin` | `DISPLAY_ADMIN` |
| `audio:control` | `audio.control` | `AUDIO_CONTROL` |
| `audio:playback` | `audio.playback` | `AUDIO_PLAYBACK` |
| `net:status` | `net.status` | `NET_STATUS` (`NET_CLIENT`) |
| `net:control` | `net.control` | `NET_CONTROL` |
| `system:query` | `log.read`, `clock.time`, read-only `manager` (`MGR_LIST`/`MGR_OBJECTS`) | `SYSTEM_QUERY` |
| `identity:query` | `identity.query` | *(always allowed)* |
| `identity:admin` | `identity.admin` | `IDENTITY_ADMIN` |
| `apps:query` | `appmgr.query` | *(always allowed)* |
| `apps:admin` | `appmgr.admin` | `APP_ADMIN` |

### Compositor permission prompt & live revocation

- **Unforgeable prompt (`OP_PERM_PROMPT` / `EVT_PERM_RESULT`):** When a user launches an app that
  declares undecided `prompt` permissions (for example, Text Editor requesting `files:write`),
  `appmgr` asks `awmi` over `awmi.launcher` to display a compositor-drawn modal prompt showing the
  app's verified name and plain-language permission descriptions. The user chooses **Allow**,
  **Deny & Launch** (runs without that capability — e.g. read-only mode), or **Cancel**.
- **Per-identity intersection:** Effective permissions are always bounded by the active user
  identity's capability mask. A Standard identity cannot grant `display:admin` or `identity:admin`.
- **Immediate live revocation:** Revoking a permission in **Settings -> Apps & Permissions** or via
  `apps revoke <app> <perm>` (`OP_SET_PERM`) updates the per-identity ledger
  (`/data/system/app-perms.toml` when writable) and immediately terminates every running instance of
  that app that held the revoked capability. Relaunching the app omits those handles completely.
- **Service linking (`MGR_LINK`):** `appmgr` requests fresh client channels on behalf of launched
  apps via `grants.manager = ["apps"]` (`svc::MGR_LINK`). `init` enforces a strict whitelist of
  non-privileged service endpoints (never `identity.session`, `devmgr.*`, `gpu.display`,
  `audio.capture`, `manager.power`, or `vmex`) and stamps `provides.identify` with the verified app
  name so window title bars always show the true app identity.

## Core native apps (`sys:/apps/*.dapp`)

All five shipped desktop applications are signed `.dapp` bundles built from in-tree `dosui` /
D-AWMI code and registered with the compositor launcher and dock via `awmi.launcher`:

| Bundle | Title | Pinned / Autostart | Role & capabilities |
|---|---|---|---|
| `terminal.dapp` | **Terminal** | pinned, autostart | Graphical terminal (`console.dx`) attached to `terminal.view`; shares session history and scrollback with the text console. |
| `files.dapp` | **Files** | pinned | File Manager (`files.dx`): browse `/home` (and `/data` for Operator) with double-click / Enter directory navigation, parent navigation, folder summary & scrollable file preview inspector, create folder/file, delete (requires `files:write`), live namespace indicator. |
| `editor.dapp` | **Text Editor** | pinned | Multiline monospace text editor (`editor.dx`, `dosui::textarea`): open/edit files in `/home`, save with `Ctrl+S` (prompts for `files:write` via compositor prompt; runs read-only if denied), unsaved indicator. |
| `settings.dapp` | **Settings** | pinned | 6-tab system settings (`settings.dx`): **Display** (output selector, mode/Hz switching, VRR, HDR10, per-output scale via `awmi.admin` `OP_SET_DISPLAY`), **Appearance** (Dark Slate / High Contrast theme, 100–200% text scale, reduce motion), **Audio** (output selection, volume, mute/unmute), **Network** (link/IP/DNS status and refresh), **Identity & Lock** (active identity, lock now, enroll passphrase, create non-root identity, idle timeout & lock-on-sleep policy), **Apps & Permissions** (list bundles, launch/stop, live grant/revoke permission toggles). |
| `sysmon.dapp` | **System Monitor** | launcher | 4-tab live monitor (`sysmon.dx`): **Overview** (system summary & memory/handle/thread totals), **Services** (live service table + read-only kernel handle inspector via `MGR_OBJECTS`), **Apps** (installed `.dapp` bundles, verified status, running counts, granted permissions), **System Log** (live `log.read` viewer with level filter). |

## Capability model (`grants.appmgr`)

```toml
[grants]
appmgr = ["query"]   # list bundles, effective permissions, running counts (Settings, System Monitor, shell)
appmgr = ["admin"]   # launch/stop apps, grant/revoke permissions, verify bundle (Settings, shell)
```

| Op | Endpoint | Meaning |
|---|---|---|
| `OP_LIST` (1200) | query, admin | enumerate verified `.dapp` bundles (`AppInfo`) |
| `OP_LAUNCH` (1201) | admin | launch an installed `.dapp` (triggers compositor prompt if `prompt` perms are undecided) |
| `OP_STOP` (1202) | admin | stop running instances of an app |
| `OP_SET_PERM` (1203) | admin | set permission decision (`Ask`/`Granted`/`Denied`); kills running instances on revoke |
| `OP_INSTALL_CHECK` (1204) | admin | verify a `.dapp` file path (outer `KIND_APP` + TOC hashes + manifest + inner `KIND_PROGRAM`) |
| `OP_PERMS` (1205) | query, admin | fetch current permission bitmasks for one app |
| `OP_RUNNING` (1206) | query, admin | count running instances of an app |

## Trade-offs

- **Termination on live revocation:** Because kernel handles cannot be remotely invalidated from
  another process without an explicit revoke proxy per channel, revoking a permission stops running
  instances of the app immediately so no stale handle survives, and relaunching omits the capability.
- **Static system bundle location:** Installed apps are currently discovered from immutable
  `sys:/apps/*.dapp`; user-installed signed packages (`.dpk`) will extend discovery once the
  package manager lands.
- **Fixed permission vocabulary:** Permissions map 1:1 to explicit service endpoints and namespace
  rights so prompts remain short, concrete, and auditable rather than arbitrary string blobs.

## Tests

- `app-host`: `dosapp` unit tests (deterministic `.dapp` build/parse/verify, tampered payload /
  bad padding / bad signature / unsorted TOC / path traversal rejection, `DRES` pack round-trip,
  `.dman` app manifest parsing & refusal, per-identity permission ledger & capability intersection).
- `apps-virtio` (QEMU with `virtio-gpu-pci`): verifies all 5 signed `.dapp` bundles load from
  `sys:/apps/`; proves tampered and unsigned `.dapp` fixtures are refused by kernel `vmo_verify`;
  proves `appmgr` holds zero `vmex` handles; exercises compositor permission prompt flow,
  launches all 5 core apps (`terminal`, `files`, `editor`, `settings`, `sysmon`), verifies
  `sysmon` read-only handle inspection and `settings` live display/theme control, and proves live
  permission revocation kills a running app instance and omits the revoked handle on relaunch.
