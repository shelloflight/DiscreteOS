# Storage: block layer, filesystems, files as handles

Storage is entirely in user space: disk drivers, a storage service and filesystem libraries.

**Code:** `user/devmgr/src/{blkserve,blk,ahci,nvme,virtio}.rs` (block drivers);
`user/storaged/` (the service); `user/lib/fs/` (`dosfs`: GPT, FAT32, DFS, BLAKE3);
`user/lib/libd/src/fs.rs` (file protocol, client, namespaces); `tools/dbuild` (`dbuild img`: host image tool, fsck).

## Processes

```
 init ──ctl──► storaged ◄──disks── devmgr ──spawns──► ahci / nvme / virtio-blk drivers
  (service manager: `storaged.disks` endpoint, CONNECT / SYNC / SHUTDOWN, docs/services.md)
  │              ▲  ▲                                        │
  │ VOLUME       │  └──── one channel per disk (BLK_*) ──────┘
  ▼              │
 app ── node channels (OPEN, READ, WRITE, ...) ──┘
```

- **Drivers** serve `BLK_READ`, `BLK_WRITE`, `BLK_FLUSH`, and shared-memory I/O ring transfers
  (`BLK_RING_SETUP`, `BLK_RING_DOORBELL`, protocol in `user/lib/libd/src/proto.rs`) through the
  shared loop in `blkserve.rs`. Each disk gets its own channel straight to storaged; block I/O
  never passes through the device manager.
- **Zero-copy I/O rings**: on disk attach (and reconnect), `storaged` negotiates a 256 KiB shared
  `libd::ring::IoRing` VMO with each block driver (`ahci`, `nvme`, `virtio-blk`), transferring up
  to 256 KiB per doorbell directly in shared memory with automatic channel fallback for drivers
  without ring support (e.g., USB mass storage).
- **Driver restart**: a restarted driver announces its disks again and storaged retries the
  interrupted request; filesystems do not notice.
- **storaged** reads each GPT (falls back to the backup table), mounts FAT32 and DFS partitions, and
  announces each volume to init. NTFS/exFAT partitions are named and left alone. The `sys` DFS
  system volume is always mounted immutable read-only, even in writable test modes.
- **Service restarts** ([services.md](services.md)): a restarted device manager reaches storaged
  through a new `disks` channel and its disks come back under the same names; a restarted storaged
  gets every known disk again from the device manager and announces its volumes anew. At shutdown,
  storaged makes every written volume durable (`SYNC`) before any driver stops.
- All DMA buffers are pinned through the IOMMU.

## Read-only by default & installed disks

A normal live boot **never writes a disk** ([hardware.md](hardware.md)). Block drivers refuse writes
by default (and AHCI ATAPI CD-ROM drives are permanently read-only), and `storaged` mounts every
volume read-only and hands out read rights only. Any change that could write a disk on a live boot
must be opt-in and verified by `readonly`.

- **Installed `/home` unlock:** When `esp:/DOS/BOOT.CFG` declares `installed = true` (written by
  the installer), `init` sends `UNLOCK_HOME` to `storaged`, which unlocks block writes only on the
  installed disk's `home` DFS volume (`sys` always stays immutable read-only, and live media never
  unlocks writes).
- **Disk installer & partitioning (`storaged.admin`):** Capability-gated to `shell` and
  `installer.dapp` (`Permission::StorageAdmin`, Operator-only; refused on live/optical media and
  under `ro` lock). Supports three modes planned and validated in `dosfs::install`:
  1. **Dual Boot (default):** Installs `sys` and `home` DFS volumes into unallocated GPT free space
     via `gpt::write_preserving()` without touching any existing OS partition, non-destructively
     adding `\EFI\DOS\BOOTX64.EFI`, `\EFI\DOS\BOOTENTRY.BIN`, `\DOS\KERNEL.BIN`, `\DOS\KERNEL.DSIG`,
     and `\DOS\BOOT.CFG` to an existing ESP while preserving existing `\EFI\BOOT\BOOTX64.EFI` and
     other OS bootloaders.
  2. **Use Entire Disk:** Formats a blank/unpartitioned disk with GPT (`bios-boot`, `esp`, `sys`,
     `home`); refuses disks with any existing partition table.
  3. **Wipe & Repartition (+ `delete-part`):** Explicitly confirmed full wipe (`--confirm` / UI
     confirmation toggle) or individual GPT partition deletion so users can reclaim space on
     existing drives. New ESPs are sized to 260 MiB FAT32 with 4 KiB clusters on drives ≥ 512 MiB
     (100 MiB on 256–512 MiB, 36 MiB minimum on smaller virtual images), verified by post-write GPT
     and FAT32 readback alongside `Dfs::fsck()` on `sys` and `home`.

## Files as handles

Every open file or directory is a **channel to storaged**. Rights are fixed when the node is opened
and can only shrink:

| Right | Allows |
|---|---|
| `R_READ` (1) | READ, READDIR, SNAPSHOT_OPEN |
| `R_WRITE` (2) | WRITE, TRUNCATE, UNLINK, RENAME, create, truncate-on-open |
| `R_ADMIN` (4) | SNAPSHOT, SNAPSHOT_DELETE, test hooks |

Paths in `OPEN` are **relative** to the directory handle; `.` and `..` are not names, so a
directory handle reaches only its own subtree. Operations (`fs.rs`): `OPEN` 200, `READ` 201,
`WRITE` 202, `STAT` 203, `READDIR` 204, `UNLINK` 205, `TRUNCATE` 206, `SYNC` 207, `CLONE` 208,
`VOLINFO` 209, `SNAPSHOT` 210, `SNAPSHOT_OPEN` 211, `SNAPSHOT_DELETE` 212, `RENAME` 213. Extra statuses:
`NOT_FOUND` -100, `EXISTS` -101, `NOT_DIR` -102, `IS_DIR` -103, `NOT_EMPTY` -104, `IO` -105,
`CORRUPT` -106, `BAD_NAME` -107, `READ_ONLY` -108.

`STAT` also returns the created and modified times (`libd::time::Time`, 0 = unknown), stamped
from the clock service.

**Rename** (`Node::rename(from, to, replace)`): both paths are below the directory it is sent to,
so a move stays inside what the caller was given. An existing `to` is refused unless `replace`
and both are files; a directory cannot move into itself. DFS commits both sides at once: after a
power cut the object is under exactly one name. FAT32 writes the new name before removing the old
one: a cut in between leaves both names on the same data, never neither.

### Per-app namespaces

A spawner builds a namespace from directory handles it holds (`dos::fs::NsBuilder`): startup
handles tagged `TAG_NS + i` plus a VMO listing their paths. The program resolves absolute paths by
longest prefix. There is no global root; anything not granted is unreachable.

## DFS (native filesystem)

A **copy-on-write B+tree** with **BLAKE3** checksums (a Merkle tree), atomic commits through a
ring of 4 superblocks, and snapshots as saved read-only roots.

- 4 KiB blocks. Block 0 reserved, blocks 1-4 the superblock ring, the rest from a bitmap.
- Every block pointer carries the block's BLAKE3 hash; a block is used only if its hash matches.
- Keys are `(object, kind, offset)`: inodes, directory entries (by name hash), extents, and bitmap
  chunks in a separate allocation tree. The root directory is object 1. Up to 40 snapshots.
- **Commit** (on `SYNC`, after 4 MiB dirty, or 2 s idle): write new blocks, write nodes bottom-up,
  flush, write the next superblock, flush. Nothing reachable from the previous commit is
  overwritten.
- **Mount** picks the newest superblock whose roots verify and falls back to older ones.
- **fsck** (`Dfs::fsck`, `dbuild img fsck`) checks every hash, key order, entry/inode consistency and
  that the bitmap equals the reachable set.

## Block cache

Each disk has an 8 MiB read cache below its partitions (`dosfs::dev::CacheDev`): 4 KiB blocks,
clock eviction, write-through (it never holds what the disk does not). Reads of 32 KiB and more
bypass it. A miss that continues the last one is sequential: up to 128 KiB is fetched at once
(read-ahead), so DFS, which reads 4 KiB blocks, costs one disk request per 128 KiB. A read longer
than one driver request (32 KiB) is sent as up to 4 requests queued at the driver at once.

## FAT32

Read/write with long file names, case-insensitive lookup, both FAT copies kept in sync. FAT12/16
are refused. FAT has no crash consistency; use DFS for data that must survive a power cut.

## Tests

- `storage-host` (`cargo test` of `dosfs`): BLAKE3 vectors, GPT, FAT32, DFS, snapshots, corruption,
  fuzzers, the cache, calendar and FAT time fields, and **power-cut sweeps** (a cut after every
  sector of a workload, and of a rename on DFS and on FAT32; the volume must mount, pass fsck and
  hold one committed state, the renamed file under exactly one name on DFS, at least one on FAT32).
- `storage` (QEMU): SATA + NVMe disks built by `dbuild img`; host-written files, FAT32 writes (then
  read back by 7-Zip on the host), DFS operations, snapshots, namespace isolation, rename on both
  filesystems (and a rename cut by power failures), simulated power cuts, corruption detection.
- `time`, `time-uefi`: file times on DFS and FAT32 kept across a reboot ([services.md](services.md)).
- `readonly`: every driver refuses raw writes, every volume refuses writes, disk images are
  byte-identical afterwards.
- `iso-bios`, `iso-uefi`: AHCI ATAPI CD-ROM read-only detection and read-only `esp`/`sys` mounts.
- `install-dual`: dual-boot NVMe installation into unallocated GPT free space; host post-check
  proves existing Windows NTFS partition and Windows/fallback EFI loaders are 100% byte-identical
  while D-OS boot files and `sys`/`home` DFS volumes pass `fsck`, then boots live UEFI media with
  the dual-boot drive attached to confirm automatic multi-volume `Boot00D0` NVRAM registration.
- `install-e2e`: blank-disk install, confirmed wipe & repartition, individual partition deletion,
  UEFI reboot directly from the installed disk (no live media), OOBE auto-launch/bypass, and
  persistent multi-user `/home` isolation.

## Limitations

- storaged is single-threaded.
- Channel-only block drivers (USB mass storage) carry at most 32 KiB per channel message; ring-capable
  block drivers (`ahci`, `nvme`, `virtio-blk`) transfer up to 256 KiB per doorbell.
- No hard links. Files written by the host image tool have unknown (0) times (reproducible images).
- FAT32 times are UTC with 2-second steps; a FAT32 file renamed while open keeps working, a DFS one
  always does.
