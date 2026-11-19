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

- **Drivers** serve `BLK_READ`, `BLK_WRITE`, `BLK_FLUSH` (protocol in `user/lib/libd/src/proto.rs`)
  through the shared loop in `blkserve.rs`. Each disk gets its own channel straight to storaged;
  block I/O never passes through the device manager.
- **Driver restart**: a restarted driver announces its disks again and storaged retries the
  interrupted request; filesystems do not notice.
- **storaged** reads each GPT (falls back to the backup table), mounts FAT32 and DFS partitions, and
  announces each volume to init. NTFS/exFAT partitions are named and left alone.
- **Service restarts** ([services.md](services.md)): a restarted device manager reaches storaged
  through a new `disks` channel and its disks come back under the same names; a restarted storaged
  gets every known disk again from the device manager and announces its volumes anew. At shutdown,
  storaged makes every written volume durable (`SYNC`) before any driver stops.
- All DMA buffers are pinned through the IOMMU.

## Read-only by default

A normal boot **never writes a disk** ([hardware.md](hardware.md)). Drivers refuse writes unless
started with `rw` (only in tests), and storaged mounts every volume read-only and hands out read
rights only. Keep it that way: any change that could write a disk on a normal boot must be opt-in
and tested by `readonly`.

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

## Limitations

- storaged is single-threaded; only long reads queue several requests at a driver.
- A driver request carries at most 32 KiB (one channel message): sequential reads of 32 KiB and
  more gain nothing from the cache.
- No hard links. Files written by the host image tool have unknown (0) times (reproducible images).
- FAT32 times are UTC with 2-second steps; a FAT32 file renamed while open keeps working, a DFS one
  always does.
