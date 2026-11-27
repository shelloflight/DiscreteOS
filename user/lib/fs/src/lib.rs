//! `dosfs`: D-OS storage code shared by the storage service (`storaged`, ring 3), the host image
//! tool (`tools/dosimg`) and host tests (`cargo test`): BLAKE3, block devices, GPT, FAT32 and
//! the D-OS native filesystem (DFS). no_std + alloc, no dependencies. Reference:
//! docs/storage.md.
//!
//! Everything read from a disk is untrusted: sizes, offsets, counts and pointers are checked
//! before use, and a filesystem that finds something impossible returns `Corrupt` instead of
//! following it (a corrupted or hostile disk image ends a request, never the service).

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod blake3;
pub mod dev;
pub mod dfs;
pub mod fat;
pub mod gpt;
pub mod install;
pub mod time;

#[cfg(test)]
mod fuzz;

use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The device failed (or a request was out of range).
    Io,
    /// On-disk data failed a check (checksum, structure): never followed.
    Corrupt,
    NotFound,
    Exists,
    NotDir,
    IsDir,
    NotEmpty,
    NoSpace,
    BadName,
    ReadOnly,
    /// Too large for this filesystem (file size, name, directory).
    TooBig,
    Unsupported,
}

pub type Result<T> = core::result::Result<T, Error>;

/// A node: a file or directory, named by a filesystem-specific number.
pub type Ino = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
}

#[derive(Clone, Copy, Debug)]
pub struct Stat {
    pub kind: Kind,
    pub size: u64,
    /// D-OS time (ns since 2000-01-01 00:00:00 UTC; 0 = unknown) of creation and last change.
    pub created: i64,
    pub modified: i64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Info {
    pub total_blocks: u64,
    pub free_blocks: u64,
    pub block_size: u64,
    /// DFS: the last committed generation (0 for FAT32).
    pub generation: u64,
}

/// One directory entry (readdir).
pub struct Entry {
    pub name: Vec<u8>,
    pub kind: Kind,
    pub ino: Ino,
}

/// What the file service needs from a filesystem. Names are single components (the service
/// splits and validates paths); a filesystem may refuse names it cannot store (`BadName`).
pub trait FileSystem {
    fn root(&self) -> Ino;
    fn lookup(&mut self, dir: Ino, name: &[u8]) -> Result<Ino>;
    fn create(&mut self, dir: Ino, name: &[u8], kind: Kind) -> Result<Ino>;
    fn stat(&mut self, ino: Ino) -> Result<Stat>;
    fn read(&mut self, ino: Ino, off: u64, buf: &mut [u8]) -> Result<usize>;
    fn write(&mut self, ino: Ino, off: u64, data: &[u8]) -> Result<usize>;
    fn truncate(&mut self, ino: Ino, size: u64) -> Result<()>;
    /// Entries from `cookie` (0 = the start), at most `max` of them: the entries and the
    /// cookie to continue from (None at the end).
    fn readdir(&mut self, dir: Ino, cookie: u64, max: usize) -> Result<(Vec<Entry>, Option<u64>)>;
    fn unlink(&mut self, dir: Ino, name: &[u8]) -> Result<()>;
    /// Move entry `from` of `from_dir` to `to` in `to_dir` (same volume). An existing `to`
    /// is refused (`Exists`) unless `replace` and both are files. The caller makes sure
    /// `to_dir` is not the moved directory or inside it.
    fn rename(&mut self, from_dir: Ino, from: &[u8], to_dir: Ino, to: &[u8], replace: bool) -> Result<()>;
    /// The wall-clock time (D-OS time, 0 = unknown) that creating or changing something records.
    fn set_time(&mut self, _now: i64) {}
    /// Make everything written durable.
    fn sync(&mut self) -> Result<()>;
    fn info(&mut self) -> Info;
    /// Whether `ino` may never be written (e.g. inside a DFS snapshot).
    fn read_only(&self, ino: Ino) -> bool;
}
