//! Storage tests (`fstest.dx`). init runs it with every volume in its namespace
//! (`/boot` FAT32 on SATA, `/system` DFS on SATA, `/data` DFS on NVMe) and storaged's test hooks
//! on. Checks: files written on the host (FAT32 long names, DFS), FAT32 writes, DFS operations
//! and a benchmark, snapshots, namespace isolation (a child process with two granted
//! directories), rename (and a rename cut by power failures), power cuts (crash consistency),
//! and corruption detection. Exit 0: all passed.
//!
//! Arguments: none (the tests), `child` (the isolated child of the namespace test), `bench` (read
//! throughput and latency on every volume; read only), or `readonly`
//! (the default read-only storage setup: every volume reads, nothing can be written).

#![no_std]

extern crate alloc;

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

use libd::fs::{self as fp, Node, NsBuilder, R_ADMIN, R_READ, R_WRITE};
use libd::sys::{self, Handle};
use libd::{Startup, println};

libd::entry!(_start, main);

macro_rules! check {
    ($c:expr, $($t:tt)*) => {
        if !$c {
            println!("fstest: FAIL: {}", format_args!($($t)*));
            return false;
        }
    };
}

/// The files the host image tool (tools/dosimg) wrote.
const README: &[u8] = b"D-OS boot volume (FAT32). Written by dosimg on the host.\r\n";
const HOST_NOTE: &[u8] = b"Hello from the host: long file names work.\r\n";
const DFS_HELLO: &[u8] = b"Hello from DFS, written on the host.\n";
/// What this test writes to the FAT32 volume (build.ps1 checks it on the host with 7-Zip).
pub const FROM_DOS: &[u8] = b"Hello from D-OS: FAT32 write works.\r\n";

fn pattern(seed: u64, n: usize) -> Vec<u8> {
    (0..n).map(|i| (i as u64).wrapping_mul(31).wrapping_add(seed * 7) as u8).collect()
}

fn st<T>(r: Result<T, impl core::borrow::Borrow<i64>>) -> &'static str {
    match r {
        Ok(_) => "OK",
        Err(e) => fp::status(*e.borrow()),
    }
}

fn open(d: &Node, p: &str, flags: u64, rights: u64) -> Result<Node, i64> {
    d.open(p.as_bytes(), flags, rights).map(|(n, _, _)| n)
}

fn read_file(d: &Node, p: &str) -> Result<Vec<u8>, i64> {
    let f = open(d, p, 0, R_READ)?;
    let size = f.stat()?.size as usize;
    let mut b = vec![0u8; size];
    let n = f.read(0, &mut b)?;
    b.truncate(n);
    Ok(b)
}

fn write_file(d: &Node, p: &str, data: &[u8]) -> Result<(), i64> {
    let f = open(d, p, fp::O_CREATE | fp::O_TRUNCATE, R_READ | R_WRITE)?;
    f.write(0, data)?;
    Ok(())
}

fn count(d: &Node) -> usize {
    let mut n = 0;
    let _ = d.list(|_, _| n += 1);
    n
}

// ---- FAT32 ----------------------------------------------------------------------------------

fn fat32(boot: &Node) -> bool {
    let i = boot.volinfo();
    check!(i.is_ok_and(|i| i.kind == fp::KIND_FAT32), "/boot is not FAT32");
    check!(read_file(boot, "README.TXT").is_ok_and(|b| b == README), "README.TXT from the host");
    check!(read_file(boot, "hello FROM the host.TXT").is_ok_and(|b| b == HOST_NOTE), "long-named host file (case-insensitive)");
    check!(read_file(boot, "EFI/BOOT/NOTE.TXT").is_ok(), "nested host file");
    check!(write_file(boot, "Written by D-OS.txt", FROM_DOS).is_ok(), "FAT32 create with a long name");
    check!(read_file(boot, "Written by D-OS.txt").is_ok_and(|b| b == FROM_DOS), "FAT32 read back");
    let big = pattern(5, 300_000);
    check!(write_file(boot, "big.bin", &big).is_ok(), "FAT32 300 KB write");
    check!(read_file(boot, "big.bin").is_ok_and(|b| b == big), "FAT32 300 KB read back");
    check!(open(boot, "D-OS logs", fp::O_CREATE | fp::O_DIRECTORY, R_READ | R_WRITE).is_ok(), "FAT32 mkdir");
    check!(write_file(boot, "D-OS logs/run.log", b"one\r\n").is_ok(), "FAT32 file in a new directory");
    check!(boot.unlink(b"D-OS logs") == Err(fp::ERR_NOT_EMPTY), "FAT32 non-empty directory removed");
    let logs = open(boot, "D-OS logs", 0, R_READ | R_WRITE);
    check!(logs.as_ref().is_ok_and(|l| l.unlink(b"run.log").is_ok()), "FAT32 unlink");
    drop(logs);
    check!(boot.unlink(b"D-OS logs").is_ok() && boot.unlink(b"big.bin").is_ok(), "FAT32 rmdir / unlink");
    check!(open(boot, "bad:name.txt", fp::O_CREATE, R_READ | R_WRITE).err() == Some(fp::ERR_BAD_NAME), "FAT32 accepted ':'");
    check!(boot.sync().is_ok(), "FAT32 sync");
    let mut names = Vec::new();
    let _ = boot.list(|n, _| names.push(n.to_vec()));
    check!(names.iter().any(|n| n == b"Written by D-OS.txt") && names.iter().any(|n| n == b"Hello from the host.txt"), "FAT32 listing");
    println!("fstest: fat32: host files (long names, nested) read, long-named file written, 300 KB round trip, mkdir/unlink/rmdir, {} entries listed", names.len());
    true
}

// ---- DFS ------------------------------------------------------------------------------------

fn dfs_basics(sys_: &Node) -> bool {
    check!(sys_.volinfo().is_ok_and(|i| i.kind == fp::KIND_DFS && i.block == 4096), "/system is not DFS");
    check!(read_file(sys_, "hello.txt").is_ok_and(|b| b == DFS_HELLO), "DFS file from the host");
    let d = open(sys_, "fstest", fp::O_CREATE | fp::O_DIRECTORY, R_READ | R_WRITE);
    check!(d.is_ok(), "DFS mkdir: {}", st(d.as_ref().map(|_| ())));
    let d = d.unwrap_or(Node::from(0));
    // 1 MiB: write, commit, read back (and how long each took).
    let data = pattern(1, 1 << 20);
    let f = open(&d, "big.bin", fp::O_CREATE | fp::O_TRUNCATE, R_READ | R_WRITE);
    check!(f.is_ok(), "DFS create");
    let f = f.unwrap_or(Node::from(0));
    let t0 = sys::clock_ns();
    check!(f.write(0, &data) == Ok(1 << 20), "DFS 1 MiB write");
    check!(f.sync().is_ok(), "DFS sync");
    let t1 = sys::clock_ns();
    let mut got = vec![0u8; 1 << 20];
    check!(f.read(0, &mut got) == Ok(1 << 20), "DFS 1 MiB read");
    let t2 = sys::clock_ns();
    check!(got == data, "DFS 1 MiB read back differs");
    println!("BENCH storage: DFS write 1 MiB + commit (SATA/AHCI) {} ms", (t1 - t0) / 1_000_000);
    println!("BENCH storage: DFS read 1 MiB, every block checksum verified (SATA/AHCI) {} ms", (t2 - t1) / 1_000_000);
    // Overwrite in the middle, sparse growth, truncate.
    check!(f.write(100_000, b"middle").is_ok(), "DFS overwrite");
    check!(f.truncate(200_000).is_ok() && f.stat().is_ok_and(|s| s.size == 200_000), "DFS truncate");
    let mut b = [0u8; 6];
    check!(f.read(100_000, &mut b) == Ok(6) && &b == b"middle", "DFS overwrite read back");
    // Many entries (the B+tree splits), then half removed.
    let many = open(&d, "many", fp::O_CREATE | fp::O_DIRECTORY, R_READ | R_WRITE).unwrap_or(Node::from(0));
    for i in 0..200 {
        if open(&many, &format!("file-{:03}", i), fp::O_CREATE | fp::O_EXCL, R_READ | R_WRITE).is_err() {
            println!("fstest: FAIL: DFS create file-{:03}", i);
            return false;
        }
    }
    check!(count(&many) == 200, "DFS listing: {} of 200", count(&many));
    check!(open(&many, "file-007", fp::O_CREATE | fp::O_EXCL, R_READ).err() == Some(fp::ERR_EXISTS), "O_EXCL on an existing file");
    for i in (0..200).step_by(2) {
        check!(many.unlink(format!("file-{:03}", i).as_bytes()).is_ok(), "DFS unlink file-{:03}", i);
    }
    check!(count(&many) == 100, "DFS listing after unlink: {}", count(&many));
    check!(sys_.sync().is_ok(), "DFS sync");
    let g = sys_.volinfo().map_or(0, |i| i.generation);
    println!("fstest: dfs: host file read, 1 MiB round trip, overwrite/truncate, 200 entries created and 100 removed, generation {}", g);
    true
}

fn snapshots(sys_: &Node) -> bool {
    let v1 = pattern(11, 50_000);
    let v2 = pattern(12, 50_000);
    check!(write_file(sys_, "fstest/state", &v1).is_ok() && sys_.sync().is_ok(), "write v1");
    let free0 = sys_.volinfo().map_or(0, |i| i.free);
    check!(sys_.snapshot(b"before").is_ok(), "snapshot");
    check!(sys_.snapshot(b"before") == Err(fp::ERR_EXISTS), "duplicate snapshot name");
    check!(write_file(sys_, "fstest/state", &v2).is_ok() && sys_.sync().is_ok(), "write v2");
    let snap = sys_.snapshot_open(b"before");
    check!(snap.is_ok(), "snapshot open: {}", st(snap.as_ref().map(|_| ())));
    let snap = snap.unwrap_or(Node::from(0));
    check!(read_file(&snap, "fstest/state").is_ok_and(|b| b == v1), "the snapshot shows v1");
    check!(read_file(sys_, "fstest/state").is_ok_and(|b| b == v2), "the live volume shows v2");
    let w = open(&snap, "fstest/state", 0, R_READ | R_WRITE);
    check!(w.err() == Some(sys::ERR_ACCESS_DENIED), "write access inside a snapshot");
    check!(open(&snap, "new", fp::O_CREATE, R_READ).is_err(), "create inside a snapshot");
    drop(snap);
    let used = free0.saturating_sub(sys_.volinfo().map_or(0, |i| i.free));
    check!(sys_.snapshot_delete(b"before").is_ok(), "snapshot delete");
    let free1 = sys_.volinfo().map_or(0, |i| i.free);
    check!(free1 + 2 >= free0, "space not returned after deleting the snapshot ({} -> {})", free0, free1);
    check!(sys_.test(fp::TEST_FSCK, 0).is_ok_and(|(e, _)| e == 0), "fsck after snapshot delete");
    println!("fstest: snapshots: snapshot keeps v1 while the volume moves to v2 ({} blocks held), read-only, deleted and space returned, fsck clean", used);
    true
}

// ---- namespace isolation --------------------------------------------------------------------

fn isolation(sys_: &Node, boot: &Node) -> bool {
    check!(write_file(sys_, "fstest/secret.txt", b"not for the child").is_ok(), "secret file");
    let home = open(sys_, "fstest/child", fp::O_CREATE | fp::O_DIRECTORY, R_READ | R_WRITE);
    check!(home.is_ok(), "child home");
    let ro = boot.clone_with(R_READ);
    check!(ro.is_ok(), "read-only clone of /boot");
    let mut ns = NsBuilder::new();
    check!(ns.add(b"/home", home.unwrap_or(Node::from(0))) && ns.add(b"/boot", ro.unwrap_or(Node::from(0))), "namespace");
    let mut hs = [sys::SpawnHandle::default(); 8];
    let log = sys::handle_duplicate(libd::startup_handle(sys::TAG_LOG), sys::RIGHTS_SAME).unwrap_or(0);
    hs[0] = sys::SpawnHandle { handle: log, rights: sys::RIGHTS_SAME, tag: sys::TAG_LOG, reserved: 0 };
    let n = ns.finish(&mut hs[1..]);
    check!(n.is_ok(), "namespace handles");
    let n = n.unwrap_or(0) + 1;
    let Some(image) = libd::find_program(b"fstest.dx") else {
        println!("fstest: FAIL: no fstest.dx program");
        return false;
    };
    let limits = sys::Limits { memory: 16 << 20, handles: 64, threads: 2 };
    let p = sys::spawn(libd::startup_handle(sys::TAG_PROC_SELF), image, b"fstest-child", b"child", &hs[..n], &limits);
    check!(p.is_ok(), "spawn the child");
    let p = p.unwrap_or(0);
    let _ = sys::object_wait(p, sys::TERMINATED, 60_000_000_000);
    let code = sys::process_exit_code(p);
    sys::handle_close(p);
    check!(code == 0, "the isolated child failed (exit code {})", code);
    check!(read_file(sys_, "fstest/child/from-child.txt").is_ok_and(|b| b == b"written inside /home"), "the child's file is not where its /home is");
    println!("fstest: namespace isolation: child saw only /home (rw) and /boot (ro); escapes, rights escalation and forged handles refused");
    true
}

fn child() -> bool {
    let ns = fp::Namespace::get();
    check!(ns.entries().count() == 2, "child namespace has {} entries", ns.entries().count());
    let (Some(home), Some(boot)) = (ns.dir(b"/home"), ns.dir(b"/boot")) else {
        println!("fstest: FAIL: child namespace incomplete");
        return false;
    };
    let (home, boot) = (Node::from(home), Node::from(boot));
    check!(write_file(&home, "from-child.txt", b"written inside /home").is_ok(), "child: write in /home");
    check!(read_file(&home, "from-child.txt").is_ok_and(|b| b == b"written inside /home"), "child: read back");
    // Paths never climb out of the directory they start from.
    for p in ["../secret.txt", "a/../../secret.txt", "/secret.txt", ".", "..", "x//y", ""] {
        let r = open(&home, p, 0, R_READ);
        check!(r.as_ref().err() == Some(&fp::ERR_BAD_NAME), "child: path '{}' gave {}", p, st(r.map(|_| ())));
    }
    check!(open(&home, "secret.txt", 0, R_READ).err() == Some(fp::ERR_NOT_FOUND), "child: the parent's file is visible");
    let (r, _) = ns.resolve(b"/home/from-child.txt").unwrap_or((0, b""));
    check!(r == home.ch, "child: namespace resolve");
    check!(ns.resolve(b"/system/fstest/secret.txt").is_none(), "child: /system resolves");
    // /boot is read-only: no write, no create, no unlink, no way to get more rights.
    check!(read_file(&boot, "README.TXT").is_ok_and(|b| b == README), "child: read /boot");
    check!(open(&boot, "README.TXT", 0, R_READ | R_WRITE).err() == Some(sys::ERR_ACCESS_DENIED), "child: opened /boot for writing");
    check!(open(&boot, "new.txt", fp::O_CREATE, R_READ).err() == Some(sys::ERR_ACCESS_DENIED), "child: created in /boot");
    check!(boot.unlink(b"README.TXT") == Err(sys::ERR_ACCESS_DENIED), "child: unlinked in /boot");
    check!(boot.clone_with(R_READ | R_WRITE).err() == Some(sys::ERR_ACCESS_DENIED), "child: widened /boot by clone");
    let f = open(&home, "from-child.txt", 0, R_READ);
    check!(f.as_ref().is_ok_and(|f| f.write(0, b"x") == Err(sys::ERR_ACCESS_DENIED)), "child: wrote through a read-only handle");
    drop(f);
    check!(home.clone_with(R_READ | R_WRITE | R_ADMIN).err() == Some(sys::ERR_ACCESS_DENIED), "child: gained R_ADMIN");
    check!(home.snapshot(b"x") == Err(sys::ERR_ACCESS_DENIED), "child: snapshot without R_ADMIN");
    check!(home.test(fp::TEST_FSCK, 0) == Err(sys::ERR_ACCESS_DENIED), "child: test hook without R_ADMIN");
    let mut names = Vec::new();
    let _ = home.list(|n, _| names.push(n.to_vec()));
    check!(names.len() == 1 && names[0] == b"from-child.txt", "child: /home lists {} entries", names.len());
    // Nothing else was granted: no programs, devices or disks; other handle numbers are not ours.
    let ours: Vec<Handle> = libd::startup_handles().map(|(h, _)| h).collect();
    check!(libd::startup_handles().all(|(_, t)| t != sys::TAG_PROGRAM && t != sys::TAG_DEVICE && t != fp::TAG_DISKS), "child: was given more than its namespace");
    let mut forged = 0;
    for h in 1..512u32 {
        if ours.contains(&h) || h == home.ch || h == boot.ch {
            continue;
        }
        let n = Node::from(h);
        let r = n.stat();
        let _ = n.into_handle(); // never close numbers that are not ours
        if r.is_ok() {
            println!("fstest: FAIL: child: handle {} works without being granted", h);
            return false;
        }
        forged += 1;
    }
    let _ = home.into_handle();
    let _ = boot.into_handle();
    println!("fstest: child: {} path escapes and 9 rights escalations refused, {} forged handle numbers refused", 7, forged);
    true
}

// ---- power cuts -----------------------------------------------------------------------------

/// Transaction t of the workload in `dir`: state = version t, add f<t>, drop f<t-2>, commit.
fn step(vol: &Node, dir: &str, t: u64) -> Result<(), i64> {
    let d = open(vol, dir, fp::O_CREATE | fp::O_DIRECTORY, R_READ | R_WRITE)?;
    let mut v = pattern(t, 9000 + t as usize * 1500);
    v[..8].copy_from_slice(&t.to_le_bytes());
    write_file(&d, "state", &v)?;
    write_file(&d, &format!("f{}", t), &pattern(t + 100, 6000))?;
    if t >= 3 {
        d.unlink(format!("f{}", t - 2).as_bytes())?;
    }
    vol.sync()
}

/// The state must be exactly what one transaction committed: its version.
fn state(vol: &Node, dir: &str) -> Result<u64, &'static str> {
    let Ok(d) = open(vol, dir, 0, R_READ) else { return Ok(0) };
    let Ok(s) = read_file(&d, "state") else {
        return if count(&d) == 0 { Ok(0) } else { Err("entries without a state file") };
    };
    if s.len() < 8 {
        return Err("short state file");
    }
    let t = u64::from_le_bytes(s[..8].try_into().unwrap_or_default());
    let mut want = pattern(t, 9000 + t as usize * 1500);
    want[..8].copy_from_slice(&t.to_le_bytes());
    if s != want {
        return Err("state file is no committed version");
    }
    for k in 1..=t + 2 {
        let exists = read_file(&d, &format!("f{}", k));
        let should = k <= t && k + 2 > t;
        match exists {
            Ok(b) if should && b == pattern(k + 100, 6000) => {}
            Err(fp::ERR_NOT_FOUND) if !should => {}
            _ => return Err("files do not match the committed version"),
        }
    }
    Ok(t)
}

fn power_cuts(data: &Node) -> bool {
    const STEPS: u64 = 4;
    let cuts = [0u64, 5, 17, 40, 90, 200, 450, 1000];
    let mut seen = Vec::new();
    for (round, &k) in cuts.iter().enumerate() {
        let dir = format!("pc{}", round);
        check!(data.test(fp::TEST_POWERCUT, k).is_ok(), "arm the power cut");
        for t in 1..=STEPS {
            if step(data, &dir, t).is_err() {
                break; // after the cut, requests may fail or (more often) appear to work
            }
        }
        let r = data.test(fp::TEST_REMOUNT, 0);
        check!(r.is_ok(), "remount after a cut at {} sectors: {}", k, st(r));
        let f = data.test(fp::TEST_FSCK, 0);
        check!(f.is_ok_and(|(e, _)| e == 0), "fsck after a cut at {} sectors: {:?}", k, f);
        match state(data, &dir) {
            Ok(v) => seen.push(v),
            Err(e) => {
                println!("fstest: FAIL: after a cut at {} sectors: {}", k, e);
                return false;
            }
        }
    }
    check!(seen.contains(&0) && seen.contains(&STEPS), "cuts did not span the workload: {:?}", seen);
    println!("fstest: power cut: {} cuts (0..{} sectors in), each remount clean (fsck 0 errors), committed versions seen {:?}", cuts.len(), cuts[cuts.len() - 1], seen);
    true
}

// ---- rename -----------------------------------------------------------------------------------

/// Rename on one volume: across directories, refusals (an existing name, a directory into itself),
/// replacing a file, and the file times (the clock service is running: they are known).
fn renames(vol: &Node, what: &str) -> bool {
    let data = pattern(77, 9000);
    let made = vol.open(b"rn-a", fp::O_CREATE | fp::O_DIRECTORY, R_READ | R_WRITE).is_ok()
        && vol.open(b"rn-b", fp::O_CREATE | fp::O_DIRECTORY, R_READ | R_WRITE).is_ok()
        && write_file(vol, "rn-a/Report draft.txt", &data).is_ok()
        && write_file(vol, "rn-b/old.txt", b"old").is_ok();
    check!(made, "{}: set up the rename test", what);
    let t = open(vol, "rn-a/Report draft.txt", 0, R_READ).and_then(|n| n.stat());
    check!(t.is_ok_and(|s| s.created != 0 && s.modified >= s.created), "{}: file times {:?}", what, t);
    let r = vol.rename(b"rn-a/Report draft.txt", b"rn-b/Final report.txt", false);
    check!(r.is_ok(), "{}: rename across directories: {}", what, st(r));
    check!(read_file(vol, "rn-a/Report draft.txt") == Err(fp::ERR_NOT_FOUND), "{}: the old name is still there", what);
    check!(read_file(vol, "rn-b/Final report.txt").is_ok_and(|b| b == data), "{}: content after the rename", what);
    let r = vol.rename(b"rn-b/Final report.txt", b"rn-b/old.txt", false);
    check!(r == Err(fp::ERR_EXISTS), "{}: an existing name was not refused: {}", what, st(r));
    let r = vol.rename(b"rn-b/Final report.txt", b"rn-b/old.txt", true);
    check!(r.is_ok() && read_file(vol, "rn-b/old.txt").is_ok_and(|b| b == data), "{}: replace: {}", what, st(r));
    let r = vol.rename(b"rn-a", b"rn-a/inside", false);
    check!(r == Err(sys::ERR_INVALID_ARGS), "{}: a directory moved into itself: {}", what, st(r));
    let r = vol.rename(b"rn-b", b"rn-a/rn-b", false);
    check!(r.is_ok() && read_file(vol, "rn-a/rn-b/old.txt").is_ok_and(|b| b == data), "{}: a directory moved: {}", what, st(r));
    let ro = vol.clone_with(R_READ).map(|n| n.rename(b"rn-a", b"rn-c", false));
    check!(ro.is_ok_and(|r| r == Err(sys::ERR_ACCESS_DENIED)), "{}: renamed through a read-only handle", what);
    check!(vol.sync().is_ok(), "{}: sync", what);
    true
}

/// A rename cut by a power failure at several points: after the remount the file is under
/// exactly one of its names, intact (DFS commits both sides at once).
fn rename_power_cuts(data: &Node) -> bool {
    let body = pattern(5, 7000);
    let mut outcomes = [0u32; 2];
    for (round, k) in [0u64, 2, 6, 12, 30, 80].into_iter().enumerate() {
        let (a, b) = (format!("rc{}/before", round), format!("rc{}/after", round));
        let made = data.open(format!("rc{}", round).as_bytes(), fp::O_CREATE | fp::O_DIRECTORY, R_READ | R_WRITE).is_ok()
            && write_file(data, &a, &body).is_ok()
            && data.sync().is_ok();
        check!(made, "set up the rename cut");
        check!(data.test(fp::TEST_POWERCUT, k).is_ok(), "arm the power cut");
        let _ = data.rename(a.as_bytes(), b.as_bytes(), false).and_then(|_| data.sync());
        let r = data.test(fp::TEST_REMOUNT, 0);
        check!(r.is_ok(), "remount after a rename cut at {} sectors: {}", k, st(r));
        let f = data.test(fp::TEST_FSCK, 0);
        check!(f.is_ok_and(|(e, _)| e == 0), "fsck after a rename cut at {} sectors: {:?}", k, f);
        let (old, new) = (read_file(data, &a), read_file(data, &b));
        check!(old.is_ok() != new.is_ok(), "a rename cut at {} sectors: old {}, new {}", k, st(old.clone()), st(new.clone()));
        check!(old.or(new).is_ok_and(|x| x == body), "a rename cut at {} sectors: content", k);
        outcomes[usize::from(read_file(data, &b).is_ok())] += 1;
    }
    check!(outcomes[0] > 0 && outcomes[1] > 0, "the cuts did not span the rename: {:?}", outcomes);
    println!("fstest: rename: power cut at 6 points: always exactly one name, content intact ({} before, {} after)", outcomes[0], outcomes[1]);
    true
}

// ---- corruption -----------------------------------------------------------------------------

fn corruption(data: &Node) -> bool {
    // The newest superblock: the volume mounts at the previous generation.
    check!(write_file(data, "gen-a", b"a").is_ok() && data.sync().is_ok(), "write");
    check!(write_file(data, "gen-b", b"b").is_ok() && data.sync().is_ok(), "write");
    let g = data.volinfo().map_or(0, |i| i.generation);
    check!(data.test(fp::TEST_CORRUPT_SUPER, 0).is_ok(), "corrupt the superblock");
    let r = data.test(fp::TEST_REMOUNT, 0);
    check!(r.is_ok_and(|(gen2, fb)| gen2 == g - 1 && fb >= 1), "superblock fallback: {:?} (was generation {})", r, g);
    check!(data.test(fp::TEST_FSCK, 0).is_ok_and(|(e, _)| e == 0), "fsck after the fallback");
    // A data block: reading it fails (never returns wrong data); rewriting repairs it.
    let v = pattern(21, 12_000);
    check!(write_file(data, "victim", &v).is_ok() && data.sync().is_ok(), "victim");
    let f = open(data, "victim", 0, R_READ | R_WRITE | R_ADMIN).unwrap_or(Node::from(0));
    check!(f.test(fp::TEST_CORRUPT_DATA, 0).is_ok(), "corrupt a data block");
    let mut b = vec![0u8; 12_000];
    let r = f.read(0, &mut b);
    check!(r == Err(fp::ERR_CORRUPT), "corrupted data block read gave {}", st(r));
    check!(data.test(fp::TEST_FSCK, 0).is_ok_and(|(e, _)| e > 0), "fsck missed the bad data block");
    check!(f.write(0, &v).is_ok() && data.sync().is_ok(), "rewrite");
    check!(f.read(0, &mut b) == Ok(12_000) && b == v, "rewritten file");
    check!(data.test(fp::TEST_FSCK, 0).is_ok_and(|(e, _)| e == 0), "fsck after the rewrite");
    // A metadata block (a tree leaf): what lives there is refused.
    let many = open(data, "meta", fp::O_CREATE | fp::O_DIRECTORY, fp::R_ALL).unwrap_or(Node::from(0));
    for i in 0..300 {
        let _ = open(&many, &format!("entry-{:03}", i), fp::O_CREATE, R_READ);
    }
    check!(data.sync().is_ok(), "sync");
    let t = open(&many, "entry-150", 0, R_READ | R_ADMIN).unwrap_or(Node::from(0));
    check!(t.test(fp::TEST_CORRUPT_META, 0).is_ok(), "corrupt a tree leaf");
    let r = t.stat();
    check!(r.err() == Some(fp::ERR_CORRUPT), "stat through a corrupted leaf gave {}", st(r.map(|_| ())));
    check!(data.test(fp::TEST_FSCK, 0).is_ok_and(|(e, _)| e > 0), "fsck missed the bad leaf");
    println!("fstest: corruption: damaged superblock -> previous generation; bad data block and bad tree leaf detected (CORRUPT, never wrong data), fsck reports them");
    true
}

// ---- code signing: a program loaded from disk --------------------------------------

fn vmo_with(data: &[u8]) -> Handle {
    let v = sys::vmo_create(data.len().max(1) as u64).unwrap_or(0);
    sys::vmo_write(v, 0, data);
    v
}

fn run_image(image: Handle) -> Result<i64, i64> {
    let log = sys::handle_duplicate(libd::startup_handle(sys::TAG_LOG), sys::RIGHTS_SAME).unwrap_or(0);
    let hs = [sys::SpawnHandle { handle: log, rights: sys::RIGHTS_SAME, tag: sys::TAG_LOG, reserved: 0 }];
    let limits = sys::Limits { memory: 8 << 20, handles: 16, threads: 1 };
    let p = sys::spawn(libd::startup_handle(sys::TAG_PROC_SELF), image, b"hello", b"", &hs, &limits)?;
    let _ = sys::object_wait(p, sys::TERMINATED, 30_000_000_000);
    let code = sys::process_exit_code(p);
    sys::handle_close(p);
    Ok(code)
}

/// The build signed hello.dx and put it on the boot volume (\DOS\APPS). Read it from disk, check
/// the kernel refuses it unverified, tampered, with junk after the signed bytes or with a forged
/// header, then verify and run it.
fn code_signing(esp: &Node) -> bool {
    let (Ok(img), Ok(sig)) = (read_file(esp, "DOS/APPS/HELLO.DX"), read_file(esp, "DOS/APPS/HELLO.DSIG")) else {
        println!("fstest: FAIL: \\DOS\\APPS\\HELLO.DX or HELLO.DSIG missing on the boot volume");
        return false;
    };
    check!(sig.len() == 256, "HELLO.DSIG is {} bytes", sig.len());
    let s = vmo_with(&sig);
    // Unverified: refused before it is parsed.
    let plain = vmo_with(&img);
    check!(run_image(plain) == Err(sys::ERR_NOT_SIGNED), "an unverified image was spawned");
    // One flipped byte: the signature no longer matches; the VMO stays untrusted.
    let mut bad = img.clone();
    bad[img.len() / 2] ^= 0x20;
    let t = vmo_with(&bad);
    check!(sys::vmo_verify(t, s) == sys::ERR_BAD_SIGNATURE, "a tampered image passed vmo_verify");
    check!(run_image(t) == Err(sys::ERR_NOT_SIGNED), "a tampered image was spawned");
    // Junk after the signed bytes (in the VMO's last page) is not accepted either.
    if img.len() % 4096 != 0 {
        let j = vmo_with(&img);
        sys::vmo_write(j, img.len() as u64, b"\xCC");
        check!(sys::vmo_verify(j, s) == sys::ERR_BAD_SIGNATURE, "junk after the signed bytes passed");
    }
    // A forged header (kind changed to "kernel"): the signature over the header fails.
    let mut forged = sig.clone();
    forged[8] = 1;
    let f = vmo_with(&forged);
    check!(sys::vmo_verify(plain, f) == sys::ERR_BAD_SIGNATURE, "a forged .dsig header passed");
    // The real thing: verified (and sealed), then it runs.
    let good = vmo_with(&img);
    check!(sys::vmo_verify(good, s) == 0, "the signed image failed vmo_verify");
    check!(sys::vmo_write(good, 0, b"x") == sys::ERR_ACCESS_DENIED, "a verified image is still writable");
    check!(run_image(good) == Ok(42), "the verified program did not run (exit {:?})", run_image(good));
    for h in [s, plain, t, f, good] {
        sys::handle_close(h);
    }
    println!(
        "fstest: code signing: hello.dx from the boot volume ({} bytes) verified (Ed25519) and run; unverified, tampered, padded and forged copies refused",
        img.len()
    );
    true
}

fn tests() -> bool {
    let ns = fp::Namespace::get();
    let mut names = Vec::new();
    for (n, _) in ns.entries() {
        names.push(core::str::from_utf8(n).unwrap_or("?"));
    }
    println!("fstest: namespace: {:?}", names);
    let (Some(boot), Some(sys_), Some(data)) = (ns.dir(b"/boot"), ns.dir(b"/system"), ns.dir(b"/data")) else {
        println!("fstest: FAIL: expected /boot, /system and /data");
        return false;
    };
    let (boot, sys_, data) = (Node::from(boot), Node::from(sys_), Node::from(data));
    let Some(esp) = ns.dir(b"/esp").map(Node::from) else {
        println!("fstest: FAIL: expected /esp (the boot disk's EFI System Partition)");
        return false;
    };
    let ok = code_signing(&esp) && fat32(&boot) && dfs_basics(&sys_) && snapshots(&sys_) && isolation(&sys_, &boot);
    let ok = ok && renames(&data, "dfs") && renames(&boot, "fat32");
    if ok {
        println!("fstest: rename: DFS and FAT32: across directories, existing names refused, a file replaced, a directory moved (never into itself), file times set");
    }
    ok && rename_power_cuts(&data) && power_cuts(&data) && corruption(&data)
}

/// Read-only storage (docs/hardware.md): every volume is readable; writing, creating, truncating
/// and asking for write or admin rights are all refused.
fn readonly() -> bool {
    let ns = fp::Namespace::get();
    let mut vols = 0;
    for (name, h) in ns.entries() {
        let vname = core::str::from_utf8(name).unwrap_or("?");
        let d = Node::from(h);
        let mut entries = 0;
        check!(d.readdir(0, |_, _| entries += 1).is_ok(), "{}: listing the root", vname);
        let created = d.open(b"ro-probe", fp::O_CREATE, R_READ | R_WRITE);
        check!(created.is_err(), "{}: a file was created ({})", vname, st(created));
        let created_ro = d.open(b"ro-probe", fp::O_CREATE, R_READ);
        check!(created_ro.is_err(), "{}: O_CREATE with read rights only created a file", vname);
        let admin = d.open(b".", fp::O_DIRECTORY, R_READ | R_ADMIN);
        check!(admin.is_err(), "{}: admin rights were granted", vname);
        vols += 1;
        println!("fstest: readonly: {}: {} entries readable; create, write and admin rights refused", vname, entries);
        let _ = d.into_handle(); // the namespace keeps owning it
    }
    check!(vols >= 1, "no volumes in the namespace");
    if let Some(boot) = ns.dir(b"/boot").map(Node::from) {
        check!(read_file(&boot, "README.TXT").is_ok_and(|b| b == README), "README.TXT reads back");
        let w = open(&boot, "README.TXT", 0, R_READ | R_WRITE);
        check!(w.is_err(), "/boot/README.TXT opened for writing");
        let t = open(&boot, "README.TXT", fp::O_TRUNCATE, R_READ);
        check!(t.is_err(), "/boot/README.TXT truncated");
    }
    if let Some(sys_) = ns.dir(b"/system").map(Node::from) {
        check!(read_file(&sys_, "hello.txt").is_ok_and(|b| b == DFS_HELLO), "DFS hello.txt reads back");
    }
    println!("fstest: readonly: {} volume(s), all read-only", vols);
    true
}

/// Storage benchmark (`fstest bench`, the hardware benchmark image; docs/benchmarks.md). Read only:
/// on every volume, the largest file found (directories walked 4 levels deep, at most 4000
/// entries) is read once from start to end in `MAX_IO` requests (at most 256 MiB), then 256
/// random 4 KiB reads of it are timed. Every byte goes through the whole stack: block driver,
/// storaged, the file system and a channel to this process.
fn bench() -> bool {
    let ns = fp::Namespace::get();
    let mut vols = 0;
    for (name, h) in ns.entries() {
        let vname = core::str::from_utf8(name).unwrap_or("?");
        let root = Node::from(h);
        if bench_volume(&root, vname) {
            vols += 1;
        }
        let _ = root.into_handle(); // the namespace keeps owning it
    }
    println!("fstest: bench: {} volume(s) measured", vols);
    true
}

/// The largest file below `root`: (path, size).
fn largest_file(root: &Node) -> Option<(Vec<u8>, u64)> {
    let mut best: Option<(Vec<u8>, u64)> = None;
    let mut seen = 0usize;
    let mut stack: Vec<(Vec<u8>, u32)> = vec![(Vec::new(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        let mut here: Vec<(Vec<u8>, u64)> = Vec::new();
        let mut add = |n: &[u8], k: u64| {
            if n != b"." && n != b".." {
                let mut p = dir.clone();
                if !p.is_empty() {
                    p.push(b'/');
                }
                p.extend_from_slice(n);
                here.push((p, k));
            }
        };
        if dir.is_empty() {
            let _ = root.list(&mut add);
        } else if let Ok((d, _, _)) = root.open(&dir, fp::O_DIRECTORY, R_READ) {
            let _ = d.list(&mut add);
        }
        for (p, k) in here {
            seen += 1;
            if seen > 4000 {
                return best;
            }
            if k == fp::KIND_DIR {
                if depth < 4 {
                    stack.push((p, depth + 1));
                }
            } else if let Ok((_, _, size)) = root.open(&p, 0, R_READ)
                && best.as_ref().is_none_or(|b| size > b.1)
            {
                best = Some((p, size));
            }
        }
    }
    best
}

fn bench_volume(root: &Node, vname: &str) -> bool {
    let Some((path, size)) = largest_file(root) else {
        println!("fstest: bench: {}: no file to read", vname);
        return false;
    };
    let pname = core::str::from_utf8(&path).unwrap_or("?");
    let Ok((f, _, _)) = root.open(&path, 0, R_READ) else {
        return false;
    };
    let total = size.min(256 << 20);
    let mut buf = vec![0u8; fp::MAX_IO];
    let t0 = sys::clock_ns();
    let mut off = 0u64;
    while off < total {
        match f.read(off, &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => off += n as u64,
        }
    }
    let ns_seq = (sys::clock_ns() - t0).max(1);
    if off < 64 * 1024 {
        println!("fstest: bench: {}: largest file /{} has {} bytes: too small to time", vname, pname, off);
        return true;
    }
    println!("BENCH fs: {}: sequential read of /{} ({} KiB, {} KiB requests): {} MB/s",
             vname, pname, off / 1024, fp::MAX_IO / 1024, off * 1000 / ns_seq);
    {
        let pages = off / 4096;
        let mut x = 0x9E37_79B9_7F4A_7C15u64 ^ off;
        let t1 = sys::clock_ns();
        let mut n = 0u64;
        for _ in 0..256 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            if f.read((x % pages) * 4096, &mut buf[..4096]).is_ok() {
                n += 1;
            }
        }
        let each = ((sys::clock_ns() - t1) / n.max(1)).max(1);
        println!("BENCH fs: {}: random 4 KiB reads: {}.{} us each ({} per second)",
                 vname, each / 1000, (each % 1000) / 100, 1_000_000_000 / each);
    }
    true
}

fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer the kernel passed to the entry point.
    if !unsafe { libd::init(s, "fstest") } {
        return -1;
    }
    if libd::args().starts_with(b"child") {
        return if child() { 0 } else { 1 };
    }
    if libd::args().starts_with(b"bench") {
        return if bench() { 0 } else { 1 };
    }
    if libd::args().starts_with(b"readonly") {
        let ok = readonly();
        println!("fstest: readonly {}", if ok { "PASSED" } else { "FAILED" });
        return if ok { 0 } else { 1 };
    }
    let ok = tests();
    println!("fstest: {}", if ok { "PASSED" } else { "FAILED" });
    if ok { 0 } else { 1 }
}
