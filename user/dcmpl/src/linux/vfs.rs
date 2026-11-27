//! Synthetic capability-scoped `/proc` and `/dev` views for D-CMPL's Linux personality.
//!
//! Strictly confined to this single supervised process:
//! - `/proc/self/*` (and `/proc/<pid>/*`) exposes only this process's own `exe`, `cmdline`,
//!   `environ`, `auxv`, `maps`, `status`, `stat`, `comm`, and `fd/*`. Any other PID returns
//!   `-ENOENT` (zero visibility into other D-OS processes or system services).
//! - `/dev/*` exposes only safe pseudo-devices (`/dev/null`, `/dev/zero`, `/dev/urandom`,
//!   `/dev/random`, `/dev/full`, `/dev/stdin`, `/dev/stdout`, `/dev/stderr`, `/dev/fd`). Hardware
//!   device nodes never appear.

use alloc::format;
use alloc::vec::Vec;

use libd::fs as fp;

use super::fs::{Kind, Open, stat_buf};
use super::{EACCES, EINVAL, EISDIR, ENOENT, ENOTDIR, Server};

pub fn is_synthetic(abs: &[u8]) -> bool {
    abs == b"/proc" || abs.starts_with(b"/proc/") || abs == b"/dev" || abs.starts_with(b"/dev/")
}

fn parse_u64(s: &[u8]) -> Option<u64> {
    if s.is_empty() || !s.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut v = 0u64;
    for &c in s {
        v = v.checked_mul(10)?.checked_add(u64::from(c - b'0'))?;
    }
    Some(v)
}

/// Normalize `/proc/<pid>/...` (matching `s.pid`) to `/proc/self/...`.
enum ProcTarget<'a> {
    Root,
    SelfDir,
    SelfFile(&'a [u8]),
    SelfFdDir,
    SelfFd(u64),
    TopFile(&'a [u8]),
    None,
}

fn classify_proc<'a>(s: &Server, abs: &'a [u8]) -> ProcTarget<'a> {
    if abs == b"/proc" {
        return ProcTarget::Root;
    }
    let Some(rest) = abs.strip_prefix(b"/proc/") else {
        return ProcTarget::None;
    };
    let (head, tail) = match rest.iter().position(|&c| c == b'/') {
        Some(i) => (&rest[..i], Some(&rest[i + 1..])),
        None => (rest, None),
    };
    let is_self = head == b"self" || parse_u64(head).is_some_and(|p| p as i64 == s.pid);
    if is_self {
        return match tail {
            None | Some(b"") => ProcTarget::SelfDir,
            Some(b"fd") => ProcTarget::SelfFdDir,
            Some(t) => {
                if let Some(fd_s) = t.strip_prefix(b"fd/") {
                    match parse_u64(fd_s) {
                        Some(fd) => ProcTarget::SelfFd(fd),
                        None => ProcTarget::None,
                    }
                } else {
                    ProcTarget::SelfFile(t)
                }
            }
        };
    }
    if tail.is_none() {
        return ProcTarget::TopFile(head);
    }
    ProcTarget::None
}

fn gen_proc_file(s: &Server, name: &[u8]) -> Option<Vec<u8>> {
    match name {
        b"cmdline" => Some(s.cmdline_nul.clone()),
        b"environ" => Some(s.environ_nul.clone()),
        b"auxv" => Some(s.auxv_bytes.clone()),
        b"maps" => Some(s.mm.format_maps()),
        b"comm" => {
            let mut v = s.comm.clone();
            v.push(b'\n');
            Some(v)
        }
        b"status" => {
            let comm = core::str::from_utf8(&s.comm).unwrap_or("linux");
            let txt = format!(
                "Name:\t{}\nState:\tR (running)\nTgid:\t{}\nPid:\t{}\nPPid:\t1\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nThreads:\t{}\n",
                comm,
                s.pid,
                s.pid,
                s.thread_count()
            );
            Some(txt.into_bytes())
        }
        b"stat" => {
            let comm = core::str::from_utf8(&s.comm).unwrap_or("linux");
            let txt = format!("{} ({}) R 1 {} {} 0 -1 0 0 0 0 0 0 0 0 0 20 0 {} 0 0 0 0\n", s.pid, comm, s.pid, s.pid, s.thread_count());
            Some(txt.into_bytes())
        }
        _ => None,
    }
}

fn gen_proc_top(name: &[u8]) -> Option<Vec<u8>> {
    match name {
        b"version" => Some(b"Linux version 6.6.0-dos (d-cmpl) #1 SMP PREEMPT\n".to_vec()),
        b"cpuinfo" => Some(
            b"processor\t: 0\nvendor_id\t: GenuineDOS\nmodel name\t: x86_64 CPU\ncpu MHz\t\t: 2400.000\nflags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 syscall nx lm sse4_1 sse4_2 xsave\n\n"
                .to_vec(),
        ),
        b"meminfo" => Some(
            b"MemTotal:         131072 kB\nMemFree:           98304 kB\nMemAvailable:      98304 kB\nBuffers:               0 kB\nCached:                0 kB\n"
                .to_vec(),
        ),
        b"stat" => Some(b"cpu  0 0 0 0 0 0 0 0 0 0\ncpu0 0 0 0 0 0 0 0 0 0\nbtime 946684800\nprocesses 1\nprocs_running 1\n".to_vec()),
        _ => None,
    }
}

fn proc_self_entries() -> Vec<(Vec<u8>, u64)> {
    alloc::vec![
        (b".".to_vec(), fp::KIND_DIR),
        (b"..".to_vec(), fp::KIND_DIR),
        (b"auxv".to_vec(), fp::KIND_FILE),
        (b"cmdline".to_vec(), fp::KIND_FILE),
        (b"comm".to_vec(), fp::KIND_FILE),
        (b"environ".to_vec(), fp::KIND_FILE),
        (b"exe".to_vec(), fp::KIND_FILE),
        (b"fd".to_vec(), fp::KIND_DIR),
        (b"maps".to_vec(), fp::KIND_FILE),
        (b"stat".to_vec(), fp::KIND_FILE),
        (b"status".to_vec(), fp::KIND_FILE),
    ]
}

fn proc_root_entries(pid: i64) -> Vec<(Vec<u8>, u64)> {
    alloc::vec![
        (b".".to_vec(), fp::KIND_DIR),
        (b"..".to_vec(), fp::KIND_DIR),
        (b"self".to_vec(), fp::KIND_DIR),
        (format!("{}", pid).into_bytes(), fp::KIND_DIR),
        (b"cpuinfo".to_vec(), fp::KIND_FILE),
        (b"meminfo".to_vec(), fp::KIND_FILE),
        (b"stat".to_vec(), fp::KIND_FILE),
        (b"version".to_vec(), fp::KIND_FILE),
    ]
}

fn dev_root_entries() -> Vec<(Vec<u8>, u64)> {
    alloc::vec![
        (b".".to_vec(), fp::KIND_DIR),
        (b"..".to_vec(), fp::KIND_DIR),
        (b"fd".to_vec(), fp::KIND_DIR),
        (b"full".to_vec(), fp::KIND_FILE),
        (b"null".to_vec(), fp::KIND_FILE),
        (b"random".to_vec(), fp::KIND_FILE),
        (b"stderr".to_vec(), fp::KIND_FILE),
        (b"stdin".to_vec(), fp::KIND_FILE),
        (b"stdout".to_vec(), fp::KIND_FILE),
        (b"urandom".to_vec(), fp::KIND_FILE),
        (b"zero".to_vec(), fp::KIND_FILE),
    ]
}

pub fn open(s: &Server, abs: &[u8], flags: u64) -> Result<Open, i64> {
    const O_WRONLY: u64 = 1;
    const O_RDWR: u64 = 2;
    const O_DIRECTORY: u64 = 0x1_0000;
    let acc = flags & 3;
    let write = acc == O_WRONLY || acc == O_RDWR;
    let want_dir = flags & O_DIRECTORY != 0;

    if abs == b"/dev" {
        if write {
            return Err(-EISDIR);
        }
        return Ok(Open::synth_dir(dev_root_entries(), abs.to_vec()));
    }
    if let Some(dev) = abs.strip_prefix(b"/dev/") {
        if dev == b"fd" {
            if write {
                return Err(-EISDIR);
            }
            return Ok(Open::synth_dir(s.fds.fd_dir_entries(), abs.to_vec()));
        }
        if let Some(fd_s) = dev.strip_prefix(b"fd/") {
            let fd = parse_u64(fd_s).ok_or(-ENOENT)?;
            return s.fds.clone_fd_open(fd);
        }
        if want_dir {
            return Err(-ENOTDIR);
        }
        let kind = match dev {
            b"null" => Kind::DevNull,
            b"zero" => Kind::DevZero,
            b"urandom" | b"random" => Kind::DevUrandom,
            b"full" => Kind::DevFull,
            b"stdin" => Kind::Stdin,
            b"stdout" | b"stderr" => Kind::Stdout,
            _ => return Err(-ENOENT),
        };
        return Ok(Open::simple(kind));
    }

    match classify_proc(s, abs) {
        ProcTarget::Root => {
            if write {
                return Err(-EISDIR);
            }
            Ok(Open::synth_dir(proc_root_entries(s.pid), abs.to_vec()))
        }
        ProcTarget::SelfDir => {
            if write {
                return Err(-EISDIR);
            }
            Ok(Open::synth_dir(proc_self_entries(), abs.to_vec()))
        }
        ProcTarget::SelfFdDir => {
            if write {
                return Err(-EISDIR);
            }
            Ok(Open::synth_dir(s.fds.fd_dir_entries(), abs.to_vec()))
        }
        ProcTarget::SelfFd(fd) => s.fds.clone_fd_open(fd),
        ProcTarget::SelfFile(b"exe") => {
            if write {
                return Err(-EACCES);
            }
            if want_dir {
                return Err(-ENOTDIR);
            }
            Ok(Open::synth_file(s.exe_bytes.clone(), abs.to_vec()))
        }
        ProcTarget::SelfFile(f) => {
            if write {
                return Err(-EACCES);
            }
            if want_dir {
                return Err(-ENOTDIR);
            }
            let data = gen_proc_file(s, f).ok_or(-ENOENT)?;
            Ok(Open::synth_file(data, abs.to_vec()))
        }
        ProcTarget::TopFile(f) => {
            if write {
                return Err(-EACCES);
            }
            if want_dir {
                return Err(-ENOTDIR);
            }
            let data = gen_proc_top(f).ok_or(-ENOENT)?;
            Ok(Open::synth_file(data, abs.to_vec()))
        }
        ProcTarget::None => Err(-ENOENT),
    }
}

pub fn readlink(s: &Server, abs: &[u8]) -> Result<Vec<u8>, i64> {
    if abs == b"/proc/self" {
        return Ok(format!("{}", s.pid).into_bytes());
    }
    if abs == b"/dev/stdin" {
        return Ok(b"/proc/self/fd/0".to_vec());
    }
    if abs == b"/dev/stdout" {
        return Ok(b"/proc/self/fd/1".to_vec());
    }
    if abs == b"/dev/stderr" {
        return Ok(b"/proc/self/fd/2".to_vec());
    }
    if abs == b"/dev/fd" {
        return Ok(b"/proc/self/fd".to_vec());
    }
    match classify_proc(s, abs) {
        ProcTarget::SelfFile(b"exe") => Ok(s.exe_path.clone()),
        ProcTarget::SelfFd(fd) => s.fds.fd_path(fd).ok_or(-ENOENT),
        ProcTarget::None => Err(-ENOENT),
        _ => Err(-EINVAL),
    }
}

pub fn stat(s: &Server, abs: &[u8], lstat: bool) -> Result<[u8; 144], i64> {
    if lstat && let Ok(link) = readlink(s, abs) {
        let mut b = stat_buf(fp::KIND_FILE, link.len() as u64, 0, 0, 0x5000);
        // S_IFLNK | 0777
        b[24..28].copy_from_slice(&0o120_777u32.to_le_bytes());
        return Ok(b);
    }
    if abs == b"/dev" {
        return Ok(stat_buf(fp::KIND_DIR, 0, 0, 0, 0x4000));
    }
    if let Some(dev) = abs.strip_prefix(b"/dev/") {
        if dev == b"fd" {
            return Ok(stat_buf(fp::KIND_DIR, 0, 0, 0, 0x4001));
        }
        if matches!(dev, b"null" | b"zero" | b"urandom" | b"random" | b"full" | b"stdin" | b"stdout" | b"stderr") {
            return Ok(stat_buf(0, 0, 0, 0, 0x4010)); // character device
        }
        return Err(-ENOENT);
    }
    match classify_proc(s, abs) {
        ProcTarget::Root | ProcTarget::SelfDir | ProcTarget::SelfFdDir => Ok(stat_buf(fp::KIND_DIR, 0, 0, 0, 0x3000)),
        ProcTarget::SelfFd(fd) => {
            if s.fds.fd_path(fd).is_some() {
                Ok(stat_buf(fp::KIND_FILE, 0, 0, 0, 0x3100 + fd))
            } else {
                Err(-ENOENT)
            }
        }
        ProcTarget::SelfFile(b"exe") => Ok(stat_buf(fp::KIND_FILE, s.exe_bytes.len() as u64, 0, 0, 0x3001)),
        ProcTarget::SelfFile(f) => {
            let data = gen_proc_file(s, f).ok_or(-ENOENT)?;
            Ok(stat_buf(fp::KIND_FILE, data.len() as u64, 0, 0, 0x3010))
        }
        ProcTarget::TopFile(f) => {
            let data = gen_proc_top(f).ok_or(-ENOENT)?;
            Ok(stat_buf(fp::KIND_FILE, data.len() as u64, 0, 0, 0x3020))
        }
        ProcTarget::None => Err(-ENOENT),
    }
}
