//! `dosimg`: host tool for D-OS disk images, built on the same storage code the OS runs
//! (user/lib/fs). build.ps1 uses it to create the test disks and to check, after a test boot,
//! what D-OS left on them.
//!
//!   dosimg boot <out.img> <stage1> <stage2> <stage3> <kernel.bin> <kernel.dsig> <BOOTX64.EFI> [esp-path=file ...]
//!                                            64 MiB boot disk (BIOS + UEFI): GPT, BIOS boot, "esp" FAT32
//!   dosimg pubkey <seed>                     print the Ed25519 public key of a 32-byte signing seed (hex)
//!   dosimg sign <seed> <kind> <name> <file> <out.dsig>   sign (kind: kernel, program, driver, package)
//!   dosimg verify <seed> <file> <dsig>       check a signature (exit 1 if invalid)
//!   dosimg sha512 | sha256 <file>            print a digest (host cross-checks)
//!   dosimg patch <img> <part> <path> <offset> <xor-hex>   flip bits of one byte of a file (tests)
//!   dosimg sata <out.img>                    64 MiB: GPT, "boot" FAT32 (ESP), "system" DFS
//!   dosimg nvme <out.img>                    32 MiB: GPT, "data" DFS
//!   dosimg ls <img> <part> [dir]             list a directory (FAT32 or DFS)
//!   dosimg cat <img> <part> <path>           print a file
//!   dosimg fsck <img> <part>                 check a DFS volume (exit 1 on any error)
//!   dosimg extract <img> <part> <out>        copy a partition out (for other tools, e.g. 7-Zip)
//!
//! Images are deterministic (fixed GUIDs, serials, timestamps): the same bytes every build.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::process::ExitCode;

use dosfs::dev::{BlockDev, Part, SECTOR};
use dosfs::dfs::{Dfs, FormatOpts};
use dosfs::fat::{self, Fat};
use dosfs::gpt;
use dosfs::{FileSystem, Ino, Kind};

struct FileDev {
    f: File,
    sectors: u64,
}

impl BlockDev for FileDev {
    fn sectors(&self) -> u64 {
        self.sectors
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> dosfs::Result<()> {
        self.f.seek(SeekFrom::Start(lba * SECTOR as u64)).map_err(|_| dosfs::Error::Io)?;
        self.f.read_exact(buf).map_err(|_| dosfs::Error::Io)
    }
    fn write(&mut self, lba: u64, buf: &[u8]) -> dosfs::Result<()> {
        self.f.seek(SeekFrom::Start(lba * SECTOR as u64)).map_err(|_| dosfs::Error::Io)?;
        self.f.write_all(buf).map_err(|_| dosfs::Error::Io)
    }
    fn flush(&mut self) -> dosfs::Result<()> {
        self.f.flush().map_err(|_| dosfs::Error::Io)
    }
}

type Shared = std::rc::Rc<std::cell::RefCell<dyn BlockDev>>;

fn open(path: &str, create_mib: Option<u64>) -> Result<Shared, String> {
    let f = match create_mib {
        Some(mib) => {
            let f = OpenOptions::new().read(true).write(true).create(true).truncate(true).open(path).map_err(|e| format!("{}: {}", path, e))?;
            f.set_len(mib << 20).map_err(|e| e.to_string())?;
            f
        }
        None => OpenOptions::new().read(true).write(true).open(path).map_err(|e| format!("{}: {}", path, e))?,
    };
    let sectors = f.metadata().map_err(|e| e.to_string())?.len() / SECTOR as u64;
    Ok(std::rc::Rc::new(std::cell::RefCell::new(FileDev { f, sectors })))
}

fn part(disk: &Shared, index: usize) -> Result<(Part, gpt::Partition), String> {
    let (parts, _) = gpt::read(&mut *disk.borrow_mut()).map_err(|e| format!("no GPT: {:?}", e))?;
    let p = parts.into_iter().find(|p| p.index == index).ok_or(format!("no partition {}", index))?;
    Ok((Part { disk: disk.clone(), start: p.first, len: p.sectors() }, p))
}

fn ok<T>(r: dosfs::Result<T>, what: &str) -> Result<T, String> {
    r.map_err(|e| format!("{}: {:?}", what, e))
}

fn mkdirs(fs: &mut dyn FileSystem, path: &str) -> Result<Ino, String> {
    let mut at = fs.root();
    for c in path.split('/').filter(|c| !c.is_empty()) {
        at = match fs.lookup(at, c.as_bytes()) {
            Ok(i) => i,
            Err(_) => ok(fs.create(at, c.as_bytes(), Kind::Dir), c)?,
        };
    }
    Ok(at)
}

fn put(fs: &mut dyn FileSystem, path: &str, data: &[u8]) -> Result<(), String> {
    let (dir, name) = path.rsplit_once('/').unwrap_or(("", path));
    let d = mkdirs(fs, dir)?;
    let f = ok(fs.create(d, name.as_bytes(), Kind::File), path)?;
    ok(fs.write(f, 0, data), path)?;
    Ok(())
}

fn resolve(fs: &mut dyn FileSystem, path: &str) -> Result<Ino, String> {
    let mut at = fs.root();
    for c in path.split('/').filter(|c| !c.is_empty()) {
        at = ok(fs.lookup(at, c.as_bytes()), c)?;
    }
    Ok(at)
}

/// The bytes the OS test checks for (user/fstest).
const README: &[u8] = b"D-OS boot volume (FAT32). Written by dosimg on the host.\r\n";
const HOST_NOTE: &[u8] = b"Hello from the host: long file names work.\r\n";
const DFS_HELLO: &[u8] = b"Hello from DFS, written on the host.\n";

fn make_sata(out: &str) -> Result<(), String> {
    let disk = open(out, Some(64))?;
    let parts = [
        gpt::NewPart { type_guid: gpt::TYPE_ESP, name: "boot", sectors: 40 * 2048 },
        gpt::NewPart { type_guid: gpt::TYPE_DFS, name: "system", sectors: 0 },
    ];
    let made = ok(gpt::write(&mut *disk.borrow_mut(), &parts, *b"D-OS-SATA-DISK-0"), "gpt")?;
    let mut p = Part { disk: disk.clone(), start: made[0].first, len: made[0].sectors() };
    ok(fat::format(&mut p, &fat::Format { label: b"D-OS BOOT", serial: 0x0D05_2026, hidden: made[0].first as u32 }), "fat format")?;
    let mut f = ok(Fat::mount(p), "fat mount")?;
    put(&mut f, "README.TXT", README)?;
    put(&mut f, "Hello from the host.txt", HOST_NOTE)?;
    put(&mut f, "EFI/BOOT/NOTE.TXT", b"A UEFI loader goes here.\r\n")?;
    ok(f.sync(), "fat sync")?;
    let p = Part { disk: disk.clone(), start: made[1].first, len: made[1].sectors() };
    let mut d = ok(Dfs::format(Box::new(p), &FormatOpts { label: b"system", uuid: *b"D-OS-DFS-SYSTEM0", time: 0 }), "dfs format")?;
    put(&mut d, "hello.txt", DFS_HELLO)?;
    mkdirs(&mut d, "apps")?;
    ok(d.sync(), "dfs sync")?;
    Ok(())
}

fn make_nvme(out: &str) -> Result<(), String> {
    let disk = open(out, Some(32))?;
    // Partition 2 imitates a Windows NTFS volume (basic data type, an NTFS boot sector): D-OS must
    // name it and leave it alone (found on the first real-hardware boot).
    let parts = [
        gpt::NewPart { type_guid: gpt::TYPE_DFS, name: "data", sectors: 28 * 2048 },
        gpt::NewPart { type_guid: gpt::TYPE_BASIC_DATA, name: "Basic data partition", sectors: 0 },
    ];
    let made = ok(gpt::write(&mut *disk.borrow_mut(), &parts, *b"D-OS-NVME-DISK-0"), "gpt")?;
    let mut ntfs = [0u8; SECTOR];
    ntfs[0..3].copy_from_slice(&[0xEB, 0x52, 0x90]);
    ntfs[3..11].copy_from_slice(b"NTFS    ");
    ntfs[510] = 0x55;
    ntfs[511] = 0xAA;
    let mut np = Part { disk: disk.clone(), start: made[1].first, len: made[1].sectors() };
    ok(np.write(0, &ntfs), "ntfs boot sector")?;
    let p = Part { disk: disk.clone(), start: made[0].first, len: made[0].sectors() };
    let mut d = ok(Dfs::format(Box::new(p), &FormatOpts { label: b"data", uuid: *b"D-OS-DFS-DATA-00", time: 0 }), "dfs format")?;
    put(&mut d, "hello.txt", DFS_HELLO)?;
    ok(d.sync(), "dfs sync")?;
    Ok(())
}


/// The D-OS boot disk: one image that boots under BIOS and UEFI (docs/boot.md).
///   LBA 0          protective MBR, whose boot code (bytes 0-439) is stage 1
///   partition 1    BIOS boot (8 MiB at LBA 2048): stage 2 (32 sectors), stage 3 (the C signature
///                  verifier, 64 sectors), the kernel's .dsig (1 sector), then the kernel
///   partition 2    EFI System Partition "esp" (FAT32): \EFI\BOOT\BOOTX64.EFI, \DOS\KERNEL.BIN,
///                  \DOS\KERNEL.DSIG, plus any extra files given as ESP-path=host-path
/// build.ps1 assembles stage 1/2 for these LBAs.
const BOOT_IMAGE_MIB: u64 = 64;
const BIOS_PART_SECTORS: u64 = 8 * 2048;
const STAGE2_LBA: u64 = 2048;
const STAGE2_SECTORS: u64 = 32;
const STAGE3_SECTORS: u64 = 64;
const KSIG_LBA: u64 = STAGE2_LBA + STAGE2_SECTORS + STAGE3_SECTORS;
const KERNEL_LBA: u64 = KSIG_LBA + 8;

fn read_file(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("{}: {}", path, e))
}

#[allow(clippy::too_many_arguments)] // one per input file of the boot image
fn make_boot(out: &str, stage1: &str, stage2: &str, stage3: &str, kernel: &str, ksig: &str, efi: &str, extra: &[String]) -> Result<(), String> {
    let (s1, s2, s3) = (read_file(stage1)?, read_file(stage2)?, read_file(stage3)?);
    let (k, ks, e) = (read_file(kernel)?, read_file(ksig)?, read_file(efi)?);
    if s1.len() != SECTOR || s1[510] != 0x55 || s1[511] != 0xAA {
        return Err("stage 1 must be one boot sector".into());
    }
    for (what, b, max) in [("stage 2", &s2, STAGE2_SECTORS), ("stage 3", &s3, STAGE3_SECTORS)] {
        if b.len() as u64 > max * SECTOR as u64 {
            return Err(format!("{} is {} bytes; at most {}", what, b.len(), max * SECTOR as u64));
        }
    }
    if k.len() < 64 || &k[0..4] != b"DKRN" {
        return Err("kernel.bin has no D-KRNL image header".into());
    }
    if ks.len() != doscrypt::dsig::SIZE || doscrypt::dsig::parse(&ks).is_err() {
        return Err("the kernel signature is not a .dsig".into());
    }
    if k.len() as u64 > (BIOS_PART_SECTORS - (KERNEL_LBA - STAGE2_LBA)) * SECTOR as u64 {
        return Err(format!("kernel is {} bytes; too large for the BIOS boot partition", k.len()));
    }
    if e.len() < 2 || &e[0..2] != b"MZ" {
        return Err("BOOTX64.EFI is not a PE image".into());
    }
    let disk = open(out, Some(BOOT_IMAGE_MIB))?;
    let parts = [
        gpt::NewPart { type_guid: gpt::TYPE_BIOS_BOOT, name: "bios-boot", sectors: BIOS_PART_SECTORS },
        gpt::NewPart { type_guid: gpt::TYPE_ESP, name: "esp", sectors: 0 },
    ];
    let made = ok(gpt::write(&mut *disk.borrow_mut(), &parts, *b"D-OS-BOOT-DISK-0"), "gpt")?;
    if made[0].first != STAGE2_LBA {
        return Err("BIOS boot partition not at LBA 2048".into());
    }
    {
        let mut d = disk.borrow_mut();
        // Stage 1 into the protective MBR's boot code area; the partition table stays.
        let mut mbr = [0u8; SECTOR];
        ok(d.read(0, &mut mbr), "mbr")?;
        mbr[..440].copy_from_slice(&s1[..440]);
        ok(d.write(0, &mbr), "mbr")?;
        let pad = |b: &[u8]| {
            let mut v = b.to_vec();
            v.resize(b.len().div_ceil(SECTOR) * SECTOR, 0);
            v
        };
        ok(d.write(STAGE2_LBA, &pad(&s2)), "stage 2")?;
        ok(d.write(STAGE2_LBA + STAGE2_SECTORS, &pad(&s3)), "stage 3")?;
        ok(d.write(KSIG_LBA, &pad(&ks)), "kernel signature")?;
        ok(d.write(KERNEL_LBA, &pad(&k)), "kernel")?;
    }
    let mut p = Part { disk: disk.clone(), start: made[1].first, len: made[1].sectors() };
    ok(fat::format(&mut p, &fat::Format { label: b"D-OS ESP", serial: 0x0D05_0013, hidden: made[1].first as u32 }), "fat format")?;
    let mut f = ok(Fat::mount(p), "fat mount")?;
    put(&mut f, "EFI/BOOT/BOOTX64.EFI", &e)?;
    put(&mut f, "DOS/KERNEL.BIN", &k)?;
    put(&mut f, "DOS/KERNEL.DSIG", &ks)?;
    put(&mut f, "DOS/README.TXT", b"D-OS boot files: the UEFI loader (\\EFI\\BOOT\\BOOTX64.EFI) loads \\DOS\\KERNEL.BIN after checking its signature (\\DOS\\KERNEL.DSIG).\r\n")?;
    for x in extra {
        let (dst, src) = x.split_once('=').ok_or(format!("extra file '{}': expected ESP-path=host-path", x))?;
        put(&mut f, dst, &read_file(src)?)?;
    }
    ok(f.sync(), "fat sync")?;
    println!("dosimg: boot image {} ({} MiB): stage 2 at LBA {}, stage 3 at LBA {}, kernel signature at LBA {}, kernel at LBA {} ({} sectors), ESP at LBA {}",
        out, BOOT_IMAGE_MIB, STAGE2_LBA, STAGE2_LBA + STAGE2_SECTORS, KSIG_LBA, KERNEL_LBA, k.len().div_ceil(SECTOR), made[1].first);
    Ok(())
}

fn read_seed(path: &str) -> Result<doscrypt::ed25519::SigningKey, String> {
    let s = read_file(path)?;
    let seed: [u8; 32] = s.as_slice().try_into().map_err(|_| format!("{}: a signing key seed is 32 bytes", path))?;
    Ok(doscrypt::ed25519::SigningKey::from_seed(&seed))
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn dsig_kind(s: &str) -> Result<u32, String> {
    use doscrypt::dsig::*;
    Ok(match s {
        "kernel" => KIND_KERNEL,
        "program" => KIND_PROGRAM,
        "driver" => KIND_DRIVER,
        "package" => KIND_PACKAGE,
        "manifest" => KIND_MANIFEST,
        _ => return Err(format!("unknown signature kind '{}' (kernel, program, driver, package, manifest)", s)),
    })
}

fn with_fs(img: &str, index: usize, f: &mut dyn FnMut(&mut dyn FileSystem) -> Result<(), String>) -> Result<(), String> {
    let disk = open(img, None)?;
    let (p, info) = part(&disk, index)?;
    if info.type_guid == gpt::TYPE_DFS {
        let mut d = Dfs::mount(Box::new(p)).map_err(|(e, _)| format!("dfs mount: {:?}", e))?;
        f(&mut d)
    } else {
        let mut fat = ok(Fat::mount(p), "fat mount")?;
        f(&mut fat)
    }
}

fn from_hex(h: &str) -> Result<Vec<u8>, String> {
    let h = h.trim();
    if !h.len().is_multiple_of(2) {
        return Err("hex: odd length".to_string());
    }
    (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).map_err(|e| e.to_string())).collect()
}

fn run(args: &[String]) -> Result<(), String> {
    let a = |i: usize| args.get(i).map(String::as_str).ok_or_else(|| "missing argument (see the source for usage)".to_string());
    let idx = |i: usize| a(i)?.parse::<usize>().map_err(|e| e.to_string());
    match a(1)? {
        "boot" => make_boot(a(2)?, a(3)?, a(4)?, a(5)?, a(6)?, a(7)?, a(8)?, args.get(9..).unwrap_or(&[])),
        "pubkey" => {
            let k = read_seed(a(2)?)?;
            println!("{}", to_hex(&k.public()));
            Ok(())
        }
        "sign" => {
            let k = read_seed(a(2)?)?;
            let content = read_file(a(5)?)?;
            let d = doscrypt::dsig::sign(&k, dsig_kind(a(3)?)?, a(4)?, &content);
            std::fs::write(a(6)?, d).map_err(|e| e.to_string())
        }
        "verify" => {
            let k = read_seed(a(2)?)?;
            let content = read_file(a(3)?)?;
            let d = read_file(a(4)?)?;
            match doscrypt::dsig::verify(&d, &k.public(), &content) {
                Ok(h) => {
                    println!("dsig: valid ({} '{}', {} bytes, key {})", h.kind, h.name_str(), h.size, to_hex(&h.key_id[..8]));
                    Ok(())
                }
                Err(e) => Err(format!("dsig: {:?}", e)),
            }
        }
        "patch" => {
            // XOR one byte of a file in a volume (tests: a tampered kernel must be refused).
            let off = idx(5)?;
            let x = u8::from_str_radix(a(6)?.trim_start_matches("0x"), 16).map_err(|e| e.to_string())?;
            with_fs(a(2)?, idx(3)?, &mut |fs| {
                let f = resolve(fs, a(4)?)?;
                let mut b = [0u8; 1];
                ok(fs.read(f, off as u64, &mut b), "read")?;
                b[0] ^= x;
                ok(fs.write(f, off as u64, &b), "write")?;
                ok(fs.sync(), "sync")
            })
        }
        "attest-verify" => {
            // attest-verify <report.bin> <nonce hex> <KERNEL.DSIG> <pubkey hex> [allow-unsigned]
            // The verifier side of remote attestation (docs/attestation.md): the nonce it sent,
            // the reference kernel's .dsig and the D-OS public key are its reference values.
            let r = read_file(a(2)?)?;
            let nonce: [u8; 32] = from_hex(a(3)?)?.try_into().map_err(|_| "nonce: 32 bytes".to_string())?;
            let kd = read_file(a(4)?)?;
            let key: [u8; 32] = from_hex(a(5)?)?.try_into().map_err(|_| "public key: 32 bytes".to_string())?;
            let allow_unsigned = args.get(6).is_some_and(|x| x == "allow-unsigned");
            let p = doscrypt::attest::Policy { kernel_dsig: &kd, key: &key, allow_unsigned };
            match doscrypt::attest::verify(&r, &nonce, &p) {
                Ok(v) => {
                    let ver = String::from_utf8_lossy(&v.kernel_version).trim_end_matches(char::from(0)).to_string();
                    let tpm = if v.flags & doscrypt::attest::F_TPM_MATCH != 0 {
                        "TPM PCRs equal the log"
                    } else if v.flags & doscrypt::attest::F_TPM != 0 {
                        "TPM present, PCRs NOT equal to the log"
                    } else {
                        "no TPM (software evidence: rooted in the verified kernel)"
                    };
                    println!(
                        "attest: VALID: D-KRNL {} ({}), the reference kernel, verified by its loader; {} events replayed to PCR 8 and 10; {} signed program(s), {} unsigned; {} service decision(s); attestation key {}; {}",
                        ver,
                        if v.firmware == 2 { "UEFI" } else { "BIOS" },
                        v.events,
                        v.signed_code,
                        v.unsigned_code,
                        v.decisions,
                        to_hex(&v.ak[..8]),
                        tpm
                    );
                    Ok(())
                }
                Err(e) => Err(format!("attest: REFUSED: {:?}", e)),
            }
        }
        "sha512" => {
            println!("{}", to_hex(&doscrypt::sha2::sha512(&read_file(a(2)?)?)));
            Ok(())
        }
        "sha256" => {
            println!("{}", to_hex(&doscrypt::sha2::sha256(&read_file(a(2)?)?)));
            Ok(())
        }
        "sata" => make_sata(a(2)?),
        "nvme" => make_nvme(a(2)?),
        "ls" => with_fs(a(2)?, idx(3)?, &mut |fs| {
            let dir = resolve(fs, args.get(4).map_or("", String::as_str))?;
            let mut c = 0;
            loop {
                let (es, next) = ok(fs.readdir(dir, c, 64), "readdir")?;
                for e in es {
                    println!("{} {}", if e.kind == Kind::Dir { "d" } else { "-" }, String::from_utf8_lossy(&e.name));
                }
                match next {
                    Some(n) => c = n,
                    None => return Ok(()),
                }
            }
        }),
        "cat" => with_fs(a(2)?, idx(3)?, &mut |fs| {
            let f = resolve(fs, a(4)?)?;
            let size = ok(fs.stat(f), "stat")?.size as usize;
            let mut b = vec![0u8; size];
            ok(fs.read(f, 0, &mut b), "read")?;
            std::io::stdout().write_all(&b).map_err(|e| e.to_string())
        }),
        "fsck" => {
            let disk = open(a(2)?, None)?;
            let (p, _) = part(&disk, idx(3)?)?;
            let mut d = Dfs::mount(Box::new(p)).map_err(|(e, _)| format!("dfs mount: {:?}", e))?;
            let r = ok(d.fsck(), "fsck")?;
            println!(
                "dfs fsck: generation {}, {} nodes, {} data blocks, {} files, {} dirs, {} errors{}",
                d.sb.generation,
                r.nodes,
                r.data_blocks,
                r.files,
                r.dirs,
                r.errors,
                r.first.map_or(String::new(), |(w, at)| format!(" (first: {} at {})", w, at))
            );
            if r.errors == 0 { Ok(()) } else { Err("errors found".into()) }
        }
        "extract" => {
            let disk = open(a(2)?, None)?;
            let (mut p, _) = part(&disk, idx(3)?)?;
            let mut out = File::create(a(4)?).map_err(|e| e.to_string())?;
            let mut buf = vec![0u8; 64 * SECTOR];
            let mut at = 0;
            while at < p.len {
                let n = (p.len - at).min(64);
                let b = &mut buf[..n as usize * SECTOR];
                ok(p.read(at, b), "read")?;
                out.write_all(b).map_err(|e| e.to_string())?;
                at += n;
            }
            Ok(())
        }
        other => Err(format!("unknown command '{}'", other)),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("dosimg: {}", e);
            ExitCode::FAILURE
        }
    }
}
