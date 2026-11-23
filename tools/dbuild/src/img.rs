//! Disk image, signing, verification, and attestation operations (in-process library and
//! `dbuild img <subcommand>` CLI). Uses the OS's own `dosfs` and `doscrypt` crates.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use dosfs::dev::{BlockDev, Part, SECTOR};
use dosfs::dfs::{Dfs, FormatOpts};
use dosfs::fat::{self, Fat};
use dosfs::gpt;
use dosfs::{FileSystem, Ino, Kind};

use crate::tools::{random_seed_32, to_hex};

pub const SECTOR_SIZE: u64 = 512;
pub const BOOT_IMAGE_MIB: u64 = 64;
pub const BIOS_PART_SECTORS: u64 = 8 * 2048;
pub const ESP_PART_SECTORS: u64 = 36 * 2048;
pub const STAGE2_LBA: u64 = 2048;
pub const STAGE2_SECTORS: u64 = 32;
pub const STAGE3_LBA: u64 = STAGE2_LBA + STAGE2_SECTORS;
pub const STAGE3_SECTORS: u64 = 64;
pub const KSIG_LBA: u64 = STAGE3_LBA + STAGE3_SECTORS;
pub const KERNEL_LBA: u64 = KSIG_LBA + 8;

/// The bytes the OS storage/shell tests check for.
const README: &[u8] = b"D-OS boot volume (FAT32). Written by dosimg on the host.\r\n";
const HOST_NOTE: &[u8] = b"Hello from the host: long file names work.\r\n";
const DFS_HELLO: &[u8] = b"Hello from DFS, written on the host.\n";

struct FileDev {
    f: File,
    sectors: u64,
}

impl BlockDev for FileDev {
    fn sectors(&self) -> u64 {
        self.sectors
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> dosfs::Result<()> {
        self.f
            .seek(SeekFrom::Start(lba * SECTOR as u64))
            .map_err(|_| dosfs::Error::Io)?;
        self.f.read_exact(buf).map_err(|_| dosfs::Error::Io)
    }
    fn write(&mut self, lba: u64, buf: &[u8]) -> dosfs::Result<()> {
        self.f
            .seek(SeekFrom::Start(lba * SECTOR as u64))
            .map_err(|_| dosfs::Error::Io)?;
        self.f.write_all(buf).map_err(|_| dosfs::Error::Io)
    }
    fn flush(&mut self) -> dosfs::Result<()> {
        self.f.flush().map_err(|_| dosfs::Error::Io)
    }
}

type Shared = std::rc::Rc<std::cell::RefCell<dyn BlockDev>>;

fn open(path: &Path, create_mib: Option<u64>) -> Result<Shared, String> {
    let f = match create_mib {
        Some(mib) => {
            let f = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(path)
                .map_err(|e| format!("{}: {e}", path.display()))?;
            f.set_len(mib << 20).map_err(|e| e.to_string())?;
            f
        }
        None => OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| format!("{}: {e}", path.display()))?,
    };
    let sectors = f.metadata().map_err(|e| e.to_string())?.len() / SECTOR as u64;
    Ok(std::rc::Rc::new(std::cell::RefCell::new(FileDev { f, sectors })))
}

fn part(disk: &Shared, index: usize) -> Result<(Part, gpt::Partition), String> {
    let (parts, _) = gpt::read(&mut *disk.borrow_mut()).map_err(|e| format!("no GPT: {e:?}"))?;
    let p = parts
        .into_iter()
        .find(|p| p.index == index)
        .ok_or_else(|| format!("no partition {index}"))?;
    Ok((Part { disk: disk.clone(), start: p.first, len: p.sectors() }, p))
}

fn ok<T>(r: dosfs::Result<T>, what: &str) -> Result<T, String> {
    r.map_err(|e| format!("{what}: {e:?}"))
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

fn read_file(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
}

fn read_seed(path: &Path) -> Result<doscrypt::ed25519::SigningKey, String> {
    let s = read_file(path)?;
    let seed: [u8; 32] = s
        .as_slice()
        .try_into()
        .map_err(|_| format!("{}: a signing key seed is 32 bytes", path.display()))?;
    Ok(doscrypt::ed25519::SigningKey::from_seed(&seed))
}

fn dsig_kind(s: &str) -> Result<u32, String> {
    use doscrypt::dsig::*;
    Ok(match s {
        "kernel" => KIND_KERNEL,
        "program" => KIND_PROGRAM,
        "driver" => KIND_DRIVER,
        "package" => KIND_PACKAGE,
        "manifest" => KIND_MANIFEST,
        "app" => KIND_APP,
        _ => {
            return Err(format!(
                "unknown signature kind '{s}' (kernel, program, driver, package, manifest, app)"
            ));
        }
    })
}

fn with_fs(
    img: &Path,
    index: usize,
    f: &mut dyn FnMut(&mut dyn FileSystem) -> Result<(), String>,
) -> Result<(), String> {
    let disk = open(img, None)?;
    let (p, info) = part(&disk, index)?;
    if info.type_guid == gpt::TYPE_DFS {
        let mut d = Dfs::mount(Box::new(p)).map_err(|(e, _)| format!("dfs mount: {e:?}"))?;
        f(&mut d)
    } else {
        let mut fat = ok(Fat::mount(p), "fat mount")?;
        f(&mut fat)
    }
}

pub fn from_hex(h: &str) -> Result<Vec<u8>, String> {
    let h = h.trim();
    if !h.len().is_multiple_of(2) {
        return Err("hex: odd length".into());
    }
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

pub fn pubkey_hex(seed_path: &Path) -> Result<String, String> {
    Ok(to_hex(&read_seed(seed_path)?.public()))
}

pub fn sign_file(
    seed_path: &Path,
    kind: &str,
    name: &str,
    input: &Path,
    output: &Path,
) -> Result<(), String> {
    let k = read_seed(seed_path)?;
    let content = read_file(input)?;
    let d = doscrypt::dsig::sign(&k, dsig_kind(kind)?, name, &content);
    std::fs::write(output, d).map_err(|e| format!("{}: {e}", output.display()))
}

/// Deterministically build and sign a `.dapp` v1 application bundle (outer `KIND_APP` + inner
/// `KIND_PROGRAM` binary signature).
pub fn build_dapp(
    seed_path: &Path,
    app_name: &str,
    manifest_path: &Path,
    binary_name: &str,
    binary_path: &Path,
    resources: &[(&str, &Path)],
    output: &Path,
) -> Result<(), String> {
    let key = read_seed(seed_path)?;
    let man_bytes = read_file(manifest_path)?;
    let bin_bytes = read_file(binary_path)?;
    let bin_sig = doscrypt::dsig::sign(&key, doscrypt::dsig::KIND_PROGRAM, binary_name, &bin_bytes);
    let bin_sig_name = format!("{binary_name}.dsig");
    let mut res_owned: Vec<(&str, Vec<u8>)> = Vec::with_capacity(resources.len());
    for &(rname, rpath) in resources {
        res_owned.push((rname, read_file(rpath)?));
    }
    let mut inputs = Vec::with_capacity(3 + res_owned.len());
    inputs.push(dosapp::BundleInput { kind: dosapp::ENTRY_MANIFEST, name: "manifest.dman", data: &man_bytes });
    inputs.push(dosapp::BundleInput { kind: dosapp::ENTRY_BINARY, name: binary_name, data: &bin_bytes });
    inputs.push(dosapp::BundleInput { kind: dosapp::ENTRY_BINARY_SIG, name: &bin_sig_name, data: &bin_sig });
    for (rname, rdata) in &res_owned {
        inputs.push(dosapp::BundleInput { kind: dosapp::ENTRY_RESOURCE, name: rname, data: rdata });
    }
    let bundle = dosapp::build_bundle(&key, app_name, &inputs)
        .map_err(|e| format!("build_dapp {app_name}: {e:?}"))?;
    std::fs::write(output, bundle).map_err(|e| format!("{}: {e}", output.display()))
}

pub fn make_sata(out: &Path) -> Result<(), String> {
    let disk = open(out, Some(64))?;
    let parts = [
        gpt::NewPart { type_guid: gpt::TYPE_ESP, name: "boot", sectors: 40 * 2048 },
        gpt::NewPart { type_guid: gpt::TYPE_DFS, name: "system", sectors: 0 },
    ];
    let made = ok(gpt::write(&mut *disk.borrow_mut(), &parts, *b"D-OS-SATA-DISK-0"), "gpt")?;
    let mut p = Part { disk: disk.clone(), start: made[0].first, len: made[0].sectors() };
    ok(
        fat::format(
            &mut p,
            &fat::Format { label: b"D-OS BOOT", serial: 0x0D05_2026, hidden: made[0].first as u32 },
        ),
        "fat format",
    )?;
    let mut f = ok(Fat::mount(p), "fat mount")?;
    put(&mut f, "README.TXT", README)?;
    put(&mut f, "Hello from the host.txt", HOST_NOTE)?;
    put(&mut f, "EFI/BOOT/NOTE.TXT", b"A UEFI loader goes here.\r\n")?;
    ok(f.sync(), "fat sync")?;
    let p = Part { disk: disk.clone(), start: made[1].first, len: made[1].sectors() };
    let mut d = ok(
        Dfs::format(Box::new(p), &FormatOpts { label: b"system", uuid: *b"D-OS-DFS-SYSTEM0", time: 0 }),
        "dfs format",
    )?;
    put(&mut d, "hello.txt", DFS_HELLO)?;
    mkdirs(&mut d, "apps")?;
    ok(d.sync(), "dfs sync")?;
    Ok(())
}

pub fn make_nvme(out: &Path) -> Result<(), String> {
    let disk = open(out, Some(32))?;
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
    let mut d = ok(
        Dfs::format(Box::new(p), &FormatOpts { label: b"data", uuid: *b"D-OS-DFS-DATA-00", time: 0 }),
        "dfs format",
    )?;
    put(&mut d, "hello.txt", DFS_HELLO)?;
    ok(d.sync(), "dfs sync")?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn make_boot(
    out: &Path,
    stage1: &Path,
    stage2: &Path,
    stage3: &Path,
    kernel: &Path,
    ksig: &Path,
    efi: &Path,
    extra: &[(String, std::path::PathBuf)],
    sys_files: &[(String, std::path::PathBuf)],
) -> Result<(), String> {
    let (s1, s2, s3) = (read_file(stage1)?, read_file(stage2)?, read_file(stage3)?);
    let (k, ks, e) = (read_file(kernel)?, read_file(ksig)?, read_file(efi)?);
    if s1.len() != SECTOR || s1[510] != 0x55 || s1[511] != 0xAA {
        return Err("stage 1 must be one boot sector".into());
    }
    for (what, b, max) in [("stage 2", &s2, STAGE2_SECTORS), ("stage 3", &s3, STAGE3_SECTORS)] {
        if b.len() as u64 > max * SECTOR as u64 {
            return Err(format!("{what} is {} bytes; at most {}", b.len(), max * SECTOR as u64));
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
        gpt::NewPart { type_guid: gpt::TYPE_ESP, name: "esp", sectors: ESP_PART_SECTORS },
        gpt::NewPart { type_guid: gpt::TYPE_DFS, name: "sys", sectors: 0 },
    ];
    let made = ok(gpt::write(&mut *disk.borrow_mut(), &parts, *b"D-OS-BOOT-DISK-0"), "gpt")?;
    if made[0].first != STAGE2_LBA {
        return Err("BIOS boot partition not at LBA 2048".into());
    }
    {
        let mut d = disk.borrow_mut();
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
        ok(d.write(STAGE3_LBA, &pad(&s3)), "stage 3")?;
        ok(d.write(KSIG_LBA, &pad(&ks)), "kernel signature")?;
        ok(d.write(KERNEL_LBA, &pad(&k)), "kernel")?;
    }
    let mut p = Part { disk: disk.clone(), start: made[1].first, len: made[1].sectors() };
    ok(
        fat::format(
            &mut p,
            &fat::Format { label: b"D-OS ESP", serial: 0x0D05_0013, hidden: made[1].first as u32 },
        ),
        "fat format",
    )?;
    let mut f = ok(Fat::mount(p), "fat mount")?;
    put(&mut f, "EFI/BOOT/BOOTX64.EFI", &e)?;
    put(&mut f, "DOS/KERNEL.BIN", &k)?;
    put(&mut f, "DOS/KERNEL.DSIG", &ks)?;
    put(
        &mut f,
        "DOS/README.TXT",
        b"D-OS boot files: the UEFI loader (\\EFI\\BOOT\\BOOTX64.EFI) loads \\DOS\\KERNEL.BIN after checking its signature (\\DOS\\KERNEL.DSIG).\r\n",
    )?;
    for (dst, src) in extra {
        put(&mut f, dst, &read_file(src)?)?;
    }
    ok(f.sync(), "fat sync")?;
    drop(f);
    let sp = Part { disk: disk.clone(), start: made[2].first, len: made[2].sectors() };
    let mut sys_fs = ok(
        Dfs::format(Box::new(sp), &FormatOpts { label: b"sys", uuid: *b"D-OS-DFS-SYS-000", time: 0 }),
        "sys dfs format",
    )?;
    for (dst, src) in sys_files {
        put(&mut sys_fs, dst, &read_file(src)?)?;
    }
    ok(sys_fs.sync(), "sys dfs sync")?;
    Ok(())
}

/// Write (create or replace) file `path` on partition `part_idx` of an image.
pub fn add_file(img: &Path, part_idx: usize, path: &str, data: &[u8]) -> Result<(), String> {
    with_fs(img, part_idx, &mut |fs| {
        if let Ok(f) = resolve(fs, path) {
            ok(fs.truncate(f, 0), path)?;
            ok(fs.write(f, 0, data), path)?;
        } else {
            put(fs, path, data)?;
        }
        ok(fs.sync(), "sync")
    })
}

pub fn patch_file(img: &Path, part_idx: usize, path: &str, off: usize, xor_byte: u8) -> Result<(), String> {
    with_fs(img, part_idx, &mut |fs| {
        let f = resolve(fs, path)?;
        let mut b = [0u8; 1];
        ok(fs.read(f, off as u64, &mut b), "read")?;
        b[0] ^= xor_byte;
        ok(fs.write(f, off as u64, &b), "write")?;
        ok(fs.sync(), "sync")
    })
}

pub fn attest_verify(
    report: &Path,
    nonce_hex: &str,
    kernel_dsig: &Path,
    pubkey_hex: &str,
    allow_unsigned: bool,
    require_tpm: bool,
    ek_ca_paths: &[&Path],
) -> Result<String, String> {
    let r = read_file(report)?;
    let nonce: [u8; 32] = from_hex(nonce_hex)?
        .try_into()
        .map_err(|_| "nonce: 32 bytes".to_string())?;
    let kd = read_file(kernel_dsig)?;
    let key: [u8; 32] = from_hex(pubkey_hex)?
        .try_into()
        .map_err(|_| "public key: 32 bytes".to_string())?;
    let mut cas = Vec::new();
    for p in ek_ca_paths {
        cas.push(read_file(p)?);
    }
    let issuers: Vec<&[u8]> = cas.iter().map(|c| c.as_slice()).collect();
    let p = doscrypt::attest::Policy {
        kernel_dsig: &kd,
        key: &key,
        allow_unsigned,
        require_tpm,
        ek_issuers: &issuers,
    };
    match doscrypt::attest::verify(&r, &nonce, &p) {
        Ok(v) => {
            let ver = String::from_utf8_lossy(&v.kernel_version)
                .trim_end_matches('\0')
                .to_string();
            let tpm = match v.tpm {
                doscrypt::attest::TpmStatus::Certified => {
                    "TPM quote verified, EK certified by a trusted TPM vendor CA"
                }
                doscrypt::attest::TpmStatus::Quoted => {
                    "TPM quote verified (EK certificate not checked: no ek-ca given)"
                }
                doscrypt::attest::TpmStatus::None if v.flags & doscrypt::attest::F_TPM != 0 => {
                    "TPM present, PCRs NOT equal to the log: no TPM evidence"
                }
                doscrypt::attest::TpmStatus::None => {
                    "no TPM (software evidence: rooted in the verified kernel)"
                }
            };
            Ok(format!(
                "attest: VALID: D-KRNL {} ({}), the reference kernel, verified by its loader; {} events replayed to PCR 8 and 10; {} signed program(s), {} unsigned; {} service decision(s); attestation key {}; {}",
                ver,
                if v.firmware == 2 { "UEFI" } else { "BIOS" },
                v.events,
                v.signed_code,
                v.unsigned_code,
                v.decisions,
                to_hex(&v.ak[..8]),
                tpm
            ))
        }
        Err(e) => Err(format!("attest: REFUSED: {e:?}")),
    }
}

pub fn attest_challenge(report: &Path, out_path: &Path) -> Result<String, String> {
    let r = read_file(report)?;
    let cred = random_seed_32();
    let (blob, secret) = doscrypt::attest::challenge(&r, &cred, &random_seed_32(), &random_seed_32())
        .ok_or_else(|| "attest-challenge: the report has no TPM evidence".to_string())?;
    let mut out = blob.to_vec();
    out.extend_from_slice(&secret);
    std::fs::write(out_path, &out).map_err(|e| format!("{}: {e}", out_path.display()))?;
    Ok(to_hex(&cred))
}

pub fn attest_test_ca(out_path: &Path) -> Result<(), String> {
    std::fs::write(out_path, doscrypt::testkeys::CA_CERT)
        .map_err(|e| format!("{}: {e}", out_path.display()))
}

pub fn fsck_dfs(img: &Path, part_idx: usize) -> Result<String, String> {
    let disk = open(img, None)?;
    let (p, _) = part(&disk, part_idx)?;
    let mut d = Dfs::mount(Box::new(p)).map_err(|(e, _)| format!("dfs mount: {e:?}"))?;
    let r = ok(d.fsck(), "fsck")?;
    let msg = format!(
        "dfs fsck: generation {}, {} nodes, {} data blocks, {} files, {} dirs, {} errors{}",
        d.sb.generation,
        r.nodes,
        r.data_blocks,
        r.files,
        r.dirs,
        r.errors,
        r.first
            .map_or(String::new(), |(w, at)| format!(" (first: {w} at {at})"))
    );
    if r.errors == 0 { Ok(msg) } else { Err(msg) }
}

pub fn extract_part(img: &Path, part_idx: usize, out_path: &Path) -> Result<(), String> {
    let disk = open(img, None)?;
    let (mut p, _) = part(&disk, part_idx)?;
    let mut out = File::create(out_path).map_err(|e| format!("{}: {e}", out_path.display()))?;
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

pub fn cli(args: &[String]) -> Result<(), String> {
    let a = |i: usize| -> Result<&str, String> {
        args.get(i)
            .map(String::as_str)
            .ok_or_else(|| "missing argument (run `dbuild img help` for usage)".to_string())
    };
    let idx = |i: usize| -> Result<usize, String> { a(i)?.parse::<usize>().map_err(|e| e.to_string()) };
    if args.is_empty() || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
        println!(
            "dbuild img <command> [args...]\n\
             \n\
             Commands:\n\
               boot <out.img> <stage1> <stage2> <stage3> <kernel.bin> <kernel.dsig> <BOOTX64.EFI> [esp-path=host ...]\n\
               pubkey <seed>\n\
               sign <seed> <kind> <name> <file> <out.dsig>\n\
               verify <seed> <file> <dsig>\n\
               sha256 | sha512 <file>\n\
               attest-verify <report> <nonce-hex> <kernel.dsig> <pubkey-hex> [allow-unsigned] [require-tpm] [ek-ca=<der>]\n\
               attest-challenge <report> <out.bin>\n\
               attest-test-ca <out.der>\n\
               patch <img> <part> <path> <offset> <xor-hex>\n\
               sata <out.img>\n\
               nvme <out.img>\n\
               ls <img> <part> [dir]\n\
               cat <img> <part> <path>\n\
               fsck <img> <part>\n\
               extract <img> <part> <out>"
        );
        return Ok(());
    }
    match a(0)? {
        "boot" => {
            let mut extra = Vec::new();
            for x in args.get(8..).unwrap_or(&[]) {
                let (dst, src) = x
                    .split_once('=')
                    .ok_or_else(|| format!("extra file '{x}': expected ESP-path=host-path"))?;
                extra.push((dst.to_string(), std::path::PathBuf::from(src)));
            }
            make_boot(
                Path::new(a(1)?),
                Path::new(a(2)?),
                Path::new(a(3)?),
                Path::new(a(4)?),
                Path::new(a(5)?),
                Path::new(a(6)?),
                Path::new(a(7)?),
                &extra,
                &[],
            )
        }
        "pubkey" => {
            println!("{}", pubkey_hex(Path::new(a(1)?))?);
            Ok(())
        }
        "sign" => sign_file(
            Path::new(a(1)?),
            a(2)?,
            a(3)?,
            Path::new(a(4)?),
            Path::new(a(5)?),
        ),
        "verify" => {
            let k = read_seed(Path::new(a(1)?))?;
            let content = read_file(Path::new(a(2)?))?;
            let d = read_file(Path::new(a(3)?))?;
            match doscrypt::dsig::verify(&d, &k.public(), &content) {
                Ok(h) => {
                    println!(
                        "dsig: valid ({} '{}', {} bytes, key {})",
                        h.kind,
                        h.name_str(),
                        h.size,
                        to_hex(&h.key_id[..8])
                    );
                    Ok(())
                }
                Err(e) => Err(format!("dsig: {e:?}")),
            }
        }
        "patch" => {
            let off = idx(4)?;
            let x = u8::from_str_radix(a(5)?.trim_start_matches("0x"), 16)
                .map_err(|e| e.to_string())?;
            patch_file(Path::new(a(1)?), idx(2)?, a(3)?, off, x)
        }
        "attest-verify" => {
            let opts = args.get(5..).unwrap_or(&[]);
            let allow_unsigned = opts.iter().any(|x| x == "allow-unsigned");
            let require_tpm = opts.iter().any(|x| x == "require-tpm");
            let mut cas = Vec::new();
            for o in opts {
                if let Some(p) = o.strip_prefix("ek-ca=") {
                    cas.push(Path::new(p));
                } else if o != "allow-unsigned" && o != "require-tpm" {
                    return Err(format!("attest-verify: unknown option {o}"));
                }
            }
            let msg = attest_verify(
                Path::new(a(1)?),
                a(2)?,
                Path::new(a(3)?),
                a(4)?,
                allow_unsigned,
                require_tpm,
                &cas,
            )?;
            println!("{msg}");
            Ok(())
        }
        "attest-challenge" => {
            println!("{}", attest_challenge(Path::new(a(1)?), Path::new(a(2)?))?);
            Ok(())
        }
        "attest-test-ca" => attest_test_ca(Path::new(a(1)?)),
        "sha512" => {
            println!("{}", to_hex(&doscrypt::sha2::sha512(&read_file(Path::new(a(1)?))?)));
            Ok(())
        }
        "sha256" => {
            println!("{}", to_hex(&doscrypt::sha2::sha256(&read_file(Path::new(a(1)?))?)));
            Ok(())
        }
        "sata" => make_sata(Path::new(a(1)?)),
        "nvme" => make_nvme(Path::new(a(1)?)),
        "ls" => with_fs(Path::new(a(1)?), idx(2)?, &mut |fs| {
            let dir = resolve(fs, args.get(3).map_or("", String::as_str))?;
            let mut c = 0;
            loop {
                let (es, next) = ok(fs.readdir(dir, c, 64), "readdir")?;
                for e in es {
                    println!(
                        "{} {}",
                        if e.kind == Kind::Dir { "d" } else { "-" },
                        String::from_utf8_lossy(&e.name)
                    );
                }
                match next {
                    Some(n) => c = n,
                    None => return Ok(()),
                }
            }
        }),
        "cat" => with_fs(Path::new(a(1)?), idx(2)?, &mut |fs| {
            let f = resolve(fs, a(3)?)?;
            let size = ok(fs.stat(f), "stat")?.size as usize;
            let mut b = vec![0u8; size];
            ok(fs.read(f, 0, &mut b), "read")?;
            std::io::stdout().write_all(&b).map_err(|e| e.to_string())
        }),
        "fsck" => {
            println!("{}", fsck_dfs(Path::new(a(1)?), idx(2)?)?);
            Ok(())
        }
        "extract" => extract_part(Path::new(a(1)?), idx(2)?, Path::new(a(3)?)),
        other => Err(format!("unknown img command '{other}'")),
    }
}
