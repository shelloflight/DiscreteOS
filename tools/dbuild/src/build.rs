//! OS build pipeline: kernel (C + NASM + Rust), user space (C + Rust workspace),
//! D-CMPL foreign test binaries (W1/W2/L1/L2), BIOS/UEFI bootloaders, signing, and disk image.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::img::{self, KERNEL_LBA, KSIG_LBA, SECTOR_SIZE, STAGE2_LBA, STAGE2_SECTORS, STAGE3_LBA, STAGE3_SECTORS};
use crate::tools::{
    Env, collect_files, hash_strings, mtime_of, needs_rebuild, newest_mtime, run_capture, run_cmd,
    sha256_file, write_stamp,
};
use crate::vendor::build_vendor_libs;

#[derive(Clone, Debug)]
pub struct ProgramEntry {
    pub name: String,
    pub path: PathBuf,
}

#[derive(Clone, Debug)]
pub struct SharedArtifacts {
    pub user_programs: Vec<ProgramEntry>,
    pub has_w2: bool,
    pub stage3_bin: PathBuf,
    pub efi_bin: PathBuf,
    pub hello_dsig: PathBuf,
    pub sys_files: Vec<(String, PathBuf)>,
    pub kernel_asm_objs: Vec<PathBuf>,
}

/// Programs that stay embedded in `kernel.bin` to bootstrap storage and early input.
/// PCI GPU `.ddrv` drivers live signed on `sys:/bin/` (with firmware on `sys:/firmware/`),
/// keeping `kernel.bin` small while `platform:display` (UEFI GOP) serves early boot.
const BOOTSTRAP_PROGS: &[&str] = &[
    "init.dx",
    "clock.dx",
    "storaged.dx",
    "devmgr.dx",
    "ahci.ddrv",
    "nvme.ddrv",
    "virtio-blk.ddrv",
    "xhci.ddrv",
    "ps2.ddrv",
    "virtio-input.ddrv",
    "hda.ddrv",
    "virtio-snd.ddrv",
    "usbaudio.ddrv",
    "virtio-net.ddrv",
    "e1000e.ddrv",
    "r8169.ddrv",
];

/// Service manifests that stay embedded in `kernel.bin` to mount `sys:`.
const BOOTSTRAP_MANIFESTS: &[&str] = &["clock.dman", "storaged.dman", "devmgr.dman"];

/// Non-bootstrap programs and PCI GPU drivers placed (with `.dsig` signatures) on `sys:/bin/`.
const SYS_BIN_PROGS: &[&str] = &[
    "virtio-gpu.ddrv",
    "amdgpu.ddrv",
    "xe.ddrv",
    "nvgpu.ddrv",
    "audio.dsvc",
    "net.dsvc",
    "gpu.dsvc",
    "awmi.dsvc",
    "awmi-demo.dsvc",
    "identity.dsvc",
    "appmgr.dsvc",
    "log.dx",
    "terminal.dx",
    "shell.dx",
    "dcmpl.dx",
    "hello.dx",
    "list.dx",
    "show.dx",
    "copy.dx",
    "move.dx",
    "delete.dx",
    "make.dx",
    "create.dx",
];

/// Core native `.dapp` application bundles `(app_name, binary_name)` packaged onto `sys:/apps/`.
const CORE_DAPPS: &[(&str, &str)] = &[
    ("terminal", "console.dx"),
    ("files", "files.dx"),
    ("editor", "editor.dx"),
    ("settings", "settings.dx"),
    ("sysmon", "sysmon.dx"),
    ("oobe", "oobe.dx"),
];

fn extra_embedded_for_test(ktest: Option<&str>, name: &str) -> bool {
    match ktest {
        Some("USER" | "SPEC" | "PROFILE" | "FUZZ" | "ATTEST" | "ATTESTTPM" | "SMAP" | "SMEP" | "CETUSER") => {
            name == "utest.dx"
        }
        Some("COMPAT") => matches!(
            name,
            "utest.dx"
                | "dcmpl.dx"
                | "w1.exe"
                | "w1_32.exe"
                | "w1fault.exe"
                | "w1bad.exe"
                | "l1"
                | "w2.exe"
                | "l2"
                | "w3.exe"
                | "w3lib.dll"
                | "l3"
                | "libl3.so"
                | "ld-linux-x86-64.so.2"
        ),
        Some("LIBD") => matches!(name, "ltest.dx" | "ctest.dx"),
        Some("SERVICES" | "TIME" | "AUDIO" | "NET" | "GPU" | "AWMI" | "IDENTITY" | "APP") => name == "ltest.dx",
        Some("STORAGE" | "READONLY") => name == "fstest.dx",
        Some("HWBENCH") => matches!(name, "utest.dx" | "fstest.dx"),
        _ => false,
    }
}

fn build_sys_files(
    env: &Env,
    out_dir: &Path,
    seed: &Path,
    user_programs: &[ProgramEntry],
) -> Result<Vec<(String, PathBuf)>, String> {
    let sig_dir = out_dir.join("sys-sigs");
    fs::create_dir_all(&sig_dir).map_err(|e| format!("mkdir {}: {e}", sig_dir.display()))?;
    let mut files: Vec<(String, PathBuf)> = Vec::new();

    for &name in SYS_BIN_PROGS {
        let p = user_programs
            .iter()
            .find(|e| e.name == name)
            .ok_or_else(|| format!("sys image: missing program '{name}'"))?;
        let sig = sig_dir.join(format!("{name}.dsig"));
        let sig_kind = if name.ends_with(".ddrv") { "driver" } else { "program" };
        img::sign_file(seed, sig_kind, name, &p.path, &sig)?;
        files.push((format!("bin/{name}"), p.path.clone()));
        files.push((format!("bin/{name}.dsig"), sig));
    }

    // Vendor GPU firmware blobs & manifests (`vendor/firmware/<vendor>/*` -> `sys:/firmware/<vendor>/*`).
    let fw_root = env.root.join("vendor").join("firmware");
    if fw_root.is_dir() {
        let mut vendor_dirs: Vec<PathBuf> = fs::read_dir(&fw_root)
            .map_err(|e| format!("read {}: {e}", fw_root.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_dir())
            .collect();
        vendor_dirs.sort();
        for vdir in vendor_dirs {
            let Some(vname) = vdir.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let mut entries: Vec<PathBuf> = fs::read_dir(&vdir)
                .map_err(|e| format!("read {}: {e}", vdir.display()))?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.is_file())
                .collect();
            entries.sort();
            for f in entries {
                if let Some(fname) = f.file_name().and_then(|n| n.to_str()) {
                    files.push((format!("firmware/{vname}/{fname}"), f));
                }
            }
        }
    }

    let man_dir = env.root.join("user").join("init").join("services");
    for m in collect_files(&man_dir, "dman", false) {
        let fname = m.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
        if BOOTSTRAP_MANIFESTS.contains(&fname.as_str()) {
            continue;
        }
        let stem = fname.strip_suffix(".dman").unwrap_or(&fname);
        let sig = sig_dir.join(format!("svc_{stem}.dsig"));
        img::sign_file(seed, "manifest", &fname, &m, &sig)?;
        let dst = format!("services/{fname}");
        let sig_dst = format!("services/{stem}.dsig");
        files.push((dst, m));
        files.push((sig_dst, sig));
    }

    let tool_dir = env.root.join("user").join("tools").join("manifests");
    for m in collect_files(&tool_dir, "dman", false) {
        let fname = m.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
        let stem = fname.strip_suffix(".dman").unwrap_or(&fname);
        let sig = sig_dir.join(format!("tool_{stem}.dsig"));
        img::sign_file(seed, "manifest", &fname, &m, &sig)?;
        let dst = format!("tools/{fname}");
        let sig_dst = format!("tools/{stem}.dsig");
        files.push((dst, m));
        files.push((sig_dst, sig));
    }

    // The shipped faces (`sys:/fonts`, with their licences) and themes (`sys:/themes`): the
    // compositor reads them and shares the fonts with window programs (docs/ui.md).
    for (sub, exts) in [("fonts", &["ttf", "txt"][..]), ("themes", &["toml"][..])] {
        let dir = env.root.join("user").join("init").join(sub);
        for ext in exts {
            for f in collect_files(&dir, ext, false) {
                let name = f.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
                files.push((format!("{sub}/{name}"), f));
            }
        }
    }

    // Core native `.dapp` signed bundles (`sys:/apps/<name>.dapp`).
    let apps_man_dir = env.root.join("user").join("apps").join("manifests");
    let apps_about = env.root.join("user").join("apps").join("res").join("about.txt");
    for &(app_name, bin_name) in CORE_DAPPS {
        let p = user_programs
            .iter()
            .find(|e| e.name == bin_name)
            .ok_or_else(|| format!("sys image: missing app binary '{bin_name}'"))?;
        let man_path = apps_man_dir.join(format!("{app_name}.dman"));
        let dapp_out = sig_dir.join(format!("{app_name}.dapp"));
        img::build_dapp(
            seed,
            app_name,
            &man_path,
            bin_name,
            &p.path,
            &[("res/about.txt", apps_about.as_path())],
            &dapp_out,
        )?;
        files.push((format!("apps/{app_name}.dapp"), dapp_out));
    }

    // Compile the curated in-tree public TLS root CA bundle into compact binary DER (`sys:/certs/roots.der`).
    let roots_pem = env.root.join("user").join("init").join("certs").join("roots.pem");
    if roots_pem.is_file() {
        let pem = fs::read(&roots_pem).map_err(|e| format!("read {}: {e}", roots_pem.display()))?;
        let ders = dosnet::roots::parse_pem_bundle(&pem);
        if ders.is_empty() {
            return Err(format!("{} contained no valid certificates", roots_pem.display()));
        }
        let refs: Vec<&[u8]> = ders.iter().map(Vec::as_slice).collect();
        let bundle = dosnet::roots::encode_der_bundle(&refs);
        let roots_der = sig_dir.join("roots.der");
        write_if_changed(&roots_der, &bundle)?;
        files.push(("certs/roots.der".to_string(), roots_der));
    }

    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

#[derive(Clone, Debug)]
pub struct BuildOpts {
    pub out_dir: PathBuf,
    pub kernel_test: Option<String>,
    pub ubsan: bool,
    pub kasan: bool,
    pub quiet: bool,
    /// When set (e.g. for parallel KTEST variant builds), reuse the prebuilt userland,
    /// compat binaries, bootloaders, and kernel NASM objects. Always None for release & repro.
    pub shared: Option<Arc<SharedArtifacts>>,
    /// Max parallel C compile jobs within this single build invocation.
    pub jobs: usize,
}

pub struct BuildResult {
    pub image: PathBuf,
    pub iso: Option<PathBuf>,
}

fn log(quiet: bool, msg: &str) {
    if !quiet {
        println!("{msg}");
    }
}

fn write_if_changed(path: &Path, content: &[u8]) -> Result<(), String> {
    if let Ok(existing) = fs::read(path)
        && existing == content
    {
        return Ok(());
    }
    fs::write(path, content).map_err(|e| format!("write {}: {e}", path.display()))
}

fn write_trust_c(path: &Path, pubkey_hex: &str) -> Result<(), String> {
    let mut bytes = Vec::with_capacity(32);
    for i in (0..64).step_by(2) {
        bytes.push(format!("0x{}", &pubkey_hex[i..i + 2]));
    }
    let text = format!(
        "/* generated by dbuild: the D-OS signing key this build trusts (Ed25519 public key) */\n\
         #include <stdint.h>\n\
         const uint8_t dos_trusted_key[32] = {{ {} }};\n",
        bytes.join(", ")
    );
    write_if_changed(path, text.as_bytes())
}

fn prefix_map_flags(root: &Path) -> Vec<String> {
    let raw = root.to_string_lossy();
    let fwd = raw.replace('\\', "/");
    let mut flags = vec![format!("-ffile-prefix-map={fwd}/=")];
    if cfg!(windows) {
        let back = raw.replace('/', "\\");
        flags.push(format!("-ffile-prefix-map={back}\\="));
    }
    flags
}

fn encoded_rustflags(root: &Path, extra: &[&str]) -> String {
    let raw = root.to_string_lossy();
    let fwd = raw.replace('\\', "/");
    let mut parts: Vec<String> = extra.iter().map(|s| (*s).to_string()).collect();
    parts.push(format!("--remap-path-prefix={fwd}/="));
    if cfg!(windows) {
        let back = raw.replace('/', "\\");
        parts.push(format!("--remap-path-prefix={back}\\="));
    }
    parts.join("\x1f")
}

/// Build the variant-independent artifacts once (used to speed up parallel KTEST variant builds).
pub fn build_shared(env: &Env, out_dir: &Path, quiet: bool) -> Result<SharedArtifacts, String> {
    let obj_dir = out_dir.join("obj");
    fs::create_dir_all(&obj_dir).map_err(|e| format!("mkdir {}: {e}", obj_dir.display()))?;
    let key = env.signing_key()?;
    let trust_c = obj_dir.join("trust.c");
    write_trust_c(&trust_c, &key.public)?;

    let kernel_asm_objs = build_kernel_asm(env, &obj_dir, quiet)?;
    let (user_programs, has_w2) = build_user_all(env, out_dir, quiet)?;
    let stage3_bin = build_stage3(env, out_dir, &trust_c, quiet)?;
    let efi_bin = build_uefi(env, out_dir, &trust_c, quiet)?;

    let hello = user_programs
        .iter()
        .find(|p| p.name == "hello.dx")
        .ok_or_else(|| "hello.dx missing from user build".to_string())?;
    let hello_dsig = out_dir.join("hello.dsig");
    img::sign_file(&key.seed, "program", "hello.dx", &hello.path, &hello_dsig)?;
    let sys_files = build_sys_files(env, out_dir, &key.seed, &user_programs)?;

    Ok(SharedArtifacts {
        user_programs,
        has_w2,
        stage3_bin,
        efi_bin,
        hello_dsig,
        sys_files,
        kernel_asm_objs,
    })
}

pub fn build_image(env: &Env, opts: &BuildOpts) -> Result<BuildResult, String> {
    let out_dir = &opts.out_dir;
    let obj_dir = out_dir.join("obj");
    fs::create_dir_all(&obj_dir).map_err(|e| format!("mkdir {}: {e}", obj_dir.display()))?;

    let clang = env.clang()?;
    let clang_inc = env.clang_resource_include()?;
    let lld = env.lld()?;
    let objcopy = env.objcopy()?;
    let nasm = env.nasm()?;
    let nm = env.nm()?;
    let key = env.signing_key()?;

    // --- Kernel C flags -------------------------------------------------------
    let mut cflags: Vec<String> = vec![
        "--target=x86_64-elf".into(),
        "-std=c17".into(),
        "-O2".into(),
        "-g".into(),
        "-ffreestanding".into(),
        "-fno-builtin".into(),
        "-nostdinc".into(),
        "-isystem".into(),
        clang_inc.to_string_lossy().into_owned(),
        "-fpie".into(),
        "-fno-omit-frame-pointer".into(),
        "-mno-red-zone".into(),
        "-mno-mmx".into(),
        "-mno-sse".into(),
        "-mno-sse2".into(),
        "-mno-80387".into(),
        "-fstack-protector-strong".into(),
        "-mstack-protector-guard=global".into(),
        "-ftrivial-auto-var-init=zero".into(),
        "-fzero-call-used-regs=used-gpr".into(),
        "-fno-common".into(),
        "-Xclang".into(),
        "-fstack-clash-protection".into(),
        "-fno-delete-null-pointer-checks".into(),
        "-fstrict-flex-arrays=3".into(),
        "-fsanitize=array-bounds".into(),
        "-fsanitize-trap=array-bounds".into(),
        "-Wframe-larger-than=4096".into(),
        "-mretpoline-external-thunk".into(),
    ];
    cflags.extend(prefix_map_flags(&env.root));
    cflags.extend([
        "-Wall".into(),
        "-Wextra".into(),
        "-Werror".into(),
        "-Wshadow".into(),
        "-Wstrict-prototypes".into(),
        "-Wmissing-prototypes".into(),
        "-Wvla".into(),
        "-I".into(),
        env.root.join("kernel").join("include").to_string_lossy().into_owned(),
    ]);
    if let Some(kt) = &opts.kernel_test {
        cflags.push("-DKTEST".into());
        cflags.push(format!("-DKTEST_{kt}"));
    }
    if opts.ubsan {
        cflags.extend([
            "-fsanitize=undefined".into(),
            "-fsanitize-trap=undefined".into(),
            "-fno-sanitize=function".into(),
            "-DKTEST_UBSAN".into(),
        ]);
    }
    let mut kasan_flags: Vec<String> = Vec::new();
    if opts.kasan {
        cflags.push("-DKTEST_KASAN".into());
        kasan_flags = vec![
            "-fsanitize=kernel-address".into(),
            "-mllvm".into(),
            "-asan-instrumentation-with-call-threshold=0".into(),
            "-mllvm".into(),
            "-asan-globals=0".into(),
            "-mllvm".into(),
            "-asan-stack=0".into(),
            "-mllvm".into(),
            "-asan-use-after-return=never".into(),
        ];
    }

    // --- Kernel NASM objects --------------------------------------------------
    let mut objects: Vec<PathBuf> = match &opts.shared {
        Some(s) => s.kernel_asm_objs.clone(),
        None => build_kernel_asm(env, &obj_dir, opts.quiet)?,
    };

    // --- Verified boot public key object --------------------------------------
    let trust_c = obj_dir.join("trust.c");
    write_trust_c(&trust_c, &key.public)?;
    let trust_obj = obj_dir.join("trust.o");
    let trust_stamp = hash_strings(&cflags);
    if needs_rebuild(&trust_obj, mtime_of(&trust_c), &trust_stamp) {
        let mut args = cflags.clone();
        args.extend([
            "-c".into(),
            "-o".into(),
            trust_obj.to_string_lossy().into_owned(),
            trust_c.to_string_lossy().into_owned(),
        ]);
        run_cmd(clang, &args, None, &[], opts.quiet)?;
        write_stamp(&trust_obj, &trust_stamp);
    }
    objects.push(trust_obj);

    // --- Kernel C files (incremental + parallel) ------------------------------
    let kernel_src = env.root.join("kernel");
    let headers = collect_files(&kernel_src.join("include"), "h", true);
    let newest_hdr = newest_mtime(&headers);
    let c_files = collect_files(&kernel_src, "c", true);
    let kasan_skip = ["heap.c", "string.c", "kasan.c"];

    struct CJob {
        src: PathBuf,
        obj: PathBuf,
        extra: Vec<String>,
        stamp: String,
    }
    let mut c_jobs = Vec::with_capacity(c_files.len());
    for src in c_files {
        let rel = env.rel(&src);
        let obj = obj_dir.join(format!("{}.o", rel.replace('/', "_")));
        let name = src.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let extra = if opts.kasan && !kasan_skip.contains(&name) {
            kasan_flags.clone()
        } else {
            Vec::new()
        };
        let mut key_parts = cflags.clone();
        key_parts.extend(extra.iter().cloned());
        let stamp = hash_strings(&key_parts);
        let input_mtime = [mtime_of(&src), newest_hdr].into_iter().flatten().max();
        if needs_rebuild(&obj, input_mtime, &stamp) {
            c_jobs.push(CJob { src, obj: obj.clone(), extra, stamp });
        }
        objects.push(obj);
    }

    if !c_jobs.is_empty() {
        let workers = opts.jobs.max(1).min(c_jobs.len());
        let next_idx = std::sync::atomic::AtomicUsize::new(0);
        let first_err: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
        std::thread::scope(|s| {
            for _ in 0..workers {
                s.spawn(|| loop {
                    if first_err.lock().unwrap().is_some() {
                        break;
                    }
                    let i = next_idx.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if i >= c_jobs.len() {
                        break;
                    }
                    let job = &c_jobs[i];
                    log(opts.quiet, &format!("  CC    {}", env.rel(&job.src)));
                    let mut args = cflags.clone();
                    args.extend(job.extra.iter().cloned());
                    args.extend([
                        "-c".into(),
                        "-o".into(),
                        job.obj.to_string_lossy().into_owned(),
                        job.src.to_string_lossy().into_owned(),
                    ]);
                    if let Err(e) = run_cmd(clang, &args, None, &[], opts.quiet) {
                        let mut g = first_err.lock().unwrap();
                        if g.is_none() {
                            *g = Some(e);
                        }
                        break;
                    }
                    write_stamp(&job.obj, &job.stamp);
                });
            }
        });
        if let Some(e) = first_err.into_inner().unwrap() {
            return Err(e);
        }
    }

    // --- Kernel Rust (dkrnl) --------------------------------------------------
    log(opts.quiet, "  CARGO kernel/rust (dkrnl)");
    let rust_lib = build_kernel_rust(env, out_dir, opts.kernel_test.as_deref(), opts.quiet)?;

    // --- User programs & manifests --------------------------------------------
    let (all_programs, _has_w2) = match &opts.shared {
        Some(s) => (s.user_programs.clone(), s.has_w2),
        None => build_user_all(env, out_dir, opts.quiet)?,
    };

    // Only the minimal bootstrap chain (and test-specific binaries for KTEST_* builds) is embedded
    // in kernel.bin; everything else lives signed on the immutable `sys` DFS volume.
    let mut embedded: Vec<ProgramEntry> = all_programs
        .iter()
        .filter(|p| {
            BOOTSTRAP_PROGS.contains(&p.name.as_str())
                || extra_embedded_for_test(opts.kernel_test.as_deref(), &p.name)
        })
        .cloned()
        .collect();

    let man_dir = env.root.join("user").join("init").join("services");
    let mut manifests: Vec<PathBuf> = collect_files(&man_dir, "dman", false)
        .into_iter()
        .filter(|m| {
            let name = m.file_name().and_then(|n| n.to_str()).unwrap_or("");
            BOOTSTRAP_MANIFESTS.contains(&name)
        })
        .collect();
    if let Some(sub) = match opts.kernel_test.as_deref() {
        Some("SERVICES") => Some("test"),
        Some("TIME") => Some("time"),
        Some("AUDIO") => Some("audio"),
        Some("NET") => Some("net"),
        Some("GPU") => Some("gpu"),
        Some("AWMI") => Some("awmi"),
        Some("IDENTITY") => Some("identity"),
        Some("APP") => Some("app"),
        _ => None,
    } {
        manifests.extend(collect_files(&man_dir.join(sub), "dman", false));
    }
    for m in manifests {
        let name = m
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| format!("bad manifest path {}", m.display()))?
            .to_string();
        embedded.push(ProgramEntry { name, path: m });
    }

    let prog_asm = obj_dir.join("programs.asm");
    let prog_obj = obj_dir.join("programs.o");
    write_programs_asm(&prog_asm, &embedded)?;
    let newest_prog = embedded
        .iter()
        .filter_map(|p| mtime_of(&p.path))
        .chain(mtime_of(&prog_asm))
        .max();
    if needs_rebuild(&prog_obj, newest_prog, "programs") {
        run_cmd(
            nasm,
            &[
                "-f".into(),
                "elf64".into(),
                "-o".into(),
                prog_obj.to_string_lossy().into_owned(),
                prog_asm.to_string_lossy().into_owned(),
            ],
            None,
            &[],
            opts.quiet,
        )?;
        write_stamp(&prog_obj, "programs");
    }
    objects.push(prog_obj);

    // --- Two-pass kernel link (embed ksyms table) -----------------------------
    let kernel_elf = out_dir.join("kernel.elf");
    let kernel_bin = out_dir.join("kernel.bin");
    let ksyms_bin = obj_dir.join("ksyms.bin");
    let ksyms_asm = obj_dir.join("ksyms.asm");
    let ksyms_obj = obj_dir.join("ksyms.o");

    let link_base: Vec<String> = vec![
        "-T".into(),
        env.root.join("kernel").join("linker.ld").to_string_lossy().into_owned(),
        "-nostdlib".into(),
        "-pie".into(),
        "--no-dynamic-linker".into(),
        "-z".into(),
        "pack-relative-relocs".into(),
        "-z".into(),
        "text".into(),
        "-z".into(),
        "noexecstack".into(),
        "--build-id=none".into(),
        "-z".into(),
        "max-page-size=0x1000".into(),
        "--gc-sections".into(),
        "-Map".into(),
        out_dir.join("kernel.map").to_string_lossy().into_owned(),
        "-o".into(),
        kernel_elf.to_string_lossy().into_owned(),
    ];

    let ksyms_asm_text = format!(
        "section .ksyms progbits alloc noexec nowrite align=8\nincbin \"{}\"\n",
        ksyms_bin.to_string_lossy().replace('\\', "/")
    );
    write_if_changed(&ksyms_asm, ksyms_asm_text.as_bytes())?;

    let link_once = |blob: &[u8]| -> Result<(), String> {
        fs::write(&ksyms_bin, blob).map_err(|e| format!("write ksyms.bin: {e}"))?;
        run_cmd(
            nasm,
            &[
                "-f".into(),
                "elf64".into(),
                "-o".into(),
                ksyms_obj.to_string_lossy().into_owned(),
                ksyms_asm.to_string_lossy().into_owned(),
            ],
            None,
            &[],
            opts.quiet,
        )?;
        let mut args = link_base.clone();
        args.extend(objects.iter().map(|o| o.to_string_lossy().into_owned()));
        args.push(ksyms_obj.to_string_lossy().into_owned());
        args.push(rust_lib.to_string_lossy().into_owned());
        run_cmd(lld, &args, None, &[], opts.quiet)
    };

    log(opts.quiet, "  LD    kernel.elf (pass 1)");
    link_once(&build_ksyms_blob(&[]))?;
    let blob = build_ksyms_blob(&extract_kernel_symbols(nm, &kernel_elf)?);
    log(opts.quiet, "  LD    kernel.elf (pass 2, with symbol table)");
    link_once(&blob)?;
    let check = build_ksyms_blob(&extract_kernel_symbols(nm, &kernel_elf)?);
    if check != blob {
        return Err("kernel symbol table: function addresses moved between the two links".into());
    }

    run_cmd(
        objcopy,
        &[
            "-O".into(),
            "binary".into(),
            kernel_elf.to_string_lossy().into_owned(),
            kernel_bin.to_string_lossy().into_owned(),
        ],
        None,
        &[],
        opts.quiet,
    )?;

    let kernel_sig = out_dir.join("kernel.dsig");
    log(opts.quiet, "  SIGN  kernel.bin (Ed25519)");
    img::sign_file(&key.seed, "kernel", "KERNEL.BIN", &kernel_bin, &kernel_sig)?;

    let klen = fs::metadata(&kernel_bin)
        .map_err(|e| format!("stat kernel.bin: {e}"))?
        .len();
    let kernel_sectors = klen.div_ceil(SECTOR_SIZE);

    // --- Bootloader stage 1 & stage 2 -----------------------------------------
    let boot_inc = format!("{}/", env.root.join("boot").to_string_lossy().replace('\\', "/"));
    let layout_defs = vec![
        "-i".into(),
        boot_inc,
        format!("-DSTAGE2_LBA={STAGE2_LBA}"),
        format!("-DSTAGE2_SECTORS={STAGE2_SECTORS}"),
        format!("-DSTAGE3_LBA={STAGE3_LBA}"),
        format!("-DSTAGE3_SECTORS={STAGE3_SECTORS}"),
        format!("-DKSIG_LBA={KSIG_LBA}"),
        format!("-DKERNEL_LBA={KERNEL_LBA}"),
        format!("-DKERNEL_SECTORS={kernel_sectors}"),
    ];
    let stage1_bin = out_dir.join("stage1.bin");
    log(opts.quiet, "  NASM  boot/stage1.asm");
    {
        let mut args = vec!["-f".into(), "bin".into(), "-o".into(), stage1_bin.to_string_lossy().into_owned()];
        args.extend(layout_defs.iter().cloned());
        args.push(env.root.join("boot").join("stage1.asm").to_string_lossy().into_owned());
        run_cmd(nasm, &args, None, &[], opts.quiet)?;
    }
    let s1_len = fs::metadata(&stage1_bin).map_err(|e| e.to_string())?.len();
    if s1_len != SECTOR_SIZE {
        return Err(format!("stage1.bin must be exactly {SECTOR_SIZE} bytes (got {s1_len})"));
    }

    let stage2_bin = out_dir.join("stage2.bin");
    log(opts.quiet, "  NASM  boot/stage2.asm");
    {
        let mut args = vec!["-f".into(), "bin".into(), "-o".into(), stage2_bin.to_string_lossy().into_owned()];
        args.extend(layout_defs.iter().cloned());
        args.push(env.root.join("boot").join("stage2.asm").to_string_lossy().into_owned());
        run_cmd(nasm, &args, None, &[], opts.quiet)?;
    }
    let s2_len = fs::metadata(&stage2_bin).map_err(|e| e.to_string())?.len();
    if s2_len > STAGE2_SECTORS * SECTOR_SIZE {
        return Err(format!(
            "stage2.bin is {s2_len} bytes; reserved area is {}",
            STAGE2_SECTORS * SECTOR_SIZE
        ));
    }

    let isoboot_bin = out_dir.join("isoboot.bin");
    let build_iso = opts.kernel_test.is_none();
    if build_iso {
        log(opts.quiet, "  NASM  boot/isoboot.asm");
        let mut args = vec!["-f".into(), "bin".into(), "-o".into(), isoboot_bin.to_string_lossy().into_owned()];
        args.extend(layout_defs);
        args.push(env.root.join("boot").join("isoboot.asm").to_string_lossy().into_owned());
        run_cmd(nasm, &args, None, &[], opts.quiet)?;
    }

    // --- Stage 3 & UEFI loader ------------------------------------------------
    let (stage3_bin, efi_bin, hello_dsig, sys_files) = match &opts.shared {
        Some(s) => (s.stage3_bin.clone(), s.efi_bin.clone(), s.hello_dsig.clone(), s.sys_files.clone()),
        None => {
            let s3 = build_stage3(env, out_dir, &trust_c, opts.quiet)?;
            let efi = build_uefi(env, out_dir, &trust_c, opts.quiet)?;
            let hello = all_programs
                .iter()
                .find(|p| p.name == "hello.dx")
                .ok_or_else(|| "hello.dx missing".to_string())?;
            let hsig = out_dir.join("hello.dsig");
            img::sign_file(&key.seed, "program", "hello.dx", &hello.path, &hsig)?;
            let sf = build_sys_files(env, out_dir, &key.seed, &all_programs)?;
            (s3, efi, hsig, sf)
        }
    };

    // --- Extra ESP files ------------------------------------------------------
    let hello = all_programs
        .iter()
        .find(|p| p.name == "hello.dx")
        .ok_or_else(|| "hello.dx missing".to_string())?;
    let mut extra_files: Vec<(String, PathBuf)> = vec![
        ("DOS/APPS/HELLO.DX".into(), hello.path.clone()),
        ("DOS/APPS/HELLO.DSIG".into(), hello_dsig),
    ];

    if opts.kernel_test.as_deref() == Some("SHELL") {
        if let Some(w2) = all_programs.iter().find(|p| p.name == "w2.exe") {
            extra_files.push(("DOS/APPS/W2.EXE".into(), w2.path.clone()));
        }
        if let Some(l2) = all_programs.iter().find(|p| p.name == "l2") {
            extra_files.push(("DOS/APPS/L2".into(), l2.path.clone()));
        }
        if let Some(w3) = all_programs.iter().find(|p| p.name == "w3.exe") {
            extra_files.push(("DOS/APPS/W3.EXE".into(), w3.path.clone()));
        }
        if let Some(w3lib) = all_programs.iter().find(|p| p.name == "w3lib.dll") {
            extra_files.push(("DOS/APPS/W3LIB.DLL".into(), w3lib.path.clone()));
        }
        if let Some(l3) = all_programs.iter().find(|p| p.name == "l3") {
            extra_files.push(("DOS/APPS/L3".into(), l3.path.clone()));
        }
        if let Some(libl3) = all_programs.iter().find(|p| p.name == "libl3.so") {
            extra_files.push(("DOS/APPS/LIBL3.SO".into(), libl3.path.clone()));
        }
        if let Some(ld) = all_programs.iter().find(|p| p.name == "ld-linux-x86-64.so.2") {
            extra_files.push(("DOS/APPS/LDL3.SO".into(), ld.path.clone()));
        }
    }

    if opts.kernel_test.as_deref() == Some("SERVICES") {
        let svc_dir = out_dir.join("services");
        fs::create_dir_all(&svc_dir).map_err(|e| e.to_string())?;
        let src = env.root.join("user/init/services/disk/hello.dman");
        let sig = svc_dir.join("HELLO.DSIG");
        img::sign_file(&key.seed, "manifest", "hello.dman", &src, &sig)?;
        let src_text = fs::read_to_string(&src).map_err(|e| e.to_string())?;
        let unsigned = svc_dir.join("UNSIGNED.DMAN");
        fs::write(&unsigned, src_text.replace("name = \"hello\"", "name = \"unsigned\""))
            .map_err(|e| e.to_string())?;
        let tampered = svc_dir.join("TAMPERED.DMAN");
        let ttext = src_text.replace("name = \"hello\"", "name = \"tampered\"");
        fs::write(&tampered, &ttext).map_err(|e| e.to_string())?;
        let tsig = svc_dir.join("TAMPERED.DSIG");
        img::sign_file(&key.seed, "manifest", "tampered.dman", &tampered, &tsig)?;
        fs::write(&tampered, format!("{ttext}# changed after it was signed\n"))
            .map_err(|e| e.to_string())?;
        extra_files.extend([
            ("DOS/SERVICES/HELLO.DMAN".into(), src),
            ("DOS/SERVICES/HELLO.DSIG".into(), sig),
            ("DOS/SERVICES/UNSIGNED.DMAN".into(), unsigned),
            ("DOS/SERVICES/TAMPERED.DMAN".into(), tampered),
            ("DOS/SERVICES/TAMPERED.DSIG".into(), tsig),
        ]);
    }

    if opts.kernel_test.as_deref() == Some("APP") {
        let app_dir = out_dir.join("app-test");
        fs::create_dir_all(&app_dir).map_err(|e| e.to_string())?;
        if let Some((_, valid_dapp)) = sys_files.iter().find(|(dst, _)| dst == "apps/files.dapp") {
            let mut tampered = fs::read(valid_dapp).map_err(|e| e.to_string())?;
            if tampered.len() > 64 {
                tampered[40] ^= 0x5A;
            }
            let bad_path = app_dir.join("BAD.DAPP");
            fs::write(&bad_path, &tampered).map_err(|e| e.to_string())?;
            let mut unsigned = fs::read(valid_dapp).map_err(|e| e.to_string())?;
            let sig_start = unsigned.len().saturating_sub(doscrypt::dsig::SIZE);
            unsigned[sig_start..].fill(0);
            let unsig_path = app_dir.join("UNSIGNED.DAPP");
            fs::write(&unsig_path, &unsigned).map_err(|e| e.to_string())?;
            extra_files.extend([
                ("DOS/APPS/BAD.DAPP".into(), bad_path),
                ("DOS/APPS/UNSIGNED.DAPP".into(), unsig_path),
            ]);
        }
    }

    // --- Disk image + SHA256SUMS ----------------------------------------------
    let image = out_dir.join("discrete.img");
    log(opts.quiet, "  IMAGE discrete.img");
    img::make_boot(
        &image,
        &stage1_bin,
        &stage2_bin,
        &stage3_bin,
        &kernel_bin,
        &kernel_sig,
        &efi_bin,
        &extra_files,
        &sys_files,
    )?;

    let iso = if build_iso {
        let iso_path = out_dir.join("discrete.iso");
        log(opts.quiet, "  ISO   discrete.iso");
        crate::iso::make_hybrid_iso(&image, &isoboot_bin, &iso_path)?;
        Some(iso_path)
    } else {
        None
    };

    let mut shipped: Vec<&PathBuf> = vec![
        &image,
        &stage1_bin,
        &stage2_bin,
        &stage3_bin,
        &kernel_bin,
        &kernel_sig,
        &efi_bin,
    ];
    if let Some(ref iso_path) = iso {
        shipped.insert(1, iso_path);
        shipped.push(&isoboot_bin);
    }
    let mut sums = Vec::with_capacity(shipped.len());
    for f in shipped {
        let h = sha256_file(f)?;
        let name = f.file_name().unwrap_or_default().to_string_lossy();
        sums.push(format!("{h}  {name}"));
    }
    fs::write(out_dir.join("SHA256SUMS"), format!("{}\n", sums.join("\n")))
        .map_err(|e| format!("write SHA256SUMS: {e}"))?;

    let size_mib = fs::metadata(&image).map_err(|e| e.to_string())?.len() / (1024 * 1024);
    let efi_kib = fs::metadata(&efi_bin).map_err(|e| e.to_string())?.len().div_ceil(1024);
    log(
        opts.quiet,
        &format!(
            "Built {} ({size_mib} MiB, BIOS + UEFI; kernel {kernel_sectors} sectors @ LBA {KERNEL_LBA}, UEFI loader {efi_kib} KiB)",
            env.rel(&image)
        ),
    );
    log(opts.quiet, &format!("  sha256 {}", sums[0]));
    if let Some(ref iso_path) = iso {
        log(opts.quiet, &format!("Built {} ({size_mib} MiB, hybrid ISO 9660 + El Torito BIOS/UEFI + GPT)", env.rel(iso_path)));
        log(opts.quiet, &format!("  sha256 {}", sums[1]));
    }

    Ok(BuildResult { image, iso })
}

fn build_kernel_asm(env: &Env, obj_dir: &Path, quiet: bool) -> Result<Vec<PathBuf>, String> {
    let nasm = env.nasm()?;
    let asm_files = collect_files(&env.root.join("kernel"), "asm", true);
    let mut objs = Vec::with_capacity(asm_files.len());
    for src in asm_files {
        let rel = env.rel(&src);
        let obj = obj_dir.join(format!("{}.o", rel.replace('/', "_")));
        if needs_rebuild(&obj, mtime_of(&src), "nasm-elf64-dwarf") {
            log(quiet, &format!("  NASM  {rel}"));
            run_cmd(
                nasm,
                &[
                    "-f".into(),
                    "elf64".into(),
                    "-g".into(),
                    "-F".into(),
                    "dwarf".into(),
                    "-o".into(),
                    obj.to_string_lossy().into_owned(),
                    src.to_string_lossy().into_owned(),
                ],
                None,
                &[],
                quiet,
            )?;
            write_stamp(&obj, "nasm-elf64-dwarf");
        }
        objs.push(obj);
    }
    Ok(objs)
}

fn build_kernel_rust(
    env: &Env,
    out_dir: &Path,
    kernel_test: Option<&str>,
    quiet: bool,
) -> Result<PathBuf, String> {
    let cargo = env.cargo()?;
    let crate_dir = env.root.join("kernel").join("rust");
    let target_dir = out_dir.join("rust");
    let raw_crate = crate_dir.to_string_lossy();
    let raw_root = env.root.to_string_lossy();
    let mut rustc_args = vec![
        format!("--remap-path-prefix={}/=kernel/rust/", raw_crate.replace('\\', "/")),
        format!("--remap-path-prefix={}/=", raw_root.replace('\\', "/")),
        "--remap-path-prefix=src/=kernel/rust/src/".to_string(),
    ];
    if cfg!(windows) {
        rustc_args.push(format!("--remap-path-prefix={}\\=kernel/rust/", raw_crate.replace('/', "\\")));
        rustc_args.push(format!("--remap-path-prefix={}\\=", raw_root.replace('/', "\\")));
        rustc_args.push("--remap-path-prefix=src\\=kernel/rust/src/".to_string());
    }
    if let Some(kt) = kernel_test {
        rustc_args.push("--cfg".into());
        rustc_args.push("ktest".into());
        rustc_args.push("--cfg".into());
        rustc_args.push(format!("ktest_{}", kt.to_ascii_lowercase()));
    }
    let mut args = vec![
        "rustc".into(),
        "--release".into(),
        "--locked".into(),
        "--target-dir".into(),
        target_dir.to_string_lossy().into_owned(),
    ];
    if quiet {
        args.push("--quiet".into());
    }
    args.push("--".into());
    args.extend(rustc_args);

    run_cmd(cargo, &args, Some(&crate_dir), &env.cargo_env_pairs(), quiet)?;
    let lib = target_dir
        .join("x86_64-unknown-none")
        .join("release")
        .join("libdkrnl.a");
    if !lib.is_file() {
        return Err(format!("cargo did not produce {}", lib.display()));
    }
    Ok(lib)
}

fn build_stage3(env: &Env, out_dir: &Path, trust_c: &Path, quiet: bool) -> Result<PathBuf, String> {
    let clang = env.clang()?;
    let clang_inc = env.clang_resource_include()?;
    let lld = env.lld()?;
    let objcopy = env.objcopy()?;
    let obj_dir = out_dir.join("obj");
    let common = env.root.join("boot").join("common");
    let mut flags: Vec<String> = vec![
        "--target=x86_64-elf".into(),
        "-std=c17".into(),
        "-Os".into(),
        "-g0".into(),
        "-ffreestanding".into(),
        "-fno-builtin".into(),
        "-nostdinc".into(),
        "-isystem".into(),
        clang_inc.to_string_lossy().into_owned(),
        "-fno-pic".into(),
        "-fno-pie".into(),
        "-mcmodel=small".into(),
        "-mno-red-zone".into(),
        "-mgeneral-regs-only".into(),
        "-fno-stack-protector".into(),
        "-fno-asynchronous-unwind-tables".into(),
    ];
    flags.extend(prefix_map_flags(&env.root));
    flags.extend([
        "-Wall".into(),
        "-Wextra".into(),
        "-Werror".into(),
        "-I".into(),
        common.to_string_lossy().into_owned(),
    ]);
    let stamp = hash_strings(&flags);
    let newest_hdr = newest_mtime(&collect_files(&common, "h", false));
    let srcs = [
        env.root.join("boot/stage3/stage3.c"),
        common.join("dcrypto.c"),
        common.join("kaslr.c"),
        trust_c.to_path_buf(),
    ];
    let mut objs = Vec::with_capacity(srcs.len());
    for src in &srcs {
        let stem = src.file_stem().and_then(|s| s.to_str()).unwrap_or("x");
        let o = obj_dir.join(format!("stage3_{stem}.o"));
        let in_mtime = [mtime_of(src), newest_hdr].into_iter().flatten().max();
        if needs_rebuild(&o, in_mtime, &stamp) {
            log(quiet, &format!("  CC    {} [stage 3]", env.rel(src)));
            let mut args = flags.clone();
            args.extend(["-c".into(), "-o".into(), o.to_string_lossy().into_owned(), src.to_string_lossy().into_owned()]);
            run_cmd(clang, &args, None, &[], quiet)?;
            write_stamp(&o, &stamp);
        }
        objs.push(o);
    }
    let elf = out_dir.join("stage3.elf");
    let bin = out_dir.join("stage3.bin");
    let ld_script = env.root.join("boot/stage3/stage3.ld");
    let link_mtime = newest_mtime(&objs).into_iter().chain(mtime_of(&ld_script)).max();
    if needs_rebuild(&bin, link_mtime, "stage3-link") {
        let mut args = vec![
            "-T".into(),
            ld_script.to_string_lossy().into_owned(),
            "-nostdlib".into(),
            "-static".into(),
            "--build-id=none".into(),
            "-z".into(),
            "max-page-size=0x1000".into(),
            "-o".into(),
            elf.to_string_lossy().into_owned(),
        ];
        args.extend(objs.iter().map(|o| o.to_string_lossy().into_owned()));
        run_cmd(lld, &args, None, &[], quiet)?;
        run_cmd(
            objcopy,
            &["-O".into(), "binary".into(), elf.to_string_lossy().into_owned(), bin.to_string_lossy().into_owned()],
            None,
            &[],
            quiet,
        )?;
        write_stamp(&bin, "stage3-link");
    }
    Ok(bin)
}

fn build_uefi(env: &Env, out_dir: &Path, trust_c: &Path, quiet: bool) -> Result<PathBuf, String> {
    let clang = env.clang()?;
    let clang_inc = env.clang_resource_include()?;
    let lld_link = env.lld_link()?;
    let nasm = env.nasm()?;
    let uefi_dir = env.root.join("boot/uefi");
    let common = env.root.join("boot/common");
    let obj_dir = out_dir.join("obj");

    let mut flags: Vec<String> = vec![
        "--target=x86_64-unknown-windows".into(),
        "-std=c17".into(),
        "-O2".into(),
        "-g0".into(),
        "-ffreestanding".into(),
        "-fno-builtin".into(),
        "-nostdinc".into(),
        "-isystem".into(),
        clang_inc.to_string_lossy().into_owned(),
        "-fno-stack-protector".into(),
        "-fshort-wchar".into(),
        "-mno-red-zone".into(),
        "-mgeneral-regs-only".into(),
    ];
    flags.extend(prefix_map_flags(&env.root));
    flags.extend(["-Wall".into(), "-Wextra".into(), "-Werror".into(), "-Wshadow".into()]);
    let stamp = hash_strings(&flags);
    let mut hdrs = collect_files(&uefi_dir, "h", false);
    hdrs.extend(collect_files(&common, "h", false));
    hdrs.extend(collect_files(&env.root.join("kernel/include"), "h", false));
    let newest_hdr = newest_mtime(&hdrs);

    let srcs = [
        uefi_dir.join("loader.c"),
        common.join("dcrypto.c"),
        common.join("kaslr.c"),
        trust_c.to_path_buf(),
    ];
    let mut objs = Vec::with_capacity(srcs.len() + 1);
    for src in &srcs {
        let stem = src.file_stem().and_then(|s| s.to_str()).unwrap_or("x");
        let o = obj_dir.join(format!("uefi_{stem}.o"));
        let in_mtime = [mtime_of(src), newest_hdr].into_iter().flatten().max();
        if needs_rebuild(&o, in_mtime, &stamp) {
            log(quiet, &format!("  CC    {} [UEFI]", env.rel(src)));
            let mut args = flags.clone();
            args.extend(["-c".into(), "-o".into(), o.to_string_lossy().into_owned(), src.to_string_lossy().into_owned()]);
            run_cmd(clang, &args, None, &[], quiet)?;
            write_stamp(&o, &stamp);
        }
        objs.push(o);
    }

    let handoff_src = uefi_dir.join("handoff.asm");
    let handoff_obj = obj_dir.join("uefi_handoff.o");
    if needs_rebuild(&handoff_obj, mtime_of(&handoff_src), "nasm-win64") {
        log(quiet, "  NASM  boot/uefi/handoff.asm");
        run_cmd(
            nasm,
            &[
                "-f".into(),
                "win64".into(),
                "-o".into(),
                handoff_obj.to_string_lossy().into_owned(),
                handoff_src.to_string_lossy().into_owned(),
            ],
            None,
            &[],
            quiet,
        )?;
        write_stamp(&handoff_obj, "nasm-win64");
    }

    let efi = out_dir.join("BOOTX64.EFI");
    let link_mtime = newest_mtime(&objs).into_iter().chain(mtime_of(&handoff_obj)).max();
    if needs_rebuild(&efi, link_mtime, "uefi-link") {
        log(quiet, "  LINK  BOOTX64.EFI");
        let mut args = vec![
            "/nologo".into(),
            "/subsystem:efi_application".into(),
            "/entry:efi_main".into(),
            "/nodefaultlib".into(),
            "/Brepro".into(),
            "/dynamicbase".into(),
            "/nxcompat".into(),
            "/debug:none".into(),
            format!("/out:{}", efi.to_string_lossy()),
            handoff_obj.to_string_lossy().into_owned(),
        ];
        args.extend(objs.iter().map(|o| o.to_string_lossy().into_owned()));
        run_cmd(lld_link, &args, None, &[], quiet)?;
        write_stamp(&efi, "uefi-link");
    }
    Ok(efi)
}

fn build_user_all(env: &Env, out_dir: &Path, quiet: bool) -> Result<(Vec<ProgramEntry>, bool), String> {
    let clang = env.clang()?;
    let clang_inc = env.clang_resource_include()?;
    let lld = env.lld()?;
    let user_src = env.root.join("user");
    let out_user = out_dir.join("user");
    fs::create_dir_all(&out_user).map_err(|e| format!("mkdir {}: {e}", out_user.display()))?;

    // Discover program directories in sorted order (same deterministic order as before).
    let mut prog_dirs: Vec<PathBuf> = fs::read_dir(&user_src)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.is_dir()
                && !matches!(
                    p.file_name().and_then(|n| n.to_str()),
                    Some("include" | "lib" | ".cargo" | "target")
                )
        })
        .collect();
    prog_dirs.sort();

    let rust_crates: Vec<&PathBuf> = prog_dirs
        .iter()
        .filter(|p| p.join("Cargo.toml").is_file())
        .collect();

    // Build scoped C/C++ `vendor/` archives first (cached by content hash).
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let vendor_libs = build_vendor_libs(env, out_dir, cpus, quiet)?;

    // Build the entire Rust user workspace in TWO fast cargo calls sharing one target dir:
    //   1) all alloc-enabled user programs in parallel (compiling libd/dosfs/doscrypt/dman once)
    //   2) devmgr (no-alloc drivers)
    let ws_target = out_user.join("rust-target");
    build_rust_user_workspace(env, &user_src, &ws_target, &rust_crates, quiet)?;

    let mut ucflags: Vec<String> = vec![
        "--target=x86_64-unknown-elf".into(),
        "-std=c17".into(),
        "-O2".into(),
        "-g0".into(),
        "-ffreestanding".into(),
        "-nostdinc".into(),
        "-isystem".into(),
        clang_inc.to_string_lossy().into_owned(),
        "-fpie".into(),
        "-fno-plt".into(),
        "-fno-stack-protector".into(),
        "-fno-asynchronous-unwind-tables".into(),
        "-fno-unwind-tables".into(),
        "-fno-common".into(),
    ];
    ucflags.extend(prefix_map_flags(&env.root));
    ucflags.extend([
        "-Wall".into(),
        "-Wextra".into(),
        "-Werror".into(),
        "-Wshadow".into(),
        "-Wno-unused-parameter".into(),
        "-I".into(),
        user_src.join("include").to_string_lossy().into_owned(),
    ]);
    let c_stamp = hash_strings(&ucflags);
    let user_hdrs = collect_files(&user_src.join("include"), "h", false);
    let lib_c = collect_files(&user_src.join("lib"), "c", false);

    let mut out = Vec::new();
    let mut libd_c: Option<PathBuf> = None;

    for p in &prog_dirs {
        let name = p
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| format!("bad user dir {}", p.display()))?;
        if p.join("Cargo.toml").is_file() {
            out.extend(link_rust_user_crate(
                env,
                p,
                name,
                &ws_target,
                &out_user,
                &vendor_libs,
                lld,
                quiet,
            )?);
            continue;
        }
        let csrc = collect_files(p, "c", false);
        let local_hdrs = collect_files(p, "h", false);
        let newest_hdr = newest_mtime(&user_hdrs)
            .into_iter()
            .chain(newest_mtime(&local_hdrs))
            .max();
        let needs_libd = csrc.iter().any(|f| {
            fs::read_to_string(f)
                .map(|s| s.contains("#include \"libd.h\""))
                .unwrap_or(false)
        });
        let mut libs: Vec<PathBuf> = Vec::new();
        if needs_libd {
            let a = match &libd_c {
                Some(a) => a.clone(),
                None => {
                    let built = build_libd_capi(env, &user_src, &out_user, quiet)?;
                    libd_c = Some(built.clone());
                    built
                }
            };
            libs.push(a);
        }
        let mut objs = Vec::new();
        for src in csrc.iter().chain(lib_c.iter()) {
            let stem = src.file_stem().and_then(|s| s.to_str()).unwrap_or("x");
            let o = out_user.join(format!("{name}_{stem}.o"));
            let in_mtime = [mtime_of(src), newest_hdr].into_iter().flatten().max();
            if needs_rebuild(&o, in_mtime, &c_stamp) {
                log(quiet, &format!("  CC    {} [user]", env.rel(src)));
                let mut args = ucflags.clone();
                args.extend([
                    "-c".into(),
                    "-o".into(),
                    o.to_string_lossy().into_owned(),
                    src.to_string_lossy().into_owned(),
                ]);
                run_cmd(clang, &args, None, &[], quiet)?;
                write_stamp(&o, &c_stamp);
            }
            objs.push(o);
        }
        let dx = out_user.join(format!("{name}.dx"));
        let link_mtime = newest_mtime(&objs).into_iter().chain(newest_mtime(&libs)).max();
        if needs_rebuild(&dx, link_mtime, "user-c-link") {
            log(quiet, &format!("  LD    user/{name}.dx"));
            let mut args = vec![
                "-pie".into(),
                "--no-dynamic-linker".into(),
                "-nostdlib".into(),
                "-e".into(),
                "_start".into(),
                "--build-id=none".into(),
                "-s".into(),
                "-z".into(),
                "noexecstack".into(),
                "-z".into(),
                "relro".into(),
                "-z".into(),
                "now".into(),
                "-z".into(),
                "separate-loadable-segments".into(),
                "-z".into(),
                "max-page-size=4096".into(),
                "-z".into(),
                "shstk".into(),
                "-o".into(),
                dx.to_string_lossy().into_owned(),
            ];
            args.extend(objs.iter().map(|o| o.to_string_lossy().into_owned()));
            if !libs.is_empty() {
                args.push("--gc-sections".into());
                args.extend(libs.iter().map(|l| l.to_string_lossy().into_owned()));
            }
            run_cmd(lld, &args, None, &[], quiet)?;
            write_stamp(&dx, "user-c-link");
        }
        out.push(ProgramEntry { name: format!("{name}.dx"), path: dx });
    }

    let (compat_progs, has_w2) = build_compat(env, out_dir, quiet)?;
    out.extend(compat_progs);
    Ok((out, has_w2))
}

fn build_rust_user_workspace(
    env: &Env,
    user_src: &Path,
    ws_target: &Path,
    crates: &[&PathBuf],
    quiet: bool,
) -> Result<(), String> {
    let cargo = env.cargo()?;
    let mut env_pairs = env.cargo_env_pairs();
    env_pairs.push((
        "CARGO_ENCODED_RUSTFLAGS".into(),
        encoded_rustflags(&env.root, &["-C", "force-frame-pointers=yes"]),
    ));

    let mut alloc_pkgs = Vec::new();
    let mut noalloc_pkgs = Vec::new();
    for c in crates {
        let name = c.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let toml = fs::read_to_string(c.join("Cargo.toml")).unwrap_or_default();
        if toml.contains("\"alloc\"") {
            alloc_pkgs.push(name);
        } else {
            noalloc_pkgs.push(name);
        }
    }

    let run_group = |label: &str, pkgs: &[&str]| -> Result<(), String> {
        if pkgs.is_empty() {
            return Ok(());
        }
        log(quiet, &format!("  CARGO user workspace ({label}: {})", pkgs.join(", ")));
        let mut args = vec![
            "build".into(),
            "--release".into(),
            "--locked".into(),
            "--target".into(),
            "x86_64-unknown-none".into(),
            "--target-dir".into(),
            ws_target.to_string_lossy().into_owned(),
        ];
        if quiet {
            args.push("--quiet".into());
        }
        for p in pkgs {
            args.push("-p".into());
            args.push((*p).to_string());
        }
        run_cmd(cargo, &args, Some(user_src), &env_pairs, quiet)
    };

    run_group("alloc", &alloc_pkgs)?;
    run_group("no-alloc", &noalloc_pkgs)?;
    Ok(())
}

fn build_libd_capi(env: &Env, user_src: &Path, out_user: &Path, quiet: bool) -> Result<PathBuf, String> {
    let cargo = env.cargo()?;
    let target_dir = out_user.join("rust-libd-c");
    let mut env_pairs = env.cargo_env_pairs();
    env_pairs.push((
        "CARGO_ENCODED_RUSTFLAGS".into(),
        encoded_rustflags(&env.root, &["-C", "force-frame-pointers=yes"]),
    ));
    log(quiet, "  CARGO user/lib/libd [C API]");
    let mut args = vec![
        "rustc".into(),
        "--release".into(),
        "--locked".into(),
        "--target".into(),
        "x86_64-unknown-none".into(),
        "-p".into(),
        "libd".into(),
        "--features".into(),
        "capi".into(),
        "--crate-type".into(),
        "staticlib".into(),
        "--target-dir".into(),
        target_dir.to_string_lossy().into_owned(),
    ];
    if quiet {
        args.push("--quiet".into());
    }
    run_cmd(cargo, &args, Some(user_src), &env_pairs, quiet)?;
    let a = target_dir
        .join("x86_64-unknown-none")
        .join("release")
        .join("liblibd.a");
    if !a.is_file() {
        return Err(format!("cargo did not produce {}", a.display()));
    }
    Ok(a)
}

fn parse_toml_string_list(toml: &str, key: &str) -> Option<Vec<String>> {
    for line in toml.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix(key) else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix('=') else {
            continue;
        };
        let rest = rest.trim();
        let inner = rest.strip_prefix('[')?.strip_suffix(']')?;
        let mut items = Vec::new();
        for part in inner.split(',') {
            let p = part.trim();
            if let Some(s) = p.strip_prefix('"').and_then(|s| s.strip_suffix('"'))
                && !s.is_empty()
            {
                items.push(s.to_string());
            }
        }
        return Some(items);
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn link_rust_user_crate(
    _env: &Env,
    crate_dir: &Path,
    name: &str,
    ws_target: &Path,
    out_user: &Path,
    vendor_libs: &std::collections::BTreeMap<String, PathBuf>,
    lld: &Path,
    quiet: bool,
) -> Result<Vec<ProgramEntry>, String> {
    let a = ws_target
        .join("x86_64-unknown-none")
        .join("release")
        .join(format!("lib{name}.a"));
    if !a.is_file() {
        return Err(format!("cargo did not produce {}", a.display()));
    }
    let toml_path = crate_dir.join("Cargo.toml");
    let toml = fs::read_to_string(&toml_path).map_err(|e| e.to_string())?;
    let mut extra_archives: Vec<PathBuf> = Vec::new();
    if let Some(vnames) = parse_toml_string_list(&toml, "vendor_libs") {
        for vn in vnames {
            let vpath = vendor_libs
                .get(&vn)
                .ok_or_else(|| format!("{}: unknown vendor_libs entry '{vn}'", toml_path.display()))?;
            extra_archives.push(vpath.clone());
        }
    }
    let mut ldflags: Vec<String> = vec![
        "-pie".into(),
        "--no-dynamic-linker".into(),
        "-nostdlib".into(),
        "--build-id=none".into(),
        "-s".into(),
        "--gc-sections".into(),
        "-z".into(),
        "noexecstack".into(),
        "-z".into(),
        "relro".into(),
        "-z".into(),
        "now".into(),
        "-z".into(),
        "separate-loadable-segments".into(),
        "-z".into(),
        "max-page-size=4096".into(),
    ];
    let no_shstk = toml
        .lines()
        .any(|l| l.trim().replace(' ', "") == "shstk=false");
    if !no_shstk {
        ldflags.push("-z".into());
        ldflags.push("shstk".into());
    }
    let a_mtime = extra_archives
        .iter()
        .filter_map(|p| mtime_of(p))
        .chain(mtime_of(&a))
        .max();
    let stamp = hash_strings(&ldflags);

    let link_one = |out_name: &str, entry: &str| -> Result<ProgramEntry, String> {
        let out_path = out_user.join(out_name);
        let s = format!("{stamp}|{entry}|{}", extra_archives.len());
        if needs_rebuild(&out_path, a_mtime, &s) {
            log(quiet, &format!("  LD    user/{out_name}"));
            let mut args = ldflags.clone();
            args.extend([
                "-e".into(),
                entry.into(),
                "-o".into(),
                out_path.to_string_lossy().into_owned(),
                a.to_string_lossy().into_owned(),
            ]);
            args.extend(extra_archives.iter().map(|p| p.to_string_lossy().into_owned()));
            run_cmd(lld, &args, None, &[], quiet)?;
            write_stamp(&out_path, &s);
        }
        Ok(ProgramEntry { name: out_name.to_string(), path: out_path })
    };

    let dx_list = parse_toml_string_list(&toml, "dx");
    let dsvc_list = parse_toml_string_list(&toml, "dsvc");
    if dx_list.is_some() || dsvc_list.is_some() {
        let mut res = Vec::new();
        if let Some(dsvc_list) = dsvc_list {
            for d in dsvc_list {
                let sym = format!("dsvc_{}", d.replace('-', "_"));
                res.push(link_one(&format!("{d}.dsvc"), &sym)?);
            }
        }
        if let Some(dx_list) = dx_list {
            for d in dx_list {
                let sym = format!("dx_{}", d.replace('-', "_"));
                res.push(link_one(&format!("{d}.dx"), &sym)?);
            }
        }
        return Ok(res);
    }

    let mut res = vec![link_one(&format!("{name}.dx"), "_start")?];
    if let Some(ddrv_list) = parse_toml_string_list(&toml, "ddrv") {
        for d in ddrv_list {
            let sym = format!("ddrv_{}", d.replace('-', "_"));
            res.push(link_one(&format!("{d}.ddrv"), &sym)?);
        }
    }
    Ok(res)
}

fn build_compat(env: &Env, out_dir: &Path, quiet: bool) -> Result<(Vec<ProgramEntry>, bool), String> {
    let clang = env.clang()?;
    let lld = env.lld()?;
    let src = env.root.join("compat");
    let out = out_dir.join("compat");
    fs::create_dir_all(&out).map_err(|e| e.to_string())?;

    let mut progs = Vec::new();
    let w1_src = src.join("win/w1.c");
    let defs: Vec<PathBuf> = collect_files(&src.join("win"), "def", false)
        .into_iter()
        .filter(|p| p.file_name().and_then(|s| s.to_str()) != Some("w3lib.def"))
        .collect();

    // W1: use MSVC when present (tests real MSVC PE codegen), else Clang + llvm-dlltool + lld-link
    // so Linux hosts build W1 natively with zero MSVC dependency.
    let w1_variants: [(&str, Option<&str>, &[&str]); 3] = [
        ("w1", None, &["kernel32.lib"]),
        ("w1fault", Some("W1_FAULT"), &["kernel32.lib"]),
        ("w1bad", Some("W1_BAD"), &["kernel32.lib", "user32.lib"]),
    ];

    if let Some(msvc) = env.msvc() {
        for def in &defs {
            let stem = def.file_stem().and_then(|s| s.to_str()).unwrap_or("x");
            let lib_out = out.join(format!("{stem}.lib"));
            if needs_rebuild(&lib_out, mtime_of(def), "msvc-def") {
                run_cmd(
                    &msvc.lib,
                    &[
                        "/nologo".into(),
                        "/Brepro".into(),
                        "/machine:x64".into(),
                        format!("/def:{}", def.to_string_lossy()),
                        format!("/out:{}", lib_out.to_string_lossy()),
                    ],
                    None,
                    &[],
                    quiet,
                )?;
                write_stamp(&lib_out, "msvc-def");
            }
        }
        let newest_def = newest_mtime(&defs);
        for (name, def_macro, libs) in w1_variants {
            let obj = out.join(format!("{name}.obj"));
            let exe = out.join(format!("{name}.exe"));
            let stamp = format!("msvc-w1-{name}");
            let in_m = [mtime_of(&w1_src), newest_def].into_iter().flatten().max();
            if needs_rebuild(&exe, in_m, &stamp) {
                log(quiet, &format!("  CL    compat/win/w1.c -> {name}.exe [MSVC]"));
                let mut cl_args = vec![
                    "/nologo".into(),
                    "/c".into(),
                    "/O1".into(),
                    "/GS-".into(),
                    "/Zl".into(),
                    "/W4".into(),
                    "/WX".into(),
                    "/Brepro".into(),
                ];
                if let Some(d) = def_macro {
                    cl_args.push(format!("/D{d}"));
                }
                cl_args.push(format!("/Fo{}", obj.to_string_lossy()));
                cl_args.push(w1_src.to_string_lossy().into_owned());
                run_cmd(&msvc.cl, &cl_args, None, &[], quiet)?;

                let mut link_args = vec![
                    "/nologo".into(),
                    "/NODEFAULTLIB".into(),
                    "/ENTRY:w1_main".into(),
                    "/SUBSYSTEM:CONSOLE".into(),
                    "/MACHINE:X64".into(),
                    "/Brepro".into(),
                    "/DYNAMICBASE".into(),
                    "/HIGHENTROPYVA".into(),
                    "/NXCOMPAT".into(),
                    "/MANIFEST:NO".into(),
                    format!("/LIBPATH:{}", out.to_string_lossy()),
                    format!("/OUT:{}", exe.to_string_lossy()),
                    obj.to_string_lossy().into_owned(),
                ];
                link_args.extend(libs.iter().map(|s| (*s).to_string()));
                run_cmd(&msvc.link, &link_args, None, &[], quiet)?;
                write_stamp(&exe, &stamp);
            }
            progs.push(ProgramEntry { name: format!("{name}.exe"), path: exe });
        }
    } else {
        let dlltool = env
            .dlltool()
            .ok_or_else(|| "llvm-dlltool not found (needed to build W1 without MSVC)".to_string())?;
        let lld_link = env.lld_link()?;
        for def in &defs {
            let stem = def.file_stem().and_then(|s| s.to_str()).unwrap_or("x");
            let lib_out = out.join(format!("{stem}.lib"));
            if needs_rebuild(&lib_out, mtime_of(def), "llvm-dlltool") {
                run_cmd(
                    dlltool,
                    &[
                        "-m".into(),
                        "i386:x86-64".into(),
                        "-d".into(),
                        def.to_string_lossy().into_owned(),
                        "-l".into(),
                        lib_out.to_string_lossy().into_owned(),
                    ],
                    None,
                    &[],
                    quiet,
                )?;
                write_stamp(&lib_out, "llvm-dlltool");
            }
        }
        let newest_def = newest_mtime(&defs);
        for (name, def_macro, libs) in w1_variants {
            let obj = out.join(format!("{name}.obj"));
            let exe = out.join(format!("{name}.exe"));
            let stamp = format!("clang-w1-{name}");
            let in_m = [mtime_of(&w1_src), newest_def].into_iter().flatten().max();
            if needs_rebuild(&exe, in_m, &stamp) {
                log(quiet, &format!("  CC    compat/win/w1.c -> {name}.exe [x86_64-windows]"));
                let mut cc_args = vec![
                    "--target=x86_64-pc-windows-msvc".into(),
                    "-std=c17".into(),
                    "-O1".into(),
                    "-g0".into(),
                    "-ffreestanding".into(),
                    "-fno-stack-protector".into(),
                    "-mno-stack-arg-probe".into(),
                    "-Wall".into(),
                    "-Wextra".into(),
                    "-Werror".into(),
                ];
                cc_args.extend(prefix_map_flags(&env.root));
                if let Some(d) = def_macro {
                    cc_args.push(format!("-D{d}"));
                }
                cc_args.extend([
                    "-c".into(),
                    "-o".into(),
                    obj.to_string_lossy().into_owned(),
                    w1_src.to_string_lossy().into_owned(),
                ]);
                run_cmd(clang, &cc_args, None, &[], quiet)?;

                let mut link_args = vec![
                    "/nologo".into(),
                    "/nodefaultlib".into(),
                    "/entry:w1_main".into(),
                    "/subsystem:console".into(),
                    "/machine:x64".into(),
                    "/Brepro".into(),
                    "/dynamicbase".into(),
                    "/highentropyva".into(),
                    "/nxcompat".into(),
                    "/manifest:no".into(),
                    format!("/libpath:{}", out.to_string_lossy()),
                    format!("/out:{}", exe.to_string_lossy()),
                    obj.to_string_lossy().into_owned(),
                ];
                link_args.extend(libs.iter().map(|s| (*s).to_string()));
                run_cmd(lld_link, &link_args, None, &[], quiet)?;
                write_stamp(&exe, &stamp);
            }
            progs.push(ProgramEntry { name: format!("{name}.exe"), path: exe });
        }
    }

    // L1: static Linux ELF
    let l1 = build_linux_compat(env, clang, lld, &src.join("linux/l1.c"), &out, "l1", quiet)?;
    progs.push(ProgramEntry { name: "l1".into(), path: l1 });

    // W2: MSVC static CRT (/MT, C++ exceptions). Built whenever MSVC + Windows SDK are available
    // (always on Windows with VS+SDK; optional on Linux).
    let mut has_w2 = false;
    if let (Some(msvc), Some(sdk)) = (env.msvc(), env.winsdk()) {
        has_w2 = true;
        let w2_c = src.join("win/w2.c");
        let w2_cpp = src.join("win/w2cxx.cpp");
        let w2 = out.join("w2.exe");
        let in_m = newest_mtime(&[w2_c.clone(), w2_cpp.clone()]);
        if needs_rebuild(&w2, in_m, "msvc-w2") {
            let mut inc_paths = vec![msvc.vc_root.join("include")];
            inc_paths.extend(sdk.include.iter().cloned());
            let mut lib_paths = vec![msvc.vc_root.join("lib/x64")];
            lib_paths.extend(sdk.lib.iter().cloned());
            let join_semi = |ps: &[PathBuf]| -> String {
                ps.iter()
                    .map(|p| p.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join(";")
            };
            let msvc_env = vec![
                ("INCLUDE".into(), join_semi(&inc_paths)),
                ("LIB".into(), join_semi(&lib_paths)),
            ];
            let mut w2_objs = Vec::new();
            for f in [&w2_c, &w2_cpp] {
                let stem = f.file_stem().and_then(|s| s.to_str()).unwrap_or("x");
                let o = out.join(format!("{stem}.obj"));
                log(quiet, &format!("  CL    {} [MSVC /MT]", env.rel(f)));
                run_cmd(
                    &msvc.cl,
                    &[
                        "/nologo".into(),
                        "/c".into(),
                        "/MT".into(),
                        "/O2".into(),
                        "/EHsc".into(),
                        "/GS".into(),
                        "/W4".into(),
                        "/WX".into(),
                        "/Brepro".into(),
                        format!("/Fo{}", o.to_string_lossy()),
                        f.to_string_lossy().into_owned(),
                    ],
                    None,
                    &msvc_env,
                    quiet,
                )?;
                w2_objs.push(o);
            }
            let mut link_args = vec![
                "/nologo".into(),
                "/SUBSYSTEM:CONSOLE".into(),
                "/MACHINE:X64".into(),
                "/Brepro".into(),
                "/DYNAMICBASE".into(),
                "/HIGHENTROPYVA".into(),
                "/NXCOMPAT".into(),
                "/MANIFEST:NO".into(),
                "/DEBUG:NONE".into(),
                format!("/OUT:{}", w2.to_string_lossy()),
            ];
            link_args.extend(w2_objs.iter().map(|o| o.to_string_lossy().into_owned()));
            run_cmd(&msvc.link, &link_args, None, &msvc_env, quiet)?;
            write_stamp(&w2, "msvc-w2");
        }
        progs.push(ProgramEntry { name: "w2.exe".into(), path: w2 });

        // W3: MSVC dynamic CRT (/MD, /EHsc) + real PE DLL (w3lib.dll).
        let mut inc_paths = vec![msvc.vc_root.join("include")];
        inc_paths.extend(sdk.include.iter().cloned());
        let mut lib_paths = vec![msvc.vc_root.join("lib/x64")];
        lib_paths.extend(sdk.lib.iter().cloned());
        let join_semi = |ps: &[PathBuf]| -> String {
            ps.iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(";")
        };
        let msvc_env = vec![
            ("INCLUDE".into(), join_semi(&inc_paths)),
            ("LIB".into(), join_semi(&lib_paths)),
        ];
        let w3lib_c = src.join("win/w3lib.c");
        let w3lib_def = src.join("win/w3lib.def");
        let w3lib_dll = out.join("w3lib.dll");
        let w3lib_imp = out.join("w3lib.lib");
        let w3lib_m = newest_mtime(&[w3lib_c.clone(), w3lib_def.clone()]);
        if needs_rebuild(&w3lib_dll, w3lib_m, "msvc-w3lib") || !w3lib_imp.is_file() {
            let o = out.join("w3lib.obj");
            log(quiet, "  CL    compat/win/w3lib.c [MSVC /MD /LD]");
            run_cmd(
                &msvc.cl,
                &[
                    "/nologo".into(),
                    "/c".into(),
                    "/MD".into(),
                    "/O2".into(),
                    "/GS".into(),
                    "/W4".into(),
                    "/WX".into(),
                    "/Brepro".into(),
                    format!("/Fo{}", o.to_string_lossy()),
                    w3lib_c.to_string_lossy().into_owned(),
                ],
                None,
                &msvc_env,
                quiet,
            )?;
            run_cmd(
                &msvc.link,
                &[
                    "/nologo".into(),
                    "/DLL".into(),
                    "/MACHINE:X64".into(),
                    "/Brepro".into(),
                    "/DYNAMICBASE".into(),
                    "/HIGHENTROPYVA".into(),
                    "/NXCOMPAT".into(),
                    "/MANIFEST:NO".into(),
                    "/DEBUG:NONE".into(),
                    format!("/DEF:{}", w3lib_def.to_string_lossy()),
                    format!("/IMPLIB:{}", w3lib_imp.to_string_lossy()),
                    format!("/OUT:{}", w3lib_dll.to_string_lossy()),
                    o.to_string_lossy().into_owned(),
                ],
                None,
                &msvc_env,
                quiet,
            )?;
            write_stamp(&w3lib_dll, "msvc-w3lib");
        }
        progs.push(ProgramEntry { name: "w3lib.dll".into(), path: w3lib_dll });

        let w3_c = src.join("win/w3.c");
        let w3_cpp = src.join("win/w3cxx.cpp");
        let w3 = out.join("w3.exe");
        let w3_m = newest_mtime(&[w3_c.clone(), w3_cpp.clone(), w3lib_imp.clone()]);
        if needs_rebuild(&w3, w3_m, "msvc-w3") {
            let mut w3_objs = Vec::new();
            for f in [&w3_c, &w3_cpp] {
                let stem = f.file_stem().and_then(|s| s.to_str()).unwrap_or("x");
                let o = out.join(format!("{stem}.obj"));
                log(quiet, &format!("  CL    {} [MSVC /MD]", env.rel(f)));
                run_cmd(
                    &msvc.cl,
                    &[
                        "/nologo".into(),
                        "/c".into(),
                        "/MD".into(),
                        "/O2".into(),
                        "/EHsc".into(),
                        "/GS".into(),
                        "/W4".into(),
                        "/WX".into(),
                        "/Brepro".into(),
                        format!("/Fo{}", o.to_string_lossy()),
                        f.to_string_lossy().into_owned(),
                    ],
                    None,
                    &msvc_env,
                    quiet,
                )?;
                w3_objs.push(o);
            }
            let mut link_args = vec![
                "/nologo".into(),
                "/SUBSYSTEM:CONSOLE".into(),
                "/MACHINE:X64".into(),
                "/Brepro".into(),
                "/DYNAMICBASE".into(),
                "/HIGHENTROPYVA".into(),
                "/NXCOMPAT".into(),
                "/MANIFEST:NO".into(),
                "/DEBUG:NONE".into(),
                format!("/OUT:{}", w3.to_string_lossy()),
            ];
            link_args.extend(w3_objs.iter().map(|o| o.to_string_lossy().into_owned()));
            link_args.push(w3lib_imp.to_string_lossy().into_owned());
            run_cmd(&msvc.link, &link_args, None, &msvc_env, quiet)?;
            write_stamp(&w3, "msvc-w3");
        }
        progs.push(ProgramEntry { name: "w3.exe".into(), path: w3 });
    } else {
        log(quiet, "  NOTE  compat/win/w2.exe and w3.exe skipped (MSVC / Windows SDK not found)");
    }

    // L2: static Linux ELF
    let l2 = build_linux_compat(env, clang, lld, &src.join("linux/l2.c"), &out, "l2", quiet)?;
    progs.push(ProgramEntry { name: "l2".into(), path: l2 });

    // L3: dynamic Linux ELF (PT_INTERP ld-linux-x86-64.so.2 + libl3.so + l3)
    let ld_so = build_linux_shared(env, clang, lld, &src.join("linux/ld_dos.c"), &out, "ld-linux-x86-64.so.2", Some("_start"), true, quiet)?;
    let libl3 = build_linux_shared(env, clang, lld, &src.join("linux/libl3.c"), &out, "libl3.so", None, false, quiet)?;
    let l3 = build_linux_dynamic(env, clang, lld, &src.join("linux/l3.c"), &libl3, &out, "l3", quiet)?;
    progs.push(ProgramEntry { name: "ld-linux-x86-64.so.2".into(), path: ld_so });
    progs.push(ProgramEntry { name: "libl3.so".into(), path: libl3 });
    progs.push(ProgramEntry { name: "l3".into(), path: l3 });

    Ok((progs, has_w2))
}

fn build_linux_compat(
    env: &Env,
    clang: &Path,
    lld: &Path,
    src: &Path,
    out_dir: &Path,
    name: &str,
    quiet: bool,
) -> Result<PathBuf, String> {
    let o = out_dir.join(format!("{name}.o"));
    let bin = out_dir.join(name);
    let stamp = format!("linux-{name}");
    if needs_rebuild(&bin, mtime_of(src), &stamp) {
        log(quiet, &format!("  CC    {} -> {name} [x86_64-linux]", env.rel(src)));
        let mut cc_args = vec![
            "--target=x86_64-linux-gnu".into(),
            "-std=c17".into(),
            "-O2".into(),
            "-g0".into(),
            "-ffreestanding".into(),
            "-fno-builtin".into(),
            "-nostdinc".into(),
            "-fno-pic".into(),
            "-fno-pie".into(),
            "-fno-stack-protector".into(),
            "-fno-asynchronous-unwind-tables".into(),
        ];
        cc_args.extend(prefix_map_flags(&env.root));
        cc_args.extend([
            "-Wall".into(),
            "-Wextra".into(),
            "-Werror".into(),
            "-c".into(),
            "-o".into(),
            o.to_string_lossy().into_owned(),
            src.to_string_lossy().into_owned(),
        ]);
        run_cmd(clang, &cc_args, None, &[], quiet)?;
        run_cmd(
            lld,
            &[
                "-static".into(),
                "-nostdlib".into(),
                "-e".into(),
                "_start".into(),
                "--build-id=none".into(),
                "-s".into(),
                "-z".into(),
                "noexecstack".into(),
                "-z".into(),
                "separate-loadable-segments".into(),
                "-z".into(),
                "max-page-size=4096".into(),
                "--image-base=0x400000".into(),
                "-o".into(),
                bin.to_string_lossy().into_owned(),
                o.to_string_lossy().into_owned(),
            ],
            None,
            &[],
            quiet,
        )?;
        write_stamp(&bin, &stamp);
    }
    Ok(bin)
}

#[allow(clippy::too_many_arguments)]
fn build_linux_shared(
    env: &Env,
    clang: &Path,
    lld: &Path,
    src: &Path,
    out_dir: &Path,
    name: &str,
    entry: Option<&str>,
    symbolic: bool,
    quiet: bool,
) -> Result<PathBuf, String> {
    let o = out_dir.join(format!("{name}.o"));
    let bin = out_dir.join(name);
    let stamp = format!("linux-so-{name}");
    if needs_rebuild(&bin, mtime_of(src), &stamp) {
        log(quiet, &format!("  CC    {} -> {name} [x86_64-linux shared]", env.rel(src)));
        let mut cc_args = vec![
            "--target=x86_64-linux-gnu".into(),
            "-std=c17".into(),
            "-O2".into(),
            "-g0".into(),
            "-ffreestanding".into(),
            "-fno-builtin".into(),
            "-nostdinc".into(),
            "-fPIC".into(),
            "-fno-stack-protector".into(),
            "-fno-asynchronous-unwind-tables".into(),
        ];
        cc_args.extend(prefix_map_flags(&env.root));
        cc_args.extend([
            "-Wall".into(),
            "-Wextra".into(),
            "-Werror".into(),
            "-c".into(),
            "-o".into(),
            o.to_string_lossy().into_owned(),
            src.to_string_lossy().into_owned(),
        ]);
        run_cmd(clang, &cc_args, None, &[], quiet)?;
        let mut ld_args = vec![
            "-shared".into(),
            "-nostdlib".into(),
            "--build-id=none".into(),
            "-s".into(),
            "-soname".into(),
            name.into(),
            "-z".into(),
            "noexecstack".into(),
            "-z".into(),
            "relro".into(),
            "-z".into(),
            "now".into(),
            "-z".into(),
            "separate-loadable-segments".into(),
            "-z".into(),
            "max-page-size=4096".into(),
        ];
        if symbolic {
            ld_args.push("-Bsymbolic".into());
        }
        if let Some(e) = entry {
            ld_args.push("-e".into());
            ld_args.push(e.into());
        }
        ld_args.extend([
            "-o".into(),
            bin.to_string_lossy().into_owned(),
            o.to_string_lossy().into_owned(),
        ]);
        run_cmd(lld, &ld_args, None, &[], quiet)?;
        write_stamp(&bin, &stamp);
    }
    Ok(bin)
}

#[allow(clippy::too_many_arguments)]
fn build_linux_dynamic(
    env: &Env,
    clang: &Path,
    lld: &Path,
    src: &Path,
    lib_so: &Path,
    out_dir: &Path,
    name: &str,
    quiet: bool,
) -> Result<PathBuf, String> {
    let o = out_dir.join(format!("{name}.o"));
    let bin = out_dir.join(name);
    let stamp = format!("linux-dyn-{name}");
    let in_m = newest_mtime(&[src.to_path_buf(), lib_so.to_path_buf()]);
    if needs_rebuild(&bin, in_m, &stamp) {
        log(quiet, &format!("  CC    {} -> {name} [x86_64-linux dynamic]", env.rel(src)));
        let mut cc_args = vec![
            "--target=x86_64-linux-gnu".into(),
            "-std=c17".into(),
            "-O2".into(),
            "-g0".into(),
            "-ffreestanding".into(),
            "-fno-builtin".into(),
            "-nostdinc".into(),
            "-fPIE".into(),
            "-fno-stack-protector".into(),
            "-fno-asynchronous-unwind-tables".into(),
        ];
        cc_args.extend(prefix_map_flags(&env.root));
        cc_args.extend([
            "-Wall".into(),
            "-Wextra".into(),
            "-Werror".into(),
            "-c".into(),
            "-o".into(),
            o.to_string_lossy().into_owned(),
            src.to_string_lossy().into_owned(),
        ]);
        run_cmd(clang, &cc_args, None, &[], quiet)?;
        run_cmd(
            lld,
            &[
                "-pie".into(),
                "-nostdlib".into(),
                "-e".into(),
                "_start".into(),
                "--dynamic-linker=/lib64/ld-linux-x86-64.so.2".into(),
                "--build-id=none".into(),
                "-s".into(),
                "-z".into(),
                "noexecstack".into(),
                "-z".into(),
                "relro".into(),
                "-z".into(),
                "now".into(),
                "-z".into(),
                "separate-loadable-segments".into(),
                "-z".into(),
                "max-page-size=4096".into(),
                "-o".into(),
                bin.to_string_lossy().into_owned(),
                o.to_string_lossy().into_owned(),
                lib_so.to_string_lossy().into_owned(),
            ],
            None,
            &[],
            quiet,
        )?;
        write_stamp(&bin, &stamp);
    }
    Ok(bin)
}

fn write_programs_asm(path: &Path, programs: &[ProgramEntry]) -> Result<(), String> {
    let mut s = String::new();
    s.push_str("; generated by dbuild: user programs embedded in the kernel image\n");
    s.push_str("section .data.rel.ro progbits alloc noexec write align=16\n");
    s.push_str("global user_program_table, user_program_count\n");
    s.push_str("align 8\n");
    s.push_str(&format!("user_program_count: dq {}\n", programs.len()));
    s.push_str("user_program_table:\n");
    for i in 0..programs.len() {
        s.push_str(&format!("    dq name{i}, data{i}, end{i} - data{i}\n"));
    }
    for (i, p) in programs.iter().enumerate() {
        s.push_str(&format!("name{i}: db \"{}\", 0\n", p.name));
        s.push_str("align 16\n");
        let path_str = p.path.to_string_lossy().replace('\\', "/");
        s.push_str(&format!("data{i}: incbin \"{path_str}\"\n"));
        s.push_str(&format!("end{i}:\n"));
    }
    write_if_changed(path, s.as_bytes())
}

struct KSym {
    off: u32,
    name: String,
}

fn strip_rust_hash(name: &str) -> &str {
    if name.len() > 19 {
        let split = name.len() - 19;
        if name.is_char_boundary(split)
            && name[split..].starts_with("::h")
            && name[split + 3..].bytes().all(|b| b.is_ascii_hexdigit())
        {
            return &name[..split];
        }
    }
    name
}

fn extract_kernel_symbols(nm: &Path, elf: &Path) -> Result<Vec<KSym>, String> {
    let elf_s = elf.to_string_lossy();
    let out = run_capture(nm, &["--defined-only", "--numeric-sort", "--demangle", &elf_s], None, &[])?;
    let mut text_start: Option<u64> = None;
    let mut syms: Vec<(u64, String)> = Vec::new();
    for line in out.lines() {
        if line.len() < 20 {
            continue;
        }
        let addr_str = &line[..16];
        let bytes = line.as_bytes();
        if bytes[16] != b' ' || bytes[18] != b' ' {
            continue;
        }
        let kind = bytes[17] as char;
        if !matches!(kind, 't' | 'T' | 'w' | 'W') {
            continue;
        }
        let Ok(addr) = u64::from_str_radix(addr_str, 16) else {
            continue;
        };
        let name = strip_rust_hash(&line[19..]);
        if name == "__text_start" {
            text_start = Some(addr);
            continue;
        }
        if name.starts_with("__") || name.starts_with(".L") {
            continue;
        }
        syms.push((addr, name.to_string()));
    }
    let text_start = text_start.ok_or_else(|| "kernel symbol table: __text_start not found".to_string())?;
    let mut result = Vec::with_capacity(syms.len());
    let mut last = u64::MAX;
    for (addr, name) in syms {
        if addr < text_start || addr == last {
            continue;
        }
        result.push(KSym { off: (addr - text_start) as u32, name });
        last = addr;
    }
    Ok(result)
}

fn build_ksyms_blob(syms: &[KSym]) -> Vec<u8> {
    let mut strtab: Vec<u8> = Vec::new();
    let mut name_offs: Vec<u32> = Vec::with_capacity(syms.len());
    for s in syms {
        name_offs.push(strtab.len() as u32);
        strtab.extend_from_slice(s.name.as_bytes());
        strtab.push(0);
    }
    let mut out = Vec::with_capacity(12 + 8 * syms.len() + strtab.len());
    out.extend_from_slice(&0x4D59_534Bu32.to_le_bytes()); // 'KSYM'
    out.extend_from_slice(&(syms.len() as u32).to_le_bytes());
    out.extend_from_slice(&((12 + 8 * syms.len()) as u32).to_le_bytes());
    for (s, noff) in syms.iter().zip(name_offs.iter()) {
        out.extend_from_slice(&s.off.to_le_bytes());
        out.extend_from_slice(&noff.to_le_bytes());
    }
    out.extend_from_slice(&strtab);
    out
}
