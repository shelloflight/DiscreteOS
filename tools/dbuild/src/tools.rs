//! Cross-platform tool discovery, process execution, incremental build stamps, and signing keys.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use doscrypt::sha2::Sha256;

#[derive(Clone, Debug)]
pub struct MsvcTools {
    pub cl: PathBuf,
    pub link: PathBuf,
    pub lib: PathBuf,
    pub vc_root: PathBuf,
}

#[derive(Clone, Debug)]
pub struct WinSdk {
    pub include: Vec<PathBuf>,
    pub lib: Vec<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct Ovmf {
    pub code: PathBuf,
    pub vars: PathBuf,
}

#[derive(Clone, Debug)]
pub struct Bochs {
    pub exe: PathBuf,
    pub bios: PathBuf,
    pub vgabios: PathBuf,
}

#[derive(Clone, Debug)]
pub struct SigningKey {
    pub seed: PathBuf,
    pub public: String,
}

pub struct Env {
    pub root: PathBuf,
    pub build: PathBuf,
    pub rust_env: BTreeMap<String, String>,
    cargo: OnceLock<PathBuf>,
    clang: OnceLock<PathBuf>,
    clang_inc: OnceLock<PathBuf>,
    lld: OnceLock<PathBuf>,
    lld_link: OnceLock<PathBuf>,
    objcopy: OnceLock<PathBuf>,
    nm: OnceLock<PathBuf>,
    readobj: OnceLock<PathBuf>,
    ar: OnceLock<Option<PathBuf>>,
    dlltool: OnceLock<Option<PathBuf>>,
    nasm: OnceLock<PathBuf>,
    qemu: OnceLock<PathBuf>,
    ovmf: OnceLock<Ovmf>,
    bochs: OnceLock<Option<Bochs>>,
    msvc: OnceLock<Option<MsvcTools>>,
    winsdk: OnceLock<Option<WinSdk>>,
    host_cc: OnceLock<Option<PathBuf>>,
    seven_zip: OnceLock<Option<PathBuf>>,
    signing_key: OnceLock<SigningKey>,
}

impl Env {
    pub fn discover() -> Result<Self, String> {
        let root = find_repo_root()?;
        let build = root.join("build");
        let rust_env = detect_rust_env(&root);
        Ok(Self {
            root,
            build,
            rust_env,
            cargo: OnceLock::new(),
            clang: OnceLock::new(),
            clang_inc: OnceLock::new(),
            lld: OnceLock::new(),
            lld_link: OnceLock::new(),
            objcopy: OnceLock::new(),
            nm: OnceLock::new(),
            readobj: OnceLock::new(),
            ar: OnceLock::new(),
            dlltool: OnceLock::new(),
            nasm: OnceLock::new(),
            qemu: OnceLock::new(),
            ovmf: OnceLock::new(),
            bochs: OnceLock::new(),
            msvc: OnceLock::new(),
            winsdk: OnceLock::new(),
            host_cc: OnceLock::new(),
            seven_zip: OnceLock::new(),
            signing_key: OnceLock::new(),
        })
    }

    pub fn rel(&self, p: &Path) -> String {
        p.strip_prefix(&self.root)
            .unwrap_or(p)
            .to_string_lossy()
            .replace('\\', "/")
    }

    pub fn cargo(&self) -> Result<&Path, String> {
        if let Some(p) = self.cargo.get() {
            return Ok(p);
        }
        let found = find_in_path_or_env("cargo", self.rust_env.get("PATH").map(String::as_str))
            .ok_or_else(|| {
                "Rust toolchain (cargo) not found on PATH (or DOS_RUST_BOX / ../Devbox/boxes/rust)."
                    .to_string()
            })?;
        Ok(self.cargo.get_or_init(|| found))
    }

    pub fn rustc(&self) -> Result<PathBuf, String> {
        let cargo = self.cargo()?;
        let name = exe_name("rustc");
        if let Some(dir) = cargo.parent() {
            let p = dir.join(&name);
            if p.is_file() {
                return Ok(p);
            }
        }
        find_in_path("rustc").ok_or_else(|| "rustc not found".to_string())
    }

    pub fn clang(&self) -> Result<&Path, String> {
        if let Some(p) = self.clang.get() {
            return Ok(p);
        }
        let p = find_tool("clang", &llvm_fallbacks())?;
        Ok(self.clang.get_or_init(|| p))
    }

    pub fn clang_resource_include(&self) -> Result<&Path, String> {
        if let Some(p) = self.clang_inc.get() {
            return Ok(p);
        }
        let clang = self.clang()?;
        let out = run_capture(clang, &["-print-resource-dir"], None, &[])?;
        let inc = PathBuf::from(out.trim()).join("include");
        Ok(self.clang_inc.get_or_init(|| inc))
    }

    pub fn lld(&self) -> Result<&Path, String> {
        if let Some(p) = self.lld.get() {
            return Ok(p);
        }
        let p = find_tool("ld.lld", &llvm_fallbacks())?;
        Ok(self.lld.get_or_init(|| p))
    }

    pub fn lld_link(&self) -> Result<&Path, String> {
        if let Some(p) = self.lld_link.get() {
            return Ok(p);
        }
        let p = find_tool("lld-link", &llvm_fallbacks())?;
        Ok(self.lld_link.get_or_init(|| p))
    }

    pub fn objcopy(&self) -> Result<&Path, String> {
        if let Some(p) = self.objcopy.get() {
            return Ok(p);
        }
        let p = find_tool("llvm-objcopy", &llvm_fallbacks())?;
        Ok(self.objcopy.get_or_init(|| p))
    }

    pub fn nm(&self) -> Result<&Path, String> {
        if let Some(p) = self.nm.get() {
            return Ok(p);
        }
        let p = find_tool("llvm-nm", &llvm_fallbacks())?;
        Ok(self.nm.get_or_init(|| p))
    }

    pub fn readobj(&self) -> Result<&Path, String> {
        if let Some(p) = self.readobj.get() {
            return Ok(p);
        }
        let p = find_tool("llvm-readobj", &llvm_fallbacks())?;
        Ok(self.readobj.get_or_init(|| p))
    }

    pub fn ar(&self) -> Option<&Path> {
        self.ar
            .get_or_init(|| find_tool("llvm-ar", &llvm_fallbacks()).ok())
            .as_deref()
    }

    pub fn dlltool(&self) -> Option<&Path> {
        self.dlltool
            .get_or_init(|| find_tool("llvm-dlltool", &llvm_fallbacks()).ok())
            .as_deref()
    }

    pub fn nasm(&self) -> Result<&Path, String> {
        if let Some(p) = self.nasm.get() {
            return Ok(p);
        }
        let p = find_tool("nasm", &nasm_fallbacks())?;
        Ok(self.nasm.get_or_init(|| p))
    }

    pub fn qemu(&self) -> Result<&Path, String> {
        if let Some(p) = self.qemu.get() {
            return Ok(p);
        }
        let p = find_tool("qemu-system-x86_64", &qemu_fallbacks())?;
        Ok(self.qemu.get_or_init(|| p))
    }

    pub fn ovmf(&self) -> Result<&Ovmf, String> {
        if let Some(o) = self.ovmf.get() {
            return Ok(o);
        }
        let qemu = self.qemu()?;
        let mut dirs: Vec<PathBuf> = Vec::new();
        if let Ok(d) = env::var("DOS_OVMF_DIR")
            && !d.is_empty()
        {
            dirs.push(PathBuf::from(d));
        }
        if let Some(qdir) = qemu.parent() {
            dirs.push(qdir.join("share"));
            if let Some(parent) = qdir.parent() {
                dirs.push(parent.join("share/qemu"));
            }
        }
        #[cfg(not(windows))]
        {
            for d in [
                "/usr/share/OVMF",
                "/usr/share/edk2/x64",
                "/usr/share/edk2-ovmf/x64",
                "/usr/share/qemu",
            ] {
                dirs.push(PathBuf::from(d));
            }
        }
        let code_names = [
            "edk2-x86_64-code.fd",
            "OVMF_CODE.4m.fd",
            "OVMF_CODE_4M.fd",
            "OVMF_CODE.fd",
        ];
        let vars_names = [
            "edk2-x86_64-vars.fd",
            "edk2-i386-vars.fd",
            "OVMF_VARS.4m.fd",
            "OVMF_VARS_4M.fd",
            "OVMF_VARS.fd",
        ];
        for dir in &dirs {
            let code = code_names.iter().map(|n| dir.join(n)).find(|p| p.is_file());
            let vars = vars_names.iter().map(|n| dir.join(n)).find(|p| p.is_file());
            if let (Some(code), Some(vars)) = (code, vars) {
                return Ok(self.ovmf.get_or_init(|| Ovmf { code, vars }));
            }
        }
        Err("UEFI firmware (OVMF) not found; install edk2/ovmf or set DOS_OVMF_DIR.".into())
    }

    pub fn bochs(&self) -> Option<&Bochs> {
        self.bochs.get_or_init(detect_bochs).as_ref()
    }

    pub fn msvc(&self) -> Option<&MsvcTools> {
        self.msvc.get_or_init(detect_msvc).as_ref()
    }

    pub fn winsdk(&self) -> Option<&WinSdk> {
        self.winsdk.get_or_init(detect_winsdk).as_ref()
    }

    pub fn host_cc(&self) -> Option<&Path> {
        self.host_cc
            .get_or_init(|| {
                let p = self.rust_env.get("PATH").map(String::as_str);
                find_in_path_or_env("gcc", p)
                    .or_else(|| find_in_path_or_env("cc", p))
                    .or_else(|| find_in_path_or_env("clang", p))
                    .or_else(|| {
                        let cargo_home = self
                            .rust_env
                            .get("CARGO_HOME")
                            .cloned()
                            .or_else(|| env::var("CARGO_HOME").ok())?;
                        let parent = Path::new(&cargo_home).parent()?;
                        let g = parent.join("mingw64/bin").join(exe_name("gcc"));
                        g.is_file().then_some(g)
                    })
            })
            .as_deref()
    }

    pub fn seven_zip(&self) -> Option<&Path> {
        self.seven_zip
            .get_or_init(|| {
                find_in_path("7z").or_else(|| {
                    #[cfg(windows)]
                    {
                        for var in ["ProgramFiles", "ProgramFiles(x86)"] {
                            if let Ok(base) = env::var(var) {
                                let p = PathBuf::from(base).join("7-Zip").join("7z.exe");
                                if p.is_file() {
                                    return Some(p);
                                }
                            }
                        }
                    }
                    None
                })
            })
            .as_deref()
    }

    pub fn signing_key(&self) -> Result<&SigningKey, String> {
        if let Some(k) = self.signing_key.get() {
            return Ok(k);
        }
        let seed_path = match env::var("DOS_SIGNING_KEY") {
            Ok(v) if !v.is_empty() => PathBuf::from(v),
            _ => {
                let dir = self.build.join("keys");
                fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
                let seed = dir.join("dev-signing.seed");
                if !seed.is_file() {
                    let bytes = random_seed_32();
                    let tmp = dir.join(format!("dev-signing.seed.{}.tmp", std::process::id()));
                    fs::write(&tmp, bytes).map_err(|e| format!("write {}: {e}", tmp.display()))?;
                    if fs::rename(&tmp, &seed).is_err() {
                        let _ = fs::remove_file(&tmp);
                    } else {
                        println!(
                            "  KEY   new development signing key: {} (not committed; set DOS_SIGNING_KEY for a release key)",
                            self.rel(&seed)
                        );
                    }
                }
                seed
            }
        };
        let meta = fs::metadata(&seed_path)
            .map_err(|e| format!("signing key {}: {e}", seed_path.display()))?;
        if meta.len() != 32 {
            return Err(format!("signing key {} must be 32 bytes", seed_path.display()));
        }
        let public = crate::img::pubkey_hex(&seed_path)?;
        Ok(self.signing_key.get_or_init(|| SigningKey { seed: seed_path, public }))
    }

    pub fn cargo_env_pairs(&self) -> Vec<(String, String)> {
        self.rust_env.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }
}

pub fn exe_name(base: &str) -> String {
    if cfg!(windows) && !base.ends_with(".exe") {
        format!("{base}.exe")
    } else {
        base.to_string()
    }
}

fn find_repo_root() -> Result<PathBuf, String> {
    let mut dir = env::current_dir().map_err(|e| format!("cwd: {e}"))?;
    loop {
        if dir.join("kernel").is_dir() && dir.join("rust-toolchain.toml").is_file() {
            return Ok(dir);
        }
        if !dir.pop() {
            return Err("could not locate D-OS repository root (expected kernel/ and rust-toolchain.toml)".into());
        }
    }
}

fn detect_rust_env(root: &Path) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    if find_in_path("cargo").is_some() {
        return map;
    }
    let mut candidates = Vec::new();
    if let Ok(b) = env::var("DOS_RUST_BOX")
        && !b.is_empty()
    {
        candidates.push(PathBuf::from(b));
    }
    if let Some(parent) = root.parent() {
        candidates.push(parent.join("Devbox").join("boxes").join("rust"));
    }
    for box_dir in candidates {
        let cargo_bin = box_dir.join("cargo").join("bin");
        if cargo_bin.join(exe_name("cargo")).is_file() {
            let mingw_bin = box_dir.join("mingw64").join("bin");
            let sep = if cfg!(windows) { ";" } else { ":" };
            let cur_path = env::var("PATH").unwrap_or_default();
            let mut new_path = cargo_bin.to_string_lossy().into_owned();
            if mingw_bin.is_dir() {
                new_path.push_str(sep);
                new_path.push_str(&mingw_bin.to_string_lossy());
            }
            if !cur_path.is_empty() {
                new_path.push_str(sep);
                new_path.push_str(&cur_path);
            }
            map.insert("RUSTUP_HOME".into(), box_dir.join("rustup").to_string_lossy().into_owned());
            map.insert("CARGO_HOME".into(), box_dir.join("cargo").to_string_lossy().into_owned());
            map.insert("PATH".into(), new_path);
            break;
        }
    }
    map
}

pub fn find_in_path(name: &str) -> Option<PathBuf> {
    find_in_path_or_env(name, None)
}

fn find_in_path_or_env(name: &str, override_path: Option<&str>) -> Option<PathBuf> {
    let exe = exe_name(name);
    let path_str = match override_path {
        Some(p) => p.to_string(),
        None => env::var("PATH").ok()?,
    };
    for dir in env::split_paths(&path_str) {
        let p = dir.join(&exe);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

fn find_tool(name: &str, fallbacks: &[PathBuf]) -> Result<PathBuf, String> {
    if let Some(p) = find_in_path(name) {
        return Ok(p);
    }
    let exe = exe_name(name);
    for dir in fallbacks {
        let p = dir.join(&exe);
        if p.is_file() {
            return Ok(p);
        }
    }
    Err(format!("Required tool '{name}' not found. See docs/building.md for setup."))
}

fn llvm_fallbacks() -> Vec<PathBuf> {
    let mut v = Vec::new();
    #[cfg(windows)]
    if let Ok(pf) = env::var("ProgramFiles") {
        v.push(PathBuf::from(pf).join("LLVM").join("bin"));
    }
    #[cfg(not(windows))]
    {
        v.push(PathBuf::from("/usr/bin"));
        v.push(PathBuf::from("/usr/local/bin"));
    }
    v
}

fn nasm_fallbacks() -> Vec<PathBuf> {
    let mut v = Vec::new();
    #[cfg(windows)]
    {
        if let Ok(pf) = env::var("ProgramFiles") {
            v.push(PathBuf::from(pf).join("NASM"));
        }
        if let Ok(la) = env::var("LOCALAPPDATA") {
            v.push(PathBuf::from(la).join("bin").join("NASM"));
        }
    }
    #[cfg(not(windows))]
    v.push(PathBuf::from("/usr/bin"));
    v
}

fn qemu_fallbacks() -> Vec<PathBuf> {
    let mut v = Vec::new();
    #[cfg(windows)]
    if let Ok(pf) = env::var("ProgramFiles") {
        v.push(PathBuf::from(pf).join("qemu"));
    }
    #[cfg(not(windows))]
    v.push(PathBuf::from("/usr/bin"));
    v
}

fn detect_bochs() -> Option<Bochs> {
    let exe = find_in_path("bochs").or_else(|| {
        #[cfg(windows)]
        {
            let pf = PathBuf::from(env::var("ProgramFiles").ok()?);
            let mut dirs: Vec<PathBuf> = fs::read_dir(&pf)
                .ok()?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| {
                    p.is_dir()
                        && p.file_name()
                            .and_then(|n| n.to_str())
                            .is_some_and(|n| n.starts_with("Bochs-"))
                })
                .collect();
            dirs.sort();
            dirs.reverse();
            for d in dirs {
                let p = d.join("bochs.exe");
                if p.is_file() {
                    return Some(p);
                }
            }
        }
        None
    })?;
    let mut share_dirs = Vec::new();
    if let Some(parent) = exe.parent() {
        share_dirs.push(parent.to_path_buf());
        if let Some(gp) = parent.parent() {
            share_dirs.push(gp.join("share/bochs"));
        }
    }
    #[cfg(not(windows))]
    {
        share_dirs.push(PathBuf::from("/usr/share/bochs"));
        share_dirs.push(PathBuf::from("/usr/local/share/bochs"));
    }
    for d in share_dirs {
        let bios = d.join("BIOS-bochs-latest");
        let vgabios = d.join("VGABIOS-lgpl-latest.bin");
        if bios.is_file() && vgabios.is_file() {
            return Some(Bochs { exe, bios, vgabios });
        }
    }
    None
}

fn detect_msvc() -> Option<MsvcTools> {
    let dir = if let Ok(d) = env::var("DOS_MSVC_BIN")
        && !d.is_empty()
    {
        PathBuf::from(d)
    } else {
        #[cfg(windows)]
        {
            let pf86 = env::var("ProgramFiles(x86)").ok()?;
            let vswhere = PathBuf::from(pf86)
                .join("Microsoft Visual Studio")
                .join("Installer")
                .join("vswhere.exe");
            if !vswhere.is_file() {
                return None;
            }
            let out = run_capture(
                &vswhere,
                &[
                    "-latest",
                    "-products",
                    "*",
                    "-requires",
                    "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                    "-property",
                    "installationPath",
                ],
                None,
                &[],
            )
            .ok()?;
            let vs = out.trim();
            if vs.is_empty() {
                return None;
            }
            let msvc_root = PathBuf::from(vs).join("VC").join("Tools").join("MSVC");
            let mut versions: Vec<PathBuf> = fs::read_dir(&msvc_root)
                .ok()?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.is_dir())
                .collect();
            versions.sort_by_key(|p| parse_ver(p.file_name().and_then(|n| n.to_str()).unwrap_or("")));
            versions.last()?.join("bin").join("Hostx64").join("x64")
        }
        #[cfg(not(windows))]
        {
            return None;
        }
    };
    let cl = dir.join(exe_name("cl"));
    let link = dir.join(exe_name("link"));
    let lib = dir.join(exe_name("lib"));
    if !(cl.is_file() && link.is_file() && lib.is_file()) {
        return None;
    }
    let vc_root = dir.parent()?.parent()?.parent()?.to_path_buf();
    Some(MsvcTools { cl, link, lib, vc_root })
}

fn detect_winsdk() -> Option<WinSdk> {
    let mut roots = Vec::new();
    if let Ok(d) = env::var("DOS_WINSDK")
        && !d.is_empty()
    {
        roots.push(PathBuf::from(d));
    }
    #[cfg(windows)]
    if let Ok(pf86) = env::var("ProgramFiles(x86)") {
        roots.push(PathBuf::from(pf86).join("Windows Kits").join("10"));
    }
    for root in roots {
        let lib_dir = root.join("Lib");
        if !lib_dir.is_dir() {
            continue;
        }
        let mut vers: Vec<PathBuf> = fs::read_dir(&lib_dir)
            .ok()?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_dir() && p.join("ucrt").join("x64").join("libucrt.lib").is_file())
            .collect();
        vers.sort_by_key(|p| parse_ver(p.file_name().and_then(|n| n.to_str()).unwrap_or("")));
        if let Some(v) = vers.last() {
            let ver_name = v.file_name()?;
            let inc = root.join("Include").join(ver_name);
            return Some(WinSdk {
                include: vec![inc.join("ucrt"), inc.join("um"), inc.join("shared")],
                lib: vec![v.join("ucrt").join("x64"), v.join("um").join("x64")],
            });
        }
    }
    None
}

fn parse_ver(s: &str) -> Vec<u32> {
    s.split('.').map(|p| p.parse::<u32>().unwrap_or(0)).collect()
}

pub fn run_cmd(
    exe: &Path,
    args: &[String],
    cwd: Option<&Path>,
    extra_env: &[(String, String)],
    quiet: bool,
) -> Result<(), String> {
    let mut cmd = Command::new(exe);
    cmd.args(args);
    if let Some(d) = cwd {
        cmd.current_dir(d);
    }
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    if quiet {
        let out = cmd
            .output()
            .map_err(|e| format!("failed to run {}: {e}", exe.display()))?;
        if !out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(format!(
                "{} failed ({}):\n{}{}",
                exe.file_name().unwrap_or_default().to_string_lossy(),
                out.status,
                stdout,
                stderr
            ));
        }
    } else {
        let status = cmd
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .map_err(|e| format!("failed to run {}: {e}", exe.display()))?;
        if !status.success() {
            return Err(format!(
                "{} failed with {}",
                exe.file_name().unwrap_or_default().to_string_lossy(),
                status
            ));
        }
    }
    Ok(())
}

pub fn run_capture(
    exe: &Path,
    args: &[&str],
    cwd: Option<&Path>,
    extra_env: &[(String, String)],
) -> Result<String, String> {
    let mut cmd = Command::new(exe);
    cmd.args(args);
    if let Some(d) = cwd {
        cmd.current_dir(d);
    }
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let out = cmd
        .output()
        .map_err(|e| format!("failed to run {}: {e}", exe.display()))?;
    if !out.status.success() {
        return Err(format!(
            "{} failed ({}): {}{}",
            exe.file_name().unwrap_or_default().to_string_lossy(),
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn run_capture_all(
    exe: &Path,
    args: &[String],
    cwd: Option<&Path>,
    extra_env: &[(String, String)],
) -> Result<(bool, String), String> {
    let mut cmd = Command::new(exe);
    cmd.args(args);
    if let Some(d) = cwd {
        cmd.current_dir(d);
    }
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let out = cmd
        .output()
        .map_err(|e| format!("failed to run {}: {e}", exe.display()))?;
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok((out.status.success(), combined))
}

pub fn mtime_of(p: &Path) -> Option<SystemTime> {
    fs::metadata(p).ok()?.modified().ok()
}

pub fn newest_mtime(paths: &[PathBuf]) -> Option<SystemTime> {
    paths.iter().filter_map(|p| mtime_of(p)).max()
}

/// Returns true if `out` must be rebuilt because it is missing, any input is newer than `out`,
/// or the recorded flag/config stamp hash differs.
pub fn needs_rebuild(out: &Path, newest_input: Option<SystemTime>, stamp_key: &str) -> bool {
    let Some(out_mtime) = mtime_of(out) else {
        return true;
    };
    if let Some(in_mtime) = newest_input
        && in_mtime > out_mtime
    {
        return true;
    }
    let stamp = stamp_path(out);
    match fs::read_to_string(&stamp) {
        Ok(s) => s != stamp_key,
        Err(_) => true,
    }
}

pub fn write_stamp(out: &Path, stamp_key: &str) {
    let _ = fs::write(stamp_path(out), stamp_key);
}

fn stamp_path(out: &Path) -> PathBuf {
    let mut s = out.as_os_str().to_os_string();
    s.push(".stamp");
    PathBuf::from(s)
}

pub fn hash_strings(parts: &[String]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p.as_bytes());
        h.update(&[0]);
    }
    to_hex(&h.finish())
}

pub fn sha256_file(path: &Path) -> Result<String, String> {
    let data = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    Ok(to_hex(&doscrypt::sha2::sha256(&data)))
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn collect_files(dir: &Path, ext: &str, recursive: bool) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_files_rec(dir, ext, recursive, &mut out);
    out.sort();
    out
}

fn collect_files_rec(dir: &Path, ext: &str, recursive: bool, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    for entry in rd.filter_map(|e| e.ok()) {
        let p = entry.path();
        if p.is_dir() {
            if recursive
                && p.file_name().and_then(|n| n.to_str()) != Some("target")
                && p.file_name().and_then(|n| n.to_str()) != Some(".git")
            {
                collect_files_rec(&p, ext, true, out);
            }
        } else if p.extension().and_then(|e| e.to_str()) == Some(ext) {
            out.push(p);
        }
    }
}

/// 32 random bytes: reads /dev/urandom when present (Linux/Unix), else hashes OS-seeded RandomState.
pub fn random_seed_32() -> [u8; 32] {
    #[cfg(unix)]
    if let Ok(mut f) = fs::File::open("/dev/urandom") {
        use std::io::Read;
        let mut buf = [0u8; 32];
        if f.read_exact(&mut buf).is_ok() {
            return buf;
        }
    }
    use std::hash::{BuildHasher, Hasher};
    let mut h = Sha256::new();
    for i in 0..8u64 {
        let mut s = std::collections::hash_map::RandomState::new().build_hasher();
        s.write_u64(i);
        h.update(&s.finish().to_le_bytes());
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    h.update(&nanos.to_le_bytes());
    h.update(&std::process::id().to_le_bytes());
    h.finish()
}
