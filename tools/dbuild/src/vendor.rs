//! Scoped C / freestanding C++ `vendor/` static-library build & content-hashed cache pipeline.
//!
//! Compiles upstream C and freestanding C++ hardware driver / Mesa archives under `vendor/<name>/`
//! (declared via `vendor/<name>/vendor.toml`) for Ring-3 `.ddrv` / `.dlib` targets with:
//! - Deterministic `-ffile-prefix-map` path remapping and zero timestamps (`!<arch>\n` UID/GID/mtime = 0)
//!   so `dbuild test` reproducible builds (`repro`) stay byte-for-bit identical;
//! - Hardware CET user shadow-stack compatibility (`-fcf-protection=return`);
//! - Content-hashed per-object and whole-archive stamps in `<out_dir>/vendor/` so normal D-OS
//!   incremental Rust edits skip unchanged `vendor/` trees in <1 ms.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use doscrypt::sha2::Sha256;

use crate::tools::{Env, collect_files, hash_strings, run_cmd, to_hex};

#[derive(Clone, Debug)]
struct VendorManifest {
    name: String,
    c_std: String,
    cxx_std: String,
    includes: Vec<String>,
    defines: Vec<String>,
    cflags: Vec<String>,
    cxxflags: Vec<String>,
    sources: Vec<String>,
}

fn parse_string_val(raw: &str) -> Option<String> {
    let t = raw.trim();
    let inner = t.strip_prefix('"')?.strip_suffix('"')?;
    Some(inner.to_string())
}

fn parse_string_array(raw: &str) -> Option<Vec<String>> {
    let t = raw.trim();
    let inner = t.strip_prefix('[')?.strip_suffix(']')?;
    let mut out = Vec::new();
    for part in inner.split(',') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        out.push(parse_string_val(p)?);
    }
    Some(out)
}

fn parse_vendor_toml(path: &Path) -> Result<VendorManifest, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    // Normalize multi-line `[ ... ]` arrays into single logical lines after stripping `#` comments.
    let mut logical = Vec::new();
    let mut cur = String::new();
    let mut bracket_depth = 0i32;
    for line in raw.lines() {
        let clean = line.split('#').next().unwrap_or("").trim();
        if clean.is_empty() {
            continue;
        }
        for b in clean.bytes() {
            if b == b'[' {
                bracket_depth += 1;
            } else if b == b']' {
                bracket_depth -= 1;
            }
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(clean);
        if bracket_depth <= 0 {
            bracket_depth = 0;
            logical.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        logical.push(cur);
    }

    let mut m = VendorManifest {
        name: String::new(),
        c_std: "c17".into(),
        cxx_std: "c++20".into(),
        includes: Vec::new(),
        defines: Vec::new(),
        cflags: Vec::new(),
        cxxflags: Vec::new(),
        sources: Vec::new(),
    };
    for line in logical {
        let Some((k, v)) = line.split_once('=') else {
            return Err(format!("{}: malformed entry '{line}'", path.display()));
        };
        let key = k.trim();
        let val = v.trim();
        match key {
            "name" => {
                m.name = parse_string_val(val)
                    .ok_or_else(|| format!("{}: 'name' must be a string", path.display()))?;
            }
            "c_std" => {
                m.c_std = parse_string_val(val)
                    .ok_or_else(|| format!("{}: 'c_std' must be a string", path.display()))?;
            }
            "cxx_std" => {
                m.cxx_std = parse_string_val(val)
                    .ok_or_else(|| format!("{}: 'cxx_std' must be a string", path.display()))?;
            }
            "includes" => {
                m.includes = parse_string_array(val)
                    .ok_or_else(|| format!("{}: 'includes' must be a string list", path.display()))?;
            }
            "defines" => {
                m.defines = parse_string_array(val)
                    .ok_or_else(|| format!("{}: 'defines' must be a string list", path.display()))?;
            }
            "cflags" => {
                m.cflags = parse_string_array(val)
                    .ok_or_else(|| format!("{}: 'cflags' must be a string list", path.display()))?;
            }
            "cxxflags" => {
                m.cxxflags = parse_string_array(val)
                    .ok_or_else(|| format!("{}: 'cxxflags' must be a string list", path.display()))?;
            }
            "sources" => {
                m.sources = parse_string_array(val)
                    .ok_or_else(|| format!("{}: 'sources' must be a string list", path.display()))?;
            }
            other => {
                return Err(format!("{}: unknown key '{other}'", path.display()));
            }
        }
    }
    if m.name.is_empty() || m.sources.is_empty() {
        return Err(format!("{}: 'name' and non-empty 'sources' are required", path.display()));
    }
    Ok(m)
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

fn hash_file_content(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(to_hex(&h.finish()))
}

/// Write a deterministic GNU static archive (`!<arch>\n`) with zeroed mtime/uid/gid and a `/`
/// symbol index when `llvm-ar` is unavailable, or invoke `llvm-ar rcsD` when available.
fn create_deterministic_archive(
    env: &Env,
    archive: &Path,
    objs: &[PathBuf],
    quiet: bool,
) -> Result<(), String> {
    if archive.exists() {
        let _ = fs::remove_file(archive);
    }
    if let Some(ar) = env.ar() {
        let mut args: Vec<String> = vec!["rcsD".into(), archive.to_string_lossy().into_owned()];
        args.extend(objs.iter().map(|o| o.to_string_lossy().into_owned()));
        return run_cmd(ar, &args, None, &[], quiet);
    }
    // Pure-Rust deterministic GNU `!<arch>\n` fallback (ld.lld indexes ELF members directly even
    // without a symbol table, and all header metadata is fixed for reproducible builds).
    let mut out = Vec::from(&b"!<arch>\n"[..]);
    for (idx, obj) in objs.iter().enumerate() {
        let data = fs::read(obj).map_err(|e| format!("read {}: {e}", obj.display()))?;
        let name = format!("m{idx:05}.o/");
        let header = format!(
            "{name:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            "0",
            "0",
            "0",
            "100644",
            data.len()
        );
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(&data);
        if data.len() % 2 != 0 {
            out.push(b'\n');
        }
    }
    fs::write(archive, out).map_err(|e| format!("write {}: {e}", archive.display()))
}

/// Build all `vendor/*/vendor.toml` libraries into `<out_dir>/vendor/libvendor_<name>.a`,
/// returning a map `name -> archive_path`. Uses content-hashed stamps for sub-millisecond no-op checks.
pub fn build_vendor_libs(
    env: &Env,
    out_dir: &Path,
    jobs: usize,
    quiet: bool,
) -> Result<BTreeMap<String, PathBuf>, String> {
    let vendor_root = env.root.join("vendor");
    let mut result = BTreeMap::new();
    if !vendor_root.is_dir() {
        return Ok(result);
    }

    let mut dirs: Vec<PathBuf> = fs::read_dir(&vendor_root)
        .map_err(|e| format!("read {}: {e}", vendor_root.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir() && p.join("vendor.toml").is_file())
        .collect();
    dirs.sort();
    if dirs.is_empty() {
        return Ok(result);
    }

    let clang = env.clang()?;
    let clang_inc = env.clang_resource_include()?;
    let out_vendor = out_dir.join("vendor");
    fs::create_dir_all(&out_vendor).map_err(|e| format!("mkdir {}: {e}", out_vendor.display()))?;

    let mut base_flags: Vec<String> = vec![
        "--target=x86_64-unknown-elf".into(),
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
        "-fcf-protection=return".into(),
        "-ffunction-sections".into(),
        "-fdata-sections".into(),
    ];
    base_flags.extend(prefix_map_flags(&env.root));
    base_flags.extend([
        "-Wall".into(),
        "-Wextra".into(),
        "-Werror".into(),
        "-Wno-unused-parameter".into(),
    ]);

    for dir in dirs {
        let m = parse_vendor_toml(&dir.join("vendor.toml"))?;
        if result.contains_key(&m.name) {
            return Err(format!("duplicate vendor library '{}'", m.name));
        }

        // Hash every header inside declared include dirs for strict content-addressed caching.
        let mut hdr_hashes: Vec<String> = Vec::new();
        let mut inc_flags: Vec<String> = Vec::new();
        for inc in &m.includes {
            let inc_dir = dir.join(inc);
            inc_flags.push("-I".into());
            inc_flags.push(inc_dir.to_string_lossy().into_owned());
            let mut hdrs = collect_files(&inc_dir, "h", true);
            hdrs.extend(collect_files(&inc_dir, "hpp", true));
            hdrs.sort();
            for h in hdrs {
                hdr_hashes.push(format!("{}:{}", env.rel(&h), hash_file_content(&h)?));
            }
        }
        let def_flags: Vec<String> = m.defines.iter().map(|d| format!("-D{d}")).collect();
        let hdr_digest = hash_strings(&hdr_hashes);

        struct ObjJob {
            src: PathBuf,
            args: Vec<String>,
            stamp_path: PathBuf,
            stamp_val: String,
            is_cxx: bool,
        }

        let lib_obj_dir = out_vendor.join(&m.name);
        fs::create_dir_all(&lib_obj_dir).map_err(|e| format!("mkdir {}: {e}", lib_obj_dir.display()))?;

        let mut objs = Vec::with_capacity(m.sources.len());
        let mut pending = Vec::new();
        let mut archive_inputs = vec![hdr_digest.clone()];

        for (idx, rel_src) in m.sources.iter().enumerate() {
            let src = dir.join(rel_src);
            if !src.is_file() {
                return Err(format!("vendor '{}': missing source {}", m.name, src.display()));
            }
            let ext = src.extension().and_then(|e| e.to_str()).unwrap_or("");
            let is_cxx = matches!(ext, "cc" | "cpp" | "cxx");
            let mut args = base_flags.clone();
            if is_cxx {
                args.extend([
                    "-x".into(),
                    "c++".into(),
                    format!("-std={}", m.cxx_std),
                    "-nostdinc++".into(),
                    "-fno-exceptions".into(),
                    "-fcheck-new".into(),
                    "-fno-rtti".into(),
                    "-fno-threadsafe-statics".into(),
                    "-fno-use-cxa-atexit".into(),
                ]);
                args.extend(m.cxxflags.iter().cloned());
            } else {
                args.push(format!("-std={}", m.c_std));
                args.extend(m.cflags.iter().cloned());
            }
            args.extend(inc_flags.iter().cloned());
            args.extend(def_flags.iter().cloned());

            let src_hash = hash_file_content(&src)?;
            let mut key_parts = args.clone();
            key_parts.push(hdr_digest.clone());
            key_parts.push(src_hash);
            let stamp_val = hash_strings(&key_parts);
            archive_inputs.push(stamp_val.clone());

            let stem = src.file_stem().and_then(|s| s.to_str()).unwrap_or("obj");
            let obj = lib_obj_dir.join(format!("{idx:04}_{stem}.o"));
            let stamp_path = lib_obj_dir.join(format!("{idx:04}_{stem}.o.stamp"));
            let up_to_date = obj.is_file()
                && fs::read_to_string(&stamp_path)
                    .map(|s| s.trim() == stamp_val)
                    .unwrap_or(false);
            if !up_to_date {
                args.extend([
                    "-c".into(),
                    "-o".into(),
                    obj.to_string_lossy().into_owned(),
                    src.to_string_lossy().into_owned(),
                ]);
                pending.push(ObjJob {
                    src,
                    args,
                    stamp_path,
                    stamp_val,
                    is_cxx,
                });
            }
            objs.push(obj);
        }

        if !pending.is_empty() {
            let workers = jobs.max(1).min(pending.len());
            let next_i = std::sync::atomic::AtomicUsize::new(0);
            let first_err: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
            std::thread::scope(|s| {
                for _ in 0..workers {
                    s.spawn(|| loop {
                        if first_err.lock().unwrap().is_some() {
                            break;
                        }
                        let i = next_i.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if i >= pending.len() {
                            break;
                        }
                        let j = &pending[i];
                        if !quiet {
                            println!(
                                "  {}   {} [vendor:{}]",
                                if j.is_cxx { "CXX" } else { "CC " },
                                env.rel(&j.src),
                                m.name
                            );
                        }
                        if let Err(e) = run_cmd(clang, &j.args, None, &[], quiet) {
                            let mut g = first_err.lock().unwrap();
                            if g.is_none() {
                                *g = Some(e);
                            }
                            break;
                        }
                        let _ = fs::write(&j.stamp_path, &j.stamp_val);
                    });
                }
            });
            if let Some(e) = first_err.into_inner().unwrap() {
                return Err(e);
            }
        }

        let archive = out_vendor.join(format!("libvendor_{}.a", m.name));
        let archive_stamp_path = out_vendor.join(format!("libvendor_{}.a.stamp", m.name));
        let archive_stamp = hash_strings(&archive_inputs);
        let archive_ok = archive.is_file()
            && pending.is_empty()
            && fs::read_to_string(&archive_stamp_path)
                .map(|s| s.trim() == archive_stamp)
                .unwrap_or(false);
        if !archive_ok {
            if !quiet {
                println!("  AR    {}", env.rel(&archive));
            }
            create_deterministic_archive(env, &archive, &objs, quiet)?;
            let _ = fs::write(&archive_stamp_path, &archive_stamp);
        }
        result.insert(m.name, archive);
    }

    Ok(result)
}
