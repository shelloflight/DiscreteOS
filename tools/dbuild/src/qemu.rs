//! QEMU and Bochs orchestration: `run`, `debug`, `soak`, and headless serial log capture
//! with monitor key injection (`sendkey`, `!cmd`, `~ms`) and serial input (`kdb`).

use std::fs;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::img;
use crate::tools::Env;

#[derive(Clone, Debug)]
pub struct QemuOpts<'a> {
    pub image: &'a Path,
    pub cpus: u32,
    pub cpu_model: &'a str,
    pub devices: bool,
    pub disk_dir: &'a Path,
    pub uefi: bool,
    pub iommu: &'a str,
    pub extra: &'a [String],
    pub must_exit: bool,
}

pub struct CaptureResult {
    pub log: String,
    pub seconds: f64,
    pub exited: bool,
}

pub fn get_test_disk(env: &Env) -> Result<PathBuf, String> {
    let path = env.build.join("disk2.img");
    if !path.is_file() {
        fs::create_dir_all(&env.build).map_err(|e| e.to_string())?;
        let mut d = vec![0u8; 1024 * 1024];
        for sec in 0..2048usize {
            let b = (sec * 13) % 256;
            for j in 0..512usize {
                d[sec * 512 + j] = ((b + j) % 256) as u8;
            }
        }
        fs::write(&path, &d).map_err(|e| format!("write disk2.img: {e}"))?;
    }
    Ok(path)
}

pub fn get_storage_disks(env: &Env, dir: &Path) -> Result<(PathBuf, PathBuf), String> {
    let base = env.build.join("disks").join("base2");
    fs::create_dir_all(&base).map_err(|e| e.to_string())?;
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;

    let base_sata = base.join("sata.img");
    if !base_sata.is_file() {
        img::make_sata(&base_sata)?;
    }
    let base_nvme = base.join("nvme.img");
    if !base_nvme.is_file() {
        img::make_nvme(&base_nvme)?;
    }

    let sata = dir.join("sata.img");
    if !sata.is_file() {
        fs::copy(&base_sata, &sata).map_err(|e| format!("copy sata.img: {e}"))?;
    }
    let nvme = dir.join("nvme.img");
    if !nvme.is_file() {
        fs::copy(&base_nvme, &nvme).map_err(|e| format!("copy nvme.img: {e}"))?;
    }
    Ok((sata, nvme))
}

pub fn many_device_args(count: usize) -> Vec<String> {
    let mut a = Vec::with_capacity(count * 2);
    for i in 0..count {
        let slot = 8 + (i / 8);
        let fn_idx = i % 8;
        let mf = if fn_idx == 0 { ",multifunction=on" } else { "" };
        a.push("-device".into());
        a.push(format!(
            "pcie-root-port,id=rp{i},bus=pcie.0,chassis={},slot={},addr=0x{slot:x}.{fn_idx}{mf}",
            i + 1,
            i + 1
        ));
    }
    a
}

pub fn convert_to_qemu_keys(lines: &[&str], pause_ms: u64) -> Vec<String> {
    let mut keys = Vec::new();
    for &raw in lines {
        if let Some(rest) = raw.strip_prefix('@') {
            keys.push(rest.to_string());
            continue;
        }
        let (line, tab) = match raw.strip_suffix("<tab>") {
            Some(l) => (l, true),
            None => (raw, false),
        };
        for ch in line.chars() {
            let mapped = match ch {
                ' ' => "spc".to_string(),
                '/' => "slash".to_string(),
                '.' => "dot".to_string(),
                '-' => "minus".to_string(),
                '|' => "shift-backslash".to_string(),
                '>' => "shift-dot".to_string(),
                '<' => "shift-comma".to_string(),
                '=' => "equal".to_string(),
                '_' => "shift-minus".to_string(),
                ':' => "shift-semicolon".to_string(),
                '"' => "shift-apostrophe".to_string(),
                '*' => "shift-8".to_string(),
                c if c.is_ascii_uppercase() => format!("shift-{}", c.to_ascii_lowercase()),
                c => c.to_string(),
            };
            keys.push(mapped);
        }
        if tab {
            keys.push("tab".into());
            keys.push("~400".into());
        }
        keys.push("ret".into());
        keys.push(format!("~{pause_ms}"));
    }
    keys
}

pub fn build_qemu_args(env: &Env, opts: &QemuOpts<'_>) -> Result<Vec<String>, String> {
    let dev = if opts.iommu == "amd" {
        "amd-iommu,dma-remap=on,intremap=on"
    } else {
        "intel-iommu,intremap=on,eim=on"
    };
    let has_net = opts.extra.iter().any(|x| x == "-netdev");
    let mut a = vec![
        "-machine".into(),
        "q35".into(),
        "-device".into(),
        dev.into(),
    ];
    if !has_net {
        a.extend(["-nic".into(), "none".into()]);
    }
    a.extend([
        "-drive".into(),
        format!("format=raw,file={},index=0,media=disk", opts.image.display()),
        "-cpu".into(),
        opts.cpu_model.into(),
        "-smp".into(),
        opts.cpus.to_string(),
        "-m".into(),
        "256M".into(),
        "-no-reboot".into(),
    ]);
    if !opts.must_exit {
        a.push("-no-shutdown".into());
    }
    if opts.uefi {
        let fw = env.ovmf()?;
        fs::create_dir_all(opts.disk_dir).map_err(|e| e.to_string())?;
        let vars = opts.disk_dir.join("ovmf-vars.fd");
        fs::copy(&fw.vars, &vars).map_err(|e| format!("copy ovmf vars: {e}"))?;
        a.push("-drive".into());
        a.push(format!("if=pflash,format=raw,unit=0,readonly=on,file={}", fw.code.display()));
        a.push("-drive".into());
        a.push(format!("if=pflash,format=raw,unit=1,file={}", vars.display()));
    }
    if opts.devices {
        let disk = get_test_disk(env)?;
        a.extend([
            "-drive".into(),
            format!("if=none,id=disk2,format=raw,file={}", disk.display()),
            "-device".into(),
            "virtio-blk-pci,drive=disk2,disable-legacy=on,iommu_platform=on".into(),
            "-device".into(),
            "virtio-keyboard-pci,disable-legacy=on,iommu_platform=on".into(),
        ]);
        let (sata, nvme) = get_storage_disks(env, opts.disk_dir)?;
        a.extend([
            "-drive".into(),
            format!("if=none,id=sata1,format=raw,file={}", sata.display()),
            "-device".into(),
            "ide-hd,drive=sata1,bus=ide.1".into(),
            "-drive".into(),
            format!("if=none,id=nvm0,format=raw,file={}", nvme.display()),
            "-device".into(),
            "nvme,serial=DOS0,drive=nvm0".into(),
        ]);
    }
    a.extend(opts.extra.iter().cloned());
    Ok(a)
}

fn free_tcp_port() -> Result<u16, String> {
    let l = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind port: {e}"))?;
    let port = l.local_addr().map_err(|e| e.to_string())?.port();
    drop(l);
    Ok(port)
}

fn connect_retry(port: u16) -> Result<TcpStream, String> {
    for _ in 0..20 {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
            return Ok(s);
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(format!("cannot connect to QEMU TCP port {port}"))
}

fn send_qemu_keys(port: u16, keys: &[String]) -> Result<(), String> {
    let mut s = connect_retry(port)?;
    for k in keys {
        if let Some(cmd) = k.strip_prefix('!') {
            writeln!(s, "{cmd}").map_err(|e| e.to_string())?;
            s.flush().map_err(|e| e.to_string())?;
        } else if let Some(ms_str) = k.strip_prefix('~') {
            let ms = ms_str.parse::<u64>().unwrap_or(100);
            thread::sleep(Duration::from_millis(ms));
        } else {
            writeln!(s, "sendkey {k}").map_err(|e| e.to_string())?;
            s.flush().map_err(|e| e.to_string())?;
        }
        thread::sleep(Duration::from_millis(60));
    }
    Ok(())
}

fn send_serial_lines(port: u16, lines: &[String]) -> Result<(), String> {
    let mut s = connect_retry(port)?;
    for l in lines {
        write!(s, "{l}\r").map_err(|e| e.to_string())?;
        s.flush().map_err(|e| e.to_string())?;
        thread::sleep(Duration::from_millis(400));
    }
    thread::sleep(Duration::from_millis(300));
    Ok(())
}

fn read_log(path: &Path) -> String {
    match fs::read(path) {
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        Err(_) => String::new(),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn qemu_capture(
    env: &Env,
    opts: &QemuOpts<'_>,
    log_path: &Path,
    expect: &[String],
    forbid: &[String],
    timeout_secs: u64,
    keys: &[String],
    keys_after: &str,
    serial: &[String],
    serial_after: &str,
) -> Result<CaptureResult, String> {
    let qemu = env.qemu()?;
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let _ = fs::remove_file(log_path);

    let mut qargs = build_qemu_args(env, opts)?;
    qargs.extend(["-display".into(), "none".into()]);

    let mut ser_port = 0u16;
    if !serial.is_empty() {
        ser_port = free_tcp_port()?;
        qargs.extend([
            "-chardev".into(),
            format!(
                "socket,id=ser0,host=127.0.0.1,port={ser_port},server=on,wait=off,logfile={}",
                log_path.display()
            ),
            "-serial".into(),
            "chardev:ser0".into(),
        ]);
    } else {
        qargs.extend(["-serial".into(), format!("file:{}", log_path.display())]);
    }

    let mut mon_port = 0u16;
    if !keys.is_empty() {
        mon_port = free_tcp_port()?;
        qargs.extend([
            "-monitor".into(),
            format!("tcp:127.0.0.1:{mon_port},server,nowait"),
        ]);
    }

    let mut child = Command::new(qemu)
        .args(&qargs)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn qemu: {e}"))?;

    let start = Instant::now();
    let timeout = Duration::from_secs(timeout_secs);
    let mut keys_sent = false;
    let mut serial_sent = false;
    let mut bad = false;

    while start.elapsed() < timeout {
        if child.try_wait().map_err(|e| e.to_string())?.is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
        let out = read_log(log_path);
        if mon_port != 0 && !keys_sent && out.contains(keys_after) {
            let _ = send_qemu_keys(mon_port, keys);
            keys_sent = true;
            continue;
        }
        if ser_port != 0 && !serial_sent && out.contains(serial_after) {
            let _ = send_serial_lines(ser_port, serial);
            serial_sent = true;
            continue;
        }
        let done = expect.iter().all(|e| out.contains(e.as_str()));
        bad = forbid.iter().any(|f| out.contains(f.as_str()));
        if done || bad {
            thread::sleep(Duration::from_millis(200));
            break;
        }
    }

    if opts.must_exit && !bad {
        let deadline = start.elapsed() + Duration::from_secs(5);
        while start.elapsed() < deadline {
            if child.try_wait().map_err(|e| e.to_string())?.is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    let exited = child.try_wait().map_err(|e| e.to_string())?.is_some();
    if !exited {
        let _ = child.kill();
    }
    let _ = child.wait();

    Ok(CaptureResult {
        log: read_log(log_path),
        seconds: start.elapsed().as_secs_f64(),
        exited,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn bochs_capture(
    env: &Env,
    image: &Path,
    log_path: &Path,
    expect: &[String],
    forbid: &[String],
    timeout_secs: u64,
    cpu_model: &str,
    strict_msr: bool,
) -> Result<Option<CaptureResult>, String> {
    let Some(bochs) = env.bochs() else {
        return Ok(None);
    };
    let dir = log_path
        .parent()
        .ok_or_else(|| "bochs log has no parent dir".to_string())?;
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let disk = dir.join("bochs-disk.img");
    fs::copy(image, &disk).map_err(|e| format!("copy bochs disk: {e}"))?;
    let lock_file = PathBuf::from(format!("{}.lock", disk.display()));
    let _ = fs::remove_file(&lock_file);
    let _ = fs::remove_file(log_path);

    let rc = dir.join("bochsrc.txt");
    let rc_text = format!(
        "megs: 512\n\
         cpu: model={cpu_model}, count=1, ips=200000000, ignore_bad_msrs={}\n\
         romimage: file=\"{}\"\n\
         vgaromimage: file=\"{}\"\n\
         ata0-master: type=disk, path=\"{}\", mode=flat\n\
         boot: disk\n\
         com1: enabled=1, mode=file, dev=\"{}\"\n\
         display_library: nogui\n\
         log: \"{}\"\n\
         panic: action=fatal\n\
         error: action=report\n\
         info: action=ignore\n\
         clock: sync=none, time0=local\n",
        if strict_msr { 0 } else { 1 },
        bochs.bios.display(),
        bochs.vgabios.display(),
        disk.display(),
        log_path.display(),
        dir.join("bochs.log").display()
    );
    fs::write(&rc, rc_text).map_err(|e| format!("write bochsrc: {e}"))?;

    let stdout_f = fs::File::create(dir.join("bochs-out.txt")).map_err(|e| e.to_string())?;
    let stderr_f = fs::File::create(dir.join("bochs-err.txt")).map_err(|e| e.to_string())?;
    let mut child = Command::new(&bochs.exe)
        .args(["-q", "-f"])
        .arg(&rc)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_f))
        .stderr(Stdio::from(stderr_f))
        .spawn()
        .map_err(|e| format!("spawn bochs: {e}"))?;

    let start = Instant::now();
    let timeout = Duration::from_secs(timeout_secs);
    while start.elapsed() < timeout {
        if child.try_wait().map_err(|e| e.to_string())?.is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(500));
        let out = read_log(log_path);
        let done = expect.iter().all(|e| out.contains(e.as_str()));
        let bad = forbid.iter().any(|f| out.contains(f.as_str()));
        if done || bad {
            thread::sleep(Duration::from_millis(500));
            break;
        }
    }

    if child.try_wait().map_err(|e| e.to_string())?.is_none() {
        let _ = child.kill();
    }
    let _ = child.wait();
    let _ = fs::remove_file(&lock_file);

    Ok(Some(CaptureResult {
        log: read_log(log_path),
        seconds: start.elapsed().as_secs_f64(),
        exited: true,
    }))
}

fn detect_host_audiodev(qemu: &Path) -> &'static str {
    let preferred: &[&str] = if cfg!(windows) {
        &["sdl", "dsound", "none"]
    } else if cfg!(target_os = "macos") {
        &["coreaudio", "sdl", "none"]
    } else {
        &["pipewire", "pa", "alsa", "sdl", "none"]
    };
    let out = match Command::new(qemu).args(["-audiodev", "help"]).output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
        Err(_) => return "none",
    };
    let avail: Vec<&str> = out.lines().map(str::trim).collect();
    for &drv in preferred {
        if avail.contains(&drv) {
            return drv;
        }
    }
    "none"
}

#[allow(clippy::too_many_arguments)]
pub fn run_interactive(
    env: &Env,
    image: &Path,
    smp: u32,
    uefi: bool,
    iommu: &str,
    audio: &str,
    net: &str,
    gpu: &str,
    debug: bool,
) -> Result<(), String> {
    let qemu = env.qemu()?;
    let mut extra: Vec<String> = Vec::new();
    if audio != "none" {
        let host_drv = detect_host_audiodev(qemu);
        extra.extend(["-audiodev".into(), format!("{host_drv},id=snd0")]);
        match audio {
            "hda" => extra.extend([
                "-device".into(),
                "ich9-intel-hda".into(),
                "-device".into(),
                "hda-duplex,audiodev=snd0".into(),
            ]),
            "virtio" => extra.extend([
                "-device".into(),
                "virtio-sound-pci,audiodev=snd0,iommu_platform=on".into(),
            ]),
            "usb" => extra.extend([
                "-device".into(),
                "qemu-xhci,id=xhci".into(),
                "-device".into(),
                "usb-audio,bus=xhci.0,audiodev=snd0".into(),
            ]),
            _ => {}
        }
    }
    if net != "none" {
        extra.extend(["-netdev".into(), "user,id=net0".into()]);
        match net {
            "virtio" => extra.extend([
                "-device".into(),
                "virtio-net-pci,netdev=net0,disable-legacy=on,iommu_platform=on".into(),
            ]),
            "e1000e" => extra.extend(["-device".into(), "e1000e,netdev=net0".into()]),
            _ => {}
        }
    }
    match gpu {
        "virtio" => extra.extend([
            "-device".into(),
            "virtio-gpu-pci,disable-legacy=on,iommu_platform=on,edid=on".into(),
        ]),
        "virtio-vga" => extra.extend([
            "-vga".into(),
            "none".into(),
            "-device".into(),
            "virtio-vga,disable-legacy=on,iommu_platform=on,edid=on".into(),
        ]),
        "none" => extra.extend(["-vga".into(), "none".into()]),
        _ => {}
    }
    let opts = QemuOpts {
        image,
        cpus: smp,
        cpu_model: "max",
        devices: !debug,
        disk_dir: &env.build,
        uefi,
        iommu,
        extra: &extra,
        must_exit: false,
    };
    let mut qargs = build_qemu_args(env, &opts)?;
    qargs.extend(["-serial".into(), "stdio".into()]);
    if debug {
        println!("QEMU paused; GDB stub on localhost:1234 (target remote :1234). Symbols: build/kernel.elf");
        qargs.extend([
            "-s".into(),
            "-S".into(),
            "-d".into(),
            "int,cpu_reset".into(),
            "-D".into(),
            env.build.join("qemu.log").to_string_lossy().into_owned(),
        ]);
    }
    let status = Command::new(qemu)
        .args(&qargs)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| format!("run qemu: {e}"))?;
    if !status.success() {
        return Err(format!("qemu exited with {status}"));
    }
    Ok(())
}

pub fn run_soak(env: &Env, image: &Path, smp: u32, minutes: u64) -> Result<(), String> {
    let qemu = env.qemu()?;
    let out_dir = image.parent().unwrap_or(&env.build);
    let log_path = out_dir.join("serial-soak-long.log");
    let _ = fs::remove_file(&log_path);

    let opts = QemuOpts {
        image,
        cpus: smp,
        cpu_model: "max",
        devices: false,
        disk_dir: out_dir,
        uefi: false,
        iommu: "intel",
        extra: &[],
        must_exit: false,
    };
    let mut qargs = build_qemu_args(env, &opts)?;
    qargs.extend([
        "-display".into(),
        "none".into(),
        "-serial".into(),
        format!("file:{}", log_path.display()),
    ]);

    let mut child = Command::new(qemu)
        .args(&qargs)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn qemu: {e}"))?;

    println!("Soak: {smp} CPUs for {minutes} min (log: {})", env.rel(&log_path));
    let start = Instant::now();
    let total = Duration::from_secs(minutes * 60);
    let mut last_round = 0u64;
    let mut last_progress = 0.0f64;
    let mut failure: Option<&str> = None;

    while start.elapsed() < total {
        thread::sleep(Duration::from_secs(2));
        let out = read_log(&log_path);
        if child.try_wait().map_err(|e| e.to_string())?.is_some() {
            failure = Some("QEMU exited");
            break;
        }
        if out.contains("KERNEL PANIC") || out.contains("SOAK FAIL") {
            failure = Some("panic or failed round");
            break;
        }
        if let Some(round) = parse_last_soak_round(&out)
            && round != last_round
        {
            last_round = round;
            last_progress = start.elapsed().as_secs_f64();
            if round.is_multiple_of(30) {
                println!("  {:.1} min: round {round}", start.elapsed().as_secs_f64() / 60.0);
            }
        }
        if start.elapsed().as_secs_f64() - last_progress.max(20.0) > 60.0 {
            failure = Some("no progress for 60 s (hang?)");
            break;
        }
    }

    if child.try_wait().map_err(|e| e.to_string())?.is_none() {
        let _ = child.kill();
    }
    let _ = child.wait();

    let out = read_log(&log_path);
    if let Some(reason) = failure.or_else(|| (last_round < 1).then_some("no rounds completed")) {
        let lines: Vec<&str> = out.lines().collect();
        let tail = &lines[lines.len().saturating_sub(25)..];
        for l in tail {
            println!("{l}");
        }
        return Err(format!(
            "SOAK FAILED after {:.1} min, round {last_round}: {reason}",
            start.elapsed().as_secs_f64() / 60.0
        ));
    }
    if let Some(last_line) = out.lines().rfind(|l| l.contains("SOAK round")) {
        println!("{last_line}");
    }
    println!(
        "SOAK PASSED: {last_round} rounds in {:.1} min on {smp} CPUs",
        start.elapsed().as_secs_f64() / 60.0
    );
    Ok(())
}

fn parse_last_soak_round(out: &str) -> Option<u64> {
    for line in out.lines().rev() {
        if let Some(rest) = line.split("SOAK round ").nth(1)
            && let Some(num) = rest.strip_suffix(" OK").or_else(|| rest.split_whitespace().next())
            && let Ok(n) = num.parse::<u64>()
        {
            return Some(n);
        }
    }
    None
}
