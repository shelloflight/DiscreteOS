//! `dbuild`: cross-platform (Windows & Linux) host build, test, image, and contributor CLI for D-OS.

mod build;
mod commit;
mod img;
mod qemu;
mod test;
mod tools;

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use build::{BuildOpts, build_image};
use commit::{CommitOpts, run_commit};
use qemu::{run_interactive, run_soak};
use test::run_test_suite;
use tools::Env;

fn print_help() {
    println!(
        "dbuild - Discrete Operating System build, test, image, and git tool (Windows & Linux)\n\
         \n\
         Usage:\n\
           dbuild [command] [options]\n\
         \n\
         Commands:\n\
           build        Assemble, compile, link, and sign build/discrete.img (default)\n\
           run          Build and boot discrete.img in QEMU (serial on this terminal)\n\
           debug        Build and boot QEMU paused with GDB stub on localhost:1234\n\
           test         Run the automated test suite (repro + QEMU/Bochs + host + static)\n\
           soak         Long randomized multi-core stress test (KTEST_SOAK)\n\
           bench        Build build/discrete-bench.img for bare-metal benchmarking\n\
           clean        Delete the build/ directory\n\
           img <cmd>    Disk image, signing, verification, and attestation utilities\n\
           commit       Interactive stage, message, DCO sign-off, commit, and push\n\
           help         Show this message\n\
         \n\
         Common options:\n\
           --uefi                  Boot with UEFI firmware (OVMF) (run, debug)\n\
           --smp <N>               Number of vCPUs, default 4 (run, debug, soak)\n\
           --iommu <intel|amd>     Emulated IOMMU, default intel (run, debug)\n\
           --audio <hda|virtio|usb|none>  Emulated audio device, default hda for run (run, debug)\n\
           --case <a,b,...>        Run only selected test cases (test)\n\
           --timeout <secs>        Min timeout per case, default 15 (test)\n\
           --no-repro              Skip the reproducible-build check (test)\n\
           --minutes <N>           Soak duration in minutes, default 10 (soak)\n\
           --out-dir <path>        Override build output directory (build)\n\
           --kernel-test <NAME>    Build KTEST_<NAME> variant (build)\n\
           --ubsan / --kasan       Enable sanitizer in C kernel (build)\n\
           --quiet                 Less build output\n\
         \n\
         Commit options:\n\
           -a, --all               Stage all changes without prompting\n\
           -m <subject>            Commit subject line\n\
           --body <text>           Commit body\n\
           --signoff / --no-signoff  Set DCO sign-off (-s) without prompting\n\
           --push / --no-push      Set push behavior without prompting\n\
           -y, --yes               Accept defaults non-interactively"
    );
}

fn run() -> Result<(), String> {
    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    if raw_args.first().is_some_and(|a| matches!(a.as_str(), "help" | "-h" | "--help")) {
        print_help();
        return Ok(());
    }

    let (cmd, rest): (&str, &[String]) = match raw_args.first() {
        None => ("build", &[]),
        Some(first) if first.starts_with('-') => ("build", &raw_args[..]),
        Some(first) => (first.as_str(), &raw_args[1..]),
    };

    if cmd == "img" {
        return img::cli(rest);
    }

    let env = Env::discover()?;
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);

    match cmd {
        "clean" => {
            if env.build.exists() {
                fs::remove_dir_all(&env.build)
                    .map_err(|e| format!("remove {}: {e}", env.build.display()))?;
            }
            println!("Cleaned.");
            Ok(())
        }
        "build" => {
            let mut out_dir = env.build.clone();
            let mut kernel_test: Option<String> = None;
            let mut ubsan = false;
            let mut kasan = false;
            let mut quiet = false;
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--out-dir" | "-OutDir" => {
                        i += 1;
                        out_dir = PathBuf::from(rest.get(i).ok_or("--out-dir needs a value")?);
                    }
                    "--kernel-test" | "-KernelTest" => {
                        i += 1;
                        kernel_test = Some(rest.get(i).ok_or("--kernel-test needs a value")?.clone());
                    }
                    "--ubsan" | "-Ubsan" => ubsan = true,
                    "--kasan" | "-Kasan" => kasan = true,
                    "--quiet" | "-Quiet" => quiet = true,
                    other => return Err(format!("unknown build option '{other}'")),
                }
                i += 1;
            }
            build_image(
                &env,
                &BuildOpts {
                    out_dir,
                    kernel_test,
                    ubsan,
                    kasan,
                    quiet,
                    shared: None,
                    jobs: cpus,
                },
            )?;
            Ok(())
        }
        "run" | "debug" => {
            let mut smp = 4u32;
            let mut uefi = false;
            let mut iommu = "intel".to_string();
            let mut audio = if cmd == "debug" { "none".to_string() } else { "hda".to_string() };
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--smp" | "-Smp" => {
                        i += 1;
                        smp = rest
                            .get(i)
                            .ok_or("--smp needs a number")?
                            .parse()
                            .map_err(|_| "--smp must be a positive integer")?;
                    }
                    "--uefi" | "-Uefi" => uefi = true,
                    "--iommu" | "-Iommu" => {
                        i += 1;
                        iommu = rest.get(i).ok_or("--iommu needs intel or amd")?.clone();
                        if iommu != "intel" && iommu != "amd" {
                            return Err("--iommu must be 'intel' or 'amd'".into());
                        }
                    }
                    "--audio" | "-Audio" => {
                        i += 1;
                        audio = rest
                            .get(i)
                            .ok_or("--audio needs hda, virtio, usb, or none")?
                            .clone();
                        if !matches!(audio.as_str(), "hda" | "virtio" | "usb" | "none") {
                            return Err("--audio must be 'hda', 'virtio', 'usb', or 'none'".into());
                        }
                    }
                    other => return Err(format!("unknown {cmd} option '{other}'")),
                }
                i += 1;
            }
            let res = build_image(
                &env,
                &BuildOpts {
                    out_dir: env.build.clone(),
                    kernel_test: None,
                    ubsan: false,
                    kasan: false,
                    quiet: false,
                    shared: None,
                    jobs: cpus,
                },
            )?;
            run_interactive(&env, &res.image, smp, uefi, &iommu, &audio, cmd == "debug")
        }
        "test" => {
            let mut cases: Vec<String> = Vec::new();
            let mut timeout = 15u64;
            let mut no_repro = false;
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--case" | "-Case" => {
                        i += 1;
                        let first = rest.get(i).ok_or("--case needs a case name")?;
                        for part in first.split(',').filter(|s| !s.is_empty()) {
                            cases.push(part.to_string());
                        }
                        // PowerShell splits unquoted `a,b,c` into separate array elements.
                        while let Some(next) = rest.get(i + 1)
                            && !next.starts_with('-')
                        {
                            i += 1;
                            for part in next.split(',').filter(|s| !s.is_empty()) {
                                cases.push(part.to_string());
                            }
                        }
                    }
                    "--timeout" | "-TestTimeout" => {
                        i += 1;
                        timeout = rest
                            .get(i)
                            .ok_or("--timeout needs seconds")?
                            .parse()
                            .map_err(|_| "--timeout must be a number")?;
                    }
                    "--no-repro" | "-NoRepro" => no_repro = true,
                    other => return Err(format!("unknown test option '{other}'")),
                }
                i += 1;
            }
            run_test_suite(&env, &cases, timeout, no_repro)
        }
        "soak" => {
            let mut smp = 4u32;
            let mut minutes = 10u64;
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--smp" | "-Smp" => {
                        i += 1;
                        smp = rest
                            .get(i)
                            .ok_or("--smp needs a number")?
                            .parse()
                            .map_err(|_| "--smp must be a number")?;
                    }
                    "--minutes" | "-Minutes" => {
                        i += 1;
                        minutes = rest
                            .get(i)
                            .ok_or("--minutes needs a number")?
                            .parse()
                            .map_err(|_| "--minutes must be a number")?;
                    }
                    other => return Err(format!("unknown soak option '{other}'")),
                }
                i += 1;
            }
            let res = build_image(
                &env,
                &BuildOpts {
                    out_dir: env.build.join("soak"),
                    kernel_test: Some("SOAK".into()),
                    ubsan: false,
                    kasan: false,
                    quiet: true,
                    shared: None,
                    jobs: cpus,
                },
            )?;
            run_soak(&env, &res.image, smp, minutes)
        }
        "bench" => {
            let mut quiet = false;
            for a in rest {
                match a.as_str() {
                    "--quiet" | "-Quiet" => quiet = true,
                    other => return Err(format!("unknown bench option '{other}'")),
                }
            }
            let res = build_image(
                &env,
                &BuildOpts {
                    out_dir: env.build.join("bench"),
                    kernel_test: Some("HWBENCH".into()),
                    ubsan: false,
                    kasan: false,
                    quiet,
                    shared: None,
                    jobs: cpus,
                },
            )?;
            let dst = env.build.join("discrete-bench.img");
            fs::copy(&res.image, &dst).map_err(|e| format!("copy bench image: {e}"))?;
            println!(
                "Hardware benchmark image: {} (write it to a USB stick like discrete.img; disks are only read)",
                env.rel(&dst)
            );
            Ok(())
        }
        "commit" => {
            let mut opts = CommitOpts::default();
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "-a" | "--all" => opts.all = true,
                    "-m" | "--message" => {
                        i += 1;
                        opts.message = Some(rest.get(i).ok_or("-m needs a message")?.clone());
                    }
                    "--body" => {
                        i += 1;
                        opts.body = Some(rest.get(i).ok_or("--body needs text")?.clone());
                    }
                    "--signoff" | "-s" => opts.signoff = Some(true),
                    "--no-signoff" => opts.signoff = Some(false),
                    "--push" => opts.push = Some(true),
                    "--no-push" => opts.push = Some(false),
                    "-y" | "--yes" => opts.yes = true,
                    other => return Err(format!("unknown commit option '{other}'")),
                }
                i += 1;
            }
            run_commit(&env, &opts)
        }
        other => Err(format!("unknown command '{other}' (run `dbuild help`)")),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("dbuild: {e}");
            ExitCode::FAILURE
        }
    }
}
