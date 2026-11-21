//! Automated test suite: reproducible build check, parallel KTEST variant builds,
//! QEMU/Bochs boot tests, post-boot host verifications, host crate tests, static analysis,
//! and `build/test-report.md` generation.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::build::{BuildOpts, build_image, build_shared};
use crate::img::{self, KERNEL_LBA, SECTOR_SIZE};
use crate::nettest::NetTestServer;
use crate::qemu::{
    QemuOpts, bochs_capture, convert_to_qemu_keys, get_test_disk, many_device_args, qemu_capture,
};
use crate::tools::{
    Env, collect_files, exe_name, find_in_path, random_seed_32, run_capture, run_capture_all,
    run_cmd, sha256_file, to_hex,
};

#[derive(Clone, Copy)]
enum PostCheck {
    DisksUnchanged,
    StorageImages,
    AttestReport,
    UsbProbedOnce,
    UsbDiskUnchanged,
    UsbPlugOnce,
    TimeReboot,
    TimeRebootUefi,
    ServicesOrder,
    KaslrReboots,
    AudioWav(u32),
}

#[derive(Clone, Copy)]
enum HostTest {
    Dosfs,
    Crypto,
    Manifest,
    Audio,
    Net,
    Gpu,
    Awmi,
    Ui,
    Aml,
    Kaslr,
    Static,
}

struct TestCase {
    name: &'static str,
    define: Option<&'static str>,
    expect: Vec<String>,
    forbid: Vec<String>,
    keys: Vec<String>,
    keys_after: &'static str,
    serial: Vec<String>,
    serial_after: &'static str,
    devices: bool,
    uefi: bool,
    iommu: &'static str,
    smp: u32,
    cpu: &'static str,
    timeout: u64,
    ubsan: bool,
    kasan: bool,
    must_exit: bool,
    tamper: bool,
    usb_disk: Option<&'static str>,
    audio_wav: bool,
    net_server: bool,
    bochs: Option<&'static str>,
    bochs_strict_msr: bool,
    qemu_extra: Vec<String>,
    post: Option<PostCheck>,
    host: Option<HostTest>,
    /// Boot the release image as shipped (to the desktop). Other release-image boots use a copy
    /// whose boot volume says `desktop = off`, so they test the text console as before.
    desktop: bool,
}

impl TestCase {
    fn boot(name: &'static str) -> Self {
        Self {
            name,
            define: None,
            expect: Vec::new(),
            forbid: Vec::new(),
            keys: Vec::new(),
            keys_after: "",
            serial: Vec::new(),
            serial_after: "",
            devices: false,
            uefi: false,
            iommu: "intel",
            smp: 4,
            cpu: "max",
            timeout: 15,
            ubsan: false,
            kasan: false,
            must_exit: false,
            tamper: false,
            usb_disk: None,
            audio_wav: false,
            net_server: false,
            bochs: None,
            bochs_strict_msr: false,
            qemu_extra: Vec::new(),
            post: None,
            host: None,
            desktop: false,
        }
    }

    fn desktop(mut self) -> Self {
        self.desktop = true;
        self
    }

    fn host_case(name: &'static str, host: HostTest) -> Self {
        let mut c = Self::boot(name);
        c.host = Some(host);
        c
    }

    fn def(mut self, d: &'static str) -> Self { self.define = Some(d); self }
    fn expect(mut self, items: &[&str]) -> Self {
        self.expect.extend(items.iter().map(|s| (*s).to_string()));
        self
    }
    fn forbid(mut self, items: &[&str]) -> Self {
        self.forbid.extend(items.iter().map(|s| (*s).to_string()));
        self
    }
    fn keys(mut self, items: &[&str], after: &'static str) -> Self {
        self.keys = items.iter().map(|s| (*s).to_string()).collect();
        self.keys_after = after;
        self
    }
    fn keys_vec(mut self, items: Vec<String>, after: &'static str) -> Self {
        self.keys = items;
        self.keys_after = after;
        self
    }
    fn serial(mut self, items: &[&str], after: &'static str) -> Self {
        self.serial = items.iter().map(|s| (*s).to_string()).collect();
        self.serial_after = after;
        self
    }
    fn devices(mut self) -> Self { self.devices = true; self }
    fn uefi(mut self) -> Self { self.uefi = true; self }
    fn iommu(mut self, k: &'static str) -> Self { self.iommu = k; self }
    fn smp(mut self, n: u32) -> Self { self.smp = n; self }
    fn cpu(mut self, m: &'static str) -> Self { self.cpu = m; self }
    fn timeout(mut self, s: u64) -> Self { self.timeout = s; self }
    fn ubsan(mut self) -> Self { self.ubsan = true; self }
    fn kasan(mut self) -> Self { self.kasan = true; self }
    fn must_exit(mut self) -> Self { self.must_exit = true; self }
    fn tamper(mut self) -> Self { self.tamper = true; self }
    fn usb_disk(mut self, s: &'static str) -> Self { self.usb_disk = Some(s); self }
    fn audio_wav(mut self) -> Self { self.audio_wav = true; self }
    fn net_server(mut self) -> Self { self.net_server = true; self }
    fn bochs(mut self, model: &'static str) -> Self { self.bochs = Some(model); self }
    fn bochs_strict_msr(mut self) -> Self { self.bochs_strict_msr = true; self }
    fn qemu(mut self, items: &[&str]) -> Self {
        self.qemu_extra.extend(items.iter().map(|s| (*s).to_string()));
        self
    }
    fn qemu_vec(mut self, items: Vec<String>) -> Self {
        self.qemu_extra.extend(items);
        self
    }
    fn post(mut self, p: PostCheck) -> Self { self.post = Some(p); self }
}

const KERNEL_STAGES: &[&str] = &[
    "D-KRNL 1.",
    "BootInfo OK",
    "GDT/TSS/IDT loaded",
    "PMM:",
    "VMM: kernel W^X",
    "NULL page unmapped",
    "KASLR: image 17 bits, direct map",
    "Heap:",
    "Speculation: Meltdown ",
    "Speculation: MDS/TAA ",
    "APIC timer:",
    "Interrupts enabled, timer OK",
    "Scheduler: preemptive",
    "SMP: ",
    "Rust: dkrnl",
    "Objects: handles",
    "PCI: ECAM at",
    "IOMMU: DMA remapping on for every device",
    "Devices: ",
    "Verified boot: kernel signature valid (Ed25519",
    "Measured boot: PCR 8 = kernel",
    "Summary: ",
    "Summary: KASLR image 17 bits",
    "Summary: KPTI ",
    "User: init started in ring 3",
    "init: running in ring 3",
];

const BIOS_STAGES: &[&str] = &[
    "D-OS: stage1 OK",
    "D-OS: stage2 OK",
    "D-OS: entering long mode",
    "D-OS: stage3: kernel signature valid (Ed25519",
    "D-OS: stage3: kernel relocated (KASLR, 17 bits",
    "BootInfo OK (v5, BIOS",
];

const UEFI_STAGES: &[&str] = &[
    "D-OS: UEFI loader",
    "D-OS: kernel signature valid (Ed25519",
    "D-OS: kernel ",
    "loaded at 0x100000",
    "D-OS: kernel relocated (KASLR, 17 bits",
    "D-OS: GOP framebuffer",
    "D-OS: ACPI 2.0 RSDP",
    "D-OS: exiting boot services",
    "BootInfo OK (v5, UEFI",
    "Console: framebuffer",
    "write-combining on",
    "(RSDP from UEFI)",
];

const HALTED: &str = "System halted.";

fn all_test_cases(has_w2: bool) -> Vec<TestCase> {
    let mut shell_lines: Vec<&str> = vec!["places", "go data", "make notes"];
    if has_w2 {
        shell_lines.extend(["run /esp/DOS/APPS/W2.EXE alpha beta notes", "@~20000"]);
    }
    shell_lines.extend([
        "run /esp/DOS/APPS/L2 notes",
        "@~15000",
        "run /boot/README.TXT",
        "copy /boot/README.TXT notes",
        "create notes/empty.txt",
        "touch notes/touched.txt",
        "list notes | where size > 10 | pick name size",
        "show notes/README.TXT",
        "move notes/README.TXT notes/readme.txt",
        "copy notes/readme.txt /nowhere/x.txt",
        "lst",
        "help copy",
        "tasks | where kind = service | where state = running | count",
        "log | where source = shell | take 1",
        "objects | where type = channel | count",
        "delete notes/empty.txt notes/touched.txt notes/readme.txt notes",
        "go /syst<tab>",
        "time",
        "power off",
    ]);

    let mut shell_expect: Vec<&str> = vec![
        "terminal: display 80x25 VGA text",
        "init: sys volume:",
        "shell: ready: 5 place(s): /boot (read-write), /data (read-write), /esp (read-write), /sys (read), /system (read-write); 7 tool(s)",
        "terminal| / > places",
        "terminal|  place",
        "terminal| data > make notes",
        "terminal| v made /data/notes",
    ];
    if has_w2 {
        shell_expect.extend([
            "shell: run /esp/DOS/APPS/W2.EXE (Windows, under D-CMPL) in /data",
            "terminal| W2: files    ok: 100 lines read back",
            "terminal| W2: 0 checks failed",
        ]);
    }
    shell_expect.extend([
        "shell: run /esp/DOS/APPS/L2 (Linux, under D-CMPL) in /data",
        "terminal| L2: files ok: 100 lines read back",
        "terminal| L2: 0 checks failed",
        "terminal| x run: /boot/README.TXT is not a program D-CMPL runs",
        "terminal| v copied /data/notes/README.TXT (58 B)",
        "terminal| v created /data/notes/empty.txt",
        "terminal| v created /data/notes/touched.txt",
        "terminal|  README.TXT",
        "terminal| D-OS boot volume (FAT32). Written by dosimg on the host.",
        "terminal| v moved /data/notes/README.TXT to /data/notes/readme.txt",
        "terminal| x copy: /nowhere/x.txt is not in this session's namespace",
        "terminal| x unknown command 'lst' - did you mean 'list'?",
        "terminal|   usage: copy <from> <to>",
        "terminal|  count",
        "shell: ready: 5 place(s)",
        "terminal| v deleted /data/notes/empty.txt",
        "terminal| v deleted /data/notes/touched.txt",
        "terminal| v deleted /data/notes/readme.txt",
        "terminal| v deleted /data/notes",
        "terminal| system > time",
        " UTC",
        "init: shell asked to switch off",
        "init: shutdown: every service stopped",
        "Power: switching off",
    ]);

    let mut compat_expect: Vec<&str> = vec![
        "utest: compat: start exception",
        "Hello, world from Windows (W1)",
        "W1: TEB at GS, PEB image base matches, kernel32 bound",
        "BENCH compat: PE load of w1.exe",
        "unsupported import USER32.dll!MessageBoxA",
        "user fault: process 'w1fault.exe'",
        "Hello, world from Linux (L1)",
        "L1: argv/auxv on the stack, TLS at FS, set_tid_address served",
        "unsupported Linux syscall 63 (uname) -> ENOSYS",
        "L1: uname -> ENOSYS, handled cleanly",
        "l1: SIGSEGV",
        "BENCH compat: forwarded Linux syscall round trip",
    ];
    if has_w2 {
        compat_expect.extend([
            "Hello from Windows (W2): MSVC static CRT on D-CMPL",
            "W2: threads  ok",
            "W2: tls      ok",
            "W2: seh      ok",
            "W2: c++      ok",
            "W2: 0 checks failed",
            "dcmpl: w2.exe: unhandled exception 0xc0000005",
            "user fault: process 'w2.exe'",
        ]);
    }
    compat_expect.extend([
        "Hello from Linux (L2): threads, memory, files and signals on D-CMPL",
        "L2: threads ok",
        "L2: signals ok",
        "L2: futex ok",
        "L2: enosys ok",
        "L2: 0 checks failed",
        "dcmpl: pe fuzz:",
        "utest: compat: PASSED",
        "init: utest compat exited with code 0",
    ]);

    vec![
        TestCase::boot("boot")
            .devices()
            .expect(BIOS_STAGES)
            .expect(KERNEL_STAGES)
            .expect(&[
                "SMP: 4 CPUs online (x2APIC)",
                "ACPI: AML: DSDT",
                "0 definition(s) skipped",
                ", 0 failed,",
                "ACPI: SCI on IRQ 9; power button: fixed",
                "IOMMU: interrupt remapping on",
                "D-KRNL: ready",
                "init: started devmgr",
                "devmgr: ps2.ddrv ready",
                "devmgr: virtio-blk.ddrv ready",
                "devmgr: virtio-input.ddrv ready",
                "devmgr: ahci.ddrv ready",
                "devmgr: nvme.ddrv ready",
                "devmgr: disks are read-only",
                "storaged: volume 'system': DFS",
                "MiB free, generation 2, 0 snapshot(s), read-only",
                "init: 5 volume(s)",
                "init: sys volume:",
                "devmgr: running",
                "shell: ready",
            ])
            .forbid(&[
                "KERNEL PANIC", "FAIL", "OFF (unsupported)", "did not start", "warning",
                "exited with code", "NOT confined", "interrupt remapping off", "blocked interrupt",
            ])
            .post(PostCheck::DisksUnchanged),

        TestCase::boot("boot-amd")
            .devices()
            .iommu("amd")
            .expect(&[
                "IOMMU: AMD-Vi, 1 unit(s)",
                "IOMMU: interrupt remapping on",
                "IOMMU: DMA remapping on for every device",
                "(the IOMMU itself: kept by the kernel)",
                "D-KRNL: ready",
                "devmgr: ps2.ddrv ready",
                "devmgr: virtio-blk.ddrv ready",
                "devmgr: virtio-input.ddrv ready",
                "devmgr: ahci.ddrv ready",
                "devmgr: nvme.ddrv ready",
                "devmgr: disks are read-only",
                "storaged: volume 'system': DFS",
                "init: 5 volume(s)",
                "init: sys volume:",
                "devmgr: running",
            ])
            .forbid(&[
                "KERNEL PANIC", "FAIL", "did not start", "warning", "exited with code",
                "NOT confined", "unusable", "blocked DMA", "interrupt remapping off", "blocked interrupt",
            ])
            .post(PostCheck::DisksUnchanged),

        TestCase::boot("uefi")
            .devices()
            .uefi()
            .timeout(90)
            .expect(UEFI_STAGES)
            .expect(KERNEL_STAGES)
            .expect(&[
                "SMP: 4 CPUs online (x2APIC)",
                "ACPI: AML: DSDT",
                "0 definition(s) skipped",
                ", 0 failed,",
                "ACPI: SCI on IRQ 9; power button: fixed",
                "IOMMU: interrupt remapping on",
                "D-KRNL: ready",
                "init: started devmgr",
                "devmgr: ps2.ddrv ready",
                "devmgr: virtio-blk.ddrv ready",
                "devmgr: virtio-input.ddrv ready",
                "devmgr: ahci.ddrv ready",
                "devmgr: nvme.ddrv ready",
                "devmgr: disks are read-only",
                "storaged: volume 'system': DFS",
                "init: 5 volume(s)",
                "init: sys volume:",
                "devmgr: running",
                "terminal: ready: framebuffer",
                "shell: ready",
            ])
            .forbid(&[
                "KERNEL PANIC", "FAIL", "OFF (unsupported)", "did not start", "warning",
                "exited with code", "NOT confined", "interrupt remapping off", "blocked interrupt", "stage1",
            ])
            .post(PostCheck::DisksUnchanged),

        TestCase::boot("uefi-uniproc")
            .uefi()
            .smp(1)
            .timeout(60)
            .expect(UEFI_STAGES)
            .expect(KERNEL_STAGES)
            .expect(&["SMP: 1 CPU", "D-KRNL: ready"])
            .forbid(&["KERNEL PANIC", "FAIL"]),

        TestCase::boot("uefi-selftest")
            .def("SELFTEST")
            .uefi()
            .timeout(60)
            .expect(UEFI_STAGES)
            .expect(KERNEL_STAGES)
            .expect(&["KTEST selftest: PASSED", "KTEST rust selftest: PASSED", "D-KRNL: ready"])
            .forbid(&["KERNEL PANIC", "FAIL"]),

        TestCase::boot("keyboard")
            .expect(&["ps2: keyboard ready", "terminal: line from ps2: Disc OS"])
            .forbid(&["KERNEL PANIC"])
            .keys(&["shift-d", "i", "s", "c", "spc", "shift-o", "shift-s", "ret"], "terminal: ready"),

        TestCase::boot("usbkbd")
            .qemu(&["-device", "qemu-xhci,id=xhci", "-device", "usb-tablet,bus=xhci.0", "-device", "usb-kbd,bus=xhci.0"])
            .expect(&[
                "xhci: controller ready on pci-",
                "HID device 0627:0001 (left unused)",
                ": keyboard ready on port ",
                "DMA confined by the IOMMU",
                "devmgr: xhci.ddrv ready",
                "terminal: line from xhci: Usb Kbd",
            ])
            .forbid(&["KERNEL PANIC", "exited with code", "blocked DMA", "FAIL"])
            .timeout(60)
            .keys(&["shift-u", "s", "b", "spc", "shift-k", "b", "d", "ret"], "terminal: ready"),

        TestCase::boot("usbnokbd")
            .qemu(&["-device", "qemu-xhci,id=xhci", "-device", "usb-tablet,bus=xhci.0", "-device", "usb-mouse,bus=xhci.0"])
            .expect(&[
                "xhci: controller ready on pci-",
                ": HID device 0627:0001 (left unused)",
                ": mouse ready on port ",
                "(USB HID report protocol, 5 buttons, wheel",
                "devmgr: xhci.ddrv ready",
                "terminal: line from ps2: Disc OS",
                "devmgr: pointer input from xhci: moved (20, -10)",
            ])
            .forbid(&["KERNEL PANIC", "exited with code", "blocked DMA", "FAIL", "keyboard ready on port"])
            .timeout(60)
            .keys(
                &[
                    "shift-d", "i", "s", "c", "spc", "shift-o", "shift-s", "ret",
                    "~300", "!mouse_move 20 -10", "~200", "!mouse_button 1", "~100", "!mouse_button 0",
                ],
                "terminal: ready",
            )
            .post(PostCheck::UsbProbedOnce),

        TestCase::boot("usbrepeat")
            .qemu(&["-device", "qemu-xhci,id=xhci", "-device", "usb-kbd,bus=xhci.0"])
            .expect(&[
                ": keyboard ready on port ",
                "devmgr: xhci.ddrv ready",
                "terminal: line from xhci: Raaaaaa",
                "terminal: line from xhci: CAPS",
            ])
            .forbid(&["KERNEL PANIC", "exited with code", "blocked DMA", "FAIL", "LED report refused"])
            .timeout(60)
            .keys(
                &["shift-r", "!sendkey a 900", "~1100", "ret", "caps_lock", "c", "a", "p", "s", "caps_lock", "ret"],
                "terminal: ready",
            ),

        TestCase::boot("usbhold")
            .qemu(&["-device", "qemu-xhci,id=xhci", "-device", "usb-kbd,bus=xhci.0,port=1"])
            .expect(&[
                ": keyboard ready on port ",
                "devmgr: xhci.ddrv ready",
                "terminal: line from xhci: One",
                "devmgr: keyboard xhci ",
                " in use",
                "is typing: its input is held until it is accepted with Ctrl+Alt+Insert",
                "keyboard 0627:0001 on port 6 unplugged",
                "terminal: line from xhci: Two",
            ])
            .forbid(&["KERNEL PANIC", "exited with code", "blocked DMA", "FAIL", "line from xhci: Evil", "not set up"])
            .timeout(60)
            .keys(
                &[
                    "shift-o", "n", "e", "ret", "~300",
                    "!device_add usb-kbd,bus=xhci.0,port=2,id=k2", "~2000",
                    "shift-e", "v", "i", "l", "ret", "~300",
                    "!device_del k2", "~1500",
                    "shift-t", "w", "o", "ret",
                ],
                "terminal: ready",
            ),

        TestCase::boot("usbstorage")
            .qemu(&["-device", "qemu-xhci,id=xhci"])
            .usb_disk("")
            .expect(&[
                "xhci: controller ready on pci-",
                ": disk ready on port ",
                "32 MiB, \"QEMU QEMU HARDDISK\" (USB mass storage, unit 0",
                "devmgr: xhci.ddrv disk 0: 65536 sectors (32 MiB)",
                "storaged: volume 'data': DFS on xhci:",
            ])
            .forbid(&["KERNEL PANIC", "exited with code", "blocked DMA", "FAIL", "not set up", "read at sector"])
            .timeout(60)
            .post(PostCheck::UsbDiskUnchanged),

        TestCase::boot("usbstorage2")
            .qemu(&["-device", "qemu-xhci,id=xhci", "-device", "usb-hub,bus=xhci.0,port=1"])
            .usb_disk(",port=1.2")
            .expect(&[
                ": hub 0409:55aa, 8 ports",
                ": disk ready on port ",
                ".2: 32 MiB",
                "storaged: volume 'data': DFS on xhci:",
            ])
            .forbid(&["KERNEL PANIC", "exited with code", "blocked DMA", "FAIL", "not set up", "read at sector"])
            .timeout(60)
            .post(PostCheck::UsbDiskUnchanged),

        TestCase::boot("usbplug")
            .qemu(&[
                "-device", "qemu-xhci,id=xhci",
                "-device", "usb-hub,bus=xhci.0,port=1",
                "-device", "usb-tablet,bus=xhci.0,port=2,id=tab",
            ])
            .expect(&[
                "xhci: controller ready on pci-",
                ": HID device 0627:0001 (left unused)",
                "device keeps reconnecting; left alone until unplugged",
                ".4 (USB HID boot protocol",
                "terminal: line from xhci: Plug",
            ])
            .forbid(&["KERNEL PANIC", "exited with code", "blocked DMA", "FAIL", "not set up", "stopped answering"])
            .timeout(60)
            .keys(
                &[
                    "!device_del tab", "~400", "!device_add usb-tablet,bus=xhci.0,port=2,id=tab", "~600",
                    "!device_del tab", "~400", "!device_add usb-tablet,bus=xhci.0,port=2,id=tab", "~600",
                    "!device_del tab", "~400", "!device_add usb-tablet,bus=xhci.0,port=2,id=tab", "~600",
                    "!device_add usb-kbd,bus=xhci.0,port=1.4,id=kbd", "~2500",
                    "shift-p", "l", "u", "g", "ret",
                ],
                "terminal: ready",
            )
            .post(PostCheck::UsbPlugOnce),

        TestCase::boot("usbtwo")
            .qemu(&[
                "-device", "qemu-xhci,id=xhci",
                "-device", "usb-kbd,bus=xhci.0,port=1",
                "-device", "usb-hub,bus=xhci.0,port=2",
                "-device", "usb-kbd,bus=xhci.0,port=2.1",
            ])
            .expect(&[
                "xhci: controller ready on pci-",
                ": keyboard ready on port 5 (",
                ": keyboard ready on port 6.1 (",
                "devmgr: xhci.ddrv ready",
                "terminal: line from xhci: Two",
            ])
            .forbid(&["KERNEL PANIC", "exited with code", "blocked DMA", "FAIL", "not set up"])
            .timeout(60)
            .keys(&["~600", "shift-t", "w", "o", "ret"], "terminal: ready"),

        TestCase::boot("usbhub")
            .qemu(&[
                "-device", "qemu-xhci,id=xhci",
                "-device", "usb-hub,bus=xhci.0,port=1",
                "-device", "usb-hub,bus=xhci.0,port=1.1",
                "-device", "usb-tablet,bus=xhci.0,port=1.2",
                "-device", "usb-kbd,bus=xhci.0,port=1.1.3",
            ])
            .expect(&[
                "xhci: controller ready on pci-",
                ": hub 0409:55aa, 8 ports",
                ".1: hub 0409:55aa, 8 ports",
                ".2: HID device 0627:0001 (left unused)",
                ".1.3 (USB HID boot protocol",
                "devmgr: xhci.ddrv ready",
                "terminal: line from xhci: Usb Hub",
            ])
            .forbid(&["KERNEL PANIC", "exited with code", "blocked DMA", "FAIL", "not set up", "stopped answering"])
            .timeout(60)
            .keys(&["~800", "shift-u", "s", "b", "spc", "shift-h", "u", "b", "ret"], "terminal: ready"),

        TestCase::boot("selftest")
            .def("SELFTEST")
            .expect(&["  measured boot: Ed25519 vectors", "KTEST selftest: PASSED", "KTEST rust selftest: PASSED", "D-KRNL: ready"])
            .forbid(&["KERNEL PANIC", "FAIL"]),

        TestCase::boot("panic")
            .def("PANIC")
            .expect(&["KERNEL PANIC", "KASSERT failed: one == 2", "ktest.c:", HALTED])
            .forbid(&["FAILED"]),

        TestCase::boot("stackprot")
            .def("STACKPROT")
            .expect(&["KERNEL PANIC", "stack smashing detected", HALTED])
            .forbid(&["FAILED"]),

        TestCase::boot("pagefault")
            .def("PAGEFAULT")
            .expect(&["Page fault (#PF)", "CR2=0000006000000000", "not-present page, read, kernel", "Backtrace", HALTED])
            .forbid(&["FAILED"]),

        TestCase::boot("doublefault")
            .def("DOUBLEFAULT")
            .expect(&["Double fault (#DF)", HALTED])
            .forbid(&["FAILED"]),

        TestCase::boot("cet")
            .bochs("tigerlake")
            .timeout(300)
            .expect(&["CET: supervisor shadow stacks on", "CET shadow stacks on, IBT", "devmgr: running"])
            .forbid(&["KERNEL PANIC", "user fault", "exited with code", "FAIL"]),

        TestCase::boot("cet-cp")
            .def("CET")
            .bochs("tigerlake")
            .timeout(240)
            .expect(&["KTEST cet: shadow stacks on", "Control protection (#CP)", HALTED])
            .forbid(&["FAILED"]),

        TestCase::boot("cet-user")
            .def("CETUSER")
            .bochs("tigerlake")
            .timeout(400)
            .expect(&[
                "utest: shadow stacks: on in every thread",
                "Control protection (#CP)",
                "return address does not match the shadow stack",
                "utest: PASSED",
                "init: utest cet exited with code 0",
            ])
            .forbid(&["KERNEL PANIC", "FAIL", "shadow stacks: off"]),

        TestCase::boot("nx")
            .def("NX")
            .expect(&["Page fault (#PF)", "instruction fetch", "execute from non-executable memory", HALTED])
            .forbid(&["FAILED", "SKIPPED"]),

        TestCase::boot("wx")
            .def("WX")
            .expect(&["Page fault (#PF)", "protection violation (present), write, kernel", "write to read-only kernel memory", HALTED])
            .forbid(&["FAILED"]),

        TestCase::boot("nullderef")
            .def("NULLDEREF")
            .expect(&["Page fault (#PF)", "CR2=0000000000000000", "NULL pointer dereference", HALTED])
            .forbid(&["FAILED"]),

        TestCase::boot("stackguard")
            .def("STACKGUARD")
            .expect(&["Double fault (#DF)", "hit guard page: kernel boot stack", HALTED])
            .forbid(&["FAILED"]),

        TestCase::boot("doublefree")
            .def("DOUBLEFREE")
            .expect(&["KERNEL PANIC", "heap: double free", HALTED])
            .forbid(&["FAILED"]),

        TestCase::boot("uaf")
            .def("UAF")
            .expect(&["KERNEL PANIC", "heap: use-after-free detected", HALTED])
            .forbid(&["FAILED"]),

        TestCase::boot("heapguard")
            .def("HEAPGUARD")
            .expect(&["Page fault (#PF)", "unmapped kernel heap address", HALTED])
            .forbid(&["FAILED"]),

        TestCase::boot("rustpanic")
            .def("RUSTPANIC")
            .expect(&["KERNEL PANIC", "Rust panic: KASSERT failed: one == 2", "kernel/rust/src/ktest.rs:", HALTED])
            .forbid(&["FAILED"]),

        TestCase::boot("deadlock")
            .def("DEADLOCK")
            .expect(&["KERNEL PANIC", "spinlock self-deadlock: 'ktest.a' is already held", "Held locks", HALTED])
            .forbid(&["FAILED"]),

        TestCase::boot("lockorder")
            .def("LOCKORDER")
            .expect(&["KERNEL PANIC", "lock order violation: acquiring 'ktest.low' (rank 5) while holding 'ktest.high'", HALTED])
            .forbid(&["FAILED"]),

        TestCase::boot("cpupm")
            .def("CPUPM")
            .expect(&[
                "Idle: HLT (under a hypervisor",
                "KTEST cpupm: MSR read ok",
                "Idle: C1 HLT (1 us), C2 I/O 0x80 (2 us) from _CST",
                "Performance: ACPI CPPC (_CPC)",
                "KTEST cpupm: 4 CPUs slept",
                " in C2 (I/O): PASSED",
            ])
            .forbid(&["KERNEL PANIC", "FAILED"]),

        TestCase::boot("cpupm-bochs")
            .def("CPUPM")
            .bochs("tigerlake")
            .bochs_strict_msr()
            .timeout(240)
            .expect(&[
                "Idle: MWAIT C1",
                "KTEST cpupm: MSR read ok, missing MSR read refused, missing MSR write refused",
                "C2 I/O 0x80 (2 us) from _CST",
                "refused on 1 CPU(s) (left as the firmware set them)",
                " in C2 (I/O): PASSED",
            ])
            .forbid(&["KERNEL PANIC", "FAILED"]),

        TestCase::boot("sched")
            .def("SCHED")
            .expect(&["KTEST sched: PASSED"])
            .forbid(&["KERNEL PANIC", "FAIL"]),

        TestCase::boot("threadguard")
            .def("THREADGUARD")
            .expect(&["Double fault (#DF)", "hit guard page: kernel stack of thread 'ktest.recurse'", "in thread 'ktest.recurse'", HALTED])
            .forbid(&["FAILED"]),

        TestCase::boot("mutexdeadlock")
            .def("MUTEXDEADLOCK")
            .expect(&["KERNEL PANIC", "mutex 'ktest.m' deadlock: already held by thread 'kmain'", HALTED])
            .forbid(&["FAILED"]),

        TestCase::boot("atomicsleep")
            .def("ATOMICSLEEP")
            .expect(&["KERNEL PANIC", "thread 'kmain' blocked while holding a spinlock", "ktest.a (rank 5)", HALTED])
            .forbid(&["FAILED"]),

        TestCase::boot("bench")
            .def("BENCH")
            .expect(&[
                "BENCH kmalloc+kfree 32 B",
                "BENCH rust Box alloc+free",
                "BENCH thread_yield round trip",
                "BENCH rust spawn+join",
                "BENCH cross-CPU semaphore ping-pong",
                "BENCH map+unmap 1 page with TLB shootdown",
                "KTEST bench: DONE",
            ])
            .forbid(&["KERNEL PANIC", "FAIL"]),

        TestCase::boot("smp")
            .def("SMP")
            .timeout(30)
            .expect(&["SMP: 4 CPUs online (x2APIC)", "TLB shootdown: 300 remaps", "KTEST smp: PASSED"])
            .forbid(&["KERNEL PANIC", "FAIL"]),

        TestCase::boot("smp-xapic")
            .def("SMP")
            .cpu("max,-x2apic")
            .timeout(30)
            .expect(&["SMP: 4 CPUs online (xAPIC)", "KTEST smp: PASSED"])
            .forbid(&["KERNEL PANIC", "FAIL"]),

        TestCase::boot("uniproc")
            .smp(1)
            .expect(BIOS_STAGES)
            .expect(KERNEL_STAGES)
            .expect(&["SMP: 1 CPU", "D-KRNL: ready"])
            .forbid(&["KERNEL PANIC", "FAIL"]),

        TestCase::boot("lockup")
            .def("LOCKUP")
            .timeout(40)
            .expect(&[
                "watchdog: CPU 1 is not responding",
                "KERNEL PANIC",
                "watchdog: hard lockup on CPU 1",
                "NMI backtrace of CPU 1 (thread 'ktest.stuck'), interrupts off",
                HALTED,
            ])
            .forbid(&["FAILED"]),

        TestCase::boot("softlockup")
            .def("SOFTLOCKUP")
            .timeout(40)
            .expect(&[
                "watchdog: soft lockup on CPU 1: thread 'ktest.hog'",
                "Backtrace",
                "KTEST softlockup: DONE (waiter ran: yes)",
            ])
            .forbid(&["KERNEL PANIC", "FAILED"]),

        TestCase::boot("soak")
            .def("SOAK")
            .timeout(40)
            .expect(&["SOAK round 3 OK"])
            .forbid(&["KERNEL PANIC", "FAIL"]),

        TestCase::boot("ubsan")
            .def("SELFTEST")
            .ubsan()
            .expect(&["KTEST selftest: PASSED", "D-KRNL: ready"])
            .forbid(&["KERNEL PANIC", "FAIL", "UBSan"]),

        TestCase::boot("ubsan-smp")
            .def("SMP")
            .ubsan()
            .timeout(40)
            .expect(&["KTEST smp: PASSED"])
            .forbid(&["KERNEL PANIC", "FAIL", "UBSan"]),

        TestCase::boot("ubsantrap")
            .def("UBSANTRAP")
            .ubsan()
            .expect(&["Invalid opcode (#UD)", "UBSan: undefined behaviour: signed integer overflow (add)", "Backtrace", HALTED])
            .forbid(&["FAILED"]),

        TestCase::boot("profile")
            .def("PROFILE")
            .timeout(120)
            .expect(&[
                "PROFILE: top ktest_prof_spin",
                "KTEST profile (kernel): OK",
                "LATENCY wakeup: ",
                "LATENCY irq: ",
                "BENCH user: channel call round trip",
                "LATENCY syscall: ",
                "KTEST profile: PASSED",
            ])
            .forbid(&["KERNEL PANIC", "FAIL"]),

        TestCase::boot("kasan")
            .def("SELFTEST")
            .kasan()
            .timeout(40)
            .expect(&["KASAN: heap shadow on", "KTEST selftest: PASSED", "KTEST rust selftest: PASSED", "D-KRNL: ready"])
            .forbid(&["KERNEL PANIC", "FAIL", "KASAN: slab"]),

        TestCase::boot("kasan-user")
            .def("USER")
            .kasan()
            .timeout(240)
            .expect(&["KASAN: heap shadow on", "utest: PASSED", "init: utest all exited with code 0"])
            .forbid(&["KERNEL PANIC", "FAIL", "KASAN: slab"]),

        TestCase::boot("kasanoob")
            .def("KASANOOB")
            .kasan()
            .expect(&["KERNEL PANIC", "KASAN: slab-out-of-bounds write of size 1", "0 bytes past the end of a 20-byte allocation", "ktest_kasan", HALTED])
            .forbid(&["FAILED"]),

        TestCase::boot("kasanuaf")
            .def("KASANUAF")
            .kasan()
            .expect(&["KERNEL PANIC", "KASAN: use-after-free read of size 8", "ktest_kasan", HALTED])
            .forbid(&["FAILED"]),

        TestCase::boot("libd")
            .def("LIBD")
            .timeout(120)
            .expect(&[
                "ltest: abi: kernel v",
                "ltest: handles: 100 owned handles closed",
                "ltest: heap: 4 threads",
                "ltest: threads: 16 threads",
                "ltest: mutex: 4 threads x 100000 increments exact (400000)",
                "(no kernel event: yielding)",
                "ltest: once: one run from 8 threads; detached: 8 threads ran and were reclaimed",
                "ltest: channels: call to a server thread",
                "ltest: stack guard: overflow faulted at",
                "ctest: heap:",
                "ctest: threads: 4 threads, distinct ids, mutex count 200000 exact",
                "ctest: PASSED",
                "ltest: C API: ctest passed",
                "BENCH libd: thread spawn+join",
                "BENCH libd: mutex lock+unlock",
                "BENCH libd: Box alloc+free 64 B",
                "ltest: PASSED",
                "init: ltest exited with code 0",
            ])
            .forbid(&["KERNEL PANIC", "FAIL", "PANIC"]),

        TestCase::boot("user")
            .def("USER")
            .timeout(120)
            .expect(&[
                "utest: abi:",
                "utest: code signing: unsigned images refused",
                "utest: pointers:",
                "utest: fault isolation: 14 kinds",
                "utest: kill:",
                "utest: fpu:",
                "utest: channels:",
                "utest: ipc:",
                "utest: ports:",
                "utest: exceptions:",
                "utest: supervisor:",
                "utest: bases:",
                "utest: sealing:",
                "utest: avx:",
                "BENCH user: null syscall",
                "BENCH user: channel call round trip",
                "BENCH user: forwarded syscall",
                "utest: fuzz:",
                "utest: ipc fuzz:",
                "utest: PASSED",
                "init: utest all exited with code 0",
            ])
            .forbid(&["KERNEL PANIC", "FAIL"]),

        TestCase::boot("spec")
            .def("SPEC")
            .timeout(180)
            .expect(&[
                "Speculation: Meltdown ",
                "KPTI: user page tables map",
                "KTEST spec: user page tables: ",
                "all entry pages",
                "KTEST spec: array_index_nospec OK",
                "KTEST spec: KPTI, VERW and RSB filling on every CPU: yes",
                "utest: fault isolation: 14 kinds",
                "utest: PASSED",
                "init: utest all exited with code 0",
                "KTEST spec: PASSED",
            ])
            .forbid(&["KERNEL PANIC", "FAIL"]),

        TestCase::boot("spec-intel")
            .def("USER")
            .cpu("Skylake-Client")
            .timeout(180)
            .expect(&[
                "(GenuineIntel)",
                "Speculation: Meltdown affected, KPTI on",
                "Spectre v2 retpolines + RSB filling",
                "KPTI: user page tables map",
                "Summary: KPTI on",
                "utest: PASSED",
                "init: utest all exited with code 0",
            ])
            .forbid(&["KERNEL PANIC", "FAIL"]),

        TestCase::boot("fuzz")
            .def("FUZZ")
            .timeout(180)
            .expect(&[
                "elf fuzz:",
                "KTEST fuzz: ELF parser OK",
                "acpi fuzz:",
                "KTEST fuzz: ACPI parsers OK",
                "utest: fuzz: 200000 random syscalls",
                "utest: ipc fuzz: 50000 operations",
                "utest: PASSED",
                "init: utest fuzz 200000 exited with code 0",
                "KTEST fuzz: objects after user space ended: none leaked",
                "KTEST fuzz: PASSED",
            ])
            .forbid(&["KERNEL PANIC", "FAIL"]),

        TestCase::boot("kasan-fuzz")
            .def("FUZZ")
            .kasan()
            .timeout(300)
            .expect(&[
                "KASAN: heap shadow on",
                "KTEST fuzz: ELF parser OK",
                "KTEST fuzz: ACPI parsers OK",
                "utest: ipc fuzz:",
                "KTEST fuzz: PASSED",
            ])
            .forbid(&["KERNEL PANIC", "FAIL", "KASAN: slab"]),

        TestCase::boot("attest")
            .def("ATTEST")
            .expect(&["Attestation: key ", "utest: attest report: ", "init: utest attest exited with code 0"])
            .forbid(&["KERNEL PANIC", "FAIL"])
            .post(PostCheck::AttestReport),

        TestCase::boot("attest-tpm")
            .def("ATTESTTPM")
            .expect(&[
                "TPM: TPM 2.0 (simulator",
                "Attestation: TPM attestation key ready",
                "utest: attest report: ",
                "init: utest attest exited with code 0",
            ])
            .forbid(&["KERNEL PANIC", "FAIL", "no TPM evidence"])
            .post(PostCheck::AttestReport),

        TestCase::boot("smap")
            .def("SMAP")
            .expect(&[
                "KTEST smap: kernel reading user address",
                "Page fault (#PF)",
                "protection violation (present), read, kernel",
                "kernel accessed user memory outside user_copy (SMAP)",
                HALTED,
            ])
            .forbid(&["KTEST smap: FAILED"]),

        TestCase::boot("smep")
            .def("SMEP")
            .expect(&[
                "KTEST smep: kernel calling user code",
                "Page fault (#PF)",
                "instruction fetch",
                "kernel tried to execute user memory (SMEP)",
                HALTED,
            ])
            .forbid(&["KTEST smep: FAILED"]),

        TestCase::boot("kdb")
            .expect(&["kdb: threads", "TID  NAME", "reaper", "kdb: cpus", "CPU  ONLINE", "PCR  8", "kdb: measure: "])
            .forbid(&["KERNEL PANIC"])
            .serial(&["threads", "cpus", "measure"], "kdb: serial console ready"),

        TestCase::boot("compat")
            .def("COMPAT")
            .timeout(120)
            .expect(&compat_expect)
            .forbid(&["KERNEL PANIC", "FAIL", "PANIC"]),

        TestCase::boot("drivers")
            .def("DRIVERS")
            .devices()
            .timeout(90)
            .expect(&[
                "IOMMU: DMA remapping on",
                "devmgr: test: device ABI: config writes filtered, MSI-X table hidden",
                "virtio-blk: 2048 sectors",
                "DMA confined by the IOMMU",
                "devmgr: test: virtio-blk: 2048 sectors",
                "write + read back OK",
                "devmgr: test: interrupt delivery: virtio-blk",
                "user fault: process 'virtio-blk.ddrv'",
                "devmgr: restarting virtio-blk.ddrv",
                "devmgr: test: virtio-blk.ddrv crashed and was restarted; I/O works again",
                "IOMMU: blocked DMA write by 00:02.0 at 0x100000",
                "IOMMU: interrupt remapping on (x2APIC destinations)",
                "IOMMU: blocked interrupt from",
                "devmgr: test: forged interrupt sent",
                "devmgr: test: DMA outside the driver's pins blocked by the IOMMU",
                "IOMMU: test range 0xc0000000-0xc000ffff identity mapped for",
                "IOMMU: test: firmware range 0xc0000000-0xc000ffff kept in",
                "devmgr: test: virtio-blk recovered after the DMA test",
                "devmgr: test: keyboard: 'virtio' typed on virtio-input",
                "devmgr: test: interrupt delivery: virtio-input",
                "devmgr: test PASSED",
                "init: devmgr exited with code 0",
                "KTEST drivers: kernel memory at 0x100000 unchanged",
                "KTEST drivers: PASSED",
            ])
            .forbid(&["KERNEL PANIC", "FAIL", "PANIC"])
            .keys(&["v", "i", "r", "t", "i", "o", "ret"], "devmgr: test: waiting for keys"),

        TestCase::boot("drivers-amd")
            .def("DRIVERS")
            .devices()
            .iommu("amd")
            .timeout(90)
            .expect(&[
                "IOMMU: AMD-Vi, 1 unit(s)",
                "IOMMU: DMA remapping on",
                "devmgr: test: device ABI: config writes filtered, MSI-X table hidden",
                "DMA confined by the IOMMU",
                "devmgr: test: virtio-blk: 2048 sectors",
                "write + read back OK",
                "devmgr: test: interrupt delivery: virtio-blk",
                "devmgr: test: virtio-blk.ddrv crashed and was restarted; I/O works again",
                "IOMMU: blocked DMA access by 00:03.0 at ",
                "IOMMU: interrupt remapping on (32-bit entries",
                "devmgr: test: forged interrupt sent",
                "KTEST drivers: 0 interrupt(s) on unhandled vectors",
                "devmgr: test: DMA outside the driver's pins blocked by the IOMMU",
                "IOMMU: test range 0xc0000000-0xc000ffff identity mapped for",
                "IOMMU: test: firmware range 0xc0000000-0xc000ffff kept in",
                "devmgr: test: virtio-blk recovered after the DMA test",
                "devmgr: test: keyboard: 'virtio' typed on virtio-input",
                "devmgr: test PASSED",
                "init: devmgr exited with code 0",
                "KTEST drivers: kernel memory at 0x100000 unchanged",
                "KTEST drivers: PASSED",
            ])
            .forbid(&["KERNEL PANIC", "FAIL", "PANIC", "unusable"])
            .keys(&["v", "i", "r", "t", "i", "o", "ret"], "devmgr: test: waiting for keys"),

        TestCase::boot("storage")
            .def("STORAGE")
            .devices()
            .timeout(300)
            .expect(&[
                "ahci: port 1:",
                "nvme: NVMe",
                "storaged: volume 'boot': FAT32",
                "storaged: volume 'system': DFS",
                "storaged: volume 'data': DFS",
                "partition 2 ('Basic data partition'): NTFS, not supported (left alone)",
                "init: 5 volume(s)",
                "fstest: fat32:",
                "fstest: dfs:",
                "BENCH storage: DFS write 1 MiB",
                "fstest: snapshots:",
                "fstest: child:",
                "fstest: code signing: hello.dx from the boot volume",
                "fstest: namespace isolation:",
                "fstest: rename: DFS and FAT32",
                "fstest: rename: power cut at 6 points",
                "fstest: power cut:",
                "fstest: corruption:",
                "fstest: PASSED",
                "init: fstest exited with code 0",
            ])
            .forbid(&["KERNEL PANIC", "FAIL", "PANIC"])
            .post(PostCheck::StorageImages),

        TestCase::boot("services")
            .def("SERVICES")
            .devices()
            .timeout(120)
            .must_exit()
            .expect(&[
                "init: service storaged accepted",
                "init: service devmgr accepted",
                "unknown key 'grants.kernel-memory'",
                "init: manifest svc-badcap.dman refused: it asks for endpoint nosuch.secrets, which no service provides",
                "init: manifest esp:/DOS/SERVICES/TAMPERED.DMAN refused: signature check failed",
                "init: manifest esp:/DOS/SERVICES/UNSIGNED.DMAN refused: not signed",
                "init: service hello accepted (esp:/DOS/SERVICES/HELLO.DMAN)",
                "hello: a signed program loaded from disk is running",
                "ltest: svc-grants: exactly the granted handles",
                "ltest: svc-quota: limits from the manifest",
                "init: restarting svc-crash in 50 ms (restart 1 of 2)",
                "init: restarting svc-crash in 100 ms (restart 2 of 2)",
                "init: svc-crash keeps failing: given up after 2 restart(s)",
                "init: test: storaged killed and restarted",
                "devmgr: storage service reconnected",
                "init: test: devmgr killed and restarted",
                "log: running:",
                "clock: ",
                "terminal: ready",
                "shell: ready",
                "storaged: file times from the clock service",
                "svc-log: ",
                "no kernel address (",
                "levels applied (warn kept, info dropped)",
                "init: stopping devmgr",
                "devmgr: shutdown:",
                "init: stopping storaged",
                "storaged: shutdown:",
                "init: shutdown: every service stopped",
                "init: test: PASSED",
                "Power: switching off",
            ])
            .forbid(&[
                "KERNEL PANIC", "test FAIL", "svc FAIL", "PANIC",
                "could not measure", "sync failed", "did not confirm", "did not stop in time",
            ])
            .post(PostCheck::ServicesOrder),

        TestCase::boot("time")
            .def("TIME")
            .devices()
            .timeout(120)
            .must_exit()
            .expect(&[
                "(from the CMOS real-time clock)",
                "svc-time: wall-clock time ",
                "svc-time: first boot: the time is recorded on DFS (/data) and FAT32 (/boot)",
                "init: time test: first boot done",
                "Power: switching off",
            ])
            .forbid(&["KERNEL PANIC", "svc FAIL", "PANIC", "test FAIL", "FAILED"])
            .post(PostCheck::TimeReboot),

        TestCase::boot("time-uefi")
            .def("TIME")
            .devices()
            .uefi()
            .timeout(180)
            .must_exit()
            .expect(&[
                "(from UEFI GetTime at boot)",
                "svc-time: first boot: the time is recorded",
                "init: time test: first boot done",
                "Power: switching off",
            ])
            .forbid(&["KERNEL PANIC", "svc FAIL", "PANIC", "test FAIL", "FAILED"])
            .post(PostCheck::TimeRebootUefi),

        TestCase::boot("shell")
            .def("SHELL")
            .devices()
            .timeout(180)
            .must_exit()
            .keys_vec(convert_to_qemu_keys(&shell_lines, 900), "shell: ready")
            .expect(&shell_expect)
            .forbid(&["KERNEL PANIC", "PANIC", "user fault", "crashed", "cannot start"]),

        TestCase::boot("powerbutton")
            .devices()
            .timeout(90)
            .must_exit()
            .keys(&["~500", "!system_powerdown"], "shell: ready")
            .expect(&[
                "ACPI: AML: DSDT",
                "ACPI: SCI on IRQ 9; power button: fixed",
                "shell: ready",
                "ACPI: power button pressed (fixed)",
                "init: power button pressed: shutting down",
                "init: shutdown: every service stopped",
                "Power: switching off (ACPI S5)",
            ])
            .forbid(&["KERNEL PANIC", "PANIC", "did not switch off", "system_power returned", "did not finish"]),

        TestCase::boot("s3")
            .def("SHELL")
            .devices()
            .qemu(&["-global", "ICH9-LPC.disable_s3=0"])
            .timeout(120)
            .must_exit()
            .keys_vec(
                {
                    let mut k = convert_to_qemu_keys(&["power sleep"], 3000);
                    k.push("!system_wakeup".into());
                    k.push("~4000".into());
                    k.extend(convert_to_qemu_keys(&["show /boot/README.TXT", "power off"], 1500));
                    k
                },
                "shell: ready",
            )
            .expect(&[
                "shell: ready",
                "devmgr: suspended:",
                "Power: entering ACPI S3",
                "Power: resumed from ACPI S3 (4 CPU(s) online)",
                "devmgr: resumed:",
                "D-OS boot volume (FAT32)",
                "Power: switching off (ACPI S5)",
            ])
            .forbid(&[
                "KERNEL PANIC",
                "PANIC",
                "FAIL",
                "user fault",
                "watchdog:",
                "did not enter sleep",
                "suspend failed",
                "TPM: Shutdown(STATE)",
                "blocked DMA",
                "blocked interrupt",
            ]),

        TestCase::boot("poweroff")
            .def("POWEROFF")
            .timeout(30)
            .must_exit()
            .expect(&[
                "Power: power-off by ACPI S5",
                "init: power: the VMEX resource is refused (-5)",
                "Power: switch-off requested by process init",
                "Power: switching off (ACPI S5)",
            ])
            .forbid(&["KERNEL PANIC", "FAIL", "did not switch off", "system_power returned", "exited with code"]),

        TestCase::boot("poweroff-uefi")
            .def("POWEROFF")
            .uefi()
            .timeout(60)
            .must_exit()
            .expect(&["Power: power-off by ACPI S5", "Power: switching off (ACPI S5)"])
            .forbid(&["KERNEL PANIC", "FAIL", "did not switch off", "system_power returned", "exited with code"]),

        TestCase::boot("reboot")
            .def("REBOOT")
            .timeout(30)
            .must_exit()
            .expect(&[
                "reset by reset register",
                "init: power: the VMEX resource is refused (-5)",
                "Power: reset requested by process init",
                "Power: resetting",
            ])
            .forbid(&["KERNEL PANIC", "FAIL", "no reset method worked", "system_power returned", "exited with code"]),

        TestCase::boot("hwbench")
            .def("HWBENCH")
            .devices()
            .uefi()
            .timeout(240)
            .expect(&[
                "lock-order checking off",
                "BENCH kmalloc+kfree 32 B",
                "BENCH thread_yield round trip",
                "KTEST bench: DONE",
                "BENCH user: null syscall round trip",
                "BENCH user: channel call round trip",
                "BENCH fs: /esp: sequential read of /DOS/KERNEL.BIN",
                "BENCH fs: /esp: random 4 KiB reads",
                "fstest: bench: 5 volume(s) measured",
                "D-OS hardware benchmark results",
                "Results:",
                "KTEST hwbench: DONE",
            ])
            .forbid(&["KERNEL PANIC", "FAIL", "PANIC", "INCOMPLETE"])
            .post(PostCheck::DisksUnchanged),

        TestCase::boot("readonly")
            .def("READONLY")
            .devices()
            .timeout(120)
            .expect(&[
                "devmgr: disks are read-only",
                "storaged: running (read-only",
                "storaged: read-only check: ahci:pci-00:1f.2:0: the driver refused a raw write",
                "storaged: read-only check: ahci:pci-00:1f.2:1: the driver refused a raw write",
                "storaged: read-only check: nvme:pci-00:04.0:0: the driver refused a raw write",
                "storaged: read-only check: virtio-blk:pci-00:02.0:0: the driver refused a raw write",
                "init: 5 volume(s)",
                "fstest: readonly: /boot:",
                "fstest: readonly: /system:",
                "fstest: readonly: /data:",
                "fstest: readonly: /esp:",
                "fstest: readonly: /sys:",
                "fstest: readonly PASSED",
                "init: fstest readonly exited with code 0",
            ])
            .forbid(&["KERNEL PANIC", "FAIL", "PANIC"])
            .post(PostCheck::DisksUnchanged),

        TestCase::boot("manydevices")
            .qemu_vec(many_device_args(64))
            .timeout(30)
            .expect(&[
                "PCI 00:0f.7",
                "PCI 00:1f.2",
                "69 functions",
                "Devices: 72 for user-space drivers",
                "User: init started in ring 3",
                "init: started devmgr with 70 devices",
                "devmgr: 70 devices, 2 with a driver",
                "init: 2 volume(s)",
                "init: sys volume:",
                "devmgr: running",
            ])
            .forbid(&["KERNEL PANIC", "cannot start init", "left out", "FAIL", "not used: the limit"]),

        TestCase::host_case("storage-host", HostTest::Dosfs),
        TestCase::host_case("crypto-host", HostTest::Crypto),
        TestCase::host_case("manifest-host", HostTest::Manifest),
        TestCase::host_case("audio-host", HostTest::Audio),
        TestCase::host_case("net-host", HostTest::Net),
        TestCase::host_case("gpu-host", HostTest::Gpu),
        TestCase::host_case("awmi-host", HostTest::Awmi),
        TestCase::host_case("ui-host", HostTest::Ui),
        TestCase::host_case("aml-host", HostTest::Aml),

        TestCase::boot("audio-hda")
            .def("SHELL")
            .audio_wav()
            .qemu(&["-device", "ich9-intel-hda", "-device", "hda-duplex,audiodev=snd0"])
            .timeout(60)
            .must_exit()
            .keys_vec(
                convert_to_qemu_keys(
                    &[
                        "audio",
                        "audio vol 42",
                        "audio mute",
                        "audio unmute",
                        "audio vol 100",
                        "audio tone 440 800",
                        "@~400",
                        "power off",
                    ],
                    400,
                ),
                "shell: ready",
            )
            .expect(&[
                "hda: controller ready on pci-",
                "devmgr: hda.ddrv ready",
                "audio: backend 'HDA",
                "terminal| v volume set to 42%",
                "terminal| v output muted",
                "terminal| v output unmuted (42%)",
                "terminal| v played 440 Hz tone for 800 ms",
                "Power: switching off",
            ])
            .forbid(&["KERNEL PANIC", "FAIL", "blocked DMA", "exited with code", "user fault"])
            .post(PostCheck::AudioWav(440)),

        TestCase::boot("audio-virtio")
            .def("SHELL")
            .audio_wav()
            .qemu(&["-device", "virtio-sound-pci,audiodev=snd0,iommu_platform=on"])
            .timeout(60)
            .must_exit()
            .keys_vec(
                convert_to_qemu_keys(&["audio", "audio tone 440 800", "@~400", "power off"], 400),
                "shell: ready",
            )
            .expect(&[
                "virtio-snd: ready on pci-",
                "devmgr: virtio-snd.ddrv ready",
                "audio: backend 'VirtIO Sound Out'",
                "terminal| v played 440 Hz tone for 800 ms",
                "Power: switching off",
            ])
            .forbid(&["KERNEL PANIC", "FAIL", "blocked DMA", "exited with code", "user fault"])
            .post(PostCheck::AudioWav(440)),

        TestCase::boot("audio-usb")
            .def("SHELL")
            .audio_wav()
            .qemu(&["-device", "qemu-xhci,id=xhci", "-device", "usb-audio,bus=xhci.0,audiodev=snd0"])
            .timeout(60)
            .must_exit()
            .keys_vec(
                convert_to_qemu_keys(&["audio", "audio tone 440 800", "@~400", "power off"], 400),
                "shell: ready",
            )
            .expect(&[
                "xhci: controller ready on pci-",
                "audio device ready on port",
                "usbaudio:",
                "audio: backend 'USB Audio Output'",
                "terminal| v played 440 Hz tone for 800 ms",
                "Power: switching off",
            ])
            .forbid(&["KERNEL PANIC", "FAIL", "blocked DMA", "exited with code", "user fault"])
            .post(PostCheck::AudioWav(440)),

        TestCase::boot("audio-sec")
            .def("AUDIO")
            .audio_wav()
            .qemu(&[
                "-audiodev", "none,id=mic0",
                "-device", "ich9-intel-hda",
                "-device", "hda-duplex,audiodev=snd0",
                "-device", "hda-micro,audiodev=mic0",
                "-device", "qemu-xhci,id=xhci",
            ])
            .timeout(90)
            .must_exit()
            .keys(
                &[
                    "!device_add usb-audio,bus=xhci.0,id=ua1,audiodev=snd0",
                    "~2000",
                    "!device_del ua1",
                ],
                "svc-audio-full: ready for usb hotplug",
            )
            .expect(&[
                "svc-audio-ungranted: PASSED (ungranted app refused)",
                "audio: refused capture on non-capture endpoint",
                "svc-audio-playonly: PASSED",
                "terminal: indicator: MIC LIVE",
                "terminal: indicator: MIC OFF",
                "audio: refused capture (microphone policy revoked)",
                "audio: output switched to 'USB Audio Output'",
                "svc-audio-full: usb hotplug active",
                "svc-audio-full: switched back to HDA",
                "hda: intentional crash requested",
                "devmgr: restarting hda.ddrv",
                "audio: backend 'HDA Line Out' (id 1) reconnected",
                "svc-audio-full: PASSED",
                "init: audio test: PASSED",
                "Power: switching off",
            ])
            .forbid(&["KERNEL PANIC", "FAIL", "audio test services did not finish"])
            .post(PostCheck::AudioWav(660)),

        TestCase::boot("net-virtio")
            .def("NET")
            .net_server()
            .qemu(&["-device", "virtio-net-pci,netdev=net0,disable-legacy=on,iommu_platform=on"])
            .timeout(90)
            .must_exit()
            .expect(&[
                "virtio-net: ready on pci-",
                "net: dhcp bound 10.0.2.15",
                "svc-net-ungranted: PASSED (ungranted app refused)",
                "svc-net-full: dhcp OK",
                "svc-net-full: dns OK (test.dos.local -> 10.0.2.100)",
                "svc-net-full: icmp ping OK",
                "svc-net-full: tcp OK",
                "svc-net-full: tls13 OK",
                "svc-net-full: tls13 bad-cert refused",
                "svc-net-full: PASSED",
                "init: net test: PASSED",
                "Power: switching off",
            ])
            .forbid(&["KERNEL PANIC", "FAIL", "blocked DMA", "user fault"]),

        TestCase::boot("net-e1000e")
            .def("NET")
            .net_server()
            .qemu(&["-device", "e1000e,netdev=net0"])
            .timeout(90)
            .must_exit()
            .expect(&[
                "e1000e: ready on pci-",
                "net: dhcp bound 10.0.2.15",
                "svc-net-ungranted: PASSED (ungranted app refused)",
                "svc-net-full: dhcp OK",
                "svc-net-full: dns OK (test.dos.local -> 10.0.2.100)",
                "svc-net-full: icmp ping OK",
                "svc-net-full: tcp OK",
                "svc-net-full: tls13 OK",
                "svc-net-full: tls13 bad-cert refused",
                "svc-net-full: PASSED",
                "init: net test: PASSED",
                "Power: switching off",
            ])
            .forbid(&["KERNEL PANIC", "FAIL", "blocked DMA", "user fault"]),

        TestCase::boot("net-shell")
            .def("SHELL")
            .qemu(&[
                "-netdev",
                "user,id=net0",
                "-device",
                "virtio-net-pci,netdev=net0,disable-legacy=on,iommu_platform=on",
            ])
            .timeout(90)
            .must_exit()
            .keys_vec(
                convert_to_qemu_keys(&["@~1500", "net", "ping 10.0.2.2 2", "net check", "power off"], 600),
                "net: dhcp bound 10.0.2.15",
            )
            .expect(&[
                "virtio-net: ready on pci-",
                "net: dhcp bound 10.0.2.15",
                "terminal|  virtio-net",
                "terminal| PING 10.0.2.2 (10.0.2.2): 2 request(s)",
                "terminal| v ping 10.0.2.2: 2/2 received (0% loss)",
                "10.0.2.2 answers ping",
                "terminal| ",
                "net check: ",
                "Power: switching off",
            ])
            .forbid(&["KERNEL PANIC", "FAIL", "blocked DMA", "user fault"]),

        TestCase::boot("gpu-virtio")
            .def("GPU")
            .qemu(&["-device", "virtio-gpu-pci,disable-legacy=on,iommu_platform=on,edid=on,xres=1024,yres=768"])
            .timeout(90)
            .must_exit()
            .expect(&[
                "virtio-gpu: ready on pci-",
                "1024x768",
                "IOMMU=true",
                "gpu: adapter #",
                "svc-gpu-ungranted: PASSED (ungranted app refused)",
                "svc-gpu-queryonly: PASSED (query ok, display/render refused)",
                "svc-gpu-full: adapter OK",
                "svc-gpu-full: scanout OK",
                "svc-gpu-full: cursor OK",
                "svc-gpu-full: modeset OK (800x600 -> 1024x768)",
                "svc-gpu-full: cs-validation OK",
                "devmgr: restarting virtio-gpu.ddrv",
                "reconnected (restart 1)",
                "svc-gpu-full: crash-recovery OK",
                "svc-gpu-full: PASSED",
                "init: gpu test: PASSED",
                "Power: switching off",
            ])
            .forbid(&["KERNEL PANIC", "FAIL", "blocked DMA", "user fault"]),

        TestCase::boot("gpu-virtio-amd")
            .def("GPU")
            .iommu("amd")
            .qemu(&["-device", "virtio-gpu-pci,disable-legacy=on,iommu_platform=on,edid=on,xres=1024,yres=768"])
            .timeout(90)
            .must_exit()
            .expect(&[
                "IOMMU: AMD-Vi, 1 unit(s)",
                "virtio-gpu: ready on pci-",
                "IOMMU=true",
                "svc-gpu-ungranted: PASSED (ungranted app refused)",
                "svc-gpu-queryonly: PASSED (query ok, display/render refused)",
                "svc-gpu-full: scanout OK",
                "svc-gpu-full: crash-recovery OK",
                "svc-gpu-full: PASSED",
                "init: gpu test: PASSED",
                "Power: switching off",
            ])
            .forbid(&["KERNEL PANIC", "FAIL", "blocked DMA", "user fault"]),

        TestCase::boot("gpu-gop")
            .def("GPU")
            .uefi()
            .timeout(90)
            .must_exit()
            .expect(&[
                "D-OS: GOP framebuffer",
                "gpu: adapter #1 'GOP Framebuffer' (gop,",
                "svc-gpu-ungranted: PASSED (ungranted app refused)",
                "svc-gpu-queryonly: PASSED (query ok, display/render refused)",
                "svc-gpu-full: adapter OK (#1 gop GOP Framebuffer",
                "svc-gpu-full: scanout OK",
                "svc-gpu-full: PASSED",
                "init: gpu test: PASSED",
                "Power: switching off",
            ])
            .forbid(&["KERNEL PANIC", "FAIL", "blocked DMA", "user fault"]),

        TestCase::boot("gpu-shell")
            .def("SHELL")
            .qemu(&["-device", "virtio-gpu-pci,disable-legacy=on,iommu_platform=on,edid=on,xres=1024,yres=768"])
            .timeout(90)
            .must_exit()
            .keys_vec(
                convert_to_qemu_keys(&["gpu", "gpu modes", "power off"], 500),
                "shell: ready",
            )
            .expect(&[
                "virtio-gpu: ready on pci-",
                "terminal|   1  virtio-gpu",
                "1af4:1050",
                "1024x768",
                "Power: switching off",
            ])
            .forbid(&["KERNEL PANIC", "FAIL", "blocked DMA", "user fault"]),

        // D-AWMI on a PCI GPU (virtio-gpu: zero-copy IOMMU scanout, hardware cursor), with a
        // capture device for the microphone indicator and a tablet for real pointer input.
        TestCase::boot("awmi-virtio")
            .def("AWMI")
            .audio_wav()
            .qemu(&[
                "-device",
                "virtio-gpu-pci,disable-legacy=on,iommu_platform=on,edid=on,xres=1024,yres=768",
                "-device",
                "ich9-intel-hda",
                "-device",
                "hda-duplex,audiodev=snd0",
                "-device",
                "virtio-tablet-pci,disable-legacy=on,iommu_platform=on",
            ])
            .timeout(150)
            .must_exit()
            .keys_vec(
                convert_to_qemu_keys(
                    &["leak", "@!mouse_move 40 30", "@~200", "@!mouse_button 1", "@~200", "@!mouse_button 0", "@~2000", "gui status"],
                    300,
                ),
                "svc-awmi-full: input grab active, type now",
            )
            .expect(&[
                "virtio-gpu: ready on pci-",
                "awmi: output: adapter #",
                "1024x768",
                "hardware cursor",
                "awmi: fonts: 4 face(s)",
                "awmi: ready, idle until a session starts",
                "svc-awmi-ungranted: PASSED (no compositor endpoint)",
                "awmi: session started:",
                "svc-awmi-a: window",
                "svc-awmi-b: window",
                "svc-awmi-full: session OK",
                "svc-awmi-full: fonts OK (",
                "svc-awmi-full: launcher & settings OK (",
                "svc-awmi-full: surface isolation OK",
                "svc-awmi-full: verified identity OK",
                "svc-awmi-full: focus & input routing OK",
                "svc-awmi-full: snapping OK",
                "svc-awmi-full: workspaces OK",
                "svc-awmi-full: multi-monitor OK",
                "svc-awmi-full: indicators OK",
                "svc-awmi-a: PASSED (only its own key 'a', closed on request)",
                "svc-awmi-b: PASSED (only its own key 'b', closed on request)",
                "svc-awmi-full: close requests OK",
                "devmgr: input grabbed by input client",
                "terminal: display released to the compositor",
                "awmi: keys routed to the compositor (input grab held)",
                "awmi: pointer input routed to the compositor (grab held)",
                "svc-awmi-full: input grab OK",
                "devmgr: input grab released",
                "terminal: display reclaimed",
                "svc-awmi-full: PASSED",
                ": gui status",
                "init: awmi test: PASSED",
                "Power: switching off",
            ])
            .forbid(&["KERNEL PANIC", "FAIL", "blocked DMA", "user fault", ": leak", "PANIC"]),

        // The release image as shipped: straight to the desktop with the terminal window (the
        // shell session, typed into through the compositor); the launcher opens an app; leaving
        // the desktop gives the text console back, where the session goes on.
        TestCase::boot("desktop-virtio")
            .desktop()
            .qemu(&["-device", "virtio-gpu-pci,disable-legacy=on,iommu_platform=on,edid=on,xres=1280,yres=800"])
            .timeout(150)
            .must_exit()
            .keys_vec(desktop_keys(), "terminal: view attached")
            .expect(&DESKTOP_EXPECT)
            .forbid(&["KERNEL PANIC", "FAIL", "blocked DMA", "user fault", "PANIC", "refused ("]),

        TestCase::boot("desktop-gop")
            .desktop()
            .uefi()
            .timeout(150)
            .must_exit()
            .keys_vec(desktop_keys(), "terminal: view attached")
            .expect(&DESKTOP_EXPECT)
            .forbid(&["KERNEL PANIC", "FAIL", "blocked DMA", "user fault", "PANIC", "refused ("]),

        // D-AWMI on the firmware framebuffer (UEFI GOP: write-combining blits, software cursor).
        TestCase::boot("awmi-gop")
            .def("AWMI")
            .uefi()
            .qemu(&["-device", "virtio-tablet-pci,disable-legacy=on,iommu_platform=on"])
            .timeout(150)
            .must_exit()
            .keys_vec(
                convert_to_qemu_keys(
                    &["leak", "@!mouse_move 40 30", "@~200", "@!mouse_button 1", "@~200", "@!mouse_button 0", "@~2000", "gui status"],
                    300,
                ),
                "svc-awmi-full: input grab active, type now",
            )
            .expect(&[
                "D-OS: GOP framebuffer",
                "awmi: output: adapter #1 'GOP Framebuffer'",
                "software cursor",
                "awmi: fonts: 4 face(s)",
                "awmi: ready, idle until a session starts",
                "svc-awmi-ungranted: PASSED (no compositor endpoint)",
                "awmi: session started:",
                "svc-awmi-a: window",
                "svc-awmi-b: window",
                "svc-awmi-full: session OK",
                "svc-awmi-full: fonts OK (",
                "svc-awmi-full: launcher & settings OK (",
                "svc-awmi-full: surface isolation OK",
                "svc-awmi-full: verified identity OK",
                "svc-awmi-full: focus & input routing OK",
                "svc-awmi-full: snapping OK",
                "svc-awmi-full: workspaces OK",
                "svc-awmi-full: multi-monitor OK",
                "svc-awmi-full: indicators OK",
                "svc-awmi-a: PASSED (only its own key 'a', closed on request)",
                "svc-awmi-b: PASSED (only its own key 'b', closed on request)",
                "svc-awmi-full: close requests OK",
                "devmgr: input grabbed by input client",
                "terminal: display released to the compositor",
                "awmi: keys routed to the compositor (input grab held)",
                "awmi: pointer input routed to the compositor (grab held)",
                "svc-awmi-full: input grab OK",
                "devmgr: input grab released",
                "terminal: display reclaimed",
                "svc-awmi-full: PASSED",
                ": gui status",
                "init: awmi test: PASSED",
                "Power: switching off",
            ])
            .forbid(&["KERNEL PANIC", "FAIL", "blocked DMA", "user fault", ": leak", "PANIC"]),

        TestCase::boot("uefi-badsig")
            .uefi()
            .tamper()
            .timeout(60)
            .expect(&[
                "D-OS: UEFI loader",
                "D-OS: kernel signature check failed: content does not match the signature",
                "refusing to boot an unverified kernel",
            ])
            .forbid(&["D-KRNL 1.", "kernel signature valid"]),

        TestCase::boot("bios-badsig")
            .tamper()
            .expect(&[
                "D-OS: stage2 OK",
                "D-OS: stage3: kernel signature check failed: content does not match the signature",
                "refusing to boot an unverified kernel",
            ])
            .forbid(&["D-KRNL 1.", "kernel signature valid"]),

        TestCase::boot("kaslr")
            .def("KASLR")
            .expect(&[
                "D-OS: stage3: kernel relocated (KASLR",
                "KTEST kaslr: layout image 0xffffff",
                "KTEST kaslr: PASSED",
                "D-KRNL: ready",
            ])
            .forbid(&["KERNEL PANIC", "FAIL"])
            .post(PostCheck::KaslrReboots),

        TestCase::host_case("kaslr-host", HostTest::Kaslr),
        TestCase::host_case("static", HostTest::Static),

        TestCase::boot("roinit")
            .def("ROINIT")
            .expect(&["Page fault (#PF)", "protection violation (present), write, kernel", "write to read-only-after-init kernel data", HALTED])
            .forbid(&["FAILED"]),

        TestCase::boot("bounds")
            .def("BOUNDS")
            .expect(&["Invalid opcode (#UD)", "UBSan: undefined behaviour: index out of bounds", "bounds_read", HALTED])
            .forbid(&["FAILED"]),

        TestCase::boot("objects")
            .def("OBJECTS")
            .timeout(60)
            .expect(&[
                "out of memory (C): thread_create",
                "rights: enforced",
                "cycles: unreachable channel cycles collected",
                "quotas: handles, memory, threads",
                "each failed cleanly with no leak",
                "KTEST objects: PASSED",
            ])
            .forbid(&["KERNEL PANIC", "FAIL"]),
    ]
}

struct CaseResult {
    name: String,
    result: &'static str,
    seconds: f64,
}

pub fn run_test_suite(
    env: &Env,
    cases_filter: &[String],
    default_timeout: u64,
    no_repro: bool,
) -> Result<(), String> {
    let has_w2 = env.msvc().is_some() && env.winsdk().is_some();
    let all = all_test_cases(has_w2);
    let known: Vec<&str> = all.iter().map(|c| c.name).collect();

    let selected: Vec<&TestCase> = if cases_filter.is_empty() {
        all.iter().collect()
    } else {
        let mut out = Vec::new();
        for name in cases_filter {
            let tc = all
                .iter()
                .find(|c| c.name == name)
                .ok_or_else(|| format!("Unknown test case '{name}'. Known: {}", known.join(", ")))?;
            out.push(tc);
        }
        out
    };

    // Ensure signing key exists before parallel variant builds.
    let _ = env.signing_key()?;

    let mut results: Vec<CaseResult> = Vec::new();
    let mut release_image: Option<PathBuf> = None;
    let mut variant_images: BTreeMap<String, PathBuf> = BTreeMap::new();
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);

    // 1. Reproducible build check (full run only): build release cleanly in build/ and build/repro/
    //    with zero shared cache between them and require byte-identical discrete.img.
    if cases_filter.is_empty() && !no_repro {
        let r1 = build_image(
            env,
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
        let sw = Instant::now();
        let repro_dir = env.build.join("repro");
        let _ = fs::remove_dir_all(&repro_dir);
        let r2 = build_image(
            env,
            &BuildOpts {
                out_dir: repro_dir,
                kernel_test: None,
                ubsan: false,
                kasan: false,
                quiet: true,
                shared: None,
                jobs: cpus,
            },
        )?;
        let h1 = sha256_file(&r1.image)?;
        let h2 = sha256_file(&r2.image)?;
        let same = h1 == h2;
        println!(
            "--- [repro] {} vs {}: {} ---",
            &h1[..16],
            &h2[..16],
            if same { "identical" } else { "DIFFERENT" }
        );
        results.push(CaseResult {
            name: "repro".into(),
            result: if same { "PASS" } else { "FAIL" },
            seconds: sw.elapsed().as_secs_f64(),
        });
        release_image = Some(r1.image);
    }

    // 2. Collect unique KTEST variants and build them in parallel using shared userland + bootloaders!
    struct VariantSpec {
        key: String,
        define: &'static str,
        ubsan: bool,
        kasan: bool,
        out_dir: PathBuf,
    }
    let mut variants: Vec<VariantSpec> = Vec::new();
    for tc in &selected {
        if let Some(def) = tc.define {
            let key = format!("{def}|{}|{}", tc.ubsan, tc.kasan);
            if !variants.iter().any(|v| v.key == key) {
                variants.push(VariantSpec {
                    key,
                    define: def,
                    ubsan: tc.ubsan,
                    kasan: tc.kasan,
                    out_dir: env.build.join("ktest").join(tc.name),
                });
            }
        }
    }

    if !variants.is_empty() {
        let sw = Instant::now();
        // Build shared userland + compat + bootloaders + kernel ASM ONCE in build/ (reusing
        // what the release build above already produced!).
        let shared = Arc::new(build_shared(env, &env.build, true)?);
        let workers = (cpus / 2).max(2).min(variants.len());
        let next_idx = &std::sync::atomic::AtomicUsize::new(0);
        let built: &std::sync::Mutex<Vec<(String, PathBuf)>> = &std::sync::Mutex::new(Vec::new());
        let errors: &std::sync::Mutex<Vec<String>> = &std::sync::Mutex::new(Vec::new());
        let variants_ref = &variants;

        std::thread::scope(|s| {
            for _ in 0..workers {
                let shared = Arc::clone(&shared);
                s.spawn(move || loop {
                    let i = next_idx.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if i >= variants_ref.len() {
                        break;
                    }
                    let v = &variants_ref[i];
                    let res = build_image(
                        env,
                        &BuildOpts {
                            out_dir: v.out_dir.clone(),
                            kernel_test: Some(v.define.to_string()),
                            ubsan: v.ubsan,
                            kasan: v.kasan,
                            quiet: true,
                            shared: Some(Arc::clone(&shared)),
                            jobs: 2,
                        },
                    );
                    match res {
                        Ok(r) => built.lock().unwrap().push((v.key.clone(), r.image)),
                        Err(e) => errors.lock().unwrap().push(format!(
                            "--- build of {} (ubsan: {}, kasan: {}) failed:\n{e}",
                            v.define, v.ubsan, v.kasan
                        )),
                    }
                });
            }
        });

        let errs = errors.lock().unwrap();
        if !errs.is_empty() {
            for e in errs.iter() {
                eprintln!("{e}");
            }
            return Err("Test variant build failed.".into());
        }
        for (k, img) in built.lock().unwrap().iter() {
            variant_images.insert(k.clone(), img.clone());
        }
        println!(
            "--- built {} test variant(s) in parallel ({:.1}s, {workers} at a time, shared userland) ---",
            variants.len(),
            sw.elapsed().as_secs_f64()
        );
    }

    // 3. Execute each selected test case sequentially (timing-sensitive tests stay accurate).
    for tc in &selected {
        if let Some(host) = tc.host {
            let sw = Instant::now();
            println!("--- [{}] host ---", tc.name);
            let ok = run_host_test(env, host)?;
            results.push(CaseResult {
                name: tc.name.into(),
                result: if ok { "PASS" } else { "FAIL" },
                seconds: sw.elapsed().as_secs_f64(),
            });
            continue;
        }

        let (out_dir, mut image) = if let Some(def) = tc.define {
            let key = format!("{def}|{}|{}", tc.ubsan, tc.kasan);
            let dir = env.build.join("ktest").join(tc.name);
            fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            let img = variant_images
                .get(&key)
                .ok_or_else(|| format!("missing built variant for {}", tc.name))?
                .clone();
            (dir, img)
        } else {
            let img = match &release_image {
                Some(i) => i.clone(),
                None => {
                    let r = build_image(
                        env,
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
                    release_image = Some(r.image.clone());
                    r.image
                }
            };
            (env.build.clone(), img)
        };

        if tc.tamper {
            image = make_tampered_image(env, &image)?;
        } else if tc.define.is_none() && !tc.desktop {
            image = make_text_console_image(env, &image)?;
        }

        let disk_dir = env.build.join("disks").join(tc.name);
        if (tc.devices || tc.usb_disk.is_some()) && disk_dir.exists() {
            let _ = fs::remove_dir_all(&disk_dir);
        }
        let mut extra = tc.qemu_extra.clone();
        if let Some(usb_suffix) = tc.usb_disk {
            fs::create_dir_all(&disk_dir).map_err(|e| e.to_string())?;
            let usb = disk_dir.join("usb.img");
            img::make_nvme(&usb)?;
            fs::copy(&usb, disk_dir.join("usb.pristine")).map_err(|e| e.to_string())?;
            extra.extend([
                "-drive".into(),
                format!("if=none,id=usb1,format=raw,file={}", usb.display()),
                "-device".into(),
                format!("usb-storage,bus=xhci.0,drive=usb1{usb_suffix}"),
            ]);
        }

        if tc.audio_wav {
            fs::create_dir_all(&disk_dir).map_err(|e| e.to_string())?;
            let wav = disk_dir.join("out.wav");
            let _ = fs::remove_file(&wav);
            extra.extend([
                "-audiodev".into(),
                format!(
                    "wav,id=snd0,out.frequency=48000,out.channels=2,out.format=s16,path={}",
                    wav.display()
                ),
            ]);
        }

        let _net_srv = if tc.net_server {
            let srv = NetTestServer::start()?;
            extra.splice(0..0, ["-netdev".into(), srv.netdev_arg()]);
            Some(srv)
        } else {
            None
        };

        let limit = tc.timeout.max(default_timeout);
        let cap = if let Some(bochs_model) = tc.bochs {
            let bdir = env.build.join("bochs").join(tc.name);
            let log_p = bdir.join(format!("serial-{}.log", tc.name));
            match bochs_capture(
                env,
                &image,
                &log_p,
                &tc.expect,
                &tc.forbid,
                limit,
                bochs_model,
                tc.bochs_strict_msr,
            )? {
                Some(c) => c,
                None => {
                    println!("--- [{}] skipped: Bochs is not installed ---", tc.name);
                    results.push(CaseResult { name: tc.name.into(), result: "SKIP", seconds: 0.0 });
                    continue;
                }
            }
        } else {
            let log_p = out_dir.join(format!("serial-{}.log", tc.name));
            let qopts = QemuOpts {
                image: &image,
                cpus: tc.smp,
                cpu_model: tc.cpu,
                devices: tc.devices,
                disk_dir: &disk_dir,
                uefi: tc.uefi,
                iommu: tc.iommu,
                extra: &extra,
                must_exit: tc.must_exit,
            };
            qemu_capture(
                env,
                &qopts,
                &log_p,
                &tc.expect,
                &tc.forbid,
                limit,
                &tc.keys,
                tc.keys_after,
                &tc.serial,
                tc.serial_after,
            )?
        };

        let mut missing: Vec<String> = tc
            .expect
            .iter()
            .filter(|e| !cap.log.contains(e.as_str()))
            .cloned()
            .collect();
        let found: Vec<String> = tc
            .forbid
            .iter()
            .filter(|f| cap.log.contains(f.as_str()))
            .cloned()
            .collect();
        let mut ok = missing.is_empty() && found.is_empty();
        if tc.must_exit && !cap.exited {
            missing.push("QEMU did not end (no power-off / reset happened)".into());
            ok = false;
        }

        println!("--- [{}] serial ({:.1}s) ---", tc.name, cap.seconds);
        println!("{}", cap.log.trim_end());

        if ok && let Some(post) = tc.post {
            let post_ok = run_post_check(env, post, &disk_dir, &image, &cap.log)?;
            if !post_ok {
                eprintln!("  host check FAILED");
            }
            ok = ok && post_ok;
        }
        if !ok {
            if !missing.is_empty() {
                eprintln!("  missing:   {}", missing.join(" | "));
            }
            if !found.is_empty() {
                eprintln!("  forbidden: {}", found.join(" | "));
            }
        }
        results.push(CaseResult {
            name: tc.name.into(),
            result: if ok { "PASS" } else { "FAIL" },
            seconds: cap.seconds,
        });
    }

    println!();
    for r in &results {
        println!("  {:<13} {:<4}  ({:.1}s)", r.name, r.result, r.seconds);
    }
    let failed = results.iter().filter(|r| r.result == "FAIL").count();
    let skipped = results.iter().filter(|r| r.result == "SKIP").count();
    let skip_note = if skipped > 0 {
        format!(", {skipped} skipped")
    } else {
        String::new()
    };
    let verdict = if failed > 0 {
        format!("TEST FAILED ({failed} of {})", results.len())
    } else {
        format!("TEST PASSED ({} cases{skip_note})", results.len())
    };
    write_test_report(env, &results, &verdict, !cases_filter.is_empty());
    if failed > 0 {
        return Err(verdict);
    }
    println!("{verdict}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Post-boot host checks
// ---------------------------------------------------------------------------

fn run_post_check(
    env: &Env,
    check: PostCheck,
    disk_dir: &Path,
    image: &Path,
    log: &str,
) -> Result<bool, String> {
    match check {
        PostCheck::DisksUnchanged => post_disks_unchanged(env, disk_dir, image),
        PostCheck::StorageImages => post_storage_images(env, disk_dir),
        PostCheck::AttestReport => post_attest_report(env, image, log),
        PostCheck::UsbProbedOnce => {
            let n = log.matches("left unused").count();
            let m = log.matches("mouse ready on port").count();
            println!("  xhci: {n} 'left unused' line(s) (expected 1: the tablet), {m} mouse (expected 1)");
            Ok(n == 1 && m == 1)
        }
        PostCheck::UsbDiskUnchanged => {
            let a = sha256_file(&disk_dir.join("usb.img"))?;
            let b = sha256_file(&disk_dir.join("usb.pristine"))?;
            println!("  host: USB stick after a read-only boot: {}", if a == b { "unchanged" } else { "CHANGED" });
            Ok(a == b)
        }
        PostCheck::UsbPlugOnce => {
            let n = log.matches("left unused").count();
            let g = log.matches("keeps reconnecting").count();
            println!("  xhci: {n} 'left unused', {g} 'keeps reconnecting' line(s) (expected 1, 1)");
            Ok(n == 1 && g == 1)
        }
        PostCheck::TimeReboot => post_time_reboot(env, disk_dir, image, log, false),
        PostCheck::TimeRebootUefi => post_time_reboot(env, disk_dir, image, log, true),
        PostCheck::ServicesOrder => Ok(post_services_order(log)),
        PostCheck::KaslrReboots => post_kaslr_reboots(env, image, log),
        PostCheck::AudioWav(hz) => post_audio_wav(disk_dir, hz),
    }
}

/// Verify a QEMU `-audiodev wav` capture file: valid RIFF/WAVE PCM header, audible RMS & peak
/// level, and dominant Goertzel frequency matching `expected_hz` (±25 Hz).
fn post_audio_wav(disk_dir: &Path, expected_hz: u32) -> Result<bool, String> {
    let path = disk_dir.join("out.wav");
    let raw = fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    if raw.len() < 44 || &raw[0..4] != b"RIFF" || &raw[8..12] != b"WAVE" {
        println!("  wav: invalid RIFF/WAVE header ({} bytes)", raw.len());
        return Ok(false);
    }
    let mut off = 12usize;
    let mut channels = 0u16;
    let mut rate = 0u32;
    let mut bits = 0u16;
    let mut pcm: &[u8] = &[];
    while off + 8 <= raw.len() {
        let id = &raw[off..off + 4];
        let sz = u32::from_le_bytes([raw[off + 4], raw[off + 5], raw[off + 6], raw[off + 7]]) as usize;
        let body_start = off + 8;
        let body_end = body_start.saturating_add(sz).min(raw.len());
        if id == b"fmt " && body_end - body_start >= 16 {
            channels = u16::from_le_bytes([raw[body_start + 2], raw[body_start + 3]]);
            rate = u32::from_le_bytes([
                raw[body_start + 4],
                raw[body_start + 5],
                raw[body_start + 6],
                raw[body_start + 7],
            ]);
            bits = u16::from_le_bytes([raw[body_start + 14], raw[body_start + 15]]);
        } else if id == b"data" {
            // Streaming WAV writers (including QEMU `-audiodev wav`) leave `sz == 0` when closed
            // without rewriting the header, meaning PCM continues to EOF.
            let data_end = if sz == 0 { raw.len() } else { body_end };
            pcm = &raw[body_start..data_end];
            break;
        }
        off = body_start.saturating_add(sz + (sz & 1));
    }
    if channels == 0 || rate == 0 || bits != 16 || pcm.is_empty() {
        println!("  wav: unsupported format (ch={channels}, rate={rate}, bits={bits}, data={})", pcm.len());
        return Ok(false);
    }
    let frame_bytes = usize::from(channels) * 2;
    let total_frames = pcm.len() / frame_bytes;
    let mut mono = Vec::with_capacity(total_frames);
    for i in 0..total_frames {
        let mut sum = 0i32;
        for c in 0..usize::from(channels) {
            let p = i * frame_bytes + c * 2;
            sum += i32::from(i16::from_le_bytes([pcm[p], pcm[p + 1]]));
        }
        mono.push((sum / i32::from(channels)) as f64);
    }
    // Locate the active non-silent window (samples above threshold 400).
    let first = mono.iter().position(|&s| s.abs() > 400.0);
    let last = mono.iter().rposition(|&s| s.abs() > 400.0);
    let (Some(start), Some(end)) = (first, last) else {
        println!("  wav: {total_frames} frames @ {rate} Hz, but completely silent (peak < 400)");
        return Ok(false);
    };
    let active = &mono[start..=end];
    let n = active.len().min((rate as usize) * 3 / 4); // analyze up to the final 750 ms of active tone
    if n < 480 {
        println!("  wav: active tone too short ({n} frames)");
        return Ok(false);
    }
    let seg = &active[active.len() - n..];
    let mut peak = 0.0f64;
    let mut sum_sq = 0.0f64;
    for &s in seg {
        peak = peak.max(s.abs());
        sum_sq += s * s;
    }
    let rms = (sum_sq / n as f64).sqrt();

    // Goertzel magnitude sweep across 100..=1600 Hz in 5 Hz steps.
    let goertzel = |freq_hz: f64| -> f64 {
        let omega = 2.0 * std::f64::consts::PI * freq_hz / (rate as f64);
        let coeff = 2.0 * omega.cos();
        let (mut s1, mut s2) = (0.0f64, 0.0f64);
        for &x in seg {
            let s0 = x + coeff * s1 - s2;
            s2 = s1;
            s1 = s0;
        }
        (s1 * s1 + s2 * s2 - coeff * s1 * s2).max(0.0).sqrt() / (n as f64)
    };

    let mut best_hz = 0u32;
    let mut best_mag = 0.0f64;
    let mut bg_sum = 0.0f64;
    let mut bg_cnt = 0usize;
    let mut f = 100u32;
    while f <= 1600 {
        let m = goertzel(f64::from(f));
        if m > best_mag {
            best_mag = m;
            best_hz = f;
        }
        if f.abs_diff(expected_hz) > 60 {
            bg_sum += m;
            bg_cnt += 1;
        }
        f += 5;
    }
    let bg_avg = if bg_cnt > 0 { bg_sum / bg_cnt as f64 } else { 1.0 };
    let snr = best_mag / bg_avg.max(1.0);
    let freq_ok = best_hz.abs_diff(expected_hz) <= 25;
    let level_ok = peak >= 2500.0 && rms >= 1200.0 && snr >= 5.0;
    println!(
        "  wav: {rate} Hz {channels}ch 16-bit, active {n} frames ({:.0} ms), peak={peak:.0}, rms={rms:.0}, dominant={best_hz} Hz (expected {expected_hz} Hz, SNR={snr:.1}x)",
        (n as f64 * 1000.0) / (rate as f64)
    );
    Ok(freq_ok && level_ok)
}

fn post_disks_unchanged(env: &Env, disk_dir: &Path, image: &Path) -> Result<bool, String> {
    let mut ok = true;
    let sums_path = image.parent().unwrap_or(&env.build).join("SHA256SUMS");
    let sums = fs::read_to_string(&sums_path).map_err(|e| e.to_string())?;
    let want = sums
        .lines()
        .find(|l| l.ends_with(" discrete.img"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or("");
    let got = sha256_file(image)?;
    let mut results = vec![format!(
        "boot image {}",
        if want == got { "unchanged" } else { "CHANGED" }
    )];
    ok &= want == got;

    for k in ["sata", "nvme"] {
        let d = disk_dir.join(format!("{k}.img"));
        let b = env.build.join("disks/base2").join(format!("{k}.img"));
        let u = d.is_file() && sha256_file(&d)? == sha256_file(&b)?;
        results.push(format!("{k} {}", if u { "unchanged" } else { "CHANGED" }));
        ok &= u;
    }

    let mut expected_d = vec![0u8; 1024 * 1024];
    for sec in 0..2048usize {
        let b = (sec * 13) % 256;
        for j in 0..512usize {
            expected_d[sec * 512 + j] = ((b + j) % 256) as u8;
        }
    }
    let want_v = to_hex(&doscrypt::sha2::sha256(&expected_d));
    let got_v = sha256_file(&get_test_disk(env)?)?;
    let u = want_v == got_v;
    results.push(format!("virtio-blk {}", if u { "unchanged" } else { "CHANGED" }));
    ok &= u;

    println!("  host: disks after a read-only boot: {}", results.join(", "));
    Ok(ok)
}

fn post_storage_images(env: &Env, disk_dir: &Path) -> Result<bool, String> {
    let sata = disk_dir.join("sata.img");
    let fat = disk_dir.join("boot.fat");
    let mut ok = true;
    img::extract_part(&sata, 1, &fat)?;
    if let Some(sz) = env.seven_zip() {
        let (_, list) = run_capture_all(sz, &["l".into(), fat.to_string_lossy().into_owned()], None, &[])?;
        let (_, text) = run_capture_all(
            sz,
            &["e".into(), "-so".into(), fat.to_string_lossy().into_owned(), "Written by D-OS.txt".into()],
            None,
            &[],
        )?;
        let seen = list.contains("Written by D-OS.txt")
            && text.contains("Hello from D-OS: FAT32 write works.");
        println!(
            "  host: 7-Zip reads 'Written by D-OS.txt' from the FAT32 volume: {}",
            if seen { "yes" } else { "NO" }
        );
        ok &= seen;
    } else {
        println!("  host: 7-Zip not installed: FAT32 interoperability check skipped");
    }
    match img::fsck_dfs(&sata, 2) {
        Ok(msg) => {
            println!("  host: {msg}");
            Ok(ok)
        }
        Err(msg) => {
            println!("  host: {msg}");
            Ok(false)
        }
    }
}

fn post_attest_report(env: &Env, image: &Path, log: &str) -> Result<bool, String> {
    let dir = image.parent().unwrap_or(&env.build);
    let mut nonce = String::new();
    let mut hex = String::new();
    for line in log.lines() {
        if let Some(rest) = line.split("utest: attest nonce ").nth(1) {
            let tok = rest.split_whitespace().next().unwrap_or("");
            if tok.len() == 64 && tok.bytes().all(|b| b.is_ascii_hexdigit()) {
                nonce = tok.to_string();
            }
        } else if let Some(rest) = line.split("utest: attest data ").nth(1) {
            let tok = rest.split_whitespace().next().unwrap_or("");
            if tok.bytes().all(|b| b.is_ascii_hexdigit()) {
                hex.push_str(tok);
            }
        }
    }
    if nonce.is_empty() || hex.len() < 2 {
        println!("  attest: no report in the log");
        return Ok(false);
    }
    let bytes = img::from_hex(&hex)?;
    let report = dir.join("attest-report.bin");
    fs::write(&report, &bytes).map_err(|e| e.to_string())?;
    let dsig = dir.join("kernel.dsig");
    let key = &env.signing_key()?.public;
    let with_tpm = log.contains("TPM: TPM 2.0 (simulator");
    let ca = dir.join("attest-test-ca.der");
    if with_tpm {
        img::attest_test_ca(&ca)?;
    }

    let mut ok = true;
    let cas: Vec<&Path> = if with_tpm { vec![ca.as_path()] } else { Vec::new() };
    match img::attest_verify(&report, &nonce, &dsig, key, false, with_tpm, &cas) {
        Ok(msg) => {
            println!("  host: {msg}");
            if !msg.contains("attest: VALID") || (with_tpm && !msg.contains("EK certified")) {
                ok = false;
            }
        }
        Err(msg) => {
            println!("  host: {msg}");
            ok = false;
        }
    }

    if with_tpm {
        let ch = dir.join("attest-challenge.bin");
        match img::attest_challenge(&report, &ch) {
            Ok(cred) => {
                let len = fs::metadata(&ch).map(|m| m.len()).unwrap_or(0);
                let made = cred.len() == 64 && len == 328;
                println!(
                    "  host: attest, credential challenge for the report's EK and AK: {}",
                    if made { "made (328 bytes)" } else { "NOT MADE" }
                );
                ok &= made;
            }
            Err(e) => {
                println!("  host: attest, credential challenge NOT MADE: {e}");
                ok = false;
            }
        }
        let bad_ca = dir.join("attest-other-ca.der");
        let mut c = fs::read(&ca).map_err(|e| e.to_string())?;
        c[300] ^= 0x10;
        fs::write(&bad_ca, &c).map_err(|e| e.to_string())?;
        let r = img::attest_verify(&report, &nonce, &dsig, key, false, true, &[bad_ca.as_path()]);
        let refused = matches!(&r, Err(m) if m.contains("REFUSED: EkUntrusted"));
        println!(
            "  host: attest, EK certificate checked against a CA that did not sign it: {}",
            if refused { "refused (EkUntrusted)" } else { "NOT REFUSED" }
        );
        ok &= refused;
    } else {
        let r = img::attest_verify(&report, &nonce, &dsig, key, false, true, &[]);
        let refused = matches!(&r, Err(m) if m.contains("REFUSED: TpmRequired"));
        println!(
            "  host: attest, a TPM required of a machine without one: {}",
            if refused { "refused (TpmRequired)" } else { "NOT REFUSED" }
        );
        ok &= refused;
    }

    // Attack checks
    let mut other = nonce[..63].to_string();
    other.push(if nonce.as_bytes()[63] == b'0' { '1' } else { '0' });
    let tampered = dir.join("attest-tampered.bin");
    let mut t = bytes.clone();
    t[200] ^= 1;
    fs::write(&tampered, &t).map_err(|e| e.to_string())?;
    let foreign = dir.join("attest-other-kernel.dsig");
    let mut fd = fs::read(&dsig).map_err(|e| e.to_string())?;
    fd[100] ^= 1;
    fs::write(&foreign, &fd).map_err(|e| e.to_string())?;

    for (label, rep, n, d, want_err) in [
        ("replayed for another nonce", report.as_path(), other.as_str(), dsig.as_path(), "Nonce"),
        ("one byte changed", tampered.as_path(), nonce.as_str(), dsig.as_path(), "Signature"),
        ("checked against another kernel", report.as_path(), nonce.as_str(), foreign.as_path(), "UnknownKernel"),
    ] {
        let r = img::attest_verify(rep, n, d, key, false, with_tpm, &cas);
        let refused = matches!(&r, Err(m) if m.contains(&format!("REFUSED: {want_err}")));
        println!(
            "  host: attest, {label}: {}",
            if refused { format!("refused ({want_err})") } else { format!("NOT REFUSED: {r:?}") }
        );
        ok &= refused;
    }
    Ok(ok)
}

fn post_time_reboot(
    env: &Env,
    disk_dir: &Path,
    image: &Path,
    first_log: &str,
    uefi: bool,
) -> Result<bool, String> {
    let dir = image.parent().unwrap_or(&env.build);
    let log2 = dir.join(format!("serial-time-second{}.log", if uefi { "-uefi" } else { "" }));
    let expect: Vec<String> = [
        "svc-time: second boot: PASSED",
        "init: time test: second boot PASSED",
        "Power: switching off",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    let forbid: Vec<String> = ["KERNEL PANIC", "svc FAIL", "PANIC", "FAILED"]
        .iter()
        .map(|s| (*s).to_string())
        .collect();

    std::thread::sleep(Duration::from_millis(1100));
    let qopts = QemuOpts {
        image,
        cpus: 4,
        cpu_model: "max",
        devices: true,
        disk_dir,
        uefi,
        iommu: "intel",
        extra: &[],
        must_exit: true,
    };
    let r = qemu_capture(env, &qopts, &log2, &expect, &forbid, 180, &[], "", &[], "")?;
    let mut ok = expect.iter().all(|e| r.log.contains(e.as_str()));
    let line = r
        .log
        .lines()
        .find(|l| l.contains("svc-time: second boot"))
        .unwrap_or("FAILED");
    println!("  time: second boot: {}", if ok { line.trim() } else { "FAILED" });
    if !ok {
        let ls: Vec<&str> = r.log.lines().collect();
        for l in &ls[ls.len().saturating_sub(15)..] {
            println!("{l}");
        }
    }

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    for l in [first_log, r.log.as_str()] {
        if let Some((ts, disp)) = parse_clock_line(l) {
            let off_min = ((now_secs - ts).abs() as f64) / 60.0;
            println!("  time: D-OS said {disp}, host diff {off_min:.1} min");
            if off_min > 15.0 {
                ok = false;
            }
        } else {
            println!("  time: no clock line");
            ok = false;
        }
    }
    Ok(ok)
}

fn parse_clock_line(log: &str) -> Option<(i64, String)> {
    for line in log.lines() {
        let Some(rest) = line.split("clock: ").nth(1) else {
            continue;
        };
        if rest.len() < 23 || !rest[19..].starts_with(" UTC") {
            continue;
        }
        let s = &rest[..19];
        let b = s.as_bytes();
        if b[4] != b'-' || b[7] != b'-' || b[10] != b' ' || b[13] != b':' || b[16] != b':' {
            continue;
        }
        let y: i64 = s[0..4].parse().ok()?;
        let mo: i64 = s[5..7].parse().ok()?;
        let d: i64 = s[8..10].parse().ok()?;
        let h: i64 = s[11..13].parse().ok()?;
        let mi: i64 = s[14..16].parse().ok()?;
        let se: i64 = s[17..19].parse().ok()?;
        let days = days_from_civil(y, mo, d);
        return Some((days * 86400 + h * 3600 + mi * 60 + se, format!("{s} UTC")));
    }
    None
}

/// Howard Hinnant's algorithm: days since 1970-01-01.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = y - if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn civil_from_unix(secs: i64) -> (i64, u32, u32, u32, u32) {
    let z = secs.div_euclid(86400) + 719468;
    let rem = secs.rem_euclid(86400) as u32;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = y + if m <= 2 { 1 } else { 0 };
    (y, m, d, rem / 3600, (rem % 3600) / 60)
}

fn post_services_order(log: &str) -> bool {
    let seq = [
        "init: syncing storaged",
        "storaged: sync: 5 volume(s) durable",
        "init: stopping shell",
        "init: stopping terminal",
        "init: stopping devmgr",
        "devmgr: shutdown:",
        "init: stopping storaged",
        "storaged: shutdown: 5 volume(s) durable",
        "init: shutdown: every service stopped",
        "Power: switch-off requested by process init",
    ];
    let pos: Vec<Option<usize>> = seq.iter().map(|s| log.find(s)).collect();
    let mut ok = pos.iter().all(Option::is_some);
    if ok {
        for w in pos.windows(2) {
            if w[1].unwrap() < w[0].unwrap() {
                ok = false;
            }
        }
    }
    println!(
        "  services: shutdown order {}",
        if ok {
            "volumes made durable, then shell, terminal, devmgr, storaged (each after what depends on it), then power-off".to_string()
        } else {
            format!("WRONG: {pos:?}")
        }
    );
    ok
}

fn parse_kaslr_layout(log: &str) -> Option<[String; 4]> {
    for line in log.lines() {
        let Some(rest) = line.split("KTEST kaslr: layout image ").nth(1) else {
            continue;
        };
        let parts: Vec<&str> = rest.split_whitespace().collect();
        // <img_addr> direct map <dm_addr> heap <h_addr> stacks <s_addr>
        if parts.len() >= 8 && parts[1] == "direct" && parts[2] == "map" && parts[4] == "heap" && parts[6] == "stacks" {
            return Some([
                parts[0].to_string(),
                parts[3].to_string(),
                parts[5].to_string(),
                parts[7].to_string(),
            ]);
        }
    }
    None
}

fn post_kaslr_reboots(env: &Env, image: &Path, first_log: &str) -> Result<bool, String> {
    let mut layouts = Vec::new();
    if let Some(l) = parse_kaslr_layout(first_log) {
        layouts.push(l);
    }
    let dir = image.parent().unwrap_or(&env.build);
    let expect: Vec<String> = ["KTEST kaslr: PASSED", "D-KRNL: ready"]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let forbid: Vec<String> = ["KERNEL PANIC", "FAIL"]
        .iter()
        .map(|s| (*s).to_string())
        .collect();

    for uefi in [false, true] {
        let log_p = dir.join(format!("serial-kaslr-{}.log", if uefi { "uefi" } else { "bios2" }));
        let qopts = QemuOpts {
            image,
            cpus: 4,
            cpu_model: "max",
            devices: false,
            disk_dir: dir,
            uefi,
            iommu: "intel",
            extra: &[],
            must_exit: false,
        };
        let r = qemu_capture(env, &qopts, &log_p, &expect, &forbid, 90, &[], "", &[], "")?;
        if let Some(l) = parse_kaslr_layout(&r.log) {
            layouts.push(l);
        }
        let passed = expect.iter().all(|e| r.log.contains(e.as_str()));
        println!(
            "  {} reboot: {}",
            if uefi { "UEFI" } else { "BIOS" },
            if passed { "KTEST kaslr: PASSED" } else { "FAILED" }
        );
        if !passed {
            return Ok(false);
        }
    }
    if layouts.len() != 3 {
        println!("  kaslr: expected 3 layouts, got {}", layouts.len());
        return Ok(false);
    }
    let names = ["image", "direct map", "heap", "stacks"];
    let mut ok = true;
    for (k, name) in names.iter().enumerate() {
        let vals: Vec<&str> = layouts.iter().map(|l| l[k].as_str()).collect();
        let mut uniq = vals.clone();
        uniq.sort_unstable();
        uniq.dedup();
        println!("  kaslr: {name}: {} ({} distinct)", vals.join(", "), uniq.len());
        if uniq.len() != 3 {
            ok = false;
        }
    }
    Ok(ok)
}

/// A copy of the release image that boots to the text console (`esp:/DOS/BOOT.CFG`:
/// `desktop = off`), made again whenever the release image changed.
fn make_text_console_image(env: &Env, image: &Path) -> Result<PathBuf, String> {
    let dir = env.build.join("textmode");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let copy = dir.join("discrete.img");
    let newer = |a: &Path, b: &Path| -> bool {
        match (fs::metadata(a).and_then(|m| m.modified()), fs::metadata(b).and_then(|m| m.modified())) {
            (Ok(x), Ok(y)) => x > y,
            _ => true,
        }
    };
    if newer(image, &copy) || !dir.join("SHA256SUMS").is_file() {
        fs::copy(image, &copy).map_err(|e| format!("copy text console image: {e}"))?;
        img::add_file(&copy, 2, "DOS/BOOT.CFG", b"# D-OS boot settings\r\ndesktop = off\r\n")?;
        // The checks that the boot image stayed unchanged compare against this copy's digest.
        fs::write(dir.join("SHA256SUMS"), format!("{}  discrete.img\n", sha256_file(&copy)?))
            .map_err(|e| format!("write SHA256SUMS: {e}"))?;
    }
    Ok(copy)
}

fn make_tampered_image(env: &Env, image: &Path) -> Result<PathBuf, String> {
    let dir = env.build.join("tampered");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let copy = dir.join("discrete.img");
    fs::copy(image, &copy).map_err(|e| format!("copy tampered image: {e}"))?;
    img::patch_file(&copy, 2, "DOS/KERNEL.BIN", 8192, 0x01)?;
    let mut f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&copy)
        .map_err(|e| e.to_string())?;
    let off = KERNEL_LBA * SECTOR_SIZE + 8192;
    f.seek(SeekFrom::Start(off)).map_err(|e| e.to_string())?;
    let mut b = [0u8; 1];
    f.read_exact(&mut b).map_err(|e| e.to_string())?;
    b[0] ^= 1;
    f.seek(SeekFrom::Start(off)).map_err(|e| e.to_string())?;
    f.write_all(&b).map_err(|e| e.to_string())?;
    Ok(copy)
}

// ---------------------------------------------------------------------------
// Host tests
// ---------------------------------------------------------------------------

/// Typed in the boot-to-desktop tests: commands in the terminal window, Super and an app from
/// the launcher, Ctrl+Alt+Esc out of the desktop, then a command in the text console.
fn desktop_keys() -> Vec<String> {
    let mut k = vec!["~1500".to_string()];
    k.extend(convert_to_qemu_keys(&["gui status", "gui text 125"], 1500));
    k.extend(["meta_l".to_string(), "~800".to_string()]);
    k.extend(convert_to_qemu_keys(&["widgets"], 2500));
    k.extend(["ctrl-alt-esc".to_string(), "~2000".to_string()]);
    k.extend(convert_to_qemu_keys(&["power off"], 500));
    k
}

const DESKTOP_EXPECT: [&str; 14] = [
    "init: boot: desktop",
    "awmi: fonts: 4 face(s)",
    "awmi: desktop session started at boot",
    "console: terminal window",
    "terminal: view attached",
    "terminal: line from console: gui status",
    "awmi: settings: theme Dark Slate, text 125%, motion on",
    "awmi: launcher: opening entry 0 of client",
    "awmi-demo: widgets window open",
    "awmi: session ended (the user left the session)",
    "terminal: view detached",
    "terminal: display reclaimed",
    ": power off",
    "Power: switching off",
];

fn run_host_test(env: &Env, test: HostTest) -> Result<bool, String> {
    match test {
        HostTest::Dosfs => host_cargo_test(env, "user/lib/fs", &[], &[]),
        HostTest::Manifest => host_cargo_test(env, "user/lib/dman", &["--", "--nocapture"], &["test result", "FAILED", "panicked", "dman fuzz"]),
        HostTest::Audio => host_cargo_test(env, "user/lib/audio", &["--", "--nocapture"], &["test result", "FAILED", "panicked"]),
        HostTest::Net => host_cargo_test(env, "user/lib/net", &["--", "--nocapture"], &["test result", "FAILED", "panicked"]),
        HostTest::Gpu => host_cargo_test(env, "user/lib/gpu", &["--", "--nocapture"], &["test result", "FAILED", "panicked"]),
        HostTest::Awmi => host_cargo_test(env, "user/lib/awmi", &["--", "--nocapture"], &["test result", "FAILED", "panicked"]),
        HostTest::Ui => Ok(host_cargo_test(env, "user/lib/font", &["--", "--nocapture"], &["test result", "FAILED", "panicked"])?
            && host_cargo_test(env, "user/lib/ui", &["--", "--nocapture"], &["test result", "FAILED", "panicked"])?),
        HostTest::Aml => host_aml_test(env),
        HostTest::Crypto => host_crypto_test(env),
        HostTest::Kaslr => host_kaslr_test(env),
        HostTest::Static => host_static_analysis(env),
    }
}

fn host_cargo_test(
    env: &Env,
    rel_crate: &str,
    extra: &[&str],
    filter: &[&str],
) -> Result<bool, String> {
    let cargo = env.cargo()?;
    let mut args = vec![
        "test".into(),
        "--release".into(),
        "--locked".into(),
        "--quiet".into(),
        "--target-dir".into(),
        env.build.join("host").to_string_lossy().into_owned(),
    ];
    args.extend(extra.iter().map(|s| (*s).to_string()));
    let (ok, out) = run_capture_all(
        cargo,
        &args,
        Some(&env.root.join(rel_crate)),
        &env.cargo_env_pairs(),
    )?;
    if filter.is_empty() {
        println!("{}", out.trim());
    } else {
        for line in out.lines() {
            if filter.iter().any(|f| line.contains(f)) {
                println!("  {}", line.trim());
            }
        }
    }
    Ok(ok)
}

fn export_acpi_tables(env: &Env) -> usize {
    let dir = env.build.join("host").join("acpi");
    #[cfg(windows)]
    {
        let script = format!(
            "$d = '{}'; if (Test-Path 'HKLM:\\HARDWARE\\ACPI') {{ \
             New-Item -ItemType Directory -Force $d | Out-Null; $n = 0; \
             foreach ($k in Get-ChildItem 'HKLM:\\HARDWARE\\ACPI' -ErrorAction SilentlyContinue) {{ \
               if ($k.PSChildName -notmatch '^(DSDT|SSD.|SSDT)$') {{ continue }}; \
               $leaf = Get-ChildItem $k.PSPath -Recurse -ErrorAction SilentlyContinue | Where-Object {{ $_.Property -contains '00000000' }} | Select-Object -First 1; \
               if (-not $leaf) {{ continue }}; \
               $b = (Get-ItemProperty $leaf.PSPath).'00000000'; \
               if ($b -is [byte[]] -and $b.Length -ge 36) {{ [IO.File]::WriteAllBytes((Join-Path $d \"$($k.PSChildName).aml\"), $b); $n++ }} \
             }}; $n }} else {{ 0 }}",
            dir.to_string_lossy().replace('\'', "''")
        );
        if let Some(ps) = find_in_path("pwsh").or_else(|| find_in_path("powershell"))
            && let Ok(out) = run_capture(&ps, &["-NoProfile", "-Command", &script], None, &[])
            && let Ok(n) = out.trim().parse::<usize>()
        {
            return n;
        }
        0
    }
    #[cfg(not(windows))]
    {
        let sys_dir = Path::new("/sys/firmware/acpi/tables");
        let Ok(rd) = fs::read_dir(sys_dir) else {
            return 0;
        };
        let _ = fs::create_dir_all(&dir);
        let mut n = 0usize;
        for e in rd.filter_map(|e| e.ok()) {
            let name = e.file_name().to_string_lossy().into_owned();
            if name == "DSDT" || name.starts_with("SSD") {
                if let Ok(bytes) = fs::read(e.path())
                    && bytes.len() >= 36
                    && fs::write(dir.join(format!("{name}.aml")), &bytes).is_ok()
                {
                    n += 1;
                }
            }
        }
        n
    }
}

fn host_aml_test(env: &Env) -> Result<bool, String> {
    let n = export_acpi_tables(env);
    if n > 0 {
        println!("  host: {n} firmware AML table(s) of this machine in build/host/acpi");
    } else {
        println!("  host: no firmware tables readable: built tables only");
    }
    host_cargo_test(
        env,
        "kernel/aml",
        &["--", "--nocapture", "--test-threads", "1"],
        &["test result", "FAILED", "panicked", "aml "],
    )
}

fn generate_p256_vectors(env: &Env, path: &Path) -> bool {
    let _ = env;
    #[cfg(windows)]
    {
        let script = format!(
            "$p = '{}'; $lines = [Collections.Generic.List[string]]::new(); \
             $hash = [Security.Cryptography.HashAlgorithmName]::SHA256; \
             for ($i = 0; $i -lt 48; $i++) {{ \
               $e = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256); \
               $q = $e.ExportParameters($false).Q; \
               $m = [byte[]]::new($i * 7); [Security.Cryptography.RandomNumberGenerator]::Fill($m); \
               $sig = $e.SignData($m, $hash); \
               $mh = if ($m.Length) {{ [Convert]::ToHexString($m) }} else {{ '-' }}; \
               $key = \"$([Convert]::ToHexString($q.X)) $([Convert]::ToHexString($q.Y))\"; \
               $lines.Add(\"$key $mh $([Convert]::ToHexString($sig)) 1\"); \
               $bad = [byte[]]$sig.Clone(); $bad[$i % 64] = $bad[$i % 64] -bxor (1 -shl ($i % 8)); \
               $lines.Add(\"$key $mh $([Convert]::ToHexString($bad)) 0\"); \
               $e.Dispose(); \
             }}; [IO.File]::WriteAllLines($p, $lines)",
            path.to_string_lossy().replace('\'', "''")
        );
        if let Some(ps) = find_in_path("pwsh").or_else(|| find_in_path("powershell")) {
            return run_capture(&ps, &["-NoProfile", "-Command", &script], None, &[]).is_ok();
        }
        false
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        false
    }
}

fn host_crypto_test(env: &Env) -> Result<bool, String> {
    let cargo = env.cargo()?;
    let vectors = env.build.join("host/p256-ext.txt");
    if let Some(p) = vectors.parent() {
        let _ = fs::create_dir_all(p);
    }
    let mut extra_env = env.cargo_env_pairs();
    if generate_p256_vectors(env, &vectors) {
        extra_env.push((
            "DOSCRYPT_P256_VECTORS".into(),
            vectors.to_string_lossy().into_owned(),
        ));
    }
    let (mut ok, out) = run_capture_all(
        cargo,
        &[
            "test".into(),
            "--release".into(),
            "--locked".into(),
            "--quiet".into(),
            "--target-dir".into(),
            env.build.join("host").to_string_lossy().into_owned(),
        ],
        Some(&env.root.join("user/lib/crypto")),
        &extra_env,
    )?;
    for line in out.lines() {
        if line.contains("test result") || line.contains("FAILED") || line.contains("panicked") {
            println!("  {}", line.trim());
        }
    }

    let Some(cc) = env.host_cc() else {
        println!("  host: no host C compiler: C verifier checks skipped");
        return Ok(ok);
    };
    let dir = env.build.join("host/ctest");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let exe = dir.join(exe_name("test_dcrypto"));
    let common = env.root.join("boot/common");
    run_cmd(
        cc,
        &[
            "-O2".into(),
            "-std=c11".into(),
            "-Wall".into(),
            "-Wextra".into(),
            "-Werror".into(),
            "-o".into(),
            exe.to_string_lossy().into_owned(),
            common.join("test_dcrypto.c").to_string_lossy().into_owned(),
            common.join("dcrypto.c").to_string_lossy().into_owned(),
        ],
        None,
        &[],
        true,
    )?;

    let cc_env = host_cc_runtime_env(cc);
    let (vec_ok, r) = run_capture_all(&exe, &[], None, &cc_env)?;
    println!("  host: {}", r.trim());
    ok &= vec_ok;

    let seed = dir.join("test.seed");
    fs::write(&seed, random_seed_32()).map_err(|e| e.to_string())?;
    let pub_hex = img::pubkey_hex(&seed)?;
    let mut agree = 0usize;
    for size in [0usize, 1, 127, 128, 129, 4096, 100003] {
        let f = dir.join(format!("data{size}.bin"));
        let mut d = vec![0u8; size];
        let mut blk = random_seed_32();
        for chunk in d.chunks_mut(32) {
            chunk.copy_from_slice(&blk[..chunk.len()]);
            blk = doscrypt::sha2::sha256(&blk);
        }
        fs::write(&f, &d).map_err(|e| e.to_string())?;
        let dsig = dir.join(format!("data{size}.bin.dsig"));
        img::sign_file(&seed, "program", &format!("data{size}"), &f, &dsig)?;
        let (good, _) = run_capture_all(
            &exe,
            &[
                pub_hex.clone(),
                f.to_string_lossy().into_owned(),
                dsig.to_string_lossy().into_owned(),
                "ok".into(),
            ],
            None,
            &cc_env,
        )?;
        let mut bad = true;
        if size > 0 {
            d[size - 1] ^= 0x80;
            fs::write(&f, &d).map_err(|e| e.to_string())?;
            let (b_ok, _) = run_capture_all(
                &exe,
                &[
                    pub_hex.clone(),
                    f.to_string_lossy().into_owned(),
                    dsig.to_string_lossy().into_owned(),
                    "bad".into(),
                ],
                None,
                &cc_env,
            )?;
            bad = b_ok;
        }
        if good && bad {
            agree += 1;
        } else {
            eprintln!("  host: cross-check FAILED for {size} bytes (verify {good}, tamper refused {bad})");
        }
    }
    println!("  host: {agree}/7 sizes: Rust signer -> C verifier valid, tampered copy refused");
    Ok(ok && agree == 7)
}

fn host_cc_runtime_env(cc: &Path) -> Vec<(String, String)> {
    let mut v = Vec::new();
    if let Some(dir) = cc.parent() {
        let sep = if cfg!(windows) { ";" } else { ":" };
        let cur = std::env::var("PATH").unwrap_or_default();
        v.push(("PATH".into(), format!("{}{sep}{cur}", dir.display())));
    }
    v
}

fn host_kaslr_test(env: &Env) -> Result<bool, String> {
    let Some(cc) = env.host_cc() else {
        println!("  host: no host C compiler");
        return Ok(false);
    };
    let elf = env.build.join("kernel.elf");
    let bin = env.build.join("kernel.bin");
    if !(elf.is_file() && bin.is_file()) {
        let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
        build_image(
            env,
            &BuildOpts {
                out_dir: env.build.clone(),
                kernel_test: None,
                ubsan: false,
                kasan: false,
                quiet: true,
                shared: None,
                jobs: cpus,
            },
        )?;
    }
    let dir = env.build.join("host/ctest");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let exe = dir.join(exe_name("test_kaslr"));
    let common = env.root.join("boot/common");
    run_cmd(
        cc,
        &[
            "-O2".into(),
            "-std=c11".into(),
            "-Wall".into(),
            "-Wextra".into(),
            "-Werror".into(),
            "-o".into(),
            exe.to_string_lossy().into_owned(),
            common.join("test_kaslr.c").to_string_lossy().into_owned(),
            common.join("kaslr.c").to_string_lossy().into_owned(),
            common.join("dcrypto.c").to_string_lossy().into_owned(),
        ],
        None,
        &[],
        true,
    )?;

    let cc_env = host_cc_runtime_env(cc);
    let (ok, r) = run_capture_all(&exe, &[], None, &cc_env)?;
    println!("  host: {}", r.trim());
    let (ok_list, list_out) = run_capture_all(
        &exe,
        &["list".into(), bin.to_string_lossy().into_owned()],
        None,
        &cc_env,
    )?;
    let mut ours: Vec<String> = list_out
        .lines()
        .map(|l| l.trim().to_ascii_lowercase())
        .filter(|l| !l.is_empty())
        .collect();
    ours.sort();

    let readobj = env.readobj()?;
    let elf_s = elf.to_string_lossy();
    let ro_out = run_capture(readobj, &["-r", &elf_s], None, &[])?;
    let mut theirs: Vec<String> = Vec::new();
    for line in ro_out.lines() {
        let t = line.trim();
        if t.contains("R_X86_64_RELATIVE")
            && let Some(hex) = t.strip_prefix("0x").and_then(|r| r.split_whitespace().next())
            && hex.len() == 16
        {
            theirs.push(hex.to_ascii_lowercase());
        }
    }
    theirs.sort();

    let same = ok_list && !ours.is_empty() && ours == theirs;
    println!(
        "  host: kernel.bin RELR: {} relocations decoded, llvm-readobj lists {}: {}",
        ours.len(),
        theirs.len(),
        if same { "identical" } else { "DIFFERENT" }
    );
    Ok(ok && same)
}

fn host_static_analysis(env: &Env) -> Result<bool, String> {
    let clang = env.clang()?;
    let inc = env.clang_resource_include()?;
    let null_out = if cfg!(windows) { "NUL" } else { "/dev/null" };
    let an: Vec<String> = vec![
        "--analyze".into(),
        "-Xanalyzer".into(),
        "-analyzer-output=text".into(),
        "-Xanalyzer".into(),
        "-analyzer-checker=core,unix,security,deadcode,nullability".into(),
        "-Xanalyzer".into(),
        "-analyzer-disable-checker=security.insecureAPI.DeprecatedOrUnsafeBufferHandling".into(),
        "-o".into(),
        null_out.into(),
    ];
    let kernel_flags: Vec<String> = vec![
        "--target=x86_64-elf".into(),
        "-std=c17".into(),
        "-ffreestanding".into(),
        "-fno-builtin".into(),
        "-nostdinc".into(),
        "-isystem".into(),
        inc.to_string_lossy().into_owned(),
        "-mno-red-zone".into(),
        "-mno-sse".into(),
        "-mno-mmx".into(),
        "-mno-80387".into(),
        "-I".into(),
        env.root.join("kernel/include").to_string_lossy().into_owned(),
    ];
    let kfiles = collect_files(&env.root.join("kernel"), "c", true);
    let common = env.root.join("boot/common");
    let user_src = env.root.join("user");
    let ufiles = collect_files(&user_src, "c", true);

    let mut sets: Vec<(String, Vec<String>, Vec<PathBuf>)> = Vec::new();
    sets.push(("kernel (release)".into(), kernel_flags.clone(), kfiles.clone()));
    for t in ["SELFTEST", "SPEC", "FUZZ"] {
        let mut fl = kernel_flags.clone();
        fl.extend(["-DKTEST".into(), format!("-DKTEST_{t}")]);
        sets.push((format!("kernel (KTEST_{t})"), fl, kfiles.clone()));
    }
    sets.push((
        "stage 3".into(),
        vec![
            "--target=x86_64-elf".into(),
            "-std=c17".into(),
            "-ffreestanding".into(),
            "-fno-builtin".into(),
            "-nostdinc".into(),
            "-isystem".into(),
            inc.to_string_lossy().into_owned(),
            "-mgeneral-regs-only".into(),
            "-I".into(),
            common.to_string_lossy().into_owned(),
        ],
        vec![
            env.root.join("boot/stage3/stage3.c"),
            common.join("dcrypto.c"),
            common.join("kaslr.c"),
        ],
    ));
    sets.push((
        "UEFI loader".into(),
        vec![
            "--target=x86_64-unknown-windows".into(),
            "-std=c17".into(),
            "-ffreestanding".into(),
            "-fno-builtin".into(),
            "-nostdinc".into(),
            "-isystem".into(),
            inc.to_string_lossy().into_owned(),
            "-fshort-wchar".into(),
            "-mgeneral-regs-only".into(),
        ],
        vec![env.root.join("boot/uefi/loader.c")],
    ));
    sets.push((
        "user C".into(),
        vec![
            "--target=x86_64-unknown-elf".into(),
            "-std=c17".into(),
            "-ffreestanding".into(),
            "-nostdinc".into(),
            "-isystem".into(),
            inc.to_string_lossy().into_owned(),
            "-I".into(),
            user_src.join("include").to_string_lossy().into_owned(),
        ],
        ufiles,
    ));

    let mut findings = 0usize;
    let mut total_files = 0usize;
    let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);

    for (name, flags, files) in &sets {
        let next_idx = std::sync::atomic::AtomicUsize::new(0);
        let warn_lines: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
        let fail: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
        let workers = cpus.min(files.len().max(1));

        std::thread::scope(|s| {
            for _ in 0..workers {
                s.spawn(|| loop {
                    if fail.lock().unwrap().is_some() {
                        break;
                    }
                    let i = next_idx.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if i >= files.len() {
                        break;
                    }
                    let f = &files[i];
                    let mut args = flags.clone();
                    args.extend(an.iter().cloned());
                    args.push(f.to_string_lossy().into_owned());
                    match run_capture_all(clang, &args, None, &[]) {
                        Ok((true, out)) => {
                            let ws: Vec<String> = out
                                .lines()
                                .filter(|l| l.contains(": warning: "))
                                .map(|l| l.trim().to_string())
                                .collect();
                            if !ws.is_empty() {
                                warn_lines.lock().unwrap().extend(ws);
                            }
                        }
                        Ok((false, out)) => {
                            *fail.lock().unwrap() =
                                Some(format!("clang failed on {}:\n{out}", env.rel(f)));
                            break;
                        }
                        Err(e) => {
                            *fail.lock().unwrap() = Some(e);
                            break;
                        }
                    }
                });
            }
        });
        if let Some(e) = fail.into_inner().unwrap() {
            println!("  static: {e}");
            return Ok(false);
        }
        let ws = warn_lines.into_inner().unwrap();
        for w in &ws {
            println!("  {w}");
        }
        println!("  static: clang analyzer, {name}: {} files, {} findings", files.len(), ws.len());
        findings += ws.len();
        total_files += files.len();
    }

    // Clippy across every Rust crate (standalone crates + user workspace).
    let cargo = env.cargo()?;
    let clippy_dir = env.build.join("clippy");
    let cargo_env = env.cargo_env_pairs();
    let standalone: [(&str, &[&str]); 12] = [
        ("kernel/rust", &[]),
        ("kernel/aml", &["--all-targets"]),
        ("user/lib/audio", &["--all-targets"]),
        ("user/lib/net", &["--all-targets"]),
        ("user/lib/gpu", &["--all-targets"]),
        ("user/lib/awmi", &["--all-targets"]),
        ("user/lib/font", &["--all-targets"]),
        ("user/lib/ui", &["--all-targets"]),
        ("user/lib/crypto", &["--all-targets"]),
        ("user/lib/fs", &["--all-targets"]),
        ("user/lib/dman", &["--all-targets"]),
        ("tools/dbuild", &["--all-targets"]),
    ];
    let mut crate_count = 0usize;
    for (rel, extra) in standalone {
        let mut args = vec![
            "clippy".into(),
            "--release".into(),
            "--locked".into(),
            "--quiet".into(),
        ];
        args.extend(extra.iter().map(|s| (*s).to_string()));
        args.extend([
            "--target-dir".into(),
            clippy_dir.to_string_lossy().into_owned(),
            "--".into(),
            "-D".into(),
            "warnings".into(),
        ]);
        let (ok, out) = run_capture_all(cargo, &args, Some(&env.root.join(rel)), &cargo_env)?;
        let errs = out.lines().filter(|l| l.starts_with("error")).count();
        println!(
            "  static: clippy -D warnings, {rel}: {}",
            if ok { "clean".into() } else { format!("{} findings", errs.max(1)) }
        );
        if !ok {
            println!("{}", out.trim());
            findings += errs.max(1);
        }
        crate_count += 1;
    }

    // User workspace crates (shared target-dir, ring-3 target):
    let user_pkgs = [
        ("libd", &["--features", "capi"][..]),
        ("audio", &[]),
        ("net", &[]),
        ("gpu", &[]),
        ("awmi", &[]),
        ("init", &[]),
        ("log", &[]),
        ("clock", &[]),
        ("terminal", &[]),
        ("shell", &[]),
        ("tools", &[]),
        ("devmgr", &[]),
        ("storaged", &[]),
        ("fstest", &[]),
        ("ltest", &[]),
        ("dcmpl", &[]),
    ];
    for (pkg, extra) in user_pkgs {
        let mut args = vec![
            "clippy".into(),
            "--release".into(),
            "--locked".into(),
            "--quiet".into(),
            "--target".into(),
            "x86_64-unknown-none".into(),
            "-p".into(),
            pkg.into(),
        ];
        args.extend(extra.iter().map(|s| (*s).to_string()));
        args.extend([
            "--target-dir".into(),
            clippy_dir.to_string_lossy().into_owned(),
            "--".into(),
            "-D".into(),
            "warnings".into(),
        ]);
        let (ok, out) = run_capture_all(cargo, &args, Some(&user_src), &cargo_env)?;
        let errs = out.lines().filter(|l| l.starts_with("error")).count();
        println!(
            "  static: clippy -D warnings, user/{pkg}: {}",
            if ok { "clean".into() } else { format!("{} findings", errs.max(1)) }
        );
        if !ok {
            println!("{}", out.trim());
            findings += errs.max(1);
        }
        crate_count += 1;
    }

    println!("  static: {total_files} C files analyzed, {crate_count} Rust crates linted: {findings} findings");
    Ok(findings == 0)
}

// ---------------------------------------------------------------------------
// build/test-report.md
// ---------------------------------------------------------------------------

fn first_line(cmd_res: Result<String, String>) -> String {
    cmd_res
        .ok()
        .and_then(|s| s.lines().next().map(|l| l.trim().to_string()))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

fn write_test_report(env: &Env, results: &[CaseResult], verdict: &str, partial: bool) {
    let git = find_in_path("git");
    let commit = git
        .as_deref()
        .map(|g| first_line(run_capture(g, &["-C", &env.root.to_string_lossy(), "rev-parse", "--short=12", "HEAD"], None, &[])))
        .unwrap_or_else(|| "unknown".into());
    let dirty = git
        .as_deref()
        .map(|g| first_line(run_capture(g, &["-C", &env.root.to_string_lossy(), "status", "--porcelain", "--untracked-files=no"], None, &[])))
        .unwrap_or_default();
    let tree = if !dirty.is_empty() && dirty != "unknown" {
        let diff = git
            .as_deref()
            .and_then(|g| run_capture(g, &["-C", &env.root.to_string_lossy(), "diff", "HEAD"], None, &[]).ok())
            .unwrap_or_default();
        let h = &to_hex(&doscrypt::sha2::sha256(diff.as_bytes()))[..16];
        format!("{commit} + uncommitted changes (diff sha256 {h})")
    } else {
        format!("{commit} (clean)")
    };

    let clang_v = env.clang().ok().map(|p| first_line(run_capture(p, &["--version"], None, &[]))).unwrap_or_else(|| "unknown".into());
    let nasm_v = env.nasm().ok().map(|p| first_line(run_capture(p, &["-v"], None, &[]))).unwrap_or_else(|| "unknown".into());
    let qemu_v = env.qemu().ok().map(|p| first_line(run_capture(p, &["--version"], None, &[]))).unwrap_or_else(|| "unknown".into());
    let rustc_v = env
        .rustc()
        .ok()
        .map(|p| first_line(run_capture(&p, &["--version"], Some(&env.root.join("kernel/rust")), &env.cargo_env_pairs())))
        .unwrap_or_else(|| "unknown".into());

    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (y, mo, d, h, mi) = civil_from_unix(secs);
    let host_info = detect_host_info();

    let mut lines = vec![
        "# D-OS test report".to_string(),
        String::new(),
        format!(
            "- Result: **{verdict}**{}",
            if partial { " (partial run: selected cases only)" } else { " (full suite)" }
        ),
        format!("- Tree: {tree}"),
        format!("- Date (UTC): {y:04}-{mo:02}-{d:02} {h:02}:{mi:02}"),
        format!("- Host: {host_info}"),
        format!("- Tools: clang: {clang_v}; nasm: {nasm_v}; qemu: {qemu_v}; rustc: {rustc_v}"),
        String::new(),
        "| Case | Result | Seconds |".to_string(),
        "|---|---|---|".to_string(),
    ];
    for r in results {
        lines.push(format!("| {} | {} | {:.1} |", r.name, r.result, r.seconds));
    }

    let path = env.build.join("test-report.md");
    let _ = fs::create_dir_all(&env.build);
    if fs::write(&path, format!("{}\n", lines.join("\n"))).is_ok() {
        println!("Test report: {}", env.rel(&path));
    }
}

fn detect_host_info() -> String {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    #[cfg(target_os = "linux")]
    if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo")
        && let Some(line) = cpuinfo.lines().find(|l| l.starts_with("model name"))
        && let Some(name) = line.split(':').nth(1)
    {
        return format!("linux/{arch}, {}", name.trim());
    }
    #[cfg(windows)]
    if let Ok(id) = std::env::var("PROCESSOR_IDENTIFIER") {
        return format!("windows/{arch}, {id}");
    }
    format!("{os}/{arch}")
}
