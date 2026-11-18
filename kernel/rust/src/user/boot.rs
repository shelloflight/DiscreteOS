//! The first user process: `init`, embedded in the kernel image with the other programs (there is
//! no filesystem yet; build.ps1 links them in through programs.asm).
//!
//! init gets exactly these handles, and no other authority exists for it:
//! - its own process, thread and root VMAR (like every spawned process);
//! - the debug log (`WRITE`): the only way to print;
//! - one read-only VMO per embedded program (tag PROGRAM, named "<name>.dx"), to spawn them;
//! - the VMEX resource (tag VMEX): the authority to make sealed VMOs executable, for user-space
//!   program loaders. init hands it on only deliberately;
//! - one handle per device (tag DEVICE): init passes them to the device manager.

use alloc::vec::Vec;
use core::ffi::{CStr, c_char};

use super::loader::{self, tag};
use crate::ffi::{self, RawProgram};
use crate::object::quota::Limits;
use crate::object::resource::{KIND_POWER, KIND_VMEX};
use crate::object::{
    KRef, LogObj, ObjType, Object, Process, ResourceObj, Rights, Status, Vmo, default_rights, kernel_process,
    kernel_process_ref, sig,
};

/// The embedded programs (name, bytes).
pub fn programs() -> impl Iterator<Item = (&'static str, &'static [u8])> {
    // SAFETY: the table and its count are emitted together by build.ps1 (programs.asm); every
    // entry points at a NUL-terminated name and `len` bytes inside the kernel image.
    let table = unsafe {
        core::slice::from_raw_parts(
            (&raw const ffi::user_program_table).cast::<RawProgram>(),
            ffi::user_program_count as usize,
        )
    };
    table.iter().map(|p| {
        // SAFETY: as above.
        let name = unsafe { CStr::from_ptr(p.name) }.to_str().unwrap_or("?");
        // SAFETY: as above.
        let data = unsafe { core::slice::from_raw_parts(p.data, p.len as usize) };
        (name, data)
    })
}

/// A read-only VMO holding a copy of an embedded program.
fn program_vmo(name: &str, data: &[u8]) -> Result<KRef<Vmo>, Status> {
    let v = Vmo::create_named(kernel_process().account(), (data.len() as u64).max(1), name)?;
    v.write(0, data)?;
    // Part of the kernel image, which the loader verified: sealed and trusted as such.
    v.seal()?;
    v.set_trust(crate::security::Trust::KernelImage);
    Ok(v)
}

fn exit_text(code: i32) -> &'static str {
    match code {
        ffi::EXIT_KILLED => " (KILLED)",
        ffi::EXIT_FAULT => " (FAULT)",
        _ => "",
    }
}

fn start(args: &[u8]) -> Result<KRef<Process>, Status> {
    let (_, image) = programs().find(|(n, _)| *n == "init.dx").ok_or(Status::NotSupported)?;
    let image = program_vmo("init.dx", image)?;
    let mut handles = Vec::new();
    let n = programs().count();
    let devs = crate::dev::devices();
    handles.try_reserve_exact(n + 3 + devs.len()).map_err(|_| Status::NoMemory)?;
    handles.push((Object::Log(LogObj::create()?), default_rights(ObjType::Log), tag::LOG));
    let vmex = ResourceObj::new(KIND_VMEX)?;
    handles.push((Object::Resource(vmex), default_rights(ObjType::Resource), tag::VMEX));
    let power = ResourceObj::new(KIND_POWER)?;
    handles.push((Object::Resource(power), default_rights(ObjType::Resource), tag::POWER));
    let prog_rights = Rights::READ | Rights::DUPLICATE | Rights::TRANSFER | Rights::INSPECT;
    for (name, data) in programs() {
        handles.push((Object::Vmo(program_vmo(name, data)?), prog_rights, tag::PROGRAM));
    }
    for d in devs {
        handles.push((Object::Device(d.clone()), default_rights(ObjType::Device), tag::DEVICE));
    }
    if handles.len() > loader::MAX_HANDLES {
        crate::kprintln!(
            "User: init would get {} startup handles ({} programs, {} devices), more than the limit of {}",
            handles.len(),
            n,
            devs.len(),
            loader::MAX_HANDLES
        );
        return Err(Status::OutOfRange);
    }
    let parent = kernel_process_ref();
    loader::spawn(loader::Spawn {
        parent,
        image,
        name: "init",
        args,
        handles,
        limits: Limits { memory: 128 << 20, handles: 4096, threads: 64 },
        exception_channel: false,
        forward: false,
        start_exception: false,
    })
    .map(|(p, _)| p)
    .map_err(|e| e.status())
}

/// kmain / ktest: start init with `args` and report when it exits.
#[unsafe(no_mangle)]
pub extern "C" fn dkrnl_start_init(args: *const c_char, len: u64) {
    let args: &[u8] = if args.is_null() {
        &[]
    } else {
        // SAFETY: the caller passes `len` readable bytes.
        unsafe { core::slice::from_raw_parts(args.cast::<u8>(), len as usize) }
    };
    let init = match start(args) {
        Ok(p) => p,
        Err(e) => {
            crate::kprintln!("User: cannot start init: {}", e.name());
            return;
        }
    };
    crate::kprintln!(
        "User: init started in ring 3 (koid {}), ABI v{}, {} programs embedded",
        init.header.koid,
        loader::ABI_VERSION,
        programs().count()
    );
    let watcher = crate::thread::spawn(c"init.watch", ffi::prio::NORMAL, move || {
        let _ = init.signals.wait(sig::TERMINATED, ffi::WAIT_FOREVER);
        let code = init.exit_code().unwrap_or(0);
        crate::kprintln!("User: init exited with code {}{}", code, exit_text(code));
        drop(init); // the last reference: the leak check below counts processes
        #[cfg(ktest)]
        // SAFETY: plain call into the test harness.
        unsafe {
            ffi::ktest_after_init(code)
        };
        0
    });
    drop(watcher); // detached
}
