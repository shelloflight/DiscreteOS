//! Windows personality, milestone W1 (docs/compat.md): a user-space PE32+ loader and a minimal
//! `kernel32`, running a Windows program inside this process on the native D-OS ABI.
//!
//! Loading (parse + map + bind, measured):
//! 1. parse and validate the image (`pe.rs`);
//! 2. reserve its span at the preferred ImageBase (a VMAR sub-region at a fixed address), or
//!    anywhere if that is taken (then the base relocations are applied);
//! 3. lay the image out in a private staging buffer, relocate, and bind the imports to the
//!    functions below (any other import refuses the program, naming the DLL and function);
//! 4. map it page-exactly: headers R, each section in its own VMO with the section's
//!    permissions; code is **sealed and made executable with the VMEX resource** before it is
//!    mapped, so it is never writable through any alias (W^X holds for foreign code too);
//! 5. a 1 MiB stack with unmapped guard pages, and a TEB (GS base, as on Windows: `gs:[0x30]` is
//!    the TEB itself, `gs:[0x60]` the PEB, whose ImageBaseAddress is the load address);
//! 6. call the entry point with the Windows x64 calling convention on the new stack; returning
//!    from it exits the process with the returned value (as ExitProcess would).
//!
//! D-CMPL is not the security boundary (docs/compat.md): the program runs in this process and can
//! do anything this process can. Its authority is only the handles the process holds.

use core::arch::asm;

use crate::pe::{self, PeError};
use crate::sys::{self, Handle, PAGE};
use crate::{EXIT_REFUSED, EXIT_USAGE, find_program, out, println, read_program, root_vmar, startup_handle, text};

const STACK_SIZE: u64 = 1 << 20;

// ---- kernel32 ---------------------------------------------------------------------------------

const STD_INPUT_HANDLE: i32 = -10;
const STD_OUTPUT_HANDLE: i32 = -11;
const STD_ERROR_HANDLE: i32 = -12;
/// Pseudo handles for the console (Windows' own values are just as arbitrary).
const H_STDOUT: u64 = 0x07;
const H_STDERR: u64 = 0x0B;
const INVALID_HANDLE_VALUE: u64 = u64::MAX;

/// HANDLE GetStdHandle(DWORD nStdHandle): stdout and stderr go to the debug log; there is no
/// console input yet.
extern "win64" fn get_std_handle(n: u32) -> u64 {
    match n as i32 {
        STD_OUTPUT_HANDLE => H_STDOUT,
        STD_ERROR_HANDLE => H_STDERR,
        STD_INPUT_HANDLE => INVALID_HANDLE_VALUE,
        _ => INVALID_HANDLE_VALUE,
    }
}

/// BOOL WriteFile(HANDLE, LPCVOID buf, DWORD len, LPDWORD written, LPOVERLAPPED): synchronous
/// writes to the console handles only, as text: CR LF becomes the D-OS log's LF. The buffer is
/// copied through the kernel (process_read_memory on ourselves), so a bad one is FALSE, as on
/// Windows; a bad `written` pointer faults the program (an access violation on Windows too).
extern "win64" fn write_file(h: u64, buf: u64, len: u32, written: *mut u32, overlapped: u64) -> i32 {
    if !written.is_null() {
        // SAFETY: the program's own out-pointer, in its (this) address space; a bad one faults
        // the program like an access violation on Windows.
        unsafe { written.write_volatile(0) };
    }
    if overlapped != 0 || (h != H_STDOUT && h != H_STDERR) {
        return 0;
    }
    let me = startup_handle(sys::TAG_PROC_SELF);
    let mut chunk = [0u8; 1024];
    let mut done = 0u64;
    while done < u64::from(len) {
        let n = (u64::from(len) - done).min(chunk.len() as u64) as usize;
        if sys::process_read_memory(me, buf.wrapping_add(done), &mut chunk[..n]) < 0 {
            return 0;
        }
        // Drop each CR that a LF follows (a CR at the chunk end is kept: rare, and harmless).
        let mut k = 0;
        for i in 0..n {
            if chunk[i] == b'\r' && i + 1 < n && chunk[i + 1] == b'\n' {
                continue;
            }
            chunk[k] = chunk[i];
            k += 1;
        }
        if sys::log_write(out::log(), &chunk[..k]) < 0 {
            return 0;
        }
        done += n as u64;
    }
    if !written.is_null() {
        // SAFETY: as above.
        unsafe { written.write_volatile(len) };
    }
    1
}

/// VOID ExitProcess(UINT code).
extern "win64" fn exit_process(code: u32) -> ! {
    sys::process_exit(code as i32)
}

/// The exports D-CMPL provides (KERNEL32.dll).
fn kernel32(func: &[u8]) -> Option<u64> {
    Some(match func {
        b"GetStdHandle" => get_std_handle as *const () as usize as u64,
        b"WriteFile" => write_file as *const () as usize as u64,
        b"ExitProcess" => exit_process as *const () as usize as u64,
        _ => return None,
    })
}

pub fn resolve(dll: &[u8], func: &[u8]) -> Option<u64> {
    if dll.eq_ignore_ascii_case(b"kernel32.dll") { kernel32(func) } else { None }
}

// ---- loader -----------------------------------------------------------------------------------

struct Loaded {
    base: u64,
    entry: u64,
    stack_top: u64,
    preferred: bool,
    relocs: u32,
    imports: u32,
    /// Parse + map + bind, and the rest (stack, TEB/PEB), in TSC cycles.
    image_cycles: u64,
    setup_cycles: u64,
}

fn fail(name: &[u8], what: &str, r: i64) -> i32 {
    println!("dcmpl: {}: {}: {}", text(name), what, sys::status(r));
    EXIT_REFUSED
}

/// Map `pages` bytes of the laid-out image at `rva` into `region`, in a VMO of their own.
fn map_piece(region: Handle, staged: &[u8], rva: u32, pages: u32, perms: u32, vmex: Handle) -> Result<(), i64> {
    let v = sys::vmo_create(u64::from(pages));
    if v < 0 {
        return Err(v);
    }
    let mut v = v as Handle;
    let (from, len) = (rva as usize, pages as usize);
    let mut off = 0;
    while off < len {
        let n = (len - off).min(64 * 1024);
        let r = sys::vmo_write(v, off as u64, &staged[from + off..from + off + n]);
        if r < 0 {
            sys::handle_close(v);
            return Err(r);
        }
        off += n;
    }
    if perms & sys::RIGHT_EXECUTE != 0 {
        let x = sys::vmo_make_executable(v, vmex); // seals: never writable again, through any alias
        if x < 0 {
            sys::handle_close(v);
            return Err(x);
        }
        v = x as Handle;
    }
    let r = sys::vmar_map(region, u64::from(rva), v, 0, u64::from(pages), perms);
    sys::handle_close(v); // the mapping keeps the VMO
    if r < 0 { Err(r) } else { Ok(()) }
}

fn load(name: &[u8], data: &[u8], vmex: Handle) -> Result<Loaded, i32> {
    let t0 = sys::rdtsc();
    let img = pe::parse(data).map_err(|e| refused(name, e))?;
    let root = root_vmar();
    let size = u64::from(img.size_of_image);

    // Preferred base if it is free and inside the user half, else anywhere (relocated).
    let fixed = (img.image_base >= sys::USER_BASE && img.image_base + size <= sys::USER_TOP)
        .then(|| sys::vmar_allocate(root, img.image_base - sys::USER_BASE, size).ok())
        .flatten();
    let (region, base) = match fixed {
        Some(r) => r,
        None => sys::vmar_allocate(root, sys::ANY, size).map_err(|r| fail(name, "cannot reserve the image", r))?,
    };
    let delta = base.wrapping_sub(img.image_base);

    let mut staging = sys::Mapping::new(root, size).map_err(|r| fail(name, "no memory to stage the image", r))?;
    let staged = &mut staging.bytes()[..size as usize];
    img.layout(data, staged).map_err(|e| refused(name, e))?;
    let relocs = img.relocate(staged, delta).map_err(|e| refused(name, e))?;
    let imports = img.bind(staged, resolve).map_err(|e| refused(name, e))?;

    let hdr = img.size_of_headers.div_ceil(PAGE as u32) * PAGE as u32;
    map_piece(region, staged, 0, hdr, sys::RIGHT_READ, vmex).map_err(|r| fail(name, "cannot map the headers", r))?;
    for s in img.sections() {
        let perms = if s.executable() {
            sys::RIGHT_READ | sys::RIGHT_EXECUTE
        } else if s.writable() {
            sys::RIGHT_READ | sys::RIGHT_WRITE
        } else {
            sys::RIGHT_READ
        };
        map_piece(region, staged, s.rva, s.pages(), perms, vmex).map_err(|r| {
            println!("dcmpl: {}: section {}", text(name), s.name());
            fail(name, "cannot map a section", r)
        })?;
    }
    sys::handle_close(region); // the image can no longer be remapped through a handle
    drop(staging);
    let image_cycles = sys::rdtsc() - t0;

    // Stack with a guard page below and above, TEB and PEB.
    let (sreg, sbase) = sys::vmar_allocate(root, sys::ANY, STACK_SIZE + 2 * PAGE).map_err(|r| fail(name, "no stack", r))?;
    let sv = sys::vmo_create(STACK_SIZE);
    if sv < 0 {
        return Err(fail(name, "no stack", sv));
    }
    let sm = sys::vmar_map(sreg, PAGE, sv as Handle, 0, STACK_SIZE, sys::RIGHT_READ | sys::RIGHT_WRITE);
    sys::handle_close(sv as Handle);
    sys::handle_close(sreg);
    if sm < 0 {
        return Err(fail(name, "no stack", sm));
    }
    let stack_top = sbase + PAGE + STACK_SIZE;
    let teb = sys::Mapping::new(root, 2 * PAGE).map_err(|r| fail(name, "no TEB", r))?;
    let (t, peb) = (teb.addr, teb.addr + PAGE);
    let put = |at: u64, v: u64| {
        // SAFETY: inside the fresh 2-page TEB/PEB mapping (offsets below 0x70).
        unsafe { (at as *mut u64).write(v) }
    };
    put(t + 0x08, stack_top); // NT_TIB.StackBase
    put(t + 0x10, stack_top - STACK_SIZE); // NT_TIB.StackLimit
    put(t + 0x30, t); // NT_TIB.Self
    put(t + 0x40, 4); // ClientId.UniqueProcess (placeholder)
    put(t + 0x48, 8); // ClientId.UniqueThread (placeholder)
    put(t + 0x60, peb); // ProcessEnvironmentBlock
    put(peb + 0x10, base); // PEB.ImageBaseAddress
    core::mem::forget(teb); // lives as long as the process
    let r = sys::thread_set_base(sys::BASE_GS, t);
    if r < 0 {
        return Err(fail(name, "cannot set the GS base (TEB)", r));
    }
    Ok(Loaded {
        base,
        entry: base + u64::from(img.entry),
        stack_top,
        preferred: delta == 0,
        relocs,
        imports,
        image_cycles,
        setup_cycles: sys::rdtsc() - t0 - image_cycles,
    })
}

fn refused(name: &[u8], e: PeError) -> i32 {
    match e {
        PeError::Import { .. } => println!(
            "dcmpl: {} refused: {} (D-CMPL provides KERNEL32.dll!GetStdHandle, WriteFile, ExitProcess)",
            text(name),
            e
        ),
        _ => println!("dcmpl: {} refused: {}", text(name), e),
    }
    EXIT_REFUSED
}

/// Call the entry point on its own stack with the Windows x64 convention (32 bytes of shadow
/// space, RSP + 8 16-byte aligned at entry). RCX = PEB, as Windows passes it.
fn call_entry(entry: u64, stack_top: u64, peb: u64) -> u32 {
    let ret: u64;
    // SAFETY: the entry point of the image just mapped, on its own stack. Callee-saved registers
    // (Windows x64: RBX, RBP, RDI, RSI, R12-R15, XMM6-15) survive; R12 keeps our RSP.
    unsafe {
        asm!(
            "mov r12, rsp",
            "mov rsp, {st}",
            "sub rsp, 32",
            "call {e}",
            "mov rsp, r12",
            st = in(reg) stack_top,
            e = in(reg) entry,
            in("rcx") peb,
            out("r12") _,
            lateout("rax") ret,
            clobber_abi("win64"),
        );
    }
    ret as u32
}

pub fn run(name: &[u8]) -> i32 {
    if name.is_empty() {
        println!("dcmpl: win: which program?");
        return EXIT_USAGE;
    }
    let Some(h) = find_program(name) else {
        println!("dcmpl: win: no program '{}'", text(name));
        return EXIT_USAGE;
    };
    let vmex = startup_handle(sys::TAG_VMEX);
    if vmex == 0 {
        println!("dcmpl: win: no VMEX resource: cannot make code executable");
        return EXIT_REFUSED;
    }
    let (mut file, len) = match read_program(h, pe::MAX_FILE as u64) {
        Ok(f) => f,
        Err(r) => return fail(name, "cannot read the image", r),
    };
    let ns0 = sys::clock_ns();
    let l = match load(name, &file.bytes()[..len], vmex) {
        Ok(l) => l,
        Err(code) => return code,
    };
    let ns = sys::clock_ns() - ns0;
    drop(file);
    println!(
        "dcmpl: {}: PE32+ loaded at {:#x} ({}), {} relocations, {} imports bound; TEB at GS",
        text(name),
        l.base,
        if l.preferred { "preferred base" } else { "relocated" },
        l.relocs,
        l.imports
    );
    println!(
        "BENCH compat: PE load of {} (parse + map + bind): {} cycles; stack + TEB: {} cycles; total {} us",
        text(name),
        l.image_cycles,
        l.setup_cycles,
        ns / 1000
    );
    // SAFETY: the TEB's PEB pointer, written by `load`.
    let peb = unsafe { *((sys_gs_base() + 0x60) as *const u64) };
    call_entry(l.entry, l.stack_top, peb) as i32
}

/// This thread's GS base (the TEB), read through the TEB's self pointer.
fn sys_gs_base() -> u64 {
    let v: u64;
    // SAFETY: the GS base was set to the TEB by `load`; gs:[0x30] is its self pointer.
    unsafe { asm!("mov {}, gs:[0x30]", out(reg) v, options(nostack, readonly, preserves_flags)) };
    v
}
