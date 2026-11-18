//! TPM 2.0 driver: the commands measured boot needs, over the two memory-mapped interfaces PCs
//! have, found through the ACPI `TPM2` table:
//!
//! - TIS / FIFO (TCG PC Client Platform TPM Profile, start method 6), locality 0 at 0xFED40000
//! - CRB (Command Response Buffer, start method 7), control area from the table
//!
//! Commands (TPM 2.0 Library, Part 3): `TPM2_Startup(SU_CLEAR)` (the firmware normally did it:
//! `TPM_RC_INITIALIZE` is fine), `TPM2_GetCapability` (manufacturer), `TPM2_PCR_Extend` and
//! `TPM2_PCR_Read` on the SHA-256 bank. Every response is length- and tag-checked; a TPM that
//! misbehaves or times out is dropped (measurements stay in the kernel's log).
//!
//! The kernel drives the TPM itself (not a user-space driver): it is the root of the measurement
//! chain, found through ACPI rather than PCI, and used only for a handful of short commands.
//! Without a TPM in the test machine (QEMU on Windows has none), the command layer is tested
//! against the simulator below (`Sim`, selftest); TIS and CRB are tested on real hardware.

use alloc::boxed::Box;

use crate::ffi;

pub const SHA256_ALG: u16 = 0x000B;
const ST_NO_SESSIONS: u16 = 0x8001;
const ST_SESSIONS: u16 = 0x8002;
const CC_STARTUP: u32 = 0x144;
const CC_PCR_EXTEND: u32 = 0x182;
const CC_PCR_READ: u32 = 0x17E;
const CC_GET_CAPABILITY: u32 = 0x17A;
const RC_INITIALIZE: u32 = 0x100;
const RS_PW: u32 = 0x4000_0009;
const CAP_TPM_PROPERTIES: u32 = 6;
const PT_MANUFACTURER: u32 = 0x105;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Timeout,
    /// The interface or the response broke the protocol.
    Protocol(&'static str),
    /// The TPM answered with this response code.
    Tpm(u32),
}

/// Moves one command to the TPM and its response back.
pub trait Transport: Send {
    fn exchange(&mut self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize, Error>;
    fn name(&self) -> &'static str;
}

pub struct Tpm {
    t: Box<dyn Transport>,
    pub manufacturer: [u8; 4],
}

/// Big-endian command builder.
struct Cmd {
    b: [u8; 128],
    n: usize,
}

impl Cmd {
    fn new(tag: u16, cc: u32) -> Cmd {
        let mut c = Cmd { b: [0; 128], n: 10 };
        c.b[0..2].copy_from_slice(&tag.to_be_bytes());
        c.b[6..10].copy_from_slice(&cc.to_be_bytes());
        c
    }
    fn u8(&mut self, v: u8) -> &mut Self {
        self.b[self.n] = v;
        self.n += 1;
        self
    }
    fn u16(&mut self, v: u16) -> &mut Self {
        self.bytes(&v.to_be_bytes())
    }
    fn u32(&mut self, v: u32) -> &mut Self {
        self.bytes(&v.to_be_bytes())
    }
    fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.b[self.n..self.n + v.len()].copy_from_slice(v);
        self.n += v.len();
        self
    }
    fn done(&mut self) -> &[u8] {
        let n = self.n as u32;
        self.b[2..6].copy_from_slice(&n.to_be_bytes());
        &self.b[..self.n]
    }
}

fn be16(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(o)?, *b.get(o + 1)?]))
}
fn be32(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_be_bytes([*b.get(o)?, *b.get(o + 1)?, *b.get(o + 2)?, *b.get(o + 3)?]))
}

/// Builders, shared with the simulator's tests.
pub fn cmd_pcr_extend(pcr: u32, digest: &[u8; 32]) -> ([u8; 128], usize) {
    let mut c = Cmd::new(ST_SESSIONS, CC_PCR_EXTEND);
    c.u32(pcr).u32(9).u32(RS_PW).u16(0).u8(0).u16(0); // password session, empty auth
    c.u32(1).u16(SHA256_ALG).bytes(digest);
    let n = c.done().len();
    (c.b, n)
}

impl Tpm {
    /// Bring a TPM up on `t`: Startup (or already started), then the manufacturer.
    pub fn new(t: Box<dyn Transport>) -> Result<Tpm, Error> {
        let mut tpm = Tpm { t, manufacturer: [0; 4] };
        let mut c = Cmd::new(ST_NO_SESSIONS, CC_STARTUP);
        c.u16(0); // TPM_SU_CLEAR
        match tpm.command(c.done().to_owned_array()) {
            Ok(_) | Err(Error::Tpm(RC_INITIALIZE)) => {}
            Err(e) => return Err(e),
        }
        let mut c = Cmd::new(ST_NO_SESSIONS, CC_GET_CAPABILITY);
        c.u32(CAP_TPM_PROPERTIES).u32(PT_MANUFACTURER).u32(1);
        let (r, n) = tpm.command(c.done().to_owned_array())?;
        // moreData(1) capability(4) count(4) property(4) value(4)
        let r = &r[..n];
        if be32(r, 11) != Some(CAP_TPM_PROPERTIES) || be32(r, 15) != Some(1) || be32(r, 19) != Some(PT_MANUFACTURER) {
            return Err(Error::Protocol("unexpected GetCapability answer"));
        }
        let v = be32(r, 23).ok_or(Error::Protocol("short GetCapability answer"))?;
        tpm.manufacturer = v.to_be_bytes();
        Ok(tpm)
    }

    pub fn interface(&self) -> &'static str {
        self.t.name()
    }

    /// One command; checks the response header. Returns the response buffer and its length.
    fn command(&mut self, (cmd, n): ([u8; 128], usize)) -> Result<([u8; 512], usize), Error> {
        let mut rsp = [0u8; 512];
        let got = self.t.exchange(&cmd[..n], &mut rsp)?;
        if got < 10 || got > rsp.len() {
            return Err(Error::Protocol("short response"));
        }
        let tag = be16(&rsp, 0).unwrap_or(0);
        let size = be32(&rsp, 2).unwrap_or(0) as usize;
        let rc = be32(&rsp, 6).unwrap_or(0);
        if (tag != ST_NO_SESSIONS && tag != ST_SESSIONS) || size != got {
            return Err(Error::Protocol("malformed response header"));
        }
        if rc != 0 {
            return Err(Error::Tpm(rc));
        }
        Ok((rsp, got))
    }

    pub fn pcr_extend(&mut self, pcr: u32, digest: &[u8; 32]) -> Result<(), Error> {
        self.command(cmd_pcr_extend(pcr, digest)).map(|_| ())
    }

    pub fn pcr_read(&mut self, pcr: u32) -> Result<[u8; 32], Error> {
        if pcr >= 24 {
            return Err(Error::Protocol("PCR index"));
        }
        let mut sel = [0u8; 3];
        sel[(pcr / 8) as usize] = 1 << (pcr % 8);
        let mut c = Cmd::new(ST_NO_SESSIONS, CC_PCR_READ);
        c.u32(1).u16(SHA256_ALG).u8(3).bytes(&sel);
        let (r, n) = self.command(c.done().to_owned_array())?;
        let r = &r[..n];
        // updateCounter(4) TPML_PCR_SELECTION(4 + 2 + 1 + 3) TPML_DIGEST count(4) TPM2B size(2) digest
        if be32(r, 10 + 4) != Some(1) || be32(r, 24) != Some(1) || be16(r, 28) != Some(32) || r.len() < 62 {
            return Err(Error::Protocol("unexpected PCR_Read answer"));
        }
        let mut d = [0u8; 32];
        d.copy_from_slice(&r[30..62]);
        Ok(d)
    }
}

trait ToOwnedArray {
    fn to_owned_array(&self) -> ([u8; 128], usize);
}
impl ToOwnedArray for [u8] {
    fn to_owned_array(&self) -> ([u8; 128], usize) {
        let mut b = [0u8; 128];
        b[..self.len()].copy_from_slice(self);
        (b, self.len())
    }
}

// ---- hardware interfaces --------------------------------------------------------------------------

fn wait(timeout_ns: u64, mut done: impl FnMut() -> bool) -> Result<(), Error> {
    // SAFETY: time_ns only reads the clock.
    let t0 = unsafe { ffi::time_ns() };
    loop {
        if done() {
            return Ok(());
        }
        // SAFETY: as above.
        if unsafe { ffi::time_ns() } - t0 > timeout_ns {
            return Err(Error::Timeout);
        }
        core::hint::spin_loop();
    }
}

const MS: u64 = 1_000_000;

/// A mapped MMIO window (uncached), accessed with volatile loads and stores.
struct Mmio(*mut u8);
// SAFETY: the window is device memory owned by the driver; it is used under the measurement lock.
unsafe impl Send for Mmio {}

impl Mmio {
    fn map(pa: u64, len: u64) -> Mmio {
        // SAFETY: maps a device range named by ACPI (not RAM: bootinfo/PMM keep it reserved).
        Mmio(unsafe { ffi::vmm_map_phys(pa, len, ffi::VMM_W | ffi::VMM_UC) })
    }
    fn r8(&self, o: usize) -> u8 {
        // SAFETY: o is inside the mapped window (constant register offsets).
        unsafe { core::ptr::read_volatile(self.0.add(o)) }
    }
    fn w8(&self, o: usize, v: u8) {
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile(self.0.add(o), v) }
    }
    fn r32(&self, o: usize) -> u32 {
        // SAFETY: as above; registers are 4-byte aligned.
        unsafe { core::ptr::read_volatile(self.0.add(o).cast::<u32>()) }
    }
    fn w32(&self, o: usize, v: u32) {
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile(self.0.add(o).cast::<u32>(), v) }
    }
}

/// TIS / FIFO interface, locality 0.
pub struct Tis(Mmio);

const TIS_BASE: u64 = 0xFED4_0000;
const TIS_ACCESS: usize = 0x00;
const TIS_STS: usize = 0x18;
const TIS_FIFO: usize = 0x24;
const TIS_DID_VID: usize = 0xF00;
const ACCESS_VALID: u8 = 0x80;
const ACCESS_ACTIVE: u8 = 0x20;
const ACCESS_REQUEST: u8 = 0x02;
const STS_VALID: u32 = 0x80;
const STS_READY: u32 = 0x40;
const STS_GO: u32 = 0x20;
const STS_DATA: u32 = 0x10;
const STS_EXPECT: u32 = 0x08;

impl Tis {
    fn probe() -> Option<Tis> {
        let m = Mmio::map(TIS_BASE, 0x1000);
        let id = m.r32(TIS_DID_VID);
        (id != 0 && id != 0xFFFF_FFFF).then_some(Tis(m))
    }
    fn burst(&self) -> usize {
        ((self.0.r32(TIS_STS) >> 8) & 0xFFFF) as usize
    }
}

impl Transport for Tis {
    fn name(&self) -> &'static str {
        "TIS"
    }
    fn exchange(&mut self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize, Error> {
        let m = &self.0;
        if m.r8(TIS_ACCESS) & ACCESS_ACTIVE == 0 {
            m.w8(TIS_ACCESS, ACCESS_REQUEST);
            wait(750 * MS, || m.r8(TIS_ACCESS) & (ACCESS_VALID | ACCESS_ACTIVE) == ACCESS_VALID | ACCESS_ACTIVE)?;
        }
        m.w32(TIS_STS, STS_READY);
        wait(2000 * MS, || m.r32(TIS_STS) & STS_READY != 0)?;
        let mut i = 0;
        while i < cmd.len() {
            wait(2000 * MS, || self.burst() > 0)?;
            let n = self.burst().min(cmd.len() - i);
            for b in &cmd[i..i + n] {
                m.w8(TIS_FIFO, *b);
            }
            i += n;
        }
        wait(750 * MS, || m.r32(TIS_STS) & STS_VALID != 0)?;
        if m.r32(TIS_STS) & STS_EXPECT != 0 {
            return Err(Error::Protocol("TPM expects more command bytes"));
        }
        m.w32(TIS_STS, STS_GO);
        wait(10_000 * MS, || m.r32(TIS_STS) & (STS_VALID | STS_DATA) == STS_VALID | STS_DATA)?;
        let mut got = 0;
        let mut want = 10;
        while got < want {
            wait(750 * MS, || self.burst() > 0)?;
            let n = self.burst().min(want - got);
            for _ in 0..n {
                rsp[got] = m.r8(TIS_FIFO);
                got += 1;
            }
            if got == 10 && want == 10 {
                want = be32(rsp, 2).unwrap_or(0) as usize;
                if want < 10 || want > rsp.len() {
                    m.w32(TIS_STS, STS_READY);
                    return Err(Error::Protocol("response size out of range"));
                }
            }
        }
        m.w32(TIS_STS, STS_READY);
        Ok(got)
    }
}

/// CRB interface, locality 0: command and response buffers named by the control area.
pub struct Crb {
    ctl: Mmio,
    cmd: Mmio,
    cmd_len: usize,
    rsp: Mmio,
    rsp_len: usize,
}

const CRB_LOC_CTRL: usize = 0x08;
const CRB_LOC_STS: usize = 0x0C;
const CRB_CTRL_REQ: usize = 0x40;
const CRB_CTRL_STS: usize = 0x44;
const CRB_CTRL_START: usize = 0x4C;
const CRB_CMD_SIZE: usize = 0x58;
const CRB_CMD_LO: usize = 0x5C;
const CRB_CMD_HI: usize = 0x60;
const CRB_RSP_SIZE: usize = 0x64;
const CRB_RSP_PA: usize = 0x68;

impl Crb {
    fn probe(control: u64) -> Option<Crb> {
        if control == 0 || !control.is_multiple_of(4) {
            return None;
        }
        let ctl = Mmio::map(control, 0x80);
        let cmd_pa = u64::from(ctl.r32(CRB_CMD_LO)) | u64::from(ctl.r32(CRB_CMD_HI)) << 32;
        let rsp_pa = u64::from(ctl.r32(CRB_RSP_PA)) | u64::from(ctl.r32(CRB_RSP_PA + 4)) << 32;
        let (cl, rl) = (ctl.r32(CRB_CMD_SIZE) as usize, ctl.r32(CRB_RSP_SIZE) as usize);
        if cmd_pa == 0 || rsp_pa == 0 || !(128..=4096).contains(&cl) || !(128..=4096).contains(&rl) {
            return None;
        }
        // SAFETY: the buffers are TPM device memory named by its control area.
        if unsafe { ffi::pmm_range_is_ram(cmd_pa, cl as u64) || ffi::pmm_range_is_ram(rsp_pa, rl as u64) } {
            return None; // never let a device name RAM the kernel owns
        }
        Some(Crb { ctl, cmd: Mmio::map(cmd_pa, cl as u64), cmd_len: cl, rsp: Mmio::map(rsp_pa, rl as u64), rsp_len: rl })
    }
}

impl Transport for Crb {
    fn name(&self) -> &'static str {
        "CRB"
    }
    fn exchange(&mut self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize, Error> {
        let c = &self.ctl;
        if cmd.len() > self.cmd_len {
            return Err(Error::Protocol("command larger than the CRB buffer"));
        }
        c.w32(CRB_LOC_CTRL, 1); // requestAccess
        wait(750 * MS, || c.r32(CRB_LOC_STS) & 1 != 0)?;
        c.w32(CRB_CTRL_REQ, 1); // cmdReady
        wait(2000 * MS, || c.r32(CRB_CTRL_REQ) & 1 == 0)?;
        if c.r32(CRB_CTRL_STS) & 1 != 0 {
            return Err(Error::Protocol("CRB reports a fatal error"));
        }
        for (i, b) in cmd.iter().enumerate() {
            self.cmd.w8(i, *b);
        }
        c.w32(CRB_CTRL_START, 1);
        wait(10_000 * MS, || c.r32(CRB_CTRL_START) & 1 == 0)?;
        for (i, b) in rsp.iter_mut().take(10).enumerate() {
            *b = self.rsp.r8(i);
        }
        let n = be32(rsp, 2).unwrap_or(0) as usize;
        if n < 10 || n > rsp.len() || n > self.rsp_len {
            return Err(Error::Protocol("response size out of range"));
        }
        for (i, b) in rsp.iter_mut().enumerate().take(n).skip(10) {
            *b = self.rsp.r8(i);
        }
        c.w32(CRB_CTRL_REQ, 2); // goIdle
        c.w32(CRB_LOC_CTRL, 2); // relinquish
        Ok(n)
    }
}

/// The TPM named by ACPI, if any: (transport, how it was found) or a reason there is none.
/// The ACPI TPM2 table's bytes (untrusted; also the fuzzing entry point): start method and
/// control area address.
pub fn parse_tpm2(tb: &[u8]) -> Result<(u32, u64), &'static str> {
    if tb.len() < 52 {
        return Err("ACPI TPM2 table too short");
    }
    let control = u64::from_le_bytes(tb[40..48].try_into().unwrap_or([0; 8]));
    let method = u32::from_le_bytes(tb[48..52].try_into().unwrap_or([0; 4]));
    Ok((method, control))
}

pub fn probe() -> Result<Box<dyn Transport>, &'static str> {
    let mut len = 0u32;
    // SAFETY: returns a mapped, checksum-verified table of `len` bytes, or NULL.
    let t = unsafe { ffi::acpi_find_table(b"TPM2".as_ptr(), &mut len) };
    if t.is_null() {
        return Err("none (no ACPI TPM2 table)");
    }
    // SAFETY: the table is `len` bytes, mapped read-only for ever.
    let (method, control) = parse_tpm2(unsafe { core::slice::from_raw_parts(t, len as usize) })?;
    match method {
        6 => Tis::probe().map(|t| Box::new(t) as Box<dyn Transport>).ok_or("TIS interface not responding"),
        7 => Crb::probe(control).map(|t| Box::new(t) as Box<dyn Transport>).ok_or("CRB control area invalid"),
        _ => {
            // Named in the log: which method a real machine uses decides the future work
            // (2 = ACPI, 8 = CRB + ACPI, 11 = CRB + SMC, 12/13 = Pluton).
            crate::kprintln!("TPM: ACPI TPM2 table: start method {}, control area {:#x}", method, control);
            Err("unsupported start method (ACPI start methods need AML)")
        }
    }
}

// ---- simulator (selftest) ---------------------------------------------------------------------------

/// A software TPM answering the four commands, for testing the command layer and the log
/// replay. `fault` breaks responses on purpose.
#[cfg(ktest)]
pub struct Sim {
    pub pcrs: [[u8; 32]; 24],
    started: bool,
    pub fault: SimFault,
    pub commands: u32,
}

#[cfg(ktest)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SimFault {
    None,
    Truncated,
    BadTag,
    Timeout,
}

#[cfg(ktest)]
impl Sim {
    pub fn new() -> Sim {
        Sim { pcrs: [[0; 32]; 24], started: false, fault: SimFault::None, commands: 0 }
    }
}

#[cfg(ktest)]
impl Transport for Sim {
    fn name(&self) -> &'static str {
        "simulator"
    }
    fn exchange(&mut self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize, Error> {
        use doscrypt::sha2::Sha256;
        self.commands += 1;
        if self.fault == SimFault::Timeout {
            return Err(Error::Timeout);
        }
        let mut out = [0u8; 128];
        let mut n = 10;
        let mut rc = 0u32;
        let size = be32(cmd, 2).unwrap_or(0) as usize;
        let cc = be32(cmd, 6).unwrap_or(0);
        if size != cmd.len() {
            rc = 0x95; // TPM_RC_COMMAND_SIZE
        } else {
            match cc {
                CC_STARTUP => {
                    if self.started {
                        rc = RC_INITIALIZE;
                    }
                    self.started = true;
                }
                CC_GET_CAPABILITY => {
                    let vals = [0u32, CAP_TPM_PROPERTIES, 1, PT_MANUFACTURER, u32::from_be_bytes(*b"DOSS")];
                    out[10] = 0; // moreData
                    n = 11;
                    for v in &vals[1..] {
                        out[n..n + 4].copy_from_slice(&v.to_be_bytes());
                        n += 4;
                    }
                }
                CC_PCR_EXTEND => {
                    let pcr = be32(cmd, 10).unwrap_or(99) as usize;
                    let auth = be32(cmd, 14).unwrap_or(0) as usize;
                    let at = 18 + auth;
                    if pcr >= 24 || be32(cmd, at) != Some(1) || be16(cmd, at + 4) != Some(SHA256_ALG) || cmd.len() < at + 6 + 32 {
                        rc = 0x1C4; // TPM_RC_VALUE-ish
                    } else {
                        let mut h = Sha256::new();
                        h.update(&self.pcrs[pcr]);
                        h.update(&cmd[at + 6..at + 38]);
                        self.pcrs[pcr] = h.finish();
                        out[10..14].copy_from_slice(&0u32.to_be_bytes()); // parameterSize
                        n = 14;
                    }
                }
                CC_PCR_READ => {
                    let sel = cmd.get(17..20).unwrap_or(&[0, 0, 0]);
                    let pcr = (0..24).find(|i| sel[i / 8] & (1 << (i % 8)) != 0);
                    match pcr {
                        Some(p) => {
                            let mut w = |b: &[u8]| {
                                out[n..n + b.len()].copy_from_slice(b);
                                n += b.len();
                            };
                            w(&1u32.to_be_bytes()); // update counter
                            w(&1u32.to_be_bytes());
                            w(&SHA256_ALG.to_be_bytes());
                            w(&[3]);
                            w(&cmd[17..20]);
                            w(&1u32.to_be_bytes());
                            w(&32u16.to_be_bytes());
                            w(&self.pcrs[p]);
                        }
                        None => rc = 0x1C4,
                    }
                }
                _ => rc = 0x143, // TPM_RC_COMMAND_CODE
            }
        }
        if rc != 0 {
            n = 10;
        }
        out[0..2].copy_from_slice(&(if self.fault == SimFault::BadTag { 0x1234u16 } else { ST_NO_SESSIONS }).to_be_bytes());
        out[2..6].copy_from_slice(&(n as u32).to_be_bytes());
        out[6..10].copy_from_slice(&rc.to_be_bytes());
        let give = if self.fault == SimFault::Truncated { 6 } else { n };
        rsp[..give].copy_from_slice(&out[..give]);
        Ok(give)
    }
}
