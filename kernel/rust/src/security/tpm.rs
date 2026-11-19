//! TPM 2.0 driver: measured boot and hardware-rooted attestation, over the memory-mapped
//! interfaces PCs have, found through the ACPI `TPM2` table:
//!
//! - TIS / FIFO (TCG PC Client Platform TPM Profile, start method 6), locality 0 at 0xFED40000
//! - CRB (Command Response Buffer), control area from the table, started by writing its start
//!   register (method 7), by the TPM device's ACPI `_DSM` (method 2: AMD firmware TPMs), or both
//!   (method 8). The `_DSM` runs on the ACPI thread (`dev::acpi::tpm_start`).
//!
//! Commands (TPM 2.0 Library, Part 3): Startup, GetCapability (manufacturer), PCR_Extend and
//! PCR_Read on the SHA-256 bank; for attestation CreatePrimary, ReadPublic, FlushContext, Quote,
//! NV_ReadPublic / NV_Read (the EK certificate), and StartAuthSession + PolicySecret +
//! ActivateCredential (proving the attestation key and the endorsement key share a TPM). Every
//! response is length- and tag-checked; a TPM that misbehaves or times out is dropped
//! (measurements stay in the kernel's log).
//!
//! The kernel drives the TPM itself (not a user-space driver): it is the root of the measurement
//! chain, found through ACPI rather than PCI, and used only for a handful of short commands.
//! Without a TPM in the test machine (QEMU on Windows has none), the command layer is tested
//! against the simulator below (`Sim`); TIS and CRB are tested on real hardware.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use crate::ffi;

pub const SHA256_ALG: u16 = 0x000B;
const ST_NO_SESSIONS: u16 = 0x8001;
const ST_SESSIONS: u16 = 0x8002;
const CC_STARTUP: u32 = 0x144;
const CC_PCR_EXTEND: u32 = 0x182;
const CC_PCR_READ: u32 = 0x17E;
const CC_GET_CAPABILITY: u32 = 0x17A;
const CC_CREATE_PRIMARY: u32 = 0x131;
const CC_FLUSH_CONTEXT: u32 = 0x165;
const CC_QUOTE: u32 = 0x158;
const CC_READ_PUBLIC: u32 = 0x173;
const CC_NV_READ_PUBLIC: u32 = 0x169;
const CC_NV_READ: u32 = 0x14E;
const CC_START_AUTH_SESSION: u32 = 0x176;
const CC_POLICY_SECRET: u32 = 0x151;
const CC_ACTIVATE_CREDENTIAL: u32 = 0x147;
const RC_INITIALIZE: u32 = 0x100;
const RS_PW: u32 = 0x4000_0009;
const CAP_TPM_PROPERTIES: u32 = 6;
const PT_MANUFACTURER: u32 = 0x105;
pub const RH_OWNER: u32 = 0x4000_0001;
pub const RH_NULL: u32 = 0x4000_0007;
pub const RH_ENDORSEMENT: u32 = 0x4000_000B;
/// Where Windows and Linux tools keep the RSA EK (TCG Provisioning Guidance).
pub const EK_PERSISTENT: u32 = 0x8101_0001;
/// The NV index of the RSA 2048 EK certificate (TCG EK Credential Profile).
pub const EK_CERT_NV_RSA: u32 = 0x01C0_0002;
/// Largest EK certificate read.
pub const EK_CERT_MAX: usize = 2048;
const SE_POLICY: u8 = 1;
const ALG_NULL: u16 = 0x0010;
/// Largest response accepted (and buffer allocated).
const RSP_MAX: usize = 4096;

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

/// A loaded key: its handle, `TPMT_PUBLIC` and Name (SHA-256 || digest of the public area).
pub struct Key {
    pub handle: u32,
    pub public: Vec<u8>,
    pub name: [u8; 34],
}

/// Big-endian command builder.
struct Cmd(Vec<u8>);

impl Cmd {
    fn new(tag: u16, cc: u32) -> Cmd {
        let mut v = Vec::with_capacity(96);
        v.extend_from_slice(&tag.to_be_bytes());
        v.extend_from_slice(&[0; 4]);
        v.extend_from_slice(&cc.to_be_bytes());
        Cmd(v)
    }
    fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    fn u16(&mut self, v: u16) -> &mut Self {
        self.bytes(&v.to_be_bytes())
    }
    fn u32(&mut self, v: u32) -> &mut Self {
        self.bytes(&v.to_be_bytes())
    }
    fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.0.extend_from_slice(v);
        self
    }
    fn tpm2b(&mut self, v: &[u8]) -> &mut Self {
        self.u16(v.len() as u16).bytes(v)
    }
    /// The authorization area: one password session with an empty password.
    fn pw(&mut self) -> &mut Self {
        self.u32(9).u32(RS_PW).u16(0).u8(0).u16(0)
    }
    fn done(mut self) -> Vec<u8> {
        let n = self.0.len() as u32;
        self.0[2..6].copy_from_slice(&n.to_be_bytes());
        self.0
    }
}

fn be16(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(o)?, *b.get(o + 1)?]))
}
fn be32(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_be_bytes([*b.get(o)?, *b.get(o + 1)?, *b.get(o + 2)?, *b.get(o + 3)?]))
}

/// Response parameter reader: every read is bounds-checked.
struct Rsp<'a> {
    b: &'a [u8],
    o: usize,
}

const SHORT: Error = Error::Protocol("response too short");

impl<'a> Rsp<'a> {
    /// The parameters of a response with `handles` handles (and, with sessions, a parameter size).
    fn params(r: &'a [u8], handles: usize) -> Result<Rsp<'a>, Error> {
        let mut p = Rsp { b: r, o: 10 + 4 * handles };
        if be16(r, 0) == Some(ST_SESSIONS) {
            let size = p.u32()? as usize;
            let end = p.o.checked_add(size).filter(|&e| e <= r.len()).ok_or(SHORT)?;
            p.b = &r[..end];
        }
        Ok(p)
    }
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let v = self.b.get(self.o..self.o.checked_add(n).ok_or(SHORT)?).ok_or(SHORT)?;
        self.o += n;
        Ok(v)
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.bytes(2)?.try_into().map_err(|_| SHORT)?))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.bytes(4)?.try_into().map_err(|_| SHORT)?))
    }
    fn tpm2b(&mut self) -> Result<&'a [u8], Error> {
        let n = usize::from(self.u16()?);
        self.bytes(n)
    }
}

fn name_of(public: &[u8]) -> [u8; 34] {
    let mut n = [0u8; 34];
    n[..2].copy_from_slice(&SHA256_ALG.to_be_bytes());
    n[2..].copy_from_slice(&doscrypt::sha2::sha256(public));
    n
}

impl Tpm {
    /// Bring a TPM up on `t`: Startup (or already started), then the manufacturer.
    pub fn new(t: Box<dyn Transport>) -> Result<Tpm, Error> {
        let mut tpm = Tpm { t, manufacturer: [0; 4] };
        let mut c = Cmd::new(ST_NO_SESSIONS, CC_STARTUP);
        c.u16(0); // TPM_SU_CLEAR
        match tpm.command(c.done()) {
            Ok(_) | Err(Error::Tpm(RC_INITIALIZE)) => {}
            Err(e) => return Err(e),
        }
        let mut c = Cmd::new(ST_NO_SESSIONS, CC_GET_CAPABILITY);
        c.u32(CAP_TPM_PROPERTIES).u32(PT_MANUFACTURER).u32(1);
        let r = tpm.command(c.done())?;
        // moreData(1) capability(4) count(4) property(4) value(4)
        if be32(&r, 11) != Some(CAP_TPM_PROPERTIES) || be32(&r, 15) != Some(1) || be32(&r, 19) != Some(PT_MANUFACTURER) {
            return Err(Error::Protocol("unexpected GetCapability answer"));
        }
        let v = be32(&r, 23).ok_or(Error::Protocol("short GetCapability answer"))?;
        tpm.manufacturer = v.to_be_bytes();
        Ok(tpm)
    }

    pub fn interface(&self) -> &'static str {
        self.t.name()
    }

    /// One command; checks the response header. Returns the response.
    fn command(&mut self, cmd: Vec<u8>) -> Result<Vec<u8>, Error> {
        let mut rsp = vec![0u8; RSP_MAX];
        let got = self.t.exchange(&cmd, &mut rsp)?;
        if !(10..=rsp.len()).contains(&got) {
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
        rsp.truncate(got);
        Ok(rsp)
    }

    pub fn pcr_extend(&mut self, pcr: u32, digest: &[u8; 32]) -> Result<(), Error> {
        let mut c = Cmd::new(ST_SESSIONS, CC_PCR_EXTEND);
        c.u32(pcr).pw();
        c.u32(1).u16(SHA256_ALG).bytes(digest);
        self.command(c.done()).map(|_| ())
    }

    pub fn pcr_read(&mut self, pcr: u32) -> Result<[u8; 32], Error> {
        if pcr >= 24 {
            return Err(Error::Protocol("PCR index"));
        }
        let mut sel = [0u8; 3];
        sel[(pcr / 8) as usize] = 1 << (pcr % 8);
        let mut c = Cmd::new(ST_NO_SESSIONS, CC_PCR_READ);
        c.u32(1).u16(SHA256_ALG).u8(3).bytes(&sel);
        let r = self.command(c.done())?;
        // updateCounter(4) TPML_PCR_SELECTION(4 + 2 + 1 + 3) TPML_DIGEST count(4) TPM2B size(2) digest
        if be32(&r, 10 + 4) != Some(1) || be32(&r, 24) != Some(1) || be16(&r, 28) != Some(32) || r.len() < 62 {
            return Err(Error::Protocol("unexpected PCR_Read answer"));
        }
        let mut d = [0u8; 32];
        d.copy_from_slice(&r[30..62]);
        Ok(d)
    }

    /// TPM2_CreatePrimary under `hierarchy` (empty authorization) from a `TPMT_PUBLIC` template.
    pub fn create_primary(&mut self, hierarchy: u32, template: &[u8]) -> Result<Key, Error> {
        let mut c = Cmd::new(ST_SESSIONS, CC_CREATE_PRIMARY);
        c.u32(hierarchy).pw();
        c.u16(4).u16(0).u16(0); // inSensitive: no auth, no data
        c.tpm2b(template).u16(0).u32(0); // inPublic, outsideInfo, creationPCR
        let r = self.command(c.done())?;
        let handle = be32(&r, 10).ok_or(SHORT)?;
        let mut p = Rsp::params(&r, 1)?;
        let public = p.tpm2b()?.to_vec();
        p.tpm2b()?; // creationData
        p.tpm2b()?; // creationHash
        p.u16()?; // creationTicket: tag
        p.u32()?; // hierarchy
        p.tpm2b()?; // digest
        let n = p.tpm2b()?;
        let name = name_of(&public);
        if n != name {
            self.flush(handle);
            return Err(Error::Protocol("CreatePrimary: the name does not match the public area"));
        }
        Ok(Key { handle, public, name })
    }

    /// TPM2_ReadPublic of a loaded or persistent object.
    pub fn read_public(&mut self, handle: u32) -> Result<Key, Error> {
        let mut c = Cmd::new(ST_NO_SESSIONS, CC_READ_PUBLIC);
        c.u32(handle);
        let r = self.command(c.done())?;
        let mut p = Rsp::params(&r, 0)?;
        let public = p.tpm2b()?.to_vec();
        let name = name_of(&public);
        if p.tpm2b()? != name {
            return Err(Error::Protocol("ReadPublic: the name does not match the public area"));
        }
        Ok(Key { handle, public, name })
    }

    /// TPM2_FlushContext (transient objects and sessions); errors are ignored.
    pub fn flush(&mut self, handle: u32) {
        let mut c = Cmd::new(ST_NO_SESSIONS, CC_FLUSH_CONTEXT);
        c.u32(handle);
        let _ = self.command(c.done());
    }

    /// TPM2_Quote: the SHA-256 PCRs in `pcrs` (bit i = PCR i, below 24) signed by the restricted
    /// signing key `key` with `nonce` as qualifying data. Returns (`TPMS_ATTEST`, `TPMT_SIGNATURE`).
    pub fn quote(&mut self, key: u32, nonce: &[u8], pcrs: u32) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let mut c = Cmd::new(ST_SESSIONS, CC_QUOTE);
        c.u32(key).pw();
        c.tpm2b(nonce).u16(ALG_NULL); // the key's own scheme
        c.u32(1).u16(SHA256_ALG).u8(3).bytes(&[pcrs as u8, (pcrs >> 8) as u8, (pcrs >> 16) as u8]);
        let r = self.command(c.done())?;
        let mut p = Rsp::params(&r, 0)?;
        let attest = p.tpm2b()?.to_vec();
        let start = p.o;
        p.u16()?; // sigAlg
        p.u16()?; // hash
        p.tpm2b()?; // r
        p.tpm2b()?; // s
        Ok((attest, r[start..p.o].to_vec()))
    }

    /// The whole contents of an NV index (at most `max` bytes), read with the index's own
    /// (empty) authorization, or the owner's when the index does not allow that.
    pub fn nv_read_all(&mut self, index: u32, max: usize) -> Result<Vec<u8>, Error> {
        let mut c = Cmd::new(ST_NO_SESSIONS, CC_NV_READ_PUBLIC);
        c.u32(index);
        let r = self.command(c.done())?;
        let mut p = Rsp::params(&r, 0)?;
        let mut pubp = Rsp { b: p.tpm2b()?, o: 0 };
        if pubp.u32()? != index {
            return Err(Error::Protocol("NV_ReadPublic: another index"));
        }
        pubp.u16()?; // nameAlg
        pubp.u32()?; // attributes
        pubp.tpm2b()?; // authPolicy
        let size = usize::from(pubp.u16()?);
        if size > max {
            return Err(Error::Protocol("NV index larger than expected"));
        }
        let mut out = Vec::with_capacity(size);
        let mut auth = index;
        while out.len() < size {
            let n = (size - out.len()).min(512);
            let mut c = Cmd::new(ST_SESSIONS, CC_NV_READ);
            c.u32(auth).u32(index).pw();
            c.u16(n as u16).u16(out.len() as u16);
            let r = match self.command(c.done()) {
                Err(Error::Tpm(_)) if auth == index && out.is_empty() => {
                    auth = RH_OWNER;
                    continue;
                }
                r => r?,
            };
            let mut p = Rsp::params(&r, 0)?;
            let data = p.tpm2b()?;
            if data.len() != n {
                return Err(Error::Protocol("NV_Read: short data"));
            }
            out.extend_from_slice(data);
        }
        Ok(out)
    }

    /// TPM2_ActivateCredential: the secret a verifier encrypted to the EK `ek` for the object `ak`
    /// (`blob`: `TPM2B_ID_OBJECT`, `secret`: `TPM2B_ENCRYPTED_SECRET`, each with its size). The EK's
    /// policy is satisfied with a policy session and PolicySecret(TPM_RH_ENDORSEMENT).
    pub fn activate_credential(&mut self, ak: u32, ek: u32, blob: &[u8], secret: &[u8]) -> Result<[u8; 32], Error> {
        let mut c = Cmd::new(ST_NO_SESSIONS, CC_START_AUTH_SESSION);
        c.u32(RH_NULL).u32(RH_NULL); // unsalted, unbound
        c.tpm2b(&[0x5A; 16]).u16(0).u8(SE_POLICY).u16(ALG_NULL).u16(SHA256_ALG);
        let r = self.command(c.done())?;
        let session = be32(&r, 10).ok_or(SHORT)?;
        let res = self.activate_in(session, ak, ek, blob, secret);
        if res.is_err() {
            self.flush(session); // on success the TPM ended the session (continueSession clear)
        }
        res
    }

    fn activate_in(&mut self, session: u32, ak: u32, ek: u32, blob: &[u8], secret: &[u8]) -> Result<[u8; 32], Error> {
        let mut c = Cmd::new(ST_SESSIONS, CC_POLICY_SECRET);
        c.u32(RH_ENDORSEMENT).u32(session).pw();
        c.u16(0).u16(0).u16(0).u32(0); // nonceTPM, cpHashA, policyRef, expiration
        self.command(c.done())?;
        let mut c = Cmd::new(ST_SESSIONS, CC_ACTIVATE_CREDENTIAL);
        c.u32(ak).u32(ek);
        c.u32(9 + 9).u32(RS_PW).u16(0).u8(0).u16(0); // the AK: empty password
        c.u32(session).u16(0).u8(0).u16(0); // the EK: the policy session
        c.bytes(blob).bytes(secret);
        let r = self.command(c.done())?;
        let mut p = Rsp::params(&r, 0)?;
        p.tpm2b()?.try_into().map_err(|_| Error::Protocol("ActivateCredential: not 32 bytes"))
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
        // Key creation (CreatePrimary of an RSA EK) can take tens of seconds on slow TPMs.
        wait(60_000 * MS, || m.r32(TIS_STS) & (STS_VALID | STS_DATA) == STS_VALID | STS_DATA)?;
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

/// How a CRB command is started (the TPM2 table's start method).
#[derive(Clone, Copy, PartialEq, Eq)]
enum CrbStart {
    /// Method 7: the start register.
    Register,
    /// Method 2: the ACPI `_DSM` only; the firmware TPM has no locality or idle states to drive.
    Acpi,
    /// Method 8: the start register, then the `_DSM`.
    Both,
}

/// CRB interface, locality 0: command and response buffers named by the control area.
pub struct Crb {
    /// The control area (the TPM2 table's address: `CTRL_REQ` first).
    ctl: Mmio,
    /// The locality registers, 0x40 below the control area (not with method 2).
    loc: Option<Mmio>,
    cmd: Mmio,
    cmd_len: usize,
    rsp: Mmio,
    rsp_len: usize,
    start: CrbStart,
}

// Control area (TCG PC Client Platform TPM Profile, CRB), from the table's address.
const CRB_CTRL_REQ: usize = 0x00;
const CRB_CTRL_STS: usize = 0x04;
const CRB_CTRL_START: usize = 0x0C;
const CRB_CMD_SIZE: usize = 0x18;
const CRB_CMD_LO: usize = 0x1C;
const CRB_CMD_HI: usize = 0x20;
const CRB_RSP_SIZE: usize = 0x24;
const CRB_RSP_PA: usize = 0x28;
const CRB_CTRL_LEN: u64 = 0x30;
// Locality registers, at control area - 0x40.
const CRB_LOC_CTRL: usize = 0x08;
const CRB_LOC_STS: usize = 0x0C;
/// The buffers are mapped up to this size (commands and responses here are smaller).
const CRB_BUF_MAX: usize = 4096;

impl Crb {
    fn probe(control: u64, start: CrbStart) -> Option<Crb> {
        if control < 0x40 || !control.is_multiple_of(4) {
            return None;
        }
        let ctl = Mmio::map(control, CRB_CTRL_LEN);
        let cmd_pa = u64::from(ctl.r32(CRB_CMD_LO)) | u64::from(ctl.r32(CRB_CMD_HI)) << 32;
        let rsp_pa = u64::from(ctl.r32(CRB_RSP_PA)) | u64::from(ctl.r32(CRB_RSP_PA + 4)) << 32;
        let (cl, rl) = (ctl.r32(CRB_CMD_SIZE) as usize, ctl.r32(CRB_RSP_SIZE) as usize);
        if cmd_pa == 0 || rsp_pa == 0 || cl < 128 || rl < 128 {
            return None;
        }
        let (cl, rl) = (cl.min(CRB_BUF_MAX), rl.min(CRB_BUF_MAX));
        // SAFETY: the buffers are TPM device memory named by its control area.
        if unsafe { ffi::pmm_range_is_ram(cmd_pa, cl as u64) || ffi::pmm_range_is_ram(rsp_pa, rl as u64) } {
            return None; // never let a device name RAM the kernel owns
        }
        let loc = (start != CrbStart::Acpi).then(|| Mmio::map(control - 0x40, 0x10));
        Some(Crb { ctl, loc, cmd: Mmio::map(cmd_pa, cl as u64), cmd_len: cl, rsp: Mmio::map(rsp_pa, rl as u64), rsp_len: rl, start })
    }
}

impl Transport for Crb {
    fn name(&self) -> &'static str {
        match self.start {
            CrbStart::Register => "CRB",
            CrbStart::Acpi => "CRB, ACPI start",
            CrbStart::Both => "CRB + ACPI start",
        }
    }
    fn exchange(&mut self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize, Error> {
        let c = &self.ctl;
        if cmd.len() > self.cmd_len {
            return Err(Error::Protocol("command larger than the CRB buffer"));
        }
        if let Some(l) = &self.loc {
            l.w32(CRB_LOC_CTRL, 1); // requestAccess
            wait(750 * MS, || l.r32(CRB_LOC_STS) & 1 != 0)?;
            c.w32(CRB_CTRL_REQ, 1); // cmdReady
            wait(2000 * MS, || c.r32(CRB_CTRL_REQ) & 1 == 0)?;
        }
        if c.r32(CRB_CTRL_STS) & 1 != 0 {
            return Err(Error::Protocol("CRB reports a fatal error"));
        }
        for (i, b) in cmd.iter().enumerate() {
            self.cmd.w8(i, *b);
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        if self.start != CrbStart::Acpi {
            c.w32(CRB_CTRL_START, 1);
        }
        if self.start != CrbStart::Register {
            crate::dev::acpi::tpm_start().map_err(Error::Protocol)?;
        }
        wait(60_000 * MS, || c.r32(CRB_CTRL_START) & 1 == 0)?;
        if c.r32(CRB_CTRL_STS) & 1 != 0 {
            return Err(Error::Protocol("CRB reports a fatal error"));
        }
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
        if let Some(l) = &self.loc {
            c.w32(CRB_CTRL_REQ, 2); // goIdle
            l.w32(CRB_LOC_CTRL, 2); // relinquish
        }
        Ok(n)
    }
}

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

/// The TPM named by ACPI, if any, or a reason there is none.
pub fn probe() -> Result<Box<dyn Transport>, &'static str> {
    let mut len = 0u32;
    // SAFETY: returns a mapped, checksum-verified table of `len` bytes, or NULL.
    let t = unsafe { ffi::acpi_find_table(b"TPM2".as_ptr(), &mut len) };
    if t.is_null() {
        return Err("none (no ACPI TPM2 table)");
    }
    // SAFETY: the table is `len` bytes, mapped read-only for ever.
    let (method, control) = parse_tpm2(unsafe { core::slice::from_raw_parts(t, len as usize) })?;
    let crb = |s| Crb::probe(control, s).map(|t| Box::new(t) as Box<dyn Transport>).ok_or("CRB control area invalid");
    match method {
        2 => crb(CrbStart::Acpi),
        6 => Tis::probe().map(|t| Box::new(t) as Box<dyn Transport>).ok_or("TIS interface not responding"),
        7 => crb(CrbStart::Register),
        8 => crb(CrbStart::Both),
        _ => {
            // Named in the log: 11 = CRB + Arm SMC, 12/13 = Pluton.
            crate::kprintln!("TPM: ACPI TPM2 table: start method {}, control area {:#x}", method, control);
            Err("unsupported start method")
        }
    }
}

// ---- simulator (tests) ------------------------------------------------------------------------------

/// A software TPM for testing the command layer, the log replay and attestation: the commands
/// above, with the fixed TEST endorsement key and certificate of `doscrypt::testkeys` and a fixed
/// attestation key. `fault` breaks responses on purpose. Never in a release kernel.
#[cfg(ktest)]
pub struct Sim {
    pub pcrs: [[u8; 32]; 24],
    started: bool,
    pub fault: SimFault,
    pub commands: u32,
    /// Loaded objects: (handle, is the EK).
    objects: Vec<(u32, bool)>,
    /// Policy sessions: (handle, PolicySecret(endorsement) done).
    sessions: Vec<(u32, bool)>,
    next: u32,
}

#[cfg(ktest)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SimFault {
    None,
    Truncated,
    BadTag,
    Timeout,
}

/// The simulator's attestation private key (P-256, big-endian; a test key).
#[cfg(ktest)]
fn sim_ak_secret() -> [u8; 32] {
    doscrypt::sha2::sha256(b"D-OS simulated TPM attestation key (test only)")
}

#[cfg(ktest)]
fn sim_ak_public() -> Vec<u8> {
    let p = doscrypt::p256::sim::public(&sim_ak_secret());
    let (a, n) = doscrypt::tpm::sim::ak_public(&p.x(), &p.y());
    a[..n].to_vec()
}

#[cfg(ktest)]
fn sim_ek_public() -> Vec<u8> {
    let (a, n) = doscrypt::tpm::sim::ek_public(&doscrypt::testkeys::EK_N);
    a[..n].to_vec()
}

#[cfg(ktest)]
impl Sim {
    pub fn new() -> Sim {
        Sim { pcrs: [[0; 32]; 24], started: false, fault: SimFault::None, commands: 0, objects: Vec::new(), sessions: Vec::new(), next: 0 }
    }

    /// Objects and sessions still loaded (tests check nothing leaks).
    pub fn loaded(&self) -> usize {
        self.objects.len() + self.sessions.len()
    }

    /// The answer to one well-formed command: (response code, parameters, with sessions).
    fn run(&mut self, cmd: &[u8]) -> (u32, Vec<u8>) {
        use doscrypt::sha2::{Sha256, sha256};
        const VALUE: u32 = 0x1C4;
        const HANDLE: u32 = 0x18B;
        let cc = be32(cmd, 6).unwrap_or(0);
        let mut out = Vec::new();
        let put16 = |o: &mut Vec<u8>, v: u16| o.extend_from_slice(&v.to_be_bytes());
        let put32 = |o: &mut Vec<u8>, v: u32| o.extend_from_slice(&v.to_be_bytes());
        let tpm2b = |o: &mut Vec<u8>, v: &[u8]| {
            o.extend_from_slice(&(v.len() as u16).to_be_bytes());
            o.extend_from_slice(v);
        };
        // Parameters start after the handles and (with sessions) the authorization area.
        let handles = match cc {
            CC_PCR_EXTEND | CC_CREATE_PRIMARY | CC_QUOTE | CC_READ_PUBLIC | CC_NV_READ_PUBLIC | CC_FLUSH_CONTEXT => 1,
            CC_NV_READ | CC_POLICY_SECRET | CC_ACTIVATE_CREDENTIAL | CC_START_AUTH_SESSION => 2,
            _ => 0,
        };
        let mut at = 10 + 4 * handles;
        let mut auth: &[u8] = &[];
        if be16(cmd, 0) == Some(ST_SESSIONS) {
            let n = be32(cmd, at).unwrap_or(u32::MAX) as usize;
            let Some(a) = cmd.get(at + 4..at + 4 + n) else { return (VALUE, out) };
            auth = a;
            at += 4 + n;
        }
        let h = |i: usize| be32(cmd, 10 + 4 * i).unwrap_or(0);
        let mut p = Rsp { b: cmd, o: at };
        match cc {
            CC_STARTUP => {
                if self.started {
                    return (RC_INITIALIZE, out);
                }
                self.started = true;
            }
            CC_GET_CAPABILITY => {
                out.push(0); // moreData
                for v in [CAP_TPM_PROPERTIES, 1, PT_MANUFACTURER, u32::from_be_bytes(*b"DOSS")] {
                    put32(&mut out, v);
                }
            }
            CC_PCR_EXTEND => {
                let pcr = h(0) as usize;
                if pcr >= 24 || be32(cmd, at) != Some(1) || be16(cmd, at + 4) != Some(SHA256_ALG) || cmd.len() < at + 6 + 32 {
                    return (VALUE, out);
                }
                let mut s = Sha256::new();
                s.update(&self.pcrs[pcr]);
                s.update(&cmd[at + 6..at + 38]);
                self.pcrs[pcr] = s.finish();
            }
            CC_PCR_READ => {
                let sel = cmd.get(17..20).unwrap_or(&[0, 0, 0]);
                let Some(pcr) = (0..24).find(|i| sel[i / 8] & (1 << (i % 8)) != 0) else { return (VALUE, out) };
                put32(&mut out, 1); // update counter
                put32(&mut out, 1);
                put16(&mut out, SHA256_ALG);
                out.push(3);
                out.extend_from_slice(&cmd[17..20]);
                put32(&mut out, 1);
                tpm2b(&mut out, &self.pcrs[pcr]);
            }
            CC_CREATE_PRIMARY => {
                let (Ok(_), Ok(template)) = (p.tpm2b(), p.tpm2b()) else { return (VALUE, out) };
                let is_ek = template == &doscrypt::tpm::ek_template().0[..doscrypt::tpm::ek_template().1];
                let is_ak = template == &doscrypt::tpm::ak_template().0[..doscrypt::tpm::ak_template().1];
                if h(0) != RH_ENDORSEMENT || !(is_ek || is_ak) {
                    return (VALUE, out);
                }
                let public = if is_ek { sim_ek_public() } else { sim_ak_public() };
                self.next += 1;
                let handle = 0x8000_0000 + self.next;
                self.objects.push((handle, is_ek));
                put32(&mut out, handle);
                tpm2b(&mut out, &public);
                tpm2b(&mut out, &[]); // creationData
                tpm2b(&mut out, &[]); // creationHash
                put16(&mut out, 0x8021);
                put32(&mut out, RH_ENDORSEMENT);
                tpm2b(&mut out, &[]);
                tpm2b(&mut out, &name_of(&public));
            }
            CC_READ_PUBLIC => {
                let Some(&(_, ek)) = self.objects.iter().find(|o| o.0 == h(0)) else { return (HANDLE, out) };
                let public = if ek { sim_ek_public() } else { sim_ak_public() };
                tpm2b(&mut out, &public);
                tpm2b(&mut out, &name_of(&public));
                tpm2b(&mut out, &name_of(&public)); // qualifiedName (not checked)
            }
            CC_FLUSH_CONTEXT => {
                let n = self.loaded();
                self.objects.retain(|o| o.0 != h(0));
                self.sessions.retain(|s| s.0 != h(0));
                if self.loaded() == n {
                    return (HANDLE, out);
                }
            }
            CC_QUOTE => {
                if !self.objects.iter().any(|o| o.0 == h(0) && !o.1) {
                    return (HANDLE, out);
                }
                let (Ok(extra), Ok(ALG_NULL), Ok(1), Ok(SHA256_ALG), Ok(3), Ok(sel)) = (p.tpm2b(), p.u16(), p.u32(), p.u16(), p.bytes(1).map(|b| b[0]), p.bytes(3)) else {
                    return (VALUE, out);
                };
                let bits = u32::from(sel[0]) | u32::from(sel[1]) << 8 | u32::from(sel[2]) << 16;
                let mut s = Sha256::new();
                for i in 0..24 {
                    if bits & (1 << i) != 0 {
                        s.update(&self.pcrs[i]);
                    }
                }
                let (info, n) = doscrypt::tpm::sim::quote_info(&name_of(&sim_ak_public()), extra, bits, &s.finish());
                let digest = sha256(&info[..n]);
                let d = sim_ak_secret();
                let mut k = sha256(&[&d[..], &digest[..]].concat());
                let (r, sg) = loop {
                    if let Some(rs) = doscrypt::p256::sim::sign_prehash(&d, &k, &digest) {
                        break rs;
                    }
                    k = sha256(&k);
                };
                let (sig, sn) = doscrypt::tpm::sim::ecdsa_signature(&r, &sg);
                tpm2b(&mut out, &info[..n]);
                out.extend_from_slice(&sig[..sn]);
            }
            CC_NV_READ_PUBLIC => {
                if h(0) != EK_CERT_NV_RSA {
                    return (HANDLE, out);
                }
                let mut nv = Vec::new();
                put32(&mut nv, EK_CERT_NV_RSA);
                put16(&mut nv, SHA256_ALG);
                put32(&mut nv, 0x0006_2002); // PPWRITE..., AUTHREAD, NO_DA, WRITTEN: illustrative
                tpm2b(&mut nv, &[]);
                put16(&mut nv, doscrypt::testkeys::EK_CERT.len() as u16);
                tpm2b(&mut out, &nv);
                tpm2b(&mut out, &[0; 34]);
            }
            CC_NV_READ => {
                let cert = &doscrypt::testkeys::EK_CERT[..];
                let (Ok(n), Ok(off)) = (p.u16(), p.u16()) else { return (VALUE, out) };
                let (n, off) = (usize::from(n), usize::from(off));
                if h(1) != EK_CERT_NV_RSA || off + n > cert.len() || n > 1024 {
                    return (VALUE, out);
                }
                tpm2b(&mut out, &cert[off..off + n]);
            }
            CC_START_AUTH_SESSION => {
                let (Ok(nonce), Ok(salt), Ok(kind)) = (p.tpm2b(), p.tpm2b(), p.bytes(1)) else { return (VALUE, out) };
                if nonce.len() < 16 || !salt.is_empty() || kind[0] != SE_POLICY || h(0) != RH_NULL || h(1) != RH_NULL {
                    return (VALUE, out);
                }
                self.next += 1;
                let handle = 0x0300_0000 + self.next;
                self.sessions.push((handle, false));
                put32(&mut out, handle);
                tpm2b(&mut out, &[0xA5; 16]);
            }
            CC_POLICY_SECRET => {
                if h(0) != RH_ENDORSEMENT {
                    return (VALUE, out);
                }
                let Some(s) = self.sessions.iter_mut().find(|s| s.0 == h(1)) else { return (HANDLE, out) };
                s.1 = true;
                tpm2b(&mut out, &[]); // timeout
                put16(&mut out, 0x8025);
                put32(&mut out, RH_ENDORSEMENT);
                tpm2b(&mut out, &[]);
            }
            CC_ACTIVATE_CREDENTIAL => {
                // Sessions: the AK's password, then the EK's policy session (used up).
                let policy = be32(auth, 9).unwrap_or(0);
                let ok = auth.len() == 18 && be32(auth, 0) == Some(RS_PW) && self.sessions.iter().any(|s| s.0 == policy && s.1);
                self.sessions.retain(|s| s.0 != policy);
                let ak = self.objects.iter().any(|o| o.0 == h(0) && !o.1);
                let ek = self.objects.iter().any(|o| o.0 == h(1) && o.1);
                if !ok {
                    return (0x9A2, out); // TPM_RC_POLICY_FAIL (session 2)
                }
                if !ak || !ek {
                    return (HANDLE, out);
                }
                let start = p.o;
                let (Ok(_), Ok(_)) = (p.tpm2b(), p.tpm2b()) else { return (VALUE, out) };
                let blob_end = start + 2 + usize::from(be16(cmd, start).unwrap_or(0));
                let (blob, secret) = (&cmd[start..blob_end], &cmd[blob_end..p.o]);
                let name = name_of(&sim_ak_public());
                let t = &doscrypt::testkeys::EK_N;
                match doscrypt::tpm::sim::open_credential(t, &doscrypt::testkeys::EK_D, &name, blob, secret) {
                    Some(c) => tpm2b(&mut out, &c),
                    None => return (0x0A1, out), // TPM_RC_INTEGRITY-ish
                }
            }
            _ => return (0x143, out), // TPM_RC_COMMAND_CODE
        }
        (0, out)
    }
}

#[cfg(ktest)]
impl Transport for Sim {
    fn name(&self) -> &'static str {
        "simulator"
    }
    fn exchange(&mut self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize, Error> {
        self.commands += 1;
        if self.fault == SimFault::Timeout {
            return Err(Error::Timeout);
        }
        let size = be32(cmd, 2).unwrap_or(0) as usize;
        let (rc, params) = if size != cmd.len() { (0x95, Vec::new()) } else { self.run(cmd) };
        // Responses to commands with sessions: handle(s), parameterSize, parameters, one empty
        // session response per session; errors are headers only.
        let sessions = be16(cmd, 0) == Some(ST_SESSIONS) && rc == 0;
        let handles = match be32(cmd, 6).unwrap_or(0) {
            CC_CREATE_PRIMARY | CC_START_AUTH_SESSION => 4,
            _ => 0,
        };
        let mut out = Vec::with_capacity(params.len() + 32);
        let tag = if self.fault == SimFault::BadTag { 0x1234 } else if sessions { ST_SESSIONS } else { ST_NO_SESSIONS };
        out.extend_from_slice(&tag.to_be_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&rc.to_be_bytes());
        if rc == 0 {
            if sessions {
                let nsess = if be32(cmd, 6) == Some(CC_ACTIVATE_CREDENTIAL) { 2 } else { 1 };
                out.extend_from_slice(&params[..handles]);
                out.extend_from_slice(&((params.len() - handles) as u32).to_be_bytes());
                out.extend_from_slice(&params[handles..]);
                for _ in 0..nsess {
                    out.extend_from_slice(&[0, 0, 0, 0, 0]);
                }
            } else {
                out.extend_from_slice(&params);
            }
        }
        let n = out.len();
        out[2..6].copy_from_slice(&(n as u32).to_be_bytes());
        let give = if self.fault == SimFault::Truncated { 6 } else { n };
        if give > rsp.len() {
            return Err(Error::Protocol("response too large"));
        }
        rsp[..give].copy_from_slice(&out[..give]);
        Ok(give)
    }
}
