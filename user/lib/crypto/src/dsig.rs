//! `.dsig`: D-OS detached signature, version 1 (docs/signing.md). Shared by the boot loaders (C:
//! boot/common/dsig.c), the kernel and D-PACK. 256 bytes, little-endian:
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | 0 | 4 | magic `DSIG` |
//! | 4 | 2 | version (1) |
//! | 6 | 2 | algorithm (1 = Ed25519) |
//! | 8 | 4 | kind (1 kernel, 2 program, 3 driver, 4 package) |
//! | 12 | 4 | flags (0) |
//! | 16 | 16 | key id: the first 16 bytes of SHA-512(public key) |
//! | 32 | 8 | content size in bytes |
//! | 40 | 64 | SHA-512 of the content |
//! | 104 | 88 | name (UTF-8, NUL-padded; what the content is, e.g. `KERNEL.BIN`) |
//! | 192 | 64 | Ed25519 signature of bytes 0..192 |
//!
//! Signing the header (which commits to the content's hash and size) lets a verifier hash the
//! content as it streams in and check one fixed-size message.

use crate::ed25519::{self, SigningKey};
use crate::sha2::{Sha512, sha512};

pub const SIZE: usize = 256;
pub const SIGNED: usize = 192;
pub const MAGIC: &[u8; 4] = b"DSIG";
pub const VERSION: u16 = 1;
pub const ALG_ED25519: u16 = 1;
pub const NAME_MAX: usize = 88;

pub const KIND_KERNEL: u32 = 1;
pub const KIND_PROGRAM: u32 = 2;
pub const KIND_DRIVER: u32 = 3;
pub const KIND_PACKAGE: u32 = 4;
/// A service manifest (`.dman`): data the service manager trusts, never runnable.
pub const KIND_MANIFEST: u32 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Not a `.dsig` of a version and algorithm this code knows.
    Format,
    /// Signed by a key that is not the one given.
    UnknownKey,
    /// The content does not match the signed size or hash.
    Content,
    /// The signature over the header is not valid.
    Signature,
}

pub fn key_id(public: &[u8; 32]) -> [u8; 16] {
    let h = sha512(public);
    let mut id = [0u8; 16];
    id.copy_from_slice(&h[..16]);
    id
}

/// The parsed header.
#[derive(Clone, Debug)]
pub struct Header {
    pub kind: u32,
    pub key_id: [u8; 16],
    pub size: u64,
    pub hash: [u8; 64],
    pub name: [u8; NAME_MAX],
}

impl Header {
    pub fn name_str(&self) -> &str {
        let n = self.name.iter().position(|&b| b == 0).unwrap_or(NAME_MAX);
        core::str::from_utf8(&self.name[..n]).unwrap_or("?")
    }
}

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Parse (no signature check): format errors only.
pub fn parse(d: &[u8]) -> Result<Header, Error> {
    if d.len() != SIZE || &d[0..4] != MAGIC || u16_at(d, 4) != VERSION || u16_at(d, 6) != ALG_ED25519 || u32_at(d, 12) != 0 {
        return Err(Error::Format);
    }
    let mut size = [0u8; 8];
    size.copy_from_slice(&d[32..40]);
    let mut h = Header { kind: u32_at(d, 8), key_id: [0; 16], size: u64::from_le_bytes(size), hash: [0; 64], name: [0; NAME_MAX] };
    h.key_id.copy_from_slice(&d[16..32]);
    h.hash.copy_from_slice(&d[40..104]);
    h.name.copy_from_slice(&d[104..192]);
    Ok(h)
}

/// Check a `.dsig` against `public` and the content's SHA-512 and size (hashed by the caller, who
/// may stream it). Returns the header on success.
pub fn verify_hashed(d: &[u8], public: &[u8; 32], size: u64, hash: &[u8; 64]) -> Result<Header, Error> {
    let h = parse(d)?;
    if h.key_id != key_id(public) {
        return Err(Error::UnknownKey);
    }
    if h.size != size || h.hash != *hash {
        return Err(Error::Content);
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&d[SIGNED..SIZE]);
    if !ed25519::verify(public, &d[..SIGNED], &sig) {
        return Err(Error::Signature);
    }
    Ok(h)
}

/// Check only that the header is a valid signature by `public` (not the content: for a record of
/// something already verified elsewhere, e.g. the kernel's .dsig the loader checked).
pub fn verify_header(d: &[u8], public: &[u8; 32]) -> Result<Header, Error> {
    let h = parse(d)?;
    if h.key_id != key_id(public) {
        return Err(Error::UnknownKey);
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&d[SIGNED..SIZE]);
    if !ed25519::verify(public, &d[..SIGNED], &sig) {
        return Err(Error::Signature);
    }
    Ok(h)
}

pub fn verify(d: &[u8], public: &[u8; 32], content: &[u8]) -> Result<Header, Error> {
    let mut s = Sha512::new();
    s.update(content);
    verify_hashed(d, public, content.len() as u64, &s.finish())
}

/// Make a `.dsig` for `content`.
pub fn sign(key: &SigningKey, kind: u32, name: &str, content: &[u8]) -> [u8; SIZE] {
    let mut d = [0u8; SIZE];
    d[0..4].copy_from_slice(MAGIC);
    d[4..6].copy_from_slice(&VERSION.to_le_bytes());
    d[6..8].copy_from_slice(&ALG_ED25519.to_le_bytes());
    d[8..12].copy_from_slice(&kind.to_le_bytes());
    d[16..32].copy_from_slice(&key_id(&key.public()));
    d[32..40].copy_from_slice(&(content.len() as u64).to_le_bytes());
    d[40..104].copy_from_slice(&sha512(content));
    let n = name.len().min(NAME_MAX - 1);
    d[104..104 + n].copy_from_slice(&name.as_bytes()[..n]);
    let sig = key.sign(&d[..SIGNED]);
    d[SIGNED..].copy_from_slice(&sig);
    d
}
