//! `.dapp` v1 signed application bundle format and `DRES` read-only resource pack codec.
//!
//! Layout of a `.dapp` file (all integers little-endian):
//! - Header (32 bytes): magic `DAPP`, version 1, flags 0, `entry_count` (1..=64), `toc_size`
//!   (`entry_count * 96`), `payload_size` (offset of trailing `.dsig`), reserved (8 bytes of 0).
//! - Table of contents (`entry_count * 96` bytes), strictly sorted by entry name ascending:
//!   `kind(4)`, `flags(4)`, `offset(8)`, `size(8)`, `sha256(32)`, `name(40, NUL-padded)`.
//! - Entry payloads packed sequentially on 8-byte boundaries (zero padding verified).
//! - Trailing 256-byte `.dsig` (`doscrypt::dsig::KIND_APP`) covering bytes `0..payload_size`.
//!
//! Required entries:
//! - Exactly one `ENTRY_MANIFEST` (`manifest.dman`)
//! - Exactly one `ENTRY_BINARY` (`<name>.dx`)
//! - Exactly one `ENTRY_BINARY_SIG` (`<name>.dx.dsig`, 256 bytes, `KIND_PROGRAM`)
//! - Zero or more `ENTRY_RESOURCE` entries (`res/...`)

use alloc::vec::Vec;

use doscrypt::dsig::{self, KIND_APP, KIND_PROGRAM};
use doscrypt::ed25519::SigningKey;
use doscrypt::sha2::sha256;

pub const BUNDLE_MAGIC: &[u8; 4] = b"DAPP";
pub const BUNDLE_VERSION: u16 = 1;
pub const BUNDLE_HEADER_LEN: usize = 32;
pub const TOC_ENTRY_LEN: usize = 96;
pub const MAX_ENTRIES: usize = 64;
pub const MAX_ENTRY_NAME: usize = 40;

pub const ENTRY_MANIFEST: u32 = 1;
pub const ENTRY_BINARY: u32 = 2;
pub const ENTRY_BINARY_SIG: u32 = 3;
pub const ENTRY_RESOURCE: u32 = 4;

const DRES_MAGIC: &[u8; 4] = b"DRES";
const DRES_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BundleError {
    TooShort,
    BadMagic,
    BadVersion,
    BadFlags,
    TooManyEntries,
    BadToc,
    BadName,
    UnsortedOrDuplicate,
    BadOffset,
    NonZeroPadding,
    HashMismatch,
    MissingRequired,
    DuplicateRequired,
    BadSignature,
    BadBinarySignature,
    BadManifest,
}

/// Input entry for `build_bundle`.
#[derive(Clone, Copy)]
pub struct BundleInput<'a> {
    pub kind: u32,
    pub name: &'a str,
    pub data: &'a [u8],
}

/// Validate a bundle entry path (ASCII printable, no leading/trailing `/`, no `..`, no NUL).
pub fn valid_entry_name(name: &str) -> bool {
    let b = name.as_bytes();
    if b.is_empty() || b.len() >= MAX_ENTRY_NAME {
        return false;
    }
    if b[0] == b'/' || b[b.len() - 1] == b'/' {
        return false;
    }
    if !b.iter().all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'/')) {
        return false;
    }
    for seg in name.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return false;
        }
    }
    true
}

fn align8(n: usize) -> usize {
    (n + 7) & !7
}

/// Deterministically build and sign a `.dapp` v1 bundle (`KIND_APP` trailing `.dsig`).
/// Entries are sorted by `name` ascending so builds are byte-for-byte reproducible.
pub fn build_bundle(key: &SigningKey, app_name: &str, inputs: &[BundleInput<'_>]) -> Result<Vec<u8>, BundleError> {
    if inputs.is_empty() || inputs.len() > MAX_ENTRIES {
        return Err(BundleError::TooManyEntries);
    }
    let mut sorted: Vec<BundleInput<'_>> = inputs.to_vec();
    sorted.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
    let (mut n_man, mut n_bin, mut n_sig) = (0usize, 0usize, 0usize);
    for (i, e) in sorted.iter().enumerate() {
        if !valid_entry_name(e.name) {
            return Err(BundleError::BadName);
        }
        if i > 0 && sorted[i - 1].name == e.name {
            return Err(BundleError::UnsortedOrDuplicate);
        }
        match e.kind {
            ENTRY_MANIFEST => n_man += 1,
            ENTRY_BINARY => n_bin += 1,
            ENTRY_BINARY_SIG => {
                if e.data.len() != dsig::SIZE {
                    return Err(BundleError::BadBinarySignature);
                }
                n_sig += 1;
            }
            ENTRY_RESOURCE => {}
            _ => return Err(BundleError::BadToc),
        }
    }
    if n_man != 1 || n_bin != 1 || n_sig != 1 {
        return Err(BundleError::MissingRequired);
    }

    let toc_size = sorted.len() * TOC_ENTRY_LEN;
    let mut cur = BUNDLE_HEADER_LEN + toc_size;
    let mut offsets = Vec::with_capacity(sorted.len());
    for e in &sorted {
        offsets.push(cur);
        cur = align8(cur + e.data.len());
    }
    let payload_size = cur;
    let mut out = Vec::with_capacity(payload_size + dsig::SIZE);

    // Header (32 bytes)
    out.extend_from_slice(BUNDLE_MAGIC);
    out.extend_from_slice(&BUNDLE_VERSION.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(sorted.len() as u32).to_le_bytes());
    out.extend_from_slice(&(toc_size as u32).to_le_bytes());
    out.extend_from_slice(&(payload_size as u64).to_le_bytes());
    out.extend_from_slice(&[0u8; 8]);

    // TOC entries
    for (e, &off) in sorted.iter().zip(offsets.iter()) {
        out.extend_from_slice(&e.kind.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(off as u64).to_le_bytes());
        out.extend_from_slice(&(e.data.len() as u64).to_le_bytes());
        out.extend_from_slice(&sha256(e.data));
        let mut name_buf = [0u8; MAX_ENTRY_NAME];
        name_buf[..e.name.len()].copy_from_slice(e.name.as_bytes());
        out.extend_from_slice(&name_buf);
    }

    // Payloads + zero padding
    for e in &sorted {
        out.extend_from_slice(e.data);
        let pad = align8(e.data.len()) - e.data.len();
        out.resize(out.len() + pad, 0);
    }
    debug_assert_eq!(out.len(), payload_size);

    let sig = dsig::sign(key, KIND_APP, app_name, &out);
    out.extend_from_slice(&sig);
    Ok(out)
}

#[derive(Clone, Copy, Debug)]
pub struct ParsedEntry<'a> {
    pub kind: u32,
    pub name: &'a str,
    pub data: &'a [u8],
    pub sha256: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct ParsedBundle<'a> {
    /// Bytes `0..payload_size`, covered by `bundle_dsig`.
    pub signed_payload: &'a [u8],
    /// Trailing 256-byte `.dsig` (`KIND_APP`).
    pub bundle_dsig: &'a [u8; dsig::SIZE],
    pub manifest: ParsedEntry<'a>,
    pub binary: ParsedEntry<'a>,
    pub binary_sig: ParsedEntry<'a>,
    pub resources: Vec<ParsedEntry<'a>>,
}

fn u16_le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32_le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn u64_le(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3], b[o + 4], b[o + 5], b[o + 6], b[o + 7]])
}

/// Parse and structurally verify a `.dapp` bundle (header, TOC bounds, strict sorting, zero
/// padding, SHA-256 of every entry, and presence of manifest/binary/binary-sig).
///
/// NOTE: On D-OS, `appmgr.dsvc` MUST also verify `signed_payload` against `bundle_dsig` via
/// kernel `vmo_verify` (`KIND_APP`) AND `binary` against `binary_sig` via kernel `vmo_verify`
/// (`KIND_PROGRAM`) before trusting or spawning the bundle!
pub fn parse_bundle(bytes: &[u8]) -> Result<ParsedBundle<'_>, BundleError> {
    if bytes.len() < BUNDLE_HEADER_LEN + dsig::SIZE {
        return Err(BundleError::TooShort);
    }
    if &bytes[0..4] != BUNDLE_MAGIC {
        return Err(BundleError::BadMagic);
    }
    if u16_le(bytes, 4) != BUNDLE_VERSION {
        return Err(BundleError::BadVersion);
    }
    if u16_le(bytes, 6) != 0 || bytes[24..32].iter().any(|&b| b != 0) {
        return Err(BundleError::BadFlags);
    }
    let count = u32_le(bytes, 8) as usize;
    let toc_size = u32_le(bytes, 12) as usize;
    let payload_size = usize::try_from(u64_le(bytes, 16)).map_err(|_| BundleError::BadOffset)?;
    if count == 0 || count > MAX_ENTRIES {
        return Err(BundleError::TooManyEntries);
    }
    if toc_size != count * TOC_ENTRY_LEN {
        return Err(BundleError::BadToc);
    }
    if payload_size.checked_add(dsig::SIZE) != Some(bytes.len()) {
        return Err(BundleError::BadOffset);
    }
    let data_start = BUNDLE_HEADER_LEN.checked_add(toc_size).ok_or(BundleError::BadToc)?;
    if data_start > payload_size {
        return Err(BundleError::BadToc);
    }

    let signed_payload = &bytes[..payload_size];
    let bundle_dsig: &[u8; dsig::SIZE] = bytes[payload_size..].try_into().map_err(|_| BundleError::BadSignature)?;

    let mut expected_off = data_start;
    let mut prev_name: Option<&str> = None;
    let mut manifest: Option<ParsedEntry<'_>> = None;
    let mut binary: Option<ParsedEntry<'_>> = None;
    let mut binary_sig: Option<ParsedEntry<'_>> = None;
    let mut resources = Vec::new();

    for i in 0..count {
        let eoff = BUNDLE_HEADER_LEN + i * TOC_ENTRY_LEN;
        let kind = u32_le(signed_payload, eoff);
        let flags = u32_le(signed_payload, eoff + 4);
        if flags != 0 {
            return Err(BundleError::BadFlags);
        }
        let off = usize::try_from(u64_le(signed_payload, eoff + 8)).map_err(|_| BundleError::BadOffset)?;
        let size = usize::try_from(u64_le(signed_payload, eoff + 16)).map_err(|_| BundleError::BadOffset)?;
        let mut want_hash = [0u8; 32];
        want_hash.copy_from_slice(&signed_payload[eoff + 24..eoff + 56]);
        let raw_name = &signed_payload[eoff + 56..eoff + 96];
        let nul = raw_name.iter().position(|&b| b == 0).ok_or(BundleError::BadName)?;
        if raw_name[nul..].iter().any(|&b| b != 0) {
            return Err(BundleError::BadName);
        }
        let name = core::str::from_utf8(&raw_name[..nul]).map_err(|_| BundleError::BadName)?;
        if !valid_entry_name(name) {
            return Err(BundleError::BadName);
        }
        if let Some(prev) = prev_name
            && prev.as_bytes() >= name.as_bytes()
        {
            return Err(BundleError::UnsortedOrDuplicate);
        }
        prev_name = Some(name);

        if off != expected_off {
            return Err(BundleError::BadOffset);
        }
        let end = off.checked_add(size).ok_or(BundleError::BadOffset)?;
        let padded_end = align8(end);
        if padded_end > payload_size {
            return Err(BundleError::BadOffset);
        }
        if signed_payload[end..padded_end].iter().any(|&b| b != 0) {
            return Err(BundleError::NonZeroPadding);
        }
        expected_off = padded_end;

        let data = &signed_payload[off..end];
        if sha256(data) != want_hash {
            return Err(BundleError::HashMismatch);
        }
        let entry = ParsedEntry { kind, name, data, sha256: want_hash };
        match kind {
            ENTRY_MANIFEST => {
                if manifest.is_some() {
                    return Err(BundleError::DuplicateRequired);
                }
                manifest = Some(entry);
            }
            ENTRY_BINARY => {
                if binary.is_some() {
                    return Err(BundleError::DuplicateRequired);
                }
                binary = Some(entry);
            }
            ENTRY_BINARY_SIG => {
                if binary_sig.is_some() {
                    return Err(BundleError::DuplicateRequired);
                }
                if data.len() != dsig::SIZE {
                    return Err(BundleError::BadBinarySignature);
                }
                binary_sig = Some(entry);
            }
            ENTRY_RESOURCE => resources.push(entry),
            _ => return Err(BundleError::BadToc),
        }
    }

    if expected_off != payload_size {
        return Err(BundleError::BadOffset);
    }

    let (Some(manifest), Some(binary), Some(binary_sig)) = (manifest, binary, binary_sig) else {
        return Err(BundleError::MissingRequired);
    };

    Ok(ParsedBundle { signed_payload, bundle_dsig, manifest, binary, binary_sig, resources })
}

/// Full offline cryptographic + structural verification against `public_key` (checks both the
/// outer `KIND_APP` bundle signature and the inner `KIND_PROGRAM` binary signature).
pub fn verify_bundle_with_key<'a>(bytes: &'a [u8], public_key: &[u8; 32]) -> Result<ParsedBundle<'a>, BundleError> {
    let b = parse_bundle(bytes)?;
    let hdr = dsig::verify(b.bundle_dsig, public_key, b.signed_payload).map_err(|_| BundleError::BadSignature)?;
    if hdr.kind != KIND_APP {
        return Err(BundleError::BadSignature);
    }
    let bhdr = dsig::verify(b.binary_sig.data, public_key, b.binary.data).map_err(|_| BundleError::BadBinarySignature)?;
    if bhdr.kind != KIND_PROGRAM {
        return Err(BundleError::BadBinarySignature);
    }
    let m = crate::manifest::parse_manifest(b.manifest.data).map_err(|_| BundleError::BadManifest)?;
    if m.binary != b.binary.name {
        return Err(BundleError::BadManifest);
    }
    Ok(b)
}

/// Compact read-only resource pack (`DRES`) passed to spawned apps via `TAG_APP_RESOURCES` VMO.
pub struct ResourcePack;

impl ResourcePack {
    /// Pack resource entries into a `DRES` v1 byte buffer.
    pub fn build(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let count = entries.len().min(MAX_ENTRIES);
        let mut out = Vec::new();
        out.extend_from_slice(DRES_MAGIC);
        out.extend_from_slice(&DRES_VERSION.to_le_bytes());
        out.extend_from_slice(&(count as u16).to_le_bytes());
        let mut off = 8 + count * 48;
        for &(name, data) in entries.iter().take(count) {
            let mut nb = [0u8; 40];
            let l = name.len().min(39);
            nb[..l].copy_from_slice(&name.as_bytes()[..l]);
            out.extend_from_slice(&nb);
            out.extend_from_slice(&(off as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            off += data.len();
        }
        for &(_, data) in entries.iter().take(count) {
            out.extend_from_slice(data);
        }
        out
    }

    /// Look up resource `name` inside a read-only `DRES` buffer (zero panics on untrusted bytes).
    pub fn get<'a>(blob: &'a [u8], name: &str) -> Option<&'a [u8]> {
        if blob.len() < 8 || &blob[0..4] != DRES_MAGIC || u16_le(blob, 4) != DRES_VERSION {
            return None;
        }
        let count = usize::from(u16_le(blob, 6));
        let toc_end = 8usize.checked_add(count.checked_mul(48)?)?;
        if toc_end > blob.len() {
            return None;
        }
        for i in 0..count {
            let o = 8 + i * 48;
            let raw = &blob[o..o + 40];
            let nul = raw.iter().position(|&b| b == 0).unwrap_or(40);
            if core::str::from_utf8(&raw[..nul]).ok() == Some(name) {
                let start = u32_le(blob, o + 40) as usize;
                let len = u32_le(blob, o + 44) as usize;
                let end = start.checked_add(len)?;
                if start >= toc_end && end <= blob.len() {
                    return Some(&blob[start..end]);
                }
                return None;
            }
        }
        None
    }
}
