//! Strict in-tree SSH-2 client (RFC 4251/4252/4253/4254/5647/5656/8332/8709/8731) over `doscrypt`.
//!
//! - **Key Exchange**: `curve25519-sha256` / `curve25519-sha256@libssh.org` with constant-time
//!   X25519 (`doscrypt::x25519`, rejecting low-order all-zero points) and strict KEX
//!   (`kex-strict-c-v00@openssh.com` / `kex-strict-s-v00@openssh.com`).
//! - **Host Key Verification**: `ssh-ed25519`, `ecdsa-sha2-nistp256`, `rsa-sha2-256`, and
//!   `rsa-sha2-512`, with SHA-256 fingerprint exposure (`SHA256:<base64>`) before any credentials
//!   are transmitted.
//! - **AEAD Transport**: `aes256-gcm@openssh.com` and `aes128-gcm@openssh.com` (RFC 5647),
//!   zero-table constant-time AES-GCM, strict length bounds, and automatic key zeroization on
//!   `Drop`.
//! - **Authentication**: `publickey` (`ssh-ed25519`), `password`, automatic `keyboard-interactive`
//!   single-prompt password fallback, and `none`.
//! - **Connection Protocol**: `session` channel with `exec` or `pty-req` + `shell`, stdout/stderr
//!   demux, flow-control window management, and exit-status reporting.
//! - **Sans-IO**: zero platform calls and `#![forbid(unsafe_code)]`.

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use doscrypt::aes_gcm::{
    aes128_gcm_open_in_place, aes128_gcm_seal_in_place, aes256_gcm_open_in_place,
    aes256_gcm_seal_in_place,
};
use doscrypt::ct::wipe_bytes;
use doscrypt::ed25519::{self, SigningKey};
use doscrypt::p256;
use doscrypt::rsa::{self, Hash as RsaHash};
use doscrypt::sha2::{Sha256, sha256};
use doscrypt::x25519;

pub const CLIENT_BANNER: &str = "SSH-2.0-DiscreteOS_1.0";

const MAX_BANNER_LEN: usize = 255;
const MAX_PRE_BANNER_LINES: usize = 32;
const MAX_PACKET_LEN: usize = 256 * 1024;
const INITIAL_LOCAL_WINDOW: u32 = 256 * 1024;
const MAX_LOCAL_PACKET: u32 = 32 * 1024;

// SSH message numbers (RFC 4250..4254)
const MSG_DISCONNECT: u8 = 1;
const MSG_IGNORE: u8 = 2;
const MSG_UNIMPLEMENTED: u8 = 3;
const MSG_DEBUG: u8 = 4;
const MSG_SERVICE_REQUEST: u8 = 5;
const MSG_SERVICE_ACCEPT: u8 = 6;
const MSG_EXT_INFO: u8 = 7;
const MSG_KEXINIT: u8 = 20;
const MSG_NEWKEYS: u8 = 21;
const MSG_KEX_ECDH_INIT: u8 = 30;
const MSG_KEX_ECDH_REPLY: u8 = 31;
const MSG_USERAUTH_REQUEST: u8 = 50;
const MSG_USERAUTH_FAILURE: u8 = 51;
const MSG_USERAUTH_SUCCESS: u8 = 52;
const MSG_USERAUTH_BANNER: u8 = 53;
const MSG_USERAUTH_INFO_REQUEST: u8 = 60;
const MSG_USERAUTH_INFO_RESPONSE: u8 = 61;
const MSG_GLOBAL_REQUEST: u8 = 80;
const MSG_REQUEST_FAILURE: u8 = 82;
const MSG_CHANNEL_OPEN: u8 = 90;
const MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
const MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
const MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
const MSG_CHANNEL_DATA: u8 = 94;
const MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
const MSG_CHANNEL_EOF: u8 = 96;
const MSG_CHANNEL_CLOSE: u8 = 97;
const MSG_CHANNEL_REQUEST: u8 = 98;
const MSG_CHANNEL_SUCCESS: u8 = 99;
const MSG_CHANNEL_FAILURE: u8 = 100;

const KEX_STRICT_SERVER: &str = "kex-strict-s-v00@openssh.com";

const CLIENT_KEX_ALGS: &str =
    "curve25519-sha256,curve25519-sha256@libssh.org,kex-strict-c-v00@openssh.com";
const CLIENT_HOST_KEY_ALGS: &str = "ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-256,rsa-sha2-512";
const CLIENT_CIPHERS: &str = "aes256-gcm@openssh.com,aes128-gcm@openssh.com";
const CLIENT_MACS: &str = "hmac-sha2-256";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cipher {
    Aes256Gcm,
    Aes128Gcm,
}

impl Cipher {
    pub fn name(self) -> &'static str {
        match self {
            Self::Aes256Gcm => "aes256-gcm@openssh.com",
            Self::Aes128Gcm => "aes128-gcm@openssh.com",
        }
    }

    fn key_len(self) -> usize {
        match self {
            Self::Aes256Gcm => 32,
            Self::Aes128Gcm => 16,
        }
    }

    fn from_name(s: &str) -> Option<Self> {
        match s {
            "aes256-gcm@openssh.com" => Some(Self::Aes256Gcm),
            "aes128-gcm@openssh.com" => Some(Self::Aes128Gcm),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostKeyAlg {
    Ed25519,
    EcdsaP256,
    RsaSha256,
    RsaSha512,
}

impl HostKeyAlg {
    pub fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => "ssh-ed25519",
            Self::EcdsaP256 => "ecdsa-sha2-nistp256",
            Self::RsaSha256 => "rsa-sha2-256",
            Self::RsaSha512 => "rsa-sha2-512",
        }
    }

    fn from_name(s: &str) -> Option<Self> {
        match s {
            "ssh-ed25519" => Some(Self::Ed25519),
            "ecdsa-sha2-nistp256" => Some(Self::EcdsaP256),
            "rsa-sha2-256" => Some(Self::RsaSha256),
            "rsa-sha2-512" => Some(Self::RsaSha512),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SshError {
    BadBanner,
    AlgorithmMismatch(&'static str),
    ProtocolViolation(&'static str),
    BadHostKey,
    BadHostSignature,
    HostKeyRejected,
    DecryptFailed,
    LowOrderKey,
    AuthFailed(String),
    ChannelOpenFailed(String),
    ChannelRequestFailed,
    Disconnected(u32, String),
    InvalidState,
}

/// Client lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Banner,
    KexInit,
    KexReply,
    NewKeys,
    /// KEX & host-key signature verified; waiting for caller to check host key fingerprint and
    /// call [`SshClient::accept_host_key`] (or disconnect).
    VerifyHostKey,
    ServiceRequest,
    /// Ready for caller to start authentication via [`SshClient::authenticate`].
    AuthReady,
    Authenticating,
    /// Authenticated; caller may open a session channel via [`SshClient::open_session`].
    Authenticated,
    OpeningChannel,
    /// Channel open; caller may call [`SshClient::request_exec`] or [`SshClient::request_shell`].
    ChannelReady,
    RequestingExec,
    RequestingPty,
    RequestingShell,
    /// Session active (streaming stdout/stderr and accepting stdin).
    Active,
    Closed,
}

/// Authentication method for [`SshClient::authenticate`].
pub enum AuthMethod {
    None,
    Password(Vec<u8>),
    PublicKeyEd25519([u8; 32]),
}

impl Drop for AuthMethod {
    fn drop(&mut self) {
        match self {
            Self::None => {}
            Self::Password(p) => wipe_bytes(p),
            Self::PublicKeyEd25519(s) => wipe_bytes(s),
        }
    }
}

/// Output chunk or status event emitted during an active session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Banner(String),
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    ExitStatus(u32),
    Eof,
    Closed,
}

/// Negotiated session parameters once KEX completes.
#[derive(Clone, Debug)]
pub struct HostKeyInfo {
    pub server_banner: String,
    pub kex_alg: String,
    pub host_key_alg: HostKeyAlg,
    pub cipher_c2s: Cipher,
    pub cipher_s2c: Cipher,
    pub host_key_blob: Vec<u8>,
    pub fingerprint: String,
}

// ---- Wire encoding / decoding helpers (RFC 4251) -----------------------------------------------

struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }

    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    fn bool(&mut self, v: bool) {
        self.buf.push(u8::from(v));
    }

    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    fn raw(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    fn bytes(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.buf.extend_from_slice(b);
    }

    fn str(&mut self, s: &str) {
        self.bytes(s.as_bytes());
    }

    /// Encode a non-negative big-endian integer as SSH `mpint` (RFC 4251 §5).
    fn mpint_unsigned(&mut self, b: &[u8]) {
        let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
        let sig = &b[start..];
        if sig.is_empty() {
            self.u32(0);
            return;
        }
        if (sig[0] & 0x80) != 0 {
            self.u32((sig.len() + 1) as u32);
            self.buf.push(0);
            self.buf.extend_from_slice(sig);
        } else {
            self.bytes(sig);
        }
    }

    fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn bool(&mut self) -> Option<bool> {
        Some(self.u8()? != 0)
    }

    fn u32(&mut self) -> Option<u32> {
        if self.remaining() < 4 {
            return None;
        }
        let v = u32::from_be_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Some(v)
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n {
            return None;
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }

    fn bytes(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    fn str(&mut self) -> Option<&'a str> {
        core::str::from_utf8(self.bytes()?).ok()
    }
}

/// Standard Base64 encoding (optional padding).
pub fn base64_encode(input: &[u8], pad: bool) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i];
        let b1 = if i + 1 < input.len() { input[i + 1] } else { 0 };
        let b2 = if i + 2 < input.len() { input[i + 2] } else { 0 };
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
        if i + 1 < input.len() {
            out.push(TABLE[((n >> 6) & 0x3F) as usize] as char);
        } else if pad {
            out.push('=');
        }
        if i + 2 < input.len() {
            out.push(TABLE[(n & 0x3F) as usize] as char);
        } else if pad {
            out.push('=');
        }
        i += 3;
    }
    out
}

/// Compute OpenSSH-compatible `SHA256:<base64-no-pad>` host key fingerprint.
pub fn host_key_fingerprint(blob: &[u8]) -> String {
    let digest = sha256(blob);
    format!("SHA256:{}", base64_encode(&digest, false))
}

/// Format an Ed25519 public key (32 bytes) as an SSH wire public-key blob.
pub fn encode_ed25519_pubkey_blob(pub_key: &[u8; 32]) -> Vec<u8> {
    let mut w = Writer::new();
    w.str("ssh-ed25519");
    w.bytes(pub_key);
    w.into_vec()
}

/// Derive the 32-byte Ed25519 public key from a 32-byte private seed.
pub fn ed25519_public_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_seed(seed).public()
}

/// Format an Ed25519 public key as an OpenSSH `authorized_keys` line (`ssh-ed25519 <base64> <comment>`).
pub fn format_ed25519_authorized_key(pub_key: &[u8; 32], comment: &str) -> String {
    let blob = encode_ed25519_pubkey_blob(pub_key);
    format!("ssh-ed25519 {} {}", base64_encode(&blob, true), comment)
}

fn first_match<'a>(client_list: &'a str, server_list: &str) -> Option<&'a str> {
    for c in client_list.split(',') {
        if c.is_empty() {
            continue;
        }
        if server_list.split(',').any(|s| s == c) {
            return Some(c);
        }
    }
    None
}

fn list_contains(list: &str, needle: &str) -> bool {
    list.split(',').any(|s| s == needle)
}

// ---- AEAD cipher state (RFC 5647) --------------------------------------------------------------

struct AeadState {
    cipher: Cipher,
    key: [u8; 32],
    fixed_iv: [u8; 4],
    counter: u64,
}

impl AeadState {
    fn new(cipher: Cipher, key_bytes: &[u8], iv_bytes: &[u8]) -> Self {
        let mut key = [0u8; 32];
        key[..cipher.key_len()].copy_from_slice(&key_bytes[..cipher.key_len()]);
        let mut fixed_iv = [0u8; 4];
        fixed_iv.copy_from_slice(&iv_bytes[..4]);
        let counter = u64::from_be_bytes([
            iv_bytes[4],
            iv_bytes[5],
            iv_bytes[6],
            iv_bytes[7],
            iv_bytes[8],
            iv_bytes[9],
            iv_bytes[10],
            iv_bytes[11],
        ]);
        Self { cipher, key, fixed_iv, counter }
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.fixed_iv);
        nonce[4..12].copy_from_slice(&self.counter.to_be_bytes());
        self.counter = self.counter.wrapping_add(1);
        nonce
    }

    fn seal(&mut self, aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        let nonce = self.next_nonce();
        match self.cipher {
            Cipher::Aes256Gcm => aes256_gcm_seal_in_place(&self.key, &nonce, aad, buf),
            Cipher::Aes128Gcm => {
                let mut k16 = [0u8; 16];
                k16.copy_from_slice(&self.key[..16]);
                let tag = aes128_gcm_seal_in_place(&k16, &nonce, aad, buf);
                wipe_bytes(&mut k16);
                tag
            }
        }
    }

    fn open(&mut self, aad: &[u8], buf: &mut [u8], tag: &[u8; 16]) -> bool {
        let nonce = self.next_nonce();
        match self.cipher {
            Cipher::Aes256Gcm => aes256_gcm_open_in_place(&self.key, &nonce, aad, buf, tag),
            Cipher::Aes128Gcm => {
                let mut k16 = [0u8; 16];
                k16.copy_from_slice(&self.key[..16]);
                let ok = aes128_gcm_open_in_place(&k16, &nonce, aad, buf, tag);
                wipe_bytes(&mut k16);
                ok
            }
        }
    }
}

impl Drop for AeadState {
    fn drop(&mut self) {
        wipe_bytes(&mut self.key);
        wipe_bytes(&mut self.fixed_iv);
        self.counter = 0;
    }
}

/// Derive a key/IV block of `len <= 32` bytes per RFC 4253 §7.2 using SHA-256.
fn derive_key_sha256(k_mpint: &[u8], h: &[u8; 32], letter: u8, session_id: &[u8; 32]) -> [u8; 32] {
    let mut sha = Sha256::new();
    sha.update(k_mpint);
    sha.update(h);
    sha.update(&[letter]);
    sha.update(session_id);
    sha.finish()
}

#[allow(clippy::too_many_arguments)]
fn compute_exchange_hash(
    v_c: &[u8],
    v_s: &[u8],
    i_c: &[u8],
    i_s: &[u8],
    k_s: &[u8],
    q_c: &[u8; 32],
    q_s: &[u8; 32],
    k_mpint: &[u8],
) -> [u8; 32] {
    let mut w = Writer::new();
    w.bytes(v_c);
    w.bytes(v_s);
    w.bytes(i_c);
    w.bytes(i_s);
    w.bytes(k_s);
    w.bytes(q_c);
    w.bytes(q_s);
    w.raw(k_mpint);
    sha256(&w.into_vec())
}

/// Verify server host key signature over exchange hash `h`.
fn verify_host_signature(
    expected_alg: HostKeyAlg,
    host_key_blob: &[u8],
    sig_blob: &[u8],
    h: &[u8; 32],
) -> Result<(), SshError> {
    let mut kr = Reader::new(host_key_blob);
    let key_type = kr.str().ok_or(SshError::BadHostKey)?;
    let mut sr = Reader::new(sig_blob);
    let sig_type = sr.str().ok_or(SshError::BadHostSignature)?;
    let sig_data = sr.bytes().ok_or(SshError::BadHostSignature)?;
    if sr.remaining() != 0 {
        return Err(SshError::BadHostSignature);
    }
    if sig_type != expected_alg.name() {
        return Err(SshError::BadHostSignature);
    }

    match expected_alg {
        HostKeyAlg::Ed25519 => {
            if key_type != "ssh-ed25519" {
                return Err(SshError::BadHostKey);
            }
            let pk_bytes = kr.bytes().ok_or(SshError::BadHostKey)?;
            if pk_bytes.len() != 32 || kr.remaining() != 0 {
                return Err(SshError::BadHostKey);
            }
            if sig_data.len() != 64 {
                return Err(SshError::BadHostSignature);
            }
            let pk: [u8; 32] = pk_bytes.try_into().map_err(|_| SshError::BadHostKey)?;
            let sig: [u8; 64] = sig_data.try_into().map_err(|_| SshError::BadHostSignature)?;
            if !ed25519::verify(&pk, h, &sig) {
                return Err(SshError::BadHostSignature);
            }
            Ok(())
        }
        HostKeyAlg::EcdsaP256 => {
            if key_type != "ecdsa-sha2-nistp256" {
                return Err(SshError::BadHostKey);
            }
            let curve = kr.str().ok_or(SshError::BadHostKey)?;
            let point = kr.bytes().ok_or(SshError::BadHostKey)?;
            if curve != "nistp256" || kr.remaining() != 0 {
                return Err(SshError::BadHostKey);
            }
            let pk = p256::PublicKey::from_sec1(point).ok_or(SshError::BadHostKey)?;
            let mut inner = Reader::new(sig_data);
            let r_mp = inner.bytes().ok_or(SshError::BadHostSignature)?;
            let s_mp = inner.bytes().ok_or(SshError::BadHostSignature)?;
            if inner.remaining() != 0 {
                return Err(SshError::BadHostSignature);
            }
            let mut sig64 = [0u8; 64];
            mpint_to_fixed_be(r_mp, &mut sig64[..32]).ok_or(SshError::BadHostSignature)?;
            mpint_to_fixed_be(s_mp, &mut sig64[32..]).ok_or(SshError::BadHostSignature)?;
            if !p256::verify(&pk, h, &sig64) {
                return Err(SshError::BadHostSignature);
            }
            Ok(())
        }
        HostKeyAlg::RsaSha256 | HostKeyAlg::RsaSha512 => {
            if key_type != "ssh-rsa" {
                return Err(SshError::BadHostKey);
            }
            let e_bytes = kr.bytes().ok_or(SshError::BadHostKey)?;
            let n_bytes = kr.bytes().ok_or(SshError::BadHostKey)?;
            if kr.remaining() != 0 {
                return Err(SshError::BadHostKey);
            }
            let e_trimmed = trim_mpint_leading_zero(e_bytes);
            if e_trimmed.is_empty() || e_trimmed.len() > 4 {
                return Err(SshError::BadHostKey);
            }
            let mut e_val = 0u32;
            for &b in e_trimmed {
                e_val = (e_val << 8) | u32::from(b);
            }
            let pk = rsa::PublicKey::new(n_bytes, e_val).ok_or(SshError::BadHostKey)?;
            if pk.bits() < 2048 {
                return Err(SshError::BadHostKey);
            }
            let k = pk.size();
            if sig_data.is_empty() || sig_data.len() > k {
                return Err(SshError::BadHostSignature);
            }
            let mut padded = vec![0u8; k];
            padded[k - sig_data.len()..].copy_from_slice(sig_data);
            let hash = if expected_alg == HostKeyAlg::RsaSha512 {
                RsaHash::Sha512
            } else {
                RsaHash::Sha256
            };
            if !rsa::verify_pkcs1(&pk, hash, h, &padded) {
                return Err(SshError::BadHostSignature);
            }
            Ok(())
        }
    }
}

fn trim_mpint_leading_zero(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[start..]
}

fn mpint_to_fixed_be(mp: &[u8], out: &mut [u8]) -> Option<()> {
    let sig = trim_mpint_leading_zero(mp);
    if sig.len() > out.len() {
        return None;
    }
    out.fill(0);
    let start = out.len() - sig.len();
    out[start..].copy_from_slice(sig);
    Some(())
}

// ---- Packet codec shared between client & test server ------------------------------------------

fn encode_packet(
    payload: &[u8],
    tx_aead: &mut Option<AeadState>,
    pad_seed: &mut u64,
    out: &mut Vec<u8>,
) {
    let mut next_pad = || -> u8 {
        *pad_seed = pad_seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (*pad_seed >> 56) as u8
    };
    if let Some(aead) = tx_aead.as_mut() {
        // RFC 5647 §7.2: `packet_length` (= 1 + payload.len() + pad_len) MUST be a multiple of 16.
        let min_len = 1 + payload.len() + 4;
        let rem = min_len % 16;
        let pad_len = 4 + if rem == 0 { 0 } else { 16 - rem };
        let pkt_len = (1 + payload.len() + pad_len) as u32;
        let len_be = pkt_len.to_be_bytes();
        let mut body = Vec::with_capacity(pkt_len as usize);
        body.push(pad_len as u8);
        body.extend_from_slice(payload);
        for _ in 0..pad_len {
            body.push(next_pad());
        }
        let tag = aead.seal(&len_be, &mut body);
        out.extend_from_slice(&len_be);
        out.extend_from_slice(&body);
        out.extend_from_slice(&tag);
    } else {
        // RFC 4253 §6: `4 + packet_length` must be a multiple of 8, min 16, pad_len >= 4.
        let min_total = 4 + 1 + payload.len() + 4;
        let rem = min_total % 8;
        let pad_len = 4 + if rem == 0 { 0 } else { 8 - rem };
        let pkt_len = (1 + payload.len() + pad_len) as u32;
        out.extend_from_slice(&pkt_len.to_be_bytes());
        out.push(pad_len as u8);
        out.extend_from_slice(payload);
        for _ in 0..pad_len {
            out.push(next_pad());
        }
    }
}

fn try_decode_packet(
    rx_buf: &mut Vec<u8>,
    rx_aead: &mut Option<AeadState>,
) -> Result<Option<Vec<u8>>, SshError> {
    if rx_buf.len() < 4 {
        return Ok(None);
    }
    let len_be = [rx_buf[0], rx_buf[1], rx_buf[2], rx_buf[3]];
    let pkt_len = u32::from_be_bytes(len_be) as usize;
    if !(12..=MAX_PACKET_LEN).contains(&pkt_len) {
        return Err(SshError::ProtocolViolation("invalid packet length"));
    }

    if let Some(aead) = rx_aead.as_mut() {
        if pkt_len < 16 || !pkt_len.is_multiple_of(16) {
            return Err(SshError::ProtocolViolation("unaligned AEAD packet length"));
        }
        let total = 4 + pkt_len + 16;
        if rx_buf.len() < total {
            return Ok(None);
        }
        let mut body = rx_buf[4..4 + pkt_len].to_vec();
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&rx_buf[4 + pkt_len..total]);
        rx_buf.drain(..total);
        if !aead.open(&len_be, &mut body, &tag) {
            return Err(SshError::DecryptFailed);
        }
        let pad_len = body[0] as usize;
        if pad_len < 4 || 1 + pad_len > pkt_len {
            return Err(SshError::ProtocolViolation("invalid padding length"));
        }
        let payload = body[1..pkt_len - pad_len].to_vec();
        wipe_bytes(&mut body);
        Ok(Some(payload))
    } else {
        if !(4 + pkt_len).is_multiple_of(8) {
            return Err(SshError::ProtocolViolation("unaligned plaintext packet"));
        }
        let total = 4 + pkt_len;
        if rx_buf.len() < total {
            return Ok(None);
        }
        let pad_len = rx_buf[4] as usize;
        if pad_len < 4 || 1 + pad_len > pkt_len {
            return Err(SshError::ProtocolViolation("invalid plaintext padding"));
        }
        let payload = rx_buf[5..4 + pkt_len - pad_len].to_vec();
        rx_buf.drain(..total);
        Ok(Some(payload))
    }
}

// ---- SSH-2 Client ------------------------------------------------------------------------------

pub struct SshClient {
    state: State,
    rx_buf: Vec<u8>,
    tx_buf: Vec<u8>,
    pre_banner_lines: usize,
    server_banner: String,
    client_kexinit: Vec<u8>,
    server_kexinit: Vec<u8>,
    ephemeral_priv: [u8; 32],
    ephemeral_pub: [u8; 32],
    pad_seed: u64,
    strict_kex: bool,
    kex_alg: String,
    host_key_alg: Option<HostKeyAlg>,
    cipher_c2s: Option<Cipher>,
    cipher_s2c: Option<Cipher>,
    session_id: [u8; 32],
    pending_tx_aead: Option<AeadState>,
    pending_rx_aead: Option<AeadState>,
    tx_aead: Option<AeadState>,
    rx_aead: Option<AeadState>,
    host_info: Option<HostKeyInfo>,
    // Authentication state
    username: String,
    auth_password: Vec<u8>,
    tried_kb_interactive: bool,
    // Channel state
    remote_channel: u32,
    local_window: u32,
    remote_window: u32,
    remote_max_packet: u32,
    pending_stdin: VecDeque<u8>,
    events: VecDeque<Event>,
    // Pending shell request params
    pending_pty_cols: u32,
    pending_pty_rows: u32,
}

impl SshClient {
    /// Start a new SSH-2 client handshake. `rand64` must come from a CSPRNG.
    pub fn new(rand64: &[u8; 64]) -> Self {
        let mut ephemeral_priv = [0u8; 32];
        ephemeral_priv.copy_from_slice(&rand64[..32]);
        let ephemeral_pub = x25519::public_key(&ephemeral_priv);
        let mut cookie = [0u8; 16];
        cookie.copy_from_slice(&rand64[32..48]);
        let pad_seed = u64::from_le_bytes([
            rand64[48], rand64[49], rand64[50], rand64[51], rand64[52], rand64[53], rand64[54],
            rand64[55],
        ]);

        let mut tx_buf = Vec::with_capacity(512);
        tx_buf.extend_from_slice(CLIENT_BANNER.as_bytes());
        tx_buf.extend_from_slice(b"\r\n");

        let client_kexinit = build_kexinit(&cookie, CLIENT_KEX_ALGS, CLIENT_HOST_KEY_ALGS);
        let mut s = Self {
            state: State::Banner,
            rx_buf: Vec::new(),
            tx_buf,
            pre_banner_lines: 0,
            server_banner: String::new(),
            client_kexinit,
            server_kexinit: Vec::new(),
            ephemeral_priv,
            ephemeral_pub,
            pad_seed,
            strict_kex: false,
            kex_alg: String::new(),
            host_key_alg: None,
            cipher_c2s: None,
            cipher_s2c: None,
            session_id: [0u8; 32],
            pending_tx_aead: None,
            pending_rx_aead: None,
            tx_aead: None,
            rx_aead: None,
            host_info: None,
            username: String::new(),
            auth_password: Vec::new(),
            tried_kb_interactive: false,
            remote_channel: 0,
            local_window: INITIAL_LOCAL_WINDOW,
            remote_window: 0,
            remote_max_packet: 32768,
            pending_stdin: VecDeque::new(),
            events: VecDeque::new(),
            pending_pty_cols: 80,
            pending_pty_rows: 24,
        };
        // Send client KEXINIT immediately after banner (saves 1 RTT, standard in OpenSSH).
        let kex_copy = s.client_kexinit.clone();
        s.send_packet(&kex_copy);
        s
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn host_key_info(&self) -> Option<&HostKeyInfo> {
        self.host_info.as_ref()
    }

    pub fn take_tx(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.tx_buf)
    }

    pub fn pop_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    fn send_packet(&mut self, payload: &[u8]) {
        encode_packet(payload, &mut self.tx_aead, &mut self.pad_seed, &mut self.tx_buf);
    }

    /// Feed raw bytes received from the TCP socket into the SSH state machine.
    pub fn feed_rx(&mut self, data: &[u8]) -> Result<(), SshError> {
        if self.state == State::Closed {
            return Ok(());
        }
        self.rx_buf.extend_from_slice(data);

        if self.state == State::Banner {
            self.process_banner()?;
        }
        if self.state == State::Banner {
            return Ok(());
        }

        while let Some(pkt) = try_decode_packet(&mut self.rx_buf, &mut self.rx_aead)? {
            self.handle_packet(&pkt)?;
            if self.state == State::Closed || self.state == State::VerifyHostKey {
                break;
            }
        }
        Ok(())
    }

    fn process_banner(&mut self) -> Result<(), SshError> {
        loop {
            let Some(lf) = self.rx_buf.iter().position(|&b| b == b'\n') else {
                if self.rx_buf.len() > MAX_BANNER_LEN {
                    return Err(SshError::BadBanner);
                }
                return Ok(());
            };
            if lf > MAX_BANNER_LEN {
                return Err(SshError::BadBanner);
            }
            let line_end = if lf > 0 && self.rx_buf[lf - 1] == b'\r' { lf - 1 } else { lf };
            let line = core::str::from_utf8(&self.rx_buf[..line_end])
                .map_err(|_| SshError::BadBanner)?;
            if line.starts_with("SSH-2.0-") {
                self.server_banner = String::from(line);
                self.rx_buf.drain(..=lf);
                self.state = State::KexInit;
                return Ok(());
            } else if line.starts_with("SSH-") {
                // Refuse SSH-1.x
                return Err(SshError::BadBanner);
            }
            self.rx_buf.drain(..=lf);
            self.pre_banner_lines += 1;
            if self.pre_banner_lines > MAX_PRE_BANNER_LINES {
                return Err(SshError::BadBanner);
            }
        }
    }

    fn handle_packet(&mut self, pkt: &[u8]) -> Result<(), SshError> {
        if pkt.is_empty() {
            return Err(SshError::ProtocolViolation("empty packet"));
        }
        let msg = pkt[0];

        // Global transport messages
        match msg {
            MSG_DISCONNECT => {
                let mut r = Reader::new(&pkt[1..]);
                let code = r.u32().unwrap_or(0);
                let desc = r.str().unwrap_or("").into();
                self.state = State::Closed;
                self.events.push_back(Event::Closed);
                return Err(SshError::Disconnected(code, desc));
            }
            MSG_IGNORE | MSG_DEBUG | MSG_UNIMPLEMENTED => {
                // Strict KEX forbids extraneous messages before initial NEWKEYS.
                if self.strict_kex
                    && matches!(self.state, State::KexInit | State::KexReply | State::NewKeys)
                {
                    return Err(SshError::ProtocolViolation("unexpected message during strict KEX"));
                }
                return Ok(());
            }
            MSG_EXT_INFO => {
                return Ok(());
            }
            MSG_GLOBAL_REQUEST => {
                let mut r = Reader::new(&pkt[1..]);
                let _name = r.str();
                if r.bool() == Some(true) {
                    self.send_packet(&[MSG_REQUEST_FAILURE]);
                }
                return Ok(());
            }
            _ => {}
        }

        match self.state {
            State::KexInit => {
                if msg != MSG_KEXINIT {
                    return Err(SshError::ProtocolViolation("expected KEXINIT"));
                }
                self.handle_kexinit(pkt)?;
            }
            State::KexReply => {
                if msg != MSG_KEX_ECDH_REPLY {
                    return Err(SshError::ProtocolViolation("expected KEX_ECDH_REPLY"));
                }
                self.handle_kex_reply(&pkt[1..])?;
            }
            State::NewKeys => {
                if msg != MSG_NEWKEYS {
                    return Err(SshError::ProtocolViolation("expected NEWKEYS"));
                }
                self.rx_aead = self.pending_rx_aead.take();
                self.state = State::VerifyHostKey;
            }
            State::VerifyHostKey => {
                // Caller must accept or reject the host key before proceeding.
                return Err(SshError::InvalidState);
            }
            State::ServiceRequest => {
                if msg != MSG_SERVICE_ACCEPT {
                    return Err(SshError::ProtocolViolation("expected SERVICE_ACCEPT"));
                }
                self.state = State::AuthReady;
            }
            State::Authenticating => match msg {
                MSG_USERAUTH_BANNER => {
                    let mut r = Reader::new(&pkt[1..]);
                    if let Some(text) = r.str() {
                        self.events.push_back(Event::Banner(String::from(text)));
                    }
                }
                MSG_USERAUTH_SUCCESS => {
                    wipe_bytes(&mut self.auth_password);
                    self.auth_password.clear();
                    self.state = State::Authenticated;
                }
                MSG_USERAUTH_INFO_REQUEST => {
                    // Keyboard-interactive challenge: answer single-prompt challenge with password.
                    let mut r = Reader::new(&pkt[1..]);
                    let _name = r.str();
                    let _instr = r.str();
                    let _lang = r.str();
                    let num = r.u32().unwrap_or(0);
                    let mut w = Writer::new();
                    w.u8(MSG_USERAUTH_INFO_RESPONSE);
                    w.u32(num);
                    for i in 0..num {
                        if i == 0 {
                            w.bytes(&self.auth_password);
                        } else {
                            w.bytes(b"");
                        }
                    }
                    let resp = w.into_vec();
                    self.send_packet(&resp);
                }
                MSG_USERAUTH_FAILURE => {
                    let mut r = Reader::new(&pkt[1..]);
                    let methods = String::from(r.str().unwrap_or(""));
                    let _partial = r.bool().unwrap_or(false);
                    if !self.auth_password.is_empty()
                        && !self.tried_kb_interactive
                        && list_contains(&methods, "keyboard-interactive")
                    {
                        self.tried_kb_interactive = true;
                        let mut w = Writer::new();
                        w.u8(MSG_USERAUTH_REQUEST);
                        w.str(&self.username);
                        w.str("ssh-connection");
                        w.str("keyboard-interactive");
                        w.str("");
                        w.str("");
                        let req = w.into_vec();
                        self.send_packet(&req);
                    } else {
                        wipe_bytes(&mut self.auth_password);
                        self.auth_password.clear();
                        self.state = State::AuthReady;
                        return Err(SshError::AuthFailed(methods));
                    }
                }
                _ => return Err(SshError::ProtocolViolation("unexpected auth message")),
            },
            State::OpeningChannel => match msg {
                MSG_CHANNEL_OPEN_CONFIRMATION => {
                    let mut r = Reader::new(&pkt[1..]);
                    let _recip = r.u32().ok_or(SshError::ProtocolViolation("bad chan confirm"))?;
                    self.remote_channel =
                        r.u32().ok_or(SshError::ProtocolViolation("bad chan confirm"))?;
                    self.remote_window =
                        r.u32().ok_or(SshError::ProtocolViolation("bad chan confirm"))?;
                    self.remote_max_packet =
                        r.u32().ok_or(SshError::ProtocolViolation("bad chan confirm"))?.clamp(1024, 32768);
                    self.state = State::ChannelReady;
                }
                MSG_CHANNEL_OPEN_FAILURE => {
                    let mut r = Reader::new(&pkt[1..]);
                    let _recip = r.u32();
                    let _code = r.u32();
                    let desc = String::from(r.str().unwrap_or("channel open rejected"));
                    self.state = State::Authenticated;
                    return Err(SshError::ChannelOpenFailed(desc));
                }
                _ => {}
            },
            State::RequestingExec | State::RequestingPty | State::RequestingShell => match msg {
                MSG_CHANNEL_SUCCESS => {
                    if self.state == State::RequestingPty {
                        self.state = State::RequestingShell;
                        let mut w = Writer::new();
                        w.u8(MSG_CHANNEL_REQUEST);
                        w.u32(self.remote_channel);
                        w.str("shell");
                        w.bool(true);
                        let req = w.into_vec();
                        self.send_packet(&req);
                    } else {
                        self.state = State::Active;
                        self.flush_stdin();
                    }
                }
                MSG_CHANNEL_FAILURE => {
                    return Err(SshError::ChannelRequestFailed);
                }
                MSG_CHANNEL_WINDOW_ADJUST => self.handle_window_adjust(&pkt[1..]),
                MSG_CHANNEL_DATA | MSG_CHANNEL_EXTENDED_DATA | MSG_CHANNEL_REQUEST
                | MSG_CHANNEL_EOF | MSG_CHANNEL_CLOSE => {
                    self.handle_channel_msg(msg, &pkt[1..]);
                }
                _ => {}
            },
            State::Active => match msg {
                MSG_CHANNEL_WINDOW_ADJUST => self.handle_window_adjust(&pkt[1..]),
                MSG_CHANNEL_DATA | MSG_CHANNEL_EXTENDED_DATA | MSG_CHANNEL_REQUEST
                | MSG_CHANNEL_EOF | MSG_CHANNEL_CLOSE => {
                    self.handle_channel_msg(msg, &pkt[1..]);
                }
                _ => {}
            },
            _ => {}
        }
        Ok(())
    }

    fn handle_kexinit(&mut self, pkt: &[u8]) -> Result<(), SshError> {
        let mut r = Reader::new(&pkt[1..]);
        let _cookie = r.take(16).ok_or(SshError::ProtocolViolation("short KEXINIT"))?;
        let srv_kex = r.str().ok_or(SshError::ProtocolViolation("bad kex list"))?;
        let srv_hk = r.str().ok_or(SshError::ProtocolViolation("bad hostkey list"))?;
        let srv_c2s = r.str().ok_or(SshError::ProtocolViolation("bad c2s cipher list"))?;
        let srv_s2c = r.str().ok_or(SshError::ProtocolViolation("bad s2c cipher list"))?;
        let _srv_mac_c2s = r.str().ok_or(SshError::ProtocolViolation("bad c2s mac list"))?;
        let _srv_mac_s2c = r.str().ok_or(SshError::ProtocolViolation("bad s2c mac list"))?;
        let srv_comp_c2s = r.str().ok_or(SshError::ProtocolViolation("bad c2s comp"))?;
        let srv_comp_s2c = r.str().ok_or(SshError::ProtocolViolation("bad s2c comp"))?;
        let _lang_c2s = r.str().ok_or(SshError::ProtocolViolation("bad lang"))?;
        let _lang_s2c = r.str().ok_or(SshError::ProtocolViolation("bad lang"))?;
        let _first_follows = r.bool().ok_or(SshError::ProtocolViolation("bad first_follows"))?;
        let _reserved = r.u32().ok_or(SshError::ProtocolViolation("bad reserved"))?;

        self.strict_kex = list_contains(srv_kex, KEX_STRICT_SERVER);
        let kex_alg = first_match("curve25519-sha256,curve25519-sha256@libssh.org", srv_kex)
            .ok_or(SshError::AlgorithmMismatch("kex (need curve25519-sha256)"))?;
        let hk_name = first_match(CLIENT_HOST_KEY_ALGS, srv_hk)
            .ok_or(SshError::AlgorithmMismatch("host key"))?;
        let c2s_name = first_match(CLIENT_CIPHERS, srv_c2s)
            .ok_or(SshError::AlgorithmMismatch("cipher c2s (need aes-gcm)"))?;
        let s2c_name = first_match(CLIENT_CIPHERS, srv_s2c)
            .ok_or(SshError::AlgorithmMismatch("cipher s2c (need aes-gcm)"))?;
        if !list_contains(srv_comp_c2s, "none") || !list_contains(srv_comp_s2c, "none") {
            return Err(SshError::AlgorithmMismatch("compression"));
        }

        self.kex_alg = String::from(kex_alg);
        self.host_key_alg = HostKeyAlg::from_name(hk_name);
        self.cipher_c2s = Cipher::from_name(c2s_name);
        self.cipher_s2c = Cipher::from_name(s2c_name);
        self.server_kexinit = pkt.to_vec();

        // Send SSH_MSG_KEX_ECDH_INIT with client ephemeral X25519 public key.
        let mut w = Writer::new();
        w.u8(MSG_KEX_ECDH_INIT);
        w.bytes(&self.ephemeral_pub);
        let init_pkt = w.into_vec();
        self.send_packet(&init_pkt);
        self.state = State::KexReply;
        Ok(())
    }

    fn handle_kex_reply(&mut self, body: &[u8]) -> Result<(), SshError> {
        let mut r = Reader::new(body);
        let host_key_blob = r.bytes().ok_or(SshError::ProtocolViolation("bad host key blob"))?;
        let q_s_bytes = r.bytes().ok_or(SshError::ProtocolViolation("bad server Q_S"))?;
        let sig_blob = r.bytes().ok_or(SshError::ProtocolViolation("bad host signature"))?;
        if q_s_bytes.len() != 32 {
            return Err(SshError::ProtocolViolation("bad X25519 key size"));
        }
        let q_s: [u8; 32] = q_s_bytes.try_into().map_err(|_| SshError::ProtocolViolation("Q_S"))?;
        let mut shared =
            x25519::diffie_hellman(&self.ephemeral_priv, &q_s).ok_or(SshError::LowOrderKey)?;
        wipe_bytes(&mut self.ephemeral_priv);

        let mut k_w = Writer::new();
        k_w.mpint_unsigned(&shared);
        let mut k_mpint = k_w.into_vec();
        wipe_bytes(&mut shared);

        let h = compute_exchange_hash(
            CLIENT_BANNER.as_bytes(),
            self.server_banner.as_bytes(),
            &self.client_kexinit,
            &self.server_kexinit,
            host_key_blob,
            &self.ephemeral_pub,
            &q_s,
            &k_mpint,
        );

        let hk_alg = self.host_key_alg.ok_or(SshError::InvalidState)?;
        let res = verify_host_signature(hk_alg, host_key_blob, sig_blob, &h);
        if let Err(e) = res {
            wipe_bytes(&mut k_mpint);
            return Err(e);
        }

        self.session_id = h;
        let c2s = self.cipher_c2s.ok_or(SshError::InvalidState)?;
        let s2c = self.cipher_s2c.ok_or(SshError::InvalidState)?;

        let mut iv_c2s = derive_key_sha256(&k_mpint, &h, b'A', &self.session_id);
        let mut iv_s2c = derive_key_sha256(&k_mpint, &h, b'B', &self.session_id);
        let mut key_c2s = derive_key_sha256(&k_mpint, &h, b'C', &self.session_id);
        let mut key_s2c = derive_key_sha256(&k_mpint, &h, b'D', &self.session_id);
        wipe_bytes(&mut k_mpint);

        self.pending_tx_aead = Some(AeadState::new(c2s, &key_c2s, &iv_c2s));
        self.pending_rx_aead = Some(AeadState::new(s2c, &key_s2c, &iv_s2c));
        wipe_bytes(&mut iv_c2s);
        wipe_bytes(&mut iv_s2c);
        wipe_bytes(&mut key_c2s);
        wipe_bytes(&mut key_s2c);

        self.host_info = Some(HostKeyInfo {
            server_banner: self.server_banner.clone(),
            kex_alg: self.kex_alg.clone(),
            host_key_alg: hk_alg,
            cipher_c2s: c2s,
            cipher_s2c: s2c,
            host_key_blob: host_key_blob.to_vec(),
            fingerprint: host_key_fingerprint(host_key_blob),
        });

        // Send SSH_MSG_NEWKEYS and switch TX encryption immediately.
        self.send_packet(&[MSG_NEWKEYS]);
        self.tx_aead = self.pending_tx_aead.take();
        self.state = State::NewKeys;
        Ok(())
    }

    /// Approve the server's verified host key and request `ssh-userauth`.
    pub fn accept_host_key(&mut self) -> Result<(), SshError> {
        if self.state != State::VerifyHostKey {
            return Err(SshError::InvalidState);
        }
        let mut w = Writer::new();
        w.u8(MSG_SERVICE_REQUEST);
        w.str("ssh-userauth");
        let req = w.into_vec();
        self.send_packet(&req);
        self.state = State::ServiceRequest;
        Ok(())
    }

    /// Authenticate `username` using `method`.
    pub fn authenticate(&mut self, username: &str, method: AuthMethod) -> Result<(), SshError> {
        if self.state != State::AuthReady {
            return Err(SshError::InvalidState);
        }
        self.username = String::from(username);
        wipe_bytes(&mut self.auth_password);
        self.auth_password.clear();
        self.tried_kb_interactive = false;

        let req = match &method {
            AuthMethod::None => {
                let mut w = Writer::new();
                w.u8(MSG_USERAUTH_REQUEST);
                w.str(username);
                w.str("ssh-connection");
                w.str("none");
                w.into_vec()
            }
            AuthMethod::Password(pw) => {
                self.auth_password = pw.clone();
                let mut w = Writer::new();
                w.u8(MSG_USERAUTH_REQUEST);
                w.str(username);
                w.str("ssh-connection");
                w.str("password");
                w.bool(false);
                w.bytes(pw);
                w.into_vec()
            }
            AuthMethod::PublicKeyEd25519(seed) => {
                let sk = SigningKey::from_seed(seed);
                let pub_blob = encode_ed25519_pubkey_blob(&sk.public());
                // RFC 4252 §7 signature payload:
                // string(session_id) || byte(50) || string(user) || string("ssh-connection")
                // || string("publickey") || bool(true) || string("ssh-ed25519") || string(pub_blob)
                let mut sign_data = Writer::new();
                sign_data.bytes(&self.session_id);
                sign_data.u8(MSG_USERAUTH_REQUEST);
                sign_data.str(username);
                sign_data.str("ssh-connection");
                sign_data.str("publickey");
                sign_data.bool(true);
                sign_data.str("ssh-ed25519");
                sign_data.bytes(&pub_blob);
                let sig = sk.sign(&sign_data.into_vec());

                let mut sig_blob = Writer::new();
                sig_blob.str("ssh-ed25519");
                sig_blob.bytes(&sig);

                let mut w = Writer::new();
                w.u8(MSG_USERAUTH_REQUEST);
                w.str(username);
                w.str("ssh-connection");
                w.str("publickey");
                w.bool(true);
                w.str("ssh-ed25519");
                w.bytes(&pub_blob);
                w.bytes(&sig_blob.into_vec());
                w.into_vec()
            }
        };
        drop(method);
        self.send_packet(&req);
        self.state = State::Authenticating;
        Ok(())
    }

    /// Open a `session` channel (RFC 4254 §6.1).
    pub fn open_session(&mut self) -> Result<(), SshError> {
        if self.state != State::Authenticated {
            return Err(SshError::InvalidState);
        }
        self.local_window = INITIAL_LOCAL_WINDOW;
        let mut w = Writer::new();
        w.u8(MSG_CHANNEL_OPEN);
        w.str("session");
        w.u32(0); // local channel id
        w.u32(INITIAL_LOCAL_WINDOW);
        w.u32(MAX_LOCAL_PACKET);
        let req = w.into_vec();
        self.send_packet(&req);
        self.state = State::OpeningChannel;
        Ok(())
    }

    /// Execute a single remote command (`exec`) on the open session channel.
    pub fn request_exec(&mut self, command: &str) -> Result<(), SshError> {
        if self.state != State::ChannelReady {
            return Err(SshError::InvalidState);
        }
        let mut w = Writer::new();
        w.u8(MSG_CHANNEL_REQUEST);
        w.u32(self.remote_channel);
        w.str("exec");
        w.bool(true);
        w.str(command);
        let req = w.into_vec();
        self.send_packet(&req);
        self.state = State::RequestingExec;
        Ok(())
    }

    /// Request a PTY (`xterm`, `cols` x `rows`) followed by an interactive `shell`.
    pub fn request_shell(&mut self, cols: u32, rows: u32) -> Result<(), SshError> {
        if self.state != State::ChannelReady {
            return Err(SshError::InvalidState);
        }
        self.pending_pty_cols = cols.clamp(20, 400);
        self.pending_pty_rows = rows.clamp(5, 200);
        let mut w = Writer::new();
        w.u8(MSG_CHANNEL_REQUEST);
        w.u32(self.remote_channel);
        w.str("pty-req");
        w.bool(true);
        w.str("xterm");
        w.u32(self.pending_pty_cols);
        w.u32(self.pending_pty_rows);
        w.u32(0); // pixel width
        w.u32(0); // pixel height
        w.bytes(&[0]); // TTY_OP_END
        let req = w.into_vec();
        self.send_packet(&req);
        self.state = State::RequestingPty;
        Ok(())
    }

    /// Notify the remote PTY of a terminal resize (RFC 4254 §6.7 `"window-change"`).
    pub fn send_window_change(&mut self, cols: u32, rows: u32) {
        if self.state != State::Active {
            return;
        }
        let mut w = Writer::new();
        w.u8(MSG_CHANNEL_REQUEST);
        w.u32(self.remote_channel);
        w.str("window-change");
        w.bool(false);
        w.u32(cols.clamp(20, 400));
        w.u32(rows.clamp(5, 200));
        w.u32(0);
        w.u32(0);
        let pkt = w.into_vec();
        self.send_packet(&pkt);
    }

    /// Queue stdin bytes to send on the active session channel.
    pub fn send_data(&mut self, data: &[u8]) -> Result<(), SshError> {
        if self.state != State::Active {
            return Err(SshError::InvalidState);
        }
        self.pending_stdin.extend(data.iter().copied());
        self.flush_stdin();
        Ok(())
    }

    fn flush_stdin(&mut self) {
        while !self.pending_stdin.is_empty() && self.remote_window > 0 {
            let chunk_len = self
                .pending_stdin
                .len()
                .min(self.remote_window as usize)
                .min(self.remote_max_packet as usize);
            let mut chunk = Vec::with_capacity(chunk_len);
            for _ in 0..chunk_len {
                if let Some(b) = self.pending_stdin.pop_front() {
                    chunk.push(b);
                }
            }
            self.remote_window = self.remote_window.saturating_sub(chunk.len() as u32);
            let mut w = Writer::new();
            w.u8(MSG_CHANNEL_DATA);
            w.u32(self.remote_channel);
            w.bytes(&chunk);
            let pkt = w.into_vec();
            self.send_packet(&pkt);
        }
    }

    /// Send `SSH_MSG_CHANNEL_EOF`.
    pub fn send_eof(&mut self) {
        if self.state == State::Active {
            let mut w = Writer::new();
            w.u8(MSG_CHANNEL_EOF);
            w.u32(self.remote_channel);
            let pkt = w.into_vec();
            self.send_packet(&pkt);
        }
    }

    /// Send `SSH_MSG_DISCONNECT` and mark the client closed.
    pub fn disconnect(&mut self) {
        if self.state == State::Closed {
            return;
        }
        let mut w = Writer::new();
        w.u8(MSG_DISCONNECT);
        w.u32(11); // SSH_DISCONNECT_BY_APPLICATION
        w.str("bye");
        w.str("");
        let pkt = w.into_vec();
        self.send_packet(&pkt);
        self.state = State::Closed;
    }

    fn handle_window_adjust(&mut self, body: &[u8]) {
        let mut r = Reader::new(body);
        let _recip = r.u32();
        if let Some(add) = r.u32() {
            self.remote_window = self.remote_window.saturating_add(add);
            if self.state == State::Active {
                self.flush_stdin();
            }
        }
    }

    fn consume_local_window(&mut self, n: usize) {
        self.local_window = self.local_window.saturating_sub(n as u32);
        if self.local_window < INITIAL_LOCAL_WINDOW / 2 {
            let add = INITIAL_LOCAL_WINDOW - self.local_window;
            self.local_window = INITIAL_LOCAL_WINDOW;
            let mut w = Writer::new();
            w.u8(MSG_CHANNEL_WINDOW_ADJUST);
            w.u32(self.remote_channel);
            w.u32(add);
            let pkt = w.into_vec();
            self.send_packet(&pkt);
        }
    }

    fn handle_channel_msg(&mut self, msg: u8, body: &[u8]) {
        let mut r = Reader::new(body);
        let _recip = r.u32();
        match msg {
            MSG_CHANNEL_DATA => {
                if let Some(data) = r.bytes() {
                    self.consume_local_window(data.len());
                    if !data.is_empty() {
                        self.events.push_back(Event::Stdout(data.to_vec()));
                    }
                }
            }
            MSG_CHANNEL_EXTENDED_DATA => {
                let _dtype = r.u32();
                if let Some(data) = r.bytes() {
                    self.consume_local_window(data.len());
                    if !data.is_empty() {
                        self.events.push_back(Event::Stderr(data.to_vec()));
                    }
                }
            }
            MSG_CHANNEL_REQUEST => {
                let Some(kind) = r.str() else { return };
                let want_reply = r.bool().unwrap_or(false);
                if kind == "exit-status"
                    && let Some(code) = r.u32()
                {
                    self.events.push_back(Event::ExitStatus(code));
                }
                if want_reply {
                    let mut w = Writer::new();
                    w.u8(MSG_CHANNEL_FAILURE);
                    w.u32(self.remote_channel);
                    let pkt = w.into_vec();
                    self.send_packet(&pkt);
                }
            }
            MSG_CHANNEL_EOF => {
                self.events.push_back(Event::Eof);
            }
            MSG_CHANNEL_CLOSE => {
                let mut w = Writer::new();
                w.u8(MSG_CHANNEL_CLOSE);
                w.u32(self.remote_channel);
                let pkt = w.into_vec();
                self.send_packet(&pkt);
                self.state = State::Closed;
                self.events.push_back(Event::Closed);
            }
            _ => {}
        }
    }
}

impl Drop for SshClient {
    fn drop(&mut self) {
        wipe_bytes(&mut self.ephemeral_priv);
        wipe_bytes(&mut self.session_id);
        wipe_bytes(&mut self.auth_password);
    }
}

fn build_kexinit(cookie: &[u8; 16], kex_algs: &str, host_key_algs: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(MSG_KEXINIT);
    w.raw(cookie);
    w.str(kex_algs);
    w.str(host_key_algs);
    w.str(CLIENT_CIPHERS);
    w.str(CLIENT_CIPHERS);
    w.str(CLIENT_MACS);
    w.str(CLIENT_MACS);
    w.str("none");
    w.str("none");
    w.str("");
    w.str("");
    w.bool(false);
    w.u32(0);
    w.into_vec()
}

// ---- In-tree RFC-compliant SSH-2 test server (used by unit tests and QEMU nettest) -------------

pub mod server {
    use super::*;

    pub const SERVER_BANNER: &str = "SSH-2.0-DiscreteOS_TestServer_1.0";

    const SERVER_KEX_ALGS: &str =
        "curve25519-sha256,curve25519-sha256@libssh.org,kex-strict-s-v00@openssh.com";

    /// Minimal sans-IO SSH-2 server supporting `curve25519-sha256` + `ssh-ed25519` +
    /// `aes256-gcm@openssh.com`, password/pubkey/none auth, `exec`, and interactive `shell`.
    pub struct SshServer {
        host_key: SigningKey,
        allowed_user: String,
        allowed_password: Option<Vec<u8>>,
        allowed_pubkey: Option<[u8; 32]>,
        allow_none: bool,
        tamper_sig: bool,
        rx_buf: Vec<u8>,
        tx_buf: Vec<u8>,
        client_banner: String,
        server_kexinit: Vec<u8>,
        client_kexinit: Vec<u8>,
        ephemeral_priv: [u8; 32],
        ephemeral_pub: [u8; 32],
        pad_seed: u64,
        session_id: [u8; 32],
        cipher_c2s: Cipher,
        cipher_s2c: Cipher,
        tx_aead: Option<AeadState>,
        rx_aead: Option<AeadState>,
        pending_rx_aead: Option<AeadState>,
        got_banner: bool,
        got_kexinit: bool,
        authenticated: bool,
        client_channel: u32,
        shell_active: bool,
        shell_line: Vec<u8>,
        pub closed: bool,
    }

    impl SshServer {
        pub fn new(
            host_seed: &[u8; 32],
            rand64: &[u8; 64],
            allowed_user: &str,
            allowed_password: Option<&[u8]>,
            allowed_pubkey: Option<[u8; 32]>,
            allow_none: bool,
        ) -> Self {
            let host_key = SigningKey::from_seed(host_seed);
            let mut ephemeral_priv = [0u8; 32];
            ephemeral_priv.copy_from_slice(&rand64[..32]);
            let ephemeral_pub = x25519::public_key(&ephemeral_priv);
            let mut cookie = [0u8; 16];
            cookie.copy_from_slice(&rand64[32..48]);
            let pad_seed = u64::from_le_bytes([
                rand64[48], rand64[49], rand64[50], rand64[51], rand64[52], rand64[53], rand64[54],
                rand64[55],
            ]);
            let server_kexinit = build_kexinit(&cookie, SERVER_KEX_ALGS, "ssh-ed25519");

            let mut tx_buf = Vec::new();
            tx_buf.extend_from_slice(SERVER_BANNER.as_bytes());
            tx_buf.extend_from_slice(b"\r\n");

            let mut s = Self {
                host_key,
                allowed_user: String::from(allowed_user),
                allowed_password: allowed_password.map(|b| b.to_vec()),
                allowed_pubkey,
                allow_none,
                tamper_sig: false,
                rx_buf: Vec::new(),
                tx_buf,
                client_banner: String::new(),
                server_kexinit,
                client_kexinit: Vec::new(),
                ephemeral_priv,
                ephemeral_pub,
                pad_seed,
                session_id: [0u8; 32],
                cipher_c2s: Cipher::Aes256Gcm,
                cipher_s2c: Cipher::Aes256Gcm,
                tx_aead: None,
                rx_aead: None,
                pending_rx_aead: None,
                got_banner: false,
                got_kexinit: false,
                authenticated: false,
                client_channel: 0,
                shell_active: false,
                shell_line: Vec::new(),
                closed: false,
            };
            let kex = s.server_kexinit.clone();
            s.send_packet(&kex);
            s
        }

        /// Deliberately corrupt the host-key signature (for negative security testing).
        pub fn set_tamper_signature(&mut self, tamper: bool) {
            self.tamper_sig = tamper;
        }

        pub fn host_key_fingerprint(&self) -> String {
            host_key_fingerprint(&encode_ed25519_pubkey_blob(&self.host_key.public()))
        }

        pub fn take_tx(&mut self) -> Vec<u8> {
            core::mem::take(&mut self.tx_buf)
        }

        fn send_packet(&mut self, payload: &[u8]) {
            encode_packet(payload, &mut self.tx_aead, &mut self.pad_seed, &mut self.tx_buf);
        }

        pub fn feed_rx(&mut self, data: &[u8]) -> Result<(), SshError> {
            if self.closed {
                return Ok(());
            }
            self.rx_buf.extend_from_slice(data);
            if !self.got_banner {
                let Some(lf) = self.rx_buf.iter().position(|&b| b == b'\n') else {
                    return Ok(());
                };
                let end = if lf > 0 && self.rx_buf[lf - 1] == b'\r' { lf - 1 } else { lf };
                self.client_banner =
                    String::from(core::str::from_utf8(&self.rx_buf[..end]).unwrap_or(""));
                self.rx_buf.drain(..=lf);
                self.got_banner = true;
            }
            while let Some(pkt) = try_decode_packet(&mut self.rx_buf, &mut self.rx_aead)? {
                self.handle_packet(&pkt)?;
                if self.closed {
                    break;
                }
            }
            Ok(())
        }

        fn handle_packet(&mut self, pkt: &[u8]) -> Result<(), SshError> {
            if pkt.is_empty() {
                return Err(SshError::ProtocolViolation("empty"));
            }
            match pkt[0] {
                MSG_DISCONNECT => {
                    self.closed = true;
                }
                MSG_KEXINIT => {
                    self.client_kexinit = pkt.to_vec();
                    let mut r = Reader::new(&pkt[1..]);
                    let _ = r.take(16);
                    let _kex = r.str();
                    let _hk = r.str();
                    let c2s = r.str().unwrap_or("");
                    let s2c = r.str().unwrap_or("");
                    self.cipher_c2s = first_match(c2s, CLIENT_CIPHERS)
                        .and_then(Cipher::from_name)
                        .unwrap_or(Cipher::Aes256Gcm);
                    self.cipher_s2c = first_match(s2c, CLIENT_CIPHERS)
                        .and_then(Cipher::from_name)
                        .unwrap_or(Cipher::Aes256Gcm);
                    self.got_kexinit = true;
                }
                MSG_KEX_ECDH_INIT => {
                    if !self.got_kexinit {
                        return Err(SshError::ProtocolViolation("init before kexinit"));
                    }
                    let mut r = Reader::new(&pkt[1..]);
                    let q_c_bytes = r.bytes().ok_or(SshError::ProtocolViolation("Q_C"))?;
                    let q_c: [u8; 32] =
                        q_c_bytes.try_into().map_err(|_| SshError::ProtocolViolation("Q_C len"))?;
                    let mut shared = x25519::diffie_hellman(&self.ephemeral_priv, &q_c)
                        .ok_or(SshError::LowOrderKey)?;
                    let mut kw = Writer::new();
                    kw.mpint_unsigned(&shared);
                    let mut k_mpint = kw.into_vec();
                    wipe_bytes(&mut shared);

                    let host_blob = encode_ed25519_pubkey_blob(&self.host_key.public());
                    let h = compute_exchange_hash(
                        self.client_banner.as_bytes(),
                        SERVER_BANNER.as_bytes(),
                        &self.client_kexinit,
                        &self.server_kexinit,
                        &host_blob,
                        &q_c,
                        &self.ephemeral_pub,
                        &k_mpint,
                    );
                    self.session_id = h;

                    let mut sig = self.host_key.sign(&h);
                    if self.tamper_sig {
                        sig[0] ^= 0xFF;
                    }
                    let mut sig_w = Writer::new();
                    sig_w.str("ssh-ed25519");
                    sig_w.bytes(&sig);

                    let mut reply = Writer::new();
                    reply.u8(MSG_KEX_ECDH_REPLY);
                    reply.bytes(&host_blob);
                    reply.bytes(&self.ephemeral_pub);
                    reply.bytes(&sig_w.into_vec());
                    self.send_packet(&reply.into_vec());
                    self.send_packet(&[MSG_NEWKEYS]);

                    let iv_c2s = derive_key_sha256(&k_mpint, &h, b'A', &self.session_id);
                    let iv_s2c = derive_key_sha256(&k_mpint, &h, b'B', &self.session_id);
                    let key_c2s = derive_key_sha256(&k_mpint, &h, b'C', &self.session_id);
                    let key_s2c = derive_key_sha256(&k_mpint, &h, b'D', &self.session_id);
                    wipe_bytes(&mut k_mpint);

                    // Server transmits with s2c keys, receives with c2s keys.
                    self.tx_aead = Some(AeadState::new(self.cipher_s2c, &key_s2c, &iv_s2c));
                    self.pending_rx_aead = Some(AeadState::new(self.cipher_c2s, &key_c2s, &iv_c2s));
                }
                MSG_NEWKEYS => {
                    self.rx_aead = self.pending_rx_aead.take();
                }
                MSG_SERVICE_REQUEST => {
                    let mut r = Reader::new(&pkt[1..]);
                    let svc = r.str().unwrap_or("");
                    if svc == "ssh-userauth" {
                        let mut w = Writer::new();
                        w.u8(MSG_SERVICE_ACCEPT);
                        w.str("ssh-userauth");
                        self.send_packet(&w.into_vec());
                    }
                }
                MSG_USERAUTH_REQUEST => {
                    let mut r = Reader::new(&pkt[1..]);
                    let user = r.str().unwrap_or("");
                    let _svc = r.str().unwrap_or("");
                    let method = r.str().unwrap_or("");
                    let ok = if user != self.allowed_user {
                        false
                    } else {
                        match method {
                            "none" => self.allow_none,
                            "password" => {
                                let _chg = r.bool();
                                let pw = r.bytes().unwrap_or(b"");
                                self.allowed_password.as_deref() == Some(pw)
                            }
                            "publickey" => {
                                let has_sig = r.bool().unwrap_or(false);
                                let alg = r.str().unwrap_or("");
                                let pk_blob = r.bytes().unwrap_or(b"");
                                let sig_blob = r.bytes().unwrap_or(b"");
                                if has_sig && alg == "ssh-ed25519" {
                                    let mut pr = Reader::new(pk_blob);
                                    let kt = pr.str().unwrap_or("");
                                    let pk = pr.bytes().unwrap_or(b"");
                                    let mut sr = Reader::new(sig_blob);
                                    let st = sr.str().unwrap_or("");
                                    let sig = sr.bytes().unwrap_or(b"");
                                    if kt == "ssh-ed25519"
                                        && st == "ssh-ed25519"
                                        && pk.len() == 32
                                        && sig.len() == 64
                                        && self.allowed_pubkey.is_none_or(|a| a.as_slice() == pk)
                                    {
                                        let mut sd = Writer::new();
                                        sd.bytes(&self.session_id);
                                        sd.u8(MSG_USERAUTH_REQUEST);
                                        sd.str(user);
                                        sd.str("ssh-connection");
                                        sd.str("publickey");
                                        sd.bool(true);
                                        sd.str("ssh-ed25519");
                                        sd.bytes(pk_blob);
                                        let pk32: [u8; 32] = pk.try_into().unwrap_or([0; 32]);
                                        let sig64: [u8; 64] = sig.try_into().unwrap_or([0; 64]);
                                        ed25519::verify(&pk32, &sd.into_vec(), &sig64)
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                }
                            }
                            _ => false,
                        }
                    };
                    if ok {
                        self.authenticated = true;
                        self.send_packet(&[MSG_USERAUTH_SUCCESS]);
                    } else {
                        let mut w = Writer::new();
                        w.u8(MSG_USERAUTH_FAILURE);
                        w.str("publickey,password");
                        w.bool(false);
                        self.send_packet(&w.into_vec());
                    }
                }
                MSG_CHANNEL_OPEN => {
                    if !self.authenticated {
                        return Err(SshError::ProtocolViolation("open before auth"));
                    }
                    let mut r = Reader::new(&pkt[1..]);
                    let _kind = r.str();
                    self.client_channel = r.u32().unwrap_or(0);
                    let mut w = Writer::new();
                    w.u8(MSG_CHANNEL_OPEN_CONFIRMATION);
                    w.u32(self.client_channel);
                    w.u32(0);
                    w.u32(INITIAL_LOCAL_WINDOW);
                    w.u32(MAX_LOCAL_PACKET);
                    self.send_packet(&w.into_vec());
                }
                MSG_CHANNEL_REQUEST => {
                    let mut r = Reader::new(&pkt[1..]);
                    let _chan = r.u32();
                    let kind = r.str().unwrap_or("");
                    let want_reply = r.bool().unwrap_or(false);
                    match kind {
                        "pty-req" => {
                            if want_reply {
                                let mut w = Writer::new();
                                w.u8(MSG_CHANNEL_SUCCESS);
                                w.u32(self.client_channel);
                                self.send_packet(&w.into_vec());
                            }
                        }
                        "shell" => {
                            self.shell_active = true;
                            if want_reply {
                                let mut w = Writer::new();
                                w.u8(MSG_CHANNEL_SUCCESS);
                                w.u32(self.client_channel);
                                self.send_packet(&w.into_vec());
                            }
                            self.send_channel_data(b"DiscreteOS Test SSH Shell\r\n$ ");
                        }
                        "exec" => {
                            let cmd = r.str().unwrap_or("");
                            if want_reply {
                                let mut w = Writer::new();
                                w.u8(MSG_CHANNEL_SUCCESS);
                                w.u32(self.client_channel);
                                self.send_packet(&w.into_vec());
                            }
                            let reply = exec_command(&self.allowed_user, cmd);
                            self.send_channel_data(reply.as_bytes());
                            self.finish_channel(0);
                        }
                        _ => {
                            if want_reply {
                                let mut w = Writer::new();
                                w.u8(MSG_CHANNEL_FAILURE);
                                w.u32(self.client_channel);
                                self.send_packet(&w.into_vec());
                            }
                        }
                    }
                }
                MSG_CHANNEL_DATA => {
                    if self.shell_active {
                        let mut r = Reader::new(&pkt[1..]);
                        let _chan = r.u32();
                        let data = r.bytes().unwrap_or(b"");
                        for &b in data {
                            if b == b'\r' || b == b'\n' {
                                self.send_channel_data(b"\r\n");
                                let line = String::from_utf8_lossy(&self.shell_line).into_owned();
                                self.shell_line.clear();
                                if line.trim() == "exit" {
                                    self.finish_channel(0);
                                    break;
                                }
                                let out = exec_command(&self.allowed_user, line.trim());
                                self.send_channel_data(out.as_bytes());
                                self.send_channel_data(b"$ ");
                            } else {
                                self.shell_line.push(b);
                                self.send_channel_data(&[b]);
                            }
                        }
                    }
                }
                MSG_CHANNEL_CLOSE => {
                    self.closed = true;
                }
                _ => {}
            }
            Ok(())
        }

        fn send_channel_data(&mut self, data: &[u8]) {
            if data.is_empty() {
                return;
            }
            let mut w = Writer::new();
            w.u8(MSG_CHANNEL_DATA);
            w.u32(self.client_channel);
            w.bytes(data);
            self.send_packet(&w.into_vec());
        }

        fn finish_channel(&mut self, code: u32) {
            let mut st = Writer::new();
            st.u8(MSG_CHANNEL_REQUEST);
            st.u32(self.client_channel);
            st.str("exit-status");
            st.bool(false);
            st.u32(code);
            self.send_packet(&st.into_vec());

            let mut eof = Writer::new();
            eof.u8(MSG_CHANNEL_EOF);
            eof.u32(self.client_channel);
            self.send_packet(&eof.into_vec());

            let mut cls = Writer::new();
            cls.u8(MSG_CHANNEL_CLOSE);
            cls.u32(self.client_channel);
            self.send_packet(&cls.into_vec());
            self.closed = true;
        }
    }

    fn exec_command(user: &str, cmd: &str) -> String {
        if let Some(rest) = cmd.strip_prefix("echo ") {
            format!("{}\n", rest)
        } else if cmd == "whoami" {
            format!("{}\n", user)
        } else if cmd == "uname" || cmd == "uname -a" {
            String::from("DiscreteOS-TestHost x86_64 SSH-2.0\n")
        } else if cmd.is_empty() {
            String::new()
        } else {
            format!("ok: {}\n", cmd)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::server::SshServer;
    use super::*;

    fn pump(client: &mut SshClient, srv: &mut SshServer) -> Result<(), SshError> {
        for _ in 0..16 {
            let c2s = client.take_tx();
            let s2c = srv.take_tx();
            if c2s.is_empty() && s2c.is_empty() {
                break;
            }
            if !c2s.is_empty() {
                srv.feed_rx(&c2s)?;
            }
            if !s2c.is_empty() {
                client.feed_rx(&s2c)?;
            }
        }
        Ok(())
    }

    #[test]
    fn ssh_handshake_password_exec_roundtrip() {
        let host_seed = [0x42u8; 32];
        let mut client = SshClient::new(&[0x11u8; 64]);
        let mut srv = SshServer::new(
            &host_seed,
            &[0x22u8; 64],
            "alice",
            Some(b"hunter2"),
            None,
            false,
        );

        pump(&mut client, &mut srv).unwrap();
        assert_eq!(client.state(), State::VerifyHostKey);
        let info = client.host_key_info().unwrap();
        assert_eq!(info.host_key_alg, HostKeyAlg::Ed25519);
        assert_eq!(info.cipher_c2s, Cipher::Aes256Gcm);
        assert_eq!(info.fingerprint, srv.host_key_fingerprint());

        client.accept_host_key().unwrap();
        pump(&mut client, &mut srv).unwrap();
        assert_eq!(client.state(), State::AuthReady);

        // Wrong password fails cleanly.
        client.authenticate("alice", AuthMethod::Password(b"wrong".to_vec())).unwrap();
        let err = pump(&mut client, &mut srv);
        assert!(matches!(err, Err(SshError::AuthFailed(_))));
        assert_eq!(client.state(), State::AuthReady);

        // Correct password succeeds.
        client.authenticate("alice", AuthMethod::Password(b"hunter2".to_vec())).unwrap();
        pump(&mut client, &mut srv).unwrap();
        assert_eq!(client.state(), State::Authenticated);

        client.open_session().unwrap();
        pump(&mut client, &mut srv).unwrap();
        assert_eq!(client.state(), State::ChannelReady);

        client.request_exec("echo hello-dos-ssh").unwrap();
        pump(&mut client, &mut srv).unwrap();

        let mut stdout = Vec::new();
        let mut exit_code = None;
        while let Some(ev) = client.pop_event() {
            match ev {
                Event::Stdout(b) => stdout.extend_from_slice(&b),
                Event::ExitStatus(c) => exit_code = Some(c),
                _ => {}
            }
        }
        assert_eq!(stdout, b"hello-dos-ssh\n");
        assert_eq!(exit_code, Some(0));
    }

    #[test]
    fn ssh_pubkey_ed25519_and_interactive_shell() {
        let host_seed = [0x55u8; 32];
        let user_seed = [0x99u8; 32];
        let user_pub = SigningKey::from_seed(&user_seed).public();

        let mut client = SshClient::new(&[0x33u8; 64]);
        let mut srv = SshServer::new(
            &host_seed,
            &[0x44u8; 64],
            "bob",
            None,
            Some(user_pub),
            false,
        );

        pump(&mut client, &mut srv).unwrap();
        client.accept_host_key().unwrap();
        pump(&mut client, &mut srv).unwrap();
        client.authenticate("bob", AuthMethod::PublicKeyEd25519(user_seed)).unwrap();
        pump(&mut client, &mut srv).unwrap();
        assert_eq!(client.state(), State::Authenticated);

        client.open_session().unwrap();
        pump(&mut client, &mut srv).unwrap();
        client.request_shell(80, 24).unwrap();
        pump(&mut client, &mut srv).unwrap();
        assert_eq!(client.state(), State::Active);

        client.send_data(b"whoami\r").unwrap();
        pump(&mut client, &mut srv).unwrap();
        client.send_data(b"exit\r").unwrap();
        pump(&mut client, &mut srv).unwrap();

        let mut out = String::new();
        while let Some(ev) = client.pop_event() {
            if let Event::Stdout(b) = ev {
                out.push_str(&String::from_utf8_lossy(&b));
            }
        }
        assert!(out.contains("DiscreteOS Test SSH Shell"), "got: {out}");
        assert!(out.contains("bob\n"), "got: {out}");
    }

    #[test]
    fn ssh_rejects_tampered_host_signature() {
        let mut client = SshClient::new(&[0x77u8; 64]);
        let mut srv = SshServer::new(&[0x88u8; 32], &[0x66u8; 64], "u", None, None, true);
        srv.set_tamper_signature(true);
        let err = pump(&mut client, &mut srv);
        assert_eq!(err, Err(SshError::BadHostSignature));
    }

    #[test]
    fn ssh_rejects_tampered_gcm_ciphertext() {
        let mut client = SshClient::new(&[0xA1u8; 64]);
        let mut srv = SshServer::new(&[0xB2u8; 32], &[0xC3u8; 64], "u", None, None, true);
        pump(&mut client, &mut srv).unwrap();
        client.accept_host_key().unwrap();
        let c2s = client.take_tx();
        srv.feed_rx(&c2s).unwrap();
        let mut s2c = srv.take_tx();
        // Flip a byte inside the encrypted SERVICE_ACCEPT packet.
        assert!(s2c.len() > 20);
        s2c[8] ^= 0x01;
        assert_eq!(client.feed_rx(&s2c), Err(SshError::DecryptFailed));
    }
}
