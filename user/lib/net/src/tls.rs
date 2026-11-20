//! Strict in-tree TLS 1.3 client (RFC 8446) built on `doscrypt`.
//!
//! - **Strict TLS 1.3 only**: refuses TLS 1.2 or older, rejects RFC 8446 §4.1.3 downgrade
//!   sentinels, rejects non-AEAD ciphers, and supports all three modern TLS 1.3 cipher suites:
//!   - `TLS_AES_256_GCM_SHA384` (`0x1302`, zero-table constant-time AES-256-GCM + HKDF-SHA384)
//!   - `TLS_CHACHA20_POLY1305_SHA256` (`0x1303`, constant-time ChaCha20-Poly1305 + HKDF-SHA256)
//!   - `TLS_AES_128_GCM_SHA256` (`0x1301`, zero-table constant-time AES-128-GCM + HKDF-SHA256)
//! - **Post-quantum hybrid key exchange**: offers `X25519MLKEM768` (`0x11EC`, FIPS 203 ML-KEM-768
//!   and constant-time X25519) alongside classical `X25519` (`0x001D`) in 1 RTT, with full RFC 8446
//!   `HelloRetryRequest` support.
//! - **Full authentication**: verifies the server X.509 v3 certificate chain against caller-supplied
//!   trust anchors (RSA ≥ 2048-bit enforcement, ECDSA P-256/P-384, Ed25519, SAN hostname/IP
//!   matching, validity period at `now_unix`, CA/KeyUsage/pathLen/NameConstraints, optional
//!   revocation denylist, unknown critical extension refusal) and verifies `CertificateVerify` +
//!   server `Finished`.
//! - **Sans-IO**: zero platform calls, `#![forbid(unsafe_code)]`, wipes all traffic & handshake
//!   secrets on `Drop`.

use alloc::string::String;
use alloc::vec::Vec;

use doscrypt::aes_gcm::{
    aes128_gcm_open_in_place, aes128_gcm_seal_in_place, aes256_gcm_open_in_place,
    aes256_gcm_seal_in_place,
};
use doscrypt::chacha20::{open_in_place as chacha_open, seal_in_place as chacha_seal};
use doscrypt::ct::{ct_eq, wipe_bytes};
use doscrypt::hkdf::{
    derive_secret_sha256, derive_secret_sha384, expand_label_sha256, expand_label_sha384,
    extract_sha256, extract_sha384, hmac_sha384,
};
use doscrypt::mlkem;
use doscrypt::sha2::{Sha256, Sha512, sha256, sha384};
use doscrypt::sym::hmac_sha256;
use doscrypt::x25519;
use doscrypt::x509::{self, TlsCert, TlsSigAlg, VerifyError};

pub const TLS_VERSION_1_2: u16 = 0x0303;
pub const TLS_VERSION_1_3: u16 = 0x0304;

pub const CIPHER_AES_128_GCM_SHA256: u16 = 0x1301;
pub const CIPHER_AES_256_GCM_SHA384: u16 = 0x1302;
pub const CIPHER_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

pub const GROUP_X25519: u16 = 0x001D;
pub const GROUP_X25519_MLKEM768: u16 = 0x11EC;

const CT_CHANGE_CIPHER_SPEC: u8 = 20;
const CT_ALERT: u8 = 21;
const CT_HANDSHAKE: u8 = 22;
const CT_APP_DATA: u8 = 23;

const HS_CLIENT_HELLO: u8 = 1;
const HS_SERVER_HELLO: u8 = 2;
const HS_NEW_SESSION_TICKET: u8 = 4;
const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
const HS_CERTIFICATE: u8 = 11;
const HS_CERTIFICATE_VERIFY: u8 = 15;
const HS_FINISHED: u8 = 20;
const HS_KEY_UPDATE: u8 = 24;
const HS_MESSAGE_HASH: u8 = 254;

const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_SUPPORTED_GROUPS: u16 = 0x000A;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000D;
const EXT_ALPN: u16 = 0x0010;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002B;
const EXT_COOKIE: u16 = 0x002C;
const EXT_KEY_SHARE: u16 = 0x0033;

const SIG_ECDSA_SECP256R1_SHA256: u16 = 0x0403;
const SIG_ECDSA_SECP384R1_SHA384: u16 = 0x0503;
const SIG_RSA_PSS_RSAE_SHA256: u16 = 0x0804;
const SIG_RSA_PSS_RSAE_SHA384: u16 = 0x0805;
const SIG_RSA_PSS_RSAE_SHA512: u16 = 0x0806;
const SIG_ED25519: u16 = 0x0807;

const MAX_RECORD_PLAINTEXT: usize = 16_384;
const MAX_RECORD_CIPHERTEXT: usize = MAX_RECORD_PLAINTEXT + 256;

const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherSuite {
    Aes128GcmSha256,
    Aes256GcmSha384,
    ChaCha20Poly1305Sha256,
}

impl CipherSuite {
    pub fn from_u16(id: u16) -> Option<Self> {
        match id {
            CIPHER_AES_128_GCM_SHA256 => Some(Self::Aes128GcmSha256),
            CIPHER_AES_256_GCM_SHA384 => Some(Self::Aes256GcmSha384),
            CIPHER_CHACHA20_POLY1305_SHA256 => Some(Self::ChaCha20Poly1305Sha256),
            _ => None,
        }
    }

    pub fn code(self) -> u16 {
        match self {
            Self::Aes128GcmSha256 => CIPHER_AES_128_GCM_SHA256,
            Self::Aes256GcmSha384 => CIPHER_AES_256_GCM_SHA384,
            Self::ChaCha20Poly1305Sha256 => CIPHER_CHACHA20_POLY1305_SHA256,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Aes128GcmSha256 => "TLS_AES_128_GCM_SHA256",
            Self::Aes256GcmSha384 => "TLS_AES_256_GCM_SHA384",
            Self::ChaCha20Poly1305Sha256 => "TLS_CHACHA20_POLY1305_SHA256",
        }
    }

    fn is_sha384(self) -> bool {
        matches!(self, Self::Aes256GcmSha384)
    }

    fn hash_len(self) -> usize {
        if self.is_sha384() { 48 } else { 32 }
    }

    fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            Self::Aes256GcmSha384 | Self::ChaCha20Poly1305Sha256 => 32,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyGroup {
    X25519,
    X25519MlKem768,
}

impl KeyGroup {
    pub fn name(self) -> &'static str {
        match self {
            Self::X25519 => "X25519",
            Self::X25519MlKem768 => "X25519MLKEM768",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsError {
    MalformedRecord,
    MalformedHandshake,
    DowngradeDetected,
    UnsupportedProtocol,
    UnexpectedMessage,
    BadKeyShare,
    DecryptionFailed,
    Certificate(VerifyError),
    BadCertificateVerify,
    BadFinished,
    Alert(u8),
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsState {
    WaitServerHello,
    WaitEncryptedExtensions,
    WaitCertificate,
    WaitCertVerify,
    WaitFinished,
    Connected,
    Closed,
}

/// Fixed-capacity secret holding either 32 (SHA-256) or 48 (SHA-384) bytes; zeroized on drop.
#[derive(Clone)]
struct Secret {
    buf: [u8; 48],
    len: usize,
}

impl Secret {
    const fn zero() -> Self {
        Self { buf: [0; 48], len: 0 }
    }

    fn from_32(b: [u8; 32]) -> Self {
        let mut s = Self { buf: [0; 48], len: 32 };
        s.buf[..32].copy_from_slice(&b);
        s
    }

    fn from_48(b: [u8; 48]) -> Self {
        Self { buf: b, len: 48 }
    }

    fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    fn as_32(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.buf[..32]);
        out
    }

    fn as_48(&self) -> [u8; 48] {
        self.buf
    }

    fn wipe(&mut self) {
        wipe_bytes(&mut self.buf);
        self.len = 0;
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        wipe_bytes(&mut self.buf);
    }
}

fn hkdf_extract(suite: CipherSuite, salt: &[u8], ikm: &[u8]) -> Secret {
    if suite.is_sha384() {
        Secret::from_48(extract_sha384(salt, ikm))
    } else {
        Secret::from_32(extract_sha256(salt, ikm))
    }
}

fn hkdf_expand_label(suite: CipherSuite, secret: &Secret, label: &[u8], ctx: &[u8], out: &mut [u8]) {
    if suite.is_sha384() {
        let mut s48 = secret.as_48();
        let _ = expand_label_sha384(&s48, label, ctx, out);
        wipe_bytes(&mut s48);
    } else {
        let mut s32 = secret.as_32();
        let _ = expand_label_sha256(&s32, label, ctx, out);
        wipe_bytes(&mut s32);
    }
}

fn derive_secret(suite: CipherSuite, secret: &Secret, label: &[u8], thash: &[u8]) -> Secret {
    if suite.is_sha384() {
        let mut s48 = secret.as_48();
        let mut h48 = [0u8; 48];
        h48.copy_from_slice(&thash[..48]);
        let r = Secret::from_48(derive_secret_sha384(&s48, label, &h48));
        wipe_bytes(&mut s48);
        r
    } else {
        let mut s32 = secret.as_32();
        let mut h32 = [0u8; 32];
        h32.copy_from_slice(&thash[..32]);
        let r = Secret::from_32(derive_secret_sha256(&s32, label, &h32));
        wipe_bytes(&mut s32);
        r
    }
}

fn finish_mac(suite: CipherSuite, base_secret: &Secret, thash: &[u8]) -> Secret {
    let mut fin_key = Secret { buf: [0; 48], len: suite.hash_len() };
    hkdf_expand_label(suite, base_secret, b"finished", b"", &mut fin_key.buf[..suite.hash_len()]);
    let res = if suite.is_sha384() {
        Secret::from_48(hmac_sha384(fin_key.as_slice(), &[thash]))
    } else {
        Secret::from_32(hmac_sha256(fin_key.as_slice(), &[thash]))
    };
    fin_key.wipe();
    res
}

struct TrafficKey {
    suite: CipherSuite,
    key: [u8; 32],
    iv: [u8; 12],
    seq: u64,
}

impl TrafficKey {
    fn from_secret(suite: CipherSuite, secret: &Secret) -> Self {
        let mut key = [0u8; 32];
        let mut iv = [0u8; 12];
        let klen = suite.key_len();
        hkdf_expand_label(suite, secret, b"key", b"", &mut key[..klen]);
        hkdf_expand_label(suite, secret, b"iv", b"", &mut iv);
        Self { suite, key, iv, seq: 0 }
    }

    fn nonce(&self) -> [u8; 12] {
        let mut n = self.iv;
        let sb = self.seq.to_be_bytes();
        for i in 0..8 {
            n[4 + i] ^= sb[i];
        }
        n
    }

    fn encrypt_record(&mut self, inner_type: u8, plaintext: &[u8]) -> Result<Vec<u8>, TlsError> {
        if plaintext.len() > MAX_RECORD_PLAINTEXT || self.seq == u64::MAX {
            return Err(TlsError::MalformedRecord);
        }
        let ct_len = plaintext.len() + 1 + 16;
        let mut out = Vec::with_capacity(5 + ct_len);
        out.push(CT_APP_DATA);
        out.extend_from_slice(&TLS_VERSION_1_2.to_be_bytes());
        out.extend_from_slice(&(ct_len as u16).to_be_bytes());
        let aad = [out[0], out[1], out[2], out[3], out[4]];

        let mut buf = Vec::with_capacity(plaintext.len() + 1);
        buf.extend_from_slice(plaintext);
        buf.push(inner_type);
        let nonce = self.nonce();
        let tag = match self.suite {
            CipherSuite::Aes128GcmSha256 => {
                let mut k16 = [0u8; 16];
                k16.copy_from_slice(&self.key[..16]);
                let t = aes128_gcm_seal_in_place(&k16, &nonce, &aad, &mut buf);
                wipe_bytes(&mut k16);
                t
            }
            CipherSuite::Aes256GcmSha384 => {
                aes256_gcm_seal_in_place(&self.key, &nonce, &aad, &mut buf)
            }
            CipherSuite::ChaCha20Poly1305Sha256 => {
                chacha_seal(&self.key, &nonce, &aad, &mut buf)
            }
        };
        self.seq = self.seq.wrapping_add(1);
        out.extend_from_slice(&buf);
        out.extend_from_slice(&tag);
        Ok(out)
    }

    fn decrypt_record(&mut self, aad: [u8; 5], ciphertext: &[u8]) -> Result<(u8, Vec<u8>), TlsError> {
        if ciphertext.len() < 17 || ciphertext.len() > MAX_RECORD_CIPHERTEXT || self.seq == u64::MAX {
            return Err(TlsError::MalformedRecord);
        }
        let split = ciphertext.len() - 16;
        let mut buf = ciphertext[..split].to_vec();
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&ciphertext[split..]);
        let nonce = self.nonce();
        let ok = match self.suite {
            CipherSuite::Aes128GcmSha256 => {
                let mut k16 = [0u8; 16];
                k16.copy_from_slice(&self.key[..16]);
                let r = aes128_gcm_open_in_place(&k16, &nonce, &aad, &mut buf, &tag);
                wipe_bytes(&mut k16);
                r
            }
            CipherSuite::Aes256GcmSha384 => {
                aes256_gcm_open_in_place(&self.key, &nonce, &aad, &mut buf, &tag)
            }
            CipherSuite::ChaCha20Poly1305Sha256 => {
                chacha_open(&self.key, &nonce, &aad, &mut buf, &tag)
            }
        };
        if !ok {
            return Err(TlsError::DecryptionFailed);
        }
        self.seq = self.seq.wrapping_add(1);
        while buf.last() == Some(&0) {
            buf.pop();
        }
        let inner_type = buf.pop().ok_or(TlsError::MalformedRecord)?;
        Ok((inner_type, buf))
    }
}

impl Drop for TrafficKey {
    fn drop(&mut self) {
        wipe_bytes(&mut self.key);
        wipe_bytes(&mut self.iv);
    }
}

#[derive(Clone)]
struct Transcript {
    s256: Sha256,
    s384: Sha512,
}

impl Transcript {
    fn new() -> Self {
        Self { s256: Sha256::new(), s384: Sha512::new_384() }
    }

    fn update(&mut self, data: &[u8]) {
        self.s256.update(data);
        self.s384.update(data);
    }

    /// Replace transcript with synthetic `message_hash` per RFC 8446 §4.4.1 for HelloRetryRequest.
    fn fold_for_hrr(&mut self, suite: CipherSuite) {
        let mut mh = Vec::with_capacity(52);
        mh.push(HS_MESSAGE_HASH);
        if suite.is_sha384() {
            let h = self.s384.clone().finish_384();
            push_u24(&mut mh, 48);
            mh.extend_from_slice(&h);
        } else {
            let h = self.s256.clone().finish();
            push_u24(&mut mh, 32);
            mh.extend_from_slice(&h);
        }
        *self = Self::new();
        self.update(&mh);
    }

    fn current_hash(&self, suite: CipherSuite) -> Secret {
        if suite.is_sha384() {
            Secret::from_48(self.s384.clone().finish_384())
        } else {
            Secret::from_32(self.s256.clone().finish())
        }
    }
}

fn push_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn push_u24(out: &mut Vec<u8>, v: usize) {
    out.push(((v >> 16) & 0xFF) as u8);
    out.push(((v >> 8) & 0xFF) as u8);
    out.push((v & 0xFF) as u8);
}

fn read_u16(b: &[u8], off: usize) -> Option<u16> {
    if off + 2 > b.len() {
        return None;
    }
    Some(u16::from_be_bytes([b[off], b[off + 1]]))
}

fn read_u24(b: &[u8], off: usize) -> Option<usize> {
    if off + 3 > b.len() {
        return None;
    }
    Some((usize::from(b[off]) << 16) | (usize::from(b[off + 1]) << 8) | usize::from(b[off + 2]))
}

fn wrap_handshake(hs_type: u8, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(4 + body.len());
    m.push(hs_type);
    push_u24(&mut m, body.len());
    m.extend_from_slice(body);
    m
}

fn wrap_plain_record(ct: u8, version: u16, payload: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(5 + payload.len());
    r.push(ct);
    push_u16(&mut r, version);
    push_u16(&mut r, payload.len() as u16);
    r.extend_from_slice(payload);
    r
}

fn cert_verify_content(transcript_hash: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + 34 + transcript_hash.len());
    out.resize(64, 0x20);
    out.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
    out.extend_from_slice(transcript_hash);
    out
}

#[allow(clippy::too_many_arguments)]
fn build_client_hello(
    hostname: &str,
    client_random: &[u8; 32],
    session_id: &[u8; 32],
    x25519_pub: &[u8; 32],
    mlkem_ek: Option<&[u8; mlkem::EK_LEN]>,
    include_x25519_share: bool,
    cookie: Option<&[u8]>,
    alpn: Option<&[u8]>,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(1400);
    push_u16(&mut body, TLS_VERSION_1_2);
    body.extend_from_slice(client_random);
    body.push(32);
    body.extend_from_slice(session_id);
    // Offer all three modern TLS 1.3 AEAD suites (AES-256-GCM, ChaCha20-Poly1305, AES-128-GCM).
    push_u16(&mut body, 6);
    push_u16(&mut body, CIPHER_AES_256_GCM_SHA384);
    push_u16(&mut body, CIPHER_CHACHA20_POLY1305_SHA256);
    push_u16(&mut body, CIPHER_AES_128_GCM_SHA256);
    body.push(1);
    body.push(0);

    let mut exts = Vec::with_capacity(1360);
    // SNI extension (only for DNS names, not literal IPv4 per RFC 6066 §3).
    if !hostname.is_empty() && crate::parse_ipv4(hostname).is_none() {
        let hb = hostname.as_bytes();
        let list_len = 3 + hb.len();
        push_u16(&mut exts, EXT_SERVER_NAME);
        push_u16(&mut exts, (2 + list_len) as u16);
        push_u16(&mut exts, list_len as u16);
        exts.push(0); // host_name
        push_u16(&mut exts, hb.len() as u16);
        exts.extend_from_slice(hb);
    }
    // supported_versions: TLS 1.3 only
    push_u16(&mut exts, EXT_SUPPORTED_VERSIONS);
    push_u16(&mut exts, 3);
    exts.push(2);
    push_u16(&mut exts, TLS_VERSION_1_3);
    // supported_groups: post-quantum hybrid X25519MLKEM768 preferred, classical X25519 fallback
    push_u16(&mut exts, EXT_SUPPORTED_GROUPS);
    push_u16(&mut exts, 6);
    push_u16(&mut exts, 4);
    push_u16(&mut exts, GROUP_X25519_MLKEM768);
    push_u16(&mut exts, GROUP_X25519);
    // signature_algorithms
    push_u16(&mut exts, EXT_SIGNATURE_ALGORITHMS);
    push_u16(&mut exts, 14);
    push_u16(&mut exts, 12);
    push_u16(&mut exts, SIG_ECDSA_SECP256R1_SHA256);
    push_u16(&mut exts, SIG_ECDSA_SECP384R1_SHA384);
    push_u16(&mut exts, SIG_RSA_PSS_RSAE_SHA256);
    push_u16(&mut exts, SIG_RSA_PSS_RSAE_SHA384);
    push_u16(&mut exts, SIG_RSA_PSS_RSAE_SHA512);
    push_u16(&mut exts, SIG_ED25519);
    // Optional ALPN (e.g. "http/1.1")
    if let Some(proto) = alpn
        && !proto.is_empty()
        && proto.len() <= 255
    {
        let list_len = 1 + proto.len();
        push_u16(&mut exts, EXT_ALPN);
        push_u16(&mut exts, (2 + list_len) as u16);
        push_u16(&mut exts, list_len as u16);
        exts.push(proto.len() as u8);
        exts.extend_from_slice(proto);
    }
    // Optional cookie echoed from HelloRetryRequest
    if let Some(ck) = cookie {
        push_u16(&mut exts, EXT_COOKIE);
        push_u16(&mut exts, (2 + ck.len()) as u16);
        push_u16(&mut exts, ck.len() as u16);
        exts.extend_from_slice(ck);
    }
    // key_share: X25519MLKEM768 (1216 bytes = ek || x25519_pub) and/or X25519 (32 bytes)
    let mut ks_entries = Vec::with_capacity(1260);
    if let Some(ek) = mlkem_ek {
        push_u16(&mut ks_entries, GROUP_X25519_MLKEM768);
        push_u16(&mut ks_entries, (mlkem::EK_LEN + 32) as u16);
        ks_entries.extend_from_slice(ek);
        ks_entries.extend_from_slice(x25519_pub);
    }
    if include_x25519_share {
        push_u16(&mut ks_entries, GROUP_X25519);
        push_u16(&mut ks_entries, 32);
        ks_entries.extend_from_slice(x25519_pub);
    }
    push_u16(&mut exts, EXT_KEY_SHARE);
    push_u16(&mut exts, (2 + ks_entries.len()) as u16);
    push_u16(&mut exts, ks_entries.len() as u16);
    exts.extend_from_slice(&ks_entries);

    push_u16(&mut body, exts.len() as u16);
    body.extend_from_slice(&exts);
    wrap_handshake(HS_CLIENT_HELLO, &body)
}

pub struct TlsClient {
    state: TlsState,
    hostname: String,
    trust_anchors: Vec<Vec<u8>>,
    revoked_sha256: Vec<[u8; 32]>,
    alpn: Option<Vec<u8>>,
    now_unix: i64,
    client_random: [u8; 32],
    legacy_session_id: [u8; 32],
    client_x25519_priv: [u8; 32],
    client_x25519_pub: [u8; 32],
    client_mlkem_ek: [u8; mlkem::EK_LEN],
    client_mlkem_dk: Option<mlkem::DecapsKey>,
    hrr_seen: bool,
    cipher: Option<CipherSuite>,
    group: Option<KeyGroup>,
    transcript: Transcript,
    c_hs_secret: Secret,
    s_hs_secret: Secret,
    master_secret: Secret,
    c_ap_secret: Secret,
    s_ap_secret: Secret,
    rx_key: Option<TrafficKey>,
    tx_key: Option<TrafficKey>,
    leaf_der: Vec<u8>,
    rx_wire: Vec<u8>,
    hs_buf: Vec<u8>,
    tx_wire: Vec<u8>,
    app_rx: Vec<u8>,
}

impl Drop for TlsClient {
    fn drop(&mut self) {
        wipe_bytes(&mut self.client_x25519_priv);
        self.client_mlkem_dk = None;
        self.c_hs_secret.wipe();
        self.s_hs_secret.wipe();
        self.master_secret.wipe();
        self.c_ap_secret.wipe();
        self.s_ap_secret.wipe();
    }
}

impl TlsClient {
    /// Create a new TLS 1.3 client with post-quantum hybrid `X25519MLKEM768` + classical `X25519`
    /// and all three modern AEAD cipher suites.
    ///
    /// `random_160` provides 160 fresh CSPRNG bytes:
    /// - `[0..32]` client random
    /// - `[32..64]` legacy session id
    /// - `[64..96]` X25519 private key
    /// - `[96..160]` ML-KEM-768 `(d || z)` keygen seed
    pub fn new(
        hostname: &str,
        trust_anchors: Vec<Vec<u8>>,
        now_unix: i64,
        random_160: &[u8; 160],
    ) -> Self {
        Self::new_with_options(hostname, trust_anchors, Vec::new(), None, now_unix, random_160)
    }

    /// Create a TLS 1.3 client with optional certificate SHA-256 revocation denylist and ALPN.
    pub fn new_with_options(
        hostname: &str,
        trust_anchors: Vec<Vec<u8>>,
        revoked_sha256: Vec<[u8; 32]>,
        alpn: Option<&[u8]>,
        now_unix: i64,
        random_160: &[u8; 160],
    ) -> Self {
        let mut client_random = [0u8; 32];
        let mut session_id = [0u8; 32];
        let mut x25519_priv = [0u8; 32];
        let mut mlkem_seed = [0u8; 64];
        client_random.copy_from_slice(&random_160[0..32]);
        session_id.copy_from_slice(&random_160[32..64]);
        x25519_priv.copy_from_slice(&random_160[64..96]);
        mlkem_seed.copy_from_slice(&random_160[96..160]);

        let x25519_pub = x25519::public_key(&x25519_priv);
        let (mlkem_ek, mlkem_dk) = mlkem::keygen(&mlkem_seed);
        wipe_bytes(&mut mlkem_seed);

        let hs = build_client_hello(
            hostname,
            &client_random,
            &session_id,
            &x25519_pub,
            Some(&mlkem_ek),
            true,
            None,
            alpn,
        );
        let mut transcript = Transcript::new();
        transcript.update(&hs);
        let rec = wrap_plain_record(CT_HANDSHAKE, 0x0301, &hs);

        Self {
            state: TlsState::WaitServerHello,
            hostname: String::from(hostname),
            trust_anchors,
            revoked_sha256,
            alpn: alpn.map(|p| p.to_vec()),
            now_unix,
            client_random,
            legacy_session_id: session_id,
            client_x25519_priv: x25519_priv,
            client_x25519_pub: x25519_pub,
            client_mlkem_ek: mlkem_ek,
            client_mlkem_dk: Some(mlkem_dk),
            hrr_seen: false,
            cipher: None,
            group: None,
            transcript,
            c_hs_secret: Secret::zero(),
            s_hs_secret: Secret::zero(),
            master_secret: Secret::zero(),
            c_ap_secret: Secret::zero(),
            s_ap_secret: Secret::zero(),
            rx_key: None,
            tx_key: None,
            leaf_der: Vec::new(),
            rx_wire: Vec::new(),
            hs_buf: Vec::new(),
            tx_wire: rec,
            app_rx: Vec::new(),
        }
    }

    pub fn state(&self) -> TlsState {
        self.state
    }

    pub fn is_connected(&self) -> bool {
        self.state == TlsState::Connected
    }

    pub fn negotiated_cipher(&self) -> Option<CipherSuite> {
        self.cipher
    }

    pub fn negotiated_group(&self) -> Option<KeyGroup> {
        self.group
    }

    pub fn take_tx(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.tx_wire)
    }

    pub fn read_app(&mut self, out: &mut [u8]) -> usize {
        let take = out.len().min(self.app_rx.len());
        out[..take].copy_from_slice(&self.app_rx[..take]);
        self.app_rx.drain(..take);
        take
    }

    pub fn write_app(&mut self, data: &[u8]) -> Result<(), TlsError> {
        if self.state != TlsState::Connected {
            return Err(TlsError::UnexpectedMessage);
        }
        let tx = self.tx_key.as_mut().ok_or(TlsError::UnexpectedMessage)?;
        for chunk in data.chunks(MAX_RECORD_PLAINTEXT) {
            let rec = tx.encrypt_record(CT_APP_DATA, chunk)?;
            self.tx_wire.extend_from_slice(&rec);
        }
        Ok(())
    }

    pub fn close(&mut self) {
        if self.state == TlsState::Connected
            && let Some(tx) = self.tx_key.as_mut()
            && let Ok(rec) = tx.encrypt_record(CT_ALERT, &[1, 0])
        {
            self.tx_wire.extend_from_slice(&rec);
        }
        self.state = TlsState::Closed;
    }

    /// Feed raw bytes received from the TCP stream into the TLS 1.3 state machine.
    pub fn feed_rx(&mut self, data: &[u8]) -> Result<(), TlsError> {
        if self.state == TlsState::Closed {
            return Err(TlsError::Closed);
        }
        self.rx_wire.extend_from_slice(data);
        loop {
            if self.rx_wire.len() < 5 {
                return Ok(());
            }
            let ct = self.rx_wire[0];
            let ver = u16::from_be_bytes([self.rx_wire[1], self.rx_wire[2]]);
            let len = usize::from(u16::from_be_bytes([self.rx_wire[3], self.rx_wire[4]]));
            if len > MAX_RECORD_CIPHERTEXT || (ver != TLS_VERSION_1_2 && ver != 0x0301) {
                return Err(TlsError::MalformedRecord);
            }
            if self.rx_wire.len() < 5 + len {
                return Ok(());
            }
            let aad = [self.rx_wire[0], self.rx_wire[1], self.rx_wire[2], self.rx_wire[3], self.rx_wire[4]];
            let payload: Vec<u8> = self.rx_wire.drain(..5 + len).skip(5).collect();

            match ct {
                CT_CHANGE_CIPHER_SPEC => {
                    if payload != [1] || self.state == TlsState::Connected {
                        return Err(TlsError::MalformedRecord);
                    }
                }
                CT_ALERT => {
                    if payload.len() != 2 {
                        return Err(TlsError::MalformedRecord);
                    }
                    if payload[1] == 0 {
                        self.state = TlsState::Closed;
                        return Ok(());
                    }
                    return Err(TlsError::Alert(payload[1]));
                }
                CT_HANDSHAKE => {
                    if self.state != TlsState::WaitServerHello {
                        return Err(TlsError::UnexpectedMessage);
                    }
                    self.hs_buf.extend_from_slice(&payload);
                    self.process_handshake_messages()?;
                }
                CT_APP_DATA => {
                    let rx = self.rx_key.as_mut().ok_or(TlsError::UnexpectedMessage)?;
                    let (inner_type, plain) = rx.decrypt_record(aad, &payload)?;
                    match inner_type {
                        CT_HANDSHAKE => {
                            self.hs_buf.extend_from_slice(&plain);
                            self.process_handshake_messages()?;
                        }
                        CT_APP_DATA => {
                            if self.state != TlsState::Connected {
                                return Err(TlsError::UnexpectedMessage);
                            }
                            self.app_rx.extend_from_slice(&plain);
                        }
                        CT_ALERT => {
                            if plain.len() != 2 {
                                return Err(TlsError::MalformedRecord);
                            }
                            if plain[1] == 0 {
                                self.state = TlsState::Closed;
                                return Ok(());
                            }
                            return Err(TlsError::Alert(plain[1]));
                        }
                        _ => return Err(TlsError::MalformedRecord),
                    }
                }
                _ => return Err(TlsError::MalformedRecord),
            }
        }
    }

    fn process_handshake_messages(&mut self) -> Result<(), TlsError> {
        loop {
            if self.hs_buf.len() < 4 {
                return Ok(());
            }
            let hs_type = self.hs_buf[0];
            let len = read_u24(&self.hs_buf, 1).ok_or(TlsError::MalformedHandshake)?;
            if len > 65_536 {
                return Err(TlsError::MalformedHandshake);
            }
            if self.hs_buf.len() < 4 + len {
                return Ok(());
            }
            let full_msg: Vec<u8> = self.hs_buf.drain(..4 + len).collect();
            let body = &full_msg[4..];

            match (self.state, hs_type) {
                (TlsState::WaitServerHello, HS_SERVER_HELLO) => {
                    self.on_server_hello(&full_msg, body)?;
                }
                (TlsState::WaitEncryptedExtensions, HS_ENCRYPTED_EXTENSIONS) => {
                    let ext_len = usize::from(read_u16(body, 0).ok_or(TlsError::MalformedHandshake)?);
                    if 2 + ext_len != body.len() {
                        return Err(TlsError::MalformedHandshake);
                    }
                    self.transcript.update(&full_msg);
                    self.state = TlsState::WaitCertificate;
                }
                (TlsState::WaitCertificate, HS_CERTIFICATE) => {
                    self.on_certificate(&full_msg, body)?;
                }
                (TlsState::WaitCertVerify, HS_CERTIFICATE_VERIFY) => {
                    self.on_certificate_verify(&full_msg, body)?;
                }
                (TlsState::WaitFinished, HS_FINISHED) => {
                    self.on_server_finished(&full_msg, body)?;
                }
                (TlsState::Connected, HS_NEW_SESSION_TICKET) => {}
                (TlsState::Connected, HS_KEY_UPDATE) => {
                    if body.len() != 1 || body[0] > 1 {
                        return Err(TlsError::MalformedHandshake);
                    }
                    let suite = self.cipher.ok_or(TlsError::UnexpectedMessage)?;
                    let hlen = suite.hash_len();
                    let mut next_s = Secret { buf: [0; 48], len: hlen };
                    hkdf_expand_label(suite, &self.s_ap_secret, b"traffic upd", b"", &mut next_s.buf[..hlen]);
                    self.s_ap_secret = next_s;
                    self.rx_key = Some(TrafficKey::from_secret(suite, &self.s_ap_secret));
                    if body[0] == 1 {
                        let ku = wrap_handshake(HS_KEY_UPDATE, &[0]);
                        if let Some(tx) = self.tx_key.as_mut() {
                            let rec = tx.encrypt_record(CT_HANDSHAKE, &ku)?;
                            self.tx_wire.extend_from_slice(&rec);
                        }
                        let mut next_c = Secret { buf: [0; 48], len: hlen };
                        hkdf_expand_label(suite, &self.c_ap_secret, b"traffic upd", b"", &mut next_c.buf[..hlen]);
                        self.c_ap_secret = next_c;
                        self.tx_key = Some(TrafficKey::from_secret(suite, &self.c_ap_secret));
                    }
                }
                _ => return Err(TlsError::UnexpectedMessage),
            }
        }
    }

    fn on_server_hello(&mut self, full_msg: &[u8], body: &[u8]) -> Result<(), TlsError> {
        if body.len() < 38 {
            return Err(TlsError::MalformedHandshake);
        }
        let legacy_ver = read_u16(body, 0).ok_or(TlsError::MalformedHandshake)?;
        if legacy_ver != TLS_VERSION_1_2 {
            return Err(TlsError::UnsupportedProtocol);
        }
        let random = &body[2..34];
        // RFC 8446 §4.1.3 downgrade detection.
        if &random[24..32] == b"DOWNGRD\x01" || &random[24..32] == b"DOWNGRD\x00" {
            return Err(TlsError::DowngradeDetected);
        }
        let is_hrr = random == HRR_RANDOM;
        let sid_len = usize::from(body[34]);
        let mut off = 35 + sid_len;
        if off + 5 > body.len() {
            return Err(TlsError::MalformedHandshake);
        }
        if sid_len != self.legacy_session_id.len() || body[35..35 + sid_len] != self.legacy_session_id[..] {
            return Err(TlsError::MalformedHandshake);
        }
        let cipher_id = read_u16(body, off).ok_or(TlsError::MalformedHandshake)?;
        let comp = body[off + 2];
        let suite = CipherSuite::from_u16(cipher_id).ok_or(TlsError::UnsupportedProtocol)?;
        if comp != 0 {
            return Err(TlsError::UnsupportedProtocol);
        }
        if let Some(prev) = self.cipher
            && prev != suite
        {
            return Err(TlsError::MalformedHandshake);
        }
        off += 3;
        let ext_len = usize::from(read_u16(body, off).ok_or(TlsError::MalformedHandshake)?);
        off += 2;
        if off + ext_len != body.len() {
            return Err(TlsError::MalformedHandshake);
        }

        let mut got_v13 = false;
        let mut hrr_group: Option<u16> = None;
        let mut hrr_cookie: Option<Vec<u8>> = None;
        let mut ks_group: Option<KeyGroup> = None;
        let mut ks_bytes: Option<&[u8]> = None;

        let end = off + ext_len;
        while off < end {
            let etype = read_u16(body, off).ok_or(TlsError::MalformedHandshake)?;
            let elen = usize::from(read_u16(body, off + 2).ok_or(TlsError::MalformedHandshake)?);
            off += 4;
            if off + elen > end {
                return Err(TlsError::MalformedHandshake);
            }
            let edata = &body[off..off + elen];
            off += elen;
            match etype {
                EXT_SUPPORTED_VERSIONS => {
                    if elen != 2 || read_u16(edata, 0) != Some(TLS_VERSION_1_3) {
                        return Err(TlsError::UnsupportedProtocol);
                    }
                    got_v13 = true;
                }
                EXT_COOKIE if is_hrr => {
                    let clen = usize::from(read_u16(edata, 0).ok_or(TlsError::MalformedHandshake)?);
                    if 2 + clen != elen || clen == 0 {
                        return Err(TlsError::MalformedHandshake);
                    }
                    hrr_cookie = Some(edata[2..].to_vec());
                }
                EXT_KEY_SHARE if is_hrr => {
                    if elen != 2 {
                        return Err(TlsError::BadKeyShare);
                    }
                    hrr_group = read_u16(edata, 0);
                }
                EXT_KEY_SHARE => {
                    if elen < 4 {
                        return Err(TlsError::BadKeyShare);
                    }
                    let grp = read_u16(edata, 0).ok_or(TlsError::BadKeyShare)?;
                    let klen = usize::from(read_u16(edata, 2).ok_or(TlsError::BadKeyShare)?);
                    if 4 + klen != elen {
                        return Err(TlsError::BadKeyShare);
                    }
                    match (grp, klen) {
                        (GROUP_X25519, 32) => {
                            ks_group = Some(KeyGroup::X25519);
                            ks_bytes = Some(&edata[4..]);
                        }
                        (GROUP_X25519_MLKEM768, n) if n == mlkem::CT_LEN + 32 => {
                            ks_group = Some(KeyGroup::X25519MlKem768);
                            ks_bytes = Some(&edata[4..]);
                        }
                        _ => return Err(TlsError::BadKeyShare),
                    }
                }
                _ => {}
            }
        }
        if !got_v13 {
            return Err(TlsError::UnsupportedProtocol);
        }

        if is_hrr {
            if self.hrr_seen {
                return Err(TlsError::UnexpectedMessage);
            }
            self.hrr_seen = true;
            self.cipher = Some(suite);
            let want_mlkem = match hrr_group {
                Some(GROUP_X25519_MLKEM768) => true,
                Some(GROUP_X25519) => false,
                None => true, // cookie-only HRR
                _ => return Err(TlsError::BadKeyShare),
            };
            self.transcript.fold_for_hrr(suite);
            self.transcript.update(full_msg);
            let ch2 = build_client_hello(
                &self.hostname,
                &self.client_random,
                &self.legacy_session_id,
                &self.client_x25519_pub,
                if want_mlkem { Some(&self.client_mlkem_ek) } else { None },
                !want_mlkem || hrr_group.is_none(),
                hrr_cookie.as_deref(),
                self.alpn.as_deref(),
            );
            self.transcript.update(&ch2);
            self.tx_wire.extend_from_slice(&wrap_plain_record(CT_HANDSHAKE, TLS_VERSION_1_2, &ch2));
            return Ok(());
        }

        let group = ks_group.ok_or(TlsError::BadKeyShare)?;
        let ks = ks_bytes.ok_or(TlsError::BadKeyShare)?;
        let mut shared_buf = [0u8; 64];
        let shared_len = match group {
            KeyGroup::X25519 => {
                let mut peer_pub = [0u8; 32];
                peer_pub.copy_from_slice(ks);
                let ss = x25519::diffie_hellman(&self.client_x25519_priv, &peer_pub)
                    .ok_or(TlsError::BadKeyShare)?;
                shared_buf[..32].copy_from_slice(&ss);
                32
            }
            KeyGroup::X25519MlKem768 => {
                // draft-ietf-tls-ecdhe-mlkem: server key_share = ML-KEM-768 ct (1088) || X25519 pub (32);
                // shared_secret = ML-KEM-768 ss (32) || X25519 ss (32).
                let dk = self.client_mlkem_dk.as_ref().ok_or(TlsError::BadKeyShare)?;
                let mut ct = [0u8; mlkem::CT_LEN];
                ct.copy_from_slice(&ks[..mlkem::CT_LEN]);
                let mut peer_pub = [0u8; 32];
                peer_pub.copy_from_slice(&ks[mlkem::CT_LEN..]);
                let pq_ss = mlkem::decaps(dk, &ct);
                let x_ss = x25519::diffie_hellman(&self.client_x25519_priv, &peer_pub)
                    .ok_or(TlsError::BadKeyShare)?;
                shared_buf[..32].copy_from_slice(&pq_ss);
                shared_buf[32..64].copy_from_slice(&x_ss);
                64
            }
        };
        wipe_bytes(&mut self.client_x25519_priv);
        self.client_mlkem_dk = None;
        self.cipher = Some(suite);
        self.group = Some(group);

        self.transcript.update(full_msg);
        let ch_sh_hash = self.transcript.current_hash(suite);

        // RFC 8446 §7.1 Key Schedule (SHA-256 or SHA-384 depending on negotiated cipher suite).
        let zeros = [0u8; 48];
        let hlen = suite.hash_len();
        let empty_hash_buf = if suite.is_sha384() {
            Secret::from_48(sha384(b""))
        } else {
            Secret::from_32(sha256(b""))
        };
        let early_secret = hkdf_extract(suite, &[], &zeros[..hlen]);
        let derived_early = derive_secret(suite, &early_secret, b"derived", empty_hash_buf.as_slice());
        let mut hs_secret = hkdf_extract(suite, derived_early.as_slice(), &shared_buf[..shared_len]);
        wipe_bytes(&mut shared_buf);

        self.c_hs_secret = derive_secret(suite, &hs_secret, b"c hs traffic", ch_sh_hash.as_slice());
        self.s_hs_secret = derive_secret(suite, &hs_secret, b"s hs traffic", ch_sh_hash.as_slice());
        let derived_hs = derive_secret(suite, &hs_secret, b"derived", empty_hash_buf.as_slice());
        hs_secret.wipe();
        self.master_secret = hkdf_extract(suite, derived_hs.as_slice(), &zeros[..hlen]);

        self.rx_key = Some(TrafficKey::from_secret(suite, &self.s_hs_secret));
        self.tx_key = Some(TrafficKey::from_secret(suite, &self.c_hs_secret));
        self.state = TlsState::WaitEncryptedExtensions;
        Ok(())
    }

    fn on_certificate(&mut self, full_msg: &[u8], body: &[u8]) -> Result<(), TlsError> {
        if body.len() < 4 {
            return Err(TlsError::MalformedHandshake);
        }
        let ctx_len = usize::from(body[0]);
        let mut off = 1 + ctx_len;
        if off + 3 > body.len() {
            return Err(TlsError::MalformedHandshake);
        }
        let list_len = read_u24(body, off).ok_or(TlsError::MalformedHandshake)?;
        off += 3;
        if off + list_len != body.len() {
            return Err(TlsError::MalformedHandshake);
        }
        let mut chain: Vec<&[u8]> = Vec::new();
        let end = off + list_len;
        while off < end {
            let clen = read_u24(body, off).ok_or(TlsError::MalformedHandshake)?;
            off += 3;
            if clen == 0 || off + clen + 2 > end {
                return Err(TlsError::MalformedHandshake);
            }
            chain.push(&body[off..off + clen]);
            off += clen;
            let ext_len = usize::from(read_u16(body, off).ok_or(TlsError::MalformedHandshake)?);
            off += 2;
            if off + ext_len > end {
                return Err(TlsError::MalformedHandshake);
            }
            off += ext_len;
        }
        let anchors: Vec<&[u8]> = self.trust_anchors.iter().map(Vec::as_slice).collect();
        x509::verify_chain_with_revoked(
            &chain,
            &anchors,
            &self.revoked_sha256,
            &self.hostname,
            self.now_unix,
        )
        .map_err(TlsError::Certificate)?;
        self.leaf_der = chain[0].to_vec();
        self.transcript.update(full_msg);
        self.state = TlsState::WaitCertVerify;
        Ok(())
    }

    fn on_certificate_verify(&mut self, full_msg: &[u8], body: &[u8]) -> Result<(), TlsError> {
        if body.len() < 4 {
            return Err(TlsError::MalformedHandshake);
        }
        let suite = self.cipher.ok_or(TlsError::UnexpectedMessage)?;
        let scheme = read_u16(body, 0).ok_or(TlsError::MalformedHandshake)?;
        let sig_len = usize::from(read_u16(body, 2).ok_or(TlsError::MalformedHandshake)?);
        if 4 + sig_len != body.len() {
            return Err(TlsError::MalformedHandshake);
        }
        let sig = &body[4..];
        let alg = match scheme {
            SIG_RSA_PSS_RSAE_SHA256 => TlsSigAlg::RsaPssSha256,
            SIG_RSA_PSS_RSAE_SHA384 => TlsSigAlg::RsaPssSha384,
            SIG_RSA_PSS_RSAE_SHA512 => TlsSigAlg::RsaPssSha512,
            SIG_ECDSA_SECP256R1_SHA256 => TlsSigAlg::EcdsaP256Sha256,
            SIG_ECDSA_SECP384R1_SHA384 => TlsSigAlg::EcdsaP384Sha384,
            SIG_ED25519 => TlsSigAlg::Ed25519,
            _ => return Err(TlsError::BadCertificateVerify),
        };
        let leaf: TlsCert<'_> = x509::parse_tls(&self.leaf_der).map_err(TlsError::Certificate)?;
        let thash = self.transcript.current_hash(suite);
        let content = cert_verify_content(thash.as_slice());
        if !leaf.verify_signature(alg, &content, sig) {
            return Err(TlsError::BadCertificateVerify);
        }
        self.transcript.update(full_msg);
        self.state = TlsState::WaitFinished;
        Ok(())
    }

    fn on_server_finished(&mut self, full_msg: &[u8], body: &[u8]) -> Result<(), TlsError> {
        let suite = self.cipher.ok_or(TlsError::UnexpectedMessage)?;
        if body.len() != suite.hash_len() {
            return Err(TlsError::MalformedHandshake);
        }
        let thash = self.transcript.current_hash(suite);
        let expected = finish_mac(suite, &self.s_hs_secret, thash.as_slice());
        if !ct_eq(expected.as_slice(), body) {
            return Err(TlsError::BadFinished);
        }
        self.transcript.update(full_msg);
        let sf_hash = self.transcript.current_hash(suite);

        // Derive application traffic secrets.
        self.c_ap_secret = derive_secret(suite, &self.master_secret, b"c ap traffic", sf_hash.as_slice());
        self.s_ap_secret = derive_secret(suite, &self.master_secret, b"s ap traffic", sf_hash.as_slice());

        // Build & encrypt Client Finished with client handshake traffic key.
        let verify_data = finish_mac(suite, &self.c_hs_secret, sf_hash.as_slice());
        let c_fin = wrap_handshake(HS_FINISHED, verify_data.as_slice());
        let tx_hs = self.tx_key.as_mut().ok_or(TlsError::UnexpectedMessage)?;
        let rec = tx_hs.encrypt_record(CT_HANDSHAKE, &c_fin)?;
        self.tx_wire.extend_from_slice(&rec);

        // Switch both directions to application traffic keys and wipe handshake secrets.
        self.rx_key = Some(TrafficKey::from_secret(suite, &self.s_ap_secret));
        self.tx_key = Some(TrafficKey::from_secret(suite, &self.c_ap_secret));
        self.c_hs_secret.wipe();
        self.s_hs_secret.wipe();
        self.master_secret.wipe();
        self.state = TlsState::Connected;
        Ok(())
    }
}

// ---- Minimal RFC 8446 TLS 1.3 test server (host tests & QEMU offline test harness) --------------

#[cfg(any(test, feature = "tls-server"))]
pub mod server {
    use super::*;
    use alloc::vec;
    use doscrypt::ed25519::SigningKey;
    use doscrypt::rsa::{self, Hash, PublicKey};

    #[derive(Clone)]
    pub enum ServerKey {
        Ed25519([u8; 32]),
        RsaPssSha256 { n: Vec<u8>, e: u32, d: Vec<u8> },
    }

    pub struct TlsServer {
        cert_chain: Vec<Vec<u8>>,
        key: ServerKey,
        preferred_cipher: CipherSuite,
        prefer_pq: bool,
        force_hrr: bool,
        hrr_sent: bool,
        server_x25519_priv: [u8; 32],
        server_random: [u8; 32],
        mlkem_m: [u8; 32],
        transcript: Transcript,
        rx_wire: Vec<u8>,
        tx_wire: Vec<u8>,
        app_rx: Vec<u8>,
        rx_key: Option<TrafficKey>,
        tx_key: Option<TrafficKey>,
        c_hs_secret: Secret,
        c_ap_secret: Secret,
        s_ap_secret: Secret,
        sf_hash: Secret,
        pub connected: bool,
        pub closed: bool,
        wait_client_fin: bool,
    }

    impl TlsServer {
        pub fn new(cert_chain: Vec<Vec<u8>>, key: ServerKey, random_64: &[u8; 64]) -> Self {
            Self::new_with_config(
                cert_chain,
                key,
                CipherSuite::Aes256GcmSha384,
                true,
                false,
                random_64,
            )
        }

        pub fn new_with_config(
            cert_chain: Vec<Vec<u8>>,
            key: ServerKey,
            preferred_cipher: CipherSuite,
            prefer_pq: bool,
            force_hrr: bool,
            random_64: &[u8; 64],
        ) -> Self {
            let mut server_random = [0u8; 32];
            let mut x25519_priv = [0u8; 32];
            server_random.copy_from_slice(&random_64[0..32]);
            x25519_priv.copy_from_slice(&random_64[32..64]);
            let mlkem_m = sha256(random_64);
            Self {
                cert_chain,
                key,
                preferred_cipher,
                prefer_pq,
                force_hrr,
                hrr_sent: false,
                server_x25519_priv: x25519_priv,
                server_random,
                mlkem_m,
                transcript: Transcript::new(),
                rx_wire: Vec::new(),
                tx_wire: Vec::new(),
                app_rx: Vec::new(),
                rx_key: None,
                tx_key: None,
                c_hs_secret: Secret::zero(),
                c_ap_secret: Secret::zero(),
                s_ap_secret: Secret::zero(),
                sf_hash: Secret::zero(),
                connected: false,
                closed: false,
                wait_client_fin: false,
            }
        }

        pub fn take_tx(&mut self) -> Vec<u8> {
            core::mem::take(&mut self.tx_wire)
        }

        pub fn read_app(&mut self, out: &mut [u8]) -> usize {
            let take = out.len().min(self.app_rx.len());
            out[..take].copy_from_slice(&self.app_rx[..take]);
            self.app_rx.drain(..take);
            take
        }

        pub fn write_app(&mut self, data: &[u8]) -> Result<(), TlsError> {
            if !self.connected {
                return Err(TlsError::UnexpectedMessage);
            }
            let tx = self.tx_key.as_mut().ok_or(TlsError::UnexpectedMessage)?;
            for chunk in data.chunks(MAX_RECORD_PLAINTEXT) {
                let rec = tx.encrypt_record(CT_APP_DATA, chunk)?;
                self.tx_wire.extend_from_slice(&rec);
            }
            Ok(())
        }

        pub fn feed_rx(&mut self, data: &[u8]) -> Result<(), TlsError> {
            self.rx_wire.extend_from_slice(data);
            loop {
                if self.rx_wire.len() < 5 {
                    return Ok(());
                }
                let ct = self.rx_wire[0];
                let len = usize::from(u16::from_be_bytes([self.rx_wire[3], self.rx_wire[4]]));
                if len > MAX_RECORD_CIPHERTEXT {
                    return Err(TlsError::MalformedRecord);
                }
                if self.rx_wire.len() < 5 + len {
                    return Ok(());
                }
                let aad = [self.rx_wire[0], self.rx_wire[1], self.rx_wire[2], self.rx_wire[3], self.rx_wire[4]];
                let payload: Vec<u8> = self.rx_wire.drain(..5 + len).skip(5).collect();

                if !self.wait_client_fin && !self.connected {
                    if ct != CT_HANDSHAKE || payload.len() < 4 || payload[0] != HS_CLIENT_HELLO {
                        return Err(TlsError::UnexpectedMessage);
                    }
                    self.handle_client_hello(&payload)?;
                } else if ct == CT_APP_DATA {
                    let rx = self.rx_key.as_mut().ok_or(TlsError::UnexpectedMessage)?;
                    let (inner_type, plain) = rx.decrypt_record(aad, &payload)?;
                    match inner_type {
                        CT_HANDSHAKE if self.wait_client_fin => {
                            let hlen = self.preferred_cipher.hash_len();
                            if plain.len() != 4 + hlen || plain[0] != HS_FINISHED {
                                return Err(TlsError::BadFinished);
                            }
                            let expected = finish_mac(
                                self.preferred_cipher,
                                &self.c_hs_secret,
                                self.sf_hash.as_slice(),
                            );
                            if !ct_eq(expected.as_slice(), &plain[4..4 + hlen]) {
                                return Err(TlsError::BadFinished);
                            }
                            self.rx_key = Some(TrafficKey::from_secret(
                                self.preferred_cipher,
                                &self.c_ap_secret,
                            ));
                            self.wait_client_fin = false;
                            self.connected = true;
                        }
                        CT_APP_DATA if self.connected => {
                            self.app_rx.extend_from_slice(&plain);
                        }
                        CT_ALERT => {
                            self.closed = true;
                            return Ok(());
                        }
                        _ => return Err(TlsError::UnexpectedMessage),
                    }
                }
            }
        }

        fn handle_client_hello(&mut self, ch_msg: &[u8]) -> Result<(), TlsError> {
            let body = &ch_msg[4..];
            if body.len() < 39 {
                return Err(TlsError::MalformedHandshake);
            }
            let sid_len = usize::from(body[34]);
            let mut off = 35 + sid_len;
            if off + 2 > body.len() {
                return Err(TlsError::MalformedHandshake);
            }
            let sid = &body[35..35 + sid_len];
            let cs_len = usize::from(read_u16(body, off).ok_or(TlsError::MalformedHandshake)?);
            off += 2 + cs_len;
            if off >= body.len() {
                return Err(TlsError::MalformedHandshake);
            }
            let comp_len = usize::from(body[off]);
            off += 1 + comp_len;
            let ext_len = usize::from(read_u16(body, off).ok_or(TlsError::MalformedHandshake)?);
            off += 2;
            if off + ext_len > body.len() {
                return Err(TlsError::MalformedHandshake);
            }

            let mut client_x25519: Option<[u8; 32]> = None;
            let mut client_pq: Option<([u8; mlkem::EK_LEN], [u8; 32])> = None;
            let end = off + ext_len;
            while off < end {
                let etype = read_u16(body, off).ok_or(TlsError::MalformedHandshake)?;
                let elen = usize::from(read_u16(body, off + 2).ok_or(TlsError::MalformedHandshake)?);
                off += 4;
                if off + elen > end {
                    return Err(TlsError::MalformedHandshake);
                }
                if etype == EXT_KEY_SHARE && elen >= 2 {
                    let ks_end = off + elen;
                    let mut p = off + 2;
                    while p + 4 <= ks_end {
                        let grp = read_u16(body, p).unwrap_or(0);
                        let klen = usize::from(read_u16(body, p + 2).unwrap_or(0));
                        p += 4;
                        if grp == GROUP_X25519 && klen == 32 && p + 32 <= ks_end {
                            let mut pk = [0u8; 32];
                            pk.copy_from_slice(&body[p..p + 32]);
                            client_x25519 = Some(pk);
                        } else if grp == GROUP_X25519_MLKEM768
                            && klen == mlkem::EK_LEN + 32
                            && p + klen <= ks_end
                        {
                            let mut ek = [0u8; mlkem::EK_LEN];
                            let mut pk = [0u8; 32];
                            ek.copy_from_slice(&body[p..p + mlkem::EK_LEN]);
                            pk.copy_from_slice(&body[p + mlkem::EK_LEN..p + klen]);
                            client_pq = Some((ek, pk));
                        }
                        p += klen;
                    }
                }
                off += elen;
            }

            let suite = self.preferred_cipher;
            if self.force_hrr && !self.hrr_sent {
                self.hrr_sent = true;
                self.transcript = Transcript::new();
                self.transcript.update(ch_msg);
                self.transcript.fold_for_hrr(suite);
                let mut hrr_body = Vec::with_capacity(96);
                push_u16(&mut hrr_body, TLS_VERSION_1_2);
                hrr_body.extend_from_slice(&HRR_RANDOM);
                hrr_body.push(sid.len() as u8);
                hrr_body.extend_from_slice(sid);
                push_u16(&mut hrr_body, suite.code());
                hrr_body.push(0);
                let mut hexts = Vec::with_capacity(32);
                push_u16(&mut hexts, EXT_SUPPORTED_VERSIONS);
                push_u16(&mut hexts, 2);
                push_u16(&mut hexts, TLS_VERSION_1_3);
                push_u16(&mut hexts, EXT_KEY_SHARE);
                push_u16(&mut hexts, 2);
                push_u16(&mut hexts, if self.prefer_pq { GROUP_X25519_MLKEM768 } else { GROUP_X25519 });
                push_u16(&mut hexts, EXT_COOKIE);
                push_u16(&mut hexts, 6);
                push_u16(&mut hexts, 4);
                hexts.extend_from_slice(b"DOS!");
                push_u16(&mut hrr_body, hexts.len() as u16);
                hrr_body.extend_from_slice(&hexts);
                let hrr = wrap_handshake(HS_SERVER_HELLO, &hrr_body);
                self.transcript.update(&hrr);
                self.tx_wire.extend_from_slice(&wrap_plain_record(CT_HANDSHAKE, TLS_VERSION_1_2, &hrr));
                return Ok(());
            }

            let server_pub = x25519::public_key(&self.server_x25519_priv);
            let (grp_code, server_ks, shared): (u16, Vec<u8>, Vec<u8>) = if self.prefer_pq
                && let Some((ek, cpub)) = client_pq
            {
                let (ct, pq_ss) = mlkem::encaps(&ek, &self.mlkem_m).ok_or(TlsError::BadKeyShare)?;
                let x_ss = x25519::diffie_hellman(&self.server_x25519_priv, &cpub)
                    .ok_or(TlsError::BadKeyShare)?;
                let mut sks = Vec::with_capacity(mlkem::CT_LEN + 32);
                sks.extend_from_slice(&ct);
                sks.extend_from_slice(&server_pub);
                let mut ss = Vec::with_capacity(64);
                ss.extend_from_slice(&pq_ss);
                ss.extend_from_slice(&x_ss);
                (GROUP_X25519_MLKEM768, sks, ss)
            } else {
                let cpub = client_x25519.ok_or(TlsError::BadKeyShare)?;
                let x_ss = x25519::diffie_hellman(&self.server_x25519_priv, &cpub)
                    .ok_or(TlsError::BadKeyShare)?;
                (GROUP_X25519, server_pub.to_vec(), x_ss.to_vec())
            };

            // Build ServerHello.
            let mut sh_body = Vec::with_capacity(128 + server_ks.len());
            push_u16(&mut sh_body, TLS_VERSION_1_2);
            sh_body.extend_from_slice(&self.server_random);
            sh_body.push(sid.len() as u8);
            sh_body.extend_from_slice(sid);
            push_u16(&mut sh_body, suite.code());
            sh_body.push(0);
            let mut shexts = Vec::with_capacity(16 + server_ks.len());
            push_u16(&mut shexts, EXT_SUPPORTED_VERSIONS);
            push_u16(&mut shexts, 2);
            push_u16(&mut shexts, TLS_VERSION_1_3);
            push_u16(&mut shexts, EXT_KEY_SHARE);
            push_u16(&mut shexts, (4 + server_ks.len()) as u16);
            push_u16(&mut shexts, grp_code);
            push_u16(&mut shexts, server_ks.len() as u16);
            shexts.extend_from_slice(&server_ks);
            push_u16(&mut sh_body, shexts.len() as u16);
            sh_body.extend_from_slice(&shexts);

            let sh = wrap_handshake(HS_SERVER_HELLO, &sh_body);
            self.tx_wire.extend_from_slice(&wrap_plain_record(CT_HANDSHAKE, TLS_VERSION_1_2, &sh));

            if !self.hrr_sent {
                self.transcript = Transcript::new();
            }
            self.transcript.update(ch_msg);
            self.transcript.update(&sh);
            let ch_sh_hash = self.transcript.current_hash(suite);

            let zeros = [0u8; 48];
            let hlen = suite.hash_len();
            let empty_hash = if suite.is_sha384() {
                Secret::from_48(sha384(b""))
            } else {
                Secret::from_32(sha256(b""))
            };
            let early = hkdf_extract(suite, &[], &zeros[..hlen]);
            let d_early = derive_secret(suite, &early, b"derived", empty_hash.as_slice());
            let hs_secret = hkdf_extract(suite, d_early.as_slice(), &shared);
            self.c_hs_secret = derive_secret(suite, &hs_secret, b"c hs traffic", ch_sh_hash.as_slice());
            let s_hs_secret = derive_secret(suite, &hs_secret, b"s hs traffic", ch_sh_hash.as_slice());
            let d_hs = derive_secret(suite, &hs_secret, b"derived", empty_hash.as_slice());
            let master = hkdf_extract(suite, d_hs.as_slice(), &zeros[..hlen]);

            let mut tx_hs = TrafficKey::from_secret(suite, &s_hs_secret);
            self.rx_key = Some(TrafficKey::from_secret(suite, &self.c_hs_secret));

            // EncryptedExtensions (empty)
            let ee = wrap_handshake(HS_ENCRYPTED_EXTENSIONS, &[0, 0]);
            self.transcript.update(&ee);

            // Certificate
            let mut cert_list = Vec::new();
            for c in &self.cert_chain {
                push_u24(&mut cert_list, c.len());
                cert_list.extend_from_slice(c);
                push_u16(&mut cert_list, 0);
            }
            let mut cert_body = Vec::with_capacity(4 + cert_list.len());
            cert_body.push(0);
            push_u24(&mut cert_body, cert_list.len());
            cert_body.extend_from_slice(&cert_list);
            let cert_msg = wrap_handshake(HS_CERTIFICATE, &cert_body);
            self.transcript.update(&cert_msg);

            // CertificateVerify
            let thash = self.transcript.current_hash(suite);
            let content = cert_verify_content(thash.as_slice());
            let (scheme, sig) = match &self.key {
                ServerKey::Ed25519(seed) => {
                    let sk = SigningKey::from_seed(seed);
                    (SIG_ED25519, sk.sign(&content).to_vec())
                }
                ServerKey::RsaPssSha256 { n, e, d } => {
                    let pk = PublicKey::new(n, *e).ok_or(TlsError::BadCertificateVerify)?;
                    let mut out = vec![0u8; pk.size()];
                    let salt = sha256(&content);
                    rsa::sim::sign_pss(&pk, d, Hash::Sha256, &content, &salt, &mut out)
                        .ok_or(TlsError::BadCertificateVerify)?;
                    (SIG_RSA_PSS_RSAE_SHA256, out)
                }
            };
            let mut cv_body = Vec::with_capacity(4 + sig.len());
            push_u16(&mut cv_body, scheme);
            push_u16(&mut cv_body, sig.len() as u16);
            cv_body.extend_from_slice(&sig);
            let cv_msg = wrap_handshake(HS_CERTIFICATE_VERIFY, &cv_body);
            self.transcript.update(&cv_msg);

            // Server Finished
            let fin_hash = self.transcript.current_hash(suite);
            let verify_data = finish_mac(suite, &s_hs_secret, fin_hash.as_slice());
            let fin_msg = wrap_handshake(HS_FINISHED, verify_data.as_slice());
            self.transcript.update(&fin_msg);
            self.sf_hash = self.transcript.current_hash(suite);

            let mut flight = Vec::with_capacity(ee.len() + cert_msg.len() + cv_msg.len() + fin_msg.len());
            flight.extend_from_slice(&ee);
            flight.extend_from_slice(&cert_msg);
            flight.extend_from_slice(&cv_msg);
            flight.extend_from_slice(&fin_msg);
            for chunk in flight.chunks(MAX_RECORD_PLAINTEXT) {
                let rec = tx_hs.encrypt_record(CT_HANDSHAKE, chunk)?;
                self.tx_wire.extend_from_slice(&rec);
            }

            self.c_ap_secret = derive_secret(suite, &master, b"c ap traffic", self.sf_hash.as_slice());
            self.s_ap_secret = derive_secret(suite, &master, b"s ap traffic", self.sf_hash.as_slice());
            self.tx_key = Some(TrafficKey::from_secret(suite, &self.s_ap_secret));
            self.wait_client_fin = true;
            Ok(())
        }
    }

    // ---- Test X.509 v3 DER cert generator (Ed25519 & RSA-PSS) -----------------------------------

    fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(body.len() + 6);
        out.push(tag);
        if body.len() < 128 {
            out.push(body.len() as u8);
        } else if body.len() < 256 {
            out.push(0x81);
            out.push(body.len() as u8);
        } else {
            out.push(0x82);
            out.push((body.len() >> 8) as u8);
            out.push(body.len() as u8);
        }
        out.extend_from_slice(body);
        out
    }

    fn der_seq(parts: &[&[u8]]) -> Vec<u8> {
        let mut body = Vec::new();
        for p in parts {
            body.extend_from_slice(p);
        }
        der_tlv(0x30, &body)
    }

    fn der_name(cn: &str) -> Vec<u8> {
        let oid_cn = der_tlv(0x06, &[0x55, 0x04, 0x03]);
        let val = der_tlv(0x0C, cn.as_bytes());
        let atv = der_seq(&[&oid_cn, &val]);
        let rdn = der_tlv(0x31, &atv);
        der_seq(&[&rdn])
    }

    fn der_uint(bytes: &[u8]) -> Vec<u8> {
        let trimmed = &bytes[bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1)..];
        let mut v = Vec::with_capacity(trimmed.len() + 1);
        if (trimmed[0] & 0x80) != 0 {
            v.push(0);
        }
        v.extend_from_slice(trimmed);
        der_tlv(0x02, &v)
    }

    #[allow(clippy::too_many_arguments)]
    fn build_cert_ed25519_signed(
        subject_cn: &str,
        issuer_cn: &str,
        spki: &[u8],
        issuer_seed: &[u8; 32],
        not_before: &[u8],
        not_after: &[u8],
        is_ca: bool,
        san_dns: &[&str],
        san_ips: &[[u8; 4]],
    ) -> Vec<u8> {
        let ver = der_tlv(0xA0, &der_tlv(0x02, &[2]));
        let serial = der_tlv(0x02, &[1]);
        let ed_alg = der_seq(&[&der_tlv(0x06, &[0x2b, 0x65, 0x70])]);
        let issuer = der_name(issuer_cn);
        let subject = der_name(subject_cn);
        let validity = der_seq(&[&der_tlv(0x17, not_before), &der_tlv(0x17, not_after)]);

        let mut exts = Vec::new();
        let bc_val = if is_ca { der_seq(&[&der_tlv(0x01, &[0xFF])]) } else { der_seq(&[]) };
        exts.extend_from_slice(&der_seq(&[
            &der_tlv(0x06, &[0x55, 0x1d, 0x13]),
            &der_tlv(0x01, &[0xFF]),
            &der_tlv(0x04, &bc_val),
        ]));
        if !san_dns.is_empty() || !san_ips.is_empty() {
            let mut sb = Vec::new();
            for d in san_dns {
                sb.extend_from_slice(&der_tlv(0x82, d.as_bytes()));
            }
            for ip in san_ips {
                sb.extend_from_slice(&der_tlv(0x87, ip));
            }
            let san_seq = der_tlv(0x30, &sb);
            exts.extend_from_slice(&der_seq(&[
                &der_tlv(0x06, &[0x55, 0x1d, 0x11]),
                &der_tlv(0x04, &san_seq),
            ]));
        }
        let exts_field = der_tlv(0xA3, &der_tlv(0x30, &exts));
        let tbs = der_seq(&[&ver, &serial, &ed_alg, &issuer, &validity, &subject, spki, &exts_field]);
        let sk = SigningKey::from_seed(issuer_seed);
        let sig = sk.sign(&tbs);
        let mut sbits = vec![0u8];
        sbits.extend_from_slice(&sig);
        der_seq(&[&tbs, &ed_alg, &der_tlv(0x03, &sbits)])
    }

    /// Deterministic test CA + RSA-PSS leaf certificate bundle for tests and QEMU offline TLS 1.3 tests.
    /// Returns `(ca_der, leaf_der, leaf_server_key)`.
    pub fn make_test_rsa_bundle(
        ca_seed: &[u8; 32],
        san_dns: &[&str],
        san_ips: &[[u8; 4]],
        not_before: &[u8],
        not_after: &[u8],
    ) -> (Vec<u8>, Vec<u8>, ServerKey) {
        let ca_sk = SigningKey::from_seed(ca_seed);
        let ed_alg = der_seq(&[&der_tlv(0x06, &[0x2b, 0x65, 0x70])]);
        let mut ca_bits = vec![0u8];
        ca_bits.extend_from_slice(&ca_sk.public());
        let ca_spki = der_seq(&[&ed_alg, &der_tlv(0x03, &ca_bits)]);
        let ca_der = build_cert_ed25519_signed(
            "D-OS Test Root CA",
            "D-OS Test Root CA",
            &ca_spki,
            ca_seed,
            b"240101000000Z",
            b"350101000000Z",
            true,
            &[],
            &[],
        );

        let rsa_alg = der_seq(&[
            &der_tlv(0x06, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]),
            &[0x05, 0x00],
        ]);
        let rsa_pub_seq = der_seq(&[&der_uint(&doscrypt::testkeys::EK_N), &der_uint(&65537u32.to_be_bytes())]);
        let mut leaf_bits = vec![0u8];
        leaf_bits.extend_from_slice(&rsa_pub_seq);
        let leaf_spki = der_seq(&[&rsa_alg, &der_tlv(0x03, &leaf_bits)]);

        let cn = san_dns.first().copied().unwrap_or("test.dos.local");
        let leaf_der = build_cert_ed25519_signed(
            cn,
            "D-OS Test Root CA",
            &leaf_spki,
            ca_seed,
            not_before,
            not_after,
            false,
            san_dns,
            san_ips,
        );
        let key = ServerKey::RsaPssSha256 {
            n: doscrypt::testkeys::EK_N.to_vec(),
            e: 65537,
            d: doscrypt::testkeys::EK_D.to_vec(),
        };
        (ca_der, leaf_der, key)
    }

    /// Deterministic test CA + Ed25519 leaf certificate + PKCS#8 private key DER for live OpenSSL interop tests.
    pub fn make_test_ed25519_bundle(
        ca_seed: &[u8; 32],
        leaf_seed: &[u8; 32],
        san_dns: &[&str],
        not_before: &[u8],
        not_after: &[u8],
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let ca_sk = SigningKey::from_seed(ca_seed);
        let leaf_sk = SigningKey::from_seed(leaf_seed);
        let ed_alg = der_seq(&[&der_tlv(0x06, &[0x2b, 0x65, 0x70])]);
        let mut ca_bits = vec![0u8];
        ca_bits.extend_from_slice(&ca_sk.public());
        let ca_spki = der_seq(&[&ed_alg, &der_tlv(0x03, &ca_bits)]);
        let ca_der = build_cert_ed25519_signed(
            "D-OS Test Root CA",
            "D-OS Test Root CA",
            &ca_spki,
            ca_seed,
            b"240101000000Z",
            b"350101000000Z",
            true,
            &[],
            &[],
        );
        let mut leaf_bits = vec![0u8];
        leaf_bits.extend_from_slice(&leaf_sk.public());
        let leaf_spki = der_seq(&[&ed_alg, &der_tlv(0x03, &leaf_bits)]);
        let cn = san_dns.first().copied().unwrap_or("test.dos.local");
        let leaf_der = build_cert_ed25519_signed(
            cn,
            "D-OS Test Root CA",
            &leaf_spki,
            ca_seed,
            not_before,
            not_after,
            false,
            san_dns,
            &[],
        );
        // RFC 8410 Ed25519 PKCS#8 OneAsymmetricKey: fixed 16-byte header + 32-byte seed.
        let mut pkcs8 = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
        ];
        pkcs8.extend_from_slice(leaf_seed);
        (ca_der, leaf_der, pkcs8)
    }

    /// Fixed seed shared between `dbuild`'s offline TLS 1.3 test server and the guest `net` test.
    pub const TEST_CA_SEED: [u8; 32] = [0xD0; 32];
}
