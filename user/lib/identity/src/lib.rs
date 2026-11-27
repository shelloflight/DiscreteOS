//! `dosid`: D-OS user identity model, PBKDF2-HMAC-SHA256 key derivation, credential sealing,
//! per-identity namespaces, explicit capability sets, and authentication throttling.
//!
//! Pure `no_std` (with `alloc`), `#![forbid(unsafe_code)]`, zero external crates.
//! D-OS has no `root` user and no ambient authority: every identity holds an explicit capability
//! bitmask and an explicit namespace view.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod kdf;
pub mod model;
pub mod oobe;
pub mod settings;
pub mod wire;

#[cfg(test)]
mod tests;

pub use kdf::{DEFAULT_ITERATIONS, MAX_ITERATIONS, MIN_ITERATIONS, derive_seal_key, derive_verifier, pbkdf2_hmac_sha256};
pub use model::{
    AuthThrottle, Credential, Identity, IdentityError, IdentityNsEntry, IdentityRole, IdentityStore, LockPolicy,
    MAX_DISPLAY, MAX_IDENTITIES, MAX_NAME, SealKind, caps, validate_name,
};
pub use oobe::{KEYBOARDS, LANGUAGES, OobeConfig, TIMEZONES};
pub use settings::{AudioSettings, DesktopSettings, NetworkSettings};
pub use wire::{IDENTITY_WIRE_BYTES, IdentityWire, LOCK_POLICY_WIRE_BYTES, LockPolicyWire};
