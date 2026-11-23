//! `dosapp`: D-OS `.dapp` application bundle format, fail-closed `kind = "app"` manifest parser,
//! revocable per-identity permission ledger, and read-only `DRES` resource pack codec.
//!
//! Pure `no_std` (with `alloc`), `#![forbid(unsafe_code)]`, zero external crates.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod bundle;
pub mod manifest;
pub mod perm;

#[cfg(test)]
mod tests;

pub use bundle::{
    BUNDLE_HEADER_LEN, BUNDLE_MAGIC, BUNDLE_VERSION, BundleError, BundleInput, ENTRY_BINARY, ENTRY_BINARY_SIG,
    ENTRY_MANIFEST, ENTRY_RESOURCE, MAX_ENTRIES, MAX_ENTRY_NAME, ParsedBundle, ParsedEntry, ResourcePack,
    TOC_ENTRY_LEN, build_bundle, parse_bundle, verify_bundle_with_key,
};
pub use manifest::{AppManifest, DEFAULT_APP_QUOTA, parse_manifest};
pub use perm::{AppPermRecord, PermDecision, Permission, PermissionLedger, format_perm_mask};
