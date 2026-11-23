//! Resource: a handle that stands for a special authority the kernel hands out explicitly, never
//! ambient. Kinds:
//! - `VMEX`: the right to turn a sealed VMO into an executable one (`vmo_make_executable`), which
//!   user-space program loaders need (D-CMPL's PE loader, later the `.dlib` loader);
//! - `POWER` (ABI v6): the right to switch the machine off or reset it (`system_power`);
//! - `MEASURE` (ABI v7): the right to record a decision in the measurement log (PCR 10,
//!   `measure`): the service manager records each manifest it accepts or refuses;
//! - `KLOG` (ABI v8): the right to read the kernel log (`klog_read`; kernel addresses filtered),
//!   which the service manager grants to the log service;
//! - `TPM_SEAL` (ABI v16): the right to seal and unseal small credentials under the TPM 2.0
//!   owner Storage Root Key (`tpm_seal`, `tpm_unseal`), granted to the identity service.
//!
//! The kernel gives them to `init` only; init passes them on deliberately.

use super::{Header, KRef, KResult, ObjType, Status};

pub const KIND_VMEX: u32 = 1;
pub const KIND_POWER: u32 = 2;
pub const KIND_MEASURE: u32 = 3;
pub const KIND_KLOG: u32 = 4;
pub const KIND_TPM_SEAL: u32 = 5;

pub struct ResourceObj {
    pub header: Header,
    pub kind: u32,
}

impl ResourceObj {
    pub fn new(kind: u32) -> KResult<KRef<ResourceObj>> {
        KRef::try_new(ResourceObj { header: Header::new(ObjType::Resource), kind }).map_err(|_| Status::NoMemory)
    }
}
