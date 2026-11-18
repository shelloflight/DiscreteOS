//! Event: an object whose only state is its `SIGNALED` signal, set and cleared by holders of the
//! `SIGNAL` right and waited on by holders of `WAIT`.

use super::signals::Signals;
use super::{Header, KRef, KResult, ObjType, Status};

pub struct EventObj {
    pub header: Header,
    pub signals: Signals,
}

impl EventObj {
    pub fn create() -> KResult<KRef<EventObj>> {
        KRef::try_new(EventObj {
            header: Header::new(ObjType::Event),
            signals: Signals::new(c"event"),
        })
        .map_err(|_| Status::NoMemory)
    }
}
