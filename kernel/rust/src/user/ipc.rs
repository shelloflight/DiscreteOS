//! IPC syscalls: channels, ports, async waits. ABI in docs/abi.md, objects in
//! object/channel.rs and object/port.rs.
//!
//! Handles in messages: every handle a write names is checked first (it exists, carries
//! `TRANSFER`, the rights asked for are a subset, it is listed once, it is not the channel's own
//! end or its peer); if any check fails nothing happens. After that the handles are moved out of
//! the writer's table and are gone even if the write then fails (`PEER_CLOSED`, `SHOULD_WAIT`),
//! as in Fuchsia: a capability never ends up in two places. A read installs all of a message's
//! handles or none: if the reader's table is full the message stays queued.

use alloc::vec::Vec;

use super::thread::UserThread;
use super::uaccess::{self, Pod};
use crate::object::channel::{self, Message, ReadError};
use crate::object::port::{self, PortObj};
use crate::object::{ChannelObj, Handle, KRef, KResult, ObjType, Object, Rights, Status, default_rights, sig};

/// `struct dos_msg`: a message buffer (write: what to send; read: where to put it, and the
/// sizes received are written back into `len` and `nhandles`).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RawMsg {
    pub data: u64,
    pub len: u32,
    pub nhandles: u32,
    pub handles: u64,
}
// SAFETY: repr(C), integers only, no padding (8 + 4 + 4 + 8).
unsafe impl Pod for RawMsg {}
const _: () = assert!(core::mem::size_of::<RawMsg>() == 24);

/// `struct dos_msg_handle`: a handle to send and the rights it travels with.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RawMsgHandle {
    handle: u32,
    rights: u32,
}
// SAFETY: as above.
unsafe impl Pod for RawMsgHandle {}

fn derive(have: Rights, want: Rights) -> KResult<Rights> {
    if want == Rights::SAME {
        return Ok(have);
    }
    if want.0 & !Rights::ALL.0 != 0 || !have.contains(want) {
        return Err(Status::AccessDenied);
    }
    Ok(want)
}

/// Copy a message out of user memory and move its handles out of the caller's table.
fn take_message(u: &UserThread, ch: &ChannelObj, ptr: u64) -> KResult<Message> {
    let m: RawMsg = uaccess::read(ptr)?;
    let len = m.len as usize;
    let nh = m.nhandles as usize;
    if len > channel::MAX_BYTES || nh > channel::MAX_HANDLES {
        return Err(Status::InvalidArgs);
    }
    let mut data = Vec::new();
    data.try_reserve_exact(len).map_err(|_| Status::NoMemory)?;
    data.resize(len, 0u8);
    uaccess::copy_from_user(&mut data, m.data)?;
    let mut list: Vec<RawMsgHandle> = Vec::new();
    list.try_reserve_exact(nh).map_err(|_| Status::NoMemory)?;
    for i in 0..nh {
        list.push(uaccess::read(m.handles + 8 * i as u64)?);
    }
    // Validate everything before moving anything.
    for (i, e) in list.iter().enumerate() {
        if list[..i].iter().any(|o| o.handle == e.handle) {
            return Err(Status::InvalidArgs);
        }
        let (obj, have) = u.proc.get(Handle(e.handle), Rights::TRANSFER)?;
        derive(have, Rights(e.rights))?;
        if ch.is_self_or_peer(&obj) {
            return Err(Status::NotSupported);
        }
    }
    let mut handles = Vec::new();
    handles.try_reserve_exact(nh).map_err(|_| Status::NoMemory)?;
    for e in &list {
        let (obj, have) = u.proc.take(Handle(e.handle))?; // consumed from here on
        let r = derive(have, Rights(e.rights)).unwrap_or(Rights::NONE);
        handles.push((obj, r));
    }
    Message::new(u.proc.account(), data, handles)
}

/// Hand a message to the reader: bytes to its buffer, handles into its table (all or none).
/// On failure the message comes back to the caller untouched.
fn give_message(u: &UserThread, m: &RawMsg, ptr: u64, msg: Message) -> Result<(), (Status, Message)> {
    if let Err(e) = uaccess::copy_to_user(m.data, &msg.data) {
        return Err((e, msg));
    }
    let mut installed: Vec<Handle> = Vec::new();
    if installed.try_reserve_exact(msg.handles.len()).is_err() {
        return Err((Status::NoMemory, msg));
    }
    let mut fail = None;
    for (i, (obj, rights)) in msg.handles.iter().enumerate() {
        match u.proc.add(obj.clone(), *rights) {
            Ok(h) => {
                if let Err(e) = uaccess::write(m.handles + 4 * i as u64, &h.0) {
                    let _ = u.proc.handle_close(h);
                    fail = Some(e);
                    break;
                }
                installed.push(h);
            }
            Err(e) => {
                fail = Some(e);
                break;
            }
        }
    }
    let sizes = RawMsg { data: m.data, len: msg.data.len() as u32, nhandles: msg.handles.len() as u32, handles: m.handles };
    if fail.is_none() {
        fail = uaccess::write(ptr, &sizes).err();
    }
    if let Some(e) = fail {
        for h in installed {
            let _ = u.proc.handle_close(h);
        }
        return Err((e, msg));
    }
    drop(msg); // the table holds its own references now
    Ok(())
}

pub fn channel_create(u: &UserThread, out: u64) -> KResult<i64> {
    u.proc.check_alive()?;
    uaccess::write(out, &0u32)?;
    let (a, b) = ChannelObj::create()?;
    let r = default_rights(ObjType::Channel);
    let ha = u.proc.add(Object::Channel(a), r)?;
    let hb = match u.proc.add(Object::Channel(b), r) {
        Ok(h) => h,
        Err(e) => {
            let _ = u.proc.handle_close(ha);
            return Err(e);
        }
    };
    if let Err(e) = uaccess::write(out, &hb.0) {
        let _ = u.proc.handle_close(ha);
        let _ = u.proc.handle_close(hb);
        return Err(e);
    }
    Ok(i64::from(ha.0))
}

pub fn channel_write(u: &UserThread, h: u64, ptr: u64, flags: u64) -> KResult<i64> {
    if flags != 0 {
        return Err(Status::InvalidArgs);
    }
    let (ch, _) = u.proc.get_channel(Handle(h as u32), Rights::WRITE)?;
    let msg = take_message(u, &ch, ptr)?;
    ch.write(msg).map_err(|(e, m)| {
        drop(m);
        e
    })?;
    Ok(0)
}

fn read_into(u: &UserThread, ch: &ChannelObj, ptr: u64, m: &RawMsg, timeout_ns: u64) -> KResult<i64> {
    let deadline = crate::object::signals::deadline(timeout_ns);
    loop {
        match ch.read(m.len as usize, m.nhandles as usize) {
            Ok(msg) => {
                return match give_message(u, m, ptr, msg) {
                    Ok(()) => Ok(0),
                    Err((e, msg)) => {
                        ch.unread(msg);
                        Err(e)
                    }
                };
            }
            Err(ReadError::TooSmall(n)) => {
                let sizes = RawMsg { data: m.data, len: n.bytes, nhandles: n.handles, handles: m.handles };
                uaccess::write(ptr, &sizes)?;
                return Err(Status::BufferTooSmall);
            }
            Err(ReadError::Status(Status::ShouldWait)) if timeout_ns != 0 => {
                let left = if deadline == 0 {
                    crate::ffi::WAIT_FOREVER
                } else {
                    let now = crate::ffi::now_ns();
                    if now >= deadline {
                        return Err(Status::TimedOut);
                    }
                    deadline - now
                };
                ch.wait_readable(left)?;
            }
            Err(ReadError::Status(e)) => return Err(e),
        }
    }
}

pub fn channel_read(u: &UserThread, h: u64, ptr: u64, flags: u64, timeout_ns: u64) -> KResult<i64> {
    if flags != 0 {
        return Err(Status::InvalidArgs);
    }
    let (ch, _) = u.proc.get_channel(Handle(h as u32), Rights::READ)?;
    let m: RawMsg = uaccess::read(ptr)?;
    uaccess::check(m.data, u64::from(m.len))?;
    uaccess::check(m.handles, 4 * u64::from(m.nhandles))?;
    read_into(u, &ch, ptr, &m, timeout_ns)
}

pub fn channel_call(u: &UserThread, h: u64, wr: u64, rd: u64, timeout_ns: u64) -> KResult<i64> {
    let (ch, _) = u.proc.get_channel(Handle(h as u32), Rights::READ | Rights::WRITE)?;
    let rm: RawMsg = uaccess::read(rd)?;
    uaccess::check(rm.data, u64::from(rm.len))?;
    uaccess::check(rm.handles, 4 * u64::from(rm.nhandles))?;
    let msg = take_message(u, &ch, wr)?;
    let reply = ch.call(msg, timeout_ns).map_err(|(e, m)| {
        drop(m);
        e
    })?;
    if reply.data.len() > rm.len as usize || reply.handles.len() > rm.nhandles as usize {
        let sizes = RawMsg { data: rm.data, len: reply.data.len() as u32, nhandles: reply.handles.len() as u32, handles: rm.handles };
        drop(reply); // a call's reply cannot be read again: it is discarded
        uaccess::write(rd, &sizes)?;
        return Err(Status::BufferTooSmall);
    }
    give_message(u, &rm, rd, reply).map_err(|(e, m)| {
        drop(m);
        e
    })?;
    Ok(0)
}

pub fn port_create(u: &UserThread, entries: u64, vmo_out: u64) -> KResult<i64> {
    u.proc.check_alive()?;
    uaccess::write(vmo_out, &0u32)?;
    let entries = u32::try_from(entries).map_err(|_| Status::InvalidArgs)?;
    let (p, vmo) = PortObj::create(u.proc.account(), entries)?;
    let hp = u.proc.add(Object::Port(p), default_rights(ObjType::Port))?;
    let hv = match u.proc.add(Object::Vmo(vmo), default_rights(ObjType::Vmo)) {
        Ok(h) => h,
        Err(e) => {
            let _ = u.proc.handle_close(hp);
            return Err(e);
        }
    };
    if let Err(e) = uaccess::write(vmo_out, &hv.0) {
        let _ = u.proc.handle_close(hp);
        let _ = u.proc.handle_close(hv);
        return Err(e);
    }
    Ok(i64::from(hp.0))
}

pub fn object_wait_async(u: &UserThread, h: u64, mask: u64, port_h: u64, key: u64, flags: u64) -> KResult<i64> {
    if flags != 0 {
        return Err(Status::InvalidArgs);
    }
    let mask = u32::try_from(mask).map_err(|_| Status::InvalidArgs)?;
    if mask == 0 || mask & !sig::USER_MASK != 0 {
        return Err(Status::InvalidArgs);
    }
    let (port, _) = u.proc.get_port(Handle(port_h as u32), Rights::WRITE)?;
    let (obj, rights) = u.proc.get(Handle(h as u32), Rights::NONE)?;
    // Ports cannot be waited on through a port: a port's pending waits would keep it alive.
    if matches!(obj, Object::Port(_)) {
        return Err(Status::WrongType);
    }
    let s = obj.signals().ok_or(Status::WrongType)?;
    if !rights.contains(Rights::WAIT) {
        return Err(Status::AccessDenied);
    }
    let node = port::new_wait(&port.core, u.proc.account(), mask, key)?;
    s.observe(node);
    Ok(0)
}

pub fn port_cancel(u: &UserThread, port_h: u64, h: u64, key: u64) -> KResult<i64> {
    let (port, _) = u.proc.get_port(Handle(port_h as u32), Rights::WRITE)?;
    let (obj, _) = u.proc.get(Handle(h as u32), Rights::NONE)?;
    let s = obj.signals().ok_or(Status::WrongType)?;
    Ok(i64::from(s.cancel(port::PortCore::id(&port.core), key)))
}

/// The port of a `port_enter` call.
pub fn port_of(u: &UserThread, h: u64) -> KResult<KRef<PortObj>> {
    Ok(u.proc.get_port(Handle(h as u32), Rights::WRITE)?.0)
}
