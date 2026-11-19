//! Field access: operation regions (through the handler), index and bank fields, buffer fields.

use alloc::vec;
use alloc::vec::Vec;

use crate::interp::Interpreter;
use crate::object::{Field, FieldKind, Object, Region, buf, space};
use crate::{Error, ErrorKind as K, Handler, Result};

fn hw<T>(r: core::result::Result<T, crate::Refused>) -> Result<T> {
    r.map_err(|_| Error::new(K::Hardware, 0))
}

/// `len` bits at `bit` of `src` as an object: an Integer if it fits the integer width, else a Buffer.
pub(crate) fn read_bits_obj(src: &[u8], bit: usize, len: usize, int64: bool) -> Object {
    let mut out = vec![0u8; len.div_ceil(8)];
    for i in 0..len {
        let s = bit + i;
        if s / 8 < src.len() && (src[s / 8] >> (s % 8)) & 1 != 0 {
            out[i / 8] |= 1 << (i % 8);
        }
    }
    bits_to_obj(out, len, int64)
}

fn bits_to_obj(out: Vec<u8>, len: usize, int64: bool) -> Object {
    if len <= if int64 { 64 } else { 32 } {
        let mut v = 0u64;
        for (i, &b) in out.iter().enumerate().take(8) {
            v |= (b as u64) << (8 * i);
        }
        Object::Integer(v)
    } else {
        Object::Buffer(buf(out))
    }
}

/// Write the low `len` bits of `data` (zero-extended) at `bit` of `dst`.
pub(crate) fn write_bits(dst: &mut [u8], bit: usize, len: usize, data: &[u8]) {
    for i in 0..len {
        let d = bit + i;
        if d / 8 >= dst.len() {
            break;
        }
        let v = i / 8 < data.len() && (data[i / 8] >> (i % 8)) & 1 != 0;
        if v {
            dst[d / 8] |= 1 << (d % 8);
        } else {
            dst[d / 8] &= !(1 << (d % 8));
        }
    }
}

impl<H: Handler> Interpreter<H> {
    pub(crate) fn read_field(&mut self, fl: &Field, int64: bool) -> Result<Object> {
        let len = fl.len as usize;
        if fl.len > (self.limits.buffer as u64) * 8 {
            return Err(Error::new(K::Limit("field size"), 0));
        }
        let mut out = vec![0u8; len.div_ceil(8)];
        if len > 0 {
            let w = fl.access as u64;
            let wb = w * 8;
            let first = fl.bit / wb;
            let last = (fl.bit + fl.len - 1) / wb;
            let locked = fl.lock && self.h.acquire_global_lock();
            let mut r = Ok(());
            for unit in first..=last {
                let val = match self.unit_read(fl, unit * w, fl.access) {
                    Ok(v) => v,
                    Err(e) => {
                        r = Err(e);
                        break;
                    }
                };
                let lo = fl.bit.max(unit * wb);
                let hi = (fl.bit + fl.len).min(unit * wb + wb);
                for b in lo..hi {
                    if (val >> (b - unit * wb)) & 1 != 0 {
                        let o = (b - fl.bit) as usize;
                        out[o / 8] |= 1 << (o % 8);
                    }
                }
            }
            if locked {
                self.h.release_global_lock();
            }
            r?;
        }
        Ok(bits_to_obj(out, len, int64))
    }

    pub(crate) fn write_field(&mut self, fl: &Field, v: &Object, int64: bool) -> Result<()> {
        let v = self.deref_all(v.clone())?;
        let data = match &v {
            Object::Integer(x) => {
                let x = if int64 { *x } else { *x & 0xFFFF_FFFF };
                x.to_le_bytes().to_vec()
            }
            Object::String(b) | Object::Buffer(b) => b.borrow().clone(),
            _ => return Err(Error::new(K::Type("integer, string or buffer"), 0)),
        };
        if fl.len == 0 {
            return Ok(());
        }
        if fl.len > (self.limits.buffer as u64) * 8 {
            return Err(Error::new(K::Limit("field size"), 0));
        }
        let w = fl.access as u64;
        let wb = w * 8;
        let first = fl.bit / wb;
        let last = (fl.bit + fl.len - 1) / wb;
        let all = if wb == 64 { u64::MAX } else { (1u64 << wb) - 1 };
        let locked = fl.lock && self.h.acquire_global_lock();
        let mut r = Ok(());
        for unit in first..=last {
            let base = unit * wb;
            let lo = fl.bit.max(base);
            let hi = (fl.bit + fl.len).min(base + wb);
            let full = lo == base && hi == base + wb;
            let mut val = if full {
                0
            } else {
                match fl.update {
                    0 => match self.unit_read(fl, unit * w, fl.access) {
                        Ok(v) => v,
                        Err(e) => {
                            r = Err(e);
                            break;
                        }
                    },
                    1 => all,
                    _ => 0,
                }
            };
            for b in lo..hi {
                let s = (b - fl.bit) as usize;
                let bitv = s / 8 < data.len() && (data[s / 8] >> (s % 8)) & 1 != 0;
                let m = 1u64 << (b - base);
                if bitv {
                    val |= m;
                } else {
                    val &= !m;
                }
            }
            if let Err(e) = self.unit_write(fl, unit * w, fl.access, val) {
                r = Err(e);
                break;
            }
        }
        if locked {
            self.h.release_global_lock();
        }
        r
    }

    fn field_of(&self, node: crate::NodeId) -> Result<alloc::rc::Rc<Field>> {
        match self.ns.obj(node) {
            Object::Field(f) => Ok(f.clone()),
            _ => Err(Error::new(K::Type("field"), 0)),
        }
    }

    /// One access-width unit at byte offset `off` of the field's region (or data window).
    fn unit_read(&mut self, fl: &Field, off: u64, w: u8) -> Result<u64> {
        match &fl.kind {
            FieldKind::Region(r) => self.region_read(r, off, w),
            FieldKind::Index { index, data } => {
                let (i, d) = (self.field_of(*index)?, self.field_of(*data)?);
                self.write_field(&i, &Object::Integer(off), true)?;
                let v = self.read_field(&d, true)?;
                self.conv_int(true, &v)
            }
            FieldKind::Bank {
                region,
                bank,
                value,
            } => {
                let b = self.field_of(*bank)?;
                self.write_field(&b, &Object::Integer(*value), true)?;
                self.region_read(region, off, w)
            }
        }
    }

    fn unit_write(&mut self, fl: &Field, off: u64, w: u8, val: u64) -> Result<()> {
        match &fl.kind {
            FieldKind::Region(r) => self.region_write(r, off, w, val),
            FieldKind::Index { index, data } => {
                let (i, d) = (self.field_of(*index)?, self.field_of(*data)?);
                self.write_field(&i, &Object::Integer(off), true)?;
                self.write_field(&d, &Object::Integer(val), true)
            }
            FieldKind::Bank {
                region,
                bank,
                value,
            } => {
                let b = self.field_of(*bank)?;
                self.write_field(&b, &Object::Integer(*value), true)?;
                self.region_write(region, off, w, val)
            }
        }
    }

    fn check(&self, r: &Region, off: u64, w: u8) -> Result<()> {
        if off.checked_add(w as u64).is_none_or(|e| e > r.len) {
            return Err(Error::new(K::Range("field outside its region"), 0));
        }
        Ok(())
    }

    fn region_read(&mut self, r: &Region, off: u64, w: u8) -> Result<u64> {
        self.check(r, off, w)?;
        match r.space {
            space::MEMORY => hw(self.h.read_mem(r.base.wrapping_add(off), w)),
            space::IO | space::PCI if w == 8 => {
                let lo = self.region_read(r, off, 4)?;
                let hi = self.region_read(r, off + 4, 4)?;
                Ok(lo | hi << 32)
            }
            space::IO => {
                let port = r.base.wrapping_add(off);
                if port > 0xFFFF - (w as u64 - 1) {
                    return Err(Error::new(K::Range("I/O port outside 0-0xFFFF"), 0));
                }
                hw(self.h.read_io(port as u16, w))
            }
            space::PCI => {
                let a = self.pci_addr(r)?;
                let o = r.base.wrapping_add(off);
                if o.checked_add(w as u64).is_none_or(|e| e > 0x1000) {
                    return Err(Error::new(K::Range("PCI configuration offset"), 0));
                }
                hw(self.h.read_pci(a, o as u16, w))
            }
            space::EC => {
                let mut v = 0u64;
                for i in 0..w as u64 {
                    let o = r.base.wrapping_add(off).wrapping_add(i);
                    if o > 0xFF {
                        return Err(Error::new(K::Range("embedded controller offset"), 0));
                    }
                    v |= (hw(self.h.read_ec(o as u8))? as u64) << (8 * i);
                }
                Ok(v)
            }
            space::CMOS => Err(Error::new(K::Unsupported("SystemCMOS regions"), 0)),
            _ => Err(Error::new(K::Unsupported("this address space"), 0)),
        }
    }

    fn region_write(&mut self, r: &Region, off: u64, w: u8, val: u64) -> Result<()> {
        self.check(r, off, w)?;
        match r.space {
            space::MEMORY => hw(self.h.write_mem(r.base.wrapping_add(off), w, val)),
            space::IO | space::PCI if w == 8 => {
                self.region_write(r, off, 4, val & 0xFFFF_FFFF)?;
                self.region_write(r, off + 4, 4, val >> 32)
            }
            space::IO => {
                let port = r.base.wrapping_add(off);
                if port > 0xFFFF - (w as u64 - 1) {
                    return Err(Error::new(K::Range("I/O port outside 0-0xFFFF"), 0));
                }
                hw(self.h.write_io(port as u16, w, val))
            }
            space::PCI => {
                let a = self.pci_addr(r)?;
                let o = r.base.wrapping_add(off);
                if o.checked_add(w as u64).is_none_or(|e| e > 0x1000) {
                    return Err(Error::new(K::Range("PCI configuration offset"), 0));
                }
                hw(self.h.write_pci(a, o as u16, w, val))
            }
            space::EC => {
                for i in 0..w as u64 {
                    let o = r.base.wrapping_add(off).wrapping_add(i);
                    if o > 0xFF {
                        return Err(Error::new(K::Range("embedded controller offset"), 0));
                    }
                    hw(self.h.write_ec(o as u8, (val >> (8 * i)) as u8))?;
                }
                Ok(())
            }
            space::CMOS => Err(Error::new(K::Unsupported("SystemCMOS regions"), 0)),
            _ => Err(Error::new(K::Unsupported("this address space"), 0)),
        }
    }
}
