//! Modern virtio-pci transport (virtio 1.x, split virtqueues), for the user-space drivers.
//!
//! Everything the device writes (used ring, configuration) is untrusted: indexes and lengths are
//! checked before use, and an impossible value ends the driver (it is restarted) instead of
//! being followed. Interrupts are MSI-X: queue `q` uses MSI-X entry `q`, configuration changes
//! none. Every buffer the device sees is pinned for it (`libd::Dma`): with an IOMMU it can reach
//! nothing else.

use libd::sys::{self, Handle};
use libd::{Dma, Mapping};

pub const STATUS_ACK: u8 = 1;
pub const STATUS_DRIVER: u8 = 2;
pub const STATUS_DRIVER_OK: u8 = 4;
pub const STATUS_FEATURES_OK: u8 = 8;
pub const STATUS_NEEDS_RESET: u8 = 0x40;

const F_VERSION_1: u64 = 1 << 32;
const F_ACCESS_PLATFORM: u64 = 1 << 33;

pub const DESC_NEXT: u16 = 1;
pub const DESC_WRITE: u16 = 2;

/// Queue size the drivers use (a power of two; at most what the device offers).
pub const QSIZE: u16 = 16;
const AVAIL: u64 = 256;
const USED: u64 = 512;

/// A window into a BAR (a virtio capability).
#[derive(Clone, Copy)]
pub struct Region {
    bar: usize,
    off: u64,
    len: u64,
}

pub struct Virtio {
    pub dev: Handle,
    bars: [Option<Mapping>; 6],
    common: Region,
    notify: Region,
    notify_mult: u32,
    pub devcfg: Option<Region>,
}

pub struct Queue {
    pub index: u16,
    pub size: u16,
    pub ring: Dma,
    notify_off: u64,
    pub avail_idx: u16,
    pub last_used: u16,
    pub irq: Handle,
}

fn err<T>(what: &str) -> Result<T, &str> {
    Err(what)
}

impl Virtio {
    fn map(&self, r: Region) -> &Mapping {
        self.bars[r.bar].as_ref().expect("region of an unmapped BAR")
    }
    pub fn r8(&self, r: Region, off: u64) -> u8 {
        assert!(off < r.len);
        self.map(r).r8(r.off + off)
    }
    pub fn r16(&self, r: Region, off: u64) -> u16 {
        assert!(off + 2 <= r.len);
        self.map(r).r16(r.off + off)
    }
    pub fn r32(&self, r: Region, off: u64) -> u32 {
        assert!(off + 4 <= r.len);
        self.map(r).r32(r.off + off)
    }
    pub fn w8(&self, r: Region, off: u64, v: u8) {
        assert!(off < r.len);
        self.map(r).w8(r.off + off, v)
    }
    pub fn w16(&self, r: Region, off: u64, v: u16) {
        assert!(off + 2 <= r.len);
        self.map(r).w16(r.off + off, v)
    }
    pub fn w32(&self, r: Region, off: u64, v: u32) {
        assert!(off + 4 <= r.len);
        self.map(r).w32(r.off + off, v)
    }

    pub fn status(&self) -> u8 {
        self.r8(self.common, 0x14)
    }
    pub fn set_status(&self, s: u8) {
        self.w8(self.common, 0x14, s)
    }

    /// Find the virtio capabilities, map their BARs, reset the device and negotiate features
    /// (VERSION_1, and ACCESS_PLATFORM when offered: DMA goes through the platform's IOMMU).
    pub fn open(dev: Handle) -> Result<Virtio, &'static str> {
        Virtio::open_with(dev, 0).map(|(v, _)| v)
    }

    /// `open`, also accepting the device-specific features in `want` that the device offers.
    /// Returns the device and the device-specific features accepted.
    pub fn open_with(dev: Handle, want: u64) -> Result<(Virtio, u64), &'static str> {
        let info = sys::device_info(dev).map_err(|_| "device_info failed")?;
        let mut v = Virtio {
            dev,
            bars: [None, None, None, None, None, None],
            common: Region { bar: 0, off: 0, len: 0 },
            notify: Region { bar: 0, off: 0, len: 0 },
            notify_mult: 0,
            devcfg: None,
        };
        let (mut have_common, mut have_notify) = (false, false);
        let mut ptr = sys::config_read(dev, 0x34, 1).map_err(|_| "config read failed")? & 0xFC;
        for _ in 0..48 {
            if ptr < 0x40 {
                break;
            }
            let id = sys::config_read(dev, ptr, 1).unwrap_or(0);
            let next = sys::config_read(dev, ptr + 1, 1).unwrap_or(0) & 0xFC;
            if id == 0x09 {
                let ty = sys::config_read(dev, ptr + 3, 1).unwrap_or(0);
                let bar = sys::config_read(dev, ptr + 4, 1).unwrap_or(0xFF) as usize;
                let off = sys::config_read(dev, ptr + 8, 4).unwrap_or(0);
                let len = sys::config_read(dev, ptr + 12, 4).unwrap_or(0);
                if bar < 6 && info.bar_kind[bar] == 1 && off.checked_add(len).is_some_and(|e| e <= info.bar_size[bar]) {
                    let r = Region { bar, off, len };
                    match ty {
                        1 => (v.common, have_common) = (r, true),
                        2 => {
                            v.notify = r;
                            v.notify_mult = sys::config_read(dev, ptr + 16, 4).unwrap_or(0) as u32;
                            have_notify = true;
                        }
                        4 => v.devcfg = Some(r),
                        _ => {}
                    }
                    if matches!(ty, 1 | 2 | 4) && v.bars[bar].is_none() {
                        let vmo = sys::device_map_bar(dev, bar as u64).map_err(|_| "cannot map a BAR")?;
                        v.bars[bar] = Some(Mapping::of(vmo, info.bar_size[bar]).map_err(|_| "cannot map a BAR")?);
                    }
                }
            }
            ptr = next;
        }
        if !have_common || !have_notify || v.common.len < 0x38 {
            return err("not a modern virtio-pci device (capabilities missing)");
        }
        // Memory decode + bus mastering (DMA through the IOMMU).
        sys::config_write(dev, 0x04, 2, 0x6).map_err(|_| "cannot enable the device")?;
        v.set_status(0);
        for _ in 0..1_000_000 {
            if v.status() == 0 {
                break;
            }
        }
        if v.status() != 0 {
            return err("device did not reset");
        }
        v.set_status(STATUS_ACK);
        v.set_status(STATUS_ACK | STATUS_DRIVER);
        let c = v.common;
        v.w32(c, 0x00, 0);
        let lo = u64::from(v.r32(c, 0x04));
        v.w32(c, 0x00, 1);
        let hi = u64::from(v.r32(c, 0x04));
        let offered = lo | hi << 32;
        if offered & F_VERSION_1 == 0 {
            return err("device does not offer VIRTIO_F_VERSION_1");
        }
        let accept = F_VERSION_1 | (offered & (F_ACCESS_PLATFORM | (want & 0xFFFF_FFFF)));
        v.w32(c, 0x08, 0);
        v.w32(c, 0x0C, accept as u32);
        v.w32(c, 0x08, 1);
        v.w32(c, 0x0C, (accept >> 32) as u32);
        v.set_status(STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK);
        if v.status() & STATUS_FEATURES_OK == 0 {
            return err("device refused the features");
        }
        v.w16(c, 0x10, 0xFFFF); // no configuration-change interrupt
        Ok((v, accept & want & 0xFFFF_FFFF))
    }

    /// Set up queue `index` (MSI-X entry `index`) with its ring in pinned memory.
    pub fn queue(&self, index: u16) -> Result<Queue, &'static str> {
        self.queue_with_vector(index, index, true)
    }

    /// Set up queue `index` routed to MSI-X entry `vector`; if `bind_irq` is false, reuses an
    /// already-bound vector (for devices offering fewer MSI-X vectors than virtqueues).
    pub fn queue_with_vector(&self, index: u16, vector: u16, bind_irq: bool) -> Result<Queue, &'static str> {
        let c = self.common;
        self.w16(c, 0x16, index);
        let max = self.r16(c, 0x18);
        if max == 0 {
            return err("queue not available");
        }
        let size = QSIZE.min(max);
        if !size.is_power_of_two() {
            return err("odd queue size");
        }
        let irq = if bind_irq {
            sys::device_interrupt(self.dev, u64::from(vector)).map_err(|_| "no interrupt for the queue")?
        } else {
            0
        };
        let ring = Dma::new(self.dev, 4096, sys::DMA_DEVICE_READ | sys::DMA_DEVICE_WRITE).map_err(|_| "cannot pin the ring")?;
        self.w16(c, 0x18, size);
        self.w16(c, 0x1A, vector);
        if self.r16(c, 0x1A) != vector {
            return err("device refused the MSI-X vector");
        }
        let base = ring.dev_addr(0);
        for (off, a) in [(0x20, base), (0x28, base + AVAIL), (0x30, base + USED)] {
            self.w32(c, off, a as u32);
            self.w32(c, off + 4, (a >> 32) as u32);
        }
        let notify_off = u64::from(self.r16(c, 0x1E)) * u64::from(self.notify_mult);
        if notify_off + 2 > self.notify.len {
            return err("notify offset outside its region");
        }
        self.w16(c, 0x1C, 1);
        Ok(Queue { index, size, ring, notify_off, avail_idx: 0, last_used: 0, irq })
    }

    pub fn driver_ok(&self) {
        self.set_status(STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);
    }

    pub fn notify(&self, q: &Queue) {
        self.w16(self.notify, q.notify_off, q.index);
    }
}

impl Queue {
    pub fn desc(&self, i: u16, addr: u64, len: u32, flags: u16, next: u16) {
        let m = &self.ring.map;
        let o = u64::from(i) * 16;
        m.w64(o, addr);
        m.w32(o + 8, len);
        m.w16(o + 12, flags);
        m.w16(o + 14, next);
    }

    /// Offer the chain starting at `head` to the device.
    pub fn push(&mut self, head: u16) {
        let m = &self.ring.map;
        m.w16(AVAIL + 4 + 2 * u64::from(self.avail_idx % self.size), head);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        self.avail_idx = self.avail_idx.wrapping_add(1);
        m.w16(AVAIL + 2, self.avail_idx);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }

    /// The next used entry (id, len), if the device returned one. A device that claims more
    /// entries than the ring holds, or an id outside it, is refused (panic: the driver restarts).
    pub fn pop(&mut self) -> Option<(u16, u32)> {
        let m = &self.ring.map;
        let used = m.r16(USED + 2);
        if used == self.last_used {
            return None;
        }
        assert!(used.wrapping_sub(self.last_used) <= self.size, "device used-ring index out of range");
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        let o = USED + 4 + 8 * u64::from(self.last_used % self.size);
        let id = m.r32(o);
        let len = m.r32(o + 4);
        assert!(id < u32::from(self.size), "device returned a descriptor id out of range");
        self.last_used = self.last_used.wrapping_add(1);
        Some((id as u16, len))
    }

    /// Wait (at most `timeout` ns) for the next used entry; interrupts are acknowledged first,
    /// then the ring checked, so none is missed.
    pub fn wait(&mut self, timeout: u64) -> Option<(u16, u32)> {
        let deadline = sys::clock_ns().saturating_add(timeout);
        loop {
            if let Some(e) = self.pop() {
                return Some(e);
            }
            let now = sys::clock_ns();
            if now >= deadline {
                return None;
            }
            let _ = sys::object_wait(self.irq, sys::SIGNALED, deadline - now);
            let _ = sys::interrupt_ack(self.irq);
        }
    }

    pub fn interrupts(&self) -> u64 {
        sys::interrupt_ack(self.irq).unwrap_or(0)
    }
}
