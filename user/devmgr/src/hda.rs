//! Intel HD Audio controller driver (`hda.ddrv`, PCI class 04.03.*).
//!
//! - CORB/RIRB command/response rings in IOMMU-pinned DMA memory (with immediate-command fallback).
//! - Dynamic codec, Audio Function Group, widget, and pin graph discovery via `dosaudio::hda_graph`
//!   (no hardcoded board or codec tables).
//! - Jack detection via unsolicited RIRB responses + `GET_PIN_SENSE`.
//! - HDMI/DisplayPort ELD discovery (`GET_DIP_SIZE` / `GET_ELD_DATA` + `dosaudio::hda_graph::parse_eld`).
//! - 4-period BDL DMA streams (playback + capture) bridged to `audio.dsvc` via shared `IoRing`.
//! - Stall watchdog monitoring `SD_LPIB` progress while streams are active.

use core::sync::atomic::{Ordering, fence};

use dosaudio::hda_graph::{
    AudioPath, MAX_CONNS, MAX_PATHS, MAX_WIDGETS, PinDefault, Widget, WidgetType, discover_paths,
    parse_eld,
};
use dosaudio::route::{DeviceKind, FLAG_ELD_VALID, FLAG_PLUGGED};
use libd::audio::{self, FMT_S16_LE, RING_READ, RING_WRITE};
use libd::handle::sleep;
use libd::proto::{self, HEADER, Header};
use libd::ring::{Cqe, IoRing};
use libd::sys::{self, Handle};
use libd::{Dma, Mapping, Port, Startup, println};

const MS: u64 = 1_000_000;
const PAGE: u64 = 4096;

// HDA global controller registers (BAR 0)
const REG_GCAP: u64 = 0x00;
const REG_GCTL: u64 = 0x08;
const REG_STATESTS: u64 = 0x0E;
const REG_INTCTL: u64 = 0x20;
const REG_INTSTS: u64 = 0x24;
const REG_CORBLBASE: u64 = 0x40;
const REG_CORBUBASE: u64 = 0x44;
const REG_CORBWP: u64 = 0x48;
const REG_CORBRP: u64 = 0x4A;
const REG_CORBCTL: u64 = 0x4C;
const REG_CORBSTS: u64 = 0x4D;
const REG_CORBSIZE: u64 = 0x4E;
const REG_RIRBLBASE: u64 = 0x50;
const REG_RIRBUBASE: u64 = 0x54;
const REG_RIRBWP: u64 = 0x58;
const REG_RINTCNT: u64 = 0x5A;
const REG_RIRBCTL: u64 = 0x5C;
const REG_RIRBSTS: u64 = 0x5D;
const REG_RIRBSIZE: u64 = 0x5E;
const REG_ICW: u64 = 0x60;
const REG_IRR: u64 = 0x64;
const REG_ICS: u64 = 0x68;

const GCTL_CRST: u32 = 1 << 0;
const GCTL_UNSOL: u32 = 1 << 8;

// Stream descriptor offsets from `0x80 + idx * 0x20`
const SD_CTL: u64 = 0x00; // u16: SRST(0) | RUN(1) | IOCE(2) | FEIE(3) | DEIE(4)
const SD_CTL_HI: u64 = 0x02; // u8: STRM(7:4)
const SD_STS: u64 = 0x03; // u8: BCIS(2) | FIFOE(3) | DESE(4)
const SD_LPIB: u64 = 0x04;
const SD_CBL: u64 = 0x08;
const SD_LVI: u64 = 0x0C;
const SD_FMT: u64 = 0x12;
const SD_BDPL: u64 = 0x18;
const SD_BDPU: u64 = 0x1C;

const SD_SRST: u16 = 1 << 0;
const SD_RUN: u16 = 1 << 1;
const SD_IOCE: u16 = 1 << 2;
const SD_FEIE: u16 = 1 << 3;
const SD_DEIE: u16 = 1 << 4;
const SD_STS_BCIS: u8 = 1 << 2;
const SD_STS_ALL: u8 = (1 << 2) | (1 << 3) | (1 << 4);

// BDL geometry: 4 periods, each in its own 4 KiB DMA page (zero multi-page contiguity assumption).
const BDL_PERIODS: usize = 4;
const PERIOD_FRAMES: usize = 480; // 10 ms at 48 kHz
const PERIOD_BYTES: usize = PERIOD_FRAMES * 4; // stereo S16_LE = 1920 bytes <= 4096
const CBL_BYTES: u32 = (BDL_PERIODS * PERIOD_BYTES) as u32;

// DMA page layout inside `dma` (10 pages total)
const PG_CORB_RIRB: u64 = 0; // CORB at +0 (1024 B), RIRB at +0x800 (2048 B)
const PG_BDL: u64 = 1; // Out BDL at +0 (64 B), In BDL at +0x100 (64 B)
const PG_OUT_BUF: u64 = 2; // 4 pages (2..6)
const PG_IN_BUF: u64 = 6; // 4 pages (6..10)
const DMA_PAGES: u64 = 10;

const RIRB_OFF: u64 = 0x800;
const IN_BDL_OFF: u64 = 0x100;

const MAX_UNITS: usize = 16;

// Port keys
const KEY_CTL: u64 = 1;
const KEY_IRQ: u64 = 2;
const KEY_UNIT_BASE: u64 = 16;

const STREAM_TAG_OUT: u8 = 1;
const STREAM_TAG_IN: u8 = 2;
/// 48 kHz (base 0, mult 0, div 0), 16-bit (1 << 4), stereo (1): 0x0011.
const FMT_48K_S16_2CH: u16 = 0x0011;

const STALL_TIMEOUT_NS: u64 = 1_500 * MS;

#[derive(Clone, Copy)]
struct Endpoint {
    cad: u8,
    path: AudioPath,
    flags: u32,
    unsol_tag: u8,
    name: [u8; 40],
    name_len: usize,
    ch: Handle,
    muted: bool,
}

impl Endpoint {
    const fn empty() -> Self {
        Self {
            cad: 0,
            path: AudioPath::empty(),
            flags: 0,
            unsol_tag: 0,
            name: [0; 40],
            name_len: 0,
            ch: 0,
            muted: false,
        }
    }

    fn set_name(&mut self, s: &str) {
        let n = s.len().min(self.name.len());
        self.name[..n].copy_from_slice(&s.as_bytes()[..n]);
        self.name_len = n;
    }
}

struct ActiveStream {
    unit: usize,
    sd_idx: usize,
    ring: IoRing,
    last_period: usize,
    last_lpib: u32,
    last_progress_ns: u64,
    stalls: u32,
    frames_done: u64,
    xruns: u64,
}

struct Hda {
    mmio: Mapping,
    dma: Dma,
    ctl: Handle,
    irq: Handle,
    port: Port,
    iss: usize,
    oss: usize,
    use_corb: bool,
    corb_entries: u16,
    rirb_entries: u16,
    corb_wp: u16,
    rirb_rp: u16,
    units: [Option<Endpoint>; MAX_UNITS],
    unit_count: usize,
    out_stream: Option<ActiveStream>,
    in_stream: Option<ActiveStream>,
    pending_unsol: [(u8, u32); 16],
    pending_unsol_len: usize,
    fatal_stall: bool,
}

impl Hda {
    fn r8(&self, off: u64) -> u8 {
        self.mmio.r8(off)
    }
    fn r16(&self, off: u64) -> u16 {
        self.mmio.r16(off)
    }
    fn r32(&self, off: u64) -> u32 {
        self.mmio.r32(off)
    }
    fn w8(&self, off: u64, v: u8) {
        self.mmio.w8(off, v);
    }
    fn w16(&self, off: u64, v: u16) {
        self.mmio.w16(off, v);
    }
    fn w32(&self, off: u64, v: u32) {
        self.mmio.w32(off, v);
    }

    fn sd_base(idx: usize) -> u64 {
        0x80 + (idx as u64) * 0x20
    }

    /// Reset controller (`GCTL.CRST` 0 -> 1) and return `STATESTS` codec bitmask.
    fn reset_controller(&mut self) -> Result<u16, &'static str> {
        let gctl = self.r32(REG_GCTL);
        self.w32(REG_GCTL, gctl & !GCTL_CRST);
        let deadline = sys::clock_ns() + 50 * MS;
        while (self.r32(REG_GCTL) & GCTL_CRST) != 0 {
            if sys::clock_ns() >= deadline {
                return Err("controller did not enter reset");
            }
            sleep(MS);
        }
        sleep(2 * MS);
        self.w32(REG_GCTL, GCTL_CRST);
        let deadline = sys::clock_ns() + 50 * MS;
        while (self.r32(REG_GCTL) & GCTL_CRST) == 0 {
            if sys::clock_ns() >= deadline {
                return Err("controller did not leave reset");
            }
            sleep(MS);
        }
        // Per HDA spec 4.3, wait >= 521 us for codecs to enumerate on STATESTS.
        sleep(5 * MS);
        let statests = self.r16(REG_STATESTS);
        // Clear STATESTS (W1C) and disable wake interrupts.
        self.w16(REG_STATESTS, statests);
        Ok(statests)
    }

    /// Initialize CORB and RIRB rings in IOMMU-pinned DMA memory; falls back to ICW/IRR if unsupported.
    fn init_corb_rirb(&mut self) {
        // Stop CORB and RIRB first.
        self.w8(REG_CORBCTL, 0);
        self.w8(REG_RIRBCTL, 0);
        sleep(MS);

        let corb_cap = self.r8(REG_CORBSIZE);
        let rirb_cap = self.r8(REG_RIRBSIZE);
        let choose = |cap: u8| -> Option<(u8, u16)> {
            if (cap & (1 << 6)) != 0 {
                Some((2, 256))
            } else if (cap & (1 << 5)) != 0 {
                Some((1, 16))
            } else if (cap & (1 << 4)) != 0 {
                Some((0, 2))
            } else {
                None
            }
        };
        let (Some((csel, ccnt)), Some((rsel, rcnt))) = (choose(corb_cap), choose(rirb_cap)) else {
            self.use_corb = false;
            return;
        };

        // Zero CORB/RIRB page.
        for o in (0..PAGE).step_by(8) {
            self.dma.map.w64(PG_CORB_RIRB * PAGE + o, 0);
        }
        let corb_da = self.dma.dev_addr(PG_CORB_RIRB * PAGE);
        let rirb_da = corb_da + RIRB_OFF;

        self.w8(REG_CORBSIZE, (corb_cap & 0xFC) | csel);
        self.w32(REG_CORBLBASE, corb_da as u32);
        self.w32(REG_CORBUBASE, (corb_da >> 32) as u32);
        // Reset CORB read pointer.
        self.w16(REG_CORBRP, 0x8000);
        let dl = sys::clock_ns() + 10 * MS;
        while (self.r16(REG_CORBRP) & 0x8000) == 0 && sys::clock_ns() < dl {
            sleep(MS / 2);
        }
        self.w16(REG_CORBRP, 0);
        let dl = sys::clock_ns() + 10 * MS;
        while (self.r16(REG_CORBRP) & 0x8000) != 0 && sys::clock_ns() < dl {
            sleep(MS / 2);
        }
        self.w16(REG_CORBWP, 0);
        self.corb_wp = 0;
        self.corb_entries = ccnt;

        self.w8(REG_RIRBSIZE, (rirb_cap & 0xFC) | rsel);
        self.w32(REG_RIRBLBASE, rirb_da as u32);
        self.w32(REG_RIRBUBASE, (rirb_da >> 32) as u32);
        self.w16(REG_RIRBWP, 0x8000);
        self.w16(REG_RINTCNT, 1);
        self.rirb_rp = 0;
        self.rirb_entries = rcnt;

        // Clear status bits and start DMA engines + unsolicited response acceptance.
        self.w8(REG_CORBSTS, 0x01);
        self.w8(REG_RIRBSTS, 0x05);
        self.w8(REG_CORBCTL, 0x02); // CORBRUN
        self.w8(REG_RIRBCTL, 0x03); // RIRBDMAEN | RINTCTL
        let gctl = self.r32(REG_GCTL);
        self.w32(REG_GCTL, gctl | GCTL_UNSOL);
        self.use_corb = true;
    }

    /// Drain any unsolicited RIRB responses into `pending_unsol` and return a solicited response if present.
    fn drain_rirb(&mut self, want_cad: Option<u8>) -> Option<u32> {
        if !self.use_corb {
            return None;
        }
        let mut found: Option<u32> = None;
        let wp = self.r16(REG_RIRBWP) % self.rirb_entries;
        fence(Ordering::Acquire);
        while self.rirb_rp != wp {
            self.rirb_rp = (self.rirb_rp + 1) % self.rirb_entries;
            let off = PG_CORB_RIRB * PAGE + RIRB_OFF + u64::from(self.rirb_rp) * 8;
            let resp = self.dma.map.r32(off);
            let ex = self.dma.map.r32(off + 4);
            let cad = (ex & 0x0F) as u8;
            let unsol = (ex & (1 << 4)) != 0;
            if unsol {
                if self.pending_unsol_len < self.pending_unsol.len() {
                    self.pending_unsol[self.pending_unsol_len] = (cad, resp);
                    self.pending_unsol_len += 1;
                }
            } else if found.is_none() && want_cad.is_none_or(|c| c == cad) {
                found = Some(resp);
            }
        }
        let sts = self.r8(REG_RIRBSTS);
        if sts != 0 {
            self.w8(REG_RIRBSTS, sts);
        }
        found
    }

    /// Execute one HDA verb `(cad, nid, verb)` via CORB/RIRB (or ICW/IRR fallback).
    fn verb(&mut self, cad: u8, nid: u8, verb: u32) -> Option<u32> {
        let cmd = (u32::from(cad & 0xF) << 28) | (u32::from(nid) << 20) | (verb & 0xF_FFFF);
        if self.use_corb {
            // Drain stale entries first.
            let _ = self.drain_rirb(None);
            let next_wp = (self.corb_wp + 1) % self.corb_entries;
            let off = PG_CORB_RIRB * PAGE + u64::from(next_wp) * 4;
            self.dma.map.w32(off, cmd);
            fence(Ordering::SeqCst);
            self.corb_wp = next_wp;
            self.w16(REG_CORBWP, next_wp);
            let dl = sys::clock_ns() + 20 * MS;
            while sys::clock_ns() < dl {
                if let Some(r) = self.drain_rirb(Some(cad)) {
                    return Some(r);
                }
                sleep(MS / 5);
            }
            return None;
        }
        // Immediate command fallback (ICW / IRR / ICS).
        let dl = sys::clock_ns() + 10 * MS;
        while (self.r16(REG_ICS) & 1) != 0 {
            if sys::clock_ns() >= dl {
                return None;
            }
        }
        self.w16(REG_ICS, 0x0002); // Clear IRV
        self.w32(REG_ICW, cmd);
        self.w16(REG_ICS, 0x0001); // Set ICB
        let dl = sys::clock_ns() + 10 * MS;
        while (self.r16(REG_ICS) & 0x0002) == 0 {
            if sys::clock_ns() >= dl {
                return None;
            }
        }
        let resp = self.r32(REG_IRR);
        self.w16(REG_ICS, 0x0002);
        Some(resp)
    }

    fn get_param(&mut self, cad: u8, nid: u8, param: u8) -> u32 {
        self.verb(cad, nid, 0xF0000 | u32::from(param)).unwrap_or(0)
    }

    fn read_conn_list(&mut self, cad: u8, nid: u8, out: &mut [u8; MAX_CONNS]) -> u8 {
        let clen = self.get_param(cad, nid, 0x0E);
        let long_form = (clen & 0x80) != 0;
        let entries = (clen & 0x7F) as usize;
        if entries == 0 {
            return 0;
        }
        let mut count = 0usize;
        let mut prev_nid = 0u8;
        let step = if long_form { 2 } else { 4 };
        let mut idx = 0usize;
        while idx < entries && count < MAX_CONNS {
            let word = self.verb(cad, nid, 0xF0200 | (idx as u32)).unwrap_or(0);
            for s in 0..step {
                if idx + s >= entries || count >= MAX_CONNS {
                    break;
                }
                let (range, val) = if long_form {
                    let raw = ((word >> (s * 16)) & 0xFFFF) as u16;
                    ((raw & 0x8000) != 0, (raw & 0x7FFF) as u8)
                } else {
                    let raw = ((word >> (s * 8)) & 0xFF) as u8;
                    ((raw & 0x80) != 0, raw & 0x7F)
                };
                if range && prev_nid != 0 && val > prev_nid {
                    for n in (prev_nid + 1)..=val {
                        if count < MAX_CONNS {
                            out[count] = n;
                            count += 1;
                        }
                    }
                } else if val != 0 {
                    out[count] = val;
                    count += 1;
                }
                prev_nid = val;
            }
            idx += step;
        }
        count as u8
    }

    /// Read HDMI/DP ELD data from a digital pin widget (returns `(eld_valid, monitor_name)`).
    fn read_eld(&mut self, cad: u8, pin_nid: u8) -> (bool, [u8; 16], usize) {
        let sense = self.verb(cad, pin_nid, 0xF0900).unwrap_or(0);
        let eld_valid = (sense & (1 << 30)) != 0;
        if !eld_valid {
            return (false, [0; 16], 0);
        }
        let size = (self.verb(cad, pin_nid, 0xF2E08).unwrap_or(0) & 0xFF) as usize;
        if size < 20 {
            return (true, [0; 16], 0);
        }
        let cap = size.min(128);
        let mut buf = [0u8; 128];
        for (i, slot) in buf.iter_mut().take(cap).enumerate() {
            let r = self.verb(cad, pin_nid, 0xF2F00 | (i as u32)).unwrap_or(0);
            if (r & (1 << 31)) == 0 {
                return (false, [0; 16], 0);
            }
            *slot = (r & 0xFF) as u8;
        }
        if let Some(eld) = parse_eld(&buf[..cap]) {
            let mut nm = [0u8; 16];
            let n = (eld.monitor_name_len as usize).min(16);
            nm[..n].copy_from_slice(&eld.monitor_name[..n]);
            (true, nm, n)
        } else {
            (false, [0; 16], 0)
        }
    }

    /// Query pin sense & ELD for an endpoint and update its flags/name.
    fn refresh_pin_sense(&mut self, u: usize) -> bool {
        let Some(ep) = self.units[u] else { return false };
        if !ep.path.jack_detect && !ep.path.is_hdmi_dp {
            return false;
        }
        let sense = self.verb(ep.cad, ep.path.pin_nid, 0xF0900).unwrap_or(0);
        let plugged = (sense & (1 << 31)) != 0;
        let mut new_flags = ep.flags & !(FLAG_PLUGGED | FLAG_ELD_VALID);
        if plugged {
            new_flags |= FLAG_PLUGGED;
        }
        let mut monitor = ([0u8; 16], 0usize);
        if plugged && ep.path.is_hdmi_dp {
            let (ev, nm, nlen) = self.read_eld(ep.cad, ep.path.pin_nid);
            if ev {
                new_flags |= FLAG_ELD_VALID;
                monitor = (nm, nlen);
            }
        }
        let changed = new_flags != ep.flags || monitor.1 > 0;
        if let Some(ep_mut) = self.units[u].as_mut() {
            ep_mut.flags = new_flags;
            if monitor.1 > 0 {
                let mut full = [0u8; 40];
                let prefix = b"HDA HDMI (";
                full[..prefix.len()].copy_from_slice(prefix);
                let mut pos = prefix.len();
                let copy = monitor.1.min(full.len() - pos - 1);
                full[pos..pos + copy].copy_from_slice(&monitor.0[..copy]);
                pos += copy;
                full[pos] = b')';
                pos += 1;
                ep_mut.name[..pos].copy_from_slice(&full[..pos]);
                ep_mut.name_len = pos;
            }
        }
        changed
    }

    /// Mute or unmute output amps along `path` on codec `cad`.
    fn apply_mute(&mut self, cad: u8, path: &AudioPath, muted: bool) {
        let mute_bit: u32 = if muted { 0x80 } else { 0 };
        for &hop in path.hops() {
            let wcaps = self.get_param(cad, hop.nid, 0x09);
            if (wcaps & (1 << 2)) != 0 {
                let caps = self.get_param(cad, hop.nid, 0x12);
                let gain = if (caps & 0x7F) != 0 { caps & 0x7F } else { (caps >> 8) & 0x7F };
                let payload = (1 << 15) | (1 << 13) | (1 << 12) | mute_bit | (gain & 0x7F);
                let _ = self.verb(cad, hop.nid, 0x30000 | payload);
            }
        }
    }

    /// Program all widgets along `path` to active D0 power, unmuted amps, selected mux inputs, and pin enable.
    fn configure_path(&mut self, cad: u8, path: &AudioPath, stream_tag: u8, fmt: u16) {
        // Walk every widget on the path and power it up + unmute + select connection.
        for &hop in path.hops() {
            let wcaps = self.get_param(cad, hop.nid, 0x09);
            if (wcaps & (1 << 10)) != 0 {
                let _ = self.verb(cad, hop.nid, 0x70500); // D0
            }
            let wtype = WidgetType::from_caps(wcaps);
            // Select connection index on pins/selectors/ADCs when conn list has > 1 entries.
            let clen = self.get_param(cad, hop.nid, 0x0E) & 0x7F;
            if clen > 1 && matches!(wtype, WidgetType::PinComplex | WidgetType::AudioSelector | WidgetType::AudioInput) {
                let _ = self.verb(cad, hop.nid, 0x70100 | u32::from(hop.conn_index));
            }
            // Unmute output amp at 0 dB (or max safe offset).
            if (wcaps & (1 << 2)) != 0 {
                let caps = self.get_param(cad, hop.nid, 0x12);
                let gain = if (caps & 0x7F) != 0 { caps & 0x7F } else { (caps >> 8) & 0x7F };
                let payload = (1 << 15) | (1 << 13) | (1 << 12) | (gain & 0x7F);
                let _ = self.verb(cad, hop.nid, 0x30000 | payload);
            }
            // Unmute input amp on this hop's selected input index.
            if (wcaps & (1 << 1)) != 0 {
                let caps = self.get_param(cad, hop.nid, 0x0D);
                let gain = if (caps & 0x7F) != 0 { caps & 0x7F } else { (caps >> 8) & 0x7F };
                let idx = u32::from(hop.conn_index & 0x0F);
                let payload = (1 << 14) | (1 << 13) | (1 << 12) | (idx << 8) | (gain & 0x7F);
                let _ = self.verb(cad, hop.nid, 0x30000 | payload);
            }
        }
        // Enable EAPD if present on output pin.
        if path.eapd {
            let _ = self.verb(cad, path.pin_nid, 0x70C02);
        }
        // Configure Pin Widget Control (OUT_EN / HP_EN for output, IN_EN for input).
        let pin_ctl = if path.is_output {
            0x40 | if path.hp_amp { 0x80 } else { 0 }
        } else {
            0x20
        };
        let _ = self.verb(cad, path.pin_nid, 0x70700 | pin_ctl);
        // Enable digital converter for HDMI/DP codecs.
        if path.is_hdmi_dp {
            let _ = self.verb(cad, path.converter_nid, 0x70D01);
        }
        // Bind converter to stream tag + format (reset tag to 0 first so codecs re-arm cleanly after a crash).
        let _ = self.verb(cad, path.converter_nid, 0x70600);
        let _ = self.verb(cad, path.converter_nid, 0x70600 | (u32::from(stream_tag & 0xF) << 4));
        let _ = self.verb(cad, path.converter_nid, 0x20000 | u32::from(fmt));
    }

    /// Walk all codecs reported in `statests`, discover AFGs and dynamic widget/pin paths.
    fn discover_codecs(&mut self, statests: u16) {
        for cad in 0..15u8 {
            if (statests & (1 << cad)) == 0 {
                continue;
            }
            let vid_did = self.get_param(cad, 0, 0x00);
            let sub = self.get_param(cad, 0, 0x04);
            let fg_start = ((sub >> 16) & 0xFF) as u8;
            let fg_count = (sub & 0xFF) as u8;
            println!("hda: codec {} vendor={:#06x} device={:#06x} ({} function group(s))", cad, vid_did >> 16, vid_did & 0xFFFF, fg_count);
            for fg in fg_start..fg_start.saturating_add(fg_count) {
                let fg_type = self.get_param(cad, fg, 0x05) & 0xFF;
                if fg_type != 0x01 {
                    continue; // not an Audio Function Group
                }
                // Power up AFG to D0.
                let _ = self.verb(cad, fg, 0x70500);
                let wsub = self.get_param(cad, fg, 0x04);
                let w_start = ((wsub >> 16) & 0xFF) as u8;
                let w_count = (wsub & 0xFF).min(MAX_WIDGETS as u32) as usize;

                let mut widgets = [Widget::empty(); MAX_WIDGETS];
                for (i, slot) in widgets.iter_mut().take(w_count).enumerate() {
                    let nid = w_start.saturating_add(i as u8);
                    let wcaps = self.get_param(cad, nid, 0x09);
                    let wtype = WidgetType::from_caps(wcaps);
                    let mut w = Widget::empty();
                    w.nid = nid;
                    w.wcaps = wcaps;
                    if wtype == WidgetType::PinComplex {
                        w.pin_caps = self.get_param(cad, nid, 0x0C);
                        w.pin_default = PinDefault::new(self.verb(cad, nid, 0xF1C00).unwrap_or(0));
                    }
                    if w.has_out_amp() {
                        w.out_amp_caps = self.get_param(cad, nid, 0x12);
                    }
                    if w.has_in_amp() {
                        w.in_amp_caps = self.get_param(cad, nid, 0x0D);
                    }
                    if (wcaps & (1 << 8)) != 0 {
                        w.conn_len = self.read_conn_list(cad, nid, &mut w.conns);
                    }
                    *slot = w;
                }

                let mut paths = [AudioPath::empty(); MAX_PATHS];
                let npaths = discover_paths(&widgets[..w_count], &mut paths);
                for p in paths.iter().take(npaths) {
                    if self.unit_count >= MAX_UNITS {
                        break;
                    }
                    let u = self.unit_count;
                    let mut ep = Endpoint::empty();
                    ep.cad = cad;
                    ep.path = *p;
                    ep.flags = p.initial_flags;
                    ep.unsol_tag = (u as u8) + 1;
                    let base_name = match p.kind {
                        DeviceKind::Headphones => "HDA Headphones",
                        DeviceKind::Speaker => "HDA Speakers",
                        DeviceKind::LineOut => "HDA Line Out",
                        DeviceKind::HdmiDp => "HDA HDMI/DP",
                        DeviceKind::Microphone => "HDA Microphone",
                        DeviceKind::LineIn => "HDA Line In",
                        _ => "HDA Audio",
                    };
                    ep.set_name(base_name);
                    self.units[u] = Some(ep);
                    self.unit_count += 1;

                    // Enable unsolicited jack/ELD events on jack-detectable pins.
                    if p.jack_detect || p.is_hdmi_dp {
                        let _ = self.verb(cad, p.pin_nid, 0x70800 | 0x80 | u32::from(ep.unsol_tag));
                        let _ = self.refresh_pin_sense(u);
                    }

                    if let Some(ep) = self.units[u] {
                        println!(
                            "hda: unit {} {} (codec {} pin {} <-> conv {}, flags={:#x})",
                            u,
                            core::str::from_utf8(&ep.name[..ep.name_len]).unwrap_or("?"),
                            cad,
                            p.pin_nid,
                            p.converter_nid,
                            ep.flags
                        );
                    }
                }
            }
        }
        for u in 0..self.unit_count {
            self.announce_unit(u);
        }
    }

    fn announce_unit(&self, u: usize) {
        let Some(ep) = self.units[u] else { return };
        let a = (u as u64) | ((ep.path.kind as u64) << 16) | ((ep.flags as u64) << 32);
        let b = 48_000u64 | (2u64 << 32) | (u64::from(FMT_S16_LE) << 40);
        let mut msg = [0u8; HEADER + 40];
        Header { txid: 0, op: proto::AUDIO_DEV, status: 0, a, b }.put(&mut msg);
        msg[HEADER..HEADER + ep.name_len].copy_from_slice(&ep.name[..ep.name_len]);
        let _ = sys::channel_write(self.ctl, &msg[..HEADER + ep.name_len]);
    }

    fn notify_jack(&self, u: usize) {
        let Some(ep) = self.units[u] else { return };
        let mut msg = [0u8; HEADER + 40];
        Header { txid: 0, op: proto::AUDIO_JACK, status: 0, a: u as u64, b: u64::from(ep.flags) }.put(&mut msg);
        msg[HEADER..HEADER + ep.name_len].copy_from_slice(&ep.name[..ep.name_len]);
        let _ = sys::channel_write(self.ctl, &msg[..HEADER + ep.name_len]);
    }

    /// Reset a stream descriptor (`SRST` 1 -> 0), program BDL/CBL/LVI/FMT/STRM, and start DMA.
    fn start_sd(&mut self, sd_idx: usize, is_output: bool, stream_tag: u8) -> Result<(), &'static str> {
        let base = Self::sd_base(sd_idx);
        // Stop stream first.
        self.w16(base + SD_CTL, 0);
        let dl = sys::clock_ns() + 20 * MS;
        while (self.r16(base + SD_CTL) & SD_RUN) != 0 && sys::clock_ns() < dl {
            sleep(MS / 2);
        }
        // Reset stream descriptor.
        self.w16(base + SD_CTL, SD_SRST);
        let dl = sys::clock_ns() + 20 * MS;
        while (self.r16(base + SD_CTL) & SD_SRST) == 0 && sys::clock_ns() < dl {
            sleep(MS / 2);
        }
        self.w16(base + SD_CTL, 0);
        let dl = sys::clock_ns() + 20 * MS;
        while (self.r16(base + SD_CTL) & SD_SRST) != 0 && sys::clock_ns() < dl {
            sleep(MS / 2);
        }
        self.w8(base + SD_STS, SD_STS_ALL);

        // Fill 4-entry BDL (each entry points to its own 4 KiB page) and zero period buffers.
        let bdl_off = PG_BDL * PAGE + if is_output { 0 } else { IN_BDL_OFF };
        let buf_pg = if is_output { PG_OUT_BUF } else { PG_IN_BUF };
        for i in 0..BDL_PERIODS {
            let pg = buf_pg + i as u64;
            for o in (0..PERIOD_BYTES as u64).step_by(8) {
                self.dma.map.w64(pg * PAGE + o, 0);
            }
            let entry = bdl_off + (i as u64) * 16;
            self.dma.map.w64(entry, self.dma.dev_addr(pg * PAGE));
            self.dma.map.w32(entry + 8, PERIOD_BYTES as u32);
            self.dma.map.w32(entry + 12, 1); // IOC = 1 on every period
        }
        fence(Ordering::SeqCst);

        let bdl_da = self.dma.dev_addr(PG_BDL * PAGE) + if is_output { 0 } else { IN_BDL_OFF };
        self.w32(base + SD_BDPL, bdl_da as u32);
        self.w32(base + SD_BDPU, (bdl_da >> 32) as u32);
        self.w32(base + SD_CBL, CBL_BYTES);
        self.w16(base + SD_LVI, (BDL_PERIODS - 1) as u16);
        self.w16(base + SD_FMT, FMT_48K_S16_2CH);
        self.w8(base + SD_CTL_HI, (stream_tag & 0x0F) << 4);

        // Enable controller + stream interrupt in INTCTL.
        let intctl = self.r32(REG_INTCTL);
        self.w32(REG_INTCTL, intctl | (1 << 31) | (1 << 30) | (1u32 << sd_idx));

        // Start DMA!
        self.w16(base + SD_CTL, SD_RUN | SD_IOCE | SD_FEIE | SD_DEIE);
        Ok(())
    }

    fn stop_sd(&mut self, sd_idx: usize) {
        let base = Self::sd_base(sd_idx);
        self.w16(base + SD_CTL, 0);
        self.w8(base + SD_STS, SD_STS_ALL);
        let intctl = self.r32(REG_INTCTL);
        self.w32(REG_INTCTL, intctl & !(1u32 << sd_idx));
    }

    /// Open playback or capture stream on `unit` with `ring_vmo`.
    fn open_stream(&mut self, unit: usize, capture: bool, ring_vmo: Handle) -> Result<(), i32> {
        let Some(ep) = self.units[unit] else {
            sys::handle_close(ring_vmo);
            return Err(sys::ERR_BAD_STATE as i32);
        };
        if ep.path.is_output == capture {
            sys::handle_close(ring_vmo);
            return Err(sys::ERR_INVALID_ARGS as i32);
        }
        let sd_idx = if capture {
            if self.iss == 0 {
                sys::handle_close(ring_vmo);
                return Err(sys::ERR_NOT_SUPPORTED as i32);
            }
            0
        } else {
            if self.oss == 0 {
                sys::handle_close(ring_vmo);
                return Err(sys::ERR_NOT_SUPPORTED as i32);
            }
            self.iss
        };
        let ring = IoRing::attach(ring_vmo).map_err(|e| e as i32)?;
        let tag = if capture { STREAM_TAG_IN } else { STREAM_TAG_OUT };

        // Stop any existing stream in this direction.
        if capture {
            if let Some(old) = self.in_stream.take() {
                self.stop_sd(old.sd_idx);
            }
        } else if let Some(old) = self.out_stream.take() {
            self.stop_sd(old.sd_idx);
        }

        self.configure_path(ep.cad, &ep.path, tag, FMT_48K_S16_2CH);
        if !capture && ep.muted {
            self.apply_mute(ep.cad, &ep.path, true);
        }
        if self.start_sd(sd_idx, !capture, tag).is_err() {
            return Err(proto::ERR_IO);
        }

        let now = sys::clock_ns();
        let st = ActiveStream {
            unit,
            sd_idx,
            ring,
            last_period: 0,
            last_lpib: 0,
            last_progress_ns: now,
            stalls: 0,
            frames_done: 0,
            xruns: 0,
        };
        if capture {
            self.in_stream = Some(st);
        } else {
            self.out_stream = Some(st);
            // Pre-fill initial playback periods if the service already pushed SQEs.
            self.pump_output(true);
        }
        Ok(())
    }

    fn copy_to_dma_period(dma: &Dma, buf_pg: u64, period_idx: usize, src: &[u8]) {
        let base = (buf_pg + (period_idx % BDL_PERIODS) as u64) * PAGE;
        let len = src.len().min(PERIOD_BYTES);
        let mut i = 0usize;
        while i + 4 <= len {
            let w = u32::from_le_bytes([src[i], src[i + 1], src[i + 2], src[i + 3]]);
            dma.map.w32(base + i as u64, w);
            i += 4;
        }
        while i < len {
            dma.map.w8(base + i as u64, src[i]);
            i += 1;
        }
        while i + 4 <= PERIOD_BYTES {
            dma.map.w32(base + i as u64, 0);
            i += 4;
        }
        while i < PERIOD_BYTES {
            dma.map.w8(base + i as u64, 0);
            i += 1;
        }
        fence(Ordering::Release);
    }

    fn copy_from_dma_period(dma: &Dma, buf_pg: u64, period_idx: usize, dst: &mut [u8]) {
        fence(Ordering::Acquire);
        let base = (buf_pg + (period_idx % BDL_PERIODS) as u64) * PAGE;
        let len = dst.len().min(PERIOD_BYTES);
        let mut i = 0usize;
        while i + 4 <= len {
            let w = dma.map.r32(base + i as u64).to_le_bytes();
            dst[i..i + 4].copy_from_slice(&w);
            i += 4;
        }
        while i < len {
            dst[i] = dma.map.r8(base + i as u64);
            i += 1;
        }
    }

    /// Advance playback DMA periods, pull SQEs from `audio.dsvc`'s `IoRing`, and run stall watchdog.
    fn pump_output(&mut self, initial_prefill: bool) {
        let Some(st) = self.out_stream.as_mut() else { return };
        let base = Self::sd_base(st.sd_idx);
        let sts = self.mmio.r8(base + SD_STS);
        if sts != 0 {
            self.mmio.w8(base + SD_STS, sts & SD_STS_ALL);
        }
        let lpib = self.mmio.r32(base + SD_LPIB);
        let cur_period = ((lpib as usize) / PERIOD_BYTES) % BDL_PERIODS;
        let now = sys::clock_ns();

        if lpib != st.last_lpib || (sts & SD_STS_BCIS) != 0 {
            st.last_lpib = lpib;
            st.last_progress_ns = now;
            st.stalls = 0;
        }

        let mut completed_any = false;
        let mut unit = st.unit;
        if initial_prefill {
            // Fill periods 0..BDL_PERIODS-1 from any ready SQEs before first wrap.
            for p in 0..BDL_PERIODS {
                if let Some(sqe) = st.ring.pop_sq() {
                    if sqe.op == RING_WRITE
                        && let Some(data) = st.ring.data(sqe.buf_off, sqe.buf_len)
                    {
                        let len = data.len().min(PERIOD_BYTES);
                        let dma_base = (PG_OUT_BUF + p as u64) * PAGE;
                        let mut i = 0;
                        while i + 4 <= len {
                            let w = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
                            self.dma.map.w32(dma_base + i as u64, w);
                            i += 4;
                        }
                        while i < PERIOD_BYTES {
                            self.dma.map.w8(dma_base + i as u64, if i < len { data[i] } else { 0 });
                            i += 1;
                        }
                        st.ring.push_cq(Cqe { id: sqe.id, status: 0, a: len as u64 });
                        st.frames_done += PERIOD_FRAMES as u64;
                        completed_any = true;
                    } else {
                        st.ring.push_cq(Cqe { id: sqe.id, status: sys::ERR_INVALID_ARGS as i32, a: 0 });
                    }
                }
            }
            fence(Ordering::Release);
            st.last_period = cur_period;
        } else {
            while st.last_period != cur_period {
                let done_p = st.last_period;
                st.last_period = (st.last_period + 1) % BDL_PERIODS;
                if let Some(sqe) = st.ring.pop_sq() {
                    if sqe.op == RING_WRITE
                        && let Some(data) = st.ring.data(sqe.buf_off, sqe.buf_len)
                    {
                        let mut tmp = [0u8; PERIOD_BYTES];
                        let len = data.len().min(PERIOD_BYTES);
                        tmp[..len].copy_from_slice(&data[..len]);
                        // Write into the period that just completed (safely behind DMA pointer).
                        Self::copy_to_dma_period(&self.dma, PG_OUT_BUF, done_p, &tmp[..len]);
                        st.ring.push_cq(Cqe { id: sqe.id, status: 0, a: len as u64 });
                        st.frames_done += PERIOD_FRAMES as u64;
                    } else {
                        st.ring.push_cq(Cqe { id: sqe.id, status: sys::ERR_INVALID_ARGS as i32, a: 0 });
                    }
                } else {
                    // Underrun: fill silence so hardware never replays stale tone!
                    Self::copy_to_dma_period(&self.dma, PG_OUT_BUF, done_p, &[]);
                    st.xruns += 1;
                }
                completed_any = true;
            }
        }

        let frames_done = st.frames_done;
        let xruns = st.xruns;
        let stalled = !initial_prefill && now.saturating_sub(st.last_progress_ns) >= STALL_TIMEOUT_NS;
        let sd_idx = st.sd_idx;
        if stalled {
            st.stalls += 1;
            st.last_progress_ns = now;
            let count = st.stalls;
            unit = st.unit;
            println!("hda: stall watchdog triggered on output stream (LPIB={:#x}, attempt {})", lpib, count);
            if count >= 2 {
                self.fatal_stall = true;
                return;
            }
            if let Some(ep) = self.units[unit] {
                self.configure_path(ep.cad, &ep.path, STREAM_TAG_OUT, FMT_48K_S16_2CH);
                let _ = self.start_sd(sd_idx, true, STREAM_TAG_OUT);
            }
            return;
        }

        if completed_any
            && let Some(ep) = self.units[unit]
            && ep.ch != 0
        {
            proto::send(ep.ch, audio::DRV_EVENT, frames_done, xruns);
        }
    }

    /// Advance capture DMA periods and fill pending `RING_READ` SQEs in `audio.dsvc`'s `IoRing`.
    fn pump_input(&mut self) {
        let Some(st) = self.in_stream.as_mut() else { return };
        let base = Self::sd_base(st.sd_idx);
        let sts = self.mmio.r8(base + SD_STS);
        if sts != 0 {
            self.mmio.w8(base + SD_STS, sts & SD_STS_ALL);
        }
        let lpib = self.mmio.r32(base + SD_LPIB);
        let cur_period = ((lpib as usize) / PERIOD_BYTES) % BDL_PERIODS;
        let now = sys::clock_ns();
        if lpib != st.last_lpib || (sts & SD_STS_BCIS) != 0 {
            st.last_lpib = lpib;
            st.last_progress_ns = now;
            st.stalls = 0;
        }
        let mut completed_any = false;
        while st.last_period != cur_period {
            let done_p = st.last_period;
            st.last_period = (st.last_period + 1) % BDL_PERIODS;
            if let Some(sqe) = st.ring.pop_sq() {
                if sqe.op == RING_READ {
                    let want = (sqe.buf_len as usize).min(PERIOD_BYTES);
                    let mut tmp = [0u8; PERIOD_BYTES];
                    Self::copy_from_dma_period(&self.dma, PG_IN_BUF, done_p, &mut tmp[..want]);
                    if let Some(dst) = st.ring.data_mut(sqe.buf_off, want as u32) {
                        dst.copy_from_slice(&tmp[..want]);
                        st.ring.push_cq(Cqe { id: sqe.id, status: 0, a: want as u64 });
                        st.frames_done += (want / 4) as u64;
                    } else {
                        st.ring.push_cq(Cqe { id: sqe.id, status: sys::ERR_INVALID_ARGS as i32, a: 0 });
                    }
                } else {
                    st.ring.push_cq(Cqe { id: sqe.id, status: sys::ERR_INVALID_ARGS as i32, a: 0 });
                }
                completed_any = true;
            }
        }
        let unit = st.unit;
        let frames_done = st.frames_done;
        let xruns = st.xruns;
        if completed_any
            && let Some(ep) = self.units[unit]
            && ep.ch != 0
        {
            proto::send(ep.ch, audio::DRV_EVENT, frames_done, xruns);
        }
    }

    fn process_unsol(&mut self) {
        let _ = self.drain_rirb(None);
        let count = self.pending_unsol_len;
        if count == 0 {
            return;
        }
        let items = self.pending_unsol;
        self.pending_unsol_len = 0;
        for &(cad, resp) in &items[..count] {
            let tag = ((resp >> 26) & 0x3F) as u8;
            for u in 0..self.unit_count {
                if self.units[u].is_some_and(|e| e.cad == cad && e.unsol_tag == tag)
                    && self.refresh_pin_sense(u)
                {
                    self.notify_jack(u);
                }
            }
        }
    }

    fn handle_irq(&mut self) {
        if self.irq != 0 {
            let _ = sys::interrupt_ack(self.irq);
            self.port.arm(self.irq, sys::SIGNALED, KEY_IRQ);
        }
        let intsts = self.r32(REG_INTSTS);
        if (intsts & (1 << 30)) != 0 {
            self.process_unsol();
        }
        self.pump_output(false);
        self.pump_input();
    }

    fn handle_ctl(&mut self) {
        let mut buf = [0u8; HEADER + 64];
        loop {
            let mut hs = [0 as Handle; 1];
            match sys::channel_read_h(self.ctl, &mut buf, &mut hs, 0) {
                Ok((n, nh)) => {
                    let hnd = if nh > 0 { hs[0] } else { 0 };
                    let Some(h) = Header::get(&buf[..n]) else {
                        if hnd != 0 {
                            sys::handle_close(hnd);
                        }
                        continue;
                    };
                    match h.op {
                        proto::AUDIO_ATTACH if hnd != 0 => {
                            let u = h.a as usize;
                            if u < self.unit_count
                                && let Some(ep) = self.units[u].as_mut()
                            {
                                if ep.ch != 0 {
                                    sys::handle_close(ep.ch);
                                }
                                ep.ch = hnd;
                                self.port.arm(hnd, sys::READABLE | sys::PEER_CLOSED, KEY_UNIT_BASE + u as u64);
                            } else {
                                sys::handle_close(hnd);
                            }
                        }
                        proto::TEST_CRASH => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                            println!("hda: intentional crash requested (test)");
                            sys::process_exit(sys::EXIT_FAULT);
                        }
                        _ => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                        }
                    }
                }
                Err(sys::ERR_SHOULD_WAIT) => {
                    self.port.arm(self.ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
                    return;
                }
                Err(_) => return,
            }
        }
    }

    fn handle_unit_msg(&mut self, u: usize) {
        let mut buf = [0u8; HEADER + 64];
        loop {
            let ch = match self.units[u] {
                Some(ep) if ep.ch != 0 => ep.ch,
                _ => return,
            };
            let mut hs = [0 as Handle; 1];
            match sys::channel_read_h(ch, &mut buf, &mut hs, 0) {
                Ok((n, nh)) => {
                    let hnd = if nh > 0 { hs[0] } else { 0 };
                    let Some(h) = Header::get(&buf[..n]) else {
                        if hnd != 0 {
                            sys::handle_close(hnd);
                        }
                        continue;
                    };
                    match h.op {
                        audio::DRV_OPEN => {
                            let (capture, _rate, _ch, _fmt) = audio::unpack_drv_open(h.a);
                            let mut rep = [0u8; HEADER];
                            if hnd == 0 {
                                Header { txid: h.txid, op: h.op, status: sys::ERR_INVALID_ARGS as i32, a: 0, b: 0 }.put(&mut rep);
                            } else {
                                match self.open_stream(u, capture, hnd) {
                                    Ok(()) => {
                                        let a = audio::pack_params(48_000, 2, FMT_S16_LE);
                                        Header { txid: h.txid, op: h.op, status: 0, a, b: PERIOD_FRAMES as u64 }.put(&mut rep);
                                    }
                                    Err(st) => {
                                        Header { txid: h.txid, op: h.op, status: st, a: 0, b: 0 }.put(&mut rep);
                                    }
                                }
                            }
                            let _ = sys::channel_write(ch, &rep);
                        }
                        audio::DRV_KICK => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                            self.pump_output(false);
                            self.pump_input();
                        }
                        audio::DRV_STOP => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                            if self.out_stream.as_ref().is_some_and(|s| s.unit == u)
                                && let Some(s) = self.out_stream.take()
                            {
                                self.stop_sd(s.sd_idx);
                            }
                            if self.in_stream.as_ref().is_some_and(|s| s.unit == u)
                                && let Some(s) = self.in_stream.take()
                            {
                                self.stop_sd(s.sd_idx);
                            }
                            let mut rep = [0u8; HEADER];
                            Header { txid: h.txid, op: h.op, status: 0, a: 0, b: 0 }.put(&mut rep);
                            let _ = sys::channel_write(ch, &rep);
                        }
                        audio::DRV_SET_VOL => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                            let muted = (h.b & 1) != 0;
                            if let Some(ep) = self.units[u].as_mut() {
                                ep.muted = muted;
                                let (cad, path) = (ep.cad, ep.path);
                                self.apply_mute(cad, &path, muted);
                            }
                            let mut rep = [0u8; HEADER];
                            Header { txid: h.txid, op: h.op, status: 0, a: 0, b: 0 }.put(&mut rep);
                            let _ = sys::channel_write(ch, &rep);
                        }
                        audio::DRV_TEST_CRASH => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                            println!("hda: intentional crash requested (audio crash recovery test)");
                            sys::process_exit(sys::EXIT_FAULT);
                        }
                        _ => {
                            if hnd != 0 {
                                sys::handle_close(hnd);
                            }
                        }
                    }
                }
                Err(sys::ERR_SHOULD_WAIT) => {
                    self.port.arm(ch, sys::READABLE | sys::PEER_CLOSED, KEY_UNIT_BASE + u as u64);
                    return;
                }
                Err(_) => {
                    // Peer (`audio.dsvc`) disconnected: stop stream and close handle.
                    if self.out_stream.as_ref().is_some_and(|s| s.unit == u)
                        && let Some(s) = self.out_stream.take()
                    {
                        self.stop_sd(s.sd_idx);
                    }
                    if self.in_stream.as_ref().is_some_and(|s| s.unit == u)
                        && let Some(s) = self.in_stream.take()
                    {
                        self.stop_sd(s.sd_idx);
                    }
                    if let Some(ep) = self.units[u].as_mut() {
                        sys::handle_close(ep.ch);
                        ep.ch = 0;
                    }
                    return;
                }
            }
        }
    }
}

pub fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer the kernel passed to the entry point.
    if !unsafe { libd::init(s, "hda") } {
        return -1;
    }
    let dev = libd::startup_handle(sys::TAG_DEVICE);
    let ctl = libd::startup_handle(proto::TAG_CONTROL);
    let Ok(info) = sys::device_info(dev) else {
        println!("hda: device_info failed");
        return 1;
    };
    if info.bar_kind[0] != 1 || info.bar_size[0] < 0x100 {
        println!("hda: BAR 0 missing or too small");
        return 1;
    }
    // Enable memory decode + bus mastering (IOMMU-confined DMA).
    if sys::config_write(dev, 0x04, 2, 0x06).is_err() {
        println!("hda: cannot enable PCI memory/bus-master");
        return 1;
    }
    // Clear TCSEL (offset 0x44) so Intel/AMD HDA controllers use snooped TC0 DMA.
    let _ = sys::config_write(dev, 0x44, 1, 0);

    let Ok(bar_vmo) = sys::device_map_bar(dev, 0) else {
        println!("hda: cannot map BAR 0");
        return 1;
    };
    let Ok(mmio) = Mapping::of(bar_vmo, info.bar_size[0]) else {
        println!("hda: cannot map BAR 0 VMO");
        return 1;
    };
    let Ok(dma) = Dma::new(dev, DMA_PAGES * PAGE, sys::DMA_DEVICE_READ | sys::DMA_DEVICE_WRITE) else {
        println!("hda: cannot allocate IOMMU DMA pages");
        return 1;
    };
    let irq = sys::device_interrupt(dev, 0).unwrap_or(0);
    let Ok(port) = Port::new(64) else {
        println!("hda: cannot create port");
        return 1;
    };

    let gcap = mmio.r16(REG_GCAP);
    let iss = ((gcap >> 8) & 0xF) as usize;
    let oss = ((gcap >> 12) & 0xF) as usize;

    let mut hda = Hda {
        mmio,
        dma,
        ctl,
        irq,
        port,
        iss,
        oss,
        use_corb: false,
        corb_entries: 0,
        rirb_entries: 0,
        corb_wp: 0,
        rirb_rp: 0,
        units: [None; MAX_UNITS],
        unit_count: 0,
        out_stream: None,
        in_stream: None,
        pending_unsol: [(0, 0); 16],
        pending_unsol_len: 0,
        fatal_stall: false,
    };

    let statests = match hda.reset_controller() {
        Ok(st) => st,
        Err(why) => {
            println!("hda: {}", why);
            return 1;
        }
    };
    hda.init_corb_rirb();
    println!(
        "hda: controller ready on {} (ISS={}, OSS={}, {}, irq={})",
        info.name(),
        iss,
        oss,
        if hda.use_corb { "CORB/RIRB" } else { "ICW" },
        if irq != 0 { "MSI" } else { "poll" }
    );
    hda.discover_codecs(statests);

    hda.port.arm(ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
    if irq != 0 {
        hda.port.arm(irq, sys::SIGNALED, KEY_IRQ);
    }
    proto::send(ctl, proto::READY, hda.unit_count as u64, 0);

    loop {
        if hda.fatal_stall {
            println!("hda: exiting after unrecoverable DMA stall for driver restart");
            return 1;
        }
        let streaming = hda.out_stream.is_some() || hda.in_stream.is_some();
        let wait_ns = if streaming { 5 * MS } else { 250 * MS };
        if let Some((key, _)) = hda.port.wait(wait_ns) {
            match key {
                KEY_CTL => hda.handle_ctl(),
                KEY_IRQ => hda.handle_irq(),
                k if k >= KEY_UNIT_BASE => hda.handle_unit_msg((k - KEY_UNIT_BASE) as usize),
                _ => {}
            }
        }
        // Periodic jack/ELD check and BDL period / stall watchdog maintenance.
        hda.process_unsol();
        if streaming {
            hda.pump_output(false);
            hda.pump_input();
        }
    }
}
