//! Realtek PCIe Gigabit/2.5GbE/5GbE Ethernet driver (`r8169.ddrv`, PCI vendor `10EC`, class `02.00`).
//!
//! Targets RTL8111/8168/8169 (1GbE) and RTL8125/8125B/8125D/8126/8127 (2.5GbE/5GbE) controllers
//! common on x86-64 desktop motherboards. Uses 64-bit C+ descriptor rings pinned through the
//! IOMMU (`libd::Dma`) and bridges raw Ethernet frames to `net.dsvc` via shared-memory `IoRing`s.

use core::sync::atomic::{Ordering, fence};

use libd::proto;
use libd::sys::{self, Handle};
use libd::{Dma, Mapping, Port, Startup, println};

use crate::net_drv::{KEY_CTL, KEY_IRQ0, KEY_SVC, MAX_FRAME, NetBridge};

// Realtek r8169 / r8168 / r8125 / r8126 MMIO register offsets
const REG_IDR0: u64 = 0x00;
const REG_IDR4: u64 = 0x04;
const REG_ERIDR: u64 = 0x70;
const REG_ERIAR: u64 = 0x74;
/// RTL8125/8126/8127: the factory MAC address (the `IDR` registers may not hold it after reset).
const REG_MAC0_BKP_8125: u64 = 0x19E0;
const REG_MAR0: u64 = 0x08;
const REG_MAR4: u64 = 0x0C;
const REG_TNPDS_LO: u64 = 0x20;
const REG_TNPDS_HI: u64 = 0x24;
const REG_THPDS_LO: u64 = 0x28;
const REG_THPDS_HI: u64 = 0x2C;
const REG_INT_CFG0_8125: u64 = 0x34;
const REG_CMD: u64 = 0x37;
const REG_TXPOLL_8168: u64 = 0x38;
const REG_IMR_8125: u64 = 0x38;
const REG_IMR_8168: u64 = 0x3C;
const REG_ISR_8125: u64 = 0x3C;
const REG_ISR_8168: u64 = 0x3E;
const REG_TCR: u64 = 0x40;
const REG_RCR: u64 = 0x44;
const REG_CFG9346: u64 = 0x50;
const REG_TDFNR: u64 = 0x57;
const REG_PHYSTATUS: u64 = 0x6C;
const REG_INT_CFG1_8125: u64 = 0x7A;
const REG_TXPOLL_8125: u64 = 0x90;
const REG_RMS: u64 = 0xDA;
const REG_CPCMD: u64 = 0xE0;
const REG_INTR_MITIGATE: u64 = 0xE2;
const REG_RDSAR_LO: u64 = 0xE4;
const REG_RDSAR_HI: u64 = 0xE8;
const REG_MTPS: u64 = 0xEC;
const REG_MISC: u64 = 0xF0;
/// RTL8125/8126/8127 Receive Side Scaling and RX queue count control registers.
/// Must be cleared for single-queue RX so unicast IPv4/UDP/ICMP/TCP frames are not
/// hashed into unconfigured RX queues 1..3 (e.g. after a warm reboot from Windows).
const REG_RSS_CTRL_8125: u64 = 0x4500;
const REG_Q_NUM_CTRL_8125: u64 = 0x4800;

const CMD_TX_EN: u8 = 1 << 2;
const CMD_RX_EN: u8 = 1 << 3;
const CMD_RESET: u8 = 1 << 4;

const MISC_RXDV_GATED_EN: u32 = 1 << 19;

// ROK | RER | TOK | TER | RDU | LinkChg
const IRQ_MASK: u32 = 0x003F;

const DESC_OWN: u32 = 1 << 31;
const DESC_EOR: u32 = 1 << 30;
const DESC_FS: u32 = 1 << 29;
const DESC_LS: u32 = 1 << 28;
const RX_DESC_RES: u32 = 1 << 21;

const RING_LEN: usize = 24;
const BUF_BYTES: usize = 2048;
// DMA layout (25 pages = 100 KiB, within `Dma::MAX_PAGES = 32`):
//   Page 0:       24 RX descriptors (0..384), 24 TX descriptors (2048..2432) — both 256-byte aligned
//   Pages 1..13:  24 RX buffers (2048 B each, never crossing 4 KiB page boundaries)
//   Pages 13..25: 24 TX buffers (2048 B each, never crossing 4 KiB page boundaries)
const OFF_RX_DESC: usize = 0;
const OFF_TX_DESC: usize = 2048;
const OFF_RX_BUFS: usize = 4096;
const OFF_TX_BUFS: usize = 4096 + RING_LEN * BUF_BYTES;
const DMA_BYTES: u64 = (4096 + RING_LEN * 2 * BUF_BYTES) as u64;
const MS: u64 = 1_000_000;

fn arm_rx_desc(dma: &Dma, i: usize, buf_addr: u64) {
    let o = (OFF_RX_DESC + i * 16) as u64;
    let eor = if i + 1 == RING_LEN { DESC_EOR } else { 0 };
    dma.map.w32(o + 4, 0);
    dma.map.w64(o + 8, buf_addr);
    fence(Ordering::Release);
    dma.map.w32(o, DESC_OWN | eor | (BUF_BYTES as u32 & 0x3FFF));
}

fn valid_mac(m: &[u8; 6]) -> bool {
    *m != [0; 6] && *m != [0xFF; 6] && m[0] & 1 == 0
}

/// ERI register read (RTL8168E-VL and later): `None` if the access does not complete.
fn eri_read(mmio: &Mapping, addr: u32) -> Option<u32> {
    // Read command, all four byte enables, ExGMAC space.
    mmio.w32(REG_ERIAR, (0xF << 12) | (addr & 0xFFF));
    for _ in 0..1000 {
        if mmio.r32(REG_ERIAR) & (1 << 31) != 0 {
            return Some(mmio.r32(REG_ERIDR));
        }
        core::hint::spin_loop();
    }
    None
}

/// The adapter's MAC address, read where Linux reads it: the backup register on RTL8125 and
/// later, ERI `0xE0` on RTL8168E-VL and later, else `IDR0-5`. If none holds a valid unicast
/// address (zero, broadcast or multicast), a random locally administered one is used.
fn factory_mac(mmio: &Mapping, bar_size: u64, is_8125: bool, xid: u32) -> ([u8; 6], &'static str) {
    let mut m = [0u8; 6];
    if is_8125 && bar_size >= REG_MAC0_BKP_8125 + 8 {
        for (i, b) in m.iter_mut().enumerate() {
            *b = mmio.r8(REG_MAC0_BKP_8125 + i as u64);
        }
        if valid_mac(&m) {
            return (m, "factory backup register");
        }
    } else if !is_8125
        && xid >= 0x2C8
        && let (Some(lo), Some(hi)) = (eri_read(mmio, 0xE0), eri_read(mmio, 0xE4))
    {
        m[..4].copy_from_slice(&lo.to_le_bytes());
        m[4..].copy_from_slice(&hi.to_le_bytes()[..2]);
        if valid_mac(&m) {
            return (m, "ERI");
        }
    }
    for (i, b) in m.iter_mut().enumerate() {
        *b = mmio.r8(REG_IDR0 + i as u64);
    }
    if valid_mac(&m) {
        return (m, "IDR");
    }
    let _ = sys::get_random(&mut m, 0);
    m[0] = (m[0] & 0xFE) | 0x02;
    (m, "random (no valid address in the adapter)")
}

/// Program the receive address filter (`IDR0-5`) with `mac` (config registers unlocked).
fn set_mac(mmio: &Mapping, mac: [u8; 6]) {
    mmio.w8(REG_CFG9346, 0xC0);
    mmio.w32(REG_IDR4, u32::from(u16::from_le_bytes([mac[4], mac[5]])));
    let _ = mmio.r32(REG_IDR4);
    mmio.w32(REG_IDR0, u32::from_le_bytes([mac[0], mac[1], mac[2], mac[3]]));
    let _ = mmio.r32(REG_IDR0);
    mmio.w8(REG_CFG9346, 0x00);
}

pub fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer passed by the kernel.
    if !unsafe { libd::init(s, "r8169") } {
        return -1;
    }
    let dev = libd::startup_handle(sys::TAG_DEVICE);
    let ctl = libd::startup_handle(proto::TAG_CONTROL);
    let Ok(info) = sys::device_info(dev) else {
        println!("r8169: device_info failed");
        return 1;
    };
    // PCIe Realtek NICs place MMIO registers in BAR 2 (older chips may use BAR 1 or BAR 0).
    let Some(bar) = [2usize, 1, 0].into_iter().find(|&b| info.bar_kind[b] == 1 && info.bar_size[b] >= 256) else {
        println!("r8169: {}: no MMIO BAR", info.name());
        return 1;
    };
    let _ = sys::config_write(dev, 0x04, 2, 0x6); // Memory + Bus Master
    let Ok(bar_vmo) = sys::device_map_bar(dev, bar as u64) else {
        println!("r8169: cannot map BAR {}", bar);
        return 1;
    };
    let Ok(mmio) = Mapping::of(bar_vmo, info.bar_size[bar]) else {
        println!("r8169: Mapping::of failed");
        return 1;
    };

    // Read hardware XID from TxConfig upper bits BEFORE modifying TxConfig.
    let xid = (mmio.r32(REG_TCR) >> 20) & 0x7CF;
    let is_8125 = matches!(info.device, 0x8125 | 0x8126 | 0x8127 | 0x3000 | 0x5000) || xid >= 0x600;
    let has_rxdv_gated = is_8125 || xid >= 0x4C0;

    // Mask interrupts, stop MAC, and perform software reset.
    if is_8125 {
        mmio.w32(REG_IMR_8125, 0);
        mmio.w32(REG_ISR_8125, 0xFFFF_FFFF);
    } else {
        mmio.w16(REG_IMR_8168, 0);
        mmio.w16(REG_ISR_8168, 0xFFFF);
    }
    mmio.w8(REG_CMD, 0);
    libd::handle::sleep(MS);
    mmio.w8(REG_CMD, CMD_RESET);
    for _ in 0..200 {
        if (mmio.r8(REG_CMD) & CMD_RESET) == 0 {
            break;
        }
        libd::handle::sleep(MS);
    }

    let (mac, mac_from) = factory_mac(&mmio, info.bar_size[bar], is_8125, xid);
    set_mac(&mmio, mac);

    let mut dma = match Dma::new(dev, DMA_BYTES, sys::DMA_DEVICE_READ | sys::DMA_DEVICE_WRITE) {
        Ok(d) => d,
        Err(e) => {
            println!("r8169: dma_map: {}", sys::status(e));
            return 1;
        }
    };
    dma.map.bytes_mut().fill(0);

    for i in 0..RING_LEN {
        arm_rx_desc(&dma, i, dma.dev_addr((OFF_RX_BUFS + i * BUF_BYTES) as u64));
    }

    // Unlock configuration registers and program rings and RX/TX parameters.
    mmio.w8(REG_CFG9346, 0xC0);

    // Disable interrupt coalescing so DHCP/ARP packets are delivered immediately.
    mmio.w16(REG_INTR_MITIGATE, 0x0000);

    // Preserve firmware C+ control bits while disabling RX checksum/VLAN offload and BIST.
    let cpcmd = mmio.r16(REG_CPCMD);
    if is_8125 || xid >= 0x200 {
        mmio.w16(REG_CPCMD, cpcmd & !0x80E0);
    } else {
        mmio.w16(REG_CPCMD, (cpcmd & !0x80E0) | 0x0003);
    }

    // Match RMS to our RX buffer size (2048 B) and configure MTPS / 8125 fetch controls.
    mmio.w16(REG_RMS, BUF_BYTES as u16);
    if is_8125 {
        mmio.w8(REG_MTPS, 0x3F);
        mmio.w8(REG_TDFNR, 0x10);
        mmio.w8(REG_INT_CFG0_8125, 0x00);
        mmio.w16(REG_INT_CFG1_8125, 0x0000);
        if info.bar_size[bar] >= REG_Q_NUM_CTRL_8125 + 2 {
            mmio.w32(REG_RSS_CTRL_8125, 0);
            mmio.w16(REG_Q_NUM_CTRL_8125, 0);
        }
    } else {
        mmio.w8(REG_MTPS, 0x3B);
    }

    // Program 64-bit RX and TX descriptor ring bases (256-byte aligned).
    let rx_base = dma.dev_addr(OFF_RX_DESC as u64);
    let tx_base = dma.dev_addr(OFF_TX_DESC as u64);
    mmio.w32(REG_RDSAR_LO, rx_base as u32);
    mmio.w32(REG_RDSAR_HI, (rx_base >> 32) as u32);
    mmio.w32(REG_TNPDS_LO, tx_base as u32);
    mmio.w32(REG_TNPDS_HI, (tx_base >> 32) as u32);
    mmio.w32(REG_THPDS_LO, 0);
    mmio.w32(REG_THPDS_HI, 0);

    // Accept all multicast hash buckets.
    mmio.w32(REG_MAR0, 0xFFFF_FFFF);
    mmio.w32(REG_MAR4, 0xFFFF_FFFF);

    // Enable MAC TX & RX engines, then apply TCR and RCR (matches Realtek HW start sequence).
    mmio.w8(REG_CMD, CMD_RX_EN | CMD_TX_EN);
    if is_8125 {
        // IFG standard (3<<24) | unlimited TX DMA burst (7<<8) | AUTO_FIFO (1<<7)
        mmio.w32(REG_TCR, 0x0300_0780);
        // RX_FETCH_DFLT_8125 (8<<27) | RX128_INT_EN (1<<15) | RX_MULTI_EN (1<<14) |
        // RX_DMA_BURST unlimited (7<<8) | AB | AM | APM (0x0E)
        mmio.w32(REG_RCR, (8 << 27) | (1 << 15) | (1 << 14) | (7 << 8) | 0x0E);
    } else {
        mmio.w32(REG_TCR, 0x0300_0700);
        // No RX FIFO threshold (7<<13) | unlimited RX DMA burst (7<<8) | AB | AM | APM (0x0E)
        mmio.w32(REG_RCR, 0x0000_E70E);
    }
    mmio.w8(REG_CFG9346, 0x00);

    // CRITICAL on RTL8168G/H and RTL8125/8126: clear RXDV_GATED_EN so RX MAC accepts frames.
    if has_rxdv_gated {
        let misc = mmio.r32(REG_MISC);
        mmio.w32(REG_MISC, misc & !MISC_RXDV_GATED_EN);
    }

    let irq: Handle = sys::device_interrupt(dev, 0).unwrap_or(0);
    if is_8125 {
        mmio.w32(REG_ISR_8125, 0xFFFF_FFFF);
        mmio.w32(REG_IMR_8125, IRQ_MASK);
    } else {
        mmio.w16(REG_ISR_8168, 0xFFFF);
        mmio.w16(REG_IMR_8168, IRQ_MASK as u16);
    }

    let mut link_up = (mmio.r8(REG_PHYSTATUS) & 0x02) != 0;
    println!(
        "r8169: ready on {} ({:04x}:{:04x} xid={:#x} {}) BAR{} MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (from {}) link={} irq={} IOMMU={}",
        info.name(),
        info.vendor,
        info.device,
        xid,
        if is_8125 { "8125" } else { "8168" },
        bar,
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5],
        mac_from,
        link_up,
        irq != 0,
        (info.flags & sys::DEV_FLAG_IOMMU) != 0
    );

    let Ok(port) = Port::new(32) else { return 1 };
    port.arm(ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
    if irq != 0 {
        port.arm(irq, sys::SIGNALED, KEY_IRQ0);
    }

    proto::send(ctl, proto::READY, 0, 0);
    NetBridge::announce(ctl, mac, link_up, 1500, "r8169");

    let mut bridge = NetBridge::new();
    let mut rx_cur = 0usize;
    let mut tx_cur = 0usize;
    let mut irqs = 0u64;
    let mut rx_copy = [0u8; MAX_FRAME];
    let mut logged_tx = false;
    let mut logged_rx = false;
    let mut logged_tx_stall = false;
    let mut last_link_poll = sys::clock_ns();

    loop {
        if let Some((key, _)) = port.wait(10 * MS) {
            match key {
                KEY_CTL => {
                    if !bridge.poll_ctl(ctl, &port, irqs) {
                        return 0;
                    }
                }
                KEY_SVC => {
                    bridge.poll_svc(&port);
                }
                KEY_IRQ0 if irq != 0 => {
                    irqs += sys::interrupt_ack(irq).unwrap_or(0);
                    if is_8125 {
                        let isr = mmio.r32(REG_ISR_8125);
                        if isr != 0 {
                            mmio.w32(REG_ISR_8125, isr);
                        }
                    } else {
                        let isr = mmio.r16(REG_ISR_8168);
                        if isr != 0 {
                            mmio.w16(REG_ISR_8168, isr);
                        }
                    }
                    port.arm(irq, sys::SIGNALED, KEY_IRQ0);
                }
                _ => {}
            }
        }

        // Poll PHY carrier link state every 250 ms and propagate changes to `net.dsvc`.
        let now = sys::clock_ns();
        if now.saturating_sub(last_link_poll) >= 250 * MS {
            last_link_poll = now;
            let cur_link = (mmio.r8(REG_PHYSTATUS) & 0x02) != 0;
            if cur_link != link_up {
                link_up = cur_link;
                println!("r8169: link {}", if link_up { "up" } else { "down" });
                NetBridge::send_link(ctl, link_up);
            }
        }

        bridge.drain_tx(|frame| {
            let desc_off = (OFF_TX_DESC + tx_cur * 16) as u64;
            let cur_opts = dma.map.r32(desc_off);
            if (cur_opts & DESC_OWN) != 0 {
                if !logged_tx_stall {
                    logged_tx_stall = true;
                    println!(
                        "r8169: tx ring full (slot {} opts1={:#x} cmd={:#x} phy={:#x})",
                        tx_cur,
                        cur_opts,
                        mmio.r8(REG_CMD),
                        mmio.r8(REG_PHYSTATUS)
                    );
                }
                return false;
            }
            let buf_off = OFF_TX_BUFS + tx_cur * BUF_BYTES;
            let tx_len = frame.len().max(60);
            dma.map.bytes_mut()[buf_off..buf_off + frame.len()].copy_from_slice(frame);
            if tx_len > frame.len() {
                dma.map.bytes_mut()[buf_off + frame.len()..buf_off + tx_len].fill(0);
            }
            let eor = if tx_cur + 1 == RING_LEN { DESC_EOR } else { 0 };
            dma.map.w32(desc_off + 4, 0);
            dma.map.w64(desc_off + 8, dma.dev_addr(buf_off as u64));
            fence(Ordering::Release);
            dma.map.w32(desc_off, DESC_OWN | eor | DESC_FS | DESC_LS | (tx_len as u32 & 0xFFFF));
            fence(Ordering::SeqCst);
            if is_8125 {
                mmio.w16(REG_TXPOLL_8125, 0x0001);
            } else {
                mmio.w8(REG_TXPOLL_8168, 0x40);
            }
            if !logged_tx {
                logged_tx = true;
                println!("r8169: tx first frame ({} B)", tx_len);
            }
            tx_cur = (tx_cur + 1) % RING_LEN;
            true
        });

        loop {
            let desc_off = (OFF_RX_DESC + rx_cur * 16) as u64;
            fence(Ordering::Acquire);
            let opts1 = dma.map.r32(desc_off);
            if (opts1 & DESC_OWN) != 0 {
                break;
            }
            if (opts1 & RX_DESC_RES) == 0 && (opts1 & (DESC_FS | DESC_LS)) == (DESC_FS | DESC_LS) {
                let raw_len = (opts1 & 0x3FFF) as usize;
                let len = raw_len.saturating_sub(4); // strip 4-byte FCS
                if (14..=MAX_FRAME).contains(&len) {
                    let buf_off = OFF_RX_BUFS + rx_cur * BUF_BYTES;
                    rx_copy[..len].copy_from_slice(&dma.map.bytes()[buf_off..buf_off + len]);
                    if !logged_rx {
                        logged_rx = true;
                        println!("r8169: rx first frame ({} B)", len);
                    }
                    bridge.deliver_rx(&rx_copy[..len]);
                }
            }
            arm_rx_desc(&dma, rx_cur, dma.dev_addr((OFF_RX_BUFS + rx_cur * BUF_BYTES) as u64));
            rx_cur = (rx_cur + 1) % RING_LEN;
        }
    }
}
