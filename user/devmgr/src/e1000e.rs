//! Intel PCIe Gigabit / 2.5GbE Ethernet driver (`e1000e.ddrv`, PCI vendor `8086`, class `02.00`).
//!
//! Supports:
//! - Classic `e1000e` / `e1000` (82574L, 82540EM, I217/I218/I219)
//! - `igb` (I210/I211/I350/82576) and `igc` (I225-V/I225-LM/I226-V/I226-LM 2.5GbE)
//!
//! Runs isolated in user space with IOMMU-pinned RX/TX rings bridged to `net.dsvc`.

use core::sync::atomic::{Ordering, fence};

use libd::proto;
use libd::sys::{self, Handle};
use libd::{Dma, Mapping, Port, Startup, println};

use crate::net_drv::{KEY_CTL, KEY_IRQ0, KEY_SVC, MAX_FRAME, NetBridge};

// Common MMIO register offsets
const REG_CTRL: u64 = 0x0000;
const REG_STATUS: u64 = 0x0008;
const REG_EERD: u64 = 0x0014;
const REG_CTRL_EXT: u64 = 0x0018;
const REG_ICR: u64 = 0x00C0;
const REG_IMS: u64 = 0x00D0;
const REG_IMC: u64 = 0x00D8;
const REG_IVAR_82574: u64 = 0x00E4;
const REG_RCTL: u64 = 0x0100;
const REG_TCTL: u64 = 0x0400;
const REG_TIPG: u64 = 0x0410;
const REG_MTA: u64 = 0x5200;
const REG_RAL0: u64 = 0x5400;
const REG_RAH0: u64 = 0x5404;

// Extended interrupt registers (igb / igc)
const REG_EIMS: u64 = 0x1524;
const REG_EIMC: u64 = 0x1528;
const REG_EICR: u64 = 0x1580;
const REG_IVAR0: u64 = 0x1700;
const REG_IVAR_MISC: u64 = 0x1740;

// Queue-0 register block bases (classic e1000e vs igb/igc)
const RXQ_BASE_E1000E: u64 = 0x2800;
const TXQ_BASE_E1000E: u64 = 0x3800;
const RXQ_BASE_IGC: u64 = 0xC000;
const TXQ_BASE_IGC: u64 = 0xE000;

// Offsets relative to RXQ_BASE / TXQ_BASE
const Q_DBAL: u64 = 0x00;
const Q_DBAH: u64 = 0x04;
const Q_DLEN: u64 = 0x08;
const Q_SRRCTL: u64 = 0x0C; // igb/igc RX split-and-replication control
const Q_DH: u64 = 0x10;
const Q_DT: u64 = 0x18;
const Q_DCTL: u64 = 0x28;

const CTRL_ASDE: u32 = 1 << 5;
const CTRL_SLU: u32 = 1 << 6;
const CTRL_RST: u32 = 1 << 26;
const CTRL_EXT_DRV_LOAD: u32 = 1 << 28;
const STATUS_LU: u32 = 1 << 1;

const RCTL_EN: u32 = 1 << 1;
const RCTL_BAM: u32 = 1 << 15;
const RCTL_SECRC: u32 = 1 << 26;

const TCTL_EN: u32 = 1 << 1;
const TCTL_PSP: u32 = 1 << 3;
const TCTL_CT: u32 = 0x10 << 4;
const TCTL_COLD: u32 = 0x40 << 12;

const QDCTL_ENABLE: u32 = 1 << 25;
const TXDCTL_GRAN: u32 = 1 << 24;

const TX_CMD_EOP: u8 = 1 << 0;
const TX_CMD_IFCS: u8 = 1 << 1;
const TX_CMD_RS: u8 = 1 << 3;
const RX_STAT_DD: u8 = 1 << 0;
const RX_STAT_EOP: u8 = 1 << 1;

const RING_LEN: usize = 24; // 24 * 16 = 384 B (128-byte aligned)
const BUF_BYTES: usize = 2048;
// DMA layout (25 pages = 100 KiB, within `Dma::MAX_PAGES = 32`):
//   Page 0:       RX descriptors (0..384), TX descriptors (2048..2432)
//   Pages 1..13:  24 RX buffers (2048 B each)
//   Pages 13..25: 24 TX buffers (2048 B each)
const OFF_RX_DESC: usize = 0;
const OFF_TX_DESC: usize = 2048;
const OFF_RX_BUFS: usize = 4096;
const OFF_TX_BUFS: usize = 4096 + RING_LEN * BUF_BYTES;
const DMA_BYTES: u64 = (4096 + RING_LEN * 2 * BUF_BYTES) as u64;
const MS: u64 = 1_000_000;

#[derive(Clone, Copy, PartialEq, Eq)]
enum NicFamily {
    E1000e,
    Igb,
    Igc,
}

impl NicFamily {
    fn detect(device: u16, bar0_size: u64) -> Self {
        match device {
            // Intel I225 / I226 2.5GbE (igc)
            0x0D9F | 0x125B..=0x125F | 0x15F2 | 0x15F3 | 0x15F7 | 0x15F8 | 0x15FD
            | 0x3100..=0x3102 | 0x5502 | 0x5503 => Self::Igc,
            // Intel I210 / I211 / I350 / 82576 (igb)
            0x10C9 | 0x10E6 | 0x10E7 | 0x150A | 0x150E | 0x150F | 0x1521..=0x1524
            | 0x1533..=0x1539 | 0x157B | 0x157C => Self::Igb,
            // Fallback: 1 MiB+ BAR0 on modern Intel Ethernet is igc/igb.
            _ if bar0_size >= 0x10_0000 => Self::Igc,
            _ => Self::E1000e,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::E1000e => "e1000e",
            Self::Igb => "igb",
            Self::Igc => "igc",
        }
    }

    fn uses_extended_queues(self) -> bool {
        matches!(self, Self::Igb | Self::Igc)
    }
}

fn read_eeprom_word(mmio: &Mapping, addr: u32) -> Option<u16> {
    // Try 82574L/e1000e format (addr << 2, DONE = bit 1).
    mmio.w32(REG_EERD, (addr << 2) | 1);
    for _ in 0..10_000 {
        let v = mmio.r32(REG_EERD);
        if (v & (1 << 1)) != 0 {
            return Some((v >> 16) as u16);
        }
    }
    // Fallback to legacy 8254x format (addr << 8, DONE = bit 4).
    mmio.w32(REG_EERD, (addr << 8) | 1);
    for _ in 0..10_000 {
        let v = mmio.r32(REG_EERD);
        if (v & (1 << 4)) != 0 {
            return Some((v >> 16) as u16);
        }
    }
    None
}

fn read_mac_ral(mmio: &Mapping) -> Option<[u8; 6]> {
    let ral = mmio.r32(REG_RAL0);
    let rah = mmio.r32(REG_RAH0);
    let mac = [
        (ral & 0xFF) as u8,
        ((ral >> 8) & 0xFF) as u8,
        ((ral >> 16) & 0xFF) as u8,
        ((ral >> 24) & 0xFF) as u8,
        (rah & 0xFF) as u8,
        ((rah >> 8) & 0xFF) as u8,
    ];
    if mac.iter().all(|&b| b == 0) || mac.iter().all(|&b| b == 0xFF) {
        None
    } else {
        Some(mac)
    }
}

fn read_mac(mmio: &Mapping, allow_eerd: bool) -> [u8; 6] {
    if let Some(mac) = read_mac_ral(mmio) {
        return mac;
    }
    if allow_eerd
        && let (Some(w0), Some(w1), Some(w2)) = (
            read_eeprom_word(mmio, 0),
            read_eeprom_word(mmio, 1),
            read_eeprom_word(mmio, 2),
        )
    {
        return [
            (w0 & 0xFF) as u8,
            (w0 >> 8) as u8,
            (w1 & 0xFF) as u8,
            (w1 >> 8) as u8,
            (w2 & 0xFF) as u8,
            (w2 >> 8) as u8,
        ];
    }
    [0x52, 0x54, 0x00, 0xE1, 0x00, 0x0E]
}

fn write_rx_desc(dma: &Dma, i: usize, addr: u64) {
    let o = (OFF_RX_DESC + i * 16) as u64;
    dma.map.w64(o, addr);
    dma.map.w64(o + 8, 0);
}

fn write_tx_desc(dma: &Dma, i: usize, addr: u64, len: u16) {
    let o = (OFF_TX_DESC + i * 16) as u64;
    dma.map.w64(o, addr);
    let meta = u64::from(len) | (u64::from(TX_CMD_EOP | TX_CMD_IFCS | TX_CMD_RS) << 24);
    dma.map.w64(o + 8, meta);
}

pub fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer passed by the kernel.
    if !unsafe { libd::init(s, "e1000e") } {
        return -1;
    }
    let dev = libd::startup_handle(sys::TAG_DEVICE);
    let ctl = libd::startup_handle(proto::TAG_CONTROL);
    let Ok(info) = sys::device_info(dev) else {
        println!("e1000e: device_info failed");
        return 1;
    };
    if info.bar_kind[0] != 1 || info.bar_size[0] < 0x10000 {
        println!("e1000e: {}: BAR 0 is not MMIO", info.name());
        return 1;
    }
    let family = NicFamily::detect(info.device, info.bar_size[0]);
    let ext_q = family.uses_extended_queues();
    let rxq = if ext_q { RXQ_BASE_IGC } else { RXQ_BASE_E1000E };
    let txq = if ext_q { TXQ_BASE_IGC } else { TXQ_BASE_E1000E };

    let _ = sys::config_write(dev, 0x04, 2, 0x6); // Memory + Bus Master
    let Ok(bar_vmo) = sys::device_map_bar(dev, 0) else {
        println!("e1000e: cannot map BAR 0");
        return 1;
    };
    let Ok(mmio) = Mapping::of(bar_vmo, info.bar_size[0]) else {
        println!("e1000e: Mapping::of failed");
        return 1;
    };

    // Mask interrupts and capture MAC before reset.
    mmio.w32(REG_IMC, 0xFFFF_FFFF);
    if ext_q {
        mmio.w32(REG_EIMC, 0xFFFF_FFFF);
    }
    let pre_mac = read_mac_ral(&mmio);

    // Software reset and wait for completion.
    mmio.w32(REG_CTRL, mmio.r32(REG_CTRL) | CTRL_RST);
    libd::handle::sleep(20 * MS);
    for _ in 0..50 {
        if (mmio.r32(REG_CTRL) & CTRL_RST) == 0 {
            break;
        }
        libd::handle::sleep(MS);
    }
    mmio.w32(REG_IMC, 0xFFFF_FFFF);
    let _ = mmio.r32(REG_ICR);
    if ext_q {
        mmio.w32(REG_EIMC, 0xFFFF_FFFF);
        let _ = mmio.r32(REG_EICR);
        // Notify firmware/ME that the OS driver owns the NIC.
        mmio.w32(REG_CTRL_EXT, mmio.r32(REG_CTRL_EXT) | CTRL_EXT_DRV_LOAD);
    }

    let mac = pre_mac.unwrap_or_else(|| read_mac(&mmio, !ext_q));

    // Set Link Up + Auto-Speed Detection (clear PHY_RST).
    mmio.w32(REG_CTRL, (mmio.r32(REG_CTRL) | CTRL_SLU | CTRL_ASDE) & !(1 << 31));

    // Program MAC address into RAL0/RAH0 and clear multicast filter table.
    let ral = u32::from(mac[0])
        | (u32::from(mac[1]) << 8)
        | (u32::from(mac[2]) << 16)
        | (u32::from(mac[3]) << 24);
    let rah = u32::from(mac[4]) | (u32::from(mac[5]) << 8) | (1 << 31);
    mmio.w32(REG_RAL0, ral);
    mmio.w32(REG_RAH0, rah);
    for i in 0..128u64 {
        mmio.w32(REG_MTA + i * 4, 0);
    }

    let mut dma = match Dma::new(dev, DMA_BYTES, sys::DMA_DEVICE_READ | sys::DMA_DEVICE_WRITE) {
        Ok(d) => d,
        Err(e) => {
            println!("e1000e: dma_map: {}", sys::status(e));
            return 1;
        }
    };
    dma.map.bytes_mut().fill(0);

    // Initialize RX ring (keep RCTL disabled until descriptors & queue are armed).
    mmio.w32(REG_RCTL, 0);
    if ext_q {
        mmio.w32(rxq + Q_DCTL, mmio.r32(rxq + Q_DCTL) & !QDCTL_ENABLE);
    }
    for i in 0..RING_LEN {
        let buf_addr = dma.dev_addr((OFF_RX_BUFS + i * BUF_BYTES) as u64);
        write_rx_desc(&dma, i, buf_addr);
    }
    let rx_base = dma.dev_addr(OFF_RX_DESC as u64);
    mmio.w32(rxq + Q_DBAL, rx_base as u32);
    mmio.w32(rxq + Q_DBAH, (rx_base >> 32) as u32);
    mmio.w32(rxq + Q_DLEN, (RING_LEN * 16) as u32);
    mmio.w32(rxq + Q_DH, 0);
    mmio.w32(rxq + Q_DT, 0);
    if ext_q {
        // BSIZEPACKET = 2 (2048 B), DESCTYPE = 0 (legacy 16-byte RX desc), DROP_EN = 1.
        mmio.w32(rxq + Q_SRRCTL, 2 | (1 << 31));
        mmio.w32(rxq + Q_DCTL, (mmio.r32(rxq + Q_DCTL) & !0x003F_FFFF) | QDCTL_ENABLE);
        for _ in 0..20 {
            if (mmio.r32(rxq + Q_DCTL) & QDCTL_ENABLE) != 0 {
                break;
            }
            libd::handle::sleep(MS);
        }
    }

    // Initialize TX ring.
    for i in 0..RING_LEN {
        let o = (OFF_TX_DESC + i * 16) as u64;
        dma.map.w64(o, 0);
        // Mark DD=1 so all TX slots start free.
        dma.map.w64(o + 8, 1u64 << 32);
    }
    let tx_base = dma.dev_addr(OFF_TX_DESC as u64);
    mmio.w32(txq + Q_DBAL, tx_base as u32);
    mmio.w32(txq + Q_DBAH, (tx_base >> 32) as u32);
    mmio.w32(txq + Q_DLEN, (RING_LEN * 16) as u32);
    mmio.w32(txq + Q_DH, 0);
    mmio.w32(txq + Q_DT, 0);

    // Enable TX and RX engines, then write RDT (required AFTER RCTL_EN & RXDCTL.ENABLE on Intel silicon).
    if !ext_q {
        mmio.w32(REG_TIPG, 0x0060_200A);
    }
    mmio.w32(REG_TCTL, TCTL_EN | TCTL_PSP | TCTL_CT | TCTL_COLD);
    if ext_q {
        mmio.w32(txq + Q_DCTL, (mmio.r32(txq + Q_DCTL) & !0x003F_FFFF) | QDCTL_ENABLE | (1 << 16) | 8);
        for _ in 0..20 {
            if (mmio.r32(txq + Q_DCTL) & QDCTL_ENABLE) != 0 {
                break;
            }
            libd::handle::sleep(MS);
        }
    } else {
        // Prompt TX DD writeback on real e1000e silicon (I217/I218/I219/82574L).
        let txdctl = mmio.r32(txq + Q_DCTL);
        mmio.w32(txq + Q_DCTL, (txdctl & !0x003F_0000) | TXDCTL_GRAN | (1 << 16));
    }

    mmio.w32(REG_RCTL, RCTL_EN | RCTL_BAM | RCTL_SECRC);
    fence(Ordering::SeqCst);
    mmio.w32(rxq + Q_DT, (RING_LEN - 1) as u32);

    // Bind interrupt vector 0 (MSI-X or MSI).
    let irq: Handle = sys::device_interrupt(dev, 0).unwrap_or(0);
    if ext_q {
        // Route RxQ0, TxQ0, and Other/LSC to vector 0 (valid bit 7/15).
        mmio.w32(REG_IVAR0, 0x0000_8080);
        mmio.w32(REG_IVAR_MISC, 0x0000_8080);
        let _ = mmio.r32(REG_EICR);
        mmio.w32(REG_EIMS, 0x8000_0001);
        mmio.w32(REG_IMS, 0x0000_0085); // TXDW | LSC | RXT0
    } else {
        if info.irqs > 1 {
            // 82574L MSI-X IVAR: map RxQ0, TxQ0, Other all to vector 0 (bit 3/11/19 = valid).
            mmio.w32(REG_IVAR_82574, 0x0008_0808);
        }
        mmio.w32(REG_IMS, 0x0150_0085); // TXDW | LSC | RXT0 | RXQ0 | TXQ0 | OTHER
    }
    let _ = mmio.r32(REG_ICR);

    let status = mmio.r32(REG_STATUS);
    let mut link_up = (status & STATUS_LU) != 0;
    println!(
        "e1000e: ready on {} ({:04x}:{:04x} {}) MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} link={} status={:#x} irq={} IOMMU={}",
        info.name(),
        info.vendor,
        info.device,
        family.label(),
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5],
        link_up,
        status,
        irq != 0,
        (info.flags & sys::DEV_FLAG_IOMMU) != 0
    );

    let Ok(port) = Port::new(32) else { return 1 };
    port.arm(ctl, sys::READABLE | sys::PEER_CLOSED, KEY_CTL);
    if irq != 0 {
        port.arm(irq, sys::SIGNALED, KEY_IRQ0);
    }

    proto::send(ctl, proto::READY, 0, 0);
    NetBridge::announce(ctl, mac, link_up, 1500, "e1000e");

    let mut bridge = NetBridge::new();
    let mut rx_cur = 0usize;
    let mut tx_tail = 0usize;
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
                    if ext_q {
                        let eicr = mmio.r32(REG_EICR);
                        if eicr != 0 {
                            mmio.w32(REG_EICR, eicr);
                        }
                    }
                    let _ = mmio.r32(REG_ICR);
                    port.arm(irq, sys::SIGNALED, KEY_IRQ0);
                }
                _ => {}
            }
        }

        // Poll link status every 250 ms and notify `net.dsvc` on transitions.
        let now = sys::clock_ns();
        if now.saturating_sub(last_link_poll) >= 250 * MS {
            last_link_poll = now;
            let cur_link = (mmio.r32(REG_STATUS) & STATUS_LU) != 0;
            if cur_link != link_up {
                link_up = cur_link;
                println!("e1000e: link {}", if link_up { "up" } else { "down" });
                NetBridge::send_link(ctl, link_up);
            }
        }

        // Transmit pending frames from `net.dsvc`.
        bridge.drain_tx(|frame| {
            let desc_off = (OFF_TX_DESC + tx_tail * 16) as u64;
            let status_byte = (dma.map.r64(desc_off + 8) >> 32) as u8;
            if (status_byte & 1) == 0 {
                if !logged_tx_stall {
                    logged_tx_stall = true;
                    println!(
                        "e1000e: tx ring full (tail={} tdh={} status={:#x})",
                        tx_tail,
                        mmio.r32(txq + Q_DH),
                        mmio.r32(REG_STATUS)
                    );
                }
                return false;
            }
            let buf_off = OFF_TX_BUFS + tx_tail * BUF_BYTES;
            let tx_len = frame.len().max(60);
            dma.map.bytes_mut()[buf_off..buf_off + frame.len()].copy_from_slice(frame);
            if tx_len > frame.len() {
                dma.map.bytes_mut()[buf_off + frame.len()..buf_off + tx_len].fill(0);
            }
            fence(Ordering::Release);
            write_tx_desc(&dma, tx_tail, dma.dev_addr(buf_off as u64), tx_len as u16);
            fence(Ordering::SeqCst);
            tx_tail = (tx_tail + 1) % RING_LEN;
            mmio.w32(txq + Q_DT, tx_tail as u32);
            if !logged_tx {
                logged_tx = true;
                println!("e1000e: tx first frame ({} B)", tx_len);
            }
            true
        });

        // Reap completed RX descriptors.
        loop {
            let desc_off = (OFF_RX_DESC + rx_cur * 16) as u64;
            fence(Ordering::Acquire);
            let meta = dma.map.r64(desc_off + 8);
            let status = (meta >> 32) as u8;
            if (status & RX_STAT_DD) == 0 {
                break;
            }
            let len = (meta & 0xFFFF) as usize;
            if (status & RX_STAT_EOP) != 0 && (14..=MAX_FRAME).contains(&len) {
                let buf_off = OFF_RX_BUFS + rx_cur * BUF_BYTES;
                rx_copy[..len].copy_from_slice(&dma.map.bytes()[buf_off..buf_off + len]);
                if !logged_rx {
                    logged_rx = true;
                    println!("e1000e: rx first frame ({} B)", len);
                }
                bridge.deliver_rx(&rx_copy[..len]);
            }
            let buf_addr = dma.dev_addr((OFF_RX_BUFS + rx_cur * BUF_BYTES) as u64);
            write_rx_desc(&dma, rx_cur, buf_addr);
            fence(Ordering::SeqCst);
            mmio.w32(rxq + Q_DT, rx_cur as u32);
            rx_cur = (rx_cur + 1) % RING_LEN;
        }
    }
}
