//! Intel Gigabit Ethernet driver (`e1000e.ddrv`, PCI vendor `8086`, class `02.00`).
//!
//! Supports Intel 82574L (QEMU `e1000e`), 82540EM (`e1000`), and compatible PCIe Intel GbE
//! controllers. Runs isolated in user space with IOMMU-pinned RX/TX rings bridged to `net.dsvc`.

use core::sync::atomic::{Ordering, fence};

use libd::proto;
use libd::sys::{self, Handle};
use libd::{Dma, Mapping, Port, Startup, println};

use crate::net_drv::{KEY_CTL, KEY_IRQ0, KEY_SVC, MAX_FRAME, NetBridge};

// MMIO register offsets
const REG_CTRL: u64 = 0x0000;
const REG_STATUS: u64 = 0x0008;
const REG_EERD: u64 = 0x0014;
const REG_ICR: u64 = 0x00C0;
const REG_IMS: u64 = 0x00D0;
const REG_IMC: u64 = 0x00D8;
const REG_IVAR: u64 = 0x00E4;
const REG_RCTL: u64 = 0x0100;
const REG_TCTL: u64 = 0x0400;
const REG_TIPG: u64 = 0x0410;
const REG_RDBAL: u64 = 0x2800;
const REG_RDBAH: u64 = 0x2804;
const REG_RDLEN: u64 = 0x2808;
const REG_RDH: u64 = 0x2810;
const REG_RDT: u64 = 0x2818;
const REG_TDBAL: u64 = 0x3800;
const REG_TDBAH: u64 = 0x3804;
const REG_TDLEN: u64 = 0x3808;
const REG_TDH: u64 = 0x3810;
const REG_TDT: u64 = 0x3818;
const REG_MTA: u64 = 0x5200;
const REG_RAL0: u64 = 0x5400;
const REG_RAH0: u64 = 0x5404;

const CTRL_ASDE: u32 = 1 << 5;
const CTRL_SLU: u32 = 1 << 6;
const CTRL_RST: u32 = 1 << 26;

const RCTL_EN: u32 = 1 << 1;
const RCTL_BAM: u32 = 1 << 15;
const RCTL_SECRC: u32 = 1 << 26;

const TCTL_EN: u32 = 1 << 1;
const TCTL_PSP: u32 = 1 << 3;
const TCTL_CT: u32 = 0x10 << 4;
const TCTL_COLD: u32 = 0x40 << 12;

const TX_CMD_EOP: u8 = 1 << 0;
const TX_CMD_IFCS: u8 = 1 << 1;
const TX_CMD_RS: u8 = 1 << 3;
const RX_STAT_DD: u8 = 1 << 0;
const RX_STAT_EOP: u8 = 1 << 1;

const RING_LEN: usize = 16;
const BUF_BYTES: usize = 2048;
// DMA layout (17 pages):
//   Page 0: RX descriptors (0..256), TX descriptors (2048..2304)
//   Pages 1..9:   16 RX buffers (2048 B each)
//   Pages 9..17:  16 TX buffers (2048 B each)
const OFF_RX_DESC: usize = 0;
const OFF_TX_DESC: usize = 2048;
const OFF_RX_BUFS: usize = 4096;
const OFF_TX_BUFS: usize = 4096 + RING_LEN * BUF_BYTES;
const DMA_BYTES: u64 = (4096 + RING_LEN * 2 * BUF_BYTES) as u64;
const MS: u64 = 1_000_000;

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

fn read_mac(mmio: &Mapping) -> [u8; 6] {
    let ral = mmio.r32(REG_RAL0);
    let rah = mmio.r32(REG_RAH0);
    let mut mac = [
        (ral & 0xFF) as u8,
        ((ral >> 8) & 0xFF) as u8,
        ((ral >> 16) & 0xFF) as u8,
        ((ral >> 24) & 0xFF) as u8,
        (rah & 0xFF) as u8,
        ((rah >> 8) & 0xFF) as u8,
    ];
    if mac.iter().all(|&b| b == 0) || mac.iter().all(|&b| b == 0xFF) {
        if let (Some(w0), Some(w1), Some(w2)) = (
            read_eeprom_word(mmio, 0),
            read_eeprom_word(mmio, 1),
            read_eeprom_word(mmio, 2),
        ) {
            mac = [
                (w0 & 0xFF) as u8,
                (w0 >> 8) as u8,
                (w1 & 0xFF) as u8,
                (w1 >> 8) as u8,
                (w2 & 0xFF) as u8,
                (w2 >> 8) as u8,
            ];
        } else {
            mac = [0x52, 0x54, 0x00, 0xE1, 0x00, 0x0E];
        }
    }
    mac
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
    let _ = sys::config_write(dev, 0x04, 2, 0x6); // Memory + Bus Master
    let Ok(bar_vmo) = sys::device_map_bar(dev, 0) else {
        println!("e1000e: cannot map BAR 0");
        return 1;
    };
    let Ok(mmio) = Mapping::of(bar_vmo, info.bar_size[0]) else {
        println!("e1000e: Mapping::of failed");
        return 1;
    };

    // Read MAC before reset, then reset controller cleanly.
    mmio.w32(REG_IMC, 0xFFFF_FFFF);
    let mac = read_mac(&mmio);
    mmio.w32(REG_CTRL, mmio.r32(REG_CTRL) | CTRL_RST);
    libd::handle::sleep(15 * MS);
    mmio.w32(REG_IMC, 0xFFFF_FFFF);
    let _ = mmio.r32(REG_ICR);

    // Force link up + auto-speed detection.
    mmio.w32(REG_CTRL, (mmio.r32(REG_CTRL) | CTRL_SLU | CTRL_ASDE) & !(1 << 31));

    // Program MAC address into RAL0/RAH0 and clear multicast table.
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

    // Initialize RX ring.
    for i in 0..RING_LEN {
        let buf_addr = dma.dev_addr((OFF_RX_BUFS + i * BUF_BYTES) as u64);
        write_rx_desc(&dma, i, buf_addr);
    }
    let rx_base = dma.dev_addr(OFF_RX_DESC as u64);
    mmio.w32(REG_RDBAL, rx_base as u32);
    mmio.w32(REG_RDBAH, (rx_base >> 32) as u32);
    mmio.w32(REG_RDLEN, (RING_LEN * 16) as u32);
    mmio.w32(REG_RDH, 0);
    mmio.w32(REG_RDT, (RING_LEN - 1) as u32);

    // Initialize TX ring.
    for i in 0..RING_LEN {
        let o = (OFF_TX_DESC + i * 16) as u64;
        dma.map.w64(o, 0);
        // Mark DD=1 so all TX slots start free.
        dma.map.w64(o + 8, 1u64 << 32);
    }
    let tx_base = dma.dev_addr(OFF_TX_DESC as u64);
    mmio.w32(REG_TDBAL, tx_base as u32);
    mmio.w32(REG_TDBAH, (tx_base >> 32) as u32);
    mmio.w32(REG_TDLEN, (RING_LEN * 16) as u32);
    mmio.w32(REG_TDH, 0);
    mmio.w32(REG_TDT, 0);

    // Enable RX and TX engines.
    mmio.w32(REG_TIPG, 0x0060_200A);
    mmio.w32(REG_TCTL, TCTL_EN | TCTL_PSP | TCTL_CT | TCTL_COLD);
    mmio.w32(REG_RCTL, RCTL_EN | RCTL_BAM | RCTL_SECRC);

    // Bind interrupt vector 0 (MSI-X on e1000e, or MSI/INTx fallback).
    let irq: Handle = sys::device_interrupt(dev, 0).unwrap_or(0);
    if info.irqs > 0 {
        // 82574L IVAR: map RxQ0, TxQ0, Other all to vector 0 (bit 3/11/19 = valid).
        mmio.w32(REG_IVAR, 0x0008_0808);
    }
    mmio.w32(REG_IMS, 0x0150_0085); // TXDW | LSC | RXT0 | RXQ0 | TXQ0 | OTHER
    let _ = mmio.r32(REG_ICR);

    let link_up = (mmio.r32(REG_STATUS) & 2) != 0 || true;
    println!(
        "e1000e: ready on {} ({:04x}:{:04x}) MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (IOMMU={})",
        info.name(),
        info.vendor,
        info.device,
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5],
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
                    let _ = mmio.r32(REG_ICR);
                    port.arm(irq, sys::SIGNALED, KEY_IRQ0);
                }
                _ => {}
            }
        }

        // Transmit pending frames from `net.dsvc`.
        bridge.drain_tx(|frame| {
            let desc_off = (OFF_TX_DESC + tx_tail * 16) as u64;
            let status_byte = (dma.map.r64(desc_off + 8) >> 32) as u8;
            if (status_byte & 1) == 0 {
                return false;
            }
            let buf_off = OFF_TX_BUFS + tx_tail * BUF_BYTES;
            dma.map.bytes_mut()[buf_off..buf_off + frame.len()].copy_from_slice(frame);
            fence(Ordering::Release);
            write_tx_desc(&dma, tx_tail, dma.dev_addr(buf_off as u64), frame.len() as u16);
            fence(Ordering::SeqCst);
            tx_tail = (tx_tail + 1) % RING_LEN;
            mmio.w32(REG_TDT, tx_tail as u32);
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
                bridge.deliver_rx(&rx_copy[..len]);
            }
            let buf_addr = dma.dev_addr((OFF_RX_BUFS + rx_cur * BUF_BYTES) as u64);
            write_rx_desc(&dma, rx_cur, buf_addr);
            fence(Ordering::SeqCst);
            mmio.w32(REG_RDT, rx_cur as u32);
            rx_cur = (rx_cur + 1) % RING_LEN;
        }
    }
}
