//! Realtek PCIe Gigabit/2.5GbE Ethernet driver (`r8169.ddrv`, PCI vendor `10EC`, class `02.00`).
//!
//! Targets RTL8111/8168/8169/8125/8126 controllers common on x86-64 desktop motherboards.
//! Uses 64-bit C+ descriptor rings pinned through the IOMMU (`libd::Dma`) and bridges raw
//! Ethernet frames to `net.dsvc` via shared-memory `IoRing`s (`net_drv.rs`).

use core::sync::atomic::{Ordering, fence};

use libd::proto;
use libd::sys::{self, Handle};
use libd::{Dma, Mapping, Port, Startup, println};

use crate::net_drv::{KEY_CTL, KEY_IRQ0, KEY_SVC, MAX_FRAME, NetBridge};

// Realtek r8169 / r8168 / r8125 MMIO register offsets
const REG_IDR0: u64 = 0x00;
const REG_TNPDS_LO: u64 = 0x20;
const REG_TNPDS_HI: u64 = 0x24;
const REG_CMD: u64 = 0x37;
const REG_TXPOLL: u64 = 0x38;
const REG_IMR: u64 = 0x3C;
const REG_ISR: u64 = 0x3E;
const REG_TCR: u64 = 0x40;
const REG_RCR: u64 = 0x44;
const REG_CFG9346: u64 = 0x50;
const REG_PHYSTATUS: u64 = 0x6C;
const REG_RMS: u64 = 0xDA;
const REG_CPCMD: u64 = 0xE0;
const REG_RDSAR_LO: u64 = 0xE4;
const REG_RDSAR_HI: u64 = 0xE8;
const REG_MTPS: u64 = 0xEC;

const CMD_TX_EN: u8 = 1 << 2;
const CMD_RX_EN: u8 = 1 << 3;
const CMD_RESET: u8 = 1 << 4;

const DESC_OWN: u32 = 1 << 31;
const DESC_EOR: u32 = 1 << 30;
const DESC_FS: u32 = 1 << 29;
const DESC_LS: u32 = 1 << 28;

const RING_LEN: usize = 16;
const BUF_BYTES: usize = 2048;
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
    // PCIe Realtek NICs place MMIO registers in BAR 2 (fallback BAR 1 or BAR 0).
    let Some(bar) = [2usize, 1, 0].into_iter().find(|&b| info.bar_kind[b] == 1 && info.bar_size[b] >= 256) else {
        println!("r8169: {}: no MMIO BAR", info.name());
        return 1;
    };
    let _ = sys::config_write(dev, 0x04, 2, 0x6);
    let Ok(bar_vmo) = sys::device_map_bar(dev, bar as u64) else {
        println!("r8169: cannot map BAR {}", bar);
        return 1;
    };
    let Ok(mmio) = Mapping::of(bar_vmo, info.bar_size[bar]) else {
        println!("r8169: Mapping::of failed");
        return 1;
    };

    // Software reset.
    mmio.w16(REG_IMR, 0);
    mmio.w8(REG_CMD, CMD_RESET);
    for _ in 0..1000 {
        if (mmio.r8(REG_CMD) & CMD_RESET) == 0 {
            break;
        }
        libd::handle::sleep(MS);
    }

    let mut mac = [0u8; 6];
    for (i, b) in mac.iter_mut().enumerate() {
        *b = mmio.r8(REG_IDR0 + i as u64);
    }

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

    // Unlock configuration registers, program rings and RX/TX parameters.
    mmio.w8(REG_CFG9346, 0xC0);
    mmio.w16(REG_RMS, 0x3FFF);
    mmio.w8(REG_MTPS, 0x3B);
    mmio.w16(REG_CPCMD, 0x0003); // C+ TX & RX enabled
    let rx_base = dma.dev_addr(OFF_RX_DESC as u64);
    let tx_base = dma.dev_addr(OFF_TX_DESC as u64);
    mmio.w32(REG_RDSAR_LO, rx_base as u32);
    mmio.w32(REG_RDSAR_HI, (rx_base >> 32) as u32);
    mmio.w32(REG_TNPDS_LO, tx_base as u32);
    mmio.w32(REG_TNPDS_HI, (tx_base >> 32) as u32);
    mmio.w32(REG_TCR, 0x0300_0700);
    mmio.w32(REG_RCR, 0x0000_E70F); // AB | AM | APM | AAP + max DMA burst
    mmio.w8(REG_CMD, CMD_RX_EN | CMD_TX_EN);
    mmio.w8(REG_CFG9346, 0x00);

    let irq: Handle = sys::device_interrupt(dev, 0).unwrap_or(0);
    mmio.w16(REG_ISR, 0xFFFF);
    mmio.w16(REG_IMR, 0x0025); // ROK | TOK | LinkChg

    let link_up = (mmio.r8(REG_PHYSTATUS) & 0x02) != 0;
    println!(
        "r8169: ready on {} ({:04x}:{:04x}) MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} link={}",
        info.name(),
        info.vendor,
        info.device,
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5],
        link_up
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
                    let isr = mmio.r16(REG_ISR);
                    mmio.w16(REG_ISR, isr);
                    port.arm(irq, sys::SIGNALED, KEY_IRQ0);
                }
                _ => {}
            }
        }

        bridge.drain_tx(|frame| {
            let desc_off = (OFF_TX_DESC + tx_cur * 16) as u64;
            if (dma.map.r32(desc_off) & DESC_OWN) != 0 {
                return false;
            }
            let buf_off = OFF_TX_BUFS + tx_cur * BUF_BYTES;
            dma.map.bytes_mut()[buf_off..buf_off + frame.len()].copy_from_slice(frame);
            let eor = if tx_cur + 1 == RING_LEN { DESC_EOR } else { 0 };
            dma.map.w32(desc_off + 4, 0);
            dma.map.w64(desc_off + 8, dma.dev_addr(buf_off as u64));
            fence(Ordering::Release);
            dma.map.w32(desc_off, DESC_OWN | eor | DESC_FS | DESC_LS | (frame.len() as u32 & 0x3FFF));
            fence(Ordering::SeqCst);
            mmio.w8(REG_TXPOLL, 0x40);
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
            let raw_len = (opts1 & 0x3FFF) as usize;
            let len = raw_len.saturating_sub(4); // strip 4-byte FCS
            if (14..=MAX_FRAME).contains(&len) {
                let buf_off = OFF_RX_BUFS + rx_cur * BUF_BYTES;
                rx_copy[..len].copy_from_slice(&dma.map.bytes()[buf_off..buf_off + len]);
                bridge.deliver_rx(&rx_copy[..len]);
            }
            arm_rx_desc(&dma, rx_cur, dma.dev_addr((OFF_RX_BUFS + rx_cur * BUF_BYTES) as u64));
            rx_cur = (rx_cur + 1) % RING_LEN;
        }
    }
}
