//! Modern VirtIO 1.x network driver (`virtio-net.ddrv`, PCI `1AF4:1041`).
//!
//! Runs isolated in user space with all packet buffers pinned through the IOMMU (`libd::Dma`)
//! and bridges raw Ethernet frames to `net.dsvc` via shared-memory `IoRing`s (`net_drv.rs`).

use core::sync::atomic::{Ordering, fence};

use libd::proto;
use libd::sys;
use libd::{Dma, Port, Startup, println};

use crate::net_drv::{KEY_CTL, KEY_IRQ0, KEY_IRQ1, KEY_SVC, MAX_FRAME, NetBridge};
use crate::virtio::{DESC_WRITE, Virtio};

const F_MAC: u64 = 1 << 5;
const F_STATUS: u64 = 1 << 16;

const VNET_HDR_LEN: usize = 12;
const SLOTS: usize = 8; // 8 RX + 8 TX, each <= QSIZE (16)
const SLOT_BYTES: usize = 2048;
const DMA_BYTES: u64 = (SLOTS * 2 * SLOT_BYTES) as u64; // 32 KiB = 8 pages
const MS: u64 = 1_000_000;

pub fn main(s: *const Startup) -> i32 {
    // SAFETY: `s` is the startup block pointer passed by the kernel.
    if !unsafe { libd::init(s, "virtio-net") } {
        return -1;
    }
    let dev = libd::startup_handle(sys::TAG_DEVICE);
    let ctl = libd::startup_handle(proto::TAG_CONTROL);
    let Ok(info) = sys::device_info(dev) else {
        println!("virtio-net: device_info failed");
        return 1;
    };
    let (v, features) = match Virtio::open_with(dev, F_MAC | F_STATUS) {
        Ok(x) => x,
        Err(e) => {
            println!("virtio-net: {}: {}", info.name(), e);
            return 1;
        }
    };
    let mut mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    if (features & F_MAC) != 0
        && let Some(cfg) = v.devcfg
        && cfg.len >= 6
    {
        for (i, b) in mac.iter_mut().enumerate() {
            *b = v.r8(cfg, i as u64);
        }
    }
    let mut rxq = match v.queue(0) {
        Ok(q) => q,
        Err(e) => {
            println!("virtio-net: rxq: {}", e);
            return 1;
        }
    };
    let mut txq = match v.queue(1) {
        Ok(q) => q,
        Err(e) => {
            println!("virtio-net: txq: {}", e);
            return 1;
        }
    };
    let mut dma = match Dma::new(dev, DMA_BYTES, sys::DMA_DEVICE_READ | sys::DMA_DEVICE_WRITE) {
        Ok(d) => d,
        Err(e) => {
            println!("virtio-net: dma_map: {}", sys::status(e));
            return 1;
        }
    };
    dma.map.bytes_mut().fill(0);

    // Pre-post all RX buffers before setting DRIVER_OK.
    for i in 0..SLOTS {
        let off = (i * SLOT_BYTES) as u64;
        rxq.desc(i as u16, dma.dev_addr(off), SLOT_BYTES as u32, DESC_WRITE, 0);
        rxq.push(i as u16);
    }
    v.driver_ok();
    v.notify(&rxq);

    println!(
        "virtio-net: ready on {} MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (IOMMU={})",
        info.name(),
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
    port.arm(rxq.irq, sys::SIGNALED, KEY_IRQ0);
    port.arm(txq.irq, sys::SIGNALED, KEY_IRQ1);

    proto::send(ctl, proto::READY, 0, 0);
    NetBridge::announce(ctl, mac, true, 1500, "virtio-net");

    let mut bridge = NetBridge::new();
    let mut tx_in_use = [false; SLOTS];
    let mut tx_cursor = 0usize;
    let mut irqs = 0u64;
    let mut rx_copy = [0u8; MAX_FRAME];

    loop {
        if let Some((key, _)) = port.wait(20 * MS) {
            match key {
                KEY_CTL => {
                    if !bridge.poll_ctl(ctl, &port, irqs) {
                        return 0;
                    }
                }
                KEY_SVC => {
                    bridge.poll_svc(&port);
                }
                KEY_IRQ0 => {
                    irqs += sys::interrupt_ack(rxq.irq).unwrap_or(0);
                    port.arm(rxq.irq, sys::SIGNALED, KEY_IRQ0);
                }
                KEY_IRQ1 => {
                    irqs += sys::interrupt_ack(txq.irq).unwrap_or(0);
                    port.arm(txq.irq, sys::SIGNALED, KEY_IRQ1);
                }
                _ => {}
            }
        }

        // Reap completed TX descriptors.
        while let Some((id, _)) = txq.pop() {
            if (id as usize) < SLOTS {
                tx_in_use[id as usize] = false;
            }
        }

        // Drain outbound frames from `net.dsvc` and transmit via `txq`.
        bridge.drain_tx(|frame| {
            // Reap again if ring looks busy.
            while let Some((id, _)) = txq.pop() {
                if (id as usize) < SLOTS {
                    tx_in_use[id as usize] = false;
                }
            }
            let slot = (0..SLOTS)
                .map(|k| (tx_cursor + k) % SLOTS)
                .find(|&s| !tx_in_use[s]);
            let Some(slot) = slot else {
                return false;
            };
            tx_cursor = (slot + 1) % SLOTS;
            let off = (SLOTS + slot) * SLOT_BYTES;
            let buf = dma.map.bytes_mut();
            buf[off..off + VNET_HDR_LEN].fill(0);
            buf[off + VNET_HDR_LEN..off + VNET_HDR_LEN + frame.len()].copy_from_slice(frame);
            fence(Ordering::Release);
            txq.desc(
                slot as u16,
                dma.dev_addr(off as u64),
                (VNET_HDR_LEN + frame.len()) as u32,
                0,
                0,
            );
            tx_in_use[slot] = true;
            txq.push(slot as u16);
            v.notify(&txq);
            true
        });

        // Drain received frames from `rxq` and deliver to `net.dsvc`.
        let mut reposted = false;
        while let Some((id, len)) = rxq.pop() {
            let slot = id as usize;
            if slot < SLOTS {
                fence(Ordering::Acquire);
                let total = (len as usize).min(SLOT_BYTES);
                if total > VNET_HDR_LEN + 14 {
                    let flen = (total - VNET_HDR_LEN).min(MAX_FRAME);
                    let off = slot * SLOT_BYTES + VNET_HDR_LEN;
                    rx_copy[..flen].copy_from_slice(&dma.map.bytes()[off..off + flen]);
                    bridge.deliver_rx(&rx_copy[..flen]);
                }
                let off = (slot * SLOT_BYTES) as u64;
                rxq.desc(slot as u16, dma.dev_addr(off), SLOT_BYTES as u32, DESC_WRITE, 0);
                rxq.push(slot as u16);
                reposted = true;
            }
        }
        if reposted {
            v.notify(&rxq);
        }
    }
}
