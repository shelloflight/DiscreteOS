//! USB 2 and USB 3 hub configuration, port reset, and hot-plug polling.

use libd::handle::sleep;
use libd::sys;

use super::*;

/// A configured hub (USB 2, or the SuperSpeed half of a USB 3 hub).
#[derive(Clone, Copy)]
pub(super) struct Hub {
    pub(super) slot: u32,
    pub(super) loc: Loc,
    pub(super) ports: u32,
    /// A USB 3 hub (SuperSpeed port status and features).
    pub(super) ss: bool,
    /// Stopped answering (its parent reports the unplug).
    pub(super) dead: bool,
    pub(super) ps: [PortState; HUB_PORTS as usize],
}

impl Xhci {
    pub(super) fn hub_index(&self, slot: u32) -> Option<usize> {
        self.hubs.iter().position(|h| h.is_some_and(|h| h.slot == slot))
    }

    fn hub_status(&mut self, slot: u32, port: u32) -> Result<(u16, u16), u32> {
        if self.control(slot, [0xA3, 0, 0, 0, port as u8, 0, 4, 0], 4)? < 4 {
            return Err(0);
        }
        Ok((u16::from_le_bytes([self.desc(0), self.desc(1)]), u16::from_le_bytes([self.desc(2), self.desc(3)])))
    }

    fn hub_feature(&mut self, slot: u32, port: u32, set: bool, feature: u8) -> Result<u32, u32> {
        self.control(slot, [0x23, if set { 3 } else { 1 }, feature, 0, port as u8, 0, 0, 0], 0)
    }

    /// Reset hub port `port`; the speed of the device there. On a USB 3 hub every device is
    /// SuperSpeed (its USB 2 half has the others).
    pub(super) fn hub_reset(&mut self, slot: u32, port: u32, ss: bool) -> Result<u32, &'static str> {
        self.hub_feature(slot, port, true, F_PORT_RESET).map_err(|_| "hub port reset refused")?;
        let deadline = sys::clock_ns() + 500 * MS;
        let status = loop {
            sleep(10 * MS);
            let (st, chg) = self.hub_status(slot, port).map_err(|_| "hub port status unreadable")?;
            if chg & HC_RESET != 0 {
                break st;
            }
            if sys::clock_ns() >= deadline {
                return Err("hub port reset timed out");
            }
        };
        let _ = self.hub_feature(slot, port, false, F_C_PORT_RESET);
        if status & HS_ENABLE == 0 {
            return Err("hub port did not enable");
        }
        sleep(20 * MS); // reset recovery (USB 2.0 7.1.7.5: 10 ms)
        if ss {
            return Ok(4);
        }
        Ok(if status & HS_LOW_SPEED != 0 {
            2
        } else if status & HS_HIGH_SPEED != 0 {
            3
        } else {
            1
        })
    }

    /// A hub: configure it, tell the controller it is a hub (ports, think time), power its ports;
    /// they are probed once power is good and the connections have settled. A USB 3 hub (on a
    /// SuperSpeed link) also learns its depth, for the route strings of the packets it forwards.
    pub(super) fn setup_hub(&mut self, slot: u32, loc: Loc, cfg_value: u8, id: Ident) -> Result<Found, &'static str> {
        let i = self.hubs.iter().position(|h| h.is_none()).ok_or("too many hubs")?;
        let ss = loc.speed >= 4;
        self.control(slot, [0, 9, cfg_value, 0, 0, 0, 0, 0], 0).map_err(|_| "SET_CONFIGURATION failed")?;
        let (ty, want) = if ss { (0x2A, 12) } else { (0x29, 9) };
        if self.control(slot, [0xA0, 6, 0, ty, 0, 0, want, 0], u16::from(want)).map_err(|_| "hub descriptor unreadable")? < 7 {
            return Err("hub descriptor too short");
        }
        let ports = u32::from(self.desc(2)).min(HUB_PORTS);
        if ports == 0 {
            return Err("hub without ports");
        }
        let ttt = if ss { 0 } else { (u32::from(self.desc(3)) >> 5) & 3 };
        let power_good = u64::from(self.desc(5)) * 2 * MS;
        if ss {
            // Depth below the root port: 0 for a hub on a root port.
            self.control(slot, [0x20, REQ_SET_HUB_DEPTH, loc.depth as u8, 0, 0, 0, 0, 0], 0).map_err(|_| "SET_HUB_DEPTH failed")?;
        }
        self.clear_page(PG_IN);
        self.ctx_w(PG_IN, 0, 1, 1);
        self.slot_ctx(&loc, 1, ports, ttt);
        let cfg = Trb { param: self.addr(PG_IN, 0), status: 0, control: T_CONFIGURE_EP << 10 | slot << 24 };
        self.command(cfg).map_err(|_| "Configure Endpoint (hub) failed")?;
        for p in 1..=ports {
            self.hub_feature(slot, p, true, F_PORT_POWER).map_err(|_| "hub port power refused")?;
        }
        let ready = PortState { pending: true, changed_at: sys::clock_ns() + power_good.max(DEBOUNCE), ..PortState::default() };
        self.hubs[i] = Some(Hub { slot, loc, ports, ss, dead: false, ps: [ready; HUB_PORTS as usize] });
        Ok(Found::Hub(ports, id, ss))
    }

    pub(super) fn poll_hub(&mut self, h: usize, slot: u32, ports: u32, now: u64) {
        for port in 1..=ports {
            let Ok((st, chg)) = self.hub_status(slot, port) else {
                if let Some(hub) = self.hubs[h].as_mut() {
                    hub.dead = true;
                    let loc = hub.loc;
                    say!(self, "hub on port {} stopped answering", loc);
                }
                return;
            };
            let ss = self.hubs[h].is_some_and(|x| x.ss);
            for b in 0..8u8 {
                let feature = match b {
                    0..=4 => F_C_PORT_CONNECTION + b,
                    5 if ss => F_C_BH_PORT_RESET,
                    6 if ss => F_C_PORT_LINK_STATE,
                    7 if ss => F_C_PORT_CONFIG_ERROR,
                    _ => continue,
                };
                if chg & (1 << b) != 0 {
                    let _ = self.hub_feature(slot, port, false, feature);
                }
            }
            let connected = st & HS_CONNECTION != 0;
            if chg & HC_CONNECTION != 0 {
                self.teardown(slot, port);
            }
            let Some(ps) = self.port_state(slot, port) else { return };
            if chg & HC_CONNECTION != 0 {
                ps.done = false;
                if connected && !ps.ignored {
                    (ps.pending, ps.changed_at) = (true, now);
                }
            }
            if ps.ignored {
                if connected {
                    ps.gone_since = 0;
                } else if ps.gone_since == 0 {
                    ps.gone_since = now;
                } else if now - ps.gone_since >= GONE_FOR {
                    *ps = PortState::default();
                }
                continue;
            }
            if !connected {
                ps.pending = false;
                continue;
            }
            if ps.pending && now >= ps.changed_at + DEBOUNCE && !ps.done {
                ps.pending = false;
                self.probe_port(slot, port, now);
                if self.hubs[h].is_none_or(|x| x.slot != slot) {
                    return;
                }
            }
        }
    }
}
