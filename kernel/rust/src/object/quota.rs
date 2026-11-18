//! Per-process resource quotas, hierarchical: a charge counts against the process's own account
//! and every ancestor's, and fails (`Status::NoResources`) if any of them would go over its limit.
//! So a child can never use more than its parent was given, whatever limits it asks for.
//!
//! Lock-free: each counter is an atomic add that is rolled back if it overshoots.

use core::sync::atomic::{AtomicU64, Ordering};

use super::kref::KRef;
use super::{KResult, Status};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(usize)]
pub enum Res {
    /// Bytes of committed memory (VMO pages).
    Memory = 0,
    /// Handles in the process's handle table.
    Handles = 1,
    /// Threads alive in the process.
    Threads = 2,
}

const RES: usize = 3;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Limits {
    pub memory: u64,
    pub handles: u64,
    pub threads: u64,
}

impl Limits {
    pub const UNLIMITED: Limits = Limits {
        memory: u64::MAX,
        handles: u64::MAX,
        threads: u64::MAX,
    };

    /// Defaults for a new process when the creator does not choose.
    pub const DEFAULT: Limits = Limits {
        memory: 64 << 20,
        handles: 4096,
        threads: 64,
    };

    fn get(&self, r: usize) -> u64 {
        [self.memory, self.handles, self.threads][r]
    }
}

pub struct Account {
    parent: Option<KRef<Account>>,
    limits: Limits,
    used: [AtomicU64; RES],
}

impl Account {
    pub fn new(parent: Option<KRef<Account>>, limits: Limits) -> Account {
        Account {
            parent,
            limits,
            used: [const { AtomicU64::new(0) }; RES],
        }
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    pub fn used(&self, r: Res) -> u64 {
        self.used[r as usize].load(Ordering::Relaxed)
    }

    fn try_one(&self, r: usize, n: u64) -> bool {
        let lim = self.limits.get(r);
        let mut cur = self.used[r].load(Ordering::Relaxed);
        loop {
            let Some(next) = cur.checked_add(n).filter(|&v| v <= lim) else {
                return false;
            };
            match self.used[r].compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return true,
                Err(v) => cur = v,
            }
        }
    }

    fn release_one(&self, r: usize, n: u64) {
        let old = self.used[r].fetch_sub(n, Ordering::Relaxed);
        crate::kassert!(old >= n); // an unbalanced refund is a kernel bug
    }

    /// Charge `n` units here and in every ancestor, all or nothing.
    pub fn charge(&self, r: Res, n: u64) -> KResult<()> {
        if n == 0 {
            return Ok(());
        }
        let ri = r as usize;
        if !self.try_one(ri, n) {
            return Err(Status::NoResources);
        }
        if let Some(Err(e)) = self.parent.as_ref().map(|p| p.charge(r, n)) {
            self.release_one(ri, n);
            return Err(e);
        }
        Ok(())
    }

    pub fn uncharge(&self, r: Res, n: u64) {
        if n == 0 {
            return;
        }
        self.release_one(r as usize, n);
        if let Some(p) = &self.parent {
            p.uncharge(r, n);
        }
    }
}

/// A charge that is refunded when dropped (owned by whatever the resource is: a VMO's pages, a
/// running thread). Holding it keeps the account alive; creating and dropping it never allocates.
pub struct Charge {
    acct: KRef<Account>,
    res: Res,
    amount: u64,
}

impl Charge {
    pub fn new(acct: &KRef<Account>, res: Res, amount: u64) -> KResult<Charge> {
        acct.charge(res, amount)?;
        Ok(Charge {
            acct: acct.clone(),
            res,
            amount,
        })
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        self.acct.uncharge(self.res, self.amount);
    }
}
