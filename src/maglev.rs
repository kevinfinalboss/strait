//! Maglev consistent hashing (Eisenbud et al., NSDI 2016).
//!
//! A Maglev table is a fixed-size array where every slot names a backend. A
//! packet goes to `table[hash(flow) % size]`. The table is built so that:
//!
//! - every backend owns almost exactly the same number of slots (they differ by
//!   at most one), so load spreads evenly;
//! - when a backend joins or leaves, few slots of the other backends change
//!   owner, so most flows keep their backend without any connection tracking.
//!
//! The XDP data plane cannot afford to build this table per packet, so
//! userspace builds it and copies it into a BPF array; the kernel side only
//! does `table[hash % size]`.

use std::net::IpAddr;

/// Default table size. Must be prime, and much larger than the number of
/// backends: the paper suggests at least 100 slots per backend. 65537 is what
/// Katran uses.
pub const DEFAULT_TABLE_SIZE: u32 = 65_537;

/// A built lookup table over a set of backends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Maglev {
    backends: Vec<IpAddr>,
    table: Vec<u32>,
}

impl Maglev {
    /// Builds a table of `size` slots over `backends`.
    ///
    /// The result depends only on the set of backends, not on their order or on
    /// duplicates, so every strait instance builds the same table from the same
    /// endpoints. `size` must be a prime larger than the number of backends.
    pub fn new(backends: impl IntoIterator<Item = IpAddr>, size: u32) -> Self {
        assert!(
            is_prime(size),
            "Maglev table size must be prime, got {size}"
        );

        let mut backends: Vec<IpAddr> = backends.into_iter().collect();
        backends.sort_unstable();
        backends.dedup();
        if backends.is_empty() {
            return Self {
                backends,
                table: Vec::new(),
            };
        }
        assert!(
            backends.len() < size as usize,
            "Maglev table size {size} is too small for {} backends",
            backends.len()
        );

        let size_u64 = u64::from(size);
        // Each backend walks its own permutation of the slots: start at
        // `offset` and advance by `skip`. `size` is prime and `skip` is in
        // 1..size, so the walk visits every slot exactly once.
        let walks: Vec<(u64, u64)> = backends
            .iter()
            .map(|backend| {
                let key = address_bytes(backend);
                let offset = hash(&key, OFFSET_SEED) % size_u64;
                let skip = hash(&key, SKIP_SEED) % (size_u64 - 1) + 1;
                (offset, skip)
            })
            .collect();

        const EMPTY: u32 = u32::MAX;
        let mut table = vec![EMPTY; size as usize];
        // How far along its permutation each backend has looked.
        let mut next = vec![0u64; backends.len()];
        let mut filled = 0;

        // Backends take turns claiming their next free slot, which is what keeps
        // the shares within one slot of each other.
        'fill: loop {
            for (index, &(offset, skip)) in walks.iter().enumerate() {
                let mut slot = (offset + next[index] * skip) % size_u64;
                while table[slot as usize] != EMPTY {
                    next[index] += 1;
                    slot = (offset + next[index] * skip) % size_u64;
                }
                table[slot as usize] = index as u32;
                next[index] += 1;
                filled += 1;
                if filled == size {
                    break 'fill;
                }
            }
        }

        Self { backends, table }
    }

    /// Backends in table order: slot values index into this list.
    pub fn backends(&self) -> &[IpAddr] {
        &self.backends
    }

    /// Slot `i` holds the index in [`backends`](Self::backends) of its owner.
    /// Empty when there are no backends.
    pub fn table(&self) -> &[u32] {
        &self.table
    }

    /// The backend for a flow with hash `flow_hash`, as the data plane picks it.
    pub fn lookup(&self, flow_hash: u32) -> Option<IpAddr> {
        if self.table.is_empty() {
            return None;
        }
        let slot = flow_hash as usize % self.table.len();
        Some(self.backends[self.table[slot] as usize])
    }
}

const OFFSET_SEED: u64 = 0x9e37_79b9_7f4a_7c15;
const SKIP_SEED: u64 = 0xc2b2_ae3d_27d4_eb4f;

/// IPv4 addresses as 4 bytes, IPv6 as 16.
fn address_bytes(addr: &IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

/// FNV-1a with a seed, finished with the splitmix64 mixer.
///
/// Spelled out instead of using `DefaultHasher`, whose output may change between
/// Rust releases: two strait builds must agree on the table.
fn hash(bytes: &[u8], seed: u64) -> u64 {
    let mut state = 0xcbf2_9ce4_8422_2325 ^ seed;
    for &byte in bytes {
        state ^= u64::from(byte);
        state = state.wrapping_mul(0x0000_0100_0000_01b3);
    }
    state = (state ^ (state >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    state = (state ^ (state >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    state ^ (state >> 31)
}

fn is_prime(n: u32) -> bool {
    if n < 2 {
        return false;
    }
    let n = u64::from(n);
    (2..).take_while(|d| d * d <= n).all(|d| n % d != 0)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn backends(count: u32) -> Vec<IpAddr> {
        (1..=count)
            .map(|i| IpAddr::V4(Ipv4Addr::from(0x0a00_0300 + i)))
            .collect()
    }

    fn shares(maglev: &Maglev) -> Vec<usize> {
        let mut shares = vec![0; maglev.backends().len()];
        for &owner in maglev.table() {
            shares[owner as usize] += 1;
        }
        shares
    }

    /// Fraction of slots whose backend changed between two tables, ignoring the
    /// slots that `before` gave to `ignore`.
    fn moved(before: &Maglev, after: &Maglev, ignore: Option<IpAddr>) -> f64 {
        let mut moved = 0;
        let mut counted = 0;
        for slot in 0..before.table().len() as u32 {
            let old = before.lookup(slot).unwrap();
            if Some(old) == ignore {
                continue;
            }
            counted += 1;
            if after.lookup(slot) != Some(old) {
                moved += 1;
            }
        }
        f64::from(moved) / f64::from(counted)
    }

    #[test]
    fn shares_differ_by_at_most_one_slot() {
        for count in [1, 2, 3, 7, 10, 100] {
            let maglev = Maglev::new(backends(count), DEFAULT_TABLE_SIZE);
            let shares = shares(&maglev);
            let (min, max) = (shares.iter().min(), shares.iter().max());
            assert!(
                max.unwrap() - min.unwrap() <= 1,
                "{count} backends: {min:?}..{max:?}"
            );
        }
    }

    #[test]
    fn ignores_order_and_duplicates() {
        let mut shuffled = backends(5);
        shuffled.reverse();
        shuffled.push(shuffled[0]);

        assert_eq!(Maglev::new(shuffled, 251), Maglev::new(backends(5), 251));
    }

    #[test]
    fn removing_a_backend_moves_few_other_flows() {
        let all = backends(10);
        let before = Maglev::new(all.clone(), DEFAULT_TABLE_SIZE);
        let removed = all[3];
        let after = Maglev::new(
            all.iter().copied().filter(|b| *b != removed),
            DEFAULT_TABLE_SIZE,
        );

        // The removed backend's flows must move; everyone else's mostly stay.
        // The paper reports a few percent; a modulo hash would move ~90%.
        assert!(after.backends().iter().all(|b| *b != removed));
        let share = moved(&before, &after, Some(removed));
        assert!(share < 0.05, "{:.1}% of other flows moved", share * 100.0);
    }

    #[test]
    fn adding_a_backend_takes_slots_mostly_from_others_evenly() {
        let before = Maglev::new(backends(10), DEFAULT_TABLE_SIZE);
        let after = Maglev::new(backends(11), DEFAULT_TABLE_SIZE);

        // Ideally exactly the new backend's 1/11 of the slots change.
        let share = moved(&before, &after, None);
        assert!(
            share < 1.0 / 11.0 + 0.05,
            "{:.1}% of flows moved",
            share * 100.0
        );
    }

    #[test]
    fn no_backends_means_no_table() {
        let maglev = Maglev::new([], 251);
        assert!(maglev.table().is_empty());
        assert_eq!(maglev.lookup(42), None);
    }

    #[test]
    fn rejects_sizes_that_are_not_prime() {
        assert!(std::panic::catch_unwind(|| Maglev::new(backends(2), 65_536)).is_err());
    }
}
