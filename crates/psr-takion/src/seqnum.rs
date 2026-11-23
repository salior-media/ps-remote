// SPDX-License-Identifier: AGPL-3.0-only
//! RFC 1982 serial number arithmetic. Ported from chiaki-ng `lib/include/chiaki/seqnum.h`.

/// A wrapping sequence number: `gt` and `lt` follow RFC 1982, and are both false at exactly half the
/// number space, where the order is undefined.
pub trait SeqNum: Copy + Eq + std::fmt::Debug {
    fn gt(self, other: Self) -> bool;
    fn lt(self, other: Self) -> bool;
    fn wrapping_add_n(self, n: u64) -> Self;
    /// The plain value.
    fn raw(self) -> u64;
}

macro_rules! seq_num {
    ($t:ty) => {
        impl SeqNum for $t {
            fn gt(self, other: Self) -> bool {
                const HALF: $t = 1 << (<$t>::BITS - 1);
                self != other
                    && ((self < other && other - self > HALF) || (self > other && self - other < HALF))
            }

            fn lt(self, other: Self) -> bool {
                const HALF: $t = 1 << (<$t>::BITS - 1);
                self != other
                    && ((self < other && other - self < HALF) || (self > other && self - other > HALF))
            }

            fn wrapping_add_n(self, n: u64) -> Self {
                self.wrapping_add(n as $t)
            }

            fn raw(self) -> u64 {
                u64::from(self)
            }
        }
    };
}

seq_num!(u16);
seq_num!(u32);
