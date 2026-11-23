// SPDX-License-Identifier: AGPL-3.0-only
//! Remote Play cryptography, ported from chiaki-ng's `lib/src/rpcrypt.c`, `gkcrypt.c` and `ecdh.c`.
//!
//! Pure Rust: no OpenSSL. Functions take inputs and return new values; nothing here does I/O.

pub mod ecdh;
pub mod gkcrypt;
pub mod rpcrypt;
mod rpcrypt_tables;

/// The console and firmware family a key schedule belongs to. Mirrors chiaki-ng's `ChiakiTarget`
/// (`lib/include/chiaki/common.h`), whose numeric values are kept for the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Target {
    Ps4Unknown,
    Ps4V8,
    Ps4V9,
    Ps4V10,
    Ps5Unknown,
    Ps5V1,
}

impl Target {
    /// chiaki-ng's numeric value for this target.
    pub const fn code(self) -> u32 {
        match self {
            Target::Ps4Unknown => 0,
            Target::Ps4V8 => 800,
            Target::Ps4V9 => 900,
            Target::Ps4V10 => 1000,
            Target::Ps5Unknown => 1_000_000,
            Target::Ps5V1 => 1_000_100,
        }
    }

    pub const fn is_ps5(self) -> bool {
        self.code() >= Target::Ps5Unknown.code()
    }

    /// PS4 firmware before 10 used a fixed schedule with no key tables.
    pub const fn is_ps4_pre10(self) -> bool {
        matches!(self, Target::Ps4V8 | Target::Ps4V9)
    }

    /// The key tables exist only for PS4 10+ and PS5 (chiaki-ng: `target < CHIAKI_TARGET_PS4_10` is refused).
    const fn has_key_tables(self) -> bool {
        self.code() >= Target::Ps4V10.code()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    #[error("this operation has no key schedule for target {0:?}")]
    UnsupportedTarget(Target),
    #[error("key offset {0:#x} is past the end of the key table (must be below 0x20)")]
    KeyOffset(usize),
}
