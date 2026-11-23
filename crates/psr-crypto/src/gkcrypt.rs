// SPDX-License-Identifier: AGPL-3.0-only
//! Stream encryption: an AES-128 counter-mode key stream, and 4-byte GMAC tags. Ported from chiaki-ng
//! `lib/src/gkcrypt.c` (LicenseRef-AGPL-3.0-only-OpenSSL).
//!
//! chiaki-ng also keeps a background thread that fills a ring buffer of key stream ahead of use. That is a
//! speed measure, not part of the protocol, and is left out until a benchmark asks for it.

use aes::Aes128;
use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};
use aes_gcm::aead::AeadInOut;
use aes_gcm::aead::consts::U16;
use aes_gcm::AesGcm;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::ecdh::SECRET_SIZE;

pub const BLOCK_SIZE: usize = 0x10;
pub const GMAC_SIZE: usize = 4;
/// Every this many bytes of key position, the GMAC key is replaced by a new one.
pub const GMAC_KEY_REFRESH_KEY_POS: u64 = 45_000;
/// How far the IV counter moves for each GMAC key refresh.
pub const GMAC_KEY_REFRESH_IV_OFFSET: u64 = 44_910;
pub const HANDSHAKE_KEY_SIZE: usize = 0x10;

pub type Block = [u8; BLOCK_SIZE];

/// AES-128-GCM with a 16-byte nonce, as chiaki-ng configures OpenSSL (`EVP_CTRL_GCM_SET_IVLEN` = 16).
type Gcm16 = AesGcm<Aes128, U16>;

/// `base` read as a little-endian 128-bit number, plus `v`, with the carry out of the top byte dropped.
/// This is chiaki-ng's `counter_add`.
fn counter_add(base: &Block, v: u64) -> Block {
    u128::from_le_bytes(*base).wrapping_add(u128::from(v)).to_le_bytes()
}

/// chiaki-ng `chiaki_gkcrypt_gen_gmac_key`: SHA-256 of `key_base ‖ (iv + index · 44910)`, folded in half
/// by XOR.
pub fn gen_gmac_key(index: u64, key_base: &Block, iv: &Block) -> Block {
    let mut hash = Sha256::new();
    hash.update(key_base);
    hash.update(counter_add(iv, index.wrapping_mul(GMAC_KEY_REFRESH_IV_OFFSET)));
    let md = hash.finalize();
    std::array::from_fn(|i| md[i] ^ md[i + BLOCK_SIZE])
}

/// One direction's stream cipher state. Immutable: the GMAC key for any position is derived on demand,
/// which gives the same tags as chiaki-ng's cached current key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GkCrypt {
    index: u8,
    key_base: Block,
    iv: Block,
    key_gmac_base: Block,
}

impl GkCrypt {
    /// chiaki-ng `chiaki_gkcrypt_init`: key and IV are the two halves of
    /// HMAC-SHA256(ecdh_secret, 01 ‖ index ‖ 00 ‖ handshake_key ‖ 01 00).
    pub fn new(index: u8, handshake_key: &[u8; HANDSHAKE_KEY_SIZE], ecdh_secret: &[u8; SECRET_SIZE]) -> Self {
        let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(ecdh_secret)
            .expect("HMAC takes a key of any length");
        mac.update(&[1, index, 0]);
        mac.update(handshake_key);
        mac.update(&[1, 0]);
        let out = mac.finalize().into_bytes();
        let key_base: Block = std::array::from_fn(|i| out[i]);
        let iv: Block = std::array::from_fn(|i| out[i + BLOCK_SIZE]);
        let key_gmac_base = gen_gmac_key(0, &key_base, &iv);
        Self { index, key_base, iv, key_gmac_base }
    }

    /// Builds the state from its parts, for tests and for state carried over from elsewhere.
    pub fn from_parts(index: u8, key_base: Block, iv: Block, key_gmac_base: Block) -> Self {
        Self { index, key_base, iv, key_gmac_base }
    }

    pub fn index(&self) -> u8 {
        self.index
    }

    pub fn key_base(&self) -> &Block {
        &self.key_base
    }

    pub fn iv(&self) -> &Block {
        &self.iv
    }

    /// The counter-mode key stream for bytes `key_pos .. key_pos + len`, at any alignment.
    pub fn key_stream(&self, key_pos: u64, len: usize) -> Vec<u8> {
        let pad = (key_pos % BLOCK_SIZE as u64) as usize;
        let blocks = (pad + len).div_ceil(BLOCK_SIZE);
        let aes = <Aes128 as KeyInit>::new(&Array::from(self.key_base));
        let first = key_pos / BLOCK_SIZE as u64;
        let mut stream = Vec::with_capacity(blocks * BLOCK_SIZE);
        for n in 0..blocks as u64 {
            let mut block = Array::from(counter_add(&self.iv, first + n));
            aes.encrypt_block(&mut block);
            stream.extend_from_slice(&block);
        }
        stream[pad..pad + len].to_vec()
    }

    /// XOR with the key stream at `key_pos`. Encrypting and decrypting are the same operation.
    pub fn crypt(&self, key_pos: u64, data: &[u8]) -> Vec<u8> {
        self.key_stream(key_pos, data.len()).iter().zip(data).map(|(k, d)| k ^ d).collect()
    }

    /// The GMAC key in force at `key_pos`.
    fn gmac_key(&self, key_pos: u64) -> Block {
        let index = key_pos.saturating_sub(1) / GMAC_KEY_REFRESH_KEY_POS;
        if index == 0 { self.key_gmac_base } else { gen_gmac_key(index, &self.key_gmac_base, &self.iv) }
    }

    /// chiaki-ng `chiaki_gkcrypt_gmac`: AES-128-GCM with `data` as associated data, no plaintext, and the
    /// IV advanced to `key_pos`; the tag is cut to 4 bytes.
    pub fn gmac(&self, key_pos: u64, data: &[u8]) -> [u8; GMAC_SIZE] {
        let gcm = <Gcm16 as KeyInit>::new(&Array::from(self.gmac_key(key_pos)));
        let nonce = Array::from(counter_add(&self.iv, key_pos / BLOCK_SIZE as u64));
        let tag = gcm
            .encrypt_inout_detached(&nonce, data, (&mut [][..]).into())
            .expect("GCM accepts associated data far longer than any packet");
        std::array::from_fn(|i| tag[i])
    }
}

/// RFC 1982 serial number comparison for 32-bit values (chiaki-ng `seqnum.h`).
fn seq32_gt(a: u32, b: u32) -> bool {
    const HALF: u32 = 1 << 31;
    a != b && ((a < b && b - a > HALF) || (a > b && a - b < HALF))
}

fn seq32_lt(a: u32, b: u32) -> bool {
    const HALF: u32 = 1 << 31;
    a != b && ((a < b && b - a < HALF) || (a > b && a - b > HALF))
}

/// Widens the 32-bit key positions on the wire to 64 bits, tracking wrap-around (chiaki-ng `ChiakiKeyState`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KeyState {
    prev: u64,
}

impl KeyState {
    /// The 64-bit position that the wire's low 32 bits most likely mean, given the last authentic one.
    pub fn request_pos(&self, low: u32) -> u64 {
        let prev_low = self.prev as u32;
        let mut high = (self.prev >> 32) as u32;
        if seq32_gt(low, prev_low) && low < prev_low {
            high = high.wrapping_add(1);
        } else if seq32_lt(low, prev_low) && low > prev_low && high != 0 {
            high -= 1;
        }
        (u64::from(high) << 32) | u64::from(low)
    }

    /// The state after `pos` is known to be authentic. Only commit after the packet's GMAC checks out.
    pub fn commit(self, pos: u64) -> Self {
        Self { prev: pos }
    }
}
