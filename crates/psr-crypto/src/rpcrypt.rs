// SPDX-License-Identifier: AGPL-3.0-only
//! Registration and authentication encryption. Ported from chiaki-ng `lib/src/rpcrypt.c`
//! (LicenseRef-AGPL-3.0-only-OpenSSL); the OpenSSL exception is moot here because nothing links OpenSSL.
//!
//! The key names (`bright`, `ambassador`, `morning`, `aeropause`) are chiaki-ng's, kept so the two can be
//! read side by side.

use aes::Aes128;
use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::rpcrypt_tables as t;
use crate::{CryptoError, Target};

pub const KEY_SIZE: usize = 0x10;
pub type Key = [u8; KEY_SIZE];

/// The key tables are 0x20 columns wide; an offset selects a column.
const TABLE_STRIDE: usize = 0x20;
/// `bright_ambassador`'s tables are rows of 0x70 bytes, selected by the top five bits of a nonce byte.
const AMBASSADOR_ROW: usize = 0x70;

fn check_offset(off: usize) -> Result<(), CryptoError> {
    if off < TABLE_STRIDE { Ok(()) } else { Err(CryptoError::KeyOffset(off)) }
}

fn keyed(target: Target) -> Result<(), CryptoError> {
    if target.has_key_tables() { Ok(()) } else { Err(CryptoError::UnsupportedTarget(target)) }
}

/// Column `off` of a 16-row table: the bytes at `i * 0x20 + off`.
fn column(table: &[u8; 512], off: usize) -> Key {
    std::array::from_fn(|i| table[i * TABLE_STRIDE + off])
}

fn bright_ambassador_ps4_pre10(nonce: &Key, morning: &Key) -> (Key, Key) {
    let ambassador = std::array::from_fn(|i| {
        nonce[i].wrapping_sub(i as u8).wrapping_sub(0x27) ^ t::ECHO_A[i]
    });
    let bright = std::array::from_fn(|i| {
        morning[i].wrapping_sub(i as u8).wrapping_add(0x34) ^ t::ECHO_B[i] ^ nonce[i]
    });
    (bright, ambassador)
}

/// Derives `(bright, ambassador)` from the console's nonce and the client's `morning`.
pub fn bright_ambassador(target: Target, nonce: &Key, morning: &Key) -> Result<(Key, Key), CryptoError> {
    if target.is_ps4_pre10() {
        return Ok(bright_ambassador_ps4_pre10(nonce, morning));
    }
    keyed(target)?;
    let ps5 = target.is_ps5();
    let (keys_a, keys_b) = if ps5 {
        (t::BRIGHT_AMBASSADOR_KEYS_A_PS5, t::BRIGHT_AMBASSADOR_KEYS_B_PS5)
    } else {
        (t::BRIGHT_AMBASSADOR_KEYS_A_PS4, t::BRIGHT_AMBASSADOR_KEYS_B_PS4)
    };
    let key_a = &keys_a[usize::from(nonce[0] >> 3) * AMBASSADOR_ROW..];
    let ambassador = std::array::from_fn(|i| {
        let v = if ps5 {
            nonce[i].wrapping_sub(0x2d).wrapping_sub(i as u8)
        } else {
            nonce[i].wrapping_add(0x36).wrapping_add(i as u8)
        };
        v ^ key_a[i]
    });
    let key_b = &keys_b[usize::from(nonce[7] >> 3) * AMBASSADOR_ROW..];
    let bright = std::array::from_fn(|i| {
        if ps5 {
            morning[i].wrapping_add(0x18).wrapping_add(i as u8) ^ nonce[i] ^ key_b[i]
        } else {
            (key_b[i] ^ morning[i]).wrapping_add(0x21).wrapping_add(i as u8) ^ nonce[i]
        }
    });
    Ok((bright, ambassador))
}

pub fn aeropause_ps4_pre10(ambassador: &Key) -> Key {
    std::array::from_fn(|i| ambassador[i].wrapping_sub(i as u8).wrapping_sub(0x29) ^ t::ECHO_B[i])
}

fn keys_1(target: Target) -> &'static [u8; 512] {
    if target.is_ps5() { t::AEROPAUSE_PS5_KEYS_1 } else { t::AEROPAUSE_PS4_KEYS_1 }
}

pub fn aeropause(target: Target, key_1_off: usize, ambassador: &Key) -> Result<Key, CryptoError> {
    keyed(target)?;
    check_offset(key_1_off)?;
    let k = column(keys_1(target), key_1_off);
    let wurzelbert: u8 = if target.is_ps5() { 0u8.wrapping_sub(0x2d) } else { 0x29 };
    Ok(std::array::from_fn(|i| (ambassador[i] ^ k[i]).wrapping_add(wurzelbert).wrapping_add(i as u8)))
}

fn wurzelbert_psn(target: Target) -> u8 {
    if target.is_ps5() { 0x2b } else { 0u8.wrapping_sub(0x29) }
}

pub fn aeropause_psn(target: Target, key_1_off: usize, ambassador: &Key) -> Result<Key, CryptoError> {
    keyed(target)?;
    check_offset(key_1_off)?;
    let k = column(keys_1(target), key_1_off);
    let w = wurzelbert_psn(target);
    Ok(std::array::from_fn(|i| ambassador[i].wrapping_sub(i as u8).wrapping_add(w) ^ k[i]))
}

/// The inverse of [`aeropause_psn`].
pub fn ambassador_from_aeropause(target: Target, key_1_off: usize, aeropause: &Key) -> Result<Key, CryptoError> {
    keyed(target)?;
    check_offset(key_1_off)?;
    let k = column(keys_1(target), key_1_off);
    let w = wurzelbert_psn(target);
    Ok(std::array::from_fn(|i| (aeropause[i] ^ k[i]).wrapping_add(i as u8).wrapping_sub(w)))
}

/// A registration or authentication cipher: AES-128-CFB128 keyed by `bright`, with an IV derived from
/// `ambassador` and a message counter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpCrypt {
    target: Target,
    bright: Key,
    ambassador: Key,
}

impl RpCrypt {
    /// chiaki-ng `chiaki_rpcrypt_init_auth`.
    pub fn auth(target: Target, nonce: &Key, morning: &Key) -> Result<Self, CryptoError> {
        let (bright, ambassador) = bright_ambassador(target, nonce, morning)?;
        Ok(Self { target, bright, ambassador })
    }

    /// chiaki-ng `chiaki_rpcrypt_init_regist_ps4_pre10`. The target is a representative pre-10 PS4.
    pub fn regist_ps4_pre10(ambassador: &Key, pin: u32) -> Self {
        let mut bright = *t::INIT_REGIST_PS4_PRE10_REGIST_AES_KEY;
        for (b, p) in bright[..4].iter_mut().zip(pin.to_be_bytes()) {
            *b ^= p;
        }
        Self { target: Target::Ps4V9, bright, ambassador: *ambassador }
    }

    /// chiaki-ng `chiaki_rpcrypt_init_regist`: the cipher for registering with the console's PIN.
    pub fn regist(target: Target, ambassador: &Key, key_0_off: usize, pin: u32) -> Result<Self, CryptoError> {
        keyed(target)?;
        check_offset(key_0_off)?;
        let table = if target.is_ps5() { t::INIT_REGIST_PS5_KEYS_0 } else { t::INIT_REGIST_PS4_KEYS_0 };
        let mut bright = column(table, key_0_off);
        for (b, p) in bright[0xc..].iter_mut().zip(pin.to_be_bytes()) {
            *b ^= p;
        }
        Ok(Self { target, bright, ambassador: *ambassador })
    }

    /// chiaki-ng `chiaki_rpcrypt_init_regist_psn`: registration over PSN, where `custom_data1` is first
    /// encrypted with `data1` as the key and `data2` as the IV seed.
    pub fn regist_psn(
        target: Target,
        ambassador: &Key,
        key_0_off: usize,
        custom_data1: &Key,
        data1: &Key,
        data2: &Key,
    ) -> Result<Self, CryptoError> {
        let custom = Self { target, bright: *data1, ambassador: *data2 }.encrypt(0, custom_data1);
        keyed(target)?;
        check_offset(key_0_off)?;
        let table = if target.is_ps5() { t::INIT_REGIST_PS5_KEYS_0 } else { t::INIT_REGIST_PS4_KEYS_0 };
        let col = column(table, key_0_off);
        let bright = std::array::from_fn(|i| col[i] ^ custom[i]);
        Ok(Self { target, bright, ambassador: *ambassador })
    }

    pub fn target(&self) -> Target {
        self.target
    }

    pub fn bright(&self) -> &Key {
        &self.bright
    }

    pub fn ambassador(&self) -> &Key {
        &self.ambassador
    }

    fn hmac_key(&self) -> &'static Key {
        match self.target {
            Target::Ps5V1 => t::HMAC_KEY_PS5,
            Target::Ps4V8 | Target::Ps4V9 => t::HMAC_KEY_PS4_PRE10,
            _ => t::HMAC_KEY_PS4,
        }
    }

    /// The first 16 bytes of HMAC-SHA256(key, ambassador ‖ counter as big-endian u64).
    pub fn iv(&self, counter: u64) -> Key {
        let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(self.hmac_key())
            .expect("HMAC takes a key of any length");
        mac.update(&self.ambassador);
        mac.update(&counter.to_be_bytes());
        let tag = mac.finalize().into_bytes();
        std::array::from_fn(|i| tag[i])
    }

    pub fn encrypt(&self, counter: u64, plain: &[u8]) -> Vec<u8> {
        self.cfb128(counter, plain, true)
    }

    pub fn decrypt(&self, counter: u64, cipher: &[u8]) -> Vec<u8> {
        self.cfb128(counter, cipher, false)
    }

    /// AES-128-CFB128 with no padding: each 16-byte segment is XORed with AES(feedback), and the feedback
    /// becomes that segment's ciphertext. A short last segment uses only part of the keystream.
    fn cfb128(&self, counter: u64, input: &[u8], encrypt: bool) -> Vec<u8> {
        let aes = <Aes128 as KeyInit>::new(&Array::from(self.bright));
        let mut feedback = self.iv(counter);
        let mut out = Vec::with_capacity(input.len());
        for segment in input.chunks(KEY_SIZE) {
            let mut block = Array::from(feedback);
            aes.encrypt_block(&mut block);
            let produced: Vec<u8> = segment.iter().zip(block.iter()).map(|(x, k)| x ^ k).collect();
            let cipher_seg = if encrypt { &produced[..] } else { segment };
            feedback[..cipher_seg.len()].copy_from_slice(cipher_seg);
            out.extend_from_slice(&produced);
        }
        out
    }
}
