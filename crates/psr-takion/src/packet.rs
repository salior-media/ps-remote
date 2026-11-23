// SPDX-License-Identifier: AGPL-3.0-only
//! Takion datagram types, their MACs, and the congestion packet. Ported from chiaki-ng `lib/src/takion.c`
//! (LicenseRef-AGPL-3.0-only-OpenSSL).

use psr_crypto::gkcrypt::{GMAC_SIZE, GkCrypt, KeyState};
use subtle::ConstantTimeEq;

use crate::TakionError;

/// The lower nibble of a datagram's first byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Control,
    FeedbackHistory,
    Video,
    Audio,
    Handshake,
    Congestion,
    FeedbackState,
    ClientInfo,
}

impl PacketType {
    pub fn of(datagram: &[u8]) -> Result<Self, TakionError> {
        let first = *datagram.first().ok_or(TakionError::TooShort { need: 1, got: 0 })?;
        Ok(match first & 0xf {
            0 => Self::Control,
            1 => Self::FeedbackHistory,
            2 => Self::Video,
            3 => Self::Audio,
            4 => Self::Handshake,
            5 => Self::Congestion,
            6 => Self::FeedbackState,
            8 => Self::ClientInfo,
            other => return Err(TakionError::UnknownType(other)),
        })
    }

    pub const fn code(self) -> u8 {
        match self {
            Self::Control => 0,
            Self::FeedbackHistory => 1,
            Self::Video => 2,
            Self::Audio => 3,
            Self::Handshake => 4,
            Self::Congestion => 5,
            Self::FeedbackState => 6,
            Self::ClientInfo => 8,
        }
    }

    /// Where the 4-byte MAC sits, for the types that carry one.
    pub const fn mac_offset(self) -> Option<usize> {
        match self {
            Self::Control => Some(5),
            Self::Video | Self::Audio => Some(0xa),
            Self::Congestion => Some(7),
            _ => None,
        }
    }

    /// Where the low 32 bits of the key position sit, big-endian.
    pub const fn key_pos_offset(self) -> Option<usize> {
        match self {
            Self::Control => Some(9),
            Self::Video | Self::Audio => Some(0xe),
            Self::Congestion => Some(0xb),
            _ => None,
        }
    }

    /// For these types the key position itself is zeroed while the MAC is computed.
    const fn mac_hides_key_pos(self) -> bool {
        matches!(self, Self::Control | Self::Congestion)
    }
}

fn offsets(datagram: &[u8]) -> Result<(PacketType, usize, usize), TakionError> {
    let ty = PacketType::of(datagram)?;
    let (mac, key) = ty.mac_offset().zip(ty.key_pos_offset()).ok_or(TakionError::NoMac(ty))?;
    let need = (mac + GMAC_SIZE).max(key + 4);
    if datagram.len() < need {
        return Err(TakionError::TooShort { need, got: datagram.len() });
    }
    Ok((ty, mac, key))
}

/// The low 32 bits of the key position in a datagram.
pub fn key_pos_low(datagram: &[u8]) -> Result<u32, TakionError> {
    let (_, _, key) = offsets(datagram)?;
    Ok(u32::from_be_bytes(datagram[key..key + 4].try_into().expect("4 bytes")))
}

/// chiaki-ng `chiaki_takion_packet_mac`: the GMAC over the datagram with its MAC field zeroed, and for
/// control and congestion packets its key position field zeroed too.
pub fn mac(crypt: &GkCrypt, datagram: &[u8], key_pos: u64) -> Result<[u8; GMAC_SIZE], TakionError> {
    let (ty, mac_at, key_at) = offsets(datagram)?;
    let mut copy = datagram.to_vec();
    copy[mac_at..mac_at + GMAC_SIZE].fill(0);
    if ty.mac_hides_key_pos() {
        copy[key_at..key_at + 4].fill(0);
    }
    Ok(crypt.gmac(key_pos, &copy))
}

/// The datagram with its MAC field filled in, ready to send.
pub fn sign(crypt: &GkCrypt, datagram: &[u8], key_pos: u64) -> Result<Vec<u8>, TakionError> {
    let tag = mac(crypt, datagram, key_pos)?;
    let (_, mac_at, _) = offsets(datagram)?;
    let mut out = datagram.to_vec();
    out[mac_at..mac_at + GMAC_SIZE].copy_from_slice(&tag);
    Ok(out)
}

/// chiaki-ng `takion_handle_packet_mac`: checks a received datagram's MAC in constant time against the
/// key position its low bits most likely mean. On success returns that position and the key state to
/// keep; the state only moves forward for an authentic packet.
pub fn verify(crypt: &GkCrypt, datagram: &[u8], state: KeyState) -> Result<(u64, KeyState), TakionError> {
    let key_pos = state.request_pos(key_pos_low(datagram)?);
    let expected = mac(crypt, datagram, key_pos)?;
    let (_, mac_at, _) = offsets(datagram)?;
    if bool::from(expected.ct_eq(&datagram[mac_at..mac_at + GMAC_SIZE])) {
        Ok((key_pos, state.commit(key_pos)))
    } else {
        Err(TakionError::BadMac { key_pos })
    }
}

pub const CONGESTION_PACKET_SIZE: usize = 0xf;

/// A congestion report the client sends back (chiaki-ng `ChiakiTakionCongestionPacket`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Congestion {
    pub word_0: u16,
    pub received: u16,
    pub lost: u16,
}

impl Congestion {
    /// chiaki-ng `chiaki_takion_format_congestion`, before the MAC is filled in.
    pub fn format(&self, key_pos: u64) -> [u8; CONGESTION_PACKET_SIZE] {
        let mut buf = [0u8; CONGESTION_PACKET_SIZE];
        buf[0] = PacketType::Congestion.code();
        buf[1..3].copy_from_slice(&self.word_0.to_be_bytes());
        buf[3..5].copy_from_slice(&self.received.to_be_bytes());
        buf[5..7].copy_from_slice(&self.lost.to_be_bytes());
        buf[0xb..0xf].copy_from_slice(&(key_pos as u32).to_be_bytes());
        buf
    }
}
