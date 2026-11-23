// SPDX-License-Identifier: AGPL-3.0-only
//! Session key exchange: ECDH on secp256k1, with each public key signed by HMAC-SHA256 under the
//! handshake key. Ported from chiaki-ng `lib/src/ecdh.c` (LicenseRef-AGPL-3.0-only-OpenSSL).
//!
//! **One deliberate difference:** chiaki-ng's `chiaki_ecdh_derive_secret` takes the console's signature and
//! never checks it. [`Ecdh::derive_secret`] checks it in constant time and refuses a key that doesn't match.
//! chiaki-ng's own test vector carries a correct signature, so real consoles send one.

use hmac::{Hmac, Mac};
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::{PublicKey, SecretKey};
use sha2::Sha256;

use crate::gkcrypt::HANDSHAKE_KEY_SIZE;

pub const SECRET_SIZE: usize = 32;
/// An uncompressed SEC1 point: 0x04 ‖ x ‖ y.
pub const PUBLIC_KEY_SIZE: usize = 65;
pub const SIGNATURE_SIZE: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EcdhError {
    #[error("the system random number generator failed: {0}")]
    Random(String),
    #[error("the private key is not a valid secp256k1 scalar")]
    PrivateKey,
    #[error("the public key given does not belong to the private key")]
    KeyMismatch,
    #[error("the console's public key is not a valid secp256k1 point")]
    RemoteKey,
    #[error("the console's public key signature does not match the handshake key")]
    RemoteSignature,
}

fn sign(handshake_key: &[u8; HANDSHAKE_KEY_SIZE]) -> Hmac<Sha256> {
    <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(handshake_key).expect("HMAC takes a key of any length")
}

/// Our side of one session's key exchange.
pub struct Ecdh {
    secret: SecretKey,
}

impl std::fmt::Debug for Ecdh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ecdh { secret: <redacted> }")
    }
}

impl Ecdh {
    /// A fresh key pair from the operating system's random number generator.
    pub fn generate() -> Result<Self, EcdhError> {
        loop {
            let mut bytes = [0u8; SECRET_SIZE];
            getrandom::fill(&mut bytes).map_err(|e| EcdhError::Random(e.to_string()))?;
            // A 32-byte value is out of range (zero, or at least the group order) with probability
            // about 2^-128; draw again in that case.
            if let Ok(secret) = SecretKey::from_slice(&bytes) {
                return Ok(Self { secret });
            }
        }
    }

    /// chiaki-ng `chiaki_ecdh_set_local_key`. Unlike chiaki-ng, the public key is checked against the
    /// private key instead of being trusted.
    pub fn from_keys(private_key: &[u8], public_key: &[u8]) -> Result<Self, EcdhError> {
        let secret = SecretKey::from_slice(private_key).map_err(|_| EcdhError::PrivateKey)?;
        let me = Self { secret };
        if me.public_key()[..] != *public_key {
            return Err(EcdhError::KeyMismatch);
        }
        Ok(me)
    }

    /// Our public key, uncompressed.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_SIZE] {
        let point = self.secret.public_key().to_sec1_point(false);
        point.as_bytes().try_into().expect("an uncompressed secp256k1 point is 65 bytes")
    }

    /// chiaki-ng `chiaki_ecdh_get_local_pub_key`: our public key and its HMAC-SHA256 under the handshake key.
    pub fn signed_public_key(
        &self,
        handshake_key: &[u8; HANDSHAKE_KEY_SIZE],
    ) -> ([u8; PUBLIC_KEY_SIZE], [u8; SIGNATURE_SIZE]) {
        let key = self.public_key();
        let mut mac = sign(handshake_key);
        mac.update(&key);
        (key, mac.finalize().into_bytes().into())
    }

    /// The shared secret: the x coordinate of our scalar times the console's point. The console's
    /// signature is checked first, in constant time.
    pub fn derive_secret(
        &self,
        remote_key: &[u8],
        handshake_key: &[u8; HANDSHAKE_KEY_SIZE],
        remote_sig: &[u8],
    ) -> Result<[u8; SECRET_SIZE], EcdhError> {
        let mut mac = sign(handshake_key);
        mac.update(remote_key);
        mac.verify_slice(remote_sig).map_err(|_| EcdhError::RemoteSignature)?;
        let remote = PublicKey::from_sec1_bytes(remote_key).map_err(|_| EcdhError::RemoteKey)?;
        let shared = k256::ecdh::diffie_hellman(self.secret.to_nonzero_scalar(), remote.as_affine());
        Ok((*shared.raw_secret_bytes()).into())
    }
}
