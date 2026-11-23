// SPDX-License-Identifier: AGPL-3.0-only
// Ported from chiaki-ng `test/gkcrypt.c` and `test/keystate.c` (LicenseRef-AGPL-3.0-only-OpenSSL).
// The byte arrays are generated from chiaki-ng's file into vectors/gkcrypt_vectors.rs.

#![allow(dead_code)]

#[path = "vectors/gkcrypt_vectors.rs"]
mod v;

use psr_crypto::ecdh::{Ecdh, EcdhError};
use psr_crypto::gkcrypt::{GkCrypt, KeyState, gen_gmac_key};

const KEY_POS_HIGH: u64 = (1 << 32) + 0x420;

#[test]
fn ecdh() {
    let ecdh = Ecdh::from_keys(v::TEST_ECDH_LOCAL_PRIVATE_KEY, v::TEST_ECDH_LOCAL_PUBLIC_KEY).unwrap();
    let (public, sig) = ecdh.signed_public_key(v::TEST_ECDH_HANDSHAKE_KEY);
    assert_eq!(&public, v::TEST_ECDH_LOCAL_PUBLIC_KEY);
    assert_eq!(&sig, v::TEST_ECDH_LOCAL_PUBLIC_KEY_SIG);
    let secret = ecdh
        .derive_secret(v::TEST_ECDH_REMOTE_PUBLIC_KEY, v::TEST_ECDH_HANDSHAKE_KEY, v::TEST_ECDH_REMOTE_PUBLIC_KEY_SIG)
        .unwrap();
    assert_eq!(&secret, v::TEST_ECDH_SECRET);
}

#[test]
fn key_stream() {
    let g = GkCrypt::new(42, v::TEST_KEY_STREAM_HANDSHAKE_KEY, v::TEST_KEY_STREAM_ECDH_SECRET);
    assert_eq!(g.key_base(), v::TEST_KEY_STREAM_GKCRYPT_KEY);
    assert_eq!(g.iv(), v::TEST_KEY_STREAM_GKCRYPT_IV);
    assert_eq!(g.key_stream(0x30, 0x20), v::TEST_KEY_STREAM_KEY_STREAM);
    assert_eq!(g.key_stream(KEY_POS_HIGH, 0x20), v::TEST_KEY_STREAM_KEY_STREAM_HIGH);
}

#[test]
fn en_decrypt() {
    let g = GkCrypt::new(42, v::TEST_ENDECRYPT_HANDSHAKE_KEY, v::TEST_ENDECRYPT_ECDH_SECRET);
    assert_eq!(g.key_base(), v::TEST_ENDECRYPT_GKCRYPT_KEY);
    assert_eq!(g.iv(), v::TEST_ENDECRYPT_GKCRYPT_IV);
    // chiaki-ng's buffer is 0x25 bytes; encryption and decryption are the same XOR.
    let clear = &v::TEST_ENDECRYPT_CLEAR_DATA[..0x25];
    assert_eq!(g.crypt(0x11, clear), v::TEST_ENDECRYPT_ENC_DATA);
    assert_eq!(g.crypt(KEY_POS_HIGH, clear), v::TEST_ENDECRYPT_ENC_DATA_HIGH);
    assert_eq!(g.crypt(0x11, v::TEST_ENDECRYPT_ENC_DATA), clear);
}

/// chiaki-ng's GMAC tests zero the whole state and then set only the *current* GMAC key and the IV, so:
/// - at a low position (index 0) the tag uses that key;
/// - at the high position (index > 0) it derives from the zeroed *base* key.
///
/// `from_parts` reproduces each of those two states exactly.
fn gmac_states(key: &[u8; 16], iv: &[u8; 16]) -> (GkCrypt, GkCrypt) {
    (GkCrypt::from_parts(0, [0; 16], *iv, *key), GkCrypt::from_parts(0, [0; 16], *iv, [0; 16]))
}

#[test]
fn gmac() {
    let (low, high) = gmac_states(v::TEST_GMAC_GKCRYPT_KEY, v::TEST_GMAC_GKCRYPT_IV);
    assert_eq!(&low.gmac(0x69a0, v::TEST_GMAC_BUF), v::TEST_GMAC_GMAC_EXPECTED);
    assert_eq!(&high.gmac(KEY_POS_HIGH, v::TEST_GMAC_BUF), v::TEST_GMAC_GMAC_EXPECTED_HIGH);
}

#[test]
fn gen_gmac_key_index_1() {
    assert_eq!(
        &gen_gmac_key(1, v::TEST_GEN_GMAC_KEY_KEY_INITIAL, v::TEST_GEN_GMAC_KEY_IV),
        v::TEST_GEN_GMAC_KEY_KEY_RESULT
    );
}

#[test]
fn gmac_split() {
    let (low, high) = gmac_states(v::TEST_GMAC_SPLIT_GKCRYPT_KEY, v::TEST_GMAC_SPLIT_GKCRYPT_IV);
    assert_eq!(&low.gmac(0xadf0, v::TEST_GMAC_SPLIT_BUF), v::TEST_GMAC_SPLIT_GMAC_EXPECTED);
    assert_eq!(&high.gmac(KEY_POS_HIGH, v::TEST_GMAC_SPLIT_BUF), v::TEST_GMAC_SPLIT_GMAC_EXPECTED_HIGH);
}

#[test]
fn gmac_multiple_of_key_refresh() {
    let g = GkCrypt::new(3, v::TEST_GMAC_MULTIPLE_OF_KEY_REFRESH_HANDSHAKE_KEY, v::TEST_GMAC_MULTIPLE_OF_KEY_REFRESH_ECDH_SECRET);
    // 0x6b1de0 is a multiple of 45000, the edge where the GMAC key changes.
    assert_eq!(&g.gmac(0x6b1de0, v::TEST_GMAC_MULTIPLE_OF_KEY_REFRESH_DATA), v::TEST_GMAC_MULTIPLE_OF_KEY_REFRESH_GMAC_EXPECTED);
}

#[test]
fn key_state_with_commit() {
    let steps: [(u32, u64); 8] = [
        (0, 0),
        (0x1337, 0x1337),
        (0xffff0000, 0xffff0000),
        (0x1337, 0x1_0000_1337),
        (0xffff1337, 0xffff1337),
        (0x50000000, 0x1_5000_0000),
        (0xb0000000, 0x1_b000_0000),
        (0x00000000, 0x2_0000_0000),
    ];
    let mut state = KeyState::default();
    for (low, want) in steps {
        let pos = state.request_pos(low);
        assert_eq!(pos, want, "low {low:#x}");
        state = state.commit(pos);
    }
}

#[test]
fn key_state_without_commit() {
    let state = KeyState::default();
    for (low, want) in [
        (0, 0),
        (0x1337, 0x1337),
        (0xffff0000, 0xffff0000),
        (0x1337, 0x1337),
        (0xffff1337, 0xffff1337),
        (0x50000000, 0x50000000),
        (0xb0000000, 0xb0000000),
        (0x00000000, 0),
    ] {
        assert_eq!(state.request_pos(low), want, "low {low:#x}");
    }
}

// Not in chiaki-ng.

#[test]
fn a_wrong_console_signature_is_refused() {
    let ecdh = Ecdh::from_keys(v::TEST_ECDH_LOCAL_PRIVATE_KEY, v::TEST_ECDH_LOCAL_PUBLIC_KEY).unwrap();
    let mut sig = *v::TEST_ECDH_REMOTE_PUBLIC_KEY_SIG;
    sig[0] ^= 1;
    assert_eq!(
        ecdh.derive_secret(v::TEST_ECDH_REMOTE_PUBLIC_KEY, v::TEST_ECDH_HANDSHAKE_KEY, &sig),
        Err(EcdhError::RemoteSignature)
    );
}

#[test]
fn a_public_key_that_is_not_ours_is_refused() {
    assert_eq!(
        Ecdh::from_keys(v::TEST_ECDH_LOCAL_PRIVATE_KEY, v::TEST_ECDH_REMOTE_PUBLIC_KEY).unwrap_err(),
        EcdhError::KeyMismatch
    );
}

#[test]
fn two_generated_keys_agree_on_one_secret() {
    let hk = [7u8; 16];
    let (a, b) = (Ecdh::generate().unwrap(), Ecdh::generate().unwrap());
    let (pa, sa) = a.signed_public_key(&hk);
    let (pb, sb) = b.signed_public_key(&hk);
    assert_eq!(a.derive_secret(&pb, &hk, &sb).unwrap(), b.derive_secret(&pa, &hk, &sa).unwrap());
}

#[test]
fn crypt_at_any_alignment_matches_the_aligned_stream() {
    let g = GkCrypt::new(42, v::TEST_KEY_STREAM_HANDSHAKE_KEY, v::TEST_KEY_STREAM_ECDH_SECRET);
    let whole = g.key_stream(0x30, 0x40);
    for start in 0..0x20 {
        for len in [0, 1, 15, 16, 17, 0x1f] {
            assert_eq!(g.key_stream(0x30 + start, len), &whole[start as usize..start as usize + len]);
        }
    }
}
