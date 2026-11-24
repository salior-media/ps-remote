// SPDX-License-Identifier: AGPL-3.0-only
//! Keeping the PSN refresh token at rest (`docs/PSN.md`): encrypted with DPAPI for this Windows user, and in
//! an owner-only file. On other systems the file is owner-only (0600) but not encrypted.

use std::path::{Path, PathBuf};

use crate::PsnError;

/// The file in the configuration folder, beside `consoles`.
pub const REFRESH_TOKEN_FILE: &str = "psn-refresh-token";

#[cfg(windows)]
mod dpapi {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    };

    /// Binds the sealed token to ps-remote: another program running as the same user has to know it too.
    /// This is hardening, not a boundary: it is in this public source.
    const ENTROPY: &[u8] = b"ps-remote psn-refresh-token v1";

    /// `None` for data too large for DPAPI's 32-bit length.
    fn blob(data: &[u8]) -> Option<CRYPT_INTEGER_BLOB> {
        Some(CRYPT_INTEGER_BLOB { cbData: u32::try_from(data.len()).ok()?, pbData: data.as_ptr().cast_mut() })
    }

    /// Copies the output blob and frees it with `LocalFree`, as DPAPI requires.
    ///
    /// # Safety
    /// `out` must be a blob DPAPI filled in.
    unsafe fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        if out.pbData.is_null() {
            return Vec::new();
        }
        // SAFETY: DPAPI set pbData, not null, to cbData readable bytes it allocated with LocalAlloc.
        let v = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
        // SAFETY: pbData came from LocalAlloc and is freed once.
        unsafe { LocalFree(out.pbData.cast()) };
        v
    }

    pub fn protect(data: &[u8]) -> Option<Vec<u8>> {
        let input = blob(data)?;
        let entropy = blob(ENTROPY)?;
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        // SAFETY: input and entropy point at live slices for the call; out is written by the call on success.
        let ok = unsafe {
            CryptProtectData(
                &input,
                std::ptr::null(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        // SAFETY: on success `out` is DPAPI's.
        (ok != 0).then(|| unsafe { take(out) })
    }

    /// With `with_entropy` false, opens a token sealed before ps-remote added its entropy.
    pub fn unprotect(data: &[u8], with_entropy: bool) -> Option<Vec<u8>> {
        let input = blob(data)?;
        let entropy = blob(ENTROPY)?;
        let entropy_ptr: *const CRYPT_INTEGER_BLOB = if with_entropy { &entropy } else { std::ptr::null() };
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        // SAFETY: as in `protect`.
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                entropy_ptr,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        // SAFETY: on success `out` is DPAPI's.
        (ok != 0).then(|| unsafe { take(out) })
    }
}

/// The bytes as kept at rest: DPAPI-encrypted on Windows, unchanged elsewhere.
pub fn seal(plain: &[u8]) -> Result<Vec<u8>, PsnError> {
    #[cfg(windows)]
    return dpapi::protect(plain).ok_or(PsnError::Seal);
    #[cfg(not(windows))]
    Ok(plain.to_vec())
}

/// The reverse of [`seal`]. On Windows it fails for another user or machine, or for altered bytes.
pub fn open(sealed: &[u8]) -> Result<Vec<u8>, PsnError> {
    // A token sealed before the entropy was added (the first sign-ins, 2026-11-25) opens without it; it is
    // sealed with it at the next save.
    #[cfg(windows)]
    return dpapi::unprotect(sealed, true).or_else(|| dpapi::unprotect(sealed, false)).ok_or(PsnError::Seal);
    #[cfg(not(windows))]
    Ok(sealed.to_vec())
}

fn path(config_dir: &Path) -> PathBuf {
    config_dir.join(REFRESH_TOKEN_FILE)
}

/// Saves the refresh token, sealed, in an owner-only file.
pub fn save_refresh_token(config_dir: &Path, token: &str) -> Result<(), PsnError> {
    psr_lan::store::create_private_dir(config_dir).map_err(PsnError::Io)?;
    psr_lan::store::write_private(&path(config_dir), &seal(token.as_bytes())?).map_err(PsnError::Io)
}

/// The saved refresh token, or `None` when nobody has signed in.
pub fn load_refresh_token(config_dir: &Path) -> Result<Option<String>, PsnError> {
    let sealed = match std::fs::read(path(config_dir)) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(PsnError::Io(e)),
    };
    let plain = open(&sealed)?;
    String::from_utf8(plain).map(Some).map_err(|_| PsnError::Seal)
}

/// Forgets the sign-in on this machine. It does not revoke it at Sony: that is done in the PSN account's
/// own settings.
pub fn forget(config_dir: &Path) -> Result<(), PsnError> {
    match std::fs::remove_file(path(config_dir)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(PsnError::Io(e)),
    }
}
