// SPDX-License-Identifier: AGPL-3.0-only
//! The account's consoles. Ported from chiaki-ng `chiaki_holepunch_list_devices` in
//! `lib/src/remote/holepunch.c` (LicenseRef-AGPL-3.0-only-OpenSSL).

use crate::PsnError;

/// chiaki-ng `device_list_url_fmt`, for PS5s (chiaki-ng lists only those).
pub const DEVICE_LIST_URL: &str = "https://web.np.playstation.com/api/cloudAssistedNavigation/v2/users/me/clients?platform=PS5&includeFields=device&limit=10&offset=0";
/// chiaki-ng `ChiakiHolepunchDeviceInfo.device_uid`'s size.
pub const DUID_SIZE: usize = 32;

/// One console on the account (chiaki-ng `ChiakiHolepunchDeviceInfo`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// The device's unique ID, which the holepunch addresses it by.
    pub duid: Vec<u8>,
    pub name: String,
    /// `remotePlay` is among its enabled features.
    pub remote_play: bool,
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || s.len() / 2 > DUID_SIZE {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

/// The reply's `clients`, checked field by field as chiaki-ng checks them: a client missing its `duid`,
/// `device`, `enabledFeatures` or `name` makes the whole reply an error.
pub fn parse_devices(json: &serde_json::Value) -> Result<Vec<Device>, PsnError> {
    let clients = json["clients"].as_array().ok_or(PsnError::MissingField("clients"))?;
    clients
        .iter()
        .map(|c| {
            let duid = c["duid"].as_str().ok_or(PsnError::MissingField("duid"))?;
            let duid = unhex(duid).ok_or(PsnError::BadField("duid"))?;
            let device = c["device"].as_object().ok_or(PsnError::MissingField("device"))?;
            let features = device
                .get("enabledFeatures")
                .and_then(|f| f.as_array())
                .ok_or(PsnError::MissingField("enabledFeatures"))?;
            let name = device.get("name").and_then(|n| n.as_str()).ok_or(PsnError::MissingField("name"))?;
            Ok(Device {
                duid,
                name: name.to_string(),
                remote_play: features.iter().any(|f| f.as_str() == Some("remotePlay")),
            })
        })
        .collect()
}

/// The account's PS5s, with an access token.
pub fn list(access_token: &str) -> Result<Vec<Device>, PsnError> {
    let sent = crate::agent()
        .get(DEVICE_LIST_URL)
        // chiaki-ng sends this language; the reply's fields are the same in any.
        .header("Accept-Language", "jp")
        .header("Authorization", format!("Bearer {access_token}"))
        .call();
    parse_devices(&crate::reply("console list", sent)?)
}
