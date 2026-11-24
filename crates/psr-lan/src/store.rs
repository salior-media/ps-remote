// SPDX-License-Identifier: AGPL-3.0-only
//! Keeping registered consoles on this device. One small text file per console, named by its MAC, in the
//! user's own configuration folder: `%APPDATA%\ps-remote\consoles` on Windows,
//! `$XDG_CONFIG_HOME/ps-remote/consoles` (or `~/.config/...`) elsewhere. The files hold the console's
//! registration key and RP key, so they never go in a repository or a log.

use std::path::{Path, PathBuf};

use psr_crypto::Target;

use crate::LanError;
use crate::regist::RegisteredHost;

pub fn default_dir() -> Option<PathBuf> {
    let base = if cfg!(windows) {
        std::env::var_os("APPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
    };
    base.map(|b| b.join("ps-remote").join("consoles"))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn target_name(t: Target) -> &'static str {
    match t {
        Target::Ps4Unknown => "ps4-unknown",
        Target::Ps4V8 => "ps4-8",
        Target::Ps4V9 => "ps4-9",
        Target::Ps4V10 => "ps4-10",
        Target::Ps5Unknown => "ps5-unknown",
        Target::Ps5V1 => "ps5-1",
    }
}

fn parse_target(s: &str) -> Option<Target> {
    [Target::Ps4Unknown, Target::Ps4V8, Target::Ps4V9, Target::Ps4V10, Target::Ps5Unknown, Target::Ps5V1]
        .into_iter()
        .find(|t| target_name(*t) == s)
}

/// `key=value` lines. Strings that came from the console are kept only if they have no line break.
pub fn to_text(h: &RegisteredHost) -> String {
    let mut lines = vec![
        "format=ps-remote-console-1".to_string(),
        format!("target={}", target_name(h.target)),
        format!("server_mac={}", hex(&h.server_mac)),
        format!("rp_regist_key={}", hex(&h.rp_regist_key)),
        format!("rp_key_type={}", h.rp_key_type),
        format!("rp_key={}", hex(&h.rp_key)),
    ];
    for (k, v) in [
        ("server_nickname", &h.server_nickname),
        ("ap_ssid", &h.ap_ssid),
        ("ap_bssid", &h.ap_bssid),
        ("ap_key", &h.ap_key),
        ("ap_name", &h.ap_name),
    ] {
        if let Some(v) = v.as_deref().filter(|v| !v.contains(['\n', '\r'])) {
            lines.push(format!("{k}={v}"));
        }
    }
    lines.join("\n") + "\n"
}

pub fn from_text(text: &str) -> Result<RegisteredHost, LanError> {
    let get = |k: &str| text.lines().find_map(|l| l.strip_prefix(k).and_then(|r| r.strip_prefix('=')));
    if get("format") != Some("ps-remote-console-1") {
        return Err(LanError::BadStore("unknown format"));
    }
    let need = |k: &'static str| get(k).ok_or(LanError::BadStore(k));
    Ok(RegisteredHost {
        target: parse_target(need("target")?).ok_or(LanError::BadStore("target"))?,
        server_mac: unhex(need("server_mac")?).ok_or(LanError::BadStore("server_mac"))?,
        rp_regist_key: unhex(need("rp_regist_key")?).ok_or(LanError::BadStore("rp_regist_key"))?,
        rp_key_type: need("rp_key_type")?.parse().map_err(|_| LanError::BadStore("rp_key_type"))?,
        rp_key: unhex(need("rp_key")?).ok_or(LanError::BadStore("rp_key"))?,
        server_nickname: get("server_nickname").map(str::to_string),
        ap_ssid: get("ap_ssid").map(str::to_string),
        ap_bssid: get("ap_bssid").map(str::to_string),
        ap_key: get("ap_key").map(str::to_string),
        ap_name: get("ap_name").map(str::to_string),
    })
}

/// Saves the console as `<mac>.txt` in `dir`, creating the folder. Returns the file's path.
pub fn save(dir: &Path, h: &RegisteredHost) -> Result<PathBuf, LanError> {
    std::fs::create_dir_all(dir).map_err(LanError::Io)?;
    let path = dir.join(format!("{}.txt", hex(&h.server_mac)));
    std::fs::write(&path, to_text(h)).map_err(LanError::Io)?;
    Ok(path)
}

/// Every console saved in `dir`. A file that doesn't parse is an error, not silently skipped.
pub fn load_all(dir: &Path) -> Result<Vec<RegisteredHost>, LanError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(LanError::Io(e)),
    };
    let mut hosts = Vec::new();
    for entry in entries {
        let path = entry.map_err(LanError::Io)?.path();
        if path.extension().is_some_and(|e| e == "txt") {
            hosts.push(from_text(&std::fs::read_to_string(&path).map_err(LanError::Io)?)?);
        }
    }
    Ok(hosts)
}
