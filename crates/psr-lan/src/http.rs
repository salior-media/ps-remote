// SPDX-License-Identifier: AGPL-3.0-only
//! The small HTTP dialect the console speaks, for discovery replies and (later) registration. Ported from
//! chiaki-ng `lib/src/http.c` (LicenseRef-AGPL-3.0-only-OpenSSL).

use crate::LanError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub code: u16,
    /// Headers in the order they arrived. chiaki-ng keeps them as a linked list built backwards.
    pub headers: Vec<(String, String)>,
}

impl Response {
    pub fn header(&self, key: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }
}

/// chiaki-ng `chiaki_http_response_parse`: `HTTP/1.1 <code> ...` then `Key: value` lines ending in `\n`
/// or `\r\n`, stopping at a blank line or a NUL byte. One space after the colon is optional.
pub fn parse_response(buf: &[u8]) -> Result<Response, LanError> {
    const VERSION: &[u8] = b"HTTP/1.1 ";
    let rest = buf.strip_prefix(VERSION).ok_or(LanError::NotHttp)?;
    let line_end = rest.iter().position(|&b| b == b'\n').ok_or(LanError::NotHttp)?;
    // chiaki-ng also refuses a status line with nothing after it.
    if rest.len() <= line_end + 1 {
        return Err(LanError::NotHttp);
    }
    let status = std::str::from_utf8(&rest[..line_end]).map_err(|_| LanError::NotHttp)?.trim_end_matches('\r');
    let code =
        status.split(' ').next().and_then(|c| c.parse::<u16>().ok()).filter(|&c| c != 0).ok_or(LanError::NotHttp)?;
    Ok(Response { code, headers: parse_headers(&rest[line_end + 1..])? })
}

/// chiaki-ng `chiaki_http_header_parse`.
pub fn parse_headers(buf: &[u8]) -> Result<Vec<(String, String)>, LanError> {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let text = std::str::from_utf8(&buf[..end]).map_err(|_| LanError::BadHeader("text that is not UTF-8".into()))?;
    let mut headers = Vec::new();
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let (key, value) = line.split_once(':').ok_or_else(|| LanError::BadHeader("a line with no colon".into()))?;
        let value = value.strip_prefix(' ').unwrap_or(value);
        if key.is_empty() || value.is_empty() {
            return Err(LanError::BadHeader(name_only(key)));
        }
        headers.push((key.to_string(), value.to_string()));
    }
    // A final line with no line ending is incomplete; chiaki-ng drops it too.
    if !text.is_empty() && !text.ends_with('\n') {
        headers.pop();
    }
    Ok(headers)
}

/// What a malformed header may say about itself: its name, cut short and printable, never its value or the
/// text around it. A registration body holds the console's keys, and an error message can reach a log.
pub fn name_only(key: &str) -> String {
    const NAME_MAX: usize = 40;
    let name: String = key.chars().filter(|c| c.is_ascii_graphic()).take(NAME_MAX).collect();
    if name.is_empty() { "a header with no name".into() } else { format!("the {name} header") }
}

/// Where a response's header ends (after `\r\n\r\n`), if it has arrived yet.
pub fn header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}
