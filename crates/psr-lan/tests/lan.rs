// SPDX-License-Identifier: AGPL-3.0-only
// `response_parse` is ported from chiaki-ng `test/http.c` (LicenseRef-AGPL-3.0-only-OpenSSL). chiaki-ng
// has no discovery test; those here are written from `lib/src/discovery.c`'s formats.

use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::time::Duration;

use psr_crypto::Target;
use psr_lan::discovery::{self, Console, Host, HostState};
use psr_lan::http;

#[test]
fn response_parse_crlf_and_lf() {
    let crlf = "HTTP/1.1 200 OK\r\nContent-type: text/html, text, plain\r\nUltimate Ability: Gamer\r\n\r\n";
    let lf = "HTTP/1.1 200 Ok\nContent-type: text/html, text, plain\nUltimate Ability:Gamer\n";
    for text in [crlf, lf] {
        let r = http::parse_response(text.as_bytes()).unwrap();
        assert_eq!(r.code, 200);
        // chiaki-ng's list is backwards; ours is in wire order.
        assert_eq!(
            r.headers,
            vec![
                ("Content-type".into(), "text/html, text, plain".into()),
                ("Ultimate Ability".into(), "Gamer".into())
            ]
        );
    }
}

#[test]
fn malformed_responses_are_refused() {
    assert!(http::parse_response(b"HTTP/1.0 200 OK\n\n").is_err());
    assert!(http::parse_response(b"HTTP/1.1 OK\nA:b\n").is_err());
    assert!(http::parse_response(b"HTTP/1.1 200 OK\nno colon here\n").is_err());
    assert!(http::parse_response(b"HTTP/1.1 200 OK\nempty:\n").is_err());
    assert!(http::parse_response(b"HTTP/1.1 200 OK\n:novalue\n").is_err());
}

#[test]
fn header_end_finds_the_blank_line() {
    assert_eq!(http::header_end(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nBODY"), Some(38));
    assert_eq!(http::header_end(b"HTTP/1.1 200 OK\r\n"), None);
}

#[test]
fn search_and_wakeup_packets_match_chiaki_ng_byte_for_byte() {
    assert_eq!(discovery::search_packet(Console::Ps5), b"SRCH * HTTP/1.1\ndevice-discovery-protocol-version:00030010\n\0");
    assert_eq!(discovery::search_packet(Console::Ps4), b"SRCH * HTTP/1.1\ndevice-discovery-protocol-version:00020020\n\0");
    assert_eq!(
        discovery::wakeup_packet(Console::Ps5, 0x1234_5678_9abc),
        b"WAKEUP * HTTP/1.1\nclient-type:vr\nauth-type:R\nmodel:w\napp-type:r\nuser-credential:20015998343868\ndevice-discovery-protocol-version:00030010\n\0".to_vec()
    );
}

/// A reply shaped like the ones chiaki-ng parses (`chiaki_discovery_srch_response_parse`). The values are
/// made up; the field names are chiaki-ng's.
const PS5_STANDBY: &str = "HTTP/1.1 620 Server Standby\nhost-id:AABBCCDDEEFF\nhost-type:PS5\nhost-name:PS5-123\nhost-request-port:997\ndevice-discovery-protocol-version:00030010\nsystem-version:08080021\n\0";

#[test]
fn a_ps5_in_rest_mode_parses() {
    let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
    let h = Host::parse(addr, PS5_STANDBY.as_bytes()).unwrap();
    assert_eq!(h.state, HostState::Standby);
    assert_eq!(h.host_request_port, 997);
    assert_eq!(h.host_name.as_deref(), Some("PS5-123"));
    assert!(h.is_ps5());
    assert_eq!(h.target(), Target::Ps5V1);
}

#[test]
fn system_versions_map_to_targets_as_chiaki_ng_does() {
    let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let host = |ver: &str, proto: &str| {
        Host::parse(
            addr,
            format!("HTTP/1.1 200 Ok\nsystem-version:{ver}\ndevice-discovery-protocol-version:{proto}\n").as_bytes(),
        )
        .unwrap()
    };
    assert_eq!(host("08050001", "00030010").target(), Target::Ps5V1);
    assert_eq!(host("08050000", "00030010").target(), Target::Ps5Unknown);
    assert_eq!(host("08050001", "00020020").target(), Target::Ps4V10);
    assert_eq!(host("07000000", "00020020").target(), Target::Ps4V9);
    assert_eq!(host("05050000", "00020020").target(), Target::Ps4V8);
    assert_eq!(host("x", "00020020").target(), Target::Ps4Unknown);
    assert_eq!(host("08050001", "00030010").state, HostState::Ready);
}

#[test]
fn search_collects_a_reply_from_a_fake_console_on_loopback() {
    // A fake console on 127.0.0.1:9302 can't receive a broadcast, so the "broadcast" address here is
    // loopback itself; the code path is the same as on the real network.
    let console = match UdpSocket::bind((Ipv4Addr::LOCALHOST, discovery::PORT_PS5)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("skipped: port {} is busy on this machine ({e})", discovery::PORT_PS5);
            return;
        }
    };
    let fake = std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        let (n, from) = console.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], discovery::search_packet(Console::Ps5));
        console.send_to(PS5_STANDBY.as_bytes(), from).unwrap();
    });
    let hosts = discovery::search(Ipv4Addr::LOCALHOST, Duration::from_millis(1500)).unwrap();
    fake.join().unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].host_name.as_deref(), Some("PS5-123"));
}
