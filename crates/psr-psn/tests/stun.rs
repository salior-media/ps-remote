// SPDX-License-Identifier: AGPL-3.0-only
// The binding request and response of RFC 5389, checked against RFC 5769's test vector (section 2.2), and the
// query against a stand-in server on loopback. Written from chiaki-ng `stun_get_external_address_from_server`
// (`lib/src/remote/stun.h`, LicenseRef-AGPL-3.0-only-OpenSSL). Nothing here leaves this machine.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::thread;

use psr_psn::stun;

const TXID: [u8; 12] = [0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae];

/// RFC 5769 2.2, "Sample IPv4 Response": SOFTWARE, XOR-MAPPED-ADDRESS 192.0.2.1:32853, MESSAGE-INTEGRITY and
/// FINGERPRINT.
const RFC5769_IPV4: [u8; 80] = [
    0x01, 0x01, 0x00, 0x3c, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf,
    0xae, 0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x20, 0x00, 0x20,
    0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43, 0x00, 0x08, 0x00, 0x14, 0x2b, 0x91, 0xf5, 0x99, 0xfd,
    0x9e, 0x90, 0xc3, 0x8c, 0x74, 0x89, 0xf9, 0x2a, 0xf9, 0xba, 0x53, 0xf0, 0x6b, 0xe7, 0xd7, 0x80, 0x28, 0x00, 0x04,
    0xc0, 0x7d, 0x4c, 0x96,
];

fn addr(s: &str) -> SocketAddrV4 {
    s.parse().unwrap()
}

#[test]
fn the_binding_request_is_a_bare_header() {
    let r = stun::binding_request(&TXID);
    assert_eq!(&r[..8], &[0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42]);
    assert_eq!(&r[8..], &TXID);
}

#[test]
fn rfc_5769s_response_is_read() {
    assert_eq!(stun::parse_binding_response(&RFC5769_IPV4, &TXID), Some(addr("192.0.2.1:32853")));
}

/// A response to `TXID` with these attributes.
fn response(attrs: &[u8]) -> Vec<u8> {
    let mut r = vec![0x01, 0x01];
    r.extend((attrs.len() as u16).to_be_bytes());
    r.extend([0x21, 0x12, 0xa4, 0x42]);
    r.extend(TXID);
    r.extend(attrs);
    r
}

const PLAIN_198_51_100_9_4000: [u8; 12] = [0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0x0f, 0xa0, 198, 51, 100, 9];

#[test]
fn a_plain_mapped_address_is_read_and_the_xored_one_preferred() {
    assert_eq!(
        stun::parse_binding_response(&response(&PLAIN_198_51_100_9_4000), &TXID),
        Some(addr("198.51.100.9:4000"))
    );
    let both = [&PLAIN_198_51_100_9_4000[..], &RFC5769_IPV4[36..48]].concat();
    assert_eq!(stun::parse_binding_response(&response(&both), &TXID), Some(addr("192.0.2.1:32853")));
}

#[test]
fn anything_else_is_not_an_answer() {
    let good = RFC5769_IPV4.to_vec();
    let with = |i: usize, v: u8| {
        let mut r = good.clone();
        r[i] = v;
        r
    };
    let mut other_txid = TXID;
    other_txid[11] ^= 1;
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("too short", good[..19].to_vec()),
        (
            "a request, not a response",
            with(1, 0x01).iter().enumerate().map(|(i, &b)| if i == 0 { 0x00 } else { b }).collect(),
        ),
        ("an error response", with(0, 0x01).iter().enumerate().map(|(i, &b)| if i == 1 { 0x11 } else { b }).collect()),
        ("a length that does not match", with(3, 0x40)),
        ("a wrong magic cookie", with(4, 0x22)),
        ("cut mid-attribute", good[..70].to_vec()),
        ("an attribute longer than the message", response(&[0x00, 0x20, 0x00, 0x30, 0x00, 0x01])),
        ("IPv6", response(&[0x00, 0x20, 0x00, 0x14, 0x00, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
        (
            "an IPv4 address of the wrong length",
            response(&[0x00, 0x01, 0x00, 0x0c, 0x00, 0x01, 0x0f, 0xa0, 1, 2, 3, 4, 0, 0, 0, 0]),
        ),
        ("no address", response(&[])),
        ("loopback", response(&[0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0x0f, 0xa0, 127, 0, 0, 1])),
        ("unspecified", response(&[0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0x0f, 0xa0, 0, 0, 0, 0])),
        ("port 0", response(&[0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 198, 51, 100, 9])),
    ];
    for (why, r) in &cases {
        assert_eq!(stun::parse_binding_response(r, &TXID), None, "{why}");
    }
    assert_eq!(stun::parse_binding_response(&good, &other_txid), None, "another transaction");
}

#[test]
fn only_the_server_asked_is_believed() {
    let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let ours = match sock.local_addr().unwrap() {
        SocketAddr::V4(a) => a,
        SocketAddr::V6(_) => unreachable!(),
    };
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let imposter = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let server_addr = match server.local_addr().unwrap() {
        SocketAddr::V4(a) => a,
        SocketAddr::V6(_) => unreachable!(),
    };
    let t = thread::spawn(move || {
        let mut buf = [0u8; 64];
        let (n, _) = server.recv_from(&mut buf).unwrap();
        assert_eq!(n, 20);
        let answer = |mapped: [u8; 4]| {
            let mut r = vec![0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42];
            r.extend(&buf[8..20]);
            r.extend([0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0x0f, 0xa0]);
            r.extend(mapped);
            r
        };
        // Someone else answers first, with the right transaction ID; then junk from the server; then the server.
        imposter.send_to(&answer([198, 51, 100, 66]), ours).unwrap();
        server.send_to(b"junk", ours).unwrap();
        server.send_to(&answer([198, 51, 100, 9]), ours).unwrap();
    });
    assert_eq!(stun::ask(&sock, server_addr).unwrap(), Some(addr("198.51.100.9:4000")));
    t.join().unwrap();
}
