// SPDX-License-Identifier: AGPL-3.0-only
//! Waiting a while for a datagram. On Windows the wait is `WSAPoll`, and the receive only runs once something
//! is there, without a timeout of its own: a receive left to time out (`SO_RCVTIMEO`, which
//! `UdpSocket::set_read_timeout` sets) lost the answer it was waiting for in the punch tests, 9 runs in 20,
//! when the answer arrived as the wait ran out, and Winsock's documentation does not say what state such a
//! receive leaves the socket in (`docs/PSN.md`, step 9c-2). Elsewhere the read timeout is used as before.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

/// A datagram and its sender, if one arrives within `timeout`. Errors other than running out of time are
/// returned (a connection reset among them, for the caller to judge).
pub fn recv_from_within(
    sock: &UdpSocket,
    buf: &mut [u8],
    timeout: Duration,
) -> io::Result<Option<(usize, SocketAddr)>> {
    received(within(sock, timeout, || sock.recv_from(buf)))
}

/// [`recv_from_within`] on a connected socket.
pub fn recv_within(sock: &UdpSocket, buf: &mut [u8], timeout: Duration) -> io::Result<Option<usize>> {
    received(within(sock, timeout, || sock.recv(buf)))
}

fn received<T>(r: io::Result<Option<T>>) -> io::Result<Option<T>> {
    match r {
        Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => Ok(None),
        other => other,
    }
}

#[cfg(windows)]
fn within<T>(sock: &UdpSocket, timeout: Duration, recv: impl FnOnce() -> io::Result<T>) -> io::Result<Option<T>> {
    if !readable(sock, timeout)? {
        return Ok(None);
    }
    // Something is there, or an error is. Received without blocking, so a readiness that went away cannot
    // turn into a wait with no end.
    sock.set_nonblocking(true)?;
    let r = recv();
    sock.set_nonblocking(false)?;
    r.map(Some)
}

/// Whether the socket has something to read (or an error to report) within `timeout`.
#[cfg(windows)]
fn readable(sock: &UdpSocket, timeout: Duration) -> io::Result<bool> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        POLLRDNORM, SOCKET, SOCKET_ERROR, WSAGetLastError, WSAPOLLFD, WSAPoll,
    };
    // Rounded up to whole milliseconds, so a wait is never cut short.
    let ms = i32::try_from(timeout.as_micros().div_ceil(1000)).unwrap_or(i32::MAX);
    let mut fd = WSAPOLLFD { fd: sock.as_raw_socket() as SOCKET, events: POLLRDNORM, revents: 0 };
    // SAFETY: `fd` is one valid WSAPOLLFD for a socket `sock` keeps open for the call, and the count says one.
    let n = unsafe { WSAPoll(&mut fd, 1, ms) };
    if n == SOCKET_ERROR {
        // SAFETY: no arguments; reads the calling thread's last Winsock error.
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    Ok(n > 0)
}

#[cfg(not(windows))]
fn within<T>(sock: &UdpSocket, timeout: Duration, recv: impl FnOnce() -> io::Result<T>) -> io::Result<Option<T>> {
    sock.set_read_timeout(Some(timeout.max(Duration::from_millis(1))))?;
    recv().map(Some)
}
