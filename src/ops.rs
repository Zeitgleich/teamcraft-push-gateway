//! Operations helpers (the same as in the TeamCraft server binaries).
//!
//! - Container health check: the image ships no `curl`, so `teamcraft-push-gateway healthcheck`
//!   probes its own health endpoint with a minimal blocking HTTP probe (HTTP/1.0, status line only).
//! - [`bind_dual_stack`]: the one way HTTP listeners of the binaries are bound (IPv4 and IPv6).
//! - [`shutdown_signal`]: resolves on SIGINT or SIGTERM. In a container the process is PID 1 and
//!   the kernel ignores SIGTERM there unless a handler is installed, so every binary needs this.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpListener;

const LISTEN_BACKLOG: i32 = 1024;

/// Binds a TCP listener for an HTTP endpoint. An IPv6 address is bound with `IPV6_V6ONLY` off, so
/// `[::]` accepts IPv4 (as IPv4-mapped addresses) and IPv6 regardless of the host's `bindv6only`
/// default; this is how every listener of the server binaries faces the network (code-style.md).
pub fn bind_dual_stack(addr: SocketAddr) -> io::Result<TcpListener> {
  let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
  if addr.is_ipv6() {
    socket.set_only_v6(false)?;
  }
  socket.set_reuse_address(true)?;
  socket.set_nonblocking(true)?;
  socket.bind(&addr.into())?;
  socket.listen(LISTEN_BACKLOG)?;
  TcpListener::from_std(socket.into())
}

/// Resolves when the process is asked to stop (Ctrl-C, or SIGTERM on Unix).
pub async fn shutdown_signal() {
  let ctrl_c = async {
    if tokio::signal::ctrl_c().await.is_err() {
      std::future::pending::<()>().await;
    }
  };
  #[cfg(unix)]
  let terminate = async {
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
      Ok(mut stream) => {
        stream.recv().await;
      },
      Err(_) => std::future::pending::<()>().await,
    }
  };
  #[cfg(not(unix))]
  let terminate = std::future::pending::<()>();

  tokio::select! {
    () = ctrl_c => {},
    () = terminate => {},
  }
}

/// How long [`probe`] waits for connecting and for each read or write by default.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);

/// Largest part of the response that is read; only the status line matters.
const MAX_RESPONSE_BYTES: usize = 512;

/// Why a probe failed.
#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
  #[error("connecting to {addr} failed: {source}")]
  Connect {
    addr: SocketAddr,
    source: std::io::Error,
  },
  #[error("talking to {addr} failed: {source}")]
  Io {
    addr: SocketAddr,
    source: std::io::Error,
  },
  #[error("{addr} answered with a malformed status line")]
  MalformedResponse { addr: SocketAddr },
  #[error("{addr} answered with HTTP status {status}")]
  Unhealthy { addr: SocketAddr, status: u16 },
}

/// The address to probe for a service that listens on `listen`: unspecified addresses (`[::]`,
/// `0.0.0.0`) are reached through loopback of the same family.
pub fn probe_target(listen: SocketAddr) -> SocketAddr {
  let ip = match listen.ip() {
    IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
    IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
    ip => ip,
  };
  SocketAddr::new(ip, listen.port())
}

/// `GET path` on `addr`; succeeds on any 2xx status.
pub fn probe(addr: SocketAddr, path: &str, timeout: Duration) -> Result<(), ProbeError> {
  let io_error = |source| ProbeError::Io { addr, source };
  let mut stream =
    TcpStream::connect_timeout(&addr, timeout).map_err(|source| ProbeError::Connect { addr, source })?;
  stream.set_read_timeout(Some(timeout)).map_err(io_error)?;
  stream.set_write_timeout(Some(timeout)).map_err(io_error)?;
  // One write: `write!` on the stream would send the request in several segments.
  let request = format!("GET {path} HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n");
  stream.write_all(request.as_bytes()).map_err(io_error)?;

  let mut buffer = [0_u8; MAX_RESPONSE_BYTES];
  let mut filled = 0;
  // The status line ends at the first CRLF; read until we have it or the buffer is full.
  while filled < buffer.len() && !buffer[..filled].windows(2).any(|pair| pair == b"\r\n") {
    let read = stream.read(&mut buffer[filled..]).map_err(io_error)?;
    if read == 0 {
      break;
    }
    filled += read;
  }
  let status = parse_status(&buffer[..filled]).ok_or(ProbeError::MalformedResponse { addr })?;
  if (200..300).contains(&status) {
    Ok(())
  } else {
    Err(ProbeError::Unhealthy { addr, status })
  }
}

/// The status code of `HTTP/1.x <code> ...`.
fn parse_status(response: &[u8]) -> Option<u16> {
  let line_end = response
    .iter()
    .position(|byte| *byte == b'\r' || *byte == b'\n')?;
  let line = std::str::from_utf8(&response[..line_end]).ok()?;
  let mut parts = line.split(' ');
  parts.next().filter(|version| version.starts_with("HTTP/1."))?;
  parts.next()?.parse().ok()
}
