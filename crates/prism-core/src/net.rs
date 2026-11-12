//! Outbound sockets. While TUN mode is active every socket the core opens is
//! pinned to the physical interface (IP_UNICAST_IF on Windows, IP_BOUND_IF
//! on macOS), so the core's own traffic bypasses the TUN routes instead of
//! looping back into itself.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpSocket, TcpStream, UdpSocket};

/// Interface index outbound sockets are bound to; 0 = no binding.
static BIND_IF: AtomicU32 = AtomicU32::new(0);
static TAILSCALE: AtomicBool = AtomicBool::new(false);
pub fn set_tailscale_bypass(enabled: bool) { TAILSCALE.store(enabled, Ordering::Relaxed); }
pub fn is_tailnet_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => { let b = v.octets(); b[0] == 100 && (64..=127).contains(&b[1]) },
        IpAddr::V6(v) => { let s = v.segments(); s[0..3] == [0xfd7a, 0x115c, 0xa1e0] },
    }
}

pub fn set_bind_interface(index: u32) {
    BIND_IF.store(index, Ordering::Relaxed);
}

pub fn bind_interface() -> u32 {
    BIND_IF.load(Ordering::Relaxed)
}

#[cfg(target_os = "android")]
type SocketProtector = Arc<dyn Fn(i32) -> io::Result<()> + Send + Sync>;
#[cfg(target_os = "android")]
static ANDROID_PROTECTOR: std::sync::RwLock<Option<SocketProtector>> = std::sync::RwLock::new(None);
/// Installed by the Android VpnService bridge before any core socket opens.
#[cfg(target_os = "android")]
pub fn set_android_protector(protector: Option<SocketProtector>) {
    *ANDROID_PROTECTOR.write().unwrap() = protector;
}
#[cfg(target_os = "android")]
fn protect_android(fd: i32) -> io::Result<()> {
    let protector = ANDROID_PROTECTOR.read().unwrap().clone()
        .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "Android VPN socket protector unavailable"))?;
    protector(fd)
}

#[cfg(windows)]
fn pin(sock: std::os::windows::io::RawSocket, v6: bool, index: u32) -> io::Result<()> {
    use windows_sys::Win32::Networking::WinSock::{setsockopt, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, IP_UNICAST_IF};
    // IPv4 takes the index in network byte order, IPv6 in host order.
    let (level, opt, val) = if v6 {
        (IPPROTO_IPV6, IPV6_UNICAST_IF, index)
    } else {
        (IPPROTO_IP, IP_UNICAST_IF, index.to_be())
    };
    let r = unsafe { setsockopt(sock as usize, level, opt, &val as *const u32 as *const u8, 4) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// macOS: IP_BOUND_IF / IPV6_BOUND_IF make the socket use that interface's
/// scoped routes, past the tunnel's default routes.
#[cfg(target_os = "macos")]
fn pin(sock: i32, v6: bool, index: u32) -> io::Result<()> {
    const IP_BOUND_IF: libc::c_int = 25;
    const IPV6_BOUND_IF: libc::c_int = 125;
    let (level, opt) = if v6 { (libc::IPPROTO_IPV6, IPV6_BOUND_IF) } else { (libc::IPPROTO_IP, IP_BOUND_IF) };
    let val = index as libc::c_int;
    let r = unsafe { libc::setsockopt(sock, level, opt, &val as *const libc::c_int as *const libc::c_void, 4) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(any(windows, target_os = "macos")))]
fn pin(_: i32, _: bool, _: u32) -> io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn raw<S: std::os::windows::io::AsRawSocket>(s: &S) -> std::os::windows::io::RawSocket {
    s.as_raw_socket()
}

#[cfg(not(windows))]
fn raw<S: std::os::fd::AsRawFd>(s: &S) -> i32 {
    s.as_raw_fd()
}

/// The interface to pin a socket for `peer` to (0 = none). Loopback never
/// goes through the TUN, and a pinned socket can't reach it at all.
#[cfg(windows)]
fn tail_interface(peer: &SocketAddr) -> io::Result<u32> {
    use windows_sys::Win32::{NetworkManagement::IpHelper::*, Networking::WinSock::*};
    unsafe {
        let mut dest: SOCKADDR_INET=std::mem::zeroed();
        match peer.ip() {
            IpAddr::V4(ip)=>{dest.Ipv4.sin_family=AF_INET;dest.Ipv4.sin_addr.S_un.S_addr=u32::from_ne_bytes(ip.octets());}
            IpAddr::V6(ip)=>{dest.Ipv6.sin6_family=AF_INET6;dest.Ipv6.sin6_addr.u.Byte=ip.octets();}
        }
        let mut index=0;
        if GetBestInterfaceEx((&dest as *const SOCKADDR_INET).cast(),&mut index)!=0 {return Err(io::Error::new(io::ErrorKind::NotConnected,"Tailscale route unavailable"));}
        let mut row:MIB_IF_ROW2=std::mem::zeroed(); row.InterfaceIndex=index;
        if GetIfEntry2(&mut row)!=0 || row.OperStatus!=1 || row.Type!=53 || String::from_utf16_lossy(&row.Alias[..row.Alias.iter().position(|c|*c==0).unwrap_or(row.Alias.len())])!="Tailscale" {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied,"Tailscale route is not a live Tailscale interface; physical fallback refused"));
        }
        Ok(index)
    }
}
fn pin_index(peer: &SocketAddr) -> io::Result<u32> {
    if peer.ip().is_loopback() {return Ok(0);}
    if TAILSCALE.load(Ordering::Relaxed) && is_tailnet_ip(peer.ip()) {
        #[cfg(windows)] return tail_interface(peer);
        #[cfg(not(windows))] return Ok(0);
    }
    Ok(bind_interface())
}

async fn connect_addr(addr: SocketAddr) -> io::Result<TcpStream> {
    #[cfg(target_os = "android")]
    let s = {
        let socket = if addr.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
        protect_android(raw(&socket))?;
        socket.connect(addr).await?
    };
    #[cfg(not(target_os = "android"))]
    let s = {
    let index = pin_index(&addr)?;
    if index == 0 {
        TcpStream::connect(addr).await?
    } else {
        let sock = if addr.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
        pin(raw(&sock), addr.is_ipv6(), index)?;
        sock.connect(addr).await?
    }
    };
    let _ = s.set_nodelay(true);
    Ok(s)
}

static RESOLVER: std::sync::RwLock<Option<Arc<crate::dns::Resolver>>> = std::sync::RwLock::new(None);

/// Name resolution for the core's own connections goes through the DNS
/// module when it is enabled.
pub fn set_resolver(r: Option<Arc<crate::dns::Resolver>>) {
    *RESOLVER.write().unwrap() = r;
}

/// Resolves `host` with the configured DNS module. TUN never falls back
/// to system resolution if its resolver becomes unavailable.
pub async fn resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    resolve_inner(host, port, false).await
}
pub async fn resolve_proxy(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    resolve_inner(host, port, true).await
}
async fn resolve_inner(host: &str, port: u16, proxy: bool) -> io::Result<Vec<SocketAddr>> {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = h.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let resolver = RESOLVER.read().unwrap().clone();
    if let Some(r) = resolver {
        let ips = if proxy { r.lookup_proxy(h).await? } else { r.lookup(h).await? };
        return Ok(ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect());
    }
    if bind_interface() != 0 || cfg!(target_os = "android") {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "DNS REJECT: TUN resolver unavailable; system DNS fallback refused"));
    }
    let addrs: Vec<SocketAddr> = tokio::time::timeout(Duration::from_secs(10), tokio::net::lookup_host((h, port)))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("resolve {h}: timeout")))??
        .collect();
    if addrs.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("resolve {h}: no address")));
    }
    Ok(addrs)
}

/// Connects to `host:port`, trying IPv4 addresses first.
pub async fn tcp_connect(host: &str, port: u16) -> io::Result<TcpStream> {
    connect_resolved(resolve(host, port).await?).await
}
pub async fn tcp_connect_proxy(host: &str, port: u16) -> io::Result<TcpStream> {
    connect_resolved(resolve_proxy(host, port).await?).await
}
async fn connect_resolved(mut addrs: Vec<SocketAddr>) -> io::Result<TcpStream> {
    addrs.sort_by_key(|a| a.is_ipv6());
    let mut last = None;
    for a in addrs.into_iter().take(4) {
        match connect_addr(a).await {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address")))
}

/// UDP socket for talking to `peer`, pinned like the TCP sockets.
pub async fn udp_socket(peer: SocketAddr) -> io::Result<UdpSocket> {
    let bind: SocketAddr = if peer.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
    let s = UdpSocket::bind(bind).await?;
    #[cfg(target_os = "android")]
    protect_android(raw(&s))?;
    let index = pin_index(&peer)?;
    if index != 0 {
        pin(raw(&s), peer.is_ipv6(), index)?;
    }
    Ok(s)
}

#[cfg(test)]
mod tailnet_tests {
    #[test]
    fn only_reserved_overlay_ranges_are_exempt() {
        for ip in ["100.64.0.0", "100.127.255.255", "fd7a:115c:a1e0::1"] { assert!(super::is_tailnet_ip(ip.parse().unwrap())); }
        for ip in ["100.63.255.255", "100.128.0.0", "8.8.8.8", "fd7a:115c:a1e1::1", "2001:4860::1"] { assert!(!super::is_tailnet_ip(ip.parse().unwrap())); }
    }
}
