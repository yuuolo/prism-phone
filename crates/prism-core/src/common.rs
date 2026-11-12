use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

/// Destination of a proxied connection: either a domain (resolved by the
/// outbound / remote server) or a literal socket address.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Address {
    Domain(String, u16),
    Ip(SocketAddr),
}

impl Address {
    pub fn new(host: &str, port: u16) -> Self {
        let h = host.trim_start_matches('[').trim_end_matches(']');
        match h.parse::<IpAddr>() {
            Ok(ip) => Address::Ip(SocketAddr::new(ip, port)),
            Err(_) => Address::Domain(h.to_ascii_lowercase(), port),
        }
    }

    /// Parses `host:port` / `[v6]:port`.
    pub fn parse_authority(s: &str) -> Option<Self> {
        if let Ok(sa) = s.parse::<SocketAddr>() {
            return Some(Address::Ip(sa));
        }
        let (host, port) = s.rsplit_once(':')?;
        let port = port.parse().ok()?;
        if host.is_empty() {
            return None;
        }
        Some(Address::new(host, port))
    }

    pub fn port(&self) -> u16 {
        match self {
            Address::Domain(_, p) => *p,
            Address::Ip(sa) => sa.port(),
        }
    }

    pub fn host(&self) -> String {
        match self {
            Address::Domain(d, _) => d.clone(),
            Address::Ip(sa) => sa.ip().to_string(),
        }
    }

    pub fn domain(&self) -> Option<&str> {
        match self {
            Address::Domain(d, _) => Some(d),
            Address::Ip(_) => None,
        }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Address::Domain(..) => None,
            Address::Ip(sa) => Some(sa.ip()),
        }
    }

    /// SOCKS5-style address: ATYP(1=v4, 3=domain, 4=v6) + addr + port(BE).
    /// Used by SOCKS5, Shadowsocks, Trojan and AnyTLS.
    pub fn write_socks(&self, buf: &mut Vec<u8>) {
        match self {
            Address::Ip(SocketAddr::V4(sa)) => {
                buf.push(1);
                buf.extend_from_slice(&sa.ip().octets());
            }
            Address::Ip(SocketAddr::V6(sa)) => {
                buf.push(4);
                buf.extend_from_slice(&sa.ip().octets());
            }
            Address::Domain(d, _) => {
                buf.push(3);
                buf.push(d.len().min(255) as u8);
                buf.extend_from_slice(&d.as_bytes()[..d.len().min(255)]);
            }
        }
        buf.extend_from_slice(&self.port().to_be_bytes());
    }

    pub async fn read_socks<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Self> {
        let atyp = r.read_u8().await?;
        let addr = match atyp {
            1 => {
                let mut b = [0u8; 4];
                r.read_exact(&mut b).await?;
                Address::Ip(SocketAddr::new(Ipv4Addr::from(b).into(), r.read_u16().await?))
            }
            4 => {
                let mut b = [0u8; 16];
                r.read_exact(&mut b).await?;
                Address::Ip(SocketAddr::new(Ipv6Addr::from(b).into(), r.read_u16().await?))
            }
            3 => {
                let len = r.read_u8().await? as usize;
                let mut b = vec![0u8; len];
                r.read_exact(&mut b).await?;
                let host = String::from_utf8(b).map_err(|_| invalid("bad domain"))?;
                Address::new(&host, r.read_u16().await?)
            }
            _ => return Err(invalid("bad address type")),
        };
        Ok(addr)
    }

    /// [`Address::read_socks`] for an in-memory packet; advances `r` past the address.
    pub fn read_socks_sync(r: &mut &[u8]) -> io::Result<Self> {
        let short = || invalid("short address");
        let (&atyp, rest) = r.split_first().ok_or_else(short)?;
        let (host, rest): (IpAddr, &[u8]) = match atyp {
            1 if rest.len() >= 6 => (Ipv4Addr::from(<[u8; 4]>::try_from(&rest[..4]).unwrap()).into(), &rest[4..]),
            4 if rest.len() >= 18 => (Ipv6Addr::from(<[u8; 16]>::try_from(&rest[..16]).unwrap()).into(), &rest[16..]),
            3 => {
                let (&len, rest) = rest.split_first().ok_or_else(short)?;
                let len = len as usize;
                if rest.len() < len + 2 {
                    return Err(short());
                }
                let host = std::str::from_utf8(&rest[..len]).map_err(|_| invalid("bad domain"))?;
                let port = u16::from_be_bytes([rest[len], rest[len + 1]]);
                *r = &rest[len + 2..];
                return Ok(Address::new(host, port));
            }
            1 | 4 => return Err(short()),
            _ => return Err(invalid("bad address type")),
        };
        let port = u16::from_be_bytes([rest[0], rest[1]]);
        *r = &rest[2..];
        Ok(Address::Ip(SocketAddr::new(host, port)))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::Domain(d, p) => write!(f, "{d}:{p}"),
            Address::Ip(sa) => write!(f, "{sa}"),
        }
    }
}

pub trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ProxyStream for T {}

pub type BoxedStream = Box<dyn ProxyStream>;

pub fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

pub fn other(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg.into())
}

/// Dials a TCP connection to `addr`, resolving domains with the system resolver.
pub async fn tcp_connect(host: &str, port: u16) -> io::Result<tokio::net::TcpStream> {
    crate::net::tcp_connect(host, port).await
}

/// A UDP session to one destination: datagrams to send go into `tx`,
/// datagrams received from the destination come out of `rx`. Dropping `tx`
/// ends the session.
pub struct UdpPipe {
    pub tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    pub rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
}

/// Runs a UDP protocol implementation: `run` receives the datagrams to send
/// and a sender for the datagrams it receives, and returns when the session
/// is over (normally when the send side is closed).
pub fn udp_pump<F, Fut>(run: F) -> UdpPipe
where
    F: FnOnce(tokio::sync::mpsc::Receiver<Vec<u8>>, tokio::sync::mpsc::Sender<Vec<u8>>) -> Fut,
    Fut: std::future::Future<Output = io::Result<()>> + Send + 'static,
{
    let (tx, out_rx) = tokio::sync::mpsc::channel(256);
    let (in_tx, rx) = tokio::sync::mpsc::channel(256);
    let fut = run(out_rx, in_tx);
    tokio::spawn(async move {
        if let Err(e) = fut.await {
            tracing::debug!("udp session closed: {e}");
        }
    });
    UdpPipe { tx, rx }
}

/// Bridges a protocol implemented as two plain async loops into a single
/// AsyncRead + AsyncWrite stream: the caller gets one end of an in-memory
/// duplex pipe, `run` gets the other end and moves bytes to / from the wire.
pub fn pump<F, Fut>(run: F) -> BoxedStream
where
    F: FnOnce(tokio::io::DuplexStream) -> Fut,
    Fut: std::future::Future<Output = io::Result<()>> + Send + 'static,
{
    let (user, inner) = tokio::io::duplex(64 * 1024);
    let fut = run(inner);
    tokio::spawn(async move {
        if let Err(e) = fut.await {
            tracing::debug!("stream closed: {e}");
        }
    });
    Box::new(user)
}

pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 CGNAT
                || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15 benchmark / fake-ip
                || o[0] >= 224
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || (s[0] & 0xfe00) == 0xfc00 // fc00::/7 unique local
                || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 link local
                || v6.to_ipv4_mapped().is_some_and(|v4| is_private_ip(v4.into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks_addr_roundtrip() {
        for a in [
            Address::new("example.com", 443),
            Address::new("1.2.3.4", 80),
            Address::new("[2001:db8::1]", 8443),
        ] {
            let mut buf = Vec::new();
            a.write_socks(&mut buf);
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            let back = rt.block_on(Address::read_socks(&mut &buf[..])).unwrap();
            assert_eq!(a, back);
        }
    }

    #[test]
    fn authority() {
        assert_eq!(Address::parse_authority("a.com:443"), Some(Address::Domain("a.com".into(), 443)));
        assert_eq!(Address::parse_authority("[::1]:80").unwrap().port(), 80);
        assert!(Address::parse_authority("nope").is_none());
    }
}

/// How datagrams are framed when carried over a stream.
#[derive(Clone, Debug)]
pub enum Framing {
    /// `u16 BE length | payload` (VLESS, sing-box UDP-over-TCP v2 connect mode).
    Length,
    /// Like `Length`, but the stream starts with a VLESS response header.
    Vless,
    /// Trojan: `socks addr | u16 length | CRLF | payload`, sent to this address.
    Trojan(Address),
}

/// Runs a UDP session over an already established stream.
pub fn udp_over_stream<S>(s: S, framing: Framing) -> UdpPipe
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use tokio::io::AsyncWriteExt;
    udp_pump(move |mut out, inc| async move {
        let (mut rd, mut wr) = tokio::io::split(s);
        let fr = framing.clone();
        let reader = tokio::spawn(async move {
            let res: io::Result<()> = async {
                if let Framing::Vless = fr {
                    let mut head = [0u8; 2];
                    rd.read_exact(&mut head).await?;
                    let mut addons = vec![0u8; head[1] as usize];
                    rd.read_exact(&mut addons).await?;
                }
                loop {
                    if let Framing::Trojan(_) = fr {
                        Address::read_socks(&mut rd).await?;
                    }
                    let len = rd.read_u16().await? as usize;
                    if let Framing::Trojan(_) = fr {
                        let mut crlf = [0u8; 2];
                        rd.read_exact(&mut crlf).await?;
                    }
                    let mut data = vec![0u8; len];
                    rd.read_exact(&mut data).await?;
                    if inc.send(data).await.is_err() {
                        return Ok(());
                    }
                }
            }
            .await;
            if let Err(e) = res {
                if e.kind() != io::ErrorKind::UnexpectedEof {
                    tracing::debug!("udp stream reader: {e}");
                }
            }
        });
        let res: io::Result<()> = async {
            while let Some(p) = out.recv().await {
                let mut f = Vec::with_capacity(p.len() + 300);
                if let Framing::Trojan(target) = &framing {
                    target.write_socks(&mut f);
                }
                f.extend_from_slice(&(p.len().min(u16::MAX as usize) as u16).to_be_bytes());
                if let Framing::Trojan(_) = &framing {
                    f.extend_from_slice(b"\r\n");
                }
                f.extend_from_slice(&p[..p.len().min(u16::MAX as usize)]);
                wr.write_all(&f).await?;
                wr.flush().await?;
            }
            Ok(())
        }
        .await;
        reader.abort();
        res
    })
}
