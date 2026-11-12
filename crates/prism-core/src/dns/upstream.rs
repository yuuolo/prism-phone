//! DNS upstream servers, in mihomo's URL syntax:
//!
//! `223.5.5.5`, `udp://1.1.1.1:53`, `tcp://8.8.8.8`, `tls://dns.alidns.com`,
//! `https://doh.pub/dns-query`, `quic://dns.alidns.com` (DNS over QUIC,
//! RFC 9250), `https://dns.alidns.com/dns-query#h3=true` or `h3://…` (DNS
//! over HTTP/3), optionally followed by `#<proxy or group>` to send the
//! queries through that outbound.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::wire;
use crate::common::{other, Address, BoxedStream};
use crate::outbound::tls::Tls;
use crate::outbound::{RegistryCell, Outbound};

const TIMEOUT: Duration = Duration::from_secs(5);
const POOL: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Udp,
    Tcp,
    Tls,
    Https,
    /// DNS over QUIC.
    Quic,
    /// DNS over HTTP/3.
    H3,
}

/// A QUIC connection to a DoQ / DoH3 server, reused across queries.
struct QuicConn {
    conn: quinn::Connection,
    _endpoint: quinn::Endpoint,
    h3: Option<h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>>,
}

pub struct Upstream {
    pub url: String,
    kind: Kind,
    host: String,
    port: u16,
    path: String,
    /// Outbound (proxy or group) the queries go through; None = direct.
    pub detour: Option<String>,
    proxy_only: bool,
    tls: Option<Tls>,
    bootstrap: Arc<Vec<SocketAddr>>,
    reg: RegistryCell,
    pool: Mutex<Vec<BoxedStream>>,
    addr: Mutex<Option<(IpAddr, Instant)>>,
    quic: tokio::sync::Mutex<Option<Arc<QuicConn>>>,
}

impl Upstream {
    /// Parses one nameserver entry. `bootstrap` (plain-IP default
    /// nameservers) resolves hostnames such as `dns.alidns.com`.
    pub fn parse(spec: &str, bootstrap: Arc<Vec<SocketAddr>>, reg: RegistryCell) -> Result<Self, String> {
        let (main, detour, h3) = match spec.split_once('#') {
            Some((m, frag)) => {
                // `#proxy`, `#proxy&h3=true`, `#h3=true`
                let parts: Vec<&str> = frag.split('&').map(str::trim).collect();
                let d = parts.first().copied().unwrap_or("");
                let h3 = parts.iter().any(|p| p.eq_ignore_ascii_case("h3=true"));
                (m.trim(), if d.is_empty() || d.eq_ignore_ascii_case("DIRECT") || d.contains('=') { None } else { Some(d.to_string()) }, h3)
            }
            None => (spec.trim(), None, false),
        };
        let (kind, rest) = match main.split_once("://") {
            Some(("udp", r)) => (Kind::Udp, r),
            Some(("tcp", r)) => (Kind::Tcp, r),
            Some(("tls", r)) => (Kind::Tls, r),
            Some(("https", r)) if h3 => (Kind::H3, r),
            Some(("https", r)) => (Kind::Https, r),
            Some(("h3", r)) => (Kind::H3, r),
            Some(("quic", r)) => (Kind::Quic, r),
            Some((s, _)) => return Err(format!("dns server {spec}: {s}:// is not supported")),
            None if main == "system" || main.starts_with("dhcp") => return Err(format!("dns server {spec} is not supported")),
            None => (Kind::Udp, main),
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, "/dns-query".to_string()),
        };
        let default_port = match kind {
            Kind::Udp | Kind::Tcp => 53,
            Kind::Tls | Kind::Quic => 853,
            Kind::Https | Kind::H3 => 443,
        };
        let addr = Address::parse_authority(authority).unwrap_or_else(|| Address::new(authority, default_port));
        let (host, port) = (addr.host(), addr.port());
        if host.is_empty() {
            return Err(format!("dns server {spec}: missing host"));
        }
        let tls = match kind {
            Kind::Tls | Kind::Https => {
                let alpn = if kind == Kind::Https { vec!["http/1.1".to_string()] } else { vec![] };
                Some(Tls::new(&host, false, &alpn, None).map_err(|e| format!("dns server {spec}: {e}"))?)
            }
            _ => None,
        };
        Ok(Upstream {
            url: spec.to_string(),
            kind,
            host,
            port,
            path,
            detour,
            proxy_only: spec.split_once('#').is_some_and(|(_, f)| f.split('&').any(|p| p == "proxy-only=true")),
            tls,
            bootstrap,
            reg,
            pool: Mutex::new(Vec::new()),
            addr: Mutex::new(None),
            quic: tokio::sync::Mutex::new(None),
        })
    }

    pub fn is_direct(&self) -> bool {
        self.detour.is_none()
    }

    /// Sends `query` and returns the response (any rcode).
    pub async fn exchange(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        if self.proxy_only {
            let name = self.detour.as_deref().ok_or_else(|| other("DNS REJECT: proxy-only requires an outbound"))?;
            self.proxy_outbound(name)?;
        }
        let res = tokio::time::timeout(TIMEOUT, async {
            match self.kind {
                Kind::Udp => self.exchange_udp(query).await,
                Kind::Quic | Kind::H3 => self.exchange_quic(query).await,
                _ => self.exchange_stream(query).await,
            }
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("dns {}: timeout", self.url)))??;
        if res.len() < 12 || wire::id(&res) != wire::id(query) {
            return Err(other(format!("dns {}: mismatched response", self.url)));
        }
        Ok(res)
    }

    fn proxy_outbound(&self, name: &str) -> io::Result<Arc<dyn Outbound>> {
        let reg = self.reg.get().ok_or_else(|| other("registry not ready"))?;
        let (out, _) = reg.resolve(name, &self.target())?;
        if self.proxy_only && !reg.configs.contains_key(out.name()) {
            return Err(other("DNS REJECT: selected outbound is not a proxy node (DIRECT/REJECT/relay forbidden)"));
        }
        Ok(out)
    }

    fn target(&self) -> Address {
        Address::new(&self.host, self.port)
    }

    /// Server IP for direct queries (hostnames go through the bootstrap
    /// servers, cached for 10 minutes).
    async fn server_ip(&self) -> io::Result<IpAddr> {
        if let Ok(ip) = self.host.parse::<IpAddr>() {
            return Ok(ip);
        }
        if let Some((ip, at)) = *self.addr.lock().unwrap() {
            if at.elapsed() < Duration::from_secs(600) {
                return Ok(ip);
            }
        }
        let ip = bootstrap_lookup(&self.bootstrap, &self.host).await?;
        *self.addr.lock().unwrap() = Some((ip, Instant::now()));
        Ok(ip)
    }

    async fn exchange_udp(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        if let Some(d) = &self.detour {
            let out = self.proxy_outbound(d)?;
            let mut pipe = out.connect_udp(&self.target()).await?;
            pipe.tx.send(query.to_vec()).await.map_err(|_| other("dns: udp session closed"))?;
            return pipe.rx.recv().await.ok_or_else(|| other("dns: no response"));
        }
        let server = SocketAddr::new(self.server_ip().await?, self.port);
        udp_query(server, query).await
    }

    async fn connect(&self) -> io::Result<BoxedStream> {
        let raw: BoxedStream = match &self.detour {
            Some(d) => {
                let out = self.proxy_outbound(d)?;
                out.connect(&self.target()).await?
            }
            None => {
                let ip = self.server_ip().await?;
                Box::new(crate::net::tcp_connect(&ip.to_string(), self.port).await?)
            }
        };
        Ok(match &self.tls {
            Some(t) => Box::new(t.wrap(raw).await?),
            None => raw,
        })
    }

    /// The QUIC connection for DoQ / DoH3, opened on first use.
    async fn quic_conn(&self) -> io::Result<Arc<QuicConn>> {
        let mut g = self.quic.lock().await;
        if let Some(c) = g.as_ref() {
            if c.conn.close_reason().is_none() {
                return Ok(c.clone());
            }
        }
        let datagrams = match &self.detour {
            Some(d) => {
                let out = self.proxy_outbound(d)?;
                crate::outbound::dialer::Datagrams::Pipe(out.connect_udp(&self.target()).await?)
            }
            None => {
                let peer = SocketAddr::new(self.server_ip().await?, self.port);
                let sock = crate::net::udp_socket(peer).await?;
                sock.connect(peer).await?;
                crate::outbound::dialer::Datagrams::Socket(sock, peer)
            }
        };
        let (socket, peer) = datagrams.into_quinn()?;
        let runtime: Arc<dyn quinn::Runtime> = Arc::new(quinn::TokioRuntime);
        let endpoint = quinn::Endpoint::new_with_abstract_socket(quinn::EndpointConfig::default(), None, socket, runtime)?;
        let alpn = if self.kind == Kind::H3 { "h3" } else { "doq" };
        let tls = crate::outbound::tls::tls13_config(false, &[alpn.to_string()])?;
        let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls)).map_err(|e| other(e.to_string()))?;
        let mut cfg = quinn::ClientConfig::new(Arc::new(quic_tls));
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(Duration::from_secs(15)));
        transport.max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()));
        cfg.transport_config(Arc::new(transport));
        let conn = endpoint
            .connect_with(cfg, peer, &self.host)
            .map_err(|e| other(format!("dns {}: {e}", self.url)))?
            .await
            .map_err(|e| other(format!("dns {}: QUIC handshake failed: {e}", self.url)))?;
        let h3 = if self.kind == Kind::H3 {
            let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn.clone())).await.map_err(|e| other(format!("dns {}: HTTP/3: {e}", self.url)))?;
            tokio::spawn(async move {
                let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
            });
            Some(send)
        } else {
            None
        };
        let c = Arc::new(QuicConn { conn, _endpoint: endpoint, h3 });
        *g = Some(c.clone());
        Ok(c)
    }

    /// One query over the shared QUIC connection; a broken connection is
    /// replaced once.
    async fn exchange_quic(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let mut last = None;
        for _ in 0..2 {
            let c = self.quic_conn().await?;
            let r = if c.h3.is_some() { self.one_h3(&c, query).await } else { self.one_doq(&c, query).await };
            match r {
                Ok(r) => return Ok(r),
                Err(e) => {
                    c.conn.close(0u32.into(), b"");
                    last = Some(e);
                }
            }
        }
        Err(last.unwrap())
    }

    /// RFC 9250: one bidirectional stream per query, 2-byte length prefix,
    /// message id 0.
    async fn one_doq(&self, c: &QuicConn, query: &[u8]) -> io::Result<Vec<u8>> {
        let e = |x: &dyn std::fmt::Display| other(format!("dns {}: {x}", self.url));
        let (mut send, mut recv) = c.conn.open_bi().await.map_err(|x| e(&x))?;
        let mut msg = (query.len() as u16).to_be_bytes().to_vec();
        msg.extend_from_slice(query);
        wire::set_id(&mut msg[2..], 0);
        send.write_all(&msg).await.map_err(|x| e(&x))?;
        let _ = send.finish();
        let mut len = [0u8; 2];
        recv.read_exact(&mut len).await.map_err(|x| e(&x))?;
        let mut resp = vec![0u8; u16::from_be_bytes(len) as usize];
        recv.read_exact(&mut resp).await.map_err(|x| e(&x))?;
        if resp.len() >= 12 {
            wire::set_id(&mut resp, wire::id(query));
        }
        Ok(resp)
    }

    async fn one_h3(&self, c: &QuicConn, query: &[u8]) -> io::Result<Vec<u8>> {
        use bytes::Buf;
        let e = |x: &dyn std::fmt::Display| other(format!("dns {}: HTTP/3: {x}", self.url));
        let mut send = c.h3.clone().unwrap();
        let authority = if self.port == 443 { self.host.clone() } else { format!("{}:{}", self.host, self.port) };
        let req = http::Request::post(format!("https://{authority}{}", self.path))
            .header("content-type", "application/dns-message")
            .header("content-length", query.len())
            .header("accept", "application/dns-message")
            .body(())
            .map_err(|x| e(&x))?;
        let mut stream = send.send_request(req).await.map_err(|x| e(&x))?;
        stream.send_data(bytes::Bytes::copy_from_slice(query)).await.map_err(|x| e(&x))?;
        stream.finish().await.map_err(|x| e(&x))?;
        let resp = stream.recv_response().await.map_err(|x| e(&x))?;
        if resp.status() != http::StatusCode::OK {
            return Err(other(format!("dns {}: HTTP {}", self.url, resp.status().as_u16())));
        }
        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.map_err(|x| e(&x))? {
            while chunk.has_remaining() {
                let n = chunk.chunk().len();
                body.extend_from_slice(chunk.chunk());
                chunk.advance(n);
            }
            if body.len() > 65535 {
                return Err(other(format!("dns {}: response too large", self.url)));
            }
        }
        Ok(body)
    }

    /// TCP / DoT / DoH over pooled keep-alive connections; a pooled
    /// connection that turns out to be dead is retried once on a new one.
    async fn exchange_stream(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        for _ in 0..2 {
            let pooled = self.pool.lock().unwrap().pop();
            let fresh = pooled.is_none();
            let mut s = match pooled {
                Some(s) => s,
                None => self.connect().await?,
            };
            // A silently dead keep-alive socket must leave time for a fresh
            // connection within the overall query deadline.
            let result = if fresh {
                self.one(&mut s, query).await
            } else {
                tokio::time::timeout(Duration::from_secs(2), self.one(&mut s, query))
                    .await.unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "stale DNS pooled connection")))
            };
            match result {
                Ok((r, reusable)) => {
                    let mut pool = self.pool.lock().unwrap();
                    if reusable && pool.len() < POOL {
                        pool.push(s);
                    }
                    return Ok(r);
                }
                Err(e) if fresh => return Err(e),
                Err(_) => continue,
            }
        }
        Err(other(format!("dns {}: failed", self.url)))
    }

    async fn one(&self, s: &mut BoxedStream, query: &[u8]) -> io::Result<(Vec<u8>, bool)> {
        if self.kind == Kind::Https {
            let host = if self.port == 443 { self.host.clone() } else { format!("{}:{}", self.host, self.port) };
            let mut req = format!(
                "POST {} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                self.path,
                query.len()
            )
            .into_bytes();
            req.extend_from_slice(query);
            crate::http::write_all(s, &req).await?;
            let resp = crate::http::read_response(s).await?;
            if resp.status != 200 {
                return Err(other(format!("dns {}: HTTP {}", self.url, resp.status)));
            }
            let reusable = !resp.header("connection").is_some_and(|c| c.split(',').any(|v| v.trim().eq_ignore_ascii_case("close")));
            // Connection: close controls reuse, not whether this answer is valid.
            return Ok((resp.body, reusable));
        }
        let mut msg = (query.len() as u16).to_be_bytes().to_vec();
        msg.extend_from_slice(query);
        s.write_all(&msg).await?;
        s.flush().await?;
        let len = s.read_u16().await? as usize;
        let mut resp = vec![0u8; len];
        s.read_exact(&mut resp).await?;
        Ok((resp, true))
    }
}

/// One UDP query to `server` (over a pinned socket), waiting for the
/// matching id.
pub async fn udp_query(server: SocketAddr, query: &[u8]) -> io::Result<Vec<u8>> {
    let sock = crate::net::udp_socket(server).await?;
    sock.send_to(query, server).await?;
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, from) = sock.recv_from(&mut buf).await?;
        if from.ip() == server.ip() && n >= 12 && wire::id(&buf[..n]) == wire::id(query) {
            return Ok(buf[..n].to_vec());
        }
    }
}

/// Resolves a DNS server hostname with the bootstrap (default) nameservers,
/// failing closed when no bootstrap is configured to avoid system DNS leaks.
pub async fn bootstrap_lookup(servers: &[SocketAddr], host: &str) -> io::Result<IpAddr> {
    if servers.is_empty() {
        return Err(other(format!("DNS bootstrap for {host} requires an explicit default-nameserver; system DNS fallback refused")));
    }
    let q = wire::query(rand::random(), host, wire::TYPE_A);
    let tries = servers.iter().map(|s| {
        let q = q.clone();
        Box::pin(async move {
            let r = tokio::time::timeout(TIMEOUT, udp_query(*s, &q)).await.map_err(|_| other("timeout"))??;
            let (ips, _) = wire::answers(&r).ok_or_else(|| other("bad response"))?;
            ips.first().map(|(ip, _)| *ip).ok_or_else(|| other(format!("{host}: no address")))
        })
    });
    futures::future::select_ok(tries).await.map(|(ip, _)| ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn up(spec: &str) -> Upstream {
        Upstream::parse(spec, Arc::new(vec![]), Arc::new(std::sync::OnceLock::new())).unwrap()
    }

    #[tokio::test]
    async fn silent_pooled_socket_retries_a_fresh_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let u = up(&format!("tcp://{}", listener.local_addr().unwrap()));
        let (stale, _silent_peer) = tokio::io::duplex(4096);
        u.pool.lock().unwrap().push(Box::new(stale));
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let len = socket.read_u16().await.unwrap();
            let mut request = vec![0; len as usize];
            socket.read_exact(&mut request).await.unwrap();
            socket.write_u16(12).await.unwrap();
            socket.write_all(&request).await.unwrap();
        });
        let answer = tokio::time::timeout(TIMEOUT, u.exchange_stream(&[0; 12])).await.unwrap().unwrap();
        assert_eq!(answer, vec![0; 12]);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn doh_connection_close_preserves_answer_without_pooling() {
        let u = up("https://1.1.1.1/dns-query");
        let (client, mut server) = tokio::io::duplex(4096);
        u.pool.lock().unwrap().push(Box::new(client));
        let task = tokio::spawn(async move {
            let mut req = vec![0; 4096];
            server.read(&mut req).await.unwrap();
            server.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nabcdefghijkl").await.unwrap();
        });
        let answer = u.exchange_stream(&[0; 12]).await.unwrap();
        assert_eq!(answer, b"abcdefghijkl");
        assert!(u.pool.lock().unwrap().is_empty());
        task.await.unwrap();
    }

    #[tokio::test]
    async fn no_implicit_system_dns() {
        let err = bootstrap_lookup(&[], "example.com").await.unwrap_err();
        assert!(err.to_string().contains("system DNS fallback refused"));
    }

    #[test]
    fn parses_mihomo_syntax() {
        let u = up("223.5.5.5");
        assert_eq!((u.kind, u.host.as_str(), u.port, u.detour.as_deref()), (Kind::Udp, "223.5.5.5", 53, None));
        let u = up("https://1.1.1.1/dns-query#PROXY");
        assert_eq!((u.kind, u.port, u.path.as_str(), u.detour.as_deref()), (Kind::Https, 443, "/dns-query", Some("PROXY")));
        let u = up("tls://dns.alidns.com");
        assert_eq!((u.kind, u.host.as_str(), u.port), (Kind::Tls, "dns.alidns.com", 853));
        let u = up("tcp://8.8.8.8:5353#DIRECT");
        assert_eq!((u.kind, u.port, u.detour.as_deref()), (Kind::Tcp, 5353, None));
        let u = up("https://doh.pub/dns-query#节点选择&h3=false");
        assert_eq!((u.kind, u.detour.as_deref()), (Kind::Https, Some("节点选择")));
        let u = up("quic://dns.adguard.com");
        assert_eq!((u.kind, u.port), (Kind::Quic, 853));
        let u = up("https://dns.alidns.com/dns-query#h3=true");
        assert_eq!((u.kind, u.port, u.detour.as_deref()), (Kind::H3, 443, None));
        let u = up("https://dns.google/dns-query#PROXY&h3=true");
        assert_eq!((u.kind, u.detour.as_deref()), (Kind::H3, Some("PROXY")));
        let u = up("h3://cloudflare-dns.com/dns-query");
        assert_eq!((u.kind, u.path.as_str()), (Kind::H3, "/dns-query"));
        assert!(Upstream::parse("dhcp://en0", Arc::new(vec![]), Arc::new(std::sync::OnceLock::new())).is_err());
    }
}
