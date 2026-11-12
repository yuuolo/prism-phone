//! DIRECT, REJECT and upstream SOCKS5 / HTTP proxies.

use std::io;

use async_trait::async_trait;
use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::tls::Tls;
use super::{Dialer, Outbound};
use crate::common::{invalid, other, tcp_connect, udp_pump, Address, BoxedStream, UdpPipe};
use crate::config::ProxyConfig;

pub struct Direct;

#[async_trait]
impl Outbound for Direct {
    fn name(&self) -> &str {
        "DIRECT"
    }
    fn api_type(&self) -> &'static str {
        "Direct"
    }
    fn udp(&self) -> bool {
        true
    }
    async fn connect(&self, target: &Address) -> io::Result<BoxedStream> {
        let s = tcp_connect(&target.host(), target.port()).await?;
        Ok(Box::new(s))
    }
    async fn connect_udp(&self, target: &Address) -> io::Result<UdpPipe> {
        let addr = *crate::net::resolve(&target.host(), target.port())
            .await?
            .iter()
            .min_by_key(|a| a.is_ipv6())
            .ok_or_else(|| other("no address"))?;
        let sock = crate::net::udp_socket(addr).await?;
        sock.connect(addr).await?;
        Ok(udp_pump(move |mut out, inc| async move {
            let mut buf = vec![0u8; 65535];
            loop {
                tokio::select! {
                    p = out.recv() => match p {
                        Some(p) => { sock.send(&p).await?; }
                        None => return Ok(()),
                    },
                    r = sock.recv(&mut buf) => {
                        let n = r?;
                        if inc.send(buf[..n].to_vec()).await.is_err() {
                            return Ok(());
                        }
                    }
                }
            }
        }))
    }
}

pub struct Reject;

#[async_trait]
impl Outbound for Reject {
    fn name(&self) -> &str {
        "REJECT"
    }
    fn api_type(&self) -> &'static str {
        "Reject"
    }
    async fn connect(&self, _: &Address) -> io::Result<BoxedStream> {
        Err(io::Error::new(io::ErrorKind::ConnectionRefused, "rejected by rule"))
    }
}

async fn dial(dialer: &Dialer, server: &str, port: u16, tls: &Option<Tls>) -> io::Result<BoxedStream> {
    let tcp = dialer.tcp(server, port).await?;
    Ok(match tls {
        Some(t) => Box::new(t.wrap(tcp).await?),
        None => Box::new(tcp),
    })
}

fn tls_of(p: &ProxyConfig) -> io::Result<Option<Tls>> {
    if !p.tls {
        return Ok(None);
    }
    Tls::new(p.sni.as_deref().unwrap_or(&p.server), p.skip_cert_verify, &p.alpn, None).map(Some)
}

pub struct Socks5 {
    name: String,
    server: String,
    port: u16,
    auth: Option<(String, String)>,
    tls: Option<Tls>,
    dialer: Dialer,
}

impl Socks5 {
    pub fn new(p: &ProxyConfig, dialer: Dialer) -> io::Result<Self> {
        Ok(Socks5 {
            name: p.name.clone(),
            server: p.server.clone(),
            port: p.port,
            auth: p.username.clone().map(|u| (u, p.password.clone().unwrap_or_default())),
            tls: tls_of(p)?,
            dialer,
        })
    }
}

#[async_trait]
impl Outbound for Socks5 {
    fn name(&self) -> &str {
        &self.name
    }
    fn api_type(&self) -> &'static str {
        "Socks5"
    }
    fn udp(&self) -> bool {
        true
    }
    async fn connect(&self, target: &Address) -> io::Result<BoxedStream> {
        self.request(1, target).await.map(|(s, _)| s)
    }
    async fn connect_udp(&self, target: &Address) -> io::Result<UdpPipe> {
        // UDP ASSOCIATE; the relay address comes back in the reply.
        let unspecified = Address::Ip("0.0.0.0:0".parse().unwrap());
        let (mut ctrl, bound) = self.request(3, &unspecified).await?;
        let (relay_host, relay_port) = match &bound {
            Address::Ip(sa) if !sa.ip().is_unspecified() => (sa.ip().to_string(), sa.port()),
            other_addr => (self.server.clone(), other_addr.port()),
        };
        let (tx, mut rx) = self.dialer.udp(&relay_host, relay_port).await?.split();
        let target = target.clone();
        Ok(udp_pump(move |mut out, inc| async move {
            let mut buf = vec![0u8; 65535];
            let mut ctl = [0u8; 64];
            loop {
                tokio::select! {
                    p = out.recv() => match p {
                        Some(p) => {
                            let mut pkt = vec![0, 0, 0];
                            target.write_socks(&mut pkt);
                            pkt.extend_from_slice(&p);
                            tx.send(&pkt).await?;
                        }
                        None => return Ok(()),
                    },
                    r = rx.recv(&mut buf) => {
                        let n = r?;
                        let mut cur = &buf[3.min(n)..n];
                        if Address::read_socks(&mut cur).await.is_err() {
                            continue;
                        }
                        if inc.send(cur.to_vec()).await.is_err() {
                            return Ok(());
                        }
                    }
                    // The association lives as long as the TCP connection.
                    r = ctrl.read(&mut ctl) => {
                        if matches!(r, Ok(0) | Err(_)) {
                            return Ok(());
                        }
                    }
                }
            }
        }))
    }
}

impl Socks5 {
    /// Handshake + request (`cmd` 1 = CONNECT, 3 = UDP ASSOCIATE); returns
    /// the stream and the bound address from the reply.
    async fn request(&self, cmd: u8, target: &Address) -> io::Result<(BoxedStream, Address)> {
        let mut s = dial(&self.dialer, &self.server, self.port, &self.tls).await?;
        let method = if self.auth.is_some() { 2u8 } else { 0u8 };
        s.write_all(&[5, 1, method]).await?;
        let mut rep = [0u8; 2];
        s.read_exact(&mut rep).await?;
        if rep[0] != 5 || rep[1] != method {
            return Err(other("socks5: no acceptable auth method"));
        }
        if let Some((u, pw)) = &self.auth {
            let mut b = vec![1, u.len() as u8];
            b.extend_from_slice(u.as_bytes());
            b.push(pw.len() as u8);
            b.extend_from_slice(pw.as_bytes());
            s.write_all(&b).await?;
            s.read_exact(&mut rep).await?;
            if rep[1] != 0 {
                return Err(other("socks5: authentication failed"));
            }
        }
        let mut req = vec![5, cmd, 0];
        target.write_socks(&mut req);
        s.write_all(&req).await?;
        let mut head = [0u8; 3];
        s.read_exact(&mut head).await?;
        if head[1] != 0 {
            return Err(other(format!("socks5: request failed (code {})", head[1])));
        }
        let bound = Address::read_socks(&mut s).await?;
        Ok((s, bound))
    }
}

pub struct Http {
    name: String,
    server: String,
    port: u16,
    auth: Option<String>,
    tls: Option<Tls>,
    dialer: Dialer,
}

impl Http {
    pub fn new(p: &ProxyConfig, dialer: Dialer) -> io::Result<Self> {
        Ok(Http {
            name: p.name.clone(),
            server: p.server.clone(),
            port: p.port,
            auth: p.username.as_ref().map(|u| {
                base64::engine::general_purpose::STANDARD
                    .encode(format!("{u}:{}", p.password.clone().unwrap_or_default()))
            }),
            tls: tls_of(p)?,
            dialer,
        })
    }
}

#[async_trait]
impl Outbound for Http {
    fn name(&self) -> &str {
        &self.name
    }
    fn api_type(&self) -> &'static str {
        "Http"
    }
    async fn connect(&self, target: &Address) -> io::Result<BoxedStream> {
        let mut s = dial(&self.dialer, &self.server, self.port, &self.tls).await?;
        let host = match target {
            Address::Ip(sa) => sa.to_string(),
            Address::Domain(d, p) => format!("{d}:{p}"),
        };
        let mut req = format!("CONNECT {host} HTTP/1.1\r\nHost: {host}\r\n");
        if let Some(a) = &self.auth {
            req.push_str(&format!("Proxy-Authorization: Basic {a}\r\n"));
        }
        req.push_str("\r\n");
        s.write_all(req.as_bytes()).await?;
        // Read the response head byte by byte so no tunneled data is consumed.
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            if head.len() > 8192 {
                return Err(invalid("http proxy: response too long"));
            }
            head.push(s.read_u8().await?);
        }
        let line = String::from_utf8_lossy(&head);
        let status = line.split_whitespace().nth(1).unwrap_or("");
        if status != "200" {
            return Err(other(format!("http proxy: CONNECT returned {status}")));
        }
        Ok(s)
    }
}
