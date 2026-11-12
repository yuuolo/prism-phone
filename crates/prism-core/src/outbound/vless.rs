//! VLESS over TCP, TLS or REALITY (optionally over WebSocket, HTTPUpgrade
//! or gRPC), with optional XTLS Vision
//! (`flow: xtls-rprx-vision`).
//!
//! Request:  ver(0) uuid[16] addons_len addons cmd(1=tcp, 2=udp, 3=mux) [port u16 BE atyp addr]
//!           addons: protobuf, field 1 = flow; mux requests carry no address
//! Response: ver addons_len addons... then payload (Vision: padded at first).
//!
//! Vision servers refuse cmd 2, so Vision UDP goes over a mux request as
//! XUDP frames (one UDP session per connection, session id 0):
//!   u16 meta_len | sid u16 | status(1 new, 2 keep, 3 end, 4 keepalive) |
//!   option(1 = data follows) | net(2 = udp) port atyp addr | [u16 len data]

use std::io;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::ctls::{self, Reality};
use super::tls::Tls;
use super::transport::Transport;
use super::vision::VisionStream;
use super::{Dialer, Outbound};
use crate::common::{pump, udp_over_stream, udp_pump, Address, BoxedStream, Framing, UdpPipe};
use crate::config::ProxyConfig;

const VISION: &str = "xtls-rprx-vision";

enum Security {
    Plain,
    Tls(Tls),
    /// The Chrome-style client: REALITY, or TLS when Vision needs to reach
    /// the raw socket.
    Ctls(ctls::Config),
}

pub struct Vless {
    name: String,
    server: String,
    port: u16,
    uuid: [u8; 16],
    vision: bool,
    security: Security,
    transport: Transport,
    /// Host header / gRPC authority.
    host: String,
    dialer: Dialer,
}

impl Vless {
    pub fn new(p: &ProxyConfig, dialer: Dialer) -> anyhow::Result<Self> {
        let vision = match p.flow.as_deref() {
            None | Some("") => false,
            Some(f) if f == VISION || f == "xtls-rprx-vision-udp443" => true,
            Some(f) => anyhow::bail!("{}: VLESS flow {f} is not supported (only {VISION})", p.name),
        };
        let uuid = uuid::Uuid::parse_str(p.uuid.as_deref().unwrap_or("")).map_err(|_| anyhow::anyhow!("{}: invalid uuid", p.name))?;
        let sni = p.sni.clone().unwrap_or_else(|| p.server.clone());
        let transport = Transport::from_config(p)?;
        if vision && !transport.is_tcp() {
            anyhow::bail!("{}: {VISION} only works over plain TCP, not {}", p.name, p.network.as_deref().unwrap_or(""));
        }
        let alpn = match (p.alpn.is_empty(), transport.is_tcp()) {
            (false, _) => p.alpn.clone(),
            (true, true) => vec!["h2".to_string(), "http/1.1".to_string()],
            (true, false) => transport.alpn(),
        };
        let host = p.ws_host.clone().unwrap_or_else(|| if p.tls { sni.clone() } else { p.server.clone() });
        let security = if let Some(pk) = &p.reality_public_key {
            let reality = Reality::parse(pk, p.reality_short_id.as_deref().unwrap_or(""))
                .ok_or_else(|| anyhow::anyhow!("{}: invalid reality-opts public-key / short-id", p.name))?;
            Security::Ctls(ctls::Config { server_name: sni, alpn, skip_verify: true, reality: Some(reality) })
        } else if p.tls && vision {
            Security::Ctls(ctls::Config { server_name: sni, alpn, skip_verify: p.skip_cert_verify, reality: None })
        } else if p.tls {
            Security::Tls(Tls::new(&sni, p.skip_cert_verify, &alpn, p.fingerprint.as_deref())?)
        } else {
            if vision {
                anyhow::bail!("{}: {VISION} needs TLS or REALITY", p.name);
            }
            Security::Plain
        };
        Ok(Vless { name: p.name.clone(), server: p.server.clone(), port: p.port, uuid: *uuid.as_bytes(), vision, security, transport, host, dialer })
    }

    /// Connection with TLS / REALITY and the transport (WebSocket, gRPC...).
    async fn dial(&self) -> io::Result<BoxedStream> {
        let s: BoxedStream = match &self.security {
            Security::Plain => self.dialer.tcp(&self.server, self.port).await?,
            Security::Tls(t) => t.connect(&self.dialer, &self.server, self.port).await?,
            Security::Ctls(cfg) => Box::new(ctls::connect(self.dialer.tcp(&self.server, self.port).await?, cfg).await?),
        };
        self.transport.wrap(s, &self.host).await
    }
}

/// VLESS / mux address: port, then atyp (1 = v4, 2 = domain, 3 = v6) + addr.
fn put_addr(h: &mut Vec<u8>, target: &Address) {
    h.extend_from_slice(&target.port().to_be_bytes());
    match target {
        Address::Ip(std::net::SocketAddr::V4(sa)) => {
            h.push(1);
            h.extend_from_slice(&sa.ip().octets());
        }
        Address::Domain(d, _) => {
            h.push(2);
            h.push(d.len() as u8);
            h.extend_from_slice(d.as_bytes());
        }
        Address::Ip(std::net::SocketAddr::V6(sa)) => {
            h.push(3);
            h.extend_from_slice(&sa.ip().octets());
        }
    }
}

/// Request header; `cmd` 1 = TCP, 2 = UDP, 3 = mux (no address).
fn header(uuid: &[u8; 16], flow: Option<&str>, cmd: u8, target: &Address) -> Vec<u8> {
    let mut h = vec![0u8];
    h.extend_from_slice(uuid);
    match flow {
        Some(f) => {
            let addons_len = 2 + f.len();
            h.push(addons_len as u8);
            h.push(0x0a); // field 1, length-delimited
            h.push(f.len() as u8);
            h.extend_from_slice(f.as_bytes());
        }
        None => h.push(0),
    }
    h.push(cmd);
    if cmd != CMD_MUX {
        put_addr(&mut h, target);
    }
    h
}

const CMD_MUX: u8 = 3;

/// One XUDP frame carrying `data` to `target` (`first`: opens the session).
pub fn xudp_frame(first: bool, target: &Address, data: &[u8]) -> Vec<u8> {
    let mut meta = vec![0, 0, if first { 1 } else { 2 }, 1, 2];
    put_addr(&mut meta, target);
    let mut f = Vec::with_capacity(meta.len() + data.len() + 4);
    f.extend_from_slice(&(meta.len() as u16).to_be_bytes());
    f.extend_from_slice(&meta);
    f.extend_from_slice(&(data.len() as u16).to_be_bytes());
    f.extend_from_slice(data);
    f
}

/// A UDP session as XUDP frames over a (Vision) mux connection.
fn xudp<S>(s: S, target: Address) -> UdpPipe
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    udp_pump(move |mut out, inc| async move {
        let (mut rd, mut wr) = tokio::io::split(s);
        let reader = tokio::spawn(async move {
            let res: io::Result<()> = async {
                loop {
                    let mlen = rd.read_u16().await? as usize;
                    let mut meta = vec![0u8; mlen];
                    rd.read_exact(&mut meta).await?;
                    if meta.len() < 4 {
                        return Err(crate::common::invalid("xudp: short frame"));
                    }
                    let (status, option) = (meta[2], meta[3]);
                    let data = if option & 1 == 1 {
                        let len = rd.read_u16().await? as usize;
                        let mut d = vec![0u8; len];
                        rd.read_exact(&mut d).await?;
                        Some(d)
                    } else {
                        None
                    };
                    match status {
                        3 => return Ok(()),
                        2 => {
                            if let Some(d) = data {
                                if inc.send(d).await.is_err() {
                                    return Ok(());
                                }
                            }
                        }
                        _ => {} // keepalive / unexpected new
                    }
                }
            }
            .await;
            if let Err(e) = res {
                if e.kind() != io::ErrorKind::UnexpectedEof {
                    tracing::debug!("xudp reader: {e}");
                }
            }
        });
        let res: io::Result<()> = async {
            let mut first = true;
            while let Some(p) = out.recv().await {
                let p = &p[..p.len().min(u16::MAX as usize)];
                wr.write_all(&xudp_frame(first, &target, p)).await?;
                wr.flush().await?;
                first = false;
            }
            Ok(())
        }
        .await;
        reader.abort();
        res
    })
}

async fn finish<S>(mut s: S, head: Vec<u8>, skip_response: bool) -> io::Result<BoxedStream>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    s.write_all(&head).await?;
    s.flush().await?;
    let (mut rd, mut wr) = tokio::io::split(s);
    Ok(pump(move |local| async move {
        let (mut lrd, mut lwr) = tokio::io::split(local);
        let upload = async move {
            tokio::io::copy(&mut lrd, &mut wr).await?;
            wr.shutdown().await
        };
        let download = async move {
            if skip_response {
                let mut resp = [0u8; 2];
                rd.read_exact(&mut resp).await?;
                let mut addons = vec![0u8; resp[1] as usize];
                rd.read_exact(&mut addons).await?;
            }
            tokio::io::copy(&mut rd, &mut lwr).await?;
            lwr.shutdown().await
        };
        tokio::try_join!(upload, download)?;
        Ok(())
    }))
}

#[async_trait]
impl Outbound for Vless {
    fn name(&self) -> &str {
        &self.name
    }
    fn api_type(&self) -> &'static str {
        "Vless"
    }
    fn udp(&self) -> bool {
        true
    }
    async fn connect(&self, target: &Address) -> io::Result<BoxedStream> {
        if self.vision {
            let Security::Ctls(cfg) = &self.security else { unreachable!() };
            let tls = ctls::connect(self.dialer.tcp(&self.server, self.port).await?, cfg).await?;
            // The header goes out plain (Vision pads what follows); the
            // stream skips the response header itself.
            let mut v = VisionStream::new(tls, self.uuid);
            v.write_header(&header(&self.uuid, Some(VISION), 1, target)).await?;
            return finish(v, Vec::new(), false).await;
        }
        let s = self.dial().await?;
        finish(s, header(&self.uuid, None, 1, target), true).await
    }
    async fn connect_udp(&self, target: &Address) -> io::Result<UdpPipe> {
        if self.vision {
            let Security::Ctls(cfg) = &self.security else { unreachable!() };
            let tls = ctls::connect(self.dialer.tcp(&self.server, self.port).await?, cfg).await?;
            let mut v = VisionStream::new(tls, self.uuid);
            v.write_header(&header(&self.uuid, Some(VISION), CMD_MUX, target)).await?;
            return Ok(xudp(v, target.clone()));
        }
        let mut s = self.dial().await?;
        s.write_all(&header(&self.uuid, None, 2, target)).await?;
        s.flush().await?;
        Ok(udp_over_stream(s, Framing::Vless))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_with_flow() {
        let h = header(&[1; 16], Some(VISION), 1, &Address::Domain("a.com".into(), 443));
        assert_eq!(h[17], 18);
        assert_eq!(&h[18..20], &[0x0a, 16]);
        assert_eq!(&h[20..36], VISION.as_bytes());
        assert_eq!(&h[36..40], &[1, 1, 187, 2]);
        let plain = header(&[1; 16], None, 2, &Address::Domain("a.com".into(), 53));
        assert_eq!(plain[17], 0);
        let mux = header(&[1; 16], Some(VISION), CMD_MUX, &Address::Domain("a.com".into(), 53));
        assert_eq!(mux.len(), 37, "mux requests end at the command");
        assert_eq!(mux[36], 3);
    }

    #[test]
    fn xudp_frames() {
        let t = Address::new("1.2.3.4", 53);
        assert_eq!(xudp_frame(true, &t, b"hi"), [0, 12, 0, 0, 1, 1, 2, 0, 53, 1, 1, 2, 3, 4, 0, 2, b'h', b'i']);
        assert_eq!(xudp_frame(false, &t, b"")[4], 2);
    }
}
