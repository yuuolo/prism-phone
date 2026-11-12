//! TUIC v5 client (compatible with tuic-server, sing-box and mihomo).
//!
//! One QUIC connection per outbound, reused. Right after the handshake the
//! client authenticates on a unidirectional stream:
//! `ver(5) cmd(0) uuid[16] token[32]`, where token is the TLS exporter with
//! label = the UUID bytes and context = the password.
//! - TCP: one bidirectional stream each, `5 1 addr`, then data both ways.
//! - UDP: `5 2 assoc(u16) packet(u16) frag_total(u8) frag_id(u8) size(u16)
//!   addr payload`, as QUIC datagrams (`udp-relay-mode: native`, fragmented
//!   to fit) or one unidirectional stream per packet (`quic`). A session
//!   ends with `5 3 assoc` on a unidirectional stream.
//! - Heartbeat: datagram `5 4` every 10 s.
//!
//! Addresses: `0 len name port`, `1 v4 port`, `2 v6 port`, `0xff` (none,
//! for the later fragments of a packet).

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::mpsc;

use super::{Dialer, Outbound};
use crate::common::{invalid, other, udp_pump, Address, BoxedStream, UdpPipe};
use crate::config::ProxyConfig;

const VERSION: u8 = 5;
const CMD_AUTH: u8 = 0;
const CMD_CONNECT: u8 = 1;
const CMD_PACKET: u8 = 2;
const CMD_DISSOCIATE: u8 = 3;
const CMD_HEARTBEAT: u8 = 4;

pub fn put_addr(v: &mut Vec<u8>, a: Option<&Address>) {
    match a {
        None => v.push(0xff),
        Some(Address::Domain(d, p)) => {
            v.push(0);
            v.push(d.len().min(255) as u8);
            v.extend_from_slice(&d.as_bytes()[..d.len().min(255)]);
            v.extend_from_slice(&p.to_be_bytes());
        }
        Some(Address::Ip(SocketAddr::V4(sa))) => {
            v.push(1);
            v.extend_from_slice(&sa.ip().octets());
            v.extend_from_slice(&sa.port().to_be_bytes());
        }
        Some(Address::Ip(SocketAddr::V6(sa))) => {
            v.push(2);
            v.extend_from_slice(&sa.ip().octets());
            v.extend_from_slice(&sa.port().to_be_bytes());
        }
    }
}

/// (address, bytes used); `Ok(None)` for the "none" address.
fn get_addr(b: &[u8]) -> io::Result<(Option<Address>, usize)> {
    let short = || invalid("tuic: short address");
    let port_at = |i: usize| -> io::Result<u16> { Ok(u16::from_be_bytes([*b.get(i).ok_or_else(short)?, *b.get(i + 1).ok_or_else(short)?])) };
    match *b.first().ok_or_else(short)? {
        0xff => Ok((None, 1)),
        0 => {
            let n = *b.get(1).ok_or_else(short)? as usize;
            let name = std::str::from_utf8(b.get(2..2 + n).ok_or_else(short)?).map_err(|_| invalid("tuic: bad domain"))?;
            Ok((Some(Address::new(name, port_at(2 + n)?)), 4 + n))
        }
        1 => {
            let o: [u8; 4] = b.get(1..5).ok_or_else(short)?.try_into().unwrap();
            Ok((Some(Address::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(o)), port_at(5)?))), 7))
        }
        2 => {
            let o: [u8; 16] = b.get(1..17).ok_or_else(short)?.try_into().unwrap();
            Ok((Some(Address::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(o)), port_at(17)?))), 19))
        }
        t => Err(invalid(format!("tuic: bad address type {t}"))),
    }
}

/// The packet messages for one UDP payload, fragmented so each fits `max`
/// (`None` = no limit, for stream mode).
pub fn packet_messages(assoc: u16, packet: u16, target: &Address, payload: &[u8], max: Option<usize>) -> Vec<Vec<u8>> {
    let mut addr = Vec::new();
    put_addr(&mut addr, Some(target));
    let head = 10 + addr.len();
    let room = max.map(|m| m.saturating_sub(head).max(1)).unwrap_or(usize::MAX);
    let chunks: Vec<&[u8]> = if payload.len() <= room { vec![payload] } else { payload.chunks(room).collect() };
    let total = chunks.len().min(255);
    chunks
        .iter()
        .take(255)
        .enumerate()
        .map(|(i, c)| {
            let mut m = Vec::with_capacity(head + c.len());
            m.extend_from_slice(&[VERSION, CMD_PACKET]);
            m.extend_from_slice(&assoc.to_be_bytes());
            m.extend_from_slice(&packet.to_be_bytes());
            m.push(total as u8);
            m.push(i as u8);
            m.extend_from_slice(&(c.len() as u16).to_be_bytes());
            if i == 0 {
                m.extend_from_slice(&addr);
            } else {
                m.push(0xff);
            }
            m.extend_from_slice(c);
            m
        })
        .collect()
}

struct Partial {
    total: u8,
    parts: Vec<Option<Vec<u8>>>,
}

/// UDP sessions of one connection, by association id.
#[derive(Default)]
struct UdpMux {
    sessions: Mutex<HashMap<u16, mpsc::Sender<Vec<u8>>>>,
    partial: Mutex<HashMap<(u16, u16), Partial>>,
}

impl UdpMux {
    /// A received message (without the `5 2` prefix).
    fn deliver(&self, b: &[u8]) {
        if b.len() < 8 {
            return;
        }
        let assoc = u16::from_be_bytes([b[0], b[1]]);
        let packet = u16::from_be_bytes([b[2], b[3]]);
        let (total, id) = (b[4], b[5]);
        let size = u16::from_be_bytes([b[6], b[7]]) as usize;
        let Ok((_, used)) = get_addr(&b[8..]) else { return };
        let Some(data) = b.get(8 + used..8 + used + size) else { return };
        if total == 0 || id >= total {
            return;
        }
        let payload = if total == 1 {
            data.to_vec()
        } else {
            let mut partial = self.partial.lock().unwrap();
            let p = partial.entry((assoc, packet)).or_insert_with(|| Partial { total, parts: vec![None; total as usize] });
            if p.total != total {
                return;
            }
            p.parts[id as usize] = Some(data.to_vec());
            if p.parts.iter().any(|x| x.is_none()) {
                if partial.len() > 1024 {
                    partial.clear();
                }
                return;
            }
            partial.remove(&(assoc, packet)).unwrap().parts.into_iter().flatten().flatten().collect()
        };
        if let Some(tx) = self.sessions.lock().unwrap().get(&assoc) {
            let _ = tx.try_send(payload);
        }
    }
}

struct Session {
    conn: quinn::Connection,
    _endpoint: quinn::Endpoint,
    udp: Arc<UdpMux>,
    next_assoc: AtomicU16,
}

pub struct Tuic {
    name: String,
    server: String,
    port: u16,
    sni: String,
    uuid: [u8; 16],
    password: String,
    skip_verify: bool,
    alpn: Vec<String>,
    congestion: String,
    /// UDP over streams (`udp-relay-mode: quic`) instead of datagrams.
    udp_streams: bool,
    dialer: Dialer,
    session: tokio::sync::Mutex<Option<Arc<Session>>>,
}

impl Tuic {
    pub fn new(p: &ProxyConfig, dialer: Dialer) -> anyhow::Result<Self> {
        let uuid = uuid::Uuid::parse_str(p.uuid.as_deref().unwrap_or("")).map_err(|_| anyhow::anyhow!("{}: invalid uuid", p.name))?;
        let congestion = p.congestion.clone().unwrap_or_else(|| "cubic".into()).to_ascii_lowercase();
        if !matches!(congestion.as_str(), "cubic" | "new_reno" | "newreno" | "bbr") {
            anyhow::bail!("{}: congestion-controller {congestion} is not supported", p.name);
        }
        let udp_streams = match p.udp_relay_mode.as_deref() {
            None | Some("") | Some("native") => false,
            Some("quic") => true,
            Some(m) => anyhow::bail!("{}: udp-relay-mode {m} is not supported", p.name),
        };
        Ok(Tuic {
            name: p.name.clone(),
            server: p.server.clone(),
            port: p.port,
            sni: p.sni.clone().unwrap_or_else(|| p.server.clone()),
            uuid: *uuid.as_bytes(),
            password: p.password.clone().unwrap_or_default(),
            skip_verify: p.skip_cert_verify,
            alpn: if p.alpn.is_empty() { vec!["h3".into()] } else { p.alpn.clone() },
            congestion,
            udp_streams,
            dialer,
            session: tokio::sync::Mutex::new(None),
        })
    }

    async fn session(&self) -> io::Result<Arc<Session>> {
        let mut g = self.session.lock().await;
        if let Some(s) = g.as_ref() {
            if s.conn.close_reason().is_none() {
                return Ok(s.clone());
            }
        }
        let s = Arc::new(tokio::time::timeout(Duration::from_secs(10), self.open()).await.map_err(|_| other("tuic: handshake timeout"))??);
        *g = Some(s.clone());
        Ok(s)
    }

    async fn open(&self) -> io::Result<Session> {
        let (socket, peer) = self.dialer.udp(&self.server, self.port).await?.into_quinn()?;
        let runtime: Arc<dyn quinn::Runtime> = Arc::new(quinn::TokioRuntime);
        let endpoint = quinn::Endpoint::new_with_abstract_socket(quinn::EndpointConfig::default(), None, socket, runtime)?;

        let tls = super::tls::tls13_config(self.skip_verify, &self.alpn)?;
        let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls)).map_err(|e| other(e.to_string()))?;
        let mut cfg = quinn::ClientConfig::new(Arc::new(quic_tls));
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(Duration::from_secs(10)));
        transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
        transport.datagram_receive_buffer_size(Some(4 << 20));
        match self.congestion.as_str() {
            "bbr" => transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default())),
            "new_reno" | "newreno" => transport.congestion_controller_factory(Arc::new(quinn::congestion::NewRenoConfig::default())),
            _ => transport.congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default())),
        };
        cfg.transport_config(Arc::new(transport));

        let conn = endpoint
            .connect_with(cfg, peer, &self.sni)
            .map_err(|e| other(format!("tuic: {e}")))?
            .await
            .map_err(|e| other(format!("tuic: QUIC handshake failed: {e}")))?;

        let mut token = [0u8; 32];
        conn.export_keying_material(&mut token, &self.uuid, self.password.as_bytes())
            .map_err(|_| other("tuic: TLS exporter unavailable"))?;
        let mut auth = vec![VERSION, CMD_AUTH];
        auth.extend_from_slice(&self.uuid);
        auth.extend_from_slice(&token);
        let mut s = conn.open_uni().await.map_err(|e| other(format!("tuic: {e}")))?;
        s.write_all(&auth).await.map_err(|e| other(format!("tuic: auth: {e}")))?;
        let _ = s.finish();

        let udp = Arc::new(UdpMux::default());
        let (c, mux) = (conn.clone(), udp.clone());
        tokio::spawn(async move {
            while let Ok(d) = c.read_datagram().await {
                if d.len() >= 2 && d[0] == VERSION && d[1] == CMD_PACKET {
                    mux.deliver(&d[2..]);
                }
            }
        });
        let (c, mux) = (conn.clone(), udp.clone());
        tokio::spawn(async move {
            while let Ok(mut s) = c.accept_uni().await {
                let mux = mux.clone();
                tokio::spawn(async move {
                    if let Ok(m) = s.read_to_end(70_000).await {
                        if m.len() >= 2 && m[0] == VERSION && m[1] == CMD_PACKET {
                            mux.deliver(&m[2..]);
                        }
                    }
                });
            }
        });
        let c = conn.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                if c.close_reason().is_some() || c.send_datagram(Bytes::from_static(&[VERSION, CMD_HEARTBEAT])).is_err() {
                    return;
                }
            }
        });
        tracing::debug!("tuic {}: connected to {}:{}", self.name, self.server, self.port);
        Ok(Session { conn, _endpoint: endpoint, udp, next_assoc: AtomicU16::new(rand::random()) })
    }
}

#[async_trait]
impl Outbound for Tuic {
    fn name(&self) -> &str {
        &self.name
    }
    fn api_type(&self) -> &'static str {
        "Tuic"
    }
    fn udp(&self) -> bool {
        true
    }

    async fn connect(&self, target: &Address) -> io::Result<BoxedStream> {
        let s = self.session().await?;
        let (mut send, recv) = s.conn.open_bi().await.map_err(|e| other(format!("tuic: {e}")))?;
        let mut req = vec![VERSION, CMD_CONNECT];
        put_addr(&mut req, Some(target));
        send.write_all(&req).await.map_err(|e| other(format!("tuic: {e}")))?;
        Ok(Box::new(tokio::io::join(recv, send)))
    }

    async fn connect_udp(&self, target: &Address) -> io::Result<UdpPipe> {
        let s = self.session().await?;
        let assoc = s.next_assoc.fetch_add(1, Ordering::Relaxed);
        let (in_tx, mut in_rx) = mpsc::channel::<Vec<u8>>(256);
        s.udp.sessions.lock().unwrap().insert(assoc, in_tx);
        let (target, streams) = (target.clone(), self.udp_streams);
        Ok(udp_pump(move |mut out, inc| async move {
            let mut packet: u16 = 0;
            let recv = async {
                while let Some(d) = in_rx.recv().await {
                    if inc.send(d).await.is_err() {
                        break;
                    }
                }
            };
            let send = async {
                while let Some(d) = out.recv().await {
                    if streams {
                        let Ok(mut u) = s.conn.open_uni().await else { return };
                        for m in packet_messages(assoc, packet, &target, &d, None) {
                            if u.write_all(&m).await.is_err() {
                                return;
                            }
                        }
                        let _ = u.finish();
                    } else {
                        // QUIC datagrams can't be split by the network, so
                        // big packets are fragmented here.
                        let max = s.conn.max_datagram_size().unwrap_or(1200);
                        for m in packet_messages(assoc, packet, &target, &d, Some(max)) {
                            if s.conn.send_datagram(Bytes::from(m)).is_err() {
                                return;
                            }
                        }
                    }
                    packet = packet.wrapping_add(1);
                }
            };
            tokio::select! {
                _ = recv => {}
                _ = send => {}
            }
            s.udp.sessions.lock().unwrap().remove(&assoc);
            if let Ok(mut u) = s.conn.open_uni().await {
                let mut m = vec![VERSION, CMD_DISSOCIATE];
                m.extend_from_slice(&assoc.to_be_bytes());
                let _ = u.write_all(&m).await;
                let _ = u.finish();
            }
            Ok(())
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses() {
        for a in [Address::new("example.com", 443), Address::new("1.2.3.4", 53), Address::new("[2001:db8::1]", 8443)] {
            let mut v = Vec::new();
            put_addr(&mut v, Some(&a));
            assert_eq!(get_addr(&v).unwrap(), (Some(a), v.len()));
        }
        assert_eq!(get_addr(&[0xff]).unwrap(), (None, 1));
        let mut v = Vec::new();
        put_addr(&mut v, Some(&Address::new("a.com", 80)));
        assert_eq!(v, [0, 5, b'a', b'.', b'c', b'o', b'm', 0, 80]);
    }

    #[test]
    fn fragments_reassemble() {
        let payload: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        let target = Address::new("1.2.3.4", 53);
        let msgs = packet_messages(9, 4, &target, &payload, Some(1200));
        assert!(msgs.len() >= 3 && msgs.iter().all(|m| m.len() <= 1200));
        assert!(msgs[1..].iter().all(|m| m[10] == 0xff), "later fragments carry no address");
        let mux = UdpMux::default();
        let (tx, mut rx) = mpsc::channel(4);
        mux.sessions.lock().unwrap().insert(9, tx);
        for m in msgs.iter().rev() {
            mux.deliver(&m[2..]);
        }
        assert_eq!(rx.try_recv().unwrap(), payload);
        let one = packet_messages(9, 5, &target, b"hi", Some(1200));
        assert_eq!(one.len(), 1);
        assert_eq!(&one[0][6..8], &[1, 0]);
        mux.deliver(&one[0][2..]);
        assert_eq!(rx.try_recv().unwrap(), b"hi");
    }
}
