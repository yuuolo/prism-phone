//! Hysteria 2 client (compatible with the reference server and sing-box).
//!
//! One QUIC connection per outbound, reused. After a TLS 1.3 handshake
//! (ALPN h3) the client authenticates with an HTTP/3 request
//! (`POST https://hysteria/auth`, header `Hysteria-Auth`; status 233 = OK).
//! - TCP: one bidirectional stream each:
//!   `varint 0x401, varint len, "host:port", varint len, padding`;
//!   reply `u8 status, varint len, message, varint len, padding`.
//! - UDP: QUIC datagrams `u32 session, u16 packet, u8 frag id, u8 frag
//!   count, varint len, "host:port", payload`.
//! - `obfs: salamander`: every UDP packet is `salt[8] || data XOR
//!   BLAKE2b-256(password || salt)`.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use rand::{Rng, RngCore};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

use super::{Dialer, Outbound};
use crate::common::{other, udp_pump, Address, BoxedStream, UdpPipe};
use crate::config::ProxyConfig;

const TCP_REQUEST: u64 = 0x401;
const AUTH_OK: u16 = 233;

// ------------------------------------------------------------- varints

/// QUIC variable-length integer.
pub fn put_varint(v: &mut Vec<u8>, x: u64) {
    match x {
        0..=63 => v.push(x as u8),
        64..=16383 => v.extend_from_slice(&((x as u16) | 0x4000).to_be_bytes()),
        16384..=1073741823 => v.extend_from_slice(&((x as u32) | 0x8000_0000).to_be_bytes()),
        _ => v.extend_from_slice(&(x | 0xc000_0000_0000_0000).to_be_bytes()),
    }
}

/// (value, bytes used)
pub fn get_varint(b: &[u8]) -> Option<(u64, usize)> {
    let first = *b.first()?;
    let len = 1usize << (first >> 6);
    if b.len() < len {
        return None;
    }
    let mut x = (first & 0x3f) as u64;
    for byte in &b[1..len] {
        x = (x << 8) | *byte as u64;
    }
    Some((x, len))
}

async fn read_varint<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> io::Result<u64> {
    let first = r.read_u8().await?;
    let len = 1usize << (first >> 6);
    let mut x = (first & 0x3f) as u64;
    for _ in 1..len {
        x = (x << 8) | r.read_u8().await? as u64;
    }
    Ok(x)
}

fn addr_string(a: &Address) -> String {
    match a {
        Address::Domain(d, p) => format!("{d}:{p}"),
        Address::Ip(sa) => sa.to_string(),
    }
}

fn padding(rng: &mut impl Rng, min: usize, max: usize) -> Vec<u8> {
    let n = rng.gen_range(min..max);
    (0..n).map(|_| *b"abcdefghijklmnopqrstuvwxyz0123456789".get(rng.gen_range(0..36)).unwrap()).collect()
}

// ------------------------------------------------------------ salamander

/// Salamander obfuscation over quinn's UDP socket.
struct Salamander {
    inner: Arc<dyn quinn::AsyncUdpSocket>,
    password: Vec<u8>,
}

impl fmt::Debug for Salamander {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Salamander")
    }
}

fn salamander_key(password: &[u8], salt: &[u8]) -> [u8; 32] {
    use blake2::digest::{Update, VariableOutput};
    let mut h = blake2::Blake2bVar::new(32).unwrap();
    h.update(password);
    h.update(salt);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).unwrap();
    out
}

pub fn obfuscate(password: &[u8], data: &[u8]) -> Vec<u8> {
    let mut salt = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut salt);
    let key = salamander_key(password, &salt);
    let mut out = salt.to_vec();
    out.extend(data.iter().enumerate().map(|(i, b)| b ^ key[i % 32]));
    out
}

/// In place; returns the payload length (packet minus the salt).
pub fn deobfuscate(password: &[u8], packet: &mut [u8]) -> Option<usize> {
    if packet.len() <= 8 {
        return None;
    }
    let key = salamander_key(password, &packet[..8]);
    let n = packet.len() - 8;
    for i in 0..n {
        packet[i] = packet[i + 8] ^ key[i % 32];
    }
    Some(n)
}

impl quinn::AsyncUdpSocket for Salamander {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, t: &quinn::udp::Transmit) -> io::Result<()> {
        // One datagram per transmit (GSO is off, see max_transmit_segments).
        let data = obfuscate(&self.password, t.contents);
        self.inner.try_send(&quinn::udp::Transmit { destination: t.destination, ecn: t.ecn, contents: &data, segment_size: None, src_ip: t.src_ip })
    }

    fn poll_recv(&self, cx: &mut Context, bufs: &mut [io::IoSliceMut<'_>], meta: &mut [quinn::udp::RecvMeta]) -> Poll<io::Result<usize>> {
        let n = match self.inner.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(n)) => n,
            other => return other,
        };
        for i in 0..n {
            let m = &mut meta[i];
            let buf = &mut bufs[i][..m.len];
            // Coalesced datagrams (stride < len) are deobfuscated one by one
            // and packed together.
            let stride = m.stride.max(1).min(m.len);
            let mut written = 0;
            let mut read = 0;
            let mut new_stride = 0;
            while read < m.len {
                let end = (read + stride).min(m.len);
                let mut seg = buf[read..end].to_vec();
                if let Some(len) = deobfuscate(&self.password, &mut seg) {
                    buf[written..written + len].copy_from_slice(&seg[..len]);
                    if new_stride == 0 {
                        new_stride = len;
                    }
                    written += len;
                }
                read = end;
            }
            m.len = written;
            m.stride = new_stride.max(1);
        }
        Poll::Ready(Ok(n))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

// ------------------------------------------------------------- sessions

/// Received UDP fragments of one packet.
struct Partial {
    count: u8,
    parts: Vec<Option<Bytes>>,
}

#[derive(Default)]
struct UdpMux {
    sessions: Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>,
    partial: Mutex<HashMap<(u32, u16), Partial>>,
}

impl UdpMux {
    fn deliver(&self, d: Bytes) {
        if d.len() < 8 {
            return;
        }
        let session = u32::from_be_bytes([d[0], d[1], d[2], d[3]]);
        let packet = u16::from_be_bytes([d[4], d[5]]);
        let (frag, count) = (d[6], d[7]);
        let Some((alen, used)) = get_varint(&d[8..]) else { return };
        let start = 8 + used + alen as usize;
        if start > d.len() || count == 0 || frag >= count {
            return;
        }
        let payload = if count == 1 {
            d.slice(start..).to_vec()
        } else {
            let mut partial = self.partial.lock().unwrap();
            let p = partial.entry((session, packet)).or_insert_with(|| Partial { count, parts: vec![None; count as usize] });
            if p.count != count {
                return;
            }
            p.parts[frag as usize] = Some(d.slice(start..));
            if p.parts.iter().any(|x| x.is_none()) {
                // Keep the table small: drop stale packets of this session.
                if partial.len() > 1024 {
                    partial.clear();
                }
                return;
            }
            let p = partial.remove(&(session, packet)).unwrap();
            p.parts.into_iter().flatten().flat_map(|b| b.to_vec()).collect()
        };
        if let Some(tx) = self.sessions.lock().unwrap().get(&session) {
            let _ = tx.try_send(payload);
        }
    }
}

struct Session {
    conn: quinn::Connection,
    _endpoint: quinn::Endpoint,
    /// Kept so the HTTP/3 layer doesn't close the connection.
    _h3: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    udp: Arc<UdpMux>,
}

pub struct Hysteria2 {
    name: String,
    server: String,
    port: u16,
    sni: String,
    password: String,
    skip_verify: bool,
    alpn: Vec<String>,
    obfs: Option<Vec<u8>>,
    dialer: Dialer,
    session: tokio::sync::Mutex<Option<Arc<Session>>>,
}

impl Hysteria2 {
    pub fn new(p: &ProxyConfig, dialer: Dialer) -> anyhow::Result<Self> {
        let obfs = match p.obfs.as_deref() {
            None | Some("") => None,
            Some("salamander") => Some(p.obfs_password.clone().filter(|s| !s.is_empty()).ok_or_else(|| anyhow::anyhow!("{}: salamander needs obfs-password", p.name))?.into_bytes()),
            Some(o) => anyhow::bail!("{}: hysteria2 obfs {o} is not supported", p.name),
        };
        Ok(Hysteria2 {
            name: p.name.clone(),
            server: p.server.clone(),
            port: p.port,
            sni: p.sni.clone().unwrap_or_else(|| p.server.clone()),
            password: p.password.clone().unwrap_or_default(),
            skip_verify: p.skip_cert_verify,
            alpn: if p.alpn.is_empty() { vec!["h3".into()] } else { p.alpn.clone() },
            obfs,
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
        let s = Arc::new(tokio::time::timeout(Duration::from_secs(10), self.open()).await.map_err(|_| other("hysteria2: handshake timeout"))??);
        *g = Some(s.clone());
        Ok(s)
    }

    async fn open(&self) -> io::Result<Session> {
        // Pinned to the physical interface in TUN mode, like TCP.
        let (mut socket, peer) = self.dialer.udp(&self.server, self.port).await?.into_quinn()?;
        let runtime: Arc<dyn quinn::Runtime> = Arc::new(quinn::TokioRuntime);
        if let Some(pw) = &self.obfs {
            socket = Arc::new(Salamander { inner: socket, password: pw.clone() });
        }
        let endpoint = quinn::Endpoint::new_with_abstract_socket(quinn::EndpointConfig::default(), None, socket, runtime)?;

        let tls = super::tls::tls13_config(self.skip_verify, &self.alpn)?;
        let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls)).map_err(|e| other(e.to_string()))?;
        let mut cfg = quinn::ClientConfig::new(Arc::new(quic_tls));
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(Duration::from_secs(10)));
        transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
        transport.datagram_receive_buffer_size(Some(4 << 20));
        cfg.transport_config(Arc::new(transport));

        let conn = endpoint
            .connect_with(cfg, peer, &self.sni)
            .map_err(|e| other(format!("hysteria2: {e}")))?
            .await
            .map_err(|e| other(format!("hysteria2: QUIC handshake failed: {e}")))?;

        let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn.clone())).await.map_err(|e| other(format!("hysteria2: HTTP/3: {e}")))?;
        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let pad = String::from_utf8(padding(&mut rand::thread_rng(), 256, 2048)).unwrap();
        let req = http::Request::post("https://hysteria/auth")
            .header("Hysteria-Auth", &self.password)
            .header("Hysteria-CC-RX", "0")
            .header("Hysteria-Padding", pad)
            .body(())
            .map_err(|e| other(e.to_string()))?;
        let mut stream = send.send_request(req).await.map_err(|e| other(format!("hysteria2: auth request: {e}")))?;
        stream.finish().await.map_err(|e| other(format!("hysteria2: auth request: {e}")))?;
        let resp = stream.recv_response().await.map_err(|e| other(format!("hysteria2: auth response: {e}")))?;
        if resp.status().as_u16() != AUTH_OK {
            conn.close(0u32.into(), b"");
            return Err(other(format!("hysteria2: authentication failed (HTTP {})", resp.status().as_u16())));
        }

        let udp = Arc::new(UdpMux::default());
        let (c, mux) = (conn.clone(), udp.clone());
        tokio::spawn(async move {
            while let Ok(d) = c.read_datagram().await {
                mux.deliver(d);
            }
        });
        tracing::debug!("hysteria2 {}: connected to {peer}", self.name);
        Ok(Session { conn, _endpoint: endpoint, _h3: send, udp })
    }
}

/// UDP datagrams for one packet, fragmented to fit `max`.
pub fn udp_datagrams(session: u32, packet: u16, addr: &str, payload: &[u8], max: usize) -> Vec<Vec<u8>> {
    let mut head_tail = Vec::new();
    put_varint(&mut head_tail, addr.len() as u64);
    head_tail.extend_from_slice(addr.as_bytes());
    let head = 8 + head_tail.len();
    let room = max.saturating_sub(head).max(1);
    let chunks: Vec<&[u8]> = if payload.len() + head <= max { vec![payload] } else { payload.chunks(room).collect() };
    let count = chunks.len().min(255) as u8;
    chunks
        .iter()
        .take(255)
        .enumerate()
        .map(|(i, c)| {
            let mut d = Vec::with_capacity(head + c.len());
            d.extend_from_slice(&session.to_be_bytes());
            d.extend_from_slice(&packet.to_be_bytes());
            d.push(i as u8);
            d.push(count);
            d.extend_from_slice(&head_tail);
            d.extend_from_slice(c);
            d
        })
        .collect()
}

#[async_trait]
impl Outbound for Hysteria2 {
    fn name(&self) -> &str {
        &self.name
    }
    fn api_type(&self) -> &'static str {
        "Hysteria2"
    }
    fn udp(&self) -> bool {
        true
    }

    async fn connect(&self, target: &Address) -> io::Result<BoxedStream> {
        let s = self.session().await?;
        let (mut send, mut recv) = s.conn.open_bi().await.map_err(|e| other(format!("hysteria2: {e}")))?;
        let addr = addr_string(target);
        let mut req = Vec::new();
        put_varint(&mut req, TCP_REQUEST);
        put_varint(&mut req, addr.len() as u64);
        req.extend_from_slice(addr.as_bytes());
        let pad = padding(&mut rand::thread_rng(), 64, 512);
        put_varint(&mut req, pad.len() as u64);
        req.extend_from_slice(&pad);
        send.write_all(&req).await?;
        let status = recv.read_u8().await?;
        let mlen = read_varint(&mut recv).await? as usize;
        let mut msg = vec![0u8; mlen.min(4096)];
        AsyncReadExt::read_exact(&mut recv, &mut msg).await?;
        let plen = read_varint(&mut recv).await? as usize;
        let mut skip = vec![0u8; plen.min(65536)];
        AsyncReadExt::read_exact(&mut recv, &mut skip).await?;
        if status != 0 {
            return Err(other(format!("hysteria2: server refused {addr}: {}", String::from_utf8_lossy(&msg))));
        }
        Ok(Box::new(tokio::io::join(recv, send)))
    }

    async fn connect_udp(&self, target: &Address) -> io::Result<UdpPipe> {
        let s = self.session().await?;
        let session_id: u32 = rand::random();
        let (in_tx, mut in_rx) = mpsc::channel::<Vec<u8>>(256);
        s.udp.sessions.lock().unwrap().insert(session_id, in_tx);
        let addr = addr_string(target);
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
                    let max = s.conn.max_datagram_size().unwrap_or(1200);
                    for dg in udp_datagrams(session_id, packet, &addr, &d, max) {
                        if s.conn.send_datagram(Bytes::from(dg)).is_err() {
                            return;
                        }
                    }
                    packet = packet.wrapping_add(1);
                }
            };
            tokio::select! {
                _ = recv => {}
                _ = send => {}
            }
            s.udp.sessions.lock().unwrap().remove(&session_id);
            Ok(())
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints() {
        for x in [0u64, 63, 64, 1025, 16383, 16384, 1 << 29, 1 << 40] {
            let mut v = Vec::new();
            put_varint(&mut v, x);
            assert_eq!(get_varint(&v), Some((x, v.len())));
        }
        let mut v = Vec::new();
        put_varint(&mut v, 0x401);
        assert_eq!(v, [0x44, 0x01]);
    }

    #[test]
    fn salamander_round_trip() {
        let data = b"quic packet bytes".to_vec();
        let mut wire = obfuscate(b"pw", &data);
        assert_eq!(wire.len(), data.len() + 8);
        assert_ne!(&wire[8..], &data[..]);
        let n = deobfuscate(b"pw", &mut wire).unwrap();
        assert_eq!(&wire[..n], &data[..]);
    }

    #[test]
    fn udp_fragments_reassemble() {
        let payload: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        let dgs = udp_datagrams(7, 3, "1.2.3.4:53", &payload, 1200);
        assert!(dgs.len() >= 3 && dgs.iter().all(|d| d.len() <= 1200));
        let mux = UdpMux::default();
        let (tx, mut rx) = mpsc::channel(4);
        mux.sessions.lock().unwrap().insert(7, tx);
        for d in dgs.into_iter().rev() {
            mux.deliver(Bytes::from(d));
        }
        assert_eq!(rx.try_recv().unwrap(), payload);
        // Small packets go in one datagram.
        let one = udp_datagrams(7, 4, "a.com:443", b"hi", 1200);
        assert_eq!(one.len(), 1);
        assert_eq!(&one[0][6..8], &[0, 1]);
    }
}
