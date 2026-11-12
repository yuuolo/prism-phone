//! V2Ray transports on top of a (TLS) stream: WebSocket, HTTPUpgrade, gRPC
//! ("gun"), HTTP/2 and xhttp, as used by VLESS, Trojan and VMess nodes.
//!
//! - WebSocket: HTTP/1.1 upgrade, then masked binary frames from the client.
//! - HTTPUpgrade: the same upgrade request, then the raw stream.
//! - gRPC: HTTP/2 `POST /<service>/Tun`, every chunk a gRPC message holding
//!   a protobuf `Hunk { bytes data = 1; }`.
//! - HTTP/2 ("h2"): one `PUT <path>` stream, raw data both ways.
//! - xhttp (Xray SplitHTTP), over HTTP/2:
//!   * stream-one: one `POST <path>/` carrying both directions;
//!   * stream-up: `GET <path>/<session>` downloads, one streaming
//!     `POST <path>/<session>` uploads;
//!   * packet-up: the same `GET`, uploads as `POST <path>/<session>/<seq>`
//!     requests of at most 1 MB;
//!   * auto: stream-one with REALITY, packet-up otherwise.
//!   Every request carries `Referer: …?x_padding=XXX…` (100-1000 X's by
//!   default), which Xray servers check.

use std::io;
use std::sync::Arc;

use base64::Engine;
use bytes::{Buf, Bytes, BytesMut};
use rand::RngCore;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common::{invalid, other, pump, BoxedStream};
use crate::config::ProxyConfig;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum XhttpMode {
    StreamOne,
    StreamUp,
    PacketUp,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Transport {
    Tcp,
    Ws { path: String, host: Option<String> },
    HttpUpgrade { path: String, host: Option<String> },
    Grpc { service: String },
    H2 { path: String, host: Option<String> },
    Xhttp { path: String, host: Option<String>, mode: XhttpMode, padding: (usize, usize) },
}

impl Transport {
    pub fn from_config(p: &ProxyConfig) -> anyhow::Result<Self> {
        let path = || {
            let path = p.ws_path.clone().filter(|x| !x.is_empty()).unwrap_or_else(|| "/".into());
            if path.starts_with('/') { path } else { format!("/{path}") }
        };
        Ok(match p.network.as_deref() {
            None | Some("") | Some("tcp") => Transport::Tcp,
            Some("ws") => Transport::Ws { path: path(), host: p.ws_host.clone() },
            Some("httpupgrade") => Transport::HttpUpgrade { path: path(), host: p.ws_host.clone() },
            Some("grpc") => Transport::Grpc { service: p.grpc_service.clone().unwrap_or_default() },
            Some("h2") => Transport::H2 { path: path(), host: p.ws_host.clone() },
            Some("xhttp") => {
                let mode = match p.xhttp_mode.as_deref().unwrap_or("auto") {
                    "stream-one" => XhttpMode::StreamOne,
                    "stream-up" => XhttpMode::StreamUp,
                    "packet-up" => XhttpMode::PacketUp,
                    "auto" | "" if p.reality_public_key.is_some() => XhttpMode::StreamOne,
                    "auto" | "" => XhttpMode::PacketUp,
                    m => anyhow::bail!("{}: xhttp mode {m} is not supported", p.name),
                };
                let padding = match p.xhttp_padding.as_deref().map(str::trim) {
                    None | Some("") => (100, 1000),
                    Some(r) => {
                        let (a, b) = r.split_once('-').unwrap_or((r, r));
                        match (a.trim().parse::<usize>(), b.trim().parse::<usize>()) {
                            (Ok(a), Ok(b)) if a <= b && b <= 8192 => (a, b),
                            _ => anyhow::bail!("{}: bad x-padding-bytes {r}", p.name),
                        }
                    }
                };
                Transport::Xhttp { path: path(), host: p.ws_host.clone(), mode, padding }
            }
            Some(n) => anyhow::bail!("{}: transport {n} is not supported by prism-core", p.name),
        })
    }

    pub fn is_tcp(&self) -> bool {
        *self == Transport::Tcp
    }

    /// ALPN to offer when the node doesn't set one: the transport only works
    /// over the matching HTTP version.
    pub fn alpn(&self) -> Vec<String> {
        match self {
            Transport::Tcp => Vec::new(),
            Transport::Ws { .. } | Transport::HttpUpgrade { .. } => vec!["http/1.1".into()],
            Transport::Grpc { .. } | Transport::H2 { .. } | Transport::Xhttp { .. } => vec!["h2".into()],
        }
    }

    /// Runs the transport over `s`; `server` is the default Host / authority.
    pub async fn wrap(&self, s: BoxedStream, server: &str) -> io::Result<BoxedStream> {
        match self {
            Transport::Tcp => Ok(s),
            Transport::Ws { path, host } => {
                let s = upgrade(s, path, host.as_deref().unwrap_or(server), true).await?;
                Ok(websocket(s))
            }
            Transport::HttpUpgrade { path, host } => upgrade(s, path, host.as_deref().unwrap_or(server), false).await,
            Transport::Grpc { service } => grpc(s, service, server).await,
            Transport::H2 { path, host } => {
                let authority = host.as_deref().unwrap_or(server);
                let client = h2_client(s, "HTTP/2").await?;
                h2_duplex(client, "PUT", &format!("https://{authority}{path}"), vec![], "HTTP/2").await
            }
            Transport::Xhttp { path, host, mode, padding } => xhttp(s, path, host.as_deref().unwrap_or(server), *mode, *padding).await,
        }
    }
}

// ------------------------------------------------------------ HTTP upgrade

/// Sends the upgrade request and reads the `101` response head byte by
/// byte, so nothing after it is consumed.
async fn upgrade(mut s: BoxedStream, path: &str, host: &str, websocket: bool) -> io::Result<BoxedStream> {
    let mut key = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut key);
    let key = base64::engine::general_purpose::STANDARD.encode(key);
    let mut req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
    );
    if websocket {
        req.push_str(&format!("Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await?;
    s.flush().await?;
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 16 * 1024 {
            return Err(invalid("transport: upgrade response too long"));
        }
        head.push(s.read_u8().await?);
    }
    let text = String::from_utf8_lossy(&head);
    let status = text.split_whitespace().nth(1).unwrap_or("");
    if status != "101" {
        let what = if websocket { "WebSocket" } else { "HTTPUpgrade" };
        return Err(other(format!("{what}: server answered HTTP {status} (check path / host)")));
    }
    if websocket {
        let want = base64::engine::general_purpose::STANDARD
            .encode(Sha1::digest(format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes()));
        let accept = text
            .lines()
            .find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("sec-websocket-accept")).map(|(_, v)| v.trim().to_string()));
        if accept.as_deref() != Some(want.as_str()) {
            return Err(invalid("WebSocket: bad Sec-WebSocket-Accept"));
        }
    }
    Ok(s)
}

/// Runs both directions of a stream. The download side decides when it is
/// over: once it ends (or fails) the upload is dropped, while an upload that
/// finishes first only ends our half and the download keeps going.
async fn both<U, D>(upload: U, download: D) -> io::Result<()>
where
    U: std::future::Future<Output = io::Result<()>>,
    D: std::future::Future<Output = io::Result<()>>,
{
    tokio::pin!(upload, download);
    tokio::select! {
        d = &mut download => d,
        u = &mut upload => match u {
            Ok(()) => download.await,
            Err(e) => Err(e),
        },
    }
}

// ------------------------------------------------------------ WebSocket

/// One client frame: FIN + `opcode`, masked.
pub fn ws_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(payload.len() + 14);
    f.push(0x80 | opcode);
    match payload.len() {
        n if n < 126 => f.push(0x80 | n as u8),
        n if n <= u16::MAX as usize => {
            f.push(0x80 | 126);
            f.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            f.push(0x80 | 127);
            f.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    let mut mask = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut mask);
    f.extend_from_slice(&mask);
    f.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    f
}

/// Reads one frame: (opcode, payload).
async fn read_frame<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> io::Result<(u8, Vec<u8>)> {
    let b0 = r.read_u8().await?;
    let b1 = r.read_u8().await?;
    let len = match b1 & 0x7f {
        126 => r.read_u16().await? as u64,
        127 => r.read_u64().await?,
        n => n as u64,
    };
    if len > 16 << 20 {
        return Err(invalid("WebSocket: frame too large"));
    }
    let mask = if b1 & 0x80 != 0 {
        let mut m = [0u8; 4];
        r.read_exact(&mut m).await?;
        Some(m)
    } else {
        None
    };
    let mut data = vec![0u8; len as usize];
    r.read_exact(&mut data).await?;
    if let Some(m) = mask {
        for (i, b) in data.iter_mut().enumerate() {
            *b ^= m[i % 4];
        }
    }
    Ok((b0 & 0x0f, data))
}

fn websocket(s: BoxedStream) -> BoxedStream {
    pump(move |local| async move {
        let (mut rd, wr) = tokio::io::split(s);
        let wr = Arc::new(tokio::sync::Mutex::new(wr));
        let (mut lrd, mut lwr) = tokio::io::split(local);
        let w = wr.clone();
        let upload = async move {
            let mut buf = vec![0u8; 32 * 1024];
            loop {
                let n = lrd.read(&mut buf).await?;
                let mut wr = w.lock().await;
                if n == 0 {
                    let _ = wr.write_all(&ws_frame(8, &1000u16.to_be_bytes())).await;
                    let _ = wr.flush().await;
                    return Ok::<_, io::Error>(());
                }
                wr.write_all(&ws_frame(2, &buf[..n])).await?;
                wr.flush().await?;
            }
        };
        let download = async move {
            loop {
                let (op, data) = match read_frame(&mut rd).await {
                    Ok(f) => f,
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(e),
                };
                match op {
                    0..=2 => lwr.write_all(&data).await?,
                    8 => break,
                    9 => {
                        let mut wr = wr.lock().await;
                        wr.write_all(&ws_frame(10, &data)).await?;
                        wr.flush().await?;
                    }
                    _ => {}
                }
            }
            lwr.shutdown().await
        };
        both(upload, download).await
    })
}

// ------------------------------------------------------------ gRPC

/// A gRPC message carrying `data` as protobuf field 1.
pub fn gun_message(data: &[u8]) -> Vec<u8> {
    let mut proto = vec![0x0a];
    let mut n = data.len() as u64;
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            proto.push(b);
            break;
        }
        proto.push(b | 0x80);
    }
    let mut m = Vec::with_capacity(5 + proto.len() + data.len());
    m.push(0);
    m.extend_from_slice(&((proto.len() + data.len()) as u32).to_be_bytes());
    m.extend_from_slice(&proto);
    m.extend_from_slice(data);
    m
}

/// Takes complete gRPC messages off the front of `buf`, returning their
/// payloads.
pub fn gun_take(buf: &mut BytesMut) -> io::Result<Vec<Bytes>> {
    let mut out = Vec::new();
    while buf.len() >= 5 {
        let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        if buf.len() < 5 + len {
            break;
        }
        buf.advance(5);
        let mut msg = buf.split_to(len);
        // Hunk: tag 0x0a, varint length, data.
        if msg.first() != Some(&0x0a) {
            return Err(invalid("gRPC: unexpected message"));
        }
        msg.advance(1);
        let (mut n, mut shift, mut used) = (0usize, 0, 0);
        for b in msg.iter() {
            n |= ((b & 0x7f) as usize) << shift;
            used += 1;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift > 28 {
                return Err(invalid("gRPC: bad length"));
            }
        }
        msg.advance(used);
        if msg.len() < n {
            return Err(invalid("gRPC: short message"));
        }
        out.push(msg.split_to(n).freeze());
    }
    Ok(out)
}

async fn grpc(s: BoxedStream, service: &str, authority: &str) -> io::Result<BoxedStream> {
    let h2err = |e: h2::Error| other(format!("gRPC: {e}"));
    let (client, conn) = h2::client::handshake(s).await.map_err(h2err)?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut client = client.ready().await.map_err(h2err)?;
    let service = service.trim_matches('/');
    let path = if service.contains('/') { format!("/{service}") } else { format!("/{service}/Tun") };
    let req = http::Request::builder()
        .method("POST")
        .uri(format!("https://{authority}{path}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("user-agent", "grpc-go/1.65.0")
        .body(())
        .map_err(|e| other(e.to_string()))?;
    let (resp, mut send) = client.send_request(req, false).map_err(h2err)?;
    Ok(pump(move |local| async move {
        let (mut lrd, mut lwr) = tokio::io::split(local);
        let upload = async move {
            let mut buf = vec![0u8; 32 * 1024];
            loop {
                let n = lrd.read(&mut buf).await?;
                if n == 0 {
                    let _ = send.send_data(Bytes::new(), true);
                    return Ok::<_, io::Error>(());
                }
                let mut data = Bytes::from(gun_message(&buf[..n]));
                while !data.is_empty() {
                    send.reserve_capacity(data.len());
                    let cap = match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
                        Some(Ok(c)) => c,
                        Some(Err(e)) => return Err(h2err(e)),
                        None => return Err(other("gRPC: stream closed")),
                    };
                    let chunk = data.split_to(cap.min(data.len()));
                    send.send_data(chunk, false).map_err(h2err)?;
                }
            }
        };
        let download = async move {
            let resp = resp.await.map_err(h2err)?;
            if resp.status() != http::StatusCode::OK {
                return Err(other(format!("gRPC: server answered HTTP {}", resp.status())));
            }
            let mut body = resp.into_body();
            let mut buf = BytesMut::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.map_err(h2err)?;
                let _ = body.flow_control().release_capacity(chunk.len());
                buf.extend_from_slice(&chunk);
                for d in gun_take(&mut buf)? {
                    lwr.write_all(&d).await?;
                }
            }
            if let Ok(Some(t)) = body.trailers().await {
                if let Some(code) = t.get("grpc-status").filter(|c| c.as_bytes() != b"0") {
                    let msg = t.get("grpc-message").map(|m| String::from_utf8_lossy(m.as_bytes()).into_owned()).unwrap_or_default();
                    return Err(other(format!("gRPC: status {} {msg}", String::from_utf8_lossy(code.as_bytes()))));
                }
            }
            lwr.shutdown().await
        };
        both(upload, download).await
    }))
}

// ------------------------------------------------------------ HTTP/2 + xhttp

const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

async fn h2_client(s: BoxedStream, what: &'static str) -> io::Result<h2::client::SendRequest<Bytes>> {
    let (client, conn) = h2::client::handshake(s).await.map_err(|e| other(format!("{what}: {e}")))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    client.ready().await.map_err(|e| other(format!("{what}: {e}")))
}

/// Sends `data` on a stream as the peer's flow control allows.
async fn h2_send(send: &mut h2::SendStream<Bytes>, mut data: Bytes, what: &str) -> io::Result<()> {
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let cap = match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
            Some(Ok(c)) => c,
            Some(Err(e)) => return Err(other(format!("{what}: {e}"))),
            None => return Err(other(format!("{what}: stream closed"))),
        };
        let chunk = data.split_to(cap.min(data.len()));
        send.send_data(chunk, false).map_err(|e| other(format!("{what}: {e}")))?;
    }
    Ok(())
}

fn h2_request(method: &str, uri: &str, headers: &[(&str, String)]) -> io::Result<http::Request<()>> {
    let mut b = http::Request::builder().method(method).uri(uri).header("user-agent", CHROME_UA);
    for (k, v) in headers {
        b = b.header(*k, v);
    }
    b.body(()).map_err(|e| other(e.to_string()))
}

/// Copies a response body to `lwr`, after checking for 200.
async fn h2_download<W: tokio::io::AsyncWrite + Unpin>(resp: h2::client::ResponseFuture, lwr: &mut W, what: &str) -> io::Result<()> {
    let h2err = |e: h2::Error| other(format!("{what}: {e}"));
    let resp = resp.await.map_err(h2err)?;
    if resp.status() != http::StatusCode::OK {
        return Err(other(format!("{what}: server answered HTTP {} (check path / host)", resp.status())));
    }
    let mut body = resp.into_body();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(h2err)?;
        let _ = body.flow_control().release_capacity(chunk.len());
        lwr.write_all(&chunk).await?;
    }
    lwr.shutdown().await
}

/// One request whose body is the upload and whose response is the download.
async fn h2_duplex(mut client: h2::client::SendRequest<Bytes>, method: &str, uri: &str, headers: Vec<(&str, String)>, what: &'static str) -> io::Result<BoxedStream> {
    let req = h2_request(method, uri, &headers)?;
    let (resp, mut send) = client.send_request(req, false).map_err(|e| other(format!("{what}: {e}")))?;
    Ok(pump(move |local| async move {
        let (mut lrd, mut lwr) = tokio::io::split(local);
        let upload = async move {
            let mut buf = vec![0u8; 32 * 1024];
            loop {
                let n = lrd.read(&mut buf).await?;
                if n == 0 {
                    let _ = send.send_data(Bytes::new(), true);
                    return Ok::<_, io::Error>(());
                }
                h2_send(&mut send, Bytes::copy_from_slice(&buf[..n]), what).await?;
            }
        };
        let download = h2_download(resp, &mut lwr, what);
        both(upload, download).await
    }))
}

/// `Referer` with the `x_padding` query Xray servers check.
fn xhttp_referer(host: &str, path: &str, padding: (usize, usize)) -> String {
    let n = rand::Rng::gen_range(&mut rand::thread_rng(), padding.0..=padding.1);
    format!("https://{host}{path}?x_padding={}", "X".repeat(n))
}

/// Path with a trailing `/`, and the query (without `?`) kept apart.
fn xhttp_path(path: &str) -> (String, Option<String>) {
    let (p, q) = match path.split_once('?') {
        Some((p, q)) => (p, Some(q.to_string()).filter(|q| !q.is_empty())),
        None => (path, None),
    };
    let mut p = if p.starts_with('/') { p.to_string() } else { format!("/{p}") };
    if !p.ends_with('/') {
        p.push('/');
    }
    (p, q)
}

/// Biggest upload request in packet-up, and the pause between them.
const XHTTP_MAX_POST: usize = 1_000_000;
const XHTTP_POST_INTERVAL: std::time::Duration = std::time::Duration::from_millis(30);
/// Upload requests in flight at once (Xray servers buffer 30 out of order).
const XHTTP_IN_FLIGHT: usize = 16;

async fn xhttp(s: BoxedStream, path: &str, host: &str, mode: XhttpMode, padding: (usize, usize)) -> io::Result<BoxedStream> {
    const WHAT: &str = "xhttp";
    let (base, query) = xhttp_path(path);
    let url = |p: String| match &query {
        Some(q) => format!("https://{host}{p}?{q}"),
        None => format!("https://{host}{p}"),
    };
    let mut client = h2_client(s, WHAT).await?;
    let referer = |p: &str| ("referer", xhttp_referer(host, p, padding));
    if mode == XhttpMode::StreamOne {
        let headers = vec![referer(&base), ("content-type", "application/grpc".to_string())];
        return h2_duplex(client, "POST", &url(base.clone()), headers, WHAT).await;
    }
    let session = uuid::Uuid::new_v4().to_string();
    let sp = format!("{base}{session}");
    let get = h2_request("GET", &url(sp.clone()), &[referer(&sp)])?;
    let (down_resp, _) = client.send_request(get, true).map_err(|e| other(format!("{WHAT}: {e}")))?;
    if mode == XhttpMode::StreamUp {
        let post = h2_request("POST", &url(sp.clone()), &[referer(&sp), ("content-type", "application/grpc".to_string())])?;
        let (up_resp, mut send) = client.send_request(post, false).map_err(|e| other(format!("{WHAT}: {e}")))?;
        tokio::spawn(async move {
            if let Ok(r) = up_resp.await {
                if r.status() != http::StatusCode::OK {
                    tracing::debug!("xhttp upload: HTTP {}", r.status());
                }
            }
        });
        return Ok(pump(move |local| async move {
            let (mut lrd, mut lwr) = tokio::io::split(local);
            let upload = async move {
                let mut buf = vec![0u8; 32 * 1024];
                loop {
                    let n = lrd.read(&mut buf).await?;
                    if n == 0 {
                        let _ = send.send_data(Bytes::new(), true);
                        return Ok::<_, io::Error>(());
                    }
                    h2_send(&mut send, Bytes::copy_from_slice(&buf[..n]), WHAT).await?;
                }
            };
            let download = h2_download(down_resp, &mut lwr, WHAT);
            both(upload, download).await
        }));
    }
    // packet-up
    let host = host.to_string();
    Ok(pump(move |local| async move {
        let (mut lrd, mut lwr) = tokio::io::split(local);
        let upload = async move {
            let slots = Arc::new(tokio::sync::Semaphore::new(XHTTP_IN_FLIGHT));
            let mut buf = vec![0u8; XHTTP_MAX_POST];
            let mut last = tokio::time::Instant::now() - XHTTP_POST_INTERVAL;
            for seq in 0u64.. {
                let mut n = lrd.read(&mut buf).await?;
                if n == 0 {
                    return Ok::<_, io::Error>(());
                }
                // Gather more until the next request may go out (an idle
                // connection sends at once), up to the size limit.
                let mut eof = false;
                let next = last + XHTTP_POST_INTERVAL;
                while n < XHTTP_MAX_POST {
                    match tokio::time::timeout_at(next, lrd.read(&mut buf[n..])).await {
                        Ok(Ok(0)) => {
                            eof = true;
                            break;
                        }
                        Ok(Ok(k)) => n += k,
                        Ok(Err(e)) => return Err(e),
                        Err(_) => break,
                    }
                }
                last = tokio::time::Instant::now();
                let p = format!("{sp}/{seq}");
                let uri = match &query {
                    Some(q) => format!("https://{host}{p}?{q}"),
                    None => format!("https://{host}{p}"),
                };
                let req = h2_request("POST", &uri, &[("referer", xhttp_referer(&host, &p, padding)), ("content-length", n.to_string())])?;
                let permit = slots.clone().acquire_owned().await.map_err(|_| other("xhttp: closed"))?;
                let mut c = client.clone().ready().await.map_err(|e| other(format!("{WHAT}: {e}")))?;
                let (resp, mut send) = c.send_request(req, false).map_err(|e| other(format!("{WHAT}: {e}")))?;
                h2_send(&mut send, Bytes::copy_from_slice(&buf[..n]), WHAT).await?;
                send.send_data(Bytes::new(), true).map_err(|e| other(format!("{WHAT}: {e}")))?;
                tokio::spawn(async move {
                    let _permit = permit;
                    match resp.await {
                        Ok(r) if r.status() == http::StatusCode::OK => {}
                        Ok(r) => tracing::debug!("xhttp upload {seq}: HTTP {}", r.status()),
                        Err(e) => tracing::debug!("xhttp upload {seq}: {e}"),
                    }
                });
                if eof {
                    return Ok(());
                }
            }
            Ok(())
        };
        let download = h2_download(down_resp, &mut lwr, WHAT);
        both(upload, download).await
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transports_from_config() {
        let mut p = ProxyConfig { name: "n".into(), ..Default::default() };
        assert_eq!(Transport::from_config(&p).unwrap(), Transport::Tcp);
        p.network = Some("ws".into());
        p.ws_path = Some("ray?ed=2048".into());
        assert_eq!(Transport::from_config(&p).unwrap(), Transport::Ws { path: "/ray?ed=2048".into(), host: None });
        p.network = Some("httpupgrade".into());
        p.ws_path = None;
        assert_eq!(Transport::from_config(&p).unwrap(), Transport::HttpUpgrade { path: "/".into(), host: None });
        p.network = Some("grpc".into());
        p.grpc_service = Some("svc".into());
        assert_eq!(Transport::from_config(&p).unwrap().alpn(), ["h2"]);
        p.network = Some("h2".into());
        assert_eq!(Transport::from_config(&p).unwrap(), Transport::H2 { path: "/".into(), host: None });
        p.network = Some("xhttp".into());
        p.ws_path = Some("xh".into());
        let t = Transport::from_config(&p).unwrap();
        assert_eq!(t, Transport::Xhttp { path: "/xh".into(), host: None, mode: XhttpMode::PacketUp, padding: (100, 1000) });
        assert_eq!(t.alpn(), ["h2"]);
        p.reality_public_key = Some("k".into());
        assert!(matches!(Transport::from_config(&p).unwrap(), Transport::Xhttp { mode: XhttpMode::StreamOne, .. }));
        p.xhttp_mode = Some("stream-up".into());
        p.xhttp_padding = Some("10-20".into());
        assert!(matches!(Transport::from_config(&p).unwrap(), Transport::Xhttp { mode: XhttpMode::StreamUp, padding: (10, 20), .. }));
        p.xhttp_mode = Some("bogus".into());
        assert!(Transport::from_config(&p).is_err());
        p.network = Some("kcp".into());
        assert!(Transport::from_config(&p).is_err());
        assert_eq!(xhttp_path("/a?ed=1"), ("/a/".to_string(), Some("ed=1".to_string())));
        assert_eq!(xhttp_path("b/"), ("/b/".to_string(), None));
        let r = xhttp_referer("h.example", "/x/", (100, 100));
        assert_eq!(r.len(), "https://h.example/x/?x_padding=".len() + 100);
    }

    #[tokio::test]
    async fn ws_frames_round_trip() {
        for n in [0usize, 5, 125, 126, 65535, 65536] {
            let data: Vec<u8> = (0..n).map(|i| i as u8).collect();
            let f = ws_frame(2, &data);
            let (op, back) = read_frame(&mut &f[..]).await.unwrap();
            assert_eq!((op, back), (2, data));
        }
    }

    #[test]
    fn gun_messages() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&gun_message(b"hello"));
        let big = vec![7u8; 300];
        buf.extend_from_slice(&gun_message(&big));
        let half = gun_message(b"x");
        buf.extend_from_slice(&half[..3]);
        let got = gun_take(&mut buf).unwrap();
        assert_eq!(got, vec![Bytes::from_static(b"hello"), Bytes::from(big)]);
        assert_eq!(buf.len(), 3, "a partial message waits for more data");
        assert_eq!(&gun_message(b"hi")[..], &[0, 0, 0, 0, 4, 0x0a, 2, b'h', b'i']);
    }
}
