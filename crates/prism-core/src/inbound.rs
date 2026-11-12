//! Mixed inbound: SOCKS5 and HTTP proxy (CONNECT + plain HTTP) on one port.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::common::{invalid, Address};
use crate::hub::Hub;
use crate::tunnel::{Metadata, Network, Tunnel, UdpNat, UdpPacket};

/// SOCKS5 UDP relay on the mixed port: `RSV(2) FRAG(1) ADDR PORT DATA`.
/// Fragmented datagrams are dropped.
pub async fn serve_udp(sock: tokio::net::UdpSocket, hub: Arc<Hub>) {
    let sock = Arc::new(sock);
    let (reply_tx, mut reply_rx) = tokio::sync::mpsc::channel::<UdpPacket>(1024);
    let out = sock.clone();
    tokio::spawn(async move {
        while let Some(p) = reply_rx.recv().await {
            let mut pkt = vec![0, 0, 0];
            p.dst.write_socks(&mut pkt);
            pkt.extend_from_slice(&p.data);
            let _ = out.send_to(&pkt, p.src).await;
        }
    });
    let nat = UdpNat::new("Socks5", reply_tx);
    let mut buf = vec![0u8; 65535];
    loop {
        let Ok((n, src)) = sock.recv_from(&mut buf).await else { continue };
        if n < 4 || buf[2] != 0 {
            continue;
        }
        let mut cur = &buf[3..n];
        let Ok(dst) = Address::read_socks(&mut cur).await else { continue };
        let data = cur.to_vec();
        nat.send(&hub.core().tunnel, UdpPacket { src, dst, data });
    }
}

pub async fn serve(listener: TcpListener, hub: Arc<Hub>) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!("accept: {e}");
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let tunnel = hub.core().tunnel.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, peer, tunnel).await {
                tracing::debug!("inbound {peer}: {e}");
            }
        });
    }
}

async fn handle(stream: TcpStream, peer: SocketAddr, tunnel: Arc<Tunnel>) -> io::Result<()> {
    let mut first = [0u8; 1];
    if stream.peek(&mut first).await? == 0 {
        return Ok(());
    }
    if first[0] == 5 {
        socks5(stream, peer, tunnel).await
    } else {
        http(stream, peer, tunnel).await
    }
}

async fn socks5(mut s: TcpStream, peer: SocketAddr, tunnel: Arc<Tunnel>) -> io::Result<()> {
    let mut head = [0u8; 2];
    s.read_exact(&mut head).await?;
    let mut methods = vec![0u8; head[1] as usize];
    s.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        s.write_all(&[5, 0xff]).await?;
        return Err(invalid("socks5: client requires authentication"));
    }
    s.write_all(&[5, 0]).await?;
    let mut req = [0u8; 3];
    s.read_exact(&mut req).await?;
    let dst = Address::read_socks(&mut s).await?;
    if req[1] == 3 {
        // UDP ASSOCIATE: datagrams go to the UDP socket on the same port
        // (see serve_udp); the association lasts while this connection is open.
        let mut reply = vec![5, 0, 0];
        Address::Ip(s.local_addr()?).write_socks(&mut reply);
        s.write_all(&reply).await?;
        let mut sink = [0u8; 256];
        while s.read(&mut sink).await? > 0 {}
        return Ok(());
    }
    if req[1] != 1 {
        s.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        return Err(invalid(format!("socks5: unsupported command {}", req[1])));
    }
    let mut meta = Metadata::new(Network::Tcp, "Socks5", peer, dst, None);
    match tunnel.dial(&mut meta).await {
        Ok(d) => {
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            tunnel.relay(s, d, meta, &[]).await;
        }
        Err(_) => {
            s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        }
    }
    Ok(())
}

async fn http(mut s: TcpStream, peer: SocketAddr, tunnel: Arc<Tunnel>) -> io::Result<()> {
    // Read the request head.
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > 64 * 1024 {
            return Err(invalid("http: request head too large"));
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let rest = buf[head_end..].to_vec();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let (method, uri, version) = (
        parts.next().unwrap_or_default().to_string(),
        parts.next().unwrap_or_default().to_string(),
        parts.next().unwrap_or("HTTP/1.1").to_string(),
    );
    let headers: Vec<(String, String)> = lines
        .filter(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
        .collect();

    if method.eq_ignore_ascii_case("CONNECT") {
        let dst = Address::parse_authority(&uri).ok_or_else(|| invalid("http: bad CONNECT target"))?;
        let mut meta = Metadata::new(Network::Tcp, "HTTPS", peer, dst, None);
        match tunnel.dial(&mut meta).await {
            Ok(d) => {
                s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
                tunnel.relay(s, d, meta, &rest).await;
            }
            Err(e) => {
                let body = format!("prism: {e}");
                let resp = format!("HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                s.write_all(resp.as_bytes()).await?;
            }
        }
        return Ok(());
    }

    // Plain HTTP proxy request: absolute-form URI -> origin-form.
    let (host, path) = match uri.strip_prefix("http://") {
        Some(r) => match r.find('/') {
            Some(i) => (r[..i].to_string(), r[i..].to_string()),
            None => (r.to_string(), "/".to_string()),
        },
        None => {
            let h = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("host")).map(|(_, v)| v.clone());
            match h {
                Some(h) => (h, uri.clone()),
                None => {
                    s.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n").await?;
                    return Ok(());
                }
            }
        }
    };
    let dst = Address::parse_authority(&host).unwrap_or_else(|| Address::new(&host, 80));
    let mut out = format!("{method} {path} {version}\r\n");
    for (k, v) in &headers {
        let lk = k.to_ascii_lowercase();
        if lk == "proxy-connection" || lk == "proxy-authorization" || lk == "connection" || lk == "keep-alive" {
            continue;
        }
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    // One upstream per client connection: ask both sides not to reuse it for
    // other hosts.
    out.push_str("Connection: close\r\n\r\n");
    let mut initial = out.into_bytes();
    initial.extend_from_slice(&rest);

    let mut meta = Metadata::new(Network::Tcp, "HTTP", peer, dst, None);
    match tunnel.dial(&mut meta).await {
        Ok(d) => tunnel.relay(s, d, meta, &initial).await,
        Err(e) => {
            let body = format!("prism: {e}");
            let resp = format!("HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            s.write_all(resp.as_bytes()).await?;
        }
    }
    Ok(())
}
