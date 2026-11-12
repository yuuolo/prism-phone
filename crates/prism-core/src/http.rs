//! Minimal HTTP/1.1 client: used for DNS-over-HTTPS and provider downloads
//! (optionally through an outbound).

use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::common::{other, Address, BoxedStream};
use crate::outbound::tls::Tls;
use crate::outbound::Outbound;

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// Reads one response. Without Content-Length or chunked encoding the body
/// runs to EOF (only valid when the request said `Connection: close`).
pub async fn read_response<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<Response> {
    let mut head = Vec::with_capacity(512);
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 32 * 1024 {
            return Err(other("http: response head too long"));
        }
        head.push(s.read_u8().await?);
    }
    let text = String::from_utf8_lossy(&head);
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    if !status_line.starts_with("HTTP/") {
        return Err(other("http: bad response"));
    }
    let status = status_line.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let get = |n: &str| headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v.clone());
    let mut body = Vec::new();
    if status == 204 || status == 304 {
    } else if get("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
        loop {
            let mut line = Vec::new();
            while !line.ends_with(b"\r\n") {
                line.push(s.read_u8().await?);
            }
            let size_text = String::from_utf8_lossy(&line[..line.len() - 2]).into_owned();
            let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
                .map_err(|_| other("http: bad chunk size"))?;
            if size == 0 {
                // optional trailer lines, then an empty line
                loop {
                    let mut t = Vec::new();
                    while !t.ends_with(b"\r\n") {
                        t.push(s.read_u8().await?);
                    }
                    if t == b"\r\n" {
                        break;
                    }
                }
                break;
            }
            let start = body.len();
            body.resize(start + size, 0);
            s.read_exact(&mut body[start..]).await?;
            let mut crlf = [0u8; 2];
            s.read_exact(&mut crlf).await?;
        }
    } else if let Some(len) = get("content-length").and_then(|v| v.parse::<usize>().ok()) {
        body.resize(len, 0);
        s.read_exact(&mut body).await?;
    } else {
        s.read_to_end(&mut body).await?;
    }
    Ok(Response { status, headers, body })
}

/// Opens a (TLS) connection to `host:port`, directly or through `via`.
pub async fn connect(host: &str, port: u16, https: bool, via: Option<&Arc<dyn Outbound>>) -> io::Result<BoxedStream> {
    let raw: BoxedStream = match via {
        Some(o) => o.connect(&Address::new(host, port)).await?,
        None => Box::new(crate::net::tcp_connect(host, port).await?),
    };
    if https {
        Ok(Box::new(Tls::new(host, false, &["http/1.1".to_string()], None)?.wrap(raw).await?))
    } else {
        Ok(raw)
    }
}

/// GET with redirects. `via` routes the request through an outbound.
pub async fn get(url: &str, via: Option<&Arc<dyn Outbound>>, user_agent: &str, timeout: Duration) -> io::Result<Response> {
    tokio::time::timeout(timeout, async {
        let mut url = url::Url::parse(url).map_err(|e| other(format!("bad url {url}: {e}")))?;
        for _ in 0..5 {
            let https = match url.scheme() {
                "https" => true,
                "http" => false,
                s => return Err(other(format!("unsupported scheme {s}"))),
            };
            let host = url.host_str().ok_or_else(|| other("url without host"))?.to_string();
            let port = url.port_or_known_default().unwrap_or(if https { 443 } else { 80 });
            let path = match url.query() {
                Some(q) => format!("{}?{q}", url.path()),
                None => url.path().to_string(),
            };
            let host_header = if url.port().is_some() { format!("{host}:{port}") } else { host.clone() };
            let mut s = connect(&host, port, https, via).await?;
            let req = format!(
                "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: {user_agent}\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
            );
            write_all(&mut s, req.as_bytes()).await?;
            let resp = read_response(&mut s).await?;
            if (300..400).contains(&resp.status) {
                if let Some(loc) = resp.header("location") {
                    url = url.join(loc).map_err(|e| other(format!("bad redirect: {e}")))?;
                    continue;
                }
            }
            return Ok(resp);
        }
        Err(other("too many redirects"))
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "http timeout"))?
}

pub async fn write_all<S: AsyncWrite + Unpin>(s: &mut S, data: &[u8]) -> io::Result<()> {
    s.write_all(data).await?;
    s.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn parses_lengths_and_chunks() {
        let mut a: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX: y\r\n\r\nhelloEXTRA";
        let r = read_response(&mut a).await.unwrap();
        assert_eq!((r.status, &r.body[..], r.header("x")), (200, &b"hello"[..], Some("y")));
        assert_eq!(a, b"EXTRA"); // keep-alive: nothing beyond the body consumed

        let mut c: &[u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nwiki\r\n5;x=1\r\npedia\r\n0\r\n\r\n";
        let r = read_response(&mut c).await.unwrap();
        assert_eq!(r.body, b"wikipedia");

        let mut e: &[u8] = b"HTTP/1.0 200 OK\r\n\r\nto-eof";
        assert_eq!(read_response(&mut e).await.unwrap().body, b"to-eof");
    }
}
