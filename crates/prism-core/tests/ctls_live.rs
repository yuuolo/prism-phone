//! Opt-in, real network: the Chrome-style TLS client against public sites.
//!   PRISM_TLS_LIVE=1 cargo test -p prism-core --test ctls_live -- --nocapture
use std::time::Duration;

use prism_core::outbound::ctls::{self, Config};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn get(host: &str, path: &str) -> Result<(Option<String>, String), String> {
    let tcp = tokio::time::timeout(Duration::from_secs(8), prism_core::net::tcp_connect(host, 443))
        .await
        .map_err(|_| "connect timeout".to_string())?
        .map_err(|e| format!("connect: {e}"))?;
    let cfg = Config { server_name: host.into(), alpn: vec!["http/1.1".into()], skip_verify: false, reality: None };
    let mut s = tokio::time::timeout(Duration::from_secs(10), ctls::connect(tcp, &cfg))
        .await
        .map_err(|_| "handshake timeout".to_string())?
        .map_err(|e| format!("handshake: {e} ({:?})", e.kind()))?;
    let alpn = s.alpn.clone();
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n").as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let mut body = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut body)).await;
    Ok((alpn, String::from_utf8_lossy(&body).into_owned()))
}

#[tokio::test]
async fn public_sites() {
    if std::env::var("PRISM_TLS_LIVE").is_err() {
        return;
    }
    for (host, path) in [
        ("www.cloudflare.com", "/cdn-cgi/trace"),
        ("www.bing.com", "/"),
        ("github.com", "/"),
        ("www.baidu.com", "/"),
        ("www.qq.com", "/"),
        ("www.microsoft.com", "/"),
        ("tls.peet.ws", "/api/all"),
    ] {
        match get(host, path).await {
            Ok((alpn, body)) => {
                let status = body.lines().next().unwrap_or("").to_string();
                println!("OK   {host:22} alpn={alpn:?} {status} ({} bytes)", body.len());
                if host == "www.cloudflare.com" {
                    for l in body.lines().filter(|l| l.starts_with("kex=") || l.starts_with("tls=")) {
                        println!("     {l}");
                    }
                }
                if host == "tls.peet.ws" {
                    for key in ["\"ja4\"", "\"ja3_hash\"", "\"peetprint_hash\"", "\"akamai_fingerprint_hash\""] {
                        if let Some(i) = body.find(key) {
                            println!("     {}", &body[i..(i + 90).min(body.len())].split(',').next().unwrap_or(""));
                        }
                    }
                }
            }
            Err(e) => println!("FAIL {host:22} {e}"),
        }
    }
}
