//! Bandwidth test through an outbound against a local HTTP server.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Serves `size` bytes per request, `delay_ms` between 64 KiB writes.
async fn server(size: usize, delay_ms: u64) -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf).await;
                let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {size}\r\nConnection: close\r\n\r\n");
                s.write_all(head.as_bytes()).await.unwrap();
                let chunk = vec![7u8; 64 * 1024];
                let mut left = size;
                while left > 0 {
                    let n = left.min(chunk.len());
                    if s.write_all(&chunk[..n]).await.is_err() {
                        return;
                    }
                    left -= n;
                    if delay_ms > 0 {
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    }
                }
            });
        }
    });
    port
}

#[tokio::test]
async fn measures_download_speed() {
    let port = server(8 * 1024 * 1024, 0).await;
    let profile = prism_core::config::parse_any("proxies: []\nrules: [MATCH,DIRECT]\n").unwrap();
    let home = std::env::temp_dir().join(format!("prism-speed-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let core = prism_core::build(profile, &home, &prism_core::BuildEnv::standalone()).await.unwrap();
    let mut reports = 0;
    let url = format!("http://127.0.0.1:{port}/blob");
    let sp = prism_core::delay::speed_test(&core.tunnel.reg, "DIRECT", &url, Duration::from_secs(5), |_| reports += 1).await.unwrap();
    assert_eq!(sp.bytes, 8 * 1024 * 1024, "whole body read");
    assert!(sp.mbps > 50.0, "{sp:?}");
    assert!(reports >= 1);

    // A slow server: stopped at the time limit, speed about 64 KiB / 50 ms ≈ 10 Mbit/s.
    let slow = server(100 * 1024 * 1024, 50).await;
    let url = format!("http://127.0.0.1:{slow}/blob");
    let sp = prism_core::delay::speed_test(&core.tunnel.reg, "DIRECT", &url, Duration::from_secs(2), |_| {}).await.unwrap();
    assert!((1.8..2.6).contains(&sp.secs), "{sp:?}");
    assert!(sp.mbps > 4.0 && sp.mbps < 16.0, "{sp:?}");

    // HTTP errors are reported.
    let err = prism_core::delay::speed_test(&core.tunnel.reg, "DIRECT", "http://127.0.0.1:9/x", Duration::from_secs(2), |_| {}).await;
    assert!(err.is_err());
    core.shutdown.cancel();
}
