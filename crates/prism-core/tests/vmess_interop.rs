//! Explicit opt-in against independently built, checksum-verified VMess servers.
//! No server binary is bundled with Prism. All listeners and allowed targets
//! are loopback-only; the fallback outbound rejects all other destinations.
use prism_core::{
    common::Address,
    config::ProxyConfig,
    outbound::{vmess::Vmess, Dialer, Outbound},
};
use std::{
    path::PathBuf,
    process::{Child, Command},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};

const ID: &str = "0b6a0b4e-1111-4222-8333-444455556666";
struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn server(tcp: u16, udp: u16, kind: &str, transport: &str) -> (Server, u16) {
    let binary = PathBuf::from(
        std::env::var_os("PRISM_VMESS_SERVER_BIN")
            .or_else(|| std::env::var_os("PRISM_XRAY_BIN"))
            .expect("Set PRISM_VMESS_SERVER_BIN to a verified server binary"),
    );
    assert!(binary.is_absolute() && binary.is_file());
    let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = reservation.local_addr().unwrap().port();
    let dir = std::env::current_dir()
        .unwrap()
        .join("../../artifacts/vmess-interop");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("server-{}-{port}.json", std::process::id()));
    let mut freedom = serde_json::json!({"tag":"echo","protocol":"freedom"});
    if kind == "xray" {
        freedom["settings"] = serde_json::json!({"finalRules":[
            {"action":"allow","network":"tcp,udp","ip":["127.0.0.1"],"port":format!("{tcp},{udp}")}
        ]});
    }
    let grpc_settings = if std::env::var("PRISM_VMESS_GRPC_DEFAULT").as_deref() == Ok("1") {
        serde_json::json!({})
    } else {
        serde_json::json!({"serviceName":"PrismVmessInterop"})
    };
    let config = serde_json::json!({
        "log":{"loglevel":"debug"},
        "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"vmess",
            "settings":{"clients":[{"id":ID,"alterId":0}]},
            "streamSettings":{"network":transport,"security":"none",
                "wsSettings":{"path":"/prism-vmess-interop"},
                "grpcSettings":grpc_settings}}],
        "outbounds":[freedom,{"tag":"blocked","protocol":"blackhole"}],
        "routing":{"domainStrategy":"AsIs","rules":[
            {"type":"field","ip":["127.0.0.1"],"port":format!("{tcp},{udp}"),"outboundTag":"echo"},
            {"type":"field","network":"tcp,udp","outboundTag":"blocked"}]}
    });
    std::fs::write(&path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    let mut command = Command::new(binary);
    command
        .args(["run", if kind == "v2fly" { "-c" } else { "-config" }])
        .arg(&path)
        .stdout(std::fs::File::create(path.with_extension("stdout.log")).unwrap())
        .stderr(std::fs::File::create(path.with_extension("log")).unwrap());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    drop(reservation);
    let mut child = Server(command.spawn().unwrap());
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "VMess server exited; inspect its fixture log"
            );
            if tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("VMess server did not start");
    (child, port)
}

fn client(port: u16, cipher: &str, uuid: &str, transport: &str, path: &str) -> Vmess {
    Vmess::new(
        &ProxyConfig {
            name: "interop".into(),
            server: "127.0.0.1".into(),
            port,
            uuid: Some(uuid.into()),
            cipher: Some(cipher.into()),
            network: Some(transport.into()),
            ws_path: Some(path.into()),
            ws_host: Some("vmess.fixture.test".into()),
            grpc_service: (transport == "grpc" && !path.is_empty()).then(|| path.into()),
            ..Default::default()
        },
        Dialer::Direct,
    )
    .unwrap()
}

#[tokio::test]
#[ignore = "Requires PRISM_VMESS_SERVER_BIN and PRISM_VMESS_SERVER_KIND (xray/v2fly)"]
async fn independent_server_tcp_udp_and_bad_credentials() {
    let kind = std::env::var("PRISM_VMESS_SERVER_KIND").unwrap_or_else(|_| "xray".into());
    assert!(matches!(kind.as_str(), "xray" | "v2fly"));
    let transport = std::env::var("PRISM_VMESS_TRANSPORT").unwrap_or_else(|_| "tcp".into());
    assert!(matches!(transport.as_str(), "tcp" | "ws" | "grpc"));
    let default_service = std::env::var("PRISM_VMESS_GRPC_DEFAULT").as_deref() == Ok("1");
    assert!(!default_service || transport == "grpc");
    let endpoint = if transport == "grpc" {
        if default_service {
            ""
        } else {
            "PrismVmessInterop"
        }
    } else {
        "/prism-vmess-interop"
    };
    // Keep the large-datagram probe separate and explicit: V2Fly 5.53.0's
    // packet writer uses a 2048-byte buffer. A passing common-size run does
    // not establish large-datagram interoperability with that server.
    let large_udp = std::env::var("PRISM_VMESS_LARGE_UDP").as_deref() == Ok("1");
    let udp_sizes: &[usize] = if large_udp {
        &[1, 1200, 8000]
    } else {
        &[1, 1200, 1900]
    };
    eprintln!("server={kind}, transport={transport}, default_service={default_service}, large_udp={large_udp}");
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_port = tcp.local_addr().unwrap().port();
    let delivered = Arc::new(AtomicUsize::new(0));
    let received = delivered.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = tcp.accept().await {
            let received = received.clone();
            tokio::spawn(async move {
                let (mut r, mut w) = stream.into_split();
                let mut bytes = [0; 16384];
                while let Ok(n) = r.read(&mut bytes).await {
                    if n == 0 {
                        break;
                    }
                    received.fetch_add(n, Ordering::SeqCst);
                    if w.write_all(&bytes[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_port = udp.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = vec![0; 65535];
        while let Ok((n, peer)) = udp.recv_from(&mut buf).await {
            let _ = udp.send_to(&buf[..n], peer).await;
        }
    });
    let (_server, port) = server(tcp_port, udp_port, &kind, &transport).await;
    // Xray 26.11.9 does not accept none/zero security types. V2Fly independently
    // exercises those formats; neither server's accepted set is fabricated.
    let ciphers: &[&str] = if kind == "v2fly" {
        &["auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"]
    } else {
        &["auto", "aes-128-gcm", "chacha20-poly1305"]
    };
    for &cipher in ciphers {
        eprintln!("checking {kind}: {cipher}");
        let node = client(port, cipher, ID, &transport, endpoint);
        let payload: Vec<u8> = (0..70000).map(|i| (i % 251) as u8).collect();
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut stream = node
                .connect(&Address::new("127.0.0.1", tcp_port))
                .await
                .unwrap();
            stream.write_all(&payload).await.unwrap();
            let mut reply = vec![0; payload.len()];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, payload, "TCP {cipher}");
        })
        .await
        .unwrap_or_else(|_| panic!("TCP timed out: {cipher}"));
        let mut pipe = node
            .connect_udp(&Address::new("127.0.0.1", udp_port))
            .await
            .unwrap();
        for &size in udp_sizes {
            let datagram = vec![size as u8; size];
            pipe.tx.send(datagram.clone()).await.unwrap();
            let reply = tokio::time::timeout(Duration::from_secs(5), pipe.rx.recv())
                .await
                .unwrap_or_else(|_| panic!("UDP timed out: {cipher}/{size}"));
            assert_eq!(reply, Some(datagram), "UDP {cipher}/{size}");
        }
    }
    let before_bad = delivered.load(Ordering::SeqCst);
    let bad = client(
        port,
        "auto",
        "1b6a0b4e-1111-4222-8333-444455556666",
        &transport,
        endpoint,
    );
    let received = tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = bad.connect(&Address::new("127.0.0.1", tcp_port)).await?;
        stream.write_all(b"wrong credential must not echo").await?;
        let mut byte = [0];
        stream.read(&mut byte).await
    })
    .await;
    assert!(
        !matches!(received, Ok(Ok(n)) if n > 0),
        "Wrong UUID forwarded payload"
    );
    assert_eq!(
        delivered.load(Ordering::SeqCst),
        before_bad,
        "Wrong UUID reached the target"
    );
    if transport == "ws" {
        let wrong_path = client(port, "auto", ID, &transport, "/wrong-prism-path");
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            wrong_path.connect(&Address::new("127.0.0.1", tcp_port)),
        )
        .await;
        assert!(
            matches!(result, Ok(Err(_))),
            "Wrong WS path must fail the upgrade"
        );
        assert_eq!(
            delivered.load(Ordering::SeqCst),
            before_bad,
            "Wrong WS path reached the target"
        );
    }
    if transport == "grpc" {
        let bad_service = client(port, "auto", ID, &transport, "WrongPrismService");
        let rejected = tokio::time::timeout(Duration::from_secs(5), async {
            let mut stream = bad_service
                .connect(&Address::new("127.0.0.1", tcp_port))
                .await?;
            stream
                .write_all(b"wrong gRPC service must not reach target")
                .await?;
            stream.read(&mut [0u8; 1]).await
        })
        .await;
        assert!(
            matches!(rejected, Ok(Err(_)) | Ok(Ok(0))),
            "Wrong service must be rejected promptly"
        );
        assert_eq!(
            delivered.load(Ordering::SeqCst),
            before_bad,
            "Wrong gRPC service reached target"
        );
    }
}
