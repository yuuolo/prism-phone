//! Opt-in, independently verified Xray server; every endpoint is loopback.
//! The camouflage certificate is not a client trust override: REALITY must
//! authenticate the temporary certificate with its configured public key.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use prism_core::{
    common::Address,
    config::{ProxyConfig, ProxyKind},
    outbound::{vless::Vless, Dialer, Outbound},
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
    time::timeout,
};

const ID: &str = "0b6a0b4e-1111-4222-8333-444455556666";
const SID: &str = "0123456789abcdef";
struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn client(port: u16, public: &str, short: &str, uuid: &str, vision: bool) -> Vless {
    Vless::new(
        &ProxyConfig {
            name: "reality-interop".into(),
            kind: Some(ProxyKind::Vless),
            server: "127.0.0.1".into(),
            port,
            uuid: Some(uuid.into()),
            tls: true,
            sni: Some("reality.fixture.test".into()),
            reality_public_key: Some(public.into()),
            reality_short_id: Some(short.into()),
            flow: vision.then(|| "xtls-rprx-vision".into()),
            ..Default::default()
        },
        Dialer::Direct,
    )
    .unwrap()
}

async fn server(camouflage: u16, tcp: u16, udp: u16, vision: bool) -> (Server, u16, String) {
    let binary = PathBuf::from(
        std::env::var_os("PRISM_REALITY_SERVER_BIN").expect("Set verified Xray binary"),
    );
    assert!(binary.is_absolute() && binary.is_file());
    let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = reserved.local_addr().unwrap().port();
    let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = URL_SAFE_NO_PAD.encode(x25519_dalek::PublicKey::from(&secret).as_bytes());
    let mut user = serde_json::json!({"id":ID});
    if vision {
        user["flow"] = serde_json::json!("xtls-rprx-vision");
    }
    let config = serde_json::json!({
        "log":{"loglevel":"info"},
        "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"vless",
            "settings":{"clients":[user],"decryption":"none"},
            "streamSettings":{"network":"raw","security":"reality","realitySettings":{
                "target":format!("127.0.0.1:{camouflage}"),"serverNames":["reality.fixture.test"],
                "privateKey":URL_SAFE_NO_PAD.encode(secret.to_bytes()),"shortIds":[SID]}}}],
        "outbounds":[{"tag":"echo","protocol":"freedom","settings":{"finalRules":[{
            "action":"allow","network":"tcp,udp","ip":["127.0.0.1"],"port":format!("{tcp},{udp}")
        }]}},{"tag":"blocked","protocol":"blackhole"}],
        "routing":{"domainStrategy":"AsIs","rules":[
            {"type":"field","ip":["127.0.0.1"],"port":format!("{tcp},{udp}"),"outboundTag":"echo"},
            {"type":"field","network":"tcp,udp","outboundTag":"blocked"}]}
    });
    let dir = std::env::current_dir()
        .unwrap()
        .join("../../artifacts/reality-interop");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("server-{}-{port}.json", std::process::id()));
    std::fs::write(&path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    let mut cmd = Command::new(binary);
    cmd.args(["run", "-config"])
        .arg(&path)
        .stdout(std::fs::File::create(path.with_extension("stdout.log")).unwrap())
        .stderr(std::fs::File::create(path.with_extension("stderr.log")).unwrap());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000);
    }
    drop(reserved);
    let mut child = Server(cmd.spawn().unwrap());
    timeout(Duration::from_secs(5), async {
        loop {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "Xray exited; inspect fixture log"
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
    .unwrap();
    (child, port, public)
}

#[tokio::test]
#[ignore = "Requires PRISM_REALITY_SERVER_BIN pointing to a checksum-verified Xray"]
async fn independent_reality_and_vision_payloads_and_authentication() {
    let camouflage = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let camouflage_port = camouflage.local_addr().unwrap().port();
    let cert = rcgen::generate_simple_self_signed(vec!["reality.fixture.test".into()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert.cert.der().clone()], key)
    .unwrap();
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    tokio::spawn(async move {
        while let Ok((s, _)) = camouflage.accept().await {
            let a = acceptor.clone();
            tokio::spawn(async move {
                let _ = timeout(Duration::from_secs(5), a.accept(s)).await;
            });
        }
    });
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_port = tcp.local_addr().unwrap().port();
    let delivered = Arc::new(AtomicUsize::new(0));
    let hits = delivered.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = tcp.accept().await {
            let hits = hits.clone();
            tokio::spawn(async move {
                let mut b = [0; 16384];
                while let Ok(n) = s.read(&mut b).await {
                    if n == 0 {
                        break;
                    }
                    hits.fetch_add(n, Ordering::SeqCst);
                    if s.write_all(&b[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_port = udp.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut b = [0; 65535];
        while let Ok((n, peer)) = udp.recv_from(&mut b).await {
            let _ = udp.send_to(&b[..n], peer).await;
        }
    });
    for vision in [false, true] {
        let (_server, port, public) = server(camouflage_port, tcp_port, udp_port, vision).await;
        eprintln!("REALITY vision={vision}");
        let node = client(port, &public, SID, ID, vision);
        timeout(Duration::from_secs(8), async {
            let mut s = node
                .connect(&Address::new("127.0.0.1", tcp_port))
                .await
                .unwrap();
            let payload: Vec<u8> = (0..70000).map(|i| (i % 251) as u8).collect();
            s.write_all(&payload).await.unwrap();
            let mut echo = vec![0; payload.len()];
            s.read_exact(&mut echo).await.unwrap();
            assert_eq!(echo, payload);
        })
        .await
        .expect("REALITY TCP timeout");
        let mut pipe = timeout(
            Duration::from_secs(5),
            node.connect_udp(&Address::new("127.0.0.1", udp_port)),
        )
        .await
        .unwrap()
        .unwrap();
        for size in [1, 1200, 8000] {
            let payload = vec![size as u8; size];
            pipe.tx.send(payload.clone()).await.unwrap();
            assert_eq!(
                timeout(Duration::from_secs(5), pipe.rx.recv())
                    .await
                    .unwrap(),
                Some(payload)
            );
        }
        drop(pipe);
        let before = delivered.load(Ordering::SeqCst);
        let wrong_key = URL_SAFE_NO_PAD.encode([42u8; 32]);
        for (pk, sid, id) in [
            (&wrong_key[..], SID, ID),
            (&public[..], "fedcba9876543210", ID),
            (&public[..], SID, "1b6a0b4e-1111-4222-8333-444455556666"),
        ] {
            let bad = client(port, pk, sid, id, vision);
            let result = timeout(Duration::from_secs(5), async {
                let mut s = bad.connect(&Address::new("127.0.0.1", tcp_port)).await?;
                s.write_all(b"must not reach echo").await?;
                let mut byte = [0];
                s.read(&mut byte).await
            })
            .await;
            assert!(
                matches!(result, Ok(Err(_)) | Ok(Ok(0))),
                "bad auth must fail promptly"
            );
            assert_eq!(
                delivered.load(Ordering::SeqCst),
                before,
                "bad auth reached target"
            );
        }
    }
}
