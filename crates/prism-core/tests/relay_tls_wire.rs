//! Protocol-composition fixtures, isolated on loopback. Self-signed TLS is
//! accepted ONLY by these core test profiles, as in anytls_wire.rs. Android
//! rejects skip-cert-verify and independently tests certificate failure.
use prism_core::{
    common::Address,
    config::{parse_any, GroupConfig, GroupKind, Profile, ProxyConfig, ProxyKind, RuleConfig},
    hub::Hub,
    inbound,
    tunnel::{Metadata, Network},
};
use sha2::{Digest, Sha224, Sha256};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tokio_util::sync::CancellationToken;

fn tls() -> TlsAcceptor {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert.cert.der().clone()], key)
    .unwrap();
    TlsAcceptor::from(Arc::new(config))
}
async fn crlf(s: &mut TlsStream<TcpStream>) {
    let mut bytes = [0; 2];
    s.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"\r\n");
}
fn target() -> Address {
    Address::new("203.0.113.9", 443)
}
async fn trojan(mut s: TlsStream<TcpStream>, hits: Arc<AtomicUsize>) {
    let mut auth = [0; 56];
    s.read_exact(&mut auth).await.unwrap();
    assert_eq!(
        auth.as_slice(),
        hex::encode(Sha224::digest(b"pw")).as_bytes()
    );
    crlf(&mut s).await;
    let cmd = s.read_u8().await.unwrap();
    assert_eq!(
        Address::read_socks(&mut s).await.unwrap().to_string(),
        target().to_string()
    );
    crlf(&mut s).await;
    if cmd == 3 {
        assert_eq!(
            Address::read_socks(&mut s).await.unwrap().to_string(),
            target().to_string()
        );
        assert_eq!(s.read_u16().await.unwrap(), 4);
        crlf(&mut s).await;
    } else {
        assert_eq!(cmd, 1)
    }
    let mut data = [0; 4];
    s.read_exact(&mut data).await.unwrap();
    assert_eq!(&data, b"ping");
    let mut response = Vec::new();
    if cmd == 3 {
        target().write_socks(&mut response);
        response.extend_from_slice(&[0, 4, 13, 10]);
    }
    response.extend_from_slice(b"pong");
    hits.fetch_add(1, Ordering::Relaxed);
    s.write_all(&response).await.unwrap();
    s.flush().await.unwrap();
}
async fn frame(s: &mut TlsStream<TcpStream>, cmd: u8, sid: u32, data: &[u8]) {
    let mut out = vec![cmd];
    out.extend_from_slice(&sid.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    s.write_all(&out).await.unwrap();
    s.flush().await.unwrap();
}
async fn anytls(mut s: TlsStream<TcpStream>, hits: Arc<AtomicUsize>) {
    let mut auth = [0; 32];
    s.read_exact(&mut auth).await.unwrap();
    assert_eq!(auth.as_slice(), Sha256::digest(b"pw").as_slice());
    let n = s.read_u16().await.unwrap();
    s.read_exact(&mut vec![0; n as usize]).await.unwrap();
    // sid -> (UDP-over-TCP, request header still pending, buffered stream data)
    let mut streams: HashMap<u32, (bool, bool, Vec<u8>)> = HashMap::new();
    loop {
        let mut head = [0; 7];
        if s.read_exact(&mut head).await.is_err() {
            return;
        }
        let sid = u32::from_be_bytes(head[1..5].try_into().unwrap());
        let n = u16::from_be_bytes(head[5..7].try_into().unwrap()) as usize;
        let mut data = vec![0; n];
        s.read_exact(&mut data).await.unwrap();
        match head[0] {
            0 | 1 => {}
            4 => frame(&mut s, 10, 0, b"v=2").await,
            8 => frame(&mut s, 9, sid, &data).await,
            3 => {
                streams.remove(&sid);
                frame(&mut s, 3, sid, &[]).await
            }
            2 => {
                if !streams.contains_key(&sid) {
                    let mut src = &data[..];
                    let dst = Address::read_socks(&mut src).await.unwrap();
                    assert!(src.is_empty());
                    let udp = dst.to_string() == "sp.v2.udp-over-tcp.arpa:0";
                    if !udp {
                        assert_eq!(dst.to_string(), target().to_string())
                    }
                    assert!(streams.len() < 16);
                    streams.insert(sid, (udp, udp, Vec::new()));
                    frame(&mut s, 7, sid, &[]).await;
                    continue;
                }
                let (udp, request, buffer) = streams.get_mut(&sid).unwrap();
                buffer.extend_from_slice(&data);
                assert!(buffer.len() < 1024);
                if *request {
                    if buffer.len() < 8 {
                        continue;
                    }
                    assert_eq!(&buffer[..8], &[1, 1, 203, 0, 113, 9, 1, 187]);
                    buffer.drain(..8);
                    *request = false;
                }
                let required = if *udp { 6 } else { 4 };
                if buffer.len() < required {
                    continue;
                }
                if *udp {
                    assert_eq!(&buffer[..6], b"\0\x04ping");
                    hits.fetch_add(1, Ordering::Relaxed);
                    frame(&mut s, 2, sid, b"\0\x04pong").await
                } else {
                    assert_eq!(&buffer[..4], b"ping");
                    hits.fetch_add(1, Ordering::Relaxed);
                    frame(&mut s, 2, sid, b"pong").await
                }
                buffer.drain(..required);
            }
            other => panic!("Unexpected AnyTLS command {other}"),
        }
    }
}
async fn composition(kind: ProxyKind) {
    for first_kind in [ProxyKind::Http, ProxyKind::Socks5] {
        let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first_port = first.local_addr().unwrap().port();
        let direct = Hub::new(
            Default::default(),
            ".".into(),
            parse_any("proxies: []\nrules: ['MATCH,DIRECT']\nfind-process-mode: off").unwrap(),
        )
        .await
        .unwrap();
        let stop = CancellationToken::new();
        let assoc = inbound::UdpAssociations::new(stop.clone());
        let forward = tokio::spawn(inbound::serve_managed(
            first,
            direct.clone(),
            stop.clone(),
            assoc,
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = tls();
        let hits = Arc::new(AtomicUsize::new(0));
        let seen = hits.clone();
        let server = tokio::spawn(async move {
            let mut children = JoinSet::new();
            loop {
                tokio::select! {
                    client=listener.accept()=>{
                        let (socket,_)=client.unwrap();assert!(children.len()<16);let acceptor=acceptor.clone();let hits=seen.clone();
                        children.spawn(async move {let stream=acceptor.accept(socket).await.unwrap();if kind==ProxyKind::AnyTls {anytls(stream,hits).await}else{trojan(stream,hits).await}});
                    },
                    done=children.join_next(),if !children.is_empty()=>{done.unwrap().unwrap();}
                }
            }
        });
        let mut profile = Profile::default();
        profile.dns.enable = false;
        profile.general.find_process_mode = "off".into();
        profile.proxies = vec![
            ProxyConfig {
                name: "first".into(),
                kind: Some(first_kind),
                server: "127.0.0.1".into(),
                port: first_port,
                ..Default::default()
            },
            ProxyConfig {
                name: "last".into(),
                kind: Some(kind),
                server: "127.0.0.1".into(),
                port,
                password: Some("pw".into()),
                sni: Some("localhost".into()),
                skip_cert_verify: true,
                ..Default::default()
            },
        ];
        profile.groups = vec![GroupConfig::new(
            "test-relay",
            GroupKind::Relay,
            vec!["first".into(), "last".into()],
        )];
        profile.rules = vec![RuleConfig::parse("MATCH,test-relay").unwrap()];
        let root = Hub::new(Default::default(), ".".into(), profile)
            .await
            .unwrap();
        let core = root.core();
        let meta = |network| {
            Metadata::new(
                network,
                "TlsRelayWire",
                "127.0.0.1:1234".parse().unwrap(),
                target(),
                None,
            )
        };
        let mut tcp = core.tunnel.dial(&mut meta(Network::Tcp)).await.unwrap();
        assert_eq!(tcp.chains, vec!["last", "first", "test-relay"]);
        tcp.stream.write_all(b"ping").await.unwrap();
        let mut reply = [0; 4];
        tokio::time::timeout(Duration::from_secs(3), tcp.stream.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply, b"pong");
        let before_udp = direct.core().tunnel.stats.upload.load(Ordering::Relaxed);
        let mut udp = core.tunnel.dial_udp(&mut meta(Network::Udp)).await.unwrap();
        udp.pipe.tx.send(b"ping".to_vec()).await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), udp.pipe.rx.recv())
                .await
                .unwrap()
                .unwrap(),
            b"pong"
        );
        drop(udp);
        assert!(
            direct.core().tunnel.stats.upload.load(Ordering::Relaxed) > before_udp,
            "UDP-over-TCP bypassed the first hop"
        );
        drop(tcp);
        assert_eq!(hits.load(Ordering::Relaxed), 2);
        assert!(direct.core().tunnel.stats.upload.load(Ordering::Relaxed) > 0);
        assert!(!server.is_finished(), "TLS protocol fixture failed");
        core.shutdown.cancel();
        drop(core);
        drop(root);
        stop.cancel();
        forward.await.unwrap();
        direct.core().shutdown.cancel();
        server.abort();
        let _ = server.await;
    }
}
#[tokio::test]
async fn anytls_tcp_and_uot_traverse_http_and_socks_first_hops() {
    tokio::time::timeout(Duration::from_secs(15), composition(ProxyKind::AnyTls))
        .await
        .unwrap()
}
#[tokio::test]
async fn trojan_tcp_and_uot_traverse_http_and_socks_first_hops() {
    tokio::time::timeout(Duration::from_secs(15), composition(ProxyKind::Trojan))
        .await
        .unwrap()
}
