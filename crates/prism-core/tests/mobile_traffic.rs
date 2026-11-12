//! Phone accounting must retain completed TCP/UDP payloads and survive reload.
use prism_core::{
    common::Address,
    config,
    hub::{Hub, Source},
    tunnel::{Metadata, Network, UdpNat, UdpPacket},
};
use std::{
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::mpsc,
};

#[tokio::test]
async fn completed_tcp_and_udp_remain_attributed_after_reload() {
    let home = std::env::temp_dir().join(format!("prism-mobile-traffic-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&home).unwrap();
    let raw =
        "mixed-port: 0\nfind-process-mode: off\nproxies: [{name: unused, type: socks5, server: 127.0.0.1, port: 9}]\nrules: ['MATCH,DIRECT']\ndns: {enable: false}\n";
    let hub = Hub::new(
        Source::default(),
        home.clone(),
        config::parse_any(raw).unwrap(),
    )
    .await
    .unwrap();
    let t = hub.core().tunnel.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = [0; 5];
        socket.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"hello");
        socket.write_all(b"world").await.unwrap();
        socket.shutdown().await.unwrap();
    });
    let mut meta = Metadata::new(
        Network::Tcp,
        "MobileAccountingTest",
        "127.0.0.1:1".parse().unwrap(),
        Address::Ip(address),
        Some(address.ip()),
    );
    let dialed = t.dial(&mut meta).await.unwrap();
    let (mut client, inside) = tokio::io::duplex(1024);
    client.shutdown().await.unwrap();
    let tunnel = t.clone();
    let relay = tokio::spawn(async move { tunnel.relay(inside, dialed, meta, b"hello").await });
    let mut reply = vec![];
    tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"world");
    server.await.unwrap();
    relay.await.unwrap();
    assert!(t.stats.snapshot().is_empty());
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = udp.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let mut b = [0; 16];
        let (n, src) = udp.recv_from(&mut b).await.unwrap();
        udp.send_to(&b[..n], src).await.unwrap();
    });
    let (tx, mut rx) = mpsc::channel(4);
    let nat = UdpNat::new("MobileAccountingTest", tx);
    nat.send(
        &t,
        UdpPacket {
            src: "127.0.0.1:2".parse().unwrap(),
            dst: Address::Ip(address),
            data: b"udp".to_vec(),
        },
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .unwrap()
            .unwrap()
            .data,
        b"udp"
    );
    echo.await.unwrap();
    t.stats.close_all();
    tokio::time::timeout(Duration::from_secs(3), async {
        while !t.stats.snapshot().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await
        }
    })
    .await
    .unwrap();
    hub.reload(Some(raw.into())).await.unwrap();
    assert!(Arc::ptr_eq(&t.stats, &hub.core().tunnel.stats));
    let counts = t
        .stats
        .traffic
        .lock()
        .unwrap()
        .get(&("DIRECT".into(), "Match".into()))
        .unwrap()
        .clone();
    assert_eq!(counts.upload.load(Ordering::Relaxed), 8);
    assert_eq!(counts.download.load(Ordering::Relaxed), 8);
    assert_eq!(t.stats.upload.load(Ordering::Relaxed), 8);
    assert_eq!(t.stats.download.load(Ordering::Relaxed), 8);
    hub.core().shutdown.cancel();
    std::fs::remove_dir_all(home).unwrap();
}
