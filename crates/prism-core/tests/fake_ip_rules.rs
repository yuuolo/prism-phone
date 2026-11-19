//! TUN connections reach the core addressed to a fake-ip. When the domain is
//! sniffed (TLS SNI), the fake-ip still comes along as the "resolved" address;
//! IP rules must not match it - common rule sets send 198.18.0.0/15 DIRECT,
//! which used to bypass the proxy for every sniffed TUN connection.

use std::net::{IpAddr, SocketAddr};

use prism_core::common::Address;
use prism_core::dns::wire;
use prism_core::tunnel::{Metadata, Network};
use prism_core::{build, config, BuildEnv};

const PROFILE: &str = r#"
proxies:
  - {name: node, type: ss, server: 127.0.0.1, port: 1, cipher: aes-128-gcm, password: x}
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver: [127.0.0.1:1]
rules:
  - IP-CIDR,198.18.0.0/15,DIRECT,no-resolve
  - DOMAIN-SUFFIX,direct.example,DIRECT
  - MATCH,REJECT
"#;

#[tokio::test]
async fn mobile_hosts_keep_fake_domains_rules_and_real_tcp_udp_destination() {
    use tokio::{io::AsyncReadExt,net::{TcpListener,UdpSocket}};
    let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();let port=listener.local_addr().unwrap().port();
    let udp=UdpSocket::bind("127.0.0.1:0").await.unwrap();let udp_port=udp.local_addr().unwrap().port();
    let server=tokio::spawn(async move {let (mut s,_)=listener.accept().await.unwrap();tokio::io::AsyncWriteExt::write_all(&mut s,b"hosts-tcp").await.unwrap();});
    let datagram=tokio::spawn(async move {let mut buf=[0u8;32];let(n,p)=udp.recv_from(&mut buf).await.unwrap();udp.send_to(&buf[..n],p).await.unwrap();});
    let raw="proxies: [{name: fixture, type: socks5, server: 127.0.0.1, port: 1}]\ndns: {enable: true, enhanced-mode: fake-ip, fake-ip-range: 198.18.0.1/16, prism-fake-ip-hosts: true, nameserver: [127.0.0.1:1]}\nhosts: {allowed.test: 127.0.0.1, blocked.test: 127.0.0.1}\nrules: ['DOMAIN,blocked.test,REJECT', 'DOMAIN,allowed.test,DIRECT', 'MATCH,REJECT']";
    let core=build(config::parse_any(raw).unwrap(),std::path::Path::new("."),&BuildEnv::standalone()).await.unwrap();
    let dns=core.dns.as_ref().unwrap();
    let fake_for=|name:&'static str|async move {let reply=dns.handle(&wire::query(9,name,wire::TYPE_A)).await.unwrap();wire::answers(&reply).unwrap().0[0].0};
    let fake=fake_for("allowed.test").await;assert!(dns.is_fake(fake));
    assert_eq!(dns.lookup("allowed.test").await.unwrap(),["127.0.0.1".parse::<IpAddr>().unwrap()]);
    let mut meta=Metadata::new(Network::Tcp,"Tun","127.0.0.1:23456".parse().unwrap(),Address::new(&fake.to_string(),port),None);
    let mut dial=core.tunnel.dial(&mut meta).await.unwrap();let mut bytes=[0u8;9];dial.stream.read_exact(&mut bytes).await.unwrap();assert_eq!(&bytes,b"hosts-tcp");assert_eq!(meta.dst.domain(),Some("allowed.test"));assert_eq!(dial.rule,"Domain(allowed.test)");
    let mut meta=Metadata::new(Network::Udp,"Tun","127.0.0.1:23457".parse().unwrap(),Address::new(&fake.to_string(),udp_port),None);
    let mut dial=core.tunnel.dial_udp(&mut meta).await.unwrap();dial.pipe.tx.send(b"hosts-udp".to_vec()).await.unwrap();assert_eq!(tokio::time::timeout(std::time::Duration::from_secs(2),dial.pipe.rx.recv()).await.unwrap().unwrap(),b"hosts-udp");
    let blocked=fake_for("blocked.test").await;assert!(dns.is_fake(blocked));
    for network in [Network::Tcp,Network::Udp] {let mut meta=Metadata::new(network,"Tun","127.0.0.1:23458".parse().unwrap(),Address::new(&blocked.to_string(),port),None);if matches!(network,Network::Tcp){assert!(core.tunnel.dial(&mut meta).await.is_err());}else{assert!(core.tunnel.dial_udp(&mut meta).await.is_err());}}
    server.await.unwrap();datagram.await.unwrap();
    let legacy=raw.replace("prism-fake-ip-hosts: true","prism-fake-ip-hosts: false");let legacy=build(config::parse_any(&legacy).unwrap(),std::path::Path::new("."),&BuildEnv::standalone()).await.unwrap();
    let dns=legacy.dns.as_ref().unwrap();assert_eq!(dns.host_override("allowed.test"),None);let r=dns.handle(&wire::query(10,"allowed.test",wire::TYPE_A)).await.unwrap();assert_eq!(wire::answers(&r).unwrap().0[0].0,"127.0.0.1".parse::<IpAddr>().unwrap());
}

#[tokio::test]
async fn sniffed_tun_connections_ignore_the_fake_ip() {
    let home = std::env::temp_dir().join(format!("prism-fakeip-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let core = build(config::parse_any(PROFILE).unwrap(), &home, &BuildEnv::standalone()).await.unwrap();
    let dns = core.dns.clone().expect("dns module");

    // What the client got from the TUN's DNS for www.google.com.
    let reply = dns.handle(&wire::query(7, "www.google.com", 1)).await.unwrap();
    let fake = wire::answers(&reply).unwrap().0[0].0;
    assert!(dns.is_fake(fake), "{fake}");

    let src: SocketAddr = "172.19.0.1:50000".parse().unwrap();
    let route = |dst: Address, dst_ip: Option<IpAddr>| {
        let tunnel = core.tunnel.clone();
        async move {
            let mut meta = Metadata::new(Network::Tcp, "Tun", src, dst, dst_ip);
            tunnel.restore_fake_ip(&mut meta);
            let target = tunnel.router.route(&mut meta).await.map(|r| r.target.clone());
            (target, meta.dst_ip)
        }
    };

    // SNI sniffed: domain plus the fake-ip the client dialled.
    let (target, ip) = route(Address::Domain("www.google.com".into(), 443), Some(fake)).await;
    assert_eq!(target.as_deref(), Some("REJECT"), "matched the fake-ip as if it were the server's address");
    assert_eq!(ip, None);

    // Nothing sniffed: the fake-ip maps back to the domain.
    let (target, _) = route(Address::Ip(SocketAddr::new(fake, 443)), None).await;
    assert_eq!(target.as_deref(), Some("REJECT"));

    // A real resolved address is kept.
    let (target, ip) = route(Address::Domain("www.google.com".into(), 443), Some("1.1.1.1".parse().unwrap())).await;
    assert_eq!((target.as_deref(), ip), (Some("REJECT"), Some("1.1.1.1".parse().unwrap())));

    let _ = std::fs::remove_dir_all(&home);
}
