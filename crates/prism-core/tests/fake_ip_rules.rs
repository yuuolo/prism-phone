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
