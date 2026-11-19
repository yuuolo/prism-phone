//! Explicit bounded relay path. Imported dialer graphs and nested groups stay disabled.
use anyhow::{ensure, Result};
use prism_core::config::{GroupConfig, GroupKind, Profile, ProxyConfig, ProxyKind};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub hops: Vec<crate::automatic::Candidate>,
    #[serde(rename = "udpEnabled")]
    pub udp_enabled: bool,
}
pub fn name(id: &str) -> String {
    format!("链节点.{id}")
}
impl Plan {
    pub fn udp_possible(&self) -> bool {
        let mut udp = true;
        for hop in &self.hops {
            udp = match hop.node.kind() {
                ProxyKind::Http => false,
                ProxyKind::AnyTls | ProxyKind::Trojan | ProxyKind::Vless => true, // UDP carried over the previous TCP path.
                ProxyKind::Socks5 | ProxyKind::Shadowsocks => udp, // Native UDP needs a UDP carrier before this hop.
                _ => false,
            };
        }
        udp
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (2..=4).contains(&self.hops.len()),
            "链式代理须有 2–4 个有序节点"
        );
        let mut ids = HashSet::new();
        let mut endpoints = HashSet::new();
        for (index, hop) in self.hops.iter().enumerate() {
            ensure!(
                !hop.id.is_empty()
                    && hop.id.len() <= 80
                    && hop
                        .id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
                    && ids.insert(&hop.id),
                "链式节点 ID 无效或重复"
            );
            ensure!(
                crate::profile::supported(&hop.node),
                "链节点包含不支持的协议、传输、证书或嵌套 dialer 设置"
            );
            let host = hop
                .node
                .server
                .parse::<std::net::IpAddr>()
                .map(|ip| ip.to_string())
                .unwrap_or_else(|_| hop.node.server.trim_end_matches('.').to_ascii_lowercase());
            ensure!(
                endpoints.insert((host, hop.node.port)),
                "链中重复服务器地址和端口可能形成回环，请调整节点"
            );
            ensure!(
                prism_core::outbound::build_proxy(&hop.node, prism_core::outbound::Dialer::Direct)
                    .is_ok(),
                "第 {} 个链节点协议参数无效",
                index + 1
            );
        }
        ensure!(
            !self.udp_enabled || self.udp_possible(),
            "此顺序无法承载 UDP，请关闭链式 UDP 或调整节点顺序"
        );
        Ok(())
    }
    pub fn apply(&self, profile: &mut Profile) -> Result<()> {
        self.validate()?;
        profile.proxies = self
            .hops
            .iter()
            .map(|hop| ProxyConfig {
                name: name(&hop.id),
                ..hop.node.clone()
            })
            .collect();
        let mut group = GroupConfig::new(
            "手机节点",
            GroupKind::Relay,
            self.hops.iter().map(|h| name(&h.id)).collect(),
        );
        group.block_udp = !self.udp_enabled;
        profile.groups = vec![group];
        Ok(())
    }
    pub fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({"enabled":true,"udpEnabled":self.udp_enabled,"hops":self.hops.iter().map(|h|serde_json::json!({"id":h.id,"name":h.node.name,"protocol":h.node.kind})).collect::<Vec<_>>()})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
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
    use tokio_util::sync::CancellationToken;
    struct Peer {
        proxy: Option<crate::local_proxy::LocalProxy>,
        hub: Arc<prism_core::hub::Hub>,
        port: u16,
    }
    async fn peer() -> Peer {
        let profile = prism_core::config::parse_any(
            "proxies: []\nrules: ['MATCH,DIRECT']\nfind-process-mode: off",
        )
        .unwrap();
        let hub = prism_core::hub::Hub::new(Default::default(), ".".into(), profile)
            .await
            .unwrap();
        let proxy = crate::local_proxy::LocalProxy::start(
            hub.clone(),
            &CancellationToken::new(),
            0,
            crate::local_proxy::Scope::Loopback,
        )
        .await
        .unwrap();
        let port = proxy.address.port();
        Peer {
            proxy: Some(proxy),
            hub,
            port,
        }
    }
    async fn client(plan: Plan) -> Arc<prism_core::hub::Hub> {
        let (mut p, _) = crate::profile::build(crate::profile::Session {
            node: plan.hops[0].node.clone(),
            direct: vec![],
            routing: None,
            automatic: None,
            geodata: None,
            adblock: None,
            chain: Some(plan),
            dns: None,
        })
        .unwrap();
        p.dns.enable = false; // Loopback protocol matrix never contacts a public resolver; Android verifies real DoH separately.
        prism_core::hub::Hub::new(Default::default(), ".".into(), p)
            .await
            .unwrap()
    }
    #[tokio::test]
    async fn real_two_to_four_hop_tcp_udp_order_and_no_direct_failure_fallback() {
        use prism_core::{
            common::Address,
            tunnel::{Metadata, Network},
        };
        let mut peers = Vec::new();
        for _ in 0..4 {
            peers.push(peer().await);
        }
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_address = echo.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let received = hits.clone();
        let tcp_task = tokio::spawn(async move {
            while let Ok((mut s, _)) = echo.accept().await {
                let hits = received.clone();
                tokio::spawn(async move {
                    let mut b = [0; 4];
                    if matches!(
                        tokio::time::timeout(Duration::from_secs(3), s.read_exact(&mut b)).await,
                        Ok(Ok(_))
                    ) {
                        assert_eq!(&b, b"ping");
                        hits.fetch_add(1, Ordering::Relaxed);
                        s.write_all(b"pong").await.unwrap();
                    }
                });
            }
        });
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_address = udp.local_addr().unwrap();
        let udp_task = tokio::spawn(async move {
            let mut b = [0; 512];
            while let Ok((n, src)) = udp.recv_from(&mut b).await {
                udp.send_to(&b[..n], src).await.unwrap();
            }
        });
        let mut cases = vec![
            vec![ProxyKind::Socks5, ProxyKind::Socks5],
            vec![ProxyKind::Http, ProxyKind::Socks5],
            vec![ProxyKind::Socks5, ProxyKind::Http],
            vec![ProxyKind::Http, ProxyKind::Http],
        ];
        cases.push(vec![ProxyKind::Socks5; 3]);
        cases.push(vec![ProxyKind::Socks5; 4]);
        for kinds in cases {
            let udp_enabled = kinds.iter().all(|k| *k == ProxyKind::Socks5);
            let hops = kinds
                .into_iter()
                .enumerate()
                .map(|(i, k)| hop(&format!("h{i}"), peers[i].port, k))
                .collect::<Vec<_>>();
            let last = name(&hops.last().unwrap().id);
            let n = hops.len();
            let before: Vec<_> = peers
                .iter()
                .take(n)
                .map(|p| p.hub.core().tunnel.stats.upload.load(Ordering::Relaxed))
                .collect();
            let plan = Plan { hops, udp_enabled };
            let root = client(plan.clone()).await;
            let tunnel = root.core().tunnel.clone();
            // Mobile IPv6 denial must happen before contacting any chain hop.
            let first_before = peers[0]
                .hub
                .core()
                .tunnel
                .stats
                .upload
                .load(Ordering::Relaxed);
            let mut blocked = Metadata::new(
                Network::Tcp,
                "ChainIpv6Test",
                "127.0.0.1:1234".parse().unwrap(),
                Address::new("2001:db8::9", 443),
                None,
            );
            assert!(tunnel.dial(&mut blocked).await.is_err());
            blocked.network = Network::Udp;
            assert!(tunnel.dial_udp(&mut blocked).await.is_err());
            assert_eq!(
                first_before,
                peers[0]
                    .hub
                    .core()
                    .tunnel
                    .stats
                    .upload
                    .load(Ordering::Relaxed)
            );
            let mut meta = Metadata::new(
                Network::Tcp,
                "ChainTest",
                "127.0.0.1:1234".parse().unwrap(),
                Address::Ip(tcp_address),
                None,
            );
            let dialed = tokio::time::timeout(Duration::from_secs(5), tunnel.dial(&mut meta))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(dialed.chains.first().unwrap(), &last);
            assert_eq!(dialed.chains.len(), n + 1);
            let (mut user, inside) = tokio::io::duplex(1024);
            user.write_all(b"ping").await.unwrap();
            user.shutdown().await.unwrap();
            let t = tunnel.clone();
            let relay = tokio::spawn(async move { t.relay(inside, dialed, meta, &[]).await });
            let mut answer = Vec::new();
            tokio::time::timeout(Duration::from_secs(5), user.read_to_end(&mut answer))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&answer, b"pong");
            relay.await.unwrap();
            for (i, p) in peers.iter().take(n).enumerate() {
                assert!(
                    p.hub.core().tunnel.stats.upload.load(Ordering::Relaxed) > before[i],
                    "hop {i} was bypassed"
                );
            }
            assert!(tunnel
                .stats
                .traffic
                .lock()
                .unwrap()
                .keys()
                .any(|(id, _)| id == &last));
            let mut meta = Metadata::new(
                Network::Udp,
                "ChainTest",
                "127.0.0.1:1234".parse().unwrap(),
                Address::Ip(udp_address),
                None,
            );
            let result = tokio::time::timeout(Duration::from_secs(5), tunnel.dial_udp(&mut meta))
                .await
                .unwrap();
            if udp_enabled {
                let mut dialed = result.unwrap();
                assert_eq!(dialed.chains.first().unwrap(), &last);
                dialed.pipe.tx.send(b"datagram".to_vec()).await.unwrap();
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(5), dialed.pipe.rx.recv())
                        .await
                        .unwrap()
                        .unwrap(),
                    b"datagram"
                );
            } else {
                assert!(result.is_err(), "UDP must not bypass a disabled chain");
                let mut direct = Profile::default();
                plan.apply(&mut direct).unwrap();
                direct.rules = vec![
                    prism_core::config::RuleConfig::parse("IP-CIDR,127.0.0.1/32,DIRECT,no-resolve")
                        .unwrap(),
                    prism_core::config::RuleConfig::parse("MATCH,手机节点").unwrap(),
                ];
                root.reload(Some(
                    serde_yaml::to_string(&prism_core::config::clash::emit(&direct)).unwrap(),
                ))
                .await
                .unwrap();
                let mut allowed = root.core().tunnel.dial_udp(&mut meta).await.unwrap();
                assert_eq!(allowed.chains.first().unwrap(), "DIRECT");
                allowed.pipe.tx.send(b"direct-udp".to_vec()).await.unwrap();
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(3), allowed.pipe.rx.recv())
                        .await
                        .unwrap()
                        .unwrap(),
                    b"direct-udp"
                );
            }
            root.core().shutdown.cancel();
        }
        let root = client(Plan {
            hops: vec![
                hop("a", peers[0].port, ProxyKind::Socks5),
                hop("b", peers[1].port, ProxyKind::Socks5),
            ],
            udp_enabled: true,
        })
        .await;
        peers[0].proxy.take().unwrap().stop().await;
        let before = hits.load(Ordering::Relaxed);
        let mut meta = Metadata::new(
            Network::Tcp,
            "ChainTest",
            "127.0.0.1:1234".parse().unwrap(),
            Address::Ip(tcp_address),
            None,
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(3), root.core().tunnel.dial(&mut meta))
                .await
                .unwrap()
                .is_err()
        );
        assert_eq!(before, hits.load(Ordering::Relaxed));
        root.core().shutdown.cancel();
        peers[3].proxy.take().unwrap().stop().await;
        let root = client(Plan {
            hops: vec![
                hop("c", peers[2].port, ProxyKind::Socks5),
                hop("d", peers[3].port, ProxyKind::Socks5),
                hop("b", peers[1].port, ProxyKind::Socks5),
            ],
            udp_enabled: true,
        })
        .await;
        assert!(
            tokio::time::timeout(Duration::from_secs(3), root.core().tunnel.dial(&mut meta))
                .await
                .unwrap()
                .is_err()
        );
        assert_eq!(before, hits.load(Ordering::Relaxed));
        root.core().shutdown.cancel();
        for mut p in peers {
            if let Some(proxy) = p.proxy.take() {
                proxy.stop().await;
            }
            p.hub.core().shutdown.cancel();
        }
        tcp_task.abort();
        udp_task.abort();
        let _ = tcp_task.await;
        let _ = udp_task.await;
    }
    fn hop(id: &str, port: u16, kind: ProxyKind) -> crate::automatic::Candidate {
        crate::automatic::Candidate {
            id: id.into(),
            node: ProxyConfig {
                name: id.into(),
                kind: Some(kind),
                server: "127.0.0.1".into(),
                port,
                ..Default::default()
            },
        }
    }
    #[test]
    fn rejects_cycles_nested_graphs_and_invalid_protocol_parameters() {
        let good = Plan {
            hops: vec![
                hop("a", 10001, ProxyKind::Socks5),
                hop("b", 10002, ProxyKind::Socks5),
            ],
            udp_enabled: true,
        };
        assert!(good.validate().is_ok());
        let mut bad = good.clone();
        bad.hops[1].id = "a".into();
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.hops[1].node.port = 10001;
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.hops[0].node.dialer_proxy = Some("b".into());
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.hops[1].node.kind = Some(ProxyKind::Vless);
        bad.hops[1].node.uuid = Some("not-a-uuid".into());
        assert!(bad.validate().is_err());
        let mut bad = good;
        bad.hops[1].node.skip_cert_verify = true;
        assert!(bad.validate().is_err());
    }
    #[tokio::test]
    async fn tls_hops_reject_untrusted_certificates_through_the_previous_proxy() {
        let mut first = peer().await;
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = rustls::pki_types::PrivateKeyDer::try_from(certificate.key_pair.serialize_der())
            .unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.cert.der().clone()], key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let attempts = Arc::new(AtomicUsize::new(0));
        let observed = attempts.clone();
        let server = tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                observed.fetch_add(1, Ordering::Relaxed);
                let _ = tokio::time::timeout(Duration::from_secs(3), acceptor.accept(s)).await;
            }
        });
        for kind in [ProxyKind::AnyTls, ProxyKind::Trojan, ProxyKind::Vless] {
            let mut last = hop("tls", port, kind);
            last.node.tls = true;
            last.node.sni = Some("localhost".into());
            last.node.password = Some("test-only-password".into());
            last.node.uuid = Some("00000000-0000-0000-0000-000000000001".into());
            let before = first.hub.core().tunnel.stats.upload.load(Ordering::Relaxed);
            let root = client(Plan {
                hops: vec![hop("first", first.port, ProxyKind::Socks5), last],
                udp_enabled: true,
            })
            .await;
            let mut meta = prism_core::tunnel::Metadata::new(
                prism_core::tunnel::Network::Tcp,
                "ChainTlsTest",
                "127.0.0.1:1234".parse().unwrap(),
                prism_core::common::Address::new("203.0.113.123", 443),
                None,
            );
            assert!(tokio::time::timeout(
                Duration::from_secs(5),
                root.core().tunnel.dial(&mut meta)
            )
            .await
            .unwrap()
            .is_err());
            assert!(first.hub.core().tunnel.stats.upload.load(Ordering::Relaxed) > before);
            root.core().shutdown.cancel();
        }
        assert_eq!(attempts.load(Ordering::Relaxed), 3);
        first.proxy.take().unwrap().stop().await;
        first.hub.core().shutdown.cancel();
        server.abort();
        let _ = server.await;
    }
    #[test]
    fn validates_udp_transport_order_instead_of_only_protocol_names() {
        let mut chain = Plan {
            hops: vec![
                hop("a", 10001, ProxyKind::Http),
                hop("b", 10002, ProxyKind::Socks5),
            ],
            udp_enabled: true,
        };
        assert!(!chain.udp_possible());
        assert!(chain.validate().is_err());
        chain.udp_enabled = false;
        assert!(chain.validate().is_ok());
        chain.hops[1].node.kind = Some(ProxyKind::Vless);
        chain.hops[1].node.uuid = Some("00000000-0000-0000-0000-000000000001".into());
        chain.udp_enabled = true;
        assert!(chain.udp_possible());
        assert!(chain.validate().is_ok());
    }
    #[tokio::test]
    async fn old_registry_is_released_after_network_rebuild_and_stop() {
        let mut a = peer().await;
        let mut b = peer().await;
        let plan = Plan {
            hops: vec![
                hop("a", a.port, ProxyKind::Socks5),
                hop("b", b.port, ProxyKind::Socks5),
            ],
            udp_enabled: true,
        };
        let root = client(plan.clone()).await;
        let old_tunnel = root.core().tunnel.clone();
        let old = Arc::downgrade(&old_tunnel.reg);
        let mut profile = Profile::default();
        plan.apply(&mut profile).unwrap();
        profile.rules = vec![prism_core::config::RuleConfig::parse("MATCH,手机节点").unwrap()];
        let raw = serde_yaml::to_string(&prism_core::config::clash::emit(&profile)).unwrap();
        root.reload(Some(raw)).await.unwrap();
        tokio::task::yield_now().await;
        assert!(
            old.upgrade().is_some(),
            "A live tunnel must retain its outbound registry"
        );
        drop(old_tunnel);
        tokio::task::yield_now().await;
        assert!(
            old.upgrade().is_none(),
            "Old outbound registry leaked after reload"
        );
        let current = Arc::downgrade(&root.core().tunnel.reg);
        root.core().shutdown.cancel();
        drop(root);
        tokio::task::yield_now().await;
        assert!(
            current.upgrade().is_none(),
            "Outbound registry leaked after stop"
        );
        a.proxy.take().unwrap().stop().await;
        b.proxy.take().unwrap().stop().await;
        a.hub.core().shutdown.cancel();
        b.hub.core().shutdown.cancel();
    }
    #[tokio::test]
    async fn proxy_only_dns_uses_both_hops_and_refuses_direct_relay_members() {
        use prism_core::{dns::wire, hub::Hub};
        let mut a = peer().await;
        let mut b = peer().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let seen = hits.clone();
        let server = tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let seen = seen.clone();
                tokio::spawn(async move {
                    while let Ok(n) = s.read_u16().await {
                        let mut q = vec![0; n as usize];
                        if s.read_exact(&mut q).await.is_err() {
                            break;
                        }
                        seen.fetch_add(1, Ordering::Relaxed);
                        let answer = wire::response(
                            &q,
                            wire::RCODE_NOERROR,
                            &[("203.0.113.7".parse().unwrap(), 60)],
                        )
                        .unwrap();
                        if s.write_u16(answer.len() as u16).await.is_err()
                            || s.write_all(&answer).await.is_err()
                        {
                            break;
                        }
                    }
                });
            }
        });
        let plan = Plan {
            hops: vec![
                hop("a", a.port, ProxyKind::Socks5),
                hop("b", b.port, ProxyKind::Socks5),
            ],
            udp_enabled: true,
        };
        let (mut profile, _) = crate::profile::build(crate::profile::Session {
            node: plan.hops[0].node.clone(),
            direct: vec![],
            routing: None,
            automatic: None,
            geodata: None,
            adblock: None,
            chain: Some(plan),
            dns: None,
        })
        .unwrap();
        profile.dns.nameserver = vec![format!("tcp://127.0.0.1:{port}#手机节点&proxy-only=true")];
        let strict = profile.clone();
        let root = Hub::new(Default::default(), ".".into(), profile)
            .await
            .unwrap();
        let core = root.core();
        assert_eq!(
            core.dns
                .as_ref()
                .unwrap()
                .lookup("positive.chain.test")
                .await
                .unwrap()[0]
                .to_string(),
            "203.0.113.7"
        );
        assert!(a.hub.core().tunnel.stats.upload.load(Ordering::Relaxed) > 0);
        assert!(b.hub.core().tunnel.stats.upload.load(Ordering::Relaxed) > 0);
        let mut bad = strict;
        bad.groups[0].proxies.push("DIRECT".into());
        let denied = Hub::new(Default::default(), ".".into(), bad).await.unwrap();
        let before = hits.load(Ordering::Relaxed);
        assert!(denied
            .core()
            .dns
            .as_ref()
            .unwrap()
            .lookup("denied.chain.test")
            .await
            .is_err());
        assert_eq!(before, hits.load(Ordering::Relaxed));
        denied.core().shutdown.cancel();
        a.proxy.take().unwrap().stop().await;
        assert!(core
            .dns
            .as_ref()
            .unwrap()
            .lookup("no-first.chain.test")
            .await
            .is_err());
        assert_eq!(before, hits.load(Ordering::Relaxed));
        core.shutdown.cancel();
        b.proxy.take().unwrap().stop().await;
        b.hub.core().shutdown.cancel();
        a.hub.core().shutdown.cancel();
        server.abort();
        let _ = server.await;
    }
    #[tokio::test]
    async fn vless_udp_over_tcp_works_through_an_http_first_hop() {
        let mut first = peer().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let commands = Arc::new(AtomicUsize::new(0));
        let observed = commands.clone();
        let server = tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let observed = observed.clone();
                tokio::spawn(async move {
                    let mut head = [0; 18];
                    s.read_exact(&mut head).await.unwrap();
                    let mut uuid = [0; 16];
                    uuid[15] = 1;
                    assert_eq!(&head[1..17], &uuid);
                    assert_eq!(head[0], 0);
                    assert_eq!(head[17], 0);
                    let command = s.read_u8().await.unwrap();
                    assert_eq!(s.read_u16().await.unwrap(), 443);
                    assert_eq!(s.read_u8().await.unwrap(), 1);
                    let mut ip = [0; 4];
                    s.read_exact(&mut ip).await.unwrap();
                    assert_eq!(ip, [203, 0, 113, 9]);
                    s.write_all(&[0, 0]).await.unwrap();
                    observed.fetch_add(1, Ordering::Relaxed);
                    if command == 1 {
                        let mut data = [0; 4];
                        s.read_exact(&mut data).await.unwrap();
                        assert_eq!(&data, b"ping");
                        s.write_all(b"pong").await.unwrap();
                    } else {
                        assert_eq!(command, 2);
                        let len = s.read_u16().await.unwrap();
                        let mut data = vec![0; len as usize];
                        s.read_exact(&mut data).await.unwrap();
                        s.write_u16(len).await.unwrap();
                        s.write_all(&data).await.unwrap();
                    }
                });
            }
        });
        let mut last = hop("vless", port, ProxyKind::Vless);
        last.node.uuid = Some("00000000-0000-0000-0000-000000000001".into());
        let root = client(Plan {
            hops: vec![hop("http", first.port, ProxyKind::Http), last],
            udp_enabled: true,
        })
        .await;
        let core = root.core();
        let meta = |network| {
            prism_core::tunnel::Metadata::new(
                network,
                "ChainVlessTest",
                "127.0.0.1:1234".parse().unwrap(),
                prism_core::common::Address::new("203.0.113.9", 443),
                None,
            )
        };
        let mut dialed = core
            .tunnel
            .dial(&mut meta(prism_core::tunnel::Network::Tcp))
            .await
            .unwrap();
        dialed.stream.write_all(b"ping").await.unwrap();
        let mut reply = [0; 4];
        tokio::time::timeout(Duration::from_secs(3), dialed.stream.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply, b"pong");
        drop(dialed);
        let mut udp = core
            .tunnel
            .dial_udp(&mut meta(prism_core::tunnel::Network::Udp))
            .await
            .unwrap();
        udp.pipe
            .tx
            .send(b"stream-carried-udp".to_vec())
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), udp.pipe.rx.recv())
                .await
                .unwrap()
                .unwrap(),
            b"stream-carried-udp"
        );
        drop(udp);
        assert_eq!(commands.load(Ordering::Relaxed), 2);
        assert!(first.hub.core().tunnel.stats.upload.load(Ordering::Relaxed) > 0);
        core.shutdown.cancel();
        first.proxy.take().unwrap().stop().await;
        first.hub.core().shutdown.cancel();
        server.abort();
        let _ = server.await;
    }
}
