//! Routing regression: target DNS must not use node bootstrap or fall back DIRECT.
use std::{collections::HashMap, io, sync::{Arc, Mutex, OnceLock}};
use async_trait::async_trait;
use prism_core::{common::{Address, BoxedStream}, config::{DnsConfig, GroupConfig, GroupKind, ProxyConfig, Mode}, dns::{self, wire}, outbound::{self, Outbound, Registry, RegistryCell, ProxyGroup}};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Proxy(Arc<Mutex<Vec<String>>>);
#[async_trait]
impl Outbound for Proxy {
    fn name(&self) -> &str { "test-proxy" }
    fn api_type(&self) -> &'static str { "TestProxy" }
    async fn connect(&self, _: &Address) -> io::Result<BoxedStream> {
        let (client, mut remote) = tokio::io::duplex(4096);
        let hits = self.0.clone();
        tokio::spawn(async move {
            while let Ok(size) = remote.read_u16().await {
                let mut q = vec![0; size as usize];
                if remote.read_exact(&mut q).await.is_err() { break; }
                hits.lock().unwrap().push(wire::question(&q).unwrap().0.name);
                let answer = wire::response(&q, wire::RCODE_NOERROR, &[("192.0.2.7".parse().unwrap(), 60)]).unwrap();
                if remote.write_u16(answer.len() as u16).await.is_err() || remote.write_all(&answer).await.is_err() { break; }
            }
        });
        Ok(Box::new(client))
    }
}

#[tokio::test]
async fn target_and_bootstrap_are_separate_and_direct_selection_fails_closed() {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bootstrap = sock.local_addr().unwrap().to_string();
    let bootstrap_hits = Arc::new(Mutex::new(Vec::new()));
    let hits = bootstrap_hits.clone();
    let task = tokio::spawn(async move {
        let mut buf = vec![0; 4096];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            hits.lock().unwrap().push(wire::question(&buf[..n]).unwrap().0.name);
            let answer = wire::response(&buf[..n], wire::RCODE_NOERROR, &[("198.51.100.2".parse().unwrap(), 60)]).unwrap();
            let _ = sock.send_to(&answer, peer).await;
        }
    });
    let proxy_hits = Arc::new(Mutex::new(Vec::new()));
    let cell: RegistryCell = Arc::new(OnceLock::new());
    let group = Arc::new(ProxyGroup::new(GroupConfig::new("G", GroupKind::Select, vec!["test-proxy".into(), "DIRECT".into()]), cell.clone()));
    let mut map: HashMap<String, Arc<dyn Outbound>> = HashMap::new();
    map.insert("test-proxy".into(), Arc::new(Proxy(proxy_hits.clone())));
    map.insert("G".into(), group.clone());
    map.insert("DIRECT".into(), Arc::new(outbound::basic::Direct));
    let reg = Arc::new(Registry { map, order: vec![], delays: Default::default(), unified_delay: false,
        configs: HashMap::from([("test-proxy".into(), ProxyConfig::default())]) });
    assert!(cell.set(reg).is_ok());
    let cfg = DnsConfig { enable: true, nameserver: vec!["tcp://192.0.2.53#G&proxy-only=true".into()],
        proxy_server_nameserver: vec![bootstrap], ..Default::default() };
    let (r, warnings) = dns::build(&cfg, &[], std::path::Path::new("."), cell, &Mutex::new(None));
    assert!(warnings.is_empty());
    let r = r.unwrap();
    assert_eq!(r.lookup("same.test").await.unwrap()[0].to_string(), "192.0.2.7");
    assert_eq!(r.lookup_proxy("same.test").await.unwrap()[0].to_string(), "198.51.100.2");
    assert_eq!(*proxy_hits.lock().unwrap(), ["same.test"]);
    assert_eq!(*bootstrap_hits.lock().unwrap(), ["same.test"]);
    group.select("DIRECT").unwrap();
    let response = r.handle(&wire::query(42, "blocked.test", wire::TYPE_A)).await.unwrap();
    assert_eq!(wire::rcode(&response), wire::RCODE_SERVFAIL);
    assert_eq!(bootstrap_hits.lock().unwrap().len(), 1, "must not retry target DNS through bootstrap");
    assert_eq!(proxy_hits.lock().unwrap().len(), 1);
    task.abort();
}

#[tokio::test]
async fn ipv6_block_applies_in_all_modes_and_aaaa_hosts_cannot_bypass() {
    let raw = "proxies: []\nprism-block-ipv6: true\nrules: ['MATCH,DIRECT']\ndns: {enable: true, ipv6: false, nameserver: [127.0.0.1]}\nhosts: {v6.test: '::1'}";
    let core = prism_core::build(prism_core::config::parse_any(raw).unwrap(), std::path::Path::new("."), &prism_core::BuildEnv::standalone()).await.unwrap();
    let answer = core.dns.as_ref().unwrap().handle(&wire::query(1, "v6.test", wire::TYPE_AAAA)).await.unwrap();
    assert!(wire::answers(&answer).unwrap().0.is_empty());
    for mode in [Mode::Rule, Mode::Global, Mode::Direct] {
        *core.tunnel.mode.write().unwrap() = mode;
        let mut meta = prism_core::tunnel::Metadata::new(prism_core::tunnel::Network::Tcp, "Tun", "127.0.0.1:1".parse().unwrap(), Address::new("::1", 80), Some("::1".parse().unwrap()));
        assert!(core.tunnel.dial(&mut meta).await.is_err());
        assert!(core.tunnel.dial_udp(&mut meta).await.is_err());
    }
}


#[tokio::test]
async fn overlay_bypass_has_priority_over_global_mode_and_ipv6_block() {
    let raw = "proxies: []\nprism-block-ipv6: true\nprism-tailscale-bypass: true\nrules: ['MATCH,REJECT']";
    let core = prism_core::build(prism_core::config::parse_any(raw).unwrap(), std::path::Path::new("."), &prism_core::BuildEnv::standalone()).await.unwrap();
    *core.tunnel.mode.write().unwrap() = Mode::Global;
    // UDP dial creates a socket without sending a packet. Loopback socket
    // pinning is untouched; this tests rule selection without joining a tailnet.
    let mut meta = prism_core::tunnel::Metadata::new(prism_core::tunnel::Network::Udp, "Tun", "127.0.0.1:1".parse().unwrap(), Address::new("100.64.0.1", 1), None);
    let result = core.tunnel.dial_udp(&mut meta).await.unwrap();
    assert_eq!(result.rule, "Tailscale"); assert_eq!(result.chains, ["DIRECT"]);
}
