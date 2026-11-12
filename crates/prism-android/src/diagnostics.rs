//! On-demand diagnostics use the embedded resolver/router, never system DNS.
use anyhow::{ensure, Result};
use prism_core::{
    common::Address,
    tunnel::{Metadata, Network},
    Core,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    io,
    net::IpAddr,
    time::{Duration, Instant},
};

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum Request {
    Dns { host: String },
    Tcp { host: String, port: u16 },
}
impl Request {
    pub fn parse(raw: &str) -> Result<Self> {
        ensure!(raw.len() <= 4096, "检测参数过长");
        let mut request: Self = serde_json::from_str(raw)?;
        let host = match &mut request {
            Self::Dns { host } | Self::Tcp { host, .. } => host,
        };
        *host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        ensure!(!host.is_empty() && host.len() <= 253, "域名格式无效");
        if let Ok(ip) = host.parse::<IpAddr>() {
            ensure!(ip.is_ipv4(), "当前手机版阻断 IPv6 目标");
            ensure!(matches!(request, Self::Tcp { .. }), "DNS 查询请输入域名");
        } else {
            ensure!(
                host.split('.').all(|label| !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-')),
                "域名格式无效"
            );
        }
        if let Self::Tcp { port, .. } = request {
            ensure!(port > 0, "端口无效");
        }
        Ok(request)
    }
}
fn failure(stage: &str, kind: io::ErrorKind) -> Value {
    let detail = match kind {
        io::ErrorKind::ConnectionRefused => "目标或代理拒绝连接",
        io::ErrorKind::TimedOut => "连接超时",
        io::ErrorKind::PermissionDenied => "路由或系统权限拒绝",
        io::ErrorKind::InvalidInput => "目标参数不受支持",
        _ if stage == "dns" => "DNS 上游不可达或没有可用 IPv4 结果",
        _ => "目标、代理或网络不可达",
    };
    json!({"error":detail,"stage":stage})
}
pub async fn run(core: &Core, request: Request) -> Value {
    let start = Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(8), async {
        match request {
            Request::Dns{host} => {
                let Some(resolver) = &core.dns else {return json!({"error":"内核 DNS 未启用","stage":"dns"});};
                match resolver.lookup(&host).await {
                    Ok(ips) if !ips.is_empty() => json!({"kind":"dns","host":host,"queryType":"A",
                        "addresses":ips.iter().map(ToString::to_string).collect::<Vec<_>>(),"ms":start.elapsed().as_millis() as u64}),
                    Ok(_) => failure("dns",io::ErrorKind::AddrNotAvailable),
                    Err(e) => failure("dns",e.kind()),
                }
            }
            Request::Tcp{host,port} => {
                let mut meta = Metadata::new(Network::Tcp,"AndroidTools","127.0.0.1:0".parse().unwrap(),Address::new(&host,port),None);
                match core.tunnel.dial(&mut meta).await {
                    Ok(dialed) => json!({"kind":"tcp","host":host,"port":port,"ms":start.elapsed().as_millis() as u64,
                        "path":if dialed.chains.first().is_some_and(|n| n == "DIRECT") {"直连"} else {"代理"},
                        "chains":dialed.chains,"rule":dialed.rule,"rulePayload":dialed.rule_payload}),
                    Err(e) => failure("connect",e.kind()),
                }
            }
        }
    }).await;
    result.unwrap_or_else(|_| json!({"error":"检测超过 8 秒","stage":"timeout"}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use prism_core::{
        common::BoxedStream,
        config::{DnsConfig, GroupConfig, GroupKind, ProxyConfig},
        dns::{self, wire},
        outbound::{self, Outbound, ProxyGroup, Registry, RegistryCell},
    };
    use std::{
        collections::HashMap,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex, OnceLock,
        },
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    struct DnsProxy(Arc<AtomicUsize>);
    #[async_trait]
    impl Outbound for DnsProxy {
        fn name(&self) -> &str {
            "test-dns-proxy"
        }
        fn api_type(&self) -> &'static str {
            "Test"
        }
        async fn connect(&self, _: &Address) -> io::Result<BoxedStream> {
            let (client, mut server) = tokio::io::duplex(4096);
            let hits = self.0.clone();
            tokio::spawn(async move {
                while let Ok(size) = server.read_u16().await {
                    let mut q = vec![0; size as usize];
                    if server.read_exact(&mut q).await.is_err() {
                        break;
                    }
                    hits.fetch_add(1, Ordering::Relaxed);
                    let answer = wire::response(
                        &q,
                        wire::RCODE_NOERROR,
                        &[("203.0.113.50".parse().unwrap(), 60)],
                    )
                    .unwrap();
                    if server.write_u16(answer.len() as u16).await.is_err()
                        || server.write_all(&answer).await.is_err()
                    {
                        break;
                    }
                }
            });
            Ok(Box::new(client))
        }
    }
    #[tokio::test]
    async fn dns_queries_real_proxy_upstream_instead_of_fake_ip_and_never_falls_back_direct() {
        let hits = Arc::new(AtomicUsize::new(0));
        let cell: RegistryCell = Arc::new(OnceLock::new());
        let group = Arc::new(ProxyGroup::new(
            GroupConfig::new(
                "dns-path",
                GroupKind::Select,
                vec!["test-dns-proxy".into(), "DIRECT".into()],
            ),
            cell.clone(),
        ));
        let mut map: HashMap<String, Arc<dyn Outbound>> = HashMap::new();
        map.insert("test-dns-proxy".into(), Arc::new(DnsProxy(hits.clone())));
        map.insert("dns-path".into(), group.clone());
        map.insert("DIRECT".into(), Arc::new(outbound::basic::Direct));
        let reg = Arc::new(Registry {
            map,
            order: vec![],
            delays: Default::default(),
            unified_delay: false,
            configs: HashMap::from([("test-dns-proxy".into(), ProxyConfig::default())]),
        });
        assert!(cell.set(reg).is_ok());
        let cfg = DnsConfig {
            enable: true,
            ipv6: false,
            enhanced_mode: "fake-ip".into(),
            nameserver: vec!["tcp://192.0.2.53#dns-path&proxy-only=true".into()],
            ..Default::default()
        };
        let (resolver, warnings) = dns::build(
            &cfg,
            &[],
            std::path::Path::new("."),
            cell,
            &Mutex::new(None),
        );
        assert!(warnings.is_empty());
        let p = prism_core::config::parse_any("proxies: []\nrules: ['MATCH,DIRECT']").unwrap();
        let mut core = prism_core::build(
            p,
            std::path::Path::new("."),
            &prism_core::BuildEnv::standalone(),
        )
        .await
        .unwrap();
        core.dns = resolver;
        let fake = core
            .dns
            .as_ref()
            .unwrap()
            .handle(&wire::query(1, "probe.test", wire::TYPE_A))
            .await
            .unwrap();
        assert!(wire::answers(&fake).unwrap().0[0]
            .0
            .to_string()
            .starts_with("198.18."));
        let result = run(
            &core,
            Request::Dns {
                host: "probe.test".into(),
            },
        )
        .await;
        assert_eq!(result["addresses"][0], "203.0.113.50");
        assert_eq!(hits.load(Ordering::Relaxed), 1);
        group.select("DIRECT").unwrap();
        let failed = run(
            &core,
            Request::Dns {
                host: "uncached.test".into(),
            },
        )
        .await;
        assert_eq!(failed["stage"], "dns");
        assert!(failed.get("error").is_some());
        assert_eq!(hits.load(Ordering::Relaxed), 1);
        core.shutdown.cancel();
    }
    #[test]
    fn validates_targets_without_accepting_urls_or_ipv6_bypass() {
        assert!(Request::parse(r#"{"kind":"dns","host":"Example.COM."}"#).is_ok());
        assert!(Request::parse(r#"{"kind":"tcp","host":"127.0.0.1","port":80}"#).is_ok());
        for raw in [
            r#"{"kind":"dns","host":"https://secret@example.com"}"#,
            r#"{"kind":"dns","host":"1.1.1.1"}"#,
            r#"{"kind":"tcp","host":"::1","port":80}"#,
            r#"{"kind":"tcp","host":"example.com","port":0}"#,
            r#"{"kind":"dns","host":"-bad.example"}"#,
        ] {
            assert!(Request::parse(raw).is_err());
        }
    }
    #[tokio::test]
    async fn tcp_probe_reports_actual_direct_rule() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            listener.accept().await.unwrap();
        });
        let p = prism_core::config::parse_any(
            "proxies: []\nrules: ['MATCH,DIRECT']\nfind-process-mode: off",
        )
        .unwrap();
        let core = prism_core::build(
            p,
            std::path::Path::new("."),
            &prism_core::BuildEnv::standalone(),
        )
        .await
        .unwrap();
        let result = run(
            &core,
            Request::Tcp {
                host: "127.0.0.1".into(),
                port,
            },
        )
        .await;
        assert_eq!(result["path"], "直连");
        assert_eq!(result["rule"], "Match");
        assert_eq!(result["chains"][0], "DIRECT");
        task.await.unwrap();
        core.shutdown.cancel();
    }
}
