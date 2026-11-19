//! Bounded encrypted DNS settings. Every user DNS path remains proxy-only;
//! only node endpoint bootstrap may use explicit direct encrypted IPv4 servers.
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::HashSet, net::Ipv4Addr};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Policy {
    pub pattern: String,
    pub servers: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Host {
    pub domain: String,
    pub address: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Config {
    pub version: u32,
    pub enabled: bool,
    pub nameservers: Vec<String>,
    pub bootstrap: Vec<String>,
    pub policies: Vec<Policy>,
    pub fallback: Vec<String>,
    pub fallback_domains: Vec<String>,
    pub fallback_cidrs: Vec<String>,
    pub hosts: Vec<Host>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            version: 1,
            enabled: false,
            nameservers: vec!["https://1.1.1.1/dns-query".into()],
            bootstrap: vec!["https://223.5.5.5/dns-query".into()],
            policies: vec![],
            fallback: vec![],
            fallback_domains: vec![],
            fallback_cidrs: vec![],
            hosts: vec![],
        }
    }
}
fn domain(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|s| {
            !s.is_empty()
                && s.len() <= 63
                && !s.starts_with('-')
                && !s.ends_with('-')
                && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
fn pattern(raw: &str) -> Result<String> {
    let value = raw.to_ascii_lowercase();
    let name = value
        .strip_prefix("+.")
        .or_else(|| value.strip_prefix("*."))
        .or_else(|| value.strip_prefix('.'))
        .unwrap_or(&value);
    ensure!(
        domain(name),
        "DNS 域名模式无效，仅支持精确域名、+.、*. 或 . 前缀"
    );
    Ok(value)
}
fn endpoint(raw: &str, bootstrap: bool) -> Result<String> {
    ensure!(
        raw.len() <= 2048
            && !raw
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control()),
        "DNS 地址为空、过长或含空白字符"
    );
    let u = url::Url::parse(raw).map_err(|_| anyhow::anyhow!("DNS 地址格式无效"))?;
    ensure!(
        matches!(u.scheme(), "https" | "tls")
            && u.host_str().is_some()
            && u.username().is_empty()
            && u.password().is_none()
            && u.query().is_none()
            && u.fragment().is_none()
            && u.port() != Some(0),
        "DNS 仅接受不含账号、查询参数或片段的 HTTPS/DoT 地址"
    );
    ensure!(
        !matches!(u.host(), Some(url::Host::Ipv6(_))),
        "DNS IPv6 上游留待双栈验收开放"
    );
    if u.scheme() == "tls" {
        ensure!(u.path().is_empty(), "DoT 地址不能带路径");
    }
    if bootstrap {
        let Some(url::Host::Ipv4(ip)) = u.host() else {
            anyhow::bail!("节点引导 DNS 必须使用加密的公网 IPv4 字面地址，避免递归或系统 DNS");
        };
        ensure!(
            !prism_core::common::is_private_ip(ip.into())
                && !ip.is_multicast()
                && !ip.is_unspecified()
                && !ip.is_broadcast(),
            "节点引导 DNS 必须使用公网 IPv4 地址"
        );
    }
    Ok(u.to_string())
}
fn servers(list: &[String], min: usize, max: usize, bootstrap: bool) -> Result<Vec<String>> {
    ensure!(
        (min..=max).contains(&list.len()),
        "DNS 上游数量超出允许范围"
    );
    let values = list
        .iter()
        .map(|s| endpoint(s, bootstrap))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        values.iter().collect::<HashSet<_>>().len() == values.len(),
        "DNS 上游地址重复"
    );
    Ok(values)
}
impl Config {
    pub fn node_is_loopback(&self, server: &str) -> bool {
        self.enabled
            && server.parse::<std::net::IpAddr>().is_err()
            && self
                .hosts
                .iter()
                .find(|h| h.domain.eq_ignore_ascii_case(server.trim_end_matches('.')))
                .and_then(|h| h.address.parse::<Ipv4Addr>().ok())
                .is_some_and(|ip| ip.is_loopback())
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "不支持的 DNS 配置版本");
        ensure!(
            serde_json::to_vec(self)?.len() <= 64 * 1024,
            "DNS 配置超过 64 KiB"
        );
        servers(&self.nameservers, 1, 3, false)?;
        servers(&self.bootstrap, 1, 2, true)?;
        servers(&self.fallback, 0, 3, false)?;
        ensure!(
            self.policies.len() <= 16
                && self.hosts.len() <= 128
                && self.fallback_domains.len() <= 32
                && self.fallback_cidrs.len() <= 32,
            "DNS 策略、hosts 或 fallback 条目超出上限"
        );
        let mut patterns = HashSet::new();
        for p in &self.policies {
            ensure!(patterns.insert(pattern(&p.pattern)?), "DNS 域名策略重复");
            servers(&p.servers, 1, 2, false)?;
        }
        let mut domains = HashSet::new();
        for p in &self.fallback_domains {
            ensure!(domains.insert(pattern(p)?), "fallback 域名重复");
        }
        let mut cidrs = HashSet::new();
        for cidr in &self.fallback_cidrs {
            let net: ipnet::Ipv4Net = cidr
                .parse()
                .map_err(|_| anyhow::anyhow!("fallback 网段须为 IPv4 CIDR"))?;
            ensure!(cidrs.insert(net.trunc()), "fallback 网段重复");
        }
        ensure!(
            !self.fallback.is_empty()
                || self.fallback_domains.is_empty() && self.fallback_cidrs.is_empty(),
            "请先设置 fallback 上游再配置其域名或网段"
        );
        let mut names = HashSet::new();
        for h in &self.hosts {
            ensure!(
                domain(&h.domain) && names.insert(h.domain.to_ascii_lowercase()),
                "hosts 域名无效或重复"
            );
            let ip: Ipv4Addr = h
                .address
                .parse()
                .map_err(|_| anyhow::anyhow!("hosts 地址须为 IPv4"))?;
            ensure!(
                !ip.is_unspecified()
                    && !ip.is_multicast()
                    && !ip.is_broadcast()
                    && !ipnet::Ipv4Net::new("198.18.0.0".parse().unwrap(), 16)
                        .unwrap()
                        .contains(&ip)
                    && !ipnet::Ipv4Net::new("172.19.0.0".parse().unwrap(), 30)
                        .unwrap()
                        .contains(&ip),
                "hosts 不能使用未指定、组播、广播、fake-IP 或 VPN 内部地址"
            );
        }
        Ok(())
    }
    pub fn apply(&self, doc: &mut serde_yaml::Value) -> Result<()> {
        self.validate()?;
        let defaults = Self::default();
        let cfg = if self.enabled { self } else { &defaults };
        let proxied = |ss: &[String]| -> Result<Vec<String>> {
            Ok(servers(ss, 0, 3, false)?
                .into_iter()
                .map(|s| format!("{s}#手机节点&proxy-only=true"))
                .collect())
        };
        let mut policy = serde_yaml::Mapping::new();
        for p in &cfg.policies {
            policy.insert(
                pattern(&p.pattern)?.into(),
                serde_yaml::to_value(proxied(&p.servers)?)?,
            );
        }
        let mut dns = serde_yaml::to_value(
            json!({"enable":true,"ipv6":false,"enhanced-mode":"fake-ip","fake-ip-range":"198.18.0.1/16",
            "nameserver":proxied(&cfg.nameservers)?,"proxy-server-nameserver":servers(&cfg.bootstrap,1,2,true)?,"default-nameserver":[],
            "fallback":proxied(&cfg.fallback)?,"fallback-filter":{"geoip":false,"ipcidr":cfg.fallback_cidrs,"domain":cfg.fallback_domains},
            "prism-fake-ip-hosts":self.enabled && !cfg.hosts.is_empty()}),
        )?;
        dns["nameserver-policy"] = serde_yaml::Value::Mapping(policy);
        doc["dns"] = dns;
        let mut hosts = serde_yaml::Mapping::new();
        for h in &cfg.hosts {
            hosts.insert(
                h.domain.to_ascii_lowercase().into(),
                h.address.clone().into(),
            );
        }
        doc["hosts"] = serde_yaml::Value::Mapping(hosts);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypted_endpoints_and_bounded_policies_reject_escape_routes() {
        let good = Config::default();
        good.validate().unwrap();
        for address in [
            "udp://1.1.1.1",
            "http://1.1.1.1/dns-query",
            "https://user:password@dns.example/dns-query",
            "https://1.1.1.1/dns-query#DIRECT",
            "https://1.1.1.1/dns-query?skip-cert-verify=true",
            "https://[::1]/dns-query",
            "https://1.1.1.1:0/dns-query",
            "tls://1.1.1.1/path",
        ] {
            let mut bad = good.clone();
            bad.nameservers = vec![address.into()];
            assert!(bad.validate().is_err(), "{address}");
        }
        for bootstrap in [
            "https://dns.example/dns-query",
            "https://127.0.0.1/dns-query",
            "tls://192.168.1.1",
            "https://198.18.0.1/dns-query",
        ] {
            let mut bad = good.clone();
            bad.bootstrap = vec![bootstrap.into()];
            assert!(bad.validate().is_err());
        }
        for address in [
            "::1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "198.18.9.1",
            "172.19.0.2",
        ] {
            let mut bad = good.clone();
            bad.hosts = vec![Host {
                domain: "host.test".into(),
                address: address.into(),
            }];
            assert!(bad.validate().is_err());
        }
        let mut bad = good.clone();
        bad.policies = vec![Policy {
            pattern: "geosite:cn".into(),
            servers: good.nameservers.clone(),
        }];
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.policies = vec![
            Policy {
                pattern: "+.test".into(),
                servers: good.nameservers.clone()
            };
            17
        ];
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.hosts = vec![
            Host {
                domain: "host.test".into(),
                address: "1.1.1.1".into()
            };
            129
        ];
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.nameservers = vec![good.nameservers[0].clone(); 4];
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.fallback_domains = vec!["+.test".into()];
        assert!(bad.validate().is_err());
        let mut value = serde_json::to_value(&good).unwrap();
        value["ipv6"] = true.into();
        assert!(serde_json::from_value::<Config>(value).is_err());
    }
    #[test]
    fn emitted_config_preserves_proxy_only_dns_and_independent_bootstrap() {
        let mut cfg = Config {
            enabled: true,
            ..Default::default()
        };
        cfg.nameservers = vec![
            "https://dns.example/dns-query".into(),
            "tls://1.1.1.1".into(),
        ];
        cfg.policies = vec![Policy {
            pattern: "+.EXAMPLE.com".into(),
            servers: vec!["https://9.9.9.9/dns-query".into()],
        }];
        cfg.fallback = vec!["https://1.1.1.1/dns-query".into()];
        cfg.fallback_domains = vec!["+.example.net".into()];
        cfg.fallback_cidrs = vec!["203.0.113.0/24".into()];
        cfg.hosts = vec![Host {
            domain: "HOST.test".into(),
            address: "192.0.2.10".into(),
        }];
        let mut doc = serde_yaml::Value::Mapping(Default::default());
        doc["proxies"] = serde_yaml::to_value(
            json!([{"name":"fixture","type":"socks5","server":"127.0.0.1","port":1}]),
        )
        .unwrap();
        cfg.apply(&mut doc).unwrap();
        let p = prism_core::config::parse_any(&serde_yaml::to_string(&doc).unwrap()).unwrap();
        assert!(p.dns.enable && !p.dns.ipv6 && p.dns.fake_ip_hosts);
        assert!(p.dns.default_nameserver.is_empty());
        assert!(p
            .dns
            .nameserver
            .iter()
            .chain(&p.dns.fallback)
            .chain(p.dns.nameserver_policy.iter().flat_map(|(_, s)| s))
            .all(|s| s.ends_with("#手机节点&proxy-only=true")));
        assert!(p
            .dns
            .proxy_server_nameserver
            .iter()
            .all(|s| !s.contains('#')));
        assert_eq!(p.dns.nameserver_policy[0].0, "+.example.com");
        assert!(!p.dns.fallback_filter.geoip);
        assert_eq!(p.hosts, vec![("host.test".into(), "192.0.2.10".into())]);
        cfg.hosts.push(Host {
            domain: "loop.test".into(),
            address: "127.0.0.1".into(),
        });
        assert!(cfg.node_is_loopback("LOOP.test."));
        assert!(!cfg.node_is_loopback("127.0.0.1"));
        assert!(!cfg.node_is_loopback("host.test"));
        cfg.enabled = false;
        assert!(!cfg.node_is_loopback("loop.test"));
        cfg.apply(&mut doc).unwrap();
        let p = prism_core::config::parse_any(&serde_yaml::to_string(&doc).unwrap()).unwrap();
        assert!(
            p.hosts.is_empty() && p.dns.nameserver_policy.is_empty() && p.dns.fallback.is_empty()
        );
        assert_eq!(
            p.dns.nameserver,
            ["https://1.1.1.1/dns-query#手机节点&proxy-only=true"]
        );
    }
    #[tokio::test]
    async fn custom_doh_and_dot_reject_untrusted_tls_through_real_socks() {
        use prism_core::{
            config::{ProxyConfig, ProxyKind},
            hub::Hub,
        };
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        use std::time::Duration;
        let certificate = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der()),
        );
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.cert.der().clone()], key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let observed = hits.clone();
        let server = tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                observed.fetch_add(1, Ordering::Relaxed);
                let _ = tokio::time::timeout(Duration::from_secs(3), acceptor.accept(s)).await;
            }
        });
        let peer=prism_core::config::parse_any("proxies: [{name: unused, type: socks5, server: 127.0.0.1, port: 1}]\nrules: ['MATCH,DIRECT']").unwrap();
        let peer = Hub::new(Default::default(), ".".into(), peer)
            .await
            .unwrap();
        let token = tokio_util::sync::CancellationToken::new();
        let service = crate::local_proxy::LocalProxy::start(
            peer.clone(),
            &token,
            0,
            crate::local_proxy::Scope::Loopback,
        )
        .await
        .unwrap();
        for scheme in ["https", "tls"] {
            let upstream = if scheme == "https" {
                format!("https://127.0.0.1:{port}/dns-query")
            } else {
                format!("tls://127.0.0.1:{port}")
            };
            let cfg = Config {
                enabled: true,
                nameservers: vec![upstream],
                ..Default::default()
            };
            let (profile, _) = crate::profile::build(crate::profile::Session {
                node: ProxyConfig {
                    name: "strict TLS".into(),
                    kind: Some(ProxyKind::Socks5),
                    server: "127.0.0.1".into(),
                    port: service.address.port(),
                    ..Default::default()
                },
                direct: vec![],
                routing: None,
                automatic: None,
                geodata: None,
                adblock: None,
                chain: None,
                dns: Some(cfg),
            })
            .unwrap();
            let hub = Hub::new(Default::default(), ".".into(), profile)
                .await
                .unwrap();
            let before = hits.load(Ordering::Relaxed);
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                hub.core().dns.as_ref().unwrap().lookup("strict-cert.test"),
            )
            .await
            .unwrap();
            assert!(result.is_err());
            assert!(
                hits.load(Ordering::Relaxed) > before,
                "TLS server must actually receive the proxied attempt"
            );
            hub.core().shutdown.cancel();
        }
        service.stop().await;
        peer.core().shutdown.cancel();
        server.abort();
        let _ = server.await;
    }
}
