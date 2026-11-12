use anyhow::{bail, ensure, Result};
use prism_core::config::{self, Profile, ProxyConfig, ProxyKind};
use serde::{Deserialize, Serialize};
use serde_json::json;

pub const MAX_IMPORT: usize = 4 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
pub struct Import {
    pub nodes: Vec<ProxyConfig>,
    pub skipped: usize,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct DirectRule {
    pub kind: String,
    pub value: String,
}
#[derive(Serialize, Deserialize)]
pub struct Session {
    pub node: ProxyConfig,
    #[serde(default)]
    pub direct: Vec<DirectRule>,
}

fn supported(node: &ProxyConfig) -> bool {
    matches!(
        node.kind(),
        ProxyKind::AnyTls
            | ProxyKind::Shadowsocks
            | ProxyKind::Trojan
            | ProxyKind::Vless
            | ProxyKind::Socks5
            | ProxyKind::Http
    ) && node.dialer_proxy.is_none()
        && matches!(node.network.as_deref(), None | Some("") | Some("tcp"))
        && node.fingerprint.is_none()
        && node.reality_public_key.is_none()
        && node.flow.is_none()
        && !node.skip_cert_verify
        && !node.server.is_empty()
        && node.port != 0
}
pub fn import(raw: &str) -> Result<Import> {
    ensure!(
        !raw.is_empty() && raw.len() <= MAX_IMPORT,
        "导入内容为空或超过 4 MiB"
    );
    let parsed = config::parse_any(raw)
        .map_err(|_| anyhow::anyhow!("配置解析失败，请检查分享链接或订阅格式"))?;
    ensure!(parsed.proxies.len() <= 2000, "最多导入 2000 个节点");
    let mut skipped = parsed.warnings.len() + parsed.proxy_providers.len();
    let nodes = parsed
        .proxies
        .into_iter()
        .filter(|n| {
            let keep = supported(n);
            if !keep {
                skipped += 1;
            }
            keep
        })
        .collect::<Vec<_>>();
    ensure!(!nodes.is_empty(), "没有首版支持的节点：仅支持基础 TCP/TLS AnyTLS、SS、Trojan、VLESS、SOCKS5、HTTP，且须校验证书");
    Ok(Import { nodes, skipped })
}
pub fn build(s: Session) -> Result<(Profile, String)> {
    ensure!(
        supported(&s.node),
        "所选节点包含首版不支持的协议、传输或证书设置"
    );
    ensure!(s.direct.len() <= 100, "直连规则最多 100 条");
    let mut rules = Vec::new();
    for rule in &s.direct {
        let v = rule.value.trim();
        match rule.kind.as_str() {
            "domain" => {
                ensure!(
                    v.len() <= 253
                        && v.contains('.')
                        && v.split('.').all(|p| !p.is_empty()
                            && p.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')),
                    "域名规则格式不正确"
                );
                rules.push(format!("DOMAIN-SUFFIX,{v},DIRECT"));
            }
            "ip" => {
                let net: ipnet::IpNet = v
                    .parse()
                    .map_err(|_| anyhow::anyhow!("IP 规则须使用 CIDR，如 192.168.1.0/24"))?;
                ensure!(net.addr().is_ipv4(), "首版仅支持 IPv4 直连规则");
                rules.push(format!("IP-CIDR,{net},DIRECT"));
            }
            _ => bail!("不支持的规则类型"),
        }
    }
    rules.push("MATCH,手机节点".into());
    let p = Profile {
        proxies: vec![ProxyConfig {
            name: "手机节点".into(),
            ..s.node
        }],
        ..Default::default()
    };
    let mut doc = config::clash::emit(&p);
    doc["mixed-port"] = 0.into();
    doc.as_mapping_mut()
        .unwrap()
        .remove(serde_yaml::Value::String("external-controller".into()));
    doc["find-process-mode"] = "off".into();
    doc["prism-block-ipv6"] = true.into();
    doc["rules"] = serde_yaml::to_value(&rules)?;
    doc["dns"] = serde_yaml::to_value(json!({
        "enable":true, "ipv6":false, "enhanced-mode":"fake-ip", "fake-ip-range":"198.18.0.1/16",
        "nameserver":["https://1.1.1.1/dns-query#手机节点&proxy-only=true"],
        "proxy-server-nameserver":["https://223.5.5.5/dns-query"]
    }))?;
    let raw = serde_yaml::to_string(&doc)?;
    let mut profile = config::parse_any(&raw)?;
    profile.general.external_controller = None;
    profile.general.find_process_mode = "off".into();
    Ok((profile, raw))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn node() -> ProxyConfig {
        ProxyConfig {
            name: "test".into(),
            kind: Some(ProxyKind::Socks5),
            server: "127.0.0.1".into(),
            port: 1080,
            ..Default::default()
        }
    }
    #[test]
    fn rejects_unsafe_or_dependent_nodes() {
        let mut n = node();
        n.skip_cert_verify = true;
        assert!(!supported(&n));
        n = node();
        n.dialer_proxy = Some("other".into());
        assert!(!supported(&n));
        n = node();
        n.network = Some("xhttp".into());
        assert!(!supported(&n));
        assert!(import("proxies: []").is_err());
    }
    #[test]
    fn mobile_dns_is_proxy_only_and_ipv6_cannot_bypass() {
        let (p, raw) = build(Session {
            node: node(),
            direct: vec![],
        })
        .unwrap();
        assert!(p.general.block_ipv6);
        assert!(p.general.external_controller.is_none());
        assert!(p.dns.enable && !p.dns.ipv6);
        assert!(raw.contains("proxy-only=true"));
        assert!(p.proxy_providers.is_empty() && p.rule_providers.is_empty());
    }
    #[test]
    fn direct_rules_cannot_inject_configuration() {
        assert!(build(Session {
            node: node(),
            direct: vec![DirectRule {
                kind: "domain".into(),
                value: "a.test,REJECT\nrules:".into()
            }]
        })
        .is_err());
        assert!(build(Session {
            node: node(),
            direct: vec![DirectRule {
                kind: "ip".into(),
                value: "192.168.1.0/24".into()
            }]
        })
        .is_ok());
    }
}
