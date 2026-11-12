//! Ordered mobile rules; every entry is validated, including disabled entries.
use anyhow::{bail, ensure, Result};
use serde::{Deserialize, Serialize};

fn yes() -> bool {
    true
}
fn selected() -> String {
    "SELECTED".into()
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub kind: String,
    pub value: String,
    pub target: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default = "yes", rename = "noResolve")]
    pub no_resolve: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub name: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    pub rules: Vec<Rule>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Routing {
    pub version: u32,
    #[serde(default = "selected", rename = "defaultTarget")]
    pub default_target: String,
    pub groups: Vec<Group>,
}
fn target(value: &str) -> Result<&str> {
    Ok(match value {
        "SELECTED" => "手机节点",
        "DIRECT" => "DIRECT",
        "REJECT" => "REJECT",
        _ => bail!("目标须为 SELECTED、DIRECT 或 REJECT"),
    })
}
fn domain(value: &str) -> bool {
    value.len() <= 253
        && value.split('.').all(|s| {
            !s.is_empty()
                && s.len() <= 63
                && !s.starts_with('-')
                && !s.ends_with('-')
                && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
}
impl Rule {
    fn line(&self) -> Result<String> {
        let value = self.value.trim().to_ascii_lowercase();
        ensure!(
            !value.is_empty()
                && value.len() <= 253
                && !value.chars().any(|c| c.is_control() || c == ','),
            "规则参数为空、过长或含非法分隔符"
        );
        let ip = matches!(self.kind.as_str(), "IP-CIDR" | "SRC-IP-CIDR");
        match self.kind.as_str() {
            "DOMAIN" | "DOMAIN-SUFFIX" => {
                ensure!(domain(&value), "域名格式无效，请使用 ASCII 或 punycode")
            }
            "DOMAIN-KEYWORD" => ensure!(
                value
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b".-_".contains(&c)),
                "域名关键词格式无效"
            ),
            "IP-CIDR" | "SRC-IP-CIDR" => {
                let net: ipnet::IpNet = value
                    .parse()
                    .map_err(|_| anyhow::anyhow!("IP 规则须为 IPv4 CIDR"))?;
                ensure!(net.addr().is_ipv4(), "当前仅支持 IPv4 CIDR");
            }
            "DST-PORT" | "SRC-PORT" => {
                for part in value.split('/') {
                    let (a, b) = part.split_once('-').unwrap_or((part, part));
                    let a: u16 = a.parse().map_err(|_| anyhow::anyhow!("端口格式无效"))?;
                    let b: u16 = b.parse().map_err(|_| anyhow::anyhow!("端口格式无效"))?;
                    ensure!(a > 0 && a <= b, "端口须为 1–65535 且范围递增");
                }
            }
            "NETWORK" => ensure!(
                matches!(value.as_str(), "tcp" | "udp"),
                "网络须为 TCP 或 UDP"
            ),
            _ => bail!("不支持的规则类型"),
        }
        let mut line = format!("{},{},{}", self.kind, value, target(&self.target)?);
        if ip && self.no_resolve {
            line.push_str(",no-resolve");
        }
        Ok(line)
    }
}
impl Routing {
    pub fn compile(&self) -> Result<Vec<String>> {
        ensure!(self.version == 1, "不支持的规则配置版本");
        ensure!(self.groups.len() <= 32, "最多 32 个规则组");
        ensure!(
            self.groups.iter().map(|g| g.rules.len()).sum::<usize>() <= 500,
            "规则最多 500 条"
        );
        let mut lines = Vec::new();
        for group in &self.groups {
            ensure!(
                !group.name.trim().is_empty()
                    && group.name.chars().count() <= 64
                    && !group.name.chars().any(char::is_control),
                "规则组名称须为 1–64 字"
            );
            for rule in &group.rules {
                let line = rule.line()?;
                if group.enabled && rule.enabled {
                    lines.push(line);
                }
            }
        }
        lines.push(format!("MATCH,{}", target(&self.default_target)?));
        Ok(lines)
    }
    /// Strict, bounded CSV paste. No silent skipping or remote rule fetches.
    pub fn import(raw: &str) -> Result<Vec<Rule>> {
        ensure!(raw.len() <= 128 * 1024, "导入规则超过 128 KiB");
        let mut rules = Vec::new();
        for (index, line) in raw.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<_> = line.split(',').map(str::trim).collect();
            ensure!(
                parts.len() == 3 || parts.len() == 4,
                "第 {} 行须为 类型,参数,目标[,no-resolve]",
                index + 1
            );
            ensure!(
                parts.len() != 4
                    || parts[3] == "no-resolve" && matches!(parts[0], "IP-CIDR" | "SRC-IP-CIDR"),
                "第 {} 行标志无效",
                index + 1
            );
            let rule = Rule {
                kind: parts[0].to_owned(),
                value: parts[1].to_owned(),
                target: parts[2].to_owned(),
                enabled: true,
                no_resolve: parts.len() == 4,
            };
            rule.line()
                .map_err(|e| anyhow::anyhow!("第 {} 行：{e}", index + 1))?;
            rules.push(rule);
            ensure!(rules.len() <= 500, "规则最多 500 条");
        }
        ensure!(!rules.is_empty(), "没有可导入的规则");
        Ok(rules)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cidr_no_resolve_and_all_supported_conditions_use_real_router() {
        use prism_core::{
            common::Address,
            rules::Router,
            tunnel::{Metadata, Network},
        };
        let cases = [
            (
                "DOMAIN-KEYWORD,example,DIRECT",
                Address::Domain("www.example.test".into(), 443),
                Network::Tcp,
                "DIRECT",
            ),
            (
                "IP-CIDR,203.0.113.0/24,DIRECT,no-resolve",
                Address::Domain("example.test".into(), 443),
                Network::Tcp,
                "手机节点",
            ),
            (
                "IP-CIDR,203.0.113.0/24,DIRECT",
                Address::Domain("example.test".into(), 443),
                Network::Tcp,
                "DIRECT",
            ),
            (
                "SRC-IP-CIDR,127.0.0.0/8,REJECT",
                Address::Domain("example.test".into(), 443),
                Network::Tcp,
                "REJECT",
            ),
            (
                "DST-PORT,80/440-445,REJECT",
                Address::Domain("example.test".into(), 443),
                Network::Tcp,
                "REJECT",
            ),
            (
                "SRC-PORT,1234,REJECT",
                Address::Domain("example.test".into(), 443),
                Network::Tcp,
                "REJECT",
            ),
            (
                "NETWORK,UDP,REJECT",
                Address::Domain("example.test".into(), 443),
                Network::Udp,
                "REJECT",
            ),
        ];
        for (line, dst, network, want) in cases {
            let routing = Routing {
                version: 1,
                default_target: "SELECTED".into(),
                groups: vec![Group {
                    name: "验收".into(),
                    enabled: true,
                    rules: Routing::import(line).unwrap(),
                }],
            };
            let raw = format!(
                "proxies: [{{name: 手机节点, type: socks5, server: 127.0.0.1, port: 1080}}]\nrules: {}",
                serde_json::to_string(&routing.compile().unwrap()).unwrap()
            );
            let p = prism_core::config::parse_any(&raw).unwrap();
            let (router, warnings) =
                Router::build(&p.rules, std::path::Path::new("."), &Default::default());
            assert!(warnings.is_empty());
            let meta = Metadata::new(network, "Tun", "127.0.0.1:1234".parse().unwrap(), dst, None);
            assert_eq!(
                router
                    .test(&meta, Some("203.0.113.7".parse().unwrap()))
                    .target,
                want,
                "{line}"
            );
        }
        let mut rules = Routing::import("DOMAIN,a.test,DIRECT").unwrap();
        rules.resize(501, rules[0].clone());
        let routing = Routing {
            version: 1,
            default_target: "SELECTED".into(),
            groups: vec![Group {
                name: "超限".into(),
                enabled: true,
                rules,
            }],
        };
        assert!(routing.compile().is_err());
    }
    #[test]
    fn invalid_disabled_rules_and_injection_fail_closed() {
        for line in [
            "DOMAIN,a.test,DIRECT,unexpected",
            "DST-PORT,90-80,DIRECT",
            "NETWORK,quic,REJECT",
            "IP-CIDR,::/0,DIRECT",
            "PROCESS-NAME,app,DIRECT",
            "DOMAIN,a.test,missing",
        ] {
            assert!(Routing::import(line).is_err(), "{line}");
        }
        let mut rules = Routing::import("DOMAIN,a.test,REJECT").unwrap();
        rules[0].enabled = false;
        rules[0].target = "DIRECT\nMATCH,DIRECT".into();
        assert!(Routing {
            version: 1,
            default_target: "SELECTED".into(),
            groups: vec![Group {
                name: "x".into(),
                enabled: false,
                rules
            }]
        }
        .compile()
        .is_err());
    }
    #[test]
    fn ordered_groups_really_hit_and_disabled_entries_do_not() {
        let mut rules = Routing::import(
            "DOMAIN,ads.example.test,REJECT\nDOMAIN-SUFFIX,example.test,DIRECT\nNETWORK,UDP,REJECT",
        )
        .unwrap();
        rules[0].enabled = false;
        let routing = Routing {
            version: 1,
            default_target: "SELECTED".into(),
            groups: vec![Group {
                name: "分流".into(),
                enabled: true,
                rules,
            }],
        };
        let lines = routing.compile().unwrap();
        let raw = format!(
            "proxies: [{{name: 手机节点, type: socks5, server: 127.0.0.1, port: 1080}}]\nrules: {}",
            serde_json::to_string(&lines).unwrap()
        );
        let p = prism_core::config::parse_any(&raw).unwrap();
        let (router, warnings) = prism_core::rules::Router::build(
            &p.rules,
            std::path::Path::new("."),
            &Default::default(),
        );
        assert!(warnings.is_empty());
        let meta = prism_core::tunnel::Metadata::new(
            prism_core::tunnel::Network::Tcp,
            "Tun",
            "127.0.0.1:1234".parse().unwrap(),
            prism_core::common::Address::Domain("ads.example.test".into(), 443),
            None,
        );
        assert_eq!(router.test(&meta, None).target, "DIRECT");
        let mut routing = routing;
        routing.groups[0].rules[0].enabled = true;
        let raw = format!(
            "proxies: [{{name: 手机节点, type: socks5, server: 127.0.0.1, port: 1080}}]\nrules: {}",
            serde_json::to_string(&routing.compile().unwrap()).unwrap()
        );
        let p = prism_core::config::parse_any(&raw).unwrap();
        let (router, warnings) = prism_core::rules::Router::build(
            &p.rules,
            std::path::Path::new("."),
            &Default::default(),
        );
        assert!(warnings.is_empty());
        assert_eq!(router.test(&meta, None).target, "REJECT");
    }
}
