//! Clash-style rule matching, including `RULE-SET` (rule-providers).

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ipnet::IpNet;
use regex::Regex;

use crate::common::{is_private_ip, Address};
use crate::config::{logical_parts, RuleConfig};
use crate::domain::DomainMatcher;
use crate::geo::{self, DomainSet, IpSet};
use crate::tunnel::{Metadata, Network};

enum Cond {
    Domain(String),
    Suffix(String),
    Keyword(String),
    Regex(Regex),
    GeoSite(Arc<DomainSet>),
    GeoIp(Arc<IpSet>),
    SrcGeoIp(Arc<IpSet>),
    Private,
    SrcPrivate,
    Cidr(IpNet),
    SrcCidr(IpNet),
    DstPort(Vec<(u16, u16)>),
    SrcPort(Vec<(u16, u16)>),
    InType(String),
    Network(Network),
    ProcessName(String),
    ProcessPath(String),
    ProcessNameRegex(Regex),
    ProcessPathRegex(Regex),
    RuleSet(Arc<RuleSet>),
    And(Vec<Cond>),
    Or(Vec<Cond>),
    Not(Box<Cond>),
    Match,
}

/// `chrome` matches `chrome.exe` too.
fn process_name_eq(name: &str, want: &str) -> bool {
    name.eq_ignore_ascii_case(want)
        || (name.len() == want.len() + 4 && name[..want.len()].eq_ignore_ascii_case(want) && name[want.len()..].eq_ignore_ascii_case(".exe"))
}

fn normalize_path(p: &str) -> String {
    p.replace('/', "\\").to_ascii_lowercase()
}

impl Cond {
    fn needs_ip(&self) -> bool {
        match self {
            Cond::GeoIp(_) | Cond::Private | Cond::Cidr(_) => true,
            Cond::RuleSet(rs) => rs.needs_ip,
            Cond::And(c) | Cond::Or(c) => c.iter().any(Cond::needs_ip),
            Cond::Not(c) => c.needs_ip(),
            _ => false,
        }
    }

    fn needs_process(&self) -> bool {
        match self {
            Cond::ProcessName(_) | Cond::ProcessPath(_) | Cond::ProcessNameRegex(_) | Cond::ProcessPathRegex(_) => true,
            Cond::RuleSet(rs) => rs.needs_process,
            Cond::And(c) | Cond::Or(c) => c.iter().any(Cond::needs_process),
            Cond::Not(c) => c.needs_process(),
            _ => false,
        }
    }

    fn matches(&self, meta: &Metadata, ip: Option<IpAddr>) -> bool {
        let host = meta.dst.domain();
        let in_ports = |v: &[(u16, u16)], p: u16| v.iter().any(|(a, b)| p >= *a && p <= *b);
        match self {
            Cond::Domain(d) => host == Some(d.as_str()),
            Cond::Suffix(s) => host.is_some_and(|h| h == s || (h.ends_with(s.as_str()) && h[..h.len() - s.len()].ends_with('.'))),
            Cond::Keyword(k) => host.is_some_and(|h| h.contains(k.as_str())),
            Cond::Regex(r) => host.is_some_and(|h| r.is_match(h)),
            Cond::GeoSite(set) => host.is_some_and(|h| set.matches(h)),
            Cond::GeoIp(set) => ip.is_some_and(|ip| set.contains(ip)),
            Cond::SrcGeoIp(set) => set.contains(meta.src.ip()),
            Cond::Private => ip.is_some_and(is_private_ip) || host == Some("localhost"),
            Cond::SrcPrivate => is_private_ip(meta.src.ip()),
            Cond::Cidr(net) => ip.is_some_and(|ip| net.contains(&ip)),
            Cond::SrcCidr(net) => net.contains(&meta.src.ip()),
            Cond::DstPort(v) => in_ports(v, meta.dst.port()),
            Cond::SrcPort(v) => in_ports(v, meta.src.port()),
            Cond::InType(t) => meta.inbound.eq_ignore_ascii_case(t),
            Cond::Network(n) => meta.network == *n,
            Cond::ProcessName(n) => meta.process.as_ref().is_some_and(|p| process_name_eq(&p.name, n)),
            Cond::ProcessPath(path) => meta.process.as_ref().is_some_and(|p| normalize_path(&p.path) == *path),
            Cond::ProcessNameRegex(r) => meta.process.as_ref().is_some_and(|p| r.is_match(&p.name)),
            Cond::ProcessPathRegex(r) => meta.process.as_ref().is_some_and(|p| r.is_match(&p.path)),
            Cond::RuleSet(rs) => match &rs.matcher {
                SetMatcher::Domain(m) => host.is_some_and(|h| m.matches(h)),
                SetMatcher::IpCidr(set) => ip.is_some_and(|ip| set.contains(ip)),
                SetMatcher::Classical(conds) => conds.iter().any(|c| c.matches(meta, ip)),
            },
            Cond::And(c) => c.iter().all(|c| c.matches(meta, ip)),
            Cond::Or(c) => c.iter().any(|c| c.matches(meta, ip)),
            Cond::Not(c) => !c.matches(meta, ip),
            Cond::Match => true,
        }
    }
}

/// Conditions that need no external data. `None` = unknown rule type,
/// `Some(None)` = invalid payload.
fn simple_cond(kind: &str, p: &str) -> Option<Option<Cond>> {
    Some(match kind {
        "DOMAIN" => Some(Cond::Domain(p.to_ascii_lowercase())),
        "DOMAIN-SUFFIX" => Some(Cond::Suffix(p.trim_start_matches('.').to_ascii_lowercase())),
        "DOMAIN-KEYWORD" => Some(Cond::Keyword(p.to_ascii_lowercase())),
        "DOMAIN-REGEX" => Regex::new(p).ok().map(Cond::Regex),
        "GEOIP" if matches!(p.to_ascii_lowercase().as_str(), "private" | "lan") => Some(Cond::Private),
        "SRC-GEOIP" if matches!(p.to_ascii_lowercase().as_str(), "private" | "lan") => Some(Cond::SrcPrivate),
        "IP-CIDR" | "IP-CIDR6" => parse_net(p).map(Cond::Cidr),
        "SRC-IP-CIDR" => parse_net(p).map(Cond::SrcCidr),
        "DST-PORT" => ports(p).map(Cond::DstPort),
        "SRC-PORT" => ports(p).map(Cond::SrcPort),
        "IN-TYPE" => Some(Cond::InType(p.to_ascii_uppercase())),
        "NETWORK" => match p.to_ascii_lowercase().as_str() {
            "tcp" => Some(Cond::Network(Network::Tcp)),
            "udp" => Some(Cond::Network(Network::Udp)),
            _ => None,
        },
        "PROCESS-NAME" => Some(Cond::ProcessName(p.to_string())),
        "PROCESS-PATH" => Some(Cond::ProcessPath(normalize_path(p))),
        "PROCESS-NAME-REGEX" => Regex::new(p).ok().map(Cond::ProcessNameRegex),
        "PROCESS-PATH-REGEX" => Regex::new(p).ok().map(Cond::ProcessPathRegex),
        "MATCH" => Some(Cond::Match),
        _ => return None,
    })
}

enum SetMatcher {
    Domain(DomainMatcher),
    IpCidr(IpSet),
    Classical(Vec<Cond>),
}

/// A loaded rule-provider.
pub struct RuleSet {
    matcher: SetMatcher,
    needs_ip: bool,
    needs_process: bool,
    pub len: usize,
}

impl RuleSet {
    /// Builds a rule-set from provider entries for `behavior`
    /// (domain / ipcidr / classical). Bad entries are reported in `warnings`.
    pub fn new(name: &str, behavior: &str, entries: &[String], warnings: &mut Vec<String>) -> RuleSet {
        let mut bad = 0;
        let (matcher, len) = match behavior {
            "domain" => {
                let mut m = DomainMatcher::default();
                for e in entries {
                    if !m.add(e) {
                        bad += 1;
                    }
                }
                let n = m.len();
                (SetMatcher::Domain(m), n)
            }
            "ipcidr" => {
                let nets: Vec<IpNet> = entries.iter().filter_map(|e| parse_net(e).or_else(|| { bad += 1; None })).collect();
                let n = nets.len();
                (SetMatcher::IpCidr(IpSet::from_nets(nets)), n)
            }
            _ => {
                let mut conds = Vec::new();
                for e in entries {
                    let mut parts = e.splitn(3, ',').map(str::trim);
                    let kind = parts.next().unwrap_or_default().to_ascii_uppercase();
                    let payload = parts.next().unwrap_or_default();
                    match simple_cond(&kind, payload) {
                        Some(Some(c)) => conds.push(c),
                        _ => bad += 1,
                    }
                }
                let n = conds.len();
                (SetMatcher::Classical(conds), n)
            }
        };
        if bad > 0 {
            warnings.push(format!("rule-provider {name}: {bad} unsupported entries skipped"));
        }
        let needs_ip = match &matcher {
            SetMatcher::IpCidr(_) => true,
            SetMatcher::Classical(c) => c.iter().any(Cond::needs_ip),
            SetMatcher::Domain(_) => false,
        };
        let needs_process = match &matcher {
            SetMatcher::Classical(c) => c.iter().any(Cond::needs_process),
            _ => false,
        };
        RuleSet { matcher, needs_ip, needs_process, len }
    }
}

pub struct Rule {
    pub kind: String,
    pub payload: String,
    pub target: String,
    no_resolve: bool,
    cond: Cond,
}

impl Rule {
    fn needs_ip(&self) -> bool {
        self.cond.needs_ip()
    }

    /// Display name in mihomo style, e.g. `DomainSuffix(google.com)`.
    pub fn display(&self) -> String {
        let kind = match self.kind.as_str() {
            "MATCH" => return "Match".into(),
            "GEOSITE" => "GeoSite".to_string(),
            "GEOIP" => "GeoIP".to_string(),
            "IP-CIDR" | "IP-CIDR6" => "IPCIDR".to_string(),
            "SRC-IP-CIDR" => "SrcIPCIDR".to_string(),
            "SRC-GEOIP" => "SrcGeoIP".to_string(),
            "RULE-SET" => "RuleSet".to_string(),
            "PROCESS-NAME" => "ProcessName".to_string(),
            "PROCESS-PATH" => "ProcessPath".to_string(),
            k => k
                .split('-')
                .map(|w| {
                    let mut c = w.chars();
                    match c.next() {
                        Some(f) => f.to_ascii_uppercase().to_string() + &c.as_str().to_ascii_lowercase(),
                        None => String::new(),
                    }
                })
                .collect::<String>(),
        };
        format!("{kind}({})", self.payload)
    }
}

fn ports(s: &str) -> Option<Vec<(u16, u16)>> {
    s.split(['/', ','])
        .map(|p| match p.split_once('-') {
            Some((a, b)) => Some((a.trim().parse().ok()?, b.trim().parse().ok()?)),
            None => {
                let v = p.trim().parse().ok()?;
                Some((v, v))
            }
        })
        .collect()
}

fn parse_net(s: &str) -> Option<IpNet> {
    s.parse::<IpNet>().ok().or_else(|| s.parse::<IpAddr>().ok().map(IpNet::from))
}

pub struct Router {
    pub rules: Vec<Rule>,
}

/// (kind, payload) of a rule and, for logical rules, of every sub-rule.
fn walk(kind: &str, payload: &str, out: &mut Vec<(String, String)>) {
    if matches!(kind, "AND" | "OR" | "NOT") {
        for (k, p) in logical_parts(payload).unwrap_or_default() {
            walk(&k, &p, out);
        }
    } else {
        out.push((kind.to_string(), payload.to_string()));
    }
}

struct GeoData<'a> {
    sites: HashMap<String, Arc<DomainSet>>,
    ips: HashMap<String, Arc<IpSet>>,
    sets: &'a HashMap<String, Arc<RuleSet>>,
}

/// Why a rule can't be used.
enum Skip {
    /// geodata missing: already reported once, the rule is dropped quietly.
    Quiet,
    Warn(String),
}

impl GeoData<'_> {
    fn cond(&self, kind: &str, p: &str) -> Result<Cond, Skip> {
        let private = matches!(p.to_ascii_lowercase().as_str(), "private" | "lan");
        match kind {
            "GEOSITE" => self.sites.get(p).cloned().map(Cond::GeoSite).ok_or(Skip::Quiet),
            "GEOIP" if !private => self.ips.get(&p.to_ascii_lowercase()).cloned().map(Cond::GeoIp).ok_or(Skip::Quiet),
            "SRC-GEOIP" if !private => self.ips.get(&p.to_ascii_lowercase()).cloned().map(Cond::SrcGeoIp).ok_or(Skip::Quiet),
            "RULE-SET" => self
                .sets
                .get(p)
                .cloned()
                .map(Cond::RuleSet)
                .ok_or_else(|| Skip::Warn(format!("rule-provider {p} not available"))),
            "AND" | "OR" | "NOT" => {
                let parts = logical_parts(p).ok_or_else(|| Skip::Warn(format!("bad {kind} payload {p}")))?;
                let mut conds = Vec::new();
                for (k, sub) in &parts {
                    conds.push(self.cond(k, sub)?);
                }
                Ok(match kind {
                    "AND" => Cond::And(conds),
                    "OR" => Cond::Or(conds),
                    _ if conds.len() == 1 => Cond::Not(Box::new(conds.pop().unwrap())),
                    _ => return Err(Skip::Warn("NOT takes exactly one condition".into())),
                })
            }
            _ => match simple_cond(kind, p) {
                Some(Some(c)) => Ok(c),
                Some(None) => Err(Skip::Warn(format!("invalid payload {kind},{p}"))),
                None => Err(Skip::Warn(format!("rule type {kind} is not supported"))),
            },
        }
    }
}

impl Router {
    pub fn build(cfgs: &[RuleConfig], home: &Path, sets: &HashMap<String, Arc<RuleSet>>) -> (Router, Vec<String>) {
        let mut warnings = Vec::new();
        let mut leaves = Vec::new();
        for r in cfgs {
            walk(&r.kind, &r.payload, &mut leaves);
        }
        let site_codes: Vec<String> = leaves.iter().filter(|(k, _)| k == "GEOSITE").map(|(_, p)| p.clone()).collect();
        let ip_codes: Vec<String> = leaves
            .iter()
            .filter(|(k, p)| (k == "GEOIP" || k == "SRC-GEOIP") && !matches!(p.to_ascii_lowercase().as_str(), "private" | "lan"))
            .map(|(_, p)| p.clone())
            .collect();
        let mut sites: HashMap<String, Arc<DomainSet>> = HashMap::new();
        if !site_codes.is_empty() {
            match geo::load_geosite(&home.join("geosite.dat"), &site_codes) {
                Ok(m) => sites = m.into_iter().map(|(k, v)| (k, Arc::new(v))).collect(),
                Err(e) => warnings.push(format!("geosite.dat: {e}; GEOSITE rules are disabled")),
            }
        }
        let mut ips: HashMap<String, Arc<IpSet>> = HashMap::new();
        if !ip_codes.is_empty() {
            match geo::load_geoip(&home.join("geoip.dat"), &ip_codes) {
                Ok(m) => ips = m.into_iter().map(|(k, v)| (k, Arc::new(v))).collect(),
                Err(e) => warnings.push(format!("geoip.dat: {e}; GEOIP rules are disabled")),
            }
        }

        let geo = GeoData { sites, ips, sets };
        let mut rules = Vec::new();
        for r in cfgs {
            match geo.cond(&r.kind, &r.payload) {
                Ok(cond) => rules.push(Rule {
                    kind: r.kind.clone(),
                    payload: r.payload.clone(),
                    target: r.target.clone(),
                    no_resolve: r.no_resolve,
                    cond,
                }),
                Err(Skip::Quiet) => {}
                Err(Skip::Warn(why)) => warnings.push(format!("rule {}: {why}, skipped", r.to_line())),
            }
        }
        (Router { rules }, warnings)
    }

    /// Returns the first matching rule (None = no rule matched; caller falls
    /// back to DIRECT like mihomo). May resolve the destination domain.
    pub async fn route(&self, meta: &mut Metadata) -> Option<&Rule> {
        for rule in &self.rules {
            if rule.cond.needs_process() {
                meta.lookup_process().await;
            }
            if rule.needs_ip() && meta.dst_ip.is_none() && !rule.no_resolve {
                if let Address::Domain(d, p) = &meta.dst {
                    let lookup = crate::net::resolve(d, *p);
                    if let Ok(Ok(addrs)) = tokio::time::timeout(Duration::from_secs(3), lookup).await {
                        meta.dst_ip = addrs.iter().min_by_key(|a| a.is_ipv6()).map(|a| a.ip());
                    }
                }
            }
            let ip = meta.dst.ip().or(meta.dst_ip);
            if rule.cond.matches(meta, ip) {
                return Some(rule);
            }
        }
        None
    }
}

/// What the rule tester found for one destination.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Hit {
    /// Position in the rule list; None = no rule matched (DIRECT).
    pub index: Option<usize>,
    pub kind: String,
    pub payload: String,
    pub target: String,
    /// The rule as written, e.g. `DOMAIN-SUFFIX,google.com,PROXY`.
    pub line: String,
    /// Whether an IP rule was reached and so the domain had to be resolved.
    pub resolved: bool,
}

impl Router {
    /// [`Router::route`] for the rule tester: the destination IP is given
    /// (looked up by the caller), and is only visible to rules from the first
    /// IP rule without `no-resolve` on, like the real lookup.
    pub fn test(&self, meta: &Metadata, dst_ip: Option<IpAddr>) -> Hit {
        let mut resolved = meta.dst.ip().is_some();
        for (i, rule) in self.rules.iter().enumerate() {
            if rule.needs_ip() && !rule.no_resolve {
                resolved = true;
            }
            let ip = meta.dst.ip().or(if resolved { dst_ip } else { None });
            if rule.cond.matches(meta, ip) {
                let mut line = format!("{},{}", rule.kind, rule.payload);
                if rule.kind == "MATCH" {
                    line = "MATCH".into();
                }
                line = format!("{line},{}", rule.target);
                if rule.no_resolve {
                    line.push_str(",no-resolve");
                }
                return Hit { index: Some(i), kind: rule.kind.clone(), payload: rule.payload.clone(), target: rule.target.clone(), line, resolved };
            }
        }
        Hit { index: None, kind: String::new(), payload: String::new(), target: "DIRECT".into(), line: String::new(), resolved }
    }
}

/// Builds the router of `profile` for the rule tester: rule-providers come
/// from their cached files (downloaded when missing), geodata from `home`.
pub async fn tester(profile: &crate::config::Profile, home: &Path) -> (Router, Vec<String>) {
    let mut warnings = Vec::new();
    let mut sets = HashMap::new();
    for rc in &profile.rule_providers {
        let entries = if rc.kind == "inline" {
            Ok(rc.inline.clone())
        } else {
            let path = crate::provider::path_for(home, "rule_providers", &rc.name, &rc.path);
            let load = crate::provider::load_bytes(&rc.kind, rc.url.as_deref(), &path, 0);
            match tokio::time::timeout(Duration::from_secs(15), load).await {
                Ok(Ok((content, _))) => crate::provider::rule_entries(&rc.format, &rc.behavior, &content),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(anyhow::anyhow!("download timed out")),
            }
        };
        match entries {
            Ok(e) => {
                sets.insert(rc.name.clone(), Arc::new(RuleSet::new(&rc.name, &rc.behavior, &e, &mut warnings)));
            }
            Err(e) => warnings.push(format!("rule-provider {}: {e:#}", rc.name)),
        }
    }
    let (router, w) = Router::build(&profile.rules, home, &sets);
    warnings.extend(w);
    (router, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(dst: &str) -> Metadata {
        Metadata::new(crate::tunnel::Network::Tcp, "HTTP", "127.0.0.1:50000".parse().unwrap(), Address::parse_authority(dst).unwrap(), None)
    }

    #[tokio::test]
    async fn process_rules() {
        let cfgs: Vec<RuleConfig> = [
            "PROCESS-NAME,Chrome,BROWSER",
            "PROCESS-PATH,C:/Tools/Game/game.exe,GAME",
            "PROCESS-NAME-REGEX,^tele.*\\.exe$,TG",
            "MATCH,M",
        ]
        .iter()
        .map(|l| RuleConfig::parse(l).unwrap())
        .collect();
        let (r, w) = Router::build(&cfgs, Path::new("."), &HashMap::new());
        assert!(w.is_empty(), "{w:?}");
        let with = |name: &str, path: &str| {
            let mut m = meta("example.com:443");
            m.process = Some(Arc::new(crate::process::ProcessInfo { pid: 1, name: name.into(), path: path.into() }));
            m.process_checked = true;
            m
        };
        let route = |mut m: Metadata| {
            let r = &r;
            async move { r.route(&mut m).await.unwrap().target.clone() }
        };
        assert_eq!(route(with("chrome.exe", "C:\\x\\chrome.exe")).await, "BROWSER");
        assert_eq!(route(with("game.exe", "c:\\tools\\game\\GAME.EXE")).await, "GAME");
        assert_eq!(route(with("telegram.exe", "C:\\t\\telegram.exe")).await, "TG");
        assert_eq!(route(with("other.exe", "C:\\other.exe")).await, "M");
        let mut unknown = meta("example.com:443");
        unknown.process_checked = true;
        assert_eq!(route(unknown).await, "M");
    }

    #[test]
    fn tester_reports_rule_and_late_resolution() {
        let cfgs: Vec<RuleConfig> = [
            "DOMAIN-SUFFIX,google.com,PROXY",
            "IP-CIDR,10.0.0.0/8,LAN,no-resolve",
            "IP-CIDR,1.0.0.0/8,ONE",
            "MATCH,FINAL",
        ]
        .iter()
        .map(|l| RuleConfig::parse(l).unwrap())
        .collect();
        let (r, _) = Router::build(&cfgs, Path::new("."), &HashMap::new());
        let h = r.test(&meta("www.google.com:443"), None);
        assert_eq!((h.index, h.target.as_str(), h.line.as_str()), (Some(0), "PROXY", "DOMAIN-SUFFIX,google.com,PROXY"));
        assert!(!h.resolved);
        // no-resolve rules don't see the looked-up address; the next IP rule does.
        let h = r.test(&meta("x.example:443"), Some("10.1.1.1".parse().unwrap()));
        assert_eq!((h.index, h.target.as_str()), (Some(3), "FINAL"));
        let h = r.test(&meta("y.example:443"), Some("1.2.3.4".parse().unwrap()));
        assert_eq!((h.index, h.target.as_str(), h.resolved), (Some(2), "ONE", true));
        assert_eq!(r.test(&meta("10.2.2.2:80"), None).target, "LAN");
    }

    #[tokio::test]
    async fn logical_rules() {
        let cfgs: Vec<RuleConfig> = [
            "AND,((NETWORK,udp),(DST-PORT,443)),QUIC",
            "OR,((DOMAIN-SUFFIX,a.com),(DOMAIN-KEYWORD,ads)),AD",
            "NOT,((DST-PORT,80/443)),ODD",
            "AND,((SRC-GEOIP,lan),(OR,((DOMAIN,x.com),(IP-CIDR,9.9.9.0/24)))),NESTED,no-resolve",
            "AND,((NETWORK,tcp),(FOO,bar)),BAD",
            "NOT,((NETWORK,udp),(DST-PORT,1)),BAD2",
            "MATCH,M",
        ]
        .iter()
        .map(|l| RuleConfig::parse(l).unwrap())
        .collect();
        let (r, w) = Router::build(&cfgs, Path::new("."), &HashMap::new());
        assert_eq!(w.len(), 2, "{w:?}");
        assert!(w[0].contains("FOO is not supported"), "{w:?}");
        let route = |dst: &str, net: crate::tunnel::Network| {
            let mut m = meta(dst);
            m.network = net;
            let r = &r;
            async move { r.route(&mut m).await.unwrap().target.clone() }
        };
        use crate::tunnel::Network::{Tcp, Udp};
        assert_eq!(route("1.2.3.4:443", Udp).await, "QUIC");
        assert_eq!(route("www.a.com:443", Tcp).await, "AD");
        assert_eq!(route("ads.example.org:80", Tcp).await, "AD");
        assert_eq!(route("8.8.8.8:22", Tcp).await, "ODD");
        // src 127.0.0.1 is private
        assert_eq!(route("x.com:443", Tcp).await, "NESTED");
        assert_eq!(route("9.9.9.9:80", Tcp).await, "NESTED");
        assert_eq!(route("y.com:443", Tcp).await, "M");
        assert_eq!(r.rules[0].display(), "And(((NETWORK,udp),(DST-PORT,443)))");
    }

    #[tokio::test]
    async fn matching_order() {
        let cfgs: Vec<RuleConfig> = [
            "DOMAIN-SUFFIX,google.com,PROXY",
            "DOMAIN-KEYWORD,baidu,DIRECT",
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
            "GEOIP,private,DIRECT,no-resolve",
            "DST-PORT,22,REJECT",
            "MATCH,PROXY",
        ]
        .iter()
        .map(|l| RuleConfig::parse(l).unwrap())
        .collect();
        let (r, w) = Router::build(&cfgs, Path::new("."), &HashMap::new());
        assert!(w.is_empty(), "{w:?}");
        let t = |d: &str| {
            let r = &r;
            let d = d.to_string();
            async move { r.route(&mut meta(&d)).await.unwrap().target.clone() }
        };
        assert_eq!(t("www.google.com:443").await, "PROXY");
        assert_eq!(t("notgoogle.com:443").await, "PROXY"); // MATCH, not suffix
        assert_eq!(t("www.baidu.com:80").await, "DIRECT");
        assert_eq!(t("10.1.2.3:80").await, "DIRECT");
        assert_eq!(t("192.168.1.1:80").await, "DIRECT");
        assert_eq!(t("8.8.8.8:22").await, "REJECT");
        let m = r.route(&mut meta("a.google.com:1")).await.unwrap();
        assert_eq!(m.display(), "DomainSuffix(google.com)");
    }

    #[tokio::test]
    async fn rule_sets_and_network() {
        let mut w = Vec::new();
        let mut sets = HashMap::new();
        let dom = ["+.google.com", "*.svc.io", "bad*pattern"].map(String::from);
        sets.insert("dom".to_string(), Arc::new(RuleSet::new("dom", "domain", &dom, &mut w)));
        let ips = ["91.108.4.0/22", "2001:b28:f23d::/48"].map(String::from);
        sets.insert("tg".to_string(), Arc::new(RuleSet::new("tg", "ipcidr", &ips, &mut w)));
        let cls = ["DOMAIN-KEYWORD,ads", "DST-PORT,6881-6889", "GEOSITE,cn"].map(String::from);
        sets.insert("cls".to_string(), Arc::new(RuleSet::new("cls", "classical", &cls, &mut w)));
        assert_eq!(w.len(), 2, "{w:?}"); // bad*pattern, GEOSITE inside a rule-set
        let cfgs: Vec<RuleConfig> = [
            "RULE-SET,dom,G",
            "RULE-SET,tg,T,no-resolve",
            "RULE-SET,cls,C",
            "NETWORK,udp,U",
            "RULE-SET,missing,X",
            "MATCH,M",
        ]
        .iter()
        .map(|l| RuleConfig::parse(l).unwrap())
        .collect();
        let (r, w) = Router::build(&cfgs, Path::new("."), &sets);
        assert_eq!(w.len(), 1, "{w:?}"); // missing provider
        let route = |dst: &str, net: crate::tunnel::Network| {
            let mut m = meta(dst);
            m.network = net;
            let r = &r;
            async move { r.route(&mut m).await.unwrap().target.clone() }
        };
        use crate::tunnel::Network::{Tcp, Udp};
        assert_eq!(route("mail.google.com:443", Tcp).await, "G");
        assert_eq!(route("a.svc.io:443", Tcp).await, "G");
        assert_eq!(route("91.108.5.1:443", Tcp).await, "T");
        assert_eq!(route("ads.example.com:80", Tcp).await, "C");
        assert_eq!(route("1.2.3.4:6885", Tcp).await, "C");
        assert_eq!(route("1.2.3.4:53", Udp).await, "U");
        assert_eq!(route("1.2.3.4:53", Tcp).await, "M");
        assert_eq!(r.route(&mut meta("x.google.com:1")).await.unwrap().display(), "RuleSet(dom)");
    }
}
