//! Unified profile model. Clash/mihomo YAML, sing-box JSON and share-link
//! subscriptions are all parsed into [`Profile`], which can be emitted again
//! as Clash YAML (for prism-core and mihomo) or sing-box JSON.

pub mod clash;
pub mod singbox;
pub mod uri;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyKind {
    Shadowsocks,
    Trojan,
    Vless,
    Vmess,
    AnyTls,
    Hysteria2,
    Tuic,
    WireGuard,
    Socks5,
    Http,
}

impl ProxyKind {
    /// Type string as used by Clash (`type:` field) and its REST API.
    pub fn clash_type(self) -> &'static str {
        match self {
            ProxyKind::Shadowsocks => "ss",
            ProxyKind::Trojan => "trojan",
            ProxyKind::Vless => "vless",
            ProxyKind::Vmess => "vmess",
            ProxyKind::AnyTls => "anytls",
            ProxyKind::Hysteria2 => "hysteria2",
            ProxyKind::Tuic => "tuic",
            ProxyKind::WireGuard => "wireguard",
            ProxyKind::Socks5 => "socks5",
            ProxyKind::Http => "http",
        }
    }

    pub fn from_clash_type(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "ss" | "shadowsocks" => ProxyKind::Shadowsocks,
            "trojan" => ProxyKind::Trojan,
            "vless" => ProxyKind::Vless,
            "vmess" => ProxyKind::Vmess,
            "anytls" => ProxyKind::AnyTls,
            "hysteria2" | "hy2" => ProxyKind::Hysteria2,
            "tuic" => ProxyKind::Tuic,
            "wireguard" | "wg" => ProxyKind::WireGuard,
            "socks5" | "socks" => ProxyKind::Socks5,
            "http" => ProxyKind::Http,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    pub name: String,
    pub kind: Option<ProxyKind>,
    pub server: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub uuid: Option<String>,
    pub cipher: Option<String>,
    pub alter_id: u32,
    pub tls: bool,
    pub sni: Option<String>,
    pub skip_cert_verify: bool,
    pub alpn: Vec<String>,
    pub fingerprint: Option<String>,
    pub flow: Option<String>,
    /// Transport: tcp (default), ws, httpupgrade, grpc, h2, xhttp.
    pub network: Option<String>,
    /// Path / Host of ws, httpupgrade, h2 and xhttp.
    pub ws_path: Option<String>,
    pub ws_host: Option<String>,
    pub grpc_service: Option<String>,
    /// xhttp: auto / stream-one / stream-up / packet-up.
    pub xhttp_mode: Option<String>,
    /// xhttp: `x_padding` length range, e.g. `100-1000`.
    pub xhttp_padding: Option<String>,
    pub reality_public_key: Option<String>,
    pub reality_short_id: Option<String>,
    pub obfs: Option<String>,
    pub obfs_password: Option<String>,
    pub udp: bool,
    /// Outbound (proxy or group) used to reach this node's server
    /// (Clash `dialer-proxy`).
    pub dialer_proxy: Option<String>,
    /// TUIC: congestion-controller (cubic / new_reno / bbr).
    pub congestion: Option<String>,
    /// TUIC: udp-relay-mode (native = QUIC datagrams, quic = streams).
    pub udp_relay_mode: Option<String>,
    /// WireGuard: this peer's private key, the server's public key and the
    /// optional pre-shared key (base64).
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub pre_shared_key: Option<String>,
    /// WireGuard: tunnel addresses, e.g. `172.16.0.2/32`, `fd01::2/128`.
    pub ip: Option<String>,
    pub ipv6: Option<String>,
    /// WireGuard: the 3 reserved header bytes (Cloudflare WARP client id).
    pub reserved: Vec<u8>,
    pub mtu: Option<u16>,
    pub allowed_ips: Vec<String>,
}

impl ProxyConfig {
    pub fn kind(&self) -> ProxyKind {
        self.kind.unwrap_or(ProxyKind::Http)
    }
}

/// WireGuard `reserved`: `1,2,3` or the base64 of the three bytes (`AQID`).
pub fn parse_reserved(s: &str) -> Vec<u8> {
    let s = s.trim().trim_start_matches('[').trim_end_matches(']');
    if s.contains(',') {
        return s.split(',').filter_map(|x| x.trim().parse().ok()).collect();
    }
    uri::b64_decode(s).filter(|b| b.len() == 3).unwrap_or_default()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GroupKind {
    Select,
    UrlTest,
    Fallback,
    LoadBalance,
    /// Chains the members: traffic goes through the first, then the second...
    Relay,
}

impl GroupKind {
    pub fn clash_type(self) -> &'static str {
        match self {
            GroupKind::Select => "select",
            GroupKind::UrlTest => "url-test",
            GroupKind::Fallback => "fallback",
            GroupKind::LoadBalance => "load-balance",
            GroupKind::Relay => "relay",
        }
    }

    /// Type name reported by the Clash REST API.
    pub fn api_type(self) -> &'static str {
        match self {
            GroupKind::Select => "Selector",
            GroupKind::UrlTest => "URLTest",
            GroupKind::Fallback => "Fallback",
            GroupKind::LoadBalance => "LoadBalance",
            GroupKind::Relay => "Relay",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupConfig {
    pub name: String,
    pub kind: GroupKind,
    pub proxies: Vec<String>,
    pub url: String,
    /// Health-check interval in seconds.
    pub interval: u64,
    /// url-test switch threshold in milliseconds.
    pub tolerance: u64,
    /// proxy-providers whose nodes are appended to `proxies` (Clash `use`).
    #[serde(default)]
    pub use_providers: Vec<String>,
    /// Regex on node names from providers (Clash `filter` / `exclude-filter`).
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default)]
    pub exclude_filter: Option<String>,
}

pub const DEFAULT_TEST_URL: &str = "https://www.gstatic.com/generate_204";

impl GroupConfig {
    pub fn new(name: &str, kind: GroupKind, proxies: Vec<String>) -> Self {
        GroupConfig {
            name: name.to_string(),
            kind,
            proxies,
            url: DEFAULT_TEST_URL.into(),
            interval: 300,
            tolerance: 50,
            use_providers: Vec::new(),
            filter: None,
            exclude_filter: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleConfig {
    /// Upper-case rule type, e.g. DOMAIN-SUFFIX, GEOIP, MATCH.
    pub kind: String,
    pub payload: String,
    pub target: String,
    pub no_resolve: bool,
}

/// Splits on commas outside parentheses, so logical rules keep their
/// payload together: `AND,((NETWORK,udp),(DST-PORT,443)),REJECT`.
pub fn split_rule(line: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut depth, mut start) = (0i32, 0);
    for (i, c) in line.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth <= 0 => {
                parts.push(line[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(line[start..].trim());
    parts
}

/// The sub-rules of a logical rule payload: `((NETWORK,udp),(DST-PORT,443))`
/// -> [(NETWORK, udp), (DST-PORT, 443)]. None when malformed.
pub fn logical_parts(payload: &str) -> Option<Vec<(String, String)>> {
    let inner = payload.trim().strip_prefix('(')?.strip_suffix(')')?;
    let mut out = Vec::new();
    for item in split_rule(inner) {
        let item = item.strip_prefix('(')?.strip_suffix(')')?;
        let parts = split_rule(item);
        let kind = parts.first()?.to_ascii_uppercase();
        if kind.is_empty() {
            return None;
        }
        out.push((kind, parts.get(1).map(|s| s.to_string()).unwrap_or_default()));
    }
    (!out.is_empty()).then_some(out)
}

impl RuleConfig {
    /// Parses a Clash rule line: `TYPE,payload,target[,no-resolve]` or `MATCH,target`.
    pub fn parse(line: &str) -> Option<Self> {
        let parts = split_rule(line);
        let kind = parts.first()?.to_ascii_uppercase();
        if kind == "MATCH" || kind == "FINAL" {
            return Some(RuleConfig {
                kind: "MATCH".into(),
                payload: String::new(),
                target: parts.get(1)?.to_string(),
                no_resolve: false,
            });
        }
        Some(RuleConfig {
            kind,
            payload: parts.get(1)?.to_string(),
            target: parts.get(2)?.to_string(),
            no_resolve: parts.iter().skip(3).any(|p| p.eq_ignore_ascii_case("no-resolve")),
        })
    }

    pub fn to_line(&self) -> String {
        if self.kind == "MATCH" {
            return format!("MATCH,{}", self.target);
        }
        let mut s = format!("{},{},{}", self.kind, self.payload, self.target);
        if self.no_resolve {
            s.push_str(",no-resolve");
        }
        s
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Rule,
    Global,
    Direct,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "rule" => Some(Mode::Rule),
            "global" => Some(Mode::Global),
            "direct" => Some(Mode::Direct),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Rule => "rule",
            Mode::Global => "global",
            Mode::Direct => "direct",
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TunConfig {
    pub enable: bool,
    pub auto_route: bool,
    /// Give the adapter an IPv6 address and route IPv6 into it too
    /// (`inet6-address` present).
    pub ipv6: bool,
    /// Plain-IP DNS servers used for queries sent to the TUN's own DNS address.
    pub dns: Vec<String>,
}

impl TunConfig {
    pub fn dns_upstream(&self) -> Vec<std::net::IpAddr> {
        let v: Vec<std::net::IpAddr> = self.dns.iter().filter_map(|s| s.trim().parse().ok()).collect();
        if v.is_empty() {
            vec!["223.5.5.5".parse().unwrap(), "119.29.29.29".parse().unwrap()]
        } else {
            v
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct General {
    #[serde(default)]
    pub block_ipv6: bool,
    #[serde(default)]
    pub tailscale_bypass: bool,
    pub mixed_port: u16,
    pub allow_lan: bool,
    pub bind_address: String,
    pub mode: Mode,
    pub log_level: String,
    pub external_controller: Option<String>,
    pub secret: String,
    #[serde(default)]
    pub tun: TunConfig,
    #[serde(default)]
    pub unified_delay: bool,
    /// always / strict / off (Clash `find-process-mode`).
    #[serde(default)]
    pub find_process_mode: String,
}

impl Default for General {
    fn default() -> Self {
        General {
            block_ipv6: false,
            tailscale_bypass: false,
            mixed_port: 7890,
            allow_lan: false,
            bind_address: "*".into(),
            mode: Mode::Rule,
            log_level: "info".into(),
            external_controller: Some("127.0.0.1:9090".into()),
            secret: String::new(),
            tun: TunConfig::default(),
            unified_delay: false,
            find_process_mode: "strict".into(),
        }
    }
}

/// A per-application rule added by the GUI: connections from the program
/// (matched by file name or full path) go to `target`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRoute {
    pub by_path: bool,
    pub value: String,
    /// Proxy / group name, DIRECT or REJECT.
    pub target: String,
    /// A target missing from the profile rejects the connections instead of
    /// leaving them to the rules below.
    pub strict: bool,
}

impl AppRoute {
    /// Program name as the cores expect it: `chrome` -> `chrome.exe` on
    /// Windows; macOS names have no extension.
    pub fn process_name(&self) -> String {
        let v = self.value.trim();
        if self.by_path || v.contains('.') || !cfg!(windows) {
            v.to_string()
        } else {
            format!("{v}.exe")
        }
    }

    fn valid(&self) -> Result<(), String> {
        let v = self.value.trim();
        if v.is_empty() {
            return Err("empty program".into());
        }
        if v.contains(',') || self.target.contains(',') {
            return Err(format!("{v}: commas are not allowed"));
        }
        Ok(())
    }
}

/// A domain / IP rule added by the GUI (域名 / IP 分流): connections to the
/// domain / address go to `target`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserRule {
    /// DOMAIN-SUFFIX, DOMAIN, DOMAIN-KEYWORD, IP-CIDR, GEOSITE or GEOIP.
    pub kind: String,
    pub value: String,
    /// Proxy / group name, DIRECT or REJECT.
    pub target: String,
    /// IP rules: resolve domain destinations to match them too (slower).
    #[serde(default)]
    pub resolve: bool,
    /// A target missing from the profile rejects the connections instead of
    /// leaving them to the rules below.
    #[serde(default)]
    pub strict: bool,
}

/// A domain that must resolve to its real address (no fake-ip), optionally
/// through a server of its own.
#[derive(Clone, Debug)]
pub struct RealIpDomain {
    pub domain: String,
    pub subdomains: bool,
    /// Empty: the profile's servers.
    pub dns: String,
}

impl RealIpDomain {
    pub fn pattern(&self) -> String {
        if self.subdomains {
            format!("+.{}", self.domain)
        } else {
            self.domain.clone()
        }
    }
}

/// A DNS server a real IP rule may name: reached directly, so no `#proxy`.
pub fn valid_dns_server(spec: &str) -> bool {
    let spec = spec.trim();
    if spec.is_empty() || spec.contains(|c: char| c.is_whitespace() || c == '#') {
        return false;
    }
    match spec.split_once("://") {
        Some((scheme, rest)) => ["udp", "tcp", "tls", "https", "quic", "h3"].contains(&scheme) && !rest.is_empty(),
        None => spec.parse::<std::net::IpAddr>().is_ok() || spec.parse::<std::net::SocketAddr>().is_ok(),
    }
}

/// What a later relay hop can be turned into.
pub enum RelayHop {
    Node,
    /// A group whose members are all known.
    Group(Vec<String>),
    /// A provider's group, another relay, or nothing at all.
    Unknown,
}

/// One thing to add for a relay on cores that only have per-node dialers.
#[derive(Debug, PartialEq)]
pub enum RelayCopy {
    /// A copy of node `base` dialing through `via`.
    Node { name: String, base: String, via: String },
    /// A copy of group `base` over copies of its members.
    Group { name: String, base: String, members: Vec<String> },
}

fn copy_hop(hop: &str, name: &str, via: &str, kind: &dyn Fn(&str) -> RelayHop, out: &mut Vec<RelayCopy>, depth: u32) -> Option<()> {
    match kind(hop) {
        RelayHop::Node => out.push(RelayCopy::Node { name: name.into(), base: hop.into(), via: via.into() }),
        RelayHop::Group(list) if depth < 8 => {
            let mut members = Vec::new();
            for m in list {
                match m.as_str() {
                    // Going direct from here means leaving at the previous hop.
                    "DIRECT" => members.push(via.to_string()),
                    "REJECT" => members.push(m),
                    _ => {
                        let copy = format!("{name} · {m}");
                        copy_hop(&m, &copy, via, kind, out, depth + 1)?;
                        members.push(copy);
                    }
                }
            }
            out.push(RelayCopy::Group { name: name.into(), base: hop.into(), members });
        }
        _ => return None,
    }
    Some(())
}

/// Rebuilds a relay from dialers: the first hop stays what it is, each later
/// one becomes a copy that dials through the hop before it, the last taking
/// the relay's name. `None` if a later hop can't be copied.
pub fn plan_relay(name: &str, hops: &[String], kind: &dyn Fn(&str) -> RelayHop) -> Option<Vec<RelayCopy>> {
    let mut prev = hops.first()?.clone();
    let mut out = Vec::new();
    let later = &hops[1..];
    for (i, h) in later.iter().enumerate() {
        let copy = if i + 1 == later.len() { name.to_string() } else { format!("{name} · {}", i + 1) };
        copy_hop(h, &copy, &prev, kind, &mut out, 0)?;
        prev = copy;
    }
    Some(out)
}

/// A chain set up in the GUI: traffic goes through `hops`, nodes or groups,
/// in order. Becomes a relay group, used as an exit by name.
#[derive(Clone, Debug)]
pub struct Chain {
    pub name: String,
    pub hops: Vec<String>,
}

impl Chain {
    /// What keeps this chain from being added to a profile.
    fn problem(&self, kind: impl Fn(&str) -> RelayHop, taken: impl Fn(&str) -> bool) -> Option<String> {
        if self.name.trim().is_empty() || self.name.contains(',') {
            return Some("invalid name".into());
        }
        if taken(&self.name) {
            return Some("its name is already used by a node or group".into());
        }
        if self.hops.len() < 2 {
            return Some("it needs at least two hops".into());
        }
        if !taken(&self.hops[0]) || ["DIRECT", "REJECT", "GLOBAL"].contains(&self.hops[0].as_str()) {
            return Some(format!("{} is not a node or group of this profile", self.hops[0]));
        }
        // The first hop may be anything; later ones must be copyable on every core.
        if plan_relay(&self.name, &self.hops, &kind).is_none() {
            return Some("a later hop is not a node or a group with fixed members of this profile".into());
        }
        if self.hops.iter().enumerate().any(|(i, h)| self.hops[..i].contains(h)) {
            return Some("a hop appears twice".into());
        }
        None
    }
}

pub const USER_RULE_KINDS: [&str; 6] = ["DOMAIN-SUFFIX", "DOMAIN", "DOMAIN-KEYWORD", "IP-CIDR", "GEOSITE", "GEOIP"];

impl UserRule {
    /// The rule as the cores take it, with the value cleaned up (a pasted
    /// URL becomes its host, a single IP a /32 or /128 network).
    pub fn to_rule(&self) -> Result<RuleConfig, String> {
        let kind = self.kind.trim().to_ascii_uppercase();
        if !USER_RULE_KINDS.contains(&kind.as_str()) {
            return Err(format!("unknown rule type {kind}"));
        }
        let target = self.target.trim();
        if target.is_empty() || target.contains(',') {
            return Err(format!("{}: bad target {target}", self.value));
        }
        let mut v = self.value.trim().to_string();
        if v.is_empty() || v.contains([',', ' ', '\t']) {
            return Err(format!("{v}: empty or contains commas / spaces"));
        }
        let ip = kind == "IP-CIDR" || kind == "GEOIP";
        match kind.as_str() {
            "DOMAIN" | "DOMAIN-SUFFIX" => {
                if let Some(host) = v.contains("://").then(|| url::Url::parse(&v).ok().and_then(|u| u.host_str().map(String::from))).flatten() {
                    v = host;
                }
                v = v.trim_start_matches("*.").trim_start_matches("+.").trim_start_matches('.').trim_end_matches('.').to_ascii_lowercase();
                if v.is_empty() || v.contains(['/', ':', '*']) {
                    return Err(format!("{}: not a domain", self.value));
                }
            }
            "DOMAIN-KEYWORD" => v = v.to_ascii_lowercase(),
            "IP-CIDR" => {
                let net = v
                    .parse::<ipnet::IpNet>()
                    .or_else(|_| v.parse::<std::net::IpAddr>().map(ipnet::IpNet::from))
                    .map_err(|_| format!("{v}: not an IP address or network"))?;
                v = net.trunc().to_string();
            }
            _ => {
                if !v.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '@' | '!' | '.')) {
                    return Err(format!("{v}: not a GEOSITE / GEOIP code"));
                }
            }
        }
        Ok(RuleConfig { kind, payload: v, target: target.to_string(), no_resolve: ip && !self.resolve })
    }
}

/// Clash `dns:` section.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DnsConfig {
    pub enable: bool,
    pub listen: Option<String>,
    pub ipv6: bool,
    /// normal / fake-ip / redir-host
    pub enhanced_mode: String,
    pub fake_ip_range: String,
    pub fake_ip_filter: Vec<String>,
    pub default_nameserver: Vec<String>,
    pub nameserver: Vec<String>,
    pub proxy_server_nameserver: Vec<String>,
    /// (domain patterns, servers), in order.
    pub nameserver_policy: Vec<(String, Vec<String>)>,
    /// Servers whose answer is used when the main one looks polluted.
    #[serde(default)]
    pub fallback: Vec<String>,
    #[serde(default)]
    pub fallback_filter: FallbackFilter,
}

/// `fallback-filter:` — when the main servers' answer is replaced by the
/// fallback servers' (mihomo semantics).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FallbackFilter {
    /// An address outside `geoip_code` means the answer is polluted.
    pub geoip: bool,
    pub geoip_code: String,
    /// Addresses in these ranges mean polluted.
    pub ipcidr: Vec<String>,
    /// Names that always use the fallback servers.
    pub domain: Vec<String>,
}

impl Default for FallbackFilter {
    fn default() -> Self {
        FallbackFilter { geoip: true, geoip_code: "CN".into(), ipcidr: Vec::new(), domain: Vec::new() }
    }
}

/// One entry of `proxy-providers:`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProxyProviderConfig {
    pub name: String,
    /// http / file / inline
    pub kind: String,
    pub url: Option<String>,
    pub path: Option<String>,
    /// Refresh interval in seconds (http).
    pub interval: u64,
    pub filter: Option<String>,
    pub exclude_filter: Option<String>,
    pub health_check: bool,
    pub health_check_url: Option<String>,
    pub health_check_interval: u64,
    /// Outbound used to download (default DIRECT).
    pub proxy: Option<String>,
    /// `inline` providers carry their nodes directly.
    pub inline: Vec<ProxyConfig>,
}

/// One entry of `rule-providers:`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RuleProviderConfig {
    pub name: String,
    /// http / file / inline
    pub kind: String,
    /// domain / ipcidr / classical
    pub behavior: String,
    /// yaml / text / mrs
    pub format: String,
    pub url: Option<String>,
    pub path: Option<String>,
    pub interval: u64,
    pub proxy: Option<String>,
    pub inline: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Profile {
    pub general: General,
    pub proxies: Vec<ProxyConfig>,
    pub groups: Vec<GroupConfig>,
    pub rules: Vec<RuleConfig>,
    pub dns: DnsConfig,
    /// Static `hosts:` entries (name, ip).
    pub hosts: Vec<(String, String)>,
    pub proxy_providers: Vec<ProxyProviderConfig>,
    pub rule_providers: Vec<RuleProviderConfig>,
    /// Things that were skipped while parsing (unknown proxy types, ...).
    pub warnings: Vec<String>,
}

impl Profile {
    pub fn relay_hop(&self, name: &str) -> RelayHop {
        if self.proxies.iter().any(|p| p.name == name) {
            return RelayHop::Node;
        }
        match self.groups.iter().find(|g| g.name == name) {
            Some(g) if g.kind != GroupKind::Relay && g.use_providers.is_empty() => RelayHop::Group(g.proxies.clone()),
            _ => RelayHop::Unknown,
        }
    }

    /// Adds the GUI's chains as relay groups. Returns warnings for skipped ones.
    pub fn add_chains(&mut self, chains: &[Chain]) -> Vec<String> {
        let mut warnings = Vec::new();
        for c in chains {
            let problem = c.problem(
                |n| self.relay_hop(n),
                |n| ["DIRECT", "REJECT", "GLOBAL"].contains(&n) || self.proxies.iter().any(|p| p.name == n) || self.groups.iter().any(|g| g.name == n),
            );
            if let Some(e) = problem {
                warnings.push(format!("chain {} skipped: {e}", c.name));
                continue;
            }
            self.groups.push(GroupConfig::new(&c.name, GroupKind::Relay, c.hops.clone()));
        }
        warnings
    }
}

/// Built-in outbound names that are always available.
pub const BUILTIN: [&str; 3] = ["DIRECT", "REJECT", "GLOBAL"];

impl Profile {
    /// Adds a default group layout + China-direct rules for subscriptions that
    /// only carry nodes (share-link lists).
    pub fn with_default_groups(mut self) -> Self {
        let names: Vec<String> = self.proxies.iter().map(|p| p.name.clone()).collect();
        if self.groups.is_empty() && !names.is_empty() {
            let mut sel = vec!["自动选择".to_string()];
            sel.extend(names.iter().cloned());
            sel.push("DIRECT".into());
            self.groups.push(GroupConfig::new("节点选择", GroupKind::Select, sel));
            self.groups.push(GroupConfig::new("自动选择", GroupKind::UrlTest, names));
        }
        if self.rules.is_empty() {
            let target = self.groups.first().map(|g| g.name.clone()).unwrap_or_else(|| "DIRECT".into());
            for line in [
                "GEOSITE,private,DIRECT",
                "GEOIP,private,DIRECT,no-resolve",
                "GEOSITE,cn,DIRECT",
                "GEOIP,CN,DIRECT",
            ] {
                self.rules.push(RuleConfig::parse(line).unwrap());
            }
            self.rules.push(RuleConfig::parse(&format!("MATCH,{target}")).unwrap());
        }
        self
    }

    /// Drops references to unknown outbounds so that every group / rule target
    /// resolves. Groups left empty fall back to DIRECT.
    pub fn sanitize(&mut self) {
        let mut known: std::collections::HashSet<String> =
            self.proxies.iter().map(|p| p.name.clone()).collect();
        known.extend(self.groups.iter().map(|g| g.name.clone()));
        known.extend(BUILTIN.iter().map(|s| s.to_string()));
        let mut warnings = Vec::new();
        for g in &mut self.groups {
            g.proxies.retain(|p| {
                let ok = known.contains(p);
                if !ok {
                    warnings.push(format!("group {}: unknown member {p}", g.name));
                }
                ok
            });
            // Groups filled from providers are completed when the core loads them.
            if g.proxies.is_empty() && g.use_providers.is_empty() {
                g.proxies.push("DIRECT".into());
            }
        }
        self.rules.retain(|r| {
            let ok = known.contains(&r.target);
            if !ok {
                warnings.push(format!("rule {}: unknown target", r.to_line()));
            }
            ok
        });
        self.warnings.extend(warnings);
    }
}

/// Detected format of a raw subscription / config file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Clash,
    SingBox,
    Uri,
}

pub fn detect(raw: &str) -> Format {
    let t = raw.trim_start_matches('\u{feff}').trim();
    if t.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(t) {
            if v.get("outbounds").is_some() || v.get("inbounds").is_some() {
                return Format::SingBox;
            }
            if v.get("proxies").is_some() {
                return Format::Clash;
            }
        }
    }
    if let Ok(serde_yaml::Value::Mapping(m)) = serde_yaml::from_str::<serde_yaml::Value>(t) {
        if m.contains_key("proxies") || m.contains_key("proxy-groups") || m.contains_key("proxy-providers") {
            return Format::Clash;
        }
    }
    // Broken YAML that is clearly a Clash config: report the YAML error
    // instead of "no nodes found".
    if t.lines().any(|l| l.starts_with("proxies:") || l.starts_with("proxy-groups:")) {
        return Format::Clash;
    }
    Format::Uri
}

/// Parses any supported format into a [`Profile`].
pub fn parse_any(raw: &str) -> anyhow::Result<Profile> {
    let t = raw.trim_start_matches('\u{feff}');
    let mut p = match detect(t) {
        Format::Clash => clash::parse(&serde_yaml::from_str(t)?)?,
        Format::SingBox => singbox::parse(&serde_json::from_str(t)?)?,
        Format::Uri => {
            let (proxies, warnings) = uri::parse_list(t);
            if proxies.is_empty() {
                anyhow::bail!("no supported nodes found in subscription");
            }
            Profile { proxies, warnings, ..Default::default() }.with_default_groups()
        }
    };
    p.sanitize();
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_lines() {
        let r = RuleConfig::parse("GEOIP,private,DIRECT,no-resolve").unwrap();
        assert!(r.no_resolve);
        assert_eq!(r.to_line(), "GEOIP,private,DIRECT,no-resolve");
        assert_eq!(RuleConfig::parse("FINAL,PROXY").unwrap().to_line(), "MATCH,PROXY");
        let and = RuleConfig::parse("AND,((NETWORK,udp),(DST-PORT,443)),REJECT").unwrap();
        assert_eq!((and.kind.as_str(), and.payload.as_str(), and.target.as_str()), ("AND", "((NETWORK,udp),(DST-PORT,443))", "REJECT"));
        assert_eq!(and.to_line(), "AND,((NETWORK,udp),(DST-PORT,443)),REJECT");
        let not = RuleConfig::parse("NOT,((DOMAIN-SUFFIX,cn)),PROXY,no-resolve").unwrap();
        assert!(not.no_resolve);
        assert_eq!(not.payload, "((DOMAIN-SUFFIX,cn))");
        assert_eq!(
            logical_parts("((NETWORK,udp),(OR,((DST-PORT,443),(DST-PORT,80))))").unwrap(),
            vec![("NETWORK".to_string(), "udp".to_string()), ("OR".to_string(), "((DST-PORT,443),(DST-PORT,80))".to_string())]
        );
        assert!(logical_parts("(NETWORK,udp)").is_none());
        assert!(logical_parts("").is_none());
    }

    #[test]
    fn detects_formats() {
        assert_eq!(detect("proxies:\n  - {name: a, type: ss}\n"), Format::Clash);
        assert_eq!(detect(r#"{"outbounds":[]}"#), Format::SingBox);
        assert_eq!(detect("anytls://pw@a.com:443#x"), Format::Uri);
    }
}
