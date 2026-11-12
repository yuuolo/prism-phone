//! DNS module (Clash `dns:` section): upstream servers with
//! nameserver-policy, a cache, hosts, fake-ip and a listening server.
//!
//! Two kinds of lookups:
//! * [`Resolver::handle`] answers queries from clients (the `listen` port
//!   and TUN DNS hijack). These may use fake-ip and proxied (`#PROXY`)
//!   servers.
//! * [`Resolver::lookup`] resolves ordinary targets and IP-rule lookups with
//!   the configured nameserver policy, including proxied upstreams.
//! * [`Resolver::lookup_proxy`] resolves proxy server endpoints using only
//!   the independent direct bootstrap servers; it never races user fallback.
//!
//! With `fallback:` servers, A / AAAA queries that would go to the main
//! servers race both; the main answer is kept unless one of its addresses
//! matches `fallback-filter` (outside `geoip-code`, or in `ipcidr`), and
//! names in `fallback-filter.domain` only ask the fallback servers.

pub mod fakeip;
pub mod upstream;
pub mod wire;

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::common::other;
use crate::config::DnsConfig;
use crate::domain::DomainMatcher;
use crate::outbound::RegistryCell;
use fakeip::FakeIpPool;
use upstream::Upstream;

type Servers = Arc<Vec<Arc<Upstream>>>;

/// When the fallback servers' answer replaces the main one.
struct Fallback {
    servers: Servers,
    /// Addresses of `geoip-code` are trusted.
    geoip: Option<crate::geo::IpSet>,
    ipcidr: Vec<ipnet::IpNet>,
    domain: DomainMatcher,
}

impl Fallback {
    /// Whether an address in the main answer means it is polluted.
    fn bad_ip(&self, ip: IpAddr) -> bool {
        if crate::common::is_private_ip(ip) {
            return false;
        }
        self.geoip.as_ref().is_some_and(|g| !g.contains(ip)) || self.ipcidr.iter().any(|n| n.contains(&ip))
    }
}

pub struct Resolver {
    main: Servers,
    fallback: Option<Fallback>,
    lookup_servers: Servers,
    policy: Vec<(DomainMatcher, Servers)>,
    pub fake: Option<Arc<FakeIpPool>>,
    fake_filter: DomainMatcher,
    ipv6: bool,
    hosts: HashMap<String, Vec<IpAddr>>,
    cache: Mutex<HashMap<(String, u16, usize), (Vec<u8>, Instant)>>,
    pub listen: Option<String>,
}

/// Builds the resolver for an enabled `dns:` section. `fake_slot` keeps the
/// fake-ip pool across reloads so existing mappings stay valid.
pub fn build(
    cfg: &DnsConfig,
    hosts: &[(String, String)],
    home: &Path,
    reg: RegistryCell,
    fake_slot: &Mutex<Option<Arc<FakeIpPool>>>,
) -> (Option<Arc<Resolver>>, Vec<String>) {
    let mut warnings = Vec::new();
    if !cfg.enable {
        return (None, warnings);
    }
    let bootstrap: Arc<Vec<SocketAddr>> = Arc::new(
        cfg.default_nameserver
            .iter()
            .filter_map(|s| {
                let s = s.trim().trim_start_matches("udp://");
                s.parse::<SocketAddr>().ok().or_else(|| s.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, 53)))
            })
            .collect(),
    );
    let mut parse_list = |list: &[String]| -> Vec<Arc<Upstream>> {
        list.iter()
            .filter_map(|s| match Upstream::parse(s, bootstrap.clone(), reg.clone()) {
                Ok(u) => Some(Arc::new(u)),
                Err(e) => {
                    warnings.push(e);
                    None
                }
            })
            .collect()
    };
    let main = parse_list(&cfg.nameserver);
    let proxy_ns = parse_list(&cfg.proxy_server_nameserver);
    let defaults = parse_list(&cfg.default_nameserver);
    let mut policy_servers = Vec::new();
    for (_, servers) in &cfg.nameserver_policy {
        policy_servers.push(parse_list(servers));
    }
    let direct_main: Vec<_> = main.iter().filter(|u| u.is_direct()).cloned().collect();
    let lookup_servers = [proxy_ns.iter().filter(|u| u.is_direct()).cloned().collect(), direct_main, defaults.iter().filter(|u| u.is_direct()).cloned().collect()]
        .into_iter()
        .find(|l| !l.is_empty())
        .unwrap_or_default();
    let main = if main.is_empty() { defaults.clone() } else { main };
    if main.is_empty() {
        warnings.push("dns: no usable nameserver, DNS module disabled".into());
        return (None, warnings);
    }
    let fallback_servers = parse_list(&cfg.fallback);

    // Patterns: domains plus geosite categories.
    let mut geo_codes: Vec<String> = Vec::new();
    let split = |key: &str| -> Vec<String> {
        let mut out = Vec::new();
        let mut in_geo = false;
        for part in key.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            if let Some(code) = part.strip_prefix("geosite:") {
                in_geo = true;
                out.push(format!("geosite:{code}"));
            } else if in_geo && !part.contains('.') {
                out.push(format!("geosite:{part}"));
            } else {
                in_geo = false;
                out.push(part.to_string());
            }
        }
        out
    };
    let policy_keys: Vec<Vec<String>> = cfg.nameserver_policy.iter().map(|(k, _)| split(k)).collect();
    let filter_keys: Vec<String> = cfg.fake_ip_filter.iter().flat_map(|k| split(k)).collect();
    let fallback_domains: Vec<String> = cfg.fallback_filter.domain.iter().flat_map(|k| split(k)).collect();
    for p in policy_keys.iter().flatten().chain(filter_keys.iter()).chain(fallback_domains.iter()) {
        if let Some(code) = p.strip_prefix("geosite:") {
            geo_codes.push(code.to_string());
        }
    }
    let sites = if geo_codes.is_empty() {
        HashMap::new()
    } else {
        match crate::geo::load_geosite(&home.join("geosite.dat"), &geo_codes) {
            Ok(m) => m.into_iter().map(|(k, v)| (k, Arc::new(v))).collect(),
            Err(e) => {
                warnings.push(format!("dns: geosite.dat: {e}; geosite patterns ignored"));
                HashMap::new()
            }
        }
    };
    let mut matcher = |patterns: &[String]| {
        let mut m = DomainMatcher::default();
        for p in patterns {
            if let Some(code) = p.strip_prefix("geosite:") {
                if let Some(s) = sites.get(code) {
                    m.add_set(s.clone());
                }
            } else if !m.add(p) {
                warnings.push(format!("dns: unsupported domain pattern {p}"));
            }
        }
        m
    };
    let policy: Vec<(DomainMatcher, Servers)> = policy_keys
        .iter()
        .zip(policy_servers)
        .filter(|(_, s)| !s.is_empty())
        .map(|(k, s)| (matcher(k), Arc::new(s)))
        .collect();
    let fake_filter = matcher(&filter_keys);
    let fallback_domain = matcher(&fallback_domains);
    let fallback = if fallback_servers.is_empty() {
        None
    } else {
        let f = &cfg.fallback_filter;
        let geoip = if f.geoip && !f.geoip_code.is_empty() {
            let code = f.geoip_code.to_ascii_lowercase();
            match crate::geo::load_geoip(&home.join("geoip.dat"), std::slice::from_ref(&code)) {
                Ok(mut m) => m.remove(&code),
                Err(e) => {
                    warnings.push(format!("dns: geoip.dat: {e}; fallback-filter geoip ignored"));
                    None
                }
            }
        } else {
            None
        };
        let ipcidr = f
            .ipcidr
            .iter()
            .filter_map(|c| {
                let n = c.parse::<ipnet::IpNet>().ok().or_else(|| c.parse::<IpAddr>().ok().map(ipnet::IpNet::from));
                if n.is_none() {
                    warnings.push(format!("dns: fallback-filter ipcidr {c} is invalid"));
                }
                n
            })
            .collect();
        Some(Fallback { servers: Arc::new(fallback_servers), geoip, ipcidr, domain: fallback_domain })
    };

    let fake = if cfg.enhanced_mode == "fake-ip" {
        let range = if cfg.fake_ip_range.is_empty() { "198.18.0.1/16" } else { &cfg.fake_ip_range };
        let mut slot = fake_slot.lock().unwrap();
        match slot.as_ref() {
            Some(p) if p.range.to_string() == range.parse::<ipnet::Ipv4Net>().map(|n| n.to_string()).unwrap_or_default() => Some(p.clone()),
            _ => match FakeIpPool::new(range) {
                Some(p) => {
                    let p = Arc::new(p);
                    *slot = Some(p.clone());
                    Some(p)
                }
                None => {
                    warnings.push(format!("dns: bad fake-ip-range {range}"));
                    None
                }
            },
        }
    } else {
        None
    };

    let mut host_map: HashMap<String, Vec<IpAddr>> = HashMap::new();
    for (name, ip) in hosts {
        match ip.parse::<IpAddr>() {
            Ok(ip) => host_map.entry(name.trim_end_matches('.').to_ascii_lowercase()).or_default().push(ip),
            Err(_) => warnings.push(format!("hosts: {name} -> {ip} is not an IP address (ignored)")),
        }
    }

    let r = Resolver {
        main: Arc::new(main),
        fallback,
        lookup_servers: Arc::new(lookup_servers),
        policy,
        fake,
        fake_filter,
        ipv6: cfg.ipv6,
        hosts: host_map,
        cache: Mutex::new(HashMap::new()),
        listen: cfg.listen.clone().filter(|l| !l.is_empty()),
    };
    (Some(Arc::new(r)), warnings)
}

/// Cache-key tag for the main server list and for lookups.
const MAIN: usize = usize::MAX;
const LOOKUP: usize = usize::MAX - 1;
const FALLBACK: usize = usize::MAX - 2;

impl Resolver {
    pub fn is_fake(&self, ip: IpAddr) -> bool {
        self.fake.as_ref().is_some_and(|f| f.contains(ip))
    }

    pub fn fake_domain(&self, ip: IpAddr) -> Option<String> {
        self.fake.as_ref()?.domain(ip)
    }

    fn servers_for(&self, name: &str) -> (Servers, usize) {
        for (i, (m, s)) in self.policy.iter().enumerate() {
            if m.matches(name) {
                return (s.clone(), i);
            }
        }
        (self.main.clone(), MAIN)
    }

    /// Answers a client query. Returns None for unparseable input.
    pub async fn handle(&self, query: &[u8]) -> Option<Vec<u8>> {
        let (q, _) = wire::question(query)?;
        let is_addr = q.qtype == wire::TYPE_A || q.qtype == wire::TYPE_AAAA;
        if q.qtype == wire::TYPE_AAAA && !self.ipv6 {
            return wire::response(query, wire::RCODE_NOERROR, &[]);
        }
        if is_addr {
            if let Some(ips) = self.hosts.get(&q.name) {
                let want_v4 = q.qtype == wire::TYPE_A;
                let ans: Vec<(IpAddr, u32)> = ips.iter().filter(|ip| ip.is_ipv4() == want_v4).map(|ip| (*ip, 10)).collect();
                return wire::response(query, wire::RCODE_NOERROR, &ans);
            }
        }
        if let Some(fake) = &self.fake {
            if is_addr && !self.fake_filter.matches(&q.name) {
                if q.qtype == wire::TYPE_AAAA {
                    return wire::response(query, wire::RCODE_NOERROR, &[]);
                }
                let ip = fake.get(&q.name);
                return wire::response(query, wire::RCODE_NOERROR, &[(IpAddr::V4(ip), 1)]);
            }
        }
        let (servers, tag) = self.servers_for(&q.name);
        let res = if tag == MAIN { self.exchange_main(&servers, tag, &q.name, q.qtype, query).await } else { self.exchange(&servers, tag, &q.name, q.qtype, query).await };
        match res {
            Ok(mut r) => {
                wire::set_id(&mut r, wire::id(query));
                Some(r)
            }
            Err(e) => {
                tracing::debug!("dns {} {}: {e}", q.name, q.qtype);
                wire::response(query, wire::RCODE_SERVFAIL, &[])
            }
        }
    }

    /// Real addresses of `host` for outgoing connections.
    pub async fn lookup(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        self.lookup_inner(host, false).await
    }

    /// Only proxy server endpoints may use the independent bootstrap servers.
    pub async fn lookup_proxy(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        self.lookup_inner(host, true).await
    }

    async fn lookup_inner(&self, host: &str, proxy: bool) -> io::Result<Vec<IpAddr>> {
        let name = host.trim_end_matches('.').to_ascii_lowercase();
        if let Some(ips) = self.hosts.get(&name) {
            return Ok(ips.iter().copied().filter(|ip| self.ipv6 || ip.is_ipv4()).collect());
        }
        let mut out = Vec::new();
        let mut qtypes = vec![wire::TYPE_A];
        if self.ipv6 {
            qtypes.push(wire::TYPE_AAAA);
        }
        // Only ordinary targets follow nameserver policies. Proxy endpoints
        // must use independent bootstrap DNS to avoid recursive dialing.
        let (policy, tag) = self.servers_for(&name);
        let use_policy = tag != MAIN && !proxy;
        let mut last = None;
        for qt in qtypes {
            let q = wire::query(rand::random(), &name, qt);
            let res = if proxy {
                self.exchange(&self.lookup_servers.clone(), LOOKUP, &name, qt, &q).await
            } else if use_policy {
                self.exchange(&policy, tag, &name, qt, &q).await
            } else {
                self.exchange_main(&self.main.clone(), MAIN, &name, qt, &q).await
            };
            match res {
                Ok(r) => {
                    if let Some((ips, _)) = wire::answers(&r) {
                        out.extend(ips.into_iter().map(|(ip, _)| ip));
                    }
                }
                Err(e) => last = Some(e),
            }
            if !out.is_empty() {
                break;
            }
        }
        if out.is_empty() {
            return Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{name}: no address"))));
        }
        Ok(out)
    }

    /// [`Resolver::exchange`] on the main (or lookup) servers, with the
    /// fallback servers when configured: both are asked at once, and the
    /// main answer wins unless it is empty or has a filtered address.
    async fn exchange_main(&self, servers: &Servers, tag: usize, name: &str, qtype: u16, query: &[u8]) -> io::Result<Vec<u8>> {
        let fb = match &self.fallback {
            Some(f) if qtype == wire::TYPE_A || qtype == wire::TYPE_AAAA => f,
            _ => return self.exchange(servers, tag, name, qtype, query).await,
        };
        if fb.domain.matches(name) {
            return self.exchange(&fb.servers, FALLBACK, name, qtype, query).await;
        }
        let main = self.exchange(servers, tag, name, qtype, query);
        let other = self.exchange(&fb.servers, FALLBACK, name, qtype, query);
        tokio::pin!(main, other);
        let mut early = None;
        let main_res = loop {
            tokio::select! {
                r = &mut main => break r,
                r = &mut other, if early.is_none() => early = Some(r),
            }
        };
        if let Ok(r) = &main_res {
            let ips = wire::answers(r).map(|(a, _)| a).unwrap_or_default();
            if !ips.is_empty() && ips.iter().all(|(ip, _)| !fb.bad_ip(*ip)) {
                return main_res;
            }
        }
        let fb_res = match early {
            Some(r) => r,
            None => other.await,
        };
        match (fb_res, main_res) {
            (Ok(r), _) => {
                tracing::debug!("dns {name}: using the fallback answer");
                Ok(r)
            }
            // Fallback failed: a main answer is better than none.
            (Err(_), Ok(r)) => Ok(r),
            (Err(e), Err(_)) => Err(e),
        }
    }

    /// Cached exchange racing all servers of a group; the first usable
    /// answer (NOERROR or NXDOMAIN) wins.
    async fn exchange(&self, servers: &Servers, tag: usize, name: &str, qtype: u16, query: &[u8]) -> io::Result<Vec<u8>> {
        let key = (name.to_string(), qtype, tag);
        if let Some((r, exp)) = self.cache.lock().unwrap().get(&key) {
            if Instant::now() < *exp {
                return Ok(r.clone());
            }
        }
        if servers.is_empty() {
            return Err(other("no dns server"));
        }
        let tries = servers.iter().map(|u| {
            let u = u.clone();
            Box::pin(async move {
                let r = u.exchange(query).await?;
                match wire::rcode(&r) {
                    wire::RCODE_NOERROR | wire::RCODE_NXDOMAIN => Ok(r),
                    rc => Err(other(format!("dns {}: rcode {rc}", u.url))),
                }
            })
        });
        let (resp, _) = futures::future::select_ok(tries).await?;
        let ttl = wire::answers(&resp).and_then(|(_, t)| t).unwrap_or(30).clamp(1, 3600);
        let mut cache = self.cache.lock().unwrap();
        if cache.len() > 4096 {
            let now = Instant::now();
            cache.retain(|_, (_, exp)| *exp > now);
        }
        cache.insert(key, (resp.clone(), Instant::now() + Duration::from_secs(ttl as u64)));
        Ok(resp)
    }
}

/// Serves DNS over UDP on `listen` using whatever resolver is current.
pub async fn serve(sock: tokio::net::UdpSocket, hub: std::sync::Weak<crate::hub::Hub>) {
    let sock = Arc::new(sock);
    let mut buf = vec![0u8; 4096];
    loop {
        let Ok((n, peer)) = sock.recv_from(&mut buf).await else { continue };
        let Some(hub) = hub.upgrade() else { return };
        let Some(r) = hub.core().dns.clone() else { continue };
        let (q, sock) = (buf[..n].to_vec(), sock.clone());
        tokio::spawn(async move {
            if let Some(resp) = r.handle(&q).await {
                let _ = sock.send_to(&resp, peer).await;
            }
        });
    }
}
