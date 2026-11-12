//! prism-core: a small rule-based proxy core.
//!
//! Mixed (SOCKS5 + HTTP) inbound and TUN -> rule router -> outbounds
//! (AnyTLS, Shadowsocks AEAD, Trojan, VLESS, Hysteria2, TUIC, WireGuard,
//! SOCKS5, HTTP, groups, relay chains), TCP and UDP, with a DNS module (fake-ip), proxy / rule providers and a
//! Clash-compatible REST API. Config is Clash/mihomo YAML (or any format
//! understood by [`config::parse_any`]).

pub mod api;
pub mod common;
pub mod config;
pub mod delay;
pub mod dns;
#[cfg(windows)]
mod dns_guard;
pub mod domain;
pub mod geo;
pub mod http;
pub mod hub;
pub mod mrs;
pub mod inbound;
pub mod net;
mod network;
pub mod outbound;
pub mod process;
pub mod provider;
pub mod rules;
pub mod sniff;
pub mod tun;
pub mod tunnel;

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

use anyhow::{Context, Result};
use regex::Regex;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use config::{General, GroupConfig, GroupKind, Profile, ProxyConfig};
use outbound::{basic, Outbound, ProxyGroup, Registry};
use provider::{ProxyProviderInfo, RuleProviderInfo};
use tunnel::{Stats, Tunnel};

pub struct Core {
    pub general: General,
    pub home: PathBuf,
    pub tunnel: Arc<Tunnel>,
    pub dns: Option<Arc<dns::Resolver>>,
    pub proxy_providers: Vec<ProxyProviderInfo>,
    pub rule_providers: Vec<RuleProviderInfo>,
    pub warnings: Vec<String>,
    /// Cancelled when this core is replaced; stops its background tasks.
    pub shutdown: CancellationToken,
}

/// State shared by all cores built over the process lifetime.
pub struct BuildEnv {
    pub stats: Arc<Stats>,
    /// Ask the hub to reload (a provider changed).
    pub reload: mpsc::UnboundedSender<()>,
    pub fake_pool: Mutex<Option<Arc<dns::fakeip::FakeIpPool>>>,
}

impl BuildEnv {
    /// For one-off builds (config checks, tests).
    pub fn standalone() -> Self {
        BuildEnv { stats: Default::default(), reload: mpsc::unbounded_channel().0, fake_pool: Default::default() }
    }
}

fn regex_opt(pattern: &Option<String>, what: &str, warnings: &mut Vec<String>) -> Option<Regex> {
    let p = pattern.as_ref()?;
    match Regex::new(p) {
        Ok(r) => Some(r),
        Err(e) => {
            warnings.push(format!("{what}: bad regex {p}: {e}"));
            None
        }
    }
}

/// Builds outbounds, groups, DNS and rules from a profile, loading providers
/// (downloads happen here). `home` holds geodata and provider files.
pub async fn build(mut profile: Profile, home: &Path, env: &BuildEnv) -> Result<Core> {
    let mut warnings = std::mem::take(&mut profile.warnings);
    let shutdown = CancellationToken::new();

    // ---- proxy-providers
    let mut provider_nodes: HashMap<String, Vec<String>> = HashMap::new();
    let mut proxy_providers = Vec::new();
    let mut names: HashSet<String> = profile.proxies.iter().map(|p| p.name.clone()).collect();
    names.extend(profile.groups.iter().map(|g| g.name.clone()));
    names.extend(config::BUILTIN.iter().map(|s| s.to_string()));
    let mut extra: Vec<ProxyConfig> = Vec::new();
    for pc in &profile.proxy_providers {
        let what = format!("proxy-provider {}", pc.name);
        let path = (pc.kind != "inline").then(|| provider::path_for(home, "proxy_providers", &pc.name, &pc.path));
        let mut nodes = if pc.kind == "inline" {
            pc.inline.clone()
        } else {
            match provider::load(&pc.kind, pc.url.as_deref(), path.as_ref().unwrap(), pc.interval).await {
                Ok((content, warn)) => {
                    if let Some(w) = warn {
                        warnings.push(format!("{what}: {w}"));
                    }
                    match config::parse_any(&content) {
                        Ok(p) => {
                            warnings.extend(p.warnings.into_iter().map(|w| format!("{what}: {w}")));
                            p.proxies
                        }
                        Err(e) => {
                            warnings.push(format!("{what}: {e:#}"));
                            Vec::new()
                        }
                    }
                }
                Err(e) => {
                    warnings.push(format!("{what}: {e:#}"));
                    Vec::new()
                }
            }
        };
        let keep = regex_opt(&pc.filter, &what, &mut warnings);
        let drop = regex_opt(&pc.exclude_filter, &what, &mut warnings);
        nodes.retain(|n| keep.as_ref().is_none_or(|r| r.is_match(&n.name)) && drop.as_ref().is_none_or(|r| !r.is_match(&n.name)));
        let mut list = Vec::new();
        for mut n in nodes {
            if names.contains(&n.name) {
                n.name = format!("{} [{}]", n.name, pc.name);
            }
            if names.insert(n.name.clone()) {
                list.push(n.name.clone());
                extra.push(n);
            }
        }
        provider_nodes.insert(pc.name.clone(), list.clone());
        let updated_at = path.as_deref().and_then(provider::updated_at);
        proxy_providers.push(ProxyProviderInfo { cfg: pc.clone(), path, proxies: list, updated_at });
    }

    // ---- groups pull in provider nodes (`use` + `filter`)
    for g in &mut profile.groups {
        if g.use_providers.is_empty() {
            continue;
        }
        let what = format!("group {}", g.name);
        let keep = regex_opt(&g.filter, &what, &mut warnings);
        let drop = regex_opt(&g.exclude_filter, &what, &mut warnings);
        for p in g.use_providers.clone() {
            match provider_nodes.get(&p) {
                Some(list) => g.proxies.extend(
                    list.iter()
                        .filter(|n| keep.as_ref().is_none_or(|r| r.is_match(n)) && drop.as_ref().is_none_or(|r| !r.is_match(n)))
                        .cloned(),
                ),
                None => warnings.push(format!("{what}: unknown proxy-provider {p}")),
            }
        }
        if g.proxies.is_empty() {
            g.proxies.push("DIRECT".into());
        }
    }

    // ---- protocol outbounds; drop the ones prism-core can't speak
    let cell: outbound::RegistryCell = Arc::new(OnceLock::new());
    let mut configs = HashMap::new();
    let mut map: HashMap<String, Arc<dyn Outbound>> = HashMap::new();
    let mut order = Vec::new();
    let mut kept = Vec::new();
    let provider_names: HashSet<String> = extra.iter().map(|p| p.name.clone()).collect();
    profile.proxies.extend(extra);
    for p in &profile.proxies {
        let dialer = outbound::Dialer::named(p.dialer_proxy.as_deref(), &cell);
        match outbound::build_proxy(p, dialer) {
            Ok(o) => {
                map.insert(p.name.clone(), o);
                configs.insert(p.name.clone(), p.clone());
                kept.push(p.clone());
            }
            Err(e) => warnings.push(e.to_string()),
        }
    }
    profile.proxies = kept;
    profile.sanitize();
    warnings.append(&mut profile.warnings);
    for pp in &mut proxy_providers {
        pp.proxies.retain(|n| map.contains_key(n));
    }

    map.insert("DIRECT".into(), Arc::new(basic::Direct));
    map.insert("REJECT".into(), Arc::new(basic::Reject));

    let mut groups = Vec::new();
    let mut global_members = Vec::new();
    for g in &profile.groups {
        let grp = Arc::new(ProxyGroup::new(g.clone(), cell.clone()));
        map.insert(g.name.clone(), grp.clone());
        groups.push(grp);
        global_members.push(g.name.clone());
        order.push(g.name.clone());
    }
    for p in &profile.proxies {
        // Provider nodes appear in GLOBAL only through their groups / providers.
        if !provider_names.contains(&p.name) {
            global_members.push(p.name.clone());
        }
        order.push(p.name.clone());
    }
    global_members.extend(["DIRECT".to_string(), "REJECT".to_string()]);
    order.extend(["DIRECT".to_string(), "REJECT".to_string()]);
    let global = Arc::new(ProxyGroup::new(GroupConfig::new("GLOBAL", GroupKind::Select, global_members), cell.clone()));
    map.insert("GLOBAL".into(), global);
    order.insert(0, "GLOBAL".into());

    let reg = Arc::new(Registry { map, order, delays: Default::default(), unified_delay: profile.general.unified_delay, configs });
    for p in &profile.proxies {
        if let Some(d) = p.dialer_proxy.as_deref().filter(|d| reg.get(d).is_none()) {
            warnings.push(format!("proxy {}: dialer-proxy {d} is not available, so this node can't connect", p.name));
        }
    }
    let _ = cell.set(reg.clone());
    for g in groups {
        g.spawn_health_loop(shutdown.clone());
    }

    // ---- provider refresh + health checks
    for pp in &proxy_providers {
        if let (Some(url), Some(path)) = (pp.cfg.url.clone(), pp.path.clone()) {
            if pp.cfg.kind == "http" {
                let via = pp.cfg.proxy.as_ref().and_then(|n| reg.get(n));
                let tx = env.reload.clone();
                provider::spawn_refresh(url, path, pp.cfg.interval, via, shutdown.clone(), move || {
                    let _ = tx.send(());
                });
            }
        }
        if pp.cfg.health_check && !pp.proxies.is_empty() {
            let (reg, nodes, stop) = (reg.clone(), pp.proxies.clone(), shutdown.clone());
            let url = pp.cfg.health_check_url.clone().unwrap_or_else(|| config::DEFAULT_TEST_URL.into());
            let every = Duration::from_secs(pp.cfg.health_check_interval.max(10));
            tokio::spawn(async move {
                loop {
                    let tests = nodes.iter().map(|n| delay::url_test(&reg, n, &url, Duration::from_secs(5)));
                    tokio::select! {
                        _ = stop.cancelled() => return,
                        _ = futures::future::join_all(tests) => {}
                    }
                    tokio::select! {
                        _ = stop.cancelled() => return,
                        _ = tokio::time::sleep(every) => {}
                    }
                }
            });
        }
    }

    // ---- rule-providers
    let mut rule_sets = HashMap::new();
    let mut rule_providers = Vec::new();
    for rc in &profile.rule_providers {
        let what = format!("rule-provider {}", rc.name);
        let path = (rc.kind != "inline").then(|| provider::path_for(home, "rule_providers", &rc.name, &rc.path));
        let entries = if rc.kind == "inline" {
            Ok(rc.inline.clone())
        } else {
            match provider::load_bytes(&rc.kind, rc.url.as_deref(), path.as_ref().unwrap(), rc.interval).await {
                Ok((content, warn)) => {
                    if let Some(w) = warn {
                        warnings.push(format!("{what}: {w}"));
                    }
                    provider::rule_entries(&rc.format, &rc.behavior, &content)
                }
                Err(e) => Err(e),
            }
        };
        let count = match entries {
            Ok(entries) => {
                let set = rules::RuleSet::new(&rc.name, &rc.behavior, &entries, &mut warnings);
                let n = set.len;
                rule_sets.insert(rc.name.clone(), Arc::new(set));
                n
            }
            Err(e) => {
                warnings.push(format!("{what}: {e:#}"));
                0
            }
        };
        if let (Some(url), Some(p), "http") = (rc.url.clone(), path.clone(), rc.kind.as_str()) {
            let via = rc.proxy.as_ref().and_then(|n| reg.get(n));
            let tx = env.reload.clone();
            provider::spawn_refresh(url, p, rc.interval, via, shutdown.clone(), move || {
                let _ = tx.send(());
            });
        }
        let updated_at = path.as_deref().and_then(provider::updated_at);
        rule_providers.push(RuleProviderInfo { cfg: rc.clone(), path, count, updated_at });
    }

    // ---- DNS + rules
    let (resolver, mut dns_warnings) = dns::build(&profile.dns, &profile.hosts, home, cell.clone(), &env.fake_pool);
    warnings.append(&mut dns_warnings);
    let (router, mut rule_warnings) = rules::Router::build(&profile.rules, home, &rule_sets);
    warnings.append(&mut rule_warnings);

    let tunnel = Arc::new(Tunnel {
        reg,
        router,
        mode: RwLock::new(profile.general.mode),
        stats: env.stats.clone(),
        dns: resolver.clone(),
        find_process: tunnel::FindProcess::parse(&profile.general.find_process_mode),
        block_ipv6: profile.general.block_ipv6,
        tailscale_bypass: profile.general.tailscale_bypass,
    });
    Ok(Core {
        general: profile.general,
        home: home.to_path_buf(),
        tunnel,
        dns: resolver,
        proxy_providers,
        rule_providers,
        warnings,
        shutdown,
    })
}

fn listen_addr(g: &General) -> SocketAddr {
    let ip = if g.allow_lan {
        match g.bind_address.as_str() {
            "*" | "" => "0.0.0.0".parse().unwrap(),
            a => a.parse().unwrap_or_else(|_| "0.0.0.0".parse().unwrap()),
        }
    } else {
        "127.0.0.1".parse().unwrap()
    };
    SocketAddr::new(ip, g.mixed_port)
}

/// Starts the inbounds (mixed TCP + UDP, DNS, TUN) and the API, then runs
/// until the process exits. Listeners stay up across reloads.
pub async fn run(hub: Arc<hub::Hub>) -> Result<()> {
    let core = hub.core();
    for w in &core.warnings {
        tracing::warn!("{w}");
    }
    let addr = listen_addr(&core.general);
    let listener = tokio::net::TcpListener::bind(addr).await.with_context(|| format!("listen on {addr}"))?;
    tracing::info!("Mixed(http+socks) proxy listening at: {addr}");
    tokio::spawn(inbound::serve(listener, hub.clone()));
    match tokio::net::UdpSocket::bind(addr).await {
        Ok(u) => {
            tokio::spawn(inbound::serve_udp(u, hub.clone()));
        }
        Err(e) => tracing::warn!("SOCKS5 UDP on {addr} unavailable: {e}"),
    }

    if let Some(listen) = core.dns.as_ref().and_then(|d| d.listen.clone()) {
        let l = tokio::net::UdpSocket::bind(&listen).await.with_context(|| format!("dns listen on {listen}"))?;
        tracing::info!("DNS server listening at: {listen}");
        tokio::spawn(dns::serve(l, Arc::downgrade(&hub)));
    }

    if core.general.tun.enable {
        tun::start(&core.general.tun, &core.home, hub.clone()).await.context("start TUN")?;
    }

    if let Some(ctl) = core.general.external_controller.clone() {
        let ctl = if ctl.starts_with(':') { format!("127.0.0.1{ctl}") } else { ctl };
        let l = tokio::net::TcpListener::bind(&ctl).await.with_context(|| format!("listen on {ctl}"))?;
        tracing::info!("RESTful API listening at: {ctl}");
        let app = api::router(hub.clone());
        tokio::spawn(async move {
            if let Err(e) = axum::serve(l, app).await {
                tracing::error!("api: {e}");
            }
        });
    }
    std::future::pending::<()>().await;
    Ok(())
}
