//! sing-box JSON <-> [`Profile`]. Targets sing-box 1.12+ (new DNS server
//! format, rule actions, anytls outbound).

use std::collections::{BTreeSet, HashMap};

use anyhow::{bail, Result};
use serde_json::{json, Map, Value};

use super::clash::Overrides;
use super::*;

pub const GEOSITE_URL: &str = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-{}.srs";
pub const GEOIP_URL: &str = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-{}.srs";

fn tls_json(p: &ProxyConfig) -> Value {
    let mut t = json!({ "enabled": true });
    let o = t.as_object_mut().unwrap();
    o.insert("server_name".into(), json!(p.sni.clone().unwrap_or_else(|| p.server.clone())));
    if p.skip_cert_verify {
        o.insert("insecure".into(), json!(true));
    }
    if !p.alpn.is_empty() {
        o.insert("alpn".into(), json!(p.alpn));
    }
    let fp = p.fingerprint.clone().or_else(|| p.reality_public_key.as_ref().map(|_| "chrome".to_string()));
    if let Some(fp) = fp {
        o.insert("utls".into(), json!({ "enabled": true, "fingerprint": fp }));
    }
    if let Some(pk) = &p.reality_public_key {
        o.insert(
            "reality".into(),
            json!({ "enabled": true, "public_key": pk, "short_id": p.reality_short_id.clone().unwrap_or_default() }),
        );
    }
    t
}

fn transport_json(p: &ProxyConfig) -> Option<Value> {
    match p.network.as_deref()? {
        "ws" => {
            let mut t = json!({ "type": "ws", "path": p.ws_path.clone().unwrap_or_else(|| "/".into()) });
            if let Some(h) = &p.ws_host {
                t["headers"] = json!({ "Host": h });
            }
            Some(t)
        }
        "httpupgrade" => {
            let mut t = json!({ "type": "httpupgrade", "path": p.ws_path.clone().unwrap_or_else(|| "/".into()) });
            if let Some(h) = &p.ws_host {
                t["host"] = json!(h);
            }
            Some(t)
        }
        "grpc" => Some(json!({ "type": "grpc", "service_name": p.grpc_service.clone().unwrap_or_default() })),
        "h2" => {
            let mut t = json!({ "type": "http", "path": p.ws_path.clone().unwrap_or_else(|| "/".into()) });
            if let Some(h) = &p.ws_host {
                t["host"] = json!([h]);
            }
            Some(t)
        }
        _ => None,
    }
}

/// Nodes on a transport sing-box lacks. They stay in the config, so groups
/// and rules that name them stay valid, but can't reach their server.
pub fn unsupported_nodes(p: &Profile) -> Vec<String> {
    p.proxies.iter().filter(|x| x.network.as_deref() == Some("xhttp")).map(|x| x.name.clone()).collect()
}

pub fn emit_outbound(p: &ProxyConfig) -> Value {
    let mut o = Map::new();
    let ty = match p.kind() {
        ProxyKind::Shadowsocks => "shadowsocks",
        ProxyKind::Trojan => "trojan",
        ProxyKind::Vless => "vless",
        ProxyKind::Vmess => "vmess",
        ProxyKind::AnyTls => "anytls",
        ProxyKind::Hysteria2 => "hysteria2",
        ProxyKind::Tuic => "tuic",
        ProxyKind::WireGuard => return wireguard_endpoint(p),
        ProxyKind::Socks5 => "socks",
        ProxyKind::Http => "http",
    };
    o.insert("type".into(), json!(ty));
    o.insert("tag".into(), json!(p.name));
    o.insert("server".into(), json!(p.server));
    o.insert("server_port".into(), json!(p.port));
    match p.kind() {
        ProxyKind::Shadowsocks => {
            o.insert("method".into(), json!(p.cipher.clone().unwrap_or_default()));
            o.insert("password".into(), json!(p.password.clone().unwrap_or_default()));
        }
        ProxyKind::Vless => {
            o.insert("uuid".into(), json!(p.uuid.clone().unwrap_or_default()));
            if let Some(f) = &p.flow {
                o.insert("flow".into(), json!(f));
            }
        }
        ProxyKind::Vmess => {
            o.insert("uuid".into(), json!(p.uuid.clone().unwrap_or_default()));
            o.insert("alter_id".into(), json!(p.alter_id));
            o.insert("security".into(), json!(p.cipher.clone().unwrap_or_else(|| "auto".into())));
        }
        ProxyKind::Socks5 => {
            o.insert("version".into(), json!("5"));
            if let Some(u) = &p.username {
                o.insert("username".into(), json!(u));
            }
            if let Some(pw) = &p.password {
                o.insert("password".into(), json!(pw));
            }
        }
        ProxyKind::Http => {
            if let Some(u) = &p.username {
                o.insert("username".into(), json!(u));
            }
            if let Some(pw) = &p.password {
                o.insert("password".into(), json!(pw));
            }
        }
        ProxyKind::Hysteria2 => {
            o.insert("password".into(), json!(p.password.clone().unwrap_or_default()));
            if let Some(obfs) = &p.obfs {
                o.insert("obfs".into(), json!({ "type": obfs, "password": p.obfs_password.clone().unwrap_or_default() }));
            }
        }
        ProxyKind::Trojan | ProxyKind::AnyTls => {
            o.insert("password".into(), json!(p.password.clone().unwrap_or_default()));
        }
        ProxyKind::Tuic => {
            o.insert("uuid".into(), json!(p.uuid.clone().unwrap_or_default()));
            o.insert("password".into(), json!(p.password.clone().unwrap_or_default()));
            if let Some(c) = &p.congestion {
                o.insert("congestion_control".into(), json!(c));
            }
            if let Some(m) = &p.udp_relay_mode {
                o.insert("udp_relay_mode".into(), json!(m));
            }
        }
        ProxyKind::WireGuard => unreachable!(),
    }
    if p.tls {
        let mut t = tls_json(p);
        if p.kind() == ProxyKind::Tuic && p.alpn.is_empty() {
            t["alpn"] = json!(["h3"]);
        }
        o.insert("tls".into(), t);
    }
    if let Some(t) = transport_json(p) {
        o.insert("transport".into(), t);
    }
    if let Some(d) = &p.dialer_proxy {
        o.insert("detour".into(), json!(d));
    }
    Value::Object(o)
}

/// WireGuard is an endpoint in sing-box 1.11+, not an outbound.
fn wireguard_endpoint(p: &ProxyConfig) -> Value {
    let mut address: Vec<String> = Vec::new();
    for (ip, bits) in [(&p.ip, 32), (&p.ipv6, 128)] {
        if let Some(ip) = ip {
            address.push(if ip.contains('/') { ip.clone() } else { format!("{ip}/{bits}") });
        }
    }
    let allowed = if p.allowed_ips.is_empty() { vec!["0.0.0.0/0".to_string(), "::/0".to_string()] } else { p.allowed_ips.clone() };
    let mut peer = json!({
        "address": p.server, "port": p.port,
        "public_key": p.public_key.clone().unwrap_or_default(),
        "allowed_ips": allowed,
    });
    if let Some(psk) = &p.pre_shared_key {
        peer["pre_shared_key"] = json!(psk);
    }
    if p.reserved.len() == 3 {
        peer["reserved"] = json!(p.reserved);
    }
    let mut v = json!({
        "type": "wireguard", "tag": p.name,
        "address": address,
        "private_key": p.private_key.clone().unwrap_or_default(),
        "peers": [peer],
    });
    if let Some(mtu) = p.mtu {
        v["mtu"] = json!(mtu);
    }
    if let Some(d) = &p.dialer_proxy {
        v["detour"] = json!(d);
    }
    v
}

/// A Clash rule condition as sing-box rule fields. None = not expressible.
fn rule_cond(kind: &str, pl: &str, sets: &mut BTreeSet<(String, String)>) -> Option<Value> {
    let pl = pl.to_string();
    Some(match kind {
        "DOMAIN" => json!({ "domain": [pl] }),
        "DOMAIN-SUFFIX" => json!({ "domain_suffix": [pl] }),
        "DOMAIN-KEYWORD" => json!({ "domain_keyword": [pl] }),
        "DOMAIN-REGEX" => json!({ "domain_regex": [pl] }),
        "IP-CIDR" | "IP-CIDR6" => json!({ "ip_cidr": [pl] }),
        "SRC-IP-CIDR" => json!({ "source_ip_cidr": [pl] }),
        "DST-PORT" => match pl.parse::<u16>() {
            Ok(port) => json!({ "port": [port] }),
            Err(_) => json!({ "port_range": [pl.replace('-', ":")] }),
        },
        "SRC-PORT" => match pl.parse::<u16>() {
            Ok(port) => json!({ "source_port": [port] }),
            Err(_) => json!({ "source_port_range": [pl.replace('-', ":")] }),
        },
        "NETWORK" => json!({ "network": [pl.to_ascii_lowercase()] }),
        "PROCESS-NAME" => json!({ "process_name": [pl] }),
        "PROCESS-PATH" => json!({ "process_path": [pl] }),
        "GEOIP" | "SRC-GEOIP" if pl.eq_ignore_ascii_case("private") || pl.eq_ignore_ascii_case("lan") => {
            if kind == "GEOIP" {
                json!({ "ip_is_private": true })
            } else {
                json!({ "source_ip_is_private": true })
            }
        }
        "GEOIP" | "SRC-GEOIP" => {
            let tag = format!("geoip-{}", pl.to_ascii_lowercase());
            sets.insert((tag.clone(), GEOIP_URL.replace("{}", &pl.to_ascii_lowercase())));
            if kind == "GEOIP" {
                json!({ "rule_set": [tag] })
            } else {
                json!({ "rule_set": [tag], "rule_set_ip_cidr_match_source": true })
            }
        }
        "GEOSITE" => {
            let tag = format!("geosite-{}", pl.to_ascii_lowercase());
            sets.insert((tag.clone(), GEOSITE_URL.replace("{}", &pl.to_ascii_lowercase())));
            json!({ "rule_set": [tag] })
        }
        "AND" | "OR" | "NOT" => {
            let subs = logical_parts(&pl)?;
            let rules = subs.iter().map(|(k, p)| rule_cond(k, p, sets)).collect::<Option<Vec<_>>>()?;
            match kind {
                "NOT" if rules.len() == 1 => {
                    let mut r = rules.into_iter().next().unwrap();
                    if r.get("type").is_some() || r.get("invert").is_some() {
                        json!({ "type": "logical", "mode": "and", "rules": [r], "invert": true })
                    } else {
                        r["invert"] = json!(true);
                        r
                    }
                }
                "NOT" => return None,
                _ => json!({ "type": "logical", "mode": kind.to_ascii_lowercase(), "rules": rules }),
            }
        }
        _ => return None,
    })
}

/// Relay groups have no sing-box counterpart: the chain is rebuilt from
/// copies of the hops, each dialing through the previous one. The last copy
/// takes the group's name. The first hop may be a group; the later ones
/// must be nodes.
fn relay_chain(g: &GroupConfig, p: &Profile) -> Option<Vec<Value>> {
    let hops: Vec<String> = g.proxies.iter().filter(|h| h.as_str() != "DIRECT").cloned().collect();
    let first = hops.first()?.clone();
    if hops.len() == 1 {
        // A one-hop relay is just that hop.
        return Some(vec![json!({ "type": "selector", "tag": g.name, "outbounds": [first] })]);
    }
    let plan = plan_relay(&g.name, &hops, &|n| p.relay_hop(n))?;
    let mut out = Vec::new();
    for item in plan {
        match item {
            RelayCopy::Node { name, base, via } => {
                let mut copy = p.proxies.iter().find(|x| x.name == base)?.clone();
                copy.name = name;
                copy.dialer_proxy = Some(via);
                out.push(emit_outbound(&copy));
            }
            RelayCopy::Group { name, base, members } => {
                let mut copy = p.groups.iter().find(|x| x.name == base)?.clone();
                copy.name = name;
                copy.proxies = members;
                out.push(group_outbound(&copy));
            }
        }
    }
    Some(out)
}

fn group_outbound(g: &GroupConfig) -> Value {
    let l: Vec<String> = g.proxies.iter().filter(|x| x.as_str() != "REJECT").cloned().collect();
    let members = if l.is_empty() { vec!["DIRECT".to_string()] } else { l };
    let mut v = match g.kind {
        GroupKind::Select => json!({ "type": "selector", "tag": g.name, "outbounds": members }),
        _ => json!({
            "type": "urltest", "tag": g.name, "outbounds": members,
            "url": g.url, "interval": format!("{}s", g.interval), "tolerance": g.tolerance,
        }),
    };
    if g.kind == GroupKind::Select {
        v["interrupt_exist_connections"] = json!(true);
    }
    v
}

/// Remote entry without a download detour: `download_detour` is deprecated
/// in sing-box 1.14 (removed in 1.16) and its replacement `http_client`
/// doesn't exist before 1.14. The GUI turns these into local rule-sets
/// (see [`localize_rule_sets`]), so sing-box never downloads at startup.
fn rule_set_entry(tag: &str, url: String) -> Value {
    json!({ "type": "remote", "tag": tag, "format": "binary", "url": url })
}

/// A remote rule-set referenced by a sing-box config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteRuleSet {
    pub tag: String,
    pub url: String,
    /// File name to store it under (`<tag>.srs` / `<tag>.json`).
    pub file: String,
}

fn rule_set_file(tag: &str, entry: &Value) -> String {
    let source = entry.get("format").and_then(|f| f.as_str()) == Some("source")
        || entry.get("url").and_then(|u| u.as_str()).is_some_and(|u| u.ends_with(".json"));
    let safe: String = tag.chars().map(|c| if c.is_alphanumeric() || "._-".contains(c) { c } else { '_' }).collect();
    format!("{safe}.{}", if source { "json" } else { "srs" })
}

/// Lists the remote rule-sets (single-tag entries) in a sing-box config.
pub fn remote_rule_sets(v: &Value) -> Vec<RemoteRuleSet> {
    let sets = v.pointer("/route/rule_set").and_then(|s| s.as_array()).cloned().unwrap_or_default();
    sets.iter()
        .filter(|e| e.get("type").and_then(|t| t.as_str()) == Some("remote"))
        .filter_map(|e| {
            let tag = e.get("tag")?.as_str()?.to_string();
            let url = e.get("url")?.as_str()?.to_string();
            Some(RemoteRuleSet { file: rule_set_file(&tag, e), tag, url })
        })
        .collect()
}

/// Rule fields that only qualify how a rule matches or acts; a rule left
/// with nothing but these after removing `rule_set` would match everything.
const NON_MATCH_FIELDS: [&str; 13] = [
    "type", "rule_set", "rule_set_ip_cidr_match_source", "rule_set_ip_cidr_accept_empty", "rule_set_ipcidr_match_source",
    "action", "outbound", "server", "invert", "strategy", "disable_cache", "rewrite_ttl", "client_subnet",
];

/// Removes references to `dropped` rule-sets. Returns false if the rule
/// should be deleted entirely.
fn strip_rule(rule: &mut Value, dropped: &BTreeSet<String>) -> bool {
    let Some(obj) = rule.as_object_mut() else { return true };
    if let Some(Value::Array(sub)) = obj.get_mut("rules") {
        sub.retain_mut(|r| strip_rule(r, dropped));
        return !sub.is_empty();
    }
    let Some(rs) = obj.get("rule_set") else { return true };
    let tags: Vec<String> = match rs {
        Value::String(s) => vec![s.clone()],
        Value::Array(a) => a.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
        _ => return true,
    };
    let kept: Vec<String> = tags.iter().filter(|t| !dropped.contains(*t)).cloned().collect();
    if kept.len() == tags.len() {
        return true;
    }
    if !kept.is_empty() {
        obj.insert("rule_set".into(), json!(kept));
        return true;
    }
    obj.remove("rule_set");
    obj.keys().any(|k| !NON_MATCH_FIELDS.contains(&k.as_str()))
}

/// Points remote rule-sets at files in `dir` so sing-box starts without
/// network access (a failed first download is fatal for sing-box). Sets with
/// no file are removed together with the rules that use them; their tags
/// are returned.
pub fn localize_rule_sets(v: &mut Value, dir: &std::path::Path) -> Vec<String> {
    let remotes = remote_rule_sets(v);
    let mut dropped = BTreeSet::new();
    let Some(sets) = v.pointer_mut("/route/rule_set").and_then(|s| s.as_array_mut()) else { return Vec::new() };
    sets.retain_mut(|entry| {
        let Some(r) = entry.get("tag").and_then(|t| t.as_str()).and_then(|t| remotes.iter().find(|r| r.tag == t)) else {
            return true; // local, inline or multi-tag entries are left alone
        };
        let path = dir.join(&r.file);
        if !path.exists() {
            dropped.insert(r.tag.clone());
            return false;
        }
        let format = if r.file.ends_with(".json") { "source" } else { "binary" };
        *entry = json!({ "type": "local", "tag": r.tag, "format": format, "path": path.to_string_lossy() });
        true
    });
    if !dropped.is_empty() {
        for ptr in ["/route/rules", "/dns/rules"] {
            if let Some(Value::Array(rules)) = v.pointer_mut(ptr) {
                rules.retain_mut(|r| strip_rule(r, &dropped));
            }
        }
    }
    dropped.into_iter().collect()
}

/// Converts a profile to a complete sing-box config that exposes a mixed
/// inbound and the Clash API (so the GUI can drive it like mihomo).
pub fn emit(p: &Profile, o: &Overrides) -> Value {
    let mut outbounds: Vec<Value> = Vec::new();
    let mut members_all: Vec<String> = Vec::new();
    for g in &p.groups {
        members_all.push(g.name.clone());
        if g.kind == GroupKind::Relay {
            match relay_chain(g, p) {
                Some(chain) => outbounds.extend(chain),
                None => outbounds.push(json!({ "type": "selector", "tag": g.name, "outbounds": group_outbound(g)["outbounds"] })),
            }
            continue;
        }
        outbounds.push(group_outbound(g));
    }
    let mut endpoints: Vec<Value> = Vec::new();
    for px in &p.proxies {
        members_all.push(px.name.clone());
        let v = emit_outbound(px);
        if px.kind() == ProxyKind::WireGuard {
            endpoints.push(v);
        } else {
            outbounds.push(v);
        }
    }
    // Relay copies of WireGuard nodes are endpoints too.
    let (eps, obs): (Vec<Value>, Vec<Value>) = outbounds.into_iter().partition(|o| o["type"] == "wireguard");
    endpoints.extend(eps);
    let mut outbounds = obs;
    members_all.push("DIRECT".into());
    outbounds.push(json!({ "type": "direct", "tag": "DIRECT" }));
    outbounds.push(json!({ "type": "selector", "tag": "GLOBAL", "outbounds": members_all }));

    let final_target = p
        .rules
        .iter()
        .find(|r| r.kind == "MATCH")
        .map(|r| r.target.clone())
        .or_else(|| p.groups.first().map(|g| g.name.clone()))
        .unwrap_or_else(|| "DIRECT".into());
    let detour = if final_target == "REJECT" { "DIRECT".to_string() } else { final_target.clone() };

    let mut rules = vec![json!({ "action": "sniff" })];
    if o.tun {
        rules.insert(0, json!({ "port": 53, "action": "hijack-dns" }));
        rules.push(json!({ "protocol": "dns", "action": "hijack-dns" }));
    }
    rules.push(json!({ "clash_mode": "Direct", "outbound": "DIRECT" }));
    rules.push(json!({ "clash_mode": "Global", "outbound": "GLOBAL" }));
    let mut sets: BTreeSet<(String, String)> = BTreeSet::new();
    for r in &p.rules {
        if r.kind == "MATCH" {
            continue;
        }
        let Some(mut rule) = rule_cond(&r.kind, &r.payload, &mut sets) else { continue };
        if r.target == "REJECT" {
            rule["action"] = json!("reject");
        } else {
            rule["outbound"] = json!(r.target);
        }
        rules.push(rule);
    }
    let group_names: Vec<String> = p.groups.iter().map(|g| g.name.clone()).collect();
    let dns = if o.tun && p.dns.enable && !p.dns.nameserver.is_empty() {
        profile_dns(&p.dns, &group_names)
    } else if o.tun {
        // System DNS would loop through the TUN: resolve explicitly, foreign
        // names through the proxy (same layout as the sbm subscription). A
        // profile that ends in DIRECT still needs a proxy for them: direct
        // DoH to 1.1.1.1 doesn't work everywhere.
        sets.insert(("geosite-cn".into(), GEOSITE_URL.replace("{}", "cn")));
        let via = if detour == "DIRECT" { group_names.first().cloned().unwrap_or(detour) } else { detour };
        let mut remote = json!({ "type": "https", "tag": "remote", "server": "1.1.1.1" });
        if via != "DIRECT" {
            remote["detour"] = json!(via);
        }
        json!({
            "servers": [remote, { "type": "https", "tag": "local", "server": "223.5.5.5" }],
            "rules": [{ "rule_set": "geosite-cn", "server": "local" }],
            "final": "remote",
            "strategy": "prefer_ipv4",
        })
    } else {
        json!({ "servers": [{ "type": "local", "tag": "local" }], "final": "local", "strategy": "prefer_ipv4" })
    };
    let mut root = json!({
        "log": { "level": singbox_level(&o.log_level), "timestamp": true },
        "dns": dns,
        "inbounds": inbounds(o),
        "outbounds": outbounds,
        "route": {
            "rules": rules,
            "rule_set": sets.iter().map(|(t, u)| rule_set_entry(t, u.clone())).collect::<Vec<_>>(),
            "final": if final_target == "REJECT" { "DIRECT".to_string() } else { final_target },
            "auto_detect_interface": true,
            "default_domain_resolver": "local",
        },
        "experimental": clash_api(o),
    });
    if !endpoints.is_empty() {
        root["endpoints"] = json!(endpoints);
    }
    root
}

/// A Clash nameserver (`223.5.5.5`, `tcp://…`, `tls://…`,
/// `https://host/path#PROXY`) as a sing-box DNS server. None for kinds
/// sing-box can't take (dhcp://, system, …).
fn dns_server(spec: &str, tag: &str, groups: &[String]) -> Option<Value> {
    let (main, detour) = match spec.trim().split_once('#') {
        Some((m, d)) => (m, d.split('&').next().filter(|d| !d.is_empty())),
        None => (spec.trim(), None),
    };
    let (scheme, rest) = main.split_once("://").unwrap_or(("udp", main));
    let ty = match scheme {
        "udp" | "tcp" | "tls" | "https" | "quic" | "h3" => scheme,
        _ => return None,
    };
    let (hostport, path) = match rest.split_once('/') {
        Some((h, p)) => (h, format!("/{p}")),
        None => (rest, String::new()),
    };
    let (host, port) = match hostport.parse::<std::net::SocketAddr>() {
        Ok(sa) => (sa.ip().to_string(), Some(sa.port())),
        Err(_) => match hostport.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (h.trim_matches(['[', ']']).to_string(), p.parse::<u16>().ok()),
            _ => (hostport.trim_matches(['[', ']']).to_string(), None),
        },
    };
    if host.is_empty() {
        return None;
    }
    let mut s = json!({ "type": ty, "tag": tag, "server": host });
    if let Some(p) = port {
        s["server_port"] = json!(p);
    }
    if ty == "https" && !path.is_empty() && path != "/dns-query" {
        s["path"] = json!(path);
    }
    if host.parse::<std::net::IpAddr>().is_err() {
        s["domain_resolver"] = json!("local");
    }
    if let Some(d) = detour {
        if d != "DIRECT" && groups.iter().any(|g| g == d) {
            s["detour"] = json!(d);
        }
    }
    Some(s)
}

/// The profile's own `dns:` for TUN: its nameservers (with `#proxy`
/// detours) and, in fake-ip mode, fake addresses for A/AAAA queries - so
/// proxied connections carry the domain instead of a possibly poisoned IP.
fn profile_dns(d: &DnsConfig, groups: &[String]) -> Value {
    // Plain resolver for DoH/DoT host names and for direct connections.
    let boot = d
        .default_nameserver
        .iter()
        .find_map(|s| s.trim().trim_start_matches("udp://").parse::<std::net::IpAddr>().ok())
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "223.5.5.5".into());
    let mut servers = vec![json!({ "type": "udp", "tag": "local", "server": boot })];
    let main: Vec<Value> = d.nameserver.iter().enumerate().filter_map(|(i, s)| dns_server(s, &format!("dns-{i}"), groups)).collect();
    let final_tag = main.first().and_then(|s| s["tag"].as_str()).unwrap_or("local").to_string();
    servers.extend(main);
    let mut rules = Vec::new();
    if d.enhanced_mode == "fake-ip" {
        let range = if d.fake_ip_range.is_empty() { "198.18.0.1/16" } else { d.fake_ip_range.as_str() };
        let range = range.parse::<ipnet::Ipv4Net>().map(|n| n.trunc().to_string()).unwrap_or_else(|_| "198.18.0.0/15".into());
        servers.push(json!({ "type": "fakeip", "tag": "fakeip", "inet4_range": range }));
        let (mut suffix, mut exact) = (Vec::new(), Vec::new());
        for f in &d.fake_ip_filter {
            if let Some(s) = f.strip_prefix("+.").or_else(|| f.strip_prefix("*.")) {
                suffix.push(s.to_string());
            } else if !f.contains(['*', ':', '+']) {
                exact.push(f.clone());
            }
        }
        if !suffix.is_empty() || !exact.is_empty() {
            rules.push(json!({ "domain_suffix": suffix, "domain": exact, "server": final_tag }));
        }
        rules.push(json!({ "query_type": ["A", "AAAA"], "server": "fakeip" }));
    }
    json!({
        "servers": servers,
        "rules": rules,
        "final": final_tag,
        "strategy": if d.ipv6 { "prefer_ipv4" } else { "ipv4_only" },
    })
}

fn inbounds(o: &Overrides) -> Value {
    let listen = if o.allow_lan { "::" } else { "127.0.0.1" };
    let mut v = vec![json!({ "type": "mixed", "tag": "mixed-in", "listen": listen, "listen_port": o.mixed_port })];
    if o.tun {
        let mut tun = json!({
            "type": "tun", "tag": "tun-in",
            "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
            "mtu": 9000, "auto_route": true, "strict_route": true, "stack": "mixed",
        });
        // macOS names TUN devices utunN itself.
        if cfg!(windows) {
            tun["interface_name"] = json!("Prism");
        }
        v.push(tun);
    }
    Value::Array(v)
}

fn singbox_level(l: &str) -> &'static str {
    match l {
        "debug" => "debug",
        "warning" | "warn" => "warn",
        "error" => "error",
        "silent" => "panic",
        _ => "info",
    }
}

fn mode_name(m: Mode) -> &'static str {
    match m {
        Mode::Rule => "Rule",
        Mode::Global => "Global",
        Mode::Direct => "Direct",
    }
}

fn clash_api(o: &Overrides) -> Value {
    json!({
        "clash_api": {
            "external_controller": o.controller,
            "secret": o.secret,
            "default_mode": mode_name(o.mode),
        },
        "cache_file": { "enabled": true },
    })
}

/// Real IP domains get DNS rules of their own in front of the fake-ip one,
/// answered by the server they name or else the final one. Those with their
/// own server also get a route rule: connections by name resolve through
/// `default_domain_resolver`, not the DNS rules. Returns warnings.
pub fn add_real_ip_dns(v: &mut Value, domains: &[RealIpDomain]) -> Vec<String> {
    let mut warnings = Vec::new();
    let Some(dns) = v.get_mut("dns").and_then(|d| d.as_object_mut()) else { return warnings };
    let servers: Vec<Value> = dns.get("servers").and_then(|s| s.as_array()).cloned().unwrap_or_default();
    let first = servers.first().and_then(|s| st(s, "tag")).unwrap_or_default();
    let final_tag = dns.get("final").and_then(|f| f.as_str()).map(String::from).unwrap_or(first);
    let mut added = Vec::new();
    let mut rules = Vec::new();
    let mut resolves = Vec::new();
    for (i, d) in domains.iter().enumerate() {
        let tag = format!("real-ip-{i}");
        let field = if d.subdomains { "domain_suffix" } else { "domain" };
        let server = match dns_server(&d.dns, &tag, &[]) {
            Some(s) if !d.dns.trim().is_empty() => {
                added.push(s);
                resolves.push(json!({ field: [d.domain], "action": "resolve", "server": tag }));
                tag
            }
            _ => {
                if !d.dns.trim().is_empty() {
                    warnings.push(format!("{}: unusable DNS server {}", d.domain, d.dns));
                }
                final_tag.clone()
            }
        };
        rules.push(json!({ field: [d.domain], "server": server }));
    }
    if let Some(list) = dns.entry("servers").or_insert_with(|| json!([])).as_array_mut() {
        list.extend(added);
    }
    if let Some(list) = dns.entry("rules").or_insert_with(|| json!([])).as_array_mut() {
        rules.append(list);
        *list = rules;
    }
    if let Some(list) = v.pointer_mut("/route/rules").and_then(|r| r.as_array_mut()) {
        let at = list.iter().take_while(|x| matches!(x.get("action").and_then(|a| a.as_str()), Some("sniff" | "hijack-dns"))).count();
        list.splice(at..at, resolves);
    }
    warnings
}

/// Puts per-application rules (`process_name` / `process_path`) in front of
/// the routing rules, after the sniff / hijack-dns / clash_mode rules so the
/// global and direct modes still win. Returns warnings for skipped rules.
pub fn add_app_rules(v: &mut Value, routes: &[AppRoute]) -> Vec<String> {
    let mut warnings = Vec::new();
    let Some(root) = v.as_object_mut() else { return warnings };
    let outbounds = root.entry("outbounds").or_insert_with(|| json!([]));
    let tags: Vec<(String, String)> = outbounds
        .as_array()
        .map(|a| a.iter().filter_map(|o| Some((st(o, "tag")?, st(o, "type").unwrap_or_default()))).collect())
        .unwrap_or_default();
    let mut direct = tags.iter().find(|(_, t)| t == "direct").map(|(tag, _)| tag.clone());
    let mut rules = Vec::new();
    for r in routes {
        if let Err(e) = r.valid() {
            warnings.push(format!("app rule skipped: {e}"));
            continue;
        }
        let mut rule = if r.by_path {
            json!({ "process_path": [r.process_name()] })
        } else {
            json!({ "process_name": [r.process_name()] })
        };
        match r.target.as_str() {
            "REJECT" => rule["action"] = json!("reject"),
            "DIRECT" => {
                let tag = direct.get_or_insert_with(|| {
                    if let Some(a) = outbounds.as_array_mut() {
                        a.push(json!({ "type": "direct", "tag": "DIRECT" }));
                    }
                    "DIRECT".to_string()
                });
                rule["outbound"] = json!(tag);
            }
            t if tags.iter().any(|(tag, _)| tag == t) => rule["outbound"] = json!(t),
            t if r.strict => {
                warnings.push(format!("app rule {}: {t} is not in this profile, rejecting its connections", r.value));
                rule["action"] = json!("reject");
            }
            t => {
                warnings.push(format!("app rule {} skipped: {t} is not in this profile", r.value));
                continue;
            }
        }
        rules.push(rule);
    }
    if rules.is_empty() {
        return warnings;
    }
    let route = root.entry("route").or_insert_with(|| json!({}));
    if let Some(r) = route.as_object_mut() {
        let list = r.entry("rules").or_insert_with(|| json!([]));
        if let Some(list) = list.as_array_mut() {
            let lead = list
                .iter()
                .take_while(|x| {
                    x.get("clash_mode").is_some()
                        || matches!(x.get("action").and_then(|a| a.as_str()), Some("sniff" | "hijack-dns" | "resolve"))
                })
                .count();
            for (i, rule) in rules.into_iter().enumerate() {
                list.insert(lead + i, rule);
            }
        }
    }
    warnings
}

/// Puts the GUI's domain / IP rules in front of the routing rules, after the
/// sniff / hijack-dns / clash_mode rules (app rules, added after these, end
/// up first). GEOSITE / GEOIP rules add their remote rule-sets. IP rules
/// never resolve domains here (sing-box has no per-rule resolve).
pub fn add_user_rules(v: &mut Value, user: &[UserRule]) -> Vec<String> {
    let mut warnings = Vec::new();
    let Some(root) = v.as_object_mut() else { return warnings };
    let tags: Vec<(String, String)> = root
        .get("outbounds")
        .and_then(|o| o.as_array())
        .map(|a| a.iter().filter_map(|o| Some((st(o, "tag")?, st(o, "type").unwrap_or_default()))).collect())
        .unwrap_or_default();
    let endpoints: Vec<String> = root
        .get("endpoints")
        .and_then(|o| o.as_array())
        .map(|a| a.iter().filter_map(|o| st(o, "tag")).collect())
        .unwrap_or_default();
    let direct = tags.iter().find(|(_, t)| t == "direct").map(|(tag, _)| tag.clone());
    let mut need_direct = false;
    let mut sets = BTreeSet::new();
    let mut rules = Vec::new();
    for r in user {
        let rc = match r.to_rule() {
            Ok(rc) => rc,
            Err(e) => {
                warnings.push(format!("rule skipped: {e}"));
                continue;
            }
        };
        let Some(mut rule) = rule_cond(&rc.kind, &rc.payload, &mut sets) else {
            warnings.push(format!("rule {} skipped: not supported by sing-box", rc.to_line()));
            continue;
        };
        match rc.target.as_str() {
            "REJECT" => rule["action"] = json!("reject"),
            "DIRECT" => {
                need_direct = direct.is_none();
                rule["outbound"] = json!(direct.clone().unwrap_or_else(|| "DIRECT".into()));
            }
            t if tags.iter().any(|(tag, _)| tag == t) || endpoints.iter().any(|e| e == t) => rule["outbound"] = json!(t),
            t if r.strict => {
                warnings.push(format!("rule {}: {t} is not in this profile, rejecting its connections", rc.payload));
                rule["action"] = json!("reject");
            }
            t => {
                warnings.push(format!("rule {} skipped: {t} is not in this profile", rc.payload));
                continue;
            }
        }
        rules.push(rule);
    }
    if rules.is_empty() {
        return warnings;
    }
    if need_direct {
        if let Some(a) = root.entry("outbounds").or_insert_with(|| json!([])).as_array_mut() {
            a.push(json!({ "type": "direct", "tag": "DIRECT" }));
        }
    }
    let route = root.entry("route").or_insert_with(|| json!({}));
    if let Some(r) = route.as_object_mut() {
        let have: BTreeSet<String> = r
            .get("rule_set")
            .and_then(|x| x.as_array())
            .map(|a| a.iter().filter_map(|e| st(e, "tag")).collect())
            .unwrap_or_default();
        if let Some(list) = r.entry("rule_set").or_insert_with(|| json!([])).as_array_mut() {
            for (tag, url) in sets.into_iter().filter(|(t, _)| !have.contains(t)) {
                list.push(rule_set_entry(&tag, url));
            }
        }
        let list = r.entry("rules").or_insert_with(|| json!([]));
        if let Some(list) = list.as_array_mut() {
            let lead = list
                .iter()
                .take_while(|x| {
                    x.get("clash_mode").is_some()
                        || matches!(x.get("action").and_then(|a| a.as_str()), Some("sniff" | "hijack-dns" | "resolve"))
                })
                .count();
            for (i, rule) in rules.into_iter().enumerate() {
                list.insert(lead + i, rule);
            }
        }
    }
    warnings
}

/// Patches a native sing-box profile: replaces inbounds (TUN needs admin
/// rights, the GUI uses system proxy) and forces the Clash API settings.
pub fn apply_overrides(v: &mut Value, o: &Overrides) {
    let Some(root) = v.as_object_mut() else { return };
    root.insert("inbounds".into(), inbounds(o));
    // Lets the connections page show which program made each connection.
    if let Some(r) = root.entry("route").or_insert_with(|| json!({})).as_object_mut() {
        r.insert("find_process".into(), json!(true));
    }
    if o.tun {
        // Make sure DNS from the TUN is answered by sing-box.
        let route = root.entry("route").or_insert_with(|| json!({}));
        if let Some(r) = route.as_object_mut() {
            r.insert("auto_detect_interface".into(), json!(true));
            let rules = r.entry("rules").or_insert_with(|| json!([]));
            if let Some(list) = rules.as_array_mut() {
                list.retain(|r| !(r.get("port") == Some(&json!(53)) && r.get("action").and_then(Value::as_str) == Some("hijack-dns")));
                list.insert(0, json!({ "port": 53, "action": "hijack-dns" }));
                if !list.iter().any(|x| x.get("action").and_then(|a| a.as_str()) == Some("hijack-dns")) {
                    list.insert(0, json!({ "protocol": "dns", "action": "hijack-dns" }));
                }
                if !list.iter().any(|x| x.get("action").and_then(|a| a.as_str()) == Some("sniff")) {
                    list.insert(0, json!({ "action": "sniff" }));
                }
            }
        }
    }
    let exp = root.entry("experimental").or_insert_with(|| json!({}));
    if let Some(e) = exp.as_object_mut() {
        if let Value::Object(api) = clash_api(o) {
            for (k, v) in api {
                e.insert(k, v);
            }
        }
    }
    if let Some(log) = root.entry("log").or_insert_with(|| json!({})).as_object_mut() {
        log.insert("level".into(), json!(singbox_level(&o.log_level)));
        log.remove("output");
    }
    // Rules that depended on the removed TUN inbound are harmless; sniff /
    // hijack-dns simply never match.
}

// ---------------------------------------------------------------- parsing

fn st(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(|x| x.as_str()).map(String::from).filter(|s| !s.is_empty())
}

fn strs(v: &Value, k: &str) -> Vec<String> {
    match v.get(k) {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str().map(String::from).or_else(|| x.as_u64().map(|n| n.to_string())))
            .collect(),
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Number(n)) => vec![n.to_string()],
        _ => Vec::new(),
    }
}

fn secs(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(m) = s.strip_suffix('m') {
        return m.parse::<u64>().ok().map(|x| x * 60);
    }
    s.trim_end_matches('s').parse().ok()
}

pub fn parse(v: &Value) -> Result<Profile> {
    let Some(obs) = v.get("outbounds").and_then(|o| o.as_array()) else { bail!("sing-box config has no outbounds") };
    let mut p = Profile::default();
    let mut rename: HashMap<String, String> = HashMap::new();
    for ob in obs {
        let ty = st(ob, "type").unwrap_or_default();
        let tag = st(ob, "tag").unwrap_or_else(|| ty.clone());
        let kind = match ty.as_str() {
            "direct" => {
                rename.insert(tag, "DIRECT".into());
                continue;
            }
            "block" => {
                rename.insert(tag, "REJECT".into());
                continue;
            }
            "dns" => continue,
            "selector" | "urltest" => {
                let kind = if ty == "selector" { GroupKind::Select } else { GroupKind::UrlTest };
                let mut g = GroupConfig::new(&tag, kind, strs(ob, "outbounds"));
                if let Some(u) = st(ob, "url") {
                    g.url = u;
                }
                if let Some(i) = st(ob, "interval").and_then(|i| secs(&i)) {
                    g.interval = i.max(10);
                }
                if let Some(t) = ob.get("tolerance").and_then(|t| t.as_u64()) {
                    g.tolerance = t;
                }
                p.groups.push(g);
                continue;
            }
            "shadowsocks" => ProxyKind::Shadowsocks,
            "trojan" => ProxyKind::Trojan,
            "vless" => ProxyKind::Vless,
            "vmess" => ProxyKind::Vmess,
            "anytls" => ProxyKind::AnyTls,
            "hysteria2" => ProxyKind::Hysteria2,
            "tuic" => ProxyKind::Tuic,
            "socks" => ProxyKind::Socks5,
            "http" => ProxyKind::Http,
            other => {
                p.warnings.push(format!("outbound {tag}: unsupported type {other}"));
                continue;
            }
        };
        let tls = ob.get("tls").cloned().unwrap_or(Value::Null);
        let tr = ob.get("transport").cloned().unwrap_or(Value::Null);
        let reality = tls.get("reality").cloned().unwrap_or(Value::Null);
        p.proxies.push(ProxyConfig {
            name: tag,
            kind: Some(kind),
            server: st(ob, "server").unwrap_or_default(),
            port: ob.get("server_port").and_then(|x| x.as_u64()).unwrap_or(0) as u16,
            username: st(ob, "username"),
            password: st(ob, "password"),
            uuid: st(ob, "uuid"),
            cipher: st(ob, "method").or_else(|| st(ob, "security")),
            alter_id: ob.get("alter_id").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
            tls: tls.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false),
            sni: st(&tls, "server_name"),
            skip_cert_verify: tls.get("insecure").and_then(|x| x.as_bool()).unwrap_or(false),
            alpn: strs(&tls, "alpn"),
            fingerprint: tls.get("utls").and_then(|u| st(u, "fingerprint")),
            flow: st(ob, "flow"),
            // sing-box's "http" transport is V2Ray's HTTP/2 one.
            network: st(&tr, "type").map(|t| if t == "http" { "h2".into() } else { t }),
            ws_path: st(&tr, "path"),
            ws_host: tr.get("headers").and_then(|h| st(h, "Host")).or_else(|| st(&tr, "host")).or_else(|| strs(&tr, "host").into_iter().next()),
            grpc_service: st(&tr, "service_name"),
            reality_public_key: st(&reality, "public_key"),
            reality_short_id: st(&reality, "short_id"),
            obfs: ob.get("obfs").and_then(|o| st(o, "type")),
            obfs_password: ob.get("obfs").and_then(|o| st(o, "password")),
            udp: true,
            dialer_proxy: st(ob, "detour"),
            congestion: st(ob, "congestion_control"),
            udp_relay_mode: st(ob, "udp_relay_mode"),
            ..Default::default()
        });
    }
    for ep in v.get("endpoints").and_then(|e| e.as_array()).cloned().unwrap_or_default() {
        let tag = st(&ep, "tag").unwrap_or_else(|| "wireguard".into());
        if st(&ep, "type").as_deref() != Some("wireguard") {
            p.warnings.push(format!("endpoint {tag}: unsupported type"));
            continue;
        }
        let peers = ep.get("peers").and_then(|x| x.as_array()).cloned().unwrap_or_default();
        let [peer] = peers.as_slice() else {
            p.warnings.push(format!("endpoint {tag}: only WireGuard with exactly one peer is supported"));
            continue;
        };
        let mut wg = ProxyConfig {
            name: tag,
            kind: Some(ProxyKind::WireGuard),
            server: st(peer, "address").unwrap_or_default(),
            port: peer.get("port").and_then(|x| x.as_u64()).unwrap_or(0) as u16,
            private_key: st(&ep, "private_key"),
            public_key: st(peer, "public_key"),
            pre_shared_key: st(peer, "pre_shared_key"),
            reserved: peer.get("reserved").and_then(|r| r.as_array()).map(|a| a.iter().filter_map(|x| x.as_u64()).map(|x| x as u8).collect()).unwrap_or_default(),
            allowed_ips: strs(peer, "allowed_ips"),
            mtu: ep.get("mtu").and_then(|x| x.as_u64()).map(|x| x as u16),
            dialer_proxy: st(&ep, "detour"),
            udp: true,
            ..Default::default()
        };
        for a in strs(&ep, "address") {
            if a.contains(':') {
                wg.ipv6 = Some(a);
            } else {
                wg.ip = Some(a);
            }
        }
        p.proxies.push(wg);
    }
    let fix = |n: &String| rename.get(n).cloned().unwrap_or_else(|| n.clone());
    for g in &mut p.groups {
        g.proxies = g.proxies.iter().map(fix).collect();
    }
    let route = v.get("route").cloned().unwrap_or(Value::Null);
    for r in route.get("rules").and_then(|r| r.as_array()).cloned().unwrap_or_default() {
        if r.get("clash_mode").is_some() || r.get("protocol").is_some() || r.get("inbound").is_some() {
            continue;
        }
        let target = match (st(&r, "action").as_deref(), st(&r, "outbound")) {
            (Some("reject"), _) => "REJECT".to_string(),
            (None | Some("route"), Some(o)) => fix(&o),
            _ => continue,
        };
        let mut push = |kind: &str, payload: String| {
            p.rules.push(RuleConfig { kind: kind.into(), payload, target: target.clone(), no_resolve: false });
        };
        for (field, kind) in [
            ("domain", "DOMAIN"),
            ("domain_suffix", "DOMAIN-SUFFIX"),
            ("domain_keyword", "DOMAIN-KEYWORD"),
            ("domain_regex", "DOMAIN-REGEX"),
            ("ip_cidr", "IP-CIDR"),
            ("port", "DST-PORT"),
            ("process_name", "PROCESS-NAME"),
        ] {
            for x in strs(&r, field) {
                push(kind, x.trim_start_matches('.').to_string());
            }
        }
        if r.get("ip_is_private").and_then(|x| x.as_bool()) == Some(true) {
            push("GEOIP", "private".into());
        }
        for tag in strs(&r, "rule_set") {
            if let Some(code) = tag.strip_prefix("geosite-") {
                push("GEOSITE", code.into());
            } else if let Some(code) = tag.strip_prefix("geoip-") {
                push("GEOIP", code.to_ascii_uppercase());
            }
        }
    }
    if let Some(f) = st(&route, "final") {
        p.rules.push(RuleConfig { kind: "MATCH".into(), payload: String::new(), target: fix(&f), no_resolve: false });
    }
    if let Some(inb) = v.get("inbounds").and_then(|i| i.as_array()) {
        if let Some(port) = inb.iter().find_map(|i| i.get("listen_port").and_then(|x| x.as_u64())) {
            p.general.mixed_port = port as u16;
        }
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tun_port53_cannot_be_bypassed_by_direct_rule() {
        let o = Overrides { mixed_port: 7890, controller: "127.0.0.1:9090".into(), secret: String::new(), mode: Mode::Rule, allow_lan: false, log_level: "info".into(), tun: true, unified_delay: false };
        let mut v = json!({"route": {"rules": [{"outbound": "DIRECT"}]}});
        apply_overrides(&mut v, &o);
        apply_overrides(&mut v, &o);
        let rules = v["route"]["rules"].as_array().unwrap();
        let dns = rules.iter().position(|r| r["port"] == 53 && r["action"] == "hijack-dns").unwrap();
        let direct = rules.iter().position(|r| r["outbound"] == "DIRECT").unwrap();
        assert!(dns < direct);
        assert_eq!(rules.iter().filter(|r| r["port"] == 53).count(), 1);
    }

    #[test]
    fn strict_rules_reject_when_the_target_is_gone() {
        let mut sb = json!({ "outbounds": [], "route": { "rules": [] } });
        add_user_rules(&mut sb, &[UserRule { kind: "DOMAIN".into(), value: "a.test".into(), target: "gone".into(), resolve: false, strict: true }]);
        add_app_rules(&mut sb, &[AppRoute { by_path: false, value: "x.exe".into(), target: "gone".into(), strict: true }]);
        let rules = &sb["route"]["rules"];
        assert_eq!(rules[0], json!({ "process_name": ["x.exe"], "action": "reject" }));
        assert_eq!(rules[1], json!({ "domain": ["a.test"], "action": "reject" }));
    }

    #[test]
    fn real_ip_rules_come_before_fake_ip() {
        let mut sb = json!({
            "dns": { "servers": [{ "type": "udp", "tag": "dns-0", "server": "1.1.1.1" }], "final": "dns-0", "rules": [{ "query_type": ["A"], "server": "fakeip" }] },
            "route": { "rules": [{ "action": "sniff" }, { "clash_mode": "Direct", "outbound": "DIRECT" }] },
        });
        let d = |domain: &str, subdomains, dns: &str| RealIpDomain { domain: domain.into(), subdomains, dns: dns.into() };
        assert!(add_real_ip_dns(&mut sb, &[d("corp.test", true, "10.1.1.1"), d("one.test", false, "")]).is_empty());
        assert_eq!(sb["dns"]["rules"][0], json!({ "domain_suffix": ["corp.test"], "server": "real-ip-0" }));
        assert_eq!(sb["dns"]["rules"][1], json!({ "domain": ["one.test"], "server": "dns-0" }));
        assert_eq!(sb["dns"]["rules"][2]["server"], "fakeip");
        assert_eq!(sb["dns"]["servers"][1]["server"], "10.1.1.1");
        assert_eq!(sb["route"]["rules"][1], json!({ "domain_suffix": ["corp.test"], "action": "resolve", "server": "real-ip-0" }));
        assert_eq!(sb["route"]["rules"].as_array().unwrap().len(), 3, "no server of its own, no route rule");
    }

    #[test]
    fn overrides_always_find_processes() {
        let mut sb = json!({ "outbounds": [] });
        apply_overrides(&mut sb, &overrides());
        assert_eq!(sb["route"]["find_process"], true);
    }

    #[test]
    fn xhttp_nodes_are_reported_as_unsupported() {
        let p = crate::config::parse_any(
            r#"
proxies:
  - {name: a, type: vless, server: x.test, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, tls: true, network: xhttp, xhttp-opts: {path: /x}}
  - {name: b, type: vless, server: x.test, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, tls: true, network: ws}
  - {name: c, type: trojan, server: x.test, port: 443, password: p}
"#,
        )
        .unwrap();
        assert_eq!(unsupported_nodes(&p), ["a"]);
    }

    #[test]
    fn tun_dns_follows_the_profile() {
        let mut o = overrides();
        o.tun = true;
        let base = "proxies:\n  - {name: n, type: ss, server: 1.2.3.4, port: 1, cipher: aes-128-gcm, password: x}\n\
                    proxy-groups:\n  - {name: PROXY, type: select, proxies: [n]}\nrules:\n  - DOMAIN-SUFFIX,x.com,PROXY\n  - MATCH,DIRECT\n";

        // Profile DNS: its servers, fake-ip, filter, detours.
        let dns = "dns:\n  enable: true\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n  fake-ip-filter: ['+.lan', 'time.windows.com', 'geosite:cn']\n  \
                   default-nameserver: [119.29.29.29]\n  nameserver: [223.5.5.5, 'https://doh.pub/q#PROXY', 'tls://1.1.1.1:853#Nope', 'dhcp://en0']\n";
        let sb = emit(&parse_any(&format!("{base}{dns}")).unwrap(), &o);
        let d = &sb["dns"];
        let servers = d["servers"].as_array().unwrap();
        let by_tag = |t: &str| servers.iter().find(|s| s["tag"] == t).cloned().unwrap_or(Value::Null);
        assert_eq!(by_tag("local"), json!({"type": "udp", "tag": "local", "server": "119.29.29.29"}));
        assert_eq!(by_tag("dns-0"), json!({"type": "udp", "tag": "dns-0", "server": "223.5.5.5"}));
        assert_eq!(by_tag("dns-1"), json!({"type": "https", "tag": "dns-1", "server": "doh.pub", "path": "/q", "domain_resolver": "local", "detour": "PROXY"}));
        // Unknown group: no detour; dhcp:// dropped.
        assert_eq!(by_tag("dns-2"), json!({"type": "tls", "tag": "dns-2", "server": "1.1.1.1", "server_port": 853}));
        assert!(by_tag("dns-3").is_null());
        assert_eq!(by_tag("fakeip"), json!({"type": "fakeip", "tag": "fakeip", "inet4_range": "198.18.0.0/16"}));
        assert_eq!(d["final"], "dns-0");
        assert_eq!(d["rules"][0], json!({"domain_suffix": ["lan"], "domain": ["time.windows.com"], "server": "dns-0"}));
        assert_eq!(d["rules"][1], json!({"query_type": ["A", "AAAA"], "server": "fakeip"}));
        assert_eq!(d["strategy"], "ipv4_only");

        // No profile DNS, final DIRECT: foreign names still resolve via a proxy group.
        let sb = emit(&parse_any(base).unwrap(), &o);
        let remote = sb["dns"]["servers"].as_array().unwrap().iter().find(|s| s["tag"] == "remote").cloned().unwrap();
        assert_eq!(remote["detour"], "PROXY");
    }

    fn overrides() -> Overrides {
        Overrides {
            mixed_port: 7890,
            controller: "127.0.0.1:9097".into(),
            secret: "s".into(),
            mode: Mode::Rule,
            allow_lan: false,
            log_level: "info".into(),
            tun: false,
            unified_delay: false,
        }
    }

    #[test]
    fn tuic_wireguard_relay_and_logical_rules() {
        let y = r#"
proxies:
  - {name: t, type: tuic, server: t.example.com, port: 443, uuid: 0b6a0b4e-0000-4000-8000-000000000000, password: pw, congestion-controller: bbr}
  - {name: w, type: wireguard, server: 1.2.3.4, port: 51820, private-key: priv=, public-key: pub=, ip: 10.0.0.2, reserved: [1, 2, 3], dialer-proxy: t}
  - {name: s, type: ss, server: 5.6.7.8, port: 1, cipher: aes-128-gcm, password: x}
proxy-groups:
  - {name: PROXY, type: select, proxies: [t, w, s]}
  - {name: chain, type: relay, proxies: [PROXY, s, t]}
rules:
  - AND,((NETWORK,udp),(DST-PORT,443)),REJECT
  - NOT,((GEOSITE,cn)),PROXY
  - OR,((DOMAIN-SUFFIX,a.com),(SRC-GEOIP,cn)),chain
  - MATCH,DIRECT
"#;
        let p = crate::config::parse_any(y).unwrap();
        let sb = emit(&p, &overrides());
        let eps = sb["endpoints"].as_array().unwrap();
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0]["address"], json!(["10.0.0.2/32"]));
        assert_eq!(eps[0]["peers"][0]["reserved"], json!([1, 2, 3]));
        assert_eq!(eps[0]["detour"], "t");
        let ob = |tag: &str| sb["outbounds"].as_array().unwrap().iter().find(|o| o["tag"] == tag).cloned().unwrap();
        assert_eq!(ob("t")["tls"]["alpn"], json!(["h3"]));
        assert_eq!(ob("t")["congestion_control"], "bbr");
        // relay [PROXY, s, t]: copy of s through PROXY, copy of t (named chain) through it
        assert_eq!(ob("chain · 1")["detour"], "PROXY");
        assert_eq!(ob("chain · 1")["type"], "shadowsocks");
        assert_eq!(ob("chain")["detour"], "chain · 1");
        assert_eq!(ob("chain")["type"], "tuic");
        let rules = sb["route"]["rules"].as_array().unwrap();
        assert!(rules.contains(&json!({"type": "logical", "mode": "and", "rules": [{"network": ["udp"]}, {"port": [443]}], "action": "reject"})));
        assert!(rules.contains(&json!({"rule_set": ["geosite-cn"], "invert": true, "outbound": "PROXY"})));
        assert!(rules.contains(&json!({"type": "logical", "mode": "or", "rules": [{"domain_suffix": ["a.com"]}, {"rule_set": ["geoip-cn"], "rule_set_ip_cidr_match_source": true}], "outbound": "chain"})));
        // and back
        let back = parse(&sb).unwrap();
        let w = back.proxies.iter().find(|x| x.name == "w").unwrap();
        assert_eq!((w.kind, w.public_key.as_deref(), w.dialer_proxy.as_deref()), (Some(ProxyKind::WireGuard), Some("pub="), Some("t")));
        assert_eq!(back.proxies.iter().find(|x| x.name == "t").unwrap().kind, Some(ProxyKind::Tuic));
    }

    #[test]
    fn clash_to_singbox_and_back() {
        let raw = "anytls://pw@jp.example.com:443/?sni=jp.example.com#jp";
        let p = parse_any(raw).unwrap();
        let sb = emit(&p, &overrides());
        let tags: Vec<&str> = sb["outbounds"].as_array().unwrap().iter().map(|o| o["tag"].as_str().unwrap()).collect();
        assert!(tags.contains(&"jp") && tags.contains(&"GLOBAL") && tags.contains(&"节点选择"));
        assert_eq!(sb["route"]["final"], "节点选择");
        assert!(sb["route"]["rule_set"].as_array().unwrap().iter().any(|r| r["tag"] == "geosite-cn"));

        let back = parse(&sb).unwrap();
        assert_eq!(back.proxies.len(), 1);
        assert_eq!(back.proxies[0].sni.as_deref(), Some("jp.example.com"));
        assert!(back.rules.iter().any(|r| r.kind == "GEOSITE" && r.payload == "cn" && r.target == "DIRECT"));
        assert_eq!(back.rules.last().unwrap().kind, "MATCH");
    }

    #[test]
    fn app_rules_go_after_mode_rules() {
        let p = parse_any("anytls://pw@jp.example.com:443/?sni=jp.example.com#jp").unwrap();
        let mut sb = emit(&p, &overrides());
        let routes = [
            AppRoute { by_path: false, value: "chrome".into(), target: "jp".into(), strict: false },
            AppRoute { by_path: true, value: "C:\\Games\\x.exe".into(), target: "DIRECT".into(), strict: false },
            AppRoute { by_path: false, value: "ads.exe".into(), target: "REJECT".into(), strict: false },
            AppRoute { by_path: false, value: "a.exe".into(), target: "missing".into(), strict: false },
        ];
        let w = add_app_rules(&mut sb, &routes);
        assert_eq!(w.len(), 1, "{w:?}");
        let rules = sb["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["action"], "sniff");
        assert_eq!(rules[2]["clash_mode"], "Global");
        assert_eq!(rules[3], json!({ "process_name": [if cfg!(windows) { "chrome.exe" } else { "chrome" }], "outbound": "jp" }));
        assert_eq!(rules[4], json!({ "process_path": ["C:\\Games\\x.exe"], "outbound": "DIRECT" }));
        assert_eq!(rules[5], json!({ "process_name": ["ads.exe"], "action": "reject" }));
    }

    #[test]
    fn user_rules_after_mode_rules_with_rule_sets() {
        let p = parse_any("anytls://pw@jp.example.com:443/?sni=jp.example.com#jp").unwrap();
        let mut sb = emit(&p, &overrides());
        let ur = |kind: &str, value: &str, target: &str| UserRule { kind: kind.into(), value: value.into(), target: target.into(), resolve: false, strict: false };
        let w = add_user_rules(
            &mut sb,
            &[ur("DOMAIN-SUFFIX", "example.com", "jp"), ur("IP-CIDR", "1.1.1.1", "DIRECT"), ur("GEOSITE", "netflix", "jp"), ur("GEOIP", "telegram", "REJECT"), ur("DOMAIN", "x.com", "missing")],
        );
        assert_eq!(w.len(), 1, "{w:?}");
        add_app_rules(&mut sb, &[AppRoute { by_path: false, value: "chrome".into(), target: "jp".into(), strict: false }]);
        let rules = sb["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[2]["clash_mode"], "Global");
        assert_eq!(rules[3], json!({ "process_name": [if cfg!(windows) { "chrome.exe" } else { "chrome" }], "outbound": "jp" }));
        assert_eq!(rules[4], json!({ "domain_suffix": ["example.com"], "outbound": "jp" }));
        assert_eq!(rules[5], json!({ "ip_cidr": ["1.1.1.1/32"], "outbound": "DIRECT" }));
        assert_eq!(rules[6], json!({ "rule_set": ["geosite-netflix"], "outbound": "jp" }));
        assert_eq!(rules[7], json!({ "rule_set": ["geoip-telegram"], "action": "reject" }));
        let tags: Vec<&str> = sb["route"]["rule_set"].as_array().unwrap().iter().map(|e| e["tag"].as_str().unwrap()).collect();
        assert!(tags.contains(&"geosite-netflix") && tags.contains(&"geoip-telegram"), "{tags:?}");
        assert_eq!(tags.iter().filter(|t| **t == "geosite-netflix").count(), 1);
    }

    #[test]
    fn localizes_rule_sets_and_drops_missing() {
        let raw = "anytls://pw@jp.example.com:443/?sni=jp.example.com#jp";
        let mut o = overrides();
        o.tun = true; // DNS rules reference geosite-cn too
        let mut sb = emit(&parse_any(raw).unwrap(), &o);
        assert!(!sb.to_string().contains("download_detour"));
        let remotes = remote_rule_sets(&sb);
        let tags: Vec<&str> = remotes.iter().map(|r| r.tag.as_str()).collect();
        assert_eq!(tags, ["geoip-cn", "geosite-cn", "geosite-private"]);
        assert_eq!(remotes[1].file, "geosite-cn.srs");

        // A rule mixing rule_set with another condition keeps the condition.
        sb["route"]["rules"].as_array_mut().unwrap().push(json!({ "rule_set": ["geoip-cn"], "domain_suffix": ["x.cn"], "outbound": "DIRECT" }));
        let dir = std::env::temp_dir().join(format!("prism-rs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("geosite-cn.srs"), b"x").unwrap();
        let dropped = localize_rule_sets(&mut sb, &dir);
        assert_eq!(dropped, ["geoip-cn", "geosite-private"]);

        let sets = sb["route"]["rule_set"].as_array().unwrap();
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0]["type"], "local");
        assert!(sets[0]["path"].as_str().unwrap().ends_with("geosite-cn.srs"));
        let text = sb.to_string();
        assert!(!text.contains("geoip-cn") && !text.contains("geosite-private"));
        // geosite-cn rules survive (route + DNS), the dropped ones are gone,
        // and the mixed rule lost only its rule_set.
        assert!(sb["dns"]["rules"].as_array().unwrap().iter().any(|r| r["rule_set"] == json!("geosite-cn")));
        let rules = sb["route"]["rules"].as_array().unwrap();
        assert!(rules.iter().any(|r| r["rule_set"] == json!(["geosite-cn"])));
        assert!(rules.iter().any(|r| r["domain_suffix"] == json!(["x.cn"]) && r.get("rule_set").is_none()));
        assert!(rules.iter().all(|r| r.as_object().unwrap().keys().any(|k| k != "outbound")));
    }
}
