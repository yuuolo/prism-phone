//! Share-link subscriptions: plain or base64 lists of `anytls://`, `ss://`,
//! `trojan://`, `vless://`, `vmess://`, `hysteria2://`, `tuic://`,
//! `wireguard://` and `socks5://` URIs.

use std::collections::HashMap;

use anyhow::{anyhow, bail, Result};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use percent_encoding::percent_decode_str;
use url::Url;

use super::{ProxyConfig, ProxyKind};

pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let t: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD]
        .iter()
        .find_map(|e| e.decode(t.as_bytes()).ok())
}

fn decode(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

/// Returns the parsed nodes plus warnings for lines that were skipped.
pub fn parse_list(raw: &str) -> (Vec<ProxyConfig>, Vec<String>) {
    let mut text = raw.trim().to_string();
    if !text.contains("://") {
        if let Some(bytes) = b64_decode(&text) {
            text = String::from_utf8_lossy(&bytes).into_owned();
        }
    }
    let mut out = Vec::new();
    let mut warnings = Vec::new();
    let mut seen: HashMap<String, usize> = HashMap::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        match parse_uri(line) {
            Ok(mut p) => {
                // Clash requires unique names.
                let count = seen.entry(p.name.clone()).or_insert(0);
                *count += 1;
                if *count > 1 {
                    p.name = format!("{} {}", p.name, count);
                }
                out.push(p);
            }
            Err(e) => warnings.push(format!("{e}: {}", line.chars().take(40).collect::<String>())),
        }
    }
    (out, warnings)
}

pub fn parse_uri(line: &str) -> Result<ProxyConfig> {
    let scheme = line.split("://").next().unwrap_or_default().to_ascii_lowercase();
    match scheme.as_str() {
        "vmess" => parse_vmess(line),
        "ss" => parse_ss(line),
        "anytls" | "trojan" | "vless" | "hysteria2" | "hy2" | "tuic" | "wireguard" | "wg" | "socks5" | "socks" => {
            parse_generic(line, &scheme)
        }
        _ => bail!("unsupported scheme {scheme}"),
    }
}

fn host_port(u: &Url) -> Result<(String, u16)> {
    let host = u.host_str().ok_or_else(|| anyhow!("missing host"))?;
    let host = host.trim_start_matches('[').trim_end_matches(']').to_string();
    let port = u.port().ok_or_else(|| anyhow!("missing port"))?;
    Ok((host, port))
}

fn name_of(u: &Url, host: &str, port: u16) -> String {
    u.fragment()
        .map(decode)
        .filter(|n| !n.trim().is_empty())
        .unwrap_or_else(|| format!("{host}:{port}"))
}

fn truthy(v: Option<&String>) -> bool {
    matches!(v.map(String::as_str), Some("1" | "true"))
}

fn parse_generic(line: &str, scheme: &str) -> Result<ProxyConfig> {
    let u = Url::parse(line)?;
    let (server, port) = host_port(&u)?;
    let q: HashMap<String, String> = u.query_pairs().into_owned().collect();
    let user = decode(u.username());
    let kind = match scheme {
        "anytls" => ProxyKind::AnyTls,
        "trojan" => ProxyKind::Trojan,
        "vless" => ProxyKind::Vless,
        "hysteria2" | "hy2" => ProxyKind::Hysteria2,
        "tuic" => ProxyKind::Tuic,
        "wireguard" | "wg" => ProxyKind::WireGuard,
        _ => ProxyKind::Socks5,
    };
    let mut p = ProxyConfig {
        name: name_of(&u, &server, port),
        kind: Some(kind),
        server,
        port,
        sni: q.get("sni").or_else(|| q.get("peer")).cloned().filter(|s| !s.is_empty()),
        skip_cert_verify: truthy(q.get("insecure")) || truthy(q.get("allowInsecure")) || truthy(q.get("allow_insecure")),
        alpn: q.get("alpn").map(|a| a.split(',').map(String::from).collect()).unwrap_or_default(),
        fingerprint: q.get("fp").cloned().filter(|s| !s.is_empty()),
        udp: true,
        ..Default::default()
    };
    match kind {
        ProxyKind::Vless => {
            p.uuid = Some(user);
            let security = q.get("security").map(String::as_str).unwrap_or("none");
            p.tls = security == "tls" || security == "reality";
            if security == "reality" {
                p.reality_public_key = q.get("pbk").cloned();
                p.reality_short_id = q.get("sid").cloned();
            }
            p.flow = q.get("flow").cloned().filter(|f| !f.is_empty());
        }
        ProxyKind::Socks5 => {
            p.username = Some(user).filter(|u| !u.is_empty());
            p.password = u.password().map(decode);
            p.udp = false;
        }
        ProxyKind::Tuic => {
            p.uuid = Some(user);
            p.password = u.password().map(decode);
            p.tls = true;
            p.congestion = q.get("congestion_control").or_else(|| q.get("congestion-controller")).cloned();
            p.udp_relay_mode = q.get("udp_relay_mode").or_else(|| q.get("udp-relay-mode")).cloned();
        }
        ProxyKind::WireGuard => {
            // v2rayN style: the private key is the userinfo.
            p.private_key = Some(user).filter(|k| !k.is_empty()).or_else(|| q.get("privatekey").cloned());
            p.public_key = q.get("publickey").or_else(|| q.get("public-key")).cloned();
            p.pre_shared_key = q.get("presharedkey").or_else(|| q.get("pre-shared-key")).cloned().filter(|k| !k.is_empty());
            for a in q.get("address").or_else(|| q.get("ip")).map(|a| a.split(',').map(str::trim).collect::<Vec<_>>()).unwrap_or_default() {
                let host = a.split('/').next().unwrap_or(a);
                match host.parse::<std::net::IpAddr>() {
                    Ok(std::net::IpAddr::V4(_)) => p.ip = Some(a.to_string()),
                    Ok(std::net::IpAddr::V6(_)) => p.ipv6 = Some(a.to_string()),
                    Err(_) => {}
                }
            }
            p.reserved = q.get("reserved").map(|r| super::parse_reserved(r)).unwrap_or_default();
            p.mtu = q.get("mtu").and_then(|m| m.parse().ok());
        }
        _ => {
            // anytls / trojan / hysteria2: the userinfo is the password. Some
            // links put it as user:pass, keep everything.
            p.password = Some(match u.password() {
                Some(pw) => format!("{user}:{}", decode(pw)),
                None => user,
            });
            p.tls = true;
            if kind == ProxyKind::Hysteria2 {
                p.obfs = q.get("obfs").cloned();
                p.obfs_password = q.get("obfs-password").cloned();
            }
        }
    }
    if matches!(kind, ProxyKind::Vless | ProxyKind::Trojan) {
        match q.get("type").map(String::as_str) {
            Some(t @ ("ws" | "httpupgrade")) => {
                p.network = Some(t.into());
                p.ws_path = q.get("path").cloned();
                p.ws_host = q.get("host").cloned().filter(|h| !h.is_empty());
            }
            Some("grpc") => {
                p.network = Some("grpc".into());
                p.grpc_service = q.get("serviceName").cloned();
            }
            // V2RayN spells the HTTP/2 transport `http`.
            Some("h2" | "http") => {
                p.network = Some("h2".into());
                p.ws_path = q.get("path").cloned();
                p.ws_host = q.get("host").and_then(|h| h.split(',').next()).map(str::to_string).filter(|h| !h.is_empty());
            }
            Some(t @ ("xhttp" | "splithttp")) => {
                if q.get("extra").is_some_and(|e| e.contains("downloadSettings")) {
                    bail!("xhttp downloadSettings is not supported");
                }
                let _ = t;
                p.network = Some("xhttp".into());
                p.ws_path = q.get("path").cloned();
                p.ws_host = q.get("host").cloned().filter(|h| !h.is_empty());
                p.xhttp_mode = q.get("mode").cloned().filter(|m| !m.is_empty());
            }
            None | Some("" | "tcp" | "raw") => {}
            // kcp, quic...: kept so the node isn't dialed as plain TCP.
            Some(t) => p.network = Some(t.into()),
        }
    }
    Ok(p)
}

fn parse_ss(line: &str) -> Result<ProxyConfig> {
    let body = &line[5..];
    let (main, frag) = body.split_once('#').map(|(a, b)| (a, Some(b))).unwrap_or((body, None));
    let main = main.split('?').next().unwrap_or(main).trim_end_matches('/');
    let (userinfo, hostport) = match main.rsplit_once('@') {
        Some((u, h)) => {
            let u = decode(u);
            let info = match b64_decode(&u) {
                Some(b) if String::from_utf8_lossy(&b).contains(':') => String::from_utf8_lossy(&b).into_owned(),
                _ => u,
            };
            (info, h.to_string())
        }
        None => {
            // Legacy: base64(method:password@host:port)
            let dec = String::from_utf8(b64_decode(main).ok_or_else(|| anyhow!("bad ss link"))?)?;
            let (u, h) = dec.rsplit_once('@').ok_or_else(|| anyhow!("bad ss link"))?;
            (u.to_string(), h.to_string())
        }
    };
    let (cipher, password) = userinfo.split_once(':').ok_or_else(|| anyhow!("bad ss userinfo"))?;
    let (host, port) = hostport.rsplit_once(':').ok_or_else(|| anyhow!("bad ss host"))?;
    let host = host.trim_start_matches('[').trim_end_matches(']').to_string();
    let port: u16 = port.parse()?;
    if line.contains("plugin=") {
        bail!("ss plugins are not supported");
    }
    Ok(ProxyConfig {
        name: frag.map(decode).filter(|n| !n.is_empty()).unwrap_or_else(|| format!("{host}:{port}")),
        kind: Some(ProxyKind::Shadowsocks),
        server: host,
        port,
        cipher: Some(cipher.to_string()),
        password: Some(password.to_string()),
        udp: true,
        ..Default::default()
    })
}

fn parse_vmess(line: &str) -> Result<ProxyConfig> {
    let raw = b64_decode(&line[8..]).ok_or_else(|| anyhow!("bad vmess base64"))?;
    let v: serde_json::Value = serde_json::from_slice(&raw)?;
    let st = |k: &str| match v.get(k) {
        Some(serde_json::Value::String(s)) => Some(s.clone()).filter(|s| !s.is_empty()),
        Some(serde_json::Value::Number(n)) => Some(n.to_string()),
        _ => None,
    };
    let server = st("add").ok_or_else(|| anyhow!("vmess: missing add"))?;
    let port: u16 = st("port").and_then(|p| p.parse().ok()).ok_or_else(|| anyhow!("vmess: bad port"))?;
    let mut net = st("net").filter(|n| n != "tcp" && n != "raw");
    // tcp with an HTTP header ("obfs") is a different transport.
    if net.is_none() && st("type").as_deref() == Some("http") {
        net = Some("http".into());
    }
    Ok(ProxyConfig {
        name: st("ps").unwrap_or_else(|| format!("{server}:{port}")),
        kind: Some(ProxyKind::Vmess),
        uuid: st("id"),
        alter_id: st("aid").and_then(|a| a.parse().ok()).unwrap_or(0),
        cipher: st("scy").or(Some("auto".into())),
        tls: st("tls").as_deref() == Some("tls"),
        sni: st("sni"),
        alpn: st("alpn").map(|a| a.split(',').map(String::from).collect()).unwrap_or_default(),
        fingerprint: st("fp"),
        ws_path: st("path"),
        ws_host: st("host"),
        grpc_service: if net.as_deref() == Some("grpc") { st("path") } else { None },
        network: net,
        server,
        port,
        udp: true,
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sbm_anytls_base64() {
        let list = "anytls://p%40ss@jp.example.com:8443/?sni=jp.example.com&fp=chrome#%E4%B8%9C%E4%BA%AC\n\
                    ss://YWVzLTI1Ni1nY206c2VjcmV0@1.2.3.4:8388#ss1\n\
                    vless://0b6a0b4e-0000-4000-8000-000000000000@v.example.com:443?security=tls&sni=v.example.com&type=ws&path=%2Fray#v\n\
                    hysteria2://pw@h.example.com:443?sni=h.example.com&insecure=1#h";
        let encoded = STANDARD.encode(list);
        let (nodes, warns) = parse_list(&encoded);
        assert!(warns.is_empty(), "{warns:?}");
        assert_eq!(nodes.len(), 4);
        let a = &nodes[0];
        assert_eq!(a.kind, Some(ProxyKind::AnyTls));
        assert_eq!(a.name, "东京");
        assert_eq!(a.password.as_deref(), Some("p@ss"));
        assert_eq!(a.port, 8443);
        assert_eq!(a.fingerprint.as_deref(), Some("chrome"));
        assert_eq!(nodes[1].cipher.as_deref(), Some("aes-256-gcm"));
        assert_eq!(nodes[2].ws_path.as_deref(), Some("/ray"));
        assert!(nodes[3].skip_cert_verify);
    }

    #[test]
    fn tuic_and_wireguard_links() {
        let t = parse_uri("tuic://0b6a0b4e-0000-4000-8000-000000000000:p%40ss@t.example.com:443?sni=t.example.com&alpn=h3&congestion_control=bbr&udp_relay_mode=quic&allow_insecure=1#tu").unwrap();
        assert_eq!(t.kind, Some(ProxyKind::Tuic));
        assert_eq!(t.password.as_deref(), Some("p@ss"));
        assert_eq!(t.congestion.as_deref(), Some("bbr"));
        assert_eq!(t.udp_relay_mode.as_deref(), Some("quic"));
        assert!(t.skip_cert_verify && t.tls);
        let w = parse_uri("wireguard://cGsAAA%3D@162.159.192.1:2408?publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D&reserved=1,2,3&address=172.16.0.2%2F32,2606:4700::2%2F128&mtu=1280#warp").unwrap();
        assert_eq!(w.kind, Some(ProxyKind::WireGuard));
        assert_eq!(w.private_key.as_deref(), Some("cGsAAA="));
        assert_eq!(w.public_key.as_deref(), Some("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="));
        assert_eq!(w.reserved, vec![1, 2, 3]);
        assert_eq!(w.ip.as_deref(), Some("172.16.0.2/32"));
        assert_eq!(w.ipv6.as_deref(), Some("2606:4700::2/128"));
        assert_eq!(w.mtu, Some(1280));
    }

    /// SIP022 links keep `method:base64-keys` percent-encoded, not base64-wrapped.
    #[test]
    fn shadowsocks_2022_links() {
        let s = parse_uri("ss://2022-blake3-aes-128-gcm:AAECAwQFBgcICQoLDA0ODw%3D%3D%3AEBESExQVFhcYGRobHB0eHw%3D%3D@s.example.com:443#ss22").unwrap();
        assert_eq!(s.cipher.as_deref(), Some("2022-blake3-aes-128-gcm"));
        assert_eq!(s.password.as_deref(), Some("AAECAwQFBgcICQoLDA0ODw==:EBESExQVFhcYGRobHB0eHw=="));
        let b = parse_uri(&format!("ss://{}@s.example.com:443#b", STANDARD.encode("2022-blake3-aes-256-gcm:a2V5"))).unwrap();
        assert_eq!(b.cipher.as_deref(), Some("2022-blake3-aes-256-gcm"));
        assert_eq!(b.password.as_deref(), Some("a2V5"));
    }
}
