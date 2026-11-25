use prism_core::{
    config::{parse_any, ProxyKind},
    outbound::{build_proxy, Dialer},
};
use serde_json::{json, Value};

const ID: &str = "0b6a0b4e-1111-4222-8333-444455556666";
const PUBLIC: &str = "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw";
const SID: &str = "0123456789abcdef";

fn sources(public: Option<Value>, vision: bool) -> Vec<String> {
    let mut clash = json!({"proxies":[{"name":"Reality","type":"vless","server":"127.0.0.1","port":443,
        "uuid":ID,"tls":true,"servername":"reality.fixture.test","client-fingerprint":"chrome",
        "reality-opts":{"short-id":SID}}]});
    let mut singbox = json!({"outbounds":[{"tag":"Reality","type":"vless","server":"127.0.0.1","server_port":443,
        "uuid":ID,"tls":{"enabled":true,"server_name":"reality.fixture.test",
            "utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"short_id":SID}}}]});
    let mut uri = format!(
        "vless://{ID}@127.0.0.1:443?security=reality&sni=reality.fixture.test&fp=chrome&sid={SID}"
    );
    if let Some(public) = public {
        clash["proxies"][0]["reality-opts"]["public-key"] = public.clone();
        singbox["outbounds"][0]["tls"]["reality"]["public_key"] = public.clone();
        uri.push_str(&format!("&pbk={}", public.as_str().unwrap_or("")));
    }
    if vision {
        clash["proxies"][0]["flow"] = json!("xtls-rprx-vision");
        singbox["outbounds"][0]["flow"] = json!("xtls-rprx-vision");
        uri.push_str("&flow=xtls-rprx-vision");
    }
    vec![clash.to_string(), singbox.to_string(), uri]
}

#[test]
fn three_formats_preserve_reality_and_optional_vision_parameters() {
    for vision in [false, true] {
        for raw in sources(Some(json!(PUBLIC)), vision) {
            let profile = parse_any(&raw).unwrap();
            assert_eq!(profile.proxies.len(), 1);
            let node = &profile.proxies[0];
            assert_eq!(node.kind(), ProxyKind::Vless);
            assert!(node.tls && !node.skip_cert_verify);
            assert_eq!(node.reality_public_key.as_deref(), Some(PUBLIC));
            assert_eq!(node.reality_short_id.as_deref(), Some(SID));
            assert_eq!(node.sni.as_deref(), Some("reality.fixture.test"));
            assert_eq!(node.fingerprint.as_deref(), Some("chrome"));
            assert_eq!(node.flow.as_deref(), vision.then_some("xtls-rprx-vision"));
            assert!(build_proxy(node, Dialer::Direct).is_ok());
        }
    }
}

fn no_vless(raw: &str) {
    if let Ok(profile) = parse_any(raw) {
        assert!(
            !profile.proxies.iter().any(|n| n.kind() == ProxyKind::Vless),
            "silently downgraded: {raw}"
        );
    }
}

#[test]
fn explicit_reality_without_required_public_key_must_not_downgrade() {
    for public in [
        None,
        Some(Value::Null),
        Some(json!("")),
        Some(json!("   ")),
        Some(json!(123)),
        Some(json!(true)),
    ] {
        for raw in sources(public, false) {
            no_vless(&raw);
        }
    }
}

#[test]
fn disabled_or_absent_reality_retains_ordinary_tls() {
    for public in [None, Some(json!(PUBLIC))] {
        let raw = sources(public, false);
        let mut singbox: Value = serde_json::from_str(&raw[1]).unwrap();
        singbox["outbounds"][0]["tls"]["reality"]["enabled"] = json!(false);
        let p = parse_any(&singbox.to_string()).unwrap();
        assert_eq!(p.proxies.len(), 1);
        assert!(p.proxies[0].tls);
        assert!(p.proxies[0].reality_public_key.is_none());
        assert!(p.proxies[0].reality_short_id.is_none());
        assert_eq!(p.proxies[0].uuid.as_deref(), Some(ID));
    }
    let raw = sources(None, false);
    let mut clash: Value = serde_json::from_str(&raw[0]).unwrap();
    clash["proxies"][0]["reality-opts"] = Value::Null;
    let p = parse_any(&clash.to_string()).unwrap();
    assert_eq!(p.proxies.len(), 1);
    assert!(p.proxies[0].tls && p.proxies[0].reality_public_key.is_none());
}

#[test]
fn unknown_vless_uri_security_must_not_become_plaintext() {
    for security in ["garbage", "Reality", "tlss"] {
        no_vless(&format!("vless://{ID}@127.0.0.1:443?security={security}"));
    }
    for security in ["none", "tls"] {
        let p = parse_any(&format!("vless://{ID}@127.0.0.1:443?security={security}")).unwrap();
        assert_eq!(p.proxies.len(), 1);
        assert_eq!(p.proxies[0].tls, security == "tls");
    }
}
