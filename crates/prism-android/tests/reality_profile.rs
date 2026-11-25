use prism_android::profile::{self, Session};
use serde_json::{json, Value};

const ID: &str = "0b6a0b4e-1111-4222-8333-444455556666";
const PUBLIC: &str = "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw";

fn sources(vision: bool) -> Vec<String> {
    let mut clash = json!({"proxies":[{"name":"Reality","type":"vless","server":"127.0.0.1","port":443,
        "uuid":ID,"tls":true,"servername":"reality.fixture.test","client-fingerprint":"chrome",
        "reality-opts":{"public-key":PUBLIC,"short-id":"0123456789abcdef"}}]});
    let mut singbox = json!({"outbounds":[{"tag":"Reality","type":"vless","server":"127.0.0.1","server_port":443,
        "uuid":ID,"tls":{"enabled":true,"server_name":"reality.fixture.test","utls":{"enabled":true,"fingerprint":"chrome"},
        "reality":{"enabled":true,"public_key":PUBLIC,"short_id":"0123456789abcdef"}}}]});
    let mut uri=format!("vless://{ID}@127.0.0.1:443?security=reality&sni=reality.fixture.test&fp=chrome&pbk={PUBLIC}&sid=0123456789abcdef");
    if vision {
        clash["proxies"][0]["flow"] = json!("xtls-rprx-vision");
        singbox["outbounds"][0]["flow"] = json!("xtls-rprx-vision");
        uri.push_str("&flow=xtls-rprx-vision");
    }
    vec![clash.to_string(), singbox.to_string(), uri]
}

#[test]
fn three_formats_retain_reality_authentication_in_mobile_sessions() {
    for vision in [false, true] {
        for raw in sources(vision) {
            let imported = profile::import(&raw).unwrap();
            assert_eq!(imported.skipped, 0);
            assert_eq!(imported.nodes.len(), 1);
            let session: Session =
                serde_json::from_value(json!({"node":imported.nodes[0]})).unwrap();
            let (built, _) = profile::build(session).unwrap();
            let node = &built.proxies[0];
            assert!(node.tls && !node.skip_cert_verify);
            assert_eq!(node.uuid.as_deref(), Some(ID));
            assert_eq!(node.reality_public_key.as_deref(), Some(PUBLIC));
            assert_eq!(node.reality_short_id.as_deref(), Some("0123456789abcdef"));
            assert_eq!(node.sni.as_deref(), Some("reality.fixture.test"));
            assert_eq!(node.fingerprint.as_deref(), Some("chrome"));
            assert_eq!(node.flow.as_deref(), vision.then_some("xtls-rprx-vision"));
        }
    }
}

#[test]
fn unsafe_authentication_and_unqualified_transport_combinations_are_rejected() {
    let node = profile::import(&sources(true)[0]).unwrap().nodes.remove(0);
    let base = serde_json::to_value(node).unwrap();
    let mut mutations: Vec<(&str, Value)> = vec![
        ("uuid", json!("bad-uuid")),
        ("reality_public_key", json!("short")),
        ("reality_public_key", json!("A".repeat(43))),
        ("reality_short_id", json!("xyz")),
        ("flow", json!("unknown")),
        ("flow", json!("xtls-rprx-vision-udp443")),
        ("fingerprint", json!("firefox")),
        ("network", json!("ws")),
        ("network", json!("grpc")),
        ("skip_cert_verify", json!(true)),
        ("tls", json!(false)),
        ("dialer_proxy", json!("other")),
        ("sni", Value::Null),
        ("sni", json!("1.1.1.1")),
        ("sni", json!("bad\r\nname")),
        ("sni", json!("bad_name.test")),
        ("sni", json!("-bad.test")),
        ("sni", json!("bad..test")),
        ("sni", json!("a".repeat(254))),
    ];
    for kind in ["vmess", "trojan", "socks5"] {
        mutations.push(("kind", json!(kind)));
    }
    for (field, value) in mutations {
        let mut invalid = base.clone();
        invalid[field] = value;
        let session: Session = serde_json::from_value(json!({"node":invalid})).unwrap();
        assert!(profile::build(session).is_err(), "accepted unsafe {field}");
    }
    let mut no_reality = base.clone();
    no_reality["reality_public_key"] = Value::Null;
    let session: Session = serde_json::from_value(json!({"node":no_reality})).unwrap();
    assert!(
        profile::build(session).is_err(),
        "Vision without Reality remains unqualified"
    );
    let mut default_fingerprint = base;
    default_fingerprint["fingerprint"] = Value::Null;
    let session: Session = serde_json::from_value(json!({"node":default_fingerprint})).unwrap();
    assert!(profile::build(session).is_ok());
}
