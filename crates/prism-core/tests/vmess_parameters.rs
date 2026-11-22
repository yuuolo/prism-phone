use base64::{engine::general_purpose::STANDARD, Engine};
use prism_core::config::{parse_any, ProxyKind};
use serde_json::{json, Value};

const ID: &str = "0b6a0b4e-1111-4222-8333-444455556666";

fn sources(alter_id: Value) -> Vec<String> {
    let clash = json!({"proxies":[{"name":"parameter","type":"vmess","server":"127.0.0.1",
        "port":443,"uuid":ID,"cipher":"auto","alterId":alter_id.clone()}]});
    let singbox = json!({"outbounds":[{"tag":"parameter","type":"vmess","server":"127.0.0.1",
        "server_port":443,"uuid":ID,"security":"auto","alter_id":alter_id.clone()}]});
    let uri = json!({"v":"2","ps":"parameter","add":"127.0.0.1","port":"443",
        "id":ID,"aid":alter_id,"scy":"auto","net":"tcp"});
    vec![
        serde_yaml::to_string(&clash).unwrap(),
        singbox.to_string(),
        format!(
            "vmess://{}",
            STANDARD.encode(serde_json::to_vec(&uri).unwrap())
        ),
    ]
}

#[test]
fn invalid_alter_id_must_not_become_aead_zero_in_any_import_format() {
    for invalid in [
        json!(-1),
        json!(4294967296u64),
        json!(u64::MAX),
        json!(1.5),
        Value::Null,
        json!(true),
        json!("garbage"),
    ] {
        for (format, raw) in sources(invalid.clone()).into_iter().enumerate() {
            if let Ok(profile) = parse_any(&raw) {
                assert!(
                    !profile.proxies.iter().any(|p| p.kind() == ProxyKind::Vmess),
                    "format {format} silently accepted invalid alterId {invalid}"
                );
            }
        }
    }
}

#[test]
fn valid_numeric_alter_id_is_preserved_for_constructor_validation() {
    for value in [0u32, 64, u32::MAX] {
        for raw in sources(json!(value)) {
            let profile = parse_any(&raw).unwrap();
            assert_eq!(profile.proxies.len(), 1);
            assert_eq!(profile.proxies[0].kind(), ProxyKind::Vmess);
            assert_eq!(profile.proxies[0].alter_id, value);
        }
    }
}

#[test]
fn vmess_ports_cannot_wrap_or_coerce_into_a_different_endpoint() {
    for port in [
        json!(0),
        json!(-1),
        json!(65536),
        json!(65537),
        json!(u64::MAX),
        json!(1.5),
        Value::Null,
        json!(true),
    ] {
        let clash = json!({"proxies":[{"name":"port","type":"vmess","server":"127.0.0.1","port":port.clone(),"uuid":ID}]});
        let singbox = json!({"outbounds":[{"tag":"port","type":"vmess","server":"127.0.0.1","server_port":port.clone(),"uuid":ID}]});
        let uri = json!({"v":"2","add":"127.0.0.1","port":port,"id":ID});
        for raw in [
            serde_yaml::to_string(&clash).unwrap(),
            singbox.to_string(),
            format!(
                "vmess://{}",
                STANDARD.encode(serde_json::to_vec(&uri).unwrap())
            ),
        ] {
            if let Ok(profile) = parse_any(&raw) {
                assert!(
                    !profile.proxies.iter().any(|p| p.kind() == ProxyKind::Vmess),
                    "invalid VMess port accepted"
                );
            }
        }
    }
}
