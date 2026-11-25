use prism_android::profile::{self, Session};
use serde_json::{json, Value};

fn source(service: Option<&str>, singbox: bool) -> Value {
    let id = "0b6a0b4e-1111-4222-8333-444455556666";
    if singbox {
        let mut value = json!({"outbounds":[{"tag":"gRPC","type":"vmess","server":"127.0.0.1",
            "server_port":443,"uuid":id,"security":"auto","transport":{"type":"grpc"}}]});
        if let Some(service) = service {
            value["outbounds"][0]["transport"]["service_name"] = json!(service);
        }
        value
    } else {
        let mut value = json!({"proxies":[{"name":"gRPC","type":"vmess","server":"127.0.0.1",
            "port":443,"uuid":id,"cipher":"auto","network":"grpc","grpc-opts":{}}]});
        if let Some(service) = service {
            value["proxies"][0]["grpc-opts"]["grpc-service-name"] = json!(service);
        }
        value
    }
}

#[test]
fn custom_and_default_grpc_service_survive_mobile_import_and_build() {
    let longest = "a".repeat(255);
    for service in [
        None,
        Some(""),
        Some("Prism.Vmess_Mobile"),
        Some(longest.as_str()),
    ] {
        for singbox in [false, true] {
            let imported = profile::import(&source(service, singbox).to_string()).unwrap();
            assert_eq!(imported.skipped, 0);
            assert_eq!(imported.nodes.len(), 1);
            let session: Session =
                serde_json::from_value(json!({"node":imported.nodes[0]})).unwrap();
            let (built, _) = profile::build(session).unwrap();
            assert_eq!(built.proxies[0].network.as_deref(), Some("grpc"));
            assert_eq!(
                built.proxies[0].grpc_service.as_deref().unwrap_or(""),
                service.unwrap_or("")
            );
        }
    }
}

#[test]
fn unsafe_service_names_and_other_protocol_grpc_are_not_mobile_supported() {
    let too_long = "a".repeat(256);
    for service in [
        "/service",
        "service/Tun",
        "bad name",
        "bad\r\nheader",
        "中文",
        "service?x=1",
        too_long.as_str(),
    ] {
        for singbox in [false, true] {
            let raw = source(Some(service), singbox);
            assert!(
                profile::import(&raw.to_string()).is_err(),
                "accepted {service:?}"
            );
        }
    }
    for kind in ["vless", "trojan", "socks5", "http"] {
        let mut raw = source(Some("SafeService"), false);
        raw["proxies"][0]["type"] = json!(kind);
        raw["proxies"][0]["password"] = json!("fixture-secret");
        assert!(
            profile::import(&raw.to_string()).is_err(),
            "opened gRPC for {kind}"
        );
    }
}
