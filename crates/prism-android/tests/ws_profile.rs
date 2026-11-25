use prism_android::profile::{self, Session};
use serde_json::json;

#[test]
fn websocket_parameters_survive_mobile_import_and_session_generation() {
    let id = "0b6a0b4e-1111-4222-8333-444455556666";
    let sources = [
        json!({"proxies":[{"name":"WS","type":"vmess","server":"127.0.0.1","port":443,
            "uuid":id,"cipher":"auto","network":"ws",
            "ws-opts":{"path":"/mobile?token=fixture","headers":{"Host":"vmess.fixture.test"}}}]}),
        json!({"outbounds":[{"tag":"WS","type":"vmess","server":"127.0.0.1","server_port":443,
            "uuid":id,"security":"auto","transport":{"type":"ws","path":"/mobile?token=fixture",
                "headers":{"Host":"vmess.fixture.test"}}}]}),
    ];
    for source in sources {
        let imported = profile::import(&source.to_string()).unwrap();
        assert_eq!(imported.skipped, 0);
        assert_eq!(imported.nodes.len(), 1);
        let session: Session = serde_json::from_value(json!({"node":imported.nodes[0]})).unwrap();
        let (built, _) = profile::build(session).unwrap();
        assert_eq!(built.proxies[0].network.as_deref(), Some("ws"));
        assert_eq!(
            built.proxies[0].ws_path.as_deref(),
            Some("/mobile?token=fixture")
        );
        assert_eq!(
            built.proxies[0].ws_host.as_deref(),
            Some("vmess.fixture.test")
        );
    }
}
