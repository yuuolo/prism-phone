//! Recovery uses the same Hub reload path as the Windows network monitor.
use std::sync::Arc;
use prism_core::{config, hub::{Hub, Source}};

#[tokio::test]
async fn repeated_recovery_preserves_routing_and_fakeip_but_replaces_sessions() {
    let dir = std::env::temp_dir().join(format!("prism-recovery-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.yaml");
    let raw = "proxies:\n  - {name: local, type: socks5, server: 127.0.0.1, port: 9}\nproxy-groups:\n  - {name: 节点选择, type: select, proxies: [DIRECT, local]}\nrules: ['MATCH,节点选择']\ndns:\n  enable: true\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n  nameserver: [127.0.0.1]\n";
    std::fs::write(&path, raw).unwrap();
    let hub = Hub::new(Source { path: Some(path.clone()), ..Default::default() }, dir.clone(), config::parse_any(raw).unwrap()).await.unwrap();
    let original = hub.core();
    original.tunnel.reg.get("节点选择").unwrap().as_group().unwrap().select("local").unwrap();
    *original.tunnel.mode.write().unwrap() = config::Mode::Global;
    for _ in 0..20 {
        hub.reload(None).await.unwrap();
        let current = hub.core();
        assert!(!Arc::ptr_eq(&original.tunnel.reg, &current.tunnel.reg));
        assert!(Arc::ptr_eq(&original.tunnel.stats, &current.tunnel.stats));
        assert!(Arc::ptr_eq(original.dns.as_ref().unwrap().fake.as_ref().unwrap(), current.dns.as_ref().unwrap().fake.as_ref().unwrap()));
        assert_eq!(current.tunnel.reg.get("节点选择").unwrap().as_group().unwrap().now(), "local");
        assert_eq!(current.tunnel.mode(), config::Mode::Global);
    }
    let working = hub.core();
    std::fs::write(&path, "not a valid config").unwrap();
    assert!(hub.reload(None).await.is_err());
    assert!(Arc::ptr_eq(&working, &hub.core()), "failed recovery must retain the working core");
    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}
