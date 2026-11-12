//! Bounded candidates and health checks for the mobile automatic selector.
use anyhow::{ensure, Result};
use prism_core::config::{GroupConfig, GroupKind, Profile, ProxyConfig};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const GROUP: &str = "手机节点";
pub const TEST_URL: &str = "https://1.1.1.1/";
fn interval() -> u64 {
    600
}
fn tolerance() -> u64 {
    100
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub id: String,
    pub node: ProxyConfig,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub candidates: Vec<Candidate>,
    #[serde(default = "interval", rename = "intervalSeconds")]
    pub interval: u64,
    #[serde(default = "tolerance", rename = "toleranceMs")]
    pub tolerance: u64,
}
pub fn name(id: &str) -> String {
    format!("候选.{id}")
}
impl Plan {
    pub fn reload_payload(raw: &str) -> Result<String> {
        let mut doc: serde_yaml::Value = serde_yaml::from_str(raw)?;
        if let Some(groups) = doc["proxy-groups"].as_sequence_mut() {
            for group in groups {
                if group["name"].as_str() == Some(GROUP) {
                    group["prism-health-initial-delay"] = 300.into();
                }
            }
        }
        Ok(serde_yaml::to_string(&doc)?)
    }
    pub fn snapshot(&self, hub: &prism_core::hub::Hub) -> serde_json::Value {
        let core = hub.core();
        let reg = &core.tunnel.reg;
        let current = reg
            .get(GROUP)
            .and_then(|g| g.as_group().map(|g| g.now()))
            .unwrap_or_default();
        let candidates:Vec<_>=self.candidates.iter().map(|c| {
            let last=reg.delays.history(&name(&c.id)).last().cloned();
            serde_json::json!({"id":c.id,"name":c.node.name,"selected":name(&c.id)==current,
                "delayMs":last.as_ref().map(|r|r.delay),"testedAt":last.map(|r|r.time.to_rfc3339())})
        }).collect();
        serde_json::json!({"enabled":true,"intervalSeconds":self.interval,"toleranceMs":self.tolerance,"candidates":candidates})
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (2..=16).contains(&self.candidates.len()),
            "自动优选须有 2–16 个候选节点"
        );
        ensure!(
            (300..=3600).contains(&self.interval),
            "自动优选间隔须为 300–3600 秒"
        );
        ensure!(self.tolerance <= 2000, "切换容差须为 0–2000 毫秒");
        let mut ids = HashSet::new();
        for c in &self.candidates {
            ensure!(
                !c.id.is_empty()
                    && c.id.len() <= 80
                    && c.id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
                    && ids.insert(&c.id),
                "候选节点 ID 无效或重复"
            );
            ensure!(
                crate::profile::supported(&c.node),
                "候选节点协议或证书配置不受支持"
            );
        }
        Ok(())
    }
    pub fn apply(&self, profile: &mut Profile) -> Result<()> {
        self.validate()?;
        profile.proxies = self
            .candidates
            .iter()
            .map(|c| ProxyConfig {
                name: name(&c.id),
                ..c.node.clone()
            })
            .collect();
        let mut group = GroupConfig::new(
            GROUP,
            GroupKind::UrlTest,
            self.candidates.iter().map(|c| name(&c.id)).collect(),
        );
        group.url = TEST_URL.into();
        group.interval = self.interval;
        group.tolerance = self.tolerance;
        profile.groups = vec![group];
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prism_core::{common::Address, config::ProxyKind, hub::Hub};
    use std::{
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Arc,
        },
        time::Duration,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    fn candidate(id: &str, port: u16) -> Candidate {
        Candidate {
            id: id.into(),
            node: ProxyConfig {
                name: id.into(),
                kind: Some(ProxyKind::Socks5),
                server: "127.0.0.1".into(),
                port,
                ..Default::default()
            },
        }
    }
    #[test]
    fn rejects_unbounded_or_unsafe_plans() {
        let good = Plan {
            candidates: vec![candidate("a", 10001), candidate("b", 10002)],
            interval: 600,
            tolerance: 100,
        };
        assert!(good.validate().is_ok());
        let mut bad = good.clone();
        bad.interval = 10;
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.candidates[1].id = "a".into();
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.candidates[1].node.skip_cert_verify = true;
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.candidates.resize(17, candidate("c", 10003));
        assert!(bad.validate().is_err());
        let mut bad = good;
        bad.candidates[0].id = "a,DIRECT".into();
        assert!(bad.validate().is_err());
    }
    struct Fixture {
        port: u16,
        fail: Arc<AtomicBool>,
        delay: Arc<AtomicU64>,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    async fn fixture(ms: u64) -> Fixture {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let fail = Arc::new(AtomicBool::new(false));
        let delay = Arc::new(AtomicU64::new(ms));
        let f = fail.clone();
        let d = delay.clone();
        let task = tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let f = f.clone();
                let d = d.clone();
                tokio::spawn(async move {
                    if f.load(Ordering::Relaxed) {
                        return;
                    }
                    let mut greet = [0; 3];
                    s.read_exact(&mut greet).await.unwrap();
                    s.write_all(&[5, 0]).await.unwrap();
                    let mut head = [0; 4];
                    s.read_exact(&mut head).await.unwrap();
                    assert_eq!(head, [5, 1, 0, 3]);
                    let n = s.read_u8().await.unwrap();
                    let mut host = vec![0; n as usize];
                    s.read_exact(&mut host).await.unwrap();
                    assert_eq!(host, b"health.test");
                    let _ = s.read_u16().await.unwrap();
                    s.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                        .await
                        .unwrap();
                    let mut request = Vec::new();
                    while !request.ends_with(b"\r\n\r\n") {
                        request.push(s.read_u8().await.unwrap());
                    }
                    tokio::time::sleep(Duration::from_millis(d.load(Ordering::Relaxed))).await;
                    let _ = s
                        .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                        .await;
                });
            }
        });
        Fixture {
            port,
            fail,
            delay,
            task,
        }
    }
    #[tokio::test]
    async fn actual_health_checks_switch_on_failure_respect_tolerance_and_never_choose_direct() {
        let a = fixture(40).await;
        let b = fixture(1).await;
        let plan = Plan {
            candidates: vec![candidate("a", a.port), candidate("b", b.port)],
            interval: 600,
            tolerance: 100,
        };
        let mut profile = Profile::default();
        plan.apply(&mut profile).unwrap();
        profile.groups[0].url = "http://health.test/generate_204".into();
        let hub = Hub::new(Default::default(), ".".into(), profile)
            .await
            .unwrap();
        let core = hub.core();
        let out = core.tunnel.reg.get(GROUP).unwrap();
        let group = out.as_group().unwrap();
        assert_eq!(group.now(), name("a"));
        group.health_check().await;
        assert_eq!(group.now(), name("a")); // 39ms difference is within 100ms tolerance
        a.fail.store(true, Ordering::Relaxed);
        group.health_check().await;
        assert_eq!(group.now(), name("b"));
        let (_, chain) = core
            .tunnel
            .reg
            .resolve(GROUP, &Address::Domain("payload.test".into(), 443))
            .unwrap();
        assert_eq!(chain, vec![GROUP.to_owned(), name("b")]);
        // Network rebuilding must preserve B while deferring repeated checks.
        let mut rebuilt_profile = Profile::default();
        plan.apply(&mut rebuilt_profile).unwrap();
        rebuilt_profile.groups[0].url = "http://health.test/generate_204".into();
        let raw =
            serde_yaml::to_string(&prism_core::config::clash::emit(&rebuilt_profile)).unwrap();
        let raw = Plan::reload_payload(&raw).unwrap();
        let parsed = prism_core::config::parse_any(&raw).unwrap();
        assert_eq!(parsed.groups[0].health_initial_delay, 300);
        hub.reload(Some(raw)).await.unwrap();
        let rebuilt = hub.core();
        let rebuilt_group = rebuilt.tunnel.reg.get(GROUP).unwrap();
        assert_eq!(rebuilt_group.as_group().unwrap().now(), name("b"));
        assert!(rebuilt.tunnel.reg.delays.history(&name("b")).is_empty());
        let core = rebuilt;
        let out = rebuilt_group;
        let group = out.as_group().unwrap();
        b.fail.store(true, Ordering::Relaxed);
        group.health_check().await;
        assert_eq!(group.now(), name("b"));
        assert_ne!(group.now(), "DIRECT");
        b.fail.store(false, Ordering::Relaxed);
        a.fail.store(false, Ordering::Relaxed);
        a.delay.store(1, Ordering::Relaxed);
        b.delay.store(180, Ordering::Relaxed);
        group.health_check().await;
        assert_eq!(group.now(), name("a"));
        core.shutdown.cancel();
    }
}
