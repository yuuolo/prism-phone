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
fn test_url() -> String {
    TEST_URL.into()
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Policy {
    #[default]
    UrlTest,
    Fallback,
    LoadBalance,
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
    #[serde(default)]
    pub policy: Policy,
    #[serde(default = "test_url", rename = "testUrl")]
    pub test_url: String,
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
            let samples=reg.delays.history(&name(&c.id));
            let last=samples.last();
            let history:Vec<_>=samples.iter().map(|r|serde_json::json!({
                "atMs":r.time.timestamp_millis(),"delayMs":if r.delay==0 {None}else{Some(r.delay)},"success":r.delay!=0
            })).collect();
            serde_json::json!({"id":c.id,"name":c.node.name,"selected":name(&c.id)==current,
                "delayMs":last.map(|r|r.delay),"testedAt":last.map(|r|r.time.to_rfc3339()),"history":history})
        }).collect();
        let candidates = if self.policy == Policy::LoadBalance {
            candidates
                .into_iter()
                .map(|mut c| {
                    c["selected"] = false.into();
                    c
                })
                .collect()
        } else {
            candidates
        };
        serde_json::json!({"enabled":true,"policy":self.policy,"testUrl":self.test_url,"intervalSeconds":self.interval,"toleranceMs":self.tolerance,"candidates":candidates})
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.test_url.len() <= 2048
                && !self
                    .test_url
                    .bytes()
                    .any(|b| b.is_ascii_whitespace() || b.is_ascii_control()),
            "检测地址过长或包含空白字符"
        );
        let url =
            url::Url::parse(&self.test_url).map_err(|_| anyhow::anyhow!("检测地址格式无效"))?;
        ensure!(
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "检测地址须为不含账号、查询参数或片段的 HTTPS URL"
        );
        ensure!(
            url.port() != Some(0) && !matches!(url.host(), Some(url::Host::Ipv6(_))),
            "当前检测地址不支持零端口或 IPv6 目标"
        );
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
            match self.policy {
                Policy::UrlTest => GroupKind::UrlTest,
                Policy::Fallback => GroupKind::Fallback,
                Policy::LoadBalance => GroupKind::LoadBalance,
            },
            self.candidates.iter().map(|c| name(&c.id)).collect(),
        );
        group.url = self.test_url.clone();
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
            policy: Policy::UrlTest,
            test_url: test_url(),
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
    #[test]
    fn legacy_plan_defaults_and_explicit_https_probe_policy() {
        let old = serde_json::json!({"candidates":[candidate("a",12001),candidate("b",12002)],"intervalSeconds":600,"toleranceMs":100});
        let mut plan: Plan = serde_json::from_value(old.clone()).unwrap();
        assert_eq!(plan.policy, Policy::UrlTest);
        assert_eq!(plan.test_url, TEST_URL);
        plan.policy = Policy::Fallback;
        plan.test_url = "https://www.gstatic.com/generate_204".into();
        let mut p = Profile::default();
        plan.apply(&mut p).unwrap();
        assert_eq!(p.groups[0].kind, GroupKind::Fallback);
        assert_eq!(p.groups[0].url, plan.test_url);
        for bad in [
            "http://test.invalid/",
            "https://user:secret@test.invalid/",
            "https://test.invalid/?token=secret",
            "https://test.invalid/#fragment",
            "https://[::1]/",
            "https://test.invalid:0/",
            "https://test.invalid/\n",
        ] {
            plan.test_url = bad.into();
            assert!(plan.validate().is_err(), "bad test URL accepted");
        }
        let mut unknown = old;
        unknown["policy"] = "unknown".into();
        assert!(serde_json::from_value::<Plan>(unknown).is_err());
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
            policy: Policy::UrlTest,
            test_url: test_url(),
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
    #[tokio::test]
    async fn fallback_and_sticky_balance_forward_and_preserve_availability_on_network_rebuild() {
        for policy in [Policy::Fallback, Policy::LoadBalance] {
            let a = fixture(40).await;
            let b = fixture(1).await;
            let plan = Plan {
                candidates: vec![candidate("a", a.port), candidate("b", b.port)],
                policy,
                test_url: test_url(),
                interval: 600,
                tolerance: 0,
            };
            let mut p = Profile::default();
            plan.apply(&mut p).unwrap();
            // Only the loopback wire fixture uses HTTP; production plans require HTTPS.
            p.groups[0].url = "http://health.test/generate_204".into();
            p.groups[0].health_initial_delay = 300;
            let raw = serde_yaml::to_string(&prism_core::config::clash::emit(&p)).unwrap();
            let hub = Hub::new(Default::default(), ".".into(), p).await.unwrap();
            let core = hub.core();
            let group = core.tunnel.reg.get(GROUP).unwrap();
            group.as_group().unwrap().health_check().await;
            if policy == Policy::Fallback {
                assert_eq!(group.as_group().unwrap().now(), name("a"));
            }
            let mut exits = HashSet::new();
            for i in 0..32 {
                let target = Address::Domain(format!("payload{i}.test"), 80);
                let (_, chain) = core.tunnel.reg.resolve(GROUP, &target).unwrap();
                assert_eq!(chain, core.tunnel.reg.resolve(GROUP, &target).unwrap().1);
                exits.insert(chain.last().unwrap().clone());
            }
            assert_eq!(
                exits.len(),
                if policy == Policy::LoadBalance { 2 } else { 1 }
            );
            a.fail.store(true, Ordering::Relaxed);
            group.as_group().unwrap().health_check().await;
            let target = Address::Domain("health.test".into(), 80);
            assert_eq!(
                core.tunnel
                    .reg
                    .resolve(GROUP, &target)
                    .unwrap()
                    .1
                    .last()
                    .unwrap(),
                &name("b")
            );
            let mut stream = group.connect(&target).await.unwrap();
            stream
                .write_all(
                    b"GET /payload HTTP/1.1\r\nHost: health.test\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).await.unwrap();
            assert!(reply.starts_with(b"HTTP/1.1 204"));
            b.fail.store(true, Ordering::Relaxed);
            group.as_group().unwrap().health_check().await;
            let (_, chain) = core.tunnel.reg.resolve(GROUP, &target).unwrap();
            assert!(chain.last().unwrap().starts_with("候选."));
            assert!(group.connect(&target).await.is_err());
            b.fail.store(false, Ordering::Relaxed);
            group.as_group().unwrap().health_check().await;
            hub.reload(Some(raw.clone())).await.unwrap();
            let rebuilt = hub.core();
            assert!(rebuilt.tunnel.reg.delays.history(&name("a")).is_empty());
            assert_eq!(
                rebuilt
                    .tunnel
                    .reg
                    .resolve(GROUP, &target)
                    .unwrap()
                    .1
                    .last()
                    .unwrap(),
                &name("b")
            );
            assert_eq!(
                rebuilt.tunnel.reg.delays.known_alive(&name("a")),
                Some(false)
            );
            // Repeated rebuilds keep availability but never fabricate a delay sample.
            hub.reload(Some(raw.clone())).await.unwrap();
            assert_eq!(
                hub.core().tunnel.reg.delays.known_alive(&name("a")),
                Some(false)
            );
            let mut changed = prism_core::config::parse_any(&raw).unwrap();
            changed.proxies[0].port = 12099;
            let changed =
                serde_yaml::to_string(&prism_core::config::clash::emit(&changed)).unwrap();
            hub.reload(Some(changed)).await.unwrap();
            assert_eq!(hub.core().tunnel.reg.delays.known_alive(&name("a")), None);
            hub.core().shutdown.cancel();
        }
    }
}
