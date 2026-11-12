//! Domain connection blocking. Exceptions fall through to ordinary mobile routing.
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
pub const CATEGORY: &str = "category-ads-all";
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub exceptions: Vec<String>,
}
impl Config {
    pub fn rule(&self) -> Result<Option<String>> {
        ensure!(self.exceptions.len() <= 100, "广告例外最多 100 个域名后缀");
        let mut exceptions = std::collections::BTreeSet::new();
        for value in &self.exceptions {
            let value = value.trim().to_ascii_lowercase();
            ensure!(
                !value.is_empty()
                    && value.len() <= 253
                    && value.split('.').all(|s| !s.is_empty()
                        && s.len() <= 63
                        && !s.starts_with('-')
                        && !s.ends_with('-')
                        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')),
                "广告例外须为 ASCII/punycode 域名后缀，不含通配符或路径"
            );
            exceptions.insert(value);
        }
        if !self.enabled {
            return Ok(None);
        }
        let payload = if exceptions.is_empty() {
            format!("((GEOSITE,{CATEGORY}))")
        } else {
            let any = format!(
                "({})",
                exceptions
                    .into_iter()
                    .map(|d| format!("(DOMAIN-SUFFIX,{d})"))
                    .collect::<Vec<_>>()
                    .join(",")
            );
            let not = format!("((OR,{any}))");
            format!("((GEOSITE,{CATEGORY}),(NOT,{not}))")
        };
        Ok(Some(format!("PRISM-ADS,{payload},REJECT")))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn real_router_exceptions_fall_through_and_tcp_udp_refusals_survive_reload() {
        use prism_core::{
            common::Address,
            config::RuleConfig,
            hub::Hub,
            tunnel::{Metadata, Network},
        };
        use std::sync::atomic::Ordering;
        fn bytes(field: u8, value: &[u8]) -> Vec<u8> {
            let mut out = vec![field * 8 + 2, value.len() as u8];
            out.extend(value);
            out
        }
        let home = std::env::temp_dir().join(format!("prism-adblock-test-{}", std::process::id()));
        std::fs::create_dir_all(&home).unwrap();
        let domain = [vec![8, 2], bytes(2, b"ads.test")].concat();
        let site = [bytes(1, CATEGORY.as_bytes()), bytes(2, &domain)].concat();
        std::fs::write(home.join("geosite.dat"), bytes(1, &site)).unwrap();
        let config = Config {
            enabled: true,
            exceptions: vec!["allowed.ads.test".into()],
        };
        let mut profile = prism_core::config::Profile::default();
        profile.general.find_process_mode = "off".into();
        profile.rules = vec![
            RuleConfig::parse(&config.rule().unwrap().unwrap()).unwrap(),
            RuleConfig::parse("DOMAIN-SUFFIX,allowed.ads.test,DIRECT").unwrap(),
            RuleConfig::parse("MATCH,REJECT").unwrap(),
        ];
        let raw = serde_yaml::to_string(&prism_core::config::clash::emit(&profile)).unwrap();
        let hub = Hub::new(Default::default(), home.clone(), profile)
            .await
            .unwrap();
        let core = hub.core();
        assert!(core.warnings.is_empty(), "{:?}", core.warnings);
        let meta = |host: &str, network| {
            Metadata::new(
                network,
                "AdTest",
                "127.0.0.1:1234".parse().unwrap(),
                Address::Domain(host.into(), 443),
                None,
            )
        };
        let hit = core
            .tunnel
            .router
            .test(&meta("x.allowed.ads.test", Network::Tcp), None);
        assert_eq!(hit.kind, "DOMAIN-SUFFIX");
        assert_eq!(hit.target, "DIRECT");
        assert_eq!(
            core.tunnel
                .router
                .test(&meta("ordinary.test", Network::Tcp), None)
                .target,
            "REJECT"
        );
        assert!(core
            .tunnel
            .dial(&mut meta("blocked.ads.test", Network::Tcp))
            .await
            .is_err());
        assert!(core
            .tunnel
            .dial_udp(&mut meta("blocked.ads.test", Network::Udp))
            .await
            .is_err());
        assert_eq!(core.tunnel.stats.ads_blocked.load(Ordering::Relaxed), 2);
        assert!(core.tunnel.stats.conns.lock().unwrap().is_empty());
        assert!(core.tunnel.stats.traffic.lock().unwrap().is_empty());
        hub.reload(Some(raw)).await.unwrap();
        let core = hub.core();
        assert_eq!(core.tunnel.stats.ads_blocked.load(Ordering::Relaxed), 2);
        assert!(core
            .tunnel
            .dial(&mut meta("blocked.ads.test", Network::Tcp))
            .await
            .is_err());
        assert_eq!(core.tunnel.stats.ads_blocked.load(Ordering::Relaxed), 3);
        core.shutdown.cancel();
        std::fs::remove_file(home.join("geosite.dat")).unwrap();
        std::fs::remove_dir(home).unwrap();
    }
    #[test]
    fn validates_even_disabled_exceptions_and_cannot_inject_rules() {
        for input in [
            "a.test,REJECT",
            "*.test",
            "https://a.test",
            "-bad.test",
            "a..test",
        ] {
            assert!(Config {
                enabled: false,
                exceptions: vec![input.into()]
            }
            .rule()
            .is_err());
        }
        let rule = Config {
            enabled: true,
            exceptions: vec!["Allowed.TEST".into(), "allowed.test".into()],
        }
        .rule()
        .unwrap()
        .unwrap();
        let parsed = prism_core::config::RuleConfig::parse(&rule).unwrap();
        assert_eq!(parsed.kind, "PRISM-ADS");
        assert_eq!(parsed.target, "REJECT");
        assert_eq!(
            prism_core::config::logical_parts(&parsed.payload)
                .unwrap()
                .len(),
            2
        );
    }
}
