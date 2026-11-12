//! Immutable, integrity-checked snapshots; missing categories never disable rules silently.
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    path::{Path, PathBuf},
};

pub const MAX_FILE: u64 = 32 * 1024 * 1024;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub snapshot: String,
    #[serde(rename = "geoipSha256")]
    pub ip_sha: String,
    #[serde(rename = "geositeSha256")]
    pub site_sha: String,
    #[serde(rename = "publishedAt")]
    pub published_at: String,
    #[serde(rename = "installedAt")]
    pub installed_at: String,
    pub tag: String,
}
impl Snapshot {
    pub fn directory(&self, home: &Path) -> Result<PathBuf> {
        ensure!(
            !self.snapshot.is_empty()
                && self.snapshot.len() <= 64
                && self
                    .snapshot
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "地区数据快照标识无效"
        );
        Ok(home.join("geo").join(&self.snapshot))
    }
    pub fn verify(&self, home: &Path) -> Result<PathBuf> {
        let dir = self.directory(home)?;
        for (file, expected) in [("geoip.dat", &self.ip_sha), ("geosite.dat", &self.site_sha)] {
            ensure!(
                expected.len() == 64 && expected.bytes().all(|b| b.is_ascii_hexdigit()),
                "地区数据摘要格式无效"
            );
            let path = dir.join(file);
            let metadata = std::fs::metadata(&path)
                .map_err(|_| anyhow::anyhow!("地区数据缺失，请重新下载"))?;
            ensure!(
                metadata.is_file() && metadata.len() > 0 && metadata.len() <= MAX_FILE,
                "地区数据大小无效"
            );
            let mut input = std::fs::File::open(path)?;
            let mut hash = Sha256::new();
            let mut buf = [0; 65536];
            let mut total = 0;
            loop {
                let n = input.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                total += n as u64;
                ensure!(total <= MAX_FILE, "地区数据过大");
                hash.update(&buf[..n]);
            }
            ensure!(
                format!("{:x}", hash.finalize()) == expected.to_ascii_lowercase(),
                "地区数据摘要不匹配，请重新下载"
            );
        }
        Ok(dir)
    }
    pub fn inspect(&self, home: &Path) -> Result<Value> {
        let dir = self.verify(home)?;
        let mut ip = prism_core::geo::codes(&dir.join("geoip.dat"))?;
        ip.sort();
        ip.dedup();
        let mut site = prism_core::geo::codes(&dir.join("geosite.dat"))?;
        site.sort();
        site.dedup();
        ensure!(
            !ip.is_empty() && !site.is_empty() && ip.len() <= 10000 && site.len() <= 10000,
            "地区数据格式无效或没有可用分类"
        );
        Ok(json!({"geoip":ip,"geosite":site,"snapshot":self.snapshot}))
    }
    pub fn validate_rules(
        &self,
        home: &Path,
        routing: &crate::routing::Routing,
    ) -> Result<PathBuf> {
        let dir = self.verify(home)?;
        let (ip, site) = routing.geo_codes();
        if !ip.is_empty() {
            let sets = prism_core::geo::load_geoip(&dir.join("geoip.dat"), &ip)?;
            for code in ip {
                ensure!(
                    sets.get(&code).is_some_and(|s| !s.is_empty()),
                    "GeoIP 分类不可用：{code}"
                );
            }
        }
        if !site.is_empty() {
            let sets = prism_core::geo::load_geosite(&dir.join("geosite.dat"), &site)?;
            for code in site {
                ensure!(
                    sets.get(&code).is_some_and(|s| !s.is_empty()),
                    "GeoSite 分类不可用：{code}"
                );
            }
        }
        Ok(dir)
    }
}
pub fn validate(
    home: &Path,
    snapshot: Option<&Snapshot>,
    routing: Option<&crate::routing::Routing>,
) -> Result<PathBuf> {
    let Some(routing) = routing else {
        return Ok(home.into());
    };
    let (ip, site) = routing.geo_codes();
    if ip.is_empty() && site.is_empty() {
        return Ok(home.into());
    }
    let snapshot =
        snapshot.ok_or_else(|| anyhow::anyhow!("请先下载并验证地区数据，再启用地区规则"))?;
    snapshot.validate_rules(home, routing)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bytes(field: u8, value: &[u8], out: &mut Vec<u8>) {
        out.push(field * 8 + 2);
        assert!(value.len() < 128);
        out.push(value.len() as u8);
        out.extend(value);
    }
    fn fixture() -> (PathBuf, Snapshot) {
        let home = std::env::temp_dir().join(format!("prism-mobile-geo-{}", std::process::id()));
        let dir = home.join("geo").join("test-snapshot");
        std::fs::create_dir_all(&dir).unwrap();
        let mut domain = vec![8, 2];
        bytes(2, b"region.test", &mut domain);
        let mut site = vec![];
        bytes(1, b"CN", &mut site);
        bytes(2, &domain, &mut site);
        let mut sites = vec![];
        bytes(1, &site, &mut sites);
        let mut cidr = vec![];
        bytes(1, &[203, 0, 113, 0], &mut cidr);
        cidr.extend([16, 24]);
        let mut ip = vec![];
        bytes(1, b"CN", &mut ip);
        bytes(2, &cidr, &mut ip);
        let mut ips = vec![];
        bytes(1, &ip, &mut ips);
        std::fs::write(dir.join("geoip.dat"), &ips).unwrap();
        std::fs::write(dir.join("geosite.dat"), &sites).unwrap();
        let snapshot = Snapshot {
            snapshot: "test-snapshot".into(),
            ip_sha: format!("{:x}", Sha256::digest(&ips)),
            site_sha: format!("{:x}", Sha256::digest(&sites)),
            published_at: "test".into(),
            installed_at: "test".into(),
            tag: "test".into(),
        };
        (home, snapshot)
    }
    #[test]
    fn snapshot_integrity_and_real_geo_matching_fail_closed() {
        let (home, snapshot) = fixture();
        assert_eq!(snapshot.inspect(&home).unwrap()["geoip"][0], "cn");
        let routing = crate::routing::Routing {
            version: 1,
            default_target: "SELECTED".into(),
            groups: vec![crate::routing::Group {
                name: "地区".into(),
                enabled: true,
                rules: crate::routing::Routing::import(
                    "GEOSITE,cn,DIRECT\nGEOIP,cn,REJECT,no-resolve",
                )
                .unwrap(),
            }],
        };
        let dir = validate(&home, Some(&snapshot), Some(&routing)).unwrap();
        let raw = format!(
            "proxies: [{{name: 手机节点, type: socks5, server: 127.0.0.1, port: 1080}}]\nrules: {}",
            serde_json::to_string(&routing.compile().unwrap()).unwrap()
        );
        let p = prism_core::config::parse_any(&raw).unwrap();
        let (router, warnings) =
            prism_core::rules::Router::build(&p.rules, &dir, &Default::default());
        assert!(warnings.is_empty());
        use prism_core::{
            common::Address,
            tunnel::{Metadata, Network},
        };
        let mut meta = Metadata::new(
            Network::Tcp,
            "Tun",
            "127.0.0.1:1234".parse().unwrap(),
            Address::Domain("a.region.test".into(), 443),
            None,
        );
        assert_eq!(router.test(&meta, None).target, "DIRECT");
        meta.dst = Address::new("203.0.113.4", 443);
        assert_eq!(router.test(&meta, None).target, "REJECT");
        assert!(validate(&home, None, Some(&routing)).is_err());
        let mut absent = routing.clone();
        absent.groups[0].rules[0].value = "not-present".into();
        assert!(validate(&home, Some(&snapshot), Some(&absent)).is_err());
        let mut bad = snapshot.clone();
        bad.snapshot = "../escape".into();
        assert!(bad.verify(&home).is_err());
        std::fs::write(dir.join("geosite.dat"), b"corrupt").unwrap();
        assert!(snapshot.verify(&home).is_err());
        std::fs::remove_dir_all(home).unwrap();
    }
}
