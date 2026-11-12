//! Bounded mobile connection snapshots; no controller listener or credentials.
use anyhow::{ensure, Result};
use prism_core::tunnel::Stats;
use serde::{Deserialize, Serialize};
use std::sync::atomic::Ordering;

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Query {
    pub search: String,
    pub network: String,
    pub route: String,
    pub sort: String,
    pub offset: usize,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Row {
    pub id: String,
    pub destination: String,
    pub network: String,
    pub rule: String,
    pub rule_payload: String,
    pub chains: Vec<String>,
    pub upload: u64,
    pub download: u64,
    pub started_at: i64,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Page {
    pub session_id: String,
    pub total: usize,
    pub matched: usize,
    pub offset: usize,
    pub connections: Vec<Row>,
}
impl Query {
    pub fn parse(raw: &str) -> Result<Self> {
        ensure!(raw.len() <= 4096, "连接查询过长");
        let q: Self = serde_json::from_str(raw)?;
        ensure!(q.search.chars().count() <= 200, "搜索最多 200 字符");
        ensure!(
            matches!(q.network.as_str(), "" | "tcp" | "udp"),
            "无效网络筛选"
        );
        ensure!(
            matches!(q.route.as_str(), "" | "direct" | "proxy"),
            "无效出口筛选"
        );
        ensure!(
            matches!(q.sort.as_str(), "" | "newest" | "traffic" | "destination"),
            "无效排序"
        );
        Ok(q)
    }
    fn page(&self, mut rows: Vec<Row>, session_id: String) -> Page {
        let total = rows.len();
        let search = self.search.trim().to_lowercase();
        rows.retain(|r| {
            let direct = r.chains.first().is_some_and(|c| c == "DIRECT");
            (self.network.is_empty() || self.network == r.network)
                && (self.route.is_empty() || (self.route == "direct") == direct)
                && (search.is_empty()
                    || [&r.destination, &r.rule, &r.rule_payload]
                        .iter()
                        .any(|s| s.to_lowercase().contains(&search))
                    || r.chains.iter().any(|s| s.to_lowercase().contains(&search)))
        });
        rows.sort_by(|a, b| {
            match self.sort.as_str() {
                "traffic" => b
                    .upload
                    .saturating_add(b.download)
                    .cmp(&a.upload.saturating_add(a.download)),
                "destination" => a.destination.cmp(&b.destination),
                _ => b.started_at.cmp(&a.started_at),
            }
            .then_with(|| a.id.cmp(&b.id))
        });
        let matched = rows.len();
        let offset = self.offset.min(matched.saturating_sub(1) / 50 * 50);
        Page {
            session_id,
            total,
            matched,
            offset,
            connections: rows.into_iter().skip(offset).take(50).collect(),
        }
    }
    pub fn snapshot(&self, stats: &Stats, session_id: String) -> Page {
        // Clone handles under the lock; formatting and sorting do not block relays.
        let conns: Vec<_> = stats
            .conns
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .cloned()
            .collect();
        let rows = conns
            .iter()
            .map(|c| Row {
                id: c.id.clone(),
                destination: c.meta.dst.to_string(),
                network: c.meta.network.as_str().into(),
                rule: c.rule.clone(),
                rule_payload: c.rule_payload.clone(),
                chains: c.chains.clone(),
                upload: c.upload.load(Ordering::Relaxed),
                download: c.download.load(Ordering::Relaxed),
                started_at: c.start.timestamp_millis(),
            })
            .collect();
        self.page(rows, session_id)
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Close {
    pub session_id: String,
    pub id: String,
}
#[cfg(test)]
mod tests {
    use super::*;
    fn row(i: usize) -> Row {
        Row {
            id: format!("{i:03}"),
            destination: format!("site-{i}.example:443"),
            network: if i % 2 == 0 { "tcp" } else { "udp" }.into(),
            rule: "DomainSuffix".into(),
            rule_payload: "example".into(),
            chains: vec![if i % 3 == 0 { "DIRECT" } else { "手机节点" }.into()],
            upload: i as u64,
            download: i as u64,
            started_at: i as i64,
        }
    }
    #[test]
    fn filters_searches_and_sorts_row_fields() {
        let q = Query::parse(
            r#"{"network":"tcp","route":"proxy","search":"EXAMPLE","sort":"traffic"}"#,
        )
        .unwrap();
        let p = q.page((0..12).map(row).collect(), "s".into());
        assert_eq!(p.total, 12);
        assert_eq!(p.matched, 4);
        assert_eq!(
            p.connections
                .iter()
                .map(|r| r.id.as_str())
                .collect::<Vec<_>>(),
            vec!["010", "008", "004", "002"]
        );
        let q = Query::parse(r#"{"search":"手机节点"}"#).unwrap();
        assert_eq!(q.page((0..12).map(row).collect(), "s".into()).matched, 8);
    }
    #[test]
    fn bounds_pages_and_recovers_after_connections_disappear() {
        let q = Query::parse(r#"{"offset":50}"#).unwrap();
        let p = q.page((0..120).map(row).collect(), "s".into());
        assert_eq!(p.connections.len(), 50);
        assert_eq!(p.connections[0].id, "069");
        let p = q.page(vec![row(1)], "s".into());
        assert_eq!(p.offset, 0);
        assert_eq!(p.connections.len(), 1);
        assert!(q.page(vec![], "s".into()).connections.is_empty());
    }
    #[test]
    fn rejects_unsupported_and_unbounded_queries() {
        assert!(Query::parse(r#"{"network":"icmp"}"#).is_err());
        assert!(Query::parse(r#"{"sort":"password"}"#).is_err());
        assert!(Query::parse(r#"{"limit":99999}"#).is_err());
        assert!(Query::parse(&serde_json::json!({"search":"x".repeat(201)}).to_string()).is_err());
    }
}
