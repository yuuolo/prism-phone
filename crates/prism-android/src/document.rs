//! Non-activating full Clash document editing. Keep the source separately from
//! the overwritten result; never sanitize away invalid routing references.
use anyhow::{bail, ensure, Result};
use prism_core::config::{self, Profile};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub version: u32,
    pub name: String,
    pub source: String,
    #[serde(default)]
    pub script: String,
}

/// An editor preview, deliberately not a runnable mobile session. Provider
/// resolution, platform policy and runtime validation still precede activation.
pub struct Preview {
    pub json: String,
    pub profile: Profile,
}

impl Document {
    pub fn preview(&self) -> Result<Preview> {
        ensure!(self.version == 1, "不支持的配置文档版本");
        ensure!(
            self.source.len() <= crate::script::MAX_CONFIG,
            "配置超过大小限制"
        );
        ensure!(
            self.name.len() <= 256 && !self.name.trim().is_empty(),
            "配置名称无效"
        );
        // JSON is a YAML subset. Conversion rejects non-string mapping keys.
        let root: Value = serde_yaml::from_str(&self.source)
            .map_err(|_| anyhow::anyhow!("配置须为有效的 Clash YAML/JSON"))?;
        ensure!(root.is_object(), "配置须为对象");
        ensure!(
            root.get("outbounds").is_none() && root.get("inbounds").is_none(),
            "此编辑通道目前仅接受 Clash 配置"
        );
        let input = serde_json::to_string(&root)?;
        let json = crate::script::apply(&input, &self.script, &self.name)?;
        let edited: Value = serde_json::from_str(&json)?;
        shape(&edited)?;
        let yaml = serde_yaml::to_value(&edited)?;
        let profile = config::clash::parse(&yaml).map_err(|_| anyhow::anyhow!("配置字段无效"))?;
        // Parser warnings can mean discarded nodes/rules or a changed group type.
        // Do not expose their text because it can contain subscription secrets.
        ensure!(
            profile.warnings.is_empty(),
            "配置包含无法完整解析的节点、组或规则"
        );
        references(&profile)?;
        Ok(Preview { json, profile })
    }
}

fn shape(root: &Value) -> Result<()> {
    ensure!(root.is_object(), "覆写结果须为配置对象");
    ensure!(
        root.get("outbounds").is_none() && root.get("inbounds").is_none(),
        "覆写不能改变配置格式"
    );
    for key in ["proxies", "proxy-groups"] {
        if let Some(value) = root.get(key) {
            let items = value
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("节点和组须为数组"))?;
            ensure!(
                items.len() <= 4096 && items.iter().all(Value::is_object),
                "节点或组格式无效或数量过多"
            );
        }
    }
    if let Some(value) = root.get("rules") {
        let items = value
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("规则须为数组"))?;
        ensure!(
            items.len() <= 65536 && items.iter().all(Value::is_string),
            "规则格式无效或数量过多"
        );
    }
    for key in ["proxy-providers", "rule-providers"] {
        if let Some(value) = root.get(key) {
            let items = value
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("providers 须为对象"))?;
            ensure!(
                items.len() <= 4096 && items.values().all(Value::is_object),
                "provider 格式无效或数量过多"
            );
        }
    }
    if let Some(groups) = root.get("proxy-groups").and_then(Value::as_array) {
        for group in groups {
            for key in ["proxies", "use"] {
                if let Some(v) = group.get(key) {
                    ensure!(
                        v.as_array()
                            .is_some_and(|a| a.len() <= 4096 && a.iter().all(Value::is_string)),
                        "组成员须为字符串数组"
                    );
                }
            }
        }
    }
    Ok(())
}

fn references(p: &Profile) -> Result<()> {
    let mut names: HashSet<&str> = config::BUILTIN.iter().copied().collect();
    for name in p
        .proxies
        .iter()
        .map(|n| n.name.as_str())
        .chain(p.groups.iter().map(|g| g.name.as_str()))
    {
        ensure!(
            !name.trim().is_empty() && names.insert(name),
            "节点/组名称为空、重复或占用保留名称"
        );
    }
    let providers: HashSet<_> = p.proxy_providers.iter().map(|x| x.name.as_str()).collect();
    let rule_providers: HashSet<_> = p.rule_providers.iter().map(|x| x.name.as_str()).collect();
    for g in &p.groups {
        ensure!(
            !g.proxies.is_empty() || !g.use_providers.is_empty(),
            "代理组不能为空"
        );
        ensure!(
            g.proxies.iter().all(|n| names.contains(n.as_str())),
            "代理组引用不存在的节点或组"
        );
        ensure!(
            g.use_providers
                .iter()
                .all(|n| providers.contains(n.as_str())),
            "代理组引用不存在的 provider"
        );
    }
    for r in &p.rules {
        ensure!(names.contains(r.target.as_str()), "规则目标不存在");
        if r.kind == "RULE-SET" {
            ensure!(
                rule_providers.contains(r.payload.as_str()),
                "规则引用不存在的规则集"
            );
        }
    }
    // Iterative topological traversal bounds stack usage for user-controlled
    // deeply nested groups, and catches indirect cycles as well as self-loops.
    let indices: HashMap<_, _> = p
        .groups
        .iter()
        .enumerate()
        .map(|(i, g)| (g.name.as_str(), i))
        .collect();
    let mut degree = vec![0usize; p.groups.len()];
    let mut edges = vec![Vec::new(); p.groups.len()];
    for (i, g) in p.groups.iter().enumerate() {
        for member in &g.proxies {
            if let Some(&j) = indices.get(member.as_str()) {
                edges[i].push(j);
                degree[j] += 1;
            }
        }
    }
    let mut ready: Vec<_> = degree
        .iter()
        .enumerate()
        .filter_map(|(i, &n)| (n == 0).then_some(i))
        .collect();
    let mut visited = 0;
    while let Some(i) = ready.pop() {
        visited += 1;
        for &j in &edges[i] {
            degree[j] -= 1;
            if degree[j] == 0 {
                ready.push(j);
            }
        }
    }
    if visited != p.groups.len() {
        bail!("代理组存在循环引用");
    }
    Ok(())
}
