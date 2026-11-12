//! proxy-providers and rule-providers: loading (download / cache file /
//! inline), periodic refresh and info for the Clash API.
//!
//! http providers are cached in a file (`path`, default
//! `./proxy_providers/<name>.yaml` or `./rule_providers/<name>.yaml` under the
//! home dir). The file is downloaded when missing or older than `interval`;
//! when a download fails the old file is used. While the core runs, http
//! providers are refreshed every `interval` and a changed file triggers a
//! hot reload.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, bail, Result};
use chrono::{DateTime, Utc};

use crate::config::{ProxyProviderConfig, RuleProviderConfig};
use crate::outbound::Outbound;

pub const USER_AGENT: &str = "clash.meta";
const TIMEOUT: Duration = Duration::from_secs(30);

pub struct ProxyProviderInfo {
    pub cfg: ProxyProviderConfig,
    pub path: Option<PathBuf>,
    /// Node names (as registered) in provider order.
    pub proxies: Vec<String>,
    pub updated_at: Option<DateTime<Utc>>,
}

pub struct RuleProviderInfo {
    pub cfg: RuleProviderConfig,
    pub path: Option<PathBuf>,
    pub count: usize,
    pub updated_at: Option<DateTime<Utc>>,
}

pub fn vehicle(kind: &str) -> &'static str {
    match kind {
        "file" => "File",
        "inline" => "Inline",
        _ => "HTTP",
    }
}

pub fn path_for(home: &Path, dir: &str, name: &str, path: &Option<String>) -> PathBuf {
    match path {
        Some(p) => home.join(p),
        None => home.join(dir).join(format!("{name}.yaml")),
    }
}

fn modified(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

pub fn updated_at(path: &Path) -> Option<DateTime<Utc>> {
    modified(path).map(DateTime::<Utc>::from)
}

/// Downloads `url` into `path`; returns whether the content changed.
pub async fn fetch_to_file(url: &str, path: &Path, via: Option<&Arc<dyn Outbound>>) -> Result<bool> {
    let resp = crate::http::get(url, via, USER_AGENT, TIMEOUT).await?;
    if resp.status != 200 {
        bail!("{url}: HTTP {}", resp.status);
    }
    if resp.body.is_empty() {
        bail!("{url}: empty response");
    }
    let old = std::fs::read(path).ok();
    if old.as_deref() == Some(&resp.body[..]) {
        // Touch so the age check sees a fresh file.
        let _ = std::fs::File::options().write(true).open(path).and_then(|f| f.set_modified(SystemTime::now()));
        return Ok(false);
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("download");
    std::fs::write(&tmp, &resp.body)?;
    std::fs::rename(&tmp, path)?;
    Ok(true)
}

/// Provider content: the cached / local file, downloading http providers
/// first when the file is missing or older than `interval` seconds.
/// Returns the content and an optional warning.
pub async fn load(kind: &str, url: Option<&str>, path: &Path, interval: u64) -> Result<(String, Option<String>)> {
    let (bytes, warn) = load_bytes(kind, url, path, interval).await?;
    Ok((String::from_utf8_lossy(&bytes).into_owned(), warn))
}

/// [`load`] for binary content (mrs rule-sets).
pub async fn load_bytes(kind: &str, url: Option<&str>, path: &Path, interval: u64) -> Result<(Vec<u8>, Option<String>)> {
    if kind == "http" {
        let url = url.ok_or_else(|| anyhow!("http provider without url"))?;
        let stale = match modified(path) {
            None => true,
            Some(t) => interval > 0 && t.elapsed().map(|a| a.as_secs() > interval).unwrap_or(true),
        };
        if stale {
            if let Err(e) = fetch_to_file(url, path, None).await {
                if !path.exists() {
                    return Err(e);
                }
                let content = std::fs::read(path)?;
                return Ok((content, Some(format!("download failed, using cached file: {e:#}"))));
            }
        }
    } else if kind != "file" {
        bail!("unsupported provider type {kind}");
    }
    let content = std::fs::read(path).map_err(|e| anyhow!("read {}: {e}", path.display()))?;
    Ok((content, None))
}

/// Entries of a rule provider in `yaml` (`payload:` list), `text` or `mrs`
/// (mihomo binary; its behavior must be the provider's).
pub fn rule_entries(format: &str, behavior: &str, content: &[u8]) -> Result<Vec<String>> {
    if format == "mrs" {
        let (b, entries) = crate::mrs::decode(content)?;
        if !behavior.eq_ignore_ascii_case(&b) {
            bail!("mrs file holds a {b} rule-set, but the provider's behavior is {behavior}");
        }
        // mrs stores `+.x` for subdomains only (the apex is its own entry):
        // that is `.x` in rule-set syntax.
        return Ok(entries.into_iter().map(|e| match e.strip_prefix("+.") {
            Some(rest) => format!(".{rest}"),
            None => e,
        }).collect());
    }
    let content = String::from_utf8_lossy(content);
    match format {
        "text" => Ok(content
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("//"))
            .map(String::from)
            .collect()),
        "yaml" | "" => {
            let v: serde_yaml::Value = serde_yaml::from_str(&content)?;
            let payload = v.get("payload").and_then(|p| p.as_sequence()).ok_or_else(|| anyhow!("no payload list"))?;
            Ok(payload.iter().filter_map(|x| x.as_str().map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).collect())
        }
        other => bail!("rule provider format {other} is not supported (use yaml, text or mrs)"),
    }
}

/// Refreshes an http provider every `interval` seconds until `stop`;
/// `on_change` runs when the downloaded content differs.
pub fn spawn_refresh(
    url: String,
    path: PathBuf,
    interval: u64,
    via: Option<Arc<dyn Outbound>>,
    stop: tokio_util::sync::CancellationToken,
    on_change: impl Fn() + Send + 'static,
) {
    if interval == 0 {
        return;
    }
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = stop.cancelled() => return,
                _ = tokio::time::sleep(Duration::from_secs(interval.max(60))) => {}
            }
            match fetch_to_file(&url, &path, via.as_ref()).await {
                Ok(true) => {
                    tracing::info!("provider {} updated", path.display());
                    on_change();
                }
                Ok(false) => {}
                Err(e) => tracing::warn!("provider {} refresh failed: {e:#}", path.display()),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_formats() {
        let y = "payload:\n  - '+.google.com'\n  - 'example.org'\n";
        assert_eq!(rule_entries("yaml", "domain", y.as_bytes()).unwrap(), ["+.google.com", "example.org"]);
        let t = "# comment\n1.0.0.0/8\n\n2.0.0.0/8\n";
        assert_eq!(rule_entries("text", "ipcidr", t.as_bytes()).unwrap(), ["1.0.0.0/8", "2.0.0.0/8"]);
        assert!(rule_entries("mrs", "domain", b"").is_err());
        assert!(rule_entries("json", "domain", b"").is_err());
    }
}
