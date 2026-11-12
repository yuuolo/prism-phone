//! Proxy groups: select, url-test, fallback, load-balance and relay.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use async_trait::async_trait;

use super::{Dialer, Outbound, RegistryCell};
use crate::common::{other, Address, BoxedStream, UdpPipe};
use crate::config::{GroupConfig, GroupKind};

pub struct ProxyGroup {
    pub cfg: GroupConfig,
    selected: RwLock<String>,
    reg: RegistryCell,
    /// Relay: the last chain built, keyed by its hop names.
    chain: Mutex<Option<(Vec<String>, Arc<dyn Outbound>)>>,
}

impl ProxyGroup {
    pub fn new(cfg: GroupConfig, reg: RegistryCell) -> Self {
        let first = cfg.proxies.first().cloned().unwrap_or_else(|| "DIRECT".into());
        ProxyGroup { cfg, selected: RwLock::new(first), reg, chain: Mutex::new(None) }
    }

    pub fn kind(&self) -> GroupKind {
        self.cfg.kind
    }

    pub fn members(&self) -> &[String] {
        &self.cfg.proxies
    }

    fn alive(&self, name: &str) -> bool {
        self.reg.get().map(|r| r.delays.alive(name)).unwrap_or(true)
    }

    /// The member currently in use (what the Clash API reports as `now`).
    pub fn now(&self) -> String {
        match self.cfg.kind {
            GroupKind::Select | GroupKind::UrlTest => self.selected.read().unwrap().clone(),
            GroupKind::Relay => self.cfg.proxies.last().cloned().unwrap_or_default(),
            GroupKind::Fallback | GroupKind::LoadBalance => self
                .cfg
                .proxies
                .iter()
                .find(|p| self.alive(p))
                .or(self.cfg.proxies.first())
                .cloned()
                .unwrap_or_default(),
        }
    }

    pub fn select(&self, name: &str) -> Result<(), String> {
        if self.cfg.kind != GroupKind::Select {
            return Err(format!("{} is not a selector group", self.cfg.name));
        }
        if !self.cfg.proxies.iter().any(|p| p == name) {
            return Err(format!("{name} is not a member of {}", self.cfg.name));
        }
        *self.selected.write().unwrap() = name.to_string();
        Ok(())
    }

    pub fn pick(&self, target: &Address) -> Option<Arc<dyn Outbound>> {
        let reg = self.reg.get()?;
        let name = match self.cfg.kind {
            GroupKind::LoadBalance => {
                // Sticky per destination host so sites keep one exit IP.
                let alive: Vec<&String> = self.cfg.proxies.iter().filter(|p| self.alive(p)).collect();
                let pool: Vec<&String> = if alive.is_empty() { self.cfg.proxies.iter().collect() } else { alive };
                let mut h = DefaultHasher::new();
                target.host().hash(&mut h);
                pool.get((h.finish() as usize) % pool.len().max(1))?.to_string()
            }
            _ => self.now(),
        };
        reg.get(&name)
    }

    /// Relay: the members resolved to nodes, the last one rebuilt to dial
    /// through the ones before it (each hop keeps its own way of reaching
    /// its server only if it is the first).
    fn relay(&self, target: &Address) -> io::Result<Arc<dyn Outbound>> {
        let reg = self.reg.get().ok_or_else(|| other("registry not ready"))?;
        let mut hops = Vec::new();
        for m in &self.cfg.proxies {
            let (o, _) = reg.resolve(m, target)?;
            match o.name() {
                "DIRECT" => continue,
                "REJECT" => return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "rejected by relay hop")),
                _ => hops.push(o),
            }
        }
        if hops.len() <= 1 {
            return Ok(hops.pop().unwrap_or_else(|| Arc::new(super::basic::Direct)));
        }
        let names: Vec<String> = hops.iter().map(|h| h.name().to_string()).collect();
        if let Some((n, o)) = self.chain.lock().unwrap().as_ref() {
            if *n == names {
                return Ok(o.clone());
            }
        }
        let mut dialer = Dialer::Via(hops[0].clone());
        let mut last = hops[0].clone();
        for name in &names[1..] {
            let cfg = reg.configs.get(name).ok_or_else(|| other(format!("relay {}: {name} can't be a later hop", self.cfg.name)))?;
            last = super::build_proxy(cfg, dialer).map_err(|e| other(e.to_string()))?;
            dialer = Dialer::Via(last.clone());
        }
        *self.chain.lock().unwrap() = Some((names, last.clone()));
        Ok(last)
    }

    /// Tests every member and, for url-test, switches to the fastest one when
    /// it beats the current member by more than `tolerance`.
    pub async fn health_check(&self) {
        let Some(reg) = self.reg.get().cloned() else { return };
        let timeout = Duration::from_secs(5);
        let tests = self.cfg.proxies.iter().map(|m| {
            let reg = reg.clone();
            let url = self.cfg.url.clone();
            async move { (m.clone(), crate::delay::url_test(&reg, m, &url, timeout).await.ok()) }
        });
        let results = futures::future::join_all(tests).await;
        if self.cfg.kind == GroupKind::UrlTest {
            let best = results.iter().filter_map(|(n, d)| d.map(|d| (n, d))).min_by_key(|(_, d)| *d);
            if let Some((best, best_delay)) = best {
                let cur = self.now();
                let cur_delay = results.iter().find(|(n, _)| *n == cur).and_then(|(_, d)| *d);
                let switch = match cur_delay {
                    Some(cd) => (cd as u64) > best_delay as u64 + self.cfg.tolerance,
                    None => true,
                };
                if switch && *best != cur {
                    tracing::info!("[{}] switched to {best} ({best_delay}ms)", self.cfg.name);
                    *self.selected.write().unwrap() = best.clone();
                }
            }
        }
    }

    /// Periodic health checks for automatic groups, until `stop`.
    pub fn spawn_health_loop(self: Arc<Self>, stop: tokio_util::sync::CancellationToken) {
        if matches!(self.cfg.kind, GroupKind::Select | GroupKind::Relay) {
            return;
        }
        tokio::spawn(async move {
            // Give the core a moment to finish starting.
            let mut wait = Duration::from_secs(1);
            loop {
                tokio::select! {
                    _ = stop.cancelled() => return,
                    _ = tokio::time::sleep(wait) => {}
                }
                tokio::select! {
                    _ = stop.cancelled() => return,
                    _ = self.health_check() => {}
                }
                wait = Duration::from_secs(self.cfg.interval.max(10));
            }
        });
    }
}

#[async_trait]
impl Outbound for ProxyGroup {
    fn name(&self) -> &str {
        &self.cfg.name
    }
    fn api_type(&self) -> &'static str {
        self.cfg.kind.api_type()
    }
    fn udp(&self) -> bool {
        true
    }
    async fn connect(&self, target: &Address) -> io::Result<BoxedStream> {
        if self.cfg.kind == GroupKind::Relay {
            return self.relay(target)?.connect(target).await;
        }
        let reg = self.reg.get().ok_or_else(|| other("registry not ready"))?;
        let (out, _) = reg.resolve(&self.cfg.name, target)?;
        out.connect(target).await
    }
    async fn connect_udp(&self, target: &Address) -> io::Result<UdpPipe> {
        if self.cfg.kind == GroupKind::Relay {
            return self.relay(target)?.connect_udp(target).await;
        }
        let reg = self.reg.get().ok_or_else(|| other("registry not ready"))?;
        let (out, _) = reg.resolve(&self.cfg.name, target)?;
        out.connect_udp(target).await
    }
    fn as_group(&self) -> Option<&ProxyGroup> {
        Some(self)
    }
}
