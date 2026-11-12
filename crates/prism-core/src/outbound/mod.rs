//! Outbounds: concrete protocols plus proxy groups, all addressed by name
//! through the [`Registry`].

pub mod anytls;
pub mod basic;
pub mod ctls;
pub mod dialer;
pub mod group;
pub mod hysteria2;
pub mod shadowsocks;
pub mod ss2022;
pub mod tls;
pub mod transport;
pub mod trojan;
pub mod tuic;
pub mod vision;
pub mod vless;
pub mod vmess;
pub mod wireguard;

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;

use crate::common::{Address, BoxedStream, UdpPipe};
use crate::config::{ProxyConfig, ProxyKind};
use crate::delay::DelayStore;

pub use dialer::Dialer;
pub use group::ProxyGroup;

#[async_trait]
pub trait Outbound: Send + Sync {
    fn name(&self) -> &str;
    /// Type name for the Clash REST API (Shadowsocks, Trojan, Selector, ...).
    fn api_type(&self) -> &'static str;
    /// Whether [`Outbound::connect_udp`] is supported.
    fn udp(&self) -> bool {
        false
    }
    async fn connect(&self, target: &Address) -> io::Result<BoxedStream>;
    /// Opens a UDP session to `target` (one destination per session).
    async fn connect_udp(&self, _target: &Address) -> io::Result<UdpPipe> {
        Err(io::Error::new(io::ErrorKind::Unsupported, format!("{} does not support UDP", self.name())))
    }
    fn as_group(&self) -> Option<&ProxyGroup> {
        None
    }
}

/// All outbounds of a running config, in profile order.
pub struct Registry {
    pub map: HashMap<String, Arc<dyn Outbound>>,
    pub order: Vec<String>,
    pub delays: Arc<DelayStore>,
    /// mihomo's unified-delay: URL tests time only a warm second request.
    pub unified_delay: bool,
    /// Configs of the protocol outbounds, for rebuilding them as relay hops.
    pub configs: HashMap<String, ProxyConfig>,
}

impl Registry {
    pub fn get(&self, name: &str) -> Option<Arc<dyn Outbound>> {
        self.map.get(name).cloned()
    }

    /// Follows group selections down to a concrete outbound. Returns the
    /// outbound plus the chain of names, rule target first.
    pub fn resolve(&self, name: &str, target: &Address) -> io::Result<(Arc<dyn Outbound>, Vec<String>)> {
        let mut out = self.get(name).ok_or_else(|| crate::common::other(format!("unknown proxy {name}")))?;
        let mut chain = vec![name.to_string()];
        for _ in 0..16 {
            // A relay group dials its chain itself.
            let Some(next) = out.as_group().filter(|g| g.kind() != crate::config::GroupKind::Relay).map(|g| g.pick(target)) else {
                break;
            };
            let next = next.ok_or_else(|| crate::common::other(format!("group {} has no usable member", out.name())))?;
            chain.push(next.name().to_string());
            out = next;
        }
        Ok((out, chain))
    }
}

/// Lazily-filled handle the groups use to look up their members (groups are
/// constructed before the registry that contains them).
pub type RegistryCell = Arc<OnceLock<Arc<Registry>>>;

/// Builds a protocol outbound that reaches its server through `dialer`.
/// Errors mean "unsupported by prism-core".
pub fn build_proxy(p: &ProxyConfig, dialer: Dialer) -> anyhow::Result<Arc<dyn Outbound>> {
    let transports = matches!(p.kind(), ProxyKind::Vless | ProxyKind::Trojan | ProxyKind::Vmess);
    if !transports && p.network.as_deref().is_some_and(|n| n != "tcp") {
        anyhow::bail!("{}: transport {} is not supported by prism-core", p.name, p.network.as_deref().unwrap());
    }
    Ok(match p.kind() {
        ProxyKind::AnyTls => Arc::new(anytls::AnyTls::new(p, dialer)?),
        ProxyKind::Shadowsocks if ss2022::is_2022(p.cipher.as_deref().unwrap_or("")) => Arc::new(ss2022::Ss2022::new(p, dialer)?),
        ProxyKind::Shadowsocks => Arc::new(shadowsocks::Shadowsocks::new(p, dialer)?),
        ProxyKind::Trojan => Arc::new(trojan::Trojan::new(p, dialer)?),
        ProxyKind::Vless => Arc::new(vless::Vless::new(p, dialer)?),
        ProxyKind::Socks5 => Arc::new(basic::Socks5::new(p, dialer)?),
        ProxyKind::Http => Arc::new(basic::Http::new(p, dialer)?),
        ProxyKind::Hysteria2 => Arc::new(hysteria2::Hysteria2::new(p, dialer)?),
        ProxyKind::Tuic => Arc::new(tuic::Tuic::new(p, dialer)?),
        ProxyKind::WireGuard => Arc::new(wireguard::WireGuard::new(p, dialer)?),
        ProxyKind::Vmess => Arc::new(vmess::Vmess::new(p, dialer)?),
    })
}
