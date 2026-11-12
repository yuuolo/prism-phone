//! Routes inbound connections to outbounds and relays traffic, keeping the
//! per-connection statistics exposed by the Clash API.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use crate::common::{Address, BoxedStream, ProxyStream, UdpPipe};
use crate::config::Mode;
use crate::outbound::Registry;
use crate::rules::Router;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Network {
    #[default]
    Tcp,
    Udp,
}

impl Network {
    pub fn as_str(self) -> &'static str {
        match self {
            Network::Tcp => "tcp",
            Network::Udp => "udp",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Metadata {
    pub network: Network,
    /// Inbound protocol: HTTP, HTTPS (CONNECT), Socks5 or Tun.
    pub inbound: &'static str,
    pub src: SocketAddr,
    pub dst: Address,
    /// Resolved destination IP (only when an IP rule needed it).
    pub dst_ip: Option<IpAddr>,
    /// Program that opened the connection (looked up on demand).
    pub process: Option<Arc<crate::process::ProcessInfo>>,
    pub process_checked: bool,
}

impl Metadata {
    pub fn new(network: Network, inbound: &'static str, src: SocketAddr, dst: Address, dst_ip: Option<IpAddr>) -> Self {
        Metadata { network, inbound, src, dst, dst_ip, process: None, process_checked: false }
    }

    /// Finds the owning process once (blocking table lookup off the runtime).
    pub async fn lookup_process(&mut self) {
        if self.process_checked {
            return;
        }
        self.process_checked = true;
        let (network, src) = (self.network, self.src);
        self.process = tokio::task::spawn_blocking(move || crate::process::find(network, src)).await.ok().flatten();
    }

    /// `src` with the process name, mihomo style: `127.0.0.1:5000(chrome.exe)`.
    pub fn source(&self) -> String {
        match &self.process {
            Some(p) => format!("{}({})", self.src, p.name),
            None => self.src.to_string(),
        }
    }
}

/// When to look up the process of a connection (`find-process-mode`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum FindProcess {
    /// Every connection (shown in /connections).
    Always,
    /// Only when a PROCESS-* rule is evaluated.
    #[default]
    Strict,
    Off,
}

impl FindProcess {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "always" => FindProcess::Always,
            "off" => FindProcess::Off,
            _ => FindProcess::Strict,
        }
    }
}

pub struct Conn {
    pub id: String,
    pub meta: Metadata,
    pub chains: Vec<String>,
    pub rule: String,
    pub rule_payload: String,
    pub start: DateTime<Utc>,
    pub upload: AtomicU64,
    pub download: AtomicU64,
    cancel: CancellationToken,
}

#[derive(Default)]
pub struct Stats {
    pub upload: AtomicU64,
    pub download: AtomicU64,
    pub conns: Mutex<HashMap<String, Arc<Conn>>>,
}

impl Stats {
    pub fn snapshot(&self) -> Vec<Arc<Conn>> {
        let mut v: Vec<_> = self.conns.lock().unwrap().values().cloned().collect();
        v.sort_by_key(|c| c.start);
        v
    }

    pub fn close(&self, id: &str) -> bool {
        match self.conns.lock().unwrap().get(id) {
            Some(c) => {
                c.cancel.cancel();
                true
            }
            None => false,
        }
    }

    pub fn close_all(&self) {
        for c in self.conns.lock().unwrap().values() {
            c.cancel.cancel();
        }
    }
}

pub struct Dialed {
    pub stream: BoxedStream,
    pub chains: Vec<String>,
    pub rule: String,
    pub rule_payload: String,
}

pub struct DialedUdp {
    pub pipe: UdpPipe,
    pub chains: Vec<String>,
    pub rule: String,
    pub rule_payload: String,
}

pub struct Tunnel {
    pub reg: Arc<Registry>,
    pub router: Router,
    pub mode: RwLock<Mode>,
    pub stats: Arc<Stats>,
    pub dns: Option<Arc<crate::dns::Resolver>>,
    pub find_process: FindProcess,
    pub block_ipv6: bool,
    pub tailscale_bypass: bool,
}

impl Tunnel {
    pub fn mode(&self) -> Mode {
        *self.mode.read().unwrap()
    }

    /// A destination that is a fake-ip handed out by our DNS is replaced by
    /// the domain it stands for. A fake-ip that came along with a sniffed
    /// domain (TUN) is dropped too: it is not the server's address, and IP
    /// rules (198.18.0.0/15 is "private" in common rule sets) must not see it.
    pub fn restore_fake_ip(&self, meta: &mut Metadata) {
        let Some(dns) = &self.dns else { return };
        if meta.dst_ip.is_some_and(|ip| dns.is_fake(ip)) {
            meta.dst_ip = None;
        }
        let Address::Ip(sa) = &meta.dst else { return };
        if !dns.is_fake(sa.ip()) {
            return;
        }
        if let Some(domain) = dns.fake_domain(sa.ip()) {
            meta.dst = Address::Domain(domain, sa.port());
            meta.dst_ip = None;
        }
    }

    /// Picks the outbound name for a connection: (target, rule, payload).
    async fn target(&self, meta: &mut Metadata) -> (String, String, String) {
        self.restore_fake_ip(meta);
        if self.tailscale_bypass && (meta.dst.ip().is_some_and(crate::net::is_tailnet_ip) || meta.dst_ip.is_some_and(crate::net::is_tailnet_ip)
            || meta.dst.domain().is_some_and(|d| d.ends_with(".ts.net"))) {
            return ("DIRECT".into(), "Tailscale".into(), "tailnet".into());
        }
        if self.block_ipv6 && (meta.dst.ip().is_some_and(|ip| ip.is_ipv6()) || meta.dst_ip.is_some_and(|ip| ip.is_ipv6())) {
            return ("REJECT".into(), "IPv6Blocked".into(), "::/0".into());
        }
        match self.find_process {
            FindProcess::Always => meta.lookup_process().await,
            FindProcess::Off => meta.process_checked = true,
            FindProcess::Strict => {}
        }
        match self.mode() {
            Mode::Direct => ("DIRECT".to_string(), "Direct".to_string(), String::new()),
            Mode::Global => ("GLOBAL".to_string(), "Global".to_string(), String::new()),
            Mode::Rule => match self.router.route(meta).await {
                Some(r) => (r.target.clone(), r.display(), r.payload.clone()),
                None => ("DIRECT".to_string(), "Match".to_string(), String::new()),
            },
        }
    }

    pub async fn dial_udp(&self, meta: &mut Metadata) -> io::Result<DialedUdp> {
        let (target, rule, payload) = self.target(meta).await;
        let (out, chain) = self.reg.resolve(&target, &meta.dst).map_err(|e| {
            tracing::warn!("异常拒绝: {} --> {} match {rule} using {target}: {e}", meta.source(), meta.dst);
            e
        })?;
        let shown = if chain.len() > 1 { format!("{target}[{}]", chain.last().unwrap()) } else { target.clone() };
        let res = tokio::time::timeout(Duration::from_secs(10), out.connect_udp(&meta.dst)).await;
        let pipe = match res {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => {
                tracing::warn!("[UDP] {} --> {} match {rule} using {shown} failed: {e}", meta.source(), meta.dst);
                return Err(e);
            }
            Err(_) => {
                tracing::warn!("[UDP] {} --> {} match {rule} using {shown} failed: timeout", meta.source(), meta.dst);
                return Err(io::Error::new(io::ErrorKind::TimedOut, "dial timeout"));
            }
        };
        tracing::info!("[UDP] {} --> {} match {rule} using {shown}", meta.source(), meta.dst);
        let mut chains = chain;
        chains.reverse();
        Ok(DialedUdp { pipe, chains, rule, rule_payload: payload })
    }

    fn register(&self, meta: Metadata, chains: Vec<String>, rule: String, rule_payload: String) -> Arc<Conn> {
        let conn = Arc::new(Conn {
            id: uuid::Uuid::new_v4().to_string(),
            meta,
            chains,
            rule,
            rule_payload,
            start: Utc::now(),
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
            cancel: CancellationToken::new(),
        });
        self.stats.conns.lock().unwrap().insert(conn.id.clone(), conn.clone());
        conn
    }

    pub async fn dial(&self, meta: &mut Metadata) -> io::Result<Dialed> {
        let (target, rule, payload) = self.target(meta).await;
        let (out, chain) = self.reg.resolve(&target, &meta.dst).map_err(|e| {
            tracing::warn!("异常拒绝: {} --> {} match {rule} using {target}: {e}", meta.source(), meta.dst);
            e
        })?;
        let shown = if chain.len() > 1 { format!("{target}[{}]", chain.last().unwrap()) } else { target.clone() };
        let res = tokio::time::timeout(Duration::from_secs(10), out.connect(&meta.dst)).await;
        let stream = match res {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                tracing::warn!("[TCP] {} --> {} match {rule} using {shown} failed: {e}", meta.source(), meta.dst);
                return Err(e);
            }
            Err(_) => {
                tracing::warn!("[TCP] {} --> {} match {rule} using {shown} failed: timeout", meta.source(), meta.dst);
                return Err(io::Error::new(io::ErrorKind::TimedOut, "dial timeout"));
            }
        };
        tracing::info!("[TCP] {} --> {} match {rule} using {shown}", meta.source(), meta.dst);
        let mut chains = chain;
        chains.reverse(); // leaf first, like mihomo
        Ok(Dialed { stream, chains, rule, rule_payload: payload })
    }

    /// Relays until both directions finish or the connection is closed via API.
    pub async fn relay<C: ProxyStream>(&self, client: C, dialed: Dialed, meta: Metadata, initial: &[u8]) {
        let conn = self.register(meta, dialed.chains, dialed.rule, dialed.rule_payload);

        let (cr, cw) = tokio::io::split(client);
        let (rr, mut rw) = tokio::io::split(dialed.stream);
        let stats = self.stats.clone();
        let work = async {
            if !initial.is_empty() {
                rw.write_all(initial).await?;
                rw.flush().await?;
                conn.upload.fetch_add(initial.len() as u64, Ordering::Relaxed);
                stats.upload.fetch_add(initial.len() as u64, Ordering::Relaxed);
            }
            tokio::try_join!(
                copy_count(cr, rw, &conn.upload, &stats.upload),
                copy_count(rr, cw, &conn.download, &stats.download),
            )
        };
        tokio::select! {
            r = work => {
                if let Err(e) = r {
                    tracing::debug!("relay {}: {e}", conn.meta.dst);
                }
            }
            _ = conn.cancel.cancelled() => {}
        }
        self.stats.conns.lock().unwrap().remove(&conn.id);
    }
}

async fn copy_count<R, W>(mut r: R, mut w: W, conn: &AtomicU64, total: &AtomicU64) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            let _ = w.shutdown().await;
            return Ok(());
        }
        w.write_all(&buf[..n]).await?;
        w.flush().await?;
        conn.fetch_add(n as u64, Ordering::Relaxed);
        total.fetch_add(n as u64, Ordering::Relaxed);
    }
}

/// A datagram between a client and a destination, as seen by the inbound.
pub struct UdpPacket {
    /// The client.
    pub src: SocketAddr,
    /// The destination the client addressed (replies appear to come from it).
    pub dst: Address,
    pub data: Vec<u8>,
}

struct UdpSession {
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
}

/// UDP session table for one inbound: one outbound session per
/// (client, destination). Replies go to `reply`, tagged with the client and
/// the destination address the client used.
pub struct UdpNat {
    inbound: &'static str,
    sessions: Mutex<HashMap<(SocketAddr, Address), Arc<UdpSession>>>,
    reply: tokio::sync::mpsc::Sender<UdpPacket>,
}

impl UdpNat {
    pub fn new(inbound: &'static str, reply: tokio::sync::mpsc::Sender<UdpPacket>) -> Arc<Self> {
        Arc::new(UdpNat { inbound, sessions: Mutex::new(HashMap::new()), reply })
    }

    /// Sends a client datagram, opening a session (routed through `tunnel`)
    /// on first use.
    pub fn send(self: &Arc<Self>, tunnel: &Arc<Tunnel>, pkt: UdpPacket) {
        let key = (pkt.src, pkt.dst.clone());
        let existing = self.sessions.lock().unwrap().get(&key).cloned();
        if let Some(s) = existing {
            let _ = s.tx.try_send(pkt.data);
            return;
        }
        let (tx, rx) = tokio::sync::mpsc::channel(256);
        let session = Arc::new(UdpSession { tx });
        let _ = session.tx.try_send(pkt.data);
        self.sessions.lock().unwrap().insert(key.clone(), session.clone());
        let nat = self.clone();
        let tunnel = tunnel.clone();
        tokio::spawn(async move {
            nat.run_session(tunnel, key.0, key.1.clone(), rx).await;
            let mut map = nat.sessions.lock().unwrap();
            if map.get(&key).is_some_and(|s| Arc::ptr_eq(s, &session)) {
                map.remove(&key);
            }
        });
    }

    async fn run_session(&self, tunnel: Arc<Tunnel>, src: SocketAddr, dst: Address, mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>) {
        let mut meta = Metadata::new(Network::Udp, self.inbound, src, dst.clone(), dst.ip());
        let Ok(dialed) = tunnel.dial_udp(&mut meta).await else { return };
        let conn = tunnel.register(meta, dialed.chains, dialed.rule, dialed.rule_payload);
        let UdpPipe { tx: out, rx: mut inc } = dialed.pipe;
        let stats = tunnel.stats.clone();
        // DNS sessions are short-lived; everything else idles out after 60s.
        let idle = Duration::from_secs(if dst.port() == 53 { 10 } else { 60 });
        loop {
            tokio::select! {
                p = rx.recv() => match p {
                    Some(p) => {
                        conn.upload.fetch_add(p.len() as u64, Ordering::Relaxed);
                        stats.upload.fetch_add(p.len() as u64, Ordering::Relaxed);
                        if out.send(p).await.is_err() { break; }
                    }
                    None => break,
                },
                p = inc.recv() => match p {
                    Some(p) => {
                        conn.download.fetch_add(p.len() as u64, Ordering::Relaxed);
                        stats.download.fetch_add(p.len() as u64, Ordering::Relaxed);
                        if self.reply.send(UdpPacket { src, dst: dst.clone(), data: p }).await.is_err() { break; }
                    }
                    None => break,
                },
                _ = tokio::time::sleep(idle) => break,
                _ = conn.cancel.cancelled() => break,
            }
        }
        tunnel.stats.conns.lock().unwrap().remove(&conn.id);
    }
}
