//! WireGuard client (one peer), as a userspace network: boringtun does the
//! Noise handshake and packet encryption, smoltcp turns proxied TCP
//! connections and UDP sessions into IP packets inside the tunnel.
//!
//! One device task per outbound owns the tunnel, the TCP/IP stack and all
//! sockets; connections talk to it over channels. Destinations are resolved
//! outside the tunnel. `reserved` (Cloudflare WARP) goes into bytes 1-3 of
//! every WireGuard message.

use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use boringtun::noise::{Tunn, TunnResult};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::{tcp, udp};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, Notify};

use super::dialer::{DgRecv, DgSend};
use super::{Dialer, Outbound};
use crate::common::{other, pump, udp_pump, Address, BoxedStream, UdpPipe};
use crate::config::ProxyConfig;

const TCP_BUF: usize = 256 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

fn key32(what: &str, s: Option<&str>) -> anyhow::Result<[u8; 32]> {
    let s = s.filter(|s| !s.is_empty()).ok_or_else(|| anyhow::anyhow!("missing {what}"))?;
    let b = super::super::config::uri::b64_decode(s).ok_or_else(|| anyhow::anyhow!("{what} is not base64"))?;
    b.try_into().map_err(|_| anyhow::anyhow!("{what} must be 32 bytes"))
}

/// `10.0.0.2`, `10.0.0.2/32` -> the address.
fn addr_of(s: &Option<String>) -> Option<IpAddr> {
    s.as_deref()?.split('/').next()?.trim().parse().ok()
}

struct Keys {
    private: [u8; 32],
    public: [u8; 32],
    psk: Option<[u8; 32]>,
}

pub struct WireGuard {
    name: String,
    server: String,
    port: u16,
    keys: Arc<Keys>,
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
    mtu: usize,
    reserved: Option<[u8; 3]>,
    dialer: Dialer,
    device: tokio::sync::Mutex<Option<Handle>>,
}

impl WireGuard {
    pub fn new(p: &ProxyConfig, dialer: Dialer) -> anyhow::Result<Self> {
        let err = |e: anyhow::Error| anyhow::anyhow!("{}: {e}", p.name);
        let keys = Keys {
            private: key32("private-key", p.private_key.as_deref()).map_err(err)?,
            public: key32("public-key", p.public_key.as_deref()).map_err(err)?,
            psk: match p.pre_shared_key.as_deref() {
                Some(k) if !k.is_empty() => Some(key32("pre-shared-key", Some(k)).map_err(err)?),
                _ => None,
            },
        };
        let (mut v4, mut v6) = (None, None);
        for a in [addr_of(&p.ip), addr_of(&p.ipv6)].into_iter().flatten() {
            match a {
                IpAddr::V4(a) => v4 = Some(a),
                IpAddr::V6(a) => v6 = Some(a),
            }
        }
        if v4.is_none() && v6.is_none() {
            anyhow::bail!("{}: WireGuard needs ip / ipv6 (the tunnel address)", p.name);
        }
        let reserved = match p.reserved.len() {
            0 => None,
            3 => Some([p.reserved[0], p.reserved[1], p.reserved[2]]),
            _ => anyhow::bail!("{}: reserved must be 3 bytes", p.name),
        };
        Ok(WireGuard {
            name: p.name.clone(),
            server: p.server.clone(),
            port: p.port,
            keys: Arc::new(keys),
            v4,
            v6,
            mtu: p.mtu.map(|m| m as usize).unwrap_or(1408).clamp(576, 9000),
            reserved,
            dialer,
            device: tokio::sync::Mutex::new(None),
        })
    }

    async fn handle(&self) -> io::Result<Handle> {
        let mut g = self.device.lock().await;
        if let Some(h) = g.as_ref() {
            if !h.cmds.is_closed() {
                return Ok(h.clone());
            }
        }
        let (send, recv) = self.dialer.udp(&self.server, self.port).await?.split();
        let tunn = Tunn::new(
            boringtun::x25519::StaticSecret::from(self.keys.private),
            boringtun::x25519::PublicKey::from(self.keys.public),
            self.keys.psk,
            Some(25),
            rand::random::<u32>() >> 8,
            None,
        );
        let (cmds, rx) = mpsc::channel(64);
        let h = Handle { cmds, wake: Arc::new(Notify::new()) };
        let dev = DeviceTask::new(tunn, self.v4, self.v6, self.mtu, self.reserved, h.wake.clone());
        let name = self.name.clone();
        tokio::spawn(async move {
            if let Err(e) = dev.run(rx, send, recv).await {
                tracing::debug!("wireguard {name}: {e}");
            }
        });
        *g = Some(h.clone());
        Ok(h)
    }

    /// The tunnel-side address for `target`.
    async fn resolve(&self, target: &Address) -> io::Result<SocketAddr> {
        let mut addrs = crate::net::resolve(&target.host(), target.port()).await?;
        addrs.sort_by_key(|a| a.is_ipv6());
        addrs
            .iter()
            .find(|a| (a.is_ipv4() && self.v4.is_some()) || (a.is_ipv6() && self.v6.is_some()))
            .copied()
            .ok_or_else(|| other(format!("{}: no tunnel address for the IP family of {target}", self.name)))
    }
}

#[derive(Clone)]
struct Handle {
    cmds: mpsc::Sender<Cmd>,
    wake: Arc<Notify>,
}

/// Channels between a connection and the device task.
struct Pipe {
    to_net: mpsc::Receiver<Vec<u8>>,
    from_net: mpsc::Sender<Vec<u8>>,
}

struct UserEnd {
    to_net: mpsc::Sender<Vec<u8>>,
    from_net: mpsc::Receiver<Vec<u8>>,
}

fn pipe_pair() -> (Pipe, UserEnd) {
    let (a, b) = mpsc::channel(64);
    let (c, d) = mpsc::channel(64);
    (Pipe { to_net: b, from_net: c }, UserEnd { to_net: a, from_net: d })
}

enum Cmd {
    Tcp(SocketAddr, Pipe, oneshot::Sender<io::Result<()>>),
    Udp(SocketAddr, Pipe),
}

#[async_trait]
impl Outbound for WireGuard {
    fn name(&self) -> &str {
        &self.name
    }
    fn api_type(&self) -> &'static str {
        "WireGuard"
    }
    fn udp(&self) -> bool {
        true
    }

    async fn connect(&self, target: &Address) -> io::Result<BoxedStream> {
        let dst = self.resolve(target).await?;
        let h = self.handle().await?;
        let (pipe, user) = pipe_pair();
        let (tx, rx) = oneshot::channel();
        h.cmds.send(Cmd::Tcp(dst, pipe, tx)).await.map_err(|_| other("wireguard: device stopped"))?;
        rx.await.map_err(|_| other("wireguard: device stopped"))??;
        let wake = h.wake;
        Ok(pump(move |inner| async move {
            let (mut rd, mut wr) = tokio::io::split(inner);
            let UserEnd { to_net, mut from_net } = user;
            let w = wake.clone();
            let up = async move {
                let mut buf = vec![0u8; 32 * 1024];
                loop {
                    let n = rd.read(&mut buf).await?;
                    if n == 0 || to_net.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                    w.notify_one();
                }
                drop(to_net);
                w.notify_one();
                Ok::<_, io::Error>(())
            };
            let down = async move {
                while let Some(d) = from_net.recv().await {
                    wake.notify_one();
                    wr.write_all(&d).await?;
                }
                wr.shutdown().await
            };
            tokio::try_join!(up, down)?;
            Ok(())
        }))
    }

    async fn connect_udp(&self, target: &Address) -> io::Result<UdpPipe> {
        let dst = self.resolve(target).await?;
        let h = self.handle().await?;
        let (pipe, user) = pipe_pair();
        h.cmds.send(Cmd::Udp(dst, pipe)).await.map_err(|_| other("wireguard: device stopped"))?;
        let wake = h.wake;
        Ok(udp_pump(move |mut out, inc| async move {
            let UserEnd { to_net, mut from_net } = user;
            loop {
                tokio::select! {
                    p = out.recv() => match p {
                        Some(p) => {
                            if to_net.send(p).await.is_err() {
                                return Ok(());
                            }
                            wake.notify_one();
                        }
                        None => break,
                    },
                    d = from_net.recv() => match d {
                        Some(d) => {
                            if inc.send(d).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    },
                }
            }
            drop(to_net);
            wake.notify_one();
            Ok(())
        }))
    }
}

// ------------------------------------------------------------ device

/// IP packets between smoltcp and the tunnel.
struct Queues {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

struct RxTok(Vec<u8>);
struct TxTok<'a>(&'a mut VecDeque<Vec<u8>>);

impl phy::RxToken for RxTok {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl phy::TxToken for TxTok<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut b = vec![0u8; len];
        let r = f(&mut b);
        self.0.push_back(b);
        r
    }
}

impl Device for Queues {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok<'a>;

    fn receive(&mut self, _: smoltcp::time::Instant) -> Option<(RxTok, TxTok<'_>)> {
        let p = self.rx.pop_front()?;
        Some((RxTok(p), TxTok(&mut self.tx)))
    }

    fn transmit(&mut self, _: smoltcp::time::Instant) -> Option<TxTok<'_>> {
        Some(TxTok(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = self.mtu;
        c
    }
}

struct TcpConn {
    handle: SocketHandle,
    pipe: Pipe,
    reply: Option<oneshot::Sender<io::Result<()>>>,
    started: std::time::Instant,
    pending: Vec<u8>,
    sent: usize,
    user_done: bool,
    fin: bool,
    eof: bool,
}

struct UdpConn {
    handle: SocketHandle,
    dst: SocketAddr,
    pipe: Pipe,
}

struct DeviceTask {
    tunn: Tunn,
    iface: Interface,
    dev: Queues,
    sockets: SocketSet<'static>,
    tcp: Vec<TcpConn>,
    udp: Vec<UdpConn>,
    reserved: Option<[u8; 3]>,
    wake: Arc<Notify>,
    next_port: u16,
    clock: std::time::Instant,
}

fn now(clock: std::time::Instant) -> smoltcp::time::Instant {
    smoltcp::time::Instant::from_micros(clock.elapsed().as_micros() as i64)
}

impl DeviceTask {
    fn new(tunn: Tunn, v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr>, mtu: usize, reserved: Option<[u8; 3]>, wake: Arc<Notify>) -> Self {
        // smoltcp cuts IPv4 fragments at the MTU, and fragment payloads must
        // be multiples of 8 bytes, or receivers drop them.
        let mtu = 20 + (mtu - 20) / 8 * 8;
        let mut dev = Queues { rx: VecDeque::new(), tx: VecDeque::new(), mtu };
        let clock = std::time::Instant::now();
        let mut iface = Interface::new(IfaceConfig::new(HardwareAddress::Ip), &mut dev, now(clock));
        iface.update_ip_addrs(|a| {
            if let Some(v4) = v4 {
                let _ = a.push(IpCidr::new(IpAddress::Ipv4(v4), 32));
            }
            if let Some(v6) = v6 {
                let _ = a.push(IpCidr::new(IpAddress::Ipv6(v6), 128));
            }
        });
        // Everything goes into the tunnel; with an IP medium the gateway is
        // only a placeholder.
        if let Some(v4) = v4 {
            let _ = iface.routes_mut().add_default_ipv4_route(v4);
        }
        if let Some(v6) = v6 {
            let _ = iface.routes_mut().add_default_ipv6_route(v6);
        }
        DeviceTask {
            tunn,
            iface,
            dev,
            sockets: SocketSet::new(Vec::new()),
            tcp: Vec::new(),
            udp: Vec::new(),
            reserved,
            wake,
            next_port: 49152 + rand::random::<u16>() % 16000,
            clock,
        }
    }

    fn port(&mut self) -> u16 {
        self.next_port = if self.next_port >= 65000 { 49152 } else { self.next_port + 1 };
        self.next_port
    }

    fn add(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Tcp(dst, pipe, reply) => {
                let mut s = tcp::Socket::new(tcp::SocketBuffer::new(vec![0; TCP_BUF]), tcp::SocketBuffer::new(vec![0; TCP_BUF]));
                s.set_nagle_enabled(false);
                s.set_keep_alive(Some(smoltcp::time::Duration::from_secs(30)));
                s.set_timeout(Some(smoltcp::time::Duration::from_secs(120)));
                let port = self.port();
                if let Err(e) = s.connect(self.iface.context(), IpEndpoint::from(dst), port) {
                    let _ = reply.send(Err(other(format!("wireguard: connect: {e}"))));
                    return;
                }
                let handle = self.sockets.add(s);
                self.tcp.push(TcpConn {
                    handle,
                    pipe,
                    reply: Some(reply),
                    started: std::time::Instant::now(),
                    pending: Vec::new(),
                    sent: 0,
                    user_done: false,
                    fin: false,
                    eof: false,
                });
            }
            Cmd::Udp(dst, pipe) => {
                let meta = || vec![udp::PacketMetadata::EMPTY; 64];
                let mut s = udp::Socket::new(udp::PacketBuffer::new(meta(), vec![0; 256 * 1024]), udp::PacketBuffer::new(meta(), vec![0; 256 * 1024]));
                if s.bind(self.port()).is_err() {
                    return;
                }
                let handle = self.sockets.add(s);
                self.udp.push(UdpConn { handle, dst, pipe });
            }
        }
    }

    /// Moves data between the connections' channels and their sockets, and
    /// drops finished connections.
    fn shuttle(&mut self) {
        let sockets = &mut self.sockets;
        self.tcp.retain_mut(|c| {
            let s = sockets.get_mut::<tcp::Socket>(c.handle);
            if c.reply.is_some() {
                match s.state() {
                    tcp::State::Established => {
                        let _ = c.reply.take().unwrap().send(Ok(()));
                    }
                    tcp::State::Closed => {
                        let _ = c.reply.take().unwrap().send(Err(io::Error::new(io::ErrorKind::ConnectionRefused, "wireguard: connection refused")));
                        sockets.remove(c.handle);
                        return false;
                    }
                    _ if c.started.elapsed() > CONNECT_TIMEOUT => {
                        let _ = c.reply.take().unwrap().send(Err(io::Error::new(io::ErrorKind::TimedOut, "wireguard: connect timed out")));
                        s.abort();
                        sockets.remove(c.handle);
                        return false;
                    }
                    _ => return true,
                }
            }
            // user -> tunnel
            loop {
                if c.sent == c.pending.len() {
                    c.pending.clear();
                    c.sent = 0;
                    if c.user_done {
                        break;
                    }
                    match c.pipe.to_net.try_recv() {
                        Ok(d) => c.pending = d,
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            c.user_done = true;
                            break;
                        }
                    }
                }
                if !s.can_send() {
                    break;
                }
                match s.send_slice(&c.pending[c.sent..]) {
                    Ok(n) => c.sent += n,
                    Err(_) => break,
                }
            }
            if c.user_done && c.pending.is_empty() && !c.fin {
                s.close();
                c.fin = true;
            }
            // tunnel -> user
            while !c.eof && s.can_recv() {
                let Ok(permit) = c.pipe.from_net.try_reserve() else { break };
                let mut b = vec![0u8; 64 * 1024];
                match s.recv_slice(&mut b) {
                    Ok(n) => {
                        b.truncate(n);
                        permit.send(b);
                    }
                    Err(_) => break,
                }
            }
            if !c.eof && !s.may_recv() && !s.can_recv() {
                // Remote finished: drop our sender so the user sees EOF.
                c.eof = true;
                let (dead, _) = mpsc::channel(1);
                c.pipe.from_net = dead;
            }
            if c.pipe.from_net.is_closed() && !c.eof {
                // The user went away without reading to the end.
                s.abort();
            }
            if matches!(s.state(), tcp::State::Closed | tcp::State::TimeWait) {
                sockets.remove(c.handle);
                return false;
            }
            true
        });
        self.udp.retain_mut(|c| {
            let s = sockets.get_mut::<udp::Socket>(c.handle);
            loop {
                if !s.can_send() {
                    break;
                }
                match c.pipe.to_net.try_recv() {
                    Ok(d) => {
                        let _ = s.send_slice(&d, IpEndpoint::from(c.dst));
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        sockets.remove(c.handle);
                        return false;
                    }
                }
            }
            if s.can_recv() {
                let mut buf = vec![0u8; 65536];
                while let Ok((n, _)) = s.recv_slice(&mut buf) {
                    let _ = c.pipe.from_net.try_send(buf[..n].to_vec());
                }
            }
            true
        });
    }

    fn mark(&self, b: &mut [u8]) {
        if let (Some(r), true) = (self.reserved, b.len() >= 4) {
            b[1..4].copy_from_slice(&r);
        }
    }

    async fn run(mut self, mut cmds: mpsc::Receiver<Cmd>, send: DgSend, mut recv: DgRecv) -> io::Result<()> {
        let mut wire = vec![0u8; 65536 + 32];
        let mut out = vec![0u8; 65536 + 32];
        let mut timers = tokio::time::interval(Duration::from_millis(250));
        timers.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Start the handshake right away so the first connection is quick.
        if let TunnResult::WriteToNetwork(p) = self.tunn.format_handshake_initiation(&mut out, false) {
            let mut p = p.to_vec();
            self.mark(&mut p);
            send.send(&p).await?;
        }
        loop {
            self.shuttle();
            let ts = now(self.clock);
            self.iface.poll(ts, &mut self.dev, &mut self.sockets);
            self.shuttle();
            while let Some(pkt) = self.dev.tx.pop_front() {
                match self.tunn.encapsulate(&pkt, &mut out) {
                    TunnResult::WriteToNetwork(p) => {
                        let mut p = p.to_vec();
                        self.mark(&mut p);
                        send.send(&p).await?;
                    }
                    TunnResult::Err(e) => tracing::debug!("wireguard encapsulate: {e:?}"),
                    _ => {}
                }
            }
            let delay = self
                .iface
                .poll_delay(now(self.clock), &self.sockets)
                .map(|d| Duration::from_micros(d.total_micros()))
                .unwrap_or(Duration::from_secs(1))
                .min(Duration::from_secs(1));
            tokio::select! {
                c = cmds.recv() => match c {
                    Some(c) => self.add(c),
                    None => return Ok(()),
                },
                r = recv.recv(&mut wire) => {
                    let n = r?;
                    if n >= 4 {
                        wire[1..4].fill(0);
                    }
                    let mut res = self.tunn.decapsulate(None, &wire[..n], &mut out);
                    loop {
                        match res {
                            TunnResult::WriteToNetwork(p) => {
                                let mut p = p.to_vec();
                                self.mark(&mut p);
                                send.send(&p).await?;
                                // Flush packets queued behind the handshake.
                                res = self.tunn.decapsulate(None, &[], &mut out);
                            }
                            TunnResult::WriteToTunnelV4(p, _) | TunnResult::WriteToTunnelV6(p, _) => {
                                self.dev.rx.push_back(p.to_vec());
                                break;
                            }
                            TunnResult::Err(e) => {
                                tracing::debug!("wireguard decapsulate: {e:?}");
                                break;
                            }
                            TunnResult::Done => break,
                        }
                    }
                }
                _ = self.wake.notified() => {}
                _ = timers.tick() => {
                    if let TunnResult::WriteToNetwork(p) = self.tunn.update_timers(&mut out) {
                        let mut p = p.to_vec();
                        self.mark(&mut p);
                        send.send(&p).await?;
                    }
                }
                _ = tokio::time::sleep(delay) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn config_checks() {
        let k = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let mut p = ProxyConfig { name: "w".into(), server: "1.2.3.4".into(), port: 51820, private_key: Some(k.clone()), public_key: Some(k.clone()), ..Default::default() };
        assert!(WireGuard::new(&p, Dialer::Direct).err().unwrap().to_string().contains("ip / ipv6"));
        p.ip = Some("172.16.0.2/32".into());
        p.reserved = vec![1, 2];
        assert!(WireGuard::new(&p, Dialer::Direct).is_err());
        p.reserved = vec![1, 2, 3];
        let w = WireGuard::new(&p, Dialer::Direct).unwrap();
        assert_eq!((w.v4, w.v6, w.mtu, w.reserved), (Some(Ipv4Addr::new(172, 16, 0, 2)), None, 1408, Some([1, 2, 3])));
        p.public_key = Some("short".into());
        assert!(WireGuard::new(&p, Dialer::Direct).is_err());
    }
}
