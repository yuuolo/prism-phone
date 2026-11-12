//! How protocol outbounds reach their servers: directly (sockets pinned to
//! the physical interface in TUN mode) or through another outbound, for
//! Clash `dialer-proxy` and relay groups.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use super::{Outbound, RegistryCell};
use crate::common::{other, Address, BoxedStream, UdpPipe};

tokio::task_local! {
    /// How many outbounds deep the current dial is; stops loops such as a
    /// node whose dialer-proxy group currently selects the node itself.
    static DEPTH: u8;
}

const MAX_DEPTH: u8 = 8;

fn deeper() -> io::Result<u8> {
    let d = DEPTH.try_with(|d| *d).unwrap_or(0);
    if d >= MAX_DEPTH {
        return Err(other("dialer-proxy / relay chain loops back on itself"));
    }
    Ok(d + 1)
}

#[derive(Clone, Default)]
pub enum Dialer {
    #[default]
    Direct,
    /// An outbound by name, looked up when dialing (`dialer-proxy` may name
    /// a group whose selection changes).
    Named(String, RegistryCell),
    /// A fixed outbound (the hops of a relay chain).
    Via(Arc<dyn Outbound>),
}

impl Dialer {
    pub fn named(name: Option<&str>, reg: &RegistryCell) -> Self {
        match name {
            Some(n) if n != "DIRECT" => Dialer::Named(n.to_string(), reg.clone()),
            _ => Dialer::Direct,
        }
    }

    fn via(&self) -> io::Result<Option<Arc<dyn Outbound>>> {
        match self {
            Dialer::Direct => Ok(None),
            Dialer::Named(n, reg) => {
                let reg = reg.get().ok_or_else(|| other("registry not ready"))?;
                reg.get(n).map(Some).ok_or_else(|| other(format!("dialer-proxy {n} not found")))
            }
            Dialer::Via(o) => Ok(Some(o.clone())),
        }
    }

    pub async fn tcp(&self, host: &str, port: u16) -> io::Result<BoxedStream> {
        match self.via()? {
            None => Ok(Box::new(crate::net::tcp_connect_proxy(host, port).await?)),
            Some(o) => DEPTH.scope(deeper()?, o.connect(&Address::new(host, port))).await,
        }
    }

    /// A datagram path to `host:port`.
    pub async fn udp(&self, host: &str, port: u16) -> io::Result<Datagrams> {
        match self.via()? {
            None => {
                let addrs = crate::net::resolve_proxy(host, port).await?;
                let peer = *addrs.iter().min_by_key(|a| a.is_ipv6()).ok_or_else(|| other("no address"))?;
                let sock = crate::net::udp_socket(peer).await?;
                sock.connect(peer).await?;
                Ok(Datagrams::Socket(sock, peer))
            }
            Some(o) => {
                if !o.udp() {
                    return Err(other(format!("{} can't carry UDP, which this node needs", o.name())));
                }
                let target = Address::new(host, port);
                Ok(Datagrams::Pipe(DEPTH.scope(deeper()?, o.connect_udp(&target)).await?))
            }
        }
    }
}

/// Datagrams to one server: a connected socket or a UDP session of another
/// outbound.
pub enum Datagrams {
    Socket(UdpSocket, SocketAddr),
    Pipe(UdpPipe),
}

/// Address quinn sees for a server reached through a pipe.
const PIPE_PEER: &str = "127.0.0.1:443";

impl Datagrams {
    pub fn split(self) -> (DgSend, DgRecv) {
        match self {
            Datagrams::Socket(s, _) => {
                let s = Arc::new(s);
                (DgSend::Socket(s.clone()), DgRecv::Socket(s))
            }
            Datagrams::Pipe(p) => (DgSend::Pipe(p.tx), DgRecv::Pipe(p.rx)),
        }
    }

    /// A quinn socket plus the address to connect it to.
    pub fn into_quinn(self) -> io::Result<(Arc<dyn quinn::AsyncUdpSocket>, SocketAddr)> {
        match self {
            Datagrams::Socket(s, peer) => {
                let runtime = quinn::TokioRuntime;
                Ok((quinn::Runtime::wrap_udp_socket(&runtime, s.into_std()?)?, peer))
            }
            Datagrams::Pipe(p) => {
                let peer: SocketAddr = PIPE_PEER.parse().unwrap();
                Ok((Arc::new(PipeSocket { tx: p.tx, rx: Mutex::new(p.rx), peer }), peer))
            }
        }
    }
}

pub enum DgSend {
    Socket(Arc<UdpSocket>),
    Pipe(mpsc::Sender<Vec<u8>>),
}

impl DgSend {
    pub async fn send(&self, b: &[u8]) -> io::Result<()> {
        match self {
            DgSend::Socket(s) => s.send(b).await.map(|_| ()),
            DgSend::Pipe(tx) => tx.send(b.to_vec()).await.map_err(|_| other("udp session closed")),
        }
    }
}

pub enum DgRecv {
    Socket(Arc<UdpSocket>),
    Pipe(mpsc::Receiver<Vec<u8>>),
}

impl DgRecv {
    pub async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            DgRecv::Socket(s) => s.recv(buf).await,
            DgRecv::Pipe(rx) => {
                let p = rx.recv().await.ok_or_else(|| other("udp session closed"))?;
                let n = p.len().min(buf.len());
                buf[..n].copy_from_slice(&p[..n]);
                Ok(n)
            }
        }
    }
}

/// QUIC over another outbound's UDP session.
struct PipeSocket {
    tx: mpsc::Sender<Vec<u8>>,
    rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    peer: SocketAddr,
}

impl fmt::Debug for PipeSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PipeSocket")
    }
}

#[derive(Debug)]
struct AlwaysWritable;

impl quinn::UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl quinn::AsyncUdpSocket for PipeSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, t: &quinn::udp::Transmit) -> io::Result<()> {
        // A full queue drops the packet, like a congested link.
        let _ = self.tx.try_send(t.contents.to_vec());
        Ok(())
    }

    fn poll_recv(&self, cx: &mut Context, bufs: &mut [io::IoSliceMut<'_>], meta: &mut [quinn::udp::RecvMeta]) -> Poll<io::Result<usize>> {
        let mut rx = self.rx.lock().unwrap();
        match rx.poll_recv(cx) {
            Poll::Ready(Some(p)) => {
                let n = p.len().min(bufs[0].len());
                bufs[0][..n].copy_from_slice(&p[..n]);
                meta[0] = quinn::udp::RecvMeta { addr: self.peer, len: n, stride: n, ecn: None, dst_ip: None };
                Poll::Ready(Ok(1))
            }
            // The carrying session ended; the QUIC connection times out.
            Poll::Ready(None) | Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok("127.0.0.1:1".parse().unwrap())
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        false
    }
}
