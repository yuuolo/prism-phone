//! AnyTLS client (protocol v2, compatible with anytls-go and sing-box).
//!
//! Wire format after the TLS handshake:
//!   auth:  sha256(password)[32] | padding_len u16 BE | padding
//!   frame: cmd u8 | stream_id u32 BE | data_len u16 BE | data
//!
//! Sessions (TLS connections) are reused like anytls-go does: a session
//! carries one stream at a time, goes back to an idle pool when its stream
//! ends, and is closed after sitting idle for [`IDLE_TIMEOUT`]. A new
//! connection on a pooled session costs no handshake round trips: SYN and
//! the destination are written immediately.
//!
//! A session's first writes follow the padding scheme, which is what hides
//! the sizes of the inner TLS handshake: each write is cut or filled up to
//! the record sizes the scheme picks (see [`write_padded`]). The server can
//! replace the scheme; new sessions then use and report the new one.
//!
//! v2 servers answer each SYN with a SYNACK. A pooled session can have died
//! without either side noticing (network change, NAT timeout), so a stream
//! on one that gets no answer within [`SYNACK_TIMEOUT`] closes the session
//! instead of hanging until TCP gives up.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use md5::{Digest as _, Md5};
use rand::Rng;
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::tls::Tls;
use super::{Dialer, Outbound};
use crate::common::{other, pump, udp_over_stream, Address, BoxedStream, Framing, UdpPipe};
use crate::config::ProxyConfig;

const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_ALERT: u8 = 5;
const CMD_UPDATE_PADDING: u8 = 6;
const CMD_SYNACK: u8 = 7;
const CMD_HEART_REQUEST: u8 = 8;
const CMD_HEART_RESPONSE: u8 = 9;
const CMD_SERVER_SETTINGS: u8 = 10;

const MAX_FRAME: usize = 16 * 1024;
/// sing-box UDP-over-TCP v2: a stream to this address carries datagrams.
const UOT_MAGIC: &str = "sp.v2.udp-over-tcp.arpa";
const MAX_IDLE_SESSIONS: usize = 32;
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const SYNACK_TIMEOUT: Duration = Duration::from_secs(3);

/// anytls-go's default padding scheme.
const DEFAULT_PADDING_SCHEME: &str = "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";

fn frame(buf: &mut Vec<u8>, cmd: u8, sid: u32, data: &[u8]) {
    buf.push(cmd);
    buf.extend_from_slice(&sid.to_be_bytes());
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
}

pub fn client_settings(padding_md5: &str) -> String {
    format!("v=2\nclient=prism/{}\npadding-md5={padding_md5}", env!("CARGO_PKG_VERSION"))
}

/// One step of a padding scheme line.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Step {
    /// A record of `min..max` bytes (exactly `min` when they are equal).
    Size(usize, usize),
    /// `c`: stop here if all payload is out.
    Check,
}

/// A parsed padding scheme: `stop=N`, then `<packet>=<steps>` lines.
#[derive(Debug)]
struct Padding {
    md5: String,
    stop: u32,
    packets: HashMap<u32, Vec<Step>>,
}

impl Padding {
    /// `None` without a numeric `stop`. Unusable steps are skipped, as in
    /// anytls-go.
    fn parse(raw: &[u8]) -> Option<Self> {
        let (mut stop, mut packets) = (None, HashMap::new());
        for line in String::from_utf8_lossy(raw).split('\n') {
            let Some((key, value)) = line.split_once('=') else { continue };
            if key == "stop" {
                stop = value.parse().ok();
            } else if let Ok(pkt) = key.parse::<u32>() {
                packets.insert(pkt, value.split(',').filter_map(Self::step).collect());
            }
        }
        Some(Padding { md5: hex::encode(Md5::digest(raw)), stop: stop?, packets })
    }

    fn step(s: &str) -> Option<Step> {
        if s == "c" {
            return Some(Step::Check);
        }
        let (a, b) = s.split_once('-')?;
        let (a, b): (usize, usize) = (a.parse().ok()?, b.parse().ok()?);
        let (min, max) = (a.min(b), a.max(b));
        (min > 0 && max <= u16::MAX as usize).then_some(Step::Size(min, max))
    }

    fn steps(&self, pkt: u32) -> &[Step] {
        self.packets.get(&pkt).map_or(&[], Vec::as_slice)
    }
}

fn pick_size(min: usize, max: usize) -> usize {
    if min == max {
        min
    } else {
        rand::thread_rng().gen_range(min..max)
    }
}

/// Writes `data` as one record per step: payload cut to the step's size, or
/// filled up with a waste frame when less is left, or all waste when none
/// is. What remains after the last step goes out as is.
async fn write_padded<W: AsyncWrite + Unpin>(wr: &mut W, mut data: &[u8], steps: &[Step]) -> io::Result<()> {
    let waste = |len: usize| {
        let mut f = Vec::with_capacity(len + 7);
        frame(&mut f, CMD_WASTE, 0, &vec![0u8; len]);
        f
    };
    for step in steps {
        let size = match *step {
            Step::Check if data.is_empty() => break,
            Step::Check => continue,
            Step::Size(min, max) => pick_size(min, max),
        };
        if data.len() > size {
            wr.write_all(&data[..size]).await?;
            data = &data[size..];
        } else if !data.is_empty() {
            let mut rec = data.to_vec();
            if let Some(fill) = size.checked_sub(data.len() + 7).filter(|n| *n > 0) {
                rec.extend_from_slice(&waste(fill));
            }
            wr.write_all(&rec).await?;
            data = &[];
        } else {
            wr.write_all(&waste(size)).await?;
        }
        // Each step is a record of its own on the wire.
        wr.flush().await?;
    }
    if !data.is_empty() {
        wr.write_all(data).await?;
    }
    Ok(())
}

/// What the session reader delivers to a stream.
enum Event {
    Data(Vec<u8>),
    Error(String),
}

/// One TLS connection to the server.
struct Session {
    /// Frames to the writer task; taken (dropped) on close.
    out: Mutex<Option<mpsc::Sender<Vec<u8>>>>,
    /// Open streams; removing a sender signals FIN to that stream.
    streams: Mutex<HashMap<u32, mpsc::Sender<Event>>>,
    next_sid: AtomicU32,
    closed: AtomicBool,
    cancel: CancellationToken,
    idle_since: Mutex<Instant>,
    /// Protocol version the server announced; 0 until it did.
    peer_version: AtomicU8,
    /// Closes the session unless a SYNACK arrives first.
    synack_watch: Mutex<Option<tokio::task::AbortHandle>>,
}

impl Session {
    fn sender(&self) -> Option<mpsc::Sender<Vec<u8>>> {
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        self.out.lock().unwrap().clone()
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Ends the session: the writer sends close_notify, the server then
    /// closes the connection and the reader exits.
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.cancel.cancel();
        self.out.lock().unwrap().take();
        self.streams.lock().unwrap().clear();
        self.synack_received();
    }

    fn synack_received(&self) {
        if let Some(h) = self.synack_watch.lock().unwrap().take() {
            h.abort();
        }
    }

    /// A stream was opened on a pooled session: expect a sign of life.
    fn watch_synack(self: &Arc<Self>) {
        if self.peer_version.load(Ordering::Acquire) < 2 {
            return;
        }
        let session = Arc::downgrade(self);
        let h = tokio::spawn(async move {
            tokio::time::sleep(SYNACK_TIMEOUT).await;
            if let Some(s) = session.upgrade() {
                tracing::debug!("anytls: no SYNACK in {SYNACK_TIMEOUT:?}, closing the session");
                // Not close(): that would abort this task on the way.
                s.synack_watch.lock().unwrap().take();
                s.close();
            }
        });
        if let Some(old) = self.synack_watch.lock().unwrap().replace(h.abort_handle()) {
            old.abort();
        }
    }
}

type Pool = Arc<Mutex<Vec<Arc<Session>>>>;

pub struct AnyTls {
    name: String,
    server: String,
    port: u16,
    password_hash: [u8; 32],
    tls: Tls,
    dialer: Dialer,
    idle: Pool,
    reaper_started: AtomicBool,
    /// Shared by sessions: the server may replace it.
    padding: Arc<RwLock<Arc<Padding>>>,
}

impl AnyTls {
    pub fn new(p: &ProxyConfig, dialer: Dialer) -> io::Result<Self> {
        let password = p.password.clone().unwrap_or_default();
        Ok(AnyTls {
            name: p.name.clone(),
            server: p.server.clone(),
            port: p.port,
            password_hash: Sha256::digest(password.as_bytes()).into(),
            tls: Tls::new(p.sni.as_deref().unwrap_or(&p.server), p.skip_cert_verify, &p.alpn, p.fingerprint.as_deref())?,
            dialer,
            idle: Arc::new(Mutex::new(Vec::new())),
            reaper_started: AtomicBool::new(false),
            padding: Arc::new(RwLock::new(Arc::new(
                Padding::parse(DEFAULT_PADDING_SCHEME.as_bytes()).expect("default padding scheme"),
            ))),
        })
    }

    /// Most recently used idle session that is still open.
    fn take_idle(&self) -> Option<Arc<Session>> {
        let mut idle = self.idle.lock().unwrap();
        while let Some(s) = idle.pop() {
            let fresh = s.idle_since.lock().unwrap().elapsed() < IDLE_TIMEOUT;
            if !s.is_closed() && fresh {
                return Some(s);
            }
            s.close();
        }
        None
    }

    /// Periodically closes sessions that sat idle too long (servers and
    /// NATs drop quiet connections; a dead pooled session would stall the
    /// next stream).
    fn start_reaper(&self) {
        if self.reaper_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let pool: Weak<Mutex<Vec<Arc<Session>>>> = Arc::downgrade(&self.idle);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                let Some(pool) = pool.upgrade() else { return };
                pool.lock().unwrap().retain(|s| {
                    let keep = !s.is_closed() && s.idle_since.lock().unwrap().elapsed() < IDLE_TIMEOUT;
                    if !keep {
                        s.close();
                    }
                    keep
                });
            }
        });
    }

    async fn new_session(&self) -> io::Result<Arc<Session>> {
        self.start_reaper();
        let mut tls = self.tls.connect(&self.dialer, &self.server, self.port).await?;
        let scheme = self.padding.read().unwrap().clone();
        // Packet 0: the authentication and its padding, alone in a record.
        let pad = match scheme.steps(0).first() {
            Some(Step::Size(min, max)) => pick_size(*min, *max),
            _ => 0,
        };
        let mut hello = Vec::with_capacity(34 + pad);
        hello.extend_from_slice(&self.password_hash);
        hello.extend_from_slice(&(pad as u16).to_be_bytes());
        hello.resize(34 + pad, 0);
        tls.write_all(&hello).await?;
        tls.flush().await?;
        // Sent together with the first stream's SYN, as packet 1.
        let mut settings = Vec::new();
        frame(&mut settings, CMD_SETTINGS, 0, client_settings(&scheme.md5).as_bytes());

        let (mut rd, mut wr) = tokio::io::split(tls);
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
        let session = Arc::new(Session {
            out: Mutex::new(Some(tx)),
            streams: Mutex::new(HashMap::new()),
            next_sid: AtomicU32::new(1),
            closed: AtomicBool::new(false),
            cancel: CancellationToken::new(),
            idle_since: Mutex::new(Instant::now()),
            peer_version: AtomicU8::new(0),
            synack_watch: Mutex::new(None),
        });

        // Writer: batches whatever is queued, flushes once per batch.
        let ws = Arc::downgrade(&session);
        let padding = self.padding.clone();
        let writer_cancel = session.cancel.clone();
        tokio::spawn(async move {
            let work = async {
                let mut pkt = 0u32;
                let mut padding_on = true;
                let mut first = Some(settings);
                while let Some(mut buf) = rx.recv().await {
                    if let Some(mut settings) = first.take() {
                        settings.append(&mut buf);
                        buf = settings;
                    }
                    if padding_on {
                        pkt += 1;
                        let scheme = padding.read().unwrap().clone();
                        padding_on = pkt < scheme.stop;
                        if padding_on {
                            while let Ok(mut more) = rx.try_recv() {
                                buf.append(&mut more);
                            }
                            write_padded(&mut wr, &buf, scheme.steps(pkt)).await?;
                            wr.flush().await?;
                            continue;
                        }
                    }
                    wr.write_all(&buf).await?;
                    while let Ok(more) = rx.try_recv() {
                        wr.write_all(&more).await?;
                    }
                    wr.flush().await?;
                }
                wr.shutdown().await
            };
            let res: io::Result<()> = tokio::select! {
                _ = writer_cancel.cancelled() => return,
                res = work => res,
            };
            if res.is_err() {
                if let Some(s) = ws.upgrade() {
                    s.close();
                }
            }
        });

        // Reader: demultiplexes frames to streams.
        let rs = session.clone();
        let padding = self.padding.clone();
        tokio::spawn(async move {
            let work = async {
                let mut head = [0u8; 7];
                let mut data = vec![0u8; 65535];
                loop {
                    rd.read_exact(&mut head).await?;
                    let cmd = head[0];
                    let sid = u32::from_be_bytes([head[1], head[2], head[3], head[4]]);
                    let len = u16::from_be_bytes([head[5], head[6]]) as usize;
                    rd.read_exact(&mut data[..len]).await?;
                    let body = &data[..len];
                    match cmd {
                        CMD_PSH => {
                            let tx = rs.streams.lock().unwrap().get(&sid).cloned();
                            if let Some(tx) = tx {
                                // Backpressure: wait for the stream to take it.
                                let _ = tx.send(Event::Data(body.to_vec())).await;
                            }
                        }
                        CMD_FIN => {
                            rs.streams.lock().unwrap().remove(&sid);
                        }
                        CMD_SYNACK => {
                            rs.synack_received();
                            if !body.is_empty() {
                                let tx = rs.streams.lock().unwrap().remove(&sid);
                                if let Some(tx) = tx {
                                    let msg = format!("anytls: server dial failed: {}", String::from_utf8_lossy(body));
                                    let _ = tx.send(Event::Error(msg)).await;
                                }
                            }
                        }
                        CMD_UPDATE_PADDING => match Padding::parse(body) {
                            Some(p) => *padding.write().unwrap() = Arc::new(p),
                            None => tracing::debug!("anytls: server sent an unusable padding scheme"),
                        },
                        CMD_SERVER_SETTINGS => {
                            let text = String::from_utf8_lossy(body);
                            let v = text.split('\n').find_map(|l| l.strip_prefix("v=")).and_then(|v| v.parse().ok());
                            rs.peer_version.store(v.unwrap_or(0), Ordering::Release);
                        }
                        CMD_ALERT => {
                            return Err(other(format!("anytls: alert: {}", String::from_utf8_lossy(body))));
                        }
                        CMD_HEART_REQUEST => {
                            if let Some(out) = rs.sender() {
                                let mut f = Vec::with_capacity(7);
                                frame(&mut f, CMD_HEART_RESPONSE, sid, &[]);
                                let _ = out.send(f).await;
                            }
                        }
                        _ => {}
                    }
                }
            };
            let res: io::Result<()> = tokio::select! {
                _ = rs.cancel.cancelled() => return,
                res = work => res,
            };
            if let Err(e) = res {
                if e.kind() != io::ErrorKind::UnexpectedEof {
                    tracing::debug!("anytls session closed: {e}");
                }
            }
            rs.close();
        });
        Ok(session)
    }

    /// Opens stream `sid` on `session`: SYN + destination in one write.
    async fn open(session: &Arc<Session>, target: &Address) -> io::Result<(u32, mpsc::Receiver<Event>)> {
        let out = session.sender().ok_or_else(|| other("anytls: session closed"))?;
        let sid = session.next_sid.fetch_add(1, Ordering::Relaxed);
        let (etx, erx) = mpsc::channel(64);
        session.streams.lock().unwrap().insert(sid, etx);
        let mut dest = Vec::new();
        target.write_socks(&mut dest);
        let mut f = Vec::with_capacity(32 + dest.len());
        frame(&mut f, CMD_SYN, sid, &[]);
        frame(&mut f, CMD_PSH, sid, &dest);
        out.send(f).await.map_err(|_| other("anytls: session closed"))?;
        Ok((sid, erx))
    }
}

impl Drop for AnyTls {
    fn drop(&mut self) {
        for session in self.idle.lock().unwrap().drain(..) {
            session.close();
        }
    }
}

#[async_trait]
impl Outbound for AnyTls {
    fn name(&self) -> &str {
        &self.name
    }
    fn api_type(&self) -> &'static str {
        "AnyTLS"
    }
    fn udp(&self) -> bool {
        true
    }
    /// UDP via sing-box UDP-over-TCP v2 (what sing-box / mihomo AnyTLS
    /// clients use): request `is_connect u8 | socks addr`, then
    /// `u16 len | data` both ways.
    async fn connect_udp(&self, target: &Address) -> io::Result<UdpPipe> {
        let mut s = self.connect(&Address::Domain(UOT_MAGIC.into(), 0)).await?;
        let mut req = vec![1u8];
        target.write_socks(&mut req);
        s.write_all(&req).await?;
        Ok(udp_over_stream(s, Framing::Length))
    }
    async fn connect(&self, target: &Address) -> io::Result<BoxedStream> {
        // Prefer a pooled session; fall back to a fresh one if it turns out
        // to be closed.
        let (session, sid, mut events) = loop {
            match self.take_idle() {
                Some(s) => match Self::open(&s, target).await {
                    Ok((sid, ev)) => {
                        s.watch_synack();
                        break (s, sid, ev);
                    }
                    Err(_) => s.close(),
                },
                None => {
                    let s = self.new_session().await?;
                    let (sid, ev) = Self::open(&s, target).await?;
                    break (s, sid, ev);
                }
            }
        };
        let pool = self.idle.clone();
        Ok(pump(move |local| async move {
            let (mut lrd, mut lwr) = tokio::io::split(local);
            let out = session.sender().ok_or_else(|| other("anytls: session closed"))?;
            let upload = async move {
                let mut buf = vec![0u8; MAX_FRAME];
                loop {
                    let n = lrd.read(&mut buf).await?;
                    let mut f = Vec::with_capacity(n + 7);
                    frame(&mut f, if n == 0 { CMD_FIN } else { CMD_PSH }, sid, &buf[..n]);
                    out.send(f).await.map_err(|_| other("anytls: session closed"))?;
                    if n == 0 {
                        return Ok::<_, io::Error>(());
                    }
                }
            };
            let download = async {
                // If the local side goes away, keep draining until the
                // server's FIN so the session stays clean for reuse.
                let mut local_open = true;
                while let Some(ev) = events.recv().await {
                    match ev {
                        Event::Data(d) => {
                            if local_open && lwr.write_all(&d).await.is_err() {
                                local_open = false;
                            }
                        }
                        // Stream-level failure; the session itself is fine.
                        Event::Error(e) => {
                            tracing::debug!("{e}");
                            break;
                        }
                    }
                }
                // Sender removed: FIN from the server, or the session died.
                if local_open {
                    let _ = lwr.shutdown().await;
                }
                if session.is_closed() {
                    return Err(other("anytls: session closed"));
                }
                Ok(())
            };
            let res = tokio::try_join!(upload, download);
            session.streams.lock().unwrap().remove(&sid);
            if res.is_ok() && !session.is_closed() {
                *session.idle_since.lock().unwrap() = Instant::now();
                let mut idle = pool.lock().unwrap();
                if idle.len() < MAX_IDLE_SESSIONS { idle.push(session); }
                else { session.close(); }
            } else {
                session.close();
            }
            res.map(|_| ())
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn closing_session_cancels_blocked_io_and_streams() {
        let (tx, _rx) = mpsc::channel(1);
        let (events, mut receiver) = mpsc::channel(1);
        let s = Session {
            out: Mutex::new(Some(tx)), streams: Mutex::new(HashMap::from([(1, events)])),
            next_sid: AtomicU32::new(2), closed: AtomicBool::new(false),
            cancel: CancellationToken::new(), idle_since: Mutex::new(Instant::now()),
            peer_version: AtomicU8::new(2), synack_watch: Mutex::new(None),
        };
        let cancel = s.cancel.clone();
        let blocked = tokio::spawn(async move {
            tokio::select! {
                _ = cancel.cancelled() => true,
                _ = std::future::pending::<()>() => false,
            }
        });
        s.close();
        s.close(); // cleanup is idempotent
        assert!(tokio::time::timeout(Duration::from_secs(1), blocked).await.unwrap().unwrap());
        assert!(receiver.recv().await.is_none());
        assert!(s.sender().is_none());
    }

    #[test]
    fn frame_layout() {
        let mut b = Vec::new();
        frame(&mut b, CMD_PSH, 1, b"hi");
        assert_eq!(b, [2, 0, 0, 0, 1, 0, 2, b'h', b'i']);
        assert!(client_settings("ab").starts_with("v=2\nclient=prism/"));
        assert!(client_settings("ab").ends_with("\npadding-md5=ab"));
    }

    #[test]
    fn parses_schemes() {
        let p = Padding::parse(DEFAULT_PADDING_SCHEME.as_bytes()).unwrap();
        assert_eq!(p.stop, 8);
        assert_eq!(p.steps(0), [Step::Size(30, 30)]);
        assert_eq!(p.steps(3), [Step::Size(9, 9), Step::Size(500, 1000)]);
        assert_eq!(p.steps(2)[1], Step::Check);
        assert!(p.steps(99).is_empty());
        assert!(Padding::parse(b"0=30-30").is_none());
        // Reversed ranges are fine; unusable steps are dropped.
        let p = Padding::parse(b"stop=1\n0=20-10,0-5,x,1-70000").unwrap();
        assert_eq!(p.steps(0), [Step::Size(10, 20)]);
    }

    /// Records as `write_padded` would produce them (one per flush).
    async fn records(data: &[u8], steps: &[Step]) -> Vec<Vec<u8>> {
        struct Rec(Vec<Vec<u8>>, Vec<u8>);
        impl AsyncWrite for Rec {
            fn poll_write(
                mut self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                b: &[u8],
            ) -> std::task::Poll<io::Result<usize>> {
                self.1.extend_from_slice(b);
                std::task::Poll::Ready(Ok(b.len()))
            }
            fn poll_flush(mut self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
                let cur = std::mem::take(&mut self.1);
                if !cur.is_empty() {
                    self.0.push(cur);
                }
                std::task::Poll::Ready(Ok(()))
            }
            fn poll_shutdown(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
        }
        let mut w = Rec(Vec::new(), Vec::new());
        write_padded(&mut w, data, steps).await.unwrap();
        w.flush().await.unwrap();
        w.0
    }

    #[tokio::test]
    async fn padding_cuts_and_fills() {
        // Less payload than the record: filled with a waste frame.
        let r = records(b"abc", &[Step::Size(100, 100)]).await;
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].len(), 100);
        assert_eq!(&r[0][..3], b"abc");
        assert_eq!(r[0][3], CMD_WASTE);
        assert_eq!(u16::from_be_bytes([r[0][8], r[0][9]]), 90);

        // More payload than the record: cut, the rest follows unchanged.
        let data = vec![1u8; 250];
        let r = records(&data, &[Step::Size(100, 100)]).await;
        assert_eq!(r.iter().map(Vec::len).collect::<Vec<_>>(), [100, 150]);

        // No room for a waste frame: sent as is.
        let r = records(b"abc", &[Step::Size(9, 9)]).await;
        assert_eq!(r, [b"abc".to_vec()]);

        // Payload gone: the check stops; without a check, a record of waste.
        let c = [Step::Size(100, 100), Step::Check, Step::Size(50, 50)];
        assert_eq!(records(b"abc", &c).await.len(), 1);
        let r = records(b"abc", &[Step::Size(100, 100), Step::Size(50, 50)]).await;
        assert_eq!(r.iter().map(Vec::len).collect::<Vec<_>>(), [100, 57]);
        // With payload left, the check continues.
        let r = records(&data, &c).await;
        assert_eq!(r.iter().map(Vec::len).collect::<Vec<_>>(), [100, 50, 100]);
    }
}
