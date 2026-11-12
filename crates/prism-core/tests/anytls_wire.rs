//! The AnyTLS client as seen on the wire: TLS record sizes follow the padding
//! scheme, server-sent schemes are adopted, dead sessions are noticed.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use prism_core::common::Address;
use prism_core::config::ProxyConfig;
use prism_core::outbound::anytls::AnyTls;
use prism_core::outbound::{Dialer, Outbound};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_UPDATE_PADDING: u8 = 6;
const CMD_SYNACK: u8 = 7;
const CMD_SERVER_SETTINGS: u8 = 10;
const PASSWORD: &str = "pw";
/// AES-GCM tag + content type on every TLS 1.3 record.
const TLS_OVERHEAD: usize = 17;

fn acceptor() -> TlsAcceptor {
    let c = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::try_from(c.key_pair.serialize_der()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![c.cert.der().clone()], key)
        .unwrap();
    TlsAcceptor::from(Arc::new(cfg))
}

fn client(port: u16, fingerprint: Option<&str>) -> AnyTls {
    let p = ProxyConfig {
        name: "t".into(),
        server: "127.0.0.1".into(),
        port,
        password: Some(PASSWORD.into()),
        sni: Some("localhost".into()),
        skip_cert_verify: true,
        fingerprint: fingerprint.map(String::from),
        ..Default::default()
    };
    AnyTls::new(&p, Dialer::Direct).unwrap()
}

async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<(u8, u32, Vec<u8>)> {
    let mut h = [0u8; 7];
    r.read_exact(&mut h).await?;
    let mut d = vec![0u8; u16::from_be_bytes([h[5], h[6]]) as usize];
    r.read_exact(&mut d).await?;
    Ok((h[0], u32::from_be_bytes([h[1], h[2], h[3], h[4]]), d))
}

fn frame(cmd: u8, sid: u32, data: &[u8]) -> Vec<u8> {
    let mut f = vec![cmd];
    f.extend_from_slice(&sid.to_be_bytes());
    f.extend_from_slice(&(data.len() as u16).to_be_bytes());
    f.extend_from_slice(data);
    f
}

/// Reads the authentication; returns the padding length.
async fn read_auth<R: AsyncRead + Unpin>(r: &mut R) -> usize {
    let mut hash = [0u8; 32];
    r.read_exact(&mut hash).await.unwrap();
    assert_eq!(hash.as_slice(), Sha256::digest(PASSWORD.as_bytes()).as_slice());
    let pad = r.read_u16().await.unwrap() as usize;
    r.read_exact(&mut vec![0u8; pad]).await.unwrap();
    pad
}

/// Relays client -> server to `server`, recording the TLS records' (type,
/// length). Replies pass through.
async fn tap(server: SocketAddr, records: Arc<Mutex<Vec<(u8, usize)>>>) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (c, _) = l.accept().await.unwrap();
        let s = TcpStream::connect(server).await.unwrap();
        let (mut cr, mut cw) = c.into_split();
        let (mut sr, mut sw) = s.into_split();
        tokio::spawn(async move {
            let _ = tokio::io::copy(&mut sr, &mut cw).await;
        });
        let mut head = [0u8; 5];
        while cr.read_exact(&mut head).await.is_ok() {
            let len = u16::from_be_bytes([head[3], head[4]]) as usize;
            let mut body = vec![0u8; len];
            if cr.read_exact(&mut body).await.is_err() {
                return;
            }
            records.lock().unwrap().push((head[0], len));
            let _ = sw.write_all(&head).await;
            let _ = sw.write_all(&body).await;
        }
    });
    port
}

async fn padded_records(fingerprint: Option<&str>) {
    let tls = acceptor();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let payload = Arc::new(Mutex::new(Vec::new()));
    let got = payload.clone();
    tokio::spawn(async move {
        let (tcp, _) = l.accept().await.unwrap();
        let mut s = tls.accept(tcp).await.unwrap();
        assert_eq!(read_auth(&mut s).await, 30);
        let (cmd, _, settings) = read_frame(&mut s).await.unwrap();
        assert_eq!(cmd, CMD_SETTINGS);
        assert!(String::from_utf8_lossy(&settings).contains("padding-md5="));
        let mut seen_dest = false;
        while let Ok((cmd, _, d)) = read_frame(&mut s).await {
            match cmd {
                CMD_PSH if !seen_dest => seen_dest = true,
                CMD_PSH => got.lock().unwrap().extend_from_slice(&d),
                CMD_SYN | CMD_WASTE | CMD_FIN => {}
                other => panic!("unexpected frame {other}"),
            }
        }
    });

    let records = Arc::new(Mutex::new(Vec::new()));
    let port = tap(addr, records.clone()).await;
    let c = client(port, fingerprint);
    let mut s = c.connect(&Address::new("1.1.1.1", 80)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    for b in [b"a", b"b", b"c"] {
        s.write_all(b).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let recs: Vec<usize> = records.lock().unwrap().iter().filter(|(t, _)| *t == 0x17).map(|(_, l)| *l).collect();
    // Skip the client's Finished: the first record of auth + 30 padding.
    let auth = recs.iter().position(|l| *l == 34 + 30 + TLS_OVERHEAD).unwrap_or_else(|| panic!("no auth record: {recs:?}"));
    let plain: Vec<usize> = recs[auth + 1..].iter().map(|l| l - TLS_OVERHEAD).collect();
    assert!(plain.len() >= 4, "{plain:?}");
    // Packet 1 (settings, SYN, destination): 100-400 filled up.
    assert!((100..400).contains(&plain[0]), "{plain:?}");
    // Packet 2 ("a"): 400-500, then the check stops it.
    assert!((400..500).contains(&plain[1]), "{plain:?}");
    // Packet 3 ("b"): 9-9 holds the 8 bytes as they are, then 500-1000 of waste.
    assert_eq!(plain[2], 8, "{plain:?}");
    assert!((500..1000).contains(&plain[3]), "{plain:?}");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(payload.lock().unwrap().as_slice(), b"abc");
}

#[tokio::test]
async fn records_follow_the_padding_scheme() {
    padded_records(None).await;
}

#[tokio::test]
async fn records_follow_the_padding_scheme_with_a_chrome_fingerprint() {
    padded_records(Some("chrome")).await;
}

#[tokio::test]
async fn adopts_the_scheme_the_server_sends() {
    let scheme = b"stop=3\n0=50-50\n1=200-200\n2=300-300";
    let tls = acceptor();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = l.accept().await.unwrap();
            let tls = tls.clone();
            let log = log.clone();
            tokio::spawn(async move {
                let mut s = tls.accept(tcp).await.unwrap();
                let pad = read_auth(&mut s).await;
                let (_, _, settings) = read_frame(&mut s).await.unwrap();
                log.lock().unwrap().push((pad, String::from_utf8_lossy(&settings).to_string()));
                s.write_all(&frame(CMD_UPDATE_PADDING, 0, scheme)).await.unwrap();
                s.flush().await.unwrap();
                while read_frame(&mut s).await.is_ok() {}
            });
        }
    });
    let c = client(port, None);
    let _first = c.connect(&Address::new("1.1.1.1", 80)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    // The first session is busy, so this one is new.
    let _second = c.connect(&Address::new("1.1.1.1", 80)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].0, 30);
    assert_eq!(seen[1].0, 50);
    let md5 = "padding-md5=";
    assert_ne!(seen[0].1.split(md5).nth(1), seen[1].1.split(md5).nth(1));
}

/// A server that acknowledges only the first stream of each session.
async fn serve_session<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, answer_second: bool) {
    read_auth(&mut s).await;
    let mut dest_seen = std::collections::HashSet::new();
    while let Ok((cmd, sid, d)) = read_frame(&mut s).await {
        let mut out = Vec::new();
        match cmd {
            CMD_SETTINGS => out = frame(CMD_SERVER_SETTINGS, 0, b"v=2"),
            CMD_PSH if dest_seen.insert(sid) => {
                if sid == 1 || answer_second {
                    out = frame(CMD_SYNACK, sid, &[]);
                }
            }
            CMD_PSH => out = frame(CMD_PSH, sid, &d),
            CMD_FIN => out = frame(CMD_FIN, sid, &[]),
            _ => {}
        }
        if !out.is_empty() {
            s.write_all(&out).await.unwrap();
            s.flush().await.unwrap();
        }
    }
}

async fn second_stream(answer_second: bool) -> std::io::Result<usize> {
    let tls = acceptor();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = l.accept().await.unwrap();
            let s = tls.accept(tcp).await.unwrap();
            tokio::spawn(serve_session(s, answer_second));
        }
    });
    let c = client(port, None);
    let target = Address::new("1.1.1.1", 80);
    let mut s = c.connect(&target).await.unwrap();
    s.write_all(b"one").await.unwrap();
    let mut b = [0u8; 3];
    s.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"one");
    drop(s);
    tokio::time::sleep(Duration::from_millis(200)).await; // back in the pool

    let mut s = c.connect(&target).await.unwrap();
    // No reply data: only the watchdog can end this read.
    let mut rest = Vec::new();
    match tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut rest)).await {
        Ok(r) => r,
        Err(_) => Ok(usize::MAX),
    }
}

#[tokio::test]
async fn a_pooled_session_without_synack_is_closed() {
    assert_ne!(second_stream(false).await.unwrap_or(0), usize::MAX, "the stream should have ended");
}

#[tokio::test]
async fn a_session_that_answers_stays_open() {
    assert_eq!(second_stream(true).await.unwrap(), usize::MAX, "the stream should still be open");
}


#[tokio::test]
async fn dropping_outbound_releases_idle_tls_socket() {
    let tls = acceptor();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let c = client(listener.local_addr().unwrap().port(), None);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let socket = tls.accept(tcp).await.unwrap();
        serve_session(socket, true).await;
    });
    let mut stream = c.connect(&Address::new("1.1.1.1", 80)).await.unwrap();
    stream.write_all(b"ok").await.unwrap();
    let mut data = [0; 2];
    stream.read_exact(&mut data).await.unwrap();
    assert_eq!(&data, b"ok");
    drop(stream);
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(c);
    tokio::time::timeout(Duration::from_secs(2), server).await
        .expect("idle TLS socket survived outbound cleanup").unwrap();
}
