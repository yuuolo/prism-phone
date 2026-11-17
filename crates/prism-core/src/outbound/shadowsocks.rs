//! Shadowsocks AEAD (aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305).
//!
//! Stream: salt | { enc(len u16) tag | enc(payload) tag }*
//! Session subkey = HKDF-SHA1(EVP_BytesToKey(password), salt, "ss-subkey").

use std::io;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use async_trait::async_trait;
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use md5::{Digest, Md5};
use rand::RngCore;
use sha1::Sha1;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{Dialer, Outbound};
use crate::common::{invalid, pump, udp_pump, Address, BoxedStream, UdpPipe};
use crate::config::ProxyConfig;

const TAG: usize = 16;
const MAX_PAYLOAD: usize = 0x3fff;

#[derive(Clone, Copy)]
enum Method {
    Aes128,
    Aes256,
    Chacha,
}

impl Method {
    fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Some(Method::Aes128),
            "aes-256-gcm" => Some(Method::Aes256),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Some(Method::Chacha),
            _ => None,
        }
    }

    fn key_len(self) -> usize {
        match self {
            Method::Aes128 => 16,
            _ => 32,
        }
    }
}

enum AeadKind {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    Chacha(Box<ChaCha20Poly1305>),
}

struct Cipher {
    aead: AeadKind,
    nonce: u64,
}

impl Cipher {
    fn new(method: Method, master: &[u8], salt: &[u8]) -> Self {
        let mut sub = vec![0u8; method.key_len()];
        Hkdf::<Sha1>::new(Some(salt), master).expand(b"ss-subkey", &mut sub).expect("hkdf length");
        let aead = match method {
            Method::Aes128 => AeadKind::Aes128(Box::new(Aes128Gcm::new_from_slice(&sub).unwrap())),
            Method::Aes256 => AeadKind::Aes256(Box::new(Aes256Gcm::new_from_slice(&sub).unwrap())),
            Method::Chacha => AeadKind::Chacha(Box::new(ChaCha20Poly1305::new_from_slice(&sub).unwrap())),
        };
        Cipher { aead, nonce: 0 }
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&self.nonce.to_le_bytes());
        self.nonce += 1;
        n
    }

    fn seal(&mut self, plain: &[u8]) -> Vec<u8> {
        let n = self.next_nonce();
        let nonce = aes_gcm::Nonce::from_slice(&n);
        match &self.aead {
            AeadKind::Aes128(c) => c.encrypt(nonce, plain),
            AeadKind::Aes256(c) => c.encrypt(nonce, plain),
            AeadKind::Chacha(c) => c.encrypt(chacha20poly1305::Nonce::from_slice(&n), plain),
        }
        .expect("aead encrypt")
    }

    fn open(&mut self, sealed: &[u8]) -> io::Result<Vec<u8>> {
        let n = self.next_nonce();
        let nonce = aes_gcm::Nonce::from_slice(&n);
        match &self.aead {
            AeadKind::Aes128(c) => c.decrypt(nonce, sealed),
            AeadKind::Aes256(c) => c.decrypt(nonce, sealed),
            AeadKind::Chacha(c) => c.decrypt(chacha20poly1305::Nonce::from_slice(&n), sealed),
        }
        .map_err(|_| invalid("shadowsocks: decryption failed (wrong password or cipher?)"))
    }

    fn seal_chunk(&mut self, payload: &[u8], out: &mut Vec<u8>) {
        out.extend(self.seal(&(payload.len() as u16).to_be_bytes()));
        out.extend(self.seal(payload));
    }
}

/// OpenSSL EVP_BytesToKey with MD5, as used by Shadowsocks.
fn evp_bytes_to_key(password: &[u8], len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(len + 16);
    let mut prev: Vec<u8> = Vec::new();
    while key.len() < len {
        let mut h = Md5::new();
        h.update(&prev);
        h.update(password);
        prev = h.finalize().to_vec();
        key.extend_from_slice(&prev);
    }
    key.truncate(len);
    key
}

pub struct Shadowsocks {
    name: String,
    server: String,
    port: u16,
    method: Method,
    key: Vec<u8>,
    dialer: Dialer,
}

impl Shadowsocks {
    pub fn new(p: &ProxyConfig, dialer: Dialer) -> anyhow::Result<Self> {
        let cipher = p.cipher.clone().unwrap_or_default();
        let method = Method::parse(&cipher)
            .ok_or_else(|| anyhow::anyhow!("{}: cipher {cipher} is not supported by prism-core", p.name))?;
        Ok(Shadowsocks {
            name: p.name.clone(),
            server: p.server.clone(),
            port: p.port,
            method,
            key: evp_bytes_to_key(p.password.as_deref().unwrap_or("").as_bytes(), method.key_len()),
            dialer,
        })
    }
}

#[async_trait]
impl Outbound for Shadowsocks {
    fn name(&self) -> &str {
        &self.name
    }
    fn api_type(&self) -> &'static str {
        "Shadowsocks"
    }
    fn udp(&self) -> bool {
        true
    }
    /// AEAD UDP: each packet is `salt | seal(addr | payload)` with a fresh
    /// salt (so a fresh subkey) and nonce 0.
    async fn connect_udp(&self, target: &Address) -> io::Result<UdpPipe> {
        let (tx, mut rx) = self.dialer.udp(&self.server, self.port).await?.split();
        let (method, key, target) = (self.method, self.key.clone(), target.clone());
        Ok(udp_pump(move |mut out, inc| async move {
            let kl = method.key_len();
            let mut buf = vec![0u8; 65535];
            loop {
                tokio::select! {
                    p = out.recv() => match p {
                        Some(p) => {
                            let mut plain = Vec::with_capacity(p.len() + 300);
                            target.write_socks(&mut plain);
                            plain.extend_from_slice(&p);
                            let mut pkt = vec![0u8; kl];
                            rand::thread_rng().fill_bytes(&mut pkt);
                            let mut c = Cipher::new(method, &key, &pkt);
                            pkt.extend(c.seal(&plain));
                            tx.send(&pkt).await?;
                        }
                        None => return Ok(()),
                    },
                    r = rx.recv(&mut buf) => {
                        let n = r?;
                        if n < kl + TAG {
                            continue;
                        }
                        let mut c = Cipher::new(method, &key, &buf[..kl]);
                        let Ok(plain) = c.open(&buf[kl..n]) else { continue };
                        let mut cur = &plain[..];
                        if Address::read_socks(&mut cur).await.is_err() {
                            continue;
                        }
                        if inc.send(cur.to_vec()).await.is_err() {
                            return Ok(());
                        }
                    }
                }
            }
        }))
    }
    async fn connect(&self, target: &Address) -> io::Result<BoxedStream> {
        let tcp = self.dialer.tcp(&self.server, self.port).await?;
        let (method, key) = (self.method, self.key.clone());
        let mut salt = vec![0u8; method.key_len()];
        rand::thread_rng().fill_bytes(&mut salt);
        let mut enc = Cipher::new(method, &key, &salt);
        let mut header = Vec::new();
        target.write_socks(&mut header);
        let (mut rd, mut wr) = tokio::io::split(tcp);
        let mut first = salt;
        enc.seal_chunk(&header, &mut first);
        wr.write_all(&first).await?;

        Ok(pump(move |local| async move {
            let (mut lrd, mut lwr) = tokio::io::split(local);
            let upload = async move {
                let mut buf = vec![0u8; MAX_PAYLOAD];
                let mut out = Vec::with_capacity(MAX_PAYLOAD + 2 * TAG + 2);
                loop {
                    let n = lrd.read(&mut buf).await?;
                    if n == 0 {
                        let _ = wr.shutdown().await;
                        return Ok::<_, io::Error>(());
                    }
                    out.clear();
                    enc.seal_chunk(&buf[..n], &mut out);
                    wr.write_all(&out).await?;
                }
            };
            let download = async move {
                let mut salt = vec![0u8; method.key_len()];
                if let Err(e) = rd.read_exact(&mut salt).await {
                    let _ = lwr.shutdown().await;
                    return if e.kind() == io::ErrorKind::UnexpectedEof { Ok(()) } else { Err(e) };
                }
                let mut dec = Cipher::new(method, &key, &salt);
                let mut lenbuf = [0u8; 2 + TAG];
                let mut data = vec![0u8; MAX_PAYLOAD + TAG];
                loop {
                    if let Err(e) = rd.read_exact(&mut lenbuf).await {
                        let _ = lwr.shutdown().await;
                        return if e.kind() == io::ErrorKind::UnexpectedEof { Ok(()) } else { Err(e) };
                    }
                    let l = dec.open(&lenbuf)?;
                    let len = (u16::from_be_bytes([l[0], l[1]]) as usize) & MAX_PAYLOAD;
                    rd.read_exact(&mut data[..len + TAG]).await?;
                    let plain = dec.open(&data[..len + TAG])?;
                    lwr.write_all(&plain).await?;
                }
            };
            tokio::try_join!(upload, download)?;
            Ok(())
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evp_key_matches_reference() {
        // Known value from shadowsocks-libev for password "foobar", 32 bytes.
        let k = evp_bytes_to_key(b"foobar", 32);
        assert_eq!(hex::encode(&k[..16]), "3858f62230ac3c915f300c664312c63f");
    }

    #[test]
    fn chunk_roundtrip() {
        let key = evp_bytes_to_key(b"pw", 32);
        let salt = [7u8; 32];
        let mut enc = Cipher::new(Method::Chacha, &key, &salt);
        let mut dec = Cipher::new(Method::Chacha, &key, &salt);
        let mut out = Vec::new();
        enc.seal_chunk(b"hello", &mut out);
        let l = dec.open(&out[..2 + TAG]).unwrap();
        assert_eq!(u16::from_be_bytes([l[0], l[1]]), 5);
        assert_eq!(dec.open(&out[2 + TAG..]).unwrap(), b"hello");
    }

    // Exercise the actual AEAD wire frames over a real preceding SOCKS hop.
    // The loopback server checks the requested destination; it never contacts it.
    #[tokio::test]
    async fn three_aead_methods_carry_tcp_and_udp_through_socks_hop() {
        use std::sync::{Arc, atomic::Ordering};
        use tokio::net::{TcpListener, UdpSocket};
        use tokio_util::sync::CancellationToken;
        use crate::{config::parse_any, hub::Hub, inbound};

        async fn chunk(s: &mut tokio::net::TcpStream, cipher: &mut Cipher) -> Vec<u8> {
            let mut len = [0; 2 + TAG];
            s.read_exact(&mut len).await.unwrap();
            let plain = cipher.open(&len).unwrap();
            let n = u16::from_be_bytes([plain[0], plain[1]]) as usize;
            assert!(n <= MAX_PAYLOAD);
            let mut body = vec![0; n + TAG];
            s.read_exact(&mut body).await.unwrap();
            cipher.open(&body).unwrap()
        }
        let mut pair = None;
        let mut seed = 0u32;
        for attempt in 0..32 {
            let port = if attempt == 0 { 0 } else { (1024 + (seed + attempt * 9973) % 64512) as u16 };
            let Ok(tcp) = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await else { continue };
            if attempt == 0 { seed = tcp.local_addr().unwrap().port() as u32; }
            if let Ok(udp) = UdpSocket::bind(tcp.local_addr().unwrap()).await {
                pair = Some((tcp, udp)); break;
            }
        }
        let (tcp, udp) = pair.expect("TCP/UDP test port");
        let first_port = tcp.local_addr().unwrap().port();
        let hub = Hub::new(Default::default(), ".".into(), parse_any("proxies: []\nrules: ['MATCH,DIRECT']\nfind-process-mode: off").unwrap()).await.unwrap();
        let stop = CancellationToken::new();
        let assoc = inbound::UdpAssociations::new(stop.clone());
        let tcp_task = tokio::spawn(inbound::serve_managed(tcp, hub.clone(), stop.clone(), assoc.clone()));
        let udp_task = tokio::spawn(inbound::serve_udp_managed(udp, hub.clone(), stop.clone(), assoc));
        let first: Arc<dyn Outbound> = super::super::build_proxy(&ProxyConfig {
            name: "first".into(), kind: Some(crate::config::ProxyKind::Socks5), server: "127.0.0.1".into(), port: first_port, ..Default::default()
        }, Dialer::Direct).unwrap();
        for (method, cipher_name) in [(Method::Aes128, "aes-128-gcm"), (Method::Aes256, "aes-256-gcm"), (Method::Chacha, "chacha20-ietf-poly1305")] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let packet = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let udp_port = packet.local_addr().unwrap().port();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let master = evp_bytes_to_key(b"chain-test", method.key_len());
                let mut salt = vec![0; method.key_len()];
                socket.read_exact(&mut salt).await.unwrap();
                let mut dec = Cipher::new(method, &master, &salt);
                let address = chunk(&mut socket, &mut dec).await;
                assert_eq!(address, [1,203,0,113,9,1,187]);
                let data = chunk(&mut socket, &mut dec).await;
                assert_eq!(data, b"chain-tcp");
                let salt = vec![31; method.key_len()];
                let mut enc = Cipher::new(method, &master, &salt);
                let mut reply = salt;
                enc.seal_chunk(b"tcp-return", &mut reply);
                socket.write_all(&reply).await.unwrap();
            });
            let datagrams = tokio::spawn(async move {
                let mut buf = vec![0; 65535];
                let (n, from) = packet.recv_from(&mut buf).await.unwrap();
                let kl = method.key_len();
                let master = evp_bytes_to_key(b"chain-test", kl);
                let plain = Cipher::new(method, &master, &buf[..kl]).open(&buf[kl..n]).unwrap();
                assert_eq!(&plain[..7], &[1,203,0,113,9,1,187]);
                assert_eq!(&plain[7..], b"chain-udp");
                let salt = vec![73; kl];
                let mut reply = salt.clone();
                let mut data = plain[..7].to_vec(); data.extend_from_slice(b"udp-return");
                reply.extend(Cipher::new(method, &master, &salt).seal(&data));
                packet.send_to(&reply, from).await.unwrap();
            });
            let cfg = |port| ProxyConfig {name:"last".into(), kind:Some(crate::config::ProxyKind::Shadowsocks), server:"127.0.0.1".into(), port, password:Some("chain-test".into()), cipher:Some(cipher_name.into()), ..Default::default()};
            let target = Address::new("203.0.113.9", 443);
            let mut tcp = Shadowsocks::new(&cfg(port), Dialer::Via(first.clone())).unwrap().connect(&target).await.unwrap();
            tcp.write_all(b"chain-tcp").await.unwrap();
            let mut reply = [0; 10];
            tokio::time::timeout(std::time::Duration::from_secs(3), tcp.read_exact(&mut reply)).await.unwrap().unwrap();
            assert_eq!(&reply, b"tcp-return"); drop(tcp);
            let mut udp = Shadowsocks::new(&cfg(udp_port), Dialer::Via(first.clone())).unwrap().connect_udp(&target).await.unwrap();
            udp.tx.send(b"chain-udp".to_vec()).await.unwrap();
            assert_eq!(tokio::time::timeout(std::time::Duration::from_secs(3), udp.rx.recv()).await.unwrap().unwrap(), b"udp-return");
            drop(udp);
            server.await.unwrap(); datagrams.await.unwrap();
        }
        assert!(hub.core().tunnel.stats.upload.load(Ordering::Relaxed) > 0);
        stop.cancel(); tcp_task.await.unwrap(); udp_task.await.unwrap();
        hub.core().shutdown.cancel();
    }
}
