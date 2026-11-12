//! Shadowsocks 2022 (SIP022): 2022-blake3-aes-128-gcm, 2022-blake3-aes-256-gcm,
//! 2022-blake3-chacha20-poly1305.
//!
//! The password is base64 PSKs; `iPSK1:iPSK2:...:uPSK` adds identity headers
//! (multi-user / relay servers, AES methods only).
//!
//! TCP: salt | identity headers | seal(type ts len) | seal(addr padding) |
//! { seal(len u16) | seal(payload) }*, subkey = BLAKE3-derive(PSK || salt).
//! The response starts with seal(type ts request-salt len) | seal(payload).
//!
//! UDP (AES): AES-ECB(PSK, session id | packet id) | identity headers |
//! seal(body) with subkey = BLAKE3-derive(PSK || session id) and nonce =
//! header[4..16]. UDP (ChaCha): nonce(24) | XChaCha20-Poly1305(PSK, header | body).

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use async_trait::async_trait;
use base64::Engine;
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use rand::{Rng, RngCore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{Dialer, Outbound};
use crate::common::{invalid, pump, udp_pump, Address, BoxedStream, UdpPipe};
use crate::config::ProxyConfig;

const TAG: usize = 16;
const MAX_PAYLOAD: usize = 0xffff;
const MAX_SKEW: u64 = 30;
const SESSION_CTX: &str = "shadowsocks 2022 session subkey";
const IDENTITY_CTX: &str = "shadowsocks 2022 identity subkey";

#[derive(Clone, Copy, PartialEq, Debug)]
enum Method {
    Aes128,
    Aes256,
    Chacha,
}

impl Method {
    fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "2022-blake3-aes-128-gcm" => Some(Method::Aes128),
            "2022-blake3-aes-256-gcm" => Some(Method::Aes256),
            "2022-blake3-chacha20-poly1305" => Some(Method::Chacha),
            _ => None,
        }
    }

    fn key_len(self) -> usize {
        if self == Method::Aes128 {
            16
        } else {
            32
        }
    }
}

pub fn is_2022(cipher: &str) -> bool {
    cipher.to_ascii_lowercase().starts_with("2022-")
}

enum AeadKind {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    Chacha(Box<ChaCha20Poly1305>),
}

impl AeadKind {
    fn new(method: Method, key: &[u8]) -> Self {
        match method {
            Method::Aes128 => AeadKind::Aes128(Box::new(Aes128Gcm::new_from_slice(key).unwrap())),
            Method::Aes256 => AeadKind::Aes256(Box::new(Aes256Gcm::new_from_slice(key).unwrap())),
            Method::Chacha => AeadKind::Chacha(Box::new(ChaCha20Poly1305::new_from_slice(key).unwrap())),
        }
    }

    fn seal(&self, n: &[u8], plain: &[u8]) -> Vec<u8> {
        match self {
            AeadKind::Aes128(c) => c.encrypt(aes_gcm::Nonce::from_slice(n), plain),
            AeadKind::Aes256(c) => c.encrypt(aes_gcm::Nonce::from_slice(n), plain),
            AeadKind::Chacha(c) => c.encrypt(chacha20poly1305::Nonce::from_slice(n), plain),
        }
        .expect("aead encrypt")
    }

    fn open(&self, n: &[u8], sealed: &[u8]) -> io::Result<Vec<u8>> {
        match self {
            AeadKind::Aes128(c) => c.decrypt(aes_gcm::Nonce::from_slice(n), sealed),
            AeadKind::Aes256(c) => c.decrypt(aes_gcm::Nonce::from_slice(n), sealed),
            AeadKind::Chacha(c) => c.decrypt(chacha20poly1305::Nonce::from_slice(n), sealed),
        }
        .map_err(|_| invalid("shadowsocks 2022: decryption failed (wrong password or cipher?)"))
    }
}

/// A TCP direction: AEAD with a little-endian counter nonce.
struct Stream {
    aead: AeadKind,
    nonce: u64,
}

impl Stream {
    fn new(method: Method, psk: &[u8], salt: &[u8]) -> Self {
        Stream { aead: AeadKind::new(method, &derive(SESSION_CTX, psk, salt, method.key_len())), nonce: 0 }
    }

    fn next(&mut self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&self.nonce.to_le_bytes());
        self.nonce += 1;
        n
    }

    fn seal(&mut self, plain: &[u8]) -> Vec<u8> {
        let n = self.next();
        self.aead.seal(&n, plain)
    }

    fn open(&mut self, sealed: &[u8]) -> io::Result<Vec<u8>> {
        let n = self.next();
        self.aead.open(&n, sealed)
    }

    fn seal_chunk(&mut self, payload: &[u8], out: &mut Vec<u8>) {
        out.extend(self.seal(&(payload.len() as u16).to_be_bytes()));
        out.extend(self.seal(payload));
    }
}

/// BLAKE3 key derivation over `psk || salt`, cut to the method's key length.
fn derive(ctx: &str, psk: &[u8], salt: &[u8], len: usize) -> Vec<u8> {
    let mut material = Vec::with_capacity(psk.len() + salt.len());
    material.extend_from_slice(psk);
    material.extend_from_slice(salt);
    blake3::derive_key(ctx, &material)[..len].to_vec()
}

/// Single-block AES with a 16- or 32-byte key.
fn block_encrypt(key: &[u8], block: &mut [u8]) {
    let b = GenericArray::from_mut_slice(block);
    if key.len() == 16 {
        aes::Aes128::new_from_slice(key).unwrap().encrypt_block(b);
    } else {
        aes::Aes256::new_from_slice(key).unwrap().encrypt_block(b);
    }
}

fn block_decrypt(key: &[u8], block: &mut [u8]) {
    let b = GenericArray::from_mut_slice(block);
    if key.len() == 16 {
        aes::Aes128::new_from_slice(key).unwrap().decrypt_block(b);
    } else {
        aes::Aes256::new_from_slice(key).unwrap().decrypt_block(b);
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn check_time(ts: u64) -> io::Result<()> {
    if now().abs_diff(ts) > MAX_SKEW {
        return Err(invalid("shadowsocks 2022: server clock differs by more than 30s"));
    }
    Ok(())
}

fn padding() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut p = vec![0u8; rng.gen_range(1..=900)];
    rng.fill_bytes(&mut p);
    p
}

/// Parses `[iPSK:...:]uPSK` (standard base64 each) into keys of the method's length.
fn parse_psks(method: Method, password: &str) -> anyhow::Result<Vec<Vec<u8>>> {
    let psks = password
        .split(':')
        .map(|s| {
            let k = base64::engine::general_purpose::STANDARD
                .decode(s.trim())
                .map_err(|_| anyhow::anyhow!("password must be base64 keys"))?;
            anyhow::ensure!(k.len() == method.key_len(), "key must be {} bytes, got {}", method.key_len(), k.len());
            Ok(k)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    anyhow::ensure!(
        psks.len() == 1 || method != Method::Chacha,
        "identity headers (iPSK:uPSK) only work with the AES methods"
    );
    Ok(psks)
}

pub struct Ss2022 {
    name: String,
    server: String,
    port: u16,
    method: Method,
    /// Identity PSKs first, the user PSK last.
    psks: Vec<Vec<u8>>,
    dialer: Dialer,
}

impl Ss2022 {
    pub fn new(p: &ProxyConfig, dialer: Dialer) -> anyhow::Result<Self> {
        let cipher = p.cipher.clone().unwrap_or_default();
        let method = Method::parse(&cipher)
            .ok_or_else(|| anyhow::anyhow!("{}: cipher {cipher} is not supported by prism-core", p.name))?;
        let psks = parse_psks(method, p.password.as_deref().unwrap_or("")).map_err(|e| anyhow::anyhow!("{}: {e}", p.name))?;
        Ok(Ss2022 { name: p.name.clone(), server: p.server.clone(), port: p.port, method, psks, dialer })
    }

    fn user_psk(&self) -> &[u8] {
        self.psks.last().unwrap()
    }

    /// TCP identity headers: AES(identity subkey of PSK i, BLAKE3(PSK i+1)[..16]).
    fn tcp_identity(&self, salt: &[u8], out: &mut Vec<u8>) {
        for w in self.psks.windows(2) {
            let mut block = blake3::hash(&w[1]).as_bytes()[..16].to_vec();
            block_encrypt(&derive(IDENTITY_CTX, &w[0], salt, self.method.key_len()), &mut block);
            out.extend(block);
        }
    }

    /// The first client packet: salt, identity headers, fixed and variable headers.
    fn request(&self, target: &Address) -> (Vec<u8>, Stream) {
        let kl = self.method.key_len();
        let mut out = vec![0u8; kl];
        rand::thread_rng().fill_bytes(&mut out);
        let salt = out.clone();
        self.tcp_identity(&salt, &mut out);
        let mut enc = Stream::new(self.method, self.user_psk(), &salt);
        let mut var = Vec::with_capacity(1024);
        target.write_socks(&mut var);
        let pad = padding();
        var.extend((pad.len() as u16).to_be_bytes());
        var.extend(pad);
        let mut fixed = vec![0u8];
        fixed.extend(now().to_be_bytes());
        fixed.extend((var.len() as u16).to_be_bytes());
        out.extend(enc.seal(&fixed));
        out.extend(enc.seal(&var));
        (out, enc)
    }
}

#[async_trait]
impl Outbound for Ss2022 {
    fn name(&self) -> &str {
        &self.name
    }
    fn api_type(&self) -> &'static str {
        "Shadowsocks"
    }
    fn udp(&self) -> bool {
        true
    }

    async fn connect(&self, target: &Address) -> io::Result<BoxedStream> {
        let tcp = self.dialer.tcp(&self.server, self.port).await?;
        let (first, mut enc) = self.request(target);
        let kl = self.method.key_len();
        let req_salt = first[..kl].to_vec();
        let (method, psk) = (self.method, self.user_psk().to_vec());
        let (mut rd, mut wr) = tokio::io::split(tcp);
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
                let eof = |e: io::Error| if e.kind() == io::ErrorKind::UnexpectedEof { Ok(()) } else { Err(e) };
                let mut salt = vec![0u8; kl];
                if let Err(e) = rd.read_exact(&mut salt).await {
                    let _ = lwr.shutdown().await;
                    return eof(e);
                }
                let mut dec = Stream::new(method, &psk, &salt);
                let mut fixed = vec![0u8; 1 + 8 + kl + 2 + TAG];
                rd.read_exact(&mut fixed).await?;
                let f = dec.open(&fixed)?;
                if f[0] != 1 {
                    return Err(invalid("shadowsocks 2022: bad response type"));
                }
                check_time(u64::from_be_bytes(f[1..9].try_into().unwrap()))?;
                if f[9..9 + kl] != req_salt[..] {
                    return Err(invalid("shadowsocks 2022: response is for another request"));
                }
                let mut len = u16::from_be_bytes([f[9 + kl], f[10 + kl]]) as usize;
                let mut data = vec![0u8; MAX_PAYLOAD + TAG];
                let mut lenbuf = [0u8; 2 + TAG];
                loop {
                    rd.read_exact(&mut data[..len + TAG]).await?;
                    let plain = dec.open(&data[..len + TAG])?;
                    lwr.write_all(&plain).await?;
                    if let Err(e) = rd.read_exact(&mut lenbuf).await {
                        let _ = lwr.shutdown().await;
                        return eof(e);
                    }
                    let l = dec.open(&lenbuf)?;
                    len = u16::from_be_bytes([l[0], l[1]]) as usize;
                }
            };
            tokio::try_join!(upload, download)?;
            Ok(())
        }))
    }

    async fn connect_udp(&self, target: &Address) -> io::Result<UdpPipe> {
        let (tx, mut rx) = self.dialer.udp(&self.server, self.port).await?.split();
        let codec = UdpCodec { method: self.method, psks: self.psks.clone(), session: rand::random(), packet: 0 };
        let target = target.clone();
        Ok(udp_pump(move |mut out, inc| async move {
            let mut codec = codec;
            let mut buf = vec![0u8; 65535];
            loop {
                tokio::select! {
                    p = out.recv() => match p {
                        Some(p) => tx.send(&codec.encode(&target, &p)).await?,
                        None => return Ok(()),
                    },
                    r = rx.recv(&mut buf) => {
                        let n = r?;
                        let Some(payload) = codec.decode(&buf[..n]) else { continue };
                        if inc.send(payload).await.is_err() {
                            return Ok(());
                        }
                    }
                }
            }
        }))
    }
}

/// One UDP session's packet encoding.
struct UdpCodec {
    method: Method,
    psks: Vec<Vec<u8>>,
    session: u64,
    packet: u64,
}

impl UdpCodec {
    fn user_psk(&self) -> &[u8] {
        self.psks.last().unwrap()
    }

    fn encode(&mut self, target: &Address, payload: &[u8]) -> Vec<u8> {
        let mut header = [0u8; 16];
        header[..8].copy_from_slice(&self.session.to_be_bytes());
        header[8..].copy_from_slice(&self.packet.to_be_bytes());
        self.packet += 1;
        let mut body = Vec::with_capacity(payload.len() + 300);
        if self.method == Method::Chacha {
            body.extend(header);
        }
        body.push(0);
        body.extend(now().to_be_bytes());
        body.extend(0u16.to_be_bytes());
        target.write_socks(&mut body);
        body.extend_from_slice(payload);

        if self.method == Method::Chacha {
            let mut nonce = [0u8; 24];
            rand::thread_rng().fill_bytes(&mut nonce);
            let c = XChaCha20Poly1305::new_from_slice(self.user_psk()).unwrap();
            let mut pkt = nonce.to_vec();
            pkt.extend(c.encrypt(chacha20poly1305::XNonce::from_slice(&nonce), &body[..]).expect("aead encrypt"));
            return pkt;
        }
        let kl = self.method.key_len();
        let sub = derive(SESSION_CTX, self.user_psk(), &header[..8], kl);
        let sealed = AeadKind::new(self.method, &sub).seal(&header[4..16], &body);
        let mut pkt = header.to_vec();
        block_encrypt(&self.psks[0], &mut pkt[..16]);
        // Identity headers: AES(PSK i, BLAKE3(PSK i+1)[..16] XOR plain header).
        for w in self.psks.windows(2) {
            let mut block: Vec<u8> = blake3::hash(&w[1]).as_bytes()[..16].iter().zip(header).map(|(a, b)| a ^ b).collect();
            block_encrypt(&w[0], &mut block);
            pkt.extend(block);
        }
        pkt.extend(sealed);
        pkt
    }

    /// A server packet's payload, or None when it doesn't decrypt or isn't ours.
    fn decode(&self, pkt: &[u8]) -> Option<Vec<u8>> {
        let body = if self.method == Method::Chacha {
            if pkt.len() < 24 + 16 + TAG {
                return None;
            }
            let c = XChaCha20Poly1305::new_from_slice(self.user_psk()).unwrap();
            let plain = c.decrypt(chacha20poly1305::XNonce::from_slice(&pkt[..24]), &pkt[24..]).ok()?;
            plain[16..].to_vec()
        } else {
            if pkt.len() < 16 + TAG {
                return None;
            }
            let mut header = pkt[..16].to_vec();
            block_decrypt(self.user_psk(), &mut header);
            let sub = derive(SESSION_CTX, self.user_psk(), &header[..8], self.method.key_len());
            AeadKind::new(self.method, &sub).open(&header[4..16], &pkt[16..]).ok()?
        };
        // type | timestamp | client session | padding len | padding | addr | payload
        if body.len() < 19 || body[0] != 1 || u64::from_be_bytes(body[9..17].try_into().unwrap()) != self.session {
            return None;
        }
        check_time(u64::from_be_bytes(body[1..9].try_into().unwrap())).ok()?;
        let pad = u16::from_be_bytes([body[17], body[18]]) as usize;
        let mut cur = body.get(19 + pad..)?;
        Address::read_socks_sync(&mut cur).ok()?;
        Some(cur.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const K16: &str = "AAECAwQFBgcICQoLDA0ODw==";

    #[test]
    fn parses_keys_and_identity_lists() {
        assert_eq!(parse_psks(Method::Aes128, K16).unwrap().len(), 1);
        assert_eq!(parse_psks(Method::Aes128, &format!("{K16}:{K16}")).unwrap().len(), 2);
        assert!(parse_psks(Method::Aes256, K16).is_err(), "16-byte key for aes-256");
        assert!(parse_psks(Method::Aes128, "not base64!").is_err());
        let k32 = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        assert!(parse_psks(Method::Chacha, &format!("{k32}:{k32}")).is_err());
    }

    /// The server's view of a client's first TCP packet decodes back to the target.
    #[test]
    fn tcp_request_decodes() {
        let p = ProxyConfig {
            name: "t".into(),
            cipher: Some("2022-blake3-aes-128-gcm".into()),
            password: Some(K16.into()),
            ..Default::default()
        };
        let ss = Ss2022::new(&p, Dialer::Direct).unwrap();
        let (pkt, _) = ss.request(&Address::new("example.com", 443));
        let mut dec = Stream::new(Method::Aes128, &ss.psks[0], &pkt[..16]);
        let fixed = dec.open(&pkt[16..16 + 11 + TAG]).unwrap();
        assert_eq!(fixed[0], 0);
        check_time(u64::from_be_bytes(fixed[1..9].try_into().unwrap())).unwrap();
        let len = u16::from_be_bytes([fixed[9], fixed[10]]) as usize;
        let var = dec.open(&pkt[16 + 11 + TAG..]).unwrap();
        assert_eq!(var.len(), len);
        let mut cur = &var[..];
        assert_eq!(Address::read_socks_sync(&mut cur).unwrap(), Address::new("example.com", 443));
    }

    /// A server-built UDP reply round-trips through decode, for both packet layouts.
    #[test]
    fn udp_reply_decodes() {
        for (method, key) in [(Method::Aes128, vec![1u8; 16]), (Method::Chacha, vec![2u8; 32])] {
            let codec = UdpCodec { method, psks: vec![key.clone()], session: 42, packet: 0 };
            let server_session = 7u64;
            let mut header = [0u8; 16];
            header[..8].copy_from_slice(&server_session.to_be_bytes());
            let mut body = Vec::new();
            if method == Method::Chacha {
                body.extend(header);
            }
            body.push(1);
            body.extend(now().to_be_bytes());
            body.extend(42u64.to_be_bytes());
            body.extend(3u16.to_be_bytes());
            body.extend([0u8; 3]);
            Address::new("1.2.3.4", 53).write_socks(&mut body);
            body.extend(b"answer");
            let pkt = if method == Method::Chacha {
                let nonce = [9u8; 24];
                let mut p = nonce.to_vec();
                p.extend(XChaCha20Poly1305::new_from_slice(&key).unwrap().encrypt(chacha20poly1305::XNonce::from_slice(&nonce), &body[..]).unwrap());
                p
            } else {
                let sub = derive(SESSION_CTX, &key, &header[..8], 16);
                let sealed = AeadKind::new(method, &sub).seal(&header[4..16], &body);
                let mut p = header.to_vec();
                block_encrypt(&key, &mut p);
                p.extend(sealed);
                p
            };
            assert_eq!(codec.decode(&pkt).as_deref(), Some(&b"answer"[..]), "{method:?}");
        }
    }
}
