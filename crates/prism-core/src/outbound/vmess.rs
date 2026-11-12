//! VMess client with the AEAD header (what current V2Ray / Xray / sing-box
//! servers require; `alterId` is ignored).
//!
//! Request: `auth_id[16] | seal(header_len) | conn_nonce[8] | seal(header)`,
//! keys from the nested-HMAC KDF over the command key
//! (`md5(uuid || "c48619fe-…")`). The header carries the body key / IV,
//! security, options and the destination. Body: chunks of
//! `masked u16 length | AEAD(data) | padding`, the mask and padding length
//! drawn from SHAKE128(IV). The response header is sealed with keys derived
//! from SHA-256 of the request key / IV.

use std::io;

use aes::cipher::{BlockEncrypt, KeyInit};
use aes_gcm::aead::{Aead, Payload};
use async_trait::async_trait;
use chacha20poly1305::ChaCha20Poly1305;
use md5::{Digest, Md5};
use rand::{Rng, RngCore};
use sha2::Sha256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake128;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use super::tls::Tls;
use super::transport::Transport;
use super::{Dialer, Outbound};
use crate::common::{invalid, other, pump, udp_pump, Address, BoxedStream, UdpPipe};
use crate::config::ProxyConfig;

const CMD_TCP: u8 = 1;
const CMD_UDP: u8 = 2;
const OPT_CHUNK_STREAM: u8 = 1;
const OPT_CHUNK_MASKING: u8 = 4;
const OPT_GLOBAL_PADDING: u8 = 8;
const SEC_AES128_GCM: u8 = 3;
const SEC_CHACHA20: u8 = 4;
const SEC_NONE: u8 = 5;
const TAG: usize = 16;
const MAX_CHUNK: usize = 15000;

// ------------------------------------------------------------- KDF

/// `F_0 = SHA-256`, `F_{i+1}(m) = HMAC_{F_i}(keys[i], m)`; returns
/// `F_n(data)`. V2Ray nests HMACs this way with the keys
/// "VMess AEAD KDF", salt, path...
fn nested(keys: &[&[u8]], data: &[u8]) -> [u8; 32] {
    let Some((last, rest)) = keys.split_last() else {
        return Sha256::digest(data).into();
    };
    let mut k = [0u8; 64];
    if last.len() > 64 {
        k[..32].copy_from_slice(&nested(rest, last));
    } else {
        k[..last.len()].copy_from_slice(last);
    }
    let mut inner: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    inner.extend_from_slice(data);
    let ih = nested(rest, &inner);
    let mut outer: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    outer.extend_from_slice(&ih);
    nested(rest, &outer)
}

pub fn kdf(key: &[u8], salt: &str, path: &[&[u8]]) -> [u8; 32] {
    let mut keys: Vec<&[u8]> = vec![b"VMess AEAD KDF", salt.as_bytes()];
    keys.extend_from_slice(path);
    nested(&keys, key)
}

pub fn cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut h = Md5::new();
    Digest::update(&mut h, uuid);
    Digest::update(&mut h, b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    h.finalize().into()
}

fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xffff_ffffu32;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xedb8_8320 } else { c >> 1 };
        }
    }
    !c
}

fn fnv1a(data: &[u8]) -> u32 {
    data.iter().fold(0x811c_9dc5u32, |h, b| (h ^ *b as u32).wrapping_mul(0x0100_0193))
}

fn gcm_seal(key: &[u8], nonce: &[u8], plain: &[u8], aad: &[u8]) -> Vec<u8> {
    let c = aes_gcm::Aes128Gcm::new_from_slice(key).unwrap();
    c.encrypt(nonce.into(), Payload { msg: plain, aad }).unwrap()
}

fn gcm_open(key: &[u8], nonce: &[u8], sealed: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
    let c = aes_gcm::Aes128Gcm::new_from_slice(key).unwrap();
    c.decrypt(nonce.into(), Payload { msg: sealed, aad }).map_err(|_| invalid("vmess: bad response (wrong uuid?)"))
}

/// The sealed request header for the AEAD scheme.
pub fn seal_header(key: &[u8; 16], header: &[u8], now: u64) -> Vec<u8> {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&now.to_be_bytes());
    rand::thread_rng().fill_bytes(&mut id[8..12]);
    let crc = crc32(&id[..12]);
    id[12..].copy_from_slice(&crc.to_be_bytes());
    let ak = kdf(key, "AES Auth ID Encryption", &[]);
    let aes = aes::Aes128::new_from_slice(&ak[..16]).unwrap();
    let mut block = aes::Block::clone_from_slice(&id);
    aes.encrypt_block(&mut block);
    let auth_id: [u8; 16] = block.into();
    let mut nonce = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut nonce);
    let path: [&[u8]; 2] = [&auth_id, &nonce];
    let mut out = auth_id.to_vec();
    let lk = kdf(key, "VMess Header AEAD Key_Length", &path);
    let ln = kdf(key, "VMess Header AEAD Nonce_Length", &path);
    out.extend(gcm_seal(&lk[..16], &ln[..12], &(header.len() as u16).to_be_bytes(), &auth_id));
    out.extend_from_slice(&nonce);
    let hk = kdf(key, "VMess Header AEAD Key", &path);
    let hn = kdf(key, "VMess Header AEAD Nonce", &path);
    out.extend(gcm_seal(&hk[..16], &hn[..12], header, &auth_id));
    out
}

// ------------------------------------------------------------- body

enum Cipher {
    Aes(aes_gcm::Aes128Gcm),
    Chacha(ChaCha20Poly1305),
}

/// One direction of the body: AEAD chunks with masked lengths.
struct Body {
    cipher: Option<Cipher>,
    iv: [u8; 16],
    count: u16,
    shake: Option<sha3::Shake128Reader>,
    padding: bool,
}

impl Body {
    fn new(security: u8, option: u8, key: &[u8; 16], iv: &[u8; 16]) -> Self {
        let cipher = match security {
            SEC_AES128_GCM => Some(Cipher::Aes(aes_gcm::Aes128Gcm::new_from_slice(key).unwrap())),
            SEC_CHACHA20 => {
                let a: [u8; 16] = Md5::digest(key).into();
                let b: [u8; 16] = Md5::digest(a).into();
                let mut k = [0u8; 32];
                k[..16].copy_from_slice(&a);
                k[16..].copy_from_slice(&b);
                Some(Cipher::Chacha(ChaCha20Poly1305::new_from_slice(&k).unwrap()))
            }
            _ => None,
        };
        let shake = (option & (OPT_CHUNK_MASKING | OPT_GLOBAL_PADDING) != 0).then(|| {
            let mut h = Shake128::default();
            h.update(iv);
            h.finalize_xof()
        });
        Body { cipher, iv: *iv, count: 0, shake, padding: option & OPT_GLOBAL_PADDING != 0 }
    }

    fn next_u16(&mut self) -> u16 {
        let mut b = [0u8; 2];
        self.shake.as_mut().map(|s| s.read(&mut b));
        u16::from_be_bytes(b)
    }

    /// (padding length, length mask) for the next chunk; padding first.
    fn draw(&mut self) -> (usize, u16) {
        let pad = if self.padding { (self.next_u16() % 64) as usize } else { 0 };
        let mask = if self.shake.is_some() { self.next_u16() } else { 0 };
        (pad, mask)
    }

    fn nonce(&mut self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n.copy_from_slice(&self.iv[..12]);
        n[..2].copy_from_slice(&self.count.to_be_bytes());
        self.count = self.count.wrapping_add(1);
        n
    }

    fn encode(&mut self, plain: &[u8]) -> Vec<u8> {
        let (pad, mask) = self.draw();
        let nonce = self.nonce();
        let sealed = match &self.cipher {
            Some(Cipher::Aes(c)) => c.encrypt((&nonce).into(), plain).unwrap(),
            Some(Cipher::Chacha(c)) => c.encrypt((&nonce).into(), plain).unwrap(),
            None => plain.to_vec(),
        };
        let mut out = Vec::with_capacity(2 + sealed.len() + pad);
        out.extend_from_slice(&(((sealed.len() + pad) as u16) ^ mask).to_be_bytes());
        out.extend_from_slice(&sealed);
        let start = out.len();
        out.resize(start + pad, 0);
        rand::thread_rng().fill_bytes(&mut out[start..]);
        out
    }

    /// The next chunk's data; None at the end of the stream.
    async fn read<R: AsyncRead + Unpin>(&mut self, r: &mut R) -> io::Result<Option<Vec<u8>>> {
        let len = match r.read_u16().await {
            Ok(l) => l,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        };
        let (pad, mask) = self.draw();
        let total = (len ^ mask) as usize;
        let data_len = total.checked_sub(pad).ok_or_else(|| invalid("vmess: bad chunk length"))?;
        let mut buf = vec![0u8; total];
        r.read_exact(&mut buf).await?;
        buf.truncate(data_len);
        if data_len == 0 || (self.cipher.is_some() && data_len < TAG) {
            return Ok(None);
        }
        let nonce = self.nonce();
        let plain = match &self.cipher {
            Some(Cipher::Aes(c)) => c.decrypt((&nonce).into(), &buf[..]).map_err(|_| invalid("vmess: bad chunk"))?,
            Some(Cipher::Chacha(c)) => c.decrypt((&nonce).into(), &buf[..]).map_err(|_| invalid("vmess: bad chunk"))?,
            None => buf,
        };
        if plain.is_empty() {
            return Ok(None);
        }
        Ok(Some(plain))
    }
}

/// Keys and expectations of one VMess request.
struct Request {
    key: [u8; 16],
    iv: [u8; 16],
    check: u8,
    security: u8,
    option: u8,
}

impl Request {
    fn new(security: u8, cmd: u8) -> Self {
        let mut rng = rand::thread_rng();
        let (mut key, mut iv) = ([0u8; 16], [0u8; 16]);
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut iv);
        let option = match security {
            SEC_NONE if cmd == CMD_UDP => OPT_CHUNK_STREAM,
            SEC_NONE => 0,
            _ => OPT_CHUNK_STREAM | OPT_CHUNK_MASKING | OPT_GLOBAL_PADDING,
        };
        Request { key, iv, check: rng.gen(), security, option }
    }

    /// The plain header (before sealing).
    fn header(&self, cmd: u8, target: &Address) -> Vec<u8> {
        let pad: u8 = rand::thread_rng().gen_range(0..16);
        let mut h = vec![1u8];
        h.extend_from_slice(&self.iv);
        h.extend_from_slice(&self.key);
        h.push(self.check);
        h.push(self.option);
        h.push((pad << 4) | self.security);
        h.push(0);
        h.push(cmd);
        h.extend_from_slice(&target.port().to_be_bytes());
        match target {
            Address::Ip(std::net::SocketAddr::V4(sa)) => {
                h.push(1);
                h.extend_from_slice(&sa.ip().octets());
            }
            Address::Domain(d, _) => {
                h.push(2);
                h.push(d.len().min(255) as u8);
                h.extend_from_slice(&d.as_bytes()[..d.len().min(255)]);
            }
            Address::Ip(std::net::SocketAddr::V6(sa)) => {
                h.push(3);
                h.extend_from_slice(&sa.ip().octets());
            }
        }
        let start = h.len();
        h.resize(start + pad as usize, 0);
        rand::thread_rng().fill_bytes(&mut h[start..]);
        let sum = fnv1a(&h);
        h.extend_from_slice(&sum.to_be_bytes());
        h
    }

    fn resp_key_iv(&self) -> ([u8; 16], [u8; 16]) {
        let k = Sha256::digest(self.key);
        let i = Sha256::digest(self.iv);
        (k[..16].try_into().unwrap(), i[..16].try_into().unwrap())
    }

    fn writer(&self) -> Body {
        Body::new(self.security, self.option, &self.key, &self.iv)
    }

    /// Reads the sealed response header; returns the body reader.
    async fn read_response<R: AsyncRead + Unpin>(&self, r: &mut R) -> io::Result<Body> {
        let (rk, ri) = self.resp_key_iv();
        let lk = kdf(&rk, "AEAD Resp Header Len Key", &[]);
        let ln = kdf(&ri, "AEAD Resp Header Len IV", &[]);
        let mut lb = [0u8; 2 + TAG];
        r.read_exact(&mut lb).await?;
        let len = gcm_open(&lk[..16], &ln[..12], &lb, &[])?;
        let len = u16::from_be_bytes([len[0], len[1]]) as usize;
        let mut hb = vec![0u8; len + TAG];
        r.read_exact(&mut hb).await?;
        let hk = kdf(&rk, "AEAD Resp Header Key", &[]);
        let hn = kdf(&ri, "AEAD Resp Header IV", &[]);
        let head = gcm_open(&hk[..16], &hn[..12], &hb, &[])?;
        if head.first() != Some(&self.check) {
            return Err(invalid("vmess: response doesn't match the request"));
        }
        Ok(Body::new(self.security, self.option, &rk, &ri))
    }
}

pub struct Vmess {
    name: String,
    server: String,
    port: u16,
    key: [u8; 16],
    security: u8,
    tls: Option<Tls>,
    transport: Transport,
    host: String,
    dialer: Dialer,
}

impl Vmess {
    pub fn new(p: &ProxyConfig, dialer: Dialer) -> anyhow::Result<Self> {
        let uuid = uuid::Uuid::parse_str(p.uuid.as_deref().unwrap_or("")).map_err(|_| anyhow::anyhow!("{}: invalid uuid", p.name))?;
        let security = match p.cipher.as_deref().unwrap_or("auto").to_ascii_lowercase().as_str() {
            "" | "auto" | "aes-128-gcm" => SEC_AES128_GCM,
            "chacha20-poly1305" => SEC_CHACHA20,
            "none" | "zero" => SEC_NONE,
            c => anyhow::bail!("{}: VMess security {c} is not supported", p.name),
        };
        let transport = Transport::from_config(p)?;
        let sni = p.sni.clone().unwrap_or_else(|| p.server.clone());
        let tls = if p.tls {
            let alpn = if p.alpn.is_empty() { transport.alpn() } else { p.alpn.clone() };
            Some(Tls::new(&sni, p.skip_cert_verify, &alpn, p.fingerprint.as_deref())?)
        } else {
            None
        };
        let host = p.ws_host.clone().unwrap_or(if p.tls { sni } else { p.server.clone() });
        Ok(Vmess {
            name: p.name.clone(),
            server: p.server.clone(),
            port: p.port,
            key: cmd_key(uuid.as_bytes()),
            security,
            tls,
            transport,
            host,
            dialer,
        })
    }

    /// Connection to the server with TLS and the transport applied.
    async fn dial(&self) -> io::Result<BoxedStream> {
        let s = match &self.tls {
            Some(t) => t.connect(&self.dialer, &self.server, self.port).await?,
            None => self.dialer.tcp(&self.server, self.port).await?,
        };
        self.transport.wrap(s, &self.host).await
    }

    async fn open(&self, cmd: u8, target: &Address) -> io::Result<(BoxedStream, Request)> {
        let mut s = self.dial().await?;
        let req = Request::new(self.security, cmd);
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        s.write_all(&seal_header(&self.key, &req.header(cmd, target), now)).await?;
        s.flush().await?;
        Ok((s, req))
    }
}

#[async_trait]
impl Outbound for Vmess {
    fn name(&self) -> &str {
        &self.name
    }
    fn api_type(&self) -> &'static str {
        "Vmess"
    }
    fn udp(&self) -> bool {
        true
    }

    async fn connect(&self, target: &Address) -> io::Result<BoxedStream> {
        let (s, req) = self.open(CMD_TCP, target).await?;
        Ok(pump(move |local| async move {
            let (mut rd, mut wr) = tokio::io::split(s);
            let (mut lrd, mut lwr) = tokio::io::split(local);
            let chunked = req.option & OPT_CHUNK_STREAM != 0;
            let mut w = req.writer();
            let upload = async move {
                let mut buf = vec![0u8; MAX_CHUNK];
                loop {
                    let n = lrd.read(&mut buf).await?;
                    if n == 0 {
                        return wr.shutdown().await;
                    }
                    if chunked {
                        wr.write_all(&w.encode(&buf[..n])).await?;
                    } else {
                        wr.write_all(&buf[..n]).await?;
                    }
                }
            };
            let download = async move {
                let mut r = req.read_response(&mut rd).await?;
                if chunked {
                    while let Some(d) = r.read(&mut rd).await? {
                        lwr.write_all(&d).await?;
                    }
                } else {
                    tokio::io::copy(&mut rd, &mut lwr).await?;
                }
                lwr.shutdown().await
            };
            tokio::try_join!(upload, download)?;
            Ok(())
        }))
    }

    async fn connect_udp(&self, target: &Address) -> io::Result<UdpPipe> {
        let (s, req) = self.open(CMD_UDP, target).await?;
        Ok(udp_pump(move |mut out, inc| async move {
            let (mut rd, mut wr) = tokio::io::split(s);
            let mut w = req.writer();
            let reader = tokio::spawn(async move {
                let res: io::Result<()> = async {
                    let mut r = req.read_response(&mut rd).await?;
                    while let Some(d) = r.read(&mut rd).await? {
                        if inc.send(d).await.is_err() {
                            break;
                        }
                    }
                    Ok(())
                }
                .await;
                if let Err(e) = res {
                    tracing::debug!("vmess udp reader: {e}");
                }
            });
            let res: io::Result<()> = async {
                while let Some(p) = out.recv().await {
                    wr.write_all(&w.encode(&p[..p.len().min(u16::MAX as usize - 200)])).await?;
                    wr.flush().await?;
                }
                Ok(())
            }
            .await;
            reader.abort();
            res.map_err(|e| other(e.to_string()))
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::Mac;

    #[test]
    fn checksums_and_kdf() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(fnv1a(b"a"), 0xe40c_292c);
        // One level of the chain is plain HMAC-SHA256; two levels use it as
        // the hash of the next HMAC (checked against servers in interop).
        let mut m = <hmac::Hmac<Sha256> as Mac>::new_from_slice(b"VMess AEAD KDF").unwrap();
        Mac::update(&mut m, b"data");
        assert_eq!(nested(&[b"VMess AEAD KDF"], b"data"), <[u8; 32]>::from(m.finalize().into_bytes()));
        assert_ne!(kdf(b"k", "a", &[]), kdf(b"k", "b", &[]));
    }

    #[tokio::test]
    async fn body_round_trip() {
        for (sec, opt) in [
            (SEC_AES128_GCM, OPT_CHUNK_STREAM | OPT_CHUNK_MASKING | OPT_GLOBAL_PADDING),
            (SEC_CHACHA20, OPT_CHUNK_STREAM | OPT_CHUNK_MASKING),
            (SEC_NONE, OPT_CHUNK_STREAM),
        ] {
            let (key, iv) = ([3u8; 16], [9u8; 16]);
            let mut w = Body::new(sec, opt, &key, &iv);
            let mut wire = Vec::new();
            for m in [&b"hello"[..], &[0x55u8; 15000][..], b"x"] {
                wire.extend(w.encode(m));
            }
            let mut r = Body::new(sec, opt, &key, &iv);
            let mut cur = &wire[..];
            assert_eq!(r.read(&mut cur).await.unwrap().unwrap(), b"hello");
            assert_eq!(r.read(&mut cur).await.unwrap().unwrap().len(), 15000);
            assert_eq!(r.read(&mut cur).await.unwrap().unwrap(), b"x");
            assert!(r.read(&mut cur).await.unwrap().is_none());
        }
    }

    #[test]
    fn header_layout() {
        let req = Request::new(SEC_AES128_GCM, CMD_TCP);
        let h = req.header(CMD_TCP, &Address::new("a.com", 443));
        assert_eq!(h[0], 1);
        assert_eq!(h[34], OPT_CHUNK_STREAM | OPT_CHUNK_MASKING | OPT_GLOBAL_PADDING);
        assert_eq!(h[35] & 0x0f, SEC_AES128_GCM);
        assert_eq!(&h[37..43], &[CMD_TCP, 1, 187, 2, 5, b'a']);
        let pad = (h[35] >> 4) as usize;
        assert_eq!(h.len(), 47 + pad + 4);
        assert_eq!(fnv1a(&h[..h.len() - 4]).to_be_bytes(), h[h.len() - 4..]);
        assert_eq!(seal_header(&[1; 16], &h, 1_700_000_000).len(), 16 + 18 + 8 + h.len() + 16);
    }
}
